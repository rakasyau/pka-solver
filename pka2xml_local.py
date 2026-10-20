"""pka2xml_local — Packet Tracer .pka/.pkt crypto, pure local Python.

Port of https://github.com/mircodz/pka2xml (BSD-2-Clause) from Crypto++ to
Python + ctypes. No Docker, no WSL, no compiler.

Pipeline (identical to pka2xml):
    decrypt: deobfuscate-1 -> Twofish/EAX -> deobfuscate-2 -> zlib
    encrypt: zlib -> obfuscate-2 -> Twofish/EAX -> obfuscate-1

EAX is implemented here rather than taken from a crypto package because
pycryptodome ships no Twofish and `twofish` ships no mode wrappers. The
implementation is validated against pycryptodome's AES-EAX (see selftest.py).
"""

import ctypes
import importlib.util
import os
import struct
import zlib
from ctypes import Structure, pointer, create_string_buffer, c_uint32

__all__ = ["decrypt_pka", "encrypt_pka", "decrypt_stream", "decrypt_nets",
           "decrypt_logs", "is_old_pt", "PKA_KEY", "PKA_IV", "NETS_KEY",
           "NETS_IV", "EAX", "Twofish", "NoCipher"]


class PkaError(Exception):
    pass


# ── Twofish block cipher (ctypes → _twofish.pyd from `pip install twofish`) ──

class _TwofishKey(Structure):
    _fields_ = [('s', (c_uint32 * 4) * 256), ('K', c_uint32 * 40)]


class _NativeTwofish:
    """Twofish via the `_twofish` C extension (pip install twofish)."""

    name = "twofish-native"

    def __init__(self, key):
        lib = _load_twofish()
        self._lib = lib
        self._key = _TwofishKey()
        lib.exp_Twofish_prepare_key(key, len(key), pointer(self._key))

    def encrypt_block(self, block: bytes) -> bytes:
        out = create_string_buffer(16)
        self._lib.exp_Twofish_encrypt(pointer(self._key), block, out)
        return out.raw


class Twofish:
    """Twofish ECB block encryptor, 128-bit blocks.

    Uses the native `_twofish` module when importable and falls back to the
    bundled pure-Python implementation. Both are checked against each other in
    selftest.py, so the fallback is not a second-class citizen.
    """

    name = "twofish"

    def __init__(self, key):
        self._impl = _make_twofish(key)

    @property
    def backend(self):
        return self._impl.name

    def encrypt_block(self, block: bytes) -> bytes:
        return self._impl.encrypt_block(block)


class NoCipher:
    """Identity cipher — for the pre-v5 'old PT' XOR-only format."""

    name = "none"

    def encrypt_block(self, block: bytes) -> bytes:
        return block


_twofish_lib = None


def _make_twofish(key: bytes):
    """Native Twofish if importable, else the bundled pure-Python one."""
    try:
        return _NativeTwofish(key)
    except PkaError:
        from twofish_pure import TwofishPure
        return TwofishPure(key)


def _load_twofish():
    global _twofish_lib
    if _twofish_lib is not None:
        return _twofish_lib
    spec = importlib.util.find_spec("_twofish")
    if spec is None or not spec.origin:
        raise PkaError("native _twofish not importable")
    lib = ctypes.CDLL(spec.origin)
    lib.exp_Twofish_initialise()
    _twofish_lib = lib
    return lib


# ── EAX authenticated encryption ───────────────────────────────────────────
#
# Crypto++'s EAX hashes three domain-separated, zero-PREFIXED messages and
# keys the CTR mode with the nonce OMAC:
#     OMAC_0 = OMAC_K( 0^15 || 0x00 || N )
#     OMAC_1 = OMAC_K( 0^15 || 0x01 || H )      (header; empty in .pka files)
#     OMAC_2 = OMAC_K( 0^15 || 0x02 || C )
#     tag    = OMAC_0 ^ OMAC_1 ^ OMAC_2
#     C      = CTR_K(key, iv = OMAC_0)(M)       counter starts AT OMAC_0

def _dbl(x: bytes) -> bytes:
    v = int.from_bytes(x, 'big')
    msb = v >> 127
    v = (v << 1) & ((1 << 128) - 1)
    return (v ^ 0x87 if msb else v).to_bytes(16, 'big')


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cmac(cipher, msg: bytes) -> bytes:
    k1 = _dbl(cipher.encrypt_block(b'\x00' * 16))
    k2 = _dbl(k1)
    if not msg:
        blocks = [_xor(b'\x80' + b'\x00' * 15, k1)]
    else:
        blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        tail = blocks[-1]
        if len(tail) == 16:
            blocks[-1] = _xor(tail, k1)
        else:
            blocks[-1] = _xor(tail + b'\x80' + b'\x00' * (15 - len(tail)), k2)
    prev = b'\x00' * 16
    for b in blocks:
        prev = cipher.encrypt_block(_xor(prev, b))
    return prev


class EAX:
    def __init__(self, cipher, nonce: bytes, header: bytes = b''):
        self.c = cipher
        pad = b'\x00' * 15
        self.nonce_omac = cmac(cipher, pad + b'\x00' + nonce)
        self.header_omac = cmac(cipher, pad + b'\x01' + header)
        self.ctr = int.from_bytes(self.nonce_omac, 'big')
        self._pad = pad

    def tag(self, ct: bytes) -> bytes:
        return _xor(_xor(self.nonce_omac, self.header_omac),
                    cmac(self.c, self._pad + b'\x02' + ct))

    def _ctr(self, data: bytes) -> bytes:
        out = bytearray()
        c = self.ctr
        eb = self.c.encrypt_block
        for i in range(0, len(data), 16):
            out += _xor(data[i:i + 16], eb(c.to_bytes(16, 'big')))
            c = (c + 1) & ((1 << 128) - 1)
        return bytes(out)

    def encrypt(self, pt: bytes) -> bytes:
        ct = self._ctr(pt)
        return ct + self.tag(ct)

    def decrypt(self, blob: bytes) -> bytes:
        ct, tg = blob[:-16], blob[-16:]
        if self.tag(ct) != tg:
            raise PkaError("EAX tag verification failed — wrong file, wrong "
                           "Packet Tracer version, or the file is corrupt")
        return self._ctr(ct)


# ── keys ────────────────────────────────────────────────────────────────────
PKA_KEY = bytes([137] * 16)      # {0x89} * 16
PKA_IV = bytes([16] * 16)        # {0x10} * 16
NETS_KEY = bytes([186] * 16)     # {0xBA} * 16
NETS_IV = bytes([190] * 16)      # {0xBE} * 16


# ── obfuscation layers ──────────────────────────────────────────────────────
def _deobfuscate_1(data: bytes) -> bytes:
    """b[i] = a[l + ~i] ^ (l - i * l)"""
    n = len(data)
    return bytes(data[n + ~i] ^ ((n - i * n) & 0xFF) for i in range(n))


def _deobfuscate_2(data: bytes) -> bytes:
    """b[i] = a[i] ^ (l - i)"""
    n = len(data)
    return bytes(b ^ ((n - i) & 0xFF) for i, b in enumerate(data))


def _obfuscate_1(data: bytes) -> bytes:
    n = len(data)
    out = bytearray(n)
    for i, b in enumerate(data):
        out[n + ~i] = b ^ ((n - i * n) & 0xFF)
    return bytes(out)


def _obfuscate_2(data: bytes) -> bytes:
    n = len(data)
    return bytes(b ^ ((n - i) & 0xFF) for i, b in enumerate(data))


# ── zlib wrappers (4-byte big-endian uncompressed length prefix) ───────────
def _uncompress(data: bytes) -> bytes:
    if len(data) < 4:
        raise PkaError("compressed stream is truncated")
    n = struct.unpack('>I', data[:4])[0]
    return zlib.decompress(data[4:4 + n])


def _compress(data: bytes, level: int = -1) -> bytes:
    return struct.pack('>I', len(data)) + zlib.compress(data, level)


def is_old_pt(blob: bytes) -> bool:
    """Pre-v5 .pkt files are XOR-obfuscated + zlib only (no EAX)."""
    if len(blob) < 6:
        return False
    return ((blob[4] ^ (len(blob) - 4)) == 0x78
            or (blob[5] ^ (len(blob) - 5)) == 0x9C)


def _decrypt_old(blob: bytes) -> bytes:
    return _uncompress(_deobfuscate_2(blob))


# ── public API ──────────────────────────────────────────────────────────────
def decrypt_pka(raw: bytes) -> bytes:
    """Decrypt a .pka/.pkt blob to XML bytes."""
    if is_old_pt(raw):
        return _decrypt_old(raw)
    return _uncompress(
        _deobfuscate_2(EAX(Twofish(PKA_KEY), PKA_IV).decrypt(_deobfuscate_1(raw))))


def decrypt_stream(raw: bytes, cipher_factory, key: bytes, iv: bytes) -> bytes:
    """Stages 1-3 only (no decompression) — what pka2xml's decrypt2 does."""
    return EAX(cipher_factory(key), iv).decrypt(_deobfuscate_1(raw))


def encrypt_pka(xml: bytes, level: int = -1) -> bytes:
    if isinstance(xml, str):
        xml = xml.encode('utf-8')
    return _obfuscate_1(
        EAX(Twofish(PKA_KEY), PKA_IV).encrypt(_obfuscate_2(_compress(xml, level))))


def decrypt_nets(raw: bytes) -> bytes:
    """PT's ~/.packettracer/nets file (EAX Twofish, key 0xBA, iv 0xBE)."""
    return decrypt_stream(raw, Twofish, NETS_KEY, NETS_IV)


def decrypt_logs(line: str) -> bytes:
    """One base64 line of a pt_*.log file."""
    import base64
    if isinstance(line, str):
        line = line.strip().encode()
    return decrypt_stream(base64.b64decode(line), Twofish, NETS_KEY, NETS_IV)


def file_decrypt(path: str) -> bytes:
    with open(path, 'rb') as fh:
        return decrypt_pka(fh.read())


def file_encrypt(xml: bytes, path: str, level: int = -1) -> None:
    with open(path, 'wb') as fh:
        fh.write(encrypt_pka(xml, level))