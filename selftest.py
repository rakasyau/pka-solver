"""Self-check for the pka2xml_local crypto layer.

    python selftest.py            # crypto only
    python selftest.py file.pka   # crypto + real-file roundtrip

Layer 1 compares EAX against pycryptodome's AES-EAX (same standard, different
block cipher) so a mistake cannot hide behind a matching pair of errors.
Layer 2 decrypts a real .pka and re-encrypts it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pka2xml_local import (  # noqa: E402
    EAX, Twofish, PKA_KEY, PKA_IV, decrypt_pka, encrypt_pka, is_old_pt, _dbl, _xor,
)


class AESBackend:
    name = "aes"

    def __init__(self, key):
        from Crypto.Cipher import AES as _A
        self._c = _A.new(key, _A.MODE_ECB)

    def encrypt_block(self, b):
        return self._c.encrypt(b)


def test_eax_matches_pycryptodome():
    from Crypto.Cipher import AES as A
    for hlen in (0, 16):
        for n in (0, 1, 5, 16, 31, 64, 100):
            k, nonce, hdr = os.urandom(16), os.urandom(16), os.urandom(hlen)
            pt = os.urandom(n)
            ref = A.new(k, A.MODE_EAX, nonce=nonce, mac_len=16)
            if hdr:
                ref.update(hdr)
            ct, tag = ref.encrypt_and_digest(pt)
            assert EAX(AESBackend(k), nonce, hdr).encrypt(pt) == ct + tag, (hlen, n)
    return "EAX == pycryptodome AES-EAX (14 header/length combinations)"


def test_twofish_known_answer():
    """Twofish book, section B.2, I=3 (128-bit key)."""
    k = bytes.fromhex("9F589F5CF6122C32B6BFEC2F2AE8C35A")
    p = bytes.fromhex("D491DB16E7B1C39E86CB086B789F5419")
    c = bytes.fromhex("019F9809DE1711858FAAC3A3BA20FBC3")
    assert Twofish(k).encrypt_block(p) == c
    return "Twofish KAT (B.2 I=3)"


def test_twofish_backends_agree():
    """The pure-Python fallback must be byte-identical to the native one.

    The runtime interpreter ships no `_twofish`, so on that path the pure
    implementation is the ONLY backend. If they drift, files solved on one
    interpreter stop opening on the other.
    """
    from twofish_pure import TwofishPure
    from pka2xml_local import _NativeTwofish
    checks = 0
    for key in (b'\x89' * 16, bytes(range(16)), bytes([0xFF] * 16),
                os.urandom(16)):
        native, pure = _NativeTwofish(key), TwofishPure(key)
        for blk in (bytes(16), b'\x10' * 16, os.urandom(16)):
            assert native.encrypt_block(blk) == pure.encrypt_block(blk), (
                key.hex(), blk.hex())
            checks += 1
    return "native == pure-Python Twofish (%d blocks)" % checks


def test_obfuscation_is_an_involution():
    from pka2xml_local import _deobfuscate_1, _obfuscate_1, _deobfuscate_2, _obfuscate_2
    blob = os.urandom(257)
    for f, g in ((_deobfuscate_1, _obfuscate_1), (_deobfuscate_2, _obfuscate_2)):
        assert g(f(blob)) == blob and f(g(blob)) == blob
    return "obfuscation layers round-trip"


def test_pka_roundtrip(path):
    raw = open(path, 'rb').read()
    xml = decrypt_pka(raw)
    assert xml.lstrip()[:1] == b"<", "decrypted payload is not XML"
    again = encrypt_pka(xml)
    assert decrypt_pka(again) == xml, "re-encrypted blob does not decrypt back"
    assert is_old_pt(raw) == is_old_pt(again)
    return "roundtrip %s (%d B in → %d B xml → %d B out%s)" % (
        os.path.basename(path), len(raw), len(xml), len(again),
        "" if again == raw else ", not byte-identical (compression level)")


def _has(mod):
    """Import probe that never raises.

    `_twofish` raises SystemError from its module init on some builds, so
    catching only ImportError would crash the probe itself.
    """
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def main():
    failures = []
    skipped = []
    tests = [test_twofish_known_answer, test_obfuscation_is_an_involution]

    # Parity needs a native backend to compare against; pycryptodome is only
    # the EAX oracle. Neither is a real failure when the module is absent.
    # Probe Twofish the way the plugin loads it — `_twofish` can fail as an
    # import yet still load fine as a library via ctypes.
    try:
        from pka2xml_local import _NativeTwofish
        _NativeTwofish(b'\x00' * 16)
        has_native = True
    except Exception:
        has_native = False
    if has_native:
        tests.insert(1, test_twofish_backends_agree)
    else:
        skipped.append("test_twofish_backends_agree (native _twofish absent)")
    if _has("Crypto"):
        tests.insert(1, test_eax_matches_pycryptodome)
    else:
        skipped.append("test_eax_matches_pycryptodome (pycryptodome absent)")

    for fn in tests:
        try:
            print("PASS", fn())
        except Exception as exc:
            failures.append(fn.__name__)
            print("FAIL", fn.__name__, "—", exc)
    for s in skipped:
        print("SKIP", s)

    if len(sys.argv) > 1:
        try:
            print("PASS", test_pka_roundtrip(sys.argv[1]))
        except Exception as exc:
            failures.append("roundtrip")
            print("FAIL roundtrip —", type(exc).__name__, exc)

    if failures:
        print("\n%d check(s) failed: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())