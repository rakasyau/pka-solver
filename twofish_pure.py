"""Pure-Python Twofish, forward (encryption) direction only.

Fallback for when no native `_twofish` module is importable: the Hermes
runtime interpreter ships none and `pip install twofish` has no cp314 wheel,
so the plugin must not depend on it.

Forward direction is all EAX needs — CTR runs the forward cipher as its
keystream generator in both directions, so decryption never calls backwards.

Derived from Bjorn Edstrom's pure-Python Twofish (sommer/loxodo), itself from
Dr Brian Gladman's C implementation, carried with permission to use freely or
for a fee in a derived implementation. selftest.py checks it against the
published known-answer test AND against the native backend when present.

ponytail: pure Python, so a large .pka costs seconds. Fine for coursework.
Install the native `twofish` wheel and this module is skipped entirely.
"""

import struct

_M = 0xFFFFFFFF

_TAB_5B = (0, 90, 180, 238)
_TAB_EF = (0, 238, 180, 90)
_ROR4 = (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)
_ASHX = (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)
_QT0 = ((8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4),
        (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5))
_QT1 = ((14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13),
        (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8))
_QT2 = ((11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1),
        (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15))
_QT3 = ((13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10),
        (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10))


def _rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & _M


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & _M


def _byte(x, n):
    """Little-endian word byte, matching Gladman's byte(x,n) macro."""
    return (x >> (8 * n)) & 0xFF


def _qp(n, x):
    a0, b0 = x >> 4, x & 15
    a1 = a0 ^ b0
    b1 = _ROR4[b0] ^ _ASHX[a0]
    a2 = _QT0[n][a1]
    b2 = _QT1[n][b1]
    a3 = a2 ^ b2
    b3 = _ROR4[b2] ^ _ASHX[a2]
    return (_QT3[n][b3] << 4) | _QT2[n][a3]


def _build_tables():
    """Key-independent q/m tables, built once at import (~1 ms)."""
    q0 = [_qp(0, i) for i in range(256)]
    q1 = [_qp(1, i) for i in range(256)]
    m = [[] for _ in range(4)]
    for i in range(256):
        f = q1[i]
        f5b = f ^ (f >> 2) ^ _TAB_5B[f & 3]
        fef = f ^ (f >> 1) ^ (f >> 2) ^ _TAB_EF[f & 3]
        m[0].append(f + (f5b << 8) + (fef << 16) + (fef << 24))
        m[2].append(f5b + (fef << 8) + (f << 16) + (fef << 24))
        g = q0[i]
        g5b = g ^ (g >> 2) ^ _TAB_5B[g & 3]
        gef = g ^ (g >> 1) ^ (g >> 2) ^ _TAB_EF[g & 3]
        m[1].append(gef + (gef << 8) + (g5b << 16) + (g << 24))
        m[3].append(g5b + (g << 8) + (gef << 16) + (g5b << 24))
    return q0, q1, m


_Q0, _Q1, _MTAB = _build_tables()


def _mds_rem(p0, p1):
    """Multiply by x^8 + 0x14D in GF(2^8)."""
    for _ in range(8):
        t = p1 >> 24
        p1 = ((p1 << 8) & _M) | (p0 >> 24)
        p0 = (p0 << 8) & _M
        u = (t << 1) & _M
        if t & 0x80:
            u ^= 0x0000014D
        p1 ^= t ^ ((u << 16) & _M)
        u ^= t >> 1
        if t & 0x01:
            u ^= 0x0000014D >> 1
        p1 ^= ((u << 24) & _M) | ((u << 8) & _M)
    return p1


class TwofishPure:
    """Twofish ECB forward cipher, 128-bit key, 128-bit blocks.

    128-bit keys only: that is what Packet Tracer uses (PKA_KEY and NETS_KEY
    are both 16 bytes), and shipping key schedules nothing exercises is worse
    than refusing the sizes nothing needs.
    """

    name = "twofish-pure"

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError(
                "pure-Python Twofish supports 16-byte keys only, got %d"
                % len(key))
        w0, w1, w2, w3 = struct.unpack("<4I", key)
        # Twofish interleaves the key: me/mo are the even/odd word streams and
        # the S-vector is mds_rem of each ADJACENT pair, stored reversed.
        me_key, mo_key = (w0, w2), (w1, w3)
        self.s_key = [_mds_rem(w2, w3), _mds_rem(w0, w1)]
        self.mk_tab = self._gen_mk_tab()
        self.l_key = [0] * 40
        for i in range(0, 40, 2):
            a = (0x01010101 * i) & _M
            b = (a + 0x01010101) & _M
            ha = self._h(a, me_key)
            hb = _rotl32(self._h(b, mo_key), 8)
            self.l_key[i] = (ha + hb) & _M
            self.l_key[i + 1] = _rotl32((ha + 2 * hb) & _M, 9)

    def _h(self, x, key):
        # Order matters: Q[b] first, XOR the S-vector byte, then the OUTER Q,
        # and only then XOR the other S-vector byte.
        b0 = _Q0[_Q0[_byte(x, 0)] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)
        b1 = _Q0[_Q1[_byte(x, 1)] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)
        b2 = _Q1[_Q0[_byte(x, 2)] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)
        b3 = _Q1[_Q1[_byte(x, 3)] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)
        m = _MTAB
        return m[0][b0] ^ m[1][b1] ^ m[2][b2] ^ m[3][b3]

    def _gen_mk_tab(self):
        """Key-dependent S-box tables: each byte walks the q-permutation."""
        k0, k1 = self.s_key
        mk = [[0] * 256 for _ in range(4)]
        for i in range(256):
            mk[0][i] = _MTAB[0][_Q0[_Q0[i] ^ _byte(k1, 0)] ^ _byte(k0, 0)]
            mk[1][i] = _MTAB[1][_Q0[_Q1[i] ^ _byte(k1, 1)] ^ _byte(k0, 1)]
            mk[2][i] = _MTAB[2][_Q1[_Q0[i] ^ _byte(k1, 2)] ^ _byte(k0, 2)]
            mk[3][i] = _MTAB[3][_Q1[_Q1[i] ^ _byte(k1, 3)] ^ _byte(k0, 3)]
        return mk

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish block must be 16 bytes")
        blk = list(struct.unpack("<4I", block))
        lk = self.l_key
        m0, m1, m2, m3 = self.mk_tab
        blk[0] ^= lk[0]
        blk[1] ^= lk[1]
        blk[2] ^= lk[2]
        blk[3] ^= lk[3]
        # Round keys are l_key[8:40]; entries 0-3 are pre-whitening and 4-7
        # post-whitening.
        for o in range(8, 40, 4):
            t1 = (m0[_byte(blk[1], 3)] ^ m1[_byte(blk[1], 0)]
                  ^ m2[_byte(blk[1], 1)] ^ m3[_byte(blk[1], 2)])
            t0 = (m0[_byte(blk[0], 0)] ^ m1[_byte(blk[0], 1)]
                  ^ m2[_byte(blk[0], 2)] ^ m3[_byte(blk[0], 3)])
            blk[2] = _rotr32(blk[2] ^ ((t0 + t1 + lk[o]) & _M), 1)
            blk[3] = _rotl32(blk[3], 1) ^ ((t0 + 2 * t1 + lk[o + 1]) & _M)
            t1 = (m0[_byte(blk[3], 3)] ^ m1[_byte(blk[3], 0)]
                  ^ m2[_byte(blk[3], 1)] ^ m3[_byte(blk[3], 2)])
            t0 = (m0[_byte(blk[2], 0)] ^ m1[_byte(blk[2], 1)]
                  ^ m2[_byte(blk[2], 2)] ^ m3[_byte(blk[2], 3)])
            blk[0] = _rotr32(blk[0] ^ ((t0 + t1 + lk[o + 2]) & _M), 1)
            blk[1] = _rotl32(blk[1], 1) ^ ((t0 + 2 * t1 + lk[o + 3]) & _M)
        out = (blk[2] ^ lk[4], blk[3] ^ lk[5], blk[0] ^ lk[6], blk[1] ^ lk[7])
        return struct.pack("<4I", *out)