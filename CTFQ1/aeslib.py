"""
aeslib.py -- self-contained AES-128-CBC with PKCS#7 padding. No external deps.

Used by both the challenge build scripts and the reference solver so that the
whole pipeline needs nothing beyond the Python standard library. The S-box is
generated from the GF(2^8) inverse + the standard AES affine transform, and the
module self-tests against the FIPS-197 known-answer vector on import-as-main.

This is intentionally straightforward (not constant-time); it is a CTF build
helper, not production crypto.
"""

# ---------------------------------------------------------------- GF(2^8) ----
def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

# multiplicative inverse table (brute force; foolproof, done once at import)
_INV = [0] * 256
for _a in range(1, 256):
    for _b in range(1, 256):
        if _gmul(_a, _b) == 1:
            _INV[_a] = _b
            break

def _affine(b):
    s = 0
    c = 0x63
    for i in range(8):
        bit = (((b >> i) & 1)
               ^ ((b >> ((i + 4) % 8)) & 1)
               ^ ((b >> ((i + 5) % 8)) & 1)
               ^ ((b >> ((i + 6) % 8)) & 1)
               ^ ((b >> ((i + 7) % 8)) & 1)
               ^ ((c >> i) & 1))
        s |= (bit << i)
    return s

SBOX = [_affine(_INV[b]) for b in range(256)]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# ------------------------------------------------------------- key schedule --
def _key_expansion(key):
    assert len(key) == 16, "AES-128 requires a 16-byte key"
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # 11 round keys of 16 bytes
    return [sum((w[4 * r + c] for c in range(4)), []) for r in range(11)]

# -------------------------------------------------------------- block ops ----
def _add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]

def _sub_bytes(s, box):
    return [box[b] for b in s]

# state is column-major: byte index = row + 4*col
def _shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return o

def _inv_shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return o

def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        o[4 * c + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        o[4 * c + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        o[4 * c + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return o

def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        o[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        o[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        o[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
    return o

def _encrypt_block(block, rks):
    s = _add_round_key(list(block), rks[0])
    for r in range(1, 10):
        s = _sub_bytes(s, SBOX)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, rks[r])
    s = _sub_bytes(s, SBOX)
    s = _shift_rows(s)
    s = _add_round_key(s, rks[10])
    return bytes(s)

def _decrypt_block(block, rks):
    s = _add_round_key(list(block), rks[10])
    for r in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = _sub_bytes(s, INV_SBOX)
        s = _add_round_key(s, rks[r])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _sub_bytes(s, INV_SBOX)
    s = _add_round_key(s, rks[0])
    return bytes(s)

# ------------------------------------------------------------- PKCS7 + CBC ---
def pkcs7_pad(data, bs=16):
    n = bs - (len(data) % bs)
    return data + bytes([n]) * n

def pkcs7_unpad(data, bs=16):
    if not data or len(data) % bs != 0:
        raise ValueError("bad padded length")
    n = data[-1]
    if n < 1 or n > bs or data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 padding")
    return data[:-n]

def encrypt_cbc(key, iv, plaintext):
    """AES-128-CBC encrypt with PKCS7 padding. Returns ciphertext bytes."""
    rks = _key_expansion(key)
    data = pkcs7_pad(plaintext)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, rks)
        out += enc
        prev = enc
    return bytes(out)

def decrypt_cbc(key, iv, ciphertext, unpad=True):
    """AES-128-CBC decrypt. Set unpad=False to keep raw padded bytes."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext not block aligned")
    rks = _key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(ciphertext), 16):
        ct = ciphertext[i:i + 16]
        dec = _decrypt_block(ct, rks)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = ct
    return pkcs7_unpad(bytes(out)) if unpad else bytes(out)


def _selftest():
    # FIPS-197 Appendix C.1 (AES-128) single-block known-answer vector.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    got = _encrypt_block(pt, _key_expansion(key))
    assert got == want, f"AES block KAT failed: {got.hex()}"
    assert _decrypt_block(want, _key_expansion(key)) == pt, "AES inverse failed"
    # CBC round-trip with padding across several block sizes.
    import os
    for n in (0, 1, 15, 16, 17, 100):
        k = os.urandom(16); iv = os.urandom(16); msg = os.urandom(n)
        assert decrypt_cbc(k, iv, encrypt_cbc(k, iv, msg)) == msg, f"CBC rt {n}"
    print("aeslib self-test OK (FIPS-197 KAT + CBC/PKCS7 round-trips)")

if __name__ == "__main__":
    _selftest()
