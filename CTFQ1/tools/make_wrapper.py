#!/usr/bin/env python3
"""Encrypt part2 with K1 (the Part-1 key) -> wrapper.enc = IV(16) || ciphertext."""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import aeslib


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--key", required=True, help="hex string or path to hex file")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    key = bytes.fromhex(open(a.key).read().strip()) if os.path.exists(a.key) else bytes.fromhex(a.key)
    data = open(a.inp, "rb").read()
    iv = os.urandom(16)
    open(a.out, "wb").write(iv + aeslib.encrypt_cbc(key, iv, data))
    print("[make_wrapper] %s -> %s (%d B, iv||ct)" % (a.inp, a.out, 16 + len(data) + (16 - len(data) % 16)))


if __name__ == "__main__":
    main()
