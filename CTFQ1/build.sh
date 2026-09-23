#!/usr/bin/env bash
# build.sh -- build the whole CTF Q1 pipeline, in dependency order, with a
# self-test after every stage. Intended to run on Linux x86-64 (see Dockerfile).
set -euo pipefail
cd "$(dirname "$0")"

CC="${CC:-cc}"
PORT="${CTF_PORT:-31337}"
SEEDARG=""
[ -n "${CTF_SEED:-}" ] && SEEDARG="--seed ${CTF_SEED}"
VERIFY=""
[ "${CTF_VERIFY:-0}" = "1" ] && VERIFY="--verify"
export PYTHONPATH=.
mkdir -p build dist
say(){ printf '\n=== %s ===\n' "$*"; }

say "1/8  python AES self-test (FIPS-197 KAT)"
python3 aeslib.py

say "2/8  compile part3 (keygen)"
$CC -O1 -o build/part3 part3.c
echo "  built build/part3"

say "3/8  generate circuits + derive Part-1 key K1"
python3 generate_circuits.py $SEEDARG $VERIFY --out-dir build --keyout build/part1_key.hex
K1="$(cat build/part1_key.hex)"
echo "  K1 = $K1"

say "4/8  encrypt part3 under K2, emit part2_gen.h"
python3 tools/make_part2_gen.py --part3 build/part3 \
        --out-header build/part2_gen.h --key-out build/part2_key.hex
K2="$(cat build/part2_key.hex)"

say "5/8  compile part2 (anti-debug wrapper) + patch self-checksum"
$CC -O1 -no-pie -fno-pic -Ibuild -o build/part2 part2.c -lcrypto
python3 tools/patch_guard.py build/part2

say "6/8  self-tests"
# 6a: a CLEAN run of part2 (no debugger) must pass all checks and reproduce part3
OUT="$(printf '%s\n' "$K2" | ./build/part2)"
printf '%s\n' "$OUT" | sed 's/^/    part2> /'
P3PATH="$(printf '%s\n' "$OUT" | sed -n 's/.*-> \(\/tmp\/part3_[A-Za-z0-9]*\).*/\1/p')"
[ -n "$P3PATH" ] || { echo "  FAIL: part2 did not report a part3 path"; exit 1; }
cmp "$P3PATH" build/part3 && echo "  [ok] clean-run part2 reproduced part3 byte-for-byte"
printf '%s\n' "$OUT" | grep -q 'flag{PART2' && echo "  [ok] PART2 flag emitted"
# 6b: invert part3's checksum from its symbols, feed the password back
PW="$(python3 -c "import sys;sys.path.insert(0,'solver');import re_utils;print(re_utils.invert_part3('build/part3'))")"
P3FLAG="$(./build/part3 "$PW")"
echo "  part3('$PW') -> $P3FLAG"
printf '%s\n' "$P3FLAG" | grep -q 'flag{PART3' && echo "  [ok] PART3 flag via inverted password"
# 6c: verify K2 can be re-derived from the part2 binary (as the solver will)
K2X="$(python3 -c "import sys;sys.path.insert(0,'solver');import re_utils;print(re_utils.extract_k2('build/part2').hex())")"
[ "$K2X" = "$K2" ] && echo "  [ok] K2 recovered from part2 binary (k2_obf ^ k2_mask)"

say "7/8  encrypt part2 with K1 -> wrapper.enc, verify round-trip"
python3 tools/make_wrapper.py --in build/part2 --key build/part1_key.hex --out dist/wrapper.enc
python3 - <<PY
import sys; sys.path.insert(0, ".")
import aeslib
k = bytes.fromhex(open("build/part1_key.hex").read().strip())
blob = open("dist/wrapper.enc", "rb").read()
pt = aeslib.decrypt_cbc(k, blob[:16], blob[16:])
assert pt == open("build/part2", "rb").read(), "wrapper.enc round-trip mismatch"
print("  [ok] wrapper.enc decrypts back to part2")
PY

say "8/8  assemble dist/challenge.zip + README.txt"
cp build/circuit.txt dist/circuit.txt
cat > dist/README.txt <<RM
CTF Q1 -- three-part reverse-engineering challenge
==================================================

Files in this archive:
  circuit.txt   Part 1 interface (block widths, TARGETs, KEY order, protocol).
  wrapper.enc   The Part 2 binary, AES-128-CBC encrypted (see below).

Pipeline (each part feeds the next):
  Part 1  Talk to the black-box circuit service and recover, per block, the
          input that yields its published TARGET. Assemble the key and SUBMIT
          it for the Part 1 flag. That same key (K1) decrypts wrapper.enc.
  Part 2  Decrypting wrapper.enc gives an executable crackme with anti-debug
          checks guarding an embedded, encrypted Part 3 binary. Get past the
          checks and feed it the right key to unpack Part 3 (and the Part 2 flag).
  Part 3  A keygen: reverse its checksum, find the password, get the Part 3 flag.

Connect to the Part 1 service:
  nc <SERVER_HOST> ${PORT}
Then use QUERY/SUBMIT as documented at the top of circuit.txt.

Key derivation (Part 1 -> K1):
  For each block listed in the KEY line of circuit.txt, in order, take the
  16-bit input X you recovered, encode it big-endian as 2 bytes, and
  concatenate. Then K1 = SHA256(concatenation)[:16] (first 16 bytes).
  Exactly one block is a DECOY -- it is listed but NOT in KEY.

Decrypting wrapper.enc:
  AES-128-CBC. The first 16 bytes are the IV; the rest is ciphertext; the key
  is K1 (the 16 bytes above). PKCS#7 padding. The result is an ELF executable.

Good luck. (Everything here is self-contained; the binaries only touch /tmp.)
RM
( cd dist && rm -f challenge.zip && zip -q challenge.zip circuit.txt wrapper.enc README.txt )
echo "  [ok] dist/challenge.zip:"; ( cd dist && unzip -l challenge.zip | sed 's/^/    /' )

say "BUILD OK"
echo "Artifacts:"
echo "  service secret : build/circuit_secret.json  (server-only, do NOT ship)"
echo "  run service    : CTF_SECRET=build/circuit_secret.json python3 nc_server.py"
echo "  ship to solvers: dist/challenge.zip"
