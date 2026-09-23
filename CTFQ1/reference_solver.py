#!/usr/bin/env python3
"""
reference_solver.py -- solve CTF Q1 end-to-end, treating the shipped material
(circuit.txt + wrapper.enc + the running service) as a black box. It never reads
circuit_secret.json.

  Part 1  differential reconstruction of each circuit block -> assemble & SUBMIT
          K1 -> Part 1 flag; K1 also decrypts wrapper.enc.
  Part 2  extract the embedded key from part2, run it WITHOUT a debugger (so the
          anti-debug checks pass by construction) -> unpack part3 + Part 2 flag.
  Part 3  invert the keygen's checksum -> password -> Part 3 flag.

Anti-debug bypass used here: none needed -- a clean run passes every check. To
solve it dynamically under a debugger instead, see NOTES.md (LD_PRELOAD shim for
ptrace + /proc/self/status, etc.).

Usage: python3 reference_solver.py --host H --port P --challenge-dir dist
"""
import argparse
import os
import random
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "solver"))

import aeslib
import re_utils
from part1_solver import parse_circuit_txt, SocketOracle, solve_part1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=31337)
    ap.add_argument("--challenge-dir", default="dist")
    ap.add_argument("--workdir", default="solve_out")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    os.makedirs(a.workdir, exist_ok=True)
    circ = os.path.join(a.challenge_dir, "circuit.txt")
    wrap = os.path.join(a.challenge_dir, "wrapper.enc")

    print("== Part 1: black-box circuit reconstruction ==")
    info = parse_circuit_txt(circ)
    widths = {n: b["w_in"] for n, b in info["blocks"].items()}
    orc = SocketOracle(a.host, a.port, widths)
    k1, resp, per = solve_part1(orc, info, random.Random(a.seed), verbose=True)
    orc.close()
    print("  total queries: %d  (budget %d/block)" % (sum(per.values()), info["budget"]))
    print("  K1 = %s" % k1)
    print("  PART 1 FLAG: %s" % resp)
    if not resp.startswith("flag{"):
        sys.exit("  !! Part 1 SUBMIT failed: %s" % resp)

    print("\n== bridge: AES-decrypt wrapper.enc with K1 ==")
    blob = open(wrap, "rb").read()
    part2 = aeslib.decrypt_cbc(bytes.fromhex(k1), blob[:16], blob[16:])
    p2 = os.path.join(a.workdir, "part2")
    open(p2, "wb").write(part2)
    os.chmod(p2, 0o755)
    print("  wrote %s (%d bytes, ELF magic=%s)" % (p2, len(part2), part2[:4] == b"\x7fELF"))

    print("\n== Part 2: recover embedded key, pass anti-debug (clean run) ==")
    k2 = re_utils.extract_k2(p2)
    print("  recovered K2 = %s   (k2_obf ^ k2_mask, read from the binary)" % k2.hex())
    env = dict(os.environ)
    env.pop("LD_PRELOAD", None)
    r = subprocess.run([os.path.abspath(p2)], input=k2.hex() + "\n",
                       capture_output=True, text=True, env=env)
    for ln in r.stdout.splitlines():
        print("    part2> " + ln)
    m = re.search(r"-> (/tmp/part3_\w+)", r.stdout)
    flag2 = next((ln for ln in r.stdout.splitlines() if ln.startswith("flag{PART2")), None)
    if not m or not flag2:
        sys.exit("  !! part2 did not unpack part3\nstdout=%s\nstderr=%s" % (r.stdout, r.stderr))
    print("  PART 2 FLAG: %s" % flag2)
    p3 = os.path.join(a.workdir, "part3")
    shutil.copy(m.group(1), p3)
    os.chmod(p3, 0o755)

    print("\n== Part 3: invert the keygen checksum ==")
    pw = re_utils.invert_part3(p3)
    print("  recovered password = %r" % pw)
    r3 = subprocess.run([os.path.abspath(p3), pw], capture_output=True, text=True)
    flag3 = r3.stdout.strip()
    print("  PART 3 FLAG: %s" % flag3)

    print("\n== SUMMARY ==")
    print("  Part 1: %s" % resp)
    print("  Part 2: %s" % flag2)
    print("  Part 3: %s" % flag3)
    ok = resp.startswith("flag{PART1") and flag2.startswith("flag{PART2") and flag3.startswith("flag{PART3")
    print("\n  decoys (present, reachable, and wrong if triggered):")
    print("   - Part 1: the block absent from circuit.txt's KEY line (never enters K1)")
    print("   - Part 2: debug_dump_flag()  [gdb -batch -ex 'call (void)debug_dump_flag()' %s]" % p2)
    print("   - Part 3: legacy_check()     [gdb -batch -ex 'call (void)legacy_check()' %s]" % p3)
    print("\nRESULT:", "ALL THREE FLAGS RECOVERED" if ok else "INCOMPLETE")
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
