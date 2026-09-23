# CTF Q1 — build notes, parameters, and anti-debug bypasses

This is an authored, self-contained reverse-engineering challenge. The Part 2
binary is a benign crackme: its "anti-debug" checks are puzzle elements, each a
standard documented technique with a documented bypass, and on failure it does
not attack anything — it just corrupts an in-memory key so decryption yields
garbage. Nothing here self-propagates or touches anything outside `/tmp`.

## Pipeline / key chain

```
Part 1 circuits ──SUBMIT──▶ flag{PART1_...}
        │ recovered inputs → K1 = SHA256(concat inputs)[:16]
        ▼
   wrapper.enc  =  IV(16) || AES-128-CBC_K1(part2)          ──decrypt──▶ part2
        │
   part2 embeds  IV(16) || AES-128-CBC_K2(part3)   (K2 = k2_obf ^ k2_mask)
        │ pass anti-debug + supply K2 ──▶ flag{PART2_...} + writes part3
        ▼
   part3 keygen: reverse checksum → password ──▶ flag{PART3_...}
```

Two independent AES-128-CBC keys: **K1** is derived from Part 1; **K2** is random
per build and embedded (obfuscated) in part2.

## Crypto parameters

- AES-128-CBC, PKCS#7 padding, random 16-byte IV **prepended** to each blob
  (`wrapper.enc` and the part3 blob inside part2).
- Python side: `aeslib.py` (pure-Python, no deps; self-tests against the
  FIPS-197 AES-128 known-answer vector). C side: OpenSSL EVP (`-lcrypto`).
  Interop is checked by `build.sh` (part2 clean-run must reproduce part3
  byte-for-byte).

## Part 1 design decisions

- **Width 16 for every block.** A bijection needs equal input/output width; the
  spec's ranges (16–32 in, 8–16 out) overlap only at 16. A bijection is what
  makes each published `TARGET` have a *unique* preimage, so "the correct input"
  — and therefore the key — is well defined and recoverable. (A non-bijective
  block would give the key an ambiguous definition.)
- **Structure:** each block is a set of independent small S-boxes (3–5 bits
  each) built from reversible gate templates (XOR=CNOT, AND+XOR=Toffoli,
  MUX=Fredkin, NOT) and wired through a secret input/output bit permutation.
  This guarantees bounded fan-in (≤5 input bits per output bit) and a genuine
  bijection, and makes black-box reconstruction tractable: discover the groups
  by differential testing, then brute-force each ≤5-bit group.
- **Budget = 300 queries/block.** Calibrated with `tests/calibrate.py` over 300
  random instances: 300/300 solved, worst case 172 queries (57% of budget),
  median 129. Comfortable headroom.
- **Decoy:** one extra block is generated and published but omitted from the
  `KEY` line; including it (or the wrong order) yields `FAILED`.

## Part 3 checksum (original, not a standard algorithm)

For input byte `in[i]` (password length 12):
```
acc = 0x5A
out[i] = ( rotl8(in[i], (i*3 + 1) & 7) XOR acc + K[i % 4] ) & 0xFF ,  K = 1F 2B 3D 47
acc = (acc + in[i]) & 0xFF
```
Invertible left-to-right (the reference solver inverts it directly; Z3 would
also work). The real flag is XOR-obfuscated with the password, so `strings`
does not reveal it; only the decoy flag is in the clear.

## Anti-debug checks and their (real) bypasses

On ANY failed check the key is XOR'd with a fixed garbage constant, so the
program keeps running and silently produces garbage instead of the real part3.

1. **`ptrace(PTRACE_TRACEME)`** — returns −1 if already traced.
   - Run with no debugger (reference path): it succeeds.
   - `LD_PRELOAD` a stub `long ptrace(...){return 0;}` (see `tools/antidbg_bypass.c`).
   - Or `catch syscall ptrace` in gdb and force the return to 0.
2. **`/proc/self/status` TracerPid** — nonzero means a tracer is attached.
   - Run clean (TracerPid 0).
   - `LD_PRELOAD` hooking `open`/`openat` to redirect that path to a spoofed
     copy with `TracerPid: 0` (implemented in `tools/antidbg_bypass.c`).
3. **`rdtsc` timing window** — a large delta implies single-stepping.
   - Don't single-step the region; run to a hardware breakpoint past it.
   - Or patch the threshold / make `rdtsc` return controlled values.
   - Threshold is generous (200M cycles): it flags single-stepping, not plain
     breakpoints. (This is the check most affected by CPU emulation; native
     x86-64 is recommended.)
4. **`.text` self-checksum** (FNV-1a over `guarded_func`, baseline patched in at
   build time and living in `.data` so patching it does not change `.text`).
   - Use **hardware** breakpoints, not software ones, so code bytes are
     unchanged — the checksum stays valid.
   - Or NOP the check, or recompute & repatch the baseline after modifying code.
5. **INT3 (`0xCC`) scan** over `guarded_func`, compared to the pristine `0xCC`
   count baked at build time.
   - Same as (4): hardware breakpoints write no `0xCC`. Or place software
     breakpoints outside the guarded region, or patch out the scan.

The reference solver uses the simplest valid bypass for all five: **run part2
with no debugger attached**, so every check passes, then supply the extracted
K2. `tools/antidbg_bypass.c` demonstrates the dynamic (LD_PRELOAD + hardware
breakpoint) route for checks 1–2, which combined with `hbreak` handles 3–5.

## Decoys (present, reachable, wrong)

- **Part 1:** the block missing from the `KEY` line — never enters K1.
- **Part 2:** `debug_dump_flag()` — unreferenced; `gdb -batch -ex 'call (void)debug_dump_flag()' ./part2`.
- **Part 3:** `legacy_check()` — unreferenced; `gdb -batch -ex 'call (void)legacy_check()' ./part3`.

## What was tested where

- **Part 1** (generation, service, differential solver, key derivation, budget
  calibration) is fully tested on the author's macOS/ARM host — pure Python,
  no container needed. See `tests/`.
- **Parts 2–3** are Linux/x86-64 + OpenSSL (ptrace, `/proc`, `rdtsc`, `INT3`,
  non-PIE ELF), so they build and run in the Docker image; `build.sh` self-tests
  each stage. `part3.c` is portable C and was additionally compiled/run
  natively. `part2.c` was not executed on the author host (no Linux/Docker
  there); `docker compose up --build` exercises it.
