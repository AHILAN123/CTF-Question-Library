# CTF Q1 — three-part reverse-engineering challenge

A self-contained RE challenge I'm authoring, plus a reference solver that solves
it end-to-end.

```
Part 1  black-box boolean circuits over a TCP service  → flag{PART1_...} + key K1
Part 2  anti-debug crackme (decrypted from wrapper.enc with K1) → flag{PART2_...}
Part 3  keygen unpacked by Part 2 → flag{PART3_...}
```

Each part also hides a **decoy** that looks like a solve but isn't (see NOTES.md).

## Layout

| File | Role |
|------|------|
| `generate_circuits.py` | build Part 1 circuits → `circuit.txt` (public) + `circuit_secret.json` (private) |
| `nc_server.py` | TCP oracle: `QUERY`/`SUBMIT`, per-block query budget |
| `part3.c` | Part 3 keygen (invertible checksum) + `legacy_check()` decoy |
| `part2.c` | Part 2 anti-debug wrapper (AES-decrypts embedded part3) + `debug_dump_flag()` decoy |
| `build.sh` | build the whole chain in order, with a self-test per stage |
| `reference_solver.py` | solve all three parts as a black box (no `circuit_secret.json`) |
| `aeslib.py` | pure-Python AES-128-CBC (FIPS-197 self-test); no external deps |
| `circuitlib.py` | circuit model / evaluator / key derivation (build + server side) |
| `solver/part1_solver.py` | differential reconstruction of the circuits |
| `solver/re_utils.py` | static-RE helpers (ELF symbol reads, checksum inversion, key deobfuscation) |
| `tools/` | build helpers + `antidbg_bypass.c` (illustrative LD_PRELOAD shim) |
| `tests/` | `calibrate.py` (budget calibration) and `e2e_part1.py` (live socket test) |
| `NOTES.md` | crypto params, design decisions, and the exact anti-debug bypasses |

## Build & run (Docker — the intended environment)

Parts 2–3 are Linux/x86-64 (ptrace, `/proc`, `rdtsc`, `INT3`, non-PIE ELF), so
build in the provided container:

```bash
docker compose up --build           # builds everything, serves Part 1 on :31337
docker compose run --rm solver      # runs reference_solver.py end-to-end
```

`build.sh` produces:
- `build/circuit_secret.json` — **server-only, never ship this**
- `dist/challenge.zip` — ship to solvers: `circuit.txt`, `wrapper.enc`, `README.txt`

## Build & run (local Linux x86-64, without Docker)

```bash
sudo apt-get install build-essential libssl-dev python3-pyelftools binutils zip gdb
./build.sh
CTF_SECRET=build/circuit_secret.json python3 nc_server.py &      # start the oracle
python3 reference_solver.py --host 127.0.0.1 --port 31337 --challenge-dir dist
```

## Part 1 only (works anywhere, incl. macOS — pure Python)

```bash
python3 tests/calibrate.py --seeds 300      # solver vs budget over 300 instances
python3 tests/e2e_part1.py                  # generate → serve → solve over a real socket
```

## Status / provenance

Part 1 (the hard algorithmic piece — generation, service, differential solver,
key derivation, and budget calibration) is fully tested natively. Parts 2–3
build and run in the Docker image, which self-tests each stage; `part3.c` was
also compiled and exercised natively. `part2.c` requires Linux/x86-64 + OpenSSL
and runs via `docker compose up --build`. See NOTES.md for details.
