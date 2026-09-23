#!/usr/bin/env python3
"""
nc_server.py -- Part 1 black-box circuit oracle (TCP line protocol).

  QUERY <block> <hex_input>   simulate the block, return hex output
  SUBMIT <hex_key>            check the assembled 16-byte key -> flag or FAILED
  HELP                        list blocks + budget
  QUIT                        disconnect

Per connection, each block has a query budget (default 300). The (budget+1)-th
QUERY for a block returns BUDGET_EXCEEDED. Gate structure is never revealed.

Env: CTF_HOST (0.0.0.0), CTF_PORT (31337), CTF_SECRET (circuit_secret.json),
     CTF_BUDGET (override budget).
"""
import os
import socketserver
import sys
import threading

import circuitlib as C

SECRET_PATH = os.environ.get("CTF_SECRET", "circuit_secret.json")
HOST = os.environ.get("CTF_HOST", "0.0.0.0")
PORT = int(os.environ.get("CTF_PORT", "31337"))

with open(SECRET_PATH) as _f:
    import json
    SECRET = json.load(_f)
META = SECRET["meta"]
BLOCKS = SECRET["blocks"]
BUDGET = int(os.environ.get("CTF_BUDGET", META.get("budget", 300)))
KEY_ORDER = META["key_order"]
PART1_FLAG = META.get("part1_flag", "flag{PART1_missing}")

# precompile evaluators + expected key once
EVALS = {name: C.make_evaluator(b) for name, b in BLOCKS.items()}
EXPECTED_KEY = C.derive_key(SECRET, KEY_ORDER)
_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


class Handler(socketserver.StreamRequestHandler):
    def send(self, s):
        self.wfile.write((s + "\n").encode())
        self.wfile.flush()

    def handle(self):
        peer = "%s:%d" % self.client_address
        used = {name: 0 for name in BLOCKS}
        log("[+] connect %s" % peer)
        self.send("CTF-Q1 Part1 oracle. Commands: QUERY <block> <hex>, "
                  "SUBMIT <hexkey>, HELP, QUIT. Budget=%d/block." % BUDGET)
        try:
            for raw in self.rfile:
                try:
                    line = raw.decode(errors="replace").strip()
                except Exception:
                    continue
                if not line:
                    continue
                parts = line.split()
                cmd = parts[0].upper()

                if cmd == "QUERY":
                    if len(parts) != 3:
                        self.send("ERR usage: QUERY <block> <hex_input>")
                        continue
                    name, hexin = parts[1], parts[2]
                    b = BLOCKS.get(name)
                    if b is None:
                        self.send("ERR no such block")
                        continue
                    if used[name] >= BUDGET:
                        self.send("BUDGET_EXCEEDED")
                        continue
                    try:
                        x = int(hexin, 16) & ((1 << b["w_in"]) - 1)
                    except ValueError:
                        self.send("ERR bad hex")
                        continue
                    used[name] += 1
                    y = EVALS[name](x)
                    self.send(C.int_to_hex(y, b["w_out"]))

                elif cmd == "SUBMIT":
                    if len(parts) != 2:
                        self.send("ERR usage: SUBMIT <hex_key>")
                        continue
                    try:
                        sub = bytes.fromhex(parts[1])
                    except ValueError:
                        self.send("ERR bad hex")
                        continue
                    if sub == EXPECTED_KEY:
                        log("[*] %s SOLVED part1 (used=%s)" % (peer, used))
                        self.send(PART1_FLAG)
                    else:
                        self.send("FAILED")

                elif cmd == "HELP":
                    self.send("blocks: %s" % " ".join(sorted(BLOCKS)))
                    self.send("budget: %d per block per connection" % BUDGET)
                    self.send("key: SHA256(concat correct inputs for KEY blocks)[:16]")

                elif cmd in ("QUIT", "EXIT", "BYE"):
                    self.send("bye")
                    return
                else:
                    self.send("ERR unknown command (try HELP)")
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            log("[-] disconnect %s used=%s" % (peer, used))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    log("[*] CTF-Q1 oracle: %d blocks, key_order=%s, budget=%d"
        % (len(BLOCKS), KEY_ORDER, BUDGET))
    log("[*] listening on %s:%d (secret=%s)" % (HOST, PORT, SECRET_PATH))
    with Server((HOST, PORT), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log("[*] shutting down")


if __name__ == "__main__":
    main()
