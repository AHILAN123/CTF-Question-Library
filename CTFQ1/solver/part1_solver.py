#!/usr/bin/env python3
"""
part1_solver.py -- black-box reconstruction of the Part 1 circuits.

Treats the service as a pure oracle (QUERY/SUBMIT); never reads the secret.

Per block (a bijection whose every output bit is a small junta of the inputs):
  1. Sample: query 0, all single-bit flips of 0, and some random inputs -- one
     shared sample set reused for every output bit.
  2. Learn juntas: for each output bit, greedily grow a support set until the
     sampled data is explained as a function of just those input bits.
  3. Complete tables: fill each output bit's truth table over its support,
     querying only the rows the samples missed.
  4. CSP: recover the unique input assignment matching every output's target;
     confirm with one query. If under-determined, add samples and retry.

Caching guarantees a repeated (block,x) never costs budget twice.
"""
import hashlib
import re
import socket
from collections import Counter


# --------------------------------------------------------- circuit.txt parse
def parse_circuit_txt(path):
    info = {"blocks": {}, "key_order": [], "budget": 300}
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            if s.startswith("BUDGET"):
                info["budget"] = int(s.split("=")[1])
            elif s.startswith("BLOCK"):
                m = re.match(r"BLOCK (\S+) W_IN=(\d+) W_OUT=(\d+) TARGET=([0-9a-fA-F]+)", s)
                name, wi, wo, tgt = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
                info["blocks"][name] = {"w_in": wi, "w_out": wo, "target": int(tgt, 16)}
            elif s.startswith("KEY"):
                inside = s[s.index("(") + 1:s.index(")")]
                info["key_order"] = [x.strip() for x in inside.split(",")]
    return info


# ----------------------------------------------------------------- oracles
class SocketOracle:
    """Real TCP protocol. Caches (block,x)->y; counts only real queries sent."""
    def __init__(self, host, port, widths, timeout=15):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.f = self.sock.makefile("rwb")
        self.f.readline()                       # banner
        self.widths = widths
        self.cache = {}
        self.count = {}

    def _line(self, s):
        self.f.write((s + "\n").encode())
        self.f.flush()
        return self.f.readline().decode().strip()

    def query(self, block, x):
        key = (block, x)
        if key in self.cache:
            return self.cache[key]
        w = self.widths[block]
        resp = self._line("QUERY %s %s" % (block, x.to_bytes((w + 7) // 8, "big").hex()))
        if resp == "BUDGET_EXCEEDED":
            raise RuntimeError("budget exceeded on %s" % block)
        if resp.startswith("ERR"):
            raise RuntimeError("oracle error: %s" % resp)
        y = int(resp, 16)
        self.cache[key] = y
        self.count[block] = self.count.get(block, 0) + 1
        return y

    def submit(self, hexkey):
        return self._line("SUBMIT %s" % hexkey)

    def close(self):
        try:
            self._line("QUIT")
        except Exception:
            pass
        self.sock.close()


# ------------------------------------------------------ grouping + brute
def _affected_outputs(y0, y1):
    d = y0 ^ y1
    s = []
    j = 0
    while d:
        if d & 1:
            s.append(j)
        d >>= 1
        j += 1
    return s


def _components(W, q, bases):
    """Union-find inputs that share an affected output bit -> groups."""
    parent = list(range(W))

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    out_inputs = {}
    for base in bases:
        yb = q(base)
        for i in range(W):
            for j in _affected_outputs(yb, q(base ^ (1 << i))):
                out_inputs.setdefault(j, set()).add(i)
    for j, ins in out_inputs.items():
        ins = sorted(ins)
        for t in range(1, len(ins)):
            union(ins[0], ins[t])
    comps = {}
    for i in range(W):
        comps.setdefault(find(i), []).append(i)
    return [sorted(c) for c in comps.values()]


def solve_block(oracle, name, W, target, rng, budget=300):
    seen = {}

    def q(x):
        if x not in seen:
            seen[x] = oracle.query(name, x)
        return seen[x]

    def guard():
        return oracle.count.get(name, 0) < budget - 2

    bases = [0] + [rng.getrandbits(W) for _ in range(3)]
    for attempt in range(9):
        comps = _components(W, q, bases)
        if all(len(c) <= 6 for c in comps):
            X = 0
            ok = True
            for comp in comps:
                k = len(comp)
                y0 = q(0)
                results = {}
                og = set()
                for v in range(1 << k):
                    if not guard():
                        raise RuntimeError("near budget on %s" % name)
                    x = 0
                    for idx, bpos in enumerate(comp):
                        if (v >> idx) & 1:
                            x |= (1 << bpos)
                    yv = q(x)
                    results[v] = yv
                    og.update(_affected_outputs(y0, yv))
                og = sorted(og)
                tbits = tuple((target >> j) & 1 for j in og)
                match = [v for v, yv in results.items()
                         if tuple((yv >> j) & 1 for j in og) == tbits]
                if len(match) != 1:
                    ok = False
                    break
                for idx, bpos in enumerate(comp):
                    if (match[0] >> idx) & 1:
                        X |= (1 << bpos)
            if ok and q(X) == target:
                return X
        # under-determined grouping: add a baseline and retry
        if not guard():
            raise RuntimeError("near budget on %s" % name)
        bases.append(rng.getrandbits(W) or 1)
    raise RuntimeError("failed to resolve block %s" % name)


# ---------------------------------------------------------- full part 1 run
def solve_part1(oracle, info, rng, verbose=True):
    parts = []
    per_block = {}
    for name in info["key_order"]:
        b = info["blocks"][name]
        x = solve_block(oracle, name, b["w_in"], b["target"], rng, info["budget"])
        parts.append(x.to_bytes((b["w_in"] + 7) // 8, "big"))
        per_block[name] = oracle.count.get(name, 0)
        if verbose:
            print("  [part1] %-3s X=%s queries=%d/%d"
                  % (name, parts[-1].hex(), per_block[name], info["budget"]))
    k1 = hashlib.sha256(b"".join(parts)).digest()[:16]
    return k1.hex(), oracle.submit(k1.hex()), per_block
