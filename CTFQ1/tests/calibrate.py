#!/usr/bin/env python3
import argparse
import os
import random
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solver"))

import circuitlib as C
import generate_circuits as G
from part1_solver import solve_part1  # noqa


class LocalOracle:
    """In-process stand-in for nc_server: same caching/budget semantics."""
    def __init__(self, secret):
        self.evals = {n: C.make_evaluator(b) for n, b in secret["blocks"].items()}
        self.widths = {n: b["w_in"] for n, b in secret["blocks"].items()}
        self.budget = secret["meta"]["budget"]
        self.expected = C.derive_key(secret, secret["meta"]["key_order"])
        self.cache = {}
        self.count = {}

    def query(self, block, x):
        key = (block, x)
        if key in self.cache:
            return self.cache[key]
        self.count[block] = self.count.get(block, 0) + 1
        if self.count[block] > self.budget:
            raise RuntimeError("BUDGET_EXCEEDED on %s" % block)
        y = self.evals[block](x)
        self.cache[key] = y
        return y

    def submit(self, hexkey):
        return "flag{OK}" if bytes.fromhex(hexkey) == self.expected else "FAILED"


def info_from_secret(secret):
    info = {"blocks": {}, "key_order": secret["meta"]["key_order"],
            "budget": secret["meta"]["budget"]}
    for n, b in secret["blocks"].items():
        info["blocks"][n] = {"w_in": b["w_in"], "w_out": b["w_out"],
                             "target": int(b["target"], 16)}
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=40)
    ap.add_argument("--max-fanin", type=int, default=5)
    ap.add_argument("--budget", type=int, default=300)
    ap.add_argument("--start", type=int, default=0)
    args = ap.parse_args()

    worst = 0
    worst_where = None
    totals = []
    fails = 0
    t0 = time.time()
    for seed in range(args.start, args.start + args.seeds):
        gargs = SimpleNamespace(seed=seed, blocks_min=5, blocks_max=8, width=16,
                                max_fanin=args.max_fanin, max_gates=200,
                                budget=args.budget, flag="flag{OK}", verify=False)
        secret, names, key_order, decoy = G.build_circuits(gargs)
        info = info_from_secret(secret)
        oracle = LocalOracle(secret)
        rng = random.Random(1000 + seed)
        try:
            k1, resp, per = solve_part1(oracle, info, rng, verbose=False)
        except Exception as e:
            print("seed %d FAILED: %s" % (seed, e))
            fails += 1
            continue
        expected = C.derive_key(secret, key_order).hex()
        if k1 != expected or resp != "flag{OK}":
            print("seed %d WRONG KEY k1=%s exp=%s resp=%s" % (seed, k1, expected, resp))
            fails += 1
            continue
        mx = max(per.values())
        tot = sum(per.values())
        totals.append((mx, tot))
        if mx > worst:
            worst, worst_where = mx, (seed, per)
    dt = time.time() - t0
    n = len(totals)
    if n:
        maxper = sorted(m for m, _ in totals)
        print("---- calibration ----")
        print("runs OK: %d  fails: %d  (%.1fs)" % (n, fails, dt))
        print("per-block queries: worst=%d  median=%d  p90=%d  (budget=%d)"
              % (worst, maxper[n // 2], maxper[min(n - 1, int(n * 0.9))], args.budget))
        print("worst case: seed=%d  per-block=%s" % worst_where)
        print("headroom at worst: %.0f%% of budget used" % (100.0 * worst / args.budget))
    else:
        print("no successful runs")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
