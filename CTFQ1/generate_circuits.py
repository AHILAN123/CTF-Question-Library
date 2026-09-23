#!/usr/bin/env python3
"""
generate_circuits.py -- build the Part 1 black-box boolean circuits.

Structure (chosen for clean black-box solvability + a well-defined key)
----------------------------------------------------------------------
Each block is a bijection on W bits, built as a set of INDEPENDENT small
"S-boxes" wired through a secret input/output bit permutation:

  * the W input positions are partitioned into groups of 3..5 bits;
  * each group is transformed by a random *reversible* gate network
    (XOR=CNOT, AND+XOR=Toffoli, MUX=Fredkin, NOT), so the group map is a
    bijection on its k bits;
  * each group's k results are scattered to a secret set of k output positions.

Consequences that make the challenge fair and sound:
  * every output bit depends only on its group's <=5 input bits (bounded fan-in);
  * the whole block is a bijection (product of group bijections under wiring),
    so the published TARGET has EXACTLY ONE preimage = "the correct input";
  * a solver can recover it by differential testing (discover the groups) then
    brute-forcing each small group -- exactly the intended method.

A short linear (XOR) pass bookends each group's nonlinear mixing so that every
group input has a strong, detectable influence on the group's outputs (keeps the
differential grouping step reliable within a small query budget).

Because a bijection needs equal in/out width and the spec's ranges (16-32 in,
8-16 out) overlap only at 16, all blocks use width 16. See NOTES.md.

Outputs:
  circuit.txt          PUBLIC interface (widths, TARGETs, KEY order, protocol)
  circuit_secret.json  PRIVATE gate netlists + correct inputs (server/tests only)
"""
import argparse
import json
import os
import random
import sys

import circuitlib as C

PART1_FLAG = "flag{PART1_bl4ckb0x_c1rcu1ts_d1ff3r3nt14l}"


def make_partition(W, lo, hi, rng):
    sizes = []
    remaining = W
    while remaining > 0:
        if remaining <= hi:
            sizes.append(remaining)
            break
        k = rng.randint(lo, hi)
        if remaining - k < lo:            # avoid leaving an un-formable remainder
            k = max(lo, remaining - hi)
        sizes.append(k)
        remaining -= k
    rng.shuffle(sizes)
    assert sum(sizes) == W and all(lo <= s <= hi for s in sizes)
    return sizes


def gen_block(W, rng, hi=5):
    sizes = make_partition(W, 3, hi, rng)
    in_pos = list(range(W)); rng.shuffle(in_pos)
    out_pos = list(range(W)); rng.shuffle(out_pos)
    gates = []
    nextw = [W]

    def emit(op, ins):
        gates.append({"op": op, "in": list(ins)})
        nextw[0] += 1
        return nextw[0] - 1

    outputs = [None] * W
    p = 0
    for k in sizes:
        ig = in_pos[p:p + k]
        og = out_pos[p:p + k]
        p += k
        slot = list(ig)                    # local bit -> current wire id (init: input wires)

        # opening linear pass (strong, detectable influence)
        for i in range(1, k):
            slot[i] = emit("XOR", [slot[i], slot[i - 1]])
        if k >= 2:
            slot[0] = emit("XOR", [slot[0], slot[k - 1]])

        # nonlinear mixing (all of t ^= a&b, t ^= a|b, controlled-swap are
        # reversible when the target slot differs from the source slots)
        for _ in range(rng.randint(2 * k, 4 * k)):
            r = rng.random()
            if k >= 3 and r < 0.35:                     # Toffoli: t ^= a&b
                t, a, b = rng.sample(range(k), 3)
                aw = emit("AND", [slot[a], slot[b]])
                slot[t] = emit("XOR", [slot[t], aw])
            elif k >= 3 and r < 0.55:                   # OR variant: t ^= a|b
                t, a, b = rng.sample(range(k), 3)
                ow = emit("OR", [slot[a], slot[b]])
                slot[t] = emit("XOR", [slot[t], ow])
            elif k >= 3 and r < 0.80:                   # Fredkin: swap x,y if c
                c, x, y = rng.sample(range(k), 3)
                oc, ox, oy = slot[c], slot[x], slot[y]
                slot[x] = emit("MUX", [oc, ox, oy])
                slot[y] = emit("MUX", [oc, oy, ox])
            elif k >= 2 and r < 0.92:                   # CNOT
                t, c = rng.sample(range(k), 2)
                slot[t] = emit("XOR", [slot[t], slot[c]])
            else:                                       # NOT
                i = rng.randrange(k)
                slot[i] = emit("NOT", [slot[i]])

        # closing linear pass (re-expose every input at the outputs)
        for i in range(1, k):
            slot[i] = emit("XOR", [slot[i], slot[i - 1]])
        if k >= 2:
            slot[0] = emit("XOR", [slot[0], slot[k - 1]])

        for qbit in range(k):
            outputs[og[qbit]] = slot[qbit]

    return {"w_in": W, "w_out": W, "gates": gates, "outputs": outputs}


def full_verify(block):
    """Enumerate the whole input space (feasible at W=16): assert bijection and
    that the target's preimage is unique and equals the stored correct input."""
    ev = C.make_evaluator(block)
    W = block["w_in"]
    seen = {}
    x_correct = int(block["correct_input"], 16)
    target = int(block["target"], 16)
    preimages = 0
    for x in range(1 << W):
        y = ev(x)
        if y in seen:
            raise AssertionError("not a bijection: collision %d,%d" % (seen[y], x))
        seen[y] = x
        if y == target:
            preimages += 1
    if preimages != 1 or seen[target] != x_correct:
        raise AssertionError("target preimage not unique/consistent")
    return True


def build_circuits(args):
    rng = random.Random(args.seed)
    n_real = rng.randint(args.blocks_min, args.blocks_max)
    total = n_real + 1
    names = ["b%d" % i for i in range(total)]

    blocks = {}
    for name in names:
        blk = gen_block(args.width, rng, hi=args.max_fanin)
        ev = C.make_evaluator(blk)
        x = rng.getrandbits(args.width)
        blk["correct_input"] = C.int_to_hex(x, args.width)
        blk["target"] = C.int_to_hex(ev(x), args.width)
        blk["is_decoy"] = False
        blocks[name] = blk

    decoy = rng.choice(names)
    blocks[decoy]["is_decoy"] = True
    key_order = [n for n in names if n != decoy]
    rng.shuffle(key_order)

    secret = {
        "meta": {
            "width": args.width,
            "max_fanin": args.max_fanin,
            "budget": args.budget,
            "key_order": key_order,
            "decoy": decoy,
            "part1_flag": args.flag,
            "key_derivation": "K1 = SHA256(concat block_input_bytes(correct_input) for b in key_order)[:16]",
        },
        "blocks": blocks,
    }

    if args.verify:
        for name in names:
            full_verify(blocks[name])
        sys.stderr.write("[generate] full bijection/uniqueness verify OK (%d blocks)\n" % total)

    return secret, names, key_order, decoy


def write_public(path, secret, names):
    m = secret["meta"]
    L = []
    L.append("# CTF Q1 -- Part 1: black-box boolean circuits")
    L.append("#")
    L.append("# Connect to the TCP service (see README.txt) and speak this line protocol:")
    L.append("#   QUERY <block> <hex_input>   -> <hex_output>   (or ERR.. / BUDGET_EXCEEDED)")
    L.append("#   SUBMIT <hex_key>            -> flag{...}      (or FAILED)")
    L.append("#   HELP                        -> short help")
    L.append("#")
    L.append("# Encoding: an N-bit value travels as its integer, big-endian, ceil(N/8)")
    L.append("#           bytes, in hex. Bit 0 is the LSB. Here N=16 -> 2 bytes -> 4 hex.")
    L.append("#")
    L.append("# Per block: find the input X with QUERY(block, X) == TARGET(block). Each")
    L.append("# block is a bijection, so exactly one X exists. Each output bit depends on")
    L.append("# only a few input bits -- differential testing + small brute force works.")
    L.append("#")
    L.append("# Key derivation (do this locally, then SUBMIT the result):")
    L.append("#   For each block in KEY (in order) take its recovered X, encode big-endian")
    L.append("#   as ceil(N/8) bytes, and concatenate. Then:")
    L.append("#       K1 = SHA256(concatenation)[:16]        (first 16 bytes)")
    L.append("#   SUBMIT lower-case hex(K1). Exactly one block is a DECOY: present below")
    L.append("#   but NOT in KEY -- do not include it.")
    L.append("#")
    L.append("BUDGET = %d" % m["budget"])
    for name in names:
        b = secret["blocks"][name]
        L.append("BLOCK %s W_IN=%d W_OUT=%d TARGET=%s"
                 % (name, b["w_in"], b["w_out"], b["target"]))
    L.append("KEY = CONCAT(%s)" % ", ".join(m["key_order"]))
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--blocks-min", type=int, default=5)
    ap.add_argument("--blocks-max", type=int, default=8)
    ap.add_argument("--width", type=int, default=16)
    ap.add_argument("--max-fanin", type=int, default=5)
    ap.add_argument("--budget", type=int, default=300)
    ap.add_argument("--flag", default=PART1_FLAG)
    ap.add_argument("--keyout", default=None)
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()

    secret, names, key_order, decoy = build_circuits(args)
    os.makedirs(args.out_dir, exist_ok=True)
    write_public(os.path.join(args.out_dir, "circuit.txt"), secret, names)
    with open(os.path.join(args.out_dir, "circuit_secret.json"), "w") as f:
        json.dump(secret, f, indent=1)

    k1 = C.derive_key(secret, key_order)
    if args.keyout:
        with open(args.keyout, "w") as f:
            f.write(k1.hex() + "\n")

    ng = {n: len(secret["blocks"][n]["gates"]) for n in names}
    sys.stderr.write("[generate] blocks=%d real=%d decoy=%s gates=%s\n"
                     % (len(names), len(key_order), decoy, ng))
    sys.stderr.write("[generate] key_order=%s  K1=%s\n" % (key_order, k1.hex()))


if __name__ == "__main__":
    main()
