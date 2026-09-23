"""
circuitlib.py -- combinational boolean-circuit model + evaluator + key
derivation. Shared by generate_circuits.py (build side) and nc_server.py
(service side). The reference solver does NOT import this (it treats the
service as a black box); it only reuses the tiny int<->bytes helpers, which
are also fully specified in circuit.txt / README.txt.

Circuit model
-------------
A "block" is a combinational DAG in SSA form:
  * wires 0 .. w_in-1        = input bits (wire i carries bit i, bit 0 = LSB)
  * gate k (0-indexed)       = wire (w_in + k), computed from lower wires only
  * block["outputs"]         = list of wire ids, output bit k = that wire
Gate ops (all published gate types): AND, OR, XOR (2 inputs), NOT (1 input),
MUX (3 inputs [s,a,b] = a if s==0 else b).

Integer/byte convention (identical everywhere in this challenge):
  * an N-bit value <-> Python int with bit 0 = LSB
  * hex on the wire   = that int, big-endian, ceil(N/8) bytes  (int_to_hex/hex_to_int)
"""
import hashlib

OPS = {"AND": 0, "OR": 1, "XOR": 2, "NOT": 3, "MUX": 4}


def int_to_hex(value, width_bits):
    return value.to_bytes((width_bits + 7) // 8, "big").hex()


def hex_to_int(h):
    return int(h, 16) if h else 0


def make_evaluator(block):
    """Return a fast function ev(x_int) -> y_int for one block."""
    w_in = block["w_in"]
    outs = block["outputs"]
    prog = [(OPS[g["op"]], g["in"]) for g in block["gates"]]

    def ev(x):
        w = [(x >> i) & 1 for i in range(w_in)]
        ap = w.append
        for op, ins in prog:
            if op == 2:      # XOR
                ap(w[ins[0]] ^ w[ins[1]])
            elif op == 0:    # AND
                ap(w[ins[0]] & w[ins[1]])
            elif op == 3:    # NOT
                ap(w[ins[0]] ^ 1)
            elif op == 4:    # MUX(s,a,b) = a if s==0 else b
                ap(w[ins[2]] if w[ins[0]] else w[ins[1]])
            else:            # OR
                ap(w[ins[0]] | w[ins[1]])
        y = 0
        for k, wid in enumerate(outs):
            y |= (w[wid] << k)
        return y

    return ev


def block_input_bytes(x_int, w_in):
    """Canonical byte encoding of one block's input, used for key derivation."""
    return x_int.to_bytes((w_in + 7) // 8, "big")


def derive_key(secret, key_order):
    """
    K1 = SHA256( concat over blocks in key_order of block_input_bytes(correct_input) )[:16]
    `secret` is the parsed circuit_secret.json dict.
    """
    parts = []
    for name in key_order:
        blk = secret["blocks"][name]
        parts.append(block_input_bytes(int(blk["correct_input"], 16), blk["w_in"]))
    return hashlib.sha256(b"".join(parts)).digest()[:16]
