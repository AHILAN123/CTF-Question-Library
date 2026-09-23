"""
re_utils.py -- small static-RE helpers used by the reference solver (and the
build self-tests). Reads named symbols out of an unstripped ELF via pyelftools,
inverts Part 3's checksum, and de-obfuscates Part 2's embedded key.

A human would recover the same facts from a disassembler (objdump/Ghidra/IDA);
we use the symbol table purely for a reproducible, scriptable reference solve.
"""
import io

from elftools.elf.elffile import ELFFile

SHF_ALLOC = 0x2


def _load(path):
    data = open(path, "rb").read()
    return data, ELFFile(io.BytesIO(data))


def _sym(elf, name):
    st = elf.get_section_by_name(".symtab")
    if st is None:
        raise RuntimeError("no .symtab (binary stripped?)")
    for s in st.iter_symbols():
        if s.name == name:
            return s
    raise KeyError("symbol %r not found" % name)


def _vaddr_off(elf, v):
    for sec in elf.iter_sections():
        a = sec["sh_addr"]
        sz = sec["sh_size"]
        if sec["sh_type"] != "SHT_NOBITS" and (sec["sh_flags"] & SHF_ALLOC) and a <= v < a + sz:
            return sec["sh_offset"] + (v - a)
    raise RuntimeError("vaddr 0x%x not in any loadable section" % v)


def sym_bytes(path, name):
    data, elf = _load(path)
    s = _sym(elf, name)
    off = _vaddr_off(elf, s["st_value"])
    n = s["st_size"]
    return data[off:off + n]


def extract_k2(part2_path):
    """K2 = k2_obf XOR k2_mask (a simple embedded-key obfuscation)."""
    obf = sym_bytes(part2_path, "k2_obf")
    mask = sym_bytes(part2_path, "k2_mask")
    return bytes(a ^ b for a, b in zip(obf, mask))


def _rotr8(b, r):
    r &= 7
    return ((b >> r) | (b << (8 - r))) & 0xFF if r else b & 0xFF


def invert_part3(part3_path):
    """Recover the password by inverting the checksum, reading its constants
    (p3_params = [SEED,ROT,R0,NK], p3_K, p3_target) from the binary."""
    params = sym_bytes(part3_path, "p3_params")
    K = sym_bytes(part3_path, "p3_K")
    target = sym_bytes(part3_path, "p3_target")
    SEED, ROT, R0, NK = params[0], params[1], params[2], params[3]
    acc = SEED
    out = bytearray()
    for i, o in enumerate(target):
        x = (o - K[i % NK]) & 0xFF
        x ^= acc
        b = _rotr8(x, (i * ROT + R0) & 7)
        out.append(b)
        acc = (acc + b) & 0xFF
    return bytes(out).decode("latin-1")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "invert":
        print(invert_part3(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "k2":
        print(extract_k2(sys.argv[2]).hex())
    else:
        print("usage: re_utils.py invert <part3> | k2 <part2>")
