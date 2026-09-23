#!/usr/bin/env python3
"""Second build pass: compute the FNV-1a checksum and 0xCC count over
guarded_func()'s compiled bytes and patch g_guard_len / g_guard_ck / g_guard_cc
(which live in .data, so patching them does not change .text)."""
import io
import struct
import sys

from elftools.elf.elffile import ELFFile

FNV_OFF = 1469598103934665603
FNV_P = 1099511628211
MASK64 = (1 << 64) - 1
SHF_ALLOC = 0x2


def fnv1a(b):
    h = FNV_OFF
    for x in b:
        h = ((h ^ x) * FNV_P) & MASK64
    return h


def main():
    path = sys.argv[1]
    raw = bytearray(open(path, "rb").read())
    elf = ELFFile(io.BytesIO(bytes(raw)))
    st = elf.get_section_by_name(".symtab")
    syms = {s.name: s for s in st.iter_symbols() if s.name}

    def off(v):
        for sec in elf.iter_sections():
            a, sz = sec["sh_addr"], sec["sh_size"]
            if sec["sh_type"] != "SHT_NOBITS" and (sec["sh_flags"] & SHF_ALLOC) and a <= v < a + sz:
                return sec["sh_offset"] + (v - a)
        raise RuntimeError("vaddr 0x%x not mapped" % v)

    gf = syms["guarded_func"]
    vaddr, size = gf["st_value"], gf["st_size"]
    assert size > 0, "guarded_func has zero size"
    foff = off(vaddr)
    region = bytes(raw[foff:foff + size])
    ck = fnv1a(region)
    cc = region.count(0xCC)

    def patch(name, fmt, val):
        o = off(syms[name]["st_value"])
        b = struct.pack(fmt, val)
        raw[o:o + len(b)] = b

    patch("g_guard_len", "<I", size)
    patch("g_guard_ck", "<Q", ck)
    patch("g_guard_cc", "<I", cc)
    open(path, "wb").write(raw)
    print("[patch_guard] guarded_func @0x%x len=%d ck=0x%016x cc=%d" % (vaddr, size, ck, cc))


if __name__ == "__main__":
    main()
