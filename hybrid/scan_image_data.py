"""scan_image_data.py IMAGE_DIR [--out FILE] - ports that touch the image's own writable data.

The ports image has no .data; its writable memory is .bss (build_report.txt: 'bss 0x... - 0x...'). A variable there is private to
the port: nothing else in the exe sees it, and it starts at zero in every run. A port that keeps in such a variable what the
original keeps in an exe global (a condition variable at 0x7257f0, a flag, a counter) diverges from the exe's view of that state.
For every hooked function this lists the .bss addresses its code uses (memory operand or immediate), the symbol they fall in,
and the exe .data globals the original references, so that a port using its own variable where the original uses a global can be
told from a scratch static.

Result on ports_next2 / ports_next3 (11,698 ports): 8 touch .bss (0x46b800 0x4d5880 0x4ecd30 0x5457f0 0x587a30 0x5fc260
0x66ab18 0x66ab68); none replaces an exe global the original uses for the same purpose. The six shadow cases 0x6345bc 0x42abbd
0x42ac56 0x438c10 0x602a60 0x621230 that first looked like 'a variable inside the image instead of the exe global' are not of
this class (0x6345bc passes a stale return address inside the image as the stdcall argument of the decoded pointer: the guard
check thunk 0x634aae takes no stack arguments and the pushed 0x7257f0 belongs to the call through the decoded pointer).

    python -I hybrid/scan_image_data.py hybrid/build/ports_next3 --out hybrid/build/work_v5/image_data.tsv
"""
import argparse
import bisect
import os
import re

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..'))
EXE = os.path.join(REA, 'game', 'Freedom.Exe')
BASE = 0x31000000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image')
    ap.add_argument('--out')
    a = ap.parse_args()
    d = a.image
    rep = open(os.path.join(d, 'build_report.txt'), encoding='utf-8', errors='replace').read()
    m = re.search(r'bss\s+0x([0-9a-f]+) - 0x([0-9a-f]+)', rep)
    blo, bhi = int(m.group(1), 16), int(m.group(2), 16)
    tsv = {}
    for l in open(os.path.join(d, 'ff_ports.tsv'), encoding='utf-8'):
        w = l.rstrip('\n').split('\t')
        if w[0].startswith('0x'):
            tsv[int(w[0], 16)] = (int(w[1], 16), w[2], w[3] if len(w) > 3 else '')
    fn_starts, dsyms = [], []
    for l in open(os.path.join(d, 'ff_ports.syms')):
        p = l.split()
        if len(p) != 3:
            continue
        v = int(p[0], 16)
        if p[1] in ('T', 't') and not p[2].startswith('L'):
            fn_starts.append(v)
        if p[1] in ('B', 'b') or blo <= v < bhi:
            dsyms.append((v, p[2]))
    fn_starts = sorted(set(fn_starts) | {v[0] for v in tsv.values()})
    dsyms.sort()
    dkeys = [x[0] for x in dsyms]
    blob = open(os.path.join(d, 'ff_ports.bin'), 'rb').read()
    pe = pefile.PE(EXE, fast_load=True)
    buf = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    for s in pe.sections:
        raw = s.get_data()
        buf[s.VirtualAddress:s.VirtualAddress + len(raw)] = raw
    data = [(0x400000 + s.VirtualAddress, 0x400000 + s.VirtualAddress + s.Misc_VirtualSize)
            for s in pe.sections if s.Name.startswith(b'.data')]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    def refs(code, addr, lo_hi):
        out = set()
        for i in md.disasm(code, addr):
            for o in i.operands:
                v = None
                if o.type == X86_OP_IMM:
                    v = o.imm & 0xffffffff
                elif o.type == X86_OP_MEM and o.mem.base == 0:
                    v = o.mem.disp & 0xffffffff
                if v is not None and any(lo <= v < hi for lo, hi in lo_hi):
                    out.add(v)
        return sorted(out)

    rows = []
    for a_, (e, folder, name) in sorted(tsv.items()):
        k = bisect.bisect_right(fn_starts, e)
        end = fn_starts[k] if k < len(fn_starts) else e + 0x1000
        mine = refs(blob[e - BASE:end - BASE], e, [(blo, bhi)])
        if not mine:
            continue
        ex = refs(bytes(buf[a_ - 0x400000:a_ - 0x400000 + 0x1000]), a_, data)
        syms = []
        for v in mine[:4]:
            j = bisect.bisect_right(dkeys, v) - 1
            syms.append('%s+%#x' % (dsyms[j][1], v - dsyms[j][0]) if j >= 0 else '?')
        rows.append((a_, folder, name, syms, ex))
    print('%d of %d ports touch the image .bss (%#x-%#x)' % (len(rows), len(tsv), blo, bhi))
    for a_, folder, name, syms, ex in rows:
        print('0x%x %s %s | %s | exe data refs of the original: %s' % (
            a_, folder, name[:30], ' '.join(syms), ' '.join('%#x' % x for x in ex[:6]) or '-'))
    if a.out:
        with open(a.out, 'w', encoding='utf-8', newline='') as fh:
            fh.write('exe_addr\tfolder\tname\timage_symbols\texe_data_refs\n')
            for a_, folder, name, syms, ex in rows:
                fh.write('0x%x\t%s\t%s\t%s\t%s\n' % (a_, folder, name, ' '.join(syms), ' '.join('%#x' % x for x in ex)))


if __name__ == '__main__':
    main()
