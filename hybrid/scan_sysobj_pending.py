"""scan_sysobj_pending.py [IMAGE_DIR] [--out FILE] [--slots 0x4c,0x58,0x88,0x90]

Finds the places in the original exe where a call through the render manager object ([[0x70039c]+0x9b], called 'sysobj') is
made with MORE pushes than the slot pops. The slots pop a fixed number of stack words (0x58: 1, 0x4c: 1, 0x88/0x90: 2,
0x114: 4, measured with a call tracer on real samples); the other pushes made right before the call are the trailing args of
the NEXT call (MSVC defers the cleanup, LTCG shares one push sequence). A port that gives such a slot all the pushes as its own
arguments gets the stack and the next call's arguments wrong (the C compiler thinks the callee pops them all).

For every `call dword ptr [reg+SLOT]` whose block (back to the previous call, jump, label or return) loads a `+0x9b` field, the
script counts the push instructions in that block. pushes > pops means pending words. Each site is attributed to the
enclosing hooked function of IMAGE_DIR/ff_ports.tsv (default hybrid/build/ports_next3), and printed as
    site  slot  pops  pushes  function  folder  name

    python -I hybrid/scan_sysobj_pending.py hybrid/build/ports_next3 --out hybrid/build/work_v6/sysobj_pending.tsv
"""
import argparse
import bisect
import os

import capstone
import pefile
from capstone.x86 import X86_OP_MEM

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..'))
EXE = os.path.join(REA, 'game', 'Freedom.Exe')
POPS = {0x4c: 1, 0x58: 1, 0x88: 2, 0x90: 2, 0x114: 4}
BARRIER = {'call', 'jmp', 'ret', 'retn', 'je', 'jne', 'jb', 'jbe', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge', 'js', 'jns', 'jp',
           'jnp', 'jo', 'jno', 'jecxz', 'loop', 'int3'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image', nargs='?', default=os.path.join(REA, 'hybrid', 'build'))
    ap.add_argument('--out')
    ap.add_argument('--slots', default='0x4c,0x58,0x88,0x90,0x114')
    a = ap.parse_args()
    slots = {int(x, 16) for x in a.slots.split(',')}
    hooked = {}
    for l in open(os.path.join(a.image, 'ff_ports.tsv'), encoding='utf-8'):
        w = l.rstrip('\n').split('\t')
        if w[0].startswith('0x'):
            hooked[int(w[0], 16)] = (w[2], w[3] if len(w) > 3 else '')
    starts = sorted(hooked)
    pe = pefile.PE(EXE, fast_load=True)
    text = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
    base = 0x400000 + text.VirtualAddress
    code = text.get_data()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    rows = []
    window = []     # instructions since the last barrier
    for ins in md.disasm(code, base):
        if ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == X86_OP_MEM and ins.operands[0].mem.disp in slots \
                and ins.operands[0].mem.base != 0 and ins.operands[0].mem.index == 0:
            slot = ins.operands[0].mem.disp
            has9b = False
            for w in window:
                for o in w.operands:
                    if o.type == X86_OP_MEM and o.mem.disp == 0x9b:
                        has9b = True
            if has9b:
                pushes = sum(1 for w in window if w.mnemonic == 'push')
                if pushes > POPS[slot]:
                    k = bisect.bisect_right(starts, ins.address) - 1
                    fn = starts[k] if k >= 0 and ins.address - starts[k] < 0x3000 else 0
                    rows.append((ins.address, slot, POPS[slot], pushes, fn))
        if ins.mnemonic in BARRIER:
            window = []
        else:
            window.append(ins)
    print('%d sites with pending pushes' % len(rows))
    lines = []
    for site, slot, pops, pushes, fn in rows:
        f, n = hooked.get(fn, ('', ''))
        lines.append('0x%x\t0x%x\t%d\t%d\t0x%x\t%s\t%s' % (site, slot, pops, pushes, fn, f, n))
    for l in lines:
        print(l)
    if a.out:
        with open(a.out, 'w', encoding='utf-8', newline='') as fh:
            fh.write('site\tslot\tpops\tpushes\tfunction\tfolder\tname\n' + '\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
