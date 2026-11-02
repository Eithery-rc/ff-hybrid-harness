#!/usr/bin/env python3
"""scan_fs0.py - every port that touches the SEH chain head (fs:[0]) and the ways it can leave a wrong value there.

Run:  python -I hybrid/scan_fs0.py [IMAGE_DIR] [--out FILE]
      IMAGE_DIR defaults to hybrid/build (ff_ports.bin + ff_ports.tsv + ff_ports.syms)

A port that builds an SEH frame does `mov eax, fs:[0]; mov [slot], eax` (the previous head, first dword of the record),
`lea eax, [record]; mov fs:[0], eax` (install) and, at every exit, `mov eax, [slot]; mov fs:[0], eax` (restore). The shadow
differential tester found ports that restore 0 / 1: the record (or the saved head) was overwritten, in both cases by a local
too small for the 12-byte iterator state that the vtable slots 0x4c / 0x5c write through its address.

Classes (one line per port and class, tsv: exe_addr, folder, name, class, evidence):
  restore-slot-mismatch  the value written to fs:[0] at an exit is loaded from a different stack slot than the one that holds
                         the head read at entry
  restore-not-from-slot  fs:[0] is written from something that is not a load of the saved slot (immediate, xor, a register
                         computed by other means) and it is not the install (lea of the record)
  no-restore             the port installs a record but never writes fs:[0] again
  no-install             fs:[0] is read but never written (harmless), or restored without an install (wrong)
  record-overlap         an address-taken stack local starts less than 12 bytes below the saved head (or inside the record) and its
                         address is passed to an iterator slot (0x4c 0x5c 0x64 0xc): the callee fills 12 bytes and overwrites the record
  record-near            the same, but the address goes to another call (a one-dword out parameter is fine; info, no verdict)
  odd-record             the record is not 12 bytes of its own (install lea target differs from the saved-head slot)

Nothing here runs the game; the exe is not needed.
"""
import bisect
import collections
import os
import re
import sys

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 0x31000000
ITER_SLOTS = {0x4c, 0x5c, 0x64, 0xc}   # vtable slots that fill a 12-byte iterator state through the address they are given


def load(d):
    tsv = {}
    for l in open(os.path.join(d, 'ff_ports.tsv'), encoding='utf-8'):
        w = l.rstrip('\n').split('\t')
        if w[0].startswith('0x'):
            tsv[int(w[0], 16)] = (int(w[1], 16), w[2], w[3] if len(w) > 3 else '')
    syms = set(v[0] for v in tsv.values())
    for l in open(os.path.join(d, 'ff_ports.syms')):
        p = l.split()
        if len(p) == 3 and p[1] in ('T', 't') and not p[2].startswith('L'):
            syms.add(int(p[0], 16))
    blob = open(os.path.join(d, 'ff_ports.bin'), 'rb').read()
    rep = open(os.path.join(d, 'build_report.txt'), encoding='utf-8', errors='replace').read()
    m = re.search(r'text\s+0x([0-9a-f]+) - 0x([0-9a-f]+)', rep)
    text_end = int(m.group(2), 16) if m else BASE + len(blob)
    return tsv, sorted(syms), blob, text_end


def is_fs0(o):
    return o.type == X86_OP_MEM and o.mem.segment != 0 and o.mem.base == 0 and o.mem.index == 0 and o.mem.disp == 0


def slot(o, md_i, alias=None):
    """('esp'|'ebp', disp) of a plain stack memory operand (also through a register that holds a copy of esp), else None."""
    if o.type != X86_OP_MEM or o.mem.index != 0 or o.mem.segment != 0:
        return None
    b = md_i.reg_name(o.mem.base) if o.mem.base else ''
    if b in ('esp', 'ebp'):
        return (b, o.mem.disp)
    if alias and b in alias:
        return ('esp', alias[b] + o.mem.disp)
    return None


def scan_function(md, blob, entry, end):
    insns = list(md.disasm(blob[entry - BASE:end - BASE], entry))
    # register aliases of esp (mov esi, esp / lea esi, [esp+d]) at every instruction, valid until the register is rewritten
    al_at, alias = [], {}
    for i in insns:
        al_at.append(dict(alias))
        o = i.operands
        if o and o[0].type == X86_OP_REG:
            d = i.reg_name(o[0].reg)
            if i.mnemonic == 'mov' and len(o) == 2 and o[1].type == X86_OP_REG and i.reg_name(o[1].reg) == 'esp' and d not in ('esp', 'ebp'):
                alias[d] = 0
            elif i.mnemonic == 'lea' and len(o) == 2 and o[1].type == X86_OP_MEM and o[1].mem.index == 0 and o[1].mem.base                     and i.reg_name(o[1].mem.base) == 'esp' and d not in ('esp', 'ebp'):
                alias[d] = o[1].mem.disp
            elif d in alias and i.mnemonic not in ('cmp', 'test', 'push'):
                del alias[d]
    reads, writes, rets = [], [], 0
    leas = []                       # (index, reg, ('esp', disp))
    for n, i in enumerate(insns):
        ops = i.operands
        if i.mnemonic == 'ret':
            rets += 1
        if i.mnemonic == 'mov' and len(ops) == 2:
            if is_fs0(ops[1]) and ops[0].type == X86_OP_REG:
                reads.append(n)
            elif is_fs0(ops[0]):
                writes.append(n)
        if i.mnemonic == 'lea' and len(ops) == 2 and ops[0].type == X86_OP_REG:
            s = slot(ops[1], i, al_at[n])
            if s:
                leas.append((n, i.reg_name(ops[0].reg), s))
    res = []
    if not reads and not writes:
        return res, False
    # the saved head: the first store of the register that read fs:[0]
    saved = None
    for n in reads:
        reg = insns[n].operands[0].reg
        for j in range(n + 1, min(n + 6, len(insns))):
            q = insns[j]
            if q.mnemonic == 'mov' and len(q.operands) == 2 and q.operands[1].type == X86_OP_REG and q.operands[1].reg == reg:
                s = slot(q.operands[0], q, al_at[j])
                if s:
                    saved = s
                    break
        if saved:
            break
    installs, restores, others = [], [], []
    for n in writes:
        i = insns[n]
        src = i.operands[1]
        kind, info = 'other', None
        if src.type == X86_OP_REG and i.reg_name(src.reg) in al_at[n]:
            kind, info = 'install', ('esp', al_at[n][i.reg_name(src.reg)])
        elif src.type == X86_OP_REG:
            for j in range(n - 1, max(n - 8, -1), -1):
                q = insns[j]
                if q.operands and q.operands[0].type == X86_OP_REG and q.operands[0].reg == src.reg and q.mnemonic in ('mov', 'lea', 'xor', 'sub', 'add', 'pop'):
                    if q.mnemonic == 'lea':
                        s = slot(q.operands[1], q, al_at[j])
                        kind, info = ('install', s) if s else ('other', 'lea')
                    elif q.mnemonic == 'mov' and len(q.operands) == 2 and q.operands[1].type == X86_OP_REG and q.reg_name(q.operands[1].reg) == 'esp':
                        kind, info = 'install', ('esp', 0)         # mov reg, esp: the record sits at the frame bottom
                    elif q.mnemonic == 'mov' and len(q.operands) == 2:
                        s = slot(q.operands[1], q, al_at[j])
                        if s:
                            kind, info = 'restore', s
                        elif q.operands[1].type == X86_OP_IMM:
                            kind, info = 'other', 'imm %#x' % (q.operands[1].imm & 0xffffffff)
                        else:
                            kind, info = 'other', 'mov'
                    else:
                        kind, info = 'other', q.mnemonic
                    break
        elif src.type == X86_OP_IMM:
            kind, info = 'other', 'imm %#x' % (src.imm & 0xffffffff)
        {'install': installs, 'restore': restores, 'other': others}[kind].append((n, info))
    if reads and not saved:
        saved = None
    if installs and not restores and not others:
        res.append(('no-restore', 'fs:[0] installed at +%#x, never written again' % (insns[installs[0][0]].address - entry)))
    if (restores or others) and not installs:
        res.append(('no-install', 'fs:[0] written %d time(s) with no install in the function' % (len(restores) + len(others))))
    for n, info in others:
        res.append(('restore-not-from-slot', 'fs:[0] written at +%#x from %s' % (insns[n].address - entry, info)))
    if saved:
        for n, info in restores:
            if info != saved:
                res.append(('restore-slot-mismatch', 'restore at +%#x loads [%s%+#x], the head was saved to [%s%+#x]' % (
                    insns[n].address - entry, info[0], info[1], saved[0], saved[1])))
        for n, info in installs:
            if info and info[0] == saved[0] and info[1] != saved[1]:
                res.append(('odd-record', 'install at +%#x points at [%s%+#x], the head was saved to [%s%+#x]' % (
                    insns[n].address - entry, info[0], info[1], saved[0], saved[1])))
        # address-taken locals just below the record: a 12-byte fill through them reaches the saved head
        rec = saved[1]
        for n, reg, s in leas:
            if s[0] != saved[0] or s == saved:
                continue
            if any(inst[1] == s for inst in installs):
                continue
            d = s[1]
            if rec - 12 < d < rec + 12 and d != rec:
                # does the register reach a call within 10 instructions?
                reach, callee = False, None
                for j in range(n + 1, min(n + 12, len(insns))):
                    q = insns[j]
                    if q.mnemonic == 'call':
                        reach = True
                        o0 = q.operands[0] if q.operands else None
                        if o0 is not None and o0.type == X86_OP_MEM and o0.mem.base:
                            callee = o0.mem.disp
                        break
                    if q.operands and q.operands[0].type == X86_OP_REG and q.operands[0].reg == insns[n].operands[0].reg and q.mnemonic in ('mov', 'lea', 'xor', 'pop'):
                        break
                if reach:
                    cls = 'record-overlap' if callee in ITER_SLOTS else 'record-near'
                    res.append((cls, 'local at [%s%+#x] has its address passed to %s, the saved head is at [%s%+#x] (%d bytes above it)' % (
                        s[0], d, ('vslot %#x' % callee) if callee is not None else 'a call', saved[0], rec, rec - d)))
                    if cls == 'record-overlap':
                        break
    return res, True


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    d = args[0] if args else os.path.join(HERE, 'build')
    out = None
    if '--out' in sys.argv:
        out = sys.argv[sys.argv.index('--out') + 1]
        if out in args:
            args.remove(out)
            d = args[0] if args else d
    tsv, syms, blob, text_end = load(d)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rows = []
    touching = 0
    for a, (e, folder, name) in sorted(tsv.items()):
        k = bisect.bisect_right(syms, e)
        end = syms[k] if k < len(syms) else text_end
        end = min(end, text_end, e + 0x20000)
        res, touches = scan_function(md, blob, e, end)
        touching += touches
        seen = set()
        for cls, ev in res:
            if cls in seen:
                continue
            seen.add(cls)
            rows.append((a, folder, name, cls, ev))
    cnt = collections.Counter(r[3] for r in rows)
    print('%d ports of %d touch fs:[0]; %d findings in %d ports' % (touching, len(tsv), len(rows), len({r[0] for r in rows})))
    for c, n in sorted(cnt.items()):
        print('  %-24s %d' % (c, n))
    for r in rows:
        print('0x%x\t%s\t%s\t%s\t%s' % (r[0], r[1], r[2][:40], r[3], r[4]))
    if out:
        with open(out, 'w', encoding='utf-8', newline='') as fh:
            fh.write('exe_addr\tfolder\tname\tclass\tevidence\n')
            for r in rows:
                fh.write('0x%x\t%s\t%s\t%s\t%s\n' % (r[0], r[1], r[2], r[3], r[4]))


if __name__ == '__main__':
    main()
