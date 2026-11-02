"""scan_port_sysobj_arity.py [IMAGE_DIR] : sysobj slot calls in the PORT machine code whose stack-arg count differs from what the slot pops.

The render manager object [[0x70039c]+0x9b] ('sysobj') slots pop a fixed number of stack words (0x114: 4, 0x58: 1, 0x4c: 1,
0x88/0x90: 2; see scan_sysobj_pending.py). clang restores a reserved call frame after a callee-pop call with `sub esp, N`, so N/4
is the arg count the port's declaration gave; without that, the pushes since the previous call are counted. A site counts as a
sysobj call when a `+0x9b` load appears in the 12 instructions before it. Prints: port_site exe_fn slot pops port_args folder name.
"""
import bisect, os, re, sys
import capstone
REA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
img_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REA, 'hybrid', 'build')
POPS = {0x114: 4, 0x58: 1, 0x4c: 1, 0x88: 2, 0x90: 2}
data = open(os.path.join(img_dir, 'install', 'ff_ports.bin'), 'rb').read()
rows = []
for l in open(os.path.join(img_dir, 'ff_ports.tsv'), encoding='utf-8'):
    w = l.rstrip('\n').split('\t')
    if w[0].startswith('0x'):
        rows.append((int(w[1], 16), int(w[0], 16), w[2], w[3] if len(w) > 3 else ''))
rows.sort()
starts = [r[0] for r in rows] + [0x31000000 + len(data)]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
call_re = re.compile(r'dword ptr \[(\w+) \+ (0x[0-9a-f]+)\]$')
seen = set()
for k, (entry, exe, folder, name) in enumerate(rows):
    if entry in seen:
        continue
    seen.add(entry)
    end = min(starts[k + 1], entry + 0x4000)
    ins = list(md.disasm(data[entry - 0x31000000:end - 0x31000000], entry))
    for i, x in enumerate(ins):
        if x.mnemonic != 'call':
            continue
        m = call_re.match(x.op_str)
        if not m or int(m.group(2), 16) not in POPS:
            continue
        slot = int(m.group(2), 16)
        back = ins[max(0, i - 12):i]
        if not any('+ 0x9b]' in y.op_str for y in back):
            continue
        nxt = ins[i + 1] if i + 1 < len(ins) else None
        if nxt is not None and nxt.mnemonic == 'sub' and nxt.op_str.startswith('esp, '):
            n = int(nxt.op_str.split(', ')[1], 0) // 4
        else:
            n = 0
            for y in reversed(ins[:i]):
                if y.mnemonic in ('call', 'ret', 'jmp') or y.mnemonic.startswith('j'):
                    break
                if y.mnemonic == 'push':
                    n += 1
        if n != POPS[slot]:
            print('0x%08x\t0x%06x\t0x%x\t%d\t%d\t%s\t%s' % (x.address, exe, slot, POPS[slot], n, folder, name[:60]))
