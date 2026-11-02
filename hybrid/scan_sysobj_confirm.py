"""scan_sysobj_confirm.py [IMAGE_DIR] [--out FILE] : sysobj slot sites where the port's argument split differs from the original's.

Port side: every call through [reg+SLOT] (0x114 pops 4, 0x58/0x4c pop 1, 0x88/0x90 pop 2) with a `+0x9b` load in the 12 instructions
before it; the port's arg count is the `sub esp, N` clang emits after a callee-pop call, else the pushes plus the [esp+k] stores
(movups/movaps of 16 bytes count 4) since the previous call. Exe side: the same slot calls in the original function; pushes since
the previous call/jump, minus leading pushes of esi/edi/ebx/ebp (register saves), and the next call after the site (it takes the
pending words). A site is listed only when the original has a call to that slot in the function and
  port args > pops and some original site of that slot pushes more than it pops (the port took the pending words), or
  port args < pops and some original site pushes at least `pops` words (the port left out the slot's own argument).
"""
import argparse, bisect, os, re
import capstone, pefile
from capstone.x86 import X86_OP_MEM
REA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
POPS = {0x114: 4, 0x58: 1, 0x4c: 1, 0x88: 2, 0x90: 2}
SAVES = {'esi', 'edi', 'ebx', 'ebp'}


def port_sites(img_dir):
    data = open(os.path.join(img_dir, 'install', 'ff_ports.bin'), 'rb').read()
    rows = sorted((int(w[1], 16), int(w[0], 16), w[2], w[3] if len(w) > 3 else '')
                  for w in (l.rstrip('\n').split('\t') for l in open(os.path.join(img_dir, 'ff_ports.tsv'), encoding='utf-8'))
                  if w[0].startswith('0x'))
    starts = [r[0] for r in rows] + [0x31000000 + len(data)]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rx = re.compile(r'dword ptr \[(\w+) \+ (0x[0-9a-f]+)\]$')
    out, seen = [], set()
    for k, (entry, exe, folder, name) in enumerate(rows):
        if entry in seen:
            continue
        seen.add(entry)
        ins = list(md.disasm(data[entry - 0x31000000:min(starts[k + 1], entry + 0x4000) - 0x31000000], entry))
        for i, x in enumerate(ins):
            m = rx.match(x.op_str) if x.mnemonic == 'call' else None
            if not m or int(m.group(2), 16) not in POPS or not any('+ 0x9b]' in y.op_str for y in ins[max(0, i - 12):i]):
                continue
            slot = int(m.group(2), 16)
            nxt = ins[i + 1] if i + 1 < len(ins) else None
            if nxt is not None and nxt.mnemonic == 'sub' and nxt.op_str.startswith('esp, '):
                n = int(nxt.op_str.split(', ')[1], 0) // 4
            else:
                pushes, top = 0, 0
                for y in reversed(ins[:i]):
                    if y.mnemonic in ('call', 'ret', 'jmp') or y.mnemonic.startswith('j'):
                        break
                    if y.mnemonic == 'push' and y.op_str not in SAVES:   # clang's prologue saves are not arguments
                        pushes += 1
                    mm = re.match(r'(?:x|y)?mmword ptr \[esp(?: \+ (0x[0-9a-f]+|\d+))?\]|dword ptr \[esp(?: \+ (0x[0-9a-f]+|\d+))?\]',
                                  y.op_str.split(', ')[0])
                    if mm and y.mnemonic.startswith('mov'):
                        off = int(mm.group(1) or mm.group(2) or '0', 0)
                        top = max(top, off // 4 + (4 if 'mmword' in y.op_str.split(', ')[0] else 1))
                n = max(pushes, top)
            if n != POPS[slot]:
                out.append((x.address, exe, slot, n, folder, name))
    return out


def exe_sites(fns):
    pe = pefile.PE(os.path.join(REA, 'game', 'Freedom.Exe'), fast_load=True)
    base, img = pe.OPTIONAL_HEADER.ImageBase, pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    res = {}
    for fn in fns:
        ins = list(md.disasm(img[fn - base:fn - base + 0x2000], fn))
        cut = next((j for j, y in enumerate(ins) if y.mnemonic in ('ret', 'int3') and j > 0 and
                    not any(z.mnemonic.startswith('j') and z.operands and z.operands[0].type != X86_OP_MEM and
                            z.operands[0].imm > y.address for z in ins[:j])), len(ins) - 1)
        ins = ins[:cut + 1]
        window = []
        for j, y in enumerate(ins):
            if y.mnemonic == 'call' and y.operands and y.operands[0].type == X86_OP_MEM and y.operands[0].mem.disp in POPS \
                    and any(o.type == X86_OP_MEM and o.mem.disp == 0x9b for w in window for o in w.operands):
                pw = [w for w in window if w.mnemonic == 'push']
                while pw and pw[0].op_str in SAVES:
                    pw = pw[1:]
                nxt = next((z for z in ins[j + 1:] if z.mnemonic == 'call'), None)
                res.setdefault((fn, y.operands[0].mem.disp), []).append(
                    (y.address, len(pw), '%s %s at 0x%x' % (nxt.mnemonic, nxt.op_str, nxt.address) if nxt else '-'))
            if y.mnemonic in ('call', 'ret', 'jmp') or y.mnemonic.startswith('j'):
                window = []
            else:
                window.append(y)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image', nargs='?', default=os.path.join(REA, 'hybrid', 'build'))
    ap.add_argument('--out')
    ap.add_argument('--exclude', default=os.path.join(REA, 'game', 'exclude_map.txt'))
    a = ap.parse_args()
    ps = port_sites(a.image)
    ex = exe_sites({p[1] for p in ps})
    exc = set()
    for l in open(a.exclude, encoding='utf-8'):
        l = l.split('#')[0].strip()
        if l.startswith('0x'):
            exc.add(int(l, 16))
    lines = []
    for site, fn, slot, n, folder, name in ps:
        orig = ex.get((fn, slot), [])
        k = POPS[slot]
        if not orig or not ((n > k and any(p > k for _, p, _ in orig)) or (n < k and any(p >= k for _, p, _ in orig))):
            continue
        o = '; '.join('0x%x pushes %d, pops %d, then %s' % (s, p, k, nc) for s, p, nc in orig)
        lines.append('0x%06x\t0x%08x\tslot 0x%x\t%s\tport passes %d\t%s\t%s\t%s' % (
            fn, site, slot, o, n, 'excluded' if fn in exc else 'enabled', folder, name[:50]))
    hdr = '# function\tport_site\tslot\toriginal (site, pushes, pops, next call)\tport\tstate\tfolder\tname'
    text = hdr + '\n' + '\n'.join(lines) + '\n'
    if a.out:
        open(a.out, 'w', encoding='utf-8', newline='').write(text)
    fns = {l.split('\t')[0] for l in lines}
    en = {l.split('\t')[0] for l in lines if '\tenabled\t' in l}
    print('%d port sites flagged; %d confirmed sites in %d functions (%d enabled)' % (len(ps), len(lines), len(fns), len(en)))


if __name__ == '__main__':
    main()
