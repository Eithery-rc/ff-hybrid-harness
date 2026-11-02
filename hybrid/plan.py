"""plan.py - hook plan for the hybrid loader (stage 1).

Reads a ports image (flat, mapped at 0x31000000) and decides, for every exe function it replaces, whether a
5-byte JMP rel32 at the function start is safe. Writes ff_hooks.bin (read by dinput8.dll) and a human TSV report.

Image sources (--build DIR), first match wins:
  ff_ports.bin + ff_ports.tsv   unified build manifest: exe_addr, port_entry_addr, folder, name (hex addresses)
  ff_ports.bin + ff_ports.syms  pc_<hex> data symbols, each holding the port entry
  pilot.bin + pilot.syms        a single-folder build from tooling/build.sh (same pc_<hex> convention)

Function starts used for the size check (a patch is safe when the next known start is >= 5 bytes away):
  RESULTS.tsv addresses, every ext_<hex> the ports call, direct call targets from a linear sweep of .text,
  and .text pointers found through .reloc entries in .rdata/.data (vtables, callback tables).
A patch is also refused when any branch target, ext_ target or relocated .text pointer lands inside its 5 bytes.

Usage: python -I plan.py --build DIR [--dry-run] [--out GAME_DIR]
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

import capstone
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..'))
BASE = 0x31000000
MAGIC = 0x4b484646            # 'FFHK'
VERSION = 1
OK, SHORT, INTERIOR, RANGE, BADENTRY, DUP = range(6)
STATUS = ['ok', 'short', 'interior', 'range', 'badentry', 'dup']


def fnv1a_fast(data):
    """FNV-1a over little-endian dwords, then the tail bytes (dinput8.c computes the same)."""
    h = 0x811c9dc5
    n = len(data) // 4
    for (w,) in struct.iter_unpack('<I', data[:n * 4]):
        h = ((h ^ w) * 0x01000193) & 0xffffffff
    for b in data[n * 4:]:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


# ---------------------------------------------------------------- inputs
def load_entries(build):
    """[(exe_addr, port_entry, name)] and the image bytes."""
    for binname, side in (('ff_ports.bin', 'ff_ports.tsv'), ('ff_ports.bin', 'ff_ports.syms'),
                          ('pilot.bin', 'pilot.syms')):
        b, s = os.path.join(build, binname), os.path.join(build, side)
        if os.path.exists(b) and os.path.exists(s):
            img = open(b, 'rb').read()
            if side.endswith('.tsv'):
                out = []
                for line in open(s, encoding='utf-8', errors='replace'):
                    p = re.split(r'[\t,]', line.rstrip('\n'))
                    try:
                        out.append((int(p[0], 16), int(p[1], 16), p[3] if len(p) > 3 else ''))
                    except (ValueError, IndexError):
                        continue    # header or junk
                return out, img, b
            out = []
            for line in open(s):
                p = line.split()
                if len(p) == 3 and p[2].startswith('pc_'):
                    v = int(p[0], 16)
                    entry = struct.unpack_from('<I', img, v - BASE)[0]
                    out.append((int(p[2][3:], 16), entry, ''))
            return out, img, b
    raise SystemExit('no ports image in %s' % build)


def results_starts(path):
    starts, names = set(), {}
    for line in open(path, encoding='utf-8', errors='replace'):
        p = line.rstrip('\n').split('\t')
        if p and p[0].startswith('0x'):
            a = int(p[0], 16)
            starts.add(a)
            names[a] = p[1] if len(p) > 1 else ''
    return starts, names


def ext_targets(ports, cache):
    files = []
    for root, _, fs in os.walk(ports):
        files += [os.path.join(root, f) for f in fs if f.endswith(('.cpp', '.h'))]
    key = '%d:%d' % (len(files), sum(os.path.getsize(f) for f in files))
    cf = os.path.join(cache, 'ext_targets.json')
    if os.path.exists(cf):
        c = json.load(open(cf))
        if c.get('key') == key:
            return set(c['targets'])
    rx = re.compile(rb'\bext_([0-9a-f]{6,8})\b')
    t = set()
    for f in files:
        t.update(int(m, 16) for m in rx.findall(open(f, 'rb').read()))
    json.dump({'key': key, 'targets': sorted(t)}, open(cf, 'w'))
    return t


def text_sweep(pe, text, cache, sha):
    """Linear sweep of .text: (call targets, all direct branch targets)."""
    cf = os.path.join(cache, 'text_sweep_%s.json' % sha[:16])
    if os.path.exists(cf):
        c = json.load(open(cf))
        return set(c['calls']), set(c['branches'])
    base = pe.OPTIONAL_HEADER.ImageBase
    va, data = base + text.VirtualAddress, text.get_data()[:text.Misc_VirtualSize]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    calls, branches = set(), set()
    lo, hi = va, va + len(data)
    for addr, size, mn, op in md.disasm_lite(data, va):
        if mn == 'call' or mn == 'jmp' or (mn.startswith('j') and size in (2, 6)):
            if op.startswith('0x'):
                try:
                    t = int(op, 16)
                except ValueError:
                    continue
                if lo <= t < hi:
                    branches.add(t)
                    if mn == 'call':
                        calls.add(t)
    json.dump({'calls': sorted(calls), 'branches': sorted(branches)}, open(cf, 'w'))
    return calls, branches


def reloc_pointers(pe, text):
    """.text addresses stored in relocated dwords: (from .rdata/.data, from .text itself)."""
    base = pe.OPTIONAL_HEADER.ImageBase
    tlo, thi = base + text.VirtualAddress, base + text.VirtualAddress + text.Misc_VirtualSize
    from_data, from_text = set(), set()
    if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        return from_data, from_text
    for blk in pe.DIRECTORY_ENTRY_BASERELOC:
        for e in blk.entries:
            if e.type != 3:      # IMAGE_REL_BASED_HIGHLOW
                continue
            v = pe.get_dword_at_rva(e.rva)
            if v is None or not tlo <= v < thi:
                continue
            (from_text if tlo <= base + e.rva < thi else from_data).add(v)
    return from_data, from_text


# ---------------------------------------------------------------- stack alignment hazards in the ports image
SSE_UNALIGNED_OK = {'movups', 'movupd', 'movdqu', 'movss', 'movsd', 'movlps', 'movhps', 'movlpd', 'movhpd',
                    'movq', 'movd', 'lddqu'}


def align_hazards(img, code_end, fn_starts):
    """Functions with legacy SSE ops that need 16-byte alignment on an esp/ebp operand and no `and esp, -16`
    realignment. The ports are built for i686-linux (16-byte stack at calls); the game only guarantees 4, so
    these can fault in the real process. Returns ({mnemonic: count}, [(fn_addr, n_hits)])."""
    import bisect
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    fs = sorted(fn_starts) or [BASE]
    hits, per_fn, realigned = {}, {}, set()
    for addr, size, mn, op in md.disasm_lite(img[:code_end - BASE], BASE):
        f = fs[max(bisect.bisect_right(fs, addr) - 1, 0)]
        if mn == 'and' and op.startswith('esp, 0xfffffff'):
            realigned.add(f)
            continue
        if 'xmm' not in op or '[' not in op or not ('esp' in op or 'ebp' in op):
            continue
        if mn.startswith('v') or mn in SSE_UNALIGNED_OK:
            continue
        packed = mn in ('movaps', 'movapd', 'movdqa', 'movntps', 'movntpd', 'movntdq') or \
            mn.endswith(('ps', 'pd')) or (mn.startswith('p') and not mn.startswith(('pextr', 'pinsr')))
        if packed and not mn.endswith(('ss', 'sd')):
            hits[mn] = hits.get(mn, 0) + 1
            per_fn[f] = per_fn.get(f, 0) + 1
    return hits, sorted((f, n) for f, n in per_fn.items() if f not in realigned)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', required=True, help='folder with ff_ports.bin(+tsv/syms) or pilot.bin+pilot.syms')
    ap.add_argument('--exe', default=os.path.join(REA, 'game', 'Freedom.Exe'))
    ap.add_argument('--results', default=os.path.join(REA, 'ReFreedomFighters', 'RESULTS.tsv'))
    ap.add_argument('--ports', default=os.path.join(REA, 'ReFreedomFighters', 'ports'))
    ap.add_argument('--out', default=os.path.join(REA, 'game'), help='game folder: ff_ports.bin and ff_hooks.bin go here')
    ap.add_argument('--report', default=os.path.join(HERE, 'build', 'hooks_plan.tsv'))
    ap.add_argument('--dry-run', action='store_true', help='print the counts, write nothing')
    a = ap.parse_args()
    cache = os.path.join(HERE, 'cache')
    os.makedirs(cache, exist_ok=True)

    entries, img, imgpath = load_entries(a.build)
    exe_bytes = open(a.exe, 'rb').read()
    sha = hashlib.sha256(exe_bytes).hexdigest()
    pe = pefile.PE(data=exe_bytes)
    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x40:
        print('warning: %s still has DYNAMIC_BASE set; run patch_exe.py on the work copy' % a.exe)
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    ibase = pe.OPTIONAL_HEADER.ImageBase
    tlo, thi = ibase + text.VirtualAddress, ibase + text.VirtualAddress + text.Misc_VirtualSize
    text_data = text.get_data()[:text.Misc_VirtualSize]

    res, names = results_starts(a.results)
    ext = ext_targets(a.ports, cache)
    calls, branches = text_sweep(pe, text, cache, sha)
    rdata_ptrs, text_ptrs = reloc_pointers(pe, text)
    starts = {x for x in res | ext | calls | rdata_ptrs if tlo <= x < thi}
    starts.add(ibase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    inner = branches | ext | text_ptrs | starts
    sorted_starts = sorted(starts)

    import bisect
    plan, seen = [], set()
    counts = [0] * len(STATUS)
    for addr, entry, nm in sorted(entries):
        gap = None
        if addr in seen:
            st = DUP
        elif not (BASE <= entry < BASE + len(img)):
            st = BADENTRY
        elif not (tlo <= addr and addr + 5 <= thi):
            st = RANGE
        else:
            k = bisect.bisect_right(sorted_starts, addr)
            nxt = sorted_starts[k] if k < len(sorted_starts) else thi
            gap = nxt - addr
            if gap < 5:
                st = SHORT
            elif any(t in inner for t in range(addr + 1, addr + 5)):
                st = INTERIOR
            else:
                st = OK
        seen.add(addr)
        counts[st] += 1
        plan.append((addr, entry, st, gap, nm or names.get(addr, '')))

    syms = os.path.join(os.path.dirname(imgpath), os.path.basename(imgpath).replace('.bin', '.syms'))
    code_end, fn_starts = BASE + len(img), {e for _, e, _ in entries if BASE <= e < BASE + len(img)}
    if os.path.exists(syms):
        rows = [l.split() for l in open(syms)]
        pcs = [int(r[0], 16) for r in rows if len(r) == 3 and r[2].startswith('pc_')]
        if pcs:
            code_end = min(pcs)          # pc_ pointers are .rodata, laid out after all code
        fn_starts |= {int(r[0], 16) for r in rows if len(r) == 3 and int(r[0], 16) < code_end}
    hz, hz_fns = align_hazards(img, code_end, fn_starts)

    print('image   %s  %d bytes at %#x, %d port entries' % (imgpath, len(img), BASE, len(entries)))
    print('exe     %s  sha256 %s..  .text %#x-%#x' % (a.exe, sha[:16], tlo, thi))
    print('starts  %d known (RESULTS %d, ext_ %d, call targets %d, reloc ptrs %d), %d inner targets'
          % (len(starts), len(res), len(ext), len(calls), len(rdata_ptrs), len(inner)))
    print('plan    ' + ', '.join('%s %d' % (STATUS[i], counts[i]) for i in range(len(STATUS))))
    print('align   %d aligned-SSE stack ops %s; %d functions use them without realigning the stack'
          % (sum(hz.values()), dict(sorted(hz.items(), key=lambda kv: -kv[1])[:6]), len(hz_fns)))
    if a.dry_run:
        return
    os.makedirs(os.path.dirname(a.report), exist_ok=True)
    with open(os.path.join(os.path.dirname(a.report), 'align_hazards.tsv'), 'w') as f:
        f.write('port_fn\thits\n')
        for fa, n in hz_fns:
            f.write('%#x\t%d\n' % (fa, n))

    os.makedirs(os.path.dirname(a.report), exist_ok=True)
    with open(a.report, 'w', encoding='utf-8') as f:
        f.write('exe_addr\tport_entry\tstatus\tgap\tname\n')
        for addr, entry, st, gap, nm in plan:
            f.write('%#x\t%#x\t%s\t%s\t%s\n' % (addr, entry, STATUS[st], '' if gap is None else gap, nm))
    hdr = struct.pack('<10I', MAGIC, VERSION, BASE, len(img), fnv1a_fast(img),
                      text.VirtualAddress, len(text_data), fnv1a_fast(text_data), len(plan), 0)
    body = b''.join(struct.pack('<III', addr, entry, st) for addr, entry, st, _, _ in plan)
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'ff_hooks.bin'), 'wb').write(hdr + body)
    open(os.path.join(a.out, 'ff_ports.bin'), 'wb').write(img)
    print('wrote   %s, %s, report %s' % (os.path.join(a.out, 'ff_hooks.bin'), os.path.join(a.out, 'ff_ports.bin'),
                                          a.report))


if __name__ == '__main__':
    sys.exit(main())
