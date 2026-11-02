"""scan_decl_conv.py [--out FILE] - extern declarations whose convention drops a register the exe callee reads.

The lifted ports (and some hand ports) declare every callee they call as `ext_<addr>_stdcallN` / `_cdecl` / `_fastcallN` /
`_thiscallN`. When the exe function at <addr> itself reads ECX (or EDX) on ANY path from its entry (liveness over the whole CFG of
that function, calls only clobber) but the declaration is stdcall/cdecl, the port cannot pass the register: the call site leaves
ECX/EDX stale. Example: 0x64d490 called 0x63da80 as stdcall1; 0x63da80 reads ECX only behind a `je`, so the lifter's entry scan
missed it and the game crashed at 0x63da99 with ECX=0 (the call sets `ecx = [esi+0x1005d]` right before, dropped by the declaration).

Output: every wrong declaration (file, callee, convention, register) and, for lifted code, the definite call sites: a statement
`ecx = <value>;` (not the `ecx = edx = 0` clobber model) between the previous call/label and the call through the wrong declaration,
with the hooked port (address after `// @N_`) that contains it. Ports marked [not excluded] are not in game/exclude_level2.txt.

    python -I hybrid/scan_decl_conv.py --out hybrid/build/work_v6/decl_conv.tsv      (about 1 minute)
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import audit_ports as A  # noqa: E402

PORTS = os.path.join(HERE, '..', 'ReFreedomFighters', 'ports')
DECL = re.compile(r'extern\s+"C"\s+\w[\w\s\*]*?\b(STDCALL|CDECL|FASTCALL|THISCALL|__stdcall|__cdecl|__fastcall|__thiscall)\s+(ext_([0-9a-f]+)\w*)\s*\(([^)]*)\)')
SETTER = re.compile(r'\s*ecx = (?!edx = 0)')
LABEL = re.compile(r'\s*L[0-9a-f]+:;')
SITE = re.compile(r'// @\d+_([0-9a-f]{6})')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out')
    a = ap.parse_args()
    exe, secs, exe_entry = A.load_exe()
    port = A.load_port()
    rows = [l.rstrip('\n').split('\t') for l in open(A.PORTS_TSV, encoding='utf-8')]
    hooked = []
    for r in rows:
        if len(r) >= 3 and r[0].startswith('0x'):
            hooked.append((int(r[0], 16), int(r[1], 16), r[2], r[3] if len(r) > 3 else ''))
    port_starts = set()
    for l in open(A.PORTS_SYMS):
        p = l.split()
        if len(p) == 3 and (p[1] == 'T' or (p[1] == 't' and not re.match(r'^(L[0-9A-Za-z_]*|asm_.*)$', p[2]))):
            port_starts.add(int(p[0], 16))
    port_starts |= {h[1] for h in hooked}
    seeds = {h[0] for h in hooked} | {exe_entry}
    seeds |= {int(l.split('\t')[0], 16) for l in open(os.path.join(A.ROOT, 'ReFreedomFighters', 'RESULTS.tsv')) if l.startswith('0x')}
    seeds |= {int(l.split('\t')[0], 16) for l in open(os.path.join(A.BUILD, 'skipped.tsv')) if l.startswith('0x')}
    core_seeds = {s for s in seeds if exe.in_code(s)}
    seeds = core_seeds | A.data_pointer_seeds(exe, secs)
    an = A.Analyzer(exe, port, set(seeds), port_starts)
    calls_to, seen, starts, nfail = A.global_descent(an, seeds, exe)
    an.starts['exe'] = core_seeds | {t for t in calls_to if exe.in_code(t)}
    an.tailstarts['exe'] = starts | seeds

    def direct_live(addr):
        # registers read before written by the function's own instructions (calls only clobber: no pass-through of callee reads)
        w = an.which(addr)
        if w is None:
            return None
        fi = A.FI(addr)
        insns, succ = an.explore(w, addr, fi)
        if fi.err or not insns:
            return None
        use, ddef = {}, {}
        for ad, it in insns.items():
            u, d = it.uses, it.defs
            if it.kind in (A.K_CALL, A.K_INDCALL):
                d |= A.CLOBBER
            use[ad], ddef[ad] = u, d
        live = {ad: 0 for ad in insns}
        changed = True
        order = sorted(insns, reverse=True)
        while changed:
            changed = False
            for ad in order:
                lo = 0
                for sc in succ.get(ad, ()):
                    lo |= live.get(sc, 0)
                li = use[ad] | (lo & ~ddef[ad])
                if li != live[ad]:
                    live[ad] = li
                    changed = True
        return live[addr] & A.ALLREG

    excl = set()
    ex_path = os.path.join(A.ROOT, 'game', 'exclude_level2.txt')
    if os.path.exists(ex_path):
        for l in open(ex_path, encoding='utf-8', errors='replace'):
            m = re.match(r'\s*0x([0-9a-fA-F]+)', l)
            if m:
                excl.add(int(m.group(1), 16))
    out, sites = [], []
    memo = {}
    for folder in sorted(os.listdir(PORTS)):
        sd = os.path.join(PORTS, folder, 'src')
        if not os.path.isdir(sd):
            continue
        for fn in sorted(os.listdir(sd)):
            if not fn.endswith('.cpp'):
                continue
            txt = open(os.path.join(sd, fn), encoding='utf-8', errors='replace').read()
            wrong = []
            for m in DECL.finditer(txt):
                conv = m.group(1).replace('__', '').upper()
                if conv in ('THISCALL', 'FASTCALL'):
                    continue
                addr, nm = int(m.group(3), 16), m.group(2)
                if not exe.in_code(addr):
                    continue
                if addr not in memo:
                    memo[addr] = direct_live(addr)
                live = memo[addr]
                if live is None:
                    continue
                regs = A.regs_of(live)
                bad = [n for n, bit in (('ECX', 2), ('EDX', 4)) if regs & bit]
                if bad:
                    wrong.append((addr, nm, conv, '+'.join(bad)))
            if not wrong:
                continue
            for addr, nm, conv, bad in wrong:
                out.append((folder, fn, '0x%x' % addr, nm, conv, bad))
            lines = txt.split('\n')
            for addr, nm, conv, bad in wrong:
                if 'ECX' not in bad:
                    continue
                for k_, ln_ in enumerate(lines):
                    if (nm + '(') not in ln_ or ln_.lstrip().startswith('extern'):
                        continue
                    m_ = SITE.search(ln_)
                    setter = None
                    for j_ in range(k_ - 1, max(k_ - 9, -1), -1):
                        lj = lines[j_]
                        if ('ext_' in lj and '(' in lj and 'extern' not in lj) or LABEL.match(lj) or 'THISCALL *)' in lj:
                            break
                        if SETTER.match(lj) and 'ecx = ecx' not in lj:
                            setter = lj.strip()[:70]
                            break
                    if setter and m_:
                        sites.append((folder, fn, m_.group(1), '0x%x' % addr, nm, setter))
    print('%d wrong declarations in %d files' % (len(out), len({(o[0], o[1]) for o in out})))
    print('definite call sites (lifted code sets ECX right before a call through a stdcall/cdecl declaration):')
    seen_ = set()
    for st in sites:
        key = (st[2], st[3])
        if key in seen_:
            continue
        seen_.add(key)
        print('port 0x%s%s calls %s (%s) in %s/%s: %s' % (st[2], '' if int(st[2], 16) in excl else ' [not excluded]', st[3], st[4], st[0], st[1], st[5]))
    if a.out:
        with open(a.out, 'w', encoding='utf-8', newline='') as fh:
            fh.write('folder\tfile\tcallee\tdecl\tconv\treads\n')
            for o in out:
                fh.write('\t'.join(o) + '\n')
        with open(a.out + '.sites', 'w', encoding='utf-8', newline='') as fh:
            fh.write('folder\tfile\tport\tcallee\tdecl\tecx_setter\n')
            for st in sites:
                fh.write('\t'.join(st) + '\n')


if __name__ == '__main__':
    main()
