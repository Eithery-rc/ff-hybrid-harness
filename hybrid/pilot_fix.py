#!/usr/bin/env python3
"""pilot_fix.py - run the pilot specs of the ports a build changed, against the objects of that build.

Run:  python -I hybrid/pilot_fix.py LIST.tsv [--image DIR] [-n N]
      [--seed S] [-j JOBS] [--out FILE]

LIST.tsv: one address per line in the first column (0x...), other columns ignored. For every address the objects of its port
folder are taken from DIR/obj/<folder>/*.o (default hybrid/build/ports_next: the same flags and the same linker as the
shipped image, including the -fstack-clash-protection probes and the ext_633654 rebinding), linked per folder with
hybrid/mini_ld.py into a temporary pilot.bin / pilot.syms, and the spec of the address (found in its own folder's harness or
in the folder that holds it, see audit_ports.parse_specs) is run by tooling/pilot.py in the Unicorn emulator.

Result per address: exact / mismatch / not-exercisable / ... as pilot.py reports it. The summary goes to --out (tsv).
Nothing here starts the game or touches game/.
"""
import argparse
import collections
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.join(ROOT, 'ReFreedomFighters')
PY = sys.executable
sys.path.insert(0, HERE)
import audit_ports as A  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('list')
    ap.add_argument('--image', default=os.path.join(HERE, 'build', 'ports_next'))
    ap.add_argument('-n', type=int, default=300)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('-j', type=int, default=6)
    ap.add_argument('--out')
    ap.add_argument('--lean', action='store_true', help='give the pilot only the spec files that define the wanted addresses (a spec file elsewhere in the folder that needs a data file missing from the clone otherwise stops every address of the folder)')
    ap.add_argument('--no-rebind', action='store_true', help='link without the ext_633654 rebinding (specs that hook 0x633654)')
    a = ap.parse_args()
    addrs = []
    for ln in open(a.list, encoding='utf-8'):
        t = ln.split('\t')[0].strip()
        if t.lower().startswith('0x'):
            addrs.append(int(t, 16))
    folder_of = {}
    for ln in open(os.path.join(a.image, 'ff_ports.tsv'), encoding='utf-8'):
        p = ln.rstrip('\n').split('\t')
        folder_of[int(p[0], 16)] = p[2]
    addrs = sorted(set(addrs))
    missing = [x for x in addrs if x not in folder_of]
    wanted = {(folder_of[x], x) for x in addrs if x in folder_of}
    specs, alt, _fails = A.parse_specs(sorted({f for f, _ in wanted}), wanted)
    groups = collections.defaultdict(list)           # (src folder, spec folder) -> [addr]
    nospec = []
    for f, x in sorted(wanted):
        sp = specs.get((f, x)) or alt.get(x)
        if not sp:
            nospec.append(x)
            continue
        groups[(f, sp[0].get('folder', f))].append(x)
    tmp = tempfile.mkdtemp(prefix='pilot_fix_')
    # The specs' helpers (recruits_util) use pe_emu.TEB; the repo's pe_emu keeps its fake TEB at address 0 but does not name it.
    shim = os.path.join(tmp, '_shim')
    os.makedirs(shim)
    tool = os.path.join(REPO, 'tooling')
    for fn in os.listdir(tool):
        if fn.endswith('.py'):
            src = open(os.path.join(tool, fn), encoding='utf-8', newline='').read()
            if fn == 'pe_emu.py' and 'TEB =' not in src:
                src += '\nTEB = 0\n'
            open(os.path.join(shim, fn), 'w', encoding='utf-8', newline='').write(src)
    # helper modules some spec families import by bare name
    for modname, path in (('wkit', os.path.join(REPO, 'ports', 'shared-wkit.py')),
                          ('sthelp', os.path.join(REPO, 'ports', 'inline-fresh-15', 'harness', 'sthelp.py'))):
        if os.path.exists(path):
            open(os.path.join(shim, modname + '.py'), 'w', encoding='utf-8', newline='').write(
                open(path, encoding='utf-8', newline='').read())
    results = {}

    def run(key):
        src, spec = key
        objs = sorted(os.path.join(a.image, 'obj', src, fn) for fn in os.listdir(os.path.join(a.image, 'obj', src))
                      if fn.endswith('.o'))
        out = os.path.join(tmp, src)
        os.makedirs(out, exist_ok=True)
        lenv = dict(os.environ)
        if a.no_rebind:
            lenv['FF_NO_EXT_REBIND'] = '1'
        r = subprocess.run([PY, '-I', os.path.join(HERE, 'mini_ld.py'), '--base', '0x31000000', '-o', os.path.join(out, 'pilot.bin'),
                            '--syms', os.path.join(out, 'pilot.syms')] + objs, capture_output=True, text=True, env=lenv)
        if r.returncode:
            return key, {x: ('link-fail', r.stderr[-200:]) for x in groups[key]}
        spec_dir = os.path.join(REPO, 'ports', spec, 'harness')
        if a.lean:
            import re
            import shutil
            lean = os.path.join(out, 'harness_lean')
            shutil.rmtree(lean, ignore_errors=True)
            os.makedirs(lean)
            pats = [re.compile(r'S\(\s*0x%x[,)]' % x, re.I) for x in groups[key]]
            for fn in os.listdir(spec_dir):
                fp = os.path.join(spec_dir, fn)
                if not os.path.isfile(fp):
                    continue
                if fn.startswith('specs_') and fn.endswith('.py'):
                    txt = open(fp, encoding='utf-8', errors='replace').read()
                    if not any(pt.search(txt) for pt in pats):
                        continue
                shutil.copy(fp, os.path.join(lean, fn))
            spec_dir = lean
        env = dict(os.environ, FF_RE_ROOT=os.path.join(ROOT, 'ffre-root'), PILOT_BUILD=out, PILOT_EXE_VERIFY=shim,
                   PILOT_SPECS=spec_dir)
        def pilot(xs, tag):
            js = os.path.join(out, 'result_%s_%s.json' % (spec, tag))
            cmd = [PY, '-I', os.path.join(REPO, 'tooling', 'pilot.py')] + ['0x%x' % x for x in xs] + [
                '-n', str(a.n), '--seed', str(a.seed), '--no-build', '--json', js]
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if os.environ.get('PILOT_FIX_DEBUG'):
                print('--- pilot', tag, (r.stdout + r.stderr)[-1500:], flush=True)
            try:
                data = json.load(open(js))
            except (OSError, ValueError):
                return None, (r.stdout + r.stderr)[-300:]
            return {int(d['addr'], 16): (d['status'], d.get('why', '')) for d in data}, ''
        got, err = pilot(groups[key], 'all')
        if got is None:
            # one spec raised (missing data file, missing module): the run stops there, so run the addresses one by one
            got = {}
            for x in groups[key]:
                g1, err1 = pilot([x], '%x' % x)
                got[x] = (g1 or {}).get(x, ('run-fail', err1))
        return key, {x: got.get(x, ('no-result', '')) for x in groups[key]}

    with cf.ThreadPoolExecutor(max_workers=a.j) as ex:
        for key, res in ex.map(run, sorted(groups)):
            results.update(res)
            bad = [x for x, v in res.items() if v[0] != 'exact']
            print('%-28s specs from %-24s %3d ports, %s' % (key[0], key[1], len(res),
                  'all exact' if not bad else 'NOT exact: ' + ' '.join('0x%x' % x for x in bad)), flush=True)
    cnt = collections.Counter(v[0] for v in results.values())
    print('summary:', dict(cnt), '| no spec found:', len(nospec), '| not in the image:', len(missing))
    if a.out:
        with open(a.out, 'w', encoding='utf-8', newline='') as fh:
            fh.write('exe_addr\tstatus\tdetail\n')
            for x in addrs:
                v = results.get(x)
                if v is None:
                    v = ('no-spec-found' if x in nospec else 'not-in-image', '')
                fh.write('0x%x\t%s\t%s\n' % (x, v[0], v[1].replace('\t', ' ').replace('\n', ' ')[:300]))


if __name__ == '__main__':
    sys.setrecursionlimit(60000)
    main()
