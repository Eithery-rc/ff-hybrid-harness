#!/usr/bin/env python3
"""build_all.py - one linked image of every verified port listed in RESULTS.tsv.

Run (from anywhere):
    python -I hybrid/build_all.py [options]

For each RESULTS.tsv row (exe address, name, folder) the port is taken from exactly that folder
(ReFreedomFighters/ports/<folder>/src/*.cpp, same clang flags as tooling/build.sh). All other `pc_<hex>`
registrations (other folders' duplicates, addresses RESULTS does not list for this folder) are hidden from
the link, their code stays only where it is reachable from a selected object.

Outputs in hybrid/build/:
    ff_ports.bin   flat image at 0x31000000        ff_ports.syms  nm-style symbols of the image
    ff_ports.tsv   exe_addr, port_entry_addr, folder, name        build_report.txt
    obj/<folder>/*.o, logs/<folder>/*.log (compile failures)

Options: -j N (parallel compiles), --force (rebuild every object), --no-prune (link every object of the
selected folders instead of only the reachable ones), --compile-only, --out-dir DIR (build somewhere else than
hybrid/build, e.g. hybrid/build/ports_next).
"""
import argparse
import collections
import concurrent.futures as cf
import csv
import hashlib
import os
import random
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mini_ld  # noqa: E402  (hybrid copy)

ROOT = os.path.dirname(HERE)
REPO = os.path.join(ROOT, 'ReFreedomFighters')
PORTS = os.path.join(REPO, 'ports')
TOOLING = os.path.join(REPO, 'tooling')
RESULTS = os.path.join(REPO, 'RESULTS.tsv')
SUPPORT = os.path.join(HERE, 'support')
BUILD = os.path.join(HERE, 'build')
BASE = 0x31000000
LLVM_BIN = r'C:\Program Files\LLVM\bin'

CXXFLAGS = ['--target=i686-linux-gnu', '-O2', '-msse2', '-mfpmath=sse', '-fno-pic', '-fno-pie', '-ffreestanding',
            '-fno-builtin', '-fno-exceptions', '-fno-rtti', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
            '-fno-threadsafe-statics', '-std=c++20', '-ffp-contract=off', '-fno-strict-aliasing', '-w',
            # frames of 4 KB and more get an inline probe per page; a plain `sub esp, N` jumps over the stack guard page
            # and faults (0x4d6520 reserves 192 KB, 0x63d4a0 and 80 more reserve 4 to 16 KB)
            '-fstack-clash-protection']
REALIGN = '-mstackrealign'      # added per file, see Job
PC_RE = re.compile(r'pc_(?:0[xX])?([0-9a-fA-F]+)')
PCREG_SRC_RE = re.compile(r'PCREG\(\s*(?:0[xX])?([0-9a-fA-F]+)\s*,')


def find_clang():
    for d in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(d, 'clang++.exe')
        if os.path.exists(p):
            return p
    return os.path.join(LLVM_BIN, 'clang++.exe')


def read_deps(dfile):
    txt = open(dfile, encoding='utf-8', errors='replace').read().replace('\\\r\n', ' ').replace('\\\n', ' ')
    rest = txt.partition(': ')[2].strip()
    return [t.replace('\\ ', ' ') for t in re.split(r'(?<!\\) +', rest) if t]


INC_RE = re.compile(rb'^\s*#\s*include\s*"([^"]+)"', re.M)
EBP_RE = re.compile(rb'%%ebp', re.I)


def ebp_readers(src, dirs, seen=None):
    """Files (the source and the quoted headers it pulls in from its own folder) whose text contains `%%ebp`."""
    seen = set() if seen is None else seen
    if src in seen or not os.path.exists(src):
        return []
    seen.add(src)
    data = open(src, 'rb').read()
    out = [src] if EBP_RE.search(data) else []
    for m in INC_RE.finditer(data):
        name = m.group(1).decode('utf-8', 'replace')
        for d in [os.path.dirname(src)] + dirs:
            p = os.path.normpath(os.path.join(d, name))
            if os.path.exists(p):
                out += ebp_readers(p, dirs, seen)
                break
    return out


def up_to_date(job):
    """An object is current when it was built from the same requested flags and nothing it reads is newer.
    The flag file holds: requested flags, effective flags, fallback reason (one per line)."""
    try:
        try:
            lines = open(job.flagfile).read().splitlines()
        except OSError:
            lines = ['']        # objects built before per-file flags existed had no extra flags
        n = len(lines)
        lines += [''] * (3 - len(lines))
        if lines[0] != ' '.join(job.req):
            return False
        t = os.path.getmtime(job.obj)
        if os.path.getmtime(job.src) > t:
            return False
        if not all(os.path.getmtime(p) <= t for p in read_deps(job.dep)):
            return False
        job.extra = (lines[1] if n >= 2 else lines[0]).split()
        job.fallback = lines[2]
        return True
    except OSError:
        return False


class Job:
    def __init__(self, folder, src, inc_dirs):
        self.folder, self.src, self.inc = folder, src, inc_dirs
        stem = os.path.splitext(os.path.basename(src))[0]
        self.stem = stem
        self.obj = os.path.join(BUILD, 'obj', folder, stem + '.o')
        self.dep = os.path.join(BUILD, 'obj', folder, stem + '.d')
        self.flagfile = os.path.join(BUILD, 'obj', folder, stem + '.flags')
        self.log = os.path.join(BUILD, 'logs', folder, stem + '.log')
        self.status = None      # 'ok' | 'cached' | 'fail'
        # Per-file stack realignment: the ports assume a 16-byte aligned stack, the game only gives 4. Files that
        # read EBP in inline asm (EH funclets reading the parent frame) must keep their frame layout.
        self.ebp_files = ebp_readers(src, inc_dirs)
        self.req = [] if self.ebp_files else [REALIGN]     # requested extra flags
        self.extra = list(self.req)                        # flags the object was really built with
        self.fallback = ''                                 # why the request could not be honoured


def run_clang(clang, job, extra):
    cmd = [clang] + CXXFLAGS + extra + ['-I' + d for d in job.inc] + ['-MD', '-MF', job.dep, '-c', job.src,
                                                                      '-o', job.obj]
    p = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
    return cmd, p, p.returncode == 0 and os.path.exists(job.obj)


def compile_job(clang, job, force):
    if not force and up_to_date(job):
        job.status = 'cached'
        return job
    os.makedirs(os.path.dirname(job.obj), exist_ok=True)
    if os.path.exists(job.obj):
        os.remove(job.obj)
    job.extra, job.fallback = list(job.req), ''
    cmd, p, ok = run_clang(clang, job, job.extra)
    if not ok and job.req:
        # -mstackrealign reserves ebp and esi: inline asm that needs every register no longer compiles.
        # Build the file without it; plan.py's hazard list covers what remains.
        first = [x for x in (p.stderr or '').splitlines() if 'error' in x]
        cmd2, p2, ok2 = run_clang(clang, job, [])
        if ok2:
            job.extra = []
            job.fallback = (first[0].split('error:')[-1].strip() if first else 'compile error')[:100]
            cmd, p, ok = cmd2, p2, True
    if ok:
        job.status = 'ok'
        with open(job.flagfile, 'w') as f:
            f.write('\n'.join([' '.join(job.req), ' '.join(job.extra), job.fallback, '']))
        if os.path.exists(job.log):
            os.remove(job.log)
    else:
        job.status = 'fail'
        os.makedirs(os.path.dirname(job.log), exist_ok=True)
        with open(job.log, 'w', encoding='utf-8') as f:
            f.write(' '.join(cmd) + '\n\n' + (p.stderr or '') + (p.stdout or ''))
        if os.path.exists(job.obj):
            os.remove(job.obj)
    return job


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-j', type=int, default=os.cpu_count() or 4)
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--no-prune', action='store_true')
    ap.add_argument('--compile-only', action='store_true')
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--out-dir', help='write objects and the image here instead of hybrid/build (the live build is left alone)')
    a = ap.parse_args()
    global BUILD
    if a.out_dir:
        BUILD = os.path.abspath(a.out_dir)
    t0 = time.time()
    os.environ['PATH'] = LLVM_BIN + os.pathsep + os.environ.get('PATH', '')
    clang = find_clang()
    os.makedirs(BUILD, exist_ok=True)

    # ---------------------------------------------------------------- RESULTS
    rows = []
    with open(RESULTS, encoding='utf-8', newline='') as f:
        rd = csv.reader(f, delimiter='\t')
        next(rd)
        for r in rd:
            if len(r) >= 3 and r[0].strip():
                rows.append((int(r[0], 16), r[1], r[2].strip()))
    if len(set(r[0] for r in rows)) != len(rows):
        raise SystemExit('RESULTS.tsv has duplicate addresses')
    folders = sorted(set(r[2] for r in rows))
    want = collections.defaultdict(dict)       # folder -> {addr: name}
    for ad, nm, fo in rows:
        want[fo][ad] = nm

    missing_folders = [fo for fo in folders if not os.path.isdir(os.path.join(PORTS, fo, 'src'))]
    live_folders = [fo for fo in folders if fo not in missing_folders]

    # ---------------------------------------------------------------- compile
    sig = hashlib.sha1((' '.join(CXXFLAGS) + clang_version(clang)).encode()).hexdigest()
    sigfile = os.path.join(BUILD, 'obj', '_flags.sig')
    force = a.force
    try:
        if open(sigfile).read().strip() != sig:
            force = True
    except OSError:
        force = True
    jobs = []
    for fo in live_folders:
        src = os.path.join(PORTS, fo, 'src')
        for fn in sorted(os.listdir(src)):
            if fn.endswith('.cpp'):
                jobs.append(Job(fo, os.path.join(src, fn), [src, TOOLING]))
    if os.path.isdir(SUPPORT):
        for fn in sorted(os.listdir(SUPPORT)):
            if fn.endswith('.cpp'):
                jobs.append(Job('_support', os.path.join(SUPPORT, fn), [SUPPORT, TOOLING]))
    print('compiling %d sources from %d folders with %d workers (%s)' % (len(jobs), len(live_folders), a.j, clang),
          flush=True)
    done = 0
    with cf.ThreadPoolExecutor(max_workers=a.j) as ex:
        futs = [ex.submit(compile_job, clang, j, force) for j in jobs]
        for fu in cf.as_completed(futs):
            fu.result()
            done += 1
            if done % 500 == 0:
                print('  %d/%d (%.0fs)' % (done, len(jobs), time.time() - t0), flush=True)
    os.makedirs(os.path.dirname(sigfile), exist_ok=True)
    open(sigfile, 'w').write(sig)
    failed = [j for j in jobs if j.status == 'fail']
    cstat = collections.Counter(j.status for j in jobs)
    print('compiled: %s, failed %d (%.0fs)' % (dict(cstat), len(failed), time.time() - t0), flush=True)
    if a.compile_only:
        return

    # ---------------------------------------------------------------- load objects, pc index
    good = [j for j in jobs if j.status != 'fail']
    objs = []
    for j in good:
        o = mini_ld.Obj(j.obj, folder=j.folder, label='%s/%s' % (j.folder, j.stem))
        objs.append(o)
    objs.sort(key=lambda o: (o.folder == '_support', o.folder, o.path))
    pcdefs = collections.defaultdict(list)      # (folder, addr) -> [(obj, symname)]
    nonstd_pc = 0
    for o in objs:
        for nm in o.gdefs:
            if nm.startswith('pc_'):
                m = PC_RE.fullmatch(nm)
                if m:
                    pcdefs[(o.folder, int(m.group(1), 16))].append((o, nm))
                else:
                    nonstd_pc += 1

    # ---------------------------------------------------------------- selection
    selected = {}                                # addr -> (obj, symname)
    skipped = collections.defaultdict(list)      # reason -> [(addr, folder)]
    dup_in_folder = []
    failed_by_folder = collections.defaultdict(list)
    for j in failed:
        failed_by_folder[j.folder].append(j)
    failed_addrs = collections.defaultdict(set)  # (folder, addr) -> {files}
    for j in failed:
        try:
            txt = open(j.src, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for m in PCREG_SRC_RE.finditer(txt):
            failed_addrs[(j.folder, int(m.group(1), 16))].add(j.stem + '.cpp')
    for ad, nm, fo in rows:
        if fo in missing_folders:
            skipped['folder %s not in ports/ (no src dir)' % fo].append((ad, fo))
            continue
        c = pcdefs.get((fo, ad))
        if not c:
            if (fo, ad) in failed_addrs:
                skipped['compile failure in %s/%s' % (fo, ','.join(sorted(failed_addrs[(fo, ad)])))].append((ad, fo))
            else:
                skipped['no pc_ registration for this address in folder %s' % fo].append((ad, fo))
            continue
        if len(c) > 1:
            dup_in_folder.append((ad, fo, [x[0].label for x in c]))
        selected[ad] = c[0]
    keep = set((id(o), nm) for o, nm in selected.values())

    def drop(o, nm):
        return nm.startswith('pc_') and (id(o), nm) not in keep

    n_hidden = sum(1 for o in objs for nm in o.gdefs if drop(o, nm))
    roots = None if a.no_prune else sorted(set(o for o, _ in selected.values()), key=lambda o: objs.index(o))

    # ---------------------------------------------------------------- link
    print('linking %d objects (%d roots)...' % (len(objs), len(roots) if roots is not None else len(objs)), flush=True)
    res = mini_ld.link(objs, BASE, roots=roots, drop=drop, track=lambda nm: nm.startswith('pc_'), kind_align=0x1000)
    img = res.img
    rng = res.ranges

    # ---------------------------------------------------------------- manifest + sanity
    funcsyms = set(v for v, c, nm in res.syms if c in ('T', 't', 'W'))
    tlo, thi = rng['text']
    manifest, bad_entry = [], []
    for ad, nm, fo in sorted(rows):
        if ad not in selected:
            continue
        o, sym = selected[ad]
        if (o, sym) not in res.tracked:
            bad_entry.append((ad, fo, 'pc symbol not in image'))
            continue
        p = res.tracked[(o, sym)]
        entry = int.from_bytes(img[p - BASE:p - BASE + 4], 'little')
        if not (tlo <= entry < thi):
            bad_entry.append((ad, fo, 'entry 0x%x outside text' % entry))
            continue
        manifest.append((ad, entry, fo, nm))
    ok_funcsym = sum(1 for m in manifest if m[1] in funcsyms)

    with open(os.path.join(BUILD, 'ff_ports.bin'), 'wb') as f:
        f.write(bytes(img))
    with open(os.path.join(BUILD, 'ff_ports.syms'), 'w') as f:
        for v, c, nm in res.syms:
            f.write('%08x %s %s\n' % (v, c, nm))
    with open(os.path.join(BUILD, 'ff_ports.tsv'), 'w', encoding='utf-8', newline='') as f:
        for ad, entry, fo, nm in manifest:
            f.write('0x%x\t0x%x\t%s\t%s\n' % (ad, entry, fo, nm))

    names = {ad: nm for ad, nm, fo in rows}
    skip_addrs = set(ad for lst in skipped.values() for ad, _ in lst) | set(b[0] for b in bad_entry)
    alt = find_alternatives(skip_addrs)
    with open(os.path.join(BUILD, 'skipped.tsv'), 'w', encoding='utf-8', newline='') as f:
        f.write('addr\tfolder_in_RESULTS\tname\treason\tother_folders_with_PCREG_text(unverified, not used)\n')
        for reason, lst in sorted(skipped.items()):
            for ad, fo in sorted(lst):
                f.write('0x%x\t%s\t%s\t%s\t%s\n' % (ad, fo, names[ad], reason, ' '.join(sorted(alt.get(ad, ()))[:8])))
        for ad, fo, why in bad_entry:
            f.write('0x%x\t%s\t%s\t%s\t%s\n' % (ad, fo, names[ad], why, ' '.join(sorted(alt.get(ad, ()))[:8])))

    # sanity: 3 random manifest rows read back from the files just written
    rnd = random.Random(a.seed)
    blob = open(os.path.join(BUILD, 'ff_ports.bin'), 'rb').read()
    syms_txt = {}
    for line in open(os.path.join(BUILD, 'ff_ports.syms')):
        p = line.split()
        if len(p) == 3 and p[2].startswith('pc_'):
            syms_txt[p[2]] = int(p[0], 16)
    sanity = []
    for ad, entry, fo, nm in rnd.sample(manifest, 3):
        cands = [(n, v) for n, v in syms_txt.items() if PC_RE.fullmatch(n) and int(PC_RE.fullmatch(n).group(1), 16) == ad]
        pcaddr = cands[0][1]
        val = int.from_bytes(blob[pcaddr - BASE:pcaddr - BASE + 4], 'little')
        sanity.append('0x%x %s: pc symbol @0x%x holds 0x%x; inside image=%s, inside text [0x%x,0x%x)=%s, function symbol at target=%s'
                      % (ad, nm[:50], pcaddr, val, BASE <= val < BASE + len(blob), tlo, thi, tlo <= val < thi,
                         val in funcsyms))

    # ---------------------------------------------------------------- report
    L = []
    st = res.stats
    skipped_total = sum(len(v) for v in skipped.values()) + len(bad_entry)
    L.append('build_all report (%s, %.0fs)' % (time.strftime('%Y-%m-%d %H:%M:%S'), time.time() - t0))
    L.append('')
    L.append('RESULTS rows:            %d' % len(rows))
    L.append('addresses in manifest:   %d' % len(manifest))
    L.append('addresses skipped:       %d' % skipped_total)
    L.append('image:                   %d bytes (0x%x), base 0x%x, end 0x%x' % (len(blob), len(blob), BASE, BASE + len(blob)))
    for k in mini_ld.KIND_NAMES:
        lo, hi = rng[k]
        L.append('  %-7s 0x%08x - 0x%08x (%d bytes)' % (k, lo, hi, hi - lo))
    L.append('folders in RESULTS:      %d (present in ports/: %d, missing: %d)' % (len(folders), len(live_folders), len(missing_folders)))
    L.append('sources compiled:        %d (cached %d, built %d, failed %d)' % (len(jobs), cstat['cached'], cstat['ok'], len(failed)))
    L.append('objects linked:          %d of %d loaded (%d pruned as unreachable%s)' % (
        st['objects_linked'], len(objs), st['objects_pruned'], '; pruning off' if a.no_prune else ''))
    L.append('pc_ symbols hidden:      %d (kept %d)' % (n_hidden, len(keep)))
    L.append('non-hex pc_ globals:     %d (hidden)' % nonstd_pc)
    L.append('')
    ebp_ex = [j for j in jobs if j.ebp_files]
    fb = [j for j in jobs if j.fallback]
    L.append('== Stack realignment (%s per file): %d of %d files built with it' % (
        REALIGN, sum(1 for j in jobs if j.extra), len(jobs)))
    L.append('   excluded on purpose, text contains %%%%ebp: %d files' % len(ebp_ex))
    for j in ebp_ex:
        L.append('     %s/%s.cpp%s' % (j.folder, j.stem, '' if j.ebp_files == [j.src] else
                                       ' (via ' + ', '.join(os.path.basename(x) for x in j.ebp_files) + ')'))
    L.append('   built without it because the compile failed with it: %d files' % len(fb))
    for j in fb:
        L.append('     %s/%s.cpp: %s' % (j.folder, j.stem, j.fallback))
    L.append('')
    L.append('== Skipped addresses by reason')
    for reason, lst in sorted(skipped.items(), key=lambda kv: -len(kv[1])):
        L.append('%5d  %s' % (len(lst), reason))
    for ad, fo, why in bad_entry:
        L.append('    0x%x (%s): %s' % (ad, fo, why))
    L.append('')
    L.append('== Folders in RESULTS but absent from ports/ (%d)' % len(missing_folders))
    cnt = collections.Counter(r[2] for r in rows)
    for fo in sorted(missing_folders, key=lambda x: -cnt[x]):
        L.append('%5d  %s' % (cnt[fo], fo))
    L.append('')
    L.append('== Compile failures (%d files)' % len(failed))
    for j in failed:
        aff = sorted(ad for (fo, ad), fs in failed_addrs.items() if fo == j.folder and (j.stem + '.cpp') in fs and ad in want[fo])
        first = ''
        try:
            lines = [x for x in open(j.log, encoding='utf-8', errors='replace').read().splitlines() if 'error' in x]
            first = lines[0][:200] if lines else ''
        except OSError:
            pass
        L.append('%s/%s.cpp: %d verified addresses affected; log %s\n    %s\n    %s' % (
            j.folder, j.stem, len(aff), os.path.relpath(j.log, HERE), first,
            ' '.join('0x%x' % x for x in aff[:12]) + (' ...' if len(aff) > 12 else '')))
    L.append('')
    L.append('== Duplicate registrations inside the selected folder (first object in sorted order used): %d' % len(dup_in_folder))
    for ad, fo, labs in dup_in_folder:
        L.append('  0x%x %s: %s' % (ad, fo, ', '.join(labs)))
    L.append('')
    L.append('== Symbol resolution')
    L.append('references to ext_<hex> bound to the exe (unique obj/name pairs): %d' % st['ref_ext'])
    L.append('globals referenced inside their defining object (unique pairs):    %d (first definition in link order would have been another object: %d)' % (
        st['ref_same_object'], st['ref_same_object_pref_changed']))
    L.append('  of those, own copy differs from the folder\'s first definition (tooling/build.sh would have used the first): %d' % st['ref_same_object_vs_folder_first'])
    L.append('undefined refs resolved in the same folder (unique pairs):        %d' % st['ref_same_folder'])
    L.append('undefined refs where the preference rule picked another object than the first definition: %d' % st['ref_pref_changed'])
    L.append('undefined refs resolved in another folder (unique pairs):         %d (of which with competing definitions in several folders: %d)' % (
        st['ref_elsewhere'], st['ref_elsewhere_ambiguous']))
    L.append('global names defined strongly by >1 linked object:                %d (in >1 folder: %d)' % (
        st['dup_global_names'], st['dup_global_names_cross_folder']))
    L.append('weak undefined refs bound to 0:                                   %d' % st['ref_weak_undefined'])
    L.append('COMMON symbols:                                                  %d' % st['commons'])
    if res.ext_defined:
        L.append('ext_<hex> names defined by objects (ignored, bound to exe): %d' % len(res.ext_defined))
    for nm, fl in sorted(res.ambiguous.items())[:20]:
        L.append('  ambiguous %s defined in folders: %s' % (nm, ', '.join(fl[:6])))
    L.append('')
    L.append('== Unresolved externals other than ext_<hex> (bound to ff_unresolved_trap): %d names' % len(res.unresolved))
    obj_pcs = collections.defaultdict(list)
    for ad, (o, sym) in selected.items():
        obj_pcs[o.label].append(ad)
    for nm, labs in sorted(res.unresolved.items()):
        aff = sorted(ad for lab in labs for ad in obj_pcs.get(lab, []))
        L.append('  %s: %d objects, %d verified addresses in those objects; e.g. %s' % (nm, len(labs), len(aff), sorted(labs)[0]))
    L.append('')
    L.append('== Runtime support objects linked')
    sup = [o.label for o in res.objs if o.folder == '_support']
    L.append('  ' + (', '.join(sup) if sup else 'none'))
    L.append('')
    L.append('== Static constructors / init arrays present in linked objects (never run): %d' % len(res.ctor_sections))
    for lab, nm in res.ctor_sections[:20]:
        L.append('  %s %s' % (lab, nm))
    L.append('')
    L.append('== Sanity check (3 random manifest rows, read back from the written files)')
    L.extend('  ' + s for s in sanity)
    L.append('  function symbol at entry for %d of %d manifest rows' % (ok_funcsym, len(manifest)))
    text = '\n'.join(L) + '\n'
    open(os.path.join(BUILD, 'build_report.txt'), 'w', encoding='utf-8').write(text)
    print(text)


def find_alternatives(addrs):
    """addr -> folders anywhere in ports/ whose sources mention PCREG(addr, ...). Information only."""
    rx = re.compile(rb'PCREG\(\s*(?:0[xX])?([0-9a-fA-F]+)\s*,')
    out = collections.defaultdict(set)
    for fo in os.listdir(PORTS):
        src = os.path.join(PORTS, fo, 'src')
        if not os.path.isdir(src):
            continue
        for fn in os.listdir(src):
            if fn.endswith('.cpp'):
                with open(os.path.join(src, fn), 'rb') as f:
                    for m in rx.finditer(f.read()):
                        ad = int(m.group(1), 16)
                        if ad in addrs:
                            out[ad].add(fo)
    return out


def clang_version(clang):
    try:
        return subprocess.run([clang, '--version'], capture_output=True, text=True).stdout.splitlines()[0]
    except Exception:
        return ''


if __name__ == '__main__':
    main()
