"""shadow.py - offline side of shadow differential testing: replay saved samples against ports images.

    python -I hybrid/shadow/shadow.py replay SAMPLE_OR_DIR... --image LABEL=PATH [--image ...] [--fn 0x445c50 ...]
        [--tsv OUT.tsv] [--exe PATH] [--workers N] [-v]
    python -I hybrid/shadow/shadow.py show SAMPLE
    python -I hybrid/shadow/shadow.py summary RESULTS.tsv [--top 25]

PATH is a build folder (ff_ports.bin + ff_ports.tsv) or an ff_ports.bin whose hook plan sits next to it with the same
suffix (game/ff_ports.bin.prev + game/ff_hooks.bin.prev). Each sample runs the original once and every image's port
once; the table has one line per (sample, image): verdict and the first differences. The TSV has the same columns.
Default image when none is given: cur (hybrid/build).
"""
import argparse
import glob
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import replay  # noqa: E402
from sample import FileSource, parse_context  # noqa: E402

DEFAULT_IMAGES = [('cur', 'hybrid/build')]


def sample_paths(args):
    out = []
    for a in args:
        if os.path.isdir(a):
            out += sorted(glob.glob(os.path.join(a, '**', '*.ffs'), recursive=True))
        else:
            out.append(a)
    return out


def load_images(specs):
    if not specs:
        specs = ['%s=%s' % (lb, os.path.join(replay.REA, d)) for lb, d in DEFAULT_IMAGES]
    out = []
    for s in specs:
        label, _, path = s.partition('=')
        out.append(replay.Image(path, label))
    return out


_NAMES = {}


def fn_name(images, a):
    for im in images:
        e = im.entries.get(a)
        if e and e[1]:
            return e[1]
    if not _NAMES:      # images loaded from a hook plan carry no names: take them from the unified build manifest
        p = os.path.join(replay.REA, 'hybrid', 'build', 'ff_ports.tsv')
        for line in open(p, encoding='utf-8', errors='replace') if os.path.exists(p) else ():
            w = line.rstrip('\n').split('\t')
            if w[0].startswith('0x') and len(w) > 3:
                _NAMES[int(w[0], 16)] = w[3]
        _NAMES.setdefault(-1, '')
    return _NAMES.get(a, '')


_P = {}


def _pinit(exe_path, image_specs):
    _P['exe'] = replay.Exe(exe_path) if exe_path else replay.Exe()
    _P['images'] = load_images(image_specs)


def _one(path):
    """Rows for one sample: [sample, fn, name, image, verdict, diff, orig_s, port_s]."""
    import traceback
    images = _P['images']
    try:
        src = FileSource(path)
        fn = src.header['fn']
        env, orig, res = replay.replay(src, _P['exe'], images)
    except Exception:
        err = traceback.format_exc().strip().splitlines()[-1]
        return [[os.path.basename(path), '?', '', im.label, 'error', err[:400], '0', '0'] for im in images]
    out = []
    for label, (v, diffs, q) in res.items():
        out.append([os.path.basename(path), '0x%x' % fn, fn_name(images, fn)[:48], label, v,
                    '; '.join(diffs[:3]).replace('\t', ' ')[:400], '%.2f' % orig.secs, '%.2f' % (q.secs if q else 0)])
    return out


def cmd_replay(a):
    paths = sample_paths(a.samples)
    if a.fn:
        want = {'%06x' % int(x, 16) for x in a.fn}
        paths = [p for p in paths if os.path.basename(p).split('_')[0] in want]
    rows = []
    t0 = time.time()
    counts = {}
    if a.workers > 1:
        import multiprocessing as mp
        pool = mp.get_context('spawn').Pool(a.workers, initializer=_pinit, initargs=(a.exe, a.image))
        results = pool.imap(_one, paths, chunksize=4)
    else:
        _pinit(a.exe, a.image)
        results = map(_one, paths)
    for out in results:
        for row in out:
            rows.append(row)
            label, v = row[3], row[4]
            counts[(label, v)] = counts.get((label, v), 0) + 1
            if a.v or v not in ('exact', 'no-port', 'weak'):
                print('%-28s %-9s %-36s %-5s %-12s %s' % (row[0][:28], row[1], row[2][:36], label, v, row[5][:200]),
                      flush=True)
    if a.workers > 1:
        pool.close()
        pool.join()
    print('== %d samples in %.1fs: %s' % (len({r[0] for r in rows}), time.time() - t0,
                                          ', '.join('%s %s %d' % (k[0], k[1], n) for k, n in sorted(counts.items()))))
    if a.tsv:
        with open(a.tsv, 'w', encoding='utf-8') as f:
            f.write('sample\tfn\tname\timage\tverdict\tdiff\torig_s\tport_s\n')
            for r in rows:
                f.write('\t'.join(r) + '\n')
    return 0


def cmd_show(a):
    src = FileSource(a.sample)
    h = src.header
    c = parse_context(bytes.fromhex(h['context']))
    print('fn 0x%x  seq %s  tid %s  call %s  teb 0x%x' % (h['fn'], h.get('seq'), h.get('tid'), h.get('k'), h['teb']))
    print('regs', ' '.join('%s=%08x' % (k, c[k]) for k in ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                                                            'eflags')))
    print('fpu cw %04x sw %04x tw %04x  mxcsr %08x  ctx flags %08x' % (c['fcw'], c['fsw'], c['ftw'], c['mxcsr'], c['flags']))
    print('stack', ' '.join('0x%x' % v for v in h['stack']), ' return address 0x%x' % (src.u32(c['esp']) or 0))
    print('time', h.get('time'))
    print('pages %d, regions %d, modules %d, unreadable %d' % (len(src.pages), len(h['regions']), len(h['modules']),
                                                                len(h.get('unreadable', []))))
    for k in ('verdicts', 'record'):
        if k in h:
            print(k, h[k])
    return 0


def cmd_summary(a):
    """Verdicts per image from a results.tsv (collector) or a replay --tsv, the most common reasons the original did
    not finish, and the functions whose verdict differs between images."""
    import collections
    rows = [line.rstrip('\n').split('\t') for line in open(a.tsv, encoding='utf-8')]
    head, rows = rows[0], rows[1:]
    col = {k: i for i, k in enumerate(head)}
    fn_i, im_i, v_i, d_i = col['fn'], col['image'], col['verdict'], col['diff']
    per = collections.Counter((r[im_i], r[v_i]) for r in rows)
    images = sorted({r[im_i] for r in rows})
    verdicts = sorted({r[v_i] for r in rows})
    print('%-14s' % 'verdict' + ''.join('%10s' % im for im in images))
    for v in verdicts:
        print('%-14s' % v + ''.join('%10d' % per[(im, v)] for im in images))
    print('samples %d, functions %d' % (len({(r[0], r[fn_i]) for r in rows}), len({r[fn_i] for r in rows})))
    why = collections.Counter()
    for r in rows:
        if r[v_i] == 'unsupported' and r[im_i] == images[0]:
            t = r[d_i]
            for pat, rep in ((r'0x[0-9a-f]+', 'X'), (r'\d+', 'N')):
                t = re.sub(pat, rep, t)
            why[t[:110]] += 1
    if why:
        print('\nwhy the original did not finish (first image):')
        for t, n in why.most_common(a.top):
            print('%5d  %s' % (n, t))
    rank = ['exact', 'no-port', 'weak', 'unsupported', 'missing-page', 'error', 'mismatch', 'crash']
    by_fn = collections.defaultdict(dict)
    for r in rows:
        cur = by_fn[r[fn_i]].get(r[im_i])
        worse = cur is None or (rank.index(r[v_i]) if r[v_i] in rank else 0) > (rank.index(cur[0]) if cur[0] in rank else 0)
        if worse:
            by_fn[r[fn_i]][r[im_i]] = (r[v_i], r[d_i])
    print('\nfunctions with a mismatch or crash in any image (worst sample per image):')
    for fn in sorted(by_fn, key=lambda x: int(x, 16)):
        vs = by_fn[fn]
        if any(v[0] in ('mismatch', 'crash') for v in vs.values()):
            print('%-10s %s' % (fn, '  '.join('%s=%s' % (im, vs.get(im, ('-',))[0]) for im in images)))
            first = next((vs[im][1] for im in images if im in vs and vs[im][0] in ('mismatch', 'crash')), '')
            print('           ' + first[:220])
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('replay')
    r.add_argument('samples', nargs='+')
    r.add_argument('--image', action='append', default=[])
    r.add_argument('--fn', action='append', default=[])
    r.add_argument('--tsv')
    r.add_argument('--exe', help='the original exe (default ffre-root/bin/Freedom.Exe.orig)')
    r.add_argument('--workers', type=int, default=1)
    r.add_argument('-v', action='store_true')
    s = sub.add_parser('show')
    s.add_argument('sample')
    m = sub.add_parser('summary')
    m.add_argument('tsv')
    m.add_argument('--top', type=int, default=25)
    a = ap.parse_args(argv)
    return {'replay': cmd_replay, 'show': cmd_show, 'summary': cmd_summary}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
