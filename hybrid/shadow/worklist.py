"""worklist.py - every shadow run merged into one table per function: hybrid/build/shadow/worklist.tsv.

    python -I hybrid/shadow/worklist.py [--replay] [--workers 6] [--image LABEL=PATH ...] [--runs DIR ...]
        [--out hybrid/build/shadow/worklist.tsv] [--new-wrong FILE --exclude game/exclude_level2.txt --since RUN]

A run is a folder hybrid/build/shadow/run* with samples/ (run_capture.py --out). Its verdicts come from the newest
offline replay TSV in the folder (offline*.tsv, written by shadow.py replay or by --replay here) or, when there is
none, from the collector's samples/results.tsv. --replay first replays every run's samples with the current code
(into <run>/offline.tsv), so all runs are judged by the same replay. Its images are the frozen copies in
hybrid/build/shadow/images/<label>/ (ff_ports.bin + ff_ports.tsv, oldest first) unless --image is given: game/ff_ports.bin
and the build folders change when another process installs or rebuilds an image, and a replay must not mix them.

Columns: fn, name, folder (port folder in hybrid/build/ff_ports.tsv), samples, one column per image with the worst
verdict over all samples (crash > mismatch > error > missing-page > unsupported > weak > no-port > exact),
first_difference (of the worst sample of the last image that is wrong, else of any image), first_seen (run),
runs, listed (exclude_level2 / exclude_night / hunt when the function is in that list).

--new-wrong FILE writes the functions whose verdict in the last image is mismatch or crash and that are not in
--exclude, in the exclude-file format (hex address, then a comment with the name and the first difference).
--since RUN keeps only those first sampled in RUN or later.
"""
import argparse
import collections
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
REA = os.path.normpath(os.path.join(HERE, '..', '..'))
SHADOW_BUILD = os.path.join(REA, 'hybrid', 'build', 'shadow')
RANK = ['exact', 'no-port', 'weak', 'unsupported', 'missing-page', 'error', 'mismatch', 'crash']
BAD = ('mismatch', 'crash')


def runs(dirs=None):
    """Run folders in the order they were made (oldest first)."""
    found = dirs or [d for d in glob.glob(os.path.join(SHADOW_BUILD, 'run*')) if os.path.isdir(os.path.join(d, 'samples'))]
    return sorted(found, key=lambda d: os.path.getctime(os.path.join(d, 'samples')))


def run_tsv(d):
    offline = sorted(glob.glob(os.path.join(d, 'offline*.tsv')), key=os.path.getmtime)
    if offline:
        return offline[-1]
    p = os.path.join(d, 'samples', 'results.tsv')
    return p if os.path.exists(p) else None


def read_rows(path):
    """(sample id, fn, image, verdict, diff) from either TSV format."""
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    if not lines:           # a run that is still starting
        return
    head = lines[0].split('\t')
    col = {k: i for i, k in enumerate(head)}
    sid = col.get('sample', col.get('seq'))
    for line in lines[1:]:
        w = line.split('\t')
        if len(w) < len(head) - 1 or not w[col['fn']].startswith('0x'):
            continue
        yield w[sid], int(w[col['fn']], 16), w[col['image']], w[col['verdict']], w[col['diff']]


def read_list(path):
    out = set()
    if path and os.path.exists(path):
        for line in open(path, errors='replace'):
            t = line.split('#')[0].split(';')[0].strip()
            if t.startswith('0x'):
                try:
                    out.add(int(t.split()[0], 16))
                except ValueError:
                    pass
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', nargs='*')
    ap.add_argument('--replay', action='store_true')
    ap.add_argument('--workers', type=int, default=6)
    ap.add_argument('--image', action='append', default=[])
    ap.add_argument('--out', default=os.path.join(SHADOW_BUILD, 'worklist.tsv'))
    ap.add_argument('--new-wrong')
    ap.add_argument('--exclude', default=os.path.join(REA, 'game', 'exclude_level2.txt'))
    ap.add_argument('--since')
    a = ap.parse_args(argv)
    rlist = runs(a.runs)
    if a.replay:
        import shadow
        # frozen copies (game/ff_ports.bin and the build folders change under a running replay)
        frozen = sorted(glob.glob(os.path.join(SHADOW_BUILD, 'images', '*', 'ff_ports.bin')), key=os.path.getctime)
        images = a.image or ['%s=%s' % (os.path.basename(os.path.dirname(p)), os.path.dirname(p)) for p in frozen]
        for d in rlist:
            print('replaying', os.path.basename(d), flush=True)
            argv2 = ['replay', os.path.join(d, 'samples'), '--workers', str(a.workers), '--tsv',
                     os.path.join(d, 'offline.tsv')]
            for im in images:
                argv2 += ['--image', im]
            shadow.main(argv2)

    names, folders = {}, {}
    p = os.path.join(REA, 'hybrid', 'build', 'ff_ports.tsv')
    for line in open(p, encoding='utf-8', errors='replace'):
        w = line.rstrip('\n').split('\t')
        if w[0].startswith('0x') and len(w) > 3:
            names[int(w[0], 16)], folders[int(w[0], 16)] = w[3], w[2]
    lists = [('exclude_level2', read_list(os.path.join(REA, 'game', 'exclude_level2.txt'))),
             ('exclude_night', read_list(os.path.join(REA, 'game', 'exclude_night.txt'))),
             ('hunt', {int(w.split('\t')[1], 16) for w in open(os.path.join(REA, 'hybrid', 'build', 'hunt.tsv'),
                                                               encoding='utf-8').read().splitlines()[1:]
                       if len(w.split('\t')) > 1 and w.split('\t')[1].startswith('0x')})]

    worst = collections.defaultdict(dict)       # fn -> image -> (verdict, diff)
    samples = collections.defaultdict(set)
    first = {}
    seen_runs = collections.defaultdict(list)
    images = []
    for d in rlist:
        t = run_tsv(d)
        if not t:
            continue
        rn = os.path.basename(d)
        for sid, fn, im, v, diff in read_rows(t):
            if im not in images and im != '-':
                images.append(im)
            samples[fn].add((rn, sid))
            first.setdefault(fn, rn)
            if rn not in seen_runs[fn]:
                seen_runs[fn].append(rn)
            cur = worst[fn].get(im)
            if cur is None or (RANK.index(v) if v in RANK else 0) > (RANK.index(cur[0]) if cur[0] in RANK else 0):
                worst[fn][im] = (v, diff)
    last = images[-1] if images else None

    def first_diff(fn):
        for im in reversed(images):
            v = worst[fn].get(im)
            if v and v[0] in BAD:
                return v[1]
        for im in reversed(images):
            v = worst[fn].get(im)
            if v and v[1]:
                return v[1]
        return ''

    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('\t'.join(['fn', 'name', 'folder', 'samples'] + images + ['first_difference', 'first_seen', 'runs',
                                                                           'listed']) + '\n')
        for fn in sorted(worst):
            listed = ','.join(n for n, s in lists if fn in s)
            f.write('\t'.join(['0x%x' % fn, names.get(fn, '')[:80], folders.get(fn, ''), str(len(samples[fn]))] +
                              [worst[fn].get(im, ('-', ''))[0] for im in images] +
                              [first_diff(fn).replace('\t', ' ')[:300], first[fn], ','.join(seen_runs[fn]), listed])
                    + '\n')
    counts = collections.Counter(worst[fn].get(last, ('-',))[0] for fn in worst)
    print('%d functions, %d samples, %d runs -> %s' % (len(worst), sum(len(s) for s in samples.values()), len(rlist),
                                                       a.out))
    print('last image (%s): %s' % (last, ', '.join('%s %d' % kv for kv in sorted(counts.items()))))

    if a.new_wrong:
        excl = read_list(a.exclude)
        order = [os.path.basename(d) for d in rlist]
        since = order.index(a.since) if a.since in order else 0
        new = [fn for fn in sorted(worst) if worst[fn].get(last, ('-',))[0] in BAD and fn not in excl
               and order.index(first[fn]) >= since]
        with open(a.new_wrong, 'w', encoding='utf-8') as f:
            f.write('# shadow testing: %s verdict mismatch or crash, not in %s (worklist.py, %d functions)\n' % (
                last, os.path.basename(a.exclude), len(new)))
            for fn in new:
                f.write('0x%x  # %s: %s %s\n' % (fn, names.get(fn, '')[:60], worst[fn][last][0],
                                                 first_diff(fn).replace('\n', ' ')[:160]))
        print('%d new wrong functions -> %s' % (len(new), a.new_wrong))
    return 0


if __name__ == '__main__':
    sys.exit(main())
