"""hunt.py - run the hybrid with every hook enabled, and while it crashes, find one culprit, exclude it, repeat.

Each culprit goes into the exclude file (with its name from map-data-public.json and its port folder) and into
hybrid/build/hunt.tsv. Uses hookbisect.run() for the game runs, so the same off-screen window, time scale, trace and
input options apply. When neither half of a list crashes alone, the search keeps one half enabled and looks in the
other (one member of a crashing combination is enough: excluding it breaks the crash).

    python -I hybrid/hunt.py --timeout 60 --time-scale 4 [--input hybrid/scripts/skip_intro.txt] [--max 40]
        [--workers 2] [--fixed-step 50] [--present-every-ms 250]

--workers N runs N game instances at once, each in its own folder game_w1..game_wN next to game/ (the big files are
hardlinks of game/'s, the small config files copies; see sync_worker). A narrowing round splits the candidates into N
parts and runs base + part for all of them together. The part with the lowest index that crashes becomes the new
candidate set, the same pick as the sequential halving (lo before hi). Once part j has crashed, the parts above j can
no longer change the answer: they are not started, and running ones are killed. Parts below j run to their verdict,
because one of them crashing would take priority. Default 1: one instance in game/, no tags in the log.
"""
import argparse
import contextlib
import ctypes
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hookbisect as B  # noqa: E402

BUILD = os.path.join(HERE, 'build')
ALL = os.path.join(B.GAME, 'all_addrs.txt')
TSV = os.path.join(BUILD, 'hunt.tsv')


def names():
    mp = os.path.join(BUILD, 'map-data-public.json')   # function map from the ReFreedomFighters progress page
    m = {f[0]: f for f in json.load(open(mp))['functions']} if os.path.exists(mp) else {}
    folders = {}
    for line in open(os.path.join(BUILD, 'ff_ports.tsv')):
        w = line.rstrip('\n').split('\t')
        if w[0].startswith('0x'):
            folders[int(w[0], 16)] = (w[2], w[3] if len(w) > 3 else '')
    return m, folders


def excluded(path):
    return set(B.read_addrs(path)) if os.path.exists(path) else set()


SUB_FACTOR, SUB_MARGIN = 1.3, 10     # narrowing timeout = crash time of the full run x factor + margin
RAM_PER_EXTRA_GB = 1.0               # free RAM kept for each instance beyond the first, on top of --min-free-gb


class MemoryLow(Exception):
    pass


def available_gb():
    class MS(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ulong), ('load', ctypes.c_ulong)] + \
                   [(n, ctypes.c_ulonglong) for n in ('total', 'avail', 'tpage', 'apage', 'tvirt', 'avirt', 'xvirt')]
    m = MS()
    m.len = ctypes.sizeof(MS)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return m.avail / 2**30


STEAM = os.environ.get('FF_STEAM_EXE', r'C:\Program Files (x86)\Steam\steam.exe')   # for --restart-steam


def running(image):
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq %s' % image, '/NH'], capture_output=True, text=True).stdout
    return image.lower() in out.lower()


def restart_steam(log):
    """steamwebhelper keeps ~75 MB per game launch (measured 2026-10-22) and never gives it back; a graceful Steam
    restart (shutdown, then start minimised to the tray) returns it. The game needs Steam running to start."""
    B.say(log, 'steam: restarting to release steamwebhelper memory (%.1f GB available)' % available_gb())
    subprocess.run([STEAM, '-shutdown'], capture_output=True)
    for _ in range(90):
        if not running('steam.exe'):
            break
        time.sleep(1)
    subprocess.Popen([STEAM, '-silent'], creationflags=subprocess.DETACHED_PROCESS)
    time.sleep(60)          # login and webhelper start before SteamAPI_Init can succeed
    B.say(log, 'steam: back (%s), %.1f GB available' % ('running' if running('steam.exe') else 'NOT running',
                                                       available_gb()))


def before_run(a, log, idle=True):
    """Never run the game on a starved PC (--kill closes memory-hungry background programs first).
    True when a run may start. With other instances running (idle=False) Steam is never restarted and the hunt does
    not stop: low RAM returns False and the caller waits for an instance to end."""
    for name in a.kill:
        subprocess.run(['taskkill', '/F', '/IM', name], capture_output=True)
    if available_gb() < a.min_free_gb and a.restart_steam and idle:
        restart_steam(log)
    if available_gb() < a.min_free_gb:
        if not idle:
            return False
        B.say(log, 'STOP: only %.1f GB of RAM available (minimum %.1f)' % (available_gb(), a.min_free_gb))
        raise MemoryLow()
    return True


# A worker folder is a second copy of game/ for one more instance. The big files the game only reads are hardlinks of
# game/'s (the same file: no disk space, and a build that replaces the original is picked up by relinking), the small
# config and list files are copies. Never link a file a run writes or truncates (loader log, hit table, include list,
# frames, crash logs, screenshots): truncating a hardlink rewrites the original in game/ too.
LINK_EXT = ('.exe', '.dll', '.bin', '.wav', '.whd', '.zip')     # game files, only read
RUN_OUTPUT = ('ff_hits.tsv', 'bisect_include.txt')              # written by runs (and every *.log, *.tmp)
SKIP_EXT = ('.log', '.tmp', '.prev', '.bak')
SKIP_DIRS = ('frames', 'crash_logs', 'bisect_shots', 'profile')  # prefixes: frames_level1 holds old shots;
# profile: each instance's own user folder (loader profile_dir), never linked or copied


def unlink(path):
    try:
        os.remove(path)
    except PermissionError:         # read-only attribute; only ever a copy or a stale link here
        os.chmod(path, stat.S_IWRITE)
        os.remove(path)


def link_file(src, dst):
    """dst becomes a hardlink of src; a link to an older file (a build replaced src) is relinked."""
    if os.path.exists(dst):
        if os.path.samefile(src, dst):
            return
        unlink(dst)
    os.link(src, dst)


def copy_file(src, dst):
    """dst becomes a copy of src when size or mtime differ. The old dst is removed first, never written through: it
    could be a hardlink of src."""
    if os.path.exists(dst):
        s, d = os.stat(src), os.stat(dst)
        if (s.st_size, s.st_mtime_ns) == (d.st_size, d.st_mtime_ns) and not os.path.samefile(src, dst):
            return
        unlink(dst)
    shutil.copy2(src, dst)


def link_tree(src, dst):
    for root, _, files in os.walk(src):
        out = os.path.join(dst, os.path.relpath(root, src))
        os.makedirs(out, exist_ok=True)
        for f in files:
            link_file(os.path.join(root, f), os.path.join(out, f))


def sync_worker(dst, tree):
    """Bring the worker folder dst up to date with game/. tree also mirrors the folders (Scenes), which only change
    with a new game install, so that is done once when the hunt starts; the files are checked before every run
    (ff_ports.bin and the exclude file change while a hunt runs)."""
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(B.GAME):
        src, out, low = os.path.join(B.GAME, name), os.path.join(dst, name), name.lower()
        if os.path.isdir(src):
            if tree and not low.startswith(SKIP_DIRS):
                link_tree(src, out)
        elif low in RUN_OUTPUT or low.endswith(SKIP_EXT):
            continue
        elif low.endswith(LINK_EXT):
            link_file(src, out)
        else:
            copy_file(src, out)


class Park:
    """freedom.ini (shared by every instance) has the window off-screen while any instance is starting or running and
    is restored to its original text when none is: a reference count under a lock. As a context manager around a run
    it restores after every run when one instance is all there is, so a hunt killed from outside (for example by
    a parent process on low memory) leaves the user's game settings intact."""

    def __init__(self):
        self.lock = threading.Lock()
        self.count, self.orig = 0, None

    def __enter__(self):
        with self.lock:
            if not self.count:
                self.orig = B.set_window_ini(True)
            self.count += 1

    def __exit__(self, *exc):
        with self.lock:
            self.count -= 1
            if not self.count:
                open(B.INI, 'w').write(self.orig)


class Worker:
    def __init__(self, tag, game):
        self.tag, self.game = tag, game


class Pool:
    """The game instances of a hunt: one in game/ without a tag, or --workers of them in game_w1.. tagged w1.."""

    def __init__(self, a, log):
        self.a, self.log = a, log
        if a.workers > 1:
            root = os.path.dirname(B.GAME)
            self.workers = [Worker('w%d' % i, os.path.join(root, 'game_w%d' % i)) for i in range(1, a.workers + 1)]
            for w in self.workers:
                sync_worker(w.game, tree=True)
            B.say(log, 'workers: %d instances in %s .. %s' % (a.workers, self.workers[0].game, self.workers[-1].game))
        else:
            self.workers = [Worker('', B.GAME)]
        self.idle = list(self.workers)
        self.active = 0                 # instances taken: from start() to finish(), killed and settled
        self.cv = threading.Condition()
        self.park = Park()
        self.stagger = a.stagger if a.workers > 1 else 0
        self.next_start = 0.0

    def budget(self, parts):
        """How many of `parts` runs may go at once: the workers, cut down to what the free RAM allows (min_free_gb for
        the first instance, RAM_PER_EXTRA_GB more for each further one) instead of stopping the hunt. Called between
        rounds, when nothing runs."""
        n = min(parts, len(self.workers))
        if n > 1:
            with self.cv:
                before_run(self.a, self.log)
            free = available_gb()
            want, n = n, max(1, min(n, int((free - self.a.min_free_gb) / RAM_PER_EXTRA_GB) + 1))
            if n < want:
                B.say(self.log, 'ram: %.1f GB available, %d of %d instances this round' % (free, n, want))
        return n

    def start(self):
        """A free instance, once the memory guard allows a start. Steam is restarted and the hunt stops on low RAM only
        while nothing runs; with instances up, a start on low RAM waits for one of them to end."""
        with self.cv:
            while not (self.idle and before_run(self.a, self.log, idle=not self.active)):
                self.cv.wait(5)
            w = self.idle.pop(0)
            self.active += 1
            at = max(time.time(), self.next_start)
            self.next_start = at + self.stagger         # no two instances load the profile and ini at the same time
        try:
            if w.tag:
                sync_worker(w.game, tree=False)
            time.sleep(max(0, at - time.time()))
        except BaseException:
            self.finish(w)
            raise
        return w

    def finish(self, w):
        with self.cv:
            self.idle.append(w)
            self.idle.sort(key=self.workers.index)
            self.active -= 1
            self.cv.notify_all()

    def run(self, addrs, timeout=None, cancel=None):
        """hookbisect.Result of one run on a free instance, with the window parked off-screen while it is up: by the
        loader's window_park when the instance's dinput8.dll has it, else through freedom.ini (Park)."""
        w = self.start()
        try:
            if cancel is not None and cancel.is_set():
                return B.Result('cancel', 0.0)
            with self.park if B.needs_ini_park(w.game) else contextlib.nullcontext():
                return B.run(sorted(addrs), self.a.exclude, timeout or self.a.timeout, self.log, w.game, w.tag, cancel)
        finally:
            self.finish(w)


def split(cands, n):
    """n contiguous parts of cands, sizes as equal as possible (n = 2: cands[:len // 2] and the rest)."""
    return [cands[i * len(cands) // n:(i + 1) * len(cands) // n] for i in range(n)]


def first_crash(pool, base, parts, timeout):
    """Index of the lowest-numbered part that crashes with base always enabled, or None when none does. The parts
    start in index order on as many instances as the pool allows at once (all of them, one at a time with a single
    instance). Once part j has crashed, the parts above j cannot change the answer: the ones not started are dropped
    and the running ones killed. Parts below j keep running, because one of them crashing would take priority."""
    n = len(parts)
    cancels = [threading.Event() for _ in parts]
    st = {'next': 0, 'best': n, 'error': None}      # best: lowest crashing index so far, n while none
    lock = threading.Lock()

    def work():
        while True:
            with lock:
                i = st['next']
                if i >= st['best'] or st['error']:
                    return
                st['next'] += 1
            try:
                res = pool.run(base + parts[i], timeout, cancels[i])
            except BaseException as e:      # MemoryLow, or Ctrl-C: stop the other instances too
                with lock:
                    st['error'] = st['error'] or e
                for c in cancels:
                    c.set()
                return
            if res.crashed:
                with lock:
                    if i < st['best']:
                        st['best'] = i
                        for c in cancels[i + 1:]:
                            c.set()

    limit = pool.budget(n)
    if limit > 1:
        B.say(pool.log, 'round: %d parts (%s hooks) on %d instances' % (n, '/'.join(str(len(p)) for p in parts), limit))
    def work_then(done):
        try:
            work()
        finally:
            done.set()              # after the run's finally blocks: the game is killed, the instance is free

    # Thread.join cannot be used to wait here: a Ctrl-C inside join() makes CPython 3.12 mark the thread as finished
    # while it still runs, so a second join returns at once and a game could be left running. Events do not do that.
    dones = [threading.Event() for _ in range(limit if limit > 1 else 0)]
    for d in dones:
        threading.Thread(target=work_then, args=(d,), daemon=True).start()
    if not dones:
        work()                      # one instance: in this thread, parts one after the other
    try:
        for d in dones:
            while not d.wait(0.5):  # with a timeout, so that Ctrl-C gets through on Windows
                pass
    except BaseException:           # Ctrl-C while waiting: no game is left running
        for c in cancels:
            c.set()
        for d in dones:
            d.wait()
        raise
    if st['error']:
        raise st['error']
    return st['best'] if st['best'] < n else None


def find_one(cands, base, pool, timeout=None):
    """One culprit among cands, with base always enabled. cands + base is known to crash. Each round splits cands into
    one part per instance (two halves with a single instance) and takes the lowest-numbered part that crashes."""
    while len(cands) > 1:
        parts = split(cands, max(2, min(pool.a.workers, len(cands))))
        hit = first_crash(pool, base, parts, timeout)
        if hit is None and len(parts) > 2:
            # no part crashes alone: regroup into two halves and try those, so that the rule below keeps a half
            # that passed with base (hi) enabled
            k = len(parts) // 2
            parts = [[x for p in parts[:k] for x in p], [x for p in parts[k:] for x in p]]
            hit = first_crash(pool, base, parts, timeout)
        if hit is not None:
            cands = parts[hit]
        else:
            lo, hi = parts
            B.say(pool.log, 'combination: %d + %d hooks crash only together; keeping the second half on' % (
                len(lo), len(hi)))
            base, cands = base + hi, lo
    return cands[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exclude', default='exclude_map.txt', help='exclude file in game/, culprits are appended')
    ap.add_argument('--timeout', type=float, default=60)
    ap.add_argument('--time-scale', type=float, default=4)
    ap.add_argument('--input', default=None)
    ap.add_argument('--max', type=int, default=40, help='stop after this many culprits')
    ap.add_argument('--hours', type=float, default=8, help='stop starting new hunts after this long')
    ap.add_argument('--kill', action='append', default=[], help='process image to stop before every run (repeatable)')
    ap.add_argument('--min-free-gb', type=float, default=1.5,
                    help='stop when less RAM than this is available; each instance beyond the first needs 1 GB more '
                         'free, else the round runs fewer instances')
    ap.add_argument('--restart-steam', action='store_true', help='on low RAM, restart Steam once before stopping')
    ap.add_argument('--workers', type=int, default=1,
                    help='game instances at once, in game_w1..game_wN next to game/ (1: a single run in game/)')
    ap.add_argument('--stagger', type=float, default=4,
                    help='seconds between two instance starts with --workers above 1')
    ap.add_argument('--fixed-step', type=int, default=0,
                    help='loader fixed_step: ms of game time per frame, a virtual clock that makes runs repeatable '
                         '(--time-scale is then ignored); 0 = off')
    ap.add_argument('--present-every-ms', type=int, default=250,
                    help='loader present_every_ms: real ms between frames that reach the off-screen window (the game '
                         'still renders every frame and frame_dump still sees them); 0 = every frame, about 24 fps')
    ap.add_argument('--profile-src', default=None,
                    help='user folder copied fresh into each instance\'s profile before every run (e.g. game/profile_rec '
                         'for a script recorded from a save)')
    a = ap.parse_args()
    if a.workers < 1:
        sys.exit('--workers must be at least 1')
    B.TIME_SCALE = a.time_scale
    B.FIXED_STEP, B.PRESENT_EVERY_MS = a.fixed_step, a.present_every_ms
    B.INPUT = os.path.abspath(a.input) if a.input else None
    B.PROFILE_SRC = os.path.abspath(a.profile_src) if a.profile_src else None
    B.TRACE = True          # hit counts and crash dumps; narrowing only trusts runs that left a dump
    exfile = os.path.join(B.GAME, a.exclude)
    fmap, folders = names()
    t_end = time.time() + a.hours * 3600
    try:
        with open(os.path.join(B.GAME, 'bisect.log'), 'a') as log:
            B.say(log, '=== hunt %s  timeout %s  %s  present_every_ms %d  input %s%s' % (
                time.ctime(), a.timeout, 'fixed_step %d ms' % a.fixed_step if a.fixed_step else 'x%s' % a.time_scale,
                a.present_every_ms, a.input, '  workers %d' % a.workers if a.workers > 1 else ''))
            pool = Pool(a, log)
            if not pool.run([]):
                sys.exit('baseline with no hooks fails; fix that first')
            hunt_loop(a, pool, exfile, fmap, folders, t_end)
    except MemoryLow:
        pass


def record(culprit, n, exfile, fmap, folders, log):
    f = fmap.get(culprit)
    nm = (f[3] if f and f[3] else folders.get(culprit, ('', '?'))[1]) or '?'
    folder = folders.get(culprit, ('?', ''))[0]
    B.say(log, 'CULPRIT %d: %#x %s (%s)' % (n, culprit, nm, folder))
    with open(exfile, 'a') as fx:
        fx.write('%#x  # hunt %s: %s (%s)\n' % (culprit, time.strftime('%Y-%m-%d %H:%M'), nm, folder))
    new = not os.path.exists(TSV)
    with open(TSV, 'a', encoding='utf-8') as ft:
        if new:
            ft.write('found\texe_addr\tname\tfolder\n')
        ft.write('%s\t%#x\t%s\t%s\n' % (time.strftime('%Y-%m-%d %H:%M'), culprit, nm, folder))


def hunt_loop(a, pool, exfile, fmap, folders, t_end):
    log = pool.log
    for n in range(1, a.max + 1):
        if time.time() > t_end:
            B.say(log, 'time budget used up')
            return
        ex = excluded(exfile)
        allv = [x for x in B.read_addrs(ALL) if x not in ex]
        full = pool.run(allv)
        if full:
            B.say(log, 'PASS: %d hooks run the scenario without a crash' % len(allv))
            return
        # a subset that outlives this crash by a margin is clean for this culprit; a later crash is the next round's.
        # Not capped at --timeout: a crash close to the timeout comes a little later in a subset, and cutting that
        # run short would read as a pass (the scenario has no quit, so the game just stays in the level).
        sub = min(2 * a.timeout, full.elapsed * SUB_FACTOR + SUB_MARGIN)
        cands = B.narrow(allv, full.trace)
        B.say(log, 'crash after %.0f s: narrowing runs stop at %.0f s%s' % (full.elapsed, sub, (
            '; trace: %d of %d hooks were called before the crash' % (len(cands), len(allv))
            if len(cands) < len(allv) else '')))
        record(find_one(cands, [], pool, sub), n, exfile, fmap, folders, log)


if __name__ == '__main__':
    main()
