"""Offline test of hunt.py --workers and hookbisect.run(): a fake game (no Freedom.Exe is started), fake RAM, a fake
freedom.ini. Everything lives in a temp sandbox; the real game/, game_w*/ and %APPDATA% freedom.ini are never written.

    python -I hybrid/test/test_hunt_parallel.py [quick]

The sandbox is set up before hookbisect is imported (APPDATA points into it, so hookbisect.INI does too) and guard()
aborts the run when any path the tests write resolves to a real one. Each test also has to leave no thread behind.
"""
import hashlib
import io
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REAL_APPDATA = os.environ.get('APPDATA', '')
REAL_INI = os.path.join(REAL_APPDATA, 'IO Interactive', 'Freedom Fighters', 'freedom.ini')
MARKER = 'HuntParallelTestMarker 1'       # in the fake ini text: finding it in the real ini means a leak
ORIG_INI = 'Resolution 1280x720\nWindow 0\nStartUpperPos 100 100\n%s\n' % MARKER
SANDBOX = tempfile.mkdtemp(prefix='hunt_test_')
tempfile.tempdir = SANDBOX                   # every other temp folder of the tests is inside it
os.environ['APPDATA'] = os.path.join(SANDBOX, 'appdata')
os.makedirs(os.path.join(os.environ['APPDATA'], 'IO Interactive', 'Freedom Fighters'))
sys.path.insert(0, os.path.dirname(HERE))
import hookbisect as B  # noqa: E402
import hunt  # noqa: E402

B.GAME, B.SHOTS, B.FRAMES, B.DUMPS = (os.path.join(SANDBOX, n) for n in ('game', 'shots', 'frames', 'crash_logs'))
hunt.ALL, hunt.TSV = os.path.join(SANDBOX, 'all_addrs.txt'), os.path.join(SANDBOX, 'hunt.tsv')
open(B.INI, 'w').write(ORIG_INI)

QUICK = 'quick' in sys.argv
REAL_RUN = B.run
CANDS = list(range(0x401000, 0x401000 + 96 * 16, 16))


def guard():
    """Abort when a path the tests write is outside the temp folder or is the real game, worker or settings path."""
    real = [os.path.normcase(os.path.abspath(p)) for p in (
        os.path.join(REAL_APPDATA, 'IO Interactive'), os.path.join(ROOT, 'game'), os.path.join(ROOT, 'hybrid', 'build'))]
    temp = os.path.normcase(os.path.abspath(tempfile.gettempdir()))
    for label, path in (('B.INI', B.INI), ('B.GAME', B.GAME), ('B.SHOTS', B.SHOTS), ('B.FRAMES', B.FRAMES),
                        ('B.DUMPS', B.DUMPS), ('hunt.ALL', hunt.ALL), ('hunt.TSV', hunt.TSV)):
        p = os.path.normcase(os.path.abspath(path))
        if any(p.startswith(r) for r in real) or not p.startswith(temp):
            sys.exit('ABORT: %s = %s is not a sandbox path' % (label, path))


def no_threads_left(name):
    """A thread that outlives its test (a Park or worker thread, a Timer) could write into the next test's files."""
    for _ in range(60):
        extra = [t.name for t in threading.enumerate() if t is not threading.main_thread()]
        if not extra:
            return
        time.sleep(0.05)
    sys.exit('ABORT: %s left threads running: %s' % (name, extra))


guard()


def make_game(root):
    files = {
        'Freedom.Exe': 'exe', 'Launcher.exe': 'exe', 'dinput8.dll': 'dll', 'steam_api.dll': 'dll', 'eax.dll': 'dll',
        'ff_ports.bin': 'ports-old', 'ff_hooks.bin': 'hooks', 'ff_names.bin': 'names', 'streams.wav': 'wav',
        'ff_ports.bin.prev': 'prev', 'dinput8.dll.prev': 'prev',
        'Scenes/FF-Intro.ZIP': 'z', 'Scenes/FF-Intro.WHD': 'w', 'Scenes/Singleplayer/L1.ZIP': 'z', 'Scenes/credits.txt': 'c',
        'hooks.ini': '[hybrid]\nmode=none\n', 'steam_appid.txt': '1234', 'exclude_x.txt': '0x401010\n',
        'all_addrs.txt': '0x401000\n', 'align_exclude.txt': '',
        'ff_hybrid.log': 'log', 'ff_hits.tsv': 'hits', 'bisect_include.txt': '0x1\n', 'bisect.log': 'blog',
        'error.log': 'err', 'frames/00001.bmp': 'bmp', 'frames_level1/00001.bmp': 'bmp', 'crash_logs/c.log': 'c',
        'bisect_shots/s.png': 'png', 'profile/freedom.ini': 'Window 1', 'profile/Profiles/FREEDOM FIGHTER.dat': 'p',
    }
    for name, text in files.items():
        path = os.path.join(root, *name.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, 'w').write(text)
    return root


def digest(path):
    return hashlib.sha1(open(path, 'rb').read()).hexdigest()


class Sim:
    """Fake B.run: crash(addrs) -> seconds until the crash or None. Records every run."""

    def __init__(self, crash, pass_s=0.02, poll=0.002):
        self.crash, self.pass_s, self.poll = crash, pass_s, poll
        self.lock = threading.Lock()
        self.runs = []                  # (tag, game, n hooks, verdict)
        self.busy = {}                  # game -> True while a run is in it
        self.live = self.max_live = 0
        self.errors = []
        self.on_start = None

    def run(self, addrs, exclude, timeout, log, game=None, tag='', cancel=None):
        with self.lock:
            if self.busy.get(game):
                self.errors.append('two runs at once in %s' % game)
            self.busy[game] = True
            self.live += 1
            self.max_live = max(self.max_live, self.live)
            if open(B.INI).read() == ORIG_INI:
                self.errors.append('window not parked during a run')
        if self.on_start:
            self.on_start()
        t = self.crash(set(addrs))
        dur = min(timeout, t if t is not None else self.pass_s)
        verdict, t0 = 'crash' if t is not None and t <= timeout else 'pass', time.time()
        while time.time() - t0 < dur:
            time.sleep(self.poll)
            if cancel is not None and cancel.is_set():
                verdict = 'cancel'
                break
        with self.lock:
            self.busy[game] = False
            self.live -= 1
            self.runs.append((tag, game, len(addrs), verdict))
        return B.Result(verdict, time.time() - t0)


class Env:
    def __init__(self, sim, free=8.0, **kw):
        self.tmp = tempfile.mkdtemp()
        self.game = make_game(os.path.join(self.tmp, 'game'))
        self.logs = []
        self.free = free
        self.sim = sim
        B.GAME, B.INI = self.game, os.path.join(self.tmp, 'freedom.ini')
        open(B.INI, 'w').write(ORIG_INI)
        B.run = sim.run
        B.say = lambda log, msg: self.logs.append(msg)
        hunt.available_gb = lambda: self.free() if callable(self.free) else self.free
        self.kw = dict(stagger=0, min_free_gb=1.5, kill=[], restart_steam=False, exclude='exclude_x.txt', timeout=1.0)
        self.kw.update(kw)
        guard()

    def pool(self, workers):
        return hunt.Pool(types.SimpleNamespace(workers=workers, **self.kw), None)


def solve(env, workers, cands=CANDS, timeout=None):
    pool = env.pool(workers)
    t0 = time.time()
    got = hunt.find_one(list(cands), [], pool, timeout)
    return got, time.time() - t0, pool


def check_clean(env, pool):
    assert not env.sim.errors, env.sim.errors
    assert open(B.INI).read() == ORIG_INI, 'freedom.ini not restored'
    assert pool.park.count == 0 and pool.active == 0


# ---- tests ----------------------------------------------------------------------------------------------------------

def test_single_culprit():
    for workers in (1, 2, 3, 4):
        for c in (CANDS[0], CANDS[1], CANDS[47], CANDS[48], CANDS[-1], random.choice(CANDS)):
            env = Env(Sim(lambda s, c=c: 0.01 if c in s else None))
            got, _, pool = solve(env, workers)
            assert got == c, (workers, hex(got), hex(c))
            check_clean(env, pool)
            assert env.sim.max_live <= workers
            assert all(g == env.game if not t else g.endswith('game_' + t) for t, g, _, _ in env.sim.runs)


def test_two_singles_lowest_wins():
    """Two hooks that each crash alone: every worker count ends at the one with the lower position, like the
    sequential halving (lo before hi)."""
    random.seed(7)
    for _ in range(12 if QUICK else 40):
        a, b = sorted(random.sample(CANDS, 2))
        for workers in (1, 2, 3, 4, 5):
            # the later hook crashes sooner: it must not win while an earlier part is still running
            env = Env(Sim(lambda s, a=a, b=b: 0.03 if a in s else (0.005 if b in s else None)))
            got, _, pool = solve(env, workers)
            assert got == a, (workers, hex(got), hex(a), hex(b))
            check_clean(env, pool)


def test_combinations():
    """Crash only with all of a set present: the answer is a member of the set, and workers=2 repeats what the
    sequential run finds (same algorithm)."""
    random.seed(11)
    for _ in range(10 if QUICK else 30):
        size = random.choice((2, 2, 3, 4))
        group = set(random.sample(CANDS, size))
        base_result = None
        for workers in (1, 2, 3, 4):
            env = Env(Sim(lambda s, g=group: 0.005 if g <= s else None, pass_s=0.01))
            got, _, pool = solve(env, workers)
            assert got in group, (workers, hex(got), sorted(map(hex, group)))
            check_clean(env, pool)
            if workers == 1:
                base_result = got
            if workers == 2:
                assert got == base_result, (hex(got), hex(base_result))


def test_combination_with_base():
    """The base set stays enabled in every run of a round."""
    group = {CANDS[5], CANDS[70]}
    seen = []
    env = Env(Sim(lambda s: (seen.append(len(s)), 0.005)[1] if group <= s else None, pass_s=0.01))
    got, _, pool = solve(env, 2)
    assert got in group
    check_clean(env, pool)


def test_no_crash_and_baseline():
    env = Env(Sim(lambda s: None, pass_s=0.01))
    pool = env.pool(2)
    assert pool.run([]) and bool(pool.run([1, 2]))
    check_clean(env, pool)
    # hunt_loop with a game that never crashes: PASS and nothing to narrow
    hunt.ALL, hunt.TSV = os.path.join(env.tmp, 'all.txt'), os.path.join(env.tmp, 'hunt.tsv')
    open(hunt.ALL, 'w').write(''.join('%#x\n' % x for x in CANDS))
    a = types.SimpleNamespace(max=3, timeout=1.0, workers=2)
    hunt.hunt_loop(a, pool, os.path.join(env.tmp, 'ex.txt'), {}, {}, time.time() + 60)
    assert any(m.startswith('PASS') for m in env.logs), env.logs
    assert not os.path.exists(hunt.TSV)


def test_hunt_loop_many_culprits():
    """Whole hunt: culprits that crash alone are found one by one in the same order for every worker count; the
    narrowing timeout comes from the elapsed time of the full run."""
    culprits = [CANDS[40], CANDS[9], CANDS[81]]
    order = None
    for workers in (1, 2, 3):
        env = Env(Sim(lambda s: 0.02 if s & set(culprits) else None, pass_s=0.03))
        hunt.ALL, hunt.TSV = os.path.join(env.tmp, 'all.txt'), os.path.join(env.tmp, 'hunt.tsv')
        open(hunt.ALL, 'w').write(''.join('%#x\n' % x for x in CANDS))
        ex = os.path.join(env.tmp, 'exclude_x.txt')
        open(ex, 'w').write('')
        pool = env.pool(workers)
        a = types.SimpleNamespace(max=10, timeout=1.0, workers=workers)
        hunt.hunt_loop(a, pool, ex, {}, {}, time.time() + 120)
        found = [int(l.split()[0], 16) for l in open(ex) if l.strip()]
        assert sorted(found) == sorted(culprits), (workers, found)
        order = order or found
        assert found == order, (workers, found, order)
        assert any(m.startswith('PASS') for m in env.logs)
        assert any('narrowing runs stop at' in m for m in env.logs)
        check_clean(env, pool)
        tsv = [l.split('\t')[1] for l in open(hunt.TSV)][1:]
        assert [int(x, 16) for x in tsv] == found


def test_early_kill_rules():
    # a lower part crashing kills the running higher one
    env = Env(Sim(lambda s: 0.03 if 1 in s else (0.6 if 2 in s else None), pass_s=0.6), timeout=1.0)
    pool = env.pool(2)
    t0 = time.time()
    hit = hunt.first_crash(pool, [], [[1], [2]], 1.0)
    took = time.time() - t0
    assert hit == 0 and took < 0.35, (hit, took)
    assert sorted(v for *_, v in env.sim.runs) == ['cancel', 'crash'], env.sim.runs
    check_clean(env, pool)
    # a higher part crashing first does not kill the lower one: it runs to its own verdict and wins
    env = Env(Sim(lambda s: 0.25 if 1 in s else (0.02 if 2 in s else None)))
    pool = env.pool(2)
    t0 = time.time()
    hit = hunt.first_crash(pool, [], [[1], [2]], 1.0)
    assert hit == 0 and time.time() - t0 >= 0.25
    assert sorted(v for *_, v in env.sim.runs) == ['crash', 'crash'], env.sim.runs
    check_clean(env, pool)
    # a higher part crashing while the lower one passes: answer is the higher part, after the lower one ended
    env = Env(Sim(lambda s: 0.02 if 2 in s else None, pass_s=0.15))
    pool = env.pool(2)
    t0 = time.time()
    hit = hunt.first_crash(pool, [], [[1], [2]], 1.0)
    assert hit == 1 and time.time() - t0 >= 0.15
    assert sorted(v for *_, v in env.sim.runs) == ['crash', 'pass'], env.sim.runs
    # more parts than instances: parts above a crash are never started
    env = Env(Sim(lambda s: 0.03 if 1 in s else None, pass_s=0.2))
    pool = env.pool(2)
    hit = hunt.first_crash(pool, [], [[1], [2], [3], [4]], 1.0)
    assert hit == 0 and len(env.sim.runs) == 2, env.sim.runs
    check_clean(env, pool)
    # no part crashes: all of them run, answer None
    env = Env(Sim(lambda s: None, pass_s=0.02))
    pool = env.pool(3)
    assert hunt.first_crash(pool, [], [[1], [2], [3], [4]], 1.0) is None and len(env.sim.runs) == 4
    assert env.sim.max_live == 3
    check_clean(env, pool)


def test_ram_budget():
    env = Env(Sim(lambda s: 0.01 if CANDS[3] in s else None), free=2.0)
    got, _, pool = solve(env, 3)
    assert got == CANDS[3] and env.sim.max_live == 1, env.sim.max_live
    assert any(m.startswith('ram: 2.0 GB') for m in env.logs), env.logs
    env = Env(Sim(lambda s: 0.01 if CANDS[3] in s else None), free=3.6)
    got, _, pool = solve(env, 3)
    assert got == CANDS[3] and env.sim.max_live == 3 and not any(m.startswith('ram:') for m in env.logs)
    env = Env(Sim(lambda s: 0.01 if CANDS[3] in s else None), free=2.6)
    got, _, pool = solve(env, 4)
    assert got == CANDS[3] and env.sim.max_live == 2, env.sim.max_live
    check_clean(env, pool)
    # below the minimum with nothing running: the hunt stops, nothing was started, the ini is intact
    env = Env(Sim(lambda s: None), free=1.0)
    pool = env.pool(2)
    try:
        hunt.find_one(list(CANDS), [], pool)
        raise AssertionError('no MemoryLow')
    except hunt.MemoryLow:
        pass
    assert not env.sim.runs
    check_clean(env, pool)


def test_low_ram_while_running_waits():
    """Another instance is up and RAM is short: the start waits for it (no stop, no Steam restart); with nothing
    running, Steam is restarted when asked to, and never while an instance is up."""
    state = {}
    restarts = []

    def free():
        return 1.0 if state['pool'].active else 6.0     # an instance is up: short of RAM
    env = Env(Sim(lambda s: 0.01 if CANDS[3] in s else None), free=free, restart_steam=True)
    old = hunt.restart_steam
    hunt.restart_steam = lambda log: restarts.append(state['pool'].active)
    try:
        pool = env.pool(2)
        state['pool'] = pool
        got = hunt.find_one(list(CANDS), [], pool)
    finally:
        hunt.restart_steam = old
    assert got == CANDS[3] and env.sim.max_live == 1, env.sim.max_live
    assert not restarts
    check_clean(env, pool)
    # idle and short: Steam restart (once, nothing running), then the run goes on
    low = {'v': True}
    restarts.clear()
    env = Env(Sim(lambda s: None, pass_s=0.01), free=lambda: 1.0 if low['v'] else 6.0, restart_steam=True)
    pool = env.pool(2)
    state['pool'] = pool

    def fake_restart(log):
        restarts.append(pool.active)
        low['v'] = False
    hunt.restart_steam = fake_restart
    try:
        assert pool.run([])
    finally:
        hunt.restart_steam = old
    assert restarts == [0], restarts
    check_clean(env, pool)


def test_error_in_a_run_stops_the_round():
    env = Env(Sim(lambda s: None, pass_s=0.5))
    fired = []

    def boom():
        if not fired:
            fired.append(1)
            time.sleep(0.05)
            raise hunt.MemoryLow()
    env.sim.on_start = boom
    pool = env.pool(3)
    t0 = time.time()
    try:
        hunt.first_crash(pool, [], [[1], [2], [3]], 1.0)
        raise AssertionError('no exception')
    except hunt.MemoryLow:
        pass
    assert time.time() - t0 < 0.4, 'running instances were not stopped'
    check_clean(env, pool)


def test_ctrl_c_stops_every_instance():
    import _thread
    env = Env(Sim(lambda s: None, pass_s=3.0))
    pool = env.pool(3)
    threading.Timer(0.3, _thread.interrupt_main).start()
    t0 = time.time()
    try:
        hunt.first_crash(pool, [], [[1], [2], [3]], 5.0)
        raise AssertionError('no KeyboardInterrupt')
    except KeyboardInterrupt:
        pass
    assert time.time() - t0 < 1.5, time.time() - t0
    # every instance is down when first_crash raises (an instance that had not started yet is simply not started)
    assert env.sim.live == 0 and env.sim.runs and {v for *_, v in env.sim.runs} == {'cancel'}, env.sim.runs
    check_clean(env, pool)


def test_park_refcount():
    ini = os.path.join(tempfile.mkdtemp(), 'freedom.ini')
    open(ini, 'w').write(ORIG_INI)
    B.INI = ini
    park = hunt.Park()
    with park:
        parked = open(ini).read()
        assert parked != ORIG_INI and 'Window 1' in parked
        with park:
            pass
        assert open(ini).read() == parked, 'restored while an instance is still up'
    assert open(ini).read() == ORIG_INI
    try:
        with park:
            raise RuntimeError
    except RuntimeError:
        pass
    assert open(ini).read() == ORIG_INI and park.count == 0


def test_sync_worker():
    root = tempfile.mkdtemp()
    game = make_game(os.path.join(root, 'game'))
    B.GAME = game
    w1 = os.path.join(root, 'game_w1')
    hunt.sync_worker(w1, tree=True)
    listing = sorted(os.path.relpath(os.path.join(d, f), w1).replace('\\', '/') for d, _, fs in os.walk(w1) for f in fs)
    assert listing == sorted([
        'Freedom.Exe', 'Launcher.exe', 'dinput8.dll', 'steam_api.dll', 'eax.dll', 'ff_ports.bin', 'ff_hooks.bin',
        'ff_names.bin', 'streams.wav', 'Scenes/FF-Intro.ZIP', 'Scenes/FF-Intro.WHD', 'Scenes/Singleplayer/L1.ZIP',
        'Scenes/credits.txt', 'hooks.ini', 'steam_appid.txt', 'exclude_x.txt', 'all_addrs.txt', 'align_exclude.txt']), listing
    linked = {'Freedom.Exe', 'Launcher.exe', 'dinput8.dll', 'steam_api.dll', 'eax.dll', 'ff_ports.bin', 'ff_hooks.bin',
              'ff_names.bin', 'streams.wav'}
    for rel in listing:
        same = os.path.samefile(os.path.join(game, rel), os.path.join(w1, rel))
        assert same == (rel in linked or rel.startswith('Scenes/')), rel
    # what a run writes in the worker folder never reaches game/
    before = {n: digest(os.path.join(game, n)) for n in ('ff_hybrid.log', 'ff_hits.tsv', 'bisect_include.txt', 'bisect.log',
                                                         'error.log', 'hooks.ini', 'exclude_x.txt')}
    for n in ('ff_hybrid.log', 'ff_hits.tsv', 'bisect_include.txt', 'error.log', 'hooks.ini', 'exclude_x.txt'):
        with open(os.path.join(w1, n), 'w') as f:       # truncate, as the game, the loader and run() do
            f.write('worker only')
    os.makedirs(os.path.join(w1, 'frames'), exist_ok=True)
    open(os.path.join(w1, 'frames', '1.bmp'), 'w').write('x')
    for n, h in before.items():
        assert digest(os.path.join(game, n)) == h, '%s in game/ changed' % n
    assert open(os.path.join(game, 'frames', '00001.bmp')).read() == 'bmp'
    assert not os.path.exists(os.path.join(game, 'frames', '1.bmp'))
    # nothing in game/ that a run writes is linked anywhere
    for n in ('ff_hybrid.log', 'ff_hits.tsv', 'bisect_include.txt', 'bisect.log', 'error.log', 'hooks.ini'):
        assert os.stat(os.path.join(game, n)).st_nlink == 1, n
    # config copies come back to game/'s content on the next sync
    hunt.sync_worker(w1, tree=False)
    assert open(os.path.join(w1, 'hooks.ini')).read() == open(os.path.join(game, 'hooks.ini')).read()
    assert open(os.path.join(w1, 'exclude_x.txt')).read() == '0x401010\n'
    # the exclude file grows in game/ (the hunt appends a culprit): the worker copy follows
    open(os.path.join(game, 'exclude_x.txt'), 'a').write('0x401020\n')
    hunt.sync_worker(w1, tree=False)
    assert open(os.path.join(w1, 'exclude_x.txt')).read() == '0x401010\n0x401020\n'
    # a build replaces ff_ports.bin with a new file: the stale link is relinked
    new = os.path.join(game, 'ff_ports.bin.new')
    open(new, 'w').write('ports-new')
    os.replace(new, os.path.join(game, 'ff_ports.bin'))
    assert open(os.path.join(w1, 'ff_ports.bin')).read() == 'ports-old'
    hunt.sync_worker(w1, tree=False)
    assert open(os.path.join(w1, 'ff_ports.bin')).read() == 'ports-new'
    assert os.path.samefile(os.path.join(game, 'ff_ports.bin'), os.path.join(w1, 'ff_ports.bin'))
    # a copy that was once a link is not written through
    os.remove(os.path.join(w1, 'hooks.ini'))
    os.link(os.path.join(game, 'hooks.ini'), os.path.join(w1, 'hooks.ini'))
    hunt.sync_worker(w1, tree=False)
    assert not os.path.samefile(os.path.join(game, 'hooks.ini'), os.path.join(w1, 'hooks.ini'))


def test_run_with_fake_process():
    """The real hookbisect.run() with a fake process: tags, cancel, crash log move, Result, per-call state."""
    root = tempfile.mkdtemp()
    main_game, wgame = os.path.join(root, 'game'), os.path.join(root, 'game_w2')
    for g in (main_game, wgame):
        os.makedirs(g)
        open(os.path.join(g, 'Freedom.Exe'), 'w').write('x')
    B.GAME, B.DUMPS, B.TRACE = main_game, os.path.join(main_game, 'crash_logs'), True
    B.time = types.SimpleNamespace(time=time.time, sleep=lambda s: time.sleep(min(s, 0.02)), strftime=time.strftime,
                                   ctime=time.ctime)
    B.screenshot = lambda tag, pid=None, since=None, frames=None: os.path.join(root, 'shot_%s.png' % tag)
    started = []
    crash_after = {'s': 0.05, 't0': 0}

    class Proc:
        pid = 1

        def __init__(self, cmd, cwd=None, env=None):
            started.append((cmd, cwd, env))
            self.returncode = None
            crash_after['t0'] = time.time()
            # what the loader leaves in its folder
            open(os.path.join(cwd, 'ff_hybrid.log'), 'w').write('== crash dump\ndistinct 0x401000\n== end of crash dump\n')
            open(os.path.join(cwd, 'ff_hits.tsv'), 'w').write('exe_addr\thits\n0x401000\t5\n')

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = 1

        def wait(self):
            pass
    B.subprocess = types.SimpleNamespace(Popen=Proc)
    B.window_titles = lambda pid: (['Send crash log?'] if crash_after['s'] is not None
                                   and time.time() - crash_after['t0'] >= crash_after['s'] else [])
    log = io.StringIO()
    res = REAL_RUN([0x401000], 'ex.txt', 5, log, wgame, 'w2')
    assert res.crashed and not res.passed and not res.cancelled and not res and res.verdict == 'crash'
    assert started[-1][1] == wgame and started[-1][0] == [os.path.join(wgame, 'Freedom.Exe')]
    assert open(os.path.join(wgame, 'bisect_include.txt')).read() == '0x401000\n'
    assert not os.path.exists(os.path.join(main_game, 'bisect_include.txt')), 'wrote into game/'
    assert res.trace[0] is True and res.trace[2] == {0x401000}, res.trace
    assert log.getvalue().startswith('w2 crash '), log.getvalue()
    assert 'shot_w2_crash_1.png' in log.getvalue()
    kept = os.listdir(B.DUMPS)
    assert len(kept) == 1 and kept[0].endswith('_w2_401000.log'), kept
    assert not os.path.exists(os.path.join(wgame, 'crash_logs', kept[0])), 'not moved'
    # a cancelled run: no screenshot, no trace, no kept log, killed
    crash_after['s'] = None
    ev = threading.Event()
    threading.Timer(0.1, ev.set).start()
    log = io.StringIO()
    res = REAL_RUN([0x401000], 'ex.txt', 5, log, wgame, 'w2', ev)
    assert res.cancelled and not res.crashed and not res.passed and res.verdict == 'cancel'
    assert log.getvalue().startswith('w2 cancel ') and ' - ' in log.getvalue() and 'trace' not in log.getvalue()
    assert len(os.listdir(B.DUMPS)) == 1
    # untagged, default folder: the format of a single-instance hunt
    crash_after['s'] = 0.05
    log = io.StringIO()
    res = REAL_RUN([0x401000, 0x401010], 'ex.txt', 5, log, main_game)
    assert log.getvalue().startswith('crash   '), log.getvalue()
    assert len(os.listdir(B.DUMPS)) == 2
    # a pass at the timeout
    crash_after['s'] = None
    log = io.StringIO()
    res = REAL_RUN([0x401000], 'ex.txt', 0.6, log, wgame, 'w1')
    assert res.passed and res and log.getvalue().startswith('w1 pass ')


def test_bisect_cli_still_works():
    """hookbisect's own CLI path (bisect_list) on Results: plain, --trace and --from-trace."""
    random.seed(1)
    all_ = sorted(random.sample(range(0x401000, 0x675000, 16), 3000))
    called = set(random.sample(all_, 400))
    culprit = sorted(called)[200]
    late = [a for a in sorted(called) if a != culprit][-40:]
    for trace, ft in ((False, False), (True, False), (False, True)):
        tmp = tempfile.mkdtemp()
        B.GAME = tmp
        lst = os.path.join(tmp, 'list.txt')
        open(lst, 'w').write(''.join('%#x\n' % a for a in all_))
        runs = []

        def fake(addrs, exclude, timeout, log, game=None, tag='', cancel=None):
            runs.append(len(addrs))
            s = set(addrs)
            if culprit in s:
                return B.Result('crash', 1.0, (True, [a for a in late if a in s], {a for a in called if a in s}))
            return B.Result('pass', 1.0)
        B.run, B.TRACE = fake, trace or ft
        out = []
        real_print, B.print = print, lambda *x, **k: out.append(' '.join(map(str, x)))
        try:
            B.bisect_list(types.SimpleNamespace(include=lst, exclude='', timeout=1, from_trace=ft))
        finally:
            del B.print
        assert ['culprit: %#x' % culprit] == [l for l in out if l.startswith('culprit')], (trace, ft, out[-3:])
    B.TRACE = False


def test_speed():
    """Wall time of a single-culprit search over 2000 hooks for 1..4 workers. Fake runs: a crash after 0.15 s, a pass
    takes the whole 0.25 s timeout (the real ratio is about 35 s to 60 s), so start-up costs stay small."""
    random.seed(3)
    cands = list(range(0x401000, 0x401000 + 2000 * 16, 16))
    picks = [random.choice(cands) for _ in range(2 if QUICK else 5)]
    rows = []
    for workers in (1, 2, 3, 4):
        tot = 0
        for c in picks:
            env = Env(Sim(lambda s, c=c: 0.15 if c in s else None, pass_s=0.25))
            got, took, pool = solve(env, workers, cands, 0.25)
            assert got == c
            tot += took
        rows.append((workers, tot / len(picks)))
    print('  mean wall time per search (fake runs): ' + ', '.join('%d workers %.2fs (x%.2f)' % (w, t, rows[0][1] / t)
                                                                 for w, t in rows))


def test_loader_window_park():
    """A dinput8.dll with window_park and a windowed freedom.ini: runs leave the ini alone (the loader parks the
    window). An older dll, a full-screen ini or --onscreen (PARK False) still go through the ini, restored after."""
    windowed = ORIG_INI.replace('Window 0', 'Window 1')
    saved = B.PARK
    try:
        for workers in (1, 2):
            env = Env(Sim(lambda s: None, pass_s=0.01))
            open(B.INI, 'w').write(windowed)
            dll = os.path.join(env.game, 'dinput8.dll')
            os.remove(dll)                  # a new file: worker links must follow on the next sync
            open(dll, 'wb').write(b'MZ\0FF_HYBRID_WINDOW_PARK\0')
            seen = []
            env.sim.on_start = lambda: seen.append(open(B.INI).read())
            pool = env.pool(workers)
            assert pool.run([]) and pool.run([1])
            assert seen == [windowed, windowed] and open(B.INI).read() == windowed, seen
            for case in ('old dll', 'full screen', 'onscreen'):
                if case == 'old dll':
                    os.remove(dll)
                    open(dll, 'w').write('dll')
                elif case == 'full screen':
                    os.remove(dll)
                    open(dll, 'wb').write(b'MZ\0FF_HYBRID_WINDOW_PARK\0')
                    windowed = ORIG_INI
                    open(B.INI, 'w').write(windowed)
                else:
                    windowed = ORIG_INI.replace('Window 0', 'Window 1')
                    open(B.INI, 'w').write(windowed)
                    B.PARK = False
                seen.clear()
                assert pool.run([])
                assert seen[0] != windowed and 'StartUpperPos' in seen[0], (case, seen)
                assert open(B.INI).read() == windowed and pool.park.count == 0, case
            B.PARK = True
            windowed = ORIG_INI.replace('Window 0', 'Window 1')
    finally:
        B.PARK = saved


def test_run_env_loader_options():
    """run() passes window_park, fixed_step and present_every_ms to the loader, and a crash dialog still ends the run
    as a crash."""
    root = tempfile.mkdtemp()
    game = os.path.join(root, 'game')
    os.makedirs(game)
    open(os.path.join(game, 'Freedom.Exe'), 'w').write('x')
    B.GAME, B.DUMPS = game, os.path.join(game, 'crash_logs')
    B.time = types.SimpleNamespace(time=time.time, sleep=lambda s: time.sleep(min(s, 0.02)), strftime=time.strftime,
                                   ctime=time.ctime)
    B.screenshot = lambda tag, pid=None, since=None, frames=None: os.path.join(root, 'shot_%s.png' % tag)
    envs = []

    class Proc:
        pid = 1

        def __init__(self, cmd, cwd=None, env=None):
            envs.append(env)
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = 1

        def wait(self):
            pass
    B.subprocess = types.SimpleNamespace(Popen=Proc)
    B.window_titles = lambda pid: ['Send crash log?']
    saved = B.PARK, B.FIXED_STEP, B.PRESENT_EVERY_MS
    keys = ('FF_HYBRID_WINDOW_PARK', 'FF_HYBRID_FIXED_STEP', 'FF_HYBRID_PRESENT_EVERY_MS')
    try:
        B.FIXED_STEP, B.PRESENT_EVERY_MS = 50, 250
        res = REAL_RUN([], '', 5, io.StringIO(), game)
        assert res.crashed and res.verdict == 'crash', res.verdict
        assert tuple(envs[-1][k] for k in keys) == ('1', '50', '250'), envs[-1]
        B.PARK, B.FIXED_STEP, B.PRESENT_EVERY_MS = False, 0, 0
        assert REAL_RUN([], '', 5, io.StringIO(), game).crashed
        assert tuple(envs[-1][k] for k in keys) == ('0', '0', '0'), envs[-1]
        # window_park suppressed the crash message box and ended the game with MSGBOX_EXIT: a crash, not 'exit N'
        B.window_titles = lambda pid: []
        for code, verdict in ((B.MSGBOX_EXIT, 'crash'), (1, 'exit 1')):
            Proc.poll = lambda self, code=code: setattr(self, 'returncode', code) or code
            res = REAL_RUN([], '', 5, io.StringIO(), game)
            assert res.verdict == verdict and res.crashed, (code, res.verdict)
    finally:
        B.PARK, B.FIXED_STEP, B.PRESENT_EVERY_MS = saved


def test_profile_dir():
    """With a dinput8.dll that has profile_dir, run() gives every game folder its own user folder <game>/profile seeded
    from the template, the real freedom.ini is never parked (even when it asks for full screen), and a worker folder
    never gets game/'s profile (no shared FREEDOM FIGHTER.dat)."""
    saved = B.PARK, B.PROFILE
    try:
        env = Env(Sim(lambda s: None, pass_s=0.01))     # B.INI holds ORIG_INI: full screen
        dll = os.path.join(env.game, 'dinput8.dll')
        os.remove(dll)
        open(dll, 'wb').write(b'MZ\0FF_HYBRID_WINDOW_PARK\0FF_HYBRID_PROFILE_DIR\0')
        seen = []
        env.sim.on_start = lambda: seen.append(open(B.INI).read())
        for workers in (1, 2):
            pool = env.pool(workers)
            assert pool.run([]) and pool.run([1])
            assert seen and all(x == ORIG_INI for x in seen) and open(B.INI).read() == ORIG_INI, seen
            seen.clear()
        assert not B.needs_ini_park(env.game)
        B.PARK = False                                  # --onscreen: the template's position, still no ini edit
        assert not B.needs_ini_park(env.game)
        B.PARK, B.PROFILE = True, False                 # profile_dir off: back to window_park and the ini check
        assert B.needs_ini_park(env.game)
        w1 = os.path.join(env.tmp, 'game_w1')
        assert os.path.isdir(w1) and not os.path.exists(os.path.join(w1, 'profile')), os.listdir(w1)
    finally:
        B.PARK, B.PROFILE = saved
    # run(): FF_HYBRID_PROFILE_DIR is the run's own folder, the template the repo's
    root = tempfile.mkdtemp()
    game = os.path.join(root, 'game_w2')
    os.makedirs(game)
    open(os.path.join(game, 'Freedom.Exe'), 'w').write('x')
    B.GAME, B.DUMPS = game, os.path.join(game, 'crash_logs')
    B.time = types.SimpleNamespace(time=time.time, sleep=lambda s: time.sleep(min(s, 0.02)), strftime=time.strftime,
                                   ctime=time.ctime)
    B.screenshot = lambda tag, pid=None, since=None, frames=None: os.path.join(root, 'shot.png')
    envs = []

    class Proc:
        pid = 1

        def __init__(self, cmd, cwd=None, env=None):
            envs.append(env)
            self.returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = 1

        def wait(self):
            pass
    B.subprocess = types.SimpleNamespace(Popen=Proc)
    B.window_titles = lambda pid: ['Send crash log?']
    REAL_RUN([], '', 5, io.StringIO(), game)
    assert envs[-1]['FF_HYBRID_PROFILE_DIR'] == os.path.join(game, 'profile'), envs[-1]['FF_HYBRID_PROFILE_DIR']
    assert envs[-1]['FF_HYBRID_PROFILE_TEMPLATE'] == B.PROFILE_TEMPLATE and os.path.isfile(B.PROFILE_TEMPLATE)
    assert 'Window 1' in open(B.PROFILE_TEMPLATE).read().splitlines()


SAVED = {(mod, n): getattr(mod, n) for mod, ns in (
    (B, ('GAME', 'INI', 'DUMPS', 'TRACE', 'subprocess', 'screenshot', 'window_titles', 'run', 'say', 'time')),
    (hunt, ('available_gb', 'ALL', 'TSV', 'restart_steam'))) for n in ns}


def real_ini_state():
    """(sha1 or None, whether the fake ini text is in it). Read only."""
    try:
        data = open(REAL_INI, 'rb').read()
    except OSError:
        return None, False
    return hashlib.sha1(data).hexdigest(), MARKER.encode() in data


def main():
    names = [n for n in sorted(globals()) if n.startswith('test_')]
    sha_before, leaked = real_ini_state()
    if leaked:
        sys.exit('ABORT: the real freedom.ini already holds the test marker; restore it first')
    for name in names:
        t0 = time.time()
        guard()
        try:
            globals()[name]()
        finally:
            for (mod, n), v in SAVED.items():
                setattr(mod, n, v)
        guard()
        no_threads_left(name)
        print('ok  %-38s %.1fs' % (name, time.time() - t0), flush=True)
    sha_after, leaked = real_ini_state()
    if leaked:
        sys.exit('FAIL: the test marker is in the real freedom.ini')
    shutil.rmtree(SANDBOX, ignore_errors=True)
    print('real freedom.ini: sha1 %s before, %s after (%s), test marker absent' % (
        sha_before, sha_after, 'same' if sha_before == sha_after else 'differs: a running hunt parks and restores it'))


if __name__ == '__main__':
    main()
