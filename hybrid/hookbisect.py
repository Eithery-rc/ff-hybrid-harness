"""hookbisect.py - find which hooked exe functions crash the hybrid game, by halving the hook list.

Each run starts game/Freedom.Exe with FF_HYBRID_MODE=list and an include file, waits up to --timeout seconds,
and counts the run as a crash when the game's "Send crash log?" dialog appears or the process exits early.
The game is killed after every run. Steam must be running.

    python -I hybrid/hookbisect.py game/camera_addrs.txt [--exclude game/align_exclude.txt] [--timeout 25]
        [--time-scale 4] [--trace] [--from-trace]

--time-scale N  speeds up the game clock N times (loader key time_scale); the frame delta is capped at 0.1 s,
                so N above about 0.1 * fps gains nothing.
--trace         loader trace=1: every crash writes a dump (last 256 hooked calls) to game/ff_hybrid.log and the
                hooks called so far to game/ff_hits.tsv. A crashing run then narrows the list to the hooks it called.
--from-trace    (implies --trace) after the first crash, try only the distinct hooks of its last 256 calls; if that
                set does not crash, try every hook the run called; if that does not crash either, the full list.
--input FILE    loader input_script (scripted DirectInput keys and mouse); it also keeps the game window active
                without focus, so --focus is not needed.

Every run turns on the loader's frame_dump (back buffer BMPs in game/frames every FRAME_EVERY game seconds); the
screenshots in game/bisect_shots are the newest frame of the run as PNG, since PrintWindow only sees white.
Every run also sets the loader's window_park: the loader itself keeps the game window right of the desktop and away
from the focus and the mouse. And profile_dir: the game's user folder (freedom.ini, Keyboard.cfg, Profiles) is
<game folder>/profile, seeded from hybrid/freedom_template.ini, so runs never touch the user's settings or profiles.
The real freedom.ini is only edited when needs_ini_park() says so: a dinput8.dll older than profile_dir, and then
--onscreen, one older than window_park, or an ini without windowed mode.

run() takes the game folder, so hunt.py can run several instances at once, each in its own folder (game_w1, ...).
What one run produces is per call (the Result it returns); the module settings below are only read during runs.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import shutil
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GAME = os.path.join(os.path.dirname(HERE), 'game')
SHOTS = os.path.join(GAME, 'bisect_shots')
SHOT_EVERY = 0      # seconds between progress screenshots during a run; 0 = only the final one (--shot-every)
FOCUS = False       # pull the game window to the foreground during runs (--focus); off so the PC stays usable
TRACE = False       # loader trace=1 (--trace)
TIME_SCALE = None   # loader time_scale (--time-scale)
INPUT = None        # loader input_script, absolute path (--input)
MAX_DUMPS = 64      # loader max_dumps during traced runs; narrowing trusts a run only when no dump was dropped
FRAME_EVERY = 5     # loader frame_dump_every: game seconds between back buffer BMPs in game/frames; 0 = no frame_dump
FRAMES = os.path.join(GAME, 'frames')
PARK = True         # loader window_park keeps the window off-screen (freedom.ini untouched); False with --onscreen
FIXED_STEP = 0      # loader fixed_step: ms of game time per frame, a virtual clock (time_scale is then ignored); 0 = off
PRESENT_EVERY_MS = 0    # loader present_every_ms: real ms between frames that reach the off-screen window; 0 = all
MSGBOX_EXIT = 0xC0DEB0C5    # exit code of a game whose message box (the crash reporter) window_park suppressed
PROFILE = True      # loader profile_dir: every game folder has its own user folder <game>/profile (freedom.ini from
                    # PROFILE_TEMPLATE, Keyboard.cfg, Profiles), so runs never read or write the user's real ones
PROFILE_TEMPLATE = os.path.join(HERE, 'freedom_template.ini')
PROFILE_SRC = None  # a user folder (e.g. game/profile_rec) copied over <game>/profile before every run, so a recorded
                    # input script always starts from the same save (--profile-src)
LOG_LOCK = threading.Lock()     # runs on several threads write the same log
user32 = ctypes.windll.user32
EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def windows(pid):
    """[(hwnd, title)] of the visible top-level windows of a process."""
    found = []

    def cb(hwnd, _):
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            found.append((hwnd, buf.value))
        return True
    user32.EnumWindows(EnumProc(cb), 0)
    return found


def window_titles(pid):
    return [t for _, t in windows(pid) if t]


def focus(pid):
    """Bring the game window to the foreground; the intro only plays while the game has focus. A synthetic ALT
    press lifts Windows' foreground lock for a background process."""
    for hwnd, title in windows(pid):
        if 'crash' not in title.lower():
            user32.keybd_event(0x12, 0, 0, 0)
            user32.keybd_event(0x12, 0, 2, 0)
            user32.ShowWindow(hwnd, 9)
            return bool(user32.SetForegroundWindow(hwnd))
    return False


def grab_window(hwnd):
    """Capture one window's content with PrintWindow, so it works off-screen and behind other windows."""
    from PIL import Image
    gdi32 = ctypes.windll.gdi32
    r = wt.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return None
    hdc = user32.GetDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mdc, bmp)
    user32.PrintWindow(hwnd, mdc, 3)            # PW_CLIENTONLY | PW_RENDERFULLCONTENT
    buf = ctypes.create_string_buffer(w * h * 4)
    bmi = struct.pack('<IiiHHIIiiII', 40, w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
    gdi32.GetDIBits(mdc, bmp, 0, h, buf, bmi, 0)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mdc)
    user32.ReleaseDC(hwnd, hdc)
    return Image.frombuffer('RGBX', (w, h), buf, 'raw', 'BGRX', 0, 1).convert('RGB')


def newest_frame(since, frames=None):
    """Newest frames/*.bmp written since the run started, or None. The loader names them by game seconds."""
    frames = frames or FRAMES
    try:
        bmps = [os.path.join(frames, n) for n in os.listdir(frames) if n.lower().endswith('.bmp')]
        bmps = [p for p in bmps if os.path.getmtime(p) >= since - 1]
        return max(bmps, key=os.path.getmtime) if bmps else None
    except OSError:
        return None


def screenshot(tag, pid=None, since=None, frames=None):
    """PNG in bisect_shots: the newest frame_dump BMP of this run when there is one (PrintWindow only sees white in a
    D3D window), else a PrintWindow capture of the game or its crash dialog, else the whole screen."""
    try:
        from PIL import Image, ImageGrab
        os.makedirs(SHOTS, exist_ok=True)
        path = os.path.join(SHOTS, '%s_%s.png' % (time.strftime('%H%M%S'), tag))
        img = None
        frame = newest_frame(since, frames) if since else None
        if frame:
            img = Image.open(frame)
            img.load()
            path = path[:-4] + '_f%s.png' % os.path.splitext(os.path.basename(frame))[0]
        elif pid:
            wins = windows(pid)
            crash = [h for h, t in wins if 'crash' in t.lower()]
            for hwnd in crash or [h for h, _ in wins]:
                img = grab_window(hwnd)
                if img:
                    break
        (img or ImageGrab.grab()).save(path)
        return path
    except Exception as e:      # a screenshot must never stop the bisection
        return 'no screenshot (%s)' % e


INI = os.path.join(os.environ.get('APPDATA', ''), 'IO Interactive', 'Freedom Fighters', 'freedom.ini')


def set_window_ini(offscreen):
    """Windowed mode, and the window parked off-screen when asked. Returns the original text to restore.
    Off-screen means right of the whole virtual desktop: a negative position crashes the original game."""
    orig = open(INI).read()
    right = user32.GetSystemMetrics(76) + user32.GetSystemMetrics(78) + 100   # SM_XVIRTUALSCREEN + SM_CXVIRTUALSCREEN
    lines = [l for l in orig.splitlines() if not l.startswith(('Window ', 'StartUpperPos '))]
    lines += ['Window 1', 'StartUpperPos %s' % ('%d 100' % right if offscreen else '320 180')]
    open(INI, 'w').write('\n'.join(lines) + '\n')
    return orig


def loader_has(game, option):
    """True when the dinput8.dll in `game` (default GAME) knows the loader option (b'WINDOW_PARK')."""
    try:
        with open(os.path.join(game or GAME, 'dinput8.dll'), 'rb') as f:
            return b'FF_HYBRID_' + option in f.read()
    except OSError:
        return False


def loader_parks(game=None):
    return loader_has(game, b'WINDOW_PARK')


def ini_windowed():
    """freedom.ini asks for windowed mode ('Window 1'); window_park cannot park a full-screen game. Only reads."""
    try:
        return any(line.strip() == 'Window 1' for line in open(INI))
    except OSError:
        return False


def needs_ini_park(game=None):
    """Whether runs in `game` still have to park the window by editing freedom.ini (set_window_ini): with --onscreen,
    with a loader older than window_park, or when the ini does not ask for windowed mode. freedom.ini is shared by
    every instance and by the user's own game, so editing it is the fallback. Never with profile_dir: the game then
    reads the template's copy in <game>/profile, not the real freedom.ini."""
    if PROFILE and loader_has(game, b'PROFILE_DIR'):
        return False
    return not (PARK and loader_parks(game) and ini_windowed())


def read_addrs(path):
    out = []
    for line in open(path):
        line = line.split('#')[0].split(';')[0].strip()
        if line:
            out.append(int(line, 16))
    return out


def read_trace(game=None):
    """(trusted, distinct, hits) of the run that just ended in `game` (default GAME): the distinct hooked addresses of
    the last crash dump in ff_hybrid.log and the hooks ff_hits.tsv says were called. trusted is False when there is no
    dump or the loader dropped dumps (max_dumps reached), because then ff_hits.tsv may predate the fatal exception."""
    game = game or GAME
    hits_path = os.path.join(game, 'ff_hits.tsv')
    try:
        text = open(os.path.join(game, 'ff_hybrid.log'), errors='replace').read()
    except OSError:
        return False, [], set()
    ndumps = text.count('== crash dump')
    k = text.rfind('== crash dump')
    if k < 0:
        return False, [], set()
    distinct = []
    for line in text[k:].splitlines()[1:]:
        if line.startswith('== end of crash dump'):
            break
        w = line.split()
        if len(w) >= 2 and w[0] == 'distinct' and w[1].startswith('0x'):
            distinct.append(int(w[1], 16))
    hits = set()
    if os.path.exists(hits_path):
        for line in open(hits_path):
            w = line.split('\t')
            if w[0].startswith('0x') and len(w) > 1 and w[1].strip() not in ('', '0'):
                hits.add(int(w[0], 16))
    return ndumps < MAX_DUMPS and bool(hits), distinct, hits


def narrow(addrs, trace):
    """Keep only the hooks a crashing run called; a hook that never ran cannot have caused the crash."""
    trusted, _, hits = trace
    keep = [a for a in addrs if a in hits] if trusted else addrs
    return keep or addrs


class Result:
    """What one run() found. Truthy when the game passed, so `if run(...)` keeps working. verdict is 'pass', 'crash',
    'exit N' or 'cancel' (stopped from outside, nothing learned); elapsed is the seconds from start to the verdict;
    trace is read_trace() of the run (with TRACE, and not for a cancelled run)."""

    def __init__(self, verdict, elapsed, trace=None):
        self.verdict, self.elapsed = verdict, elapsed
        self.trace = trace or (False, [], set())

    passed = property(lambda self: self.verdict == 'pass')
    cancelled = property(lambda self: self.verdict == 'cancel')
    crashed = property(lambda self: self.verdict not in ('pass', 'cancel'))

    def __bool__(self):
        return self.passed


def run(addrs, exclude, timeout, log, game=None, tag='', cancel=None):
    """Result of one run of the game in the folder `game` (default GAME; game_w1 and so on when runs go in parallel).
    tag ('w2') marks the log line, the screenshot and the kept crash log. A threading.Event as `cancel` stops the run
    when set."""
    game = game or GAME
    hits_path = os.path.join(game, 'ff_hits.tsv')
    with open(os.path.join(game, 'bisect_include.txt'), 'w') as f:
        f.write(''.join('%#x\n' % a for a in addrs))
    env = dict(os.environ, FF_HYBRID_MODE='list', FF_HYBRID_INCLUDE_FILE='bisect_include.txt',
               FF_HYBRID_EXCLUDE_FILE=exclude or '', FF_HYBRID_ON_ERROR='abort')
    if TRACE:
        env.update(FF_HYBRID_TRACE='1', FF_HYBRID_MAX_DUMPS=str(MAX_DUMPS))
        if os.path.exists(hits_path):
            os.remove(hits_path)
    if TIME_SCALE:
        env['FF_HYBRID_TIME_SCALE'] = str(TIME_SCALE)
    if INPUT:  # only the script's input: the devices are in background mode and would also see the user's typing
        env.update(FF_HYBRID_INPUT_SCRIPT=INPUT, FF_HYBRID_INPUT_REAL='0')
    if PROFILE and PROFILE_SRC:
        prof = os.path.join(game, 'profile')
        shutil.rmtree(prof, ignore_errors=True)
        shutil.copytree(PROFILE_SRC, prof)
    if FRAME_EVERY:
        env.update(FF_HYBRID_FRAME_DUMP='1', FF_HYBRID_FRAME_DUMP_EVERY=str(FRAME_EVERY))
    env.update(FF_HYBRID_WINDOW_PARK='1' if PARK else '0', FF_HYBRID_FIXED_STEP=str(int(FIXED_STEP or 0)),
               FF_HYBRID_PRESENT_EVERY_MS=str(int(PRESENT_EVERY_MS or 0)),
               FF_HYBRID_PROFILE_DIR=os.path.join(game, 'profile') if PROFILE else '',
               FF_HYBRID_PROFILE_TEMPLATE=PROFILE_TEMPLATE if PROFILE else '')
    frames = os.path.join(game, 'frames')
    p = subprocess.Popen([os.path.join(game, 'Freedom.Exe')], cwd=game, env=env)
    t0, verdict, focused = time.time(), 'pass', False
    last_shot = t0
    try:
        while time.time() - t0 < timeout:
            time.sleep(0.5)
            if cancel is not None and cancel.is_set():
                verdict = 'cancel'
                break
            if p.poll() is not None:
                # with window_park the loader ends the game at its crash message box instead of showing it
                verdict = 'crash' if p.returncode & 0xffffffff == MSGBOX_EXIT else 'exit %d' % p.returncode
                break
            if any('crash' in t.lower() for t in window_titles(p.pid)):
                verdict = 'crash'
                break
            if FOCUS and (not focused or int(time.time() - t0) % 10 == 0):
                focused = focus(p.pid) or focused
            if SHOT_EVERY and time.time() - last_shot >= SHOT_EVERY:
                screenshot('%st%03d_%d' % (tag and tag + '_', time.time() - t0, len(addrs)), p.pid, t0, frames)
                last_shot = time.time()
        elapsed = time.time() - t0
        shot = '-' if verdict == 'cancel' else os.path.basename(screenshot(
            '%s%s_%d' % (tag and tag + '_', verdict.split()[0], len(addrs)),
            p.pid if p.poll() is None else None, t0, frames))
    finally:
        if p.poll() is None:        # also when the hunt is interrupted: no orphaned game
            p.kill()
            p.wait()
    time.sleep(2)   # let the window and Steam settle before the next start
    line = '%s%-7s %4d hooks  %.1fs  focus=%s  %s  %s' % (
        tag and tag + ' ', verdict, len(addrs), time.time() - t0, 'yes' if focused else 'no', shot,
        ' '.join('%#x' % a for a in addrs[:6]) + (' ...' if len(addrs) > 6 else ''))
    result = Result(verdict, elapsed)
    if TRACE and not result.cancelled:
        result.trace = read_trace(game)
        trusted, distinct, hits = result.trace
        line += '\n        trace: %s, %d distinct in the last calls, %d hooks called' % (
            'dump' if trusted else 'no trusted dump', len(distinct), len(hits))
    if result.crashed and len(addrs) <= KEEP_LOG_HOOKS:
        # ff_hybrid.log is rewritten at every start: keep the crash dump of a narrowed-down run. A worker folder
        # keeps it in its own crash_logs first, then it moves to the shared one.
        os.makedirs(os.path.join(game, 'crash_logs'), exist_ok=True)
        name = '%s_%s%s.log' % (time.strftime('%Y%m%d_%H%M%S'), tag and tag + '_',
                               '_'.join('%x' % a for a in addrs) or 'none')
        keep = os.path.join(game, 'crash_logs', name)
        try:
            shutil.copyfile(os.path.join(game, 'ff_hybrid.log'), keep)
            if os.path.abspath(game) != os.path.abspath(GAME):
                os.makedirs(DUMPS, exist_ok=True)
                keep = shutil.move(keep, os.path.join(DUMPS, name))
            line += '\n        log kept: %s' % os.path.basename(keep)
        except OSError:
            pass
    with LOG_LOCK:
        print(line, flush=True)
        log.write(line + '\n')
        log.flush()
    return result


KEEP_LOG_HOOKS = 3      # crash runs with at most this many hooks keep a copy of ff_hybrid.log in DUMPS
DUMPS = os.path.join(GAME, 'crash_logs')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('include', help='address list that crashes')
    ap.add_argument('--exclude', default='', help='exclude file next to the exe (relative to game/)')
    ap.add_argument('--timeout', type=float, default=25)
    ap.add_argument('--shot-every', type=float, default=0, help='progress screenshot interval in seconds')
    ap.add_argument('--focus', action='store_true', help='pull the game window to the foreground')
    ap.add_argument('--onscreen', action='store_true', help='keep the window visible instead of parking it off-screen')
    ap.add_argument('--time-scale', type=float, default=None, help='speed up the game clock (loader time_scale)')
    ap.add_argument('--trace', action='store_true', help='loader trace=1: crash dumps, hit counts, narrowing')
    ap.add_argument('--from-trace', action='store_true',
                    help='start from the hooks of the first crash dump (implies --trace)')
    ap.add_argument('--input', default=None,
                    help='loader input_script for every run (e.g. hybrid/scripts/skip_intro.txt); also keeps the game '
                         'active without focus')
    a = ap.parse_args()
    global SHOT_EVERY, FOCUS, TRACE, TIME_SCALE, INPUT, PARK
    SHOT_EVERY, FOCUS = a.shot_every, a.focus
    TRACE, TIME_SCALE = a.trace or a.from_trace, a.time_scale
    INPUT = os.path.abspath(a.input) if a.input else None
    PARK = not a.onscreen
    if INPUT and not os.path.exists(INPUT):
        sys.exit('no input script %s' % INPUT)
    orig = set_window_ini(not a.onscreen) if needs_ini_park() else None
    try:
        bisect_list(a)
    finally:
        if orig is not None:
            open(INI, 'w').write(orig)


def say(log, msg):
    with LOG_LOCK:
        print(msg, flush=True)
        log.write(msg + '\n')
        log.flush()


def from_trace(addrs, full, a, log):
    """--from-trace: smallest crashing start set among (distinct hooks of the first dump, hooks it called, all).
    full is the Result of the crashing run of the whole list."""
    trusted, distinct, hits = full.trace
    if not trusted:
        say(log, 'from-trace: the full run left no trusted crash dump; bisecting the full list')
        return addrs
    cand = [x for x in addrs if x in set(distinct)]
    if cand and len(cand) < len(addrs):
        say(log, 'from-trace: trying the %d distinct hooks of the last calls before the crash' % len(cand))
        res = run(cand, a.exclude, a.timeout, log)
        if not res:
            return narrow(cand, res.trace)
        say(log, 'from-trace: they do not crash alone (the damage happened earlier)')
    called = narrow(addrs, full.trace)
    if len(called) < len(addrs):
        say(log, 'from-trace: trying the %d hooks the crashing run called' % len(called))
        res = run(called, a.exclude, a.timeout, log)
        if not res:
            return narrow(called, res.trace)
        say(log, 'from-trace: they do not crash alone; bisecting the full list')
    return addrs


def bisect_list(a):
    addrs = read_addrs(a.include)
    with open(os.path.join(GAME, 'bisect.log'), 'a') as log:
        log.write('=== %s  %s (%d)  time_scale=%s trace=%s from_trace=%s\n' % (
            time.ctime(), a.include, len(addrs), TIME_SCALE, TRACE, a.from_trace))
        if not run([], a.exclude, a.timeout, log):
            sys.exit('baseline with no hooks fails; fix that first')
        full = run(addrs, a.exclude, a.timeout, log)
        if full:
            sys.exit('the full list does not crash within the timeout')
        if a.from_trace:
            addrs = from_trace(addrs, full, a, log)
        elif TRACE:
            addrs = narrow(addrs, full.trace)
        while len(addrs) > 1:
            half = len(addrs) // 2
            lo, hi = addrs[:half], addrs[half:]
            part, res = lo, run(lo, a.exclude, a.timeout, log)
            if res:
                part, res = hi, run(hi, a.exclude, a.timeout, log)
            if res:
                msg = 'neither half crashes alone: an interaction between %d and %d hooks' % (len(lo), len(hi))
                print(msg)
                log.write(msg + '\n')
                return
            addrs = narrow(part, res.trace) if TRACE else part
        msg = 'culprit: %#x' % addrs[0]
        print(msg)
        log.write(msg + '\n')


if __name__ == '__main__':
    main()
