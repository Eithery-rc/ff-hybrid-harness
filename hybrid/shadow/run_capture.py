"""run_capture.py - one shadow capture run of the game: the collector, then the vanilla game with the shadow probes.

    python -I hybrid/shadow/run_capture.py --list LIST [--k 1] [--every 2000] [--script hybrid/scripts/skip_intro.txt]
        [--timeout 120] [--time-scale 4] [--workers 4] [--slots 6] [--out hybrid/build/shadow/run_<time>]
        [--image LABEL=PATH ...] [--min-free-gb 3] [--game game_shadow] [--fresh-profile] [--profile-file DAT]

The game runs from --game (default game_shadow/ next to game/): Scenes and the big read-only files are hardlinks of
game/'s, the small files copies, dinput8.dll is the shadow loader (hybrid/build/shadow) and hooks.ini is written here
(mode=none, window_park=1, keep_active=1, the input script, the shadow_* keys, profile_dir=<game>/profile seeded from
hybrid/freedom_template.ini). Nothing in game/ or in the real %APPDATA% user folder is written. Steam must run.
Each game folder has its own collector pipe and semaphore, so two folders (game_shadow, game_shadow2) can capture at
the same time. --fresh-profile deletes <game>/profile first; --profile-file copies a .dat into its Profiles folder.
The run ends at --timeout seconds, when the game exits (0xC0DEB0C5 = the crash box the parked window suppressed),
when free RAM drops below --min-free-gb, or --stop-after seconds after --stop-on shows up in ff_hybrid.log; then the
game is killed (only the process started here) and the collector drains its queue. Samples and results.tsv go to
--out; ff_shadow.log, ff_shadow_hits.tsv and ff_hybrid.log are copied there too.
"""
import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..', '..'))
GAME = os.path.join(REA, 'game')
LOADER = os.path.join(REA, 'hybrid', 'build', 'shadow', 'dinput8.dll')
TEMPLATE = os.path.join(REA, 'hybrid', 'freedom_template.ini')
LINK_EXT = ('.exe', '.wav', '.whd', '.zip')
COPY = ('eax.dll', 'steam_api.dll', 'steam_appid.txt')
CRASH_BOX_EXIT = 0xC0DEB0C5         # loader window_park: the crash message box was suppressed and the game exited


def free_gb():
    class MS(ctypes.Structure):
        _fields_ = [('len', ctypes.c_uint32), ('load', ctypes.c_uint32), ('total', ctypes.c_uint64),
                    ('avail', ctypes.c_uint64), ('tp', ctypes.c_uint64), ('ap', ctypes.c_uint64),
                    ('tv', ctypes.c_uint64), ('av', ctypes.c_uint64), ('ext', ctypes.c_uint64)]
    m = MS()
    m.len = ctypes.sizeof(m)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return m.avail / 2 ** 30


def link(src, dst):
    if os.path.exists(dst):
        if os.path.samefile(src, dst):
            return
        os.remove(dst)
    os.link(src, dst)


def copy(src, dst):
    if os.path.exists(dst):
        os.remove(dst)          # never write through: it could be a hardlink
    shutil.copy2(src, dst)


def setup(game_dir, ini):
    """The game folder: hardlinks of the read-only game files, copies of the small ones, our loader and hooks.ini."""
    os.makedirs(game_dir, exist_ok=True)
    for name in os.listdir(GAME):
        src, dst, low = os.path.join(GAME, name), os.path.join(game_dir, name), name.lower()
        if os.path.isdir(src):
            if low == 'scenes':
                for root, _, files in os.walk(src):
                    out = os.path.join(game_dir, os.path.relpath(root, GAME))
                    os.makedirs(out, exist_ok=True)
                    for f in files:
                        link(os.path.join(root, f), os.path.join(out, f))
        elif low.endswith(LINK_EXT) and low != 'launcher.exe':
            link(src, dst)
        elif low in COPY:
            copy(src, dst)
    copy(LOADER, os.path.join(game_dir, 'dinput8.dll'))
    with open(os.path.join(game_dir, 'hooks.ini'), 'w', newline='\r\n') as f:
        f.write('[hybrid]\n' + ''.join('%s=%s\n' % kv for kv in ini.items()))


def window_titles(pid):
    import ctypes.wintypes as wt
    user32 = ctypes.windll.user32
    out = []

    def cb(hwnd, _):
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            out.append(buf.value)
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)(cb), 0)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--list', required=True)
    ap.add_argument('--k', type=int, default=1)
    ap.add_argument('--every', type=int, default=2000)
    ap.add_argument('--max', type=int, default=100000)
    ap.add_argument('--script', default=os.path.join(REA, 'hybrid', 'scripts', 'skip_intro.txt'))
    ap.add_argument('--timeout', type=float, default=120)
    ap.add_argument('--time-scale', default='4')
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--slots', type=int, default=6)
    ap.add_argument('--out', default=None)
    ap.add_argument('--image', action='append', default=[])
    ap.add_argument('--min-free-gb', type=float, default=3.0)
    ap.add_argument('--frames', type=int, nargs='?', const=5, default=0,
                    help='loader frame_dump every N game seconds (5 without a value)')
    ap.add_argument('--fixed-step', default='', help='loader fixed_step (ms per frame): the script clock follows '
                    'the frames, so captures that stall the game do not shift the input script')
    ap.add_argument('--present-every', default='', help='loader present_every_ms')
    ap.add_argument('--stop-on', default='', help='end the run --stop-after seconds after this text shows up in '
                    'ff_hybrid.log (e.g. a script "log" line)')
    ap.add_argument('--stop-after', type=float, default=60)
    ap.add_argument('--game', default='game_shadow', help='game folder next to game/ (game_shadow, game_shadow2)')
    ap.add_argument('--fresh-profile', action='store_true', help='delete <game>/profile before the run')
    ap.add_argument('--profile-file', action='append', default=[],
                    help='a profile .dat copied into <game>/profile/Profiles (e.g. a copy of your own save)')
    a = ap.parse_args(argv)
    if free_gb() < a.min_free_gb:
        sys.exit('only %.1f GB of RAM free (need %.1f): not starting' % (free_gb(), a.min_free_gb))
    game_dir = os.path.join(REA, a.game)
    tag = a.game.replace('game_', '')
    pipe, sem = r'\\.\pipe\ff_%s' % tag, r'Local\ff_%s_slots' % tag
    out = os.path.abspath(a.out or os.path.join(REA, 'hybrid', 'build', 'shadow', 'run_' + time.strftime('%m%d_%H%M%S')))
    os.makedirs(out, exist_ok=True)
    profile = os.path.join(game_dir, 'profile')
    if a.fresh_profile and os.path.isdir(profile):
        shutil.rmtree(profile)
    for dat in a.profile_file:
        os.makedirs(os.path.join(profile, 'Profiles'), exist_ok=True)
        shutil.copy2(dat, os.path.join(profile, 'Profiles', os.path.basename(dat).split('_', 1)[-1]
                                       if os.path.basename(dat)[:4].isdigit() else os.path.basename(dat)))
    ini = {'mode': 'none', 'window_park': '1', 'keep_active': '1', 'input_script': os.path.abspath(a.script),
           'time_scale': a.time_scale, 'shadow_list': 'shadow_list.txt', 'shadow_k': a.k, 'shadow_every': a.every,
           'shadow_max': a.max, 'shadow_pipe': pipe, 'shadow_sem': sem, 'log_scenes': '1',
           'profile_dir': profile, 'profile_template': TEMPLATE}
    if a.frames:
        ini.update(frame_dump='1', frame_dump_every=str(a.frames), frame_dump_keep='200')
    if a.fixed_step:
        ini['fixed_step'] = a.fixed_step
    if a.present_every:
        ini['present_every_ms'] = a.present_every
    setup(game_dir, ini)
    shutil.copy(a.list, os.path.join(game_dir, 'shadow_list.txt'))
    for f in ('ff_shadow.log', 'ff_shadow_hits.tsv', 'ff_hybrid.log'):
        if os.path.exists(os.path.join(game_dir, f)):
            os.remove(os.path.join(game_dir, f))

    py = sys.executable
    log_path = os.path.join(out, 'collector.log')
    cmd = [py, '-I', os.path.join(HERE, 'collector.py'), '--out', os.path.join(out, 'samples'),
           '--workers', str(a.workers), '--slots', str(a.slots), '--pipe', pipe, '--sem', sem]
    for im in a.image:
        cmd += ['--image', im]
    with open(log_path, 'w') as log:
        if a.k:
            col = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        else:       # coverage only: the probes need no collector
            col = None
            log.write('ready (shadow_k=0, no collector)\n')
    game = None
    t0 = time.time()
    why = 'timeout'
    stop_seen = None
    try:
        for _ in range(300):
            if 'ready' in open(log_path).read() or col.poll() is not None:
                break
            time.sleep(0.2)
        if 'ready' not in open(log_path).read():
            print(open(log_path).read())
            return 1
        print('collector ready; starting the game in %s (%.1f GB free)' % (a.game, free_gb()), flush=True)
        game = subprocess.Popen([os.path.join(game_dir, 'Freedom.Exe')], cwd=game_dir)
        t0 = time.time()
        while time.time() - t0 < a.timeout:
            time.sleep(1)
            if game.poll() is not None:
                rc = game.returncode & 0xffffffff
                why = 'crash dialog (exit 0x%X)' % rc if rc == CRASH_BOX_EXIT else 'game exited 0x%X' % rc
                break
            if any('crash' in t.lower() for t in window_titles(game.pid)):
                why = 'crash dialog'
                break
            if free_gb() < a.min_free_gb:
                why = 'free RAM below %.1f GB' % a.min_free_gb
                break
            if a.stop_on and stop_seen is None:
                try:
                    if a.stop_on in open(os.path.join(game_dir, 'ff_hybrid.log'), errors='replace').read():
                        stop_seen = time.time()
                        print('"%s" in ff_hybrid.log; stopping in %ds' % (a.stop_on, a.stop_after), flush=True)
                except OSError:
                    pass
            if stop_seen is not None and time.time() - stop_seen >= a.stop_after:
                why = 'scenario done ("%s" + %ds)' % (a.stop_on, a.stop_after)
                break
    finally:
        if game is not None and game.poll() is None:
            game.kill()
            game.wait()
        el = time.time() - t0
        print('game stopped after %.0fs: %s; waiting for the collector' % (el, why), flush=True)
        try:
            if col is not None:
                col.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            col.kill()
        for f in ('ff_shadow.log', 'ff_shadow_hits.tsv', 'ff_hybrid.log'):
            p = os.path.join(game_dir, f)
            if os.path.exists(p):
                shutil.copy(p, out)
    print(open(log_path).read()[-3000:])
    print('out:', out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
