"""collector.py - the live side of shadow testing: receive probe hits from the shadow loader, replay each sample while
its process clone is alive, and save it for offline replays.

    python -I hybrid/shadow/collector.py --out DIR [--image LABEL=PATH ...] [--exe PATH] [--workers 4] [--slots 6]
        [--pipe NAME] [--sem NAME]

It creates the pipe (\\\\.\\pipe\\ff_shadow) and a semaphore with --slots free slots (Local\\ff_shadow_slots), prints
'ready', then waits for the game. Each message from shadow.c carries a clone handle already duplicated into this
process. A worker process gets its own duplicate, reads the clone through ReadProcessMemory (sample.CloneSource),
runs the original and every image's port (replay.py), writes DIR/<fn>_<seq>.ffs with every page the replays read,
closes the clone and frees the slot. One line per sample goes to DIR/results.tsv. The collector stops when the game
closes the pipe and the queue is empty (or after --idle seconds without a message).
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import multiprocessing as mp
import os
import queue
import struct
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MSG_FMT = '<12I3Q716s4x'          # shadow.c Msg, padded to 8 bytes by the compiler
MSG_SIZE = struct.calcsize(MSG_FMT)
MSG_MAGIC = 0x4d534646
PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE, PIPE_WAIT = 1, 0, 0
DUPLICATE_SAME_ACCESS, DUPLICATE_CLOSE_SOURCE = 2, 1
PROCESS_DUP_HANDLE = 0x40

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.CreateNamedPipeW.restype = wt.HANDLE
k32.CreateNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CreateSemaphoreW.restype = wt.HANDLE
k32.CreateSemaphoreW.argtypes = [ctypes.c_void_p, wt.LONG, wt.LONG, wt.LPCWSTR]
k32.ReleaseSemaphore.argtypes = [wt.HANDLE, wt.LONG, ctypes.c_void_p]
k32.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.GetCurrentProcess.restype = wt.HANDLE
k32.DuplicateHandle.argtypes = [wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL,
                                wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]


def parse_msg(b):
    v = struct.unpack(MSG_FMT, b)
    (magic, size, seq, fn, tid, k, teb, pid, clone, tick, clock, stack_limit, qpc, qpf, ft, ctx) = v
    if magic != MSG_MAGIC or size != MSG_SIZE:
        raise ValueError('bad message (magic 0x%x, size %d)' % (magic, size))
    return {'fn': fn, 'seq': seq, 'tid': tid, 'k': k, 'teb': teb, 'pid': pid, 'clone': clone, 'stack_limit': stack_limit,
            'time': {'tick': tick, 'clock': clock, 'qpc': qpc, 'qpf': qpf, 'ft': ft}, 'context': ctx.hex()}


# ============================================================================ worker
_W = {}


def _init(exe_path, image_specs, out):
    import replay
    _W['exe'] = replay.Exe(exe_path) if exe_path else replay.Exe()
    _W['images'] = [replay.Image(p, lb) for lb, p in image_specs]
    _W['out'] = out


def record(job):
    """Replay one sample against the live clone and save it. Returns the result row."""
    import replay
    from sample import CloneSource
    h, header = job
    t0 = time.time()
    row = {'seq': header['seq'], 'fn': header['fn'], 'k': header['k'], 'tid': header['tid'], 'verdicts': {},
           'orig': '', 'pages': 0, 'secs': 0.0, 'error': ''}
    path = os.path.join(_W['out'], '%06x_%05d.ffs' % (header['fn'], header['seq']))
    src = None
    try:
        src = CloneSource(h, dict(header, clone=None))
        replay.discover(src, _W['exe'])
        env, orig, res = replay.replay(src, _W['exe'], _W['images'])
        row['orig'] = '%s %s' % (orig.end, orig.detail)
        for label, (v, diffs, q) in res.items():
            row['verdicts'][label] = (v, diffs[:4], round(q.secs, 3) if q else 0)
        src.header['record'] = {'orig': row['orig'], 'orig_secs': round(orig.secs, 3), 'calls': len(orig.calls)}
        src.header['verdicts'] = row['verdicts']
    except Exception:
        row['error'] = traceback.format_exc()[-1500:]
        if src is not None:
            src.header['error'] = row['error']
    finally:
        if src is not None:
            exe = _W['exe']
            row['pages'] = src.save(path, skip=lambda p: exe.text_lo <= p < exe.text_hi)
        k32.CloseHandle(h)
    row['secs'] = round(time.time() - t0, 3)
    row['path'] = path
    return row


# ============================================================================ main process
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--image', action='append', default=[])
    ap.add_argument('--exe', default=None)
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--slots', type=int, default=6)
    ap.add_argument('--pipe', default=r'\\.\pipe\ff_shadow')
    ap.add_argument('--sem', default=r'Local\ff_shadow_slots')
    ap.add_argument('--idle', type=float, default=0, help='stop after this many seconds without a message (0: never)')
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    import shadow
    specs = [(im.label, im.path) for im in shadow.load_images(a.image)]

    sem = k32.CreateSemaphoreW(None, a.slots, a.slots, a.sem)
    pipe = k32.CreateNamedPipeW(a.pipe, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 1 << 20, 0, None)
    if not sem or pipe in (None, wt.HANDLE(-1).value):
        sys.exit('cannot create the pipe or semaphore (error %d)' % ctypes.get_last_error())
    pool = mp.get_context('spawn').Pool(a.workers, initializer=_init, initargs=(a.exe, specs, a.out))
    print('ready: pipe %s, %d slots, %d workers, images %s' % (a.pipe, a.slots, a.workers,
                                                                ', '.join(lb for lb, _ in specs)), flush=True)

    msgs = queue.Queue()

    def reader():
        k32.ConnectNamedPipe(pipe, None)    # returns when the game connects (or already connected)
        print('game connected', flush=True)
        buf = ctypes.create_string_buffer(MSG_SIZE)
        while True:
            got, n = b'', wt.DWORD()
            while len(got) < MSG_SIZE:
                if not k32.ReadFile(pipe, buf, MSG_SIZE - len(got), ctypes.byref(n), None) or not n.value:
                    msgs.put(None)
                    return
                got += buf.raw[:n.value]
            msgs.put(got)

    threading.Thread(target=reader, daemon=True).start()
    tsv_path = os.path.join(a.out, 'results.tsv')
    new = not os.path.exists(tsv_path)
    tsv = open(tsv_path, 'a', encoding='utf-8')
    if new:
        tsv.write('seq\tfn\tcall\ttid\timage\tverdict\tdiff\torig\tpages\tsecs\terror\n')
    pending = []
    stats = {'n': 0, 't0': time.time(), 'last': time.time()}
    done_pipe = False

    def collect(block=False):
        for r in list(pending):
            if block or r.ready():
                row = r.get()
                pending.remove(r)
                k32.ReleaseSemaphore(sem, 1, None)
                stats['n'] += 1
                for label, (v, diffs, secs) in (row['verdicts'] or {'-': ('error', [], 0)}).items():
                    tsv.write('%d\t0x%x\t%d\t%d\t%s\t%s\t%s\t%s\t%d\t%.2f\t%s\n' % (
                        row['seq'], row['fn'], row['k'], row['tid'], label, v, '; '.join(diffs)[:500].replace('\t', ' '),
                        row['orig'][:200], row['pages'], row['secs'], row['error'].strip().splitlines()[-1][:200]
                        if row['error'] else ''))
                tsv.flush()
                if stats['n'] <= 20 or stats['n'] % 50 == 0:
                    vs = ' '.join('%s=%s' % (lb, x[0]) for lb, x in row['verdicts'].items())
                    print('%5d 0x%06x call %d  %-60s %5.2fs %4d pages%s' % (
                        row['seq'], row['fn'], row['k'], vs[:60], row['secs'], row['pages'],
                        '  ERROR ' + row['error'].strip().splitlines()[-1][:120] if row['error'] else ''), flush=True)

    try:
        while True:
            collect()
            try:
                m = msgs.get(timeout=0.2)
            except queue.Empty:
                if done_pipe and not pending:
                    break
                if a.idle and time.time() - stats['last'] > a.idle and not pending:
                    print('idle for %ds: stopping' % a.idle, flush=True)
                    break
                continue
            if m is None:
                done_pipe = True
                print('game closed the pipe', flush=True)
                continue
            stats['last'] = time.time()
            header = parse_msg(m)
            # the clone handle stays here until the worker that runs the job takes it over (DUPLICATE_CLOSE_SOURCE)
            pending.append(pool.apply_async(_run_on, ((os.getpid(), header['clone'], header),)))
    finally:
        collect(block=True)
        pool.close()
        pool.join()
        tsv.close()
        el = time.time() - stats['t0']
        print('collector done: %d samples in %.0fs (%.1f per minute)' % (stats['n'], el, 60 * stats['n'] / max(el, 1)),
              flush=True)
    return 0


def _run_on(job):
    """In a worker: take the clone handle over from the collector's main process, then record()."""
    pid, h, header = job
    owner = k32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    mine = wt.HANDLE()
    ok = owner and k32.DuplicateHandle(owner, h, k32.GetCurrentProcess(), ctypes.byref(mine), 0, False,
                                       DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)
    if owner:
        k32.CloseHandle(owner)
    if not ok:
        return {'seq': header['seq'], 'fn': header['fn'], 'k': header['k'], 'tid': header['tid'], 'verdicts': {},
                'orig': '', 'pages': 0, 'secs': 0, 'error': 'handle transfer failed %d' % ctypes.get_last_error()}
    return record((mine.value, header))


if __name__ == '__main__':
    sys.exit(main())
