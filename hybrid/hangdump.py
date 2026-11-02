"""hangdump.py [--game DIR] [--samples 3] [--gap 1.0] : where a hung Freedom.Exe is stuck.

Suspends each thread of the running Freedom.Exe for a moment, reads its WOW64 context and the top of its stack, and
prints EIP plus the exe/port code addresses found on the stack, named from <game>/hooks_plan.tsv (or the image's plan).
Several samples a second apart tell a spin (EIP moves inside one loop, CPU busy) from a wait (EIP parked in a system DLL).
"""
import argparse
import bisect
import ctypes
import ctypes.wintypes as W
import os
import re
import struct
import sys
import time

import psutil

REA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K = ctypes.WinDLL('kernel32', use_last_error=True)
K.OpenThread.restype = W.HANDLE
K.OpenProcess.restype = W.HANDLE

PORTS_LO, PORTS_HI = 0x31000000, 0x31400000
EXE_LO, EXE_HI = 0x401000, 0x700000
STACK_BYTES = 0x20000


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [('ControlWord', W.DWORD), ('StatusWord', W.DWORD), ('TagWord', W.DWORD), ('ErrorOffset', W.DWORD),
                ('ErrorSelector', W.DWORD), ('DataOffset', W.DWORD), ('DataSelector', W.DWORD),
                ('RegisterArea', ctypes.c_byte * 80), ('Cr0NpxState', W.DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [('ContextFlags', W.DWORD), ('Dr0', W.DWORD), ('Dr1', W.DWORD), ('Dr2', W.DWORD), ('Dr3', W.DWORD),
                ('Dr6', W.DWORD), ('Dr7', W.DWORD), ('FloatSave', FLOATING_SAVE_AREA), ('SegGs', W.DWORD),
                ('SegFs', W.DWORD), ('SegEs', W.DWORD), ('SegDs', W.DWORD), ('Edi', W.DWORD), ('Esi', W.DWORD),
                ('Ebx', W.DWORD), ('Edx', W.DWORD), ('Ecx', W.DWORD), ('Eax', W.DWORD), ('Ebp', W.DWORD),
                ('Eip', W.DWORD), ('SegCs', W.DWORD), ('EFlags', W.DWORD), ('Esp', W.DWORD), ('SegSs', W.DWORD),
                ('ExtendedRegisters', ctypes.c_byte * 512)]


def load_plan(game):
    exe, port = [], []
    with open(os.path.join(game, 'hooks_plan.tsv') if os.path.exists(os.path.join(game, 'hooks_plan.tsv'))
              else os.path.join(REA, 'hybrid', 'build', 'hooks_plan.tsv'), encoding='utf-8') as f:
        next(f)
        for line in f:
            p = line.rstrip('\n').split('\t')
            name = p[4] if len(p) > 4 else ''
            exe.append((int(p[0], 16), name))
            if p[1].startswith('0x'):
                port.append((int(p[1], 16), int(p[0], 16), name))
    exe.sort()
    port.sort()
    return exe, port


def namer(plan):
    exe, port = plan
    ek = [a for a, _ in exe]
    pk = [a for a, _, _ in port]

    def name(v):
        if EXE_LO <= v < EXE_HI:
            i = bisect.bisect_right(ek, v) - 1
            return f'0x{v:08x} exe {exe[i][1]}+0x{v - exe[i][0]:x}' if i >= 0 else None
        if PORTS_LO <= v < PORTS_HI:
            i = bisect.bisect_right(pk, v) - 1
            return f'0x{v:08x} port of 0x{port[i][1]:06x} {port[i][2]}+0x{v - port[i][0]:x}' if i >= 0 else None
        return None
    return name


def snapshot(pid, hproc, name):
    out = []
    try:
        threads = psutil.Process(pid).threads()
    except psutil.NoSuchProcess:
        sys.exit('Freedom.Exe exited during the samples')
    for t in threads:
        h = K.OpenThread(0x0002 | 0x0008 | 0x0040, False, t.id)  # SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION
        if not h:
            continue
        try:
            if K.Wow64SuspendThread(h) == 0xFFFFFFFF:
                continue
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = 0x10003  # WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER
            ok = K.Wow64GetThreadContext(h, ctypes.byref(ctx))
            buf = ctypes.create_string_buffer(STACK_BYTES)
            got = ctypes.c_size_t()
            if ok:  # page by page: the read must stop at the unmapped page above the stack base
                for page in range(0, STACK_BYTES, 0x1000):
                    part = ctypes.c_size_t()
                    chunk = ctypes.create_string_buffer(0x1000)
                    if not K.ReadProcessMemory(hproc, ctypes.c_void_p(ctx.Esp + page), chunk, 0x1000,
                                               ctypes.byref(part)):
                        break
                    ctypes.memmove(ctypes.addressof(buf) + page, chunk, part.value)
                    got.value = page + part.value
        finally:
            K.ResumeThread(h)
            K.CloseHandle(h)
        if not ok:
            continue
        frames = []
        for off in range(0, got.value - 3, 4):
            n = name(struct.unpack_from('<I', buf.raw, off)[0])
            if n:
                frames.append(f'  [esp+0x{off:04x}] {n}')
        text = [m.decode() for m in re.findall(rb'[\x20-\x7e]{12,}', buf.raw[:got.value])]
        out.append((t.id, ctx, name(ctx.Eip), frames, text))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--game', default=os.path.join(REA, 'game'))
    ap.add_argument('--samples', type=int, default=3)
    ap.add_argument('--gap', type=float, default=1.0)
    ap.add_argument('--frames', type=int, default=25)
    ap.add_argument('--strings', type=int, default=0, help='print up to N distinct ASCII strings found on each stack')
    a = ap.parse_args()
    procs = [p for p in psutil.process_iter(['name']) if (p.info['name'] or '').lower() == 'freedom.exe']
    if not procs:
        sys.exit('no Freedom.Exe running')
    p = procs[0]
    hproc = K.OpenProcess(0x0010 | 0x0400, False, p.pid)  # VM_READ | QUERY_INFORMATION
    name = namer(load_plan(a.game))
    c0 = p.cpu_times()
    for s in range(a.samples):
        if s:
            time.sleep(a.gap)
        print(f'== sample {s + 1} pid {p.pid}')
        for tid, ctx, eipname, frames, text in snapshot(p.pid, hproc, name):
            if not eipname and not frames:
                continue
            print(f'thread {tid}: eip=0x{ctx.Eip:08x} {eipname or "(system DLL)"} esp=0x{ctx.Esp:08x} '
                  f'eax=0x{ctx.Eax:08x} ecx=0x{ctx.Ecx:08x} esi=0x{ctx.Esi:08x}')
            print('\n'.join(frames[:a.frames]))
            if a.strings:
                seen = list(dict.fromkeys(text))
                print(f'  strings on the stack ({len(seen)} distinct):')
                print('\n'.join('    ' + x[:160] for x in seen[:a.strings]))
    c1 = p.cpu_times()
    span = a.gap * max(a.samples - 1, 1)
    print(f'cpu over the samples: {(c1.user + c1.system - c0.user - c0.system) / span:.0%} of one core')


if __name__ == '__main__':
    main()
