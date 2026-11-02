"""trace.py - run one sample (orig or a port) and print the last instructions before it stopped.

    python -I hybrid/shadow/trace.py SAMPLE.ffs [--image LABEL=PATH] [--orig] [--last 60] [--calls]

The run is the same as in replay.py (same state, same DLL models); an instruction hook keeps a ring of the last N
executed instructions (address, text, ESP, EAX, ECX, EDX). With --calls every direct or indirect call target is
printed as it happens (first 300), which shows where the port and the original diverge.
"""
import argparse
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capstone  # noqa: E402
import unicorn.x86_const as R  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

import replay  # noqa: E402
from sample import FileSource  # noqa: E402

REA = os.path.normpath(os.path.join(HERE, '..', '..'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sample')
    ap.add_argument('--image', default='cur=' + os.path.join(REA, 'hybrid', 'build'))
    ap.add_argument('--orig', action='store_true', help='trace the original instead of the port')
    ap.add_argument('--last', type=int, default=60)
    ap.add_argument('--calls', action='store_true')
    a = ap.parse_args()
    label, _, path = a.image.partition('=')
    image = replay.Image(path, label)
    env = replay.Env(FileSource(a.sample), replay.Exe())
    start = env.fn if a.orig else image.entry(env.fn)
    run = replay.Run(env, 'orig' if a.orig else label, start, image=None if a.orig else image)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ring = collections.deque(maxlen=a.last)
    calls = []

    def hook(uc, addr, size, _):
        try:
            code = bytes(uc.mem_read(addr, size))
        except Exception:
            code = b''
        ins = next(md.disasm(code, addr), None) if code else None
        txt = ('%s %s' % (ins.mnemonic, ins.op_str)).strip() if ins else '?'
        regs = (uc.reg_read(R.UC_X86_REG_ESP), uc.reg_read(R.UC_X86_REG_EAX), uc.reg_read(R.UC_X86_REG_ECX),
                uc.reg_read(R.UC_X86_REG_EDX))
        ring.append((addr, txt, regs))
        if a.calls and ins is not None and ins.mnemonic == 'call' and len(calls) < 300:
            calls.append((addr, txt, regs))

    run.mu.hook_add(UC_HOOK_CODE, hook)
    res = run.execute()
    print('end:', res.end, res.detail, 'dll calls:', len(res.calls))
    if a.calls:
        for addr, txt, regs in calls:
            print('call @%x %-40s esp=%x eax=%x ecx=%x edx=%x' % ((addr, txt) + regs))
        print('----')
    for addr, txt, regs in ring:
        print('%08x  %-44s esp=%08x eax=%08x ecx=%08x edx=%08x' % ((addr, txt) + regs))


if __name__ == '__main__':
    main()
