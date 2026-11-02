"""calltrace.py SAMPLE [--image label=path] [--orig] [--max N] [--callers LO-HI]

Like hybrid/shadow/trace.py --calls but also reports, for each call, the resolved target and the number of bytes the callee
popped (esp after return minus esp before the call, so a stdcall `ret 8` shows 8, a cdecl callee 0). Lines:
  caller_addr -> target  esp_before_call  pop_bytes  (ecx at call)
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, HERE)
import capstone  # noqa: E402
import unicorn.x86_const as R  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

import replay  # noqa: E402
from sample import FileSource  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sample')
    ap.add_argument('--image', default='cur=' + os.path.join(REA, 'hybrid', 'build'))
    ap.add_argument('--orig', action='store_true')
    ap.add_argument('--max', type=int, default=400)
    ap.add_argument('--callers', default='')
    a = ap.parse_args()
    label, _, path = a.image.partition('=')
    image = replay.Image(path, label)
    env = replay.Env(FileSource(a.sample), replay.Exe())
    start = env.fn if a.orig else image.entry(env.fn)
    run = replay.Run(env, 'orig' if a.orig else label, start, image=None if a.orig else image)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    lo, hi = (0, 1 << 32)
    if a.callers:
        lo, hi = [int(x, 16) for x in a.callers.split('-')]
    stack = []     # [ret_addr, esp_before, caller, target, ecx, record_idx]
    recs = []
    pending = {}

    def hook(uc, addr, size, _):
        esp = uc.reg_read(R.UC_X86_REG_ESP)
        # returns first
        while stack and addr == stack[-1][0] and esp >= stack[-1][1]:
            ret, eb, caller, tgt, ecx, idx = stack.pop()
            recs[idx][4] = esp - eb
        if pending.get('p'):
            p = pending.pop('p')
            recs[p][3] = addr
        try:
            code = bytes(uc.mem_read(addr, size))
        except Exception:
            return
        ins = next(md.disasm(code, addr), None)
        if ins is not None and ins.mnemonic == 'call' and len(recs) < a.max and lo <= addr < hi:
            recs.append([addr, size, esp, 0, None, uc.reg_read(R.UC_X86_REG_ECX)])
            pending['p'] = len(recs) - 1
            stack.append((addr + size, esp, addr, 0, 0, len(recs) - 1))

    run.mu.hook_add(UC_HOOK_CODE, hook)
    res = run.execute()
    print('end:', res.end, res.detail)
    for addr, size, esp, tgt, pop, ecx in recs:
        print('%08x -> %08x esp=%08x pop=%s ecx=%08x' % (addr, tgt, esp, '?' if pop is None else pop, ecx))


if __name__ == '__main__':
    main()
