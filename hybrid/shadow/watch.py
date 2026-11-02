"""watch.py SAMPLE ADDR [--len 4] [--image label=path] [--orig] : print every write overlapping [ADDR, ADDR+len): pc, value, size."""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, HERE)
import unicorn.x86_const as R  # noqa: E402
from unicorn import UC_HOOK_MEM_WRITE  # noqa: E402

import replay  # noqa: E402
from sample import FileSource  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sample')
    ap.add_argument('addr')
    ap.add_argument('--len', type=int, default=4)
    ap.add_argument('--image', default='cur=' + os.path.join(REA, 'hybrid', 'build'))
    ap.add_argument('--orig', action='store_true')
    a = ap.parse_args()
    lo = int(a.addr, 16)
    hi = lo + a.len
    label, _, path = a.image.partition('=')
    image = replay.Image(path, label)
    env = replay.Env(FileSource(a.sample), replay.Exe())
    start = env.fn if a.orig else image.entry(env.fn)
    run = replay.Run(env, 'orig' if a.orig else label, start, image=None if a.orig else image)

    def hook(uc, access, address, size, value, _):
        if address < hi and address + size > lo:
            print('write pc=%08x addr=%08x size=%d value=%08x esp=%08x' % (uc.reg_read(R.UC_X86_REG_EIP), address, size,
                                                                          value & 0xffffffff, uc.reg_read(R.UC_X86_REG_ESP)))

    run.mu.hook_add(UC_HOOK_MEM_WRITE, hook, begin=lo & ~0xfff, end=(hi + 0xfff) & ~0xfff)
    res = run.execute()
    print('end:', res.end, res.detail)


if __name__ == '__main__':
    main()
