"""synth.py - synthetic shadow samples for offline tests of the replay (no game needed).

Builds a fake process around the pristine exe: its .rdata/.data pages, a thread stack with a TEB (guard page and
all), a heap region with hand-made objects, and an entry CONTEXT whose return address is a real call site of the
function in the exe, so the caller's register liveness is the real one.

    python -I hybrid/shadow/test/synth.py [OUT_DIR]      # writes the samples, then replays them against the images
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import replay  # noqa: E402
from sample import PAGE, CTX_SIZE, CTX_OFF, MEM_COMMIT, MEM_RESERVE, write_sample  # noqa: E402

STACK_LO, STACK_COMMIT, STACK_HI = 0x00100000, 0x001f0000, 0x00200000
TEB, PEB = 0x7efdd000, 0x7efde000
HEAP = 0x02000000
IMAGE_LIST = [('prev', 'hybrid/build'), ('v3', 'hybrid/build/ports_next'), ('cur', 'hybrid/build/ports_next2')]


class Proc:
    def __init__(self, exe):
        self.exe = exe
        self.pages = {}
        self.regions = []
        img = exe.image
        # exe image: header R, .text XR (pages come from the file at replay time), .rdata R, .data RW
        self.regions += [[0x400000, 0x1000, MEM_COMMIT, 0x02, 0x1000000], [0x401000, 0x275000, MEM_COMMIT, 0x20, 0x1000000],
                         [0x676000, 0x6e000, MEM_COMMIT, 0x02, 0x1000000], [0x6e4000, 0x131000, MEM_COMMIT, 0x04, 0x1000000]]
        for a in list(range(0x400000, 0x401000, PAGE)) + list(range(0x676000, 0x815000, PAGE)):
            self.pages[a] = bytes(img[a - 0x400000:a - 0x400000 + PAGE]).ljust(PAGE, b'\0')
        self.regions += [[STACK_LO, STACK_COMMIT - PAGE - STACK_LO, MEM_RESERVE, 0, 0x20000],
                         [STACK_COMMIT - PAGE, PAGE, MEM_COMMIT, 0x104, 0x20000],
                         [STACK_COMMIT, STACK_HI - STACK_COMMIT, MEM_COMMIT, 0x04, 0x20000],
                         [TEB, 0x2000, MEM_COMMIT, 0x04, 0x20000], [HEAP, 0x100000, MEM_COMMIT, 0x04, 0x20000]]
        for a in range(STACK_COMMIT, STACK_HI, PAGE):
            self.pages[a] = bytes([0x5a]) * PAGE        # stale stack bytes
        for a in range(HEAP, HEAP + 0x100000, PAGE):
            self.pages[a] = bytes(PAGE)
        self.pages[TEB] = bytes(PAGE)
        self.pages[PEB] = bytes(PAGE)
        self.w32(TEB + 0, 0xffffffff)
        self.w32(TEB + 4, STACK_HI)
        self.w32(TEB + 8, STACK_COMMIT)
        self.w32(TEB + 0x18, TEB)
        self.w32(TEB + 0x30, PEB)
        self.w32(TEB + 0xe0c, STACK_LO)
        self.heap_next = HEAP + 0x100

    def w32(self, a, v):
        self.wbytes(a, struct.pack('<I', v & 0xffffffff))

    def wbytes(self, a, b):
        while b:
            p = a & ~(PAGE - 1)
            k = min(len(b), p + PAGE - a)
            pg = bytearray(self.pages[p])
            pg[a - p:a - p + k] = b[:k]
            self.pages[p] = bytes(pg)
            a, b = a + k, b[k:]

    def alloc(self, n):
        a = self.heap_next
        self.heap_next = (a + n + 15) & ~15
        return a

    def sample(self, path, fn, regs, ra, stack_args=()):
        esp = STACK_HI - 0x2000
        self.w32(esp, ra)
        for i, v in enumerate(stack_args):
            self.w32(esp + 4 + 4 * i, v)
        ctx = bytearray(CTX_SIZE)
        struct.pack_into('<I', ctx, 0, 0x1003f)
        struct.pack_into('<I', ctx, CTX_OFF['fcw'], 0x27f)
        struct.pack_into('<I', ctx, CTX_OFF['ftw'], 0xffff)
        struct.pack_into('<I', ctx, CTX_OFF['fx'] + 24, 0x1f80)
        for k in ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'ebp'):
            struct.pack_into('<I', ctx, CTX_OFF[k], regs.get(k, {'ebx': 0xb0b0b0b, 'esi': 0x5151515,
                                                                  'edi': 0xd0d0d0d, 'ebp': STACK_HI - 0x100}.get(k, 0x77)))
        struct.pack_into('<I', ctx, CTX_OFF['eip'], fn)
        struct.pack_into('<I', ctx, CTX_OFF['esp'], esp)
        struct.pack_into('<I', ctx, CTX_OFF['eflags'], 0x202)
        header = {'fn': fn, 'seq': 0, 'tid': 1, 'pid': 2, 'k': 1, 'teb': TEB, 'context': bytes(ctx).hex(),
                  'time': {'tick': 1000, 'qpc': 123456789, 'qpf': 10000000, 'ft': 133000000000000000, 'clock': 5000},
                  'regions': self.regions, 'stack': [STACK_LO, STACK_COMMIT, STACK_HI], 'modules': [],
                  'unreadable': [], 'synthetic': True}
        write_sample(path, header, self.pages)
        return path


def call_sites(exe, fn, reads_eax=True):
    """Return addresses of direct calls to fn whose caller reads EAX afterwards (or not), first ones first."""
    import liveness
    t, lo = exe.text, exe.text_lo
    out = []
    i = t.find(b'\xe8')
    while i >= 0 and len(out) < 50:
        if i + 5 <= len(t) and lo + i + 5 + struct.unpack_from('<i', t, i + 1)[0] == fn:
            ra = lo + i + 5
            live, _ = liveness.live_after(exe.code_at, ra)
            if bool(live.get('eax', 0) == 0xffffffff) == reads_eax:
                out.append(ra)
        i = t.find(b'\xe8', i + 1)
    return out


def build(out):
    exe = replay.Exe()
    os.makedirs(out, exist_ok=True)
    paths = []
    # 0x445c50 ZCAMERA::CurrentRoom (thiscall, returns EAX): this+0x18 == 0, so it reads [[0x70039c]+0x9b]+0xadc
    p = Proc(exe)
    cam = p.alloc(0x40)
    q = p.alloc(0x1000)
    w = p.alloc(0x100)
    p.w32(0x70039c, w)
    p.w32(w + 0x9b, q)
    p.w32(q + 0xadc, 0x12345678)
    ra = call_sites(exe, 0x445c50)[0]
    paths.append(p.sample(os.path.join(out, 'synth_445c50.ffs'), 0x445c50, {'ecx': cam, 'eax': 0x0badf00d}, ra))
    # 0x4d5120 IOFSMemoryAccess_t::nativeEof (thiscall, ret 4, bool): pos [this+8] >= size [this+0xc]
    p = Proc(exe)
    o = p.alloc(0x20)
    p.w32(o + 8, 0x1234)
    p.w32(o + 0xc, 0x1000)
    sites = call_sites(exe, 0x4d5120) or call_sites(exe, 0x4d5120, reads_eax=False)
    paths.append(p.sample(os.path.join(out, 'synth_4d5120.ffs'), 0x4d5120, {'ecx': o}, sites[0] if sites else 0x401000,
                          stack_args=[0]))
    return paths


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(replay.REA, 'hybrid', 'build', 'shadow', 'synth')
    paths = build(out)
    import shadow
    images = [replay.Image(os.path.join(replay.REA, d), label) for label, d in IMAGE_LIST]
    return shadow.main(['replay'] + paths + sum([['--image', '%s=%s' % (lb, os.path.join(replay.REA, d))]
                                                for lb, d in IMAGE_LIST], []) + ['-v']) if images else 0


if __name__ == '__main__':
    sys.exit(main())
