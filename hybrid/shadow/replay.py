"""replay.py - run an exe function and its port from the same captured game state in Unicorn, and compare.

One sample (sample.py) holds the registers, x87/SSE state and stack pointer the probe saw at a function's first
instruction in the running game, and a page source for the process memory at that moment. Run() builds a fresh
Unicorn per execution:
  * exe .text from the pristine Freedom.Exe.orig (the snapshot's .text carries the probes' int3 bytes); every other
    page comes from the source on first touch, read-only or read-write as the game had it, never executable;
  * the ports image (ff_ports.bin) at 0x31000000 for a port run; its ext_ calls reach the ORIGINAL exe callees here,
    so each port is tested alone against the original code around it;
  * FS points at the thread's real TEB (a GDT entry), so SEH frames, TLS and the security cookie work;
  * the thread stack keeps Windows' guard page rule: touching the guard page commits it, touching below it faults
    (a port frame without a stack probe crashes here as it does in the game);
  * a fetch outside exe .text and the ports image is a call into a DLL: models.py answers it (log, fake return value,
    the same for both runs) and execution goes on at the return address.
The run ends when execution reaches the caller's return address with ESP above the entry ESP.

compare() then checks: callee pop (ESP), callee-saved registers, the scratch registers the caller reads (liveness.py),
x87 depth and ST0, FPCW/MXCSR/DF, every byte of memory either run changed except the dead frame below the entry ESP
and the callee's own argument slots, the log of DLL calls, and the `this` passed to exe callees (callsites.py).
Verdicts:
  exact        no difference
  weak         differences only in registers that are 'maybe' live (the caller returns right after the call)
  mismatch     a difference (the first ones are listed)
  crash        the port faulted where the original returned
  unsupported  the original did not return in the emulator (model gap, budget, a fault the game's SEH handles)
  missing-page the port needs memory no replay touched while the clone was alive (offline replays only)
"""
import collections
import math
import os
import re
import struct
import time

import pefile
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_PROT,
                     UC_HOOK_INTR, UC_HOOK_MEM_READ, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
                     UC_MEM_READ_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UC_MEM_WRITE_PROT, UC_MEM_READ_PROT,
                     UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED, UC_ERR_INSN_INVALID)
from unicorn import x86_const as R

import callsites
import liveness
import models
from sample import PAGE, MissingPage, parse_context

REA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
EXE_PATH = os.path.join(REA, 'ffre-root', 'bin', 'Freedom.Exe.orig')
EXE_BASE = 0x400000
PORTS_BASE = 0x31000000
HARNESS_SIZE = 0x02000000          # GDT, then the fake heap for malloc/HeapAlloc models
HEAP_OFF = 0x00100000
HEAP_CHUNK = 0x00100000
HEAP_FILL = 0xcd                   # fresh fake-heap bytes: not zero, so a read of uninitialised memory shows
UNTIL = 0xfffffff0
BUDGET = int(os.environ.get('SHADOW_BUDGET', '20000000'))      # instructions per emu_start
TIMEOUT = float(os.environ.get('SHADOW_TIMEOUT', '30'))        # seconds per run
MAX_BOUNDARY = 200000                                          # DLL calls per run
ARGMAX = 0x40                                                  # argument bytes at most (16 dwords)
DEAD_STACK_ZERO = os.environ.get('SHADOW_STACK', 'zero') == 'zero'   # 'snapshot': keep the old bytes below ESP
GPRS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
REG = {n: getattr(R, 'UC_X86_REG_' + n.upper()) for n in GPRS + ('eip', 'eflags')}


# ============================================================================ inputs
class Exe:
    """The pristine exe: .text bytes and the import slots (IAT address -> 'DLL!name')."""

    def __init__(self, path=EXE_PATH):
        pe = pefile.PE(path, fast_load=False)
        if pe.OPTIONAL_HEADER.ImageBase != EXE_BASE:
            raise SystemExit('%s: unexpected image base' % path)
        self.image = pe.get_memory_mapped_image()
        t = pe.sections[0]
        self.text_lo = EXE_BASE + t.VirtualAddress
        self.text_hi = self.text_lo + ((t.Misc_VirtualSize + PAGE - 1) & ~(PAGE - 1))
        self.text = bytes(self.image[t.VirtualAddress:self.text_hi - EXE_BASE]).ljust(self.text_hi - self.text_lo, b'\0')
        self.size = (pe.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) & ~(PAGE - 1)
        self.rdtsc = [self.text_lo + m.start() for m in re.finditer(b'\x0f\x31', self.text)]
        self.sections = [(s.Name.rstrip(b'\0').decode('latin-1'), EXE_BASE + s.VirtualAddress,
                          EXE_BASE + s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections]
        self.slots = {}
        for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll = e.dll.decode('latin-1')
            for imp in e.imports:
                self.slots[imp.address] = '%s!%s' % (dll, imp.name.decode('latin-1') if imp.name else 'ord%d' % imp.ordinal)

    def in_text(self, a):
        return self.text_lo <= a < self.text_hi

    def code_at(self, a, n):
        if not self.in_text(a):
            return b''
        return self.text[a - self.text_lo:a - self.text_lo + n]


class Image:
    """A ports image: ff_ports.bin and exe address -> (port entry, name), from ff_ports.tsv or a hook plan."""

    def __init__(self, path, label=None):
        if os.path.isdir(path):
            binp, tsv, plan = os.path.join(path, 'ff_ports.bin'), os.path.join(path, 'ff_ports.tsv'), None
        else:
            binp, tsv = path, None
            plan = path.replace('ff_ports.bin', 'ff_hooks.bin')
        self.path = path
        self.label = label or os.path.basename(os.path.normpath(path))
        self.blob = open(binp, 'rb').read()
        self.size = (len(self.blob) + 0xffff) & ~0xffff
        self._rdtsc = None
        self.entries = {}
        if tsv and os.path.exists(tsv):
            for line in open(tsv, encoding='utf-8', errors='replace'):
                p = line.rstrip('\n').split('\t')
                try:
                    self.entries[int(p[0], 16)] = (int(p[1], 16), p[3] if len(p) > 3 else '')
                except (ValueError, IndexError):
                    continue
        else:
            d = open(plan, 'rb').read()
            count = struct.unpack_from('<I', d, 32)[0]
            for i in range(count):
                a, e, _st = struct.unpack_from('<III', d, 40 + 12 * i)
                self.entries[a] = (e, '')

    def entry(self, a):
        e = self.entries.get(a)
        return e[0] if e else None

    def code_at(self, a, n):
        """Code bytes at a: the image's own, else the exe's (static walks of a port follow its ext_ tail jumps)."""
        if PORTS_BASE <= a < PORTS_BASE + len(self.blob):
            return self.blob[a - PORTS_BASE:a - PORTS_BASE + n]
        return self.exe_code_at(a, n) if self.exe_code_at else b''

    exe_code_at = None

    @property
    def rdtsc(self):
        """Addresses of real rdtsc instructions: 0f 31 pairs that a linear disassembly from the nearest port entry
        below reaches as an instruction start (the image also holds data)."""
        if self._rdtsc is None:
            import bisect
            import capstone
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            starts = sorted(e for e, _ in self.entries.values())
            self._rdtsc = []
            for m in re.finditer(b'\x0f\x31', self.blob):
                a = PORTS_BASE + m.start()
                i = bisect.bisect_right(starts, a) - 1
                if i < 0 or a - starts[i] > 0x10000:
                    continue
                s = starts[i]
                for ins in md.disasm(self.blob[s - PORTS_BASE:a - PORTS_BASE + 2], s):
                    if ins.address >= a:
                        if ins.address == a and ins.mnemonic == 'rdtsc':
                            self._rdtsc.append(a)
                        break
        return self._rdtsc


# ============================================================================ per-sample environment
def discover(src, exe):
    """Header facts read from the snapshot once, at record time: thread stack bounds and the module list (PEB
    loader list). The pages read here are recorded like any other."""
    h = src.header
    teb = h['teb']
    # reservation base, committed low, top. The capture itself ran below the function's frame and may have committed
    # more stack: the probe reports the StackLimit from before the capture, and that one counts.
    low = max(src.u32(teb + 8), h.get('stack_limit') or 0)
    h['stack'] = [src.u32(teb + 0xe0c), low, src.u32(teb + 4)]
    mods = []
    peb = src.u32(teb + 0x30)
    ldr = src.u32(peb + 0x0c) if peb else None
    if ldr:
        head = ldr + 0x0c
        e = src.u32(head)
        while e and e != head and len(mods) < 512:
            base, size = src.u32(e + 0x18), src.u32(e + 0x20)
            ln, buf = struct.unpack('<HxxI', src.read(e + 0x2c, 8) or bytes(8))
            raw = src.read(buf, ln) if buf and ln else None
            name = raw.decode('utf-16-le', 'replace') if raw else '?'
            if base:
                mods.append([name, base, size])
            e = src.u32(e)
    h['modules'] = mods


class Env:
    """Everything shared by the runs of one sample."""

    def __init__(self, src, exe):
        self.src = src
        self.exe = exe
        h = src.header
        self.h = h
        self.fn = h['fn']
        self.ctx = parse_context(bytes.fromhex(h['context']))
        self.esp0 = self.ctx['esp']
        self.teb = h['teb']
        self.stack_lo, self.stack_commit, self.stack_hi = h['stack']
        self.ra = src.u32(self.esp0)
        self.hb = src.regions.free_hole(HARNESS_SIZE, avoid=[(0x30000000, 0x34000000)])
        if self.hb is None:
            raise RuntimeError('no free 32 MB hole for the harness')
        self.heap_lo = self.hb + HEAP_OFF
        self.iat = {}
        for slot, name in exe.slots.items():
            v = src.u32(slot)
            if v and v not in self.iat:
                self.iat[v] = name
        self.modules = sorted((b, b + s, n) for n, b, s in h.get('modules', []))
        self._exports = {}
        self._pops = {}
        self.forwards = {}
        if exe.in_text(self.ra):
            self.live, self.maybe = liveness.live_after(exe.code_at, self.ra)
            self.cleanup = liveness.caller_cleanup(exe.code_at, self.ra)
        else:   # called from a DLL (window procedure, qsort comparator...): nothing known about the caller
            self.live, self.maybe = {}, {b: (0xffffffff if not b.startswith('xmm') else 1) for b in liveness.SCRATCH}
            self.cleanup = 0

    # ---------------------------------------------------------------- names of DLL entry points
    def module_of(self, a):
        for lo, hi, n in self.modules:
            if lo <= a < hi:
                return lo, n
        return None, None

    def name_of(self, x):
        n = self.iat.get(x)
        if n:
            return n
        base, mod = self.module_of(x)
        if base is None:
            return 'unknown!0x%x' % x
        ex = self._exports.get(base)
        if ex is None:
            ex = self._exports[base] = self._read_exports(base)
        n = ex.get(x)
        return '%s!%s' % (mod, n) if n else '%s+0x%x' % (mod, x - base)

    def _read_exports(self, base):
        out = {}
        try:
            src = self.src
            pe = src.u32(base + 0x3c)
            d = src.read(base + pe + 0x78, 8)            # export directory RVA, size
            if not d:
                return out
            rva, _sz = struct.unpack('<II', d)
            if not rva:
                return out
            hdr = src.read(base + rva, 40)
            nfun, nnames, afun, anames, aords = struct.unpack_from('<IIIII', hdr, 20)
            funs = src.read(base + afun, 4 * nfun)
            names = src.read(base + anames, 4 * nnames)
            ords = src.read(base + aords, 2 * nnames)
            for i in range(nnames):
                o = struct.unpack_from('<H', ords, 2 * i)[0]
                f = struct.unpack_from('<I', funs, 4 * o)[0]
                na = struct.unpack_from('<I', names, 4 * i)[0]
                s = src.read(base + na, 64) or b''
                out[base + f] = s.split(b'\0')[0].decode('latin-1')
        except (TypeError, struct.error, MissingPage):
            pass
        return out

    def ret_pop(self, x):
        """Bytes a DLL function pops (its `ret N`), found by walking its code in the snapshot."""
        if x not in self._pops:
            self._pops[x] = models.scan_ret(self.src, x)
        return self._pops[x]

    def describe(self, a):
        """Where an address is: exe section, stack (caller frame or dead), fake heap, module, other."""
        if self.teb <= a < self.teb + PAGE:
            return 'TEB+0x%x%s' % (a - self.teb, ' (SEH chain head)' if a == self.teb else '')
        if EXE_BASE <= a < EXE_BASE + self.exe.size:
            for nm, lo, hi in self.exe.sections:
                if lo <= a < hi:
                    return 'exe ' + nm
            return 'exe'
        if self.stack_lo <= a < self.stack_hi:
            return 'stack+%x' % (a - self.esp0) if a >= self.esp0 else 'dead stack'
        if self.hb <= a < self.hb + HARNESS_SIZE:
            return 'fake heap'
        if PORTS_BASE <= a < PORTS_BASE + 0x01000000:
            return 'ports image'
        base, mod = self.module_of(a)
        if mod:
            return mod
        return 'heap'


# ============================================================================ one execution
def _desc(base, limit, access, flags):
    d = (limit & 0xffff) | ((base & 0xffffff) << 16) | ((access & 0xff) << 40) | (((limit >> 16) & 0xf) << 48)
    d |= ((flags & 0xf) << 52) | (((base >> 24) & 0xff) << 56)
    return struct.pack('<Q', d)


def f80_to_float(mant, exp):
    sign = -1.0 if exp & 0x8000 else 1.0
    e = exp & 0x7fff
    if e == 0x7fff:
        return sign * math.inf if not (mant << 1) & 0xffffffffffffffff else math.nan
    if mant == 0:
        return sign * 0.0
    try:
        return sign * math.ldexp(mant, e - 16383 - 63)
    except OverflowError:
        return sign * math.inf


def float_to_f80(v):
    if v != v:
        return 0xc000000000000000, 0xffff           # the x87 default NaN
    sign = 0x8000 if math.copysign(1.0, v) < 0 else 0
    if math.isinf(v):
        return 0x8000000000000000, 0x7fff | sign
    if v == 0:
        return 0, sign
    m, e = math.frexp(abs(v))
    return int(m * (1 << 64)) & 0xffffffffffffffff, (e - 1 + 16383) | sign


class Result:
    def __init__(self):
        self.end, self.detail = None, ''
        self.regs = {}
        self.pages = {}
        self.heap = b''
        self.calls = []
        self.secs = 0.0


class Run:
    def __init__(self, env, label, start, image=None):
        self.env, self.label, self.start, self.image = env, label, start, image
        self.src = env.src
        self.calls = []
        self.allocs = {}
        self.heap_next = env.heap_lo
        self.heap_mapped = env.heap_lo
        self.mapped = {}                   # page -> 'snap' | 'grown' (stack page committed by the guard rule)
        self.commit_low = env.stack_commit
        self.stop = None
        self.fault = None
        self.nboundary = 0
        self.rand_state = 1
        self.strtok = 0
        self.clock_reads = {}
        self.unknown_pop = []           # DLL calls answered with pop 0 for want of a `ret N`
        self.stack_copies = []          # (dst, n) of memcpy from a local buffer to outside the frame
        mu = self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        exe = env.exe
        mu.mem_map(exe.text_lo, exe.text_hi - exe.text_lo, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_write(exe.text_lo, exe.text)
        if image is not None:
            mu.mem_map(PORTS_BASE, image.size, UC_PROT_ALL)
            mu.mem_write(PORTS_BASE, image.blob)
        hb = env.hb
        mu.mem_map(hb, HEAP_OFF, UC_PROT_READ | UC_PROT_WRITE)
        # GDT: 1 = FS at the TEB, 2 = flat 32-bit data (SS must be loaded with it, the default SS is 16-bit)
        mu.mem_write(hb, b'\0' * 8 + _desc(env.teb, 0xfff, 0xf3, 0x4) + _desc(0, 0xfffff, 0x93, 0xc))
        mu.reg_write(R.UC_X86_REG_GDTR, (0, hb, 0x17, 0))
        for seg in (R.UC_X86_REG_SS, R.UC_X86_REG_DS, R.UC_X86_REG_ES):
            mu.reg_write(seg, 2 << 3)
        mu.reg_write(R.UC_X86_REG_FS, (1 << 3) | 3)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        mu.hook_add(UC_HOOK_MEM_PROT, self._on_prot)
        # the incoming argument slots the code reads: the callee owns them, its writes there are not outputs
        self.argread = 0
        mu.hook_add(UC_HOOK_MEM_READ, self._on_argread, begin=env.esp0 + 4, end=env.esp0 + 4 + ARGMAX - 1)
        mu.hook_add(UC_HOOK_INTR, self._on_intr)
        if exe.in_text(env.ra):
            mu.hook_add(UC_HOOK_CODE, self._on_ret, begin=env.ra, end=env.ra)
        # rdtsc returns host time in Unicorn and cannot be hooked as an instruction: hook every 0f 31 in the code
        # instead (a pair that is not an instruction start never fires) and answer from a counter
        self.tsc = 0x100000000
        for a in exe.rdtsc + (image.rdtsc if image is not None else []):
            mu.hook_add(UC_HOOK_CODE, self._on_rdtsc, begin=a, end=a)
        # the calls the function under test makes into other exe functions (callsites.py): target and inputs
        self.callees = []
        if image is None:
            self.sites = callsites.call_sites(exe.code_at, start, tag='exe')
        else:
            if image.exe_code_at is None:
                image.exe_code_at = exe.code_at
            self.sites = callsites.call_sites(image.code_at, start, tag=image.path,
                                              inside=lambda a: PORTS_BASE <= a < PORTS_BASE + len(image.blob))
        self.in_call = None             # (return address, ESP at the call) of the recorded call in progress
        for a, ins in self.sites.items():
            mu.hook_add(UC_HOOK_CODE, self._on_site, begin=a, end=a)
            mu.hook_add(UC_HOOK_CODE, self._on_site_return, begin=a + ins.size, end=a + ins.size)
        self._set_entry_state()

    # ---------------------------------------------------------------- state
    def _set_entry_state(self):
        mu, c = self.mu, self.env.ctx
        for n in GPRS:
            mu.reg_write(REG[n], c[n])
        mu.reg_write(REG['eflags'], c['eflags'] & ~0x100)     # TF off
        mu.reg_write(R.UC_X86_REG_FPCW, c['fcw'])
        mu.reg_write(R.UC_X86_REG_FPSW, c['fsw'])
        top = (c['fsw'] >> 11) & 7
        for i, raw in enumerate(c['st']):
            mant, exp = struct.unpack('<QH', raw)
            mu.reg_write(R.UC_X86_REG_FP0 + ((top + i) & 7), (mant, exp))
        mu.reg_write(R.UC_X86_REG_FPTAG, c['ftw'])
        mu.reg_write(R.UC_X86_REG_MXCSR, c['mxcsr'])
        for i, raw in enumerate(c['xmm']):
            mu.reg_write(R.UC_X86_REG_XMM0 + i, int.from_bytes(raw, 'little'))

    def reg(self, n):
        return self.mu.reg_read(REG[n])

    def set_reg(self, n, v):
        self.mu.reg_write(REG[n], v & 0xffffffff)

    # ---------------------------------------------------------------- memory
    def map_page(self, p):
        """Map one page on first touch. False: the game had nothing readable there (the access faults)."""
        env = self.env
        if p in self.mapped:
            return True
        if env.stack_lo <= p < env.stack_hi:
            if p >= self.commit_low:
                d = self.src.page(p) or bytes(PAGE)
                if p < env.esp0 and DEAD_STACK_ZERO:
                    # below the entry ESP lies whatever ran there before (and the probe's own frames): both frames
                    # start from zeros, so an uninitialised local reads the same in both layouts
                    k = min(PAGE, env.esp0 - p)
                    d = bytes(k) + d[k:]
                kind = 'snap'
            elif p == self.commit_low - PAGE:     # the guard page: committed now, the next one becomes the guard
                d, kind = bytes(PAGE), 'grown'
                self.commit_low = p
            else:
                self.fault = ('stack', p, 'touched 0x%x below the stack guard page 0x%x (missing stack probe?)' % (
                    p, self.commit_low - PAGE))
                return False
            self.mu.mem_map(p, PAGE, UC_PROT_READ | UC_PROT_WRITE)
            self.mu.mem_write(p, d)
            self.mapped[p] = kind
            return True
        d = self.src.page(p)
        if d is None:
            return False
        self.mu.mem_map(p, PAGE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.mem_write(p, d)
        if not self.src.regions.writable(p):
            self.mu.mem_protect(p, PAGE, UC_PROT_READ)
        self.mapped[p] = 'snap'
        return True

    def ensure(self, a, n, write=False):
        """Make [a, a+n) accessible to a model; raises models.ModelFault like the access would fault in the game."""
        p = a & ~(PAGE - 1)
        while p < a + n:
            if not (self.env.hb <= p < self.env.hb + HARNESS_SIZE) and not self.env.exe.in_text(p) and \
                    not (self.image is not None and PORTS_BASE <= p < PORTS_BASE + self.image.size):
                if not self.map_page(p):
                    raise models.ModelFault('%s at 0x%x' % ('write' if write else 'read', max(a, p)))
                if write and self.mapped.get(p) == 'snap' and not self.src.regions.writable(p) and \
                        not (self.env.stack_lo <= p < self.env.stack_hi):
                    raise models.ModelFault('write to read-only 0x%x' % max(a, p))
            p += PAGE
        return True

    def read(self, a, n):
        if n <= 0:
            return b''
        self.ensure(a, n)
        return bytes(self.mu.mem_read(a, n))

    def write(self, a, data):
        if data:
            self.ensure(a, len(data), write=True)
            self.mu.mem_write(a, bytes(data))

    def u32(self, a):
        return struct.unpack('<I', self.read(a, 4))[0]

    def cstr(self, a, limit=0x10000, wide=False):
        out = bytearray()
        step = 2 if wide else 1
        while len(out) < limit:
            p = a & ~(PAGE - 1)
            chunk = self.read(a, p + PAGE - a)
            for i in range(0, len(chunk) - step + 1, step):
                ch = chunk[i:i + step]
                if ch == b'\0' * step:
                    return bytes(out)
                out += ch
            a = p + PAGE
        return bytes(out)

    def alloc(self, n, fill=HEAP_FILL):
        a = (self.heap_next + 15) & ~15
        end = a + max(n, 1)
        if end > self.env.hb + HARNESS_SIZE:
            raise models.ModelFault('fake heap full')
        while self.heap_mapped < end:
            self.mu.mem_map(self.heap_mapped, HEAP_CHUNK, UC_PROT_READ | UC_PROT_WRITE)
            self.mu.mem_write(self.heap_mapped, bytes([HEAP_FILL]) * HEAP_CHUNK)
            self.heap_mapped += HEAP_CHUNK
        if fill != HEAP_FILL:
            self.mu.mem_write(a, bytes([fill]) * max(n, 1))
        self.heap_next = end
        self.allocs[a] = n
        return a

    # ---------------------------------------------------------------- x87 helpers for the models
    def _top(self):
        return (self.mu.reg_read(R.UC_X86_REG_FPSW) >> 11) & 7

    def st(self, i=0):
        mant, exp = self.mu.reg_read(R.UC_X86_REG_FP0 + ((self._top() + i) & 7))
        return f80_to_float(mant, exp)

    def _tag(self, phys, v):
        t = self.mu.reg_read(R.UC_X86_REG_FPTAG)
        self.mu.reg_write(R.UC_X86_REG_FPTAG, (t & ~(3 << 2 * phys)) | (v << 2 * phys))

    def st_pop(self):
        top = self._top()
        self._tag(top, 3)
        sw = self.mu.reg_read(R.UC_X86_REG_FPSW)
        self.mu.reg_write(R.UC_X86_REG_FPSW, (sw & ~0x3800) | (((top + 1) & 7) << 11))

    def st_push(self, v):
        top = (self._top() - 1) & 7
        sw = self.mu.reg_read(R.UC_X86_REG_FPSW)
        self.mu.reg_write(R.UC_X86_REG_FPSW, (sw & ~0x3800) | (top << 11))
        self.mu.reg_write(R.UC_X86_REG_FP0 + top, float_to_f80(v))
        self._tag(top, 0)

    # ---------------------------------------------------------------- hooks
    def _on_unmapped(self, uc, access, addr, size, value, _):
        if access == UC_MEM_FETCH_UNMAPPED:
            return False                     # a call into a DLL (or a wild jump): the run loop decides
        try:
            if self.map_page(addr & ~(PAGE - 1)):
                return True
        except MissingPage as e:
            self.stop = ('missing', str(e))
            return False
        if self.fault is None:
            self.fault = ('read' if access == UC_MEM_READ_UNMAPPED else 'write', addr,
                          '%s of unmapped 0x%x' % ('read' if access == UC_MEM_READ_UNMAPPED else 'write', addr))
        return False

    def _on_prot(self, uc, access, addr, size, value, _):
        if access == UC_MEM_WRITE_PROT and self.fault is None:
            self.fault = ('write', addr, 'write to read-only 0x%x (%s)' % (addr, self.env.describe(addr)))
        elif access == UC_MEM_READ_PROT and self.fault is None:
            self.fault = ('read', addr, 'read of protected 0x%x' % addr)
        return False

    def _on_intr(self, uc, intno, _):
        eip = uc.reg_read(R.UC_X86_REG_EIP)
        if intno == 0x29:
            self.stop = ('fault', 'fastfail %d' % uc.reg_read(R.UC_X86_REG_ECX))
        else:
            self.stop = ('fault', 'interrupt %d near %s' % (intno, self.where(eip)))
        uc.emu_stop()

    def _on_rdtsc(self, uc, addr, size, _):
        if size == 2:
            self.tsc += 100000
            uc.reg_write(R.UC_X86_REG_EAX, self.tsc & 0xffffffff)
            uc.reg_write(R.UC_X86_REG_EDX, self.tsc >> 32)
            uc.reg_write(R.UC_X86_REG_EIP, addr + 2)

    def _on_site(self, uc, addr, size, _):
        ins = self.sites.get(addr)
        if ins is None or len(self.callees) >= 4096 or self.in_call is not None:
            return                  # a call site reached again inside a recorded call (recursion) is not ours

        def read32(a):
            try:
                return struct.unpack('<I', uc.mem_read(a, 4))[0]
            except UcError:
                return None
        t = callsites.operand_target(ins, lambda n: uc.reg_read(REG[n]) if n in REG else 0, read32)
        if t is None or not self.env.exe.in_text(t):
            return                  # DLL calls are in the call log; image-internal helpers are walked as the port
        esp = uc.reg_read(R.UC_X86_REG_ESP)
        try:
            stack = bytes(uc.mem_read(esp, 64))
        except UcError:
            stack = b''
        self.callees.append((t, {n: uc.reg_read(REG[n]) for n in callsites.INPUT_REGS}, stack,
                             addr + ins.size))
        self.in_call = (addr + ins.size, esp)

    def _on_site_return(self, uc, addr, size, _):
        if self.in_call is not None and addr == self.in_call[0] and                 uc.reg_read(R.UC_X86_REG_ESP) >= self.in_call[1]:
            self.in_call = None

    def _on_ret(self, uc, addr, size, _):
        if uc.reg_read(R.UC_X86_REG_ESP) > self.env.esp0:
            self.stop = ('returned', '')
            uc.emu_stop()

    def where(self, eip):
        if self.image is not None and PORTS_BASE <= eip < PORTS_BASE + self.image.size:
            return 'port 0x%x' % eip
        return '0x%x' % eip

    # ---------------------------------------------------------------- returning from a model
    def ret(self, eax=None, edx=None, pop=0):
        esp = self.reg('esp')
        ra = self.u32(esp)
        if eax is not None:
            self.set_reg('eax', eax)
        if edx is not None:
            self.set_reg('edx', edx)
        self.set_reg('esp', esp + 4 + pop)
        self.mu.reg_write(R.UC_X86_REG_EIP, ra)
        return ra

    def log(self, name, *args):
        """Raw values; compare() turns pointers into the function's own frame into 'stk' once the frame is known."""
        self.calls.append((name,) + tuple(args))

    def _on_argread(self, uc, access, addr, size, value, _):
        self.argread = max(self.argread, addr + size - self.env.esp0 - 4)

    # ---------------------------------------------------------------- the run loop
    def execute(self):
        t0 = time.time()
        mu = self.mu
        eip = self.start
        deadline = t0 + TIMEOUT
        while self.stop is None:
            self.fault = None
            try:
                mu.emu_start(eip, UNTIL, count=BUDGET)
            except UcError as e:
                if self.stop is not None:
                    break
                eip = mu.reg_read(R.UC_X86_REG_EIP)
                if e.errno in (UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED) and self.fault is None:
                    if eip == self.env.ra and self.reg('esp') > self.env.esp0:
                        self.stop = ('returned', '')
                        break
                    self.boundary(eip)
                    if self.stop is None:
                        eip = mu.reg_read(R.UC_X86_REG_EIP)
                        if time.time() > deadline:
                            self.stop = ('budget', 'time limit %ds' % TIMEOUT)
                    continue
                if self.fault is not None:
                    self.stop = ('fault', self.fault[2] + ' near ' + self.where(eip))
                elif e.errno == UC_ERR_INSN_INVALID:
                    code = bytes(mu.mem_read(eip, 8)) if self._readable(eip) else b''
                    self.stop = ('fault', 'invalid instruction at %s (%s)' % (self.where(eip), code.hex()))
                else:
                    self.stop = ('fault', '%s at %s' % (e, self.where(eip)))
                break
            if self.stop is None:
                self.stop = ('budget', 'instruction budget %d at %s' % (BUDGET, self.where(mu.reg_read(R.UC_X86_REG_EIP))))
        return self.result(time.time() - t0)

    def _readable(self, a):
        try:
            self.mu.mem_read(a, 1)
            return True
        except UcError:
            return False

    def boundary(self, x):
        self.nboundary += 1
        if self.nboundary > MAX_BOUNDARY:
            self.stop = ('budget', 'more than %d DLL calls' % MAX_BOUNDARY)
            return
        if x < 0x10000:
            self.stop = ('fault', 'call to 0x%x' % x)
            return
        if EXE_BASE <= x < EXE_BASE + self.env.exe.size or PORTS_BASE <= x < PORTS_BASE + 0x01000000:
            self.stop = ('fault', 'execution of 0x%x (%s)' % (x, self.env.describe(x)))
            return
        name = self.env.name_of(x)
        try:
            models.call(self, name, x)
        except models.ModelFault as e:
            self.stop = ('fault', 'in %s: %s' % (name, e))
        except MissingPage as e:
            self.stop = ('missing', str(e))
        except (UcError, struct.error, ValueError, OverflowError) as e:
            self.stop = ('error', 'model %s: %s' % (name, e))

    def result(self, secs):
        r = Result()
        r.end, r.detail = self.stop
        r.secs = secs
        mu = self.mu
        r.regs = {n: self.reg(n) for n in GPRS + ('eip', 'eflags')}
        r.regs['top'] = self._top()
        mant, exp = mu.reg_read(R.UC_X86_REG_FP0 + r.regs['top'])
        r.regs['st0'] = struct.pack('<QH', mant, exp).hex()
        r.regs['fpcw'] = mu.reg_read(R.UC_X86_REG_FPCW)
        r.regs['mxcsr'] = mu.reg_read(R.UC_X86_REG_MXCSR) & ~0x3f
        for i in range(8):
            r.regs['xmm%d' % i] = mu.reg_read(R.UC_X86_REG_XMM0 + i)
        r.pages = {p: bytes(mu.mem_read(p, PAGE)) for p in self.mapped}
        r.grown = {p for p, k in self.mapped.items() if k == 'grown'}
        r.heap = bytes(mu.mem_read(self.env.heap_lo, self.heap_next - self.env.heap_lo))
        r.calls = self.calls
        r.allocs = dict(self.allocs)
        r.argread = self.argread
        r.unknown_pop = self.unknown_pop
        r.stack_copies = self.stack_copies
        r.callees = self.callees
        return r


# ============================================================================ comparison
def _nan80(h):
    b = bytes.fromhex(h)
    mant, exp = struct.unpack('<QH', b)
    return (exp & 0x7fff) == 0x7fff and (mant << 1) & 0xffffffffffffffff


def frame_args(env, o):
    """Bytes of incoming argument slots: what the original pops, what its caller cleans up, what it reads (capped)."""
    pop = o.regs['esp'] - env.esp0 - 4 if o.regs else 0
    return min(max(pop, env.cleanup, (o.argread + 3) & ~3, 0), ARGMAX)


def norm_calls(env, calls, argbytes):
    """A call argument that points into the function's own frame (locals below the entry ESP, or its argument slots)
    differs between the two frame layouts: compare it as 'stk'."""
    hi = env.esp0 + 4 + argbytes

    def one(v):
        if isinstance(v, int) and env.stack_lo <= v < hi and not env.esp0 <= v < env.esp0 + 4:
            return 'stk'
        return v
    return [tuple(one(v) for v in c) for c in calls]


def _up_chain(env, o):
    """EAX/EDX bits read by callers further up, through the real return addresses on the captured stack."""
    if getattr(env, '_chain', None) is None:
        def read32(a):
            try:
                return env.src.u32(a)
            except MissingPage:
                return None
        env._chain = liveness.through_returns(env.exe.code_at, env.ra, o.regs['esp'], o.regs['ebp'], read32) \
            if env.exe.in_text(env.ra) else {}
    return env._chain


def compare(env, o, q):
    """(verdict, [difference strings]) for the original run o and the port run q."""
    argbytes = frame_args(env, o)
    oc, qc = norm_calls(env, o.calls, argbytes), norm_calls(env, q.calls, argbytes)
    if o.end != 'returned':
        if o.end in ('throw', 'exit') and q.end == o.end and q.detail == o.detail and qc == oc:
            return 'exact', []
        if o.end in ('throw', 'exit'):
            return 'mismatch', ['orig %s %s, port %s %s' % (o.end, o.detail, q.end, q.detail)] + _call_diff(oc, qc)
        if o.end == 'missing':
            return 'missing-page', ['orig: ' + o.detail]
        return 'unsupported', ['orig %s: %s' % (o.end, o.detail)]
    if q.end == 'missing':
        return 'missing-page', [q.detail]
    if q.end == 'fault':
        return 'crash', ['port fault: ' + q.detail] + _call_diff(oc, qc)[:1]
    if q.end != 'returned':
        return 'mismatch', ['port %s: %s' % (q.end, q.detail)] + _call_diff(oc, qc)[:1]
    hard, maybe = [], []
    ro, rq = o.regs, q.regs
    broken = [n for n in ('ebx', 'esi', 'edi', 'ebp') if ro[n] != env.ctx[n]]
    if broken and o.unknown_pop:
        # the original lost its own saved registers: a DLL call popped the wrong number of bytes in the replay
        return 'unsupported', ['orig changed %s after DLL calls with no known pop (%s)' % (
            '/'.join(broken), ', '.join(sorted(set(o.unknown_pop)))[:200])]
    pop_o, pop_q = ro['esp'] - env.esp0 - 4, rq['esp'] - env.esp0 - 4
    if pop_o != pop_q:
        hard.append('pop: orig ret %d, port ret %d' % (pop_o, pop_q))
    for n in ('ebx', 'esi', 'edi', 'ebp'):
        if ro[n] != rq[n]:
            hard.append('%s (callee-saved, entry 0x%x): orig 0x%x port 0x%x' % (n, env.ctx[n], ro[n], rq[n]))
    for n in liveness.SCRATCH:
        full = 0xffffffff if not n.startswith('xmm') else (1 << 128) - 1
        live = env.live.get(n, 0)
        mb = env.maybe.get(n, 0)
        if n.startswith('xmm'):
            live, mb = full if live else 0, full if mb else 0
        elif live and not live & 0xff:
            # the caller wrote the low byte first and then read the whole register (`mov dl, [esi]; lea ecx,
            # [edx-0x41]; cmp cl, 0x19`): the upper bytes rarely matter, so they only count as maybe live
            live, mb = 0, mb | live
        d = (ro[n] ^ rq[n]) & full
        if d & live:
            hard.append('%s (read by the caller, mask 0x%x): orig 0x%x port 0x%x' % (n, live, ro[n], rq[n]))
        elif d & mb and n in ('eax', 'edx') and d & _up_chain(env, o).get(n, 0):
            hard.append('%s (the caller returns it, a caller up the chain reads it): orig 0x%x port 0x%x' % (
                n, ro[n], rq[n]))
        elif d & mb:
            maybe.append('%s (maybe live): orig 0x%x port 0x%x' % (n, ro[n], rq[n]))
    top0 = (env.ctx['fsw'] >> 11) & 7
    if ro['top'] != rq['top']:
        hard.append('x87 depth: orig TOP %d port TOP %d (entry %d)' % (ro['top'], rq['top'], top0))
    elif ro['top'] != top0 and ro['st0'] != rq['st0'] and not (_nan80(ro['st0']) and _nan80(rq['st0'])):
        hard.append('ST0: orig %s (%r) port %s (%r)' % (
            ro['st0'], f80_to_float(*struct.unpack('<QH', bytes.fromhex(ro['st0']))),
            rq['st0'], f80_to_float(*struct.unpack('<QH', bytes.fromhex(rq['st0'])))))
    if ro['fpcw'] != rq['fpcw']:
        hard.append('FPCW: orig 0x%x port 0x%x' % (ro['fpcw'], rq['fpcw']))
    if ro['mxcsr'] != rq['mxcsr']:
        hard.append('MXCSR: orig 0x%x port 0x%x' % (ro['mxcsr'], rq['mxcsr']))
    if (ro['eflags'] ^ rq['eflags']) & 0x400:
        hard.append('DF: orig %d port %d' % (ro['eflags'] >> 10 & 1, rq['eflags'] >> 10 & 1))
    hard += _call_diff(oc, qc)          # a different DLL call usually explains the memory differences after it
    hard += _callee_diff(env, o, q, argbytes)
    mh, mm = _mem_diff(env, o, q, argbytes)
    hard += mh
    maybe += mm
    if hard and (o.unknown_pop or q.unknown_pop):
        hard.append('(note: DLL calls with no known pop: %s)' % ', '.join(sorted(set(o.unknown_pop + q.unknown_pop)))[:200])
    if hard:
        return 'mismatch', hard + maybe
    if maybe:
        return 'weak', maybe
    return 'exact', []


def _callee_diff(env, o, q, argbytes, limit=2):
    """`this` of the calls into exe functions: the k-th call of the original to a callee is paired with the k-th call
    of the port to the same callee, and when the callee reads ECX before writing it on some path from its entry,
    both must pass the same ECX, even when the callee ignored it in this state (0x64d490's port passes its own `this`,
    then 0, to 0x63da80, which reads ECX only for an argument that already holds a slot index). The values of one
    callee are compared as a multiset (a list walked in the other order passes the same objects), and only when both
    made the same number of calls to it. A pointer into the function's own frame compares as 'stk'. Stack arguments
    and the order of calls are not compared: MSVC batches cdecl cleanups and ports inline or reorder helper calls,
    which made those checks mostly noise."""
    hi = env.esp0 + 4 + argbytes

    def norm(v):
        return 'stk' if env.stack_lo <= v < hi and not env.esp0 <= v < env.esp0 + 4 else v
    code_at = env.exe.code_at
    seq_o, seq_q = collections.defaultdict(list), collections.defaultdict(list)
    for t, regs, _stack, _after in o.callees:
        seq_o[t].append(regs['ecx'])
    for t, regs, _stack, _after in q.callees:
        seq_q[t].append(regs['ecx'])
    out = []
    for t in seq_o:
        if t not in seq_q or callsites.ignored_callee(code_at, t) or 'ecx' not in callsites.callee_inputs(code_at, t):
            continue
        # a callee that takes a byte in CL (`lea eax, [ecx-0x41]; cmp al, 0x19`) reads all of ECX on paper: when the
        # low bytes agree, the upper bytes are left over from the caller (`mov cl, [esi]`), so such pairs are equal
        ra, rb = seq_o[t], [x if x != y and not (x ^ y) & 0xff else y for x, y in zip(seq_o[t], seq_q[t])]
        rb += seq_q[t][len(ra):]
        a, b = [norm(x) for x in ra], [norm(x) for x in rb]
        if len(a) != len(b) or collections.Counter(a) == collections.Counter(b):
            continue            # a different number of calls, or the same objects in another order (a list walked
                                # the other way round ends in the same memory): not this check's business
        k = next(i for i in range(len(a)) if a[i] != b[i])
        out.append('this of call %d to 0x%x: orig %s port %s' % (k + 1, t, _fmt_v(a[k]), _fmt_v(b[k])))
        if len(out) >= limit:
            break
    return out


def _fmt_v(v):
    return hex(v) if isinstance(v, int) else str(v)


def _call_diff(a, b):
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else None
        y = b[i] if i < len(b) else None
        if x != y:
            return ['DLL call #%d: orig %s port %s (orig %d calls, port %d)' % (
                i, _fmt_call(x), _fmt_call(y), len(a), len(b))]
    return []


def _fmt_call(c):
    if c is None:
        return '-'
    return '%s(%s)' % (c[0], ', '.join(hex(v) if isinstance(v, int) else repr(v)[:80] for v in c[1:]))


def _mem_diff(env, o, q, argbytes, limit=4):
    """Byte differences in the final memory of the two runs, as 'address (where): orig dword, port dword'.
    Returns (hard, maybe): a difference inside a local buffer that was copied out whole (Run.stack_copies) is maybe,
    since that buffer's unused tail holds stack leftovers that differ between the frame layouts."""
    hard, maybe = [], []
    skip = [(env.stack_lo, env.esp0), (env.esp0 + 4, env.esp0 + 4 + argbytes)]
    copies = o.stack_copies + q.stack_copies
    src = env.src

    def pristine(p, run):
        if p in run.grown:
            return bytes(PAGE)
        try:
            d = src.page(p)
        except MissingPage:
            d = None
        return d if d is not None else bytes(PAGE)

    def put(addr, text):
        soft = any(d <= addr < d + n for d, n in copies)
        lst = maybe if soft else hard
        if len(lst) < limit:
            lst.append(text + (' (copied from a local buffer)' if soft else ''))
        return not soft

    ndiff = 0
    for p in sorted(set(o.pages) | set(q.pages)):
        if any(lo <= p and p + PAGE <= hi for lo, hi in skip):
            continue
        a = o.pages.get(p) or pristine(p, q)
        b = q.pages.get(p) or pristine(p, o)
        if a == b:
            continue
        # bytes where both runs hold an address in their own dead frame, also unaligned (packed records)
        excused = set()
        for j in range(PAGE - 3):
            if a[j] != b[j] or a[j + 3] != b[j + 3]:
                va, vb = struct.unpack_from('<I', a, j)[0], struct.unpack_from('<I', b, j)[0]
                if va != vb and env.stack_lo <= va < env.esp0 and env.stack_lo <= vb < env.esp0:
                    excused.update(range(j, j + 4))
        for i in range(0, PAGE, 4):
            if a[i:i + 4] == b[i:i + 4]:
                continue
            addr = p + i
            if any(lo <= addr < hi for lo, hi in skip):
                continue
            va, vb = struct.unpack_from('<I', a, i)[0], struct.unpack_from('<I', b, i)[0]
            if all(k in excused for k in range(i, i + 4) if a[k] != b[k]):
                continue                     # both hold an address in their own (dead) frame
            ndiff += put(addr, 'mem 0x%x (%s): orig %08x port %08x' % (addr, env.describe(addr), va, vb))
    a, b = o.heap, q.heap
    n = max(len(a), len(b))
    a, b = a.ljust(n, bytes([HEAP_FILL])), b.ljust(n, bytes([HEAP_FILL]))
    for i in range(0, n, 4):
        if a[i:i + 4] != b[i:i + 4]:
            ndiff += put(env.heap_lo + i, 'fake heap 0x%x: orig %s port %s' % (env.heap_lo + i, a[i:i + 4].hex(),
                                                                                b[i:i + 4].hex()))
    if ndiff > len(hard):
        hard.append('... %d differing dwords in all' % ndiff)
    return hard, maybe


# ============================================================================ one sample
def replay(src, exe, images, orig=None):
    """Run the original once and each image's port. Returns (orig Result, {label: (verdict, diffs, port Result)})."""
    env = Env(src, exe)
    if orig is None:
        orig = Run(env, 'orig', env.fn).execute()
    out = {}
    for im in images:
        e = im.entry(env.fn)
        if e is None:
            out[im.label] = ('no-port', [], None)
            continue
        q = Run(env, im.label, e, image=im).execute()
        v, d = compare(env, orig, q)
        out[im.label] = (v, d, q)
    return env, orig, out
