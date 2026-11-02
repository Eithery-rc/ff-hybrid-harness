"""sample.py - shadow samples: the entry state of one exe function call in the running game, and the memory pages
its replays touched.

A sample file (.ffs) is b'FFSHADOW1\\n', a u32 header length, the JSON header, then zlib of the page records (u32 page
address + 4096 bytes each). The header holds the call (function, thread, call number, game clock values), the raw
x86 CONTEXT the probe saw at the function's first instruction (716 bytes, hex), the thread's TEB, the region map of
the process below 4 GB (VirtualQuery of the clone), the module list and the pages that could not be read.

Page sources give the replay one interface over two backings:
  CloneSource  a live VA clone of the game process (PssCaptureSnapshot), read with ReadProcessMemory; every page read
               is kept, so the sample can be written after the replays
  FileSource   a saved sample; a page the region map calls readable but the file does not hold raises MissingPage
               (the replay that wants it touched memory no replay touched while the clone was alive)
"""
import json
import struct
import zlib

PAGE = 0x1000
MAGIC = b'FFSHADOW1\n'
MEM_COMMIT, MEM_RESERVE, MEM_FREE = 0x1000, 0x2000, 0x10000
PAGE_NOACCESS, PAGE_GUARD = 0x01, 0x100
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}          # R, RW, WC, XR, XRW, XWC
WRITABLE = {0x04, 0x08, 0x40, 0x80}

# x86 CONTEXT offsets (winnt.h, i386)
CTX_SIZE = 716
CTX_OFF = {'flags': 0x00, 'fcw': 0x1c, 'fsw': 0x20, 'ftw': 0x24, 'st': 0x38, 'gs': 0x8c, 'fs': 0x90, 'es': 0x94,
           'ds': 0x98, 'edi': 0x9c, 'esi': 0xa0, 'ebx': 0xa4, 'edx': 0xa8, 'ecx': 0xac, 'eax': 0xb0, 'ebp': 0xb4,
           'eip': 0xb8, 'cs': 0xbc, 'eflags': 0xc0, 'esp': 0xc4, 'ss': 0xc8, 'fx': 0xcc}
CONTEXT_EXTENDED_REGISTERS = 0x00010020


class MissingPage(Exception):
    """A replay needs a page that the sample file does not hold (only FileSource raises it)."""


def parse_context(raw):
    """CONTEXT bytes -> dict: GPRs, eflags, x87 (cw, sw, full tag word, ST0..ST7 as 10-byte values in stack order),
    MXCSR and XMM0..7 (16-byte values) when the context has the extended registers."""
    u32 = lambda o: struct.unpack_from('<I', raw, o)[0]  # noqa: E731
    c = {k: u32(CTX_OFF[k]) for k in ('flags', 'edi', 'esi', 'ebx', 'edx', 'ecx', 'eax', 'ebp', 'eip', 'eflags',
                                       'esp', 'fs', 'gs', 'cs', 'ds', 'es', 'ss')}
    c['fcw'] = u32(CTX_OFF['fcw']) & 0xffff
    c['fsw'] = u32(CTX_OFF['fsw']) & 0xffff
    c['ftw'] = u32(CTX_OFF['ftw']) & 0xffff
    c['st'] = [bytes(raw[CTX_OFF['st'] + 10 * i:CTX_OFF['st'] + 10 * i + 10]) for i in range(8)]
    if c['flags'] & CONTEXT_EXTENDED_REGISTERS == CONTEXT_EXTENDED_REGISTERS:
        fx = CTX_OFF['fx']
        c['mxcsr'] = u32(fx + 24)
        c['xmm'] = [bytes(raw[fx + 160 + 16 * i:fx + 176 + 16 * i]) for i in range(8)]
    else:
        c['mxcsr'] = 0x1f80
        c['xmm'] = [bytes(16)] * 8
    return c


class Regions:
    """The region map: sorted [base, size, state, protect, type] for committed and reserved regions below 4 GB."""

    def __init__(self, rows):
        self.rows = sorted(tuple(r) for r in rows)
        self.bases = [r[0] for r in self.rows]

    def find(self, a):
        import bisect
        i = bisect.bisect_right(self.bases, a) - 1
        if i >= 0:
            r = self.rows[i]
            if r[0] <= a < r[0] + r[1]:
                return r
        return None

    def readable(self, a):
        r = self.find(a)
        return bool(r and r[2] == MEM_COMMIT and (r[3] & 0xff) in READABLE and not r[3] & PAGE_GUARD)

    def writable(self, a):
        r = self.find(a)
        return bool(r and r[2] == MEM_COMMIT and (r[3] & 0xff) in WRITABLE and not r[3] & PAGE_GUARD)

    def free_hole(self, size, lo=0x01000000, hi=0x7fff0000, avoid=()):
        """Lowest free, 64 KB aligned range of `size` bytes in [lo, hi) that overlaps no region and no avoid range."""
        busy = sorted([(r[0], r[0] + r[1]) for r in self.rows] + list(avoid))
        a = lo
        for b, e in busy:
            if e <= a:
                continue
            if b >= a + size:
                break
            a = (e + 0xffff) & ~0xffff
        return a if a + size <= hi else None


class Source:
    """Pages of one sample (see the module doc)."""
    header = None
    regions = None

    def page(self, p):
        raise NotImplementedError

    def read(self, a, n):
        """n bytes at a, or None when any page is unreadable."""
        out = b''
        while n > 0:
            p = a & ~(PAGE - 1)
            d = self.page(p)
            if d is None:
                return None
            k = min(n, p + PAGE - a)
            out += d[a - p:a - p + k]
            a += k
            n -= k
        return out

    def u32(self, a):
        d = self.read(a, 4)
        return None if d is None else struct.unpack('<I', d)[0]


class CloneSource(Source):
    """ReadProcessMemory on a VA clone handle. Pages are cached; `touched` is everything read so far."""

    def __init__(self, handle, header):
        import ctypes
        self.k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ct = ctypes
        self.k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                               ctypes.POINTER(ctypes.c_size_t)]
        self.k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        self.k32.VirtualQueryEx.restype = ctypes.c_size_t
        self.h = handle
        self.header = header
        self.cache = {}
        self.unreadable = set()
        self._buf = ctypes.create_string_buffer(PAGE)
        self.header['regions'] = self.query_regions()
        self.regions = Regions(self.header['regions'])

    def query_regions(self):
        ct = self.ct

        class MBI(ct.Structure):    # MEMORY_BASIC_INFORMATION, 64-bit layout (this Python is 64-bit)
            _fields_ = [('BaseAddress', ct.c_uint64), ('AllocationBase', ct.c_uint64), ('AllocationProtect', ct.c_uint32),
                        ('PartitionId', ct.c_uint16), ('RegionSize', ct.c_uint64), ('State', ct.c_uint32),
                        ('Protect', ct.c_uint32), ('Type', ct.c_uint32)]
        m = MBI()
        rows, a = [], 0
        while a < 0x100000000:
            if not self.k32.VirtualQueryEx(self.h, a, ct.byref(m), ct.sizeof(m)):
                break
            base, size = m.BaseAddress, m.RegionSize
            if size == 0:
                break
            if m.State != MEM_FREE and base < 0x100000000:
                rows.append([base, min(size, 0x100000000 - base), m.State, m.Protect, m.Type])
            a = base + size
        return rows

    def page(self, p):
        d = self.cache.get(p)
        if d is not None or p in self.unreadable:
            return d
        n = self.ct.c_size_t()
        if self.regions.readable(p) and self.k32.ReadProcessMemory(self.h, p, self._buf, PAGE, self.ct.byref(n)) \
                and n.value == PAGE:
            d = self._buf.raw
            self.cache[p] = d
            return d
        self.unreadable.add(p)
        return None

    def save(self, path, skip=lambda p: False):
        """Write the sample: header, and every page read so far (skip(p) True drops one, e.g. exe .text)."""
        self.header['unreadable'] = sorted(self.unreadable)
        pages = {p: d for p, d in self.cache.items() if not skip(p)}
        write_sample(path, self.header, pages)
        return len(pages)


class FileSource(Source):
    def __init__(self, path):
        self.path = path
        self.header, self.pages = read_sample(path)
        self.regions = Regions(self.header['regions'])
        self.unreadable = set(self.header.get('unreadable', ()))

    def page(self, p):
        d = self.pages.get(p)
        if d is not None:
            return d
        if p in self.unreadable or not self.regions.readable(p):
            return None
        raise MissingPage('page 0x%x is readable in the game but not in %s' % (p, self.path))


def write_sample(path, header, pages):
    blob = b''.join(struct.pack('<I', p) + d for p, d in sorted(pages.items()))
    h = json.dumps(header, separators=(',', ':')).encode()
    with open(path + '.tmp', 'wb') as f:
        f.write(MAGIC + struct.pack('<I', len(h)) + h + zlib.compress(blob, 6))
    import os
    os.replace(path + '.tmp', path)


def read_sample(path):
    d = open(path, 'rb').read()
    if not d.startswith(MAGIC):
        raise ValueError('%s: not a shadow sample' % path)
    n = struct.unpack_from('<I', d, len(MAGIC))[0]
    o = len(MAGIC) + 4
    header = json.loads(d[o:o + n])
    blob = zlib.decompress(d[o + n:])
    pages = {}
    for i in range(0, len(blob), 4 + PAGE):
        pages[struct.unpack_from('<I', blob, i)[0]] = blob[i + 4:i + 4 + PAGE]
    return header, pages
