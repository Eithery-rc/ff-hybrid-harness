"""models.py - what a call into a DLL does during a shadow replay.

The replay never runs DLL code. A call that leaves exe .text and the ports image lands in models.call() with the
entry's name (from the exe's import slots, else the module's export table, else module+offset). Both runs of a sample
get the same answers, so a difference can only come from the code under test. Three kinds of answers:
  pure     the effect is fully visible in registers and memory (mem*/str* functions, math, clocks): not logged, so a
           port whose compiler inlined memcpy where the original called it still compares equal
  logged   the call is an outside effect (allocation, file, D3D, critical section...): name and arguments go into the
           call log that compare() checks; arguments that point into the dead stack frame are logged as 'stk'
  default  any name without a model: logged with as many stack dwords as the function pops (its `ret N`, found by
           walking its code in the snapshot), returns 0
Stops: _CxxThrowException ends the run as 'throw', exit/terminate/_purecall as 'exit' (compared as outcomes).
"""
import math
import re
import struct
import time  # noqa: F401  (models may want it for debugging)

import capstone

from sample import MissingPage


class ModelFault(Exception):
    """The modelled function would fault in the game (bad pointer)."""


MAXCOPY = 0x4000000
_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def scan_ret(src, x, budget=4000):
    """Bytes popped by the DLL function at x: the immediate of the first `ret` its code reaches (fallthrough first,
    direct and `jmp [mem]` jumps followed, calls stepped over). None when no ret is found."""
    seen, work, steps = set(), [x], 0
    try:
        while work and steps < budget:
            a = work.pop()
            while steps < budget and a not in seen:
                seen.add(a)
                steps += 1
                b = src.read(a, 16)
                if b is None:
                    break
                ins = next(_md.disasm(b, a), None)
                if ins is None:
                    break
                m, op = ins.mnemonic, ins.op_str
                if m == 'ret':
                    return int(op, 0) if op else 0
                if m == 'jmp':
                    if re.fullmatch(r'0x[0-9a-f]+', op):
                        a = int(op, 16)
                        continue
                    mm = re.fullmatch(r'dword ptr \[(0x[0-9a-f]+)\]', op)
                    if mm:
                        p = src.u32(int(mm.group(1), 16))
                        if p:
                            a = p
                            continue
                    break
                if m.startswith('j') and re.fullmatch(r'0x[0-9a-f]+', op):
                    work.append(int(op, 16))
                if m in ('int3', 'hlt', 'ud2'):
                    break
                a = ins.address + ins.size
    except MissingPage:
        return None
    return None


def forward_target(run, x, limit=32):
    """Where a forwarder stub jumps: a short straight-line prefix ending in an indirect jmp (the Steam overlay wraps
    the D3D device with `mov ecx, [this+0x108]; mov [esp+4], ecx; jmp [vtbl+slot]`). The prefix runs in a scratch
    Unicorn on a copy of the current stack and the snapshot's pages; the jump target is where the fetch leaves the
    prefix. None when x is not such a stub."""
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_UNMAPPED, UC_PROT_ALL, UC_PROT_READ, \
        UC_PROT_WRITE, UC_MEM_FETCH_UNMAPPED
    from unicorn import x86_const as R
    src = run.src
    a, n = x, 0
    try:
        while True:
            b = src.read(a, 16)
            if b is None:
                return None
            ins = next(_md.disasm(b, a), None)
            if ins is None or n >= limit:
                return None
            m = ins.mnemonic
            if m == 'jmp':
                if re.fullmatch(r'0x[0-9a-f]+', ins.op_str):
                    return None
                end = a + ins.size
                break
            if m.startswith('j') or m in ('call', 'ret', 'int3', 'loop', 'int') or m.startswith('rep'):
                return None
            a += ins.size
            n += 1
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        code_pages = range(x & ~0xfff, (end + 0xfff) & ~0xfff, 0x1000)
        for p in code_pages:
            mu.mem_map(p, 0x1000, UC_PROT_ALL)
            mu.mem_write(p, src.page(p) or bytes(0x1000))
        esp = run.reg('esp')
        sp = esp & ~0xfff
        for p in (sp - 0x1000, sp, sp + 0x1000):
            if p not in code_pages:
                mu.mem_map(p, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                try:
                    mu.mem_write(p, run.read(p, 0x1000))
                except (ModelFault, MissingPage):
                    pass

        def lazy(uc, access, addr, size, value, _):
            if access == UC_MEM_FETCH_UNMAPPED:
                return False
            d = src.page(addr & ~0xfff)
            if d is None:
                return False
            uc.mem_map(addr & ~0xfff, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(addr & ~0xfff, d)
            return True
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, lazy)
        for nm in ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'ebp', 'esp'):
            mu.reg_write(getattr(R, 'UC_X86_REG_' + nm.upper()), run.reg(nm))
        try:
            mu.emu_start(x, 0xfffffff0, count=n + 1)
        except UcError:
            pass
        t = mu.reg_read(R.UC_X86_REG_EIP)
        return t if not x <= t < end and mu.reg_read(R.UC_X86_REG_ESP) == esp else None
    except (MissingPage, ModelFault, UcError, StopIteration):
        return None


# ============================================================================ the call frame of a model
class Call:
    def __init__(self, run, name, x):
        self.run, self.name, self.x = run, name, x
        self.short = name.split('!')[-1]
        self.esp = run.reg('esp')

    def arg(self, i):
        return self.run.u32(self.esp + 4 + 4 * i)

    def sarg(self, i):
        v = self.arg(i)
        return v - (1 << 32) if v & 0x80000000 else v

    def argd(self, off):
        """double at byte offset off of the stack arguments"""
        return struct.unpack('<d', self.run.read(self.esp + 4 + off, 8))[0]

    def ret(self, eax=0, edx=None, pop=0):
        self.run.ret(eax=eax, edx=edx, pop=pop)

    def log(self, *args):
        self.run.log(self.short, *args)


class Va:
    """Reads variadic arguments in order from address a."""

    def __init__(self, run, a):
        self.run, self.a = run, a

    def u32(self):
        v = self.run.u32(self.a)
        self.a += 4
        return v

    def u64(self):
        v = struct.unpack('<Q', self.run.read(self.a, 8))[0]
        self.a += 8
        return v

    def f64(self):
        v = struct.unpack('<d', self.run.read(self.a, 8))[0]
        self.a += 8
        return v


# ============================================================================ printf / scanf
FMT = re.compile(rb'%([-+ #0]*)(\*|\d+)?(\.\*|\.\d*)?(hh|h|ll|l|L|I64|I32|I|j|z|t|w)?([diouxXeEfFgGaAcCsSpnZ%])')


def vformat(run, fmt, va, wide_default=False):
    out = bytearray()
    i = 0
    while i < len(fmt):
        if fmt[i] != 0x25:
            out.append(fmt[i])
            i += 1
            continue
        m = FMT.match(fmt, i)
        if not m:
            out.append(fmt[i])
            i += 1
            continue
        i = m.end()
        flags, width, prec, ln, conv = m.groups()
        flags = flags or b''
        if width == b'*':
            w = va.u32()
            w = w - (1 << 32) if w & 0x80000000 else w
            if w < 0:
                flags += b'-'
                w = -w
            width = str(w).encode()
        width = width or b''
        if prec == b'.*':
            p = va.u32()
            p = p - (1 << 32) if p & 0x80000000 else p
            prec = (b'.' + str(p).encode()) if p >= 0 else b''
        prec = prec or b''
        c = chr(conv[0])
        big = ln in (b'll', b'I64', b'j')
        spec = b'%' + flags + width + prec
        if c == '%':
            out += b'%'
        elif c in 'di':
            v = va.u64() if big else va.u32()
            bits = 64 if big else 32
            if ln == b'h':
                v &= 0xffff
                bits = 16
            elif ln == b'hh':
                v &= 0xff
                bits = 8
            if v >> (bits - 1):
                v -= 1 << bits
            out += (spec + b'd') % v
        elif c in 'ouxX':
            v = va.u64() if big else va.u32()
            if ln == b'h':
                v &= 0xffff
            elif ln == b'hh':
                v &= 0xff
            out += (spec + (b'd' if c == 'u' else conv)) % v
        elif c in 'eEfFgG':
            v = va.f64()
            try:
                out += (spec + conv) % v
            except (ValueError, OverflowError):
                out += b'nan'
        elif c in 'aA':
            out += float.hex(va.f64()).encode()
        elif c in 'cC':
            out += (b'%' + flags + width + b'c') % (va.u32() & 0xff)
        elif c in 'sSZ':
            p = va.u32()
            wide = (c == 'S') != (ln in (b'l', b'w') or wide_default)
            s = run.cstr(p, wide=wide) if p else b'(null)'
            if wide and p:
                s = s.decode('utf-16-le', 'replace').encode('latin-1', 'replace')
            if prec:
                s = s[:int(prec[1:] or b'0')]
            out += (b'%' + flags + width + b's') % s
        elif c == 'p':
            out += b'%08X' % va.u32()
        elif c == 'n':
            va.u32()
    return bytes(out)


def vscan(run, s, fmt, va):
    """A small sscanf: whitespace, literals, %d %i %u %x %o %f %e %g %s %c %[ with width, * and h/l/ll."""
    si, fi, n = 0, 0, 0
    conv_re = re.compile(rb'%(\*)?(\d+)?(hh|h|ll|l|L|I64)?([diouxXeEfgGsc%]|\[\^?\]?[^\]]*\])')
    while fi < len(fmt):
        ch = fmt[fi]
        if ch in b' \t\n\r':
            while si < len(s) and s[si] in b' \t\n\r':
                si += 1
            fi += 1
            continue
        if ch != 0x25:
            if si < len(s) and s[si] == ch:
                si += 1
                fi += 1
                continue
            break
        m = conv_re.match(fmt, fi)
        if not m:
            break
        fi = m.end()
        skip, width, ln, conv = m.groups()
        width = int(width) if width else None
        c = chr(conv[0])
        if c == '%':
            if si < len(s) and s[si] == 0x25:
                si += 1
                continue
            break
        if c not in 'c[':
            while si < len(s) and s[si] in b' \t\n\r':
                si += 1
        if si >= len(s):
            return n if n else -1
        end = len(s) if width is None else min(len(s), si + width)
        if c in 'diuxXo':
            pat = {'d': rb'[-+]?\d+', 'i': rb'[-+]?(0[xX][0-9a-fA-F]+|0[0-7]*|\d+)', 'u': rb'[-+]?\d+',
                   'x': rb'[-+]?(0[xX])?[0-9a-fA-F]+', 'X': rb'[-+]?(0[xX])?[0-9a-fA-F]+', 'o': rb'[-+]?[0-7]+'}[c]
            mm = re.compile(pat).match(s[:end], si)
            if not mm:
                break
            t = mm.group(0)
            base = 16 if c in 'xX' else 8 if c == 'o' else 0 if c == 'i' else 10
            try:
                v = int(t, base)
            except ValueError:
                v = int(t, 10)
            si = mm.end()
            if not skip:
                p = va.u32()
                if ln in (b'll', b'I64'):
                    run.write(p, struct.pack('<q', max(min(v, (1 << 63) - 1), -(1 << 63))))
                elif ln == b'h':
                    run.write(p, struct.pack('<H', v & 0xffff))
                elif ln == b'hh':
                    run.write(p, struct.pack('<B', v & 0xff))
                else:
                    run.write(p, struct.pack('<I', v & 0xffffffff))
                n += 1
        elif c in 'eEfgG':
            mm = re.compile(rb'[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?').match(s[:end], si)
            if not mm:
                break
            v = float(mm.group(0))
            si = mm.end()
            if not skip:
                p = va.u32()
                run.write(p, struct.pack('<d', v) if ln in (b'l', b'L') else struct.pack('<f', v))
                n += 1
        elif c == 's':
            j = si
            while j < end and s[j] not in b' \t\n\r':
                j += 1
            if not skip:
                run.write(va.u32(), s[si:j] + b'\0')
                n += 1
            si = j
        elif c == 'c':
            k = width or 1
            if not skip:
                run.write(va.u32(), s[si:si + k])
                n += 1
            si += k
        else:   # %[set]
            body = conv[1:-1]
            neg = body.startswith(b'^')
            chars = set(body[1:] if neg else body)
            j = si
            while j < end and ((s[j] in chars) != neg):
                j += 1
            if j == si:
                break
            if not skip:
                run.write(va.u32(), s[si:j] + b'\0')
                n += 1
            si = j
    return n


# ============================================================================ the models
MODELS = {}


def model(*names):
    def deco(f):
        for n in names:
            MODELS[n] = f
        return f
    return deco


def _cmp(a, b):
    return (a > b) - (a < b)


@model('memcpy', 'memmove')
def m_memcpy(r, c):
    d, s, n = c.arg(0), c.arg(1), c.arg(2)
    if n > MAXCOPY:
        raise ModelFault('%s of 0x%x bytes' % (c.short, n))
    if r.env.stack_lo <= s < r.env.esp0 and not r.env.stack_lo <= d < r.env.esp0:
        # a local buffer copied out whole (a 1 KB string buffer into .data): its unused tail holds what earlier calls
        # left on the stack, which differs between the two frame layouts; compare() treats those bytes as maybe
        r.stack_copies.append((d, n))
    r.write(d, r.read(s, n))
    c.ret(d)


@model('memset')
def m_memset(r, c):
    d, v, n = c.arg(0), c.arg(1), c.arg(2)
    if n > MAXCOPY:
        raise ModelFault('memset of 0x%x bytes' % n)
    r.write(d, bytes([v & 0xff]) * n)
    c.ret(d)


@model('memchr')
def m_memchr(r, c):
    p, v, n = c.arg(0), c.arg(1) & 0xff, c.arg(2)
    i = r.read(p, min(n, MAXCOPY)).find(bytes([v])) if n else -1
    c.ret(p + i if i >= 0 else 0)


@model('strchr', 'strrchr')
def m_strchr(r, c):
    p, v = c.arg(0), c.arg(1) & 0xff
    s = r.cstr(p) + b'\0'
    i = s.find(bytes([v])) if c.short == 'strchr' else s.rfind(bytes([v]))
    c.ret(p + i if i >= 0 else 0)


@model('strstr')
def m_strstr(r, c):
    p, q = c.arg(0), c.arg(1)
    i = r.cstr(p).find(r.cstr(q))
    c.ret(p + i if i >= 0 else 0)


@model('wcsstr')
def m_wcsstr(r, c):
    p, q = c.arg(0), c.arg(1)
    hs, nd = r.cstr(p, wide=True), r.cstr(q, wide=True)
    i = 0
    while i <= len(hs) - len(nd):
        if hs[i:i + len(nd)] == nd:
            break
        i += 2
    c.ret(p + i if i <= len(hs) - len(nd) else 0)


@model('strpbrk')
def m_strpbrk(r, c):
    p = c.arg(0)
    s, cs = r.cstr(p), set(r.cstr(c.arg(1)))
    i = next((k for k, ch in enumerate(s) if ch in cs), -1)
    c.ret(p + i if i >= 0 else 0)


@model('strncmp', '_strnicmp', '_stricmp', '_memicmp')
def m_strcmp(r, c):
    a, b = c.arg(0), c.arg(1)
    if c.short == '_memicmp':
        n = c.arg(2)
        x, y = r.read(a, n).lower(), r.read(b, n).lower()
    else:
        x, y = r.cstr(a), r.cstr(b)
        if c.short != '_stricmp':
            n = c.arg(2)
            x, y = x[:n], y[:n]
        if c.short != 'strncmp':
            x, y = x.lower(), y.lower()
    c.ret(_cmp(x, y) & 0xffffffff)


@model('strncpy')
def m_strncpy(r, c):
    d, s, n = c.arg(0), c.arg(1), c.arg(2)
    t = r.cstr(s, limit=n)[:n]
    r.write(d, t + b'\0' * (n - len(t)))
    c.ret(d)


@model('strncat')
def m_strncat(r, c):
    d, s, n = c.arg(0), c.arg(1), c.arg(2)
    t = r.cstr(s, limit=n)[:n]
    r.write(d + len(r.cstr(d)), t + b'\0')
    c.ret(d)


@model('_strdup')
def m_strdup(r, c):
    p = c.arg(0)
    s = r.cstr(p) + b'\0'
    a = r.alloc(len(s))
    r.write(a, s)
    c.log(s[:-1])
    c.ret(a)


@model('toupper')
def m_toupper(r, c):
    v = c.arg(0)
    c.ret(v - 32 if 0x61 <= v <= 0x7a else v)


@model('isprint')
def m_isprint(r, c):
    v = c.arg(0)
    c.ret(1 if 0x20 <= v <= 0x7e else 0)


def _atoi(s):
    m = re.match(rb'\s*([-+]?\d+)', s)
    return int(m.group(1)) & 0xffffffff if m else 0


@model('atoi', 'atol')
def m_atoi(r, c):
    c.ret(_atoi(r.cstr(c.arg(0))))


@model('atof')
def m_atof(r, c):
    m = re.match(rb'\s*([-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?)', r.cstr(c.arg(0)))
    r.st_push(float(m.group(1)) if m else 0.0)
    c.ret(None)


@model('_ltoa')
def m_ltoa(r, c):
    v, buf, radix = c.sarg(0), c.arg(1), c.arg(2)
    if radix == 10:
        s = str(v).encode()
    else:
        u = v & 0xffffffff
        digits = b''
        while True:
            digits = b'0123456789abcdefghijklmnopqrstuvwxyz'[u % max(radix, 2):u % max(radix, 2) + 1] + digits
            u //= max(radix, 2)
            if not u:
                break
        s = digits
    r.write(buf, s + b'\0')
    c.ret(buf)


@model('strtok')
def m_strtok(r, c):
    s, delim = c.arg(0), set(r.cstr(c.arg(1)))
    p = s or r.strtok
    if not p:
        c.ret(0)
        return
    t = r.cstr(p)
    i = 0
    while i < len(t) and t[i] in delim:
        i += 1
    if i == len(t):
        r.strtok = 0
        c.ret(0)
        return
    j = i
    while j < len(t) and t[j] not in delim:
        j += 1
    if j < len(t):
        r.write(p + j, b'\0')
        r.strtok = p + j + 1
    else:
        r.strtok = 0
    c.ret(p + i)


# ---------------------------------------------------------------- heap
@model('malloc')
def m_malloc(r, c):
    n = c.arg(0)
    c.log(n)
    c.ret(r.alloc(n) if n < MAXCOPY else 0)


@model('calloc')
def m_calloc(r, c):
    n = c.arg(0) * c.arg(1)
    c.log(c.arg(0), c.arg(1))
    c.ret(r.alloc(n, fill=0) if n < MAXCOPY else 0)


@model('realloc')
def m_realloc(r, c):
    p, n = c.arg(0), c.arg(1)
    c.log(p, n)
    if n >= MAXCOPY:
        c.ret(0)
        return
    a = r.alloc(n)
    if p:
        old = r.allocs.get(p)
        k = min(n, old) if old is not None else n
        try:
            data = r.read(p, k)
        except ModelFault:
            data = b''
        r.write(a, data)
    c.ret(a)


@model('free')
def m_free(r, c):
    c.log(c.arg(0))
    c.ret(0)


@model('HeapAlloc')
def m_heapalloc(r, c):
    n, flags = c.arg(2), c.arg(1)
    c.log(flags, n)
    c.ret(r.alloc(n, fill=0 if flags & 8 else 0xcd) if n < MAXCOPY else 0, pop=12)


@model('HeapFree')
def m_heapfree(r, c):
    c.log(c.arg(1), c.arg(2))
    c.ret(1, pop=12)


@model('GetProcessHeap')
def m_getprocessheap(r, c):
    peb = r.u32(r.env.teb + 0x30)
    c.ret(r.u32(peb + 0x18))


# ---------------------------------------------------------------- math (x87 and the SSE2 libm entry points)
@model('_ftol')
def m_ftol(r, c):
    v = r.st(0)
    r.st_pop()
    if v != v or abs(v) >= 2.0 ** 63:
        q = 1 << 63
    else:
        q = int(v) & 0xffffffffffffffff
    c.ret(q & 0xffffffff, q >> 32)


def _x87_2(f):
    def m(r, c):
        y, x = r.st(0), r.st(1)
        r.st_pop()
        r.st_pop()
        try:
            v = f(x, y)
        except (ValueError, OverflowError, ZeroDivisionError):
            v = math.nan
        r.st_push(v)
        c.ret(None)
    return m


MODELS['_CIpow'] = _x87_2(lambda x, y: math.pow(x, y))
MODELS['_CIatan2'] = _x87_2(lambda y, x: math.atan2(y, x))
MODELS['_CIfmod'] = _x87_2(lambda x, y: math.fmod(x, y))


def _x87_1(f):
    def m(r, c):
        x = r.st(0)
        r.st_pop()
        try:
            v = f(x)
        except (ValueError, OverflowError):
            v = math.nan
        r.st_push(v)
        c.ret(None)
    return m


for _n, _f in (('_CIacos', math.acos), ('_CIasin', math.asin), ('_CIsqrt', math.sqrt), ('_CIsin', math.sin),
               ('_CIcos', math.cos), ('_CItan', math.tan), ('_CIatan', math.atan), ('_CIexp', math.exp),
               ('_CIlog', math.log), ('_CIlog10', math.log10)):
    MODELS[_n] = _x87_1(_f)


def _st_double(f):
    def m(r, c):
        try:
            v = f(r, c)
        except (ValueError, OverflowError):
            v = math.nan
        r.st_push(v)
        c.ret(None)
    return m


MODELS['ceil'] = _st_double(lambda r, c: float(math.ceil(c.argd(0))) if math.isfinite(c.argd(0)) else c.argd(0))
MODELS['floor'] = _st_double(lambda r, c: float(math.floor(c.argd(0))) if math.isfinite(c.argd(0)) else c.argd(0))
MODELS['ldexp'] = _st_double(lambda r, c: math.ldexp(c.argd(0), c.sarg(2)))


@model('_isnan')
def m_isnan(r, c):
    c.ret(1 if math.isnan(c.argd(0)) else 0)


def _xmm_d(r, i):
    from unicorn.x86_const import UC_X86_REG_XMM0
    return struct.unpack('<d', struct.pack('<Q', r.mu.reg_read(UC_X86_REG_XMM0 + i) & 0xffffffffffffffff))[0]


def _sse2(f, nargs=1):
    def m(r, c):
        from unicorn.x86_const import UC_X86_REG_XMM0
        try:
            v = f(*[_xmm_d(r, i) for i in range(nargs)])
        except (ValueError, OverflowError, ZeroDivisionError):
            v = math.nan
        old = r.mu.reg_read(UC_X86_REG_XMM0)
        r.mu.reg_write(UC_X86_REG_XMM0, (old & ~0xffffffffffffffff) | struct.unpack('<Q', struct.pack('<d', v))[0])
        c.ret(None)
    return m


for _n, _f in (('sqrt', math.sqrt), ('sin', math.sin), ('cos', math.cos), ('tan', math.tan), ('atan', math.atan),
               ('asin', math.asin), ('acos', math.acos), ('exp', math.exp), ('log', math.log), ('log10', math.log10)):
    MODELS['_libm_sse2_%s_precise' % _n] = _sse2(_f)
MODELS['_libm_sse2_pow_precise'] = _sse2(math.pow, 2)


# ---------------------------------------------------------------- C++ runtime
@model('_CxxThrowException')
def m_throw(r, c):
    info = c.arg(1)
    r.stop = ('throw', 'ThrowInfo 0x%x' % info)


@model('_purecall', '__std_terminate', 'terminate', 'exit', '_exit', 'abort', 'TerminateProcess')
def m_exit(r, c):
    r.stop = ('exit', c.short)


@model('__RTDynamicCast')
def m_dyncast(r, c):
    """dynamic_cast through the MSVC RTTI in the exe's .rdata (complete object locator, class hierarchy, base class
    array). Virtual bases are followed through the vbtable; a failed reference cast throws."""
    p, vfdelta, _src, tgt, isref = (c.arg(i) for i in range(5))
    if not p:
        c.ret(0)
        return
    vft = r.u32(p)
    col = r.u32(vft - 4)
    off, cdoff = r.u32(col + 4), r.u32(col + 8)
    obj = (p - off) & 0xffffffff
    if cdoff:
        obj = (obj - struct.unpack('<i', r.read(p - cdoff, 4))[0]) & 0xffffffff
    tname = r.cstr(tgt + 8, limit=512)
    chd = r.u32(col + 16)
    n, arr = r.u32(chd + 8), r.u32(chd + 12)
    res = 0
    for i in range(min(n, 256)):
        bcd = r.u32(arr + 4 * i)
        td = r.u32(bcd)
        if td != tgt and r.cstr(td + 8, limit=512) != tname:
            continue
        mdisp, pdisp, vdisp = struct.unpack('<iii', r.read(bcd + 8, 12))
        attrs = r.u32(bcd + 20)
        if attrs & 1:          # BCD_NOTVISIBLE
            continue
        q = obj
        if pdisp >= 0:
            vbt = r.u32(obj + pdisp)
            q = obj + pdisp + struct.unpack('<i', r.read(vbt + vdisp, 4))[0]
        res = (q + mdisp) & 0xffffffff
        break
    if not res and isref:
        r.stop = ('throw', 'bad_cast')
        return
    c.ret(res)


# ---------------------------------------------------------------- printf and scanf family
def _sprintf_out(r, c, buf, cap, text, legacy):
    if buf and cap:
        if len(text) < cap:
            r.write(buf, text + b'\0')
        elif legacy:
            r.write(buf, text[:cap])
        else:
            r.write(buf, text[:cap - 1] + b'\0')


@model('__stdio_common_vsprintf')
def m_vsprintf(r, c):
    opts = c.arg(0)
    buf, cap, fmt, va = c.arg(2), c.arg(3), c.arg(4), c.arg(6)
    text = vformat(r, r.cstr(fmt), Va(r, va))
    c.log('sprintf', text)
    _sprintf_out(r, c, buf, cap, text, opts & 1)
    c.ret(len(text) if not buf or len(text) < cap or not opts & 1 else 0xffffffff)


@model('__stdio_common_vsnprintf_s')
def m_vsnprintf_s(r, c):
    buf, size, maxc, fmt, va = c.arg(2), c.arg(3), c.arg(4), c.arg(5), c.arg(7)
    text = vformat(r, r.cstr(fmt), Va(r, va))
    c.log('snprintf_s', text)
    lim = min(maxc, size - 1) if size else 0
    if len(text) <= lim:
        r.write(buf, text + b'\0')
        c.ret(len(text))
    else:
        if size:
            r.write(buf, text[:lim] + b'\0')
        c.ret(0xffffffff)


@model('wsprintfA')
def m_wsprintf(r, c):
    buf, fmt = c.arg(0), c.arg(1)
    text = vformat(r, r.cstr(fmt), Va(r, c.esp + 12))
    c.log('wsprintf', text)
    r.write(buf, text[:1023] + b'\0')
    c.ret(min(len(text), 1023))


@model('wvsprintfA')
def m_wvsprintf(r, c):
    buf, fmt, va = c.arg(0), c.arg(1), c.arg(2)
    text = vformat(r, r.cstr(fmt), Va(r, va))
    c.log('wvsprintf', text)
    r.write(buf, text[:1023] + b'\0')
    c.ret(min(len(text), 1023), pop=12)


@model('__stdio_common_vfprintf')
def m_vfprintf(r, c):
    f, fmt, va = c.arg(2), c.arg(3), c.arg(5)
    text = vformat(r, r.cstr(fmt), Va(r, va))
    c.log(f, text)
    c.ret(len(text))


@model('__stdio_common_vsscanf')
def m_vsscanf(r, c):
    buf, cnt, fmt, va = c.arg(2), c.arg(3), c.arg(4), c.arg(6)
    s = r.cstr(buf) if cnt == 0xffffffff else r.read(buf, cnt).split(b'\0')[0]
    f = r.cstr(fmt)
    c.log(s, f)
    c.ret(vscan(r, s, f, Va(r, va)) & 0xffffffff)


@model('__acrt_iob_func')
def m_iob(r, c):
    c.ret(r.env.hb + 0x800 + 0x40 * (c.arg(0) & 3))


# ---------------------------------------------------------------- C stdio files: the replay has none
@model('fopen')
def m_fopen(r, c):
    c.log(r.cstr(c.arg(0)), r.cstr(c.arg(1)))
    c.ret(0)


@model('fread')
def m_fread(r, c):
    c.log(c.arg(1), c.arg(2), c.arg(3))
    c.ret(0)


@model('fwrite')
def m_fwrite(r, c):
    n = c.arg(1) * c.arg(2)
    c.log(r.read(c.arg(0), min(n, 4096)), c.arg(3))
    c.ret(c.arg(2))


for _n, _k in (('fclose', 1), ('fflush', 1), ('fseek', 3), ('ftell', 1), ('feof', 1), ('ferror', 1), ('rewind', 1),
               ('tmpfile', 0), ('_flushall', 0)):
    def _m(r, c, _k=_k):
        c.log(*[c.arg(i) for i in range(_k)])
        c.ret(0 if c.short != 'feof' else 1)
    MODELS[_n] = _m


# ---------------------------------------------------------------- clocks and randomness: the values of the capture
# Every read of a clock moves it forward by a fixed step from the value the probe saw, so a loop that waits for time
# to pass ends, and both runs see the same sequence as long as they read the clocks in the same order.
def _clock(r, name, base, step):
    n = r.clock_reads.get(name, 0)
    r.clock_reads[name] = n + 1
    return base + n * step


@model('clock')
def m_clock(r, c):
    c.ret(_clock(r, 'clock', r.env.h['time'].get('clock', 0), 1) & 0xffffffff)


@model('_time32')
def m_time(r, c):
    t = (r.env.h['time'].get('ft', 0) - 116444736000000000) // 10000000
    if c.arg(0):
        r.write(c.arg(0), struct.pack('<I', t & 0xffffffff))
    c.ret(t & 0xffffffff)


@model('QueryPerformanceCounter')
def m_qpc(r, c):
    t = r.env.h['time']
    r.write(c.arg(0), struct.pack('<Q', _clock(r, 'qpc', t.get('qpc', 0), max(t.get('qpf', 10000000) // 10000, 1))))
    c.ret(1, pop=4)


@model('QueryPerformanceFrequency')
def m_qpf(r, c):
    r.write(c.arg(0), struct.pack('<Q', r.env.h['time'].get('qpf', 10000000)))
    c.ret(1, pop=4)


@model('GetSystemTimeAsFileTime')
def m_ft(r, c):
    r.write(c.arg(0), struct.pack('<Q', _clock(r, 'ft', r.env.h['time'].get('ft', 0), 1000)))
    c.ret(0, pop=4)


@model('GetTickCount', 'timeGetTime')
def m_tick(r, c):
    c.ret(_clock(r, 'tick', r.env.h['time'].get('tick', 0), 1) & 0xffffffff)


@model('rand')
def m_rand(r, c):
    r.rand_state = (r.rand_state * 214013 + 2531011) & 0xffffffff
    c.log()
    c.ret((r.rand_state >> 16) & 0x7fff)


@model('srand')
def m_srand(r, c):
    r.rand_state = c.arg(0)
    c.log(c.arg(0))
    c.ret(0)


# ---------------------------------------------------------------- kernel32 / user32
@model('GetLastError')
def m_getlasterror(r, c):
    c.ret(r.u32(r.env.teb + 0x34))


@model('GetCurrentThreadId')
def m_tid(r, c):
    c.ret(r.env.h.get('tid', 0))


@model('GetCurrentProcessId')
def m_pid(r, c):
    c.ret(r.env.h.get('pid', 0))


@model('GetCurrentProcess')
def m_curproc(r, c):
    c.ret(0xffffffff)


@model('GetCurrentThread')
def m_curthread(r, c):
    c.ret(0xfffffffe)


@model('EnterCriticalSection', 'LeaveCriticalSection', 'InitializeCriticalSection', 'DeleteCriticalSection',
       'Sleep', 'SetEvent', 'ResetEvent', 'CloseHandle')
def m_simple1(r, c):
    c.log(c.arg(0))
    c.ret(1, pop=4)


@model('WaitForSingleObject')
def m_wait(r, c):
    c.log(c.arg(0), c.arg(1))
    c.ret(0, pop=8)


@model('WaitForSingleObjectEx')
def m_waitex(r, c):
    c.log(c.arg(0), c.arg(1))
    c.ret(0, pop=12)


@model('IsBadReadPtr')
def m_isbadreadptr(r, c):
    p, n = c.arg(0), c.arg(1)
    bad = 0
    a = p & ~0xfff
    while a < p + max(n, 1):
        if not r.src.regions.readable(a) and not (r.env.hb <= a < r.env.hb + 0x02000000):
            bad = 1
            break
        a += 0x1000
    c.ret(bad, pop=8)


@model('OutputDebugStringA')
def m_ods(r, c):
    c.log(r.cstr(c.arg(0)))
    c.ret(0, pop=4)


@model('IsProcessorFeaturePresent')
def m_ipfp(r, c):
    c.ret(1 if c.arg(0) in (3, 6, 7, 8, 10, 13, 17, 18, 21, 23) else 0, pop=4)


@model('CreateFileA', 'FindFirstFileA')
def m_createfile(r, c):
    c.log(r.cstr(c.arg(0)))
    c.ret(0xffffffff, pop=28 if c.short == 'CreateFileA' else 8)


@model('GetFileAttributesA')
def m_getfileattr(r, c):
    c.log(r.cstr(c.arg(0)))
    c.ret(0xffffffff, pop=4)


@model('VirtualQuery')
def m_virtualquery(r, c):
    p, mbi, n = c.arg(0), c.arg(1), c.arg(2)
    reg = r.src.regions.find(p)
    if reg and n >= 28:
        base, size, state, prot, typ = reg
        page = p & ~0xfff
        r.write(mbi, struct.pack('<IIIIIII', page, base, prot, base + size - page, state, prot, typ))
        c.ret(28, pop=12)
    else:
        c.ret(0, pop=12)


# ============================================================================ dispatch
# cdecl functions without a model: how many stack dwords to log
CDECL_ARGS = {'_controlfp_s': 3, '_configthreadlocale': 1, '_set_new_mode': 1, '_localtime32': 1, '_ctime32': 1,
              'bsearch': 5, 'qsort': 4, 'wcstombs': 3, '_set_se_translator': 1, '__std_exception_copy': 2,
              'SteamAPI_Init': 0, 'SteamAPI_Shutdown': 0, 'SteamAPI_RestartAppIfNecessary': 1}
PURE_UNKNOWN = set()


def call(run, name, x):
    c = Call(run, name, x)
    if name.startswith('unknown!'):
        raise ModelFault('call into memory outside every module (0x%x)' % x)
    f = MODELS.get(c.short)
    if f is not None:
        f(run, c)
        return
    pop = run.env.ret_pop(x)
    if pop is None:
        # a forwarder (overlay wrapper): the pop count is the one of the function it jumps to, which depends on the
        # object (this), so the answer is cached per (stub, first argument)
        key = (x, c.arg(0))
        if key not in run.env.forwards:
            t = forward_target(run, x)
            run.env.forwards[key] = run.env.ret_pop(t) if t else None
        pop = run.env.forwards[key]
    if pop is None:
        pop = 0
        nargs = CDECL_ARGS.get(c.short, 0)
        if c.short not in CDECL_ARGS:
            run.unknown_pop.append(name)
    else:
        nargs = pop // 4 if pop else CDECL_ARGS.get(c.short, 0)
    args = [c.arg(i) for i in range(nargs)]
    c.log(*args)
    # An argument that points into the thread stack is most likely an out parameter (D3D Lock, Get*, QueryInterface):
    # the real DLL would fill it. Both runs get the same answer there, a pointer to a fresh zeroed fake-heap block, so
    # an uninitialised local does not differ between the frames, and what the code writes through it is compared.
    env = run.env
    for v in args:
        if env.stack_lo <= v < env.stack_hi - 4:
            try:
                run.write(v, struct.pack('<I', run.alloc(0x1000, fill=0)))
            except ModelFault:
                pass
    c.ret(0, pop=pop)
