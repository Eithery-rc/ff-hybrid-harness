#!/usr/bin/env python
"""audit_ports.py - static audit of the hooked ports for interface bugs the verification checker cannot see.

Run (about 3 minutes):  python -I hybrid/audit_ports.py

For every address in build/ff_ports.tsv it compares, at machine-code level, the original exe function
(game/Freedom.Exe) with the compiled port (build/ff_ports.bin at port_entry), and reads the verification spec
(ports/*/harness/specs_*.py) and the port's C++ signature (ports/<folder>/src) to say why the checker did not notice.

Interface of a function = registers read before they are written (ECX / EDX / others), the `ret N` pop count, whether EAX /
ST0 holds a result at `ret`. The exe side also gets caller evidence: a direct `call <addr>` site that reads EAX (AL, AX or
EAX) after the call before overwriting it.

Outputs (build/): audit.tsv (exe_addr, folder, category, evidence), audit_exclude.txt (hooks.ini exclude_file format:
categories 1 and 2 with evidence), audit_exclude_unverified.txt (softer findings).

Categories
  1 return value
    ret-lost              port never sets EAX before ret, a caller reads it                       (exclude)
    ret-void-scratch      port declared void, spec does not compare EAX, port writes EAX with an unrelated value  (exclude)
    ret-void-passthrough  same, but EAX is only whatever the port's last call returned            (exclude)
    ret-unchecked         spec ret=None/absent, port returns a value, a caller reads it           (exclude)
    ret-narrow            port returns u8/bool or spec compares AL, callers read all of EAX       (exclude)
    ret-st0-lost          original leaves a value on the x87 stack, port leaves none               (exclude)
    ret-lost-passthrough / ret-lost-nocaller(-weak) / ret-void-nocaller   no direct caller reads it: callers unknown (soft)
  2 calling convention
    conv-ecx / conv-edx / conv-reg   original reads the register before writing it, port never reads it (exclude)
    pop-mismatch          original `ret N` (or its tail target's) differs from the port's `ret N`    (exclude)
    conv-spec             spec abi is cdecl/stdcall (thiscall) but the original reads ECX (EDX): the check ran without a real
                          this pointer (soft)
  3 other
    void-port-eax-local   port is void and its body assigns a local named eax
  4 v2 detectors (defect classes found by bisecting the live game, hybrid/build/hunt.tsv; written to audit_exclude_v2.txt,
    which holds only addresses missing from audit_exclude*.txt and game/exclude_night.txt)
    sec-cookie-const      port calls __security_check_cookie (0x633654) with a constant ECX: fast-fail 0xC0000409
    pending-stack-args    orig pushes arguments, calls an input-less accessor, then another call consumes the pushes
    va-address-lost       orig takes the address of its argument area past the named args (va_list), port never does
    local-too-small       orig hands a local to a virtual call with room for N bytes, the port's matching local is smaller
    fwd-args-dropped      orig is a pure tail-jump forwarder (indirect, or to a function that reads stack args), port calls
                          the target with no stack args and returns with ret 0
  5 v3 detectors (second batch of runtime culprits; audit_exclude_v3.txt, audit_exclude_v3_folders.txt, audit_fix_const_args.tsv)
    clobbers-callee-saved port leaves ebx / esi / edi / ebp modified at a ret (naked wrapper without push / pop), orig preserves it
    no-stack-probe        port reserves a frame of 4 KB or more with a plain `sub esp` (no __chkstk): skips the guard page
    bool-upper-garbage    orig returns a clean 0..255 in EAX, port only sets AL over a stale EAX
    sec-cookie-stale      port calls __security_check_cookie without loading ECX (the cookie is passed on the stack instead)
    call-arg-mismatch     same callee, one call site each, plain pushes / stores: a constant argument changed or moved (swapped
                          arguments, wrong object size passed to the sized delete 0x4690b0)
    byvalue-arg-truncated orig takes the address of a multi-dword by-value stack argument, the port reads only part of it
    vslot-thunk-arity     orig is a `jmp [vtable+off]` thunk, the port's `ret N` disagrees with the parameter list in its name
    local-too-small       (v2 class, bug fixed: an address pushed and then the register reused was missed) 92 more hits
  6 v4 detectors (third batch; audit_exclude_v4.txt = flagged and not in game/exclude_level2.txt)
    call-args-short       port calls an exe function with fewer stack arg dwords than the callee reads / pops (wrong declared arity or
                          convention of the callee, a vslot popping fewer args than assumed so the rest belong to a later call)
    call-this-unset       port calls an exe function that reads ECX on entry without setting ECX (call-edx-unset: the same for EDX)
    orig-pending-slot     the original touches a stack slot below esp through a saved esp (MSVC pending-argument layout)
    orig-pending-args     the original pushes some arguments of a call before an earlier virtual call (callee pops fewer than the
                          pushes next to it); the port's vslot arities are then a guess (informational, no verdict)
  The folder table (hooked / culprits / already excluded / GUESS-named / no spec) is printed at the end of a run.
  Parse problems: parse-fail-orig / -port / -spec / -source, and no-spec-found (no S() for the address in any harness).

Nothing here runs the game or touches game/ (the exe is only read). Parse problems are recorded, never guessed.
"""
import ast
import bisect
import collections
import glob
import json
import os
import re
import struct
import sys
import threading

import capstone
import pefile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(ROOT, 'game', 'Freedom.Exe')
BUILD = os.path.join(ROOT, 'hybrid', 'build')
# AUDIT_IMAGE_DIR: audit another image (e.g. hybrid/build/ports_next); AUDIT_OUT_DIR: write the results there too, so a
# trial run does not replace the audit files of the live build.
IMAGE_DIR = os.environ.get('AUDIT_IMAGE_DIR') or BUILD
OUT_DIR = os.environ.get('AUDIT_OUT_DIR') or BUILD
PORTS_BIN = os.path.join(IMAGE_DIR, 'ff_ports.bin')
PORTS_TSV = os.path.join(IMAGE_DIR, 'ff_ports.tsv')
PORTS_SYMS = os.path.join(IMAGE_DIR, 'ff_ports.syms')
PLAN_TSV = os.path.join(BUILD, 'hooks_plan.tsv')
SPEC_ROOT = os.path.join(ROOT, 'ReFreedomFighters', 'ports')
OUT_TSV = os.path.join(OUT_DIR, 'audit.tsv')
OUT_EXCLUDE = os.path.join(OUT_DIR, 'audit_exclude.txt')
OUT_EXCLUDE_UNVERIFIED = os.path.join(OUT_DIR, 'audit_exclude_unverified.txt')
OUT_EXCLUDE_V2 = os.path.join(OUT_DIR, 'audit_exclude_v2.txt')
OUT_EXCLUDE_V3 = os.path.join(OUT_DIR, 'audit_exclude_v3.txt')
OUT_EXCLUDE_V3_FOLDERS = os.path.join(OUT_DIR, 'audit_exclude_v3_folders.txt')
OUT_EXCLUDE_V4 = os.path.join(OUT_DIR, 'audit_exclude_v4.txt')
OUT_FIX_CONST = os.path.join(OUT_DIR, 'audit_fix_const_args.tsv')
PORT_BASE = 0x31000000
EXE_BASE = 0x400000

# ------------------------------------------------------------------------------------------ registers
REG_NAMES = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'ebp']
# Registers are tracked in three slices each (bit 0: bits 0-7, bit 1: bits 8-15, bit 2: bits 16-31), so that
# `fnstsw ax; test ah, 1` is not a read of the incoming EAX, while `mov ax, 1; cmp eax, 2` is.
SUB = {}   # register name -> (canonical index, slice mask, width in bits)
for _i, (_r32, _r16, _r8l, _r8h) in enumerate([('eax', 'ax', 'al', 'ah'), ('ecx', 'cx', 'cl', 'ch'),
                                                ('edx', 'dx', 'dl', 'dh'), ('ebx', 'bx', 'bl', 'bh'),
                                                ('esi', 'si', None, None), ('edi', 'di', None, None),
                                                ('ebp', 'bp', None, None)]):
    SUB[_r32] = (_i, 7 << (3 * _i), 32)
    SUB[_r16] = (_i, 3 << (3 * _i), 16)
    if _r8l:
        SUB[_r8l] = (_i, 1 << (3 * _i), 8)
        SUB[_r8h] = (_i, 2 << (3 * _i), 8)
EAX, ECX, EDX = 7, 7 << 3, 7 << 6   # slice masks
ALLREG = (1 << 21) - 1
CLOBBER = EAX | ECX | EDX           # destroyed by a call
PROPAGATE = ECX | EDX               # registers whose callee live-in is passed on to the caller (others: noreturn
                                    # helpers such as __report_gsfailure dump every register)


def regs_of(m):
    """slice mask -> register-level mask. A register counts as an input when its low byte is read before it is
    written: `mov dl, [x]; lea ecx, [edx-0x61]; cmp cl, ..` reads the upper bits of EDX but only to use CL."""
    return sum(1 << i for i in range(7) if m >> (3 * i) & 1)


def mask_names(m):
    return ','.join(n for i, n in enumerate(REG_NAMES) if m >> (3 * i) & 7) or '-'


# x87 stack depth effect by mnemonic (only what changes the depth)
FPU_PUSH = {'fld', 'fild', 'fld1', 'fldz', 'fldpi', 'fldl2e', 'fldl2t', 'fldlg2', 'fldln2', 'fbld', 'fsincos',
            'fptan', 'fxtract'}
FPU_POP = {'fstp', 'fistp', 'fisttp', 'fbstp', 'fcomp', 'ficomp', 'fucomp', 'faddp', 'fsubp', 'fsubrp', 'fmulp',
           'fdivp', 'fdivrp', 'fcomip', 'fucomip', 'ffreep', 'fyl2x', 'fpatan', 'fyl2xp1'}
FPU_POP2 = {'fcompp', 'fucompp'}
FPU_RESET = {'finit', 'fninit'}

K_SEQ, K_JMP, K_JCC, K_CALL, K_RET, K_INDJMP, K_INDCALL, K_STOP = range(8)


class Insn:
    __slots__ = ('addr', 'size', 'mnem', 'kind', 'target', 'uses', 'defs', 'push_uses', 'ereads',
                 'pop', 'fpu', 'tbl', 'cmpimm', 'mbase', 'mdisp', 'mindex', 'lea', 'immdef', 'absdef', 'espadj',
                 'espset', 'movebp', 'fsmem', 'argop', 'msize', 'eaxhi', 'memdst', 'espsrc')


class Img:
    def __init__(self, name, data, base, code_lo, code_hi):
        self.name, self.data, self.base = name, data, base
        self.code_lo, self.code_hi = code_lo, code_hi
        self.end = base + len(data)

    def read(self, va, n):
        o = va - self.base
        if o < 0 or o >= len(self.data):
            return b''
        return bytes(self.data[o:o + n])

    def u32(self, va):
        b = self.read(va, 4)
        return struct.unpack('<I', b)[0] if len(b) == 4 else None

    def in_code(self, va):
        return self.code_lo <= va < self.code_hi


def load_exe():
    pe = pefile.PE(EXE, fast_load=True)
    size = pe.OPTIONAL_HEADER.SizeOfImage
    buf = bytearray(size)
    buf[:len(pe.header)] = pe.header
    code_lo = code_hi = None
    secs = []
    for s in pe.sections:
        raw = s.get_data()
        va = s.VirtualAddress
        buf[va:va + len(raw)] = raw
        name = s.Name.rstrip(b'\0').decode('latin1')
        secs.append((name, EXE_BASE + va, EXE_BASE + va + max(s.Misc_VirtualSize, len(raw)), s.Characteristics))
        if s.Characteristics & 0x20000000 and code_lo is None:    # first executable section
            code_lo, code_hi = EXE_BASE + va, EXE_BASE + va + max(s.Misc_VirtualSize, len(raw))
    entry = EXE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return Img('exe', buf, EXE_BASE, code_lo, code_hi), secs, entry


def load_port():
    data = open(PORTS_BIN, 'rb').read()
    return Img('port', data, PORT_BASE, PORT_BASE, PORT_BASE + len(data))


# ------------------------------------------------------------------------------------------ decoding
class Decoder:
    def __init__(self, img):
        self.img = img
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.cache = {}

    def text(self, va):
        raw = self.img.read(va, 16)
        try:
            i = next(self.md.disasm(raw, va, 1))
        except StopIteration:
            return '?'
        return ('%s %s' % (i.mnemonic, i.op_str)).strip()

    def at(self, va):
        c = self.cache
        if va in c:
            return c[va]
        r = self._decode(va)
        c[va] = r
        return r

    def _decode(self, va):
        img = self.img
        if not img.in_code(va):
            return None
        raw = img.read(va, 16)
        if not raw:
            return None
        try:
            i = next(self.md.disasm(raw, va, 1))
        except StopIteration:
            return None
        it = Insn()
        it.addr, it.size = va, i.size
        mn = sys.intern(i.mnemonic)
        # drop rep/lock/bnd prefixes shown in the mnemonic text (capstone 5 keeps them in the mnemonic)
        it.mnem = mn
        it.target, it.pop, it.fpu, it.tbl, it.cmpimm = None, 0, 0, None, None
        it.mbase, it.mdisp, it.mindex, it.lea, it.immdef, it.absdef, it.espadj, it.espset, it.movebp = \
            None, 0, False, False, None, None, None, False, False
        it.fsmem = False
        it.memdst = False
        it.espsrc = False
        it.argop = None
        it.msize = 0
        it.eaxhi = None
        base = mn.split(' ')[-1]
        ops = i.operands
        if base == 'cmp' and len(ops) == 2 and ops[1].type == capstone.x86.X86_OP_IMM:
            it.cmpimm = ops[1].imm & 0xffffffff
        elif base == 'and' and len(ops) == 2 and ops[1].type == capstone.x86.X86_OP_IMM and 0 < ops[1].imm < 256                 and ops[1].imm & (ops[1].imm + 1) == 0:
            it.cmpimm = ops[1].imm                  # `and reg, 3` bounds a following table index too
        if base == 'call':
            if ops and ops[0].type == capstone.x86.X86_OP_IMM:
                it.kind, it.target = K_CALL, ops[0].imm & 0xffffffff
            else:
                it.kind = K_INDCALL
        elif base == 'jmp':
            if ops and ops[0].type == capstone.x86.X86_OP_IMM:
                it.kind, it.target = K_JMP, ops[0].imm & 0xffffffff
            else:
                it.kind = K_INDJMP
                o = ops[0] if ops else None
                if o is not None and o.type == capstone.x86.X86_OP_MEM and o.mem.index != 0 and o.mem.base == 0:
                    it.tbl = (o.mem.disp & 0xffffffff, o.mem.scale)
        elif base in ('ret', 'retn'):
            it.kind = K_RET
            if ops and ops[0].type == capstone.x86.X86_OP_IMM:
                it.pop = ops[0].imm & 0xffff
        elif base in ('int3', 'hlt', 'ud2', 'retf', 'iret', 'iretd', 'int') or raw[:2] == b'\x00\x00':
            it.kind = K_STOP                    # (00 00 = `add [eax], al` is zero padding between functions)
        elif base[0] == 'j' or base in ('loop', 'loope', 'loopne'):
            if ops and ops[0].type == capstone.x86.X86_OP_IMM:
                it.kind, it.target = K_JCC, ops[0].imm & 0xffffffff
            else:
                it.kind = K_STOP
        else:
            it.kind = K_SEQ
        # registers
        rd, wr = i.regs_access()
        uses = defs = push_uses = ereads = 0
        for r in rd:
            sb = SUB.get(i.reg_name(r))
            if sb is None:
                continue
            uses |= sb[1]
            if sb[0] == 0:
                ereads |= {8: 1, 16: 2, 32: 4}[sb[2]]
        for r in wr:
            sb = SUB.get(i.reg_name(r))
            if sb is not None:
                defs |= sb[1]
        if base == 'cdq':
            defs = EDX
        # idioms whose result does not depend on the old value: no read of the register
        if len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG:
            sb = SUB.get(i.reg_name(ops[0].reg))
            if sb is not None:
                idiom = False
                if base in ('xor', 'sub', 'sbb') and ops[1].type == capstone.x86.X86_OP_REG and ops[1].reg == ops[0].reg:
                    idiom = True
                elif ops[1].type == capstone.x86.X86_OP_IMM:
                    full = (1 << sb[2]) - 1
                    if base == 'or' and (ops[1].imm & full) == full:
                        idiom = True
                    elif base == 'and' and (ops[1].imm & full) == 0:
                        idiom = True
                if idiom:
                    uses &= ~sb[1]
                    if sb[0] == 0:
                        ereads = 0
        # push reg: a save / stack-slot reservation more often than a real use; keep it apart
        if base == 'push' and ops and ops[0].type == capstone.x86.X86_OP_REG:
            sb = SUB.get(i.reg_name(ops[0].reg))
            if sb is not None and sb[2] == 32:
                push_uses = sb[1]
                uses &= ~push_uses
        if base == 'mov' and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_REG                 and ops[0].mem.index == 0 and i.reg_name(ops[0].mem.base) in ('ebp', 'esp'):
            sb = SUB.get(i.reg_name(ops[1].reg))
            if sb is not None and sb[2] == 32:
                push_uses |= sb[1]
                uses &= ~sb[1]
        if base == 'cpuid':
            uses &= ~ECX                    # ECX is only the sub-leaf, which most leaves ignore
        if base in ('nop', 'fnop', 'prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchnta', 'prefetchw'):
            uses = ereads = 0
        # x87 depth
        if base in FPU_PUSH:
            it.fpu = 1
        elif base in FPU_POP:
            it.fpu = -1
        elif base in FPU_POP2:
            it.fpu = -2
        elif base in FPU_RESET:
            it.fpu = 99
        it.uses, it.defs, it.push_uses, it.ereads = uses, defs, push_uses, ereads
        # memory operand, immediate / absolute loads, stack pointer effects (for the interface detectors)
        for o in ops:
            if o.type == capstone.x86.X86_OP_MEM:
                it.mbase = i.reg_name(o.mem.base) if o.mem.base else ''
                it.mdisp, it.mindex = o.mem.disp, o.mem.index != 0
                it.fsmem = bool(o.mem.segment) and i.reg_name(o.mem.segment) == 'fs'
                it.msize = o.size
                break
        it.lea = base == 'lea'
        it.memdst = bool(ops) and ops[0].type == capstone.x86.X86_OP_MEM and base != 'lea'
        if len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG:
            sb = SUB.get(i.reg_name(ops[0].reg))
            if sb is not None and sb[2] == 32:
                if base == 'mov' and ops[1].type == capstone.x86.X86_OP_IMM:
                    it.immdef = (sb[0], ops[1].imm & 0xffffffff)
                elif base in ('xor', 'sub') and ops[1].type == capstone.x86.X86_OP_REG and ops[1].reg == ops[0].reg:
                    it.immdef = (sb[0], 0)
                elif base == 'mov' and ops[1].type == capstone.x86.X86_OP_MEM and not ops[1].mem.base and not ops[1].mem.index \
                        and not ops[1].mem.segment:
                    it.absdef = (sb[0], ops[1].mem.disp & 0xffffffff)
            if i.reg_name(ops[0].reg) == 'esp':
                if base in ('add', 'sub') and ops[1].type == capstone.x86.X86_OP_IMM:
                    it.espadj = ops[1].imm if base == 'sub' else -ops[1].imm
                else:
                    it.espset = True                       # mov esp, ebp / lea esp, [..] / and esp, -16
            elif i.reg_name(ops[0].reg) == 'ebp' and base == 'mov' and ops[1].type == capstone.x86.X86_OP_REG \
                    and i.reg_name(ops[1].reg) == 'esp':
                it.movebp = True
            elif base == 'mov' and ops[1].type == capstone.x86.X86_OP_REG and i.reg_name(ops[1].reg) == 'esp' \
                    and SUB.get(i.reg_name(ops[0].reg), (0, 0, 0))[2] == 32:
                it.espsrc = True                           # mov reg, esp: the register now points into the stack
        # what the instruction does to the upper 24 bits of EAX: 'Z' = result provably < 256, 'U' = unknown, 'P' = only
        # AL / AX written (upper bits kept)
        if it.kind in (K_CALL, K_INDCALL):
            it.eaxhi = 'U'
        elif defs & EAX == EAX:
            if it.immdef and it.immdef[0] == 0 and it.immdef[1] < 256:
                it.eaxhi = 'Z'
            elif base == 'movzx' and len(ops) == 2 and ops[1].size == 1:
                it.eaxhi = 'Z'
            elif base == 'and' and it.cmpimm is not None and it.cmpimm < 256:
                it.eaxhi = 'Z'
            else:
                it.eaxhi = 'U'
        elif defs & EAX:
            it.eaxhi = 'P'
        # outgoing stack argument: `push X` or `mov [esp+k], X`
        def _opd(o):
            if o.type == capstone.x86.X86_OP_IMM:
                return ('imm', o.imm & 0xffffffff)
            if o.type == capstone.x86.X86_OP_REG:
                return ('reg', i.reg_name(o.reg))
            if o.type == capstone.x86.X86_OP_MEM:
                return ('mem', i.reg_name(o.mem.base) if o.mem.base else '', o.mem.disp)
            return ('?',)
        if base == 'push' and ops:
            it.argop = ('push', _opd(ops[0]))
        elif base == 'mov' and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_MEM and it.mbase == 'esp' \
                and not it.mindex and ops[0].size == 4 and ops[1].type in (capstone.x86.X86_OP_IMM, capstone.x86.X86_OP_REG):
            it.argop = ('store', it.mdisp, _opd(ops[1]))
        if base in ('push', 'pushfd'):
            it.espadj = 4
        elif base in ('pop', 'popfd'):
            it.espadj = -4
            if ops and ops[0].type == capstone.x86.X86_OP_REG and i.reg_name(ops[0].reg) == 'esp':
                it.espadj, it.espset = None, True
        elif base == 'leave':
            it.espset = True
        return it


# ------------------------------------------------------------------------------------------ function analysis
class FI:
    """Interface summary of one function."""
    __slots__ = ('entry', 'ok', 'err', 'live', 'live_weak', 'pops', 'eax_kinds', 'eax_unread', 'fpu', 'n', 'tails',
                 'indtail', 'switch', 'truncated', 'cookie_const', 'argaddr', 'nstack', 'local_ext', 'local_kind',
                 'pending', 'has_ret', 'local_ext_ic', 'arg_slots', 'lea_slots', 'clobbers', 'eax_hi', 'frame', 'probe',
                 'cookie_stale', 'callsigs', 'callargs', 'below_esp')

    def __init__(self, entry):
        self.entry = entry
        self.ok = False
        self.err = ''
        self.live = 0            # registers read before written (push saves excluded)
        self.live_weak = 0       # ... including push reads
        self.pops = set()
        self.eax_kinds = 0       # bit 1 IN (untouched), 2 W (full write), 4 WP (partial), 8 C (call result)
        self.eax_unread = 0      # the subset of those definitions that nothing in the function reads before ret
        self.fpu = set()
        self.n = 0
        self.tails = []
        self.indtail = False
        self.switch = False
        self.truncated = False
        self.cookie_const = []   # [(call site, constant)]: __security_check_cookie called with a constant ECX
        self.argaddr = False     # takes the address of its incoming stack arguments (va_list)
        self.nstack = 0          # stack argument dwords it reads
        self.local_ext = []      # extents (bytes) of its address-taken locals, largest first
        self.local_kind = None
        self.local_ext_ic = []   # the same, only for locals whose address reaches an indirect (virtual) call
        self.arg_slots = set()   # stack argument dwords it reads
        self.lea_slots = set()   # stack argument dwords whose address it takes
        self.clobbers = 0        # callee-saved registers (ebx esi edi ebp) it leaves modified at a ret
        self.eax_hi = set()      # upper-bits state of EAX at ret: Z (clean byte), U (unknown), PU (AL set over unknown bits)
        self.frame = 0           # largest `sub esp, N`
        self.probe = False       # calls a stack probe (__chkstk / _alloca_probe)
        self.cookie_stale = []   # [(call site, why)]: __security_check_cookie called without setting ECX
        self.callsigs = []       # [(callee key, argument operands)] for direct calls with plain push / esp-store arguments
        self.callargs = []       # [(call site, callee, stack arg dwords supplied, ECX set, run is clean)] for every direct call
        self.below_esp = []      # [(site, why)]: a stack slot reached through a saved esp that a call has already popped
        self.pending = []        # [(call site, callee, pushes)]: pushes consumed by a LATER call (callee ignores them)
        self.has_ret = False


IN, W, WP, C = 1, 2, 4, 8
COOKIE_CHECK = 0x633654


class Analyzer:
    def __init__(self, exe, port, funcstarts_exe, funcstarts_port):
        self.dec = {'exe': Decoder(exe), 'port': Decoder(port)}
        self.img = {'exe': exe, 'port': port}
        self.starts = {'exe': funcstarts_exe, 'port': funcstarts_port}         # a fall-through into one ends the walk
        self.tailstarts = {'exe': funcstarts_exe, 'port': funcstarts_port}     # a `jmp` to one is a tail call
        self.memo = {}
        self.inprog = set()

    def which(self, va):
        if self.img['port'].base <= va < self.img['port'].end:
            return 'port'
        if self.img['exe'].in_code(va):
            return 'exe'
        return None

    def info(self, va):
        if va in self.memo:
            return self.memo[va]
        w = self.which(va)
        if w is None:
            fi = FI(va)
            fi.err = 'outside code'
            self.memo[va] = fi
            return fi
        if va in self.inprog:
            fi = FI(va)
            fi.err = 'cycle'
            return fi                      # not memoised
        self.inprog.add(va)
        try:
            fi = self._analyze(w, va)
        finally:
            self.inprog.discard(va)
        self.memo[va] = fi
        return fi

    # --- CFG
    def explore(self, w, entry, fi, limit=6000):
        dec = self.dec[w]
        starts = self.starts[w]
        tailstarts = self.tailstarts[w]
        insns, succ = {}, {}
        top = entry
        work = [(entry, None)]
        while work:
            a, bound = work.pop()
            while True:
                if a in insns:
                    break
                if len(insns) >= limit:
                    fi.truncated = True
                    return insns, succ
                it = dec.at(a)
                if it is None:
                    fi.err = 'undecodable at 0x%x' % a
                    return insns, succ
                insns[a] = it
                if a > top:
                    top = a
                k = it.kind
                nxt = a + it.size
                if it.cmpimm is not None:
                    bound = it.cmpimm
                if k in (K_SEQ, K_CALL, K_INDCALL):
                    # Port: symbols are reliable, so a fall-through into the next function ends the walk (a call to a
                    # noreturn function is followed by padding that decodes as nop). Exe: MSVC pads with int3, and
                    # some "function starts" are fragments inside a bigger function, so only int3 ends the walk.
                    if w == 'port' and nxt in starts and nxt != entry:
                        succ[a] = []
                        break
                    succ[a] = [nxt]
                    a = nxt
                    continue
                if k == K_JCC:
                    succ[a] = [nxt, it.target]
                    work.append((it.target, bound))
                    a = nxt
                    continue
                if k == K_JMP:
                    t = it.target
                    # a jump to a function start is a tail call, unless it lands inside the span already walked
                    # (a loop back edge to a fragment entry) or leaves the image (port -> original exe code)
                    if (t in tailstarts and t != entry and not entry < t <= top) or not self.img[w].in_code(t):
                        fi.tails.append((a, it.target))
                        succ[a] = []
                    else:
                        succ[a] = [it.target]
                        work.append((it.target, bound))
                    break
                if k == K_INDJMP:
                    tg = self.switch_targets(w, it, bound, entry)
                    if tg:
                        fi.switch = True
                        succ[a] = tg
                        work.extend((t, None) for t in tg)
                    else:
                        fi.indtail = True
                        succ[a] = []
                    break
                succ[a] = []              # ret / stop
                break
        for k_ in succ:
            succ[k_] = [x_ for x_ in succ[k_] if x_ in insns]
        return insns, succ

    def switch_targets(self, w, it, bound, entry=None):
        """Targets of `jmp [index*4 + table]`; the entry count comes from the preceding `cmp index, N` (N+1 entries)."""
        if not it.tbl:
            return None
        disp, scale = it.tbl
        if scale != 4:
            return None
        img = self.img[w]
        out = []
        n = bound + 1 if bound is not None and 0 <= bound < 1024 else 24
        for k in range(n):
            v = img.u32(disp + 4 * k)
            if v is None or not img.in_code(v) or abs(v - it.addr) > 0x20000:
                break
            out.append(v)
        return out or None

    def _features(self, w, insns, succ, fi):
        """Stack / frame facts used by the interface detectors (security cookie, stack args, address-taken locals)."""
        order = sorted(insns)
        # 1. __security_check_cookie (0x633654) called with a constant ECX: the real one compares ECX with [0x6f5630]
        for idx, a in enumerate(order):
            it = insns[a]
            if it.kind == K_CALL and it.target == COOKIE_CHECK:
                for j in range(idx - 1, max(idx - 9, -1), -1):
                    q = insns[order[j]]
                    if q.kind not in (K_SEQ, K_JCC):
                        break
                    if q.immdef and q.immdef[0] == 1:
                        fi.cookie_const.append((a, q.immdef[1]))
                        break
                    if (q.absdef and q.absdef[0] == 1) or q.defs & ECX:
                        break
        seh_lea = set()
        for idx, a in enumerate(order):
            if insns[a].lea and any(insns[order[j]].fsmem for j in range(idx + 1, min(idx + 4, len(order)))):
                seh_lea.add(a)               # the address goes to fs:[0]: an SEH registration record, not a buffer
        # 2. stack pointer tracking from the entry: highest stack argument read, address of the argument area taken
        entry = fi.entry
        state = {entry: (0, None)}
        work = [entry]
        maxarg = -1
        lea_idx = []
        ebp_acc, ebp_lea = set(), set()
        while work:
            a = work.pop()
            it = insns[a]
            e, b = state[a]
            if it.mbase and not it.mindex:
                rel = None
                if it.mbase == 'esp' and e is not None:
                    rel = e + it.mdisp
                elif it.mbase == 'ebp' and b is not None:
                    rel = b + it.mdisp
                if rel is not None and rel >= 4 and not it.espset:
                    if it.lea:
                        lea_idx.append((rel - 4) // 4)
                    else:
                        maxarg = max(maxarg, (rel - 4) // 4)
                        for k_ in range(max(1, it.msize // 4)):
                            fi.arg_slots.add((rel - 4) // 4 + k_)
                if it.mbase == 'ebp' and it.mdisp < 0 and not it.espset and a not in seh_lea:  # (`lea esp, [ebp-N]` = epilogue)
                    (ebp_lea if it.lea else ebp_acc).add(it.mdisp)
            if it.movebp:
                b = e
            if it.espadj is not None and e is not None:
                e -= it.espadj
            elif it.espset:
                m = it.mnem.split(' ')[-1]
                if m == 'leave':
                    e, b = (b + 4 if b is not None else None), None
                elif m == 'mov':
                    e = b
                elif m == 'lea' and it.mbase == 'ebp' and b is not None:
                    e = b + it.mdisp
                else:
                    e = None
            if it.kind == K_CALL and e is not None:
                tf = self.memo.get(it.target)
                if tf is not None and tf.ok and len(tf.pops) == 1:
                    e += next(iter(tf.pops))
            for sc in succ.get(a, ()):
                if sc not in state:
                    state[sc] = (e, b)
                    work.append(sc)
        fi.nstack = maxarg + 1
        # va_start pattern: the address of an argument slot past every slot the function reads by name
        fi.argaddr = any(i_ >= fi.nstack for i_ in lea_idx)
        fi.lea_slots = set(lea_idx)
        # 3. address-taken locals: extent = distance to the next used slot above (ebp frames: all functions with one;
        #    esp frames: clang ports, when nothing is pushed after the frame is set up)
        def reaches_icall(idx):
            # lea reg, [local]; ...; push reg / mov [esp+k], reg / mov ecx, reg; ...; call [..]  (within 8 instructions)
            q0 = insns[order[idx]]
            reg = next((r for r in range(7) if q0.defs >> (3 * r) & 7 == 7), None)
            if reg is None:
                return False
            bit = 7 << (3 * reg)
            used_it = False
            for j in range(idx + 1, min(idx + 9, len(order))):
                q = insns[order[j]]
                if q.kind == K_INDCALL:
                    return used_it
                if q.kind not in (K_SEQ, K_JCC):
                    return False
                if q.uses & bit or q.push_uses & bit:
                    used_it = True
                if q.defs & bit and not used_it:
                    return False
            return False

        ic_disp = set()
        for idx, a in enumerate(order):
            q = insns[a]
            if q.lea and q.mbase in ('ebp', 'esp') and not q.mindex and a not in seh_lea and not q.espset and reaches_icall(idx):
                ic_disp.add((q.mbase, q.mdisp))
        if ebp_lea:
            used = ebp_acc | ebp_lea
            fi.local_ext = sorted(((min([x for x in used if x > d] or [0]) - d) for d in ebp_lea), reverse=True)
            fi.local_ext_ic = sorted(((min([x for x in used if x > d] or [0]) - d) for d in ebp_lea if ('ebp', d) in ic_disp),
                                     reverse=True)
            fi.local_kind = 'ebp'
        else:
            frame_k = None
            stable = True
            seen_sub = False
            for a in order:
                it = insns[a]
                m = it.mnem.split(' ')[-1]
                if not seen_sub:
                    if m == 'sub' and it.espadj and it.espadj > 0 and not it.mindex:
                        seen_sub, frame_k = True, it.espadj
                    continue
                if m == 'push' or (m == 'add' and it.espadj is not None):
                    stable = False
            if seen_sub and stable:
                lea_d = {it.mdisp for it in insns.values()
                         if it.lea and it.mbase == 'esp' and not it.mindex and it.mdisp >= 0 and it.addr not in seh_lea}
                acc_d = {it.mdisp for it in insns.values() if it.mbase == 'esp' and not it.mindex and it.mdisp >= 0}
                if lea_d:
                    used = acc_d | lea_d
                    fi.local_ext = sorted(((min([x for x in used if x > d] or [frame_k]) - d) for d in lea_d), reverse=True)
                    fi.local_ext_ic = sorted(((min([x for x in used if x > d] or [frame_k]) - d) for d in lea_d
                                              if ('esp', d) in ic_disp), reverse=True)
                    fi.local_kind = 'esp'
        # 4. exe only: pushes that feed the NEXT call because the callee A reads no stack arguments at all
        if w == 'exe':
            for idx, a in enumerate(order):
                it = insns[a]
                if it.kind != K_CALL or not self.which(it.target):
                    continue
                npush = 0
                j = idx - 1
                while j >= 0 and insns[order[j]].mnem.split(' ')[-1] == 'push' and order[j] + insns[order[j]].size == order[j + 1]:
                    # (a push of ebx / esi / edi / ebp is a prologue save, not an argument)
                    if not insns[order[j]].push_uses & (7 << 9 | 7 << 12 | 7 << 15 | 7 << 18):
                        npush += 1
                    j -= 1
                if not npush:
                    continue
                nxt = insns.get(a + it.size)
                if nxt is not None and (nxt.espadj is not None or nxt.espset):
                    continue                                   # cleaned up right after the call
                ca = self.info(it.target)
                # A takes no inputs at all (no stack args, no ECX / EDX / EAX, e.g. `mov eax, imm; ret`): a C++ author who
                # sees the pushes will hand them to A, and the call that really consumes them gets too few
                if ca.ok and ca.nstack == 0 and ca.live == 0 and ca.pops <= {0} and ca.n <= 40 and not ca.tails \
                        and not ca.indtail and ca.eax_kinds & W \
                        and any(t_ != 'pass' for t_ in eax_after_call(self.dec[w], a + it.size, limit=6)):
                    # ... and another call follows before the stack is cleaned: that call sees the pushes as its arguments
                    later = False
                    for j2 in range(idx + 1, min(idx + 12, len(order))):
                        q2 = insns[order[j2]]
                        if q2.espadj is not None and q2.espadj < 0 or q2.espset:
                            break
                        if q2.kind in (K_CALL, K_INDCALL):
                            later = True
                            break
                        if q2.kind not in (K_SEQ, K_JCC):
                            break
                    if later:
                        fi.pending.append((a, it.target, npush))
        fi.has_ret = any(i.kind == K_RET for i in insns.values())
        # 5. stack frame size and probe
        for it in insns.values():
            m = it.mnem.split(' ')[-1]
            if m == 'sub' and it.espadj and it.espadj > 0 and not it.mindex and it.argop is None:
                fi.frame = max(fi.frame, it.espadj)
            if it.kind == K_CALL and it.target in (0x6336b0, 0x633c90, 0x633ca6):
                fi.probe = True
        # inline probes (-fstack-clash-protection): `sub esp, 0x1000` next to a touch of [esp] (before it in an alloca loop,
        # after it in a fixed frame)
        for idx, a in enumerate(order):
            it = insns[a]
            if it.mnem.split(' ')[-1] == 'sub' and it.espadj == 0x1000 and not it.mindex:
                for j in (idx - 1, idx + 1):
                    if 0 <= j < len(order):
                        q = insns[order[j]]
                        if q.mbase == 'esp' and q.mdisp == 0 and not q.mindex:
                            fi.probe = True
        # 6. __security_check_cookie called without ECX being set since the last call
        for idx, a in enumerate(order):
            it = insns[a]
            if it.kind == K_CALL and it.target == COOKIE_CHECK:
                stale = True
                for j in range(idx - 1, -1, -1):
                    q = insns[order[j]]
                    if q.kind in (K_CALL, K_INDCALL):
                        break                       # a call clobbers ECX: stale from here on
                    if q.kind not in (K_SEQ, K_JCC):
                        stale = False               # a jump / ret ends the straight-line run: unknown
                        break
                    if q.defs & ECX or (q.absdef and q.absdef[0] == 1):
                        stale = False
                        break
                if stale:
                    fi.cookie_stale.append((a, 'ECX not set'))
        # 9. argument operands of every direct call whose arguments are all pushes (or all `mov [esp+k]` stores)
        for idx, a in enumerate(order):
            it = insns[a]
            if it.kind == K_CALL:
                key = ('d', it.target)
            elif it.kind == K_INDCALL and it.mbase == '' and not it.mindex:
                key = ('a', it.mdisp & 0xffffffff)
            elif it.kind == K_INDCALL and it.mbase and not it.mindex:
                key = ('i', it.mdisp)
            else:
                continue
            pushes, stores = [], {}
            j = idx - 1
            while j >= 0 and len(pushes) + len(stores) <= 8:
                q = insns[order[j]]
                if q.kind in (K_CALL, K_INDCALL, K_RET, K_JMP, K_STOP, K_INDJMP) or q.espset \
                        or (q.espadj is not None and q.espadj < 0):
                    break
                if q.argop:
                    if q.argop[0] == 'push':
                        pushes.append(q.argop[1])
                    elif q.argop[1] % 4 == 0 and (q.argop[1] // 4) not in stores:
                        stores[q.argop[1] // 4] = q.argop[2]
                j -= 1
            if pushes and not stores:
                fi.callsigs.append((key, tuple(pushes)))             # pushes[0] = the last push = argument 0
            elif stores and not pushes:
                n_ = max(stores) + 1
                fi.callsigs.append((key, tuple(stores.get(k_, ('?',)) for k_ in range(n_))))
        # 10. what the code supplies at every direct call: stack argument dwords (pushes / `mov [esp+k]` stores since the previous
        #     call, `sub esp` or `add esp`) and whether ECX is set. clean = the run ended at one of those, not at a join point.
        npred = collections.Counter()
        for a_, ss_ in succ.items():
            for s_ in ss_:
                npred[s_] += 1
        for idx, a in enumerate(order):
            it = insns[a]
            if it.kind != K_CALL:
                continue
            # ecx_set: bit 0 ECX defined, bit 1 EDX defined (the run starts at the function entry: both are the incoming values),
            # bit 2 the run starts at a join / jump target: the register state is unknown (no verdict)
            npush, stores, ecx_set, clean, counting = 0, set(), 0, False, True
            cur = a
            j = idx - 1
            while True:
                if npred[cur] > 1:
                    ecx_set |= 4
                    break
                if j < 0:
                    ecx_set |= 3
                    clean = clean or counting
                    break
                q = insns[order[j]]
                if order[j] + q.size != cur:
                    ecx_set |= 4
                    break
                if q.kind in (K_CALL, K_INDCALL):
                    clean = clean or counting         # (a call clobbers ECX / EDX: still unset if nothing set them since)
                    break
                if q.kind in (K_RET, K_JMP, K_STOP, K_INDJMP):
                    clean = clean or counting
                    ecx_set |= 4
                    break
                if counting and (q.espset or (q.espadj is not None and q.espadj != 0 and q.argop is None)):
                    counting, clean = False, True     # (`sub esp, N` / `add esp, N` / `pop`: earlier pushes are not arguments)
                if counting:
                    if q.argop:
                        if q.argop[0] == 'push':
                            npush += 1
                        elif q.argop[1] % 4 == 0 and 0 <= q.argop[1] < 64:
                            stores.add(q.argop[1] // 4)
                    elif q.memdst and q.mbase == 'esp' and not q.mindex and q.mdisp % 4 == 0 and 0 <= q.mdisp < 64 and q.msize >= 4:
                        for k_ in range((q.msize + 3) // 4):          # movss / movsd / movq / fstp [esp+k]: float arguments
                            stores.add(q.mdisp // 4 + k_)
                if q.defs & ECX or (q.absdef and q.absdef[0] == 1):
                    ecx_set |= 1
                if q.defs & EDX or (q.absdef and q.absdef[0] == 2):
                    ecx_set |= 2
                cur = order[j]
                j -= 1
            fi.callargs.append((a, it.target, npush + len(stores), ecx_set, clean))
        # 11. exe functions that keep a register pointing into the stack (`mov reg, esp` / `lea reg, [esp+k]`) and later reach a slot
        #     through it that the stack pointer has already moved past, assuming every call pops what was pushed next to it. MSVC never
        #     touches memory below esp, so one of those calls popped fewer arguments than the pushes beside it: the stack layout is
        #     "pending arguments" and a port that gives each vcall its adjacent pushes is wrong.
        if w == 'exe':
            st = {entry: (0, 0, (), 0)}
            wk = [entry]
            while wk:
                a = wk.pop()
                it = insns[a]
                e, adj, al, dset = st[a]
                al = dict(al)
                m_ = it.mnem.split(' ')[-1]
                if e is not None and it.mbase and not it.mindex and it.mbase in REG_NAMES and not it.lea:
                    r_ = REG_NAMES.index(it.mbase)
                    if r_ in al and r_ != 6:
                        slot = al[r_] + it.mdisp
                        if slot + max(it.msize, 1) <= e and len(fi.below_esp) < 4:
                            fi.below_esp.append((a, '[%s%+d] is %d bytes below esp' % (it.mbase, it.mdisp, e - slot - max(it.msize, 1))))
                dreg = next((r_ for r_ in range(7) if it.defs >> (3 * r_) & 7 == 7), None)
                ne, nadj = e, adj
                if m_ == 'push':
                    ne = e - 4 if e is not None else None
                    nadj = adj + 1
                    if it.argop and it.argop[1][0] == 'reg' and it.argop[1][1] in ('ebx', 'esi', 'edi', 'ebp')                             and not dset >> REG_NAMES.index(it.argop[1][1]) & 1:
                        nadj = adj                                       # (saves the caller's value: not an argument)
                elif it.kind == K_CALL:
                    tf = self.memo.get(it.target)
                    if ne is not None and tf is not None and tf.ok and len(tf.pops) == 1:
                        ne = e + next(iter(tf.pops))
                    nadj = 0
                    for r_ in (0, 1, 2):
                        al.pop(r_, None)
                elif it.kind == K_INDCALL:
                    ne = e + 4 * adj if e is not None else None
                    nadj = 0
                    for r_ in (0, 1, 2):
                        al.pop(r_, None)
                elif it.espadj is not None and e is not None:
                    ne = e - it.espadj
                elif it.espset:
                    ne = None
                if it.kind in (K_JMP, K_JCC, K_RET, K_STOP, K_INDJMP):
                    nadj = adj
                if it.fsmem and it.memdst:
                    nadj = 0                                             # (end of the SEH prologue pushes)
                ndset = dset | (1 << dreg if dreg is not None else 0)
                if dreg is not None and dreg != 6 and it.kind not in (K_CALL, K_INDCALL):
                    al.pop(dreg, None)
                    if it.espsrc and e is not None:
                        al[dreg] = e
                    elif it.lea and it.mbase == 'esp' and not it.mindex and e is not None:
                        al[dreg] = e + it.mdisp
                for sc in succ.get(a, ()):
                    if sc not in st:
                        st[sc] = (ne, nadj, tuple(al.items()), ndset)
                        wk.append(sc)
        # 7. callee-saved registers left modified at a ret (a naked wrapper that forgets its push / pop)
        regs4 = (3, 4, 5, 6)                        # ebx esi edi ebp
        bits4 = {r_: 7 << (3 * r_) for r_ in regs4}
        cst = {entry: tuple(frozenset('I') for _ in regs4)}
        cwork = [entry]
        bad = 0
        while cwork:
            a = cwork.pop()
            it = insns[a]
            cur = cst[a]
            nxt_ = []
            m = it.mnem.split(' ')[-1]
            for k_, r_ in enumerate(regs4):
                bit = bits4[r_]
                new = set()
                for st_ in cur[k_]:
                    if m == 'push' and it.push_uses & bit:
                        new.add('IS' if st_ == 'I' else st_)
                    elif m == 'pop' and it.defs & bit:
                        new.add('I' if st_ in ('IS', 'MS') else 'X')
                    elif m == 'leave' and r_ == 6:
                        new.add('I' if st_ in ('IS', 'MS') else st_)
                    elif it.defs & bit:
                        new.add({'I': 'X', 'IS': 'MS'}.get(st_, st_))
                    else:
                        new.add(st_)
                nxt_.append(frozenset(new))
            if it.kind == K_RET or any(t_[0] == a for t_ in fi.tails):
                for k_, r_ in enumerate(regs4):
                    if nxt_[k_] & {'X', 'MS'}:
                        bad |= 1 << r_
                continue
            for sc in succ.get(a, ()):
                o_ = cst.get(sc)
                if o_ is None:
                    cst[sc] = tuple(nxt_)
                    cwork.append(sc)
                else:
                    mg = tuple(o_[k_] | nxt_[k_] for k_ in range(4))
                    if mg != o_:
                        cst[sc] = mg
                        cwork.append(sc)
        fi.clobbers = bad
        # 8. upper bits of EAX at ret
        hst = {entry: frozenset(['U'])}
        hwork = [entry]
        hres = set()
        while hwork:
            a = hwork.pop()
            it = insns[a]
            cur = hst[a]
            if it.eaxhi == 'Z':
                cur = frozenset(['Z'])
            elif it.eaxhi == 'U':
                cur = frozenset(['U'])
            elif it.eaxhi == 'P':
                cur = frozenset('Z' if x_ == 'Z' else 'PU' for x_ in cur)
            if it.kind == K_RET:
                hres |= cur
                continue
            if any(t_[0] == a for t_ in fi.tails):
                continue
            for sc in succ.get(a, ()):
                o_ = hst.get(sc, frozenset())
                if not cur <= o_:
                    hst[sc] = o_ | cur
                    hwork.append(sc)
        fi.eax_hi = hres

    def _analyze(self, w, entry):
        fi = FI(entry)
        insns, succ = self.explore(w, entry, fi)
        fi.n = len(insns)
        if fi.truncated and not fi.err:
            fi.err = 'cfg truncated (> %d insns)' % len(insns)
        if fi.err or not insns:
            if not fi.err:
                fi.err = 'empty'
            return fi
        tail_at = dict(fi.tails)
        # per-instruction use/def
        use, use_weak, ddef = {}, {}, {}
        for a, it in insns.items():
            u, d = it.uses, it.defs
            uw = u | it.push_uses
            if it.kind in (K_CALL, K_INDCALL):
                if it.kind == K_CALL:
                    tf = self.info(it.target)
                    u |= tf.live & PROPAGATE
                    uw |= tf.live_weak & PROPAGATE
                d |= CLOBBER
            elif a in tail_at:
                tf = self.info(tail_at[a])
                u |= tf.live & PROPAGATE
                uw |= tf.live_weak & PROPAGATE
            use[a], use_weak[a], ddef[a] = u, uw, d
        # backward liveness; weak variant adds push reads
        for weak in (False, True):
            live_in = {a: 0 for a in insns}
            changed = True
            order = sorted(insns, reverse=True)
            while changed:
                changed = False
                for a in order:
                    lo = 0
                    for s in succ.get(a, ()):
                        lo |= live_in.get(s, 0)
                    u = use_weak[a] if weak else use[a]
                    li = u | (lo & ~ddef[a])
                    if li != live_in[a]:
                        live_in[a] = li
                        changed = True
            if weak:
                fi.live_weak = live_in[entry] & ALLREG
            else:
                fi.live = live_in[entry] & ALLREG
        # pops, tails
        for a, it in insns.items():
            if it.kind == K_RET:
                fi.pops.add(it.pop)
        for a, t in fi.tails:
            tf = self.info(t)
            if tf.ok:
                fi.pops |= tf.pops
            else:
                fi.indtail = True
        # forward EAX kinds: state = (possible kinds of the last definition, those not read since)
        st = {entry: (IN, 0)}
        work = [entry]
        res = res_unread = 0
        while work:
            a = work.pop()
            it = insns[a]
            s, un = st[a]
            if it.uses & EAX or it.push_uses & EAX:
                un = 0
            if it.kind in (K_CALL, K_INDCALL):
                s = un = C
            elif it.defs & EAX == EAX:
                s = un = W
            elif it.defs & EAX:
                s |= WP
                un |= WP
            if it.kind == K_RET:
                res |= s
                res_unread |= un
                continue
            if a in tail_at or (it.kind == K_INDJMP and not succ.get(a)):
                res |= C
                res_unread |= C
                continue
            for sc in succ.get(a, ()):
                o, ou = st.get(sc, (0, 0))
                if o | s != o or ou | un != ou:
                    st[sc] = (o | s, ou | un)
                    work.append(sc)
        fi.eax_kinds = res
        fi.eax_unread = res_unread
        # forward x87 depth (set of possible depths at ret)
        fst = {entry: frozenset([0])}
        work = [entry]
        fres = set()
        while work:
            a = work.pop()
            it = insns[a]
            s = fst[a]
            if it.fpu == 99:
                s = frozenset([0])
            elif it.fpu:
                s = frozenset(max(-3, min(8, d + it.fpu)) for d in s)
            if it.kind == K_RET:
                fres |= s
                continue
            if a in tail_at:
                tf = self.info(tail_at[a])
                fres |= s | (tf.fpu if tf.ok else set())
                continue
            for sc in succ.get(a, ()):
                o = fst.get(sc, frozenset())
                n = o | s
                if n != o and len(n) <= 6:
                    fst[sc] = n
                    work.append(sc)
        fi.fpu = fres
        self._features(w, insns, succ, fi)
        fi.ok = True
        return fi


# ------------------------------------------------------------------------------------------ global scan of the exe
def global_descent(an, seeds, exe):
    """Recursive descent from the seeds over the whole exe code. Returns calls_to {target: [site]}, tail_to,
    the set of visited instruction addresses and the set of function starts."""
    dec = an.dec['exe']
    starts = set(seeds)
    seen = set()
    calls_to = collections.defaultdict(list)
    work = [(t, None) for t in seeds]
    queued = set(seeds)
    nfail = 0

    def push(t, b=None):
        if exe.in_code(t) and t not in queued:
            queued.add(t)
            work.append((t, b))

    while work:
        a, bound = work.pop()
        while True:
            if a in seen:
                break
            it = dec.at(a)
            if it is None:
                nfail += 1
                break
            seen.add(a)
            k = it.kind
            nxt = a + it.size
            if it.cmpimm is not None:
                bound = it.cmpimm
            if k == K_CALL:
                calls_to[it.target].append(a)
                if exe.in_code(it.target):
                    starts.add(it.target)
                    push(it.target)
                a = nxt
                continue
            if k in (K_SEQ, K_INDCALL):
                a = nxt
                continue
            if k == K_JCC:
                push(it.target, bound)
                a = nxt
                continue
            if k == K_JMP:
                push(it.target, bound)
                break
            if k == K_INDJMP:
                tg = an.switch_targets('exe', it, bound)
                for t in tg or ():
                    push(t)
                break
            break
    return calls_to, seen, starts, nfail


def data_pointer_seeds(exe, secs):
    """Dword values in non-code sections that point into code right after a function boundary (vtables, callbacks)."""
    out = set()
    for name, lo, hi, ch in secs:
        if ch & 0x20000000:
            continue
        data = exe.data[lo - exe.base:hi - exe.base]
        n = len(data) // 4
        for v in struct.unpack('<%dI' % n, bytes(data[:n * 4])):
            if exe.code_lo <= v < exe.code_hi:
                pb = exe.data[v - 1 - exe.base]
                if pb == 0xcc or (pb == 0xc3 and v % 16 == 0):     # int3 padding / a ret right before a 16-aligned address
                    out.add(v)
    return out


def eax_after_call(dec, start, limit=40, maxstates=300):
    """Paths from `start` (instruction after a call): which EAX reads happen before EAX is overwritten.
    Returns {tag: address of the first such read}: tags 'al', 'ax', 'eax' (reads) and 'pass' (EAX reaches a
    ret/tail jmp untouched)."""
    tags = {}
    seen = set()
    stack = [(start, 0)]
    n = 0
    while stack and n < maxstates:
        a, d = stack.pop()
        while d < limit:
            if a in seen:
                break
            seen.add(a)
            n += 1
            it = dec.at(a)
            if it is None:
                break
            er = it.ereads | (0)
            if it.push_uses & EAX:
                er |= 4
            if er:
                if er & 4:
                    tags.setdefault('eax', a)
                if er & 2:
                    tags.setdefault('ax', a)
                if er & 1:
                    tags.setdefault('al', a)
                break
            if it.kind in (K_CALL, K_INDCALL) or it.defs & EAX:
                break
            if it.kind == K_RET:
                tags.setdefault('pass', a)
                break
            if it.kind == K_JMP:
                if it.target is not None:
                    a = it.target
                    d += 1
                    continue
                break
            if it.kind == K_INDJMP:
                tags.setdefault('pass', a)
                break
            if it.kind == K_JCC:
                stack.append((it.target, d + 1))
            if it.kind == K_STOP:
                break
            a += it.size
            d += 1
    return tags


# ------------------------------------------------------------------------------------------ specs
def _const(node, env):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(_const(e, env) for e in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = _const(node.operand, env)
        if isinstance(v, (int, float)):
            return -v
    raise ValueError(ast.unparse(node)[:40])


UNRES = type('Unres', (), {'__repr__': lambda self: '<expr>'})()


def exec_spec_file(path, folder):
    """Fallback for spec files whose S(...) calls sit in loops or helper functions: run the file against a stub
    `pilot` module that only records the S() calls. Returns [spec dict]; raises on any error."""
    import types
    cap = []

    class Any:
        def __call__(self, *a, **k):
            return Any()

        def __getattr__(self, n):
            if n.startswith('__'):
                raise AttributeError(n)
            return Any()

        def __iter__(self):
            return iter(())

        def __getitem__(self, i):
            return Any()

        def __bool__(self):
            return False

    pil = types.ModuleType('pilot')
    pil.S = lambda *a, **k: cap.append((a, k))
    pil.F = type('F', (float,), {})
    pil.D = type('D', (float,), {})
    pil.__getattr__ = lambda n: Any()
    hdir = os.path.join(SPEC_ROOT, folder, 'harness')
    saved_mod, saved_path = dict(sys.modules), list(sys.path)
    sys.modules['pilot'] = pil
    sys.path[:0] = [hdir, os.path.join(SPEC_ROOT, 'shared-harness'), os.path.join(SPEC_ROOT, '..', 'tooling')]
    try:
        try:
            import importlib.util
            wk = importlib.util.spec_from_file_location('wkit', os.path.join(SPEC_ROOT, 'shared-wkit.py'))
            wm = importlib.util.module_from_spec(wk)
            sys.modules['wkit'] = wm
            wk.loader.exec_module(wm)
        except Exception:
            sys.modules.pop('wkit', None)
        g = {'__name__': 'spec_exec', '__file__': path}
        exec(compile(open(path, encoding='utf-8', errors='replace').read(), path, 'exec'), g)
    finally:
        for k in [k for k in sys.modules if k not in saved_mod]:
            del sys.modules[k]
        sys.modules.update(saved_mod)
        sys.path[:] = saved_path
    out = []
    for a, k in cap:
        d = {'file': os.path.basename(path), 'line': 0, 'exec': True}
        names = ['addr', 'name', 'abi', 'args', 'ret']
        for i, nm in enumerate(names):
            v = a[i] if len(a) > i else k.get(nm, 'ABSENT' if nm == 'ret' else None)
            d[nm] = v
        d['abi_mine'] = k.get('abi_mine')
        if isinstance(d['addr'], int):
            out.append(d)
    return out


def parse_spec_file(p, f, specs, fails):
    """Add the S(...) calls of one spec file (belonging to folder f) to specs."""
    need_exec = []
    try:
        tree = ast.parse(open(p, encoding='utf-8', errors='replace').read())
    except Exception as e:
        fails.append((f, os.path.basename(p), 'ast: %s' % e))
        return
    env = {}
    for n in tree.body:       # module-level simple constants
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                and isinstance(n.value, ast.Constant):
            env[n.targets[0].id] = n.value.value
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'S'):
            continue
        kw = {k.arg: k.value for k in n.keywords}
        d = {'file': os.path.basename(p), 'line': n.lineno, 'folder': f}
        try:
            d['addr'] = _const(n.args[0], env) if n.args else _const(kw['addr'], env)
        except Exception as e:
            need_exec.append('%s:%d addr not constant: %s' % (d['file'], n.lineno, e))
            continue
        pos = {1: 'name', 2: 'abi', 3: 'args', 4: 'ret'}
        for idx, key in pos.items():
            node = n.args[idx] if len(n.args) > idx else kw.get(key)
            if key in ('name', 'args'):
                continue
            if node is None:
                d[key] = 'ABSENT' if key == 'ret' else None
                continue
            try:
                d[key] = _const(node, env)
            except Exception:
                d[key] = UNRES
                d[key + '_src'] = ast.unparse(node)[:40]
        am = kw.get('abi_mine')
        if am is not None:
            try:
                d['abi_mine'] = _const(am, env)
            except Exception:
                d['abi_mine'] = UNRES
        if d.get('abi') is UNRES or d.get('ret') is UNRES:
            need_exec.append('%s:%d abi/ret not constant' % (d['file'], n.lineno))
        specs[(f, d['addr'])].append(d)
    if need_exec:
        try:
            got = exec_spec_file(p, f)
            base = os.path.basename(p)
            have = {(k[1], str(x.get('abi')), str(x.get('ret'))) for k, v in specs.items() if k[0] == f for x in v
                    if x['file'] == base and x.get('abi') is not UNRES and x.get('ret') is not UNRES}
            # replace the unresolved AST entries of this file by the executed ones
            for k in [k for k in specs if k[0] == f]:
                specs[k] = [x for x in specs[k] if not (x['file'] == base and (x.get('abi') is UNRES or x.get('ret') is UNRES))]
            for d in got:
                d['folder'] = f
                if (d['addr'], str(d.get('abi')), str(d.get('ret'))) not in have:
                    specs[(f, d['addr'])].append(d)
                    have.add((d['addr'], str(d.get('abi')), str(d.get('ret'))))
        except Exception as e:
            for msg in need_exec[:3]:
                fails.append((f, os.path.basename(p), '%s; exec fallback failed: %s: %s' % (
                    msg, type(e).__name__, str(e)[:80])))


def parse_specs(folders, wanted):
    """{(folder, addr): [spec dict]} for the folders' own harness, plus {addr: [spec dict]} found in other folders'
    harness for addresses (wanted) that have no S() in their own folder, plus parse failures (folder, file, why)."""
    specs = collections.defaultdict(list)
    fails = []
    for f in folders:
        for p in sorted(glob.glob(os.path.join(SPEC_ROOT, f, 'harness', 'specs_*.py'))):
            parse_spec_file(p, f, specs, fails)
    alt = collections.defaultdict(list)
    by_addr = collections.defaultdict(list)
    for (f, a), v in specs.items():
        by_addr[a].extend(v)
    missing = set()
    for f, a in wanted:
        if (f, a) not in specs:
            if a in by_addr:
                alt[a] = by_addr[a]         # the S() sits in another folder that is also parsed
            else:
                missing.add(a)
    if missing:
        pat = re.compile(r'0x([0-9a-fA-F]{5,6})\b')
        want_txt = {'%x' % a: a for a in missing}
        files = {}
        for p in glob.glob(os.path.join(SPEC_ROOT, '*', 'harness', 'specs_*.py')):
            f = os.path.basename(os.path.dirname(os.path.dirname(p)))
            if f in folders:
                continue               # already parsed
            txt = open(p, encoding='utf-8', errors='replace').read()
            if any(h in want_txt for h in (m.lower() for m in pat.findall(txt))):
                files[p] = f
        other = collections.defaultdict(list)
        for p, f in sorted(files.items()):
            parse_spec_file(p, f, other, fails)
        for (f, a), v in other.items():
            if a in missing:
                alt[a].extend(v)
    return specs, alt, fails


def ret_checked(r):
    """True when the checker compares EAX (or AL) for this ret= value; False when it is not compared."""
    if r is UNRES:
        return None
    if r in (None, 'ABSENT', 'none', 'void'):
        return False
    if r in ('st0', 'xmm0'):
        return False                      # float result compared, EAX not
    return True


# ------------------------------------------------------------------------------------------ names
PRIM4 = {'int', 'unsigned', 'unsigned int', 'long', 'unsigned long', 'short', 'unsigned short', 'char', 'unsigned char',
         'signed char', 'bool', 'float', 'wchar_t', 'size_t', 'int32', 'uint32'}
PRIM8 = {'double', 'long long', 'unsigned long long', '__int64', 'unsigned __int64', 'int64', 'uint64'}


def name_pop(nm):
    """Bytes of stack arguments implied by the parameter list in a demangled name, or None when unknown."""
    if not nm or '(' not in nm or nm.startswith(('GUESS', 'FUN_', 'thunk', 'lifted')) or 'operator' in nm:
        return None
    if '<' in nm[:nm.index('(')]:
        return None
    body = nm[nm.index('(') + 1:nm.rindex(')')] if ')' in nm else None
    if body is None:
        return None
    parts, depth, cur = [], 0, ''
    for ch in body:
        if ch in '<(':
            depth += 1
        elif ch in '>)':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    if parts == ['void']:
        parts = []
    total = 0
    for t_ in parts:
        if t_ == '...':
            return None
        t2 = ' '.join(w for w in t_.replace('&', ' & ').replace('*', ' * ').split() if w != 'const')
        if '*' in t2 or '&' in t2:
            total += 4
        elif t2 in PRIM4:
            total += 4
        elif t2 in PRIM8:
            total += 8
        else:
            return None
    return total


# ------------------------------------------------------------------------------------------ port sources
PCREG_RE = re.compile(r'^[ \t]*PCREG\(\s*([0-9a-fA-F]+)\s*,\s*([A-Za-z_]\w*)\s*\)', re.M)
QUAL_RE = re.compile(r'__attribute__\s*\(\(.*?\)\)|__declspec\([^)]*\)|\[\[.*?\]\]|\b(?:static|inline|extern|__forceinline|'
                     r'constexpr|THISCALL|FASTCALL|STDCALL|VECTORCALL|NOINLINE)\b|"C"')
NARROW = {'bool', 'u8', 's8', 'char', 'unsigned char', 'signed char', 'uint8_t', 'int8_t', '_Bool'}


def scan_sources(hooked):
    """{exe_addr: dict(file, fn, ret, conv, void_eax)} from the PCREG lines and definitions in the port folder."""
    want = collections.defaultdict(set)
    for a, pe, folder, name in hooked:
        want[folder].add(a)
    res, fails = {}, []
    for folder, addrs in want.items():
        for p in sorted(glob.glob(os.path.join(SPEC_ROOT, folder, 'src', '*.cpp'))):
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except OSError as e:
                fails.append((folder, os.path.basename(p), str(e)))
                continue
            for m in PCREG_RE.finditer(text):
                a = int(m.group(1), 16)
                if a not in addrs or a in res:
                    continue
                fn = m.group(2)
                d = {'file': os.path.basename(p), 'fn': fn, 'ret': None, 'conv': '', 'void_eax': False}
                if re.search(r'(?:\\n|[^\w])%s:' % re.escape(fn), text):
                    d['ret'] = 'asm'               # hand-written asm(): the declared C type means nothing
                dm = re.search(r'(?m)^([^\n;{}#]*?)\b%s\s*\(([^)]*)\)\s*(?:noexcept\s*)?\{' % re.escape(fn), text)
                if dm:
                    pre = dm.group(1)
                    ctx = pre + ' ' + text[max(0, dm.start() - 160):dm.start()]
                    d['conv'] = ' '.join(sorted(set(re.findall(r'\b(THISCALL|FASTCALL|STDCALL|VECTORCALL|naked)\b', ctx))))
                    rt = ' '.join(QUAL_RE.sub(' ', pre).split())
                    if d['ret'] != 'asm':
                        d['ret'] = 'asm' if 'naked' in d['conv'] else (rt or None)
                    i, depth, j = dm.end(), 1, dm.end()
                    while j < len(text) and depth:
                        c = text[j]
                        depth += (c == '{') - (c == '}')
                        j += 1
                    body = text[i:j]
                    d['void_eax'] = bool(re.search(r'\beax\s*=[^=]', body)) and 'asm' not in body
                res[a] = d
    return res, fails


# ------------------------------------------------------------------------------------------ main
def hexs(v):
    return '0x%x' % v


def main():
    exe, secs, exe_entry = load_exe()
    port = load_port()
    rows = [l.rstrip('\n').split('\t') for l in open(PORTS_TSV, encoding='utf-8')]
    hooked = []
    for r in rows:
        if len(r) >= 3 and r[0].startswith('0x'):
            hooked.append((int(r[0], 16), int(r[1], 16), r[2], r[3] if len(r) > 3 else ''))
    plan = {}
    for l in open(PLAN_TSV, encoding='utf-8'):
        p = l.rstrip('\n').split('\t')
        if p[0].startswith('0x'):
            plan[int(p[0], 16)] = p[2]
    print('hooked addresses: %d' % len(hooked))

    # function starts
    port_starts = set()
    for l in open(PORTS_SYMS):
        p = l.split()
        if len(p) == 3 and (p[1] == 'T' or (p[1] == 't' and not re.match(r'^(L[0-9A-Za-z_]*|asm_.*)$', p[2]))):
            port_starts.add(int(p[0], 16))
    port_starts |= {h[1] for h in hooked}
    seeds = {h[0] for h in hooked} | {exe_entry}
    seeds |= {int(l.split('\t')[0], 16) for l in open(os.path.join(ROOT, 'ReFreedomFighters', 'RESULTS.tsv'))
              if l.startswith('0x')}
    seeds |= {int(l.split('\t')[0], 16) for l in open(os.path.join(BUILD, 'skipped.tsv')) if l.startswith('0x')}
    core_seeds = {s for s in seeds if exe.in_code(s)}
    data_seeds = data_pointer_seeds(exe, secs)
    seeds = core_seeds | data_seeds
    print('seeds: %d (%d from data pointers)' % (len(seeds), len(data_seeds - core_seeds)))

    an = Analyzer(exe, port, set(seeds), port_starts)
    calls_to, seen, starts, nfail = global_descent(an, seeds, exe)
    call_targets = {t for t in calls_to if exe.in_code(t)}
    an.starts['exe'] = core_seeds | call_targets
    an.tailstarts['exe'] = starts | seeds
    print('exe: %d instructions reached, %d function starts (%d incl. data-pointer seeds), %d undecodable block starts, %d call targets'
          % (len(seen), len(an.starts['exe']), len(an.tailstarts['exe']), nfail, len(calls_to)))
    starts_sorted = sorted(an.tailstarts['exe'])

    def owner(a):
        i = bisect.bisect_right(starts_sorted, a) - 1
        return starts_sorted[i] if i >= 0 else None

    dexe = an.dec['exe']
    caller_cache = {}

    def caller_tags(target):
        """{'direct': {tag: [sites]}, 'n': number of direct call sites}"""
        if target in caller_cache:
            return caller_cache[target]
        res = {'n': len(calls_to.get(target, ())), 'sites': collections.defaultdict(list)}
        for site in calls_to.get(target, ()):
            it = dexe.at(site)
            if it is None:
                continue
            for t, ra in eax_after_call(dexe, site + it.size).items():
                res['sites'][t].append((site, ra))
        caller_cache[target] = res
        return res

    def readers(target, depth=0):
        """(direct read tags, passthrough-read description or None)"""
        ct = caller_tags(target)
        direct = {t: s for t, s in ct['sites'].items() if t != 'pass'}
        via = None
        if not direct and 'pass' in ct['sites'] and depth < 2:
            for site, _ra in ct['sites']['pass']:
                g = owner(site)
                if g is None or g == target:
                    continue
                d2, _ = readers(g, depth + 1)
                if d2:
                    via = (g, sorted(d2))
                    break
        return direct, via

    specs, alt_specs, spec_fails = parse_specs(sorted({h[2] for h in hooked}), {(h[2], h[0]) for h in hooked})
    print('specs parsed: %d addresses in their own folder, %d more found in other folders, %d parse failures' % (
        len(specs), len(alt_specs), len(spec_fails)))
    srcs, src_fails = scan_sources(hooked)
    print('port sources: %d of %d addresses located, %d unreadable files' % (len(srcs), len(hooked), len(src_fails)))

    out = []        # (addr, folder, category, evidence)
    excl = {}       # addr -> category (definite)
    excl_unv = {}   # addr -> category (weaker)
    stats = collections.Counter()

    for f, w, why in spec_fails:
        out.append((0, f, 'parse-fail-spec', '%s %s' % (w, why)))
    for f, w, why in src_fails:
        out.append((0, f, 'parse-fail-source', '%s %s' % (w, why)))

    soft = {'ret-lost-nocaller', 'ret-lost-nocaller-weak', 'ret-void-nocaller', 'ret-lost-passthrough', 'conv-spec',
            'ret-unchecked-al', 'void-port-eax-local'}

    new2 = {}       # addr -> [categories] found by the v2 detectors
    stats2 = collections.Counter()
    nospec = set()
    constfix = []   # (addr, folder, callee, argument index, original constant, port constant)
    new3 = {}       # addr -> [(category, evidence)] found by the v3 detectors
    stats3 = collections.Counter()
    names = {}
    try:
        for f_ in json.load(open(os.path.join(BUILD, 'map-data-public.json'), encoding='utf-8'))['functions']:
            names[f_[0]] = f_[3]
    except (OSError, ValueError, KeyError):
        pass

    def add3(addr, folder, name, cat, ev):
        out.append((addr, folder, cat, ev))
        new3.setdefault(addr, []).append((cat, name, folder))
        stats3[cat] += 1

    new4 = {}       # addr -> [(category, name, folder)] found by the v4 detectors
    stats4 = collections.Counter()

    def add4(addr, folder, name, cat, ev):
        out.append((addr, folder, cat, ev))
        new4.setdefault(addr, []).append((cat, name, folder))
        stats4[cat] += 1

    def add2(addr, folder, cat, ev):
        out.append((addr, folder, cat, ev))
        new2.setdefault(addr, []).append(cat)
        stats2[cat] += 1

    def add(addr, folder, cat, ev, definite=False, weak=False):
        """definite / weak: category 1 or 2 with direct-caller or machine-code evidence -> audit_exclude.txt.
        Rows in `soft` (unknown callers, spec-only findings) -> audit_exclude_unverified.txt."""
        out.append((addr, folder, cat, ev))
        if definite or weak:
            excl.setdefault(addr, cat)
        elif cat in soft:
            excl_unv.setdefault(addr, cat)

    for addr, pentry, folder, name in hooked:
        o = an.info(addr)
        p = an.info(pentry)
        sp = specs.get((folder, addr)) or alt_specs.get(addr, [])
        sd = srcs.get(addr)
        if not sp:
            add(addr, folder, 'no-spec-found', 'no S(0x%x) in any ports/*/harness (RESULTS.tsv lists it as verified in %s)' % (addr, folder))
            nospec.add(addr)
        if sd is None:
            add(addr, folder, 'parse-fail-source', 'no PCREG(%x, ...) found in %s/src' % (addr, folder))
        elif sd['ret'] is None:
            add(addr, folder, 'parse-fail-source', 'definition of %s not parsed (%s)' % (sd['fn'], sd['file']))
        if not o.ok:
            add(addr, folder, 'parse-fail-orig', o.err or 'not analysable')
            stats['orig-fail'] += 1
            continue
        if not p.ok:
            add(addr, folder, 'parse-fail-port', 'entry 0x%x: %s' % (pentry, p.err or 'not analysable'))
            stats['port-fail'] += 1
            continue
        if o.truncated or p.truncated:
            add(addr, folder, 'parse-fail-orig' if o.truncated else 'parse-fail-port', 'cfg truncated')
            continue
        abis = sorted({str(s.get('abi')) for s in sp})
        rets = sorted({str(s.get('ret')) for s in sp})
        spec_str = 'spec abi=%s ret=%s%s' % ('/'.join(abis) or '?', '/'.join(rets) or '?',
                                             ' (spec lives in %s)' % sp[0]['folder'] if sp and sp[0].get('folder') != folder else '')
        src_str = 'port %s %s' % (sd['ret'] if sd else '?', sd['conv'] if sd else '')
        unchecked = bool(sp) and all(ret_checked(s.get('ret')) is False for s in sp)
        eax_unknown = any(ret_checked(s.get('ret')) is None for s in sp)
        sp_al = bool(sp) and all(s.get('ret') == 'al' for s in sp)
        port_void = bool(sd) and sd['ret'] == 'void'
        port_narrow = bool(sd) and (sd['ret'] in NARROW)
        orig_ret = bool(o.eax_kinds & (W | C | WP))
        port_sets = bool(p.eax_kinds & (W | C | WP))
        port_ret = port_sets and not port_void
        direct, via = readers(addr)
        ncalls = caller_tags(addr)['n']
        pk = p.eax_kinds
        port_sets_any = bool(pk & (W | WP | C))
        port_sets_expl = bool(pk & (W | WP))
        spec_blind = unchecked or eax_unknown or not sp          # the checker did not compare EAX

        # ---- category 1: lost return value
        if orig_ret and direct:
            stats['callers-read-eax'] += 1
            if spec_blind:
                stats['callers-read-eax-spec-blind'] += 1
        if orig_ret:
            if direct:
                sites = sorted(sum(direct.values(), []))
                ev = 'callers read %s: %s (%d direct call sites, %d read it)' % (
                    '/'.join(sorted(direct)),
                    ', '.join('call@%x then `%s`@%x' % (x, dexe.text(ra), ra) for x, ra in sites[:2]),
                    ncalls, len({x for x, _ in sites}))
                tail = '; orig EAX=%s, port EAX=%s; %s; %s' % (kinds(o.eax_kinds), kinds(pk), spec_str, src_str)
                if not port_sets_any:
                    add(addr, folder, 'ret-lost', 'port never sets EAX before ret; ' + ev + tail, definite=True)
                elif port_void and spec_blind and port_sets_expl:
                    add(addr, folder, 'ret-void-scratch',
                        'port declared void and the spec does not compare EAX; its code writes EAX but nothing ties that to the original result; '
                        + ev + tail, definite=True)
                elif port_void and spec_blind:
                    add(addr, folder, 'ret-void-passthrough',
                        'port declared void and the spec does not compare EAX; EAX only survives from the last call in the port; '
                        + ev + tail, weak=True)
                elif unchecked and ('eax' in direct or 'ax' in direct):
                    add(addr, folder, 'ret-unchecked', 'spec does not compare EAX; port returns a value; ' + ev + tail, weak=True)
                elif unchecked:
                    add(addr, folder, 'ret-unchecked-al', 'spec does not compare EAX (callers read AL only); ' + ev + tail)
                if (sp_al or port_narrow) and (o.eax_kinds & W) and ('eax' in direct or 'ax' in direct):
                    add(addr, folder, 'ret-narrow', 'orig sets full EAX, callers read %s, but %s%s; %s' % (
                        '/'.join(sorted(direct)), 'port returns ' + sd['ret'] if port_narrow else '',
                        ' and spec compares AL only' if sp_al else '', ev), weak=True)
            elif via:
                if not port_sets_any:
                    add(addr, folder, 'ret-lost-passthrough',
                        'port never sets EAX; EAX passes through caller 0x%x whose result is read (%s); %s; %s' % (
                            via[0], '/'.join(via[1]), spec_str, src_str))
            elif ncalls == 0 and (o.eax_unread & (W | WP)) and not port_sets_any and spec_blind:
                add(addr, folder, 'ret-lost-nocaller',
                    'port never sets EAX; orig leaves an unread EAX result (%s) at ret; no direct callers (vtable/indirect): unknown callers; %s; %s' % (
                        kinds(o.eax_unread), spec_str, src_str))
            elif ncalls == 0 and (o.eax_unread & (W | WP)) and port_void and port_sets_expl and spec_blind:
                add(addr, folder, 'ret-void-nocaller',
                    'port declared void and the spec does not compare EAX; orig leaves an unread EAX result (%s) at ret; '
                    'no direct callers (vtable/indirect): unknown callers; orig EAX=%s, port EAX=%s; %s; %s' % (
                        kinds(o.eax_unread), kinds(o.eax_kinds), kinds(pk), spec_str, src_str))
            elif ncalls == 0 and (o.eax_kinds & W) and not port_sets_any and spec_blind:
                add(addr, folder, 'ret-lost-nocaller-weak',
                    'port never sets EAX; orig writes EAX (%s) but also reads it back; no direct callers: unknown callers; %s; %s' % (
                        kinds(o.eax_kinds), spec_str, src_str))
            if port_void and sd and sd['void_eax'] and not direct:
                add(addr, folder, 'void-port-eax-local',
                    'port is void but its body assigns a local named eax (orig sets EAX, %s); %s' % (
                        'no direct callers' if not ncalls else 'callers do not read it', spec_str))
        # ---- x87 return
        if o.fpu and max(o.fpu) >= 1 and o.fpu <= {1} and not (p.fpu and max(p.fpu) >= 1):
            add(addr, folder, 'ret-st0-lost', 'orig leaves a value on the x87 stack at ret; port leaves none (%d direct call sites); %s; %s' % (
                ncalls, spec_str, src_str), definite=bool(ncalls))

        # ---- category 2: calling convention
        lost = regs_of(o.live) & ~regs_of(p.live_weak)     # port side lenient: push / spill count as a read
        for reg in range(7):
            if not (lost & (1 << reg)):
                continue
            rn = REG_NAMES[reg]
            cat = 'conv-%s' % (rn if rn in ('ecx', 'edx') else 'reg')
            add(addr, folder, cat, 'orig reads %s before writing it; port does not (orig live-in: %s; port live-in: %s); %s; %s' % (
                rn, mask_names(o.live), mask_names(p.live_weak), spec_str, src_str), definite=True)
        # spec abi that cannot supply the registers the original reads
        if sp and all(isinstance(s.get('abi'), str) and s.get('abi') in ('cdecl', 'stdcall') for s in sp) and regs_of(o.live) & 2:
            add(addr, folder, 'conv-spec', 'spec abi %s but orig reads ECX before writing it; port live-in: %s' % (
                '/'.join(abis), mask_names(p.live_weak)))
        if sp and all(isinstance(s.get('abi'), str) and s.get('abi') in ('cdecl', 'stdcall', 'thiscall') for s in sp) and regs_of(o.live) & 4:
            add(addr, folder, 'conv-spec', 'spec abi %s but orig reads EDX before writing it; port live-in: %s' % (
                '/'.join(abis), mask_names(p.live_weak)))
        # pop count
        if not o.indtail and not p.indtail and o.pops and p.pops and o.pops != p.pops:
            add(addr, folder, 'pop-mismatch', 'orig ret %s, port ret %s; %s; %s' % (
                sorted(o.pops), sorted(p.pops), spec_str, src_str), definite=True)
        # ---- v2 detectors: defect classes found by bisecting the live game (see hybrid/build/hunt.tsv)
        port_asm = bool(sd) and sd['ret'] == 'asm'
        if p.cookie_const:
            site, val = p.cookie_const[0]
            add2(addr, folder, 'sec-cookie-const',
                 'port calls __security_check_cookie (0x633654) at 0x%x with ECX=0x%x; the real check compares ECX with [0x6f5630] and '
                 'fast-fails (0xC0000409) on any other value; %s' % (site, val, src_str))
        if o.pending and not port_asm:
            c_, a_, n_ = o.pending[0]
            add2(addr, folder, 'pending-stack-args',
                 'orig pushes %d dword(s) before call@%x to 0x%x, which never reads stack args, so they belong to a later call; '
                 'a C++ port must hand them on (%d such site(s)); %s' % (n_, c_, a_, len(o.pending), src_str))
        if o.argaddr and not p.argaddr and not port_asm:
            add2(addr, folder, 'va-address-lost',
                 'orig takes the address of its incoming stack arguments (lea [ebp+d], va_list style); port never does; %s' % src_str)
        if o.local_ext_ic and p.local_ext_ic and not port_asm:
            need = [e_ for e_ in o.local_ext_ic if e_ >= 8]
            have = sorted(p.local_ext_ic, reverse=True)
            bad = None
            for n_, e_ in enumerate(need):
                k_ = next((i_ for i_, h_ in enumerate(have) if h_ >= e_), None)
                if k_ is None:
                    # the port may read the fields of one buffer through several stack slots, which cuts its extents
                    # into pieces: only complain when even the total address-taken space is smaller than what is still needed
                    if sum(have) < sum(need[n_:]):
                        bad = e_
                    break
                have.pop(k_)
            if bad is not None:
                add2(addr, folder, 'local-too-small',
                     'orig hands the address of a local with room for %d bytes to a virtual call (extents %s); the port\'s such '
                     'locals have extents %s (%s frame), so the callee writes past them; %s' % (
                         bad, o.local_ext_ic, p.local_ext_ic, p.local_kind, src_str))
        if (not o.has_ret) and (o.tails or o.indtail) and o.n <= 12 and p.has_ret and p.nstack == 0 and p.pops <= {0} \
                and not port_asm and not o.switch:
            if o.indtail and not o.tails:
                add2(addr, folder, 'fwd-args-dropped',
                     'orig only tail-jumps through a register / vtable slot (callee and its stack args unknown); the port calls it '
                     'with no stack args and returns with ret 0; %s' % src_str)
            elif o.tails:
                tf_ = an.info(o.tails[0][1])
                if tf_.ok and tf_.nstack > 0:
                    add2(addr, folder, 'fwd-args-dropped',
                         'orig tail-jumps to 0x%x, which reads %d stack arg dword(s); the port forwards none; %s' % (
                             o.tails[0][1], tf_.nstack, src_str))
        # ---- v3 detectors: defect classes behind the second batch of runtime culprits (hunt.tsv, 03:56 and later)
        if p.clobbers & ~o.clobbers:
            rn_ = [REG_NAMES[r_] for r_ in range(7) if (p.clobbers & ~o.clobbers) >> r_ & 1]
            add3(addr, folder, name, 'clobbers-callee-saved',
                 'port leaves %s modified at a ret (no matching push / pop), the original preserves it: the caller\'s register is destroyed; %s'
                 % ('/'.join(rn_), src_str))
        if p.frame >= 0x1000 and not p.probe:
            add3(addr, folder, name, 'no-stack-probe',
                 'port reserves a 0x%x byte frame with a plain `sub esp` (no __chkstk / probe loop); touching it skips the stack guard page%s; %s' % (
                     p.frame, ' (orig frame 0x%x, probe %s)' % (o.frame, 'yes' if o.probe else 'no') if o.frame or o.probe else '', src_str))
        if o.eax_hi == {'Z'} and 'PU' in p.eax_hi:
            add3(addr, folder, name, 'bool-upper-garbage',
                 'orig returns a clean byte in EAX (upper 24 bits zero); the port only sets AL over a stale EAX, so callers that test or '
                 'compare the whole register see garbage; %s' % src_str)
        if p.cookie_stale:
            add3(addr, folder, name, 'sec-cookie-stale',
                 'port calls __security_check_cookie at 0x%x without loading ECX (%s); the real check takes the cookie in ECX and fast-fails; %s' % (
                     p.cookie_stale[0][0], p.cookie_stale[0][1], src_str))
        if o.lea_slots and not p.lea_slots:
            for i_ in sorted(o.lea_slots):
                higher = [x_ for x_ in o.arg_slots if x_ > i_]
                if not higher:
                    continue
                gap = min(higher) - i_
                miss = [i_ + k_ for k_ in range(gap) if (i_ + k_) not in p.arg_slots]
                if gap >= 2 and miss:
                    add3(addr, folder, name, 'byvalue-arg-truncated',
                         'orig passes the address of stack arg slot %d, an object of %d dwords (the next named arg is slot %d); the port never '
                         'reads slot(s) %s of it; %s' % (i_, gap, min(higher), miss, src_str))
                    break
        # same callee, constant argument moved to another position or changed (swapped / wrong size argument)
        oc_ = collections.defaultdict(list)
        pc_ = collections.defaultdict(list)
        for k_, ar_ in o.callsigs:
            oc_[k_].append(ar_)
        for k_, ar_ in p.callsigs:
            pc_[k_].append(ar_)
        for k_, lst_ in oc_.items():
            if len(lst_) != 1 or len(pc_.get(k_, ())) != 1 or len(pc_[k_][0]) != len(lst_[0]) or len(lst_[0]) > 6:
                continue
            oa_, pa_ = lst_[0], pc_[k_][0]
            if any(x_[0] == '?' for x_ in pa_) or any(x_[0] == '?' for x_ in oa_):
                continue                # the port's argument list is not clean (stores to locals mixed in): no verdict
            for i_, ov_ in enumerate(oa_):
                if ov_[0] != 'imm':
                    continue
                pv_ = pa_[i_]
                if (pv_[0] == 'imm' and pv_[1] != ov_[1]) or (pv_[0] != 'imm' and any(x_ == ov_ for x_ in pa_)):
                    if pv_[0] == 'imm' and k_[0] == 'd':
                        constfix.append((hexs(addr), folder, hexs(k_[1]), i_, '0x%x' % ov_[1], '0x%x' % pv_[1]))
                    add3(addr, folder, name, 'call-arg-mismatch',
                         'call to %s: orig passes constant 0x%x as argument %d; the port passes %s there (port args %s, orig args %s); %s' % (
                             ('0x%x' % k_[1]) if k_[0] == 'd' else '[0x%x]' % k_[1], ov_[1], i_, pv_, pa_, oa_, src_str))
                    break
        # pure indirect forwarder (jmp [vtable+off]): the stack args are unknown, so the port's `ret N` is a guess; check it against
        # the parameter list in the function's name
        if not o.has_ret and o.indtail and not o.tails and o.n <= 12 and p.has_ret and not port_asm:
            ex_ = name_pop(names.get(addr, ''))
            if ex_ is not None and p.pops != {ex_}:
                add3(addr, folder, name, 'vslot-thunk-arity',
                     'orig only tail-jumps through a vtable slot; its name `%s` implies %d bytes of stack args but the port returns with ret %s; %s' % (
                         names.get(addr, ''), ex_, sorted(p.pops), src_str))
        # ---- v4 detectors: the call sites of the port against the interface of the exe function it calls
        def need_of(tf_):
            return max(tf_.nstack, (min(tf_.pops) // 4) if len(tf_.pops) == 1 else 0)
        if not port_asm:
            seen4 = set()
            for site_, tgt_, nprov_, ecx_set_, clean_ in p.callargs:
                if an.which(tgt_) != 'exe':
                    continue
                tf_ = an.info(tgt_)
                if not tf_.ok or tf_.truncated:
                    continue
                need_ = need_of(tf_)
                if clean_ and nprov_ < need_ and ('args', tgt_) not in seen4:
                    seen4.add(('args', tgt_))
                    add4(addr, folder, name, 'call-args-short',
                         'port calls 0x%x at 0x%x with %d stack arg dword(s); the callee reads %d and pops %s (the orig supplies %s); %s' % (
                             tgt_, site_, nprov_, tf_.nstack, sorted(tf_.pops),
                             sorted({n_ for s2_, t2_, n_, e2_, c2_ in o.callargs if t2_ == tgt_}) or '-', src_str))
                if not ecx_set_ & 6 and regs_of(tf_.live) & 4 and ('edx', tgt_) not in seen4:
                    seen4.add(('edx', tgt_))
                    add4(addr, folder, name, 'call-edx-unset',
                         'port calls 0x%x at 0x%x, which reads EDX on entry, without setting EDX since the previous call; %s' % (
                             tgt_, site_, src_str))
                if not ecx_set_ & 5 and regs_of(tf_.live) & 2 and ('ecx', tgt_) not in seen4:
                    seen4.add(('ecx', tgt_))
                    add4(addr, folder, name, 'call-this-unset',
                         'port calls 0x%x at 0x%x, which reads ECX on entry, without setting ECX since the previous call; %s' % (
                             tgt_, site_, src_str))
            if o.below_esp:
                add4(addr, folder, name, 'orig-pending-slot',
                     'orig reaches a stack slot below esp through a saved stack pointer at 0x%x (%s): one of the calls before it pops '
                     'fewer arguments than the pushes beside it, so the port\'s vcall arities are a guess; %s' % (
                         o.below_esp[0][0], o.below_esp[0][1], src_str))
            for site_, tgt_, nprov_, ecx_set_, clean_ in o.callargs:
                if an.which(tgt_) != 'exe':
                    continue
                tf_ = an.info(tgt_)
                if tf_.ok and clean_ and nprov_ < need_of(tf_) and need_of(tf_) > 0:
                    add4(addr, folder, name, 'orig-pending-args',
                         'orig supplies %d stack arg dword(s) right before call 0x%x@%x, which pops %s: the rest were pushed before an '
                         'earlier (virtual) call that therefore popped fewer than the pushes next to it; %s' % (
                             nprov_, tgt_, site_, sorted(tf_.pops), src_str))
                    break
        stats['analysed'] += 1

    # sort and write
    out.sort(key=lambda r: (r[2], r[0]))
    with open(OUT_TSV, 'w', encoding='utf-8', newline='') as fh:
        fh.write('exe_addr\tfolder\tcategory\tevidence\n')
        for a, f, c, e in out:
            fh.write('%s\t%s\t%s\t%s\n' % (hexs(a) if a else '-', f, c, e.replace('\t', ' ').replace('\n', ' ')))
    with open(OUT_EXCLUDE, 'w', encoding='utf-8', newline='') as fh:
        fh.write('# Generated by hybrid/audit_ports.py (build/audit.tsv has the evidence per address).\n'
                 '# Category 1 (return value) and 2 (calling convention, pop count) findings with direct-caller or\n'
                 '# machine-code evidence. The tag after # is the first category found.\n')
        for a in sorted(excl):
            fh.write('%s  # %s\n' % (hexs(a), excl[a]))
    with open(OUT_EXCLUDE_UNVERIFIED, 'w', encoding='utf-8', newline='') as fh:
        fh.write('# Generated by hybrid/audit_ports.py. Softer findings, not in audit_exclude.txt: callers unknown (vtable only),\n'
                 '# or the spec abi is wrong while the port itself reads the registers. Not known to be wrong.\n')
        for a in sorted(excl_unv):
            if a not in excl:
                fh.write('%s  # %s\n' % (hexs(a), excl_unv[a]))
    # audit_exclude_v2.txt: only addresses the v2 detectors flag that no existing exclude list covers
    have = set(excl) | set(excl_unv)
    night = os.path.join(ROOT, 'game', 'exclude_night.txt')
    for fn_ in (night, OUT_EXCLUDE, OUT_EXCLUDE_UNVERIFIED):
        if os.path.exists(fn_):
            for ln in open(fn_, encoding='utf-8'):
                ln = ln.split('#')[0].split(';')[0].strip()
                for tok in ln.replace(',', ' ').split():
                    if tok.lower().startswith('0x') and '-' not in tok:
                        have.add(int(tok, 16))
    v2 = {a: c for a, c in new2.items() if a not in have}
    if os.environ.get('AUDIT_WRITE_V2'):         # (game/exclude_night.txt now contains the v2 list, so a rerun would empty it)
        with open(OUT_EXCLUDE_V2, 'w', encoding='utf-8', newline='') as fh:
            fh.write('# Generated by hybrid/audit_ports.py: addresses flagged only by the v2 detectors (defect classes found by the\n'
                     '# live-game bisect) and not in audit_exclude*.txt or game/exclude_night.txt.\n')
            for a in sorted(v2):
                fh.write('%s  # %s\n' % (hexs(a), '+'.join(v2[a])))
    print('v2 detectors:')
    for c_, n_ in sorted(stats2.items()):
        print('  %-22s flagged %4d   new (not in any exclude list) %4d' % (
            c_, n_, sum(1 for a in v2 if c_ in v2[a])))
    print('audit_exclude_v2.txt: %d addresses (not rewritten unless AUDIT_WRITE_V2=1)' % len(v2))
    report_v3(hooked, new2, new3, stats3, excl, excl_unv, night, nospec)
    report_v4(hooked, new4, stats4)
    with open(OUT_FIX_CONST, 'w', encoding='utf-8', newline='') as fh:
        fh.write('exe_addr\tfolder\tcallee\targ_index\torig_constant\tport_constant\n')
        for r_ in constfix:
            fh.write('\t'.join(str(x_) for x_ in r_) + '\n')
    print('audit_fix_const_args.tsv: %d rows (a constant argument the port gets wrong; the original value is the fix)' % len(constfix))
    culprits = [0x445c50, 0x565a30, 0x420ea0, 0x42abbd, 0x42ac56, 0x438910, 0x438c10, 0x438cc0, 0x43bc80, 0x43f2b0, 0x4557c0]
    print('known runtime culprits caught: ' + ', '.join(
        '%s:%s' % (hexs(a), '+'.join(new2.get(a, []) + ([excl[a]] if a in excl else []) + (['v1-soft'] if a in excl_unv else [])) or 'MISSED')
        for a in culprits))
    cnt = collections.Counter(r[2] for r in out)
    print('categories:')
    for c, n in sorted(cnt.items()):
        print('  %-24s %d' % (c, n))
    print('audit_exclude.txt: %d addresses; unverified list: %d' % (len(excl), len([a for a in excl_unv if a not in excl])))
    print(dict(stats))
    return out, excl


def load_set(fn_):
    out_ = set()
    if os.path.exists(fn_):
        for ln in open(fn_, encoding='utf-8'):
            ln = ln.split('#')[0].split(';')[0].strip()
            for tok in ln.replace(',', ' ').split():
                if tok.lower().startswith('0x') and '-' not in tok:
                    out_.add(int(tok, 16))
    return out_


def report_v3(hooked, new2, new3, stats3, excl, excl_unv, night_path, nospec):
    night = load_set(night_path)
    hunt = []
    for ln in open(os.path.join(BUILD, 'hunt.tsv'), encoding='utf-8'):
        t_ = ln.rstrip('\n').split('\t')
        if len(t_) >= 4 and t_[1].startswith('0x'):
            hunt.append((t_[0], int(t_[1], 16), t_[2], t_[3]))
    batch2 = [h for h in hunt if h[0] >= '2026-10-22 03:56']
    info = {h[0]: (h[2], h[3], h[1]) for h in hooked}      # addr -> (folder, name, port entry)
    # the v2 local-too-small detector had a bug (fixed in v3), so its new hits belong to the v3 list
    merged = {a: list(c) for a, c in new3.items()}
    for a, cs in new2.items():
        for c_ in cs:
            if c_ == 'local-too-small':
                merged.setdefault(a, []).append((c_, info[a][1], info[a][0]))
    v3 = {a: c for a, c in merged.items() if a not in night}
    with open(OUT_EXCLUDE_V3, 'w', encoding='utf-8', newline='') as fh:
        fh.write('# Generated by hybrid/audit_ports.py: addresses flagged by the v3 detectors and not in game/exclude_night.txt.\n'
                 '# Format: address  # class: name (folder)\n')
        for a in sorted(v3):
            fh.write('%s  # %s: %s (%s)\n' % (hexs(a), '+'.join(sorted({c_[0] for c_ in v3[a]})), info[a][1], info[a][0]))
    classes = sorted({c_[0] for cs in merged.values() for c_ in cs})
    print('v3 detectors (class: flagged / not yet in exclude_night / of the %d batch-2 culprits):' % len(batch2))
    for c_ in classes:
        print('  %-24s %4d %4d %3d' % (
            c_, sum(1 for a in merged if any(x_[0] == c_ for x_ in merged[a])),
            sum(1 for a in v3 if any(x_[0] == c_ for x_ in v3[a])),
            sum(1 for h in batch2 if any(x_[0] == c_ for x_ in merged.get(h[1], [])))))
    print('audit_exclude_v3.txt: %d addresses' % len(v3))
    caught = 0
    print('batch-2 culprits and the v3 class that flags them:')
    for h in batch2:
        cats = sorted({c_[0] for c_ in merged.get(h[1], [])})
        caught += bool(cats)
        print('  %s %-30s %s' % (hexs(h[1]), h[3][:30], ','.join(cats) or '-'))
    print('batch-2 culprits flagged: %d of %d' % (caught, len(batch2)))
    # folder risk
    culp = collections.Counter(h[3] for h in hunt)
    per = collections.defaultdict(lambda: collections.Counter())
    for a, (folder, name, _pe) in info.items():
        c = per[folder]
        c['n'] += 1
        c['night'] += a in night
        c['v3'] += a in v3
        c['nospec'] += a in nospec
        if re.search(r'GUESS|FUN_|unknown|unnamed|^thunk|lifted|^wrap', name):
            c['guess'] += 1
    rows_ = []
    for folder, c in per.items():
        risk = (2 * culp[folder] + c['night'] + c['v3']) / c['n']
        rows_.append((folder, c['n'], culp[folder], c['night'], c['v3'], c['guess'], c['nospec'], risk))
    rows_.sort(key=lambda r_: (-r_[7] if r_[1] >= 5 else 0, -r_[1]))
    print('folder risk: folder, hooked, hunt culprits, already in exclude_night, v3 new, GUESS-named, no spec, risk=(2*culprits+night+v3)/hooked')
    for r_ in rows_[:15]:
        print('  %-24s %4d %2d %4d %3d %4d %2d  %.2f' % r_)
    whole = [r_ for r_ in rows_ if r_[1] >= 5 and r_[3] < r_[1] and (r_[7] >= 0.4 or r_[2] >= 3 or (r_[4] >= 8 and r_[4] / r_[1] >= 0.2))]
    for r_ in whole:
        if r_ not in rows_[:15]:
            print('  %-24s %4d %2d %4d %3d %4d %2d  %.2f   (wholesale, not in the top 15)' % r_)
    with open(OUT_EXCLUDE_V3_FOLDERS, 'w', encoding='utf-8', newline='') as fh:
        fh.write('# Generated by hybrid/audit_ports.py: folders to exclude wholesale (rule: >= 5 hooked functions, and risk >= 0.4\n'
                 '# or >= 3 runtime culprits or >= 20% of the folder hit by >= 8 v3 detectors). Only addresses not already in game/exclude_night.txt.\n'
                 '# Format: address  # folder-risk: name (folder)\n')
        n_ = 0
        for r_ in whole:
            for a in sorted(info):
                if info[a][0] == r_[0] and a not in night:
                    fh.write('%s  # folder-risk: %s (%s)\n' % (hexs(a), info[a][1], info[a][0]))
                    n_ += 1
    print('wholesale folders: %s -> audit_exclude_v3_folders.txt (%d addresses not yet excluded)' % (', '.join(r_[0] for r_ in whole), n_))
    return v3


def report_v4(hooked, new4, stats4):
    """audit_exclude_v4.txt: addresses the v4 detectors flag, minus game/exclude_level2.txt (the list the live game runs with)."""
    have = load_set(os.path.join(ROOT, 'game', 'exclude_level2.txt'))
    info = {h[0]: (h[2], h[3]) for h in hooked}
    hunt = []
    for ln in open(os.path.join(BUILD, 'hunt.tsv'), encoding='utf-8'):
        t_ = ln.rstrip('\n').split('\t')
        if len(t_) >= 4 and t_[1].startswith('0x'):
            hunt.append((t_[0], int(t_[1], 16), t_[2], t_[3]))
    verdict = ('call-args-short', 'call-this-unset', 'call-edx-unset', 'orig-pending-slot')     # orig-pending-args: no verdict
    v4 = {a: [c_ for c_ in c if c_[0] in verdict] for a, c in new4.items() if a not in have}
    v4 = {a: c for a, c in v4.items() if c}
    with open(OUT_EXCLUDE_V4, 'w', encoding='utf-8', newline='') as fh:
        fh.write('# Generated by hybrid/audit_ports.py: addresses flagged by the v4 detectors and not in game/exclude_level2.txt.\n'
                 '# Format: address  # class: name (folder)\n')
        for a in sorted(v4):
            fh.write('%s  # %s: %s (%s)\n' % (hexs(a), '+'.join(sorted({c_[0] for c_ in v4[a]})), info[a][1], info[a][0]))
    print('v4 detectors (class: flagged / not in exclude_level2 / of the %d hunt culprits):' % len({h[1] for h in hunt}))
    for c_ in sorted(stats4):
        print('  %-20s %4d %4d %3d' % (
            c_, sum(1 for a in new4 if any(x_[0] == c_ for x_ in new4[a])),
            sum(1 for a in v4 if any(x_[0] == c_ for x_ in v4[a])),
            sum(1 for h in {h[1] for h in hunt} if any(x_[0] == c_ for x_ in new4.get(h, [])))))
    print('audit_exclude_v4.txt: %d addresses' % len(v4))
    print('hunt culprits flagged by a v4 detector: ' + ', '.join(
        '%s:%s' % (hexs(a), '+'.join(sorted({c_[0] for c_ in new4[a]}))) for a in sorted({h[1] for h in hunt}) if a in new4))
    return v4


def kinds(k):
    return '|'.join(n for b, n in ((IN, 'in'), (W, 'w'), (WP, 'wp'), (C, 'call')) if k & b) or '-'


if __name__ == '__main__':
    sys.setrecursionlimit(60000)
    threading.stack_size(128 * 1024 * 1024)
    t = threading.Thread(target=main)
    t.start()
    t.join()
