"""liveness.py - which registers the caller reads after a call returns, from the exe code at the return address.

The replay compares a scratch register (EAX, ECX, EDX, XMM0..7) only when the caller reads it before writing it: EAX of
a void function and ECX after any call are garbage that may differ. Reads are tracked per byte (AL, AH, AX, EAX), so a
caller that only tests AL compares only AL, and one that uses all of EAX catches upper-byte garbage behind a setcc
(0x4d5120 nativeEof). Paths are followed through direct jumps and both arms of conditional jumps. A path ends at:
  call          the callee clobbers the scratch registers; whatever was not read yet is dead
  ret           the value flows to the caller's caller: what is not killed yet is 'maybe' live (a void caller ends
                the same way as one that returns our EAX)
  indirect jmp  'maybe' for everything not killed
EBX, ESI, EDI, EBP and ESP are callee-saved: the replay always compares them, liveness is not needed.
"""
import capstone
from capstone import x86_const as X

GPR = {}
for base, names in (('eax', ('AL', 'AH', 'AX', 'EAX')), ('ecx', ('CL', 'CH', 'CX', 'ECX')),
                    ('edx', ('DL', 'DH', 'DX', 'EDX')), ('ebx', ('BL', 'BH', 'BX', 'EBX'))):
    for nm, m in zip(names, (0xff, 0xff00, 0xffff, 0xffffffff)):
        GPR[getattr(X, 'X86_REG_' + nm)] = (base, m)
for base, names in (('esi', ('SI', 'ESI')), ('edi', ('DI', 'EDI')), ('ebp', ('BP', 'EBP'))):
    for nm, m in zip(names, (0xffff, 0xffffffff)):
        GPR[getattr(X, 'X86_REG_' + nm)] = (base, m)
for i in range(8):
    GPR[getattr(X, 'X86_REG_XMM%d' % i)] = ('xmm%d' % i, 1)
SCRATCH = ('eax', 'ecx', 'edx') + tuple('xmm%d' % i for i in range(8))
ZERO_IDIOMS = {'xor', 'sub', 'pxor', 'xorps', 'xorpd', 'sbb'}

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_md.detail = True


def _one(code_at, a):
    b = code_at(a, 16)
    if not b:
        return None
    for ins in _md.disasm(b, a):
        return ins
    return None


def _esp0_access(ins):
    """'w' / 'r' when the instruction writes / reads dword [esp] (no displacement, no index), else None."""
    for op in ins.operands:
        if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_ESP and op.mem.index == 0 and op.mem.disp == 0:
            return 'w' if op.access & capstone.CS_AC_WRITE and not op.access & capstone.CS_AC_READ else 'r'
    return None


def _push_is_alloc(code_at, a, look=16):
    """MSVC's `push ecx` that only reserves a stack slot: the slot is overwritten through [esp] before anything reads
    it or the stack moves (`push ecx; lea ecx, [ebp-0x58]; ...; movss [esp], xmm0`). Such a push does not read the
    register."""
    for i in range(look):
        ins = _one(code_at, a)
        if ins is None:
            return False
        if i == 0 and ins.mnemonic in ('mov', 'lea') and ins.op_str.endswith(', esp'):
            return True         # `push ecx; mov ecx, esp`: the slot's address is taken for a pending argument
        acc = _esp0_access(ins)
        if acc == 'w':
            return True
        try:
            _rd, wr = ins.regs_access()
        except capstone.CsError:
            return False
        if acc == 'r' or ins.mnemonic in ('push', 'pop', 'call', 'ret', 'jmp', 'leave') or \
                ins.mnemonic.startswith('j') or X.X86_REG_ESP in wr:
            return False
        a = ins.address + ins.size
    return False


def live_after(code_at, ra, budget=400):
    """code_at(addr, n) -> bytes of exe code. Returns (live, maybe): {reg: mask} for the scratch registers."""
    live, maybe = {}, {}
    seen = set()
    work = [(ra, ())]
    steps = 0
    while work and steps < budget:
        a, killed_t = work.pop()
        killed = dict(killed_t)
        while steps < budget:
            key = (a, tuple(sorted(killed.items())))
            if key in seen:
                break
            seen.add(key)
            steps += 1
            ins = _one(code_at, a)
            if ins is None:
                break
            m = ins.mnemonic
            try:
                rd, wr = ins.regs_access()
            except capstone.CsError:
                rd, wr = [], []
            if m == 'nop':          # `nop dword ptr [eax]` names EAX in its operand but reads nothing
                rd, wr = [], []
            ops = ins.operands
            if m == 'push' and ops and ops[0].type == X.X86_OP_REG and _push_is_alloc(code_at, ins.address + ins.size):
                rd = [r for r in rd if r != ops[0].reg]
            if m in ZERO_IDIOMS and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_REG \
                    and ops[0].reg == ops[1].reg:
                rd = [r for r in rd if r != ops[0].reg]
            if m in ('or', 'and') and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_IMM \
                    and (ops[1].imm & 0xffffffff) == (0xffffffff if m == 'or' else 0) and ins.op_str.startswith('e'):
                rd = [r for r in rd if r != ops[0].reg]       # `or edx, -1` / `and eax, 0` only write
            for r in rd:
                if r in GPR:
                    b, mk = GPR[r]
                    if b in SCRATCH:
                        live[b] = live.get(b, 0) | (mk & ~killed.get(b, 0))
            if m == 'call':
                break
            if m in ('ret', 'retf') or (m == 'jmp' and ops and ops[0].type != X.X86_OP_IMM):
                for b in SCRATCH:
                    if m in ('ret', 'retf') and b not in ('eax', 'edx', 'xmm0'):
                        continue
                    full = 0xffffffff if not b.startswith('xmm') else 1
                    left = full & ~killed.get(b, 0)
                    if left:
                        maybe[b] = maybe.get(b, 0) | left
                break
            for r in wr:
                if r in GPR:
                    b, mk = GPR[r]
                    killed[b] = killed.get(b, 0) | mk
            if m in ('int3', 'hlt', 'ud2', 'int'):
                break
            if m == 'jmp':
                a = ops[0].imm
                continue
            if m.startswith('j') or m in ('loop', 'loope', 'loopne', 'jecxz'):
                if ops and ops[0].type == X.X86_OP_IMM:
                    work.append((ops[0].imm, tuple(sorted(killed.items()))))
            a = ins.address + ins.size
    for b in list(maybe):
        maybe[b] &= ~live.get(b, 0)
        if not maybe[b]:
            del maybe[b]
    return {b: v for b, v in live.items() if v}, maybe


def through_returns(code_at, ra, esp, ebp, read32, depth=2, budget=300):
    """'maybe' made definite: follow the caller from the return address to its own `ret` while EAX/EDX stay
    unwritten, tracking ESP and EBP through the epilogue (push/pop, add/sub/lea esp, mov esp,ebp, leave), take the
    next return address from the real stack (read32) and see whether THAT caller reads them. Returns {reg: mask}
    of EAX/EDX bits read up the chain (`call CurrentRoom; pop esi; ret` returns our EAX to a caller that uses it)."""
    out = {}
    work = [(ra, esp, ebp, ())]
    seen, steps = set(), 0
    while work and steps < budget:
        a, sp, bp, killed_t = work.pop()
        killed = dict(killed_t)
        while steps < budget:
            if (a, sp, bp, killed_t) in seen:
                break
            seen.add((a, sp, bp, killed_t))
            steps += 1
            ins = _one(code_at, a)
            if ins is None:
                break
            m, ops = ins.mnemonic, ins.operands
            if m == 'call' or m in ('int3', 'hlt', 'ud2', 'int') or (m == 'jmp' and ops and ops[0].type != X.X86_OP_IMM):
                break
            if m == 'ret':
                nxt = read32(sp) if sp is not None else None
                if nxt is not None:
                    pop = int(ins.op_str, 0) if ins.op_str else 0
                    live, maybe = live_after(code_at, nxt)
                    for b in ('eax', 'edx'):
                        bits = (live.get(b, 0) | 0) & ~killed.get(b, 0)
                        if bits:
                            out[b] = out.get(b, 0) | bits
                    if depth > 1 and any(maybe.get(b, 0) & ~killed.get(b, 0) for b in ('eax', 'edx')):
                        for b, v in through_returns(code_at, nxt, sp + 4 + pop, bp, read32, depth - 1).items():
                            v &= ~killed.get(b, 0)
                            if v:
                                out[b] = out.get(b, 0) | v
                break
            try:
                _rd, wr = ins.regs_access()
            except capstone.CsError:
                _rd, wr = [], []
            if m != 'nop':
                for r in wr:
                    if r in GPR and GPR[r][0] in ('eax', 'edx'):
                        b, mk = GPR[r]
                        killed[b] = killed.get(b, 0) | mk
            if all(killed.get(b, 0) == 0xffffffff for b in ('eax', 'edx')):
                break
            # ESP / EBP through the epilogue
            o0 = ops[0] if ops else None
            if m == 'push':
                sp = sp - 4 if sp is not None else None
            elif m == 'pop':
                if o0.type == X.X86_OP_REG and o0.reg == X.X86_REG_EBP:
                    bp = read32(sp) if sp is not None else None
                sp = sp + 4 if sp is not None else None
            elif m == 'leave':
                sp = bp
                bp = read32(sp) if sp is not None else None
                sp = sp + 4 if sp is not None else None
            elif X.X86_REG_ESP in wr:
                src = ins.op_str.split(', ', 1)[1] if ', ' in ins.op_str else ''
                if m == 'mov' and src == 'ebp':
                    sp = bp
                elif m in ('add', 'sub') and len(ops) == 2 and ops[1].type == X.X86_OP_IMM and sp is not None:
                    sp = sp + ops[1].imm if m == 'add' else sp - ops[1].imm
                elif m == 'lea' and ops[1].mem.index == 0 and ops[1].mem.base in (X.X86_REG_EBP, X.X86_REG_ESP):
                    base = bp if ops[1].mem.base == X.X86_REG_EBP else sp
                    sp = base + ops[1].mem.disp if base is not None else None
                else:
                    sp = None
            elif X.X86_REG_EBP in wr:
                bp = sp if (m == 'mov' and ins.op_str == 'ebp, esp') else None
            killed_t = tuple(sorted(killed.items()))
            if m == 'jmp':
                a = ops[0].imm
                continue
            if m.startswith('j') and ops and ops[0].type == X.X86_OP_IMM:
                work.append((ops[0].imm, sp, bp, killed_t))
            a = ins.address + ins.size
    return out


def caller_cleanup(code_at, ra):
    """Bytes the caller pops right after the call: `add esp, N`, or one or two `pop ecx` (MSVC's short cleanup).
    Writes the callee makes into its own argument slots are not outputs; this bounds that area for cdecl calls."""
    ins = _one(code_at, ra)
    if ins is None:
        return 0
    if ins.mnemonic == 'add' and ins.op_str.startswith('esp, '):
        try:
            return int(ins.op_str.split(', ')[1], 0) & 0xffff
        except ValueError:
            return 0
    n = 0
    while ins is not None and ins.mnemonic == 'pop' and ins.op_str == 'ecx' and n < 8:
        n += 4
        ins = _one(code_at, ins.address + ins.size)
    return n
