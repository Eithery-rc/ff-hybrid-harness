"""callsites.py - the calls a function makes into other exe functions, and what those callees take as input.

A port can pass a wrong `this` or a wrong argument to an exe callee that ignores it in the sampled state: 0x64d490's
port calls ZDrawBase::PrimInstanceEnter (0x63da80) with ECX = its own `this`, and once with ECX = 0, but 0x63da80 reads
ECX only when its argument already holds a slot index. Seventeen samples never had one, the memory came out equal, and
the real game crashed on the 682nd call. So the replay also compares the calls themselves: at every call instruction
of the function under test (the original's body; for a port its body and the image-internal helpers it calls) a code
hook records the target and the inputs; compare() then checks, call by call, the target and every input the callee
can read: the registers it reads before writing them on some path from its entry (entry liveness), and its stack
arguments (its `ret N`, or the caller's `add esp, N` cleanup for cdecl).
"""
import capstone
from capstone import x86_const as X

import liveness

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_md.detail = True
_inputs_cache, _nargs_cache, _sites_cache = {}, {}, {}
INPUT_REGS = ('eax', 'ecx', 'edx')


def _one(code_at, a):
    b = code_at(a, 16)
    if not b:
        return None
    return next(_md.disasm(b, a), None)


def call_sites(code_at, entry, inside=None, tag='', budget=4000):
    """Addresses of the call instructions reachable from entry without following calls (jumps and tail jumps are
    followed). inside(addr) True means a call target is part of the same code (a port's image-internal helper): its
    body is walked as well. Returns {call address: capstone instruction}."""
    key = (entry, tag)
    if key in _sites_cache:
        return _sites_cache[key]
    sites, seen, work, steps = {}, set(), [entry], 0
    while work and steps < budget:
        a = work.pop()
        while steps < budget and a not in seen:
            seen.add(a)
            steps += 1
            ins = _one(code_at, a)
            if ins is None:
                break
            m, ops = ins.mnemonic, ins.operands
            if m == 'call':
                sites[a] = ins
                if inside and ops and ops[0].type == X.X86_OP_IMM and inside(ops[0].imm):
                    work.append(ops[0].imm)
            elif m in ('ret', 'retf', 'int3', 'hlt', 'ud2'):
                break
            elif m == 'jmp':
                if ops and ops[0].type == X.X86_OP_IMM:
                    a = ops[0].imm
                    continue
                break
            elif m.startswith('j') or m.startswith('loop'):
                if ops and ops[0].type == X.X86_OP_IMM:
                    work.append(ops[0].imm)
            a = ins.address + ins.size
    _sites_cache[key] = sites
    return sites


def callee_inputs(code_at, target, budget=300):
    """Registers among EAX/ECX/EDX that the callee reads before writing them on some path from its entry."""
    if target in _inputs_cache:
        return _inputs_cache[target]
    found, seen, work, steps = set(), set(), [(target, frozenset())], 0
    while work and steps < budget:
        a, killed = work.pop()
        while steps < budget and (a, killed) not in seen:
            seen.add((a, killed))
            steps += 1
            ins = _one(code_at, a)
            if ins is None:
                break
            m, ops = ins.mnemonic, ins.operands
            try:
                rd, wr = ins.regs_access()
            except capstone.CsError:
                break
            if m == 'nop':
                rd, wr = [], []
            if m in liveness.ZERO_IDIOMS and len(ops) == 2 and ops[0].type == X.X86_OP_REG and \
                    ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg:
                rd = []
            if m == 'push' and ops and ops[0].type == X.X86_OP_REG and \
                    liveness._push_is_alloc(code_at, ins.address + ins.size):
                rd = []
            for r in rd:
                b = liveness.GPR.get(r, (None,))[0]
                if b in INPUT_REGS and b not in killed:
                    found.add(b)
            if m in ('call', 'ret', 'retf', 'int3', 'hlt', 'ud2') or (m == 'jmp' and ops[0].type != X.X86_OP_IMM):
                break
            kill = {liveness.GPR[r][0] for r in wr if r in liveness.GPR and liveness.GPR[r][1] == 0xffffffff}
            killed = killed | frozenset(k for k in kill if k in INPUT_REGS)
            if m == 'jmp':
                a = ops[0].imm
                continue
            if (m.startswith('j') or m.startswith('loop')) and ops and ops[0].type == X.X86_OP_IMM:
                work.append((ops[0].imm, killed))
            a = ins.address + ins.size
    out = tuple(r for r in INPUT_REGS if r in found)
    _inputs_cache[target] = out
    return out


def callee_nargs(code_at, target, site_after):
    """Stack argument dwords of a call: the callee's `ret N` (callee-pop), else the caller's cleanup right after the
    call site (cdecl), capped at 16."""
    import models

    class _Src:
        def read(self, a, n):
            return code_at(a, n) or None

        def u32(self, a):
            return None
    if target not in _nargs_cache:
        _nargs_cache[target] = models.scan_ret(_Src(), target)
    pop = _nargs_cache[target]
    if pop:
        return min(pop // 4, 16)
    return min(liveness.caller_cleanup(code_at, site_after) // 4, 16)


def operand_target(ins, reg, read32):
    """Call target from the operand: imm, register, or [base + index*scale + disp]."""
    op = ins.operands[0]
    if op.type == X.X86_OP_IMM:
        return op.imm
    if op.type == X.X86_OP_REG:
        return reg(ins.reg_name(op.reg))
    if op.type == X.X86_OP_MEM:
        a = op.mem.disp
        if op.mem.base:
            a += reg(ins.reg_name(op.mem.base))
        if op.mem.index:
            a += reg(ins.reg_name(op.mem.index)) * op.mem.scale
        if op.mem.segment:
            return None
        return read32(a & 0xffffffff)
    return None


SEC_COOKIE, SEC_COOKIE_RET, CHKSTK = 0x633654, 0x63365d, 0x6336b0


def ignored_callee(code_at, t):
    """Callees whose `this` is not part of the contract: the /GS cookie check and its `ret` (the ports bind it to
    0x63365d), _chkstk, and import thunks (`jmp [IAT]`, compared in the DLL call log)."""
    if t in (SEC_COOKIE, SEC_COOKIE_RET, CHKSTK):
        return True
    ins = _one(code_at, t)
    return ins is not None and ins.mnemonic == 'jmp' and ins.op_str.startswith('dword ptr [0x')
