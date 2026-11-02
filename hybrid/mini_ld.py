#!/usr/bin/env python3
"""mini_ld.py (hybrid copy) - tiny static linker for i386 ELF relocatable objects.

Copy of ReFreedomFighters/tooling/mini_ld.py, extended so objects from many port folders link into
one image (used by hybrid/build_all.py). The original is left untouched. Differences:

  * objects carry a `folder` label. A reference to a global symbol resolves in this order:
    a definition in the same object, then in the same folder, then anywhere (first strong
    definition wins, a weak one only if no strong one exists in that scope);
  * `ext_<hex>` (whole name) always binds to that absolute exe address, even if some object
    defines a symbol of that name;
  * a `drop(obj, name)` predicate removes definitions from the symbol tables (used to hide the
    unselected `pc_<hex>` registrations); the code behind a dropped symbol stays in the image;
  * optional pruning: only objects reachable from the root objects through relocations are laid out;
  * unresolved symbols do not stop the link: they bind to `ff_unresolved_trap` (or 0) and are listed;
  * the result carries the section-kind ranges and statistics.

Without the folder machinery the command line behaves like the original:

    mini_ld.py --base 0x31000000 -o out.bin --syms out.syms a.o b.o ...
"""
import argparse
import os
import re
import struct
import sys
from collections import defaultdict

SHT_PROGBITS, SHT_SYMTAB, SHT_NOBITS, SHT_REL, SHT_RELA = 1, 2, 8, 9, 4
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xfff1, 0xfff2
STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
KIND_NAMES = ('text', 'rodata', 'data', 'bss')
# ext_<hex>, optionally with the vectorcall decoration clang adds on this target (ext_634d70@@8)
EXT_RE = re.compile(r'ext_([0-9a-fA-F]+)(?:@@?[0-9]+)?')
# ext_<hex> addresses that bind somewhere else. 0x633654 is __security_check_cookie (`cmp ecx, [cookie]; jne fail; ret`):
# the ports have no /GS frame, so there is no cookie to check, and a port that passes 0 (or leaves ECX alone) would fast-fail
# with 0xC0000409. 0x63365d is the `ret` right behind its compare, so every caller (any declared convention, nothing is
# popped) returns at once.
EXT_REBIND = {0x633654: 0x63365d}
if os.environ.get('FF_NO_EXT_REBIND'):      # pilot runs: the specs hook 0x633654 and compare the call log
    EXT_REBIND = {}


class Obj:
    def __init__(self, path, folder='', label=None):
        self.path = path
        self.folder = folder
        self.label = label or path
        d = self.d = open(path, 'rb').read()
        if d[:4] != b'\x7fELF' or d[4] != 1 or d[18] != 3:
            raise SystemExit('%s: not an i386 ELF32 object' % path)
        shoff = struct.unpack_from('<I', d, 0x20)[0]
        shnum, shstrndx = struct.unpack_from('<HH', d, 0x30)
        self.sh = [struct.unpack_from('<10I', d, shoff + 40 * i) for i in range(shnum)]
        strsec = self.sh[shstrndx]
        self.names = [self._str(strsec, s[0]) for s in self.sh]
        self.addr = {}            # section index -> final address
        self.syms = []            # (name, value, size, bind, type, shndx)
        self.gdefs = {}           # defined global/weak name -> (bind, shndx, value)
        for i, s in enumerate(self.sh):
            if s[1] == SHT_SYMTAB:
                strtab = self.sh[s[6]]
                for k in range(s[5] // 16):
                    nm, val, size, info, other, shndx = struct.unpack_from('<IIIBBH', d, s[4] + 16 * k)
                    name = self._str(strtab, nm)
                    bind, typ = info >> 4, info & 0xf
                    self.syms.append((name, val, size, bind, typ, shndx))
                    if bind in (STB_GLOBAL, STB_WEAK) and shndx != SHN_UNDEF and typ not in (3, 4) and name:
                        if name not in self.gdefs or (self.gdefs[name][0] == STB_WEAK and bind == STB_GLOBAL):
                            self.gdefs[name] = (bind, shndx, val)
        self._undef = None

    def _str(self, sec, off):
        o = sec[4] + off
        e = self.d.index(b'\0', o)
        return self.d[o:e].decode()

    def laid_out(self, i):
        return kind(self.names[i], self.sh[i]) is not None

    def rel_entries(self, s):
        return struct.iter_unpack('<II', self.d[s[4]:s[4] + (s[5] & ~7)])

    def undef_names(self):
        """Names of undefined global symbols referenced by relocations of the allocated sections."""
        if self._undef is None:
            out = set()
            for s in self.sh:
                if s[1] == SHT_RELA:
                    raise SystemExit('%s: RELA sections not supported' % self.path)
                if s[1] != SHT_REL or not self.laid_out(s[7]):
                    continue
                for _off, info in self.rel_entries(s):
                    k = info >> 8
                    if k == 0:
                        continue
                    nm, _v, _sz, _bind, typ, shndx = self.syms[k]
                    if shndx == SHN_UNDEF and typ != 3 and nm:
                        out.add(nm)
            self._undef = out
        return self._undef


def kind(name, s):
    flags, typ = s[2], s[1]
    if not flags & SHF_ALLOC or typ not in (SHT_PROGBITS, SHT_NOBITS):
        return None
    if flags & SHF_EXEC:
        return 0
    if typ == SHT_NOBITS:
        return 3
    return 2 if flags & SHF_WRITE else 1


class Result:
    pass


def link(objs, base=0x31000000, roots=None, drop=None, track=None, trap_sym='ff_unresolved_trap', kind_align=0):
    """Link `objs` (list of Obj, in layout order). roots=None keeps every object, otherwise only the
    objects reachable from `roots`. drop(o, name) -> True hides a global definition. track(name) -> True
    records the final address of such global definitions in Result.tracked[(obj, name)].
    kind_align (e.g. 0x1000) starts rodata, data and bss on that boundary so a loader can give each
    kind its own page protection."""
    drop = drop or (lambda o, nm: False)
    track = track or (lambda nm: False)
    st = defaultdict(int)
    res = Result()
    res.stats = st

    # ---- definition tables (dropped names are invisible to everybody)
    by_name = defaultdict(list)                   # name -> [obj, ...] in object order
    for o in objs:
        for nm in o.gdefs:
            if not drop(o, nm):
                by_name[nm].append(o)
    cache_any, cache_fold = {}, {}

    def strength(o, nm):
        return o.gdefs[nm][0] == STB_GLOBAL

    def best(cands):
        for c in cands:
            if strength(c[0], c[1]):
                return c[0]
        return cands[0][0] if cands else None

    def in_folder(folder, nm):
        key = (folder, nm)
        if key not in cache_fold:
            cache_fold[key] = best([(o, nm) for o in by_name.get(nm, ()) if o.folder == folder])
        return cache_fold[key]

    def anywhere(nm):
        if nm not in cache_any:
            cache_any[nm] = best([(o, nm) for o in by_name.get(nm, ())])
        return cache_any[nm]

    def lookup(o, nm):
        """-> ('ext', addr) | ('obj', defining obj, level) | ('none',)"""
        m = EXT_RE.fullmatch(nm)
        if m:
            return ('ext', EXT_REBIND.get(int(m.group(1), 16), int(m.group(1), 16)))
        t = in_folder(o.folder, nm)
        if t is not None:
            return ('obj', t, 'folder')
        t = anywhere(nm)
        if t is not None:
            return ('obj', t, 'other')
        return ('none',)

    # ---- reachability
    if roots is None:
        inc = list(objs)
    else:
        seen = set(id(r) for r in roots)
        work = list(roots)
        while work:
            o = work.pop()
            for nm in o.undef_names():
                r = lookup(o, nm)
                if r[0] == 'obj' and id(r[1]) not in seen:
                    seen.add(id(r[1]))
                    work.append(r[1])
        inc = [o for o in objs if id(o) in seen]
    res.objs = inc
    st['objects_linked'] = len(inc)
    st['objects_pruned'] = len(objs) - len(inc)

    # ---- layout
    addr = base
    kr = {}
    for k in range(4):
        lo = None
        if kind_align and k:
            addr = (addr + kind_align - 1) & ~(kind_align - 1)
        for o in inc:
            for i, s in enumerate(o.sh):
                if kind(o.names[i], s) == k:
                    al = max(s[8], 1)
                    addr = (addr + al - 1) & ~(al - 1)
                    o.addr[i] = addr
                    if lo is None:
                        lo = addr
                    addr += s[5]
        kr[KIND_NAMES[k]] = (lo if lo is not None else addr, addr)
    commons = {}
    for o in inc:
        for nm, val, size, bind, typ, shndx in o.syms:
            if shndx == SHN_COMMON and nm not in commons:
                al = max(val, 1)
                addr = (addr + al - 1) & ~(al - 1)
                commons[nm] = addr
                addr += size
    if kind_align:
        addr = (addr + kind_align - 1) & ~(kind_align - 1)     # the image ends on a page boundary
    if commons or kind_align:
        kr['bss'] = (kr['bss'][0], addr)
    st['commons'] = len(commons)
    end = addr
    res.ranges = kr
    res.base, res.end = base, end
    img = bytearray(end - base)
    for o in inc:
        for i, at in o.addr.items():
            s = o.sh[i]
            if s[1] == SHT_PROGBITS:
                img[at - base:at - base + s[5]] = o.d[s[4]:s[4] + s[5]]
    res.img = img

    # ---- symbols
    out_syms = []
    tracked = {}
    letters = ('t', 'r', 'd', 'b')
    sec_kind = {}
    for o in inc:
        for i, s in enumerate(o.sh):
            sec_kind[(id(o), i)] = kind(o.names[i], s)
    ctor_secs = set()
    for o in inc:
        for i, nm in enumerate(o.names):
            if nm.startswith(('.init_array', '.ctors', '.fini_array', '.dtors')) and o.sh[i][5] > 0:
                ctor_secs.add((o.label, nm))
        for nm, val, size, bind, typ, shndx in o.syms:
            if shndx in (SHN_UNDEF, SHN_COMMON) or typ in (3, 4) or not nm:
                continue
            if bind in (STB_GLOBAL, STB_WEAK) and drop(o, nm):
                continue
            if shndx == SHN_ABS:
                v, c = val, 'a'
            elif shndx in o.addr:
                v, c = o.addr[shndx] + val, letters[sec_kind[(id(o), shndx)]]
            else:
                continue
            if bind in (STB_GLOBAL, STB_WEAK):
                c = c.upper()
                if track(nm):
                    tracked[(o, nm)] = v
            out_syms.append((v, c, nm))
    for nm, v in commons.items():
        out_syms.append((v, 'B', nm))
    res.syms = sorted(out_syms)
    res.tracked = tracked
    res.ctor_sections = sorted(ctor_secs)

    # ---- duplicate global definitions among the linked objects
    dup_names = dup_cross = 0
    inc_ids = set(id(o) for o in inc)
    for nm, lst in by_name.items():
        if len(lst) < 2:
            continue
        strong = [o for o in lst if id(o) in inc_ids and strength(o, nm)]
        if len(strong) > 1:
            dup_names += 1
            if len(set(o.folder for o in strong)) > 1:
                dup_cross += 1
    st['dup_global_names'] = dup_names
    st['dup_global_names_cross_folder'] = dup_cross

    trap = anywhere(trap_sym)
    trap_addr = 0
    if trap is not None:
        _b, shndx, val = trap.gdefs[trap_sym]
        if shndx in trap.addr:
            trap_addr = trap.addr[shndx] + val
    res.unresolved = defaultdict(set)          # name -> {obj labels}
    res.ext_defined = set()                    # ext_<hex> names that some object defines (ignored)
    res.ambiguous = {}                         # name -> folders (chosen by "anywhere")

    # ---- resolution + relocation
    rcache = {}
    same_seen = set()

    def resolve(o, k):
        nm, val, size, bind, typ, shndx = o.syms[k]
        if k == 0:        # STN_UNDEF: absolute target (LLVM emits call <abs addr> as PC32 against symbol 0)
            return 0
        if typ == 3:      # section symbol
            return o.addr[shndx]
        if shndx == SHN_ABS:
            return val
        if shndx not in (SHN_UNDEF, SHN_COMMON):
            if bind != STB_LOCAL and (id(o), nm) not in same_seen:
                same_seen.add((id(o), nm))
                st['ref_same_object'] += 1
                if by_name.get(nm) and by_name[nm][0] is not o:
                    st['ref_same_object_pref_changed'] += 1
                ff = in_folder(o.folder, nm)
                if ff is not None and ff is not o:
                    st['ref_same_object_vs_folder_first'] += 1
            return o.addr[shndx] + val
        key = (id(o), nm)
        v = rcache.get(key)
        if v is not None:
            return v
        m = EXT_RE.fullmatch(nm)
        if m:
            st['ref_ext'] += 1
            v = int(m.group(1), 16)
            if v in EXT_REBIND:
                v = EXT_REBIND[v]
                st['ref_ext_rebound'] += 1
        else:
            r = lookup(o, nm)
            if r[0] == 'obj':
                t = r[1]
                _b, tsh, tval = t.gdefs[nm]
                v = t.addr[tsh] + tval
                if t is not by_name[nm][0]:
                    st['ref_pref_changed'] += 1
                if r[2] == 'folder':
                    st['ref_same_folder'] += 1
                else:
                    st['ref_elsewhere'] += 1
                    folders = sorted(set(c.folder for c in by_name[nm]))
                    if len(folders) > 1:
                        st['ref_elsewhere_ambiguous'] += 1
                        res.ambiguous[nm] = folders
            elif nm in commons:
                v = commons[nm]
                st['ref_common'] += 1
            elif bind == STB_WEAK:
                v = 0
                st['ref_weak_undefined'] += 1
            else:
                v = trap_addr
                st['ref_unresolved'] += 1
                res.unresolved[nm].add(o.label)
        rcache[key] = v
        return v

    for o in inc:
        for s in o.sh:
            if s[1] != SHT_REL or s[7] not in o.addr:
                continue
            at = o.addr[s[7]]
            for off, info in o.rel_entries(s):
                t, sym = info & 0xff, info >> 8
                P = at + off
                S = resolve(o, sym)
                A = struct.unpack_from('<i', img, P - base)[0]
                if t == 0:
                    continue
                if t == 1:
                    v = S + A
                elif t in (2, 4):
                    v = S + A - P
                else:
                    raise SystemExit('%s: relocation type %d not supported (section %s)' % (o.path, t, o.names[s[7]]))
                struct.pack_into('<I', img, P - base, v & 0xffffffff)
    # ext_ names that objects define themselves are ignored by resolution: list them
    for nm in by_name:
        if EXT_RE.fullmatch(nm):
            res.ext_defined.add(nm)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('objs', nargs='+')
    ap.add_argument('--base', type=lambda x: int(x, 0), default=0x31000000)
    ap.add_argument('-o', required=True)
    ap.add_argument('--syms', required=True)
    a = ap.parse_args()
    objs = [Obj(p) for p in a.objs]
    r = link(objs, a.base, track=lambda nm: nm.startswith('pc_'))
    if r.unresolved:
        raise SystemExit('unresolved symbols: %s' % ', '.join(sorted(r.unresolved)))
    open(a.o, 'wb').write(bytes(r.img))
    with open(a.syms, 'w') as f:
        for v, t, nm in r.syms:
            f.write('%08x %s %s\n' % (v, t, nm))
    print('built %d registered functions, %d bytes' % (len(r.tracked), len(r.img)))


if __name__ == '__main__':
    main()
