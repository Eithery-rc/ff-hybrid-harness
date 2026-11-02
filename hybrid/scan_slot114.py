"""scan_slot114.py [IMAGE_DIR] - hooked ports that call sysobj slot 0x114 with more than four stack args.

Slot 0x114 of the +0x9b table object (0x493980, ret 0x10) pops FOUR words (name, 0, file, line). A port that passes a fifth or sixth word to it
(vcall<R, ...>(m, 0x114, ...) with more than four args, or a function-pointer cast with more than four stack args and VSLOT(.., 0x114)) mis-models the
original: the extra pushed words belong to the next call (0x128 / 0x12c / 0x130 ...). Sources of hand-written and lifted ports are scanned; a site counts
only when its enclosing PCREG is hooked from that folder in IMAGE_DIR. Default image: hybrid/build.
"""
import os, re, sys
REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ROOT = os.path.join(REPO_ROOT, 'ReFreedomFighters', 'ports') + '/'
image = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO_ROOT, 'hybrid', 'build')
hooked = {}
for l in open(image + '/ff_ports.tsv', encoding='utf-8'):
    w = l.rstrip('\n').split('\t')
    if w[0].startswith('0x'):
        hooked[w[0]] = w[2]
folders = set(hooked.values())
res = []
pat_cast = re.compile(r'\(\s*u32\s*\(\s*(?:THISCALL|STDCALL|__attribute__\(\(thiscall\)\)|__attribute__\(\(stdcall\)\))?\s*\*\s*\)\s*\(([^)]*)\)\s*\)\s*(?:VSLOT\([^)]*0x114\)|\(\s*\*\s*\(u32\s*\*\)\s*\([^)]*\+\s*(?:0x114|276)\s*\)\s*\))')
for folder in sorted(folders):
    d = ROOT + folder + '/src'
    if not os.path.isdir(d):
        continue
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('.cpp'):
            continue
        txt = open(d + '/' + fn, encoding='utf-8', errors='replace').read()
        for m in re.finditer(r'0x114|\b276\b', txt):
            # take the statement around the match
            s = txt.rfind(';', 0, m.start()) + 1
            e = txt.find(';', m.start())
            st = txt[s:e]
            if '0x114' not in st and '276' not in st:
                continue
            # vcall<R, A...>(obj, 0x114, args...)
            n = None
            mm = re.search(r'vcall<([^>]*)>\s*\(([^;]*)', st)
            if mm and '0x114' in mm.group(2):
                tparams = [x for x in re.split(r',\s*(?![^<]*>)', mm.group(1)) if x.strip()]
                n = len(tparams) - 1            # R + args
                kind = 'vcall'
            else:
                mc = re.search(r'\(\s*u32\s*\(\s*\w*\s*\*\s*\)\s*\(([^)]*)\)\s*\)\s*(?:VSLOT|\()', st)
                if mc and ('VSLOT' in st or '+ 276' in st or '+ 0x114' in st):
                    n = len([x for x in mc.group(1).split(',') if x.strip()]) - 1   # minus this
                    kind = 'cast'
            if n is not None and n > 4:
                line = txt.count('\n', 0, m.start()) + 1
                res.append((folder, fn, line, n, kind, ' '.join(st.split())[:150]))
by_fn = {}
for r in res:
    by_fn.setdefault((r[0], r[1]), []).append(r)
for (f, fn), rs in by_fn.items():
    print(f, fn, [(r[2], r[3]) for r in rs])
print(len(res), 'sites in', len(by_fn), 'files')

# enclosing hooked function of each site: the nearest PCREG(addr, ...) below the site, hooked in this folder
print('--- sites whose enclosing PCREG is hooked from this folder')
hits = set()
for r in res:
    folder, fn, line = r[0], r[1], r[2]
    lines = open(ROOT + folder + '/src/' + fn, encoding='utf-8', errors='replace').read().split('\n')
    for k in range(line - 1, len(lines)):
        m = re.match(r'\s*PCREG\(([0-9a-fA-F]+)\s*,', lines[k])
        if m:
            a = '0x' + m.group(1).lower()
            if hooked.get(a) == folder:
                hits.add((a, folder, fn))
            break
for a, folder, fn in sorted(hits):
    print(a, folder, fn)
print(len(hits), 'hooked functions')
