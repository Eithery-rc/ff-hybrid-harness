"""names.py - ff_names.bin: exe function names for the loader's crash dumps and ff_hits.tsv.

Format: 'FFNM', count, pool offset; count x (addr, size, name offset) sorted by addr; then NUL-terminated names.
Names come from build/map-data-public.json (functions: [addr, size, status, name, ...]); a function without a
name there takes its RESULTS.tsv name.

Usage: python -I names.py [--out build/loader_next/ff_names.bin]
"""
import argparse
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
REA = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--map', default=os.path.join(HERE, 'build', 'map-data-public.json'))
    ap.add_argument('--results', default=os.path.join(REA, 'ReFreedomFighters', 'RESULTS.tsv'))
    ap.add_argument('--out', default=os.path.join(HERE, 'build', 'loader_next', 'ff_names.bin'))
    a = ap.parse_args()
    res = {}
    for line in open(a.results, encoding='utf-8', errors='replace'):
        p = line.rstrip('\n').split('\t')
        if p[0].startswith('0x') and len(p) > 1:
            res[int(p[0], 16)] = p[1]
    rows = []
    for f in json.load(open(a.map))['functions']:
        addr, size, name = f[0], f[1], f[3] or res.get(f[0], '')
        rows.append((addr, size, name[:100]))
    rows.sort()
    pool, offs = bytearray(), []
    for _, _, name in rows:
        offs.append(len(pool))
        pool += name.encode('ascii', 'replace') + b'\0'
    hdr = 12 + 12 * len(rows)
    out = struct.pack('<III', 0x4d4e4646, len(rows), hdr)
    out += b''.join(struct.pack('<III', addr, size, o) for (addr, size, _), o in zip(rows, offs)) + pool
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    open(a.out, 'wb').write(out)
    print('%s: %d functions, %d named' % (a.out, len(rows), sum(1 for r in rows if r[2])))


if __name__ == '__main__':
    main()
