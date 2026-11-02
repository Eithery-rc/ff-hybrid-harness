"""disasm.py ADDR [BYTES] [--port IMAGE_DIR] : disassemble the original exe (game/Freedom.Exe) at ADDR up to the first ret,
or with --port the port of exe function ADDR in IMAGE_DIR/install/ff_ports.bin (entry from IMAGE_DIR/ff_ports.tsv)."""
import argparse
import os

import capstone
import pefile

REA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ap = argparse.ArgumentParser()
ap.add_argument('addr')
ap.add_argument('n', nargs='?', default='0x400')
ap.add_argument('--port')
a = ap.parse_args()
addr, n = int(a.addr, 16), int(a.n, 0)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
if a.port:
    entry = next(int(w[1], 16) for w in (l.split('\t') for l in open(os.path.join(a.port, 'ff_ports.tsv'), encoding='utf-8'))
                 if w[0].startswith('0x') and int(w[0], 16) == addr)
    data = open(os.path.join(a.port, 'install', 'ff_ports.bin'), 'rb').read()[entry - 0x31000000:entry - 0x31000000 + n]
    start = entry
else:
    pe = pefile.PE(os.path.join(REA, 'game', 'Freedom.Exe'), fast_load=True)
    data = pe.get_memory_mapped_image()[addr - pe.OPTIONAL_HEADER.ImageBase:addr - pe.OPTIONAL_HEADER.ImageBase + n]
    start = addr
for i in md.disasm(data, start):
    print('%08x %s %s' % (i.address, i.mnemonic, i.op_str))
    if i.mnemonic == 'ret':
        break
