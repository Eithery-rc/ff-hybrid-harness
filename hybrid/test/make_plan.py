"""make_plan.py - fake ports image and plan for test/host.exe (same format plan.py writes).

Two ports in the image at 0x31000000:
  +0x00  target():  mov eax, 42; ret
  +0x10  t2(a, b, c) fastcall: mov eax, [esp+4]; shl eax, 2; lea eax, [eax+edx*2]; add eax, ecx; ret 4
Usage: python -I make_plan.py OUT_DIR   (OUT_DIR holds host.exe)
"""
import os
import struct
import sys

import pefile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from plan import BASE, MAGIC, VERSION, OK, fnv1a_fast  # noqa: E402

out = sys.argv[1]
pe = pefile.PE(os.path.join(out, 'host.exe'))
text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
data = text.get_data()[:text.Misc_VirtualSize]
exp = {e.name: pe.OPTIONAL_HEADER.ImageBase + e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}
p1 = bytes([0xB8, 42, 0, 0, 0, 0xC3]).ljust(16, b'\xcc')
p2 = bytes([0x8B, 0x44, 0x24, 0x04, 0xC1, 0xE0, 0x02, 0x8D, 0x04, 0x50, 0x01, 0xC8, 0xC2, 0x04, 0x00]).ljust(16, b'\xcc')
img = p1 + p2
plan = sorted([(exp[b'target'], BASE, OK), (exp[b'@t2@12'] if b'@t2@12' in exp else exp[b't2'], BASE + 0x10, OK)])
hdr = struct.pack('<10I', MAGIC, VERSION, BASE, len(img), fnv1a_fast(img), text.VirtualAddress, len(data),
                  fnv1a_fast(data), len(plan), 0)
open(os.path.join(out, 'ff_hooks.bin'), 'wb').write(hdr + b''.join(struct.pack('<III', *e) for e in plan))
open(os.path.join(out, 'ff_ports.bin'), 'wb').write(img)
print('test plan: ' + ', '.join('%#x -> %#x' % (a, e) for a, e, _ in plan))
wp = [v for k, v in exp.items() if k.startswith((b'host_wndproc', b'_host_wndproc'))]
open(os.path.join(out, 'target.txt'), 'w').write('%#010x' % exp[b'target'])
open(os.path.join(out, 'wndproc.txt'), 'w').write('%#x' % wp[0] if wp else '0')
