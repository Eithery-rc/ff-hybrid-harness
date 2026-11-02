"""patch_exe.py - pin the work copy of Freedom.Exe at its preferred base 0x400000.

The ports address exe globals and functions by absolute address, so the exe must never be rebased.
This clears IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40) and rewrites the PE checksum. Idempotent.
Only ever run it on the work copy (game/ at the repo root), never on the Steam install.

Usage: python -I patch_exe.py [path/to/Freedom.Exe]
"""
import os
import sys

import pefile

DYNAMIC_BASE = 0x40
DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'game', 'Freedom.Exe')


def main():
    path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
    if 'steamapps' in path.lower():
        raise SystemExit('refusing to patch the Steam install: %s' % path)
    pe = pefile.PE(path)
    oh = pe.OPTIONAL_HEADER
    if oh.ImageBase != 0x400000:
        raise SystemExit('unexpected ImageBase %#x' % oh.ImageBase)
    before = oh.DllCharacteristics
    oh.DllCharacteristics = before & ~DYNAMIC_BASE
    oh.CheckSum = 0
    data = bytearray(pe.write())
    pe.close()
    pe = pefile.PE(data=bytes(data))
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    data = pe.write()
    pe.close()
    open(path, 'wb').write(data)
    print('%s: DllCharacteristics %#06x -> %#06x, checksum fixed' % (path, before, before & ~DYNAMIC_BASE))


if __name__ == '__main__':
    main()
