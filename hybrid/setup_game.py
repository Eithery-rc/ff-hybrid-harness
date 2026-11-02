"""setup_game.py - make the game work copy the harness runs: <repo>/game.

Copies the installed game (the Steam folder is only read), pins the copy's Freedom.Exe at 0x400000 (patch_exe.py) and
puts the hook lists hunt.py expects next to it (all_addrs.txt, exclude_map.txt from hybrid/lists).

Usage: python -I hybrid/setup_game.py --steam-dir "C:/Program Files (x86)/Steam/steamapps/common/Freedom_Fighters"
                                       [--game DIR] [--force]
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--steam-dir', required=True, help='the installed game folder (holds Freedom.Exe); never modified')
    ap.add_argument('--game', default=os.path.join(ROOT, 'game'), help='work copy to create (default <repo>/game)')
    ap.add_argument('--force', action='store_true', help='copy over an existing work copy')
    a = ap.parse_args()
    src, dst = os.path.abspath(a.steam_dir), os.path.abspath(a.game)
    if not os.path.isfile(os.path.join(src, 'Freedom.Exe')):
        sys.exit('no Freedom.Exe in %s' % src)
    if os.path.normcase(src) == os.path.normcase(dst):
        sys.exit('the work copy must be a different folder than the install')
    if os.path.exists(dst) and not a.force:
        sys.exit('%s exists (use --force to copy over it)' % dst)
    shutil.copytree(src, dst, dirs_exist_ok=a.force)
    subprocess.check_call([sys.executable, '-I', os.path.join(HERE, 'patch_exe.py'), os.path.join(dst, 'Freedom.Exe')])
    for f in ('all_addrs.txt', 'exclude_map.txt'):
        shutil.copy(os.path.join(HERE, 'lists', f), os.path.join(dst, f))
    print('work copy ready: %s' % dst)


if __name__ == '__main__':
    main()
