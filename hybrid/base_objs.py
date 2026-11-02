#!/usr/bin/env python3
"""base_objs.py - compile port folders of an older commit with the current build flags (for before / after pilot comparisons).

Run:  python -I hybrid/base_objs.py REV OUT_DIR FOLDER [FOLDER ...]

Extracts ports/<folder>/src of commit REV from the ReFreedomFighters clone (git archive, the working tree is not touched),
compiles it with the flags of hybrid/build_all.py into OUT_DIR/obj/<folder>/*.o, and copies ff_ports.tsv from
hybrid/build/ports_next so that pilot_fix.py --image OUT_DIR can run the specs of those folders against the old code.
"""
import io
import os
import shutil
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_all as B  # noqa: E402


def main():
    rev, out = sys.argv[1], os.path.abspath(sys.argv[2])
    folders = sys.argv[3:]
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, 'src_' + rev)
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)
    tar = subprocess.run(['git', '-C', B.REPO, 'archive', rev] + ['ports/%s/src' % f for f in folders], capture_output=True)
    if tar.returncode:
        raise SystemExit(tar.stderr.decode())
    tarfile.open(fileobj=io.BytesIO(tar.stdout)).extractall(work)
    B.BUILD = out
    if os.environ.get('BASE_NO_CLASH'):         # compare with / without the stack probes
        B.CXXFLAGS[:] = [f for f in B.CXXFLAGS if f != '-fstack-clash-protection']
    os.environ['PATH'] = B.LLVM_BIN + os.pathsep + os.environ.get('PATH', '')
    clang = B.find_clang()
    bad = 0
    for fo in folders:
        src = os.path.join(work, 'ports', fo, 'src')
        for fn in sorted(os.listdir(src)):
            if fn.endswith('.cpp'):
                j = B.Job(fo, os.path.join(src, fn), [src, B.TOOLING])
                B.compile_job(clang, j, True)
                bad += j.status == 'fail'
    shutil.copy(os.path.join(HERE, 'build', 'ports_next', 'ff_ports.tsv'), os.path.join(out, 'ff_ports.tsv'))
    print('compiled %s of %s, %d failed' % (', '.join(folders), rev, bad))


if __name__ == '__main__':
    main()
