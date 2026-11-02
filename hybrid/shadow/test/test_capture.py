"""test_capture.py - end-to-end test of the capture side without the game.

Builds test/host_shadow.exe (fixed base 0x400000) next to the shadow loader, two fake ports images for its three
functions (good: byte copies of the originals; bad: sh_sum returns 0, sh_alloc writes another pattern, sh_fmt passes
another format string), starts collector.py, runs the host, and checks that every sample is exact against 'good' and
not exact against 'bad'. Then replays the saved samples offline (shadow.py) and checks the same verdicts.

    python -I hybrid/shadow/test/test_capture.py      (needs sh hybrid/shadow/build.sh first)
"""
import os
import shutil
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHADOW = os.path.dirname(HERE)
sys.path.insert(0, SHADOW)
import replay  # noqa: E402

REA = replay.REA
OUT = os.path.join(REA, 'hybrid', 'build', 'shadow', 'test_capture')
LLVM = os.environ.get('LLVM', r'C:\Program Files\LLVM\bin')
PY = sys.executable
PIPE, SEM = r'\\.\pipe\ff_shadow_test', r'Local\ff_shadow_test'


def sdk():
    root = r'C:\Program Files (x86)\Windows Kits\10\Lib'
    for d in sorted(os.listdir(root), reverse=True):
        if os.path.exists(os.path.join(root, d, 'um', 'x86', 'kernel32.lib')):
            return os.path.join(root, d)
    raise SystemExit('no Windows SDK')


def build_host():
    s = sdk()
    obj, exe = os.path.join(OUT, 'host.obj'), os.path.join(OUT, 'host_shadow.exe')
    subprocess.check_call([os.path.join(LLVM, 'clang'), '--target=i686-pc-windows-msvc', '-O2', '-ffreestanding',
                           '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe', '-c',
                           os.path.join(HERE, 'host_shadow.c'), '-o', obj])
    subprocess.check_call([os.path.join(LLVM, 'lld-link'), '-nologo', '-machine:x86', '-nodefaultlib', '-entry:start',
                           '-subsystem:console', '-base:0x400000', '-fixed', '-safeseh:no', '-out:' + exe, obj,
                           '-libpath:' + os.path.join(s, 'um', 'x86'), '-libpath:' + os.path.join(s, 'ucrt', 'x86'),
                           'kernel32.lib', 'user32.lib', 'ucrt.lib'])
    shutil.copy(os.path.join(REA, 'hybrid', 'build', 'shadow', 'dinput8.dll'), OUT)
    return exe


def make_images(exe_path):
    import pefile
    import capstone
    pe = pefile.PE(exe_path)
    img = pe.get_memory_mapped_image()
    exp = {e.name.decode(): 0x400000 + e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}
    names = {}
    for n, a in exp.items():
        for want in ('sh_sum', 'sh_alloc', 'sh_fmt'):
            if want in n:
                names[want] = a
    starts = sorted(names.values())
    size = {a: (starts[i + 1] - a if i + 1 < len(starts) else 0x100) for i, a in enumerate(starts)}
    code = {k: bytes(img[a - 0x400000:a - 0x400000 + size[a]]).ljust(0x200, bytes([0xcc])) for k, a in names.items()}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for k, c in code.items():      # the copies must not hold rel32 calls/jumps out of the function
        for ins in md.disasm(c, names[k]):
            if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x') and not (
                    names[k] <= int(ins.op_str, 16) < names[k] + size[names[k]]):
                raise SystemExit('%s has a relative %s at 0x%x; cannot copy it' % (k, ins.mnemonic, ins.address))
            if ins.mnemonic == 'ret':
                break
    bad = dict(code)
    bad['sh_sum'] = b'\x31\xc0\xc3'.ljust(0x200, b'\xcc')                 # xor eax,eax; ret
    i = code['sh_alloc'].find(struct.pack('<I', 0x5a5a0000))
    assert i > 0, 'pattern immediate not found in sh_alloc'
    bad['sh_alloc'] = code['sh_alloc'][:i] + struct.pack('<I', 0x5a5b0000) + code['sh_alloc'][i + 4:]
    fmt_addr = None
    for ins in md.disasm(code['sh_fmt'], names['sh_fmt']):
        if ins.mnemonic == 'push' and ins.op_str.startswith('0x'):
            v = int(ins.op_str, 16)
            if bytes(img[v - 0x400000:v - 0x400000 + 4]) == b'v=%d':
                fmt_addr = v
    assert fmt_addr, 'format string push not found in sh_fmt'
    j = code['sh_fmt'].find(struct.pack('<I', fmt_addr))
    bad['sh_fmt'] = code['sh_fmt'][:j] + struct.pack('<I', fmt_addr + 2) + code['sh_fmt'][j + 4:]
    dirs = {}
    for label, c in (('good', code), ('bad', bad)):
        d = os.path.join(OUT, label)
        os.makedirs(d, exist_ok=True)
        blob, rows = b'', []
        for k in ('sh_sum', 'sh_alloc', 'sh_fmt'):
            rows.append('0x%x\t0x%x\ttest\t%s\n' % (names[k], 0x31000000 + len(blob), k))
            blob += c[k]
        open(os.path.join(d, 'ff_ports.bin'), 'wb').write(blob)
        open(os.path.join(d, 'ff_ports.tsv'), 'w').write(''.join(rows))
        dirs[label] = d
    return names, dirs


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    exe = build_host()
    names, dirs = make_images(exe)
    open(os.path.join(OUT, 'shadow_list.txt'), 'w').write(''.join('0x%x  # %s\n' % (a, k) for k, a in names.items()))
    open(os.path.join(OUT, 'hooks.ini'), 'w').write(
        '[hybrid]\nmode=none\nshadow_list=shadow_list.txt\nshadow_k=3\nshadow_every=100\nshadow_pipe=%s\nshadow_sem=%s\n'
        % (PIPE, SEM))
    samples = os.path.join(OUT, 'samples')
    log_path = os.path.join(OUT, 'collector.log')
    with open(log_path, 'w') as log:
        col = subprocess.Popen([PY, '-I', os.path.join(SHADOW, 'collector.py'), '--out', samples, '--exe', exe,
                                '--image', 'good=' + dirs['good'], '--image', 'bad=' + dirs['bad'], '--pipe', PIPE,
                                '--sem', SEM, '--workers', '2', '--slots', '4', '--idle', '60'],
                               stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            if 'ready' in open(log_path).read() or col.poll() is not None:
                break
            time.sleep(0.2)
        if 'ready' not in open(log_path).read():
            print(open(log_path).read())
            return 1
        t0 = time.time()
        host = subprocess.Popen([exe], cwd=OUT)
        try:
            rc = host.wait(timeout=120)
        except subprocess.TimeoutExpired:
            host.kill()         # only the PID started here
            rc = host.wait()
        print('host exit %d after %.1fs' % (rc, time.time() - t0))
        col.wait(timeout=300)
    finally:
        if col.poll() is None:
            col.kill()
    print(open(log_path).read())
    print(open(os.path.join(OUT, 'ff_shadow.log')).read())
    rows = [l.rstrip('\n').split('\t') for l in open(os.path.join(samples, 'results.tsv'))][1:]
    ok = True
    byname = {v: k for k, v in names.items()}
    seen = set()
    for r in rows:
        fn, image, verdict = int(r[1], 16), r[4], r[5]
        want_ok = image == 'good'
        good = (verdict == 'exact') == want_ok and verdict not in ('unsupported', 'error')
        seen.add((byname.get(fn), image))
        if not good:
            ok = False
            print('FAIL %s %s: %s %s %s' % (byname.get(fn), image, verdict, r[6], r[10]))
    if len(seen) != 6:
        ok = False
        print('FAIL: expected samples of 3 functions x 2 images, got', sorted(seen))
    import shadow
    print('--- offline replay of the saved samples')
    tsv = os.path.join(OUT, 'offline.tsv')
    shadow.main(['replay', samples, '--image', 'good=' + dirs['good'], '--image', 'bad=' + dirs['bad'], '--tsv', tsv,
                 '--exe', exe])
    off = [l.rstrip('\n').split('\t') for l in open(tsv)][1:]
    live = {(r[0], r[1], r[4]) for r in rows}
    for r in off:
        if (r[3] == 'good') != (r[4] == 'exact'):
            ok = False
            print('FAIL offline %s %s %s: %s' % (r[0], r[3], r[4], r[5]))
    print('PASS' if ok else 'FAILED', '(%d live rows, %d offline rows)' % (len(rows), len(off)))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
