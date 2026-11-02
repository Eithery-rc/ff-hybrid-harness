#!/bin/sh
# run_test.sh - end-to-end test of dinput8.dll without the game: fixed-base host, fake two-function ports image.
# Usage: sh hybrid/test/run_test.sh [LOADER_DIR]   (default hybrid/build/loader; must hold dinput8.dll)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REA=$(cd "$HERE/../.." && pwd)
LOADER=${1:-$REA/hybrid/build/loader}
PY=${PY:-$REA/.venv/Scripts/python.exe}
[ -x "$PY" ] || PY=python   # no venv: python from PATH
LLVM=${LLVM:-"/c/Program Files/LLVM/bin"}
T="$HERE/out"
rm -rf "$T"
mkdir -p "$T"
SDK=""
for d in "/c/Program Files (x86)/Windows Kits/10/Lib/"*; do
  [ -f "$d/um/x86/kernel32.lib" ] && SDK="$d"
done
"$LLVM/clang" --target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector -mno-stack-arg-probe \
  -c "$HERE/host.c" -o "$T/host.obj"
"$LLVM/lld-link" -nologo -machine:x86 -nodefaultlib -entry:start -subsystem:console -base:0x400000 -fixed \
  -safeseh:no -out:"$T/host.exe" "$T/host.obj" -libpath:"$SDK/um/x86" -libpath:"$SDK/ucrt/x86" kernel32.lib user32.lib ucrt.lib
cp "$LOADER/dinput8.dll" "$T/"
"$PY" -I "$HERE/make_plan.py" "$T"

check() {  # name, expected exit code, env assignments...
  name=$1; want=$2; shift 2
  set +e
  (cd "$T" && env "$@" ./host.exe)
  got=$?
  set -e
  if [ "$got" = "$want" ]; then echo "PASS $name (exit $got)"; else echo "FAIL $name: exit $got, want $want"; cat "$T/ff_hybrid.log"; exit 1; fi
}
expect() {  # file, fixed string
  grep -qF "$2" "$1" || { echo "FAIL: '$2' not in $1"; cat "$1"; exit 1; }
}
check "mode=all patches both functions" 0 FF_HYBRID_MODE=all HOST_CASE=basic
expect "$T/ff_hybrid.log" "hooks applied: 2"
check "mode=none leaves them alone" 0 FF_HYBRID_MODE=none HOST_CASE=orig
check "mode=list without include skips them" 0 FF_HYBRID_MODE=list HOST_CASE=orig
check "exclude wins over all" 0 FF_HYBRID_MODE=all FF_HYBRID_EXCLUDE=0x401000-0x4fffff HOST_CASE=orig
check "mode=list with include patches both" 0 FF_HYBRID_MODE=list FF_HYBRID_INCLUDE=0x401000-0x401fff HOST_CASE=basic
printf '# bisect half\n0x400000-0x401fff ; both targets\n' > "$T/half.txt"
check "include_file with a range" 0 FF_HYBRID_MODE=list FF_HYBRID_INCLUDE_FILE=half.txt HOST_CASE=basic
check "missing plan, on_error=continue runs the original" 0 FF_HYBRID_ON_ERROR=continue FF_HYBRID_PLAN=nope.bin HOST_CASE=orig
expect "$T/ff_hybrid.log" "ERROR: cannot read the hook plan"

# trace stubs keep ECX, EDX, the stack argument and the callee pop intact
check "trace=1 through stubs" 0 FF_HYBRID_MODE=all FF_HYBRID_TRACE=1 FF_HYBRID_HITS_EVERY=0 HOST_CASE=basic
expect "$T/ff_hybrid.log" "trace: stubs at"
expect "$T/ff_hits.tsv" "	1	"

# time_scale
check "time_scale=4: QueryPerformanceCounter 4x" 0 FF_HYBRID_MODE=none FF_HYBRID_TIME_SCALE=4 HOST_CASE=qpc4
expect "$T/ff_hybrid.log" "time_scale: wrapped QueryPerformanceCounter"
check "time_scale=4: clock() 4x" 0 FF_HYBRID_MODE=none FF_HYBRID_TIME_SCALE=4 HOST_CASE=clock4
expect "$T/ff_hybrid.log" "time_scale: wrapped clock"
check "time_scale unset: QueryPerformanceCounter 1x" 0 FF_HYBRID_MODE=none HOST_CASE=qpc1
check "time_scale=2.5 with hooks and trace still calls ports right" 0 FF_HYBRID_TIME_SCALE=2.5 FF_HYBRID_TRACE=1 HOST_CASE=basic

# crash dump: the loader's handler runs first, the host's own handler recovers afterwards
check "crash dump on access violation" 0 FF_HYBRID_MODE=all FF_HYBRID_TRACE=1 FF_HYBRID_HITS_EVERY=0 HOST_CASE=crash
expect "$T/ff_hybrid.log" "== crash dump: exception 0xc0000005"
expect "$T/ff_hybrid.log" "writing 0x00000010"
expect "$T/ff_hybrid.log" "last 3 hooked calls, newest first (3 in total)"
expect "$T/ff_hybrid.log" "distinct hooked addresses in the last calls: 2"
expect "$T/ff_hits.tsv" "$(cat "$T/target.txt")	2"
sed -n '/== crash dump/,/== end of crash dump/p' "$T/ff_hybrid.log"
cat "$T/ff_hits.tsv"

# input_script: keyboard (buffered) and mouse (immediate) through the wrapped DirectInput, wait_scene, keep_active
WNDPROC=$(cat "$T/wndproc.txt")
cat > "$T/script.txt" <<'SCRIPT'
# test script
at 0.1 key ESCAPE
at 0.25 down RETURN
at 0.35 up RETURN
at 0.35 mouse 10 -5
at 0.4 click left
at 0.4 log before the scene
wait_scene test.zip
at 0.1 key A
at 0.1 bogus command
SCRIPT
check "input_script drives keyboard, mouse, wait_scene; keep_active hides focus loss" 0 FF_HYBRID_MODE=none   FF_HYBRID_INPUT_SCRIPT=script.txt FF_HYBRID_INPUT_REAL=0 FF_HYBRID_KEEP_ACTIVE_WNDPROC=$WNDPROC HOST_CASE=input
expect "$T/ff_hybrid.log" "input: keyboard SetCooperativeLevel 0x00000006 -> 0x0000000a, result 0x00000000"
expect "$T/ff_hybrid.log" "input: mouse SetCooperativeLevel 0x00000005 -> 0x0000000a, result 0x00000000"
expect "$T/ff_hybrid.log" "keep_active: game window procedure wrapped"
expect "$T/ff_hybrid.log" "scene: "
expect "$T/ff_hybrid.log" "wait_scene satisfied: test.zip"
expect "$T/ff_hybrid.log" "line 10 ignored: unknown command"
expect "$T/ff_hybrid.log" "script finished"
grep -E "^(input|scene|keep_active)" "$T/ff_hybrid.log"
check "keep_active=0: the window procedure sees focus loss" 0 FF_HYBRID_MODE=none FF_HYBRID_KEEP_ACTIVE=0 HOST_CASE=focus0
echo "all loader tests passed"
