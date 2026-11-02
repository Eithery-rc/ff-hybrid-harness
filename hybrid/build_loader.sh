#!/bin/sh
# build_loader.sh - build only the loader: dinput8.dll and ff_names.bin into OUT_DIR. Touches nothing in the game.
# Usage: sh hybrid/build_loader.sh [OUT_DIR]   (default hybrid/build/loader)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REA=$(cd "$HERE/.." && pwd)
OUT=${1:-$HERE/build/loader}
PY=${PY:-$REA/.venv/Scripts/python.exe}
[ -x "$PY" ] || PY=python   # no venv: python from PATH
LLVM=${LLVM:-"/c/Program Files/LLVM/bin"}
mkdir -p "$OUT"

# Windows SDK x86 import libs (newest kit that has them)
SDK=""
for d in "/c/Program Files (x86)/Windows Kits/10/Lib/"*; do
  [ -f "$d/um/x86/kernel32.lib" ] && SDK="$d/um/x86"
done
[ -n "$SDK" ] || { echo "no Windows SDK x86 libs found"; exit 1; }

# no CRT, no stack probes, no /GS; dash-style options because Git Bash rewrites /options as paths
"$LLVM/clang" --target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector \
  -mno-stack-arg-probe -Wall -c "$HERE/loader/dinput8.c" -o "$OUT/dinput8.obj"
"$LLVM/lld-link" -nologo -dll -machine:x86 -nodefaultlib -entry:DllMain -subsystem:windows -safeseh:no \
  -def:"$HERE/loader/dinput8.def" -out:"$OUT/dinput8.dll" "$OUT/dinput8.obj" \
  -libpath:"$SDK" kernel32.lib user32.lib
echo "built $OUT/dinput8.dll"
if [ -f "$HERE/build/map-data-public.json" ]; then
  "$PY" -I "$HERE/names.py" --out "$OUT/ff_names.bin"
fi
