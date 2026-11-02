#!/bin/sh
# build.sh - the shadow loader: hybrid/loader/dinput8.c and hybrid/shadow/shadow.c in one dinput8.dll, entry ShadowMain
# (the loader's DllMain runs first). Touches nothing in any game folder.
# Usage: sh hybrid/shadow/build.sh [OUT_DIR]   (default hybrid/build/shadow)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
HYB=$(cd "$HERE/.." && pwd)
OUT=${1:-$HYB/build/shadow}
LLVM=${LLVM:-"/c/Program Files/LLVM/bin"}
mkdir -p "$OUT"

SDK=""
for d in "/c/Program Files (x86)/Windows Kits/10/Lib/"*; do
  [ -f "$d/um/x86/kernel32.lib" ] && SDK="$d/um/x86"
done
[ -n "$SDK" ] || { echo "no Windows SDK x86 libs found"; exit 1; }

CFLAGS="--target=i686-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector -mno-stack-arg-probe -Wall"
"$LLVM/clang" $CFLAGS -c "$HYB/loader/dinput8.c" -o "$OUT/dinput8.obj"
"$LLVM/clang" $CFLAGS -c "$HERE/shadow.c" -o "$OUT/shadow.obj"
"$LLVM/lld-link" -nologo -dll -machine:x86 -nodefaultlib -entry:ShadowMain -subsystem:windows -safeseh:no \
  -def:"$HYB/loader/dinput8.def" -out:"$OUT/dinput8.dll" "$OUT/dinput8.obj" "$OUT/shadow.obj" \
  -libpath:"$SDK" kernel32.lib user32.lib
echo "built $OUT/dinput8.dll"
