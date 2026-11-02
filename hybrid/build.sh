#!/bin/sh
# build.sh - build the hybrid loader and install it with a ports image into the game work copy.
# Usage: sh hybrid/build.sh [IMAGE_DIR]
#   IMAGE_DIR holds ff_ports.bin + ff_ports.tsv/.syms (unified build) or pilot.bin + pilot.syms (one folder).
#   Default: hybrid/build (the unified build).
# Steps: compile dinput8.dll, pin the work copy's exe at 0x400000, plan the hooks, copy everything into ../game.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REA=$(cd "$HERE/.." && pwd)
GAME="$REA/game"
IMG=${1:-$HERE/build}
PY=${PY:-$REA/.venv/Scripts/python.exe}
[ -x "$PY" ] || PY=python   # no venv: python from PATH
LLVM=${LLVM:-"/c/Program Files/LLVM/bin"}
OUT="$HERE/build/loader"
mkdir -p "$OUT"

# 1. loader (dinput8.dll, ff_names.bin)
LLVM="$LLVM" PY="$PY" sh "$HERE/build_loader.sh" "$OUT"

# 2. game work copy, exe pinned at its preferred base
[ -f "$GAME/Freedom.Exe" ] || { echo "no work copy at $GAME (copy the Steam folder there first)"; exit 1; }
"$PY" -I "$HERE/patch_exe.py" "$GAME/Freedom.Exe"

# 3. hook plan + image into the game folder
"$PY" -I "$HERE/plan.py" --build "$IMG" --out "$GAME"

# 4. loader and a default config
cp "$OUT/dinput8.dll" "$GAME/dinput8.dll"
[ -f "$OUT/ff_names.bin" ] && cp "$OUT/ff_names.bin" "$GAME/ff_names.bin"
[ -f "$GAME/hooks.ini" ] || cp "$HERE/hooks.ini" "$GAME/hooks.ini"
echo "installed into $GAME (hooks.ini kept if it already existed)"
