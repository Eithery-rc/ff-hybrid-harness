# Hybrid loader (stage 1)

Runs the verified ReFreedomFighters ports inside the real game. A proxy `dinput8.dll` in the game work copy maps
the ports image at 0x31000000 and patches a 5-byte `JMP` at the start of each selected exe function.

## Build and install

```sh
sh hybrid/build.sh              # unified image from hybrid/build (ff_ports.bin + ff_ports.tsv)
sh hybrid/build.sh <dir>        # any image dir, e.g. a one-folder pilot.bin + pilot.syms
sh hybrid/test/run_test.sh      # loader self-test with a fake host, no game needed
```

`build.sh` compiles `dinput8.dll` (no CRT), pins `game/Freedom.Exe` at 0x400000 (`patch_exe.py` clears
DYNAMIC_BASE), writes the hook plan, and copies `dinput8.dll`, `ff_ports.bin`, `ff_hooks.bin` and a default
`hooks.ini` (only if none exists) into `game/` at the repo root. The Steam install is never touched.

`python -I hybrid/plan.py --build <dir> --dry-run` prints how many hooks are safe and how many port functions use
aligned SSE on an unaligned stack. Reports: `build/hooks_plan.tsv`, `build/align_hazards.tsv`.

## Run

Start Steam, then run `game/Freedom.Exe` directly (`steam_appid.txt` keeps it from relaunching through Steam).
The loader writes `game/ff_hybrid.log` on every start.

## Choose hooks (`game/hooks.ini`)

| Key | Values |
|---|---|
| `mode` | `all` (every safe hook), `none` (original exe), `list` (only `include` / `include_file`) |
| `include`, `exclude` | hex addresses and ranges: `0x5cbf50, 0x401000-0x4fffff` (ranges inclusive) |
| `include_file`, `exclude_file` | the same in a file next to the exe; `#` or `;` comments |
| `allow_unsafe` | `1` also patches functions the plan marks short or interior |
| `on_error` | `abort` (message box, exit) or `continue` (log, run the original exe) |
| `verbose` | `1` logs every patched address |
| `time_scale` | game clock speed (wraps QueryPerformanceCounter, CRT `clock`, GetSystemTimeAsFileTime); any mode |
| `trace` | `1`: hooks go through recording stubs; crashes dump the last 256 hooked calls to the log, `ff_hits.tsv` lists the hooks called |
| `max_dumps`, `hits_every`, `names` | dumps per run (4), seconds between `ff_hits.tsv` rewrites (5), name table (`ff_names.bin`) |
| `input_script` | scripted keyboard and mouse through DirectInput (format in `hooks.ini`, example `scripts/skip_intro.txt`) |
| `input_real`, `keep_active`, `log_scenes` | drop real input (`0`); hide focus loss from the game; log `scene:` lines for each new `Scenes\*.zip` |
| `input_record` | write the real keyboard, mouse and GUI cursor to a file in the `input_script` format (`wait_scene` per scene, then `at` lines: `down`/`up 0x<DIK>`, `mouse dx dy`, `mdown`/`mup left`, `cursor x y`), so a path played once by hand replays: `hybrid/examples/record_path.cmd` (copied into `game/`) records into `scripts/c02rb_police.txt` from a copy of `game/profile_rec`; replay with `hunt.py --input hybrid/scripts/c02rb_police.txt --profile-src game/profile_rec` (every run starts from a fresh copy of that save; script runs drop the real input) |
| `frame_dump` | `1`: before `Present`, write the D3D back buffer to `frames\<game seconds>.bmp` (24-bit), so runs with the window off-screen can be seen |
| `frame_dump_every`, `frame_dump_keep`, `frame_dump_dir` | seconds on the script clock between frames (5, at least 1), frames kept (40; a run starts by deleting the old ones), folder (`frames`) |
| `window_park` | `1`: the loader puts the game's top-level windows right of the virtual desktop (x = right edge + 100, y = 100) and never lets them take the focus or the mouse (no activation, `SetForegroundWindow`, `ClipCursor`, `SetCursorPos`). The crash reporter's `MessageBoxA` is not shown: caption and text go to the log as `msgbox:` and the game exits with 0xC0DEB0C5 (hookbisect: `crash`). `freedom.ini` must still say `Window 1` |
| `fixed_step` | ms, e.g. `33`: virtual game clock, each `Present` moves QPC, `clock()` and the file-time clock on by exactly that step; the script clock, `frame_dump_every` and `scene:` times follow it; `time_scale` is ignored. With any of the D3D hooks on, `scene:` lines add `real=` (wall seconds) and `frames=` |
| `present_every_ms` | real ms between frames that reach the window (`0` = all): an off-screen window makes `Present` block about 42 ms; `250` lifts the game from about 24 to about 55 fps without changing what it computes |
| `profile_dir`, `profile_template` | folder that replaces the game's user folder `%APPDATA%\IO Interactive\Freedom Fighters` (`freedom.ini`, `Keyboard.cfg`, `Profiles\*.dat`) for this instance; a missing `freedom.ini` is copied from the template (`hybrid/freedom_template.ini`, `Window 1`). hookbisect gives every game folder its own `<game>/profile` |

Every key has an environment override, `FF_HYBRID_<KEY>` (e.g. `FF_HYBRID_MODE=none`); `FF_HYBRID_INI` picks
another ini.

## Crash hunting

`python -I hybrid/hookbisect.py <list> --time-scale 4 --from-trace` halves the hook list until one culprit is left.
`--from-trace` first tries the hooks from the crash dump, then the hooks the crashing run called; `--trace` alone
narrows every crashing run to the hooks it called. `python -I hybrid/hunt.py --workers 2` runs the whole hunt with two
game instances at once in `game_w1` and `game_w2` (hardlinks of the read-only files in `game/`, copies of the config
files; `python -I hybrid/test/test_hunt_parallel.py` tests the search offline). `sh hybrid/build_loader.sh <dir>` builds only `dinput8.dll` and
`ff_names.bin` (nothing in the game folder); `sh hybrid/test/run_test.sh <dir>` tests that build.
