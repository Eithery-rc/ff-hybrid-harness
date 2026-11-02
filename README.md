# ff-hybrid-harness

This harness runs [ReFreedomFighters](https://github.com/kaustubhxd/ReFreedomFighters) ports inside the real
Freedom Fighters exe (Steam build), so each port is checked against the original game rather than only against its
spec. A proxy `dinput8.dll` maps the linked ports image at 0x31000000 and patches a `JMP rel32` at the start of every
selected exe function. Scripted DirectInput then drives the game along a route, and a bisection script finds the
hook that makes a run crash. On top of that there is a differential tester ("shadow"). It snapshots a function's
inputs in a vanilla run and replays the original and the port on them in Unicorn.

I built it for my own Android port of the game and used it to find the defects reported in
[issue #1](https://github.com/kaustubhxd/ReFreedomFighters/issues/1). It is Windows-only for the game runs.
The shadow replay also runs offline on Linux.

## Layout

The scripts expect this layout under the repo root (everything except `hybrid/` is ignored by git):

```
hybrid/              this code
game/                work copy of the game (hybrid/setup_game.py makes it; the Steam install is never modified)
ReFreedomFighters/   a clone of the decomp, to build the ports image from
.venv/               optional Python venv (the shell scripts fall back to python on PATH)
```

## Requirements

- Windows 10/11, the Steam build of Freedom Fighters, Steam running (the exe calls SteamAPI_Init).
- LLVM with clang and lld-link that target i686 (I use 23.1, any recent one should do), and the Windows SDK x86
  import libs (kernel32.lib, user32.lib). The build scripts are POSIX sh: run them from Git Bash.
- Python 3.12: `pip install -r requirements.txt` (pefile, capstone, unicorn, psutil; pycaw only for mute_game.py).

## Setup

```sh
git clone https://github.com/kaustubhxd/ReFreedomFighters
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python -I hybrid/setup_game.py --steam-dir "C:/Program Files (x86)/Steam/steamapps/common/Freedom_Fighters"
.venv/Scripts/python -I hybrid/build_all.py      # every port folder into one image: hybrid/build/ff_ports.bin, .tsv, .syms
sh hybrid/build.sh                                # dinput8.dll, the hook plan ff_hooks.bin, both copied into game/
```

`setup_game.py` copies the install into `game/` and clears DYNAMIC_BASE in the copy's PE header, so the exe always
loads at 0x400000 (`patch_exe.py`). It also copies `hybrid/lists/all_addrs.txt` and `exclude_map.txt` next to the
exe. `build_all.py` compiles every port folder with the same clang flags as `tooling/build.sh` and links the
objects into one image at 0x31000000 with `hybrid/mini_ld.py`. That is a copy of `tooling/mini_ld.py` extended to
link many folders into one image. `plan.py` (run by `build.sh`) decides for every port whether a 5-byte jump at the
function start is safe: the next known function start, branch target or relocated pointer must be at least 5 bytes
away. It writes `ff_hooks.bin`.

Optional: put `map-data-public.json` from your progress page
(https://kaustubhxd.github.io/ReFreedomFighters/menu/map-data-public.json) into `hybrid/build/`. With it, logs,
crash dumps and the hunt print function names.

## The loader

`hybrid/loader/dinput8.c` has no CRT and runs entirely in DllMain. Settings come from `game/hooks.ini`, and every
key can be overridden by an environment variable `FF_HYBRID_<KEY>`. `hybrid/README.md` has the full table. The ones
I use most:

- `mode` is `all`, `none` (the original exe) or `list`. `include_file` and `exclude_file` hold address lists.
- `trace=1` sends hooks through recording stubs. On a crash the last 256 hooked calls and a symbolized stack go to
  `ff_hybrid.log`.
- `input_script` replays keyboard and mouse at the DirectInput level. Its format: `wait_scene <zip>`, then
  `at <seconds> down|up 0x<DIK>`, `mouse dx dy`, `mdown|mup left`, `cursor x y`. `input_record` writes your own play
  in the same format. Recorded times count from each scene load, so load-time differences don't matter.
- `fixed_step=50` runs a virtual clock: every Present advances the game clock by 50 ms, which makes runs repeatable.
  `time_scale=4` speeds up the real clock instead.
- `window_park=1` keeps the window off-screen and never lets it take focus or the cursor. The crash reporter's
  message box goes to the log, and the exit code becomes 0xC0DEB0C5.
- `present_every_ms=250` skips most Presents of a parked window, about 2x faster.
- `frame_dump=1` saves the back buffer as BMP every N game seconds, so you can see what a parked run did.
- `profile_dir` gives the instance its own copy of the user folder (freedom.ini, Profiles), so test runs never
  touch your real settings or saves.

## Tools

- **`hookbisect.py`, `hunt.py`**: bisection over the enabled hooks until one culprit is left. `hunt.py` repeats it,
  appends each culprit to the exclude file in `game/` and stops on a PASS. `--workers N` runs several game copies
  at once (hardlinked copies of `game/`).
- **`shadow/`**: differential replay. `shadow/README.md` has the details. `run_capture.py` takes
  `PssCaptureSnapshot` clones at function entries during a vanilla run. `shadow.py replay` runs the original and
  each image's port in Unicorn on the same state and compares memory writes, exe calls, stack balance, callee-saved
  registers, x87 state and the `this` passed to callees.
- **`hangdump.py`**: samples the thread contexts and stacks of a hung game, symbolized.
- **`mute_game.py`**: keeps the test instances silent.
- **Static scanners**: `scan_port_sysobj_arity.py` and `scan_sysobj_confirm.py` cover the sysobj slot pop counts
  from the issue (slot 0x114 pops 4, 0x4c and 0x58 pop 1). `scan_decl_conv.py` finds extern declarations whose
  callee reads ECX/EDX. `audit_ports.py` holds older heuristic detectors. It is tied to my exclude lists, so treat it
  as reference.
- **`pilot_fix.py`, `base_objs.py`**: run your pilot specs against the old and the new objects of a folder.

## Example: a scripted route and a crash bisection

With Steam running, `game/` set up and the image installed:

```sh
.venv/Scripts/python -I hybrid/hunt.py --exclude exclude_map.txt --input hybrid/scripts/to_level1.txt \
    --timeout 120 --fixed-step 50 --present-every-ms 250 --workers 1
```

`to_level1.txt` skips the intro, starts a new game and walks around in C01A. Every run starts the parked game
with the enabled hooks. If it crashes, the hunt halves the hook set until one hook is left (about 14 runs, 1 to 2
minutes each). It writes `CULPRIT n: 0x... name (folder)` to `game/bisect.log`, appends the address to
`game/exclude_map.txt` and starts again. It ends with `PASS: N hooks run the scenario without a crash`.

Check the `scene:` lines in `game/ff_hybrid.log`, or the last screenshot in `game/bisect_shots/`, before you
trust a PASS. A replay that drifts can stall before the interesting part and then "pass" without ever loading the
mission.

`hybrid/scripts/c02rb_police.txt` is a recorded route from a save after mission 1: the C02RB hideout, the city map,
the police station, then C02B. It needs that save in `game/profile_rec` (a copy of
`%APPDATA%\IO Interactive\Freedom Fighters`) and the `--profile-src game/profile_rec` flag. A save of your own
probably needs its own recording: copy `hybrid/examples/record_path.cmd` into `game/` and play the route once.

## Lists

- `hybrid/lists/all_addrs.txt`: every function the plan can hook.
- `hybrid/lists/exclude_map.txt`: what I exclude today, with the reason for each block in comments: crashes found
  in-game, audit and shadow findings. With it and the ports from my `hybrid-fixes` branch
  (Eithery-rc/ReFreedomFighters), both routes above pass with about 10,500 hooks. With the ports from main you will
  need more exclusions, which is what the hunt is for.

## License

MIT, see LICENSE.
