# Shadow differential testing

Runs an exe function and its port from the same real game state and compares what they do. The crash hunt
(`hybrid/hunt.py`) only sees ports that crash the game. The pilot specs feed random inputs to stubs that can share the
port's wrong assumptions. Here, both codes start from a state the real game produced, the code around them is the
original, and every effect is compared.

## How it works

1. **Capture** (`shadow.c`, linked with the unchanged `../loader/dinput8.c` into a separate `dinput8.dll`). The game
   runs vanilla (`mode=none`). Each function in `shadow_list` gets an `int3` at its first byte, caught by a
   first-in-chain vectored exception handler. On a hit the probe disarms itself. For the first `shadow_k` hits it takes
   a `PssCaptureSnapshot(PSS_CAPTURE_VA_CLONE)` (a copy-on-write clone of the process, about 20 ms), duplicates the
   clone's handle into the collector, frees the snapshot and sends the CONTEXT at the function entry plus the game's
   clock values over a pipe. Then the game continues. A background thread re-arms the probe `shadow_every` ms of game clock later.
   A semaphore caps the number of live clones (`--slots`).
2. **Record** (`collector.py`). Worker processes read the clone with `ReadProcessMemory`, run the original and each
   image's port (`replay.py`), save the sample (`<fn>_<seq>.ffs`: header plus every page any replay read), then close
   the clone and free the slot. One line per sample and image goes to `results.tsv`.
3. **Replay** (`replay.py`, `models.py`, `liveness.py`; offline with `shadow.py replay`). Each run gets a fresh
   Unicorn:
   - exe `.text` comes from `ffre-root/bin/Freedom.Exe.orig`; every other page is loaded from the sample on first
     touch, read-only or read-write as the game had it, never executable;
   - the ports image is mapped at 0x31000000. Its `ext_` calls reach the original exe code, so each port is tested
     alone;
   - FS points at the real TEB through a GDT entry, so SEH frames, TLS and the security cookie work;
   - the thread stack keeps the guard-page rule: touching the guard page commits it, and touching below it faults;
   - a fetch outside exe `.text` and the image is a DLL call. `models.py` answers it with the same value in both runs:
     CRT memory and string functions, malloc/HeapAlloc on a fake heap, printf/scanf, x87 and SSE2 math,
     `__RTDynamicCast`, clocks taken at capture time, files that never open. Other calls are logged with as many
     arguments as their `ret N` pops, and return 0.
4. **Compare**:
   - callee pop (ESP) and the callee-saved registers;
   - the scratch registers the caller reads after the call, found by reading the caller's code at the real return
     address, per byte (AL vs EAX);
   - x87 depth, ST0, FPCW, MXCSR and DF;
   - every byte of memory either run changed, except the dead frame below the entry ESP and the callee's own argument
     slots;
   - the log of DLL calls (pure functions such as memcpy are not logged);
   - the `this` (ECX) the function passes to every exe callee that reads ECX on some path from its entry
     (`callsites.py`), even when the callee ignored it in the sampled state. 0x64d490's port passes its own
     `this`, then 0, to 0x63da80, which reads ECX only once its argument holds a slot index: 17 samples came out
     exact on memory while the game crashed on the 682nd call. The values for one callee compare as a multiset,
     and only when both made the same number of calls to it; stack arguments and call order are not compared
     (cdecl cleanup batching and inlined helpers made that mostly noise).

Verdicts: `exact`, `weak` (only registers the caller may read through its own return differ), `mismatch` (first
differences listed), `crash` (the port faulted where the original returned), `unsupported` (the original did not
return in the emulator), `missing-page` (offline: the port wants memory no replay read while the clone lived).

## Use

```sh
sh hybrid/shadow/build.sh                                  # hybrid/build/shadow/dinput8.dll
python -I hybrid/shadow/test/test_capture.py                # end-to-end test on a fake host, no game
python -I hybrid/shadow/test/synth.py                       # synthetic samples (0x445c50, 0x4d5120), no game
python -I hybrid/shadow/run_capture.py --list LIST --k 1 --timeout 150      # one game run from game_shadow/
python -I hybrid/shadow/shadow.py replay DIR [--image LABEL=PATH ...] [--fn 0x445c50] [--tsv out.tsv]
python -I hybrid/shadow/shadow.py show SAMPLE.ffs
python -I hybrid/shadow/shadow.py summary RESULTS.tsv      # verdicts per image, why originals failed, flagged list
```

`run_capture.py` builds `game_shadow/` next to `game/` (hardlinks of the read-only files, copies of the small ones,
the shadow loader, its own `hooks.ini` with `mode=none`, `window_park=1`, `keep_active=1`, the input script and the
`shadow_*` keys). It refuses to start below `--min-free-gb` of free RAM, and kills the game when RAM drops below it.
`--k 0` only records which probes fire (`ff_shadow_hits.tsv`), with no collector. `--game game_shadow2` uses another
folder with its own collector pipe and semaphore, so two captures can run at once. Each folder keeps the game's user
files in `<game>/profile` (loader `profile_dir`, seeded from `hybrid/freedom_template.ini`; the real
`%APPDATA%\IO Interactive\Freedom Fighters` is never touched): `--fresh-profile` empties it, `--profile-file DAT`
copies a save into its `Profiles` (a `2026-10-22_Name.dat` backup becomes `Name.dat`). `--frames N` dumps the back
buffer every N game seconds. Exit code 0xC0DEB0C5 (the crash box `window_park` suppressed) is reported as a crash.
Scenarios in `scripts/`: `c01a_play.txt` (new game, mission C01A, 6 minutes of varied play), `c02rb_hub.txt` (loads
the save after mission 1: the C02RB sewer hideout), `explore_load.txt` (the menu path to a loaded profile, with frame dumps). Default image: `cur`
(`hybrid/build`); pass `--image label=dir` (repeatable) to compare others. An image is a build folder
(`ff_ports.bin` + `ff_ports.tsv`) or an `ff_ports.bin*` with its `ff_hooks.bin*` plan next to it.

Loader keys (`[hybrid]` in hooks.ini, `FF_HYBRID_<KEY>` overrides): `shadow_list`, `shadow_k` (samples per
function, 1), `shadow_every` (2000 ms of game clock between two samples of a function: the exe's own
QueryPerformanceCounter, so `time_scale` and `fixed_step` apply and capture stalls do not count), `shadow_max`
(100000), `shadow_wait` (60000 ms for a clone slot), `shadow_pipe`, `shadow_sem`.

`run_capture.py --stop-on TEXT --stop-after N` ends a run N seconds after TEXT appears in `ff_hybrid.log` (a script
`log` line). `worklist.py` merges every run folder into `hybrid/build/shadow/worklist.tsv` (one row per function:
samples, worst verdict per image, first difference, first run that sampled it, which exclude lists hold it);
`--replay` re-judges all runs with the current replay code first, `--new-wrong FILE` writes the wrong functions
missing from an exclude list in the exclude format.

## Results (2026-10-22, menus scenario, images prev / v3 / cur)

| Run | What | Numbers |
|---|---|---|
| A | `--k 0`, all 11,694 status-ok starts, `scripts/skip_intro.txt` | 2,582 functions reached up to the main menu |
| B | `--k 1`, `time_scale 4` | 2,634 samples, 655 per minute live (4 workers), 334 MB |
| C | `--k 2`, `menus.txt`, `fixed_step 33`, `present_every_ms 250` | 2,604 functions, 4,524 samples, 645 per minute (6 workers), 597 MB |
| D | `--k 4 --every 30000` (game clock), `scripts/to_level1.txt`, `fixed_step 50`, stop 180 s after "level: idle" | 4,541 functions, 11,011 samples (2.4 per function), 728 per minute, 1.5 GB, 15 min |

| E | `--k 6 --every 30000`, `scripts/c01a_play.txt` (6 min of play in C01A), own `profile_dir`, `fixed_step 50` | 4,635 functions, 15,070 samples, 739 per minute, 2.1 GB, 20 min |
| F | `--k 4 --every 30000`, `scripts/c02rb_hub.txt` (save after mission 1, C02RB hideout) in `game_shadow2` | 3,860 functions, 9,097 samples, 639 per minute |

Two captures at once did not fit in RAM next to each other (the second stopped at its 3.5 GB floor in the menu).

Run D, cur verdicts per function: exact 3,717, weak 621, unsupported 59, missing-page 2, mismatch 79, crash 63.
Runs B-F against the frozen images (`images/`: prev, v3, cur = ports_next2, next3 = ports_next3): 4,762 functions,
42,336 samples. 25 functions wrong in cur are exact or weak in next3, 129 stay wrong, none regress.
`worklist.tsv` (all runs, 4,547 functions, 18,169 samples) and `new_wrong_level1.txt` (45 functions wrong in cur
and not in `game/exclude_level2.txt`) are in `hybrid/build/shadow`.

- Offline replays give the same verdicts as the live ones (run C: 4,524 samples, identical counts). With 6 workers
  they run at about 1,370 samples per minute against 3 images.
- A capture stalls the game thread for about 20 ms (p90 31 ms). The collector is the limit: run C reached the menu
  after 235 s of real time.
- Over runs B and C (2,641 functions), cur verdicts per function are: exact 2,124, weak 367, unsupported 85,
  missing-page 4, mismatch 34, crash 27.
- Of the 51 hunt culprits (`hybrid/build/hunt.tsv`), 43 were sampled. 33 of them mismatch or crash in prev. The
  defects fixed in v3/cur turn exact there:
  - 0x4d5120: EAX upper garbage;
  - the 0x5819a0 family: ESI clobbered;
  - 0x4d6520 and 0x4d6c60: stack below the guard page;
  - 14 fastfail cookie cases;
  - 0x4f9c00 and 0x563620: exact only in cur.
  The other 10 are exact in every image: combination culprits, or a defect on a path this state did not take.
- `hybrid/build/shadow/validation.tsv` lists every flagged function with its first difference. 20 of the cur suspects
  are in no exclude list. Among them, 0x444530 and 0x4b3a70 restore fs:[0] (SEH chain head) to 0, a silent
  defect class. 0x4419f0 and 0x4de040 differ by 1 ulp under the game's FPCW 0x007f (24-bit x87).

False-positive classes found on real samples and fixed:
- `rdtsc` (hooked per instruction address);
- liveness that took `nop dword ptr [eax]`, `push ecx` slot reservations and upper-byte reads behind a byte write
  for real reads;
- writes into the callee's own argument slots (the slots it reads are excluded);
- pointers into the caller's argument area in call logs;
- uninitialised stack garbage (the dead stack starts as zeros);
- DLL out-parameters (each stack-pointer argument of an unmodelled call gets a zeroed fake-heap block);
- Steam overlay D3D forwarders (their target found by running the stub prefix);
- (level run) longer `push ecx` slot reservations, `or edx, -1`, dead-frame addresses stored unaligned in packed
  records, and whole local buffers copied out with `memcpy` (their tail is now only "maybe").

## Limits

- Coverage is what the scenario runs: the menus reach about 2,600 of the 11,694 hookable functions. A level script
  reaches more (`to_level1.txt` writes the shared test profile, so it needs a run of its own), later levels need
  save games, and code the game never runs can only be checked statically.
- One sample checks one path. A defect on a branch the captured state does not take stays invisible (0x4c3d30's
  logging branch, the iterator overflows of 0x4cdf70 and 0x4e6ce0). `--k 2` and later re-arming give more states.
- About 2-3% of the functions are `unsupported`: the original faults in the emulator. The usual cause is a DLL that
  returned a real object (CoCreateInstance, D3D creation calls) where the model returns a zeroed block. A fault the
  game's own SEH would catch ends up here as well.
- Only the probed thread runs; code that waits for another thread spins until the budget ends (`unsupported`).
- DLL calls get modelled answers. A function whose result depends on what a D3D, DirectSound or file call really
  returns follows the same fake path in both runs. Coverage there is shallow, but it causes no false differences.
- Math models use Python's libm, not the UCRT's. Both runs get the same values, so only realism suffers. x87 runs
  with the captured control word (0x007f in the game), so precision differences against SSE ports are real
  findings, not noise.
- A port that keeps state in the image's own `.data` starts from the file's initial values, not from the hybrid's.
- Register liveness is a static scan of the caller (and, for EAX/EDX, of the callers up the captured stack). A
  caller that keeps a value in a scratch register across a different call (LTCG register allocation) is missed.
- Capture is Windows-only (PSS clones). Offline replay (`shadow.py replay`, `FileSource`) needs only Python,
  Unicorn, capstone, pefile, the exe and the images, and runs on Linux unchanged.

## Open

- Mission 2: loading a profile saved after mission 1 (profile screen RIGHT, RETURN, RETURN) starts in the C02RB
  hideout. The city map lies on a table to the left of Mr. Jones; E next to him only starts his dialogue.
  `scripts/explore_map.txt` tries that route with frames every game second. A recorded route
  (`input_record`, `hybrid/scripts/c02rb_police.txt`) now covers the hideout, the map and the police station.
- The callee check compares only `this` (ECX). Stack arguments and call order were too noisy (cdecl cleanup batching,
  inlined helpers). A wrong stack argument that a callee ignores in the sampled state is still invisible, the same way
  0x64d490's wrong `this` was before `callsites.py`.
- About 2-3% of functions stay `unsupported`: the original faults on modelled COM/D3D objects. Modelling the D3D
  device methods that return objects would turn most of them into verdicts.
- Two captures at once do not fit next to other game instances (RAM); run them one at a time.
