@echo off
rem Play the hybrid build by hand: ports image in ff_ports.bin, same hook set as the acceptance hunt.
rem Profile (freedom.ini, saves) comes from profile_play, a copy of the real one; the real profile is untouched.
rem On a crash the last 256 hooked calls go to ff_hybrid.log (trace=1).
cd /d "%~dp0"
set FF_HYBRID_MODE=list
set FF_HYBRID_INCLUDE_FILE=all_addrs.txt
set FF_HYBRID_EXCLUDE_FILE=exclude_level2.txt
set FF_HYBRID_ON_ERROR=abort
set FF_HYBRID_TRACE=1
set FF_HYBRID_PROFILE_DIR=%~dp0profile_play
start "" Freedom.Exe
