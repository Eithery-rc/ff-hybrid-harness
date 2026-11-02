@echo off
rem Record a path through the game once, so the hunt can replay it without anyone at the keyboard.
rem Vanilla game (no ports), sound on, normal window; the save comes from a fresh copy of profile_rec (a
rem profile folder copied from %APPDATA%\IO Interactive\Freedom Fighters), the same state every replay starts from (hunt.py --profile-src game/profile_rec).
rem Keyboard, mouse and the GUI cursor go to hybrid\scripts\c02rb_police.txt (loader input_record).
cd /d "%~dp0"
if exist profile_recording rmdir /s /q profile_recording
xcopy /e /i /q profile_rec profile_recording >nul
set FF_HYBRID_MODE=none
set FF_HYBRID_PROFILE_DIR=%~dp0profile_recording
set FF_HYBRID_INPUT_RECORD=%~dp0..\hybrid\scripts\c02rb_police.txt
start "" Freedom.Exe
