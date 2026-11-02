"""mute_game.py - keep the test game silent: mutes the audio sessions of Freedom.Exe started from this project.

Runs next to a hunt and checks every second, so the intro music never reaches the user's headphones. Only sessions
whose process path is inside this repo's folder are touched; the Steam copy of the game keeps its sound. Windows
remembers a per-application mute, so --unmute is there to give the work copy its sound back for a manual session.

    python -I hybrid/mute_game.py [--hours 4]      # mute loop
    python -I hybrid/mute_game.py --unmute         # once: unmute every project copy that is running
"""
import argparse
import os
import sys
import time

from pycaw.pycaw import AudioUtilities

ROOT = os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def project_sessions():
    for s in AudioUtilities.GetAllSessions():
        p = s.Process
        try:
            if p and p.name().lower() == 'freedom.exe' and os.path.normcase(p.exe()).startswith(ROOT):
                yield s
        except Exception:   # the process ended between the listing and the check
            continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hours', type=float, default=4)
    ap.add_argument('--unmute', action='store_true')
    a = ap.parse_args()
    if a.unmute:
        for s in project_sessions():
            s.SimpleAudioVolume.SetMute(0, None)
            print('unmuted pid %d' % s.ProcessId)
        return
    t_end = time.time() + a.hours * 3600
    muted = set()
    while time.time() < t_end:
        try:
            for s in project_sessions():
                if not s.SimpleAudioVolume.GetMute():
                    s.SimpleAudioVolume.SetMute(1, None)
                if s.ProcessId not in muted:
                    muted.add(s.ProcessId)
                    print('%s muted pid %d' % (time.strftime('%H:%M:%S'), s.ProcessId), flush=True)
        except Exception as e:  # audio device switch or COM hiccup: try again next second
            print('%s retry: %s' % (time.strftime('%H:%M:%S'), e), file=sys.stderr, flush=True)
        time.sleep(1)


if __name__ == '__main__':
    main()
