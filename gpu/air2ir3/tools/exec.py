#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""exec.py - llvmpipe execution of the AIR-derived NIR versus M3 Max Metal goldens.

  python3 tools/scenes.py            # (re)writes scenes/*.json + scenes/data
  python3 tools/exec.py [scene ...]  # -> results/exec/<scene>.{metal,lp}.bgra, compare.json, contact-sheet.png
Both sides render 3 frames (clear + draw, one command buffer / flush each) and keep frame 2.
"""
import os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'results', 'exec')

def main():
    os.makedirs(OUT, exist_ok=True)
    names = sys.argv[1:] or sorted(f[:-5] for f in os.listdir(os.path.join(ROOT, 'scenes')) if f.endswith('.json'))
    for n in names:
        sc = os.path.join(ROOT, 'scenes', n + '.json')
        for tool, ext in (('mtlgold', 'metal'), ('nirexec', 'lp')):
            r = subprocess.run([os.path.join(ROOT, 'build', tool), sc, os.path.join(OUT, f'{n}.{ext}.bgra'), '--frames', '3'],
                               capture_output=True, text=True)
            print((r.stdout + r.stderr).strip())
            if r.returncode: sys.exit(f'{tool} failed on {n}')
    subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'compare.py'), OUT], check=True)

if __name__ == '__main__':
    main()
