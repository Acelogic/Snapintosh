#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay every commit of a capture through the production kext IB validator (tools/test-adreno-ib-command.c, as
gfx-correctness run-suite.py S3 does) using TREE's tools/ and compat/.
    replay-validator.py TREE CAPTURE_DIR WORKDIR"""
import importlib.util, json, os, sys
from pathlib import Path
tree, cap, work = (Path(p).resolve() for p in sys.argv[1:4])
work.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('ds', tree / 'tools/test-adreno-depth-stencil.py')
DS = importlib.util.module_from_spec(spec)
cwd = os.getcwd(); os.chdir(tree)
try:
    spec.loader.exec_module(DS)
    kernel = DS.build_replay(work, guest_size=0x4400000, arena=0x4000000, fixtures=400, capacity=800,
                             name='kernel-replay-gpuperf', arena_pages=129)
    rep = cap / 'report.json'
    if not rep.is_file(): rep = cap / 'scenes/report.json'; cap = cap / 'scenes'
    commits = json.loads(rep.read_text())['commits']
    ok = bad = 0
    for c in commits:
        if not (cap / c['dir'] / 'commands.bin').is_file(): continue
        if 'encoded' in c and not int(c['encoded'] or 0): continue          # fence-only commits (as S3 skips them)
        if int(c.get('work', {}).get('encoded', 1) or 0) == 0: continue
        d = work / 'commits' / c['dir']                                      # never write into the capture
        d.mkdir(parents=True, exist_ok=True)
        (d / 'commands.bin').write_bytes((cap / c['dir'] / 'commands.bin').read_bytes())
        try:
            DS.replay(kernel, d, f'gpuperf-{c["dir"]}', window=0x3e00000); ok += 1
        except Exception as e:
            bad += 1; print('REFUSED', c['dir'], str(e)[:300])
finally:
    os.chdir(cwd)
print(f'replayed {ok + bad} commits, {bad} refused'); sys.exit(1 if bad else 0)
