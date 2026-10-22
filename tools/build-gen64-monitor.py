#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the generation64 monitor: generation61's qualified flags plus the
SWITCH_ROOT validated-table memo (-DSNAP_ROOT_VALIDATE_MEMO=1).

Failure inventory: wrong flag list, reused output, code reservation overflow,
or a binary that differs from the memo worktree's host-tested build.
"""
from pathlib import Path
import hashlib
import json
import runpy

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT.parent/'Snapintosh/build/sks-transport-candidate-20260928-v2/qualification.json'
OUT = ROOT/'build/gen64-monitor-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
flags = json.loads(QUAL.read_text())['flags']
assert '-DSNAP_ROOT_VALIDATE_MEMO=1' not in flags
runner = runpy.run_path(str(ROOT/'probes/run.py'))
runner['FLAGS'][:] = flags+['-DSNAP_ROOT_VALIDATE_MEMO=1']
OUT.mkdir(parents=True, exist_ok=False)
payload = runner['build']('xnuboot', OUT)
record = dict(qualification_sha256=sha(QUAL), flags=runner['FLAGS'], bytes=len(payload),
              bin_sha256=sha(OUT/'xnuboot.bin'), elf_sha256=sha(OUT/'xnuboot.elf'))
(OUT/'build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k: record[k] for k in ('bytes', 'bin_sha256', 'elf_sha256')}))
