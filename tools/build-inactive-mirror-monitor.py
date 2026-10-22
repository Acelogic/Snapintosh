#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the SWITCH_ROOT step B monitor: generation61's qualified flags, the
validated-table memo (-DSNAP_ROOT_VALIDATE_MEMO=1, as generation64-72) and
inactive-root mirroring (-DSNAP_INACTIVE_MIRROR=1). --control builds the same
tree with mirroring off, the matched baseline for this context layout.

Failure inventory: wrong flag list, reused output, code reservation overflow.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT.parent/'Snapintosh/build/sks-transport-candidate-20260928-v2/qualification.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--control', action='store_true', help='mirroring off (SNAP_INACTIVE_MIRROR=0)')
args = ap.parse_args()
OUT = ROOT/('build/inactive-mirror-control-v1' if args.control else 'build/inactive-mirror-monitor-v1')
flags = json.loads(QUAL.read_text())['flags']
assert not any(f.startswith(('-DSNAP_ROOT_VALIDATE_MEMO', '-DSNAP_INACTIVE_MIRROR')) for f in flags)
assert '-DSNAP_ROOT_VALIDATE_WORDS=1' in flags
runner = runpy.run_path(str(ROOT/'probes/run.py'))
runner['FLAGS'][:] = flags+['-DSNAP_ROOT_VALIDATE_MEMO=1']+([] if args.control else ['-DSNAP_INACTIVE_MIRROR=1'])
OUT.mkdir(parents=True, exist_ok=False)
payload = runner['build']('xnuboot', OUT)
record = dict(qualification_sha256=sha(QUAL), flags=runner['FLAGS'], bytes=len(payload),
              reserved=runner['OUT_AT']-runner['CODE_AT'],
              bin_sha256=sha(OUT/'xnuboot.bin'), elf_sha256=sha(OUT/'xnuboot.elf'))
(OUT/'build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k: record[k] for k in ('bytes', 'reserved', 'bin_sha256', 'elf_sha256')}))
