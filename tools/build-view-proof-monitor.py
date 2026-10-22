#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the step B monitor plus the fast canonical-view proof: generation61's
qualified flags, the validated-table memo (-DSNAP_ROOT_VALIDATE_MEMO=1),
inactive-root mirroring (-DSNAP_INACTIVE_MIRROR=1) and
-DSNAP_CANONICAL_VIEW_FAST=1. --control builds the same tree with the fast
proof off, the matched baseline for this source.

Failure inventory: wrong flag list, reused output, code reservation overflow.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT.parent/'Snapintosh/build/sks-transport-candidate-20260928-v2/qualification.json'
ADDED = ['-DSNAP_ROOT_VALIDATE_MEMO=1', '-DSNAP_INACTIVE_MIRROR=1']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--control', action='store_true', help='fast proof off (SNAP_CANONICAL_VIEW_FAST=0)')
args = ap.parse_args()
OUT = ROOT/('build/view-proof-control-v1' if args.control else 'build/view-proof-monitor-v1')
flags = json.loads(QUAL.read_text())['flags']
assert not any(f.startswith(('-DSNAP_ROOT_VALIDATE_MEMO', '-DSNAP_INACTIVE_MIRROR',
                             '-DSNAP_CANONICAL_VIEW_FAST')) for f in flags)
assert '-DSNAP_ROOT_VALIDATE_WORDS=1' in flags and '-DSNAP_SERVICE_DETAIL=1' in flags
runner = runpy.run_path(str(ROOT/'probes/run.py'))
runner['FLAGS'][:] = flags+ADDED+([] if args.control else ['-DSNAP_CANONICAL_VIEW_FAST=1'])
OUT.mkdir(parents=True, exist_ok=False)
payload = runner['build']('xnuboot', OUT)
record = dict(qualification_sha256=sha(QUAL), flags=runner['FLAGS'], bytes=len(payload),
              reserved=runner['OUT_AT']-runner['CODE_AT'],
              bin_sha256=sha(OUT/'xnuboot.bin'), elf_sha256=sha(OUT/'xnuboot.elf'))
(OUT/'build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k: record[k] for k in ('bytes', 'reserved', 'bin_sha256', 'elf_sha256')}))
