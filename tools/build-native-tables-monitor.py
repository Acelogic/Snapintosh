#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the native-page-table monitor, phase 1 (docs/NATIVE-TABLES-DESIGN-20260929.md):
generation74's exact define set -- generation61's qualified flags,
-DSNAP_ROOT_VALIDATE_MEMO=1, -DSNAP_INACTIVE_MIRROR=1, -DSNAP_CANONICAL_VIEW_FAST=1
-- plus -DSNAP_NATIVE_TABLES=1; --shared adds -DSNAP_NATIVE_SHARED=1 (phase 3
shared-region groups) and --live -DSNAP_NATIVE_LIVE=1 (roots cached from their
constructor; needs --shared). --control builds the same tree with native
tables off, the matched baseline for this source (generation74's behaviour
with this source's context layout).

Failure inventory: wrong flag list, reused output, code reservation overflow.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT.parent/'Snapintosh/build/sks-transport-candidate-20260928-v2/qualification.json'
ADDED = ['-DSNAP_ROOT_VALIDATE_MEMO=1', '-DSNAP_INACTIVE_MIRROR=1', '-DSNAP_CANONICAL_VIEW_FAST=1']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--control', action='store_true', help='native tables off (SNAP_NATIVE_TABLES=0)')
ap.add_argument('--shared', action='store_true', help='also -DSNAP_NATIVE_SHARED=1')
ap.add_argument('--live', action='store_true', help='also -DSNAP_NATIVE_LIVE=1 (with --shared)')
ap.add_argument('--out', help='output directory name under build/ (default: native-tables-{monitor,control}-v1)')
args = ap.parse_args()
assert not (args.control and (args.shared or args.live)) and (args.shared or not args.live)
OUT = ROOT/'build'/(args.out or ('native-tables-control-v1' if args.control else 'native-tables-monitor-v1'))
flags = json.loads(QUAL.read_text())['flags']
assert not any(f.startswith(('-DSNAP_ROOT_VALIDATE_MEMO', '-DSNAP_INACTIVE_MIRROR',
                             '-DSNAP_CANONICAL_VIEW_FAST', '-DSNAP_NATIVE_TABLES',
                             '-DSNAP_NATIVE_AUDIT', '-DSNAP_NATIVE_SHARED', '-DSNAP_NATIVE_LIVE'))
           for f in flags)
assert '-DSNAP_ROOT_VALIDATE_WORDS=1' in flags and '-DSNAP_SERVICE_DETAIL=1' in flags
runner = runpy.run_path(str(ROOT/'probes/run.py'))
runner['FLAGS'][:] = flags+ADDED+([] if args.control else ['-DSNAP_NATIVE_TABLES=1'])+\
    (['-DSNAP_NATIVE_SHARED=1'] if args.shared else [])+(['-DSNAP_NATIVE_LIVE=1'] if args.live else [])
OUT.mkdir(parents=True, exist_ok=False)
payload = runner['build']('xnuboot', OUT)
record = dict(qualification_sha256=sha(QUAL), flags=runner['FLAGS'], bytes=len(payload),
              reserved=runner['OUT_AT']-runner['CODE_AT'],
              bin_sha256=sha(OUT/'xnuboot.bin'), elf_sha256=sha(OUT/'xnuboot.elf'))
(OUT/'build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k: record[k] for k in ('bytes', 'reserved', 'bin_sha256', 'elf_sha256')}))
