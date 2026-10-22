#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the fast-exit monitor: generation78's exact define set --
generation61's qualified flags, -DSNAP_ROOT_VALIDATE_MEMO=1,
-DSNAP_INACTIVE_MIRROR=1, -DSNAP_CANONICAL_VIEW_FAST=1, -DSNAP_NATIVE_TABLES=1,
-DSNAP_NATIVE_SHARED=1, -DSNAP_NATIVE_LIVE=1 -- plus the lock-free and removed
exits of docs/TRAP-CENSUS-20260929.md:

  -DSNAP_FAST_VCPU_TRAPS=1  counter/ESR/FAR/PMC/key sysreg reads and PACGA, no lock
  -DSNAP_VECTOR_BRANCH=1    perform the vector slot's B, no single step
  -DSNAP_ERET_SNAPSHOT=1    snapshot at the ERET, no exception_return breakpoint
  -DSNAP_FAST_CROSSINGS=1   vector entry and ERET without the lock
  -DSNAP_NATIVE_WFE=1       guest WFE native, woken by the hardware event stream
  -DSNAP_FAST_TIMER_WRITE=1 CNTV_TVAL writes that keep the timer line, no lock
  -DSNAP_FAST_IDLE_POLL=1   the ACC idle-poll read, no lock (docs/FAST-TRAP-BATCH2-20261016.md)
  -DSNAP_KERNEL_PPERM_VARIANTS=1  a kernel PPERM flip swaps copy columns and TTBR1
                            (docs/KERNEL-PPERM-VARIANTS-20261016.md)

--control builds the same tree with none of them (generation78's define set);
--without NAME drops one for a bisect. The record has build-native-tables-
monitor.py's fields.

Failure inventory: wrong flag list, reused output, code reservation overflow.
"""
from pathlib import Path
import argparse
import hashlib
import json
import runpy

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT/'config/monitor-flags.json'
ADDED = ['-DSNAP_ROOT_VALIDATE_MEMO=1', '-DSNAP_INACTIVE_MIRROR=1', '-DSNAP_CANONICAL_VIEW_FAST=1',
         '-DSNAP_NATIVE_TABLES=1', '-DSNAP_NATIVE_SHARED=1', '-DSNAP_NATIVE_LIVE=1']
FAST = ['-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_VECTOR_BRANCH=1', '-DSNAP_ERET_SNAPSHOT=1',
        '-DSNAP_FAST_CROSSINGS=1', '-DSNAP_NATIVE_WFE=1', '-DSNAP_FAST_TIMER_WRITE=1',
        '-DSNAP_FAST_IDLE_POLL=1', '-DSNAP_KERNEL_PPERM_VARIANTS=1']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument('--control', action='store_true', help='none of the fast-exit defines')
ap.add_argument('--sptm-hvc-calls', action='store_true',
                help='opt into the image-pinned HVC call-entry experiment (still EL2)')
ap.add_argument('--without', action='append', default=[], metavar='NAME',
                help='drop one define, e.g. SNAP_NATIVE_WFE (repeatable)')
ap.add_argument('--out', help='output directory name under build/ (default: fast-traps-{monitor,control}-v1)')
args = ap.parse_args()
dropped = {f'-D{name}=1' for name in args.without}
if not dropped <= set(FAST):
    ap.error(f'--without takes one of {[f[2:-2] for f in FAST]}')
if (dropped & {'-DSNAP_FAST_VCPU_TRAPS=1', '-DSNAP_VECTOR_BRANCH=1'} and
        '-DSNAP_FAST_CROSSINGS=1' not in dropped):
    ap.error('SNAP_FAST_CROSSINGS needs SNAP_FAST_VCPU_TRAPS and SNAP_VECTOR_BRANCH: drop it too')
if ('-DSNAP_FAST_VCPU_TRAPS=1' in dropped and
        not {'-DSNAP_FAST_TIMER_WRITE=1', '-DSNAP_FAST_IDLE_POLL=1'} <= dropped):
    ap.error('SNAP_FAST_TIMER_WRITE and SNAP_FAST_IDLE_POLL need SNAP_FAST_VCPU_TRAPS: drop them too')
extra = [] if args.control else [f for f in FAST if f not in dropped]
if args.sptm_hvc_calls:
    extra.append('-DSNAP_SPTM_HVC_CALLS=1')
default_out = 'fast-traps-control-v1' if args.control else 'fast-traps-monitor-v1'
if args.sptm_hvc_calls:
    default_out = default_out.removesuffix('-v1')+'-sptm-hvc-v1'
OUT = ROOT/'build'/(args.out or default_out)
flags = json.loads(QUAL.read_text())['flags']
assert not any(f.startswith(('-DSNAP_ROOT_VALIDATE_MEMO', '-DSNAP_INACTIVE_MIRROR',
                             '-DSNAP_CANONICAL_VIEW_FAST', '-DSNAP_NATIVE_TABLES',
                             '-DSNAP_NATIVE_AUDIT', '-DSNAP_NATIVE_SHARED', '-DSNAP_NATIVE_LIVE',
                             '-DSNAP_FAST_', '-DSNAP_VECTOR_BRANCH', '-DSNAP_ERET_SNAPSHOT',
                             '-DSNAP_NATIVE_WFE', '-DSNAP_SPTM_HVC_CALLS')) for f in flags)
assert '-DSNAP_ROOT_VALIDATE_WORDS=1' in flags and '-DSNAP_SERVICE_DETAIL=1' in flags
assert '-DSNAP_NATIVE_WRITER_BREAKPOINTS=1' in flags and '-DSNAP_NATIVE_CALLS=1' in flags
runner = runpy.run_path(str(ROOT/'probes/run.py'))
runner['FLAGS'][:] = flags+ADDED+extra
OUT.mkdir(parents=True, exist_ok=False)
payload = runner['build']('xnuboot', OUT)
record = dict(flags_recipe_sha256=sha(QUAL), flags=runner['FLAGS'], bytes=len(payload),
              reserved=runner['OUT_AT']-runner['CODE_AT'],
              bin_sha256=sha(OUT/'xnuboot.bin'), elf_sha256=sha(OUT/'xnuboot.elf'))
(OUT/'build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k: record[k] for k in ('bytes', 'reserved', 'bin_sha256', 'elf_sha256')}))
