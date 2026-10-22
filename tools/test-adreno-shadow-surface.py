#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Aligned shadows for IOSurfaces with unaligned rows, end to end on this Mac (no GPU submission, no A16).

docs/USERSPACE-GRAPHICS-20261019.md (aligned shadows): CoreImage's IOSurface intermediates have rows such as 1,120
bytes, and Adreno linear pitches are 64-byte multiples, so v82's icon kernels dropped. The harness
(gpu/adreno-kext/plugin/harness/shadow-surface.m) checks the data path on the plug-in device:
  - an unaligned surface's texture gets a 64-byte-pitch shadow filled from the surface, padding zero;
  - textures over one surface share one shadow; aligned surfaces keep the zero-copy path;
  - a CoreImage render into the unaligned surface commits with nothing omitted, and the command buffer's
    write-back copies the shadow (the simulated GPU output) into the surface once, recording the seed;
  - a CPU write or replaceRegion refills the shadow before the next GPU read;
  - each committed render's kernel commands replay through the production kext validator.
--expect-before: the unchanged plug-in has no shadows (and so fails the checks above).

    python3 tools/test-adreno-shadow-surface.py --bundle BUNDLE --output NEW-DIR [--expect-before]
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness/shadow-surface.m'
EXPECTED = 17        # the harness's checks when every step runs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = out / 'shadow-surface'
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', str(HARNESS), '-o', str(exe),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'CoreImage', '-framework', 'CoreGraphics',
                    '-framework', 'IOSurface', '-framework', 'IOKit'], check=True)
    subprocess.run(['codesign', '-f', '-s', '-', str(exe)], check=True, capture_output=True)
    cap = out / 'capture'
    run = subprocess.run([str(exe), str(args.bundle.resolve()), str(cap)], capture_output=True, text=True, timeout=300)
    (out / 'harness.log').write_text(run.stdout + run.stderr)
    report = json.loads((cap / 'report.json').read_text())
    failures = [c['what'] for c in report.get('checks', []) if not c['ok']]
    if report.get('status') != 'CAPTURED_NOT_SUBMITTED':
        failures.append(f'harness status {report.get("status")} {report.get("exception")}')
    if len(report.get('checks', [])) != EXPECTED:
        failures.append(f'{len(report.get("checks", []))} harness checks ran (expected {EXPECTED})')
    replays = 0
    if not args.expect_before:
        spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
        DS = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(DS)
        kernel = DS.build_replay(out)
        for c in report.get('cases', []):
            if not (cap / c['name'] / 'commands.bin').is_file():
                failures.append(f'{c["name"]}: no committed kernel commands')
                continue
            try:
                DS.replay(kernel, cap / c['name'], c['name'])
                replays += 1
            except Exception as error:          # the replay module's own Fail class
                failures.append(f'{c["name"]}: kext validator: {error}')
    result = dict(checks=len(report.get('checks', [])) + replays, failures=failures, expect_before=args.expect_before,
                  surface_row=report.get('surface_row'), shadow_row=report.get('shadow_row'))
    (out / 'result.json').write_text(json.dumps(result, indent=2))
    if args.expect_before:
        if failures:
            print(f'PASS: the unchanged plug-in fails {len(failures)} shadow checks (first: {failures[0]}); {out / "result.json"}')
            return 0
        print(f'FAIL: the unchanged plug-in passed every shadow check; {out / "result.json"}')
        return 1
    if failures:
        for f in failures:
            print(f'FAIL {f}')
        print(f'FAIL: {len(failures)} shadow failures; {out / "result.json"}')
        return 1
    print(f'PASS: {result["checks"]} shadow checks ({replays} kext replays, rows {result["surface_row"]} -> '
          f'{result["shadow_row"]}); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
