#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real CoreImage compute work on the AdrenoMetal device, end to end on this Mac (no GPU submission, no A16).

docs/USERSPACE-GRAPHICS-20261019.md (v80 CoreImage compute shapes): iconservicesagent's icon kernels dropped with
"compute requires one sampled texture/sampler and storage-image slot 1". The harness
(gpu/adreno-kext/plugin/harness/ci-compute.m) renders icon-like CoreImage graphs (downscale, Lanczos, blur, srcOver, and a
solid-colour fill: ci_fill writes its image with no sampled texture or sampler)
into BGRA8 textures on the plug-in device with native commits intercepted. The checks:
  - every compute pipeline CoreImage builds compiles and is admitted by the plug-in;
  - every case commits, with work encoded, nothing omitted and no encoding failure;
  - each case's committed kernel commands replay through the production kext validator
    (tools/test-adreno-depth-stencil.py's replay of tools/test-adreno-ib-command.c), every package admitted.
--expect-before: the unchanged plug-in must refuse at least one kernel (and so fail the checks above).

    python3 tools/test-adreno-ci-compute.py --bundle BUNDLE --output NEW-DIR [--expect-before]
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness/ci-compute.m'
checks, failures = 0, []


def check(ok, what):
    global checks
    checks += 1
    if not ok:
        failures.append(what)
        print(f'FAIL {what}')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    exe = out / 'ci-compute'
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', str(HARNESS), '-o', str(exe),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'CoreImage', '-framework', 'CoreGraphics',
                    '-framework', 'IOKit'], check=True)
    subprocess.run(['codesign', '-f', '-s', '-', str(exe)], check=True, capture_output=True)
    cap = out / 'capture'
    run = subprocess.run([str(exe), str(args.bundle.resolve()), str(cap)], capture_output=True, text=True, timeout=300)
    (out / 'harness.log').write_text(run.stdout + run.stderr)
    report = json.loads((cap / 'report.json').read_text())
    pipelines, cases = report.get('pipelines', []), report.get('cases', [])
    refused = [p for p in pipelines if p.get('admission') != 'admitted']
    if args.expect_before:
        check(report.get('status') == 'CAPTURED_NOT_SUBMITTED', f'harness status {report.get("status")} {report.get("exception")}')
        check(bool(refused), 'the unchanged plug-in admitted every CoreImage kernel')
        reasons = sorted({p.get('admission') or p.get('error') for p in refused})
        print(json.dumps(dict(refused=len(refused), of=len(pipelines), reasons=reasons), indent=1))
    else:
        check(report.get('status') == 'CAPTURED_NOT_SUBMITTED', f'harness status {report.get("status")} {report.get("exception")}')
        check(len(pipelines) >= 8, f'{len(pipelines)} compute pipelines (expected CoreImage to build at least 8)')
        for p in pipelines:
            check(bool(p.get('compiled')) and p.get('admission') == 'admitted',
                  f'{p["case"]}/{p["entry"]}: {p.get("admission") or p.get("error")}')
        spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
        DS = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(DS)
        kernel = DS.build_replay(out)
        for c in cases:
            work = c.get('work') or {}
            check(c.get('status') == 'committed', f'{c["name"]}: {c.get("status")} {c.get("exception")}')
            check(work.get('encoded', 0) > 0 and work.get('omitted') == 0 and not work.get('encoding_failed'),
                  f'{c["name"]}: encoded {work.get("encoded")} omitted {work.get("omitted")} omissions {work.get("omissions")}')
            kinds = {e.get('kind') for e in (work.get('encoders') or {}).values()}
            check('compute' in kinds, f'{c["name"]}: no compute encoder ({sorted(kinds)})')
            if (cap / c['name'] / 'commands.bin').is_file():
                try:
                    DS.replay(kernel, cap / c['name'], c['name'])
                    admitted = ''
                except Exception as error:          # the replay module's own Fail class
                    admitted = str(error)
                check(not admitted, f'{c["name"]}: kext validator: {admitted}')
            else:
                check(False, f'{c["name"]}: no committed kernel commands')
    result = dict(checks=checks, failures=failures, pipelines=len(pipelines), cases=len(cases),
                  expect_before=args.expect_before, refused=len(refused))
    (out / 'result.json').write_text(json.dumps(result, indent=2))
    if failures:
        print(f'FAIL: {len(failures)} of {checks} checks; {out / "result.json"}')
        return 1
    print(f'PASS: {checks} CoreImage compute checks ({len(pipelines)} kernels, {len(cases)} cases'
          f'{", unchanged plug-in refuses" if args.expect_before else ""}); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
