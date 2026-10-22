#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""iconservicesagent's icon rendering on the Adreno device, end to end on this Mac (no GPU submission, no A16).

docs/USERSPACE-GRAPHICS-20261019.md ("Why the Dock gets placeholders"): IconRendering's RenderBox renderer needs
pointer phis and selects in air2ir3, the commitAndWaitUntilSubmitted commit variant, [[front_facing]] fragment input and
render pipelines without a fragment function. Without any of them the renderer drops work or returns no image, and the
Dock shows the generic placeholder. The harness (gpu/adreno-kext/plugin/harness/icon-render.m, with
default-device-interpose.m making the plug-in device the system default) renders app icons through
ISIconStackAssetCatalogResource. The checks, per app:
  - the icon resource is an icon stack and an image comes back;
  - RenderBox logs no pipeline error (air2ir3 refused nothing);
  - every commit encodes work, omits nothing and fails no encoding;
  - each commit's kernel commands replay through the production kext validator.
--expect-before: the unchanged plug-in must fail at least one of these.
The host must run 26A428 (the guest's build): IconServices, IconRendering and RenderBox are the guest's code.

    python3 tools/test-adreno-icon-render.py --bundle BUNDLE --output NEW-DIR [--expect-before]
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
# Photos' icon uses RenderBox's custom_effect (a linked visible function that keeps a texture in private memory).
APPS = ['/System/Applications/Calculator.app', '/System/Applications/Calendar.app', '/System/Applications/Notes.app',
        '/System/Applications/Photos.app']


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    build = subprocess.run(['sw_vers', '-buildVersion'], capture_output=True, text=True).stdout.strip()
    if build != '26A428':
        print(f'FAIL: host build {build}, not 26A428')
        return 1
    lib, exe = out / 'default-device-interpose.dylib', out / 'icon-render'
    subprocess.run(['xcrun', 'clang', '-dynamiclib', '-arch', 'arm64e', str(HARNESS / 'default-device-interpose.m'), '-o', str(lib),
                    '-framework', 'Foundation', '-framework', 'Metal'], check=True)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', str(HARNESS / 'icon-render.m'), '-o', str(exe),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'CoreGraphics', '-framework', 'IOKit'],
                   check=True)
    for f in (lib, exe):
        subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
    cap = out / 'capture'
    env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(lib), OS_ACTIVITY_DT_MODE='1')
    run = subprocess.run([str(exe), str(args.bundle.resolve()), str(cap)] + APPS, capture_output=True, text=True, env=env,
                         timeout=900)
    log = run.stdout + run.stderr
    (out / 'harness.log').write_text(log)
    failures, checks = [], 0

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    check(run.returncode in (0, 1), f'harness exit {run.returncode}')
    pipeline_errors = sorted({line.split('pipeline error: ', 1)[1][:160] for line in log.splitlines() if 'pipeline error: ' in line})
    check(not pipeline_errors, f'RenderBox pipeline errors: {pipeline_errors[:4]}')
    spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
    DS = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(DS)
    # RenderBox's targets and coverage buffers need a larger host window than the draw tests' 4 MiB replay.
    # RenderBox's targets, coverage buffers and packages (up to ADRENO_IB_MAX_PACKAGE, 2 MiB) need a larger host
    # window and arena than the draw tests' 4 MiB replay.
    kernel = None if args.expect_before else DS.build_replay(out, guest_size=0x4000000, arena=0x3c00000, fixtures=160,
                                                             capacity=320, name='kernel-replay-64m', arena_pages=129)
    apps = {}
    for app in APPS:
        name = Path(app).stem
        path = cap / name / 'report.json'
        report = json.loads(path.read_text()) if path.is_file() else {}
        commits = report.get('commits', [])
        omitted = [o for c in commits for o in (c.get('omissions') or [])]
        apps[name] = dict(image=report.get('image'), commits=len(commits), omitted=len(omitted))
        check(report.get('resource') == 'ISIconStackAssetCatalogResource', f'{name}: resource {report.get("resource")}')
        check(bool(report.get('image')), f'{name}: no image')
        check(bool(commits), f'{name}: no commits')
        check(not omitted, f'{name}: {len(omitted)} omitted: '
              f'{sorted({(o.get("details") or {}).get("pipeline", "?") + ": " + str((o.get("details") or {}).get("reason")) for o in omitted})[:3]}')
        check(not any(c.get('encoding_failed') for c in commits), f'{name}: an encoding failed')
        if kernel:
            for d in sorted(p for p in (cap / name).iterdir() if p.is_dir()):
                if not (d / 'commands.bin').is_file():
                    continue
                try:
                    DS.replay(kernel, d, f'{name}/{d.name}', window=0x3a00000)
                    admitted = ''
                except Exception as error:          # the replay module's own Fail class
                    admitted = str(error)
                check(not admitted, f'{name}/{d.name}: kext validator: {admitted}')
    result = dict(checks=checks, failures=failures, apps=apps, pipeline_errors=pipeline_errors, expect_before=args.expect_before)
    (out / 'result.json').write_text(json.dumps(result, indent=2))
    if args.expect_before:
        if failures:
            print(f'PASS: the unchanged plug-in fails {len(failures)} icon checks (first: {failures[0][:200]}); {out / "result.json"}')
            return 0
        print(f'FAIL: the unchanged plug-in passed every icon check; {out / "result.json"}')
        return 1
    if failures:
        for f in failures:
            print(f'FAIL {f[:400]}')
        print(f'FAIL: {len(failures)} of {checks} icon checks; {out / "result.json"}')
        return 1
    summary = ', '.join(f'{k} {v["commits"]} commits' for k, v in apps.items())
    print(f'PASS: {checks} icon checks ({summary}); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
