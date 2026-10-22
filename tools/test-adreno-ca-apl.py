#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CoreAnimation's APL filter and Metal texture reads on the plug-in device, end to end on this Mac.

docs/WINDOWSERVER-APL-ABORT-20261020.md: WindowServer died about 30 s after its first present in
installed-fresh-20261020-v13 and -v14 (SIGABRT from __assert_rtn in llvm::CallBase::getArgOperand, inside
libAdrenoCompiler.dylib). Metal's compiler service hands the plug-in AIR 2.2, whose texture read is
air.read_texture_2d(texture, coord, lod, access); the translator assumed AIR 2.9's six operands and read operand 4.
CoreAnimation's limitAveragePixelLuminance filter runs such a read in its compute_apl kernel. The harness
(gpu/adreno-kext/plugin/harness/ca-apl.m) uses this Mac's real 26A428 CoreAnimation and compiler service.

What it protects, and which regression fails it:
  apl         the filter with the plug-in as built: the process survives, CoreAnimation binds dim_factor 1 (its APL
              filter is off, AdrenoMTLDevice's CA_DISABLE_APL_FILTER) and nothing is omitted. Fails if the option is
              lost: CoreAnimation then runs two kernels the compute builder omits and scales the layer by 0 (black).
  apl-forced  the same with CA_DISABLE_APL_FILTER=0: CoreAnimation builds compute_apl and
              sum_apl_and_compute_dimming_factor (a failed compute pipeline makes CoreAnimation abort, namespace
              COREANIMATION code 10), so the process survives. Fails if the AIR 2.2 read lowering regresses (SIGABRT).
              The omitted dispatches are reported, and only those two kernels may be omitted.
  kernels     every texture2d read() form compiles through the compiler service (each in its own process), and a
              multisample size query is refused with an NSError. Fails on any out-of-bounds operand read (SIGABRT).
--expect-before: the unchanged plug-in must fail at least one check. The host must run 26A428 (the guest's build).

    python3 tools/test-adreno-ca-apl.py --bundle BUNDLE --output NEW-DIR [--expect-before]
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
KERNELS = HARNESS / 'texture-read-kernels.metal'
READS = ['read_sample', 'read_sample_lod', 'read_read', 'read_read_lod', 'read_ushort', 'read_uint', 'read_int']
APL_KERNELS = {'compute_apl', 'sum_apl_and_compute_dimming_factor'}


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
    lib, exe = out / 'default-device-interpose.dylib', out / 'ca-apl'
    subprocess.run(['xcrun', 'clang', '-dynamiclib', '-arch', 'arm64e', str(HARNESS / 'default-device-interpose.m'), '-o', str(lib),
                    '-framework', 'Foundation', '-framework', 'Metal'], check=True)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', '-Wall', '-Werror', str(HARNESS / 'ca-apl.m'),
                    '-o', str(exe), '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'QuartzCore',
                    '-framework', 'IOSurface', '-framework', 'IOKit', '-framework', 'CoreGraphics'], check=True)
    for f in (lib, exe):
        subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
    base = {k: v for k, v in os.environ.items() if not k.startswith(('CA_', 'ADRENO_'))}
    base['ADRENO_SHADER_CACHE'] = '0'                 # every pipeline compiles now, not from an earlier run's records
    bundle = str(args.bundle.resolve())
    failures, checks = [], 0

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    def run(name, argv, env):
        r = subprocess.run([str(exe)] + argv, capture_output=True, text=True, env=env, timeout=900)
        (out / f'{name}.log').write_text(r.stdout + r.stderr)
        return r

    insert = dict(base, DYLD_INSERT_LIBRARIES=str(lib))
    r = run('apl', ['--apl', bundle, '4'], insert)
    check(r.returncode == 0, f'apl: harness exit {r.returncode}')
    factors = re.findall(r'^FRAME \d+ dim_factor (.*)$', r.stdout, re.M)
    check(len(factors) == 4 and all(f == '1 1 1 1' for f in factors), f'apl: dim_factor {factors} (want 1 1 1 1 every frame)')
    m = re.search(r'^APL commits=(\d+) encoded=(\d+) omitted=(\d+)$', r.stdout, re.M)
    check(bool(m) and int(m.group(1)) > 0 and int(m.group(3)) == 0, f'apl: {m.group(0) if m else "no totals line"}')
    print(f'apl         exit {r.returncode}; dim_factor {sorted(set(factors))}; {m.group(0) if m else "no totals"}')

    r = run('apl-forced', ['--apl', bundle, '4'], dict(insert, CA_DISABLE_APL_FILTER='0'))
    check(r.returncode == 0, f'apl-forced: harness exit {r.returncode} (CoreAnimation needs compute_apl and '
          f'sum_apl_and_compute_dimming_factor)')
    omitted = re.findall(r'^OMITTED (\S+): (.*)$', r.stdout, re.M)
    check(all(k in APL_KERNELS for k, _ in omitted), f'apl-forced: other operations omitted: {omitted}')
    print(f'apl-forced  exit {r.returncode}; omitted {sorted(set(omitted))}')

    for name in READS + ['ms_size']:
        r = run(f'kernel-{name}', ['--kernel', bundle, str(KERNELS), name], base)
        line = (re.findall(rf'^KERNEL {name} (.*)$', r.stdout, re.M) or [''])[0]
        if name == 'ms_size':
            check(r.returncode == 0 and line.startswith('error:') and 'multisample' in line,
                  f'{name}: exit {r.returncode}, {line or "no result"} (want a refusal naming multisample textures)')
        else:
            check(r.returncode == 0 and line == 'ok', f'{name}: exit {r.returncode}, {line or "no result"}')
        print(f'kernel      {name:16s} exit {r.returncode}; {line[:100] or "no result"}')

    print(f'{checks - len(failures)}/{checks} checks passed')
    for f in failures:
        print(f'FAIL: {f}')
    if args.expect_before:
        print('expect-before: ' + ('the unchanged plug-in fails, as it must' if failures else 'FAIL: the unchanged plug-in passes'))
        return 0 if failures else 1
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
