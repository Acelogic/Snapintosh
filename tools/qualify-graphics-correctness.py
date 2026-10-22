#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline graphics qualification; no target I/O or GPU submission.

Builds real Metal plug-ins and runs intercepted Metal entry points, real planar
IOSurface layout, intermediate framebuffer publication replay, and the production
SPTM lifecycle. Saves repeatable commands, logs, raw output and source hashes.
--reference-refs must name a retained pre-change compat/sptm-refs.c.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CORE = ['compat/sptm-root.c', 'compat/sptm-user.c', 'compat/sptm.c', 'compat/sptm-refs.c',
        'compat/sptm-unmap.c', 'compat/sptm-update.c', 'compat/txm.c', 'compat/sptm-papt.c',
        'compat/sptm-slide.c', 'shadow/shadow.c', 'shadow/mmu.c', 'shadow/sprr-view.c']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--reference-refs', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    if args.verify:
        receipt = json.loads(args.verify.read_text())
        for name, digest in receipt['sources'].items():
            if sha(ROOT/name) != digest:
                raise ValueError(f'source drift: {name}')
        for name, digest in receipt['artifacts'].items():
            if sha(args.verify.parent/name) != digest:
                raise ValueError(f'artifact drift: {name}')
        print(json.dumps(dict(status='VERIFIED', artifacts=len(receipt['artifacts']), sources=len(receipt['sources']))))
        return
    if not args.out or not args.reference_refs:
        parser.error('--out and --reference-refs are required')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    baseline = out/'reference-refs.c'
    baseline.write_bytes(args.reference_refs.read_bytes())
    commands = []

    def run(command, name, env=None):
        command = [str(x) for x in command]
        commands.append(dict(argv=command, cwd=str(ROOT), env=env or {}))
        (out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        with (out/f'{name}.log').open('w') as log:
            result = subprocess.run(command, cwd=ROOT, env={**os.environ, **(env or {})},
                                    stdout=log, stderr=subprocess.STDOUT, timeout=300)
        if result.returncode:
            raise RuntimeError(f'{name}: exit {result.returncode}; see {out/name}.log')

    for mode in ['strict', 'lenient']:
        run(['sh', 'gpu/adreno-kext/plugin/build.sh'], f'build-{mode}',
            dict(OUT=str(out/mode), ADRENO_LENIENT='1' if mode == 'lenient' else ''))
    for name in ['work-accounting', 'plane-layout']:
        run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc',
             '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit',
             '-framework', 'IOSurface', f'gpu/adreno-kext/plugin/harness/{name}.m', '-o', out/name], f'build-{name}')
        run(['codesign', '-f', '-s', '-', out/name], f'sign-{name}')
    for mode in ['strict', 'lenient']:
        run([out/'work-accounting', out/mode/'AdrenoMetal.bundle', out/f'{mode}.json', int(mode == 'lenient')], mode)
        events = []
        for line in (out/f'{mode}.json.trace.log').read_text().splitlines():
            at = line.find('{')
            if at >= 0:
                events.append(json.loads(line[at:]))
        omitted = [event for event in events if event.get('event') == 'omitted']
        summaries = [event for event in events if event.get('event') == 'commit-encoding']
        if len(omitted) != (6 if mode == 'strict' else 316) or len(summaries) != 6:
            raise ValueError(f'{mode}: missing durable work records')
        identities = {(event['command_buffer'], event['ordinal']) for event in omitted}
        if len(identities) != len(omitted):
            raise ValueError(f'{mode}: duplicate work identity')
    run([out/'plane-layout', out/'strict/AdrenoMetal.bundle', out/'planes.json'], 'planes')
    run(['xcrun', 'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
         'tools/replay-adreno-presentation.c', '-o', out/'presentation'], 'build-presentation')
    run([out/'presentation', out], 'presentation')
    run(['sh', 'gpu/adreno-kext/kext/build.sh'], 'build-kext', dict(OUT=str(out/'kext')))
    # The alignment variant runs the same complete lifecycle with a backend
    # returning unaligned host addresses; it exercises the required fallback.
    fixture = (ROOT/'tools/test-sptm-user.c').read_text()
    needle = 'static uint8_t ram[SIZE],before[SIZE];'
    if needle not in fixture:
        raise ValueError('lifecycle fixture changed; review alignment variant')
    (out/'unaligned-fixture.c').write_text(fixture.replace(needle,
        '_Alignas(8) static uint8_t ram_storage[SIZE+1],before[SIZE];\n#define ram (ram_storage+1)'))
    wrapper = (ROOT/'tools/replay-sptm-map-cost.c').read_text()
    (out/'unaligned-replay.c').write_text(wrapper.replace('"test-sptm-user.c"', '"unaligned-fixture.c"'))
    for name in ['before', 'after', 'unaligned-before', 'unaligned-after', 'sanitize-after']:
        directory = out/name
        directory.mkdir()
        source = out/'unaligned-replay.c' if name.startswith('unaligned') else ROOT/'tools/replay-sptm-map-cost.c'
        core = [baseline if c == 'compat/sptm-refs.c' and name.endswith('before') else ROOT/c for c in CORE]
        flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'] if name == 'sanitize-after' else []
        run(['cc', '-std=gnu11', '-Os', '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow',
             *flags, source, *core, '-o', directory/'replay'], f'build-{name}')
        run([directory/'replay', directory], name)
    reference = (out/'before/memory.bin').read_bytes()
    before_report = json.loads((out/'before/monitor-cost.json').read_text())
    for name in ['after', 'unaligned-before', 'unaligned-after', 'sanitize-after']:
        report = json.loads((out/name/'monitor-cost.json').read_text())
        if (out/name/'memory.bin').read_bytes() != reference or report['publications'] != before_report['publications']:
            raise ValueError(f'lifecycle state/publication mismatch: {name}')
    # Balanced order addresses host warmup/order effects. Timings are host-only.
    samples = {'before': [], 'after': []}
    for i, name in enumerate(['before', 'after', 'after', 'before']*2):
        directory = out/f'timing-{i}-{name}'
        directory.mkdir()
        run([out/name/'replay', directory], f'timing-{i}-{name}')
        report = json.loads((directory/'monitor-cost.json').read_text())
        samples[name].extend(report['seconds'])
        if (directory/'memory.bin').read_bytes() != reference:
            raise ValueError('timing replay state drift')
    medians = {key: statistics.median(values) for key, values in samples.items()}
    timing = dict(samples=samples, medians=medians, reduction_percent=100*(1-medians['after']/medians['before']),
                  scope='Host MAP/MAP/UNMAP replay, not A16 monitor hold time or desktop FPS')
    (out/'timing.json').write_text(json.dumps(timing, indent=2)+'\n')
    sources = [p for base in ['compat', 'shadow', 'gpu/adreno-kext'] for p in (ROOT/base).rglob('*')
               if p.is_file() and p.suffix in ('.c', '.cpp', '.h', '.m', '.sh', '.tbd', '.plist') and '/out/' not in str(p)]
    sources += [ROOT/f'tools/{name}' for name in ['qualify-graphics-correctness.py', 'replay-adreno-presentation.c',
                                                'replay-sptm-map-cost.c', 'test-sptm-user.c']]
    receipt = dict(status='OFFLINE_PASS', gpu_submission=False, target_access=False, timing=timing,
                   sources={str(p.relative_to(ROOT)): sha(p) for p in sorted(set(sources))},
                   artifacts={str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
    (out/'qualification.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(dict(status=receipt['status'], reduction_percent=timing['reduction_percent'], receipt=str(out/'qualification.json'))))


if __name__ == '__main__':
    main()
