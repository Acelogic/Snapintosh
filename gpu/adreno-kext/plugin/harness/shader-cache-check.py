#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host qualification of the AdrenoMetal compile-result cache (no GPU work, no A16).

Runs the compile-timing harness (18 recorded CoreAnimation pipelines, public Metal API) against:
  baseline   the reference bundle (no cache), fresh Metal function cache
  miss       candidate, empty record directory: every stage compiles and is stored
  disk       candidate, same record directory: every stage must come from disk
  pack       the same sources rebuilt with the records packed and linked in (build.sh
             ADRENO_SHADER_CACHE_PACK), empty directory; the plain rebuild must equal --bundle
  corrupt    one record with a flipped payload byte and one truncated record: both rejected,
             recompiled and rewritten; a second run hits again
  threads    candidate, empty directory, 3 rounds on 6 threads: one compile per key, the rest wait
             or hit memory
  disabled   candidate with ADRENO_SHADER_CACHE=0
Every candidate pipeline must hand the draw path byte-identical programs, code, sidecars and linkage
to the baseline's. Doc: docs/SHADER-COMPILE-PATH-20260928.md.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import shader_cache_pack as scp  # noqa: E402


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(harness, bundle, spec, out, name, metal_cache, records=None, repeat=1, threads=1, disabled=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith('ADRENO_')}
    if records is not None:
        env['ADRENO_SHADER_CACHE_DIR'] = str(records)
    if disabled:
        env['ADRENO_SHADER_CACHE'] = '0'
    report = out / f'{name}.json'
    argv = [str(harness), str(bundle), str(spec), str(report), str(metal_cache), str(repeat), str(threads)]
    proc = subprocess.run(argv, env=env, capture_output=True, text=True)
    (out / f'{name}.log').write_text(proc.stdout + proc.stderr)
    data = json.loads(report.read_text())
    data['exit_code'] = proc.returncode
    return data


def outputs_by_label(data):
    table = {}
    for row in data['rows']:
        assert row.get('status') == 'COMPILED', (row['label'], row.get('error'))
        table.setdefault(row['label'], []).append(row['outputs'])
    return table


def record_files(root):
    return sorted(p for p in Path(root).rglob('*.amse'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--baseline-bundle', type=Path, required=True)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--spec', type=Path, required=True)
    ap.add_argument('--harness', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    checks, runs = {}, {}

    def check(name, ok, detail=None):
        checks[name] = dict(ok=bool(ok), detail=detail)

    base = runs['baseline'] = run(args.harness, args.baseline_bundle, args.spec, out, 'baseline', out / 'metal-baseline')
    reference = {label: rows[0] for label, rows in outputs_by_label(base).items()}
    check('baseline_compiled', base['exit_code'] == 0 and base['passed'] == len(reference), base['passed'])
    unique = set()
    for rows in outputs_by_label(base).values():
        unique.add(rows[0]['vertexCode.sidecarData'])
        unique.add(rows[0]['fragmentCode.sidecarData'])

    def same_as_reference(name, data):
        table = outputs_by_label(data)
        bad = [label for label, rows in table.items() for o in rows if o != reference[label]]
        check(f'{name}_identical_to_baseline', not bad and set(table) == set(reference), bad)

    records = out / 'records'
    miss = runs['miss'] = run(args.harness, args.bundle, args.spec, out, 'miss', out / 'metal-miss', records)
    same_as_reference('miss', miss)
    stats = miss['shader_cache']
    files = record_files(records)
    check('miss_all_compiled_and_stored', stats['ready'] and stats['misses'] == len(files) and stats['writes'] == len(files)
          and not stats['write_errors'] and not stats['rejects'] and stats['hits_pack'] == stats['hits_disk'] == 0, stats)
    check('miss_duplicates_served_from_memory', stats['hits_memory'] > 0, stats['hits_memory'])

    disk = runs['disk'] = run(args.harness, args.bundle, args.spec, out, 'disk', out / 'metal-miss', records)
    same_as_reference('disk', disk)
    stats = disk['shader_cache']
    check('disk_no_compile', stats['misses'] == 0 and stats['hits_disk'] == len(files) and not stats['rejects']
          and not stats['writes'], stats)
    check('disk_no_compiler_service', disk['compiler_services_started'] == [], disk['compiler_services_started'])

    namespace, = {p.parent.parent for p in files}
    pack_path = out / 'AdrenoShaderCache.amsp'
    packed = subprocess.run([sys.executable, str(HERE.parent / 'shader_cache_pack.py'), 'build', '--records', str(namespace),
                             '--output', str(pack_path)], capture_output=True, text=True)
    (out / 'pack-build.log').write_text(packed.stdout + packed.stderr)
    check('pack_built', packed.returncode == 0, packed.stdout.strip())
    builds = {}
    for name, pack in (('plain-build', None), ('pack-build', pack_path)):
        env = {k: v for k, v in os.environ.items() if not k.startswith('ADRENO_')}
        env.update(OUT=str(out / name), ADRENO_COMPILER_RUNTIME=str(args.bundle / 'Contents/Frameworks'))
        if pack:
            env['ADRENO_SHADER_CACHE_PACK'] = str(pack)
        built = subprocess.run(['sh', str(HERE.parent / 'build.sh')], env=env, capture_output=True, text=True)
        (out / f'{name}.log').write_text(built.stdout + built.stderr)
        builds[name] = out / name / 'AdrenoMetal.bundle'
        check(f'{name}_succeeded', built.returncode == 0, built.returncode)
    check('candidate_rebuilds_from_these_sources', sha(builds['plain-build'] / 'Contents/MacOS/AdrenoMetal') ==
          sha(args.bundle / 'Contents/MacOS/AdrenoMetal'))
    bundle2 = builds['pack-build']
    verified = subprocess.run(['codesign', '--verify', '--strict', str(bundle2)], capture_output=True, text=True)
    sections = subprocess.run(['otool', '-l', str(bundle2 / 'Contents/MacOS/AdrenoMetal')], capture_output=True, text=True).stdout
    check('pack_bundle_signed_with_section', verified.returncode == 0 and 'sectname __shadercache' in sections
          and f'size 0x{pack_path.stat().st_size:016x}' in sections, verified.stderr)
    pack = runs['pack'] = run(args.harness, bundle2, args.spec, out, 'pack', out / 'metal-pack', out / 'records-pack')
    same_as_reference('pack', pack)
    stats = pack['shader_cache']
    check('pack_no_compile', stats['misses'] == 0 and stats['hits_pack'] == len(files) and not stats['rejects']
          and not stats['writes'] and not record_files(out / 'records-pack'), stats)

    corrupt = out / 'records-corrupt'
    shutil.copytree(records, corrupt)
    victims = sorted(record_files(corrupt), key=lambda p: p.stat().st_size)
    flipped, truncated = victims[-1], victims[0]
    data = bytearray(flipped.read_bytes())
    data[-1] ^= 0x40
    flipped.write_bytes(bytes(data))
    truncated.write_bytes(truncated.read_bytes()[:-1])
    first = runs['corrupt'] = run(args.harness, args.bundle, args.spec, out, 'corrupt', out / 'metal-miss', corrupt)
    same_as_reference('corrupt', first)
    stats = first['shader_cache']
    check('corrupt_records_rejected_and_rewritten', stats['rejects'] == 2 and stats['misses'] == 2 and stats['writes'] == 2, stats)
    again = runs['corrupt_again'] = run(args.harness, args.bundle, args.spec, out, 'corrupt-again', out / 'metal-miss', corrupt)
    same_as_reference('corrupt_again', again)
    stats = again['shader_cache']
    check('corrupt_rewritten_records_hit', stats['misses'] == 0 and not stats['rejects'], stats)
    for p in (flipped, truncated):
        scp.parse_record(p.read_bytes(), p.stem.encode())

    threads = runs['threads'] = run(args.harness, args.bundle, args.spec, out, 'threads', out / 'metal-threads',
                                    out / 'records-threads', repeat=3, threads=6)
    same_as_reference('threads', threads)
    stats = threads['shader_cache']
    check('threads_compiled_and_consistent', threads['exit_code'] == 0 and threads['passed'] == 3 * len(reference)
          and not stats['write_errors'] and not stats['rejects'], stats)
    check('threads_one_compile_per_key', stats['misses'] == stats['writes'] == len(files)
          and len(record_files(out / 'records-threads')) == len(files), stats)

    disabled = runs['disabled'] = run(args.harness, args.bundle, args.spec, out, 'disabled', out / 'metal-disabled',
                                      out / 'records-disabled', disabled=True)
    same_as_reference('disabled', disabled)
    check('disabled_is_inert', not disabled['shader_cache']['ready'] and not record_files(out / 'records-disabled'),
          disabled['shader_cache'])

    timing = {name: dict(plugin_ms=round(sum(r.get('plugin_ms', 0) for r in data['rows']), 1),
                         pipelines_wall_ms=round(data['pipelines_wall_ms'], 1),
                         compiler_services=data['compiler_services_started'], shader_cache=data.get('shader_cache'))
              for name, data in runs.items()}
    summary = dict(status='PASS' if all(c['ok'] for c in checks.values()) else 'FAIL', checks=checks, timing=timing,
                   records=len(files), unique_sidecars=len(unique),
                   inputs_sha256={str(p): sha(p) for p in (args.spec, args.harness,
                                  args.baseline_bundle / 'Contents/MacOS/AdrenoMetal', args.bundle / 'Contents/MacOS/AdrenoMetal',
                                  args.bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib', pack_path)},
                   boundary='Host Metal/plug-in compile path only; no command buffers, no Adreno execution, no A16.')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(status=summary['status'], failed=[k for k, c in checks.items() if not c['ok']],
                          timing={k: v['plugin_ms'] for k, v in timing.items()})))
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
