#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the early-stop monitor exactly as the current one is built, and record it.

Same compiler, linker script and build_defines as the booted SKS monitor
340bae8f (build/sks-transport-candidate-20260928-v2, from runtime root
Snapintosh-adreno-sks at 23c583f); only this checkout's sources differ. No
hardware access: it compiles, measures and writes qualification.json.

    python3 tools/build-early-stop-candidate.py --output-dir build/early-stop-candidate-20260928-v1 \
        --flags-from ../Snapintosh/build/sks-transport-candidate-20260928-v2/qualification.json
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import runpy
import subprocess
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--flags-from', type=Path, required=True,
                    help="a monitor qualification.json whose 'flags' are the booted build_defines")
    args = ap.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=False, exist_ok=False)
    reference = json.loads(args.flags_from.read_text())
    runner = runpy.run_path(str(ROOT / 'probes/run.py'))
    runner['FLAGS'][:] = reference['flags']
    reservation = runner['OUT_AT'] - runner['CODE_AT']
    record = dict(status='RUNNING', hardware_access=False, runtime_root=str(ROOT),
                  flags=runner['FLAGS'], flags_from=str(args.flags_from.resolve()),
                  flags_from_sha256=sha(args.flags_from), reference_monitor=reference.get('monitor'))
    try:
        payload = runner['build']('xnuboot', out / 'monitor')
        binary = out / 'monitor/xnuboot.bin'
        record['monitor'] = dict(path=str(binary), bytes=len(payload), sha256=sha(binary),
                                 code_reservation=reservation, headroom=reservation - len(payload))
        if len(payload) > reservation:
            raise ValueError(f'{len(payload)} bytes exceed the {reservation}-byte code reservation')
        command = [str(runner['LLVM'] / 'clang'), *runner['FLAGS'], '-I' + str(ROOT / 'shadow'),
                   '-I' + str(ROOT.parent / 'q1n1/platform/uefi'), '-Xclang', '-fdump-record-layouts',
                   '-fsyntax-only', str(ROOT / 'probes/xnuboot.c')]
        result = subprocess.run(command, text=True, capture_output=True)
        (out / 'layout.txt').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise ValueError(result.stderr)
        context = next(b for b in result.stdout.split('*** Dumping AST Record Layout')
                       if re.search(r'^\s*0 \| struct context\s*$', b, re.M))
        params = next(b for b in result.stdout.split('*** Dumping AST Record Layout')
                      if re.search(r'^\s*0 \| struct params\s*$', b, re.M))
        def field(block, name):
            return int(re.search(r'^\s*(\d+) \|   \S.* ' + name + r'$', block, re.M)[1])
        record.update(
            context_bytes=int(re.search(r'\[sizeof=(\d+),', context)[1]),
            context_early_stop_offset=field(context, 'early_stop'),
            context_sep_sks_request_offset=field(context, 'sep_sks_request'),
            params_bytes=int(re.search(r'\[sizeof=(\d+),', params)[1]),
            params_early_stop_offset=field(params, 'early_stop'),
            layout_sha256=sha(out / 'layout.txt'))
        sources = {ROOT / p for p in runner['MULTI']['xnuboot']}
        sources.update(p for p in (ROOT / 'compat').glob('*.h'))
        sources.update(p for p in (ROOT / 'shadow').glob('*.h'))
        sources.update([Path(__file__), ROOT / 'probes/run.py', ROOT / 'probes/probe.ld',
                        ROOT / 'probes/xnuboot.py', ROOT / 'tools/early_stop.py', args.flags_from.resolve()])
        sources.update(q for p in list(sources) if p.suffix == '.c' for q in source_files(p))
        record['inputs_sha256'] = {str(p.resolve()): sha(p) for p in sorted(sources)}
        record.update(status='EARLY_STOP_MONITOR_BUILT',
                      boundary='Current SKS monitor flags and sources plus compat/early-stop.c and its '
                               'appended params/context/report fields. No hardware upload or execution.')
    except Exception as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], monitor=record.get('monitor'),
                          qualification=str(out / 'qualification.json'),
                          sha256=sha(out / 'qualification.json'))))


if __name__ == '__main__':
    main()
