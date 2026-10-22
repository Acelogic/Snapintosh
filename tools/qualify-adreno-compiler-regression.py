#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare candidate and baseline compilers on all pinned A16 render stages."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / 'gpu/air2ir3'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    baseline, out = args.baseline.resolve(), args.output.resolve()
    assert not out.exists()
    out.mkdir(parents=True)
    candidate = COMPILER / 'build/air2ir3'
    pinned_path = COMPILER / 'tools/a16ref/render-shaders.pinned.json'
    pinned = json.loads(pinned_path.read_text())
    inputs = {str(p): sha(p) for p in [baseline, candidate, pinned_path, Path(__file__)]}
    rows = []
    record = dict(status='RUNNING', started=time.time(), inputs_sha256=inputs, stages=rows,
        boundary='Compiler regression over previously pinned A16 shaders; no new hardware execution.')
    try:
        for name in pinned['order']:
            pipeline = pinned['pipelines'][name]
            for stage in ['vs', 'fs']:
                entry = pipeline[stage + '_function']
                module = (COMPILER / 'tools/a16ref/probes.air' if pipeline['lib'] == 'Probe'
                    else COMPILER / 'corpus' / pipeline['lib'] / (entry + '.bc'))
                inputs[str(module)] = sha(module)
                row = dict(pipeline=name, stage=stage, entry=entry, module=str(module), commands=[])
                rows.append(row)
                hashes = []
                for tag, binary in [('baseline', baseline), ('candidate', candidate)]:
                    stem = name + '.' + stage + '.' + tag
                    blob = out / (stem + '.ir3v')
                    command = [str(binary), *pipeline['compile'][stage]['args'],
                        '--variant', str(blob), '--json', str(out / (stem + '.json')), str(module)]
                    log_path = out / (stem + '.log')
                    with log_path.open('x') as log:
                        completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
                    row['commands'].append(dict(command=command, exit_code=completed.returncode,
                        log=log_path.name))
                    assert completed.returncode == 0, row
                    hashes.append(sha(blob))
                row.update(baseline_sha256=hashes[0], candidate_sha256=hashes[1],
                    matches_baseline=hashes[0] == hashes[1],
                    matches_historical_pin=hashes[1] == pipeline['compile'][stage]['blob_sha256'])
                assert row['matches_baseline'], row
        for name, digest in inputs.items(): assert sha(Path(name)) == digest, name
        record['status'] = 'ALL_PINNED_STAGES_MATCH_BASELINE'
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.iterdir() if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], stages=len(rows))))


if __name__ == '__main__':
    main()
