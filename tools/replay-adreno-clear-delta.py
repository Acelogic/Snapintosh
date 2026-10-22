#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the clear delta and rollback over its complete fresh main snapshot."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--original-root', type=Path, required=True)
    ap.add_argument('--snapshot', type=Path, required=True)
    ap.add_argument('--payload', type=Path, required=True)
    ap.add_argument('--package-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    original, snapshot_path, payload = args.original_root.resolve(), args.snapshot.resolve(), args.payload.resolve()
    package_path = payload / 'package.json'
    assert sha(package_path) == args.package_sha256
    package = json.loads(package_path.read_text())
    assert package['result'] == 'PACKAGED_LOCAL_ONLY' and not package['ssd_writes']
    assert package['source_sha256'] == sha(ROOT / 'tools/package-adreno-clear.py')
    for name, digest in package['binding_inputs_sha256'].items(): assert sha(Path(name)) == digest
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot['result'] == 'PASS' and snapshot['generation'] == 45
    assert sha(snapshot_path) == package['binding_inputs_sha256'][str(snapshot_path)]
    base = original / 'build/replay-installed-metal-delta-20260926.py'
    base_sha = 'd53eebb204e177b272d3f9b9ae1e36cc51b60fdb5a4f4ad5c15099739516a321'
    assert sha(base) == base_sha
    changes = {
        'ROOT = Path(__file__).resolve().parents[1]': f'ROOT = Path({str(original)!r})',
        "BASE / 'snapshot-v1/snapshot.json'": f'Path({str(snapshot_path)!r})',
        "BASE / 'snapshot-v1/header.bin'": f'Path({str(snapshot_path.parent / "header.bin")!r})',
        "BASE / 'snapshot-v1/current.img'": f'Path({snapshot["image"]!r})',
        'baseline_snapshot_sha256=sha(snapshot_raw))':
            f'baseline_snapshot_sha256=sha(snapshot_raw), base_source_sha256={base_sha!r})',
    }
    source = base.read_text()
    for old, new in changes.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    sys.argv = [str(Path(__file__)), '--payload', str(payload), '--package-sha256', args.package_sha256,
                '--output', str(args.output.resolve())]
    exec(compile(source, str(base), 'exec'), dict(__file__=str(Path(__file__).resolve()), __name__='__main__'))


if __name__ == '__main__':
    main()
