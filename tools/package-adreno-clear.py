#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the existing delta algorithm to fresh clear-stage and ISC evidence."""
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
    ap.add_argument('--normalization', type=Path, required=True)
    ap.add_argument('--isc', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    original = args.original_root.resolve()
    snapshot_path, norm_path, isc_path = args.snapshot.resolve(), args.normalization.resolve(), args.isc.resolve()
    snapshot, norm, isc = [json.loads(p.read_text()) for p in (snapshot_path, norm_path, isc_path)]
    assert snapshot['result'] == 'PASS' and snapshot['generation'] == 45
    assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
    assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
    assert norm['status'] == 'CLEAR_STAGE_NORMALIZED_LOCAL_ONLY' and not norm['ssd_writes']
    assert norm['verified_bytes'] == 64 << 30
    assert norm['source_sha256'] == sha(ROOT / 'tools/normalize-adreno-clear-stage.py')
    stage_path = Path(norm['original_stage'])
    assert sha(stage_path) == norm['original_stage_sha256']
    stage = json.loads(stage_path.read_text())
    assert stage['status'] == 'CLEAR_FILES_STAGED_LOCAL_ONLY' and stage['generation'] == 45
    assert not stage['ssd_writes'] and stage['seed_stat'] == stage['seed_stat_after']
    assert stage['source_sha256'] == sha(ROOT / 'tools/stage-adreno-clear-image.py')
    assert stage['snapshot_sha256'] == sha(snapshot_path)
    assert stage['detach'] and not any(x['exit_code'] for x in stage['detach'])
    for name, h in stage['inputs_sha256'].items(): assert sha(Path(name)) == h, name
    assert isc['result'] == 'PASS' and isc['generation'] == isc['bootinfo']['stage_generation'] == 45
    assert not isc['ssd_writes'] and isc['native_host_equal']
    assert isc['snapshot_sha256'] == sha(snapshot_path)
    assert isc['source_sha256'] == sha(original / 'build/capture-metal-raw-sign-isc-20260927.py')
    assert isc['edges_unchanged'] and isc['checkpoints_unchanged']
    assert not any(isc['serror'].values()) and not any(snapshot['serror'].values())
    assert isc['header_sha256'] == snapshot['header_sha256']
    assert isc['isc_bytes'] == 268435456 and isc['zero_tail_bytes'] == 268435456
    assert isc['shutdown'] == ['normal shutdown, CSTS 0x9', 'CC.EN 0, CSTS 0x0']
    assert snapshot['shutdown'] == isc['shutdown']
    for name, h in isc['sources'].items(): assert sha(original.parent / 'q1n1' / name) == h
    isc_image = isc_path.parent / 'isc.apfs'
    assert isc_image.stat().st_size == isc['isc_bytes'] and sha(isc_image) == isc['isc_sha256']
    before, after = Path(snapshot['image']), Path(norm['image'])
    assert before == Path(stage['seed']) == Path(norm['seed'])
    assert Path(stage['image']) == Path(norm['original_image'])
    old_window = json.loads((original / 'build/full-install/m5-payload/window.json').read_text())
    def current_window(window):
        assert window == old_window
        assert window['layout']['isc_image'] == isc['isc_bytes']
        assert window['isc']['zero_tail_sha256'] == isc['zero_tail_sha256']
        window['isc'] = dict(file=str(isc_image), sha256=isc['isc_sha256'], zero_tail_sha256=isc['zero_tail_sha256'])
        return window
    base = original / 'build/package-installed-metal-20260926.py'
    base_sha = 'd81a81c5bb32b30c08047d26446202288e2106de5bac8245e4b41df2981f1213'
    assert sha(base) == base_sha
    bindings = {str(p): sha(p) for p in (snapshot_path, norm_path, isc_path, stage_path,
        ROOT / 'tools/normalize-adreno-clear-stage.py', ROOT / 'tools/stage-adreno-clear-image.py',
        original / 'build/capture-metal-raw-sign-isc-20260927.py', base)}
    old_checks = """    assert stage['result'] == 'STAGED_LOCAL_ONLY' and stage['owner_enforcement']
    assert stage['snapshot_sha256'] == digest(snapshot_raw)
    assert stage['backing_image'] == str(AFTER)
    assert stage['volume_uuid'] == '501065D4-E49E-4DDA-B4E7-056CA04D4B90'
    assert stage['build_sha256'] == digest((BASE / 'plugin-v2/build.json').read_bytes())"""
    new_checks = """    assert stage['status'] == 'CLEAR_STAGE_NORMALIZED_LOCAL_ONLY'
    assert stage['image'] == str(AFTER) and stage['seed'] == str(BEFORE)
    assert stage['image_stat'] == list(stats[1]) and stage['seed_stat'] == list(stats[0])
    assert stage['verified_bytes'] == 64 << 30 and not stage['ssd_writes']
    for filename, expected in binding_inputs.items():
        assert digest(Path(filename).read_bytes()) == expected, filename"""
    changes = {
        'ROOT = Path(__file__).resolve().parents[1]': f'ROOT = Path({str(original)!r})',
        "BEFORE = BASE / 'snapshot-v1/current.img'": f'BEFORE = Path({str(before)!r})',
        "AFTER = BASE / 'stage-v1/staged.img'": f'AFTER = Path({str(after)!r})',
        "BASELINE = 'd4ca5d44cc2514ab5402e05dc016c21470ea07f17c7d362d55620433c850786a'":
            f'BASELINE = {snapshot["container_sha256"]!r}',
        "window = json.loads((M5 / 'window.json').read_bytes())":
            "window = current_window(json.loads((M5 / 'window.json').read_bytes()))",
        "BASE / 'snapshot-v1/snapshot.json'": f'Path({str(snapshot_path)!r})',
        "snapshot['generation'] == 37": "snapshot['generation'] == 45",
        "BASE / 'snapshot-v1/header.bin'": f'Path({str(snapshot_path.parent / "header.bin")!r})',
        "BASE / 'stage-v1/stage.json'": f'Path({str(norm_path)!r})',
        old_checks: new_checks,
        'baseline_snapshot_sha256=digest(snapshot_raw), baseline_header_sha256=old_header_sha,':
            'baseline_snapshot_sha256=digest(snapshot_raw), baseline_header_sha256=old_header_sha, baseline_isc_capture_sha256=isc_binding,',
        'ssd_writes=False, replay_qualified=False,':
            'ssd_writes=False, replay_qualified=False, binding_inputs_sha256=binding_inputs, base_source_sha256=base_source_sha,',
        "assert 0 < packed <= MAX_DELTA and extents":
            "assert 0 < packed <= MAX_DELTA and extents\n    assert newhash.hexdigest() == normalized_main_hash",
    }
    source = base.read_text()
    for old, new in changes.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    sys.argv = [str(Path(__file__)), '--output', str(args.output.resolve())]
    exec(compile(source, str(base), 'exec'), dict(__file__=str(Path(__file__).resolve()),
        __name__='__main__', current_window=current_window, isc_binding=sha(isc_path),
        binding_inputs=bindings, base_source_sha=base_sha, normalized_main_hash=norm['main_sha256']))


if __name__ == '__main__':
    main()
