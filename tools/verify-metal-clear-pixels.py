#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind actual guest clear readback to the stopped A16 command stream.

Failure inventory: docs/METAL-CLEAR-USAGE-20260927.md. No hardware access,
no reference pixels are presented, and no claim of shader drawing or GUI.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
digest = lambda data: hashlib.sha256(data).hexdigest()
sha = lambda path: digest(Path(path).read_bytes())
read = lambda path: json.loads(Path(path).read_text())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--inspection', type=Path, required=True)
    ap.add_argument('--inspection-source', type=Path, required=True)
    ap.add_argument('--snapshot', type=Path, required=True)
    ap.add_argument('--deployment', type=Path, required=True)
    ap.add_argument('--report', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    assert args.prefix == 'installed-metal-clear-usage-3600s-20260927'
    assert not args.output.exists()
    inputs = {}

    def bound(path):
        path = Path(path).resolve()
        inputs[str(path)] = sha(path)
        return read(path)

    path = lambda suffix: ROOT / 'build' / (args.prefix + suffix)
    verified = bound(path('-pre-reset-verification.json'))
    assert verified['status'] == 'CLEAR_USAGE_STOPPED_CAPTURES_VERIFIED'
    assert verified['generation'] == 46 and verified['gpu_fault_free']
    for suffix, expected in verified['artifacts_sha256'].items():
        assert sha(path(suffix)) == expected, suffix
    launch, ring, adoption = [bound(path(s)) for s in ('-launch.json', '-gpu-ring.json', '-adopt.json')]
    assert ring['generation'] == adoption['stage_generation'] == 46
    assert ring['launch_sha256'] == sha(path('-launch.json'))
    assert ring['monitor_sha256'] == launch['monitor_sha256'] == verified['monitor_sha256']
    assert ring['adoption_sha256'] == sha(path('-adopt.json'))
    assert ring['repeated_reads_equal'] and not ring['writes'] and not ring['mmio_access']
    assert not ring['gpu']['faults'] and not ring['gpu']['fence_error']
    inspection, snapshot, deployment, report = [bound(p) for p in
        (args.inspection, args.snapshot, args.deployment, args.report)]
    assert inspection['status'] == 'READ_ONLY_REPORT_INSPECTION_COMPLETE'
    assert inspection['image_stat'] == inspection['image_stat_after']
    assert inspection['detach'] and not any(x['exit_code'] for x in inspection['detach'])
    assert inspection['mounts'] and not any(x['writable'] for x in inspection['mounts'])
    assert args.inspection_source.resolve().parent == ROOT / 'build'
    assert inspection['source_sha256'] == sha(args.inspection_source)
    inputs[str(args.inspection_source.resolve())] = sha(args.inspection_source)
    assert inspection['snapshot_sha256'] == sha(args.snapshot)
    assert snapshot['result'] == 'PASS' and snapshot['generation'] == 47
    assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
    assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
    assert not any(snapshot['serror'].values())
    assert launch['qualification_sha256'] == sha(args.deployment)
    assert inspection['files'] and all(x['matches'] for x in inspection['files'])
    installed = {x['path'].lstrip('/'): x['sha256'] for x in inspection['files']}
    intended = {x['destination'].lstrip('/'): x['sha256'] for x in deployment['installs']}
    assert installed == intended
    copied = {Path(x['copy']).resolve(): x for x in inspection['reports']}

    def extracted(p):
        p = Path(p).resolve()
        entry = copied[p]
        data = p.read_bytes()
        assert len(data) == entry['bytes'] and digest(data) == entry['sha256']
        inputs[str(p)] = digest(data)
        return data

    extracted(args.report)
    assert report['schema'] == 'snapintosh-metal-clear-probe/1'
    assert report['stage'] == 'finished'
    assert report['result'] == 'METAL_TEXTURE_CLEAR_COMPLETED_PIXELS_VERIFIED'
    assert report['image_produced'] and not report['screen_presented']
    assert report['command_status'] == 4 and not report['command_error']
    assert report['mismatches'] == 0 and report['changed_bytes'] == 37 * 23 * 4
    assert report['allocation_length'] == 32768 and report['width'] == 37
    assert report['height'] == 23 and report['row_bytes'] == 1024
    assert report['pixel_pattern'] == 0xff4080bf
    plugin = next(x for x in inspection['files']
                  if x['path'].endswith('/Contents/MacOS/AdrenoMetal'))
    assert report['plugin_sha256'] == report['expected_plugin_sha256'] == plugin['sha256']
    stem = 'metal-clear-probe-' + report['run_id']
    assert args.report.name == stem + '.json'
    console = path('-console-tail.txt').read_text()
    assert stem + '.json' in console and 'finished result=METAL_TEXTURE_CLEAR_COMPLETED_PIXELS_VERIFIED' in console
    before, after, pixels = [extracted(args.report.parent / (stem + suffix))
                             for suffix in ('-before.bin', '-after.bin', '-pixels.bgra')]
    assert digest(before) == report['before_sha256'] and before == b'\x69' * 32768
    assert digest(after) == report['after_sha256'] and len(after) == 32768
    assert digest(pixels) == report['image_sha256'] and len(pixels) == 37 * 23 * 4
    pixel = struct.pack('<I', report['pixel_pattern'])
    expected = bytearray(before)
    rows = []
    for y in range(23):
        expected[y * 1024:y * 1024 + 148] = pixel * 37
        rows.append(after[y * 1024:y * 1024 + 148])
    assert after == expected and pixels == b''.join(rows)
    raw = path('-gpu-ring.bin').read_bytes()
    assert digest(raw) == ring['ring_sha256'] and len(raw) == ring['ring_bytes']
    assert sha(path('-gpu-fence.bin')) == ring['fence_sha256']
    words = struct.unpack('<' + str(len(raw) // 4) + 'I', raw)
    begin, end = adoption['ring']['wptr'], ring['gpu']['wptr']
    assert 0 <= begin < end <= len(words)
    packets = []
    at = begin
    while at < end:
        header = words[at]
        count = header & 0x7fff
        assert header == (0x703d0000 | count | (((count.bit_count() ^ 1) & 1) << 15))
        assert count >= 3 and at + count + 1 <= end
        address = words[at + 1] | (words[at + 2] << 32)
        payload = list(words[at + 3:at + 1 + count])
        packets.append(dict(word=at, address=address, data=payload))
        at += count + 1
    assert at == end
    fills = [(i, p) for i, p in enumerate(packets) if len(p['data']) == 37]
    assert len(fills) == 23
    first = fills[0][1]['address']
    for row, (i, p) in enumerate(fills):
        assert p['address'] == first + row * 1024 and p['data'] == [report['pixel_pattern']] * 37
        completion = packets[i + 1]
        assert completion['address'] == adoption['fence']['va']
        assert completion['data'] == [0x534e6000 ^ (row + 2)]
    assert ring['fence_value'] == (0x534e6000 ^ 24)
    assert all(len(p['data']) in (1, 37) for p in packets)
    assert all(not first <= p['address'] < first + 23 * 1024
               for p in packets if len(p['data']) == 1)
    assert ring['gpu']['fences'] >= 24
    for filename, expected_hash in inputs.items():
        assert sha(filename) == expected_hash
    result = dict(status='GUEST_METAL_CLEAR_PIXELS_AND_GPU_PACKETS_VERIFIED',
        prefix=args.prefix, generation=46, run_id=report['run_id'], width=37, height=23,
        source_sha256=sha(__file__), inputs_sha256=inputs,
        pixel_path=str((args.report.parent / (stem + '-pixels.bgra')).resolve()),
        pixel_sha256=digest(pixels), allocation_sha256=digest(after),
        fill_rows=23, destination_iova=first, gpu=ring['gpu'],
        gpu_packets=packets, screen_presented=False,
        boundary='Guest public Metal clear plus exact readback and matching physical GPU writes. No shader draw, WindowServer frame or panel presentation is established.')
    with args.output.open('x') as output:
        json.dump(result, output, indent=2); output.write('\n')
    print(json.dumps(dict(status=result['status'], run_id=report['run_id'], sha256=sha(args.output))))


if __name__ == '__main__':
    main()
