#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently compare triangle readback, presentation and captured panel bytes.

Failure inventory: docs/ADRENO-GUI-INTEGRATION-20260927.md. This is an offline
artifact verifier; host fixtures never qualify A16 execution or presentation.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/adreno-gui-integration-20260927'
BUILD_SHA = '7883935467f53f80a918a718a529b482e6525773528abcce785e207d92cb0a2d'
DEPLOY_SHA = '53eac4ddc76738a1ea42dc97dda56f0d3515c936bb505458787ce9a91220247a'
MONITOR_SHA = '0e34c699771461a6e1c15fdaad20a55939d3135ebece8846feba6cfa41f2c07f'
PROFILE = 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            h.update(data)
    return h.hexdigest()


def signature(path):
    s = Path(path).stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def guest_path(value):
    p = PurePosixPath(value)
    assert '..' not in p.parts and p.is_absolute(), value
    name = str(p).lstrip('/')
    return 'private/' + name if name.startswith('var/') else name


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host-reference', action='store_true')
    ap.add_argument('--launch', type=Path)
    ap.add_argument('--captures', type=Path)
    ap.add_argument('--snapshot', type=Path)
    ap.add_argument('--inspection', type=Path)
    ap.add_argument('--inspection-source', type=Path)
    ap.add_argument('--report', type=Path)
    ap.add_argument('--output', type=Path, required=True, help='new evidence directory')
    args = ap.parse_args()
    hardware_args = (args.launch, args.captures, args.snapshot, args.inspection,
                     args.inspection_source, args.report)
    if args.host_reference:
        assert not any(hardware_args), 'host reference mode does not accept A16 evidence'
    else:
        assert all(hardware_args), 'A16 mode requires the complete stopped/persisted evidence chain'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    record = dict(status='RUNNING', started=time.time(), inputs_sha256={},
        source_sha256=sha(__file__), a16_access=False, a16_shader_pixels_verified=False,
        panel_framebuffer_matches=False, physical_panel_observed=False, desktop=False)

    def bind(path, wanted=None):
        path = Path(path).resolve()
        h = sha(path)
        if wanted is not None:
            assert h == wanted, path
        record['inputs_sha256'][str(path)] = h
        return path

    def read(path, wanted=None):
        return json.loads(bind(path, wanted).read_text())

    result = 1
    try:
        build_path = BASE / 'triangle-probe-v2/build.json'
        build = read(build_path, BUILD_SHA)
        assert build['status'] == 'GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16'
        for name, digest in build['inputs_sha256'].items():
            bind(name, digest)
        draw_path = Path(build['draw_qualification'])
        draw = read(draw_path, build['draw_qualification_sha256'])
        golden_path = draw_path.parent / 'golden-plan-v2-clear.json'
        assert golden_path.name in draw['artifacts_sha256']
        golden = read(golden_path, draw['artifacts_sha256'][golden_path.name])
        pixels_path = Path(golden['out']) / 'golden.bgra'
        golden_bytes = bind(pixels_path, golden['artifacts']['golden.bgra']['sha256']).read_bytes()
        assert sha(pixels_path) == build['golden_sha256'] == draw['goldens']['plan-v2-clear']['sha256']
        assert len(golden_bytes) == 3404 and len({golden_bytes[i:i+4] for i in range(0, 3404, 4)}) == 2
        panel_path = None
        if args.host_reference:
            report_path = bind(build['host_report'], build['host_report_sha256'])
            report = read(report_path)
            assert report['host_reference'] and report['result'] == 'HOST_METAL_TRIANGLE_REFERENCE_MATCHED'

            def resolve(value, digest):
                p = Path(value).resolve()
                relative = str(p.relative_to(build_path.parent.resolve()))
                assert build['artifacts_sha256'][relative] == digest
                return bind(p, digest)
        else:
            launch = read(args.launch)
            assert args.launch.name.endswith('-launch.json')
            prefix = args.launch.name[:-len('-launch.json')]
            assert launch.get('finished') and launch['exit_code'] in (0, 6, 7, 9)
            try:
                os.kill(launch['pid'], 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('launcher still present')
            assert launch['guest_profile'] == PROFILE and launch['monitor_sha256'] == MONITOR_SHA
            assert launch['context_fields'] == 216 and launch['context_bytes'] == 5108352
            for name, digest in launch['source_sha256'].items():
                bind(name, digest)
            captures = read(args.captures)
            assert captures['status'] == 'GUI_STOPPED_CAPTURES_VERIFIED'
            generation = launch['adreno_record']['stage_generation']
            assert captures['generation'] == generation == 49
            assert captures['monitor_sha256'] == MONITOR_SHA and captures['gpu_fault_free']
            gpu = captures['gpu']
            assert gpu['ib_submits'] > 0 and gpu['ib_dwords'] >= 1080
            assert not any(gpu[x] for x in ('faults', 'fence_error', 'ib_errors', 'serrors'))
            for suffix, digest in captures['artifacts_sha256'].items():
                assert suffix.startswith(('-', '.')) and '/' not in suffix
                bind(args.launch.parent / (prefix + suffix), digest)
            assert captures['artifacts_sha256']['-launch.json'] == sha(args.launch)
            panel_path = args.launch.parent / (prefix + '-panel.png')
            bind(panel_path, captures['artifacts_sha256']['-panel.png'])
            snapshot = read(args.snapshot)
            assert snapshot['result'] == 'PASS' and snapshot['generation'] == generation + 1
            assert snapshot['completed_bytes'] == snapshot['container_bytes'] == 62826479616
            assert snapshot['edges_unchanged'] and snapshot['checkpoints_unchanged']
            assert not any(snapshot['serror'].values())
            assert snapshot['header_sha256'] == launch['expected_window_header_sha256']
            assert snapshot['shutdown'] == ['normal shutdown, CSTS 0x9', 'CC.EN 0, CSTS 0x0']
            inspection = read(args.inspection)
            assert inspection['status'] == 'READ_ONLY_REPORT_INSPECTION_COMPLETE'
            assert inspection['snapshot_sha256'] == sha(args.snapshot)
            bind(args.inspection_source, inspection['source_sha256'])
            assert inspection['image'] == snapshot['image']
            assert signature(snapshot['image']) == inspection['image_stat'] == inspection['image_stat_after']
            assert inspection['detach'] and not any(x['exit_code'] for x in inspection['detach'])
            assert not any(x['writable'] for x in inspection['mounts'])
            deployment = read(BASE / 'deployment-v1/deployment.json', DEPLOY_SHA)
            installed = {x['path']: x for x in inspection['files']}
            for row in deployment['installs']:
                found = installed[guest_path(row['destination'])]
                assert found['matches'] and found['sha256'] == row['sha256']
            copies = {x['path']: x for x in inspection['reports']}
            assert len(copies) == len(inspection['reports'])
            for row in copies.values():
                copied = Path(row['copy']).resolve()
                assert copied.is_relative_to(args.inspection.resolve().parent / 'evidence')
                assert copied.stat().st_size == row['bytes']
                bind(copied, row['sha256'])
            report_path = args.report.resolve()
            rows = [x for x in copies.values() if Path(x['copy']).resolve() == report_path]
            assert len(rows) == 1
            report = read(report_path, rows[0]['sha256'])
            assert not report['host_reference']
            assert report['plugin_sha256'] == report['expected_plugin_sha256'] == build['plugin_sha256']
            assert guest_path(report['plugin_path']) == 'Library/GPUBundles/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal'
            assert any(x['class'] == 'AdrenoMTLDevice' and x['registry_id'] == report['registry_id']
                       for x in report['devices'])
            # A completed probe may already have exited. Bind its UUID to this
            # stopped boot's console evidence rather than requiring a live PID.
            assert any('report=' in marker and report['run_id'] + '.json' in marker
                       for marker in captures['triangle_probe_markers'])
            names = {'metal-triangle-probe', 'metal-triangle-p', 'metal-triangle-', 'metal-triangle'}
            record['probe_pid_seen_at_stop'] = any(pid == report['pid'] and name in names
                for pid, name in captures['process_inventory'])
            record['generation'] = generation
            record['gpu_ib_submits'] = gpu['ib_submits']
            record['gpu_ib_dwords'] = gpu['ib_dwords']

            def resolve(value, digest):
                row = copies[guest_path(value)]
                assert row['sha256'] == digest
                return bind(row['copy'], digest)

        assert report['schema'] == 'snapintosh-metal-triangle-probe/1'
        assert report['width'] == 37 and report['height'] == 23
        assert report['row_bytes'] == 1024 and report['allocation_length'] == 32768
        assert report['pixel_rgb_tolerance'] == 1 and report['golden_sha256'] == build['golden_sha256']
        assert report['command_status'] == 4 and report['command_error'] == '' and report['image_produced']
        assert report['run_id'] in report_path.name
        before = resolve(report['before_path'], report['before_sha256']).read_bytes()
        after = resolve(report['after_path'], report['after_sha256']).read_bytes()
        pixels = resolve(report['image_path'], report['image_sha256']).read_bytes()
        assert before == bytes([0x69]) * 32768 and len(after) == 32768 and len(pixels) == 3404
        packed = b''.join(after[y*1024:y*1024+148] for y in range(23))
        assert packed == pixels
        errors = [abs(a-b) for a, b in zip(pixels, golden_bytes)]
        mismatches = sum(delta > (0 if i % 4 == 3 else 1) for i, delta in enumerate(errors))
        padding = b''.join(after[y*1024+148:(y+1)*1024] for y in range(23)) + after[23*1024:]
        padding_bad = sum(value != 0x69 for value in padding)
        changed = sum(value != 0x69 for value in after)
        record.update(run_id=report['run_id'], pixel_mismatches=mismatches,
            padding_mismatches=padding_bad, max_pixel_error=max(errors), changed_bytes=changed)
        assert not mismatches and not padding_bad and changed > 0
        assert report['mismatches'] == 0 and report['changed_bytes'] == changed
        assert report['max_pixel_error'] == max(errors)
        record.update(verified_pixels=851, verified_pixel_bytes=3404, verified_padding_bytes=len(padding),
            verified_allocation_bytes=32768, a16_shader_pixels_verified=not args.host_reference)
        if 'presentation' in report:
            present = report['presentation']
            assert present['width'] == 2880 and present['height'] == 1800
            row, length = present['row_bytes'], present['allocation_length']
            assert 11520 <= row <= 65536 and row*1800 <= length <= 64 << 20
            assert present['source_sha256'] == report['image_sha256']
            data = resolve(present['path'], present['sha256']).read_bytes()
            assert len(data) == length
            rows = {}
            for y in range(1800):
                sy = y * 23 // 1800
                if sy not in rows:
                    rows[sy] = b''.join(pixels[(sy*37+x*37//2880)*4:(sy*37+x*37//2880)*4+4] for x in range(2880))
                assert data[y*row:y*row+11520] == rows[sy], ('presentation row', y)
                assert not any(data[y*row+11520:(y+1)*row]), ('presentation padding', y)
            assert not any(data[row*1800:]), 'presentation tail'
            record['verified_presentation_bytes'] = length
            if panel_path is not None:
                from PIL import Image
                with Image.open(panel_path) as panel:
                    assert panel.mode == 'RGB' and panel.size == (2880, 1800)
                    captured = panel.tobytes()
                wanted = bytearray()
                for y in range(1800):
                    line = data[y*row:y*row+11520]
                    rgb = bytearray(8640)
                    rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
                    wanted.extend(rgb)
                differences = sum(a != b for a, b in zip(captured, wanted))
                record['panel_rgb_mismatched_bytes'] = differences
                record['panel_rgb_compared_bytes'] = len(wanted)
                record['swap_completed'] = report.get('presentation_completed', False)
                record['panel_framebuffer_matches'] = (not differences and
                    report.get('presentation_requested') is True and record['swap_completed'] is True
                    and report.get('presentation_return') == 0)
        if args.host_reference:
            record['status'] = 'HOST_REFERENCE_TRIANGLE_ARTIFACTS_VERIFIED_NOT_A16'
            result = 0
        elif record['panel_framebuffer_matches']:
            record['status'] = 'A16_SHADER_PIXELS_AND_CAPTURED_FRAMEBUFFER_MATCH'
            result = 0
        else:
            record['status'] = 'A16_SHADER_PIXELS_VERIFIED_PANEL_UNPROVEN'
            result = 2
        record['boundary'] = ('Persisted artifact comparison only. A16 mode binds stopped GPU IB/fence evidence '
            'and a fresh read-only snapshot. Matching captured framebuffer pixels do not establish physical '
            'panel observation, WindowServer behavior, input responsiveness or a usable desktop.')
    except Exception as error:
        record.update(status='FAIL', exception=repr(error))
    finally:
        record['finished'] = time.time()
        with (out / 'verification.json').open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
        print(json.dumps({k: record[k] for k in ('status', 'a16_shader_pixels_verified', 'panel_framebuffer_matches')}))
    return result


if __name__ == '__main__':
    raise SystemExit(main())
