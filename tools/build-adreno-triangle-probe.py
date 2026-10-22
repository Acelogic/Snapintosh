#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a guest triangle probe and execute its explicit AGX reference variant.

Failure inventory: docs/ADRENO-GUI-INTEGRATION-20260927.md. No A16 access.
The production binary requires the qualified Adreno plug-in. Host reference
execution cannot establish Adreno shader execution or panel presentation.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--draw-qualification', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    qualification = args.draw_qualification.resolve()
    parent = qualification.parent
    draw = json.loads(qualification.read_text())
    assert draw['status'] == 'ADRENO_DRAW_PACKAGES_MATCH_PLAN_AND_MODEL'
    assert draw['cases']['plan-v2-clear']['result'] == 'PASS'
    bindings = {}
    for key, root in [('sources_sha256', ROOT), ('artifacts_sha256', parent),
                      ('q1n1_sha256', ROOT.parent/'q1n1/tools')]:
        for name, digest in draw[key].items():
            path = root/name
            assert sha(path) == digest, name
            bindings[str(path)] = digest
    capture_path = parent/'plan-v2-clear.json'
    golden_path = parent/'golden-plan-v2-clear.json'
    capture, golden = [json.loads(p.read_text()) for p in (capture_path, golden_path)]
    assert capture['status'] == 'NATIVE_DRAW_COMMIT_CAPTURED_NOT_SUBMITTED'
    assert golden['status'] == 'HOST_METAL_GOLDEN_RENDERED'
    assert capture['metal_source'] == golden['metal_source']
    assert capture['function_constants'] == golden['function_constants'] == {'0': 0.5, '1': 13}
    assert capture['load_action'] == golden['load_action'] == 'clear'
    assert capture['linear_layout'] == dict(allocation=32768, height=23,
        known=True, row_bytes=1024, width=37)
    golden_bytes_path = Path(golden['out'])/'golden.bgra'
    pixels = golden_bytes_path.read_bytes()
    assert len(pixels) == 37*23*4 and sha(golden_bytes_path) == golden['artifacts']['golden.bgra']['sha256']
    assert sha(golden_bytes_path) == draw['goldens']['plan-v2-clear']['sha256']
    # Two distinct reference colours ensure this scene contains the triangle.
    assert len({pixels[i:i+4] for i in range(0, len(pixels), 4)}) == 2
    bundle = Path(draw['bundle'])
    binary = bundle/'Contents/MacOS/AdrenoMetal'
    assert sha(binary) == draw['bundle_executable_sha256']
    source = ROOT/'gpu/adreno-kext/plugin/harness/guest-triangle-probe.m'
    presenter = source.with_name('SnapintoshTrianglePresent.h')
    out = args.output.resolve()
    assert not out.exists()
    out.mkdir(parents=True)
    record = dict(status='RUNNING', started=time.time(), a16_access=False,
        guest_executed=False, screen_presented=False,
        draw_qualification=str(qualification), draw_qualification_sha256=sha(qualification),
        plugin=str(binary), plugin_sha256=sha(binary), golden_sha256=sha(golden_bytes_path),
        inputs_sha256=bindings,
        sources_sha256={str(p.relative_to(ROOT)): sha(p) for p in (Path(__file__), source, presenter)},
        commands=[], boundary='Host AGX reference execution and signed guest build only; no A16 draw or presentation.')
    def run(name, command):
        with (out/(name+'.log')).open('x') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=90)
        record['commands'].append(dict(name=name, argv=command, exit_code=result.returncode))
        assert result.returncode == 0, name
    try:
        header = '#define SNAP_TRIANGLE_METAL_SOURCE '+json.dumps(capture['metal_source'])+'\n'
        header += '#define SNAP_TRIANGLE_GOLDEN_SHA "'+sha(golden_bytes_path)+'"\n'
        header += 'static const unsigned char SnapTriangleGolden[] = {\n'
        header += '\n'.join(','.join(str(x) for x in pixels[i:i+32])+',' for i in range(0,len(pixels),32))+'\n};\n'
        (out/'SnapTriangleReference.h').write_text(header)
        run('plugin-signature', ['codesign', '--verify', '--strict', str(bundle)])
        for name, reference in [('metal-triangle-probe', 0), ('host-reference', 1)]:
            command = ['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0',
                '-fobjc-arc', '-fobjc-arc-exceptions', '-O2', '-Wall', '-Wextra',
                '-Wno-deprecated-declarations', '-I', str(out),
                '-DSNAP_TRIANGLE_PLUGIN_SHA="'+sha(binary)+'"',
                '-DSNAP_TRIANGLE_HOST_REFERENCE='+str(reference), str(source), '-o', str(out/name),
                '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'IOKit', '-framework', 'IOSurface']
            run(name+'-build', command)
            run(name+'-sign', ['codesign', '-f', '-s', '-', str(out/name)])
            run(name+'-verify', ['codesign', '--verify', '--strict', str(out/name)])
        run('host-reference-run', [str(out/'host-reference'), '--wait', '0',
            '--prepare-presentation', '--report-base', str(out/'host-report')])
        reports = list(out.glob('host-report-*.json'))
        assert len(reports) == 1
        report = json.loads(reports[0].read_text())
        assert report['host_reference'] and not report['screen_presented']
        assert report['result'] == 'HOST_METAL_TRIANGLE_REFERENCE_MATCHED'
        assert report['mismatches'] == 0 and report['max_pixel_error'] <= 1 and report['image_produced']
        before, after = [Path(report[k]).read_bytes() for k in ('before_path', 'after_path')]
        assert before == bytes([0x69])*32768 and len(after) == 32768
        for i, byte in enumerate(after):
            y, x = divmod(i, 1024)
            active = y < 23 and x < 37*4
            expected = pixels[y*37*4+x] if active else 0x69
            tolerance = 1 if active and x % 4 != 3 else 0
            assert abs(byte-expected) <= tolerance, i
        # Independently expand source-pixel intervals using ceiling boundaries,
        # rather than the presenter's per-destination floor-division loop.
        actual_pixels_path = Path(report['image_path'])
        actual_pixels = actual_pixels_path.read_bytes()
        assert len(actual_pixels) == len(pixels) and sha(actual_pixels_path) == report['image_sha256']
        pres = report['presentation']
        assert pres['width'] == 2880 and pres['height'] == 1800
        row = pres['row_bytes']
        assert 2880*4 <= row <= 65536 and row*1800 <= pres['allocation_length'] <= 64*1024*1024
        shown_path = Path(pres['path'])
        shown = shown_path.read_bytes()
        assert len(shown) == pres['allocation_length'] and sha(shown_path) == pres['sha256']
        assert pres['source_sha256'] == report['image_sha256']
        for sy in range(23):
            chunks = []
            for sx in range(37):
                first, last = (sx*2880+36)//37, ((sx+1)*2880+36)//37
                pixel = actual_pixels[(sy*37+sx)*4:(sy*37+sx+1)*4]
                chunks.append(pixel*(last-first))
            expected_row = b''.join(chunks)+bytes(row-2880*4)
            first, last = (sy*1800+22)//23, ((sy+1)*1800+22)//23
            assert shown[first*row:last*row] == expected_row*(last-first), sy
        assert shown[1800*row:] == bytes(len(shown)-1800*row)
        assert not report.get('presentation_requested') and not report.get('presentation_completed')
        for name, digest in bindings.items():
            assert sha(Path(name)) == digest, name
        assert sha(binary) == record['plugin_sha256'] and sha(qualification) == record['draw_qualification_sha256']
        record.update(status='GUEST_TRIANGLE_BUILT_HOST_REFERENCE_MATCHED_NOT_EXECUTED_ON_A16',
            binary_sha256=sha(out/'metal-triangle-probe'), host_report=str(reports[0]),
            host_report_sha256=sha(reports[0]), host_device=report['devices'],
            verified_allocation_bytes=32768, active_pixel_bytes=len(pixels),
            host_presentation_bytes=len(shown), host_presentation_sha256=pres['sha256'])
    except BaseException as error:
        record.update(status='FAIL', error=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out/'build.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({key: record[key] for key in ('status', 'binary_sha256', 'verified_allocation_bytes')}))


if __name__ == '__main__':
    main()
