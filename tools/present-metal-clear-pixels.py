#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy proven guest GPU pixels to the idle A16 panel and verify every byte.

No desktop or direct GPU scanout is claimed. The GPU produced the source;
this host performs nearest-neighbour enlargement and CPU framebuffer writes.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from bootcontract import HostRuntime
from run import connect, q1n1

sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--proof', type=Path, required=True)
    ap.add_argument('--retirement', type=Path, required=True)
    ap.add_argument('--retirement-sha256', required=True)
    ap.add_argument('--device', default='udp://en5')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    proof = json.loads(args.proof.read_text())
    assert proof['status'] == 'GUEST_METAL_CLEAR_PIXELS_AND_GPU_PACKETS_VERIFIED'
    assert proof['generation'] == 46 and not proof['screen_presented']
    assert proof['source_sha256'] == sha(ROOT / 'tools/verify-metal-clear-pixels.py')
    for name, digest in proof['inputs_sha256'].items():
        assert sha(name) == digest, name
    pixels = Path(proof['pixel_path']).read_bytes()
    assert hashlib.sha256(pixels).hexdigest() == proof['pixel_sha256']
    width, height = proof['width'], proof['height']
    assert (width, height) == (37, 23) and len(pixels) == width * height * 4
    assert sha(args.retirement) == args.retirement_sha256
    retired = json.loads(args.retirement.read_text())
    assert retired['status'] == 'GENERATION47_IDLE' and retired['quiesce'] == 'graceful'
    assert retired['before']['stage_generation'] == 46 and retired['after']['stage_generation'] == 47
    verification = ROOT / 'build' / (proof['prefix'] + '-pre-reset-verification.json')
    assert retired['verification_sha256'] == sha(verification)
    assert proof['inputs_sha256'][str(verification)] == sha(verification)
    args.output.mkdir(parents=True, exist_ok=False)
    record = dict(status='RUNNING', started=time.time(), source_sha256=sha(__file__),
        proof_sha256=sha(args.proof), retirement_sha256=sha(args.retirement),
        guest_run_id=proof['run_id'], source_pixels_sha256=proof['pixel_sha256'],
        source_size=[width, height], bytes_written=0, screen_presented=False,
        boundary='Actual guest GPU clear, nearest-neighbour enlarged and copied by the CPU. This is not a WindowServer desktop or GPU scanout.')
    record['host_sources_sha256'] = {str(p): sha(p) for p in
        (ROOT / 'probes/bootcontract.py', ROOT / 'probes/run.py', Path(q1n1.__file__).resolve())}
    proxy = None

    def save(name, data):
        with (args.output / name).open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())

    try:
        from PIL import Image
        proxy = connect(args.device, tries=1)
        info = proxy.bootinfo()
        assert info['stage_generation'] == 47 and info['image_base'] == retired['after']['image_base']
        fb = HostRuntime.from_q1n1(info, with_framebuffer=True).framebuffer
        size = fb.stride * fb.height
        assert 0 < size <= 64 << 20
        record['bootinfo'] = info
        record['console_previously_enabled'] = proxy.fb_console(False)
        assert record['console_previously_enabled'] in (0, 1)
        keys = ('stage_generation', 'image_base', 'fb_base', 'fb_size', 'fb_width', 'fb_height', 'fb_stride', 'fb_format')
        identity = tuple(info[k] for k in keys)

        def capture():
            # Use the same PoC clean/invalidate operation as the qualified
            # q1n1 framebuffer reader, so readback reaches the display's DRAM.
            proxy.request(proxy.P_DC_CIVAC, fb.base, size)
            data = b''.join(proxy.readmem(fb.base + at, min(65536, size - at))
                            for at in range(0, size, 65536))
            assert len(data) == size
            current = proxy.bootinfo()
            assert tuple(current[k] for k in keys) == identity
            return data

        before = capture()
        save('panel-before.bin', before)
        record['before_sha256'] = hashlib.sha256(before).hexdigest()
        desired = bytearray(before)
        rows = []
        for y in range(height):
            row = bytearray()
            for x in range(fb.width):
                offset = (y * width + x * width // fb.width) * 4
                pixel = pixels[offset:offset + 4]
                row += pixel if info['fb_format'] == 1 else bytes((pixel[2], pixel[1], pixel[0], pixel[3]))
            assert len(row) == fb.width * 4
            rows.append(bytes(row))
        for y in range(fb.height):
            start = y * fb.stride
            desired[start:start + fb.width * 4] = rows[y * height // fb.height]
        save('panel-desired.bin', desired)
        for y in range(fb.height):
            offset, count = y * fb.stride, fb.width * 4
            assert offset + count <= size <= info['fb_size']
            proxy.writemem(fb.base + offset, bytes(desired[offset:offset + count]))
            record['bytes_written'] += count
        after = capture()
        save('panel-readback.bin', after)
        record['after_sha256'] = hashlib.sha256(after).hexdigest()
        record['desired_sha256'] = hashlib.sha256(desired).hexdigest()
        assert after == desired, 'panel readback differs from the intended pixels or padding'
        for name, digest in record['host_sources_sha256'].items():
            assert sha(name) == digest
        Image.frombytes('RGB', (fb.width, fb.height), after, 'raw',
                        'BGRX' if info['fb_format'] == 1 else 'RGBX', fb.stride).save(args.output / 'panel.png')
        record.update(status='VERIFIED_GUEST_GPU_PIXELS_COPIED_TO_PANEL', screen_presented=True,
                      panel_sha256=sha(args.output / 'panel.png'), panel_size=[fb.width, fb.height])
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        if proxy is not None:
            proxy.link.close()
        record['finished'] = time.time()
        with (args.output / 'presentation.json').open('x') as output:
            json.dump(record, output, indent=2); output.write('\n')
    print(json.dumps(dict(status=record['status'], bytes_written=record['bytes_written'],
                         artifact=str((args.output / 'panel.png').resolve()))))


if __name__ == '__main__':
    main()
