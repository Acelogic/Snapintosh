#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host E2E of the display path up to the panel bytes: probe -> IOSurface -> kext copy -> GOP.

No hardware and no IOMobileFramebuffer swap. It builds the real guest display probe,
runs it with --no-swap to create and fill its real IOSurface and dump the bytes, then
feeds that dump through AdrenoDisplayCopy.h (the header the kext compiles) into a
synthetic 2880x1800 / 11520-pitch BGRX GOP buffer, with the CPU cache modelled as
stale until the copy's FROM_DEVICE maintenance refetches each row. The panel that
comes out must hash to the values the probe prints in its ADRENO-VERDICT line, which
are the values the conductor compares against tools/capture-panel.py.

It also runs the copy's adversarial self-test (guard pages, refusals, formats), and the
same cases against a model of the HEAD 2cdbae5 copy, which must fail; and the cursor-layer
cases (AdrenoDisplayCursor.h: composite and clipping at every edge, premultiplied alpha,
save-under on moves, cursor-only swaps, hide, unknown formats, refusals, no cursor layer =
the layer-0 bytes), which must pass, and fail against the 7ec040b4 present that drops
layers 1-3 (except the no-cursor-layer case, which both must pass).

    python3 tools/test-adreno-display.py --output DIR   (DIR must not exist)
Artifacts: DIR/display-e2e.json, DIR/panel.png (when Pillow is present), logs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'tools/test-adreno-display-present.c'
COPY = ROOT / 'gpu/adreno-kext/kext/src/AdrenoDisplayCopy.h'
CURSOR = ROOT / 'gpu/adreno-kext/kext/src/AdrenoDisplayCursor.h'
PROBE = ROOT / 'gpu/adreno-kext/plugin/harness/guest-display-probe.m'
WIDTH, HEIGHT, PITCH = 2880, 1800, 11520
sha = lambda b: hashlib.sha256(b).hexdigest()


def run(argv, log, ok=(0,)):
    r = subprocess.run([str(a) for a in argv], cwd=ROOT, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    log.write_text(r.stdout)
    if r.returncode not in ok:
        raise SystemExit(f'{argv[0]} exited {r.returncode}; see {log}')
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations']
    new, old = out / 'present-new', out / 'present-prechange'
    run(['xcrun', 'clang', *flags, HARNESS, '-o', new], out / 'build-new.log')
    run(['xcrun', 'clang', *flags, '-DADRENO_DISPLAY_PRECHANGE', HARNESS, '-o', old], out / 'build-prechange.log')

    selftest_new = json.loads(run([new, 'selftest'], out / 'selftest-new.log').stdout.splitlines()[-1])
    r = run([old, 'selftest'], out / 'selftest-prechange.log', ok=(0, 1))
    selftest_old = json.loads(r.stdout.splitlines()[-1])
    selftest_old['exit'] = r.returncode
    cursor_new = json.loads(run([new, 'cursor'], out / 'cursor-new.log').stdout.splitlines()[-1])
    r = run([old, 'cursor'], out / 'cursor-prechange.log', ok=(0, 1))
    cursor_old = json.loads(r.stdout.splitlines()[-1])
    cursor_old['exit'] = r.returncode
    cursor_checks = {
        'cursor_cases_pass': cursor_new['failures'] == 0 and all(v == 0 for v in cursor_new['cases'].values()),
        'prechange_drops_the_cursor': cursor_old['failures'] > 0 and cursor_old['cases']['positions_and_edge_clipping'] > 0,
        'prechange_no_cursor_layer_identical': cursor_old['cases']['no_cursor_layer_identical'] == 0,
    }

    run([sys.executable, ROOT / 'tools/build-adreno-display-probe.py', '--output', out / 'probe'], out / 'probe-build.log')
    dump = out / 'surface.adsf'
    verdict_run = run([out / 'probe/display-probe', '--no-swap', '--emit-surface', dump], out / 'probe-run.log')
    verdict, = [l for l in verdict_run.stdout.splitlines() if l.startswith('ADRENO-VERDICT display ')]
    fields = dict(re.findall(r'(\w+)=(\S+)', verdict))

    # Independent read of the probe's own bytes: header, orientation blocks, both hashes.
    blob = dump.read_bytes()
    magic, width, height, fmt = [int.from_bytes(blob[i:i + 4], 'little') for i in range(0, 16, 4)]
    row, offset, length = [int.from_bytes(blob[16 + i:24 + i], 'little') for i in range(0, 24, 8)]
    pixels = blob[40:40 + length]
    tight = b''.join(pixels[offset + y * row: offset + y * row + WIDTH * 4] for y in range(HEIGHT))
    rgb = bytearray(WIDTH * HEIGHT * 3)
    rgb[0::3], rgb[1::3], rgb[2::3] = tight[2::4], tight[1::4], tight[0::4]
    px = lambda x, y: tight[(y * WIDTH + x) * 4:(y * WIDTH + x) * 4 + 4]
    dump_checks = {
        'header': (magic, width, height, fmt) == (0x46534441, WIDTH, HEIGHT, 0x42475241) and length == len(pixels),
        'top_left_red': px(0, 0)[:3] == b'\x00\x00\xff',
        'top_right_green': px(WIDTH - 1, 0)[:3] == b'\x00\xff\x00',
        'bottom_left_blue': px(0, HEIGHT - 1)[:3] == b'\xff\x00\x00',
        'distinct_pixels_ge_64': len({tight[i:i + 4] for i in range(0, len(tight), 4 * 997)}) >= 64,
        'surface_sha256': sha(tight) == fields.get('surface_sha256'),
        'panel_rgb_sha256': sha(bytes(rgb)) == fields.get('panel_rgb_sha256'),
    }

    # Through the kext copy into the synthetic GOP.
    panel = out / 'panel.bin'
    copied = json.loads(run([new, 'surface', dump, panel], out / 'copy-new.log').stdout.splitlines()[-1])
    stale = json.loads(run([old, 'surface', dump], out / 'copy-prechange.log', ok=(0, 1)).stdout.splitlines()[-1])
    copy_checks = {
        'copy_ok': copied['error'] == 0 and copied['width'] == WIDTH and copied['height'] == HEIGHT,
        'every_row_maintained_in_order': copied['maintained_rows'] == HEIGHT and copied['maintain_order_ok'] == 1,
        'panel_rgb_equals_probe_verdict': copied['panel_rgb_sha256'] == fields.get('panel_rgb_sha256'),
        # Pitch 11520 == 2880*4, so the whole GOP equals the tightly packed surface.
        'panel_raw_equals_probe_verdict': copied['panel_raw_sha256'] == fields.get('surface_sha256'),
        'prechange_shows_stale_pixels': stale['panel_rgb_sha256'] != fields.get('panel_rgb_sha256'),
    }
    png = None
    try:
        from PIL import Image
        png = out / 'panel.png'
        image = Image.frombytes('RGB', (WIDTH, HEIGHT), panel.read_bytes(), 'raw', 'BGRX', PITCH)
        image.save(png)
        copy_checks['png_rgb_equals_probe_verdict'] = (
            sha(Image.open(png).convert('RGB').tobytes()) == fields.get('panel_rgb_sha256'))
    except ImportError:
        pass
    panel.unlink()          # 20 MB; its hashes are recorded

    passed = (selftest_new['failures'] == 0 and selftest_old['failures'] > 0 and all(dump_checks.values())
              and all(copy_checks.values()) and all(cursor_checks.values())
              and fields.get('status') == 'NO_SWAP_REQUESTED')
    report = dict(verdict='PASS' if passed else 'FAIL', probe_verdict=verdict,
                  selftest=selftest_new, selftest_prechange=selftest_old,
                  cursor=cursor_new, cursor_prechange=cursor_old, cursor_checks=cursor_checks,
                  dump_checks=dump_checks, copy=copied, copy_prechange=stale, copy_checks=copy_checks,
                  png=str(png) if png else None,
                  sources_sha256={str(p.relative_to(ROOT)): sha(p.read_bytes())
                                  for p in (HARNESS, COPY, CURSOR, PROBE, Path(__file__).resolve())},
                  boundary='Host bytes only: no IOMobileFramebuffer swap, no kext, no A16 panel.')
    (out / 'display-e2e.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(verdict=report['verdict'], selftest=selftest_new, prechange_failures=selftest_old['failures'],
                          cursor=cursor_new, cursor_prechange_failures=cursor_old['failures'],
                          panel_rgb_sha256=copied['panel_rgb_sha256'], report=str(out / 'display-e2e.json'))))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
