#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Point size and point coordinate semantics: our compiler's NIR on llvmpipe against Metal on the host GPU.

CoreAnimation's generic pipeline writes [[point_size]] (vertex) and reads [[point_coord]] (fragment); the four
captured scenes draw it with triangles only, so this scene draws points the way CoreAnimation's point layout does
(its PointVertex: position, size, packed colour read by vertex_id from a device buffer) at sizes 0.5 to 32 and at
pixel-centre, pixel-corner and fractional positions, and outputs point_coord. Metal (M3 Max) is the reference;
nirexec runs the NIR air2ir3 builds for the same AIR with gallium point sprites (per-vertex size, top-left origin).
This checks the compiler's side of the point path (AIR point_size/point_coord -> VARYING_SLOT_PSIZ/PNTC) and the
reference semantics the Adreno state was chosen for (tools/inspect-ca-point-draws.py checks that state).

  python3 tools/conform-point-sprites.py --nirexec BIN --mtlgold BIN --output NEW-DIR
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
SOURCE = r'''
#include <metal_stdlib>
using namespace metal;
struct PV { packed_float2 pos; float size; uint color; };    // CoreAnimation's PointVertex layout
struct V { float4 pos [[position]]; float size [[point_size]]; half4 color; };
vertex V vsp(uint vid [[vertex_id]], const device PV *v [[buffer(1)]], constant float4x4 &mvp [[buffer(2)]]) {
    V o; o.pos = mvp * float4(float2(v[vid].pos), 0, 1); o.size = v[vid].size;
    o.color = unpack_unorm4x8_to_half(v[vid].color); return o;
}
fragment half4 fsp(V in [[stage_in]], float2 pc [[point_coord]]) {
    return half4(half2(pc), 0.25h, 1.0h) * in.color.a;
}
'''
W, H = 128, 96
POINTS = [(10.5, 10.5, 1.0), (30, 20, 2.5), (60.5, 30.5, 8.0), (96, 48, 32.0), (20.25, 70.75, 5.0), (50, 70, 0.5)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--nirexec', type=Path, required=True)
    ap.add_argument('--mtlgold', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'points.metal').write_text(SOURCE)
    subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', str(out / 'points.metal'), '-o', str(out / 'points.air')], check=True)
    subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', str(out / 'points.air'), '-o', str(out / 'points.metallib')], check=True)
    (out / 'vb.bin').write_bytes(b''.join(struct.pack('<2ffI', x, y, s, 0xffffffff) for x, y, s in POINTS))
    (out / 'mvp.bin').write_bytes(struct.pack('<16f', 2 / W, 0, 0, 0, 0, -2 / H, 0, 0, 0, 0, 1, 0, -1, 1, 0, 1))
    air, lib = str(out / 'points.air'), str(out / 'points.metallib')
    scene = dict(width=W, height=H, clear=[0, 0, 0, 1], rt=dict(format='bgra8'), blend=dict(enabled=0),
                 vertex=dict(data=dict(floats=[]), stride=0, count=len(POINTS), attributes=[], primitive='point'),
                 buffers=dict(vertex=[dict(index=1, device=True, file=str(out / 'vb.bin')), dict(index=2, file=str(out / 'mvp.bin'))]),
                 vs=dict(bc=air, metallib=lib, function='vsp', entry='vsp'), fs=dict(bc=air, metallib=lib, function='fsp', entry='fsp'))
    (out / 'scene.json').write_text(json.dumps(scene, indent=1) + '\n')
    for tool, ext in ((args.mtlgold, 'metal'), (args.nirexec, 'lp')):
        r = subprocess.run([str(tool), str(out / 'scene.json'), str(out / f'{ext}.bgra'), '--frames', '3'], capture_output=True, text=True)
        (out / f'{ext}.log').write_text(r.stdout + r.stderr)
        assert r.returncode == 0, (ext, r.stderr[-1000:])
    a, b = (out / 'metal.bgra').read_bytes(), (out / 'lp.bgra').read_bytes()
    background = bytes([0, 0, 0, 255])
    differing = [(i // 4 % W, i // 4 // W, a[i:i + 4].hex(), b[i:i + 4].hex()) for i in range(0, len(a), 4) if a[i:i + 4] != b[i:i + 4]]
    report = dict(status='POINT_SPRITES_COMPARED', points=POINTS, width=W, height=H,
                  metal_pixels_drawn=sum(1 for i in range(0, len(a), 4) if a[i:i + 4] != background),
                  llvmpipe_pixels_drawn=sum(1 for i in range(0, len(b), 4) if b[i:i + 4] != background),
                  differing_pixels=differing, max_abs_diff=max(abs(x - y) for x, y in zip(a, b)),
                  metal_sha256=sha(out / 'metal.bgra'), llvmpipe_sha256=sha(out / 'lp.bgra'), source_sha256=sha(__file__),
                  nirexec_sha256=sha(args.nirexec), mtlgold_sha256=sha(args.mtlgold), a16_access=False)
    (out / 'report.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'metal_pixels_drawn', 'llvmpipe_pixels_drawn', 'differing_pixels', 'max_abs_diff')}))


if __name__ == '__main__':
    main()
