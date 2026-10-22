#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""scenes.py - write the execution scenes shared by nirexec (llvmpipe) and mtlgold (M3 Max Metal).

Each scene is one draw of a real WindowServer vertex+fragment pair with realistic inputs (a window-
like quad in pixel space, an ortho MVP, a textured "window" image with alpha, tint/HDR uniforms).
Output: scenes/<name>.json and scenes/data/*.bin.  Every path in a scene is relative to the tree
root; the OS metallibs are named "@SkyLight" / "@CoreDisplay" (resolved by mtlgold), so the scenes
work from any checkout location.

The xr_* scenes render into / sample from MTLPixelFormatBGR10_XR (554) and BGRA10_XR (552) and
check the compiler's XR shader lowering (FORMATS.md) against Metal on this Mac.
"""
import json, math, os, struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'scenes')
SL_LIB = '@SkyLight'
CD_LIB = '@CoreDisplay'
W, H = 96, 64

def ortho(w, h):   # pixel space (origin top-left) -> NDC, column-major float4x4 as Metal stores it
    return [2.0 / w, 0, 0, 0, 0, -2.0 / h, 0, 0, 0, 0, 1, 0, -1, 1, 0, 1]

def window_texture(name, w=64, h=64):
    """RGBA8 'window': gradient body, 8-px checker detail, soft alpha edge, premultiplied."""
    px = bytearray()
    for y in range(h):
        for x in range(w):
            a = min(1.0, min(x + 0.5, w - x - 0.5, y + 0.5, h - y - 0.5) / 6.0)
            r = x / (w - 1); g = y / (h - 1); b = 0.85 if ((x // 8) + (y // 8)) % 2 else 0.25
            px += bytes(int(round(c * a * 255)) for c in (r, g, b)) + bytes([int(round(a * 255))])
    p = os.path.join(OUT, 'data', name + '.bin'); open(p, 'wb').write(px)
    return os.path.relpath(p, ROOT)

def quad(x0, y0, x1, y1, u0, v0, u1, v1):   # two triangles, (pos.xy, tex.uv) per vertex
    v = [(x0, y0, u0, v0), (x1, y0, u1, v0), (x0, y1, u0, v1), (x1, y0, u1, v0), (x1, y1, u1, v1), (x0, y1, u0, v1)]
    return [c for t in v for c in t]

def simple_vertex_draw(q):
    return dict(stride=16, data=dict(floats=q), count=6, primitive='triangle',
                attributes=[dict(index=0, format='float2', offset=0), dict(index=1, format='float2', offset=8)])

def sl(fn, **kw):
    d = dict(bc=f'corpus/SkyLight/{fn}.bc', metallib=SL_LIB, function=fn); d.update(kw); return d

# ---- XR10 (Metal layout) ----
def xr_n(v): return max(0, min(1023, int(math.floor(v * 510.0 + 384.0 + 0.5))))
def xr554(r, g, b): return struct.pack('<I', (3 << 30) | (xr_n(r) << 20) | (xr_n(g) << 10) | xr_n(b))
def xr552(r, g, b, a): return struct.pack('<4H', xr_n(b) << 6, xr_n(g) << 6, xr_n(r) << 6, xr_n(a) << 6)

def xr_texture(name, fmt, w=64, h=64):
    """extended-range test image: ramps over [-0.6, 1.2], a checker in blue, alpha ramp (552)"""
    px = bytearray()
    for y in range(h):
        for x in range(w):
            r = -0.6 + 1.8 * x / (w - 1); g = 1.2 - 1.8 * y / (h - 1); b = 1.1 if ((x // 8) + (y // 8)) % 2 else -0.4
            a = 0.25 + 0.75 * ((x + y) % 16) / 15
            px += xr554(r, g, b) if fmt == 'bgr10_xr' else xr552(r, g, b, a)
    p = os.path.join(OUT, 'data', f'{name}.bin'); open(p, 'wb').write(px)
    return os.path.relpath(p, ROOT)

def xr_init(name, fmt, w=W, h=H):
    """initial attachment contents (loadAction .load): a different XR pattern, so blending is visible"""
    px = bytearray()
    for y in range(h):
        for x in range(w):
            r = 0.9 - 1.5 * y / (h - 1); g = -0.5 + 1.6 * x / (w - 1); b = 0.3 if (x // 6) % 2 else 1.15
            px += xr554(r, g, b) if fmt == 'bgr10_xr' else xr552(r, g, b, 0.2 + 0.8 * x / (w - 1))
    p = os.path.join(OUT, 'data', f'{name}.bin'); open(p, 'wb').write(px)
    return os.path.relpath(p, ROOT)

BLEND = dict(none=dict(enabled=0), premul_over=dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=1, dst_rgb=5, src_alpha=1, dst_alpha=5),
             src_alpha=dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=4, dst_rgb=5, src_alpha=1, dst_alpha=5),
             additive=dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=1, dst_rgb=1, src_alpha=1, dst_alpha=1),
             erase=dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=0, dst_rgb=5, src_alpha=0, dst_alpha=5),
             maximum=dict(enabled=1, rgb_op=4, alpha_op=4, src_rgb=1, dst_rgb=1, src_alpha=1, dst_alpha=1),
             revsub=dict(enabled=1, rgb_op=2, alpha_op=0, src_rgb=4, dst_rgb=1, src_alpha=1, dst_alpha=5),
             dst_color=dict(enabled=1, rgb_op=0, alpha_op=0, src_rgb=6, dst_rgb=5, src_alpha=1, dst_alpha=5))

def xr_scenes(tex, mvp):
    sc = {}
    tint = [1.4, -0.3, 0.8, 1.0, 1.25, 0, 0, 0]          # colour tint + HDR scale: outputs leave [0, 1]
    for fmt in ('bgr10_xr', 'bgra10_xr'):
        tag = '554' if fmt == 'bgr10_xr' else '552'
        init = xr_init(f'xrinit_{tag}', fmt)
        for bn in (['none', 'premul_over', 'src_alpha', 'erase', 'maximum', 'additive', 'revsub', 'dst_color']):
            sc[f'xr{tag}_tint_{bn}'] = dict(    # texel-centre aligned (no filter rounding): isolates the lowering
                vs=sl('SimpleVertex'), fs=sl('SimpleTextureTintFragment'),
                vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 64, 64)),
                buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=tint)]),
                textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)],
                rt=dict(format=fmt, init_file=init), blend=BLEND[bn])
        # verify2 v2neg{554,552}_premul_over: tint -0.7 with partial alpha, i.e. a source outside the
        # premultiplied range (|s| > range*a).  ABI v2's hw source-over was off by 26 codes here;
        # ABI v3 blends premultiplied source-over in the shader (fix2 item 7).
        sc[f'xr{tag}_negtint_premul_over'] = dict(
            vs=sl('SimpleVertex'), fs=sl('SimpleTextureTintFragment'),
            vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 64, 64)),
            buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=[-0.7, 1.0, 0.8, 1.0, 1.25, 0, 0, 0])]),
            textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)],
            rt=dict(format=fmt, init_file=init), blend=BLEND['premul_over'])
        xt = xr_texture(f'xrtex_{tag}', fmt)
        sc[f'xr{tag}_sample_linear'] = dict(      # decode on sample: bilinear over an XR texture, float target
            vs=sl('SimpleVertex'), fs=sl('SimpleTextureFragment'),
            vertex=simple_vertex_draw(quad(8, 4, 88, 60, 0, 0, 1, 1)),
            buffers=dict(vertex=[mvp]), textures=[dict(index=0, width=64, height=64, format=fmt, file=xt)],
            samplers=[dict(index=0, filter='linear', address='clamp_to_edge')], rt=dict(format='rgba16f'))
        sc[f'xr{tag}_sample_to_xr'] = dict(       # decode on sample + encode on write, texel-centre aligned
            vs=sl('SimpleVertex'), fs=sl('SimpleTextureFragment'),
            vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 1, 1)),
            buffers=dict(vertex=[mvp]), textures=[dict(index=0, width=64, height=64, format=fmt, file=xt)],
            samplers=[dict(index=0, filter='nearest', address='clamp_to_edge')], rt=dict(format=fmt, init_file=init))
        sc[f'xr{tag}_fbfetch_sover'] = dict(      # framebuffer fetch of an XR attachment (decode) + write (encode)
            vs=sl('SimpleVertex'), fs=sl('InPlaceSover'),
            vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 1, 1)),
            buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=[0.3, -0.2, 0.55, 0.6])]),
            rt=dict(format=fmt, init_file=init))
    return sc

def main():
    os.makedirs(os.path.join(OUT, 'data'), exist_ok=True)
    os.makedirs(os.path.join(ROOT, 'scratch'), exist_ok=True)
    tex = window_texture('window64')
    mvp = dict(index=1, floats=ortho(W, H))
    scenes = {}
    scenes['sl_simple_texture'] = dict(
        vs=sl('SimpleVertex'), fs=sl('SimpleTextureFragment'),
        vertex=simple_vertex_draw(quad(8, 4, 88, 60, 0, 0, 1, 1)),
        buffers=dict(vertex=[mvp]), textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)],
        samplers=[dict(index=0, filter='linear', address='clamp_to_edge')])
    col = []
    for (x, y, c) in [(8, 4, (1, 0, 0, 1)), (88, 4, (0, 1, 0, 1)), (8, 60, (0, 0, 1, 1)),
                      (88, 4, (0, 1, 0, 1)), (88, 60, (1, 1, 1, 0.5)), (8, 60, (0, 0, 1, 1))]:
        col += list(c) + [x, y]
    scenes['sl_simple_color'] = dict(
        vs=sl('SimpleColorVertex'), fs=sl('SimpleColorFragment'),
        vertex=dict(stride=24, data=dict(floats=col), count=6, primitive='triangle',
                    attributes=[dict(index=0, format='float4', offset=0), dict(index=1, format='float2', offset=16)]),
        buffers=dict(vertex=[mvp]))
    scenes['sl_grayscale'] = dict(   # texture(1), constexpr clamp_to_edge / nearest / pixel coordinates
        vs=sl('SimpleVertex'), fs=sl('SimpleGrayscale'),
        vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 64, 64)),
        buffers=dict(vertex=[mvp]), textures=[dict(index=1, width=64, height=64, format='rgba8', file=tex)])
    scenes['sl_alpha_texture'] = dict(   # constexpr clamp_to_zero / nearest / pixel: shows the zero border
        vs=sl('SimpleVertex'), fs=sl('AlphaTextureFragment'),
        vertex=simple_vertex_draw(quad(8, 0, 88, 64, -8, -8, 72, 72)),
        buffers=dict(vertex=[mvp]), textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    scenes['sl_texture_tint'] = dict(    # constexpr clamp_to_edge / linear / pixel; tint + HDR scale uniforms
        vs=sl('SimpleVertex'), fs=sl('SimpleTextureTintFragment'),
        vertex=simple_vertex_draw(quad(16, 0, 80, 64, 3.25, 5.5, 51.25, 53.5)),   # 64 px over 48 texels: bilinear
        buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=[0.9, 0.75, 0.6, 1.0, 1.25, 0, 0, 0])]),
        textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    # CoreDisplay: vertex positions/texcoords/MVP fetched from device buffers by vertex_id
    pos = [8, 4, 88, 4, 8, 60, 88, 4, 88, 60, 8, 60]
    uv = [c * 64 for c in [0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1]]   # TextureCopy's constexpr sampler uses pixel coordinates (80x56 quad: filtered)
    scenes['cd_texture_copy'] = dict(
        vs=dict(bc='corpus/CoreDisplay/ViewportToNDC.bc', metallib=CD_LIB, function='ViewportToNDC'),
        fs=dict(bc='corpus/CoreDisplay/TextureCopy.bc', metallib=CD_LIB, function='TextureCopy'),
        vertex=dict(stride=0, data=dict(floats=[]), count=6, primitive='triangle', attributes=[]),
        buffers=dict(vertex=[dict(index=0, device=True, floats=pos), dict(index=1, device=True, floats=uv),
                             dict(index=2, device=True, floats=ortho(W, H))]),
        textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    # SkyLight runtime template (HorizontalBackgroundBlur, radius 8) compiled on this Mac
    man = json.load(open(os.path.join(ROOT, 'build', 'templates', 'manifest.json')))
    v = [x for x in man['variants'] if x['variant'] == 'hbb_r8'][0]
    lib = os.path.join('build', 'templates', 'hbb_r8.metallib')
    scenes['tmpl_hbb_r8'] = dict(
        vs=dict(bc=v['functions']['SimpleVertex']['bc'], metallib=lib, function='SimpleVertex'),
        fs=dict(bc=v['functions']['HorizontalBackgroundBlur']['bc'], metallib=lib, function='HorizontalBackgroundBlur'),
        vertex=simple_vertex_draw(quad(16, 0, 80, 64, -4, 0, 68, 64)),
        buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=[0.0, 1.0, 0, 0])]),
        textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    # Function-constant specialised variants (the structured selectors WindowServer uses)
    def fcidx(fn, values):
        import subprocess, tempfile
        p = subprocess.run([os.path.join(ROOT, 'build', 'air2ir3'), '--list-fcs', os.path.join(ROOT, f'corpus/SkyLight/{fn}.bc')],
                           capture_output=True, text=True, check=True)
        by = {f['name']: f['index'] for f in json.loads(p.stdout)['function_constants']}
        # Every declared constant is set explicitly (0 unless given), as WindowServer does: Metal
        # accepts a pipeline with "required" constants left unset and then treats them as undef,
        # which makes the golden meaningless (seen with ShadowHorizontalBlurFragment).
        full = {str(i): 0 for i in by.values()}
        full.update({str(by[n]): v for n, v in values.items()})
        return full
    fc = fcidx('ShadowCompositeFragment', dict(enable_rgba_shadow=1, enable_noise=0, enable_hdr=1, enable_fade=1))
    scenes['sl_shadow_composite_fc'] = dict(
        vs=sl('SimpleVertex'), fs=sl('ShadowCompositeFragment', fc=fc),
        vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 64, 64)),
        buffers=dict(vertex=[mvp], fragment=[dict(index=0, floats=[1.1, 0.8, 1.5, 0])]),
        textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    # Shadow blur, radius 12 (baked Gaussian table = shader constant data), soft rim of radius 2
    names = dict(is_horizontal=1, is_rim_state_soft=1, is_radius_eq_12=1, is_radius_ge_3=1, is_rim_radius_eq_2=1)
    fc = fcidx('ShadowHorizontalBlurFragment', names)
    fargs = [2, 0, 0] + [0]   # ints _rim_radius, _inner_rim_radius, _tex_coord_offset, then float _density
    scenes['sl_shadow_hblur_r12_soft'] = dict(
        vs=sl('SimpleVertexShadow'), fs=sl('ShadowHorizontalBlurFragment', fc=fc),   # varying 'tc': pairs with SimpleVertexShadow
        vertex=simple_vertex_draw(quad(16, 0, 80, 64, 0, 0, 64, 64)),
        buffers=dict(vertex=[mvp], fragment=[dict(index=1, uints=[2, 0, 0], floats=[])]),
        textures=[dict(index=0, width=64, height=64, format='rgba8', file=tex)])
    # _density/_rim_density/... follow the three ints: build the 64-byte ShadowBlur_FragmentArgs by hand
    fa = struct.pack('<3i3f2i', 2, 0, 0, 1.0, 0.8, 0.0, 0, 0) + struct.pack('<4f', 1, 1, 1, 1) + struct.pack('<4f', 1, 1, 1, 1)
    fp = os.path.join(OUT, 'data', 'shadowblur_fargs.bin'); open(fp, 'wb').write(fa)
    scenes['sl_shadow_hblur_r12_soft']['buffers']['fragment'] = [dict(index=1, file=os.path.relpath(fp, ROOT))]
    scenes.update(xr_scenes(tex, mvp))
    for name, s in scenes.items():
        if s is None: continue
        s.update(name=name, width=W, height=H, clear=[0.1, 0.2, 0.3, 1.0], frames=3, format='bgra8')
        json.dump(s, open(os.path.join(OUT, name + '.json'), 'w'), indent=1)
    print('scenes:', ', '.join(n for n, s in scenes.items() if s))

if __name__ == '__main__':
    main()
