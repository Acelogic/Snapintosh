#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""compare.py - compare llvmpipe renders of the AIR-derived NIR with the M3 Max Metal goldens.

  python3 tools/compare.py results/exec [tol] [--scenes DIR]  -> results/exec/compare.json, contact sheet PNG

Files are <scene>.metal.bgra / <scene>.lp.bgra: the colour attachment's raw bytes in Metal's layout.
  bgra8      8-bit channels; PASS when max |diff| <= tol (default 3/255)
  bgr10_xr   MTLPixelFormatBGR10_XR: B,G,R 10-bit codes n, value (n-384)/510; alpha (padding) ignored
  bgra10_xr  MTLPixelFormatBGRA10_XR: 16-bit words B,G,R,A, code in the top 10 bits.  A blended
             UNORM16 store can leave the 6 low bits non-zero; the code is taken as word/64 (Metal's
             own words have them 0) and the count of such words is reported
  rgba16f    half floats; the difference is expressed in XR10 steps (1/510)
For XR and float targets the difference is in XR10 code steps (LSB); PASS when max <= 2 LSB (the
same order as the 3/255 of the 8-bit scenes: bilinear weights round differently on the two GPUs).
"""
import json, math, os, struct, sys, zlib

def png(path, w, h, rgb):
    raw = b''.join(b'\0' + bytes(rgb[y * w * 3:(y + 1) * w * 3]) for y in range(h))
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    open(path, 'wb').write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) +
                           chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))

def decode(fmt, data, W, H):
    """-> (per-pixel list of channel values in comparison units, displayable rgb bytes, extra)"""
    px, disp, extra = [], [], 0
    if fmt == 'bgra8':
        for p in range(W * H):
            b, g, r, a = data[p * 4:p * 4 + 4]; px.append((r, g, b, a)); disp += [r, g, b]
        return px, disp, extra
    vis = lambda v: max(0, min(255, int((v + 0.75) / 2.0 * 255)))
    if fmt == 'bgr10_xr':
        for p in range(W * H):
            w, = struct.unpack_from('<I', data, p * 4)
            n = ((w >> 20) & 1023, (w >> 10) & 1023, w & 1023)
            px.append(n); disp += [vis((x - 384) / 510) for x in n]
    elif fmt == 'bgra10_xr':
        for p in range(W * H):
            b, g, r, a = struct.unpack_from('<4H', data, p * 8)
            extra += sum(1 for x in (b, g, r, a) if x & 63)
            n = (r / 64, g / 64, b / 64, a / 64)
            px.append(n); disp += [vis((x - 384) / 510) for x in n[:3]]
    elif fmt == 'rgba16f':
        for p in range(W * H):
            v = struct.unpack_from('<4e', data, p * 8)
            px.append(tuple(x * 510 for x in v)); disp += [vis(x) for x in v[:3]]
    else:
        raise SystemExit('compare: format ' + fmt)
    return px, disp, extra

def main():
    argv = sys.argv[1:]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scdir = os.path.join(root, 'scenes')
    if '--scenes' in argv:          # scene JSONs outside scenes/ (tools/xrrand.py: xrscenes/)
        i = argv.index('--scenes'); scdir = argv[i + 1]; del argv[i:i + 2]
    d = argv[0] if len(argv) > 0 else 'results/exec'
    tol8 = int(argv[1]) if len(argv) > 1 else 3
    res, sheet_rows = {}, []
    for f in sorted(os.listdir(d)):
        if not f.endswith('.metal.bgra'): continue
        n = f[:-len('.metal.bgra')]
        sc = json.load(open(os.path.join(scdir, n + '.json')))
        W, H = sc['width'], sc['height']
        fmt = (sc.get('rt') or {}).get('format', 'bgra8')
        lp = os.path.join(d, n + '.lp.bgra')
        if not os.path.exists(lp): res[n] = dict(status='NO-LLVMPIPE'); continue
        A, da, xa = decode(fmt, open(os.path.join(d, f), 'rb').read(), W, H)
        B, db, xb = decode(fmt, open(lp, 'rb').read(), W, H)
        tol = tol8 if fmt == 'bgra8' else 2
        diffs = [max(abs(x - y) for x, y in zip(p, q)) for p, q in zip(A, B)]
        flat = [abs(x - y) for p, q in zip(A, B) for x, y in zip(p, q)]
        mx = max(diffs); mean = sum(flat) / len(flat)
        over = sum(1 for x in diffs if x > tol)
        mse = sum(x * x for x in flat) / len(flat)
        full = 255 if fmt == 'bgra8' else 1023
        psnr = float('inf') if mse == 0 else 10 * math.log10(full * full / mse)
        distinct = len(set(A))
        r = dict(status='PASS' if mx <= tol else 'FAIL', format=fmt, unit='1/255' if fmt == 'bgra8' else 'XR10 LSB (1/510)',
                 tolerance=tol, max_abs_diff=round(mx, 3), mean_abs_diff=round(mean, 4), pixels_over_tol=over, pixels=W * H,
                 psnr_db=None if psnr == float('inf') else round(psnr, 2), distinct_golden_values=distinct,
                 vs=sc['vs']['function'], fs=sc['fs']['function'], frames=sc.get('frames', 3), blend=sc.get('blend'))
        if fmt == 'bgra10_xr': r['words_with_low_bits'] = dict(metal=xa, llvmpipe=xb)
        res[n] = r
        row = []
        for y in range(H):
            line = []
            for img in (da, db, None):
                for x in range(W):
                    p = y * W + x
                    if img is None: v = min(255, int(64 * diffs[p] / max(tol, 1))); line += [v, v, v]
                    else: line += img[p * 3:p * 3 + 3]
                line += [255, 255, 255] * 4
            row.append(line)
        sheet_rows.append((W, row))
    json.dump(res, open(os.path.join(d, 'compare.json'), 'w'), indent=1)
    if sheet_rows:
        w = max(len(r[1][0]) for r in sheet_rows) // 3
        rgb = []
        for W, rows in sheet_rows:
            for line in rows: rgb += line + [255, 255, 255] * (w - len(line) // 3)
            rgb += [255, 255, 255] * w * 4
        h = len(rgb) // (w * 3)
        png(os.path.join(d, 'contact-sheet.png'), w, h, rgb)
    for n, r in res.items():
        if r['status'] == 'NO-LLVMPIPE': print('NO-LP', n); continue
        print(f"{r['status']:5s} {n:28s} {r['format']:9s} max|d|={r['max_abs_diff']} ({r['unit']}) mean={r['mean_abs_diff']} "
              f"over_tol={r['pixels_over_tol']}/{r['pixels']} psnr={r['psnr_db']}")
    sys.exit(1 if any(r['status'] == 'FAIL' for r in res.values()) else 0)

if __name__ == '__main__':
    main()
