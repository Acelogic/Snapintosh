#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""templates.py - instantiate SkyLight's 5 runtime MSL templates (the %s holes are filled by
SkyLight's ShaderComposerHelper.cc at run time) and compile them to AIR with this Mac's
26A428 Metal toolchain (xcrun metal -c).

The fill text uses SkyLight's own format strings (extracted from the SkyLight binary):
    // Gaussian blur radius:%d
      // Trim:%d * 2 = %d taps
      %s += %g * tex2D.sample(s, %s)%s;
      %s += %g * tex2D.sample(s, %s + float2(%g, %g))%s;
    // Max filter radius:%d
      %s = tex2D.sample(s, %s)%s;
      %s = max(%s, tex2D.sample(s, %s + float2(%g, %g))%s);
    // Max filter radius:%d, skipping horizontal.
      %s = %s tex2D.sample(s, %s)%s;            (with "1 -")
      %s = max(%s, %s (%g * tex2D.sample(s, %s + float2(%g, %g))%s));
Weights/offsets follow the usual bilinear-pair Gaussian (sigma = radius/2, pairs merged into one
linear tap).  They are NOT bit-identical to get_bilinear_gaussian_weight_and_steps(); the shape
(number of taps as a function of radius, swizzles, coordinate expressions) is what matters for
compile coverage.  Output: build/templates/<variant>.metal/.air + manifest.json
"""
import hashlib, json, math, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import metallib
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import scrdir
MSL = os.path.join(scrdir.scratchpad(), 'adreno', 'windowserver-metal-usage', 'msl')
OUT = os.path.join(ROOT, 'build', 'templates')

def g(x):  # %g
    return '%g' % x

def gaussian(var, coord, swz, radius, horizontal):
    if radius <= 0:
        return f'// Gaussian blur radius:{radius}\n  {var} += tex2D.sample(s, {coord}){swz};\n'
    sigma = max(radius / 2.0, 0.5)
    w = [math.exp(-(i * i) / (2 * sigma * sigma)) for i in range(radius + 1)]
    tot = w[0] + 2 * sum(w[1:])
    w = [x / tot for x in w]
    pairs = []
    i = 1
    while i <= radius:
        a = w[i]; b = w[i + 1] if i + 1 <= radius else 0.0
        off = i + (b / (a + b) if a + b > 0 else 0)
        pairs.append((a + b, off)); i += 2
    trim = len(pairs)
    s = f'// Gaussian blur radius:{radius}\n  // Trim:{trim} * 2 = {2 * trim} taps\n'
    s += f'  {var} += {g(w[0])} * tex2D.sample(s, {coord}){swz};\n'
    for wt, off in pairs:
        for sgn in (1, -1):
            dx, dy = (sgn * off, 0.0) if horizontal else (0.0, sgn * off)
            s += f'  {var} += {g(wt)} * tex2D.sample(s, {coord} + float2({g(dx)}, {g(dy)})){swz};\n'
    return s

def maxfilter(var, coord, swz, radius, horizontal, invert=False):
    if invert:
        s = f'// Max filter radius:{radius}, skipping horizontal.\n  {var} = 1 - tex2D.sample(s, {coord}){swz};\n'
    else:
        s = f'// Max filter radius:{radius}\n  {var} = tex2D.sample(s, {coord}){swz};\n'
    for d in range(1, radius + 1):
        for sgn in (1, -1):
            dx, dy = (sgn * d, 0.0) if horizontal else (0.0, sgn * d)
            if invert:
                wt = 1.0 - d / (radius + 1.0)
                s += f'  {var} = max({var}, 1 - ({g(wt)} * tex2D.sample(s, {coord} + float2({g(dx)}, {g(dy)})){swz}));\n'
            else:
                s += f'  {var} = max({var}, tex2D.sample(s, {coord} + float2({g(dx)}, {g(dy)})){swz});\n'
    return s

def fill(tmpl, parts):
    # replace the i-th "%s" hole with parts[i]
    out = tmpl
    for p in parts:
        k = out.index('%s')
        out = out[:k] + p + out[k + 2:]
    assert '%s' not in out
    return out

def variants():
    src = [open(os.path.join(MSL, f'skylight_src{i}.metal')).read() for i in range(5)]
    v = []
    for r in [1, 2, 4, 8, 16, 32, 64, 128]:
        v.append(('HorizontalBackgroundBlur', f'hbb_r{r}', 'HorizontalBackgroundBlur',
                  fill(src[0], [gaussian('color', 'in_frag.tex_coord', '', r, True)]), dict(radius=r)))
        v.append(('VerticalBackgroundBlurComposite', f'vbbc_r{r}', 'VerticalBackgroundBlurComposite',
                  fill(src[4], [gaussian('back', 'blurTexCoord', '', r, False)]), dict(radius=r)))
    for r in [0, 3, 12, 24, 56, 112, 236, 460, 712]:
        for rim in [0, 2, 4]:
            for glow in [0, 2]:
                tag = f'r{r}_rim{rim}_glow{glow}'
                sh = gaussian('shadow_alpha', 'in_frag.tex_coord', '.a', r, True)
                rm = maxfilter('rim_alpha', 'in_frag.tex_coord', '.a', rim, True) if rim else '// no rim'
                gl = maxfilter('glow_alpha', 'in_frag.tex_coord', '.a', glow, True, invert=True) if glow else '// no glow'
                v.append(('ShadowHorizontalBlur', f'shb_{tag}', 'ShadowHorizontalBlur', fill(src[1], [sh, rm, gl]),
                          dict(radius=r, rim=rim, glow=glow)))
                sh = gaussian('shadow_alpha', 'in_frag.tex_coord', '.g', r, False)
                rm = maxfilter('rim_alpha', 'in_frag.tex_coord + offset_vector', '.r', rim, False) if rim else '// no rim'
                gl = maxfilter('glow_alpha', 'in_frag.tex_coord + offset_vector', '.a', glow, False) if glow else '// no glow'
                v.append(('ShadowVerticalBlur', f'svb_{tag}', 'ShadowVerticalBlur', fill(src[2], [sh, rm, gl]),
                          dict(radius=r, rim=rim, glow=glow)))
                v.append(('ShadowVerticalBlurRGBA', f'svbrgba_{tag}', 'ShadowVerticalBlur', fill(src[3], [sh, rm, gl]),
                          dict(radius=r, rim=rim, glow=glow)))
    return v

def build(item):
    tmpl, name, entry, text, params = item
    mp = os.path.join(OUT, name + '.metal'); ap = os.path.join(OUT, name + '.air')
    open(mp, 'w').write(text)
    p = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', mp, '-o', ap], capture_output=True, text=True)
    r = dict(template=tmpl, variant=name, entry=entry, vertex_entry='SimpleVertex', params=params,
             metal=os.path.relpath(mp, ROOT), air=os.path.relpath(ap, ROOT), metal_rc=p.returncode,
             metal_err=p.stderr.strip()[:300], functions={})
    if p.returncode: return r
    # Link into a metallib exactly like a runtime library, then split per function (HASH tag + bitcode).
    lp = os.path.join(OUT, name + '.metallib')
    q = subprocess.run(['xcrun', '-sdk', 'macosx', 'metallib', ap, '-o', lp], capture_output=True, text=True)
    if q.returncode: r['metal_rc'] = q.returncode; r['metal_err'] = q.stderr.strip()[:300]; return r
    d, hdr, funcs = metallib.parse(lp)
    for f in funcs:
        s = hdr['bitcode'][0] + f['bc_off']; bc = d[s:s + f['bc_size']]
        bp = os.path.join(OUT, name + '.' + f['name'] + '.bc'); open(bp, 'wb').write(bc)
        r['functions'][f['name']] = dict(bc=os.path.relpath(bp, ROOT), air_hash=f.get('hash'), type=f.get('type'),
                                         hash_is_bc_sha256=hashlib.sha256(bc).hexdigest() == f.get('hash'))
    return r

if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    ver = subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
    with ThreadPoolExecutor(14) as ex:
        res = list(ex.map(build, variants()))
    json.dump(dict(toolchain=ver, variants=res), open(os.path.join(OUT, 'manifest.json'), 'w'), indent=1)
    bad = [r for r in res if r['metal_rc']]
    print(f'{len(res)} template variants, {len(bad)} failed in the Metal front end ({ver})')
    for r in bad[:5]: print(r['variant'], r['metal_err'])
