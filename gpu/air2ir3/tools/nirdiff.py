#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""nirdiff.py - NIR-level differential check of air2ir3 against Mesa's own front end.

For each pair in tests/nirdiff/manifest.json (a real WindowServer AIR function + a hand-written
equivalent GLSL, glslc -> SPIR-V -> Mesa spirv_to_nir):
  1. build/nirdiff: canonical NIR signature diff + ir3 stats/binary of both   -> <name>.json
For each scene:
  2. build/nirexec renders the scene with the AIR-derived NIR and with the SPIR-V-derived NIR on
     llvmpipe (identical gallium state); both are compared with each other and with the M3 Max
     Metal golden (results/exec/<scene>.metal.bgra, frame 2 of 3; tools/exec.py).
  python3 tools/nirdiff.py [--out results/nirdiff]
"""
import argparse, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = os.path.join(ROOT, 'tests', 'nirdiff')
SPV = os.path.join(ROOT, 'build', 'spv')

def glslc(name):
    src, dst = os.path.join(T, name), os.path.join(SPV, name + '.spv')
    if not os.path.exists(dst) or os.path.getmtime(dst) < os.path.getmtime(src):
        subprocess.run(['glslc', '--target-env=vulkan1.2', '-O0', src, '-o', dst], check=True)
    return dst

def diff(a, b):
    d = [abs(x - y) for x, y in zip(a, b)]
    return max(d), sum(d) / len(d), sum(1 for p in range(len(d) // 4) if max(d[p * 4:p * 4 + 4]) > 3)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(ROOT, 'results', 'nirdiff'))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True); os.makedirs(SPV, exist_ok=True)
    man = json.load(open(os.path.join(T, 'manifest.json')))
    summary = dict(pairs=[], scenes=[])
    for p in man['pairs']:
        name = os.path.splitext(p['glsl'])[0] + ('' if 'templates' not in p['air'] else '@' + os.path.basename(p['air']).split('.')[0])
        jp = os.path.join(a.out, name + '.json')
        args = [os.path.join(ROOT, 'build', 'nirdiff'), '--air', os.path.join(ROOT, p['air']), '--spv', glslc(p['glsl']), '--json', jp]
        for k, v in p.get('fc', {}).items(): args += ['--fc', f'{k}={v}']
        r = subprocess.run(args, capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode > 1: print(r.stderr); summary['pairs'].append(dict(name=name, error=r.stderr.strip()[-300:])); continue
        j = json.load(open(jp))
        summary['pairs'].append(dict(name=name, air=p['air'], glsl=p['glsl'], fc=p.get('fc', {}), nir_identical=j['nir_identical'],
                                     only_air=j['only_air'], only_spv=j['only_spv'], air_ops=j['air_ops'], spv_ops=j['spv_ops'],
                                     ir3_air=j['ir3_air'], ir3_spv=j['ir3_spv'], ir3_binary_identical=j['ir3_binary_identical']))
    ex = os.path.join(ROOT, 'results', 'exec')
    for s in man['scenes']:
        sc = os.path.join(ROOT, 'scenes', s['scene'] + '.json')
        outs = {}
        for mode in ('air', 'spv'):
            o = os.path.join(a.out, f"{s['scene']}.{mode}.bgra")
            args = [os.path.join(ROOT, 'build', 'nirexec'), sc, o, '--frames', '3']
            if mode == 'spv':
                if 'vs' in s: args += ['--spv-vs', glslc(s['vs'])]
                if 'fs' in s: args += ['--spv-fs', glslc(s['fs'])]
            r = subprocess.run(args, capture_output=True, text=True)
            if r.returncode: print(r.stderr); outs[mode] = None; continue
            outs[mode] = open(o, 'rb').read()
        gold = os.path.join(ex, s['scene'] + '.metal.bgra')
        g = open(gold, 'rb').read() if os.path.exists(gold) else None
        row = dict(scene=s['scene'], spv_stages=[k for k in ('vs', 'fs') if k in s])
        if outs.get('air') and outs.get('spv'):
            row['air_vs_spv'] = dict(zip(('max_abs', 'mean_abs', 'px_over_3'), diff(outs['air'], outs['spv'])))
            row['air_vs_spv']['bit_identical'] = outs['air'] == outs['spv']
        for mode in ('air', 'spv'):
            if g and outs.get(mode): row[f'{mode}_vs_metal'] = dict(zip(('max_abs', 'mean_abs', 'px_over_3'), diff(outs[mode], g)))
        summary['scenes'].append(row)
        d = row.get('air_vs_spv', {})
        print(f"exec {s['scene']:24s} AIR-NIR vs SPV-NIR: {'bit-identical' if d.get('bit_identical') else 'max|d|=%s' % d.get('max_abs')}"
              f"   AIR vs Metal max|d|={row.get('air_vs_metal', {}).get('max_abs')}   SPV vs Metal max|d|={row.get('spv_vs_metal', {}).get('max_abs')}")
    json.dump(summary, open(os.path.join(a.out, 'summary.json'), 'w'), indent=1)
    n = len(summary['pairs']); ni = sum(1 for p in summary['pairs'] if p.get('nir_identical'))
    nb = sum(1 for p in summary['pairs'] if p.get('ir3_binary_identical'))
    ns = sum(1 for s in summary['scenes'] if s.get('air_vs_spv', {}).get('bit_identical'))
    print(f'NIR signatures identical {ni}/{n}; ir3 binaries identical {nb}/{n}; renders bit-identical {ns}/{len(summary["scenes"])}')

if __name__ == '__main__':
    main()
