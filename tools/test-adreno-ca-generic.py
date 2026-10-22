#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Core Animation's generic pipeline and its corner restore on the plug-in device, end to end on this Mac.

docs/USERSPACE-GRAPHICS-20261019.md ("Why rounded rects, blur and backdrop render black"): while a blended pipeline
compiles, Core Animation draws with its generic pipeline, which blends through framebuffer fetch. The plug-in device has
no framebuffer fetch, so those draws write unblended colour: the A16 glass probe's black rounded rects, blur and
backdrop. ("Window corner wedges: CoreAnimation's corner restore needs framebuffer fetch"): a layer that clips its
sublayers with rounded corners is drawn by restoring the backdrop outside the corners (Tbds), which reads the destination
by framebuffer fetch; without it the corner triangles are written 00000000, the desktop's wedges. The plug-in device
answers framebuffer fetch YES (memoryless NO), so both the generic pipeline and Tbds blend in the shader. The harness
(gpu/adreno-kext/plugin/harness/ca-generic.m) renders the probe's scenes and the clip scenes with pipeline compiles off
the render thread slowed to CA_GENERIC_TEST_DELAY_MS (the A16's compiles are slow), after a warm-up frame of each clip
scene. Checks:
  host      this Mac's GPU with its own answers renders the clip scenes (their reference)
  control   this Mac's GPU answering like the plug-in device but with framebuffer fetch forced NO: the clip scenes must
            NOT match their reference, and with CA_FORCE_GENERIC_SHADERS=1 the blended scenes must NOT match either (the
            comparison sees both failures)
  pixels    this Mac's GPU answering like the plug-in device (created from BUNDLE first, as Metal does): every scene
            matches (build/current-assets/glass-probe-20261019/host-ref.txt, the host run for the clip scenes), and every
            generic draw fetches; again with CA_DISABLE_GENERIC_SHADERS=1, where the clip scenes' corners must be drawn
            by a fetching Tbds pipeline
  plug-in   the plug-in device renders the same scenes: every pipeline builds and is classified, generic draws fetch,
            the clip scenes draw a fetching Tbds pipeline, every commit encodes with nothing omitted, and every
            commit's kernel commands replay through the production kext validator
  staging   the plug-in device renders a full-size 2880x1800 bench scene (CA_BENCH, bench-desk, specialised pipelines:
            CoreAnimation binds its 256 KB uniform buffer at 16-byte offsets, so its UBOs are staged with CP_MEMCPY):
            the staged copies' median is at most 4 KB, what the shaders can read, not the rest of the buffer ("Speed:
            CoreAnimation uniforms staged by the kilobyte"), or (agents/gpu-perf's per-command-buffer UBO mirror) the
            copies total at most 2 MiB per commit; and nothing is omitted
--expect-before: the unchanged plug-in must fail at least one check. The host must run 26A428 (the guest's build).

    python3 tools/test-adreno-ca-generic.py --bundle BUNDLE --output NEW-DIR [--expect-before]
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
REFERENCE = ROOT / 'build/current-assets/glass-probe-20261019/host-ref.txt'
GLASS = ['shadow', 'shadow-path', 'window', 'window-masked', 'blur', 'backdrop']
CLIP = ['clip-cont', 'clip-circ']
SCENES = GLASS + CLIP
BLENDED = ['window', 'window-masked', 'blur', 'backdrop']
WARMUP = 'square,clip-cont,clip-circ'
W, H = 96, 64
LUMA_TOLERANCE, SAMPLE_TOLERANCE = 6, 2      # per sample; samples allowed to differ per scene (of 48 x 32)
CHANNEL_TOLERANCE, PIXEL_TOLERANCE = 6, 4    # clip scenes: per channel; pixels allowed to differ (of 96 x 64)
FETCH_CODE = re.compile(r'X([a-z]+)(?=_|$)')   # Core Animation's output code: Xc, Xfc, Xgfc ('f': framebuffer fetch)


def fetches(label):
    codes = FETCH_CODE.findall(label.split('.')[-1])
    return bool(codes) and 'f' in codes[-1]


def pixels_differing(a, b):
    """Clip scenes against this Mac's own render: pixels with any channel (BGRA, alpha included) off by more than 6."""
    return sum(1 for p in range(0, W * H * 4, 4) if max(abs(a[p + k] - b[p + k]) for k in range(4)) > CHANNEL_TOLERANCE)


def reference_maps():
    maps, cur = {}, None
    for line in REFERENCE.read_text().splitlines():
        m = re.match(r'MAP (\S+) 96x64 step 2', line)
        if m:
            cur = maps.setdefault(m.group(1), [])
        elif cur is not None and re.fullmatch(r'([0-9a-f]{6} ){47}[0-9a-f]{6}', line.strip()):
            cur.append(line.split())
        else:
            cur = None
    return maps


def luma(rgb):
    v = int(rgb, 16)
    return 0.299 * (v >> 16) + 0.587 * ((v >> 8) & 255) + 0.114 * (v & 255)


def differing(bgra, rows):
    """Samples (glass-probe.js hexRows: every other pixel, RGB) whose luma differs from the reference."""
    n = 0
    for j, y in enumerate(range(0, H, 2)):
        for i, x in enumerate(range(0, W, 2)):
            p = 4 * (y * W + x)
            if abs(luma('%02x%02x%02x' % (bgra[p + 2], bgra[p + 1], bgra[p])) - luma(rows[j][i])) > LUMA_TOLERANCE:
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    ap.add_argument('--delay-ms', type=int, default=2000)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    build = subprocess.run(['sw_vers', '-buildVersion'], capture_output=True, text=True).stdout.strip()
    if build != '26A428':
        print(f'FAIL: host build {build}, not 26A428')
        return 1
    lib, exe = out / 'default-device-interpose.dylib', out / 'ca-generic'
    subprocess.run(['xcrun', 'clang', '-dynamiclib', '-arch', 'arm64e', str(HARNESS / 'default-device-interpose.m'), '-o', str(lib),
                    '-framework', 'Foundation', '-framework', 'Metal'], check=True)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', '-Wall', '-Werror', str(HARNESS / 'ca-generic.m'),
                    '-o', str(exe), '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'QuartzCore',
                    '-framework', 'IOSurface', '-framework', 'IOKit', '-framework', 'CoreGraphics'], check=True)
    for f in (lib, exe):
        subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
    base = {k: v for k, v in os.environ.items() if k not in ('CA_DISABLE_GENERIC_SHADERS', 'CA_FORCE_GENERIC_SHADERS')}
    base['CA_GENERIC_TEST_DELAY_MS'] = str(args.delay_ms)
    base['CA_GENERIC_TEST_WARMUP'] = WARMUP
    base.pop('CA_TEST_FETCH', None)
    bundle = str(args.bundle.resolve())
    failures, checks = [], 0

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    def run(name, mode, env, insert=False, scenes=None):
        d = out / name
        e = dict(env)
        if insert:
            e['DYLD_INSERT_LIBRARIES'] = str(lib)
        r = subprocess.run([str(exe), mode, bundle, str(d)] + (scenes or SCENES), capture_output=True, text=True, env=e,
                           timeout=1800)
        (out / f'{name}.log').write_text(r.stdout + r.stderr)
        check(r.returncode == 0, f'{name}: harness exit {r.returncode}')
        report = json.loads((d / 'report.json').read_text()) if (d / 'report.json').is_file() else {}
        return d, report

    ref = reference_maps()
    summary = {}

    def compare(d, which):
        """Per scene: samples differing from host-ref.txt (glass scenes) or pixels differing from the host run (clip)."""
        out = {}
        for s in which:
            f = d / f'{s}.bgra'
            if not f.is_file():
                continue
            out[s] = pixels_differing(f.read_bytes(), clip_ref[s]) if s in CLIP else differing(f.read_bytes(), ref[s])
        return out

    def matches(s, n):
        return n is not None and n <= (PIXEL_TOLERANCE if s in CLIP else SAMPLE_TOLERANCE)

    def tbds(draws):
        return sorted({x['label'] for x in draws if x['scene'] in CLIP and 'Tbds' in x['label'] and fetches(x['label'])})
    # host: the clip scenes' reference, this Mac with its own answers
    d, report = run('host', '--host', base)
    clip_ref = {s: (d / f'{s}.bgra').read_bytes() for s in CLIP if (d / f'{s}.bgra').is_file()}
    check(set(clip_ref) == set(CLIP), f'host: rendered {sorted(clip_ref)} of {CLIP}')
    if set(clip_ref) != set(CLIP):
        clip_ref = {s: bytes(W * H * 4) for s in CLIP}
    # control: this Mac's GPU with the plug-in's answers but framebuffer fetch NO, as the plug-in answered before
    d, report = run('control-clip', '--host-caps', dict(base, CA_TEST_FETCH='0'))
    control = compare(d, CLIP)
    for s in CLIP:
        check(control.get(s, 0) > 10 * PIXEL_TOLERANCE, f'control: {s} matches without framebuffer fetch '
              f'({control.get(s)} pixels differ): the comparison cannot see the corner restore failing')
    d, report = run('control', '--host-caps', dict(base, CA_TEST_FETCH='0', CA_FORCE_GENERIC_SHADERS='1'))
    control.update({s: n for s, n in compare(d, BLENDED).items()})
    summary['control'] = dict(differing=control, generic_draws=sum(1 for x in report.get('draws', []) if x['generic']))
    for s in BLENDED:
        check(control.get(s, 0) > 10 * SAMPLE_TOLERANCE, f'control: {s} matches with the generic pipeline forced '
              f'and no framebuffer fetch ({control.get(s)} samples differ): the comparison cannot see the failure')
    # pixels: this Mac's GPU with the plug-in's answers and the plug-in device created first; then with generic off
    for name, env in (('pixels', base), ('pixels-specialised', dict(base, CA_DISABLE_GENERIC_SHADERS='1'))):
        d, report = run(name, '--host-caps', env)
        draws = [x for x in report.get('draws', []) if not x['scene'].startswith('warmup')]
        pixels = compare(d, SCENES)
        unfetched = sorted({x['scene'] + ': ' + x['label'] for x in draws if x['generic'] and not fetches(x['label'])})
        summary[name] = dict(differing=pixels, generic_draws=len([x for x in draws if x['generic']]), draws=len(draws),
                             tbds=tbds(draws))
        for s in SCENES:
            check(matches(s, pixels.get(s)), f'{name}: {s}: {pixels.get(s)} '
                  f'{"pixels of 6144" if s in CLIP else "samples of 1536"} differ from the reference')
        check(not unfetched, f'{name}: generic draws without framebuffer fetch: {unfetched[:4]}')
        if name == 'pixels-specialised':
            check(bool(tbds(draws)), f'{name}: the clip scenes draw no fetching Tbds pipeline')
    # plug-in: the plug-in device itself, with the generic pipeline allowed (its draws must fetch) and with it off (the
    # clip scenes' corners must come from a fetching Tbds pipeline: with slow compiles and generic allowed, Core
    # Animation may draw the whole clip scene through the generic pipeline before Tbds is built)
    kernel = None
    spec = importlib.util.spec_from_file_location('depth_stencil', ROOT / 'tools/test-adreno-depth-stencil.py')
    DS = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(DS)
    if not args.expect_before:
        kernel = DS.build_replay(out, guest_size=0x4000000, arena=0x3c00000, fixtures=160, capacity=320,
                                 name='kernel-replay-64m', arena_pages=129)
    for name, env in (('plugin', base), ('plugin-specialised', dict(base, CA_DISABLE_GENERIC_SHADERS='1'))):
        d, report = run(name, '--adreno', env, insert=True)
        draws, commits = report.get('draws', []), report.get('commits', [])
        unfetched = sorted({x['scene'] + ': ' + x['label'] for x in draws if x['generic'] and not fetches(x['label'])})
        unknown = [x for x in draws if x['label'] in ('', '?')]
        failed = sorted({p['label'] for p in report.get('pipelines', []) if not p['ok']})
        summary[name] = dict(draws=len(draws), generic_draws=len([x for x in draws if x['generic']]), commits=len(commits),
                             omitted=sum(int(c['omitted']) for c in commits), failed_pipelines=failed, tbds=tbds(draws),
                             encoding_failed=sum(1 for c in commits if c['encoding_failed']),
                             framebuffer_fetch=report.get('framebuffer_fetch'))
        check(bool(draws) and bool(commits), f'{name}: {len(draws)} draws, {len(commits)} commits')
        check(report.get('framebuffer_fetch') is True, f'{name}: the device answers framebuffer fetch {report.get("framebuffer_fetch")}')
        check(not failed, f'{name}: pipelines failed to build: {failed[:4]}')
        check(not unfetched, f'{name}: generic draws without framebuffer fetch: {unfetched[:4]}')
        if name == 'plugin-specialised':
            check(bool(tbds(draws)), f'{name}: the clip scenes draw no fetching Tbds pipeline')
        check(not unknown, f'{name}: {len(unknown)} draws with an unclassified pipeline')
        check(summary[name]['omitted'] == 0, f'{name}: {summary[name]["omitted"]} draws omitted')
        check(summary[name]['encoding_failed'] == 0, f'{name}: {summary[name]["encoding_failed"]} encodings failed')
        if kernel is None:
            continue
        replayed = 0
        for c in commits:
            cap = d / c['dir']
            # The harness's own fence commits encode nothing (one empty kernel command, no Adreno package).
            if not int(c['encoded']) or not (cap / 'commands.bin').is_file():
                continue
            try:
                DS.replay(kernel, cap, f'{name}-{c["dir"]}', window=0x3a00000)
                admitted = ''
            except Exception as error:                  # the replay module's own Fail class
                admitted = str(error)
            replayed += 1
            check(not admitted, f'{name}: {c["dir"]}: kext validator: {admitted[:300]}')
        summary[name]['replayed'] = replayed
    # staging: the size of every aligned-UBO staging copy in a full-size bench frame (CP_MEMCPY dword counts)
    # Steady state: the warm-up frame builds the specialised pipelines without the compile delay, as in a running
    # WindowServer, so the bench frames draw through them (the generic pipeline's pointer arguments keep full copies).
    d, report = run('plugin-bench', '--adreno', dict(base, CA_BENCH='1', CA_BENCH_FRAMES='4', CA_GENERIC_TEST_DELAY_MS='0',
                                                     CA_GENERIC_TEST_WARMUP='bench-desk'), insert=True, scenes=['bench-desk'])
    commits = report.get('commits', [])
    copies = []
    if True:
        memcpy = int(re.search(r'^#define A8XX_E_CP_MEMCPY (0x[0-9a-f]+)u$',
                               (ROOT / 'gpu/adreno-kext/include/AdrenoA8xxRegs.h').read_text(), re.M).group(1), 16)
        for c in commits:
            cap = d / c['dir'] / 'commands.bin'
            if not int(c['encoded']) or not cap.is_file():
                continue
            for kind, command in DS.P.kernel_commands(cap.read_bytes()):
                if kind != 0x1002:
                    continue
                nwords = struct.unpack_from('<IIIIIIIIQQ', command)[4]
                words, pos = struct.unpack_from('<%dI' % nwords, command, 48), 0
                while pos < len(words):
                    h = words[pos]
                    n = h & (0x7f if h >> 28 == 4 else 0x3fff)
                    if h >> 28 == 7 and (h >> 16) & 0x7f == memcpy:
                        copies.append(4 * words[pos + 1])
                    pos += 1 + n
            # The full-size frames' resources exceed the replay kernel's 64 MB guest window; the arena's relocations
            # are replayed in the plug-in runs above, whose scenes stage CoreAnimation's uniforms the same way.
    copies.sort()
    median = copies[len(copies) // 2] if copies else None
    summary['staging'] = dict(commits=len(commits), copies=len(copies), median_bytes=median,
                              total_bytes=sum(copies), omitted=sum(int(c['omitted']) for c in commits))
    if True:
        check(len(copies) > 0, 'staging: the bench scene staged no UBO (the comparison cannot see the copies)')
        # agents/gpu-perf (ADRENO_UBO_MIRROR): one CP_MEMCPY of the whole uniform buffer per command buffer (a mirror,
        # copied before the first pass that reads it) instead of one per binding. Either way the bytes copied per
        # frame stay small: the median per-binding copy is at most 4 KB, or the copies per encoded commit total at
        # most 2 MiB (the rest-of-buffer copy per binding this check guards against is about 10 MB per commit).
        encoded = max(1, sum(1 for c in commits if int(c['encoded'])))
        per_commit = sum(copies) / encoded
        summary['staging']['bytes_per_commit'] = int(per_commit)
        check(median is not None and (median <= 4096 or per_commit <= 2 << 20),
              f'staging: median staged UBO copy {median} bytes and {int(per_commit)} bytes per commit (more than 4 KB '
              f'per binding and 2 MiB per commit: the rest of the buffer is copied per binding, not what the shader reads)')
    check(summary['staging']['omitted'] == 0, f'staging: {summary["staging"]["omitted"]} draws omitted')
    result = dict(checks=checks, failures=failures, summary=summary, expect_before=args.expect_before,
                  bundle=bundle, delay_ms=args.delay_ms)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.expect_before:
        if failures:
            print(f'PASS: the unchanged plug-in fails {len(failures)} checks (first: {failures[0][:200]}); {out / "result.json"}')
            return 0
        print(f'FAIL: the unchanged plug-in passed every check; {out / "result.json"}')
        return 1
    if failures:
        for f in failures:
            print(f'FAIL {f[:400]}')
        print(f'FAIL: {len(failures)} of {checks} checks; {out / "result.json"}')
        return 1
    g, sp = summary['plugin'], summary['plugin-specialised']
    print(f'PASS: {checks} checks (plug-in: {g["draws"]} draws in {g["commits"]} commits, {g["generic_draws"]} generic, all '
          f'fetching; generic off: {sp["draws"]} draws, Tbds {sp["tbds"]}; {g.get("replayed", 0) + sp.get("replayed", 0)} '
          f'commits replayed); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
