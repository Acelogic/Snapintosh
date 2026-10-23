#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The plug-in's UBO staging arenas give back GPU address space, end to end on this Mac (26A428).

docs/PLUGIN-ARENA-TRIM-20261021.md (failure modes A1-A20). The real plug-in bundle renders Core Animation's bench scenes
at 2880x1800 (gpu/adreno-kext/plugin/harness/ca-generic.m, CA_BENCH, default-device interpose, commits intercepted).
Command buffers complete 3 frames late (CA_BENCH_LAG=3), as the A16's GPU keeps frames in flight. An independent
harness gauge puts a dealloc sentinel on every staging arena the plug-in allocates. Checks:
  inflight   run A (lag 3, NSZombieEnabled) and run D (the same with a forced drain every 2 frames): no command buffer's
             staging destination (CP_MEMCPY destination relocation) is an arena that a command buffer in flight during
             its encoding also writes (A1); every arena is freed only after every command buffer that wrote it completed
             (A1, A3, A14); within a command buffer no two staging slices overlap, each is 64-byte aligned and inside its
             arena (A10); nothing is omitted and no command buffer needed the watchdog. Run A must reuse arenas across
             command buffers (else the check sees nothing); run D must drain at least 5 times
  steady     run B (lag 3): after each scene's 3 warm-up frames no new arena is allocated (A5)
  idle       run B: 600 ms after each scene, with no plug-in call, no staging arena is alive, even though Core Animation
             keeps its last command buffer (A6, A20); at the end the timer stops firing (A7)
  faults     run B: an injected IOGPU allocation failure drains a non-empty pool and is retried once (buffer and
             texture); with an empty pool it is not retried (A8, A16)
  gauge      the plug-in's live counts equal the harness's; its peak equals the harness's (A13)
  source     no release between gAdrenoStagingLock's lock and unlock in AdrenoDrawCommands.m and its parts (A4)
  stats      the plug-in's diagnostics stats line carries the arenas(...) fields and stays under 1 KB (A19)
--expect-before: the unchanged plug-in must fail at least one check.

    python3 tools/test-adreno-staging-arenas.py --bundle BUNDLE --output NEW-DIR [--expect-before]
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
REGS = ROOT / 'gpu/adreno-kext/include/AdrenoA8xxRegs.h'
DRAW = ROOT / 'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoDrawCommands.m'
LAG = 3
SCENES_A = ['drag-window', 'bench-blurfull', 'drag-glass']
SCENES_B = ['drag-window', 'drag-glass', 'scroll-list']


def load_drawpkg():
    spec = importlib.util.spec_from_file_location('drawpkg', ROOT / 'tools/test-adreno-draw-package.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def staging_destinations(cmd_bytes, memcpy, P):
    """(rid, offset, length) of every CP_MEMCPY destination relocation in one commit's kernel commands."""
    out = []
    for kind, command in P.kernel_commands(cmd_bytes):
        if kind != 0x1002:
            continue
        pkg = P.parse_package(command)
        words = struct.unpack_from('<%dI' % pkg['ib_dwords'], pkg['package'], 0)
        by_lo = {r['lo']: r for r in pkg['relocs']}
        pos = 0
        while pos < len(words):
            h = words[pos]
            n = h & (0x7f if h >> 28 == 4 else 0x3fff)
            if h >> 28 == 7 and (h >> 16) & 0x7f == memcpy:
                r = by_lo.get(4 * (pos + 4))
                if r is None or r['kind'] != 1:
                    out.append(('unrelocated', pos, 0))
                else:
                    out.append((r['resource_id'], r['offset'], r['length']))
            pos += 1 + n
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
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
    bundle = str(args.bundle.resolve())
    P = load_drawpkg()
    memcpy = int(re.search(r'^#define A8XX_E_CP_MEMCPY (0x[0-9a-f]+)u$', REGS.read_text(), re.M).group(1), 16)
    failures, checks = [], 0
    summary = {}

    def check(ok, what):
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    base = {k: v for k, v in os.environ.items() if not k.startswith('CA_') and k not in ('NSZombieEnabled',)}
    base.update(CA_BENCH='1', CA_GENERIC_TEST_DELAY_MS='0', CA_BENCH_ARENAS='1', CA_BENCH_LAG=str(LAG),
                DYLD_INSERT_LIBRARIES=str(lib))

    def run(name, env, scenes):
        d = out / name
        r = subprocess.run([str(exe), '--adreno', bundle, str(d)] + scenes, capture_output=True, text=True,
                           env=dict(base, CA_GENERIC_TEST_WARMUP=','.join(scenes), **env), timeout=1800)
        (out / f'{name}.log').write_text(r.stdout + r.stderr)
        check(r.returncode == 0, f'{name}: harness exit {r.returncode}')
        report = json.loads((d / 'report.json').read_text()) if (d / 'report.json').is_file() else {}
        pid = re.search(r'^PID (\d+)$', r.stdout, re.M)
        return d, report, r.stdout, int(pid.group(1)) if pid else None

    def inflight_run(name, extra):
        d, report, stdout, _ = run(name, dict(CA_BENCH_FRAMES='12', NSZombieEnabled='YES', **extra), SCENES_A)
        arenas = report.get('arenas', {})
        commits = report.get('commits', [])
        events = arenas.get('events', [])
        check(bool(commits) and bool(events), f'{name}: {len(commits)} commits, {len(events)} arena events')
        check(arenas.get('gauge_end', {}).get('watchdog', 1) == 0, f'{name}: {arenas.get("gauge_end", {}).get("watchdog")} '
              'command buffers completed by the watchdog (the frame model is not exact)')
        check(sum(int(c['omitted']) for c in commits) == 0 and not any(c['encoding_failed'] for c in commits),
              f'{name}: draws omitted or encodings failed')
        # Arena lifetimes per resource ID: (new seq, free seq or inf, bytes).
        life = {}
        for e in sorted(events, key=lambda e: e['seq']):
            if e['event'] == 'new':
                life.setdefault(e['rid'], []).append([e['seq'], float('inf'), e['bytes']])
            elif e['event'] == 'free' and e['rid'] in life and life[e['rid']][-1][1] == float('inf'):
                life[e['rid']][-1][1] = e['seq']

        def lifetime(rid, seq):
            for i, (born, died, nbytes) in enumerate(life.get(rid, [])):
                if born < seq < died:
                    return i, nbytes, died
            return None
        uses = []          # (commit index, frame, (rid, lifetime), completed_seq)
        overlap = misplaced = unknown = inflight_reuse = early_free = 0
        staged = 0
        examples = []
        for i, c in enumerate(commits):
            cap = d / c['dir'] / 'commands.bin'
            if not int(c['encoded']) or not cap.is_file():
                continue
            dests = staging_destinations(cap.read_bytes(), memcpy, P)
            staged += len(dests)
            spans = {}
            for rid, off, length in dests:
                if rid == 'unrelocated':
                    unknown += 1
                    continue
                lt = lifetime(rid, c['seq'])
                if lt is None:
                    unknown += 1
                    if len(examples) < 4:
                        examples.append(f'commit {i}: destination resource {rid} is not a staging arena alive at commit')
                    continue
                idx, nbytes, died = lt
                if off % 64 or off + length > nbytes:
                    misplaced += 1
                spans.setdefault((rid, idx), []).append((off, off + length))
                uses.append((i, c['frame'], (rid, idx), c.get('completed_seq'), died))
            for key, ss in spans.items():
                ss.sort()
                overlap += sum(1 for a, b in zip(ss, ss[1:]) if b[0] < a[1])
        by_arena = {}
        for i, frame, key, completed, died in uses:
            by_arena.setdefault(key, set()).add((i, frame))
            if completed is None or died <= completed:
                early_free += 1
                if len(examples) < 8:
                    examples.append(f'commit {i}: arena {key} freed at seq {died}, command buffer completed at {completed}')
        # Completions run only between frames (frame ends and scene-end flushes; the watchdog never fired), so command
        # buffer j is in flight while i is encoded exactly when j was committed before i and completed after i's frame began.
        starts = arenas.get('frame_starts', [])
        completed = {i: c.get('completed_seq') for i, c in enumerate(commits)}
        for key, users in by_arena.items():
            users = sorted(users)
            for (i, fi) in users:
                for (j, fj) in users:
                    if j < i and fi < len(starts) and (completed.get(j) is None or completed[j] > starts[fi]):
                        inflight_reuse += 1
                        if len(examples) < 12:
                            examples.append(f'arena {key}: commit {i} (frame {fi}) reuses it while commit {j} (frame {fj}) is in flight')
        reused = sum(1 for users in by_arena.values() if len({i for i, _ in users}) > 1)
        summary[name] = dict(reused_across_command_buffers=reused, commits=len(commits), staged_copies=staged, arenas=len(by_arena), overlap=overlap,
                                   misplaced=misplaced, unknown=unknown, inflight_reuse=inflight_reuse, early_free=early_free,
                                   plugin=arenas.get('plugin_end'), examples=examples)
        check(staged > 0, f'{name}: no staged copies seen (the checks cannot see anything)')
        check(overlap == 0, f'{name}: {overlap} overlapping staging slices in a command buffer')
        check(misplaced == 0, f'{name}: {misplaced} staging slices unaligned or outside their arena')
        check(unknown == 0, f'{name}: {unknown} staging destinations that are not a live staging arena')
        check(inflight_reuse == 0, f'{name}: {inflight_reuse} arenas reused while in flight: {examples[:3]}')
        check(early_free == 0, f'{name}: {early_free} arenas freed before their command buffer completed')
        plugin = arenas.get('plugin_end') or {}
        if extra.get('CA_BENCH_RELIEVE_EVERY'):
            check(bool(arenas.get('relieve_exported')), f'{name}: the plug-in exports no AdrenoStagingRelieve (forced drains)')
            check(int(plugin.get('drains', 0)) >= 5, f'{name}: forced drains {plugin.get("drains")} (the stress did not run)')
        else:
            check(reused >= 20, f'{name}: only {reused} arenas reused across command buffers (the in-flight check sees nothing)')
        check(int(plugin.get('continued', 0)) > 0, f'{name}: no render pass continued its command buffer\'s arena')

    for name, extra in (('inflight', {}), ('drains', dict(CA_BENCH_RELIEVE_EVERY='2'))):
        inflight_run(name, extra)

    # ---- run B: steady state, idle, faults, final idle
    d, report, stdout, pid = run('idle', dict(CA_BENCH_FRAMES='13', CA_BENCH_NOCAPTURE='1', CA_BENCH_IDLE_MS='600',
                                               CA_BENCH_FAULTS='1', CA_BENCH_FINAL_IDLE_MS='700'), SCENES_B)
    arenas = report.get('arenas', {})
    scenes = arenas.get('scenes', [])
    summary['idle'] = dict(scenes=scenes, faults=arenas.get('faults'), final_idle={k: v for k, v in arenas.get('final_idle', {}).items()
                           if k in ('ms', 'live', 'live_bytes', 'live_later')}, gauge_end=arenas.get('gauge_end'),
                           plugin=arenas.get('plugin_end'))
    check(len(scenes) == len(SCENES_B), f'idle: {len(scenes)} scene gauges of {len(SCENES_B)}')
    for s in scenes:
        check(s['new_after_warmup'] == 0, f'steady: {s["scene"]}: {s["new_after_warmup"]} new arenas after the warm-up frames')
        check(s['idle'] == 0 and s['idle_bytes'] == 0, f'idle: {s["scene"]}: {s["idle"]} arenas ({s["idle_bytes"] >> 10} KiB) '
              f'alive {s["idle_ms"]} ms after the scene ({s["idle_live_command_buffers"]} command buffers alive)')
    gauge, plugin = arenas.get('gauge_end', {}), arenas.get('plugin_end') or {}
    check(plugin.get('live') == gauge.get('live') and plugin.get('live_bytes') == gauge.get('live_bytes'),
          f'gauge: plug-in live {plugin.get("live")}/{plugin.get("live_bytes")} != harness {gauge.get("live")}/{gauge.get("live_bytes")}')
    check(plugin.get('peak_live') == gauge.get('peak') and plugin.get('peak_live_bytes') == gauge.get('peak_bytes'),
          f'gauge: plug-in peak {plugin.get("peak_live")}/{plugin.get("peak_live_bytes")} != harness {gauge.get("peak")}/{gauge.get("peak_bytes")}')
    faults = arenas.get('faults') or {}
    tp, be, bp = faults.get('texture_pooled', {}), faults.get('buffer_empty', {}), faults.get('buffer_pooled', {})
    check(tp.get('pooled_before', 0) > 0 and tp.get('ok') == 1 and tp.get('armed_left') == 0 and tp.get('drains') == 1 and
          tp.get('retries') == 1 and tp.get('failures') == 1 and tp.get('pooled_after') == 0,
          f'faults: texture with a pooled arena: {tp}')
    check(be.get('pooled_before') == 0 and be.get('ok') == 0 and be.get('armed_left') == 0 and be.get('retries') == 0 and
          be.get('failures') == 1, f'faults: buffer with an empty pool: {be}')
    check(bp.get('pooled_before', 0) > 0 and bp.get('ok') == 1 and bp.get('armed_left') == 0 and bp.get('drains') == 1 and
          bp.get('retries') == 1 and bp.get('pooled_after') == 0, f'faults: buffer with a pooled arena: {bp}')
    fi = arenas.get('final_idle') or {}
    check(fi.get('live') == 0 and fi.get('live_later') == 0, f'idle: final: {fi.get("live")} arenas alive after {fi.get("ms")} ms')
    a, b = fi.get('plugin') or {}, fi.get('plugin_later') or {}
    check(a.get('timer_fires') is not None and a.get('timer_fires') == b.get('timer_fires'),
          f'idle: the timer still fires with an empty pool ({a.get("timer_fires")} -> {b.get("timer_fires")})')
    check(a.get('pooled_count') == 0, f'idle: {a.get("pooled_count")} arenas pooled after the final idle')
    # ---- the stats line
    line = None
    if pid:
        log = Path(f'/private/var/tmp/adreno-ca-generic-{pid}.log')
        if log.is_file():
            for l in log.read_text(errors='replace').splitlines():
                if ' stats commits=' in l:
                    line = l
    summary['stats_line'] = line
    check(line is not None and ' arenas(live/live_kib/peak/peak_kib/pooled_kib/aged/capped/drains/failures/retries_ok/continued)='
          in line and len(line) <= 1024, f'stats: the diagnostics stats line lacks the arenas fields: {line and line[-200:]}')
    # ---- source check (A4)
    src = read_source(DRAW)
    bad = []
    for m in re.finditer(r'os_unfair_lock_lock\(&gAdrenoStagingLock\);(.*?)os_unfair_lock_unlock\(&gAdrenoStagingLock\);', src, re.S):
        if re.search(r'CFBridgingRelease|__bridge_transfer|CFRelease|AdrenoStagingReleaseVictims', m.group(1)):
            bad.append(src[:m.start()].count('\n') + 1)
    check(bool(re.search(r'os_unfair_lock_lock\(&gAdrenoStagingLock\)', src)) and not bad,
          f'source: a release inside gAdrenoStagingLock at lines {bad} of the expanded unit')
    result = dict(checks=checks, failures=failures, summary=summary, bundle=bundle, expect_before=args.expect_before)
    (out / 'result.json').write_text(json.dumps(result, indent=2, default=str) + '\n')
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
    s, t = summary['inflight'], summary['drains']
    print(f'PASS: {checks} checks (in flight: {s["commits"]} commits, {s["staged_copies"]} staged copies in {s["arenas"]} '
          f'arena lifetimes, {s["reused_across_command_buffers"]} reused across command buffers, none while in flight or '
          f'freed early; with forced drains: {t["commits"]} commits, {t["plugin"].get("drains")} drains, the same; idle: every '
          f'scene 0 arenas after 600 ms); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
