#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check a tools/host/ubo-mirror run (agents/gpu-perf FAILURE-MODES.md U1-U13): execute its command streams
symbolically (tools/ubocheck.py: snapshots, FILL32s and CP_MEMCPYs in order) and require that every draw's constant
buffers hold exactly the bytes report.json says Metal semantics give it at GPU time. Also prints, per render pass,
how its unaligned constants were read: from a mirror copied by a prelude, or copied inside the pass.
    ubo-mirror-check.py RUN_DIR [--expect-mirror | --expect-inpass]"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C  # noqa: E402
import ubocheck as U  # noqa: E402
import ibstats as I  # noqa: E402

run = Path(sys.argv[1]); mode = sys.argv[2] if len(sys.argv) > 2 else ''
report = json.loads((run / 'report.json').read_text())
draws = []
for c in report['commits']:
    blobs = []
    rows = {r['id']: r for r in c.get('resources', [])}
    for d in U.commit_draws(run, c):
        draws.append(d)
# the signatures hold hashes; recompute raw bytes per draw for the comparison
def raw_draws(c):
    import hashlib
    out = []
    cdir = run / c['dir']
    rows = {r['id']: r for r in c.get('resources', [])}
    mem = U.Memory(cdir, rows)
    E = C.regs()['E']
    for kind, cmd in C.kernel_commands((cdir / 'commands.bin').read_bytes()):
        if kind == C.KCMD_FILL32:
            fl = C.fill32(cmd)
            import struct
            mem.write(fl['rid'], fl['offset'], struct.pack('<I', fl['pattern']) * (fl['bytes'] // 4))
            continue
        if kind != C.KCMD_IB:
            continue
        pkg = C.parse_package(cmd); relocs = {r['lo']: r for r in pkg['relocs']}
        ubo = {}
        for ev in C.walk(C.ib_words(pkg)):
            if ev[0] != 'pkt':
                continue
            _, at, op, body = ev
            if op == E['CP_MEMCPY']:
                s, d = relocs.get(4 * (at + 2)), relocs.get(4 * (at + 4)); n = 4 * body[0]
                data = mem.read(s['rid'], s['offset'], n)
                if data is None: mem.unknown(d['rid'], d['offset'], n)
                else: mem.write(d['rid'], d['offset'], data)
            elif op in (E['CP_LOAD_STATE6_GEOM'], E['CP_LOAD_STATE6_FRAG']):
                w0 = body[0]
                if (w0 >> 14) & 3 != E['ST6_UBO'] or (w0 >> 16) & 3 != E['SS6_DIRECT']:
                    continue
                stage = 'vs' if op == E['CP_LOAD_STATE6_GEOM'] else 'fs'
                for k in range((w0 >> 22) & 0x3ff):
                    r = relocs.get(4 * (at + 4 + 2 * k)); size = ((body[4 + 2 * k] >> 17) & 0x7fff) * 16
                    ubo[(stage, (w0 & 0x3fff) + k)] = (r['rid'], r['offset'], size) if r and r['kind'] == C.RELOC_RESOURCE else None
            elif op == E['CP_DRAW_INDX_OFFSET']:
                got = []
                for key, d in sorted(ubo.items()):
                    if d:
                        got.append((key, d[2], mem.read(d[0], d[1], d[2])))
                out.append(got)
    return out
all_draws = []
for c in report['commits']:
    all_draws.extend(raw_draws(c))
exp = report['expected']
fail = []
if len(all_draws) != len(exp):
    fail.append(f'{len(all_draws)} draws in the streams, {len(exp)} expected')
for i, (got, e) in enumerate(zip(all_draws, exp)):
    for blob in e['blobs']:
        want = bytes.fromhex(blob)
        hit = [k for k, size, data in got if data is not None and data[:len(want)] == want]
        unknown = [k for k, size, data in got if data is None]
        if not hit:
            fail.append(f'draw {e["draw"]} (pass {e["pass"]}): no constant buffer holds {blob[:24]}... '
                        f'(descriptors {[(k, size) for k, size, _ in got]}, unknown {unknown})')
# how each pass read its constants
passes = []
for c in report['commits']:
    ps, _, _ = I.commit_passes(run, c)
    passes.extend(ps)
summary = [(p.kind, p.draws, p.memcpy) for p in passes]
preludes = sum(1 for k, d, m in summary if k == 'copy' and m and d == 0)
inpass = sum(m for k, d, m in summary if k == 'render')
print('passes:', ' '.join(f'{k}[{d}d,{m}cp]' for k, d, m in summary))
print(f'draws {len(all_draws)}, expected {len(exp)}; copy passes with CP_MEMCPY {preludes}; in-pass copies {inpass}')
if mode == '--expect-mirror' and not (inpass == 5 and preludes == 6):   # D's 5 in-pass copies; 5 preludes + 1 blit
    fail.append(f'mirror shape: want 5 in-pass copies (pass D) and 6 copy passes (5 preludes, 1 blit), got {inpass}/{preludes}')
if mode == '--expect-inpass' and not (inpass == 3 * 15 - 1 and preludes == 1):
    fail.append(f'in-pass shape: want 44 in-pass copies and 1 copy pass (the blit), got {inpass}/{preludes}')
for f in fail[:20]:
    print('FAIL', f)
print('PASS' if not fail else f'FAIL ({len(fail)})')
sys.exit(1 if fail else 0)
