#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Simulate the per-command-buffer UBO mirror policy (agents/gpu-perf FAILURE-MODES.md U*) over a capture: a mirror of
source B (one per 16-byte phase mod 64) is copied whole ([phase, end)) in the prelude of the first pass that stages from
B, and invalidated by any pass that relocates B with WRITE access (a device-buffer binding, a blit or compute write);
the next pass that stages from B copies it again. Also: per-pass mirrors ([min, max) per pass).
    mirrorsim.py CAPTURE"""
import collections, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C, ibstats as I
E = C.regs()['E']
cap, report = I.load(sys.argv[1])
agg = collections.defaultdict(collections.Counter)
for c in report['commits']:
    if not c.get('has_commands') or str(c.get('scene', '')).startswith('warmup:'):
        continue
    s = I.scene_of(c)
    passes = []   # [(stage list [(rid, off, bytes, buflen)], writes set)]
    for kind, cmd in C.kernel_commands((cap / c['dir'] / 'commands.bin').read_bytes()):
        if kind != C.KCMD_IB:
            continue
        pkg = C.parse_package(cmd)
        relocs = {r['lo']: r for r in pkg['relocs']}
        # reloc positions per pass: split by CP_SET_MODE / CP_THREAD_CONTROL as ibstats does (dword ranges)
        bounds = []
        cur = None; work = False; prev = None
        for ev in C.walk(C.ib_words(pkg)):
            if ev[0] != 'pkt':
                continue
            _, at, op, body = ev
            if op in (E['CP_SET_MODE'], E['CP_THREAD_CONTROL']) and (cur is None or work) and \
                    not (op == E['CP_THREAD_CONTROL'] and prev == E['CP_SET_MODE']):
                cur = dict(start=at, stage=[], work=False); bounds.append(cur); work = False
            prev = op
            if op in (E['CP_MEMCPY'], E['CP_DRAW_INDX_OFFSET'], E['CP_BLIT'], E['CP_EXEC_CS']):
                work = True
            if op == E['CP_MEMCPY']:
                r = relocs.get(4 * (at + 2))
                if r:
                    cur['stage'].append((r['rid'], r['offset'], 4 * body[0], r['offset'] + r['length']))
        starts = [b['start'] for b in bounds] + [1 << 40]
        for i, b in enumerate(bounds):
            b['writes'] = set()
        data_off = pkg['data_offset']
        # IB relocs by dword; data relocs (driver tables) belong to the pass whose draw loads that table: approximate by
        # the UBO descriptor relocation that points at the package data offset... simpler: attribute a data reloc to the
        # pass whose data range holds it (passes append data in order, the same order as their dwords)
        data_relocs = sorted([r for r in pkg['relocs'] if r['lo'] >= data_off], key=lambda r: r['lo'])
        pkg_relocs_ib = [r for r in pkg['relocs'] if r['lo'] < data_off]
        for r in pkg_relocs_ib:
            dw = r['lo'] // 4
            k = max(i for i in range(len(bounds)) if starts[i] <= dw) if bounds else None
            if k is not None and r['access'] & 2 and r['kind'] == C.RELOC_RESOURCE:
                bounds[k]['writes'].add(r['rid'])
        # package relocs pointing into the data area: the UBO descriptor of a driver table names its data offset
        table_owner = []
        for r in pkg_relocs_ib:
            if r['kind'] == C.RELOC_PACKAGE:
                dw = r['lo'] // 4
                k = max(i for i in range(len(bounds)) if starts[i] <= dw)
                table_owner.append((r['offset'], r['offset'] + r['length'], k))
        for r in data_relocs:
            if not (r['access'] & 2 and r['kind'] == C.RELOC_RESOURCE):
                continue
            pos = r['lo']
            owner = [k for lo, hi, k in table_owner if lo <= pos < hi]
            k = owner[0] if owner else (len(bounds) - 1)
            bounds[k]['writes'].add(r['rid'])
        passes.extend(bounds)
    mirrors = {}           # (rid, phase) -> valid
    cb_bytes = 0; pp_bytes = 0; copies = 0
    for p in passes:
        need = {}
        for rid, off, b, end in p['stage']:
            key = (rid, off % 64)
            lo, hi = need.get(key, (1 << 62, 0))
            need[key] = (min(lo, off), max(hi, off + b, end))
        for key, (lo, hi) in need.items():
            pp_bytes += hi - lo
            if not mirrors.get(key):
                cb_bytes += hi - key[1] if hi - key[1] <= (1 << 20) else hi - lo
                mirrors[key] = True; copies += 1
        for rid in p['writes']:
            for key in list(mirrors):
                if key[0] == rid:
                    mirrors[key] = False
    a = agg[s]
    a['commits'] += 1; a['now'] += sum(b for p in passes for _, _, b, _ in p['stage'])
    a['n'] += sum(len(p['stage']) for p in passes); a['cb'] += cb_bytes; a['pp'] += pp_bytes; a['copies'] += copies
    a['passes'] += len(passes); a['wpasses'] += sum(1 for p in passes if p['writes'] & {x[0] for q in passes for x in q['stage']})
for s, a in agg.items():
    print(f"{s:14s} stagings={a['n']:5d} now={a['now']/2**20:7.1f}MB  per-pass={a['pp']/2**20:7.1f}MB  "
          f"per-cb+invalidate={a['cb']/2**20:6.2f}MB in {a['copies']} copies  passes={a['passes']} writing-B={a['wpasses']}")
