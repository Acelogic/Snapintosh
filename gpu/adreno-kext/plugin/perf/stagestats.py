#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unaligned-UBO staging census (agents/gpu-perf): per commit, every in-render-pass CP_MEMCPY's source resource, offset
and size; what a per-command-buffer shifted mirror (4 copies per source, one per 16-byte phase mod 64) would copy; and
whether any staged source is written by the same command buffer (relocated with WRITE access).
    stagestats.py CAPTURE"""
import collections, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture as C
import ibstats as I
E = C.regs()['E']
cap, report = I.load(sys.argv[1])
tot = collections.Counter()
per_scene = collections.defaultdict(collections.Counter)
written_src = collections.Counter()
lens = collections.Counter()
for c in report['commits']:
    if not c.get('has_commands') or str(c.get('scene', '')).startswith('warmup:'):
        continue
    s = I.scene_of(c)
    blob = (cap / c['dir'] / 'commands.bin').read_bytes()
    srcs = collections.defaultdict(list)    # rid -> [(offset, bytes)]
    writes = set()
    rlen = {}
    for kind, cmd in C.kernel_commands(blob):
        if kind != C.KCMD_IB:
            continue
        pkg = C.parse_package(cmd)
        relocs = {r['lo']: r for r in pkg['relocs']}
        for r in pkg['relocs']:
            if r['access'] & C.ACCESS_WRITE and r['kind'] == C.RELOC_RESOURCE:
                writes.add(r['rid'])
        words = C.ib_words(pkg)
        in_render, draws = False, 0
        for ev in C.walk(words):
            if ev[0] != 'pkt':
                continue
            _, at, op, body = ev
            if op == E['CP_SET_MARKER'] and (body[0] & 0xf) == E['RM6_DIRECT_RENDER']:
                in_render = True
            elif op in (E['CP_SET_MODE'],):
                in_render = False
            elif op == E['CP_MEMCPY'] and in_render:
                src = relocs.get(4 * (at + 2)); dst = relocs.get(4 * (at + 4))
                if not src or not dst:
                    continue
                srcs[src['rid']].append((src['offset'], 4 * body[0]))
                rlen[src['rid']] = max(rlen.get(src['rid'], 0), src['offset'] + src['length'])
    cur = sum(b for v in srcs.values() for _, b in v)
    n = sum(len(v) for v in srcs.values())
    mirror = 0
    for rid, v in srcs.items():
        phases = collections.defaultdict(lambda: [1 << 62, 0])
        for off, b in v:
            ph = phases[off % 64]
            ph[0] = min(ph[0], off); ph[1] = max(ph[1], off + b)
        mirror += sum(hi - lo for lo, hi in phases.values())
        if rid in writes:
            written_src[s] += 1
        lens[(off % 64)] += 0
    pc = per_scene[s]
    pc['commits'] += 1; pc['stagings'] += n; pc['bytes'] += cur; pc['mirror_bytes'] += mirror; pc['sources'] += len(srcs)
    pc['phases'] += sum(len({o % 64 for o, _ in v}) for v in srcs.values())
print(f'{"scene":14s} {"commits":>7s} {"stagings":>8s} {"sources":>7s} {"phases":>6s} {"MB now":>8s} {"MB mirror":>9s} {"src also written":>16s}')
for s, pc in per_scene.items():
    print(f'{s:14s} {pc["commits"]:7d} {pc["stagings"]:8d} {pc["sources"]:7d} {pc["phases"]:6d} {pc["bytes"]/2**20:8.1f} '
          f'{pc["mirror_bytes"]/2**20:9.2f} {written_src[s]:16d}')
