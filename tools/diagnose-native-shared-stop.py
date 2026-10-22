#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only diagnosis of a stopped SNAP_NATIVE_SHARED run (generation78).

Reads, from the stopped A16, the monitor context of the run's own runtime root
(native_shared groups and link records, native_stats, the root cache, the arena
and the shared-region registry) and the guest tables of one user root: every
nested level-2 entry with its shared level-3 table, the group that mirrors it
and whether that group still names the same shared root and VA. It replays the
decisions a linked build of that root makes (group found or creatable, link
possible) and checks every group and record for staleness. It writes nothing
to the A16 and nothing to any checkout; the report goes to stdout (JSON).

  python3 -B tools/diagnose-native-shared-stop.py \\
      --runtime ../Snapintosh-native-tables-3 --prefix PREFIX --device udp://en5 --root 0x8d4ed8000
"""
import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess

FIXED = 0xac88                    # compat/sprr.h sprr_fixed_native_leaf
GUEST_OA = 0x0000ffffffffc000
USER_ROOT, SHARED_ROOT, PAGE_TABLE, PAGE_TABLE_SHARED = 18, 19, 20, 21
GROUPS, PAGES, SLOTS, SLOT_LINKS = 512, 16, 64, 512
SPAN = 1 << 25


def klass(d):
    return ((d >> 4) & 12) | ((d >> 53) & 3)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--runtime', required=True, help='the run\'s runtime root (its layout and resident monitor)')
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--device', required=True)
    ap.add_argument('--root', required=True, help='the user root whose SWITCH_ROOT refused (hex)')
    args = ap.parse_args()
    runtime = Path(args.runtime).resolve()
    if not re.fullmatch('[a-z0-9-]+', args.prefix):
        raise SystemExit('bad prefix')
    if not (args.device.startswith('udp://en') or args.device.startswith('/dev/cu.usb')):
        raise SystemExit('bad device')
    target = int(args.root, 16)
    launch = json.loads((runtime.parent / 'Snapintosh/build' / f'{args.prefix}-launch.json').read_text())
    if not launch.get('finished') or launch.get('exit_code') != int(os.environ.get('SNAP_STOPPED_EXIT', '7')):
        raise SystemExit('the launch is not a finished stop with the expected exit')
    if Path(launch['runtime_root']).resolve() != runtime:
        raise SystemExit(f'the launch ran {launch["runtime_root"]}, not {runtime}')
    try:
        os.kill(launch['pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise SystemExit('the launcher still runs')
    blob = (runtime / 'build/xnuboot.bin').read_bytes()
    if hashlib.sha256(blob).hexdigest() != launch['monitor_sha256']:
        raise SystemExit('the runtime root\'s build/xnuboot.bin is not the launched monitor')
    layout = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                             '-Ishadow', '-Icompat', '-Xclang', '-fdump-record-layouts', '-fsyntax-only',
                             'probes/xnuboot.c'], cwd=runtime, capture_output=True, text=True, check=True).stdout

    def block(kind):
        return next(b for b in layout.split('*** Dumping AST Record Layout')
                    if re.search(r'^\s*0 \| struct ' + kind + r'\n', b))

    def offset(kind, field):
        found = re.findall(r'^\s*(\d+) \|   \S.* ' + field + r'$', block(kind), re.M)
        assert len(found) == 1, (kind, field, found)
        return int(found[0])

    def size(kind):
        return int(re.search(r'\[sizeof=(\d+),', block(kind))[1])

    sys.path[:0] = [str(runtime / 'probes'), str(runtime / 'tools'), str(runtime.parent / 'q1n1/tools')]
    import run
    native_fields = runpy.run_path(str(runtime / 'tools/kernel_ops_perf.py'))['RECORDS']['native_stats'][1]
    proxy = run.connect(args.device, tries=1)
    info = proxy.bootinfo()
    work, work_size = run.resident_work(proxy, info)

    def read(pa, n):
        return b''.join(proxy.readmem(pa + i, min(65536, n - i), live=True) for i in range(0, n, 65536))

    def q(pa):
        return struct.unpack('<Q', read(pa, 8))[0]

    report = dict(prefix=args.prefix, root=hex(target), work=hex(work), work_size=hex(work_size))
    if read(info['heap_base'] + run.CODE_AT, len(blob)) != blob:
        raise SystemExit('the resident monitor is not the launched one')
    words = struct.unpack('<46Q', read(q(work), 46 * 8))
    frame_map, frame_low, frame_high = words[43], words[44], words[45]

    def meta(pa):
        if not frame_low <= pa < frame_high:
            return None
        return read(frame_map + ((pa - frame_low) >> 14) * 16, 16)

    def meta_row(m):
        return None if m is None else dict(hex=m.hex(), refs=m[0] | m[1] << 8, type=m[2], level_or_asid=m[4] | m[5] << 8,
                                          count=m[6] | m[7] << 8, slot=m[8], flags=m[10] | m[11] << 8, format=m[12])

    ctx = lambda field: work + offset('context', field)
    # native_stats, flags of failure, arena.
    report['native_stats'] = dict(zip(native_fields, struct.unpack(f'<{len(native_fields)}Q',
                                                                  read(ctx('native_stats'), 8 * len(native_fields)))))
    report['user_view_failed'] = q(ctx('user_view_failed'))
    report['root_install_failures'] = q(ctx('root_install_failures'))
    report['root_evictions'] = q(ctx('root_evictions'))
    arena_names = ('checks', 'low_water', 'clock', 'reclaims', 'slots', 'pages', 'retired', 'invalid', 'valid',
                   'alloc_failures', 'build_retries', 'flush_failures')
    report['arena_reclaim'] = dict(zip(arena_names, struct.unpack('<12Q', read(ctx('arena_reclaim'), 96))))
    work_base, next_table, work_end = q(ctx('work_base')), q(ctx('next_table')), q(ctx('work_end'))
    pool = ctx('table_pool')
    used = (next_table - work_base) // 4096
    owners = read(pool + offset('table_pool', 'owner'), used)
    free_count = struct.unpack('<I', read(pool + offset('table_pool', 'count'), 4))[0]
    report['arena'] = dict(work_base=hex(work_base), next_table=hex(next_table), work_end=hex(work_end),
                           used_pages=used, pool_free=free_count,
                           available=(work_end - next_table) // 4096 + free_count,
                           domain200_pages=owners.count(200),
                           slot_pages={i: owners.count(i + 1) for i in range(SLOTS) if owners.count(i + 1)})
    # Shared-region registry.
    regions = ctx('shared_regions')
    slots = {}
    for i in range(255):
        state, start, span, root = struct.unpack('<4Q', read(regions + 32 * i, 32))
        if state or root:
            slots[i] = dict(state=state, start=hex(start), size=hex(span), root=hex(root))
    report['shared_regions'] = slots
    # The root cache.
    user_state = ctx('user_roots')
    active = list(struct.unpack('<6Q', read(user_state, 48)))
    cache = []
    for index in range(SLOTS):
        values = struct.unpack('<7Q', read(user_state + 48 + index * 56, 56))
        e = dict(zip(('root', 'shadow', 'leaves', 'asid', 'format', 'flags', 'valid'), values), index=index)
        if e['root'] or e['shadow']:
            cache.append(e)
    report['active'] = [hex(a) for a in active]
    report['cache'] = [dict(e, root=hex(e['root']), shadow=hex(e['shadow']), flags=hex(e['flags'])) for e in cache]
    # native_shared: header, groups, link records, all tolerant of damage.
    base = ctx('native_shared')
    raw = read(base, size('native_shared'))
    header = dict(zip(('live', 'created', 'freed', 'stores', 'linked', 'unlinked', 'errors', 'pending'),
                      struct.unpack_from('<8Q', raw)))
    g_off, c_off, l_off = (offset('native_shared', f) for f in ('group', 'slot_count', 'slot_link'))
    groups = {}
    for g in range(GROUPS):
        w = struct.unpack_from(f'<{5 + PAGES}Q', raw, g_off + g * (5 + PAGES) * 8)
        if any(w):
            groups[g] = dict(guest=w[0], shared=w[1], va=w[2], leaves=w[3], links=w[4], pages=list(w[5:]))
    counts = struct.unpack_from(f'<{SLOTS}H', raw, c_off)
    records = {s: list(struct.unpack_from(f'<{SLOT_LINKS}H', raw, l_off + s * SLOT_LINKS * 2))[:min(n, SLOT_LINKS)]
               for s, n in enumerate(counts) if n}
    report['native_shared'] = dict(header=header, groups=len(groups), records={s: len(r) for s, r in records.items()})
    # Every group: does its guest table still belong to its shared root at its VA?
    by_guest, problems = {}, []
    record_links = {g: 0 for g in groups}
    for s, recs in records.items():
        for g in recs:
            if g not in groups or not groups[g]['guest']:
                problems.append(dict(kind='record names a free group', slot=s, group=g))
            else:
                record_links[g] += 1

    def shared_l2(root, va):
        """The 16K level-2 entry of 16K root `root` at va (0 when absent)."""
        l1 = q(root + 8 * ((va >> 36) & 2047))
        if l1 & 3 != 3:
            return 0
        return q((l1 & GUEST_OA) + 8 * ((va >> 25) & 2047))

    for g, grp in sorted(groups.items()):
        by_guest.setdefault(grp['guest'], []).append(g)
        if record_links[g] != grp['links']:
            problems.append(dict(kind='links differ from records', group=g, links=grp['links'], records=record_links[g]))
        if not grp['guest'] or grp['va'] % SPAN or not grp['shared']:
            problems.append(dict(kind='bad identity', group=g, **{k: hex(grp[k]) for k in ('guest', 'shared', 'va')}))
            continue
        m = meta(grp['guest'])
        entry = shared_l2(grp['shared'], grp['va']) if meta(grp['shared']) else None
        if m is None or m[2] != PAGE_TABLE_SHARED or m[4] != 3 or entry is None or entry & GUEST_OA != grp['guest']:
            problems.append(dict(kind='stale group', group=g, guest=hex(grp['guest']), shared=hex(grp['shared']),
                                 va=hex(grp['va']), links=grp['links'], leaves=grp['leaves'],
                                 guest_meta=meta_row(m), shared_entry=None if entry is None else hex(entry)))
    for guest, gs in by_guest.items():
        if len(gs) > 1:
            problems.append(dict(kind='guest table mirrored twice', guest=hex(guest), groups=gs))
    report['group_problems'] = problems
    # The refused root: metadata, cache entry, nested entries replayed.
    m = meta(target)
    report['root_meta'] = meta_row(m)
    bound = None
    if m is not None and m[8] < 255 and m[8] in slots:
        bound = int(slots[m[8]]['root'], 16)
    report['bound_shared_root'] = bound and hex(bound)
    entries = [e for e in cache if e['root'] == target]
    report['root_cache_entries'] = [e['index'] for e in entries]
    for e in entries:
        s = e['index']
        report.setdefault('root_slot_records', {})[s] = [
            dict(group=g, live=g in groups, va=g in groups and hex(groups[g]['va']),
                 links=g in groups and groups[g]['links']) for g in records.get(s, [])]
    nested = []
    if m is not None and m[2] == USER_ROOT and m[12] == 0:
        l1_table = read(target, 16384)
        for i1 in range(2048):
            l1 = struct.unpack_from('<Q', l1_table, 8 * i1)[0]
            if not l1 & 1:
                continue
            if l1 & ~GUEST_OA != 3:
                nested.append(dict(kind='l1 attributes', index=i1, entry=hex(l1)))
                continue
            l2_table = read(l1 & GUEST_OA, 16384)
            for i2 in range(2048):
                d = struct.unpack_from('<Q', l2_table, 8 * i2)[0]
                if not d & 1:
                    continue
                va = (i1 << 36) | (i2 << 25)
                child = d & GUEST_OA
                cm = meta(child)
                if d & ~GUEST_OA != 3 or cm is None or cm[2] != PAGE_TABLE_SHARED or cm[4] != 3:
                    continue
                row = dict(va=hex(va), child=hex(child), child_meta=meta_row(cm), groups=by_guest.get(child, []))
                gs = by_guest.get(child, [])
                if gs:
                    grp = groups[gs[0]]
                    row.update(group_va=hex(grp['va']), group_shared=hex(grp['shared']),
                               build_accepts=grp['va'] == va and grp['shared'] == (bound or 0))
                else:
                    table = struct.unpack('<2048Q', read(child, 16384))
                    bad = [(j, hex(x)) for j, x in enumerate(table)
                           if x & 1 and (x & 3 != 3 or not FIXED >> klass(x) & 1)]
                    row.update(group_va=None, creatable=bool(bound) and not bad, refused_leaves=bad[:8],
                               refused_count=len(bad), leaves=sum(x & 1 for x in table))
                if bound:
                    row['bound_root_entry'] = hex(shared_l2(bound, va))
                nested.append(row)
    report['nested'] = nested
    report['nested_refused'] = [r for r in nested if r.get('build_accepts') is False or r.get('creatable') is False
                                or r.get('kind')]
    print(json.dumps(report, indent=1, default=str))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
