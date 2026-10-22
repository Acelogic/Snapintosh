#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the SNAP_USER_HW_WALK state (compat/user-hw-walk.h) from a monitor work-area dump.

    python3 tools/hw-walk-dump.py RUN_DIR [--work work-dump/work.bin] [--base 0x...] [--ipa 0x...] [--json OUT]

Offline, read only. RUN_DIR is a build/installed-fresh-* directory with qualification.json
(its flags give the layout) and work-dump/work.{bin,json} (the whole monitor work area,
read from the stopped A16; the context sits at its first byte). Every offset is taken
from clang's record layout of probes/xnuboot.c under the run's own defines, so nothing
here depends on a layout reader that knows the field: context.hw_walk is found by
parsing the context record directly (the layout tool's field lookup refuses it).

Prints, and with --json writes:
  - per vCPU: the active user root, its shadow-cache entry (if any), its hardware-walk
    record (if any), SPRR UMPRR, the loaded-root record and guest TTBR0, and what the
    loaded-root audit concludes: the cache-only one (compat/sptm-root-policy.h
    sptm_root_note_loaded, which stopped v53) and the record-aware one
    (compat/user-hw-walk.h hw_walk_note_loaded);
  - the hardware-walk counters, records (root, ASID, flags, hardware ASIDs, copies), an
    index check (every record reachable by the open-addressed probe, no stray word) and a
    copy-tree check (each copy's parent before it, one level up, spanning its VA: v55's
    lost parents);
  - per vCPU stage-2 tree, over guest RAM (params.bin mem_low..mem_high): the 1G and 2M
    blocks left (none after the setup pre-split, v62's fix), the pages not mapped to
    themselves and the read-only pages; with --ipa, each tree's walk of that IPA (a
    stage-2 fault's: v62 0x92fdde030, v63 0x936f0f200).
"""
from pathlib import Path
import argparse
import json
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HW_WALK_INDEX, HW_WALK_ROOTS, HW_WALK_ASID_BASE = 2048, 1024, 0x400


def layouts(defines, source=ROOT):
    text = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding', '-mgeneral-regs-only',
                           '-Ishadow', '-Icompat', f'-I{source.parent / "q1n1/platform/uefi"}', *defines,
                           '-Xclang', '-fdump-record-layouts', '-fsyntax-only', 'probes/xnuboot.c'],
                          cwd=source, capture_output=True, text=True, check=True).stdout
    out = {}
    for block in text.split('*** Dumping AST Record Layout'):
        m = re.search(r'^\s*0 \| struct (\w+)\n', block, re.M)
        if m and m[1] not in out:
            fields = {f[3]: (int(f[1]), f[2]) for f in re.finditer(r'^\s*(\d+) \|   (?! )(\S.*) (\w+)$', block, re.M)}
            out[m[1]] = dict(size=int(re.search(r'\[sizeof=(\d+),', block)[1]), fields=fields)
    return out


class Memory:
    def __init__(self, blob, base):
        self.blob, self.base = blob, base

    def u(self, pa, size=8):
        off = pa - self.base
        if off < 0 or off + size > len(self.blob):
            raise ValueError(f'{pa:#x} is outside the work dump')
        return int.from_bytes(self.blob[off:off + size], 'little')


def hw_hash(root):
    return (((root >> 14) & 0xffffffff) * 0x9e3779b1 & 0xffffffff) >> 21 & (HW_WALK_INDEX - 1)


def decode(run, work=None, base=None, source=ROOT, ipas=()):
    run = Path(run)
    qual = json.loads((run / 'qualification.json').read_text())
    defines = [f for f in qual['flags'] if f.startswith('-D')]
    if '-DSNAP_USER_HW_WALK=1' not in defines:
        raise SystemExit('this run was not built with SNAP_USER_HW_WALK=1')
    work = Path(work) if work else run / 'work-dump/work.bin'
    meta = json.loads((work.parent / 'work.json').read_text()) if (work.parent / 'work.json').exists() else {}
    base = base if base is not None else int(meta['work'], 16)
    mem = Memory(work.read_bytes(), base)
    lay = layouts(defines, source)
    ctx, f = base, lay['context']['fields']
    off = lambda rec, name: lay[rec]['fields'][name][0]
    size = lambda rec: lay[rec]['size']
    hw = mem.u(ctx + f['hw_walk'][0])
    if 'root_ext' in f:                    # SNAP_ROOT_CACHE_WIDE: the live state is in arena pages
        roots = mem.u(ctx + f['root_ext'][0]) + off('root_ext', 'roots')
    else:
        roots = ctx + f['user_roots'][0]
    entry = lambda pa: {k: mem.u(pa + off('sptm_root_cached', k)) for k in lay['sptm_root_cached']['fields']}
    st = {k: mem.u(roots + off('sptm_root_state', k)) for k in ('switches', 'user_switches', 'kernel_switches',
                                                                 'builds', 'invalidations')}
    cache = [entry(roots + off('sptm_root_state', 'cache') + i * size('sptm_root_cached'))
             for i in range(lay['sptm_root_state']['fields']['cache'][1].count('[') and
                            int(re.search(r'\[(\d+)\]', lay['sptm_root_state']['fields']['cache'][1])[1]))]
    # The hardware-walk state.
    used = mem.u(hw + off('hw_walk_state', 'used'), 4)
    stats_at = hw + off('hw_walk_state', 'stats')
    stats = {k: mem.u(stats_at + o) for k, (o, _) in sorted(lay['hw_walk_stats']['fields'].items(), key=lambda x: x[1][0])}
    index = [mem.u(hw + off('hw_walk_state', 'index') + 2 * i, 2) for i in range(HW_WALK_INDEX)]
    rsize, tsize = size('hw_walk_root'), size('hw_walk_table')
    records, problems = {}, []
    for n in range(HW_WALK_ROOTS):
        at = hw + off('hw_walk_state', 'roots') + n * rsize
        e = entry(at + off('hw_walk_root', 'entry'))
        if not e['root']:
            continue
        count = mem.u(at + off('hw_walk_root', 'count'), 4)
        tables = []
        for t in range(min(count, 32)):
            ta = at + off('hw_walk_root', 't') + t * tsize
            tables.append(dict(source=hex(mem.u(ta)), va=hex(mem.u(ta + 8)), copy=[hex(mem.u(ta + 16)), hex(mem.u(ta + 24))],
                               level=mem.u(ta + 32, 2), parent=mem.u(ta + 34, 2), slot=mem.u(ta + 36, 2)))
        rec_index = mem.u(at + off('hw_walk_root', 'index'), 4)
        if rec_index != n:
            problems.append(f'record {n} carries index {rec_index}')
        # The copy tree (hw_walk_verify's structure): each copy's parent comes
        # before it, one level up, and spans its VA (v55 lost the parents).
        if tables and (int(tables[0]['source'], 16) != e['root'] or tables[0]['level'] or int(tables[0]['va'], 16)):
            problems.append(f'record {n}: table 0 is not the root copy')
        for k, t in enumerate(tables[1:], 1):
            p = t['parent']
            span = 1 << (12 + 9 * (3 - tables[p]['level'])) if p < len(tables) else 0
            if p >= k or tables[p]['level'] + 1 != t['level'] or \
                    int(t['va'], 16) != int(tables[p]['va'], 16) + t['slot'] * span:
                problems.append(f'record {n} (root {e["root"]:#x}) table {k}: parent {p} '
                                f'(level {t["level"]}, va {t["va"]}, slot {t["slot"]}) is not its parent')
        records[e['root']] = dict(record=n, asid=e['asid'], flags=hex(e['flags']), format=e['format'], valid=e['valid'],
                                  shadow=hex(e['shadow']), umprr=hex(mem.u(at + off('hw_walk_root', 'umprr'))),
                                  count=count, hw_asids=[hex(HW_WALK_ASID_BASE + 2 * n + (w if count else 0)) for w in (0, 1)],
                                  tables=tables)
    # The index: every record reachable, nothing else in it.
    def find(root):
        i = hw_hash(root)
        for _ in range(HW_WALK_INDEX):
            r = index[i]
            if not r:
                return None
            if r <= HW_WALK_ROOTS:
                at = hw + off('hw_walk_state', 'roots') + (r - 1) * rsize + off('hw_walk_root', 'entry')
                if mem.u(at + off('sptm_root_cached', 'root')) == root:
                    return r - 1
            i = (i + 1) & (HW_WALK_INDEX - 1)
        return None
    for root, r in records.items():
        if find(root) != r['record']:
            problems.append(f'root {root:#x} (record {r["record"]}) is not reachable through the index')
    live = sum(1 for w in index if w)
    if live != len(records) or used != len(records):
        problems.append(f'index words {live}, used {used}, records {len(records)}')
    # Per vCPU: what SWITCH_ROOT's loaded-root audit sees.
    cpus = []
    nvcpu = int(re.search(r'\[(\d+)\]', f['vcpus'][1])[1])
    for cpu in range(nvcpu):
        active = mem.u(roots + off('sptm_root_state', 'active') + 8 * cpu)
        sprr = roots + off('sptm_root_state', 'sprr') + cpu * size('sprr_state')
        loaded = ctx + f['root_loaded'][0] + cpu * size('sptm_loaded_root')
        vcpu = ctx + f['vcpus'][0] + cpu * size('vcpu')
        cached = [i for i, e in enumerate(cache) if e['root'] == active and active]
        valid = [i for i in cached if cache[i]['valid'] == 1 and cache[i]['shadow'] and not cache[i]['shadow'] & 4095]
        umprr = mem.u(sprr + off('sprr_state', 'umprr'))
        policy = lambda flags: ((flags & 8) << 15) | ((flags & 1) << 11)
        note = ('kernel root: no entry needed' if not active else
                'cache entry: passes' if len(valid) == 1 and len(cached) == 1 else
                'NO cache entry: sptm_root_note_loaded returns 0 (SWITCH_ROOT records SPTM_BAD_CONFIG)'
                if not cached else 'unusable cache entry: refused')
        # compat/user-hw-walk.h hw_walk_note_loaded: the record's identity when no valid cache entry.
        rec = records.get(active)
        live = [i for i in cached if cache[i]['valid']]
        fixed = (umprr == 0 if not active else
                 note.startswith('cache entry') and umprr == policy(cache[valid[0]]['flags']) if live else
                 bool(rec) and rec['valid'] == 1 and rec['format'] == 1 and rec['shadow'] == '0x0' and
                 0 < rec['asid'] <= 0xffff and umprr == policy(int(rec['flags'], 16)))
        cpus.append(dict(cpu=cpu, active=hex(active), cache_slots=cached, hw_record=records.get(active, {}).get('record'),
                         umprr=hex(mem.u(sprr + off('sprr_state', 'umprr'))), resets=mem.u(sprr + off('sprr_state', 'resets')),
                         loaded=dict(root=hex(mem.u(loaded)), flags=hex(mem.u(loaded + 8)), resets=mem.u(loaded + 16)),
                         guest_ttbr0=hex(mem.u(vcpu + lay['vcpu']['fields']['guest_ttbr0'][0])), note_loaded=note,
                         note_loaded_hw=fixed))
    # Stage 2 (SNAP_USER_HW_WALK_S2RO): each vCPU's tree over guest RAM. Every
    # page must translate to itself; with the setup pre-split (v62's fix) no
    # 1G or 2M block may remain, so no RETYPE changes a block size.
    stage2, walks = [], {}
    params = run / 'params.bin'
    if params.exists() and 'params' in lay:
        pb = params.read_bytes()
        pf = lay['params']['fields']
        mem_low, mem_high = (struct.unpack_from('<Q', pb, pf[k][0])[0] for k in ('mem_low', 'mem_high'))
        for cpu in range(nvcpu):
            root = mem.u(ctx + f['vcpus'][0] + cpu * size('vcpu') + lay['vcpu']['fields']['stage2_root'][0])
            row = dict(cpu=cpu, root=hex(root), blocks_1g=0, blocks_2m=0, unmapped=0, ro_pages=0)
            ipa = mem_low
            while ipa < mem_high:
                table, level, step = root, 1, 0
                while True:
                    e = mem.u(table + 8 * ((ipa >> (12 + 9 * (3 - level))) & 511))
                    step = 1 << (12 + 9 * (3 - level))
                    if not e & 1:
                        row['unmapped'] += step // 4096
                        break
                    if level == 3 or (e & 3) == 1:
                        if level == 1:
                            row['blocks_1g'] += 1
                        elif level == 2:
                            row['blocks_2m'] += 1
                        if (e >> 6) & 3 == 1:
                            row['ro_pages'] += step // 4096
                        if (e & 0x0000fffffffff000) != ipa & ~(step - 1):
                            row['unmapped'] += step // 4096
                        break
                    table, level = e & 0x0000fffffffff000, level + 1
                ipa = (ipa & ~(step - 1)) + step
            stage2.append(row)
            # The path of each asked IPA (a fault's): (level, table, entry) per step.
            for want in ipas:
                path, table = [], root
                for level in (1, 2, 3):
                    e = mem.u(table + 8 * ((want >> (12 + 9 * (3 - level))) & 511))
                    path.append((level, hex(table), hex(e)))
                    if not e & 1 or level == 3 or (e & 3) == 1:
                        break
                    table = e & 0x0000fffffffff000
                walks.setdefault(hex(want), []).append(path)
    return dict(run=str(run), work_base=hex(base), context_hw_walk=hex(hw), root_state=hex(roots), switches=st,
                stage2=stage2, walks=walks,
                failures=dict(root_install_failures=mem.u(ctx + f['root_install_failures'][0]),
                              user_view_failed=mem.u(ctx + f['user_view_failed'][0])),
                cpus=cpus, used=used, stats=stats, records={hex(k): v for k, v in records.items()},
                index_problems=problems, cached_roots=sum(1 for e in cache if e['valid'] == 1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run')
    ap.add_argument('--work')
    ap.add_argument('--base', type=lambda s: int(s, 0))
    ap.add_argument('--source', type=Path, default=ROOT, help='Snapintosh tree the run was built from')
    ap.add_argument('--ipa', type=lambda s: int(s, 0), action='append', default=[],
                    help='also walk this IPA in every vCPU stage-2 tree (repeatable)')
    ap.add_argument('--json')
    a = ap.parse_args()
    out = decode(a.run, a.work, a.base, a.source, a.ipa)
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + '\n')
    print(f"context.hw_walk {out['context_hw_walk']}  root state {out['root_state']}  "
          f"cached roots {out['cached_roots']}  switches {out['switches']}")
    print(f"failures {out['failures']}")
    for c in out['cpus']:
        print(f"cpu{c['cpu']}: active {c['active']} cache {c['cache_slots']} hw record {c['hw_record']} "
              f"umprr {c['umprr']} loaded {c['loaded']} ttbr0 {c['guest_ttbr0']}\n      {c['note_loaded']}; "
              f"hw_walk_note_loaded {'passes' if c['note_loaded_hw'] else 'refuses'}")
    print(f"hw records {out['used']}; counters " + ' '.join(f'{k}={v}' for k, v in out['stats'].items() if v))
    for root, r in out['records'].items():
        print(f"  {root}: record {r['record']} asid {r['asid']:#x} flags {r['flags']} umprr {r['umprr']} "
              f"hw asids {r['hw_asids']} copied tables {r['count']}")
    print('records and index: ' + ('consistent' if not out['index_problems'] else '; '.join(out['index_problems'])))
    for row in out['stage2']:
        print(f"stage 2 cpu{row['cpu']} {row['root']}: {row['blocks_1g']} 1G and {row['blocks_2m']} 2M blocks over "
              f"guest RAM, {row['unmapped']} pages not identity-mapped, {row['ro_pages']} read-only")
    for ipa, paths in out['walks'].items():
        for cpu, path in enumerate(paths):
            print(f"stage 2 cpu{cpu} IPA {ipa}: " + ' -> '.join(f'L{lv} {t}[{e}]' for lv, t, e in path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
