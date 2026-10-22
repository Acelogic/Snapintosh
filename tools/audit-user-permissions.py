#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently walk canonical user tables and all six private CPU views, or,
for a SNAP_NATIVE_TABLES monitor (audit_native), the two permission variants
that every CPU shares."""
import struct

OA = 0x0000fffffffff000
AP = 3 << 6
NX = 3 << 53
UPERM = 0x2010002030100000
PPERM = 0x2020a52a302abae6
STATE_FIELDS = 'root shadow el0 uperm pperm umprr syncs entries returns'.split()
# compat/native-select.h struct native_cpu, and probes/xnuboot.c native_asid.
NATIVE_CPU_FIELDS = ('ttbr0', 'ttbr1', 'uperm', 'pperm', 'el0', 'w', 'k', 'installed',
                     'selects', 'flips', 'errors')
NATIVE_CPU_BYTES = 104


def native_cpu(raw):
    """One stopped struct native_cpu."""
    if len(raw) != NATIVE_CPU_BYTES:
        raise ValueError('native CPU record size')
    q = struct.unpack_from('<6Q', raw)
    el0, w, k, installed = struct.unpack_from('<4I', raw, 64)
    selects, flips, errors = struct.unpack_from('<3Q', raw, 80)
    return dict(ttbr0=[[q[0], q[1]], [q[2], q[3]]], ttbr1=[q[4], q[5]],
                uperm=struct.unpack_from('<Q', raw, 48)[0], pperm=struct.unpack_from('<Q', raw, 56)[0],
                el0=el0, w=w, k=k, installed=installed, selects=selects, flips=flips, errors=errors)


def native_asid(slot, w, k=0):
    """Monitor-owned hardware ASID of cached slot `slot`, variant (w, k)."""
    return 0x100 + 4 * slot + 2 * w + k


def _require(ok, why):
    if not ok:
        raise ValueError(why)


def _canonical(read, *, state, entry, columns, frame_map, frame_low, work_low, work_high, syncs_ok):
    """The retained view records and a full canonical walk: raw TPRO only on
    fully copied paths, private storage never canonical. columns: how many
    copy slots per record are in use (6 CPU views, or 2 native variants)."""
    root, count, *syncs = struct.unpack_from('<8Q', state)
    _require(root == entry['shadow'] and 1 <= count <= 128 and syncs_ok(syncs),
             'canonical root or private view count differs')
    rows = [struct.unpack_from('<8Q', state, 64 + 64 * n) for n in range(count)]
    _require(not any(state[64 + 64 * count:]), 'nonzero unused private records')
    _require(not any(v for r in rows for v in r[1 + columns:7]), 'nonzero unused private copy slots')
    records = {r[0]: r for r in rows}
    copies = {pa for r in rows for pa in r[1:1 + columns]}
    _require(len(records) == count and len(copies) == count * columns and
             not copies.intersection(records), 'aliased private user storage')
    _require(rows[0][0] == root and rows[0][7] == 0, 'wrong private root record')
    pages = {}

    def page(pa):
        _require(not pa & 4095 and work_low <= pa < pa + 4096 <= work_high,
                 'user table outside allocated arena')
        if pa not in pages:
            raw = read(pa, 4096)
            _require(len(raw) == 4096, 'short user table read')
            pages[pa] = struct.unpack('<512Q', raw)
        return pages[pa]

    seen = set()
    tpro = dict(pages=0, frames=set())

    def walk(pa, level, private, path):
        _require(pa not in path and len(path) == level and pa not in copies,
                 'cyclic or private canonical table')
        seen.add(pa)
        _require(len(seen) <= 8192, 'oversized canonical user tree')
        record = records.get(pa)
        if record:
            _require(record[7] == level, 'wrong private table level')
        private = private and record is not None
        for index, d in enumerate(page(pa)):
            if not d:
                continue
            _require(d & 3 == 3 and (level or index < 256), 'invalid user descriptor')
            if level < 3:
                _require(d & ~OA == 3, 'unsupported user table attributes')
                walk(d & OA, level + 1, private, path + (pa,))
                continue
            selector = ((d >> 4) & 12) | ((d >> 53) & 3)
            _require(selector in (3, 7, 9, 10, 11, 13, 15), 'unsupported user selector')
            if selector == 9:
                _require(private and entry['flags'] & 8, 'raw TPRO exposed through shared path')
                frame = d & 0x0000ffffffffc000
                off = ((frame - frame_low) >> 14) * 16
                _require(0 <= off <= len(frame_map) - 16, 'TPRO frame outside metadata')
                meta = frame_map[off:off + 16]
                _require(meta[:2] == bytes(2) and meta[2] == 17 and not any(meta[3:8]),
                         'selector9 does not name an idle USER_TPRO frame')
                # AF (bit 10) may be clear: page aging clears it through
                # UPDATE_DISJOINT (Apple helper accepts; tools/replay-user-update.py).
                _require((d & (0xfff | NX)) | 0x400 in (0x0020000000000e83, 0x0020000000000f83),
                         'unsupported TPRO leaf attributes')
                tpro['pages'] += 1
                tpro['frames'].add(frame)

    walk(root, 0, True, ())
    _require(not seen.intersection(copies), 'private storage is reachable as canonical storage')
    return root, count, rows, records, copies, page, seen, tpro


def _compare(records, page, column, write, umprr, diagnose, found, label):
    """Every retained copy in `column` equals its source's translation with
    TPRO write permission `write`; mismatches are recorded (bounded) or fatal."""
    for source, row in records.items():
        level = row[7]
        _require(level <= 3, 'bad retained private table level')
        actual = page(row[column])
        for index, d in enumerate(page(source)):
            wanted = d
            if d & 1:
                if level < 3 and d & 3 == 3:
                    child = records.get(d & OA)
                    if child:
                        _require(child[7] == level + 1, 'wrong private child level')
                        wanted = child[column] | 3
                elif ((d >> 4) & 12) | ((d >> 53) & 3) == 9:
                    _require(level == 3 and umprr & 0xc0000 == 0x40000,
                             'TPRO without configured root policy')
                    wanted = (d & ~(AP | NX)) | NX | (1 << 6) | (0 if write else 2 << 6)
            if actual[index] != wanted:
                _require(diagnose, f'{label} private user PTE mismatch at {source:#x}+{index * 8:#x}')
                found['count'] += 1
                if len(found['rows']) < 16:
                    found['rows'].append(dict(label=label, canonical_slot=hex(source + index * 8),
                                              private_slot=hex(row[column] + index * 8),
                                              expected=hex(wanted), actual=hex(actual[index])))


def _running_policy(cpu, entry, active, sprr, loaded):
    flags = entry['flags']
    if loaded is not None:
        policy = loaded[cpu]
        _require(policy['root'] == active[cpu] and policy['resets'] == sprr[cpu]['resets'] and
                 not (policy['flags'] ^ flags) & ~1, 'loaded private policy identity or sequence differs')
        flags = policy['flags']
    return ((flags & 8) << 15) | ((flags & 1) << 11)


def audit(read, *, state, entry, active, sprr, modes, frame_map, frame_low,
          work_low, work_high, diagnose_mismatches=False,loaded=None):
    _require(len(state) == 8256 and all(len(x) == 6 for x in (active, sprr, modes)),
             'user private-view state geometry')
    _require(loaded is None or len(loaded)==6,'loaded private policy geometry')
    root, count, rows, records, copies, page, seen, tpro = _canonical(
        read, state=state, entry=entry, columns=6, frame_map=frame_map, frame_low=frame_low,
        work_low=work_low, work_high=work_high, syncs_ok=all)
    found = dict(count=0, rows=[])
    cpu_rows = []
    for cpu in range(6):
        running = active[cpu] == entry['root']
        mode = modes[cpu] if running else None
        flags = entry['flags']
        umprr = (_running_policy(cpu, entry, active, sprr, loaded) if running else
                 ((flags & 8) << 15) | ((flags & 1) << 11))
        up = sprr[cpu]['uperm'] if running else UPERM
        pp = sprr[cpu]['pperm'] if running else PPERM
        el0 = mode['el0'] if running else 0
        _require(el0 in (0, 1) and up & ~(1 << 36) == UPERM and
                 pp & ~(0x100 | (1 << 36)) == PPERM, 'unsupported private permission state')
        if running:
            _require(mode['root'] == entry['root'] and mode['shadow'] == rows[0][cpu + 1] and
                     mode['uperm'] == up and mode['pperm'] == pp and
                     mode['umprr'] == sprr[cpu]['umprr'] == umprr,
                     'installed private state differs from CPU register state')
            _require(mode['returns'] >= mode['entries'] and
                     mode['returns'] - mode['entries'] in (0, 1), 'unbalanced user boundary counts')
        write = bool((up if el0 else pp) & (1 << 36))
        _compare(records, page, cpu + 1, write, umprr, diagnose_mismatches, found, f'CPU{cpu}')
        cpu_rows.append(dict(cpu=cpu, root=hex(rows[0][cpu + 1]), active=running,
                             el0=bool(el0), tpro_write=write))
    mismatches = [dict(cpu=int(r.pop('label')[3:]), **r) for r in found['rows']]
    return dict(root=hex(entry['root']), canonical=hex(root), private_source_tables=count,
                canonical_table_pages=[hex(pa) for pa in sorted(seen)],
                private_table_pages=[hex(pa) for pa in sorted(copies)],
                private_copy_pages=len(copies), private_storage=sorted(copies),
                tpro_4k_pages=tpro['pages'], tpro_frames=[hex(p) for p in sorted(tpro['frames'])],
                cpu_views=cpu_rows, private_descriptors_verified=not found['count'],
                mismatch_count=found['count'], first_mismatches=mismatches,
                shared_selector9_absent=True)


def audit_native(read, *, state, entry, active, sprr, modes, native, frame_map, frame_low,
                 work_low, work_high, diagnose_mismatches=False, loaded=None):
    """SNAP_NATIVE_TABLES: copy[0] is the variant with TPRO pages read-only,
    copy[1] writable, shared by every CPU; copy[2..5] and the per-CPU sync
    counters stay zero. Both variants must equal the canonical translation,
    and each CPU running this root must select, with this slot's ASIDs, the
    variant its SPRR state and regime name (compat/native-select.h)."""
    _require(len(state) == 8256 and all(len(x) == 6 for x in (active, sprr, modes, native)),
             'user private-view state geometry')
    _require(loaded is None or len(loaded)==6,'loaded private policy geometry')
    slot = entry['index']
    _require(0 <= slot < 64, 'cached slot outside the root cache')
    root, count, rows, records, copies, page, seen, tpro = _canonical(
        read, state=state, entry=entry, columns=2, frame_map=frame_map, frame_low=frame_low,
        work_low=work_low, work_high=work_high, syncs_ok=lambda s: not any(s))
    flags = entry['flags']
    umprr = ((flags & 8) << 15) | ((flags & 1) << 11)
    found = dict(count=0, rows=[])
    for w in (0, 1):
        _compare(records, page, w + 1, bool(w), umprr, diagnose_mismatches, found, f'variant{w}')
    ttbr0 = [[rows[0][w + 1] | native_asid(slot, w) << 48] * 2 for w in (0, 1)]
    cpu_rows = []
    for cpu in range(6):
        if active[cpu] != entry['root']:
            continue
        n, mode = native[cpu], modes[cpu]
        running_umprr = _running_policy(cpu, entry, active, sprr, loaded)
        up, pp, el0 = sprr[cpu]['uperm'], sprr[cpu]['pperm'], mode['el0']
        _require(el0 in (0, 1) and up & ~(1 << 36) == UPERM and
                 pp & ~(0x100 | (1 << 36)) == PPERM, 'unsupported private permission state')
        w = int(bool((up if el0 else pp) & (1 << 36)))
        k = int(bool(pp & 0x100))
        _require(n['installed'] == 1 and n['ttbr0'] == ttbr0 and n['ttbr1'] == [0, 0] and
                 not n['errors'], 'native CPU selection differs from the root variants')
        _require((n['uperm'], n['pperm'], n['el0'], n['w'], n['k']) == (up, pp, el0, w, k),
                 'native CPU selection differs from its SPRR state and regime')
        _require(mode['root'] == entry['root'] and mode['shadow'] == rows[0][w + 1] and
                 mode['uperm'] == up and mode['pperm'] == pp and
                 mode['umprr'] == sprr[cpu]['umprr'] == running_umprr,
                 'installed private state differs from CPU register state')
        _require(mode['returns'] >= mode['entries'] and
                 mode['returns'] - mode['entries'] in (0, 1), 'unbalanced user boundary counts')
        cpu_rows.append(dict(cpu=cpu, root=hex(rows[0][w + 1]), active=True, el0=bool(el0),
                             tpro_write=bool(w), asid=native_asid(slot, w)))
    return dict(root=hex(entry['root']), canonical=hex(root), private_source_tables=count,
                canonical_table_pages=[hex(pa) for pa in sorted(seen)],
                private_table_pages=[hex(pa) for pa in sorted(copies)],
                private_copy_pages=len(copies), private_storage=sorted(copies),
                tpro_4k_pages=tpro['pages'], tpro_frames=[hex(p) for p in sorted(tpro['frames'])],
                cpu_views=cpu_rows, native_variants=[dict(w=w, root=hex(rows[0][w + 1]),
                                                          asid=native_asid(slot, w)) for w in (0, 1)],
                private_descriptors_verified=not found['count'],
                mismatch_count=found['count'], first_mismatches=found['rows'],
                shared_selector9_absent=True)
