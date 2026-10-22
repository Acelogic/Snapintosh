#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Plan, and later verify, the one GPT change for the Snapintosh macOS window.

Pure computation over GPT survey JSON (q1n1 tools/gpt_survey.py --json); it
reads files and writes only the plan/verdict JSON you name. Nothing here can
reach the A16 or any disk.

  plan         --survey BEFORE.json [--out plan.json]
  verify       --before BEFORE.json --after AFTER.json --plan plan.json
  verify-undo  --before BEFORE.json --after UNDONE.json

The plan pins the disk (size, sector size, GPT disk GUID, NVMe EUI64), every
existing partition (index, type, GUID, LBAs, attributes, name) and the two
neighbours of the free extent, and places one partition inside that extent
with a 1 MiB guard at each end. `verify` passes only when every existing entry
is byte-for-byte unchanged in meaning and exactly one new entry matches the
plan; `verify-undo` passes only when the layout equals BEFORE again.
"""
import argparse
import json
from pathlib import Path
import sys

# Pinned from the Windows storage records of 2026-09-21 and the pre-change GPT
# capture (build/a16-storage-backup-20260921); the survey must agree.
DISK_BYTES = 1024209543168
BLOCK = 512
DISK_GUID = '1c98f6ba-8bab-4cae-8c35-bf82870d8cf2'
EUI = '002538F261C3C291'
BEFORE_NEIGHBOUR = '17cd69a6-eb33-406a-86fd-6d54fac2d2d1'   # T: SNAPASSETS, ends at the extent
AFTER_NEIGHBOUR = '0e71a636-b076-4ab6-9f50-6425f2a618a5'    # Windows recovery, starts after it
ESP = '939a0a66-c61e-42b7-b975-5be3c2b80280'
WINDOWS_C = '419baed0-542c-4292-a670-caaabe34e2fa'
TYPE = 'af494c0f-7849-4186-8d2c-9b05cf6ab8b8'               # Snapintosh macOS window (private)
NAME = 'Snapintosh macOS'
# The free extent PROPOSAL.md was approved against. A survey showing anything
# else stops the plan; the proposal is then re-issued, not silently adapted.
APPROVED_EXTENT = (1170661376, 1996189695)
# The 18 partitions PROPOSAL.md section 1 pins, from Windows' final record of
# 2026-09-21 (staging-final.json): GUID -> (type, byte offset, byte size).
# `plan` refuses unless the survey shows exactly this set, nothing more.
PINNED = {
    'dc0777a3-2209-4316-8970-29eb200511d1': ('97745aba-135a-44c3-9adc-05616173c24c', 1048576, 1048576),
    'a642d24c-0c1c-4a11-99eb-84737f211431': ('bc0330eb-3410-4951-a617-03898dbe3372', 2097152, 16777216),
    'ff899570-2688-4192-8e02-90cd0c62ea61': ('b7524b2d-0a91-49a2-aa5e-bda266699d49', 18874368, 1048576),
    '5c92f10b-51bd-410b-9a42-48d746a3f775': ('a3381699-350c-465e-bd5d-fa3ab901a39a', 19922944, 1048576),
    '00c8adb3-028c-451b-9acf-c345b3f723c6': ('c80325ba-7ec2-4a30-b2f7-18f646086185', 20971520, 73400320),
    '9d8159d5-5938-4440-9caf-65c21392d5c2': ('fa4cbe53-31b5-4c23-9c1e-a01feb966856', 94371840, 125829120),
    '4ac52e5f-1aa6-409f-b12c-023520982261': ('6690b4ce-70e9-4817-b9f1-25d64d888357', 220200960, 125829120),
    '9c817ddb-0373-4d63-92f7-ed3bce38636d': ('aa9a5c4c-4f1f-7d3a-014a-22bd33bf7191', 346030080, 1048576),
    'aea9defe-5f13-4258-9f49-6eb36df1883e': ('80c23c26-c3f9-4a19-bb38-1e457daceb09', 347078656, 1048576),
    '5a514971-8e3b-47cf-a12b-fd95dec307f8': ('e12d830b-7f62-4f0b-b48a-8178c5bf3ac1', 348127232, 1048576),
    '5e3fcd32-6617-4a21-90bd-ed4ba1580b14': ('5af80809-aabb-4943-9168-cdfc38742598', 349175808, 536870912),
    '939a0a66-c61e-42b7-b975-5be3c2b80280': ('c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 886046720, 471859200),
    '7723b707-46b5-4404-b74f-4e3dffe17d62': ('e3c9e316-0b5c-4db8-817d-f92df00215ae', 1357905920, 16777216),
    '419baed0-542c-4292-a670-caaabe34e2fa': ('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 1374683136, 512104595456),
    '1b0d0e57-9a6f-498e-a189-264e9107bc36': ('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 513479278592, 17179869184),
    '17cd69a6-eb33-406a-86fd-6d54fac2d2d1': ('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7', 530659147776, 68719476736),
    '0e71a636-b076-4ab6-9f50-6425f2a618a5': ('de94bba4-06d1-4d40-a16a-bfd50179d6ac', 1022049124352, 1887436800),
    '4dcd54be-0986-4010-b44c-ae1fa3f853a7': ('de94bba4-06d1-4d40-a16a-bfd50179d6ac', 1023936561152, 272629760),
}
GUARD_LBAS = (1 << 20) // BLOCK
MIN_BYTES = 256 << 30
ALLOWED_ATTRS = (0, 1 << 63)
ENTRY_KEYS = ('index', 'type', 'guid', 'first_lba', 'last_lba', 'attributes', 'name')
# What "unchanged" means for a partition. The GPT slot index is not part of a
# partition's identity (Windows addresses partitions by GUID); a slot change is
# reported as a note, never silently accepted as "nothing changed".
IDENTITY_KEYS = ENTRY_KEYS[1:]


class PlanError(ValueError):
    pass


def the_disk(survey):
    disks = survey['disks'] if 'disks' in survey else [survey]
    nvme = [d for d in disks if (d.get('path_info') or {}).get('nvme_eui_bytes')]
    matches = [d for d in (nvme or disks) if d.get('disk_guid') == DISK_GUID]
    if len(matches) != 1:
        raise PlanError(f'expected exactly one disk with GPT GUID {DISK_GUID}, found {len(matches)}')
    return matches[0]


def check_disk(d, require_eui=True):
    problems = list(d.get('errors', []))
    if d.get('disk_bytes') != DISK_BYTES or d.get('block_size') != BLOCK:
        problems.append(f"disk is {d.get('disk_bytes')} bytes / {d.get('block_size')}-byte blocks")
    for which in ('primary', 'backup'):
        h = d.get(which) or {}
        if not (h.get('header_crc_ok') and h.get('array_crc_ok')):
            problems.append(f'{which} GPT header or array failed its CRC')
        if (h.get('count'), h.get('entry_size')) != (128, 128):
            problems.append(f'{which} GPT is not 128 x 128-byte entries')
    eui = (d.get('path_info') or {}).get('nvme_eui_bytes')
    if require_eui and eui not in (EUI, bytes.fromhex(EUI)[::-1].hex().upper()):
        problems.append(f'NVMe EUI64 {eui} is not the pinned Samsung {EUI}')
    if problems:
        raise PlanError('; '.join(problems))


def entries(d):
    return {p['guid']: {k: p[k] for k in ENTRY_KEYS} for p in d['partitions']}


def plan(survey, require_eui=True):
    d = the_disk(survey)
    check_disk(d, require_eui)
    parts = entries(d)
    if any(p['type'] == TYPE for p in parts.values()):
        raise PlanError('a Snapintosh window partition already exists; nothing to plan')
    for g in (BEFORE_NEIGHBOUR, AFTER_NEIGHBOUR, ESP, WINDOWS_C):
        if g not in parts:
            raise PlanError(f'pinned partition {g} is missing')
    if set(parts) != set(PINNED):
        raise PlanError(f'partition set differs from PROPOSAL.md: extra {sorted(set(parts) - set(PINNED))}, '
                        f'missing {sorted(set(PINNED) - set(parts))}')
    for g, (t, off, size) in PINNED.items():
        q = parts[g]
        if (q['type'], q['first_lba'] * BLOCK, (q['last_lba'] - q['first_lba'] + 1) * BLOCK) != (t, off, size):
            raise PlanError(f'partition {g} is not where PROPOSAL.md pins it: {q}')
    lo, hi = parts[BEFORE_NEIGHBOUR]['last_lba'] + 1, parts[AFTER_NEIGHBOUR]['first_lba'] - 1
    if (lo, hi) != APPROVED_EXTENT:
        raise PlanError(f'free extent is LBA {lo}..{hi}, the approved one is {APPROVED_EXTENT}')
    extent = [u for u in d['unallocated'] if u['first_lba'] == lo and u['last_lba'] == hi]
    if len(extent) != 1:
        raise PlanError(f'no free extent exactly between the pinned neighbours (LBA {lo}..{hi})')
    if any(p['first_lba'] <= hi and p['last_lba'] >= lo for p in parts.values()):
        raise PlanError('a partition overlaps the free extent')
    first, last = lo + GUARD_LBAS, hi - GUARD_LBAS
    if first % GUARD_LBAS or (last + 1) % GUARD_LBAS:
        raise PlanError('guarded partition is not 1 MiB aligned')
    size = (last - first + 1) * BLOCK
    if size < MIN_BYTES:
        raise PlanError(f'free extent gives only {size} bytes')
    used = {p['index'] for p in parts.values()}
    index = min(i for i in range(128) if i not in used)
    return dict(
        disk=dict(bytes=DISK_BYTES, block=BLOCK, gpt_guid=DISK_GUID, eui=EUI),
        protected=sorted(parts.values(), key=lambda p: p['first_lba']),
        extent=dict(first_lba=lo, last_lba=hi, offset=lo * BLOCK, bytes=(hi - lo + 1) * BLOCK),
        new=dict(expected_index=index, type=TYPE, name=NAME, first_lba=first, last_lba=last,
                 offset=first * BLOCK, bytes=size, end=(last + 1) * BLOCK, guard_bytes=GUARD_LBAS * BLOCK),
        windows=dict(new_partition=f"New-Partition -DiskNumber <pinned by UniqueId eui.{EUI}> "
                                   f"-Offset {first * BLOCK} -Size {size} -GptType '{{{TYPE}}}' "
                                   f"-NoDefaultDriveLetter",
                     diskpart=f"create partition primary offset={first * BLOCK // 1024} "
                              f"size={size >> 20} id={TYPE}"),
    )


def same(a, b):
    return a is not None and b is not None and all(a[k] == b[k] for k in IDENTITY_KEYS)


def verify(before, after, p, require_eui=True, notes=None):
    """Every problem found; empty means the change is exactly the plan."""
    problems = []
    notes = [] if notes is None else notes
    a = the_disk(after)
    try:
        check_disk(a, require_eui)
    except PlanError as e:
        problems.append(str(e))
    old, new = {q['guid']: q for q in p['protected']}, entries(a)
    if entries(the_disk(before)) != old:
        problems.append('BEFORE survey differs from the plan it was made from')
    for g, q in old.items():
        if not same(new.get(g), q):
            problems.append(f'existing partition {g} changed: {q} -> {new.get(g)}')
        elif new[g]['index'] != q['index']:
            notes.append(f"partition {g} moved from GPT slot {q['index']} to {new[g]['index']} (identity unchanged)")
    added = [q for g, q in new.items() if g not in old]
    if len(added) != 1:
        problems.append(f'expected one new partition, found {len(added)}')
    else:
        n, want = added[0], p['new']
        if (n['type'], n['first_lba'], n['last_lba']) != (want['type'], want['first_lba'], want['last_lba']):
            problems.append(f'new partition is {n}, planned {want}')
        if n['attributes'] not in ALLOWED_ATTRS:
            problems.append(f"new partition has attributes {n['attributes']:#x}")
        # The slot Windows picks is not part of the contract; the GUID and LBAs are.
        free = [(u['first_lba'], u['last_lba']) for u in a['unallocated']
                if p['extent']['first_lba'] <= u['first_lba'] <= p['extent']['last_lba']]
        guards = [(p['extent']['first_lba'], want['first_lba'] - 1), (want['last_lba'] + 1, p['extent']['last_lba'])]
        if free != guards:
            problems.append(f'free space inside the old extent is {free}, expected only the guards {guards}')
    for key in ('disk_guid', 'first_usable', 'last_usable', 'disk_bytes', 'block_size'):
        if the_disk(before).get(key) != a.get(key):
            problems.append(f'disk {key} changed')
    return problems


def verify_undo(before, undone):
    b, u = entries(the_disk(before)), entries(the_disk(undone))
    problems = [] if b.keys() == u.keys() and all(same(b[g], u[g]) for g in b) else ['partition set differs from BEFORE']
    b, u = the_disk(before), the_disk(undone)
    if [(x['first_lba'], x['last_lba']) for x in b['unallocated']] != [(x['first_lba'], x['last_lba']) for x in u['unallocated']]:
        problems.append('free extents differ from BEFORE')
    return problems + list(u.get('errors', []))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='mode', required=True)
    pp = sub.add_parser('plan')
    pp.add_argument('--survey', type=Path, required=True)
    pp.add_argument('--out', type=Path)
    vp = sub.add_parser('verify')
    vp.add_argument('--before', type=Path, required=True)
    vp.add_argument('--after', type=Path, required=True)
    vp.add_argument('--plan', type=Path, required=True)
    up = sub.add_parser('verify-undo')
    up.add_argument('--before', type=Path, required=True)
    up.add_argument('--after', type=Path, required=True)
    for p in (pp, vp):
        p.add_argument('--no-eui', action='store_true', help='for Windows raw captures, which carry no device path')
    args = ap.parse_args(argv)
    load = lambda path: json.loads(path.read_text())
    if args.mode == 'plan':
        result = plan(load(args.survey), not args.no_eui)
        n = result['new']
        print(f"new partition: LBA {n['first_lba']}..{n['last_lba']} ({n['last_lba'] - n['first_lba'] + 1} blocks), "
              f"offset {n['offset']}, {n['bytes']} bytes ({n['bytes'] / (1 << 30):.3f} GiB), type {n['type']}, "
              f"slot {n['expected_index']}")
        print(f"guards: {n['guard_bytes']} bytes before and after; extent {result['extent']}")
        print(result['windows']['new_partition'])
        if args.out:
            args.out.write_text(json.dumps(result, indent=1) + '\n')
        return 0
    if args.mode == 'verify':
        notes = []
        problems = verify(load(args.before), load(args.after), load(args.plan), not args.no_eui, notes)
        for n in notes:
            print('note:', n)
    else:
        problems = verify_undo(load(args.before), load(args.after))
    for p in problems:
        print('FAIL:', p)
    print('PASS' if not problems else f'{len(problems)} problem(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
