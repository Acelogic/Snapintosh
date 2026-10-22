#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only reference audit after a stopped sptm-mac-v1 kernel run.

Reconstruct allocator counts from every live guest leaf, including mappings
in monitor-owned bootstrap tables. The physical aperture is excluded. Does
not execute guest instructions, clear counters, or write target memory.
Addresses must come from the selected run's loader layout, not an older log.
"""
import argparse
import collections
import json
import itertools
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_memory import ManagedFrames, SEPFirmwareFrames


def audit(read, *, root, frame_map, frame_low, frame_high, alloc_low, alloc_high,
          aperture_va, aperture_size, ram_low, ram_high, user_roots=(), detached_commpages=(),
          dma_references=(), boot_ranges=(), boot_aliases=(), active_user_roots=(),shared_roots=(),
          sep_firmware=(0,0), sep_released=False, moved=()):
    # moved (SLIDE_REGION aliases) is for the kernel-permission audit; frame
    # ownership and reference counts do not depend on which alias XNU uses.
    del moved
    if not frame_low <= alloc_low < alloc_high <= frame_high:
        raise ValueError('allocator outside frame map')
    if (root | frame_low | frame_high | alloc_low | alloc_high) & 0x3fff:
        raise ValueError('unaligned frame range or root')
    managed=ManagedFrames(frame_map,frame_low,frame_high,alloc_low,alloc_high,
                          boot_ranges,boot_aliases,sep_firmware if sep_released else (0,0))
    firmware=SEPFirmwareFrames(managed,frame_map,frame_low,frame_high,alloc_low,
                               (0,0) if sep_released else sep_firmware)

    def owned(pa, size):
        if not ram_low <= pa < ram_high or size > ram_high - pa:
            raise ValueError(f'read outside owned RAM: {pa:#x}+{size:#x}')
        data = read(pa, size)
        if len(data) != size:
            raise ValueError('short target read')
        return data

    fm = owned(frame_map, ((frame_high - frame_low) >> 14) * 16)
    active_root_counts=collections.Counter(active_user_roots)
    if any(root not in user_roots for root in active_root_counts):
        raise ValueError('active root is missing from typed user-root inventory')
    counts, tables, seen = collections.Counter(), {}, set()
    user_links = {}
    user_parent_links=collections.Counter()
    user_geometry={}
    aperture = aperture_va & ((1 << 47) - 1)

    def check_exec_alias(pa,pte,privileged=False):
        kind=fm[((pa-frame_low)>>14)*16+2]
        if kind==42:
            selector=((pte>>4)&12)|((pte>>53)&3)
            if not privileged or selector!=11 or pte&(1<<59):
                raise ValueError('TXM_DEFAULT has a non-kernel-RO retained alias')
            return
        if kind not in (14,17):return
        selector=((pte>>4)&12)|((pte>>53)&3)
        allowed=(11,13,15) if kind==14 else (3,7,9,11,15)
        # Type17's policy is on the 4-bit class: Apple's UPDATE rows 7->23/31
        # and 9->25 leave WAS_WRITABLE on TPRO leaves (replay-sptm-matrix.py).
        if selector not in allowed or (kind==14 and pte&(1<<59)):
            label='USER_EXEC' if kind==14 else 'USER_TPRO'
            raise ValueError(f'{label} frame has an unsupported alias')

    def visit(pa, level, prefix, privileged):
        if pa in seen:
            raise ValueError('shared or cyclic table outside supported tree geometry')
        seen.add(pa)
        valid = 0
        for slot, (pte,) in enumerate(struct.iter_unpack('<Q', owned(pa, 0x4000))):
            va = prefix | (slot << (14 + (3 - level) * 11))
            target = pte & 0x0000ffffffffc000
            if level < 3:
                if pte & 3 == 3:
                    valid += 1
                    visit(target, level + 1, va, privileged)
                elif pte:
                    raise ValueError('block or malformed intermediate descriptor')
            else:
                valid += bool(pte & 3 == 3 or pte & 0xc000000000000000)
                if (pte & 3 == 3 and managed.contains(target)
                        and not (privileged and (aperture <= va < aperture + aperture_size or
                            managed.bootstrap_alias(va | 0xffff800000000000,target)))):
                    check_exec_alias(target,pte,privileged)
                    perm = ((pte >> 4) & 12) | ((pte >> 53) & 3)
                    ro = (perm & ~4) == 11 and not pte & (1 << 59)
                    counts[target, 0 if ro else 1] += 1
        if level == 3:
            tables[pa] = valid
        if not privileged:
            user_links[pa] = (level, valid)

    nested_edges=[]
    def visit_user(pa, level, prefix, shift, start, limit, table_type=20, binding=255):
        # The monitor allocates 16 KiB frames in both geometries. With 4 KiB
        # granules, one link owns four consecutive subtables in that frame.
        if pa & 0x3fff or not managed.contains(pa):
            raise ValueError('user table outside allocator')
        off = ((pa-frame_low) >> 14)*16
        repeated=pa in seen
        if repeated and (level!=3 or fm[off+2]!=23 or user_geometry.get(pa)!=shift):
            raise ValueError('shared or cyclic ordinary user table, or inconsistent commpage geometry')
        seen.add(pa)
        user_geometry[pa]=shift
        if level!=start:user_parent_links[pa]+=1
        if fm[off:off+2] != b'\0\0':
            raise ValueError('user table is busy')
        allowed_types=(20,23) if table_type==20 else (21,)
        if level != start and (fm[off+2] not in allowed_types or fm[off+4] != level
                              or (fm[off+2] == 23 and level != 3)):
            raise ValueError('user table has incompatible frame type or level')
        entries = struct.unpack('<2048Q', owned(pa, 0x4000))
        valid, group = 0, 0x4000 >> shift
        stride = shift + (3-level)*(shift-3)
        for slot in range(0, 2048, group if level < 3 else 1):
            va = prefix | (slot << stride)
            pte = entries[slot]
            if level < 3:
                siblings = entries[slot:slot+group]
                if not any(siblings):
                    continue
                # Ordinary L2 nesting owns each copied descriptor separately.
                # A partial 4K group is valid; its shared source still owns the
                # complete allocation and the data references within it.
                shared_members=[]
                if table_type==20 and level==2:
                    for tte in siblings:
                        frame=tte & 0x0000ffffffffc000
                        shared_members.append(bool(tte and managed.contains(frame) and
                            fm[((frame-frame_low)>>14)*16+2]==21))
                if any(shared_members):
                    if binding==255:
                        raise ValueError('nested table without shared binding')
                    for n,tte in enumerate(siblings):
                        if not tte:continue
                        frame=tte & 0x0000ffffffffc000
                        addr=va+(n<<stride)
                        if (not shared_members[n] or addr>=limit or
                                tte & ~((1<<48)-(1<<shift)) != 3):
                            raise ValueError('invalid partial nested table group')
                        valid+=1;user_parent_links[frame]+=1
                        nested_edges.append((binding,shift,addr,tte))
                    continue
                target = pte & 0x0000ffffffffc000
                attrs = pte & ~0x0000ffffffffc000
                if attrs != 3 and not (level == 2 and attrs == 7):
                    raise ValueError('invalid user table lifetime bits')
                if attrs == 7:
                    child_off = ((target-frame_low) >> 14)*16
                    if not managed.contains(target) or fm[child_off+2] != 20:
                        raise ValueError('only ordinary L3 tables may be condemned')
                if va >= limit or any(tte != ((target + (n << shift)) | attrs)
                                      for n, tte in enumerate(siblings)):
                    raise ValueError('malformed or out-of-range user table group')
                valid += 1
                visit_user(target, level+1, va, shift, start, limit, table_type,binding)
            else:
                if pte and va >= limit:
                    raise ValueError('user leaf outside root address width')
                valid += bool(pte & 3 == 3 or pte & 0xc000000000000000)
                target = pte & 0x0000ffffffffc000
                if not repeated and pte & 3 == 3 and managed.contains(target):
                    check_exec_alias(target,pte)
                    perm = ((pte >> 4) & 12) | ((pte >> 53) & 3)
                    ro = (perm & ~4) == 11 and not pte & (1 << 59)
                    counts[target, 0 if ro else 1] += 1
        user_links[pa] = (level, valid)
        if level == 3:
            tables[pa] = valid

    visit(root, 1, 0, True)
    bindings=collections.Counter();binding_formats={}
    for user_root in user_roots:
        if user_root & 0x3fff or not managed.contains(user_root):
            raise ValueError('user root outside allocator')
        off = ((user_root - frame_low) >> 14) * 16
        flags = struct.unpack_from('<H', fm, off+10)[0]
        fmt = struct.unpack_from('<I', fm, off+12)[0]
        if (fm[off+2] != 18 or fmt not in (0, 1) or (flags|2)&~9 not in (2, 6, 0x22)
                or (flags&4 and fmt != 1) or fm[off:off+2] != b'\0\0'):
            raise ValueError('user root must be an idle supported USER_ROOT frame')
        if fm[off+9]:
            raise ValueError('invalid user binding slot')
        if fm[off+8]!=255:
            slot=fm[off+8]
            if slot in binding_formats and binding_formats[slot]!=fmt:
                raise ValueError('inconsistent shared binding format')
            bindings[slot]+=1;binding_formats[slot]=fmt
        visit_user(user_root, 1 if fmt == 0 else 0, 0,
                   14 if fmt == 0 else 12, 1 if fmt == 0 else 0,
                   1 << (32 if flags&0x20 else 47),binding=fm[off+8])
    shared_slots=set();shared_by_slot={}
    for shared_root in shared_roots:
        if shared_root & 0x3fff or not managed.contains(shared_root):
            raise ValueError('shared root outside allocator')
        off=((shared_root-frame_low)>>14)*16
        f=fm[off:off+16]
        if (f[2]!=19 or f[:2]!=b'\0\0' or
                f[8]==255 or f[8] in shared_slots or any(f[9:12]) or
                f[12] not in (0,1) or any(f[13:])):
            raise ValueError('invalid shared root')
        refs=int.from_bytes(f[4:6],'little')
        if refs!=bindings[f[8]] or refs>0xfff9 or (refs and binding_formats[f[8]]!=f[12]):
            raise ValueError('shared root binding references disagree')
        shared_slots.add(f[8])
        shared_by_slot[f[8]]=(shared_root,12 if f[12] else 14)
        visit_user(shared_root,0 if f[12] else 1,0,
                   12 if f[12] else 14,0 if f[12] else 1,1<<47,21)
    if set(bindings)-shared_slots:
        raise ValueError('user binding has no shared root')
    for binding,shift,va,pte in nested_edges:
        source,source_shift=shared_by_slot[binding]
        if shift!=source_shift:raise ValueError('nested source geometry mismatch')
        mask=(1<<48)-(1<<shift)
        for level in range(0 if shift==12 else 1,3):
            index=(va>>(shift+(3-level)*(shift-3)))&((1<<(shift-3))-1)
            actual=struct.unpack('<Q',owned(source+index*8,8))[0]
            if actual & ~mask != 3:raise ValueError('invalid nested source path')
            if level==2 and actual!=pte:
                raise ValueError('nested descriptor differs from bound shared source')
            source=actual&mask
    active_tables = len(seen)
    for table in detached_commpages:
        if table & 0x3fff or not managed.contains(table):
            raise ValueError('detached commpage table outside allocator')
        off = ((table-frame_low) >> 14)*16
        if fm[off+2] != 23 or fm[off+4] != 3 or fm[off:off+2] != b'\0\0' or fm[off+6:off+8] != b'\0\0':
            raise ValueError('detached commpage must be an idle unattached type-23 L3')
        visit(table, 3, 0, False)
    cpu_mappings=sum(counts.values())
    boot_cpu_mappings=sum(n for (pa,_),n in counts.items() if pa<alloc_low)
    dma_mappings=0;dma_seen=set()
    for ref in dma_references:
        pa=int(ref['pa'],16);ro=ref['readonly'];other=ref['other']
        if (pa in dma_seen or pa&0x3fff or not (managed.contains(pa) or firmware.contains(pa))
                or any(type(v) is not int or not 0<=v<=0x7fffffff for v in (ro,other))
                or not ro+other or fm[((pa-frame_low)>>14)*16+2]!=11):
            raise ValueError('invalid independently audited DMA references')
        dma_seen.add(pa);counts[pa,0]+=ro;counts[pa,1]+=other;dma_mappings+=ro+other
    mismatches, tracked = [], 0
    for pa in itertools.chain(managed.frames(),firmware.frames()):
        off = ((pa - frame_low) >> 14) * 16
        kind = fm[off + 2]
        if firmware.contains(pa) and fm[off:off+8]!=bytes([0,0,11,0,0,0,0,0]):
            raise ValueError('reserved SEP firmware has non-data ownership')
        if kind==21 and pa not in user_links:
            # Fresh shared tables can be allocated before MAP_TABLE, but
            # no detached shared table may retain unexplained references.
            if fm[off:off+2]!=b'\0\0' or fm[off+4]>3:
                raise ValueError('invalid unattached shared table')
            got_shared=struct.unpack_from('<2H',fm,off+6)
            if got_shared!=(0,0):
                mismatches.append({'pa':hex(pa),'field':'unattached shared table references',
                                   'expected':(0,0),'actual':got_shared})
        if pa in user_links:
            level, children = user_links[pa]
            got_links = struct.unpack_from('<H', fm, off+6)[0]
            want_links = children+active_root_counts[pa] if kind in (18,19) else user_parent_links[pa]
            if got_links != want_links:
                mismatches.append({'pa': hex(pa), 'field': 'table links', 'expected': want_links, 'actual': got_links})
            if kind not in (18,19) and level < 3:
                got_children = struct.unpack_from('<H', fm, off+8)[0]
                if got_children != children:
                    mismatches.append({'pa': hex(pa), 'field': 'child tables', 'expected': children, 'actual': got_children})
        if kind in (11, 14, 17, 25, 29, 30, 31, 35, 42):
            if kind==17 and (any(fm[off:off+2]) or any(fm[off+3:off+8])):
                raise ValueError('USER_TPRO metadata has unsupported private fields')
            got = struct.unpack_from('<2I', fm, off + 8)
            want = (counts[pa, 0], counts[pa, 1])
            if kind==42 and (any(fm[off:off+2]) or any(fm[off+3:off+8]) or
                             got[0]>0x7fffffff or got[1] or want[1]):
                raise ValueError('TXM_DEFAULT metadata or retained references are invalid')
        elif kind == 24:
            # Ownership at +8 is device/SID/level, never CPU alias counts.
            # Only the privileged aperture may currently map IOMMU frames.
            got = (counts[pa, 0], counts[pa, 1])
            want = (0, 0)
        elif kind in (20, 21, 22, 23) and fm[off + 4] == 3:
            tracked += 1
            got = struct.unpack_from('<H', fm, off + 8)[0]
            want = tables.get(pa, 0)
        else:
            continue
        if got != want:
            mismatches.append({'pa': hex(pa), 'type': kind, 'expected': want, 'actual': got})
    return {'active_tables': active_tables, 'retained_tables': len(detached_commpages),
            'nested_descriptors':len(nested_edges),
            'nested_tables':len({pte&0x0000ffffffffc000 for _,_,_,pte in nested_edges}),
            'audited_tables': len(seen), 'tracked_l3_tables': tracked,
            'data_frames': len({pa for pa, _ in counts}),
            'boot_frames_audited': sum(pages for _,_,pages in boot_ranges),
            'boot_cpu_mappings': boot_cpu_mappings,
            'boot_data_frames': len({pa for pa,_ in counts if pa<alloc_low and managed.contains(pa)}),
            'sep_firmware_released': bool(sep_released),
            'sep_firmware_frames_audited': len(firmware.frames()),
            'sep_firmware_dma_mappings': sum(n for (pa,_),n in counts.items() if firmware.contains(pa)),
            'boot_table_frames': sum(managed.contains(pa) and pa<alloc_low for pa in seen),
            'data_mappings': cpu_mappings, 'dma_mappings': dma_mappings, 'mismatches': mismatches}


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
    import run
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', default=run.DEFAULT_DEVICE)
    parser.add_argument('--boot-memory',type=Path,
                        help='JSON with boot_ranges and boot_aliases triples (VA, PA, pages)')
    parser.add_argument('--user-root', dest='user_roots', action='append', default=[],
                        type=lambda s: int(s, 0), help='additional inactive 16 KiB or 4 KiB root; repeatable')
    parser.add_argument('--detached-commpage', dest='detached_commpages', action='append', default=[],
                        type=lambda s: int(s, 0), help='retained populated type-23 table; repeatable')
    for name in ('root', 'frame-map', 'frame-low', 'frame-high', 'alloc-low',
                 'alloc-high', 'aperture-va', 'aperture-size', 'ram-low', 'ram-high'):
        parser.add_argument('--' + name, required=True, type=lambda s: int(s, 0))
    args = vars(parser.parse_args())
    boot_memory=args.pop('boot_memory')
    if boot_memory:
        boot=json.loads(boot_memory.read_text())
        for key in ('boot_ranges','boot_aliases'):
            args[key]=[tuple(int(v,0) if isinstance(v,str) else v for v in row) for row in boot[key]]
    proxy = run.connect(args.pop('device'), tries=1)
    try:
        result = audit(proxy.readmem, **args)
    finally:
        proxy.link.close()
    print(json.dumps(result, indent=2))
    return int(bool(result['mismatches']))


if __name__ == '__main__':
    raise SystemExit(main())
