#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stopped-state audit of shared-region groups (SNAP_NATIVE_SHARED,
shadow/native-shared.h): each live group's 4K level-3 pages hold exactly the
translation of its guest 16K level-3 table (a 2 MiB without a page has no valid
guest leaf), its pages are the whole NATIVE_SHARED_OWNER allocation domain, the
index finds every live group and nothing else, and its slot bits match the
level-2 entries that cached slots' trees actually hold. Read-only; `read(pa, n)`
reads stopped memory."""
import struct

PAGES, GROUPS, INDEX, SLOTS = 16, 4096, 8192, 64
GROUP_WORDS = 5 + PAGES
OWNER = 200                     # probes/xnuboot.c NATIVE_SHARED_OWNER
HEADER = ('live', 'created', 'freed', 'stores', 'linked', 'unlinked', 'errors', 'full', 'stale')
SPAN = 1 << 25
GUEST_OA = 0x0000ffffffffc000
OA = 0x0000fffffffff000
LEAF_ATTRS = 0x7fc              # AttrIndx, NS, AP, SH, AF, nG
LEAF_UPPER = 3 << 53            # PXN, UXN
FIXED = 0xac88                  # compat/sprr.h sprr_fixed_native_leaf
MASK = INDEX - 1


def home(guest):
    """shadow/native-shared.c home(): the probe start of a guest table PA."""
    return (((guest >> 14) * 0x9e3779b97f4a7c15) & (2 ** 64 - 1)) >> (64 - 13) & MASK


def decode(raw, group_offset=len(HEADER) * 8, index_offset=None):
    """The header, live groups {index: group} and the index table."""
    index_offset = index_offset if index_offset is not None else group_offset + GROUPS * GROUP_WORDS * 8
    if len(raw) < index_offset + INDEX * 2:
        raise ValueError('native shared record too short')
    header = dict(zip(HEADER, struct.unpack_from(f'<{len(HEADER)}Q', raw)))
    groups = {}
    for g in range(GROUPS):
        words = struct.unpack_from(f'<{GROUP_WORDS}Q', raw, group_offset + g * GROUP_WORDS * 8)
        if words[0]:
            groups[g] = dict(guest=words[0], shared=words[1], va=words[2], leaves=words[3], slots=words[4],
                             pages=list(words[5:]))
        elif any(words):
            raise ValueError('free group record is not zero')
    index = list(struct.unpack_from(f'<{INDEX}H', raw, index_offset))
    return header, groups, index


def find(groups, index, guest):
    """shadow/native-shared.c native_shared_find()."""
    i = home(guest)
    for _ in range(INDEX):
        v = index[i]
        if not v:
            return -1
        if v <= GROUPS and v - 1 in groups and groups[v - 1]['guest'] == guest:
            return v - 1
        i = (i + 1) & MASK
    return -1


def translate(d):
    """shadow/native-shared.c translate(): four 4K descriptors, or None."""
    if not d & 1:
        return [0, 0, 0, 0]
    klass = ((d >> 4) & 12) | ((d >> 53) & 3)
    if d & 3 != 3 or not FIXED >> klass & 1:
        return None
    attrs = (d & (LEAF_ATTRS | LEAF_UPPER)) | 3
    return [((d & GUEST_OA) + 4096 * k) | attrs for k in range(4)]


def level2(read, root, va):
    """The 4K level-2 table of a 4K tree (T0SZ 17, start level 0) holding va, or None."""
    table = root
    for shift in (39, 30):
        d, = struct.unpack('<Q', read(table + 8 * ((va >> shift) & 511), 8))
        if d & ~OA != 3 or not d & OA:
            return None
        table = d & OA
    return table


def link_entries(grp):
    return [pa | 3 if pa else 0 for pa in grp['pages']]


def audit(read, raw, owners, work_base, trees, **layout):
    """trees: {slot: canonical 4K root} of every cached slot that still has a tree
    (valid or not: an invalid slot keeps its tree, and its links, until reused).
    Returns a summary with the set of group page PAs ('pages')."""
    header, groups, index = decode(raw, **layout)
    if header['errors'] or header['live'] != len(groups) or \
            header['created'] - header['freed'] != header['live'] or header['linked'] < header['unlinked']:
        raise ValueError('native shared counters disagree')
    if header['full']:
        raise ValueError(f'native shared group records exhausted ({header["full"]} creations refused)')
    if sum(1 for v in index if v) != len(groups) or any(v and v - 1 not in groups for v in index):
        raise ValueError('native shared index names free groups or misses live ones')
    pages, leaves = set(), 0
    for g, grp in groups.items():
        if grp['guest'] & 16383 or grp['va'] & (SPAN - 1) or not grp['shared']:
            raise ValueError(f'group {g}: bad identity')
        if find(groups, index, grp['guest']) != g:
            raise ValueError(f'group {g}: not found through the index')
        if grp['slots'] >> SLOTS:
            raise ValueError(f'group {g}: slot bits beyond the cache')
        for pa in grp['pages']:
            if not pa:
                continue
            i = (pa - work_base) // 4096
            if pa & 4095 or pa < work_base or pa in pages or i >= len(owners) or owners[i] != OWNER:
                raise ValueError(f'group {g}: page outside its allocation domain or aliased')
            pages.add(pa)
        count = 0
        guest = struct.unpack('<2048Q', read(grp['guest'], 16384))
        tables = [struct.unpack('<512Q', read(pa, 4096)) if pa else None for pa in grp['pages']]
        for j, d in enumerate(guest):
            want = translate(d)
            if want is None:
                raise ValueError(f'group {g}: guest leaf {j} cannot be shared')
            count += d & 1
            table = tables[j // 128]
            if table is None:
                if d & 1:
                    raise ValueError(f'group {g}: guest leaf {j} has no page')
                continue
            if list(table[4 * (j % 128):4 * (j % 128) + 4]) != want:
                raise ValueError(f'group {g}: 4K entries of guest leaf {j} differ from its translation')
        if count != grp['leaves']:
            raise ValueError(f'group {g}: leaf count differs')
        leaves += count
    owned = {work_base + 4096 * i for i, o in enumerate(owners) if o == OWNER}
    if owned != pages:
        raise ValueError('shared group allocation domain differs from the live groups')
    links = {}
    for g, grp in groups.items():
        for slot in range(SLOTS):
            if not grp['slots'] >> slot & 1:
                continue
            if slot not in trees:
                raise ValueError(f'group {g}: linked by slot {slot}, which has no tree')
            table = level2(read, trees[slot], grp['va'])
            first = (grp['va'] >> 21) & 511
            entries = struct.unpack('<16Q', read(table + 8 * first, 128)) if table else None
            if entries is None or list(entries) != link_entries(grp):
                raise ValueError(f'slot {slot}: its link to group {g} is not in its tree')
            links[slot] = links.get(slot, 0) + 1
    # And the reverse: every level-2 entry of a tree that names a group page is
    # that slot's link, at its own position.
    where = {pa: (g, i) for g, grp in groups.items() for i, pa in enumerate(grp['pages']) if pa}
    for slot, root in trees.items():
        for i0, l0 in enumerate(struct.unpack('<512Q', read(root, 4096))):
            if not l0 & 1:
                continue
            for i1, l1 in enumerate(struct.unpack('<512Q', read(l0 & OA, 4096))):
                if l1 & 3 != 3:
                    continue
                for i2, l2 in enumerate(struct.unpack('<512Q', read(l1 & OA, 4096))):
                    hit = where.get(l2 & OA) if l2 & 3 == 3 else None
                    if hit is None:
                        continue
                    g, i = hit
                    va = (i0 << 39) | (i1 << 30) | (i2 << 21)
                    if not groups[g]['slots'] >> slot & 1 or va != groups[g]['va'] + (i << 21) or \
                            l2 != (l2 & OA) | 3:
                        raise ValueError(f'slot {slot}: unrecorded or misplaced link to group {g}')
    return dict(header=header, groups=len(groups), leaves=leaves, pages=pages, links=links)
