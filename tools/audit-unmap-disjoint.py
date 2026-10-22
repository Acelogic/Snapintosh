#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check endpoint-8 witnesses and independently walk their current source roots.

The shipped endpoint forces options=0. Its final matching descriptor keeps
only template bits 63:61; old descriptors are returned even for stale entries.
The full runtime audit separately reconstructs ownership and verifies every
cached/private translation. Historical witnesses may have been superseded.
"""
import struct

FIELDS = 'calls entries changed options result target count root va slot old next shift flags last_changed requested'.split()
PA = 0x0000ffffffffc000
TEMPLATE = 0xe000000000000000


def audit(read, *, states, ram_low, ram_high, frame_map, frame_low, kernel_root=None):
    if len(states) != 6:
        raise ValueError('unmap CPU count')
    rows = []
    totals = [0, 0, 0]
    for cpu, pair in enumerate(states):
        if len(pair) != 2:
            raise ValueError('unmap witness pair')
        latest, changed = pair
        if (changed['calls'] > latest['calls'] or
                changed['entries'] > latest['entries'] or
                changed['changed'] != latest['changed'] or
                bool(changed['calls']) != bool(latest['changed'])):
            raise ValueError('unmap changed witness counters differ')
        totals = [a + latest[k] for a, k in zip(totals, ('calls', 'entries', 'changed'))]
        for kind, s in zip(('latest', 'changed'), pair):
            if not s['calls']:
                if any(s.values()):
                    raise ValueError('unused unmap witness is not empty')
                continue
            shift = s['shift']
            if (shift not in (12, 14) or not 1 <= s['count'] <= 64 or
                    s['entries'] < s['calls'] or s['entries'] < s['count'] or
                    s['changed'] > s['entries'] or s['options'] or s['result'] or
                    s['root'] & 0x3fff or s['target'] & 0x3fff or
                    not ram_low <= s['root'] < s['root'] + 0x4000 <= ram_high or
                    not ram_low <= s['target'] < s['target'] + 0x4000 <= ram_high or
                    s['va'] & ((1 << shift) - 1) or
                    (s['va'] >= 1 << 47 if kernel_root is None else
                     shift != 14 or s['flags'] or s['root'] != kernel_root or
                     not 0xffff800000000000 <= s['va'] <= 0xffffffffffffffff) or
                    s['slot'] & 7 or (s['slot'] and
                    not ram_low <= s['slot'] < s['slot'] + 8 <= ram_high)):
                raise ValueError('invalid unmap counters or geometry')
            matches = s['old'] & 3 == 3 and s['old'] & PA == s['target']
            expected = s['requested'] & TEMPLATE if matches else s['old']
            if (s['next'] != expected or s['last_changed'] != int(matches) or
                    (kind == 'changed' and not matches) or
                    (not s['slot'] and (s['old'] or s['next']))):
                raise ValueError('unmap descriptor policy differs')
            meta = read(frame_map + ((s['root'] - frame_low) >> 14) * 16, 16)
            live = meta[2] in (18, 19) if kernel_root is None else s['root'] == kernel_root
            current = slot = None
            if live:
                if kernel_root is None and meta[12] != int(shift == 12):
                    raise ValueError('unmap root format differs')
                table = s['root']
                for level in range(1 if shift == 14 else 0, 4):
                    at = table + 8 * ((s['va'] >> (shift + (3-level)*(shift-3))) &
                                     ((1 << (shift-3))-1))
                    if not ram_low <= at < at + 8 <= ram_high:
                        raise ValueError('unmap source walk outside RAM')
                    pte, = struct.unpack('<Q', read(at, 8))
                    if level == 3:
                        slot, current = at, pte
                    if pte & 3 != 3:
                        break
                    table = pte & ((1 << 48) - (1 << shift))
            row = dict(s, cpu=cpu, witness=kind, descriptor_policy_verified=True,
                       root_still_user=live, root_type=meta[2],
                       current_source_slot=None if slot is None else hex(slot),
                       current_source_pte=None if current is None else hex(current),
                       current_source_matches=slot == s['slot'] and current == s['next'],
                       current_mapping_absent=live and (current is None or current & 3 != 3))
            if kernel_root is not None:
                row['root_still_kernel'] = row.pop('root_still_user')
            for key in ('root', 'va', 'slot', 'old', 'next', 'target', 'requested', 'flags'):
                row[key] = hex(row[key])
            rows.append(row)
    return dict(zip(('calls', 'entries', 'changed'), totals), rows=rows,
                boundary='historical descriptor witnesses plus current source walks; '
                         'ownership and private translations require the full runtime audit')
