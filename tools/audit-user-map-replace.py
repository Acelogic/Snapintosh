#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit completed same-PA MAP_PAGE changes using the pinned Apple policy rows."""
import hashlib
from pathlib import Path
import runpy
import struct

ROOT = Path(__file__).resolve().parents[1]
FIELDS = 'calls entries changed options result target count root va slot old next shift flags last_changed requested'.split()
PA = 0x0000ffffffffc000


def policy():
    im = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    if hashlib.sha256(im.data).hexdigest() != 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0':
        raise ValueError('wrong MAP_PAGE policy image')
    tables = [struct.unpack_from('<16H',im.data,im.locate(at)[1])
              for at in (0xfffffff02701a878,0xfffffff02701a898)]
    return [a | b for a,b in zip(*tables)]


def selected(old, requested, allowed):
    if old & 3 != 3 or requested & 3 != 3 or (old ^ requested) & 0xfffffffff000:
        raise ValueError('replacement is not a valid same-PA request')
    if old == requested:
        return old
    source = ((old >> 4) & 12) | ((old >> 53) & 3)
    dest = ((requested >> 4) & 12) | ((requested >> 53) & 3)
    if source != dest and not allowed[source] & (1 << dest):
        raise ValueError('MAP_PAGE permission transition rejected by Apple policy')
    value = (old & ~0x0c680000000000c0) | (requested & 0x0c600000000000c0)
    if (1 << dest) & 0x2a8 and value & (1 << 59):
        value &= ~((1 << 59) | (1 << 51))
    return value


def audit(read, *, states, ram_low, ram_high, frame_map, frame_low):
    if len(states) != 6:
        raise ValueError('replacement CPU count')
    allowed = policy()
    rows = []
    for cpu,s in enumerate(states):
        if not s['calls']:
            if any(s.values()):
                raise ValueError('unused replacement witness is not empty')
            continue
        shift = s['shift']
        if (s['calls'] != s['entries'] or s['calls'] != s['changed'] or
                s['count'] != 1 or s['options'] not in (0,1) or s['result'] != 1 or
                s['last_changed'] != 1 or s['old'] == s['next'] or
                shift not in (12,14) or s['root'] & 0x3fff or
                not ram_low <= s['root'] < s['root']+0x4000 <= ram_high or
                s['target'] != s['old'] & PA or
                not ram_low <= s['target'] < s['target']+0x4000 <= ram_high or
                s['slot'] & 7 or not ram_low <= s['slot'] < s['slot']+8 <= ram_high or
                s['va'] & ((1 << shift)-1) or s['va'] >= 1 << 47):
            raise ValueError('invalid replacement counters or geometry')
        if selected(s['old'],s['requested'],allowed) != s['next']:
            raise ValueError('MAP_PAGE selected descriptor differs')
        meta = read(frame_map+((s['root']-frame_low) >> 14)*16,16)
        live = meta[2] == 18
        current = slot = None
        if live:
            if meta[12] != int(shift == 12):
                raise ValueError('replacement root format differs')
            table = s['root']
            for level in range(1 if shift == 14 else 0,4):
                at = table+8*((s['va'] >> (shift+(3-level)*(shift-3))) & ((1 << (shift-3))-1))
                if not ram_low <= at < at+8 <= ram_high:
                    raise ValueError('replacement source walk outside RAM')
                pte, = struct.unpack('<Q',read(at,8))
                if level == 3:
                    slot,current = at,pte
                if pte & 3 != 3:
                    break
                table = pte & ((1 << 48)-(1 << shift))
        row = dict(s,cpu=cpu,descriptor_policy_verified=True,root_still_user=live,
                   current_source_pte=None if current is None else hex(current),
                   current_source_matches=slot == s['slot'] and current == s['next'])
        for key in ('root','va','slot','old','next','target','requested','flags'):
            row[key] = hex(row[key])
        rows.append(row)
    return dict(calls=sum(s['calls'] for s in states),rows=rows,
                boundary='historical policy witnesses and current source walk; full '
                         'runtime audit checks ownership and cached/private translations')
