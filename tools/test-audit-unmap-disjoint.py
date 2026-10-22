#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise independent endpoint-8 audit against synthetic source hierarchies."""
import copy
from pathlib import Path
import runpy
import struct

mod = runpy.run_path(str(Path(__file__).with_name('audit-unmap-disjoint.py')))
checks = 0


def fixture(shift=14, kind=18, template=0):
    memory = bytearray(0x80000)
    root, target, frame_map, va = 0x4000, 0x18000, 0x60000, 0x400000
    memory[frame_map+16+2] = kind
    memory[frame_map+16+12] = int(shift == 12)
    table = root
    for level in range(1 if shift == 14 else 0, 4):
        slot = table + 8*((va >> (shift+(3-level)*(shift-3))) & ((1 << (shift-3))-1))
        child = 0x20000 + level*0x4000
        struct.pack_into('<Q', memory, slot, template if level == 3 else child | 3)
        table = child
    zero = dict.fromkeys(mod['FIELDS'], 0)
    state = dict(zero, calls=1, entries=1, changed=1, target=target, count=1,
                 root=root, va=va, slot=slot, old=target | 0xec3, next=template,
                 shift=shift, last_changed=1, requested=template | 0x1234)
    states = [[dict(zero), dict(zero)] for _ in range(6)]
    states[2] = [dict(state), dict(state)]
    read = lambda at, n: bytes(memory[at:at+n])
    kwargs = dict(states=states, ram_low=0, ram_high=0x60000,
                  frame_map=frame_map, frame_low=0)
    return memory, kwargs, read


def run(kwargs, read):
    global checks
    checks += 1
    return mod['audit'](read, **kwargs)


for shift in (12, 14):
    for kind in (18, 19):
        for bits in range(8):
            memory, kw, read = fixture(shift, kind, bits << 61)
            result = run(kw, read)
            assert result['calls'] == result['entries'] == result['changed'] == 1
            assert all(r['current_source_matches'] and r['current_mapping_absent']
                       for r in result['rows'])

memory, kw, read = fixture()
slot = kw['states'][2][0]['slot']
struct.pack_into('<Q', memory, slot, 0x34000 | 3)
assert all(not r['current_source_matches'] and not r['current_mapping_absent']
           for r in run(kw, read)['rows'])  # Superseded history is not proof of current absence.
memory[0x60000+16+2] = 11
assert all(not r['root_still_user'] and not r['current_mapping_absent']
           for r in run(kw, read)['rows'])

for field, value in [('next', 3), ('target', 0x1c000), ('options', 1), ('result', 5),
                     ('count', 65), ('last_changed', 0), ('slot', 0), ('shift', 16)]:
    memory, kw, read = fixture()
    kw['states'][2][0][field] = value
    try:
        run(kw, read)
    except ValueError:
        pass
    else:
        raise AssertionError(field)

memory, kw, read = fixture()
kw['states'][2][1]['changed'] = 0
try:
    run(kw, read)
except ValueError:
    pass
else:
    raise AssertionError('changed counter mismatch')

print(f'unmap disjoint auditor: {checks} cases passed')
