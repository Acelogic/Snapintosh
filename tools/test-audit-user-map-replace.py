#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent source-walk and policy fault injection for MAP_PAGE replacements."""
import contextlib
import io
from pathlib import Path
import runpy
import struct

HERE = Path(__file__).resolve().parent
with contextlib.redirect_stdout(io.StringIO()):
    fixture = runpy.run_path(str(HERE/'test-audit-unmap-disjoint.py'))['fixture']
mod = runpy.run_path(str(HERE/'audit-user-map-replace.py'))
checks = 0


def case(shift=14):
    memory,kw,read = fixture(shift)
    kw['states'] = [pair[0] for pair in kw['states']]
    s = kw['states'][2]
    s['old'] |= 0x0060000000000000
    s['requested'] = s['next'] = s['old'] & ~0x80
    s['result'] = 1   # shipped MAP_PAGE reports a replaced valid leaf as 1
    struct.pack_into('<Q',memory,s['slot'],s['next'])
    return memory,kw,read


def audit(kw,read):
    global checks
    checks += 1
    return mod['audit'](read,**kw)


for shift in (12,14):
    memory,kw,read = case(shift)
    result = audit(kw,read)
    assert result['calls'] == 1 and result['rows'][0]['current_source_matches']
    struct.pack_into('<Q',memory,kw['states'][2]['slot'],0)
    assert not audit(kw,read)['rows'][0]['current_source_matches']
    memory[0x60000+16+2] = 11
    assert not audit(kw,read)['rows'][0]['root_still_user']

for field,value in [('next',3),('target',0x1c000),('options',2),('result',0),
                    ('count',2),('last_changed',0),('slot',1),('shift',16),
                    ('requested',0x0020000000018ec3),('changed',0)]:
    memory,kw,read = case()
    kw['states'][2][field] = value
    try:
        audit(kw,read)
    except ValueError:
        pass
    else:
        raise AssertionError(field)
print(f'user MAP_PAGE replacement auditor: {checks} cases passed')
