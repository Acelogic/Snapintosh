#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Failure-first decoder/allowlist checks for the bounded read-only survey."""
import importlib.util, json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('survey',R/'tools/a16-thermal-survey.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
base=dict(version=0x20000000,control=1|(1<<3)|(1<<21),ready=1,status=(1<<21)|423)
assert m.decode_sensor(**base)['millidegrees_c']==42300
assert m.decode_sensor(**dict(base,status=(1<<21)|0xff6))['millidegrees_c']==-1000
for field,value in [('version',0),('control',0),('control',3|(1<<3)|(1<<21)),('control',1|(1<<21)),('control',1|(1<<3)),('status',423)]:
    assert m.decode_sensor(**dict(base,**{field:value}))['millidegrees_c'] is None,(field,value)
assert m.decode_sensor(**dict(base,version=0x30020000))['millidegrees_c']==42300
for v in (0x30010000,0x30020001,0x40000000):
    assert m.decode_sensor(**dict(base,version=v))['millidegrees_c'] is None
assert m.replay_blocks([dict(index=0,version=0x30020000)])[0]['complete'] is False
assert m.decode_sensor(**dict(base,ready=0))['millidegrees_c']==42300
assert len(m.allowed_addresses())==8*(3+16)
assert 0x0c22c000+0xc not in m.allowed_addresses() # interrupt-clear writes are never allowed
class Fake:
    def read32(self,a):raise AssertionError('out-of-allowlist address reached proxy')
try:m.read_allowed(Fake(),0x0c22c00c,[])
except ValueError:pass
else:raise AssertionError('bad address accepted')
print(json.dumps(dict(result='PASS',scope='isolated decoder and read allowlist; no hardware',checks='signed values, revision, enable/mode/validity, incomplete capture, and read allowlist')))
