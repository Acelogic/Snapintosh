#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject fabricated status history or production/secure bits in captured state."""
from copy import deepcopy
from pathlib import Path
import json
from audit_sep_rom import audit_history

ROOT=Path(__file__).resolve().parents[1]
captured=json.loads((ROOT/'build/sep-pnon-live-20260922-audit.json').read_text())['sep_asc'][0]
audit_history(captured)
state=deepcopy(captured)
state.update(status_queries=1,status_last_request='0x140800',virtual_effective_status=0,
             consumed=18,published=20,delivered=19,reply_count=1,count=0,requests=[],
             replies=[['0x140800','0x0']])
checks=1
def rejects(action):
    global checks
    try:action()
    except AssertionError:checks+=1
    else:raise AssertionError('accepted corrupt effective-status evidence')
audit_history(state);checks+=1
for tag in range(1,256):
    sample=deepcopy(state);word=0x140000|tag<<8
    sample.update(status_last_request=hex(word),replies=[[hex(word),'0x0']])
    audit_history(sample);checks+=1
for key,value in [('status_queries',-1),('status_queries',0),('status_queries',2),
                  ('status_queries',1<<64),('status_last_request',0),
                  ('status_last_request','0x140000'),('status_last_request','0x100140800'),
                  ('virtual_effective_status',None),('virtual_effective_status',1),
                  ('virtual_effective_status',2),('virtual_effective_status',3),
                  ('pnon_recovery',False),('service_bootstrap',False),('rom_stage',2),
                  ('consumed',17),('published',19),
                  ('replies',[['0x140800','0x1']]),
                  ('replies',[['0x140800','0x0'],['0x140900','0x0']])]:
    bad=deepcopy(state);bad[key]=value;rejects(lambda:audit_history(bad))
for bit in range(64):
    if 8<=bit<16:continue
    bad=deepcopy(state);bad['replies']=[[hex(0x140800^(1<<bit)),'0x0']]
    rejects(lambda:audit_history(bad))
# Generation24 stopped on the actual installed status request without pnon.
# Reconstruct its consumption and pending reply without inventing pnon state.
installed=json.loads((ROOT/'build/installed-xars-600s-20260926-audit.json').read_text())['sep_asc'][0]
assert installed['requests']==[['0x140800','0x0']]
assert installed['pnon_recovery'] is False and installed['xars_refusal'] is True
installed.update(status_queries=1,status_last_request='0x140800',virtual_effective_status=0,
                 consumed=18,published=20,delivered=19,reply_count=1,count=0,requests=[],
                 replies=[['0x140800','0x0']])
audit_history(installed);checks+=1
for value in (1,2,3,None):
    bad=deepcopy(installed);bad['virtual_effective_status']=value
    rejects(lambda:audit_history(bad))
print(f'PASS: {checks} independent effective-status audit checks')
