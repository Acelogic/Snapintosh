#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corrupt independent xars wire history and all cross-endpoint DMA spans."""
from copy import deepcopy
from audit_sep_xars import audit_history,audit_buffers,queued_reply,NAME,OOL

SH=0x10000000000
geometry=dict(frame_map=0x100000,frame_low=0x100000,frame_high=0x800000,
              alloc_low=0x300000,alloc_high=0x800000,boot_ranges=(),boot_aliases=())
state=dict(xars_refusal=True,pnon_recovery=True,rom_stage=3,rom_shared_iova=SH)
state['pnon']=dict(stage=[2,2],size=[0x1c000,0x14000],iova=[SH+0x100000,SH+0x200000],
                   physical=[[0x400000+n*0x4000 for n in range(7)],
                             [0x500000+n*0x4000 for n in range(5)]+[0,0]])
state['xars']=dict(ready=1,advertisements=2,negotiations=4,queries=1,last_request=0xa0702,last_reply=0x10702,
                   stage=[2,2],size=[0x8000,0x8000],iova=[SH+0x300000,SH+0x400000],
                   physical=[[0x600000,0x604000],[0x700000,0x704000]])
leaves=[]
for va,pa,count in [(SH,0x300000,5),(SH+0x100000,0x400000,7),(SH+0x200000,0x500000,5),
                    (SH+0x300000,0x600000,2),(SH+0x400000,0x700000,2)]:
    for n in range(count):
        leaves.append(dict(iova=va+n*0x4000,pa=pa+n*0x4000,device_id=20,sid=0,
                           readonly=False,no_read=False,begin=0,end=0x4000))
checks=0
def rejects(action):
    global checks
    try:action()
    except (AssertionError,KeyError):checks+=1
    else:raise AssertionError('accepted corrupt xars state')

assert audit_history(state)==(5,2);checks+=1
assert len(audit_buffers(state,leaves,geometry)['bindings'])==5;checks+=1
for field,value in [('ready',0),('advertisements',1),('negotiations',3),('queries',-1),
                    ('last_request',0xa0002),('last_reply',0x702),('stage',[1,2]),
                    ('size',[0x4000,0x8000]),('iova',[SH+1,SH+0x400000]),
                    ('iova',[SH+0x300000,SH+0x304000])]:
    bad=deepcopy(state);bad['xars'][field]=value
    rejects(lambda:audit_history(bad))
for index in range(21):
    rejects(lambda:audit_buffers(state,leaves[:index]+leaves[index+1:],geometry))
    for field,value in [('readonly',True),('no_read',True),('begin',4),('end',0x3ffc),
                        ('pa',0x300000),('device_id',21),('sid',1)]:
        if index==0 and field=='pa':value=0x400000
        bad=deepcopy(leaves);bad[index][field]=value
        rejects(lambda:audit_buffers(state,bad,geometry))
for d in range(2):
    for peer_va,peer_pa in [(SH,0x300000),(SH+0x100000,0x400000),(SH+0x200000,0x500000)]:
        bad=deepcopy(state);bad['xars']['iova'][d]=peer_va
        rejects(lambda:audit_buffers(bad,leaves,geometry))
        bad=deepcopy(state);altered=deepcopy(leaves)
        bad['xars']['physical'][d][0]=peer_pa;altered[17+2*d]['pa']=peer_pa
        rejects(lambda:audit_buffers(bad,altered,geometry))
for tag in range(1,256):
    for opcode in (10,11,32):
        sample=deepcopy(state)
        sample['xars'].update(last_request=opcode<<16|tag<<8|2,last_reply=1<<16|tag<<8|2)
        assert audit_history(sample)==(5,2)
        assert queued_reply(sample,sample['xars']['last_reply'],0);checks+=1
        sample['xars']['last_reply']=tag<<8|2
        rejects(lambda:audit_history(sample))
    for opcode in range(2,6):
        sample=deepcopy(state);d=opcode&1
        value=0x8000 if opcode>=4 else sample['xars']['iova'][d]>>12
        request=value<<32|2<<24|opcode<<16|tag<<8
        reply=request&~0xff000000
        sample['xars'].update(last_request=request,last_reply=reply)
        assert audit_history(sample)==(5,2) and queued_reply(sample,reply,0);checks+=1
        sample['xars']['last_reply']=request
        rejects(lambda:audit_history(sample))
for tag in range(1,256):
    for slot in (0,1):
        sample=deepcopy(state);request=slot<<48|0x18<<16|tag<<8|2
        sample['xars'].update(last_request=request,last_reply=56<<24|tag<<8|2)
        assert audit_history(sample)==(5,2)
        assert queued_reply(sample,sample['xars']['last_reply'],0);checks+=1
        for bad_reply in (tag<<8|2,1<<16|56<<24|tag<<8|2,56<<24|1<<48|tag<<8|2,55<<24|tag<<8|2):
            sample['xars']['last_reply']=bad_reply
            rejects(lambda:audit_history(sample))
    for bad_request in (2<<48|0x18<<16|tag<<8|2,1<<40|0x18<<16|tag<<8|2):
        sample=deepcopy(state)
        sample['xars'].update(last_request=bad_request,last_reply=56<<24|tag<<8|2)
        rejects(lambda:audit_history(sample))
    assert not queued_reply(state,56<<24|tag<<8|2|1<<48,0);checks+=1
    # getFullEpochs: opcode0x17 only; eight empty slots, status0, length32.
    sample=deepcopy(state);request=0x17<<16|tag<<8|2
    sample['xars'].update(last_request=request,last_reply=32<<24|tag<<8|2)
    assert audit_history(sample)==(5,2) and queued_reply(sample,32<<24|tag<<8|2,0);checks+=1
    for bad_reply in (tag<<8|2,1<<16|32<<24|tag<<8|2,33<<24|tag<<8|2,56<<24|tag<<8|2):
        sample['xars']['last_reply']=bad_reply
        rejects(lambda:audit_history(sample))
    for bad_request in (1<<48|0x17<<16|tag<<8|2,1<<32|0x17<<16|tag<<8|2):
        sample=deepcopy(state)
        sample['xars'].update(last_request=bad_request,last_reply=32<<24|tag<<8|2)
        rejects(lambda:audit_history(sample))
for word in (NAME,OOL,0x10702,0x38000702,0x20000702):
    assert queued_reply(state,word,0) and not queued_reply(state,word,1);checks+=1
empty=dict(rom_stage=0,xars_refusal=False)
assert audit_history(empty)==(0,0) and audit_buffers(empty,[],geometry) is None;checks+=1
print(f'PASS: {checks} independent xars history, refusal, empty-slot, empty-epoch and cross-endpoint DMA checks')
