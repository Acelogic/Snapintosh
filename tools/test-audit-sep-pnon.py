#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent endpoint-history and full-buffer corruption fixtures."""
from copy import deepcopy
from audit_sep_pnon import audit_history,audit_buffers,queued_reply,NAME,OOL,QUERY,REPLY,PAYLOAD
from audit_sep_pnon import REFUSED,NOT_SUPPORTED
import struct

SH=0x10000000000
SEND=SH+0x100000
RECEIVE=SEND+0x100000
geometry=dict(frame_map=0x100000,frame_low=0x100000,frame_high=0x800000,
              alloc_low=0x300000,alloc_high=0x800000,boot_ranges=(),boot_aliases=())
p=dict(ready=1,advertisements=2,negotiations=4,queries=1,last_request=QUERY,last_reply=REPLY,
       stage=[2,2],size=[0x1c000,0x14000],iova=[SEND,RECEIVE],
       physical=[[0x400000+n*0x4000 for n in range(7)],
                 [0x500000+n*0x4000 for n in range(5)]+[0,0]])
state=dict(pnon_recovery=True,rom_stage=3,pnon=p,rom_shared_iova=SH)
leaves=[]
for va,pa,count in [(SH,0x300000,5),(SEND,0x400000,7),(RECEIVE,0x500000,5)]:
    for n in range(count):
        leaves.append(dict(iova=va+n*0x4000,pa=pa+n*0x4000,device_id=20,sid=0,
                           readonly=False,no_read=False,begin=0,end=0x4000))
checks=0
def request(command):return struct.pack('<2I24x',0x42506368,command)
def reader(command,reply):
    def read(pa,size):
        if pa==0x400000:
            assert size==32
            return request(command)
        assert pa==0x500000 and size==len(reply)
        return reply
    return read
read=reader(0x3e,PAYLOAD)
def rejects(action):
    global checks
    try:action()
    except (AssertionError,KeyError):checks+=1
    else:raise AssertionError('accepted corrupt endpoint state')

assert audit_history(state)==(5,2);checks+=1
assert audit_buffers(state,leaves,geometry,read)['response_payload_verified'];checks+=1
for key,value in [('ready',0),('advertisements',1),('negotiations',3),('queries',-1),
                  ('last_request',QUERY^1),('last_reply',REPLY^1),('stage',[1,2]),
                  ('size',[0x18000,0x14000]),('iova',[SEND+1,RECEIVE]),
                  ('iova',[SEND,SEND+0x4000])]:
    bad=deepcopy(state);bad['pnon'][key]=value
    rejects(lambda:audit_history(bad))
for direction in range(2):
    for page in range(7):
        bad=deepcopy(state);bad['pnon']['physical'][direction][page]^=1
        rejects(lambda:audit_history(bad))
for index in range(5,17):
    rejects(lambda:audit_buffers(state,leaves[:index]+leaves[index+1:],geometry,read))
    for key,value in [('readonly',True),('no_read',True),('begin',4),('end',0x3ffc),
                      ('pa',0x700000),('device_id',21),('sid',1)]:
        bad=deepcopy(leaves);bad[index][key]=value
        rejects(lambda:audit_buffers(state,bad,geometry,read))
rejects(lambda:audit_buffers(state,leaves+leaves[-1:],geometry,read))
rejects(lambda:audit_buffers(state,leaves,geometry,lambda pa,n:bytes(n)))
for d in range(2):
    bad=deepcopy(state);bad['pnon']['physical'][d][0]=0x300000
    altered=deepcopy(leaves);altered[5 if d==0 else 12]['pa']=0x300000
    rejects(lambda:audit_buffers(bad,altered,geometry,read))
for tag in range(1,256):
    for op in range(2,6):
        d=op&1;data=p['size'][d] if op>=4 else p['iova'][d]>>12
        word=data<<32|1<<24|op<<16|tag<<8
        reply=word&~0xff000000
        sample=deepcopy(state);sample['pnon'].update(last_request=word,last_reply=reply)
        assert audit_history(sample)==(5,2) and queued_reply(sample,reply,0);checks+=1
        assert not queued_reply(sample,word,0);checks+=1
        sample['pnon']['last_reply']=word
        rejects(lambda:audit_history(sample))
for word in (NAME,OOL,REPLY,REFUSED):
    assert queued_reply(state,word,0) and not queued_reply(state,word,1);checks+=1
# mobileassetd's blessed recoveryOS policy nonce digest (0x10), answered not-supported.
refused=deepcopy(state);refused['pnon']['last_reply']=REFUSED
assert audit_history(refused)==(5,2);checks+=1
report=audit_buffers(refused,leaves,geometry,reader(0x10,NOT_SUPPORTED))
assert report['last_query']==dict(command='0x10',request_length=32,status=0xff,
    name='blessed recoveryOS policy nonce digest');checks+=1
assert audit_buffers(state,leaves,geometry,read)['last_query']['command']=='0x3e';checks+=1
for command,reply,sample in [(0x3e,NOT_SUPPORTED,refused),(0x10,PAYLOAD,state),(0,NOT_SUPPORTED,refused),
                             (0x100,NOT_SUPPORTED,refused)]:
    rejects(lambda:audit_buffers(sample,leaves,geometry,reader(command,reply)))
for byte in range(32):
    altered=bytearray(NOT_SUPPORTED);altered[byte]^=1
    rejects(lambda:audit_buffers(refused,leaves,geometry,reader(0x10,bytes(altered))))
    shape=bytearray(request(0x10));shape[byte]^=0x80
    if byte not in (4,5,6,7):
        rejects(lambda:audit_buffers(refused,leaves,geometry,lambda pa,n:bytes(shape) if pa==0x400000 else NOT_SUPPORTED))
# Commands with a body (header + body, up to the whole send buffer) are
# answered not-supported; 0x3e with a body is too, and never with the OS type.
for length,command in [(0x4028,0x11),(0x4030,0x3c),(0x8168,0x17),(0x1c000,0x4e),(33,0x3e),(0x124,0x3e)]:
    long=deepcopy(refused);long['pnon']['last_request']=length<<32|0x201
    assert audit_history(long)==(5,2);checks+=1
    report=audit_buffers(long,leaves,geometry,reader(command,NOT_SUPPORTED))
    assert report['last_query']['request_length']==length and report['last_query']['status']==0xff;checks+=1
    assert queued_reply(long,REFUSED,0) and not queued_reply(long,long['pnon']['last_request'],0);checks+=1
    forged=deepcopy(long);forged['pnon']['last_reply']=REPLY
    rejects(lambda:audit_history(forged))
for length in (0,31,0x1c001,0xffffffff):
    bad=deepcopy(refused);bad['pnon']['last_request']=length<<32|0x201
    rejects(lambda:audit_history(bad))
for kind in (0x301,0x10201,0x1000201,0x200):
    bad=deepcopy(refused);bad['pnon']['last_request']=0x4028<<32|kind
    rejects(lambda:audit_history(bad))
empty=deepcopy(state)
empty.update(pnon_recovery=False,rom_stage=0)
empty['pnon']=dict(ready=0,advertisements=0,negotiations=0,queries=0,last_request=0,
                  last_reply=0,stage=[0,0],size=[0,0],iova=[0,0],physical=[[0]*7,[0]*7])
assert audit_history(empty)==(0,0) and audit_buffers(empty,[],geometry,read) is None;checks+=1
installed=deepcopy(refused);installed.update(pnon_recovery=False,pnon_refusal=True)
assert audit_history(installed)==(5,2);checks+=1
for command in (0x0e,0x3e,0x11):
    report=audit_buffers(installed,leaves,geometry,reader(command,NOT_SUPPORTED))
    assert report['last_query']['status']==255 and report['os_type'] is None;checks+=1
    assert queued_reply(installed,REFUSED,0) and not queued_reply(installed,REPLY,0);checks+=1
bad=deepcopy(installed);bad['pnon']['last_reply']=REPLY
rejects(lambda:audit_history(bad))
bad=deepcopy(installed);bad['pnon_recovery']=True
rejects(lambda:audit_history(bad))
print(f'PASS: {checks} independent pnon history, DMA identity and payload checks')
