# SPDX-License-Identifier: MIT
"""Decode and independently audit the bounded SKS startup service."""
import hashlib
import struct

NAME=0x736b7320030000fd
OOL=0x02020202030100fd
STATE_BYTES=1176


def number(v):return int(v,0) if isinstance(v,str) else v


def decode(data):
    assert len(data)==STATE_BYTES,'SKS state capture size'
    words=struct.unpack_from('<16Q',data)
    state=dict(zip(('ready','advertisements','negotiations','queries','last_request','last_reply'),words[:6]))
    state.update(stage=list(words[6:8]),size=list(words[8:10]),iova=list(words[10:12]),
        physical=[list(words[12:14]),list(words[14:16])])
    updates,valid=struct.unpack_from('<QI',data,128)
    environment=data[140:]
    state['wire']=dict(updates=updates,environment_valid=valid,
        environment_version=struct.unpack_from('<I',environment)[0],
        environment_flags=struct.unpack_from('<I',environment,8)[0],
        environment_sha256=hashlib.sha256(environment).hexdigest())
    return state


def is_query(word):return word&255==3 and not word&0x8000 and not word>>24&0xffffff


def reply_shape(word):
    if word&255!=3 or not word&0x8000 or word>>32&0xffff:return False
    status=word>>24&255;length=word>>48;command=word>>8&127
    if status:return status<=4 and length==0
    return length in ((92,100) if command==0x4d else (80,88) if command==0x2a else ())


def audit_history(asc):
    selected=int(bool(asc.get('sks_startup')) and number(asc['rom_stage'])==3)
    state=asc.get('sks')
    if state is None:
        assert not selected,'missing selected SKS state'
        return 0,0
    assert state['ready']==selected and state['advertisements']==2*selected,'SKS readiness'
    controls,queries=state['negotiations'],state['queries']
    assert 0<=controls<1<<64 and 0<=queries<1<<64,'SKS counters'
    assert selected or controls==queries==0,'premature SKS traffic'
    wire=state['wire'];updates=wire['updates'];valid=wire['environment_valid']
    assert 0<=updates<=queries and valid in (0,1) and bool(updates)==bool(valid),'SKS environment accounting'
    if valid:assert wire['environment_version']==1 and wire['environment_flags'] in (4,6),'SKS environment shape'
    seen=[]
    for d in range(2):
        stage=state['stage'][d];va=number(state['iova'][d])
        assert stage in range(3) and (selected or not stage),'SKS stage'
        assert state['size'][d]==(0x8000 if stage else 0),'SKS extent'
        assert (0<va<va+0x8000<=1<<44 and not va&0x3fff) if stage==2 else va==0,'SKS IOVA'
        assert len(state['physical'][d])==2,'SKS physical array'
        for raw in state['physical'][d]:
            pa=number(raw)
            if stage!=2:assert pa==0,'unbound SKS page'
            else:
                assert pa and not pa&0x3fff and pa not in seen,'SKS physical alias/alignment'
                seen.append(pa)
    assert controls>=sum(state['stage']),'SKS negotiation count'
    assert not queries or state['stage']==[2,2],'SKS query before buffers'
    if state['stage']==[2,2]:
        a,b=map(number,state['iova']);assert a+0x8000<=b or b+0x8000<=a,'SKS IOVA overlap'
    req,reply=map(number,(state['last_request'],state['last_reply']))
    if not controls and not queries:assert req==reply==0,'empty SKS history'
    elif is_query(req):
        assert queries and req>>48<=0x8000 and reply_shape(reply),'SKS query reply shape'
        assert reply&0xffffff==(req&0xffffff)|0x8000,'SKS echoed command/sequence'
    else:
        op=req>>16&255;d=op&1
        assert controls and req&0xff0000ff==0x3000000 and req&0xff00 and 2<=op<=5,'SKS control history'
        assert reply==req&~0xff000000,'SKS control status'
        if op>=4:assert state['stage'][d]>=1 and req>>32==0x8000,'SKS length acknowledgement'
        else:assert state['stage'][d]==2 and req>>32<<12==number(state['iova'][d]),'SKS binding acknowledgement'
    return controls+queries,state['advertisements']


def queued_reply(asc,lo,hi):
    state=asc.get('sks');word=number(lo)
    if not state or not state['ready'] or number(hi):return False
    if word in (NAME,OOL):return True
    if reply_shape(word):return bool(state['queries'])
    op=word>>16&255;d=op&1
    if word&0xff0000ff or not word&0xff00 or not 2<=op<=5 or not state['negotiations']:return False
    return (state['stage'][d]>=1 and word>>32==0x8000) if op>=4 else (
        state['stage'][d]==2 and word>>32<<12==number(state['iova'][d]))
