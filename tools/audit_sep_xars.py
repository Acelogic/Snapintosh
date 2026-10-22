# SPDX-License-Identifier: MIT
"""Independent xars refusal/empty-slot history and cross-endpoint DMA audit."""
from audit_memory import ManagedFrames, released_extent

NAME=0x78617273020000fd
OOL=0x02020202020100fd


def number(v):return int(v,0) if isinstance(v,str) else v


def is_query(word):
    return word&~0xffff00==2 and bool(word&0xff00) and word>>16&255 in (10,11,32)


def is_slot_query(word):
    """get_ap_slot_info for native slots 0/1: opcode0x18, slot in byte6."""
    return word&~0x0100000000ff00==0x180002 and bool(word&0xff00)


def slot_reply(word):
    """Status0, 56-byte length, empty-slot state0; tag and endpoint echoed."""
    return (word&0xffff)|56<<24


def is_epochs_query(word):
    """AppleSEPXART::getFullEpochs: opcode0x17 and nothing else."""
    return word&~0xff00==0x170002 and bool(word&0xff00)


def epochs_reply(word):
    """Status0, 32-byte length (EPOCH_COUNT 8 x 4, eight empty slots)."""
    return (word&0xffff)|32<<24


def audit_history(asc):
    selected=int(bool(asc.get('xars_refusal')) and number(asc['rom_stage'])==3)
    state=asc.get('xars')
    if state is None:
        assert not selected,'missing selected xars state'
        return 0,0
    assert state['ready']==selected and state['advertisements']==2*selected,'xars readiness'
    controls,queries=state['negotiations'],state['queries']
    assert 0<=controls<1<<64 and 0<=queries<1<<64,'xars counters'
    assert selected or controls==queries==0,'premature xars traffic'
    seen=[]
    for d in range(2):
        stage=state['stage'][d];va=number(state['iova'][d])
        assert stage in range(3) and (selected or not stage),'xars stage'
        assert state['size'][d]==(0x8000 if stage else 0),'xars extent'
        assert (0<va<va+0x8000<=1<<44 and not va&0x3fff) if stage==2 else va==0,'xars IOVA'
        assert len(state['physical'][d])==2,'xars physical array'
        for raw in state['physical'][d]:
            pa=number(raw)
            if stage!=2:assert pa==0,'unbound xars page'
            else:
                assert pa and not pa&0x3fff and pa not in seen,'xars physical alias/alignment'
                seen.append(pa)
    assert controls>=sum(state['stage']),'xars negotiation count'
    assert not queries or state['stage']==[2,2],'xars query before buffers'
    if state['stage']==[2,2]:
        a,b=map(number,state['iova'])
        assert a+0x8000<=b or b+0x8000<=a,'xars IOVA overlap'
    req,reply=map(number,(state['last_request'],state['last_reply']))
    if not controls and not queries:assert req==reply==0,'empty xars history'
    elif is_query(req):
        assert queries and reply==(req&0xffff)|0x10000,'xars non-success reply'
    elif is_slot_query(req):
        assert queries and reply==slot_reply(req),'xars empty-slot reply'
    elif is_epochs_query(req):
        assert queries and reply==epochs_reply(req),'xars empty-epochs reply'
    else:
        op=req>>16&255;d=op&1
        assert controls and req&0xff0000ff==0x2000000 and req&0xff00 and 2<=op<=5,'xars control history'
        assert reply==req&~0xff000000,'xars control status'
        if op>=4:assert state['stage'][d]>=1 and req>>32==0x8000,'xars length acknowledgement'
        else:assert state['stage'][d]==2 and req>>32<<12==number(state['iova'][d]),'xars binding acknowledgement'
    return controls+queries,state['advertisements']


def queued_reply(asc,lo,hi):
    state=asc.get('xars');word=number(lo)
    if not state or not state['ready'] or number(hi):return False
    if word in (NAME,OOL):return True
    if word&~0xff00==0x10002:return bool(word&0xff00) and bool(state['queries'])
    if word&~0xff00==0x38000002:return bool(word&0xff00) and bool(state['queries'])
    if word&~0xff00==0x20000002:return bool(word&0xff00) and bool(state['queries'])
    op=word>>16&255;d=op&1
    if word&0xff0000ff or not word&0xff00 or not 2<=op<=5 or not state['negotiations']:return False
    return (state['stage'][d]>=1 and word>>32==0x8000) if op>=4 else (
        state['stage'][d]==2 and word>>32<<12==number(state['iova'][d]))


def audit_buffers(asc,leaves,geometry):
    audit_history(asc);state=asc.get('xars')
    if not state or not state['ready']:return None
    managed=ManagedFrames(**{k:geometry[k] for k in ('frame_map','frame_low','frame_high',
        'alloc_low','alloc_high','boot_ranges','boot_aliases')},released=released_extent(geometry))
    selected=[leaf for leaf in leaves if leaf['device_id']==20 and leaf['sid']==0]
    entries={number(leaf['iova']):leaf for leaf in selected}
    assert len(entries)==len(selected),'duplicate SEP DART leaf'
    shared=number(asc['rom_shared_iova'])
    spans=[('bootstrap',shared,0x14000,None)]
    for name in ('pnon','xars','sks'):
        peer=asc.get(name)
        if peer is None:continue
        for d in range(2):
            if peer['stage'][d]==2:
                spans.append((name+('-send','-receive')[d],number(peer['iova'][d]),peer['size'][d],peer['physical'][d]))
    seen=[];bindings=[]
    for index,(name,va,size,expected) in enumerate(spans):
        assert all(va+size<=other_va or other_va+other_size<=va for _,other_va,other_size,_ in spans[:index]),'cross-endpoint IOVA alias'
        for n in range(size//0x4000):
            leaf=entries.get(va+n*0x4000)
            assert leaf and not leaf['readonly'] and not leaf['no_read'],'SEP DMA mapping/permission'
            assert leaf['begin']==0 and leaf['end']==0x4000,'partial SEP DMA page'
            pa=number(leaf['pa'])
            assert managed.contains(pa) and pa not in seen,'cross-endpoint physical alias/ownership'
            if expected:assert pa==number(expected[n]),'SEP retained page identity'
            seen.append(pa)
        bindings.append(dict(name=name,iova=hex(va),size=size,pages=size//0x4000))
    return dict(endpoint=2,name='xars',bindings=bindings,queries=state['queries'],
                non_success_status=1,empty_slot_bytes=56,empty_epoch_bytes=32,credential_producer=False,
                firmware_execution=False)
