# SPDX-License-Identifier: MIT
"""Independent pnon state, buffer identity and reply reconstruction."""
from audit_memory import ManagedFrames, released_extent
import struct

NAME=0x706e6f6e010000fd
OOL=0x05050707010100fd
QUERY=32<<32|0x201
REPLY=36<<32|0x201
REFUSED=32<<32|0x201
PAYLOAD=struct.pack('<8IB3x',0x42507268,0,0,0,0,0,0,0,2)
# Any other well-formed BootPolicy command gets this 32-byte header: status
# 0xff, which libbootpolicy returns as "not supported" (255).
NOT_SUPPORTED=struct.pack('<8I',0x42507268,0xff,0,0,0,0,0,0)
KIND=0x201
REQUEST_MIN=32
REQUEST_MAX=0x1c000   # the whole 112 KiB send buffer


def command_word(word):
    """Any BootPolicy command: kind 0x201, DATA = request length (header + body)."""
    return word&0xffffffff==KIND and REQUEST_MIN<=word>>32<=REQUEST_MAX


# 26A428 libbootpolicy command numbers (callers of __sep_command and
# __sep_command_with_fixed_output, named from the library's own symbols).
# Request length includes the 32-byte header; None means built at run time.
COMMANDS={0x3e:'current OS type',0x0b:'proposed local policy nonce digest',
          0x0c:'proposed remote policy nonce digest',0x0d:'proposed recoveryOS policy nonce digest',
          0x0e:'blessed local policy nonce digest',0x0f:'blessed remote policy nonce digest',
          0x10:'blessed recoveryOS policy nonce digest',0x11:'security mode',
          0x3f:'OS type restrictions override status',0x43:'local policy pairing status',
          0x13:'update local policy for new local nonce',0x15:'set debug flags',
          0x16:'local policy nonce start',0x17:'update local policy UAKL',
          0x18:'verify local policy UAKL',0x19:'local policy nonce stop',
          0x1a:'update local policy boolean tag',0x1b:'update local policy for new nonces',
          0x1d:'store OIC',0x1f:'update SIP flags',0x25:'consume kcOS auth token',
          0x26:'get OIC',0x2d:'linked manifest tag list',0x30:'MDM update DEP mode',
          0x31:'MDM update kexts mode',0x32:'create kcOS auth token',
          0x35:'delete linked manifest',0x36:'booted local policy',0x39:'MDM update user-enrolled mode',
          0x3a:'MDM is managed',0x3b:'local policy boolean tag',0x3c:'local policy integer tag / SIP flags',
          0x3d:'local policy digest tag',0x40:'prepare for hibernation',0x42:'revert local policy to defaults',
          0x44:'verify local policy pairing',0x45:'post software update fixups',0x47:'MDM is DEP managed',
          0x4c:'local policy UUID tag',0x4d:'finalize SIDP measurements',0x4e:'create local policy',
          0x4f:'update local policy for software update',0x51:'create system recoveryOS SIDP measurements',
          0x52:'create paired recoveryOS local policy',0x53:'update paired recoveryOS policy for software update',
          0x54:'MDM reduce security mode',0x55:'create local policy with splat',
          0x56:'update local policy for splat update',0x58:'MDM reduce security mode with splat',
          0x59:'create linked manifest',0x5a:'get linked manifest',0x5b:'unified finalize',
          0x5c:'update local policy for kcOS',0x5d:'update local policy for custom OS'}


def number(v):return int(v,0) if isinstance(v,str) else v


def audit_history(asc):
    refusal=bool(asc.get('pnon_refusal'))
    assert not (refusal and asc.get('pnon_recovery')),'conflicting pnon modes'
    expected=int(bool(asc.get('pnon_recovery') or refusal) and number(asc['rom_stage'])==3)
    p=asc.get('pnon')
    if p is None:
        assert not expected,'missing selected pnon state'
        return 0,0
    assert p['ready']==expected and p['advertisements']==2*expected,'pnon initialization'
    controls=p['negotiations'];queries=p['queries']
    assert 0<=controls<1<<64 and 0<=queries<1<<64,'pnon counters'
    assert expected or controls==queries==0,'premature pnon traffic'
    seen=[]
    for d,size in enumerate((0x1c000,0x14000)):
        stage=p['stage'][d];va=number(p['iova'][d]);actual=p['size'][d]
        assert stage in range(3) and (expected or not stage),'pnon stage'
        assert actual==(size if stage else 0),'pnon byte length'
        assert (0<va<va+size<=1<<44 and not va&0x3fff) if stage==2 else va==0,'pnon IOVA'
        assert len(p['physical'][d])==7,'pnon physical array'
        for n,raw in enumerate(p['physical'][d]):
            pa=number(raw)
            if stage!=2 or n>=size//0x4000:assert pa==0,'unused pnon physical identity'
            else:
                assert pa and not pa&0x3fff and pa not in seen,'pnon physical alias/alignment'
                seen.append(pa)
    assert controls>=sum(p['stage']),'pnon negotiation count'
    assert not queries or p['stage']==[2,2],'query before buffers'
    if p['stage']==[2,2]:
        a,b=map(number,p['iova']);sa,sb=p['size']
        assert a+sa<=b or b+sb<=a,'overlapping pnon IOVAs'
    request=number(p['last_request']);reply=number(p['last_reply'])
    if not controls and not queries:assert request==reply==0,'empty pnon history'
    elif command_word(request):
        assert queries and (reply==REFUSED or (not refusal and request==QUERY and reply==REPLY)),'pnon query history'
    else:
        op=request>>16&255;d=op&1
        assert controls and request&0xff0000ff==0x1000000 and request&0xff00 and 2<=op<=5,'pnon control history'
        assert reply==request&~0xff000000,'pnon control acknowledgement status'
        if op>=4:assert p['stage'][d]>=1 and request>>32==p['size'][d],'pnon length acknowledgement'
        else:assert p['stage'][d]==2 and request>>32<<12==number(p['iova'][d]),'pnon address acknowledgement'
    return controls+queries,p['advertisements']


def queued_reply(asc,lo,hi):
    p=asc.get('pnon')
    if not p or not p['ready']:return False
    word=number(lo)
    if number(hi):return False
    if word in (NAME,OOL):return True
    if word in (REPLY,REFUSED):return bool(p['queries']) and (word==REFUSED or not asc.get('pnon_refusal'))
    op=word>>16&255;d=op&1
    if word&0xff0000ff or not word&0xff00 or not 2<=op<=5 or not p['negotiations']:return False
    return (p['stage'][d]>=1 and word>>32==p['size'][d]) if op>=4 else (
        p['stage'][d]==2 and word>>32<<12==number(p['iova'][d]))


def audit_buffers(asc,leaves,geometry,read):
    audit_history(asc);p=asc.get('pnon')
    if not p or not p['ready']:return None
    managed=ManagedFrames(**{k:geometry[k] for k in ('frame_map','frame_low','frame_high',
        'alloc_low','alloc_high','boot_ranges','boot_aliases')},released=released_extent(geometry))
    selected=[l for l in leaves if l['device_id']==20 and l['sid']==0]
    entries={number(l['iova']):l for l in selected}
    assert len(entries)==len(selected),'duplicate pnon DART leaf'
    shared=number(asc['rom_shared_iova'])
    seen=[number(entries[shared+off]['pa']) for off in range(0,0x14000,0x4000)]
    assert len(set(seen))==5,'shared alias before OOL audit'
    bindings=[]
    for d in range(2):
        if p['stage'][d]!=2:continue
        va=number(p['iova'][d]);size=p['size'][d]
        assert va+size<=shared or shared+0x14000<=va,'OOL/shared IOVA overlap'
        for n in range(size//0x4000):
            leaf=entries.get(va+n*0x4000)
            assert leaf and not leaf['readonly'] and not leaf['no_read'],'OOL DMA permission/mapping'
            assert leaf['begin']==0 and leaf['end']==0x4000,'partial OOL page'
            pa=number(leaf['pa'])
            assert pa==number(p['physical'][d][n]) and managed.contains(pa),'OOL physical identity/ownership'
            assert pa not in seen,'OOL/shared physical alias'
            seen.append(pa)
        bindings.append(dict(direction=('send','receive')[d],iova=hex(va),size=size,pages=size//0x4000))
    last=None
    if p['queries']:
        request=read(number(p['physical'][0][0]),32)
        magic,command=struct.unpack_from('<2I',request)
        assert magic==0x42506368 and request[8:]==bytes(24),'last BootPolicy request shape'
        length=number(p['last_request'])>>32
        if number(p['last_reply'])==REPLY:
            assert not asc.get('pnon_refusal') and command==0x3e and length==32,'OS-type reply for another command'
            assert read(number(p['physical'][1][0]),36)==PAYLOAD,'last ordinary-recovery response bytes'
        else:
            # Command 0x3e is only answered with the OS type as a bare header;
            # with a body it is refused like every other command.
            assert 0<command<=0xff and (asc.get('pnon_refusal') or command!=0x3e or length>32),'not-supported reply for OS type'
            assert read(number(p['physical'][1][0]),32)==NOT_SUPPORTED,'last not-supported response bytes'
        ok=number(p['last_reply'])==REPLY
        last=dict(command=hex(command),request_length=length,status=0 if ok else 0xff,
                  name=COMMANDS.get(command,'unnamed'))
    refusal=bool(asc.get('pnon_refusal'))
    return dict(endpoint=1,name='pnon',os_type=None if refusal else 2,
        os_type_name=None if refusal else 'ordinary recoveryOS',refusal_only=refusal,
        bindings=bindings,queries=p['queries'],response_payload_verified=bool(p['queries']),
        last_query=last,persistent_policy=False,firmware_execution=False)
