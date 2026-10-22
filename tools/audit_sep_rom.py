# SPDX-License-Identifier: MIT
"""Independent reconstruction of the virtual SEP ROM history and DMA handoffs."""
from audit_memory import ManagedFrames, released_extent
import struct
from audit_sep_pnon import audit_history as audit_pnon_history, queued_reply as pnon_queued_reply
from audit_sep_xars import audit_history as audit_xars_history, queued_reply as xars_queued_reply
from audit_sep_sks import audit_history as audit_sks_history, queued_reply as sks_queued_reply


def number(v):
    return int(v, 0) if isinstance(v, str) else v


def audit_history(asc):
    fields = ('rom_status_replies', 'rom_last_request', 'rom_last_reply',
              'rom_stage', 'rom_firmware_iova', 'rom_firmware_size',
              'rom_shared_iova', 'rom_shared_size')
    n, request, reply, stage, fw, fs, sh, ss = [number(asc[k]) for k in fields]
    ready=asc.get('service_ready',0);notifications=asc.get('service_notifications',0)
    resources=asc.get('service_resources',[0]*8)
    expected=int(bool(asc.get('service_bootstrap')) and stage==3)
    service,advertisements=audit_pnon_history(asc)
    xars_service,xars_advertisements=audit_xars_history(asc)
    service+=xars_service;advertisements+=xars_advertisements
    sks_service,sks_advertisements=audit_sks_history(asc)
    service+=sks_service;advertisements+=sks_advertisements
    status_queries=asc.get('status_queries',0)
    status_last=number(asc.get('status_last_request',0))
    assert 0<=status_queries<1<<64,'effective-status counter'
    if status_queries:
        assert expected and (asc.get('pnon_recovery') or asc.get('pnon_refusal') or asc.get('xars_refusal')),'effective status before selected initialization'
        assert asc.get('virtual_effective_status')==0,'virtual effective-status policy'
        assert status_last&~0xff00==0x140000 and status_last&0xff00,'effective-status history'
    else:assert status_last==0,'empty effective-status history'
    service+=status_queries
    entropy=asc.get('entropy_words',0);entropy_last=number(asc.get('entropy_last_request',0))
    assert 0<=entropy<1<<64 and (expected or not entropy), 'entropy before readiness'
    assert ((entropy_last&~0xff00==0x360000 and entropy_last&0xff00) if entropy
            else entropy_last==0), 'entropy request history'
    assert ready==notifications==expected, 'service initialization accounting'
    assert resources==([0x4000,0x8000,0xc000,0x10000,0,0,0,0] if expected else [0]*8), 'service resources'
    if expected:assert ss==0x14000, 'service shared span'
    if not asc['rom_status_producer']:
        assert not any(number(asc[k]) for k in fields), 'inactive ROM state'
        return
    assert stage in range(4), 'ROM stage'
    assert n >= (0, 1, 2, 2)[stage], 'ROM status history'
    assert asc['consumed'] == n + stage + entropy + service < 1<<64, 'ROM/service request accounting'
    assert asc['published'] == n + min(stage, 2) + notifications + entropy + service + advertisements < 1<<64, 'ROM/service reply accounting'
    for address, size, active, limit in ((fw, fs, stage >= 2, 0x1000000),
                                       (sh, ss, stage == 3, 0x100000)):
        if not active:
            assert address == size == 0, 'premature ROM buffer'
        else:
            assert 0 < address < address + size < 1 << 64, 'ROM buffer extent'
            assert 0 < size <= limit and not (address | size) & 0x3fff, 'ROM buffer alignment'
    if stage == 3:
        assert sh + ss <= fw or fw + fs <= sh, 'overlapping ROM buffers'
    tag = request & 0xff00
    if not asc['consumed']:
        assert request == reply == 0, 'empty ROM history'
    elif stage <= 1 and request & ~0xff00 == 0x200ff:
        assert reply == ((stage + 1) << 32) | 0x6600ff | tag, 'ROM status reply'
    elif stage == 1 and request & ~0xff00 == 0x500ff:
        assert reply == 0x6900ff | tag, 'ROM TZ0 reply'
    elif stage == 2 and request & 0xffff00ff == 0x200600ff:
        assert request >> 32 << 12 == fw and reply == 0x6a00ff | tag, 'ROM firmware reply'
    elif stage == 3 and request & 255 == 254:
        assert request >> 32 << 12 == sh, 'ROM shared address'
        assert (request >> 16 & 65535) << 12 == ss and reply == 0, 'ROM shared size/reply'
    else:
        raise AssertionError('ROM history does not match stage')
    allowed = ({0x1006600ff}, {0x6900ff, 0x2006600ff}, {0x6a00ff},
               {0x6a00ff,0xd0000} if expected else {0x6a00ff})[stage]
    entropy_pending=status_pending=0
    for lo, hi in asc['replies']:
        if pnon_queued_reply(asc,lo,hi) or xars_queued_reply(asc,lo,hi) or sks_queued_reply(asc,lo,hi):continue
        if status_queries and number(lo)&~0xff00==0x140000 and number(lo)&0xff00:
            assert not number(hi),'effective-status high word'
            status_pending+=1
            continue
        if expected and number(lo)&0xffff00ff==0x360000 and number(lo)&0xff00:
            assert not number(hi), 'entropy high word'
            entropy_pending+=1
            continue
        assert not number(hi) and number(lo) & ~0xff00 in allowed, 'ROM queued reply'
        if number(lo)&~0xff00==0xd0000:assert number(lo)==0xd0000, 'tagged startup notification'
    assert entropy_pending<=entropy, 'unaccounted entropy replies'
    assert status_pending<=status_queries,'unaccounted effective-status replies'


def audit_buffers(asc, leaves, geometry):
    """Check complete accepted extents against an independent table walk."""
    audit_history(asc)
    stage = number(asc['rom_stage'])
    if stage < 2:
        return []
    managed = ManagedFrames(**{k: geometry[k] for k in
        ('frame_map', 'frame_low', 'frame_high', 'alloc_low', 'alloc_high',
         'boot_ranges', 'boot_aliases')}, released=released_extent(geometry))
    entries = {}
    for leaf in leaves:
        if leaf['device_id'] == 20 and leaf['sid'] == 0:
            key = number(leaf['iova'])
            assert key not in entries, 'duplicate SEP stream mapping'
            entries[key] = leaf
    firmware_pa, firmware_size = geometry['sep_firmware']
    assert number(asc['rom_firmware_size']) == firmware_size, 'firmware length identity'
    out = []
    for kind in ('firmware', 'shared')[:stage-1]:
        base = number(asc['rom_' + kind + '_iova'])
        size = number(asc['rom_' + kind + '_size'])
        present=sum(base+off in entries for off in range(0,size,0x4000))
        # The native firmware object releases its IOVA allocation after ROM
        # startup. Later OOL allocations may legitimately reuse that range.
        # Call it released only when no current SEP leaf references any of the
        # reserved firmware frames; reused leaves must be managed data.
        firmware_live=any(firmware_pa<=number(l['pa'])<firmware_pa+firmware_size
                          for l in entries.values())
        if kind=='firmware' and not firmware_live and asc.get('service_ready'):
            assert all(managed.contains(number(entries[base+off]['pa']))
                       for off in range(0,size,0x4000) if base+off in entries), 'firmware IOVA reused by unowned frame'
            out.append(dict(kind=kind,iova=hex(base),size=size,pages=0,
                            admitted_pages=size//0x4000,mapping_state='released',
                            reused_iova_pages=present,
                            acceptance_reconstructed=False,firmware_execution=False))
            continue
        pages = []
        for off in range(0, size, 0x4000):
            leaf = entries.get(base + off)
            assert leaf is not None, f'missing {kind} buffer page at {base+off:x}'
            assert not leaf['no_read'] and leaf['begin'] == 0 and leaf['end'] == 0x4000, 'ROM read extent'
            pa = number(leaf['pa'])
            if kind == 'firmware':
                assert pa == firmware_pa + off, 'firmware physical identity'
            else:
                assert not leaf['readonly'] and managed.contains(pa), 'shared writable ownership'
                assert pa not in pages, 'aliased shared pages'
            pages.append(pa)
        writable = all(not entries[base+off]['readonly'] for off in range(0,size,0x4000))
        out.append(dict(kind=kind, iova=hex(base), size=size, pages=len(pages),
                        mapping_state='present',
                        readable=True, writable=writable, write_required=kind == 'shared',
                        firmware_execution=False))
    return out


def audit_bootstrap(asc,leaves,read):
    if not asc.get('service_ready'):return None
    base=number(asc['rom_shared_iova']);size=number(asc['rom_shared_size'])
    entries={number(l['iova']):l for l in leaves if l['device_id']==20 and l['sid']==0}
    def data(offset,length):
        assert 0<=offset<size and length<=size-offset and (offset&0x3fff)+length<=0x4000
        leaf=entries[(base+offset)&~0x3fff]
        return read(number(leaf['pa'])+(offset&0x3fff),length)
    directory=data(0,64);records={}
    assert struct.unpack_from('<4I',directory,48)==(0x6e756c6c,0,0,0)
    for off in (0,16,32):
        name,length,start,reserved=struct.unpack_from('<4I',directory,off)
        assert name not in records and reserved==0
        records[name]=(start,length)
    assert records=={0x504e4943:(0x4000,0x8000),0x464c4147:(0xc000,0x4000),
                     0x53434f54:(0x10000,0x4000)}, 'service directory differs'
    assert data(0x4000,4)==struct.pack('<I',1)
    assert struct.unpack('<9I',data(0xc000,36))==(32,0x78415254,0,0x5345504f,0,0x66697073,0,0x53455044,0)
    assert data(0x10000,36)==struct.pack('<I',32)+b'This is my wonderful test data!\0'
    return dict(initialized=True,notification='0xd0000',notifications=asc['service_notifications'],
                resources=['PNIC','FLAG','SCOT'],guest_memory_written=False,firmware_execution=False)
