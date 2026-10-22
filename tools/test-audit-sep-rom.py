#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise captured-state corruption and independent ROM DMA reconstruction."""
from copy import deepcopy
from audit_sep_rom import audit_history, audit_buffers, audit_bootstrap
from pathlib import Path

FW = 0x10000004000
SH = 0x10001000000
geometry = dict(frame_map=0x100000, frame_low=0x100000, frame_high=0x400000,
                alloc_low=0x300000, alloc_high=0x400000, boot_ranges=(),
                boot_aliases=(), sep_firmware=(0x200000, 0x8000))
state = dict(rom_status_producer=True, rom_status_replies=2, consumed=5,
             published=4, rom_stage=3, rom_last_request=((SH>>12)<<32)|0x801fe,
             rom_last_reply=0, rom_firmware_iova=FW, rom_firmware_size=0x8000,
             rom_shared_iova=SH, rom_shared_size=0x8000, replies=[])
leaves = [dict(iova=hex(iova), pa=hex(pa), device_id=20, sid=0,
               readonly=False, no_read=False, begin=0, end=0x4000)
          for iova, pa in ((FW, 0x200000), (FW+0x4000, 0x204000),
                           (SH, 0x300000), (SH+0x4000, 0x304000))]
checks = 0


def rejects(action):
    global checks
    try:
        action()
    except AssertionError:
        checks += 1
    else:
        raise AssertionError('corruption accepted')


assert [r['pages'] for r in audit_buffers(state, leaves, geometry)] == [2, 2]
checks += 1
result = audit_buffers(state, leaves, geometry)
assert result[0]['writable'] and not result[0]['write_required'] and result[1]['write_required']
checks += 1
readonly = deepcopy(leaves)
readonly[0]['readonly'] = readonly[1]['readonly'] = True
assert not audit_buffers(state, readonly, geometry)[0]['writable']
checks += 1
for field in ('rom_stage', 'rom_status_replies', 'consumed', 'published',
              'rom_last_request', 'rom_last_reply', 'rom_firmware_iova',
              'rom_firmware_size', 'rom_shared_iova', 'rom_shared_size'):
    bad = deepcopy(state); bad[field] += 1
    rejects(lambda: audit_buffers(bad, leaves, geometry))
bad = deepcopy(state); bad['rom_status_producer'] = False
rejects(lambda: audit_history(bad))
for index, field, value in ((3,'no_read',True), (3,'readonly',True),
                            (3,'begin',4), (3,'end',0x3ffc),
                            (3,'pa','0x300000'), (3,'pa','0x200000'),
                            (1,'pa','0x208000'), (3,'sid',1), (3,'device_id',21)):
    corrupt = deepcopy(leaves); corrupt[index][field] = value
    rejects(lambda: audit_buffers(state, corrupt, geometry))
rejects(lambda: audit_buffers(state, leaves[:-1], geometry))
rejects(lambda: audit_buffers(state, leaves + leaves[-1:], geometry))
for stage, n, request, reply in ((0,0,0,0), (0,1,0x201ff,0x1006601ff),
                               (1,1,0x501ff,0x6901ff), (1,2,0x201ff,0x2006601ff),
                               (2,2,((FW>>12)<<32)|0x200601ff,0x6a01ff)):
    sample = deepcopy(state)
    sample.update(rom_stage=stage, rom_status_replies=n, consumed=n+stage,
                  published=n+min(stage,2), rom_last_request=request, rom_last_reply=reply,
                  rom_shared_iova=0, rom_shared_size=0)
    if stage < 2:
        sample.update(rom_firmware_iova=0, rom_firmware_size=0)
    sample['replies'] = [[hex(reply), '0x0']] if reply else []
    audit_buffers(sample, leaves, geometry); checks += 1
    sample['replies'] = [['0xd201ff','0x0']]
    rejects(lambda: audit_history(sample))
service=deepcopy(state)
service.update(service_bootstrap=True,service_ready=1,service_notifications=1,
    service_resources=[0x4000,0x8000,0xc000,0x10000,0,0,0,0],published=5,
    rom_shared_size=0x14000,rom_last_request=((SH>>12)<<32)|0x1400fe,replies=[['0xd0000','0x0']])
service_leaves=deepcopy(leaves[:2])
for off in range(0,0x14000,0x4000):
    service_leaves.append(dict(iova=hex(SH+off),pa=hex(0x300000+off),device_id=20,sid=0,
                              readonly=False,no_read=False,begin=0,end=0x4000))
audit_buffers(service,service_leaves,geometry);checks+=1
assert audit_buffers(service,service_leaves[2:],geometry)[0]['mapping_state']=='released';checks+=1
rejects(lambda:audit_buffers(service,service_leaves[1:],geometry))
for reused in (1,2):
    mapped=deepcopy(service_leaves)
    for index in range(2):mapped[index]['pa']=hex(0x340000+index*0x4000)
    mapped=mapped[:reused]+mapped[2:]
    result=audit_buffers(service,mapped,geometry)[0]
    assert result['mapping_state']=='released' and result['reused_iova_pages']==reused;checks+=1
    bad=deepcopy(mapped);bad[0]['pa']='0x204000'
    rejects(lambda:audit_buffers(service,bad,geometry))
    bad=deepcopy(mapped);bad[0]['pa']='0x280000'
    rejects(lambda:audit_buffers(service,bad,geometry))
    bad=deepcopy(mapped);old=deepcopy(service_leaves[0]);old['iova']=hex(SH+0x200000);bad.append(old)
    rejects(lambda:audit_buffers(service,bad,geometry))
bad=deepcopy(service);bad['replies']=[['0xd0100','0x0']]
rejects(lambda:audit_history(bad))
captured=(Path(__file__).resolve().parents[1]/'build/sep-rom-slot-live-20260922-sep-shared.bin').read_bytes()
payload=bytearray(captured)
def read_shared(pa,n):
    assert 0x300000<=pa<pa+n<=0x314000
    return bytes(payload[pa-0x300000:pa-0x300000+n])
assert audit_bootstrap(service,service_leaves,read_shared)['initialized'];checks+=1
for key,value in [('service_ready',0),('service_notifications',2),('published',4),
                  ('service_resources',[0]*8)]:
    bad=deepcopy(service);bad[key]=value
    rejects(lambda:audit_history(bad))
for offset in (0,16,32,48,0x4000,0xc000,0xc008,0x10000,0x10008):
    payload=bytearray(captured);payload[offset]^=1
    rejects(lambda:audit_bootstrap(service,service_leaves,read_shared))
entropy=deepcopy(service)
entropy.update(entropy_words=1,entropy_last_request='0x360800',consumed=6,published=6,
               replies=[['0x1234567800360800','0x0']])
audit_history(entropy);checks+=1
for key,value in [('entropy_words',0),('entropy_words',2),('entropy_words',-1),
                  ('entropy_last_request',0),('entropy_last_request','0x360000'),
                  ('entropy_last_request','0x100360800'),('service_bootstrap',False),
                  ('replies',[['0x1234567801360800','0x0']]),
                  ('replies',[['0x1234567800360000','0x0']]),
                  ('replies',[['0x1234567800360800','0x1']]),
                  ('replies',[['0x360800','0x0'],['0x360900','0x0']])]:
    bad=deepcopy(entropy);bad[key]=value
    rejects(lambda:audit_history(bad))
entropy['replies']=[['0x360800','0x0']]
audit_history(entropy);checks+=1 # Explicitly redacted DATA is still auditable.
print(f'PASS: {checks} independent ROM and virtual-service audit checks')
