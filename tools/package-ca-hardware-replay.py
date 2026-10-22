#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package qualified real CoreAnimation commands and allocations for q1n1 replay.

No device access. Failure inventory: docs/ADRENO-CA-TEXTURES-20260928.md.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
QTOOLS = ROOT.parent / 'q1n1/tools'
sys.path.insert(0, str(QTOOLS))
import adreno_x2 as R
import a16gpu_render as RD
import a16gpu_replay as REPLAY

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
align = lambda n, a: (n+a-1) & -a
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--capture', type=Path, required=True)
ap.add_argument('--qualification', type=Path, required=True)
ap.add_argument('--reference', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
capture = args.capture.resolve()
qualification = args.qualification.resolve()
reference = args.reference.resolve()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
record = dict(status='RUNNING', a16_access=False, gpu_execution=False, source_sha256=sha(__file__),
              capture_sha256=sha(capture), qualification_sha256=sha(qualification), reference_sha256=sha(reference),
              qualification_path=str(qualification))
try:
    c, q, ref = (json.loads(p.read_text()) for p in [capture,qualification,reference])
    assert q['status'] == 'NATIVE_CA_TEXTURE_KERNEL_REPLAY_PASSED' and q['capture_sha256'] == sha(capture)
    assert not q['a16_access'] and not q['gpu_execution']
    assert c['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED' and len(c['commits']) == 1
    assert ref['status'] == 'HOST_CA_RENDER_COMPLETED' and (ref['width'],ref['height'],ref['scene']) == (c['width'],c['height'],c['scene'])
    golden_path = ROOT / ref['pixels']['path']
    assert sha(golden_path) == ref['pixels']['sha256']
    golden = golden_path.read_bytes()
    assert len(golden) == c['width']*c['height']*4
    for name, digest in q['production_inputs'].items(): assert sha(ROOT/name) == digest, name
    commit = c['commits'][0]
    command_path = ROOT / commit['path']
    assert sha(command_path) == commit['sha256']
    command = command_path.read_bytes()
    kind,size,version,flags,nwords,ndata,nrel,reserved,r0,r1 = struct.unpack_from('<8I2Q',command)
    assert (kind,version,flags,reserved,r0,r1) == (0x1002,1,0,0,0,0)
    package_size = align(nwords*4,64)+ndata
    reloc_start = 48+package_size
    assert size == reloc_start+nrel*32 and command[size:] == struct.pack('<II',0x1000,8)
    package = bytearray(command[48:reloc_start])
    package_va, zero_va = RD.region_va('r_data'), RD.region_va('r_misc')
    assert package_size <= R.ARENA_LAYOUT['r_data'][1]
    spec = dict(format='snapintosh-adreno-replay-v1', source=str(capture), ib={'file':'ib.bin'},
                uploads=[], references=[], readback=[])
    allocations, inputs, used = {}, {}, dict(r_code=0x4000,r_rt=0x4000)
    for row in sorted(commit['published_resources'], key=lambda x:x['id']):
        rid = row['id']
        assert rid not in allocations and row['size'] > 0 and row['usage'] in (1,2,3)
        bound = q['resource_snapshots'][str(rid)]
        source = Path(row['path'])
        assert sha(source) == row['sha256'] == bound['sha256']
        blob = source.read_bytes()
        assert len(blob) == row['size'] == bound['bytes']
        region = 'r_rt' if row['usage'] & 2 else 'r_code'
        offset = align(used[region],0x4000)
        assert offset+len(blob)+64 <= R.ARENA_LAYOUT[region][1], 'Captured resources exceed '+region
        va = RD.region_va(region,offset)
        used[region] = offset+len(blob)+128
        allocations[rid] = dict(va=va,bytes=len(blob),usage=row['usage'],region=region)
        inputs[rid] = row['sha256']
        filename = 'resource-%d.bin' % rid
        if row['usage'] & 2:
            # Check both edges on readback; these guards are outside the relocated allocation.
            guarded = bytes([0xa5])*64 + blob + bytes([0x5a])*64
            (out/filename).write_bytes(guarded)
            spec['readback'].append(dict(va=va-64,size=len(guarded),seed_file=filename,what='resource-%d-with-guards' % rid))
        else:
            (out/filename).write_bytes(blob)
            spec['uploads'].append(dict(va=va,file=filename,what='resource-%d' % rid))
        spec['references'].append(dict(va=va,size=len(blob),write=bool(row['usage']&2),what='resource-%d' % rid))
    spec['references'] += [dict(va=zero_va,size=4096,write=False,what='zero-page'),
                           dict(va=package_va,size=package_size,write=False,what='package')]
    touched = set()
    for i in range(nrel):
        lo,hi,kind,access,alog,hbits,rid,offset,length = struct.unpack_from('<IIBBBBIQQ',command,reloc_start+32*i)
        assert kind in (1,2,3) and access in (1,2,3) and 0 <= alog <= 16 and length > 0
        if kind == 1:
            allocation = allocations[rid]
            assert access & allocation['usage'] == access
            assert offset+length <= allocation['bytes']
            base = allocation['va']
        else:
            assert rid == 0 and access == 1
            assert offset+length <= (package_size if kind == 2 else 4096)
            if kind == 2: assert offset >= align(nwords*4,64)
            base = package_va if kind == 2 else zero_va
        address = base+offset
        assert address % (1<<alog) == 0
        assert 0 <= lo <= package_size-4 and lo%4 == 0 and lo not in touched
        touched.add(lo)
        original = struct.unpack_from('<I',package,lo)[0]
        assert original >> alog == 0
        struct.pack_into('<I',package,lo,original | (address & 0xffffffff))
        if hi != 0xffffffff:
            assert 0 < hbits <= 32 and address >> (32+hbits) == 0
            assert 0 <= hi <= package_size-4 and hi%4 == 0 and hi not in touched
            touched.add(hi)
            original = struct.unpack_from('<I',package,hi)[0]
            assert not original & ((1<<hbits)-1)
            struct.pack_into('<I',package,hi,original | (address >> 32))
        else:
            assert hbits == 0 and address < 1<<32
    (out/'package.bin').write_bytes(package)
    (out/'ib.bin').write_bytes(package[:nwords*4])
    (out/'zero.bin').write_bytes(bytes(4096))
    (out/'expected.bgra').write_bytes(golden)
    spec['uploads'] += [dict(va=package_va,file='package.bin',what='relocated-package'),
                        dict(va=zero_va,file='zero.bin',what='zero-page')]
    target = allocations[c['target_resource_id']]
    assert target['usage'] & 2 and target['bytes'] >= len(golden)
    (out/'bundle.json').write_text(json.dumps(spec,indent=2)+'\n')
    plan = REPLAY.load_bundle(out)
    record.update(status='CA_HARDWARE_REPLAY_BUNDLE_PLANNED', allocations=allocations, input_sha256=inputs,
                  target_resource_id=c['target_resource_id'], width=c['width'],height=c['height'],pitch=c['width']*4,
                  expected_sha256=sha(out/'expected.bgra'), relocations=nrel, ib_dwords=plan['ib_dwords'],
                  window_address_words=plan['ib_window_addresses'], region_bytes=used,
                  artifact_sha256={p.name:sha(p) for p in out.iterdir() if p.is_file()},
                  q1n1_sha256={str(QTOOLS/n):sha(QTOOLS/n) for n in ['a16gpu_replay.py','a16gpu_render.py','adreno_x2.py']})
except BaseException as error:
    record.update(status='FAIL',exception=repr(error))
    raise
finally:
    (out/'preparation.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],output=str(out),a16_access=False)))
