#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check real CA pass extents against captured Adreno registers and relocations.

Failure inventory: docs/ADRENO-CA-COMPOSITE-20260928.md. Independently decode
the actual packets; distinguish logical scissor/clear bounds from memory pitch.
No hardware access or claim of completed physical pixels.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text())
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--capture', type=Path, required=True)
ap.add_argument('--kernel-replay', type=Path, required=True)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
capture, replay, output = [p.resolve() for p in (args.capture,args.kernel_replay,args.output)]
assert not output.exists()
c,q = read(capture),read(replay)
assert c['status'] == 'ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED'
assert q['status'] == 'NATIVE_CA_COPY_KERNEL_REPLAY_PASSED' and q['capture_sha256'] == sha(capture)
assert len(q['cases']) == 11 and not q['a16_access'] and not q['gpu_execution']
assert not c['a16_access'] and not c['adreno_submitted_to_gpu'] and len(c['commits']) == 1
for name,digest in q['production_inputs'].items(): assert sha(ROOT/name) == digest,name
for pair in c['programs']:
    for data in pair.values(): assert sha(data['path']) == data['sha256']
commit = c['commits'][0]
assert sha(commit['path']) == commit['sha256']
blob = Path(commit['path']).read_bytes()
kind,size,version,flags,nwords,ndata,nrel,reserved,r0,r1 = struct.unpack_from('<8I2Q',blob)
assert (kind,version,flags,reserved,r0,r1) == (0x1002,1,0,0,0,0)
reloc_at = 48+((4*nwords+63)&~63)+ndata
assert size == reloc_at+32*nrel and blob[size:] == struct.pack('<II',0x1000,8)
words = struct.unpack_from('<%dI'%nwords,blob,48)
relocs = [struct.unpack_from('<IIBBBBIQQ',blob,reloc_at+32*i) for i in range(nrel)]
by_lo = {x[0]:x for x in relocs}
assert len(by_lo) == nrel
sys.path.insert(0,str(ROOT.parent/'q1n1/tools'))
import a8xx_regs as X
import adreno_x2 as R
names = ['GRAS_SC_WINDOW_SCISSOR_BR','GRAS_A2D_SCISSOR_BR','RB_RESOLVE_CNTL_2',
         'RB_MRT_PITCH','RB_MRT_ARRAY_PITCH','RB_MRT_BASE','GRAS_A2D_DEST_TL','GRAS_A2D_DEST_BR']
offsets = {X.REGS[n][0]:n for n in names}
observed = {n:[] for n in names}
pos = 0
while pos < nwords:
    header = words[pos]; packet = header>>28
    assert packet in (4,7)
    count = header & (0x7f if packet == 4 else 0x3fff)
    assert pos+count+1 <= nwords
    pairs = []
    if packet == 4:
        start = (header>>8)&0x7ffff
        pairs = [(start+i,words[pos+1+i],pos+1+i) for i in range(count)]
    else:
        op = (header>>16)&0x7f
        if op in (R.CP_CONTEXT_REG_BUNCH,R.CP_NON_CONTEXT_REG_BUNCH):
            skip = 2 if op == R.CP_NON_CONTEXT_REG_BUNCH else 0
            if skip: assert words[pos+1:pos+3] == (1,0)
            assert count >= skip and (count-skip)%2 == 0
            pairs = [(words[pos+1+i],words[pos+2+i],pos+2+i) for i in range(skip,count,2)]
    for offset,value,at in pairs:
        if offset in offsets: observed[offsets[offset]].append((at,value))
    pos += count+1
passes = c['render_passes']
assert passes and any(p['pass_width'] and p['pass_width'] < p['width'] for p in passes)
extents = [(p['pass_width'] or p['width'],p['pass_height'] or p['height']) for p in passes]
for p,(w,h) in zip(passes,extents):
    assert p['known'] and p['format'] == 80 and 0 < w <= p['width'] <= 16384 and 0 < h <= p['height'] <= 16384
    assert p['pitch']%64 == 0 and p['pitch'] >= p['width']*4
    assert p['offset']+p['pitch']*p['height'] <= p['allocation_bytes']
br = [(h-1)<<16 | (w-1) for w,h in extents]
for name in names[:3]: assert [v for _,v in observed[name]] == br,name
assert [v for _,v in observed['RB_MRT_PITCH']] == [p['pitch']>>6 for p in passes]
assert [v for _,v in observed['RB_MRT_ARRAY_PITCH']] == [(p['pitch']*p['height'])>>6 for p in passes]
assert len(observed['RB_MRT_BASE']) == len(passes)
for p,(at,value) in zip(passes,observed['RB_MRT_BASE']):
    reloc = by_lo[at*4]
    assert not value and reloc[2:4] == (1,3) and reloc[6] == p['resource_id']
    assert reloc[7:] == (p['offset'],p['pitch']*p['height'])
clears = [xy for p,xy in zip(passes,extents) if p['load'] == 2]
assert [v for _,v in observed['GRAS_A2D_DEST_TL']] == [0]*len(clears)
assert [v for _,v in observed['GRAS_A2D_DEST_BR']] == [(h-1)<<16 | (w-1) for w,h in clears]
seeded = []
for row in commit['published_resources']:
    bound = q['resource_snapshots'][str(row['id'])]
    assert sha(row['path']) == row['sha256'] == bound['sha256']
    if row['snapshot_kind'] == 'undefined-private-replay-seed':
        assert Path(row['path']).read_bytes() == bytes([row['replay_seed']])*row['size']
        seeded.append(dict(id=row['id'],bytes=row['size'],seed=row['replay_seed']))
record = dict(status='NATIVE_CA_COMPOSITE_EXTENTS_VERIFIED',source_sha256=sha(__file__),
    capture=str(capture),capture_sha256=sha(capture),kernel_replay=str(replay),kernel_replay_sha256=sha(replay),
    scene=c['scene'],pass_extents=extents,clear_extents=clears,register_writes=observed,
    private_replay_seeds=seeded,reference_sha256={str(ROOT.parent/'q1n1/tools'/name):
        sha(ROOT.parent/'q1n1/tools'/name) for name in ['a8xx_regs.py','adreno_x2.py']},
    physical_rendering_verified=False,desktop_verified=False,a16_access=False)
output.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],scene=c['scene'],passes=len(passes),clears=len(clears),output=str(output))))
