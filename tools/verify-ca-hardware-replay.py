#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify actual GPU copies, allocation guards and every CoreAnimation image pixel.

Failure inventory and scene geometry: docs/ADRENO-CA-TEXTURES-20260928.md
and docs/ADRENO-BUFFER-TEXTURES-20260928.md for the gradient scene.
This is offscreen standalone Adreno execution, not WindowServer presentation.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import json
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--run',type=Path,required=True)
ap.add_argument('--output',type=Path,required=True)
ap.add_argument('--scene',choices=['image','gradient'],default='image')
args = ap.parse_args()
run_path = args.run.resolve()
out = args.output.resolve()
out.mkdir(parents=True,exist_ok=False)
record = dict(status='RUNNING',source_sha256=sha(__file__),run_sha256=sha(run_path),desktop_verified=False,scene=args.scene,
              boundary='Physical offscreen replay of real CoreAnimation-generated Adreno commands; no guest or presentation')
try:
    run = json.loads(run_path.read_text())
    assert run['status'] == 'HARDWARE_REPLAY_RETURNED_PIXELS_PENDING' and run['replay_exit'] == 0
    assert run['hardware_access'] and not run['guest_boot']
    bundle = Path(run['bundle'])
    assert sha(bundle/'preparation.json') == run['preparation_sha256']
    prepared = json.loads((bundle/'preparation.json').read_text())
    for name,digest in prepared['artifact_sha256'].items(): assert sha(bundle/name) == digest
    spec = json.loads((bundle/'bundle.json').read_text())
    replay_path = run_path.parent/'replay.json'
    assert sha(replay_path) == run['replay_sha256']
    replay = json.loads(replay_path.read_text())
    assert replay['mode'] == 'a16' and replay['stopped'] is None
    assert 'replay_read_back' in replay['order'] and len(replay['submissions']) == 1
    guard = replay['serror_guard']['after']
    assert not any(guard[k] for k in ['before','during','unconsumed'])
    record['replay_sha256'] = sha(replay_path)
    record['submission'] = replay['submissions'][0]
    outputs, guards = {}, []
    for rid,allocation in prepared['allocations'].items():
        if not allocation['usage']&2: continue
        seed = next(b for b in spec['readback'] if b['va'] == allocation['va']-64)
        result = next(b for b in replay['replay']['results'] if b['what'] == seed['what'])
        assert int(result['va'],16) == seed['va'] and result['bytes'] == seed['size']
        # Match the reported readback hash instead of depending on filenames or region constants.
        candidates = [Path(p) for p in replay['images'].values() if sha(p) == result['sha256']]
        assert candidates
        raw = candidates[0].read_bytes()
        assert len(raw) == allocation['bytes']+128
        before,after = raw[:64] == bytes([0xa5])*64, raw[-64:] == bytes([0x5a])*64
        assert before and after and result['changed_words_outside_writes'] == 0
        outputs[int(rid)] = raw[64:-64]
        guards.append(dict(resource=int(rid),before=before,after=after,readback_sha256=result['sha256']))
    record['guards'] = guards
    capture_path = Path(spec['source'])
    assert sha(capture_path) == prepared['capture_sha256']
    capture = json.loads(capture_path.read_text())
    qualification_path = Path(prepared.get('qualification_path',ROOT/'build/ca-texture-kernel-replay-20260928-v4/qualification.json'))
    assert sha(qualification_path) == prepared['qualification_sha256']
    qualification = json.loads(qualification_path.read_text())
    checks = []
    for cp in qualification['copies']:
        source = qualification['resource_snapshots'][str(cp['source_id'])]
        assert sha(source['path']) == source['sha256']
        data = Path(source['path']).read_bytes()
        expected = data[cp['source_offset']:cp['source_offset']+cp['bytes']]
        actual = outputs[cp['destination_id']][:cp['bytes']]
        assert len(expected) == cp['bytes'] and actual == expected
        checks.append(dict(destination=cp['destination_id'],source=cp['source_id'],source_offset=cp['source_offset'],
                           bytes=cp['bytes'],exact=True,sha256=hashlib.sha256(actual).hexdigest()))
    record['copies'] = checks
    target = prepared['target_resource_id']
    width,height = prepared['width'],prepared['height']
    assert (width,height,prepared['pitch']) == (256,160,1024)
    expected = (bundle/'expected.bgra').read_bytes()
    actual = outputs[target][:len(expected)]
    assert len(actual) == len(expected) == width*height*4
    mismatches = Counter()
    maximum = 0
    for y in range(height):
        for x in range(width):
            at = (y*width+x)*4
            a,e = actual[at:at+4],expected[at:at+4]
            region = ('image_child' if 48<=x<208 and 32<=y<128 else 'background') if args.scene == 'image' else 'frame'
            if a != e: mismatches[region] += 1
            maximum = max(maximum,max(abs(a[i]-e[i]) for i in range(4)))
    record['pixels'] = dict(width=width,height=height,total=width*height,
                           mismatches=dict(mismatches),max_channel_error=maximum,
                           actual_colors=dict(Counter(actual[i:i+4].hex() for i in range(0,len(actual),4))),
                           expected_colors=dict(Counter(expected[i:i+4].hex() for i in range(0,len(expected),4))))
    if args.scene == 'image':
        record['pixels'].update(image_child_total=160*96,background_total=width*height-160*96)
    else:
        record['pixels']['frame_total'] = width*height
    (out/'actual.bgra').write_bytes(actual)
    Image.frombytes('RGBA',(width,height),actual,'raw','BGRA').save(out/'actual.png')
    Image.frombytes('RGBA',(width,height),expected,'raw','BGRA').save(out/'expected.png')
    record['artifact_sha256'] = {p.name:sha(p) for p in out.iterdir() if p.is_file()}
    record['status'] = 'A16_CA_FRAME_EXACT' if not mismatches else 'A16_CA_FRAME_MISMATCH'
except BaseException as error:
    record.update(status='FAIL',exception=repr(error))
    raise
finally:
    (out/'verification.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],output=str(out/'verification.json'),pixels=record.get('pixels',{}).get('mismatches'))))
