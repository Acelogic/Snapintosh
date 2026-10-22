#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce Metal fill bytes through native packing and the driver/GPU model.

No host GPU is opened and no A16 connection is made. Native resource object
backing/destruction and kernel retain/prepare are fixtures; GPU execution is
the noncoherent RAM/SMMU/PM4 model. Full command-buffer submission is untested.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    baseline=args.baseline_build.resolve()
    sources={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__).resolve(),
        ROOT/'gpu/adreno-kext/plugin/harness/fill-encoding.m']}
    commands=[]
    def run(name,argv,env=None):
        commands.append(argv)
        with (out/(name+'.log')).open('x') as log:
            subprocess.run(argv,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)

    # This binds the native IOGPU/Metal image UUIDs and producer code, checks
    # native retention/packing, and builds the actual candidate Metal bundle.
    run('native-resource',['python3','tools/check-adreno-resource-encoding.py',
        '--output',str(out/'native-resource')])
    native=json.loads((out/'native-resource/qualification.json').read_text())
    sources.update(native['sources'])
    plugin=out/'native-resource/plugin/AdrenoMetal.bundle/Contents/MacOS/AdrenoMetal'
    binary=out/'fill-encoding'
    run('encoding-build',['xcrun','clang','-arch','arm64e','-mmacosx-version-min=27.0',
        '-fobjc-arc','-fobjc-arc-exceptions','-O1','-g','-Wall','-Werror',
        'gpu/adreno-kext/plugin/harness/fill-encoding.m',
        'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoFillCommands.m',
        'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoResourceUsage.m',
        'compat/adreno-fill-command.c','compat/adreno-resource-list.c',
        '-framework','Foundation','-framework','Metal',
        'gpu/adreno-kext/plugin/AdrenoMetal/IOGPU.tbd','-o',str(binary)])
    payload=out/'native-descriptors.bin';stream=out/'native-commands.bin'
    run('encoding',[str(binary),str(payload),str(stream)])
    encoded=json.loads((out/'encoding.log').read_text())
    assert encoded['status']=='ADRENO_FILL_ENCODING_PASS'
    assert payload.stat().st_size==96
    words=struct.unpack('<IIIIQQII',stream.read_bytes())
    assert words==(0x1001,32,7,0x3c3c3c3c,0x3f00,0x4000,0x1000,8)

    env=dict(os.environ,SNAP_METAL_FILL_DESCRIPTORS=str(payload),SNAP_METAL_FILL_COMMANDS=str(stream))
    run('integration',['python3','tools/qualify-adreno-fill-integration.py',
        '--baseline-build',str(baseline),'--output',str(out/'integration')],env)
    integration=json.loads((out/'integration/qualification.json').read_text())
    for name,digest in integration['sources_sha256'].items():
        assert name not in sources or sources[name]==digest,name
        sources[name]=digest
    assert any(s.startswith('NATIVE_METAL_FILL_MODEL_PASS:') for s in integration['replay'])
    sys.path.insert(0,str(ROOT.parent/'q1n1/tools'))
    from adreno_x2 import pkt7
    ring=(out/'integration/native-metal-submitted-ring.bin').read_bytes()
    words=struct.unpack('<'+'I'*(len(ring)//4),ring)
    assert len(words)==4103 and words[0]==pkt7(0x3d,4098)
    assert words[1:3]==(0x40003f00,0)
    assert all(w==0x3c3c3c3c for w in words[3:4099])
    assert words[4099]==pkt7(0x3d,3) and words[4100:4102]==(0x10200080,0)
    data=(out/'integration/native-metal-gpu-destination.bin').read_bytes()
    assert len(data)==0x10000
    for offset in range(0,len(data),4):
        changed=0x3f00<=offset<0x4000 or 0xc000<=offset<0xff00
        assert struct.unpack_from('<I',data,offset)[0]==(0x3c3c3c3c if changed else 0xa55aa55a),offset
    for name,digest in sources.items(): assert sha(ROOT/name)==digest,name
    # Recheck nested artifacts independently of their producers before binding.
    for directory,record,key in [('native-resource',native,'artifacts'),
                                  ('integration',integration,'artifacts_sha256')]:
        for name,digest in record[key].items(): assert sha(out/directory/name)==digest,name
    result=dict(status='METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED',
        sources_sha256=sources,commands=commands,plugin_sha256=sha(plugin),
        monitor_sha256=integration['monitor_sha256'],kext_sha256=integration['kext_sha256'],
        baseline_build=str(baseline),baseline_build_sha256=sha(baseline),
        packet_reference_sha256=sha(ROOT.parent/'q1n1/tools/adreno_x2.py'),
        encoding=encoded,replay=integration['replay'],
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
        boundary=__doc__+' The terminal fence callback is dispatch-only; the fill has modeled marker/RPTR completion. No AuxKC, guest image, A16 fill or presentation proof.')
    report=out/'qualification.json';report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],sources=len(sources),artifacts=len(result['artifacts_sha256']),
                         plugin_sha256=result['plugin_sha256'],report=str(report))))

if __name__=='__main__':main()
