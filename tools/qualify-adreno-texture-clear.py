#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare production Metal clear packets/driver replay with real Apple GPU images.

Native resource packing is executed on this Mac. Texture backing/destruction,
kernel retain/prepare and GPU/SMMU memory are fixtures in the Adreno replay.
No A16 connection is opened, and no screen presentation is claimed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
MODEL=['tools/replay-adreno-texture-clear.c','compat/adreno-fill-command.c',
    'compat/adreno-fill.c','compat/adreno-submit.c','compat/adreno-resource.c',
    'compat/adreno-resource-list.c','compat/adreno.c','compat/irq-forward.c',
    'shadow/stage2.c','shadow/shadow.c','shadow/mmu.c']

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    reference=args.reference.resolve()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(ROOT)):sha(p) for directory in
        ['compat','shadow','gpu/adreno-kext/plugin'] for p in (ROOT/directory).rglob('*')
        if p.is_file() and p.suffix in ['.c','.h','.m','.sh','.tbd','.plist'] and '/out/' not in str(p)}
    for n in MODEL+['tools/test-adreno.c','tools/test-adreno-fill.c','tools/test-adreno-fill-command.c',
                    'tools/qualify-adreno-texture-clear.py']:
        sources[n]=sha(ROOT/n)
    commands=[]
    def run(name,argv,env=None):
        commands.append(argv)
        with (out/(name+'.log')).open('x') as log:
            subprocess.run(argv,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    measured=json.loads((reference/'reference.json').read_text())
    assert measured['status']=='APPLE_GPU_CLEAR_REFERENCE_COMPLETE' and 'Apple' in measured['device']
    assert len(measured['cases'])==20
    refs=out/'reference';refs.mkdir()
    shutil.copyfile(reference/'reference.json',refs/'reference.json')
    for row in measured['cases']:
        assert row['width']==37 and row['height']==23 and row['command_status']==4
        name=row['readback'];assert Path(name).name==name
        pixels=(reference/name).read_bytes()
        assert pixels==struct.pack('<I',row['pixel_word'])*(37*23)
        (refs/name).write_bytes(pixels)
    run('host-version',['sw_vers'])
    run('compiler',['xcrun','clang','--version'])
    base=['xcrun','clang','-arch','arm64e','-mmacosx-version-min=27.0',
          '-fobjc-arc','-fobjc-arc-exceptions','-O1','-g','-Wall','-Werror']
    producer=['gpu/adreno-kext/plugin/AdrenoMetal/AdrenoFillCommands.m',
              'gpu/adreno-kext/plugin/AdrenoMetal/AdrenoResourceUsage.m',
              'compat/adreno-fill-command.c','compat/adreno-resource-list.c',
              '-framework','Foundation','-framework','Metal',
              'gpu/adreno-kext/plugin/AdrenoMetal/IOGPU.tbd']
    run('encoding-build',base+['gpu/adreno-kext/plugin/harness/clear-encoding.m']+
        producer+['-o',str(out/'clear-encoding')])
    run('encoding',[str(out/'clear-encoding'),str(refs/'reference.json'),str(out/'encoding')])
    encoded=json.loads((out/'encoding/encoding.json').read_text())
    assert encoded['status']=='CLEAR_ENCODING_MATCHES_APPLE_GPU_REFERENCE' and len(encoded['cases'])==20
    run('buffer-regression-build',base+['gpu/adreno-kext/plugin/harness/fill-encoding.m']+
        producer+['-o',str(out/'fill-encoding')])
    run('buffer-regression',[str(out/'fill-encoding'),str(out/'buffer-descriptors.bin'),str(out/'buffer-commands.bin')])
    run('model-build',['clang','-std=gnu11','-Icompat','-Ishadow','-O1','-g',
        '-fsanitize=address,undefined','-Wall','-Wextra','-Werror',*MODEL,'-o',str(out/'clear-model')])
    for index,row in enumerate(encoded['cases']):
        directory=out/f'case-{index}';directory.mkdir()
        env=dict(os.environ,SNAP_FILL_ARTIFACT_DIR=str(directory))
        run(f'case-{index}',[str(out/'clear-model'),str(out/'encoding'/row['descriptors']),
            str(out/'encoding'/row['commands']),str(refs/row['readback'])],env)
        actual=(directory/'clear-gpu-destination.bin').read_bytes()
        expected=bytearray(struct.pack('<I',0xa55aa55a)*(0x10000//4))
        pixels=(refs/row['readback']).read_bytes()
        for y in range(23):
            logical=0x3f00+y*256
            physical=logical if logical<0x4000 else logical+0x8000
            expected[physical:physical+37*4]=pixels[y*37*4:(y+1)*37*4]
        assert actual==expected,index
    run('plugin-build',['/bin/sh','gpu/adreno-kext/plugin/build.sh'],dict(os.environ,OUT=str(out/'plugin')))
    plugin=out/'plugin/AdrenoMetal.bundle'
    run('plugin-signature',['codesign','--verify','--strict',str(plugin)])
    assert all(sha(ROOT/n)==h for n,h in sources.items())
    record=dict(status='METAL_TEXTURE_CLEAR_NATIVE_PACKING_GPU_MODEL_MATCHES_APPLE_REFERENCE',
        sources_sha256=sources,commands=commands,reference_source=str(reference),
        reference_device=measured['device'],cases=20,pixel_writes_per_case=851,
        gpu_fill_commands_per_case=23,cpu_destination_stores=0,checked_bytes_per_case=65536,
        plugin_sha256=sha(plugin/'Contents/MacOS/AdrenoMetal'),
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()},
        boundary=__doc__+' Public command-buffer submission, constructor-provided texture geometry, A16 IOSurface coherence and display presentation still require guest execution.')
    (out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ['status','cases','plugin_sha256']}))

if __name__=='__main__':main()
