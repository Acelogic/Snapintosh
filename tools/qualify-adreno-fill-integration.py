#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build candidate monitor/kext and replay resource-bound fills; no hardware I/O."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
SOURCES=['tools/test-adreno-fill-command.c','compat/adreno-fill-command.c',
    'compat/adreno-fill.c','compat/adreno-submit.c','compat/adreno-resource.c',
    'compat/adreno-resource-list.c','compat/adreno.c','compat/irq-forward.c',
    'shadow/stage2.c','shadow/shadow.c','shadow/mmu.c']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    baseline_path=args.baseline_build.resolve()
    baseline=json.loads(baseline_path.read_text())
    assert sha(baseline_path)=='6ba98be3c18e7e7d08a189ceb4dedd03441211c4e4ba38ae675f708815242971'
    assert baseline['monitor_sha256']=='190e1bbd063563bb080ce6368da6774fb0bd83b894580279870f2fcefdaf21f0'
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    commands=[]
    environment=dict(os.environ,SNAP_FILL_ARTIFACT_DIR=str(output),OUT=str(output/'kext'))
    inputs=set(SOURCES)|{str(Path(__file__).relative_to(ROOT))}
    for directory in ['compat','shadow','probes','gpu/adreno-kext/kext','gpu/adreno-kext/include']:
        inputs.update(str(p.relative_to(ROOT)) for p in (ROOT/directory).rglob('*')
                      if p.is_file() and p.suffix in ('.h','.c','.cpp','.S','.py','.sh','.plist'))
    inputs.add('tools/test-adreno.c');inputs.add('tools/test-adreno-fill.c')
    sources={n:sha(ROOT/n) for n in sorted(inputs)}

    def run(name,command):
        commands.append(command)
        result=subprocess.run(command,cwd=ROOT,env=environment,text=True,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (output/(name+'.log')).write_text(result.stdout)
        assert result.returncode==0,(name,result.returncode,str(output/(name+'.log')))
        return result.stdout

    run('compiler',['clang','--version'])
    binary=output/'fill-command-path'
    run('model-build',['clang','-std=gnu11','-Icompat','-Ishadow','-O1','-g',
        '-fsanitize=address,undefined','-Wall','-Wextra','-Werror',*SOURCES,'-o',str(binary)])
    replay=run('model-replay',[str(binary)])
    assert 'PASS: 1969 Adreno' in replay and 'FAIL' not in replay
    assert re.search(r'PASS: \d+ fill command path checks;',replay)
    assert re.search(r'PASS: \d+ fill transport checks;',replay)
    sys.path.insert(0,str(ROOT.parent/'q1n1/tools'))
    from adreno_x2 import pkt7
    for stem in ('model','command-model'):
        ring=(output/(stem+'-submitted-ring.bin')).read_bytes()
        words=struct.unpack('<'+'I'*(len(ring)//4),ring)
        assert len(words)==4096+7 and words[0]==pkt7(0x3d,4098)
        assert words[1:3]==(0x40003f00,0) and all(v==0xff00ff00 for v in words[3:4099])
        assert words[4099]==pkt7(0x3d,3) and words[4100:4102]==(0x10200080,0)
        data=(output/(stem+'-gpu-destination.bin')).read_bytes()
        assert len(data)==0x10000
        for offset in range(0,len(data),4):
            changed=0x3f00<=offset<0x4000 or 0xc000<=offset<0xff00
            assert struct.unpack_from('<I',data,offset)[0]==(0xff00ff00 if changed else 0xa55aa55a),offset

    run('kext-build',['sh','gpu/adreno-kext/kext/build.sh'])
    kext=output/'kext/AdrenoX2.kext'
    run('kext-signature',['codesign','--verify','--strict','--verbose=2',str(kext)])
    kext_binary=kext/'Contents/MacOS/AdrenoX2'
    assert b'snapintosh,guest-fill32-abi\0' in kext_binary.read_bytes()
    symbols=run('kext-symbols',['nm',str(kext_binary)])
    for name in ('_adreno_fill32_decode','_adreno_fill32_submit','_adreno_fill32_resource_range'):
        assert re.search(r'\bT '+re.escape(name)+r'$',symbols,re.M),name

    # The normal builder compiles the real HVC dispatch plus the fill helper.
    # It never calls run.main(), connects to q1n1 or constructs a guest image.
    program=('import pathlib,sys\n'
        'root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root/"probes"))\n'
        'import run\n'
        'import json\n'
        'run.FLAGS=json.loads(sys.argv[2])\n'
        'run.build("xnuboot",pathlib.Path(sys.argv[3]))\n')
    monitor=output/'monitor'
    run('monitor-build',[sys.executable,'-c',program,str(ROOT),json.dumps(baseline['build_defines']),str(monitor)])
    monitor_binary=monitor/'xnuboot.bin'
    assert 0<monitor_binary.stat().st_size<=baseline['budget']
    run('monitor-symbols',['/opt/homebrew/opt/llvm/bin/llvm-nm',str(monitor/'xnuboot.elf')])
    assert (monitor/'adreno-fill-c.o').stat().st_size>0
    for n,h in sources.items(): assert sha(ROOT/n)==h,n
    result=dict(status='FILL_COMMAND_MONITOR_KEXT_HOST_QUALIFIED_NOT_INSTALLED',
        baseline_build=str(baseline_path),baseline_build_sha256=sha(baseline_path),
        monitor_sha256=sha(monitor_binary),monitor_bytes=monitor_binary.stat().st_size,
        monitor_budget=baseline['budget'],build_defines=baseline['build_defines'],
        kext_sha256=sha(kext_binary),sources_sha256=sources,
        packet_reference_sha256=sha(ROOT.parent/'q1n1/tools/adreno_x2.py'),
        commands=commands,replay=replay.splitlines(),
        artifacts_sha256={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file()},
        boundary='Sanitized command/list/cache/CP/SMMU model and compiled monitor/signed kext. Native IOGPU retain/prepare are model callbacks. Metal encoding, linked AuxKC, complete boot image, A16 execution and presentation remain unverified.')
    report=output/'qualification.json'
    report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(status=result['status'],sources=len(sources),artifacts=len(result['artifacts_sha256']),report=str(report))))

if __name__=='__main__':main()
