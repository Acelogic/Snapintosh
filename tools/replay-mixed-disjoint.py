#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay generation47's captured mixed-root UPDATE_DISJOINT, without hardware."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import runpy
from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def apple_descriptors(request):
    sys.path.insert(0,str(ROOT/'build/test-python-deps'))
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    import unicorn.arm64_const as reg
    image = runpy.run_path(str(ROOT/'tools/sptm-dispatch.py'))['Image'](
        ROOT/'downloads/extracted/j700ap/sptm.t8140.release')
    digest=hashlib.sha256(image.data).hexdigest()
    assert digest=='bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'
    base=0xfffffff027000000
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x200000)
    for _,va,_,off,size in image.segs:u.mem_write(va,image.data[off:off+size])
    u.mem_map(0x1000000,0x100000)
    context,data,table,out=0x1010000,0x1011000,0x1012000,0x1013000
    u.mem_write(context,data.to_bytes(8,'little')+table.to_bytes(8,'little'))
    u.mem_write(data+2,bytes([11]));u.mem_write(table+2,bytes([20]))
    endpoints=(base+0xfd8f0,base+0xfda34,base+0xfd904,base+0xfd94c)
    def stop(uc,address,size,user):
        if address in endpoints:uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,stop)
    results=[]
    for item in request['records']:
        for n,value in enumerate((context,int(item['old_pte'],0),int(item['template'],0),
                                  int(request['options'],0),out)):
            u.reg_write(getattr(reg,f'UC_ARM64_REG_X{n}'),value)
        u.reg_write(reg.UC_ARM64_REG_SP,0x1080000)
        u.emu_start(base+0xfd544,base+0xfd900,count=1000)
        pc=u.reg_read(reg.UC_ARM64_REG_PC)
        value=int.from_bytes(u.mem_read(out,8),'little')
        assert pc in endpoints[:2] and value==int(item['template'],0)
        results.append({'domain':item['root_kind'],'selected':hex(value),'end_pc':hex(pc)})
    return {'sptm_sha256':digest,'records':results,
            'boundary':'Unmodified Apple descriptor helper only; not whole-batch atomicity or TLBI.'}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--monitor-baseline', type=Path)
    args = ap.parse_args()
    capture = args.capture.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    data = json.loads(capture.read_text())
    req = data['update_disjoint_request']
    assert req['count'] == 2 and int(req['options'], 0) == 0x10a
    u, k = req['records']
    assert u['root_kind'] == 'user' and k['root_kind'] == 'kernel'
    assert u['target_matches'] and k['target_matches']
    assert not u['active_cpus'] and k['active_cpus'] == list(range(6))
    sources = ['tools/replay-mixed-disjoint.c', 'tools/replay-mixed-disjoint.py',
               'tools/test-sptm-update.c','tools/test-user-update.c',
               'tools/test-user-tpro.c','tools/sptm-dispatch.py']
    # Production engines and real canonical shadow builders; linker dead-strips
    # unrelated compatibility entry points. No instruction or result is mocked.
    impl = sorted(str(p.relative_to(ROOT)) for p in (ROOT/'compat').glob('sptm*.c'))
    impl += ['shadow/sprr-view.c','shadow/mmu.c','shadow/shadow.c']
    headers = sorted(str(p.relative_to(ROOT)) for d in ['compat','shadow']
                     for p in (ROOT/d).glob('*.h'))
    sources += impl + headers + ['probes/xnuboot.c']
    sources += [str(q.relative_to(ROOT)) for p in sources if p.endswith('.c') for q in source_files(ROOT/p)[1:]]
    record = {'status':'FAIL', 'hardware_access':False,
              'capture':str(capture),'capture_sha256':sha(capture),
              'request':req, 'source_sha256':{p:sha(ROOT/p) for p in sources},
              'boundary':'Captured descriptor attributes and request order, relocated fixture RAM and constructed table ancestors; production engines and canonical shadows. No physical CPU private-view or TLBI proof.'}
    record['apple_descriptor_comparison']=apple_descriptors(req)
    binary = out/'replay'
    command = ['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
               '-fno-sanitize-recover=all','-ffunction-sections','-Wl,-dead_strip',
               '-Icompat','-Ishadow','tools/replay-mixed-disjoint.c',*impl,'-o',str(binary)]
    compile_run = subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
    (out/'build.log').write_text(compile_run.stdout+compile_run.stderr)
    record['build_exit']=compile_run.returncode
    if not compile_run.returncode:
        arguments=[u['old_pte'],u['template'],k['old_pte'],k['template'],req['options']]
        run=subprocess.run([str(binary),*arguments],cwd=ROOT,capture_output=True,text=True)
        (out/'replay.log').write_text(run.stdout+run.stderr)
        record['replay_exit']=run.returncode
        if run.returncode==0:
            record['regressions']={}
            for name in ['test-sptm-update','test-user-update']:
                cmd=[*command[:command.index('tools/replay-mixed-disjoint.c')],
                     'tools/'+name+'.c',*impl,'-o',str(out/name)]
                compiled=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True)
                (out/(name+'-build.log')).write_text(compiled.stdout+compiled.stderr)
                assert compiled.returncode==0, name+' build'
                checked=subprocess.run([str(out/name)],cwd=ROOT,capture_output=True,text=True)
                (out/(name+'.log')).write_text(checked.stdout+checked.stderr)
                record['regressions'][name]=checked.returncode
            if not any(record['regressions'].values()):record['status']='PASS'
    if record['status']=='PASS' and args.monitor_baseline:
        baseline=args.monitor_baseline.resolve()
        spec=json.loads(baseline.read_text())
        sys.path.insert(0,str(ROOT/'probes'))
        import run as monitor
        monitor.FLAGS=spec['build_defines']
        inputs=monitor.MULTI['xnuboot']+['probes/probe.ld','probes/run.py']
        inputs+=[str(q.relative_to(ROOT)) for p in inputs if p.endswith('.c') for q in source_files(ROOT/p)[1:]]
        for name in inputs:record['source_sha256'][name]=sha(ROOT/name)
        blob=monitor.build('xnuboot',out/'monitor')
        record['monitor']={'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),
            'budget':monitor.OUT_AT-monitor.CODE_AT,'baseline':str(baseline),
            'baseline_sha256':sha(baseline),'build_defines':monitor.FLAGS,
            'boundary':'Original checkout ARM monitor builds; clear-runtime integration and hardware boot are still required.'}
    record['artifacts_sha256']={p.name:sha(p) for p in out.iterdir() if p.is_file()}
    (out/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'output':str(out),'build_exit':record['build_exit'],
                      'replay_exit':record.get('replay_exit')}))
    return 0 if record['status']=='PASS' else 1

if __name__=='__main__':
    sys.exit(main())
