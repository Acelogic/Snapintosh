#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retained capture -> AArch64 policy -> service stop -> production report decoder.

CPU0 only; never boots XNU, initializes GPU, writes sensors or changes clocks.
Injected hot/invalid readings follow an unmodified first sample.
Failure inventory: docs/A16-THERMAL-GUARD-20261018.md.
"""
import argparse,fcntl,hashlib,json,struct,subprocess,sys,time
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'tools'),str(R/'probes')]
import run,early_stop,a16_thermal
from cycle_lib.common import Workspace,require_exclusive,need,serror_clear

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--capture',type=Path,required=True)
    ap.add_argument('--qemu',action='store_true');ap.add_argument('--idle',action='store_true')
    ap.add_argument('--device');ap.add_argument('--generation',type=int);ap.add_argument('--image-base',type=lambda x:int(x,0))
    ap.add_argument('--case',choices=['cool','hot','invalid'],required=True)
    a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if not a.qemu and not(a.idle and a.device and a.generation is not None and a.image_base is not None):ap.error('hardware requires explicit idle identity')
    case=['cool','hot','invalid'].index(a.case)
    capture=json.loads(a.capture.read_text());need(capture['status']=='READ_COMPLETE','incomplete capture')
    fixture=struct.pack('<152I',*[v for b in capture['blocks'] for v in [b['version'],b['control'],b['ready'],*b['status_words']]])
    (out/'sensors.bin').write_bytes(fixture)
    sources=[R/'tools/a16-thermal-probe.c',R/'compat/a16-thermal.c',R/'compat/early-stop.c',R/'compat/service-lock.c']
    record=dict(status='BUILDING',case=a.case,qemu=a.qemu,scope='CPU0 EL2 polling/return and decoder; no guest timer, SMP, GPU quiescence, fan, CPU policy or power-off proof',capture_sha256=sha(a.capture),source_sha256={str(p):sha(p) for p in [*sources,R/'tools/qualify-a16-thermal.py',R/'compat/a16-thermal.h',R/'compat/early-stop.h',R/'compat/service-lock.h',R/'tools/a16_thermal.py',R/'tools/early_stop.py']})
    def save():(out/'receipt.json').write_text(json.dumps(record,indent=2)+'\n')
    save()
    # Exercise the same Python settings encoder used by the guest loader.
    settings=early_stop.settings({'SNAP_EARLY_STOP':'thermal'})
    need(settings.thermal and settings.host and len(settings.params_words(1,2))==6 and settings.params_words(1,2)[0]==10,'thermal settings ABI')
    with (out/'build.log').open('w') as log:
        objs=[]
        for src in sources:
            obj=out/(src.stem+'.o');objs.append(str(obj))
            subprocess.run([str(run.LLVM/'clang'),*run.FLAGS,'-I'+str(R/'compat'),'-c',str(src),'-o',str(obj)],check=True,stdout=log,stderr=log)
        elf=out/'probe.elf';binary=out/'probe.bin'
        subprocess.run([run.LLD,'-T',str(R/'probes/probe.ld'),*objs,'-o',str(elf)],check=True,stdout=log,stderr=log)
        subprocess.run([str(run.LLVM/'llvm-objcopy'),'-O','binary',str(elf),str(binary)],check=True,stdout=log,stderr=log)
    blob=binary.read_bytes();need(len(blob)<0x10000,'probe exceeds code slot')
    record['binary_sha256']=sha(binary);save()
    qemu=run.Qemu(R) if a.qemu else None
    path=qemu.__enter__() if qemu else a.device
    proxy=None;saved=None;unknown=False
    with open('/tmp/snapintosh-hardware.lock','a') as lock:
        if not a.qemu:
            require_exclusive(Workspace(R));fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            proxy=run.connect(path,tries=60 if a.qemu else 1)
            info=proxy.bootinfo();record['bootinfo']=info;need(info['current_el']==2,'not EL2')
            if not a.qemu:
                need(info['stage_generation']==a.generation and info['image_base']==a.image_base,'identity mismatch')
                a16_thermal.admit_target(info)
            record['guard_before']=proxy.serror_state();need(serror_clear(record['guard_before']),'preexisting SError')
            entry,state=run.call_service(proxy,info)
            if state:need(struct.unpack('<Q',proxy.readmem(state+24,8))[0]==0,'call service armed')
            base=info['heap_base']+0x4a0000;result=base+0x10000;data=base+0x12000;span=0x13000
            need(base+span<=info['heap_base']+info['heap_size'],'scratch outside heap')
            saved=proxy.readmem(base,span);(out/'scratch-before.bin').write_bytes(saved)
            proxy.writemem(base,blob);need(proxy.readmem(base,len(blob))==blob,'upload mismatch');proxy.flush_code(base,len(blob))
            proxy.writemem(result,bytes(4096));need(proxy.readmem(result,4096)==bytes(4096),'result clear mismatch')
            if a.qemu:
                proxy.writemem(data,fixture);need(proxy.readmem(data,len(fixture))==fixture,'fixture upload mismatch')
            record.update(status='CALL_IN_FLIGHT',started=time.time());save();unknown=True
            returned=proxy.call(base,result,data if a.qemu else 0,case,0,timeout=8)
            unknown=False;record.update(call_return=returned,returned=time.time());save()
            need(not proxy.exceptions,'proxy exception')
            record['guard_after']=proxy.serror_state();need(serror_clear(record['guard_after']),'SError after probe')
            raw=proxy.readmem(result,4096);(out/'report.bin').write_bytes(raw)
            head=dict(zip('magic status hz start end mode local stop_word first_valid_count healthy_polls'.split(),struct.unpack('<10Q',raw[:80])))
            thermal=a16_thermal.decode(raw[80:80+a16_thermal.SIZE])
            stop=early_stop.decode(raw[80+a16_thermal.SIZE:80+a16_thermal.SIZE+early_stop.SIZE])
            record.update(report=head,thermal=thermal,stop=stop)
            # The terminal P_CALL and clean guard permit restoring reserved scratch.
            proxy.writemem(base,saved);proxy.request(proxy.P_DC_CVAC,base,len(saved))
            need(proxy.readmem(base,len(saved))==saved,'scratch restore mismatch');saved=None;record['scratch_restored']=True
            need(head['magic']==0x31505248543641 and returned==head['status']==0,'probe status')
            elapsed=(head['end']-head['start'])/head['hz']
            need(0<elapsed<4,'fallback or invalid duration')
            need(thermal is not None and thermal['read_failures']==0 and not thermal['read_inflight'],'reader failed/in-flight')
            need(head['stop_word']==(1<<32)|1,'service stop word')
            expected=[0,1,3][case];need(thermal['reason']==expected,'unexpected thermal reason')
            if case:
                need(stop['state']==3 and stop['source']==3 and stop['reason']==expected and stop['outcome']==1,'thermal FIRED/STOPPED not retained')
                need(thermal['location']==0xc22c0a0,'wrong injected sensor')
                need((0.25 if case==1 else 1)<=elapsed< (1 if case==1 else 2),'trip latency')
            else:
                counts=[13,9,13,8,13,8,13,15]
                ages=[(head['end']-thermal['last_valid'][b*16+n])/head['hz'] for b,c in enumerate(counts) for n in range(c)]
                record['oldest_valid_seconds']=max(ages)
                need(head['healthy_polls']>0 and thermal['polls']>=8 and 2<=elapsed<3,'cool control')
                need(thermal['seen_mask']==[(1<<c)-1 for c in counts] and 0<=min(ages)<=max(ages)<1,'sensor freshness')
            record.update(status='PASS',elapsed_seconds=elapsed,hardware_verified=not a.qemu)
        except BaseException as e:
            record.update(status='UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO' if unknown else 'FAILED',error=repr(e));raise
        finally:
            if proxy:proxy.link.close()
            if qemu:qemu.__exit__(None,None,None)
            record['scratch_retained']=saved is not None
            record['artifacts_sha256']={p.name:sha(p) for p in out.iterdir() if p.is_file() and p.name!='receipt.json'};save()
    print(json.dumps({k:record[k] for k in ['status','case','qemu','elapsed_seconds','hardware_verified']}))
if __name__=='__main__':main()
