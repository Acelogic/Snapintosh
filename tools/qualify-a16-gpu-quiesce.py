#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded native GPU fence/quiescence candidate; no guest or CPU startup.

Failure inventory: docs/A16-GPU-NATIVE-QUALIFICATION-20261019.md.
prepare/check are offline. run is for the one main hardware operator only.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import secrets
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'probes'), str(ROOT/'tools'), str(ROOT.parent/'q1n1/tools')]
import run
import adreno
import a16gpu as S1
import a16gpu_stage3 as S3
import a16gpu_adopt as ADOPT
from cycle_lib.common import Workspace, require_exclusive

MAGIC, REPORT_BYTES = 0x3151504736314141, 768
CODE, PARAMS, REPORT, TARGET, TOP = 0x500000, 0x510000, 0x511000, 0x514000, 0x518000
LIVE_TOKENS = ('gmu_ttbr','gpu_ttbr','boot_token','hfi_token','oob_token','cp_token','rb_wptr',
               'hwinit_token','sqe_probe','p67_token','fb_mapped')
NATIVE_SOURCES = ['tools/a16-gpu-quiesce-probe.c','compat/adreno.c','compat/adreno.h',
                  'compat/adreno-guest.h','compat/irq-forward.h']
SOURCES = NATIVE_SOURCES + ['tools/qualify-a16-gpu-quiesce.py','tools/a16-control-guard.py',
    'tools/qualify-a16-cpu-policy.py','tools/a16-cpu-perf.py','tools/measure-a16-cpu-clock.py',
    'tools/a16-cpu-stub.S','tools/probe-a16-cpus.py','tools/a16-thermal-survey.py',
    'tools/cycle_lib/common.py','probes/run.py','probes/adreno.py','probes/psci-info.S',
    '../q1n1/tools/q1n1proxy.py'] + [str(p.relative_to(ROOT.parent)).replace('q1n1/', '../q1n1/', 1)
        for pattern in ('a16gpu*.py','adreno_*.py') for p in sorted((ROOT.parent/'q1n1/tools').glob(pattern))]


def sha(data):return hashlib.sha256(data).hexdigest()
def need(value, reason):
    if not value:raise RuntimeError(reason)
def module(name):return runpy.run_path(str(ROOT/'tools'/name))
def hashes():return {n:sha((ROOT/n).read_bytes()) for n in SOURCES}
def integer(value):return int(value, 0) if isinstance(value, str) else int(value)


def build(out):
    out.mkdir(parents=True, exist_ok=False)
    linker = out/'probe.ld'
    linker.write_text('ENTRY(gpu_probe_entry)\nSECTIONS { . = 0; .text : { KEEP(*(.text.entry)) *(.text*) *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) *(COMMON) } /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) } }\n')
    commands, objects = [], []
    for name in ('tools/a16-gpu-quiesce-probe.c','compat/adreno.c'):
        obj=out/(Path(name).stem+'.o');objects.append(str(obj))
        commands.append([str(run.LLVM/'clang'),*run.FLAGS,'-O2','-ffixed-x18','-fno-builtin',
                         '-ffunction-sections','-fdata-sections','-I'+str(ROOT/'compat'),
                         '-c',str(ROOT/name),'-o',str(obj)])
    elf, binary = out/'gpu-quiesce.elf', out/'gpu-quiesce.bin'
    commands += [[run.LLD,'--gc-sections','-T',str(linker),*objects,'-o',str(elf)],
                 [str(run.LLVM/'llvm-objcopy'),'-O','binary',str(elf),str(binary)]]
    logs=[]
    for command in commands:
        result=subprocess.run(command,capture_output=True,text=True)
        logs.append(dict(command=command,returncode=result.returncode,stdout=result.stdout,stderr=result.stderr))
        (out/'build.json').write_text(json.dumps(logs,indent=2)+'\n')
        need(result.returncode==0,'native build failed; see '+str(out/'build.json'))
    blob=binary.read_bytes();need(0<len(blob)<=0x10000,'native payload outside code slot')
    nm=subprocess.run([str(run.LLVM/'llvm-nm'),'-n',str(elf)],capture_output=True,text=True,check=True).stdout
    (out/'symbols.txt').write_text(nm)
    need(any(line.split()==['0000000000000000','T','gpu_probe_entry'] for line in nm.splitlines()),'entry is not at offset zero')
    need(not any(' U ' in line for line in nm.splitlines()),'unresolved native symbol')
    record=dict(schema='a16-gpu-native-candidate-v1',hardware_access=False,bytes=len(blob),
                binary_sha256=sha(blob),source_sha256=hashes(),commands=commands)
    (out/'candidate.json').write_text(json.dumps(record,indent=2)+'\n')
    return blob,record


def candidate(path):
    record=json.loads((path/'candidate.json').read_text());blob=(path/'gpu-quiesce.bin').read_bytes()
    need(record['schema']=='a16-gpu-native-candidate-v1' and 0<len(blob)<=0x10000 and
         record['bytes']==len(blob) and record['binary_sha256']==sha(blob),'candidate binary mismatch')
    need(record['source_sha256']==hashes(),'candidate sources changed; rebuild/replay offline')
    return blob,record


def native_terminal(guard, value, record, save):
    # A known failure is distinct from transport uncertainty. Neither permits
    # host report capture, quiescence commands or restoration in this run.
    record['native_return']=value;save()
    if value!=0:
        record['native_quarantine']=True;save()
        guard.freeze('native GPU probe returned quarantine '+hex(value))
        raise RuntimeError(guard.reason)


def report_checks(raw, marker, target, params):
    need(len(raw)==REPORT_BYTES,'native report extent')
    w=struct.unpack('<96Q',raw);s=w[32:77]
    checks=dict(magic=w[:3]==(MAGIC,1,REPORT_BYTES),request=w[3:6]==(marker,target,0x40000000),
        terminal=w[9:13]==(0,0,0,0),fence_value=w[13]==marker,
        cpu=w[24]==8 and not(w[25]&0xff00ffffff) and ((w[26]>>16)&15)==4 and w[27]==19200000,
        serror=not((w[22]|w[23])&(1<<8)),
        bounded=w[8]==19200000 and w[7]>w[6] and w[7]-w[6]<19200000//2,
        cb0=w[14]==params[5] and w[15]==params[6] and bool(w[16]&1) and
            not((w[16]^params[7])&~0x1000),
        root_unlinked=w[17:20]==(0,0,0),ring_idle=w[20]==w[21]==s[2],
        state=s[0]==49 and s[1]==0 and s[3]==1 and s[4]==marker and s[6]==0,
        mapping=s[8]==4 and s[13]==2 and s[14]==0 and s[15]==0 and s[39]==0,
        teardown=s[36]==41 and bool(s[37]&1) and s[38]==params[5],
        reserved=not any(w[28:32]+w[77:]))
    return dict(header=list(w[:32]),gpu_state=list(s)),checks


class GuardedStageSession(S3.Session3):
    """Existing command implementations with bounded calls and no fallback I/O."""
    def __init__(self,guard,out,deadline,**kwargs):
        super().__init__(guard.proxy,guarded=True,**kwargs)
        self.guard,self.out,self.deadline=guard,out,deadline
    def budget(self):
        if self.clock()>self.deadline:
            self.guard.freeze('GPU qualification host deadline expired');raise RuntimeError(self.guard.reason)
        if str(self.out.get('quiesce','')).startswith('graceful path failed'):
            self.guard.freeze('graceful GPU shutdown failed; forced fallback prohibited');raise RuntimeError(self.guard.reason)
    def _check(self,reg,write):self.budget();return super()._check(reg,write)
    def _dram(self,op,address,call):self.budget();return super()._dram(op,address,call)
    def dram(self,*args):self.budget();return super().dram(*args)
    def call_gpu(self,op,*args,what=''):
        self.budget();need(self.gpu_call,'no native GPU service')
        need(self.allow_writes or op==S3.GPU_QUERY,'native GPU write refused')
        value=self.p.call(self.gpu_call,op,*args,timeout=5)
        self.log.append(dict(op='gpu_call',call=op,args=list(args),result=value,what=what))
        if value!=0:
            self.guard.freeze('native q1n1 GPU service returned nonzero '+hex(value));raise RuntimeError(self.guard.reason)
        return value
    def poll(self,*args,**kwargs):
        try:return super().poll(*args,**kwargs)
        except BaseException as error:
            self.guard.freeze('Stage1 poll failed: '+str(error));raise RuntimeError(self.guard.reason) from error
    def poll3(self,*args,**kwargs):
        try:return super().poll3(*args,**kwargs)
        except BaseException as error:
            self.guard.freeze('Stage3 poll failed: '+str(error));raise RuntimeError(self.guard.reason) from error


def stage(guard,record,save,command,args,deadline):
    out=dict(command=command,order=[],stopped=None,started=time.time())
    record.setdefault('stages',[]).append(out);save()
    fn,writes=(lambda s,o,a:S1.cx_on(s,o),True) if command=='cx-on' else S3.COMMANDS[command]
    session=GuardedStageSession(guard,out,deadline,allow_writes=writes)
    S3._hook_efi_regions(session,out)
    try:
        fn(session,out,args)
        if guard.frozen:raise RuntimeError(guard.reason)
        fault=guard.proxy.serror_state();out['serror_after']=fault
        if any(fault.get(k,0) for k in ('before','during','unconsumed')):
            guard.freeze('Stage3 returned with SError');raise RuntimeError(guard.reason)
        if guard.proxy.exceptions or guard.proxy.get_exc_count():
            guard.freeze('Stage3 returned with exception evidence');raise RuntimeError(guard.reason)
    except BaseException as error:
        out['stopped']=dict(step=session.step,reason=str(error));raise
    finally:
        # Local objects only. No legacy run() finally and no failure diagnostics.
        out.update(proven=session.proven,polls=session.polls,log=session.log,finished=time.time())
        out.pop('_efi_regions',None);out.pop('_leave_halted',None);save()
    return out,session


def unprepared(status):
    host=status.get('host_record')
    return not status.get('stopped') and not status.get('gmu',{}).get('live') and (
        host is None and 'missing' in status.get('arena',{}) or
        host is not None and all(integer(host.get(k,-1))==0 for k in LIVE_TOKENS))


def shutdown_checks(quiesce,status,session):
    R=S3.R
    scr0,groups=S3.smmu_globals(session,{})
    live=S3.sids_reaching_memory(session,scr0,groups,R.GPU_SIDS+(R.GMU_SID,)+R.MUST_FAULT_SIDS)
    host=status.get('host_record',{});gmu=status.get('gmu',{});regs=status.get('gmu_regs',{})
    return dict(graceful=quiesce.get('quiesce')=='graceful' and not quiesce.get('rscc'),
        complete=quiesce.get('order',[])[-3:]==['smmu_off','clocks_parked','quiesced'],
        hfi=quiesce.get('hfi_stop')=='indices zeroed with the CM3 in reset',
        reset=bool(integer(gmu.get('sysreset',0))&1) and not gmu.get('live',True),
        gx_off=integer(regs.get('GMU_PWR_CLK_STATUS',0))&3==3,
        banks_off=all(not(integer(status.get('cb',{}).get(str(cb),{}).get('SMMU_CB_SCTLR',1))&1) for cb in (0,1)),
        streams_fault=not live,
        tokens=bool(host) and all(integer(host.get(k,-1))==0 for k in LIVE_TOKENS),
        clocks=all(S1.is_xo(integer(regs.get(n,-1))) for n in ('GPU_CC_GMU_CFG_RCGR','GPU_CC_HUB_CFG_RCGR')) and
               not(integer(regs.get('GPU_CC_PLL0_OPMODE',1))&R.PLL_OPMODE_RUN))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=('prepare','check','run'));ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--device');ap.add_argument('--generation',type=int)
    ap.add_argument('--image-base',type=lambda s:int(s,0));ap.add_argument('--heap-base',type=lambda s:int(s,0))
    ap.add_argument('--stage',type=Path);ap.add_argument('--cpu-cap',type=Path);ap.add_argument('--idle',action='store_true')
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    if args.mode=='prepare':
        blob,cand=build(args.candidate.resolve());print(json.dumps(dict(status='OFFLINE_BUILT',sha256=sha(blob),bytes=len(blob))));return 0
    blob,cand=candidate(args.candidate.resolve())
    if args.mode=='check':print(json.dumps(dict(status='OFFLINE_CANDIDATE_VERIFIED',sha256=sha(blob))));return 0
    need(args.idle and args.device and args.generation is not None and args.image_base is not None and
         args.heap_base is not None and args.stage and args.cpu_cap and args.output,
         'run requires explicit idle/device/identity/stage/CPU-cap/output')
    cap=json.loads(args.cpu_cap.read_text())
    need(cap.get('status')=='CPU0_CHARACTERIZED_CAP_VERIFIED' and cap.get('final_conservative_policy_verified') and
         cap.get('scratch',{}).get('restored') and not cap.get('control_guard',{}).get('frozen'),'CPU cap receipt is not verified')
    retained_stage=args.stage.read_bytes();need(len(retained_stage)>=8192,'stage reference too short')
    dest=args.output.resolve();need(not dest.exists(),'output exists')
    require_exclusive(Workspace(ROOT));dest.mkdir(parents=True)
    record=dict(schema='a16-gpu-native-v1',status='PREPARING',started=time.time(),candidate=cand,
        scope='CPU0 native GPU fence/teardown and q1n1 shutdown; no guest/SMP proof',
        cpu_cap=dict(path=str(args.cpu_cap),sha256=sha(args.cpu_cap.read_bytes())),
        stage=dict(path=str(args.stage),sha256=sha(retained_stage)))
    def save():
        temp=dest/'receipt.tmp'
        with temp.open('w') as f:f.write(json.dumps(record,indent=2)+'\n');f.flush();os.fsync(f.fileno())
        temp.replace(dest/'receipt.json')
        fd=os.open(dest,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def artifact(name,data):
        with (dest/name).open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        record.setdefault('artifacts_sha256',{})[name]=sha(data);save()
    save();artifact('gpu-quiesce.bin',blob)
    policy=module('qualify-a16-cpu-policy.py');clock=policy['clock'];guard_module=module('a16-control-guard.py')
    psci=run.build('psci-info',dest/'native');pmu=clock['build_stub'](dest/'native')
    record['probe_sha256']=dict(psci=sha(psci),pmu=sha(pmu));save()
    raw=guard=scratch=None;close_raw=None;changed=False;mutated=False;terminal=False
    with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            raw=run.connect(args.device,tries=1);close_raw=raw.link.close
            guard=guard_module['ControlGuard'](raw,record,save);proxy=guard.proxy
            info=proxy.bootinfo();record['bootinfo']=info
            need(info['stage_generation']==args.generation and info['image_base']==args.image_base and
                 info['heap_base']==args.heap_base and info['current_el']==2 and info['timer_hz']==19200000 and
                 info['heap_size']>=TOP,'resident identity/heap mismatch')
            need(all(info[k]==cap['bootinfo'][k] for k in policy['IDENTITY']),'CPU cap receipt is from another resident')
            resident=proxy.readmem(info['image_base']+0x1000,4096,live=True);artifact('resident-code-page.bin',resident)
            need(resident==retained_stage[0x1000:0x2000] and sha(resident)==cap['resident_code']['sha256'],'resident immutable page mismatch')
            record['serror_before']=proxy.serror_state()
            if not policy['perf']['serror_clear'](record['serror_before']):
                guard.freeze('preexisting SError');raise RuntimeError(guard.reason)
            proxy.serror_strict(True);changed=True
            returned=proxy.call(info['battery_call'],0,0,0,0,0,timeout=12)
            if returned!=0:guard.freeze('native battery result is nonzero');raise RuntimeError(guard.reason)
            battery=proxy.live_battery_record(info['battery_result']);record['battery']=battery;save()
            need(battery['plausible'] and battery['ac'],'GPU qualification requires AC')
            def temperatures(name):return policy['temperature_snapshot'](proxy,record,name,save,guard)
            temperatures('initial')
            base=info['heap_base'];ranges=[(base+0x480000,TOP-0x480000)]
            scratch=clock['Scratch'](proxy,ranges)
            for i,(address,data) in enumerate(scratch.saved):artifact(f'scratch-before-{i}.bin',data)
            record['scratch_ranges']=[dict(address=a,bytes=len(d),sha256=sha(d)) for a,d in scratch.saved];save()
            try:
                inv=module('probe-a16-cpus.py')['collect'](proxy,psci,True);record['inventory']=inv
                states=clock['cpu_states'](inv)
                need(inv['boot_mpidr']=='0x0' and len(states)==18 and all(v==(0 if m==0 else 1) for m,v in states.items()),'require CPU0 ON/17 peers OFF')
                code=base+clock['CODE_AT'];out=base+clock['RESULT_AT'];clock['upload'](proxy,code,pmu)
                proxy.writemem(out,bytes(clock['REPORT_BYTES']))
                returned=proxy.call(code+clock['ENTRY_MEASURE'],out,4,192000,timeout=2)
                need(returned==0,'PMU returned nonzero')
                data=proxy.readmem(out,clock['REPORT_BYTES'],live=True);artifact('admission-pmu.bin',data)
                measured=clock['decode'](struct.unpack('<64Q',data),4,192000,19200000)
                policy['measured_point'](measured,1939.2,'fresh CPU0 cap');record['cpu0_pmu']=measured;save()
            except BaseException as error:guard.freeze('native CPU admission failed: '+str(error));raise
            temperatures('cpu-admission-after')
            deadline=time.monotonic()+120
            status,_=stage(guard,record,save,'status',S3.Args(),deadline)
            need(unprepared(status),'GPU is not unprepared; no reinitialization admitted')
            scratch.keep('GPU preparation began; DMA and shutdown ownership not yet proven')
            mutated=True;record['status']='GPU_PREPARATION';save()
            recipe=[('cx-on',{}),('arena',{}),('gmu-smmu',{}),
                    ('gmu-boot',dict(rail_vote_unseen=True,rail_level='nom')),('hfi',{}),('oob',{}),
                    ('cp-fence',dict(stop_after='C3')),('cp-fence',dict(stop_after='C3S')),
                    ('cp-fence',dict(stop_after='C5')),('cp-fence',{})]
            for index,(command,options) in enumerate(recipe):
                stage(guard,record,save,command,S3.Args(**options),deadline)
                temperatures(f'prep-{index}-{command}')
            adopt_path=dest/'adoption.json'
            stage(guard,record,save,'adopt',S3.Args(record=str(adopt_path)),deadline)
            adopted=adreno.load_adoption(str(adopt_path),info);adreno.check_disjoint(adopted,ranges)
            words=adreno.params_words(adreno.AdrenoSpec(dart=True,cx_misc=False,ring_at_seconds=0,self_irq=False,ring_test=True),adopted)
            need(words[0]==29,'unexpected adoption flags')
            target=base+TARGET;marker=secrets.randbits(32) or 1
            params=struct.pack('<16Q',*words)
            record.update(params=words,marker=marker,target=target);artifact('params.bin',params)
            for address,data in ((base+CODE,blob),(base+PARAMS,params),(base+REPORT,bytes(REPORT_BYTES)),(target,bytes(0x4000))):
                proxy.writemem(address,data);need(proxy.readmem(address,len(data))==data,'native upload readback mismatch')
            proxy.flush_code(base+CODE,len(blob))
            temperatures('native-before')
            need(time.monotonic()<deadline,'deadline before native entry')
            record['status']='NATIVE_IN_FLIGHT';save()
            returned=proxy.call(base+CODE,base+REPORT,base+PARAMS,target,marker,timeout=2)
            native_terminal(guard,returned,record,save)
            data=proxy.readmem(base+REPORT,REPORT_BYTES,live=True);artifact('native-report.bin',data)
            decoded,checks=report_checks(data,marker,target,words);record.update(native_report=decoded,native_checks=checks);save()
            if not all(checks.values()):guard.freeze('native GPU terminal oracle failed');raise RuntimeError(guard.reason)
            proxy.request(proxy.P_DC_CIVAC,target,0x4000)
            result_page=proxy.readmem(target,0x4000,live=True);artifact('target-after.bin',result_page)
            if result_page!=struct.pack('<I',marker)+bytes(0x4000-4):
                guard.freeze('independent GPU target readback mismatch');raise RuntimeError(guard.reason)
            temperatures('native-after')
            quiesce,_=stage(guard,record,save,'quiesce',S3.Args(),deadline)
            status,session=stage(guard,record,save,'status',S3.Args(),deadline)
            checks=shutdown_checks(quiesce,status,session);record['shutdown_checks']=checks;save()
            if not all(checks.values()):guard.freeze('GPU/GMU shutdown oracle failed');raise RuntimeError(guard.reason)
            temperatures('shutdown-after')
            record['serror_after']=proxy.serror_state()
            if not policy['perf']['serror_clear'](record['serror_after']) or proxy.exceptions or proxy.get_exc_count():
                guard.freeze('terminal GPU session has exception evidence');raise RuntimeError(guard.reason)
            terminal=True;scratch.release();record['status']='NATIVE_GPU_QUIESCE_VERIFIED';save()
        except BaseException as error:
            if mutated and not terminal and guard and not guard.frozen:guard.freeze('GPU sequence did not reach verified shutdown: '+str(error))
            record['status']='FROZEN_NO_FURTHER_TARGET_IO' if guard and guard.frozen else 'REFUSED_OR_FAILED'
            record['error']=f'{type(error).__name__}: {error}'
        finally:
            if guard:
                try:
                    if scratch:record['scratch']=guard.restore_scratch(scratch)
                    if not guard.frozen and changed:proxy.serror_strict(bool(record['serror_before']['flags']&1))
                except BaseException as error:
                    record.setdefault('cleanup_errors',[]).append(str(error));record['status']='FROZEN_NO_FURTHER_TARGET_IO' if guard.frozen else 'REFUSED_OR_FAILED'
                finally:guard.close()
            elif close_raw:close_raw()
            record['finished']=time.time();save()
    print(json.dumps({k:record.get(k) for k in ('status','error','scratch','cleanup_errors')}))
    return 0 if record['status']=='NATIVE_GPU_QUIESCE_VERIFIED' and record.get('scratch',{}).get('restored') else 1


if __name__=='__main__':raise SystemExit(main())
