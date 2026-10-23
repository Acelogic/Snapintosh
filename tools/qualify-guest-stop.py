#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the bounded real-monitor EL1 stop candidate; optionally replay in QEMU.

This offline driver never discovers or opens a hardware target. Native entry
arguments and safety gates are retained in the candidate manifest for the
single hardware conductor. Failure inventory: docs/GUEST-STOP-PROBE-20261018.md.
"""
import argparse, hashlib, json, secrets, struct, subprocess, sys, time
from pathlib import Path
from source_text import source_files
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'probes'))
import run
MAGIC=0x31504f5453474c45
WORK_BYTES=16*1024*1024

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(v,message):
    if not v:raise RuntimeError(message)

def decode(blob):
    w=struct.unpack('<512Q',blob[:4096])
    names='status entered magic version mode start end hz context_bytes request owner stopped lifecycle reusable loop loop_end last_event last_pc setup_error finish first_cval budget'.split()
    d=dict(zip(names,w));d['native_before']=w[22:26];d['native_after']=w[26:30]
    en='state source reason detail requested_delay accepted_delay request_ticks deadline fire_ticks request_cpu request_pc fire_cpu refusals last_refusal duplicates host_polls host_next_poll host_armed host_status host_errors host_in_call outcome'.split()
    d['early']=dict(zip(en,w[30:60]));d['cpu']=[w[60+i*8:68+i*8] for i in range(6)]
    d['secondary']=[w[108+i*37:145+i*37] for i in range(6)]
    d['el1_before']=w[330:332];d['el1_after']=w[332:334]
    d['retirement_start'],d['retirement_end'],d['retirement_ok']=w[334:337]
    if d['hz']:
        d['elapsed_seconds']=(d['end']-d['start'])/d['hz']
        d['first_arm_seconds']=(d['first_cval']-d['start'])/d['hz']
        d['retirement_seconds']=(d['retirement_end']-d['retirement_start'])/d['hz']
    return d

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--qemu',action='store_true')
    ap.add_argument('--case',choices=('normal','reserved-peer','thermal-retirement'),default='normal')
    args=ap.parse_args();out=args.output.resolve()
    if args.case!='normal' and not args.qemu:ap.error('failure stages are QEMU-only')
    if out.exists():ap.error('output directory must be new')
    out.mkdir(parents=True)
    sources=[R/'tools/guest-stop-probe.S',R/'tools/guest-stop-probe.c',*[R/s for s in run.MULTI['xnuboot'][2:]]]
    inputs=sorted(set(sources+[R/'probes/xnuboot.c',R/'probes/xnuboot.S',R/'probes/run.py',Path(__file__).resolve(),R/'docs/GUEST-STOP-PROBE-20261018.md']+list((R/'compat').glob('*.h'))+list((R/'shadow').glob('*.h'))+list((R/'probes').glob('*.h'))))
    inputs=sorted(set(inputs+[q for p in inputs if p.suffix=='.c' for q in source_files(p)[1:]]))
    receipt=dict(status='BUILDING',scope='Real monitor EL1 timer/vectors/async/service stop; minimal guest setup and CPU0 report; no XNU or GPU',source_sha256={str(p):sha(p) for p in inputs},flags=run.FLAGS,qemu=args.qemu,case=args.case)
    def save():(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    save()
    linker=out/'probe.ld'
    linker.write_text((R/'probes/probe.ld').read_text().replace('ENTRY(_start)','ENTRY(guest_stop_entry)').replace('*(.text.entry)','*(.text.guest_stop_entry)\n        *(.text.entry)'))
    with (out/'build.log').open('w') as log:
        objects=[]
        for i,src in enumerate(sources):
            obj=out/f'{i:02}-{src.stem}.o';objects.append(str(obj))
            subprocess.run([str(run.LLVM/'clang'),*run.FLAGS,'-I'+str(R/'shadow'),'-I'+str(R.parent/'q1n1/platform/uefi'),'-c',str(src),'-o',str(obj)],check=True,stdout=log,stderr=log)
        elf=out/'probe.elf';binary=out/'probe.bin'
        subprocess.run([run.LLD,'-T',str(linker),'-o',str(elf),*objects],check=True,stdout=log,stderr=log)
        subprocess.run([str(run.LLVM/'llvm-objcopy'),'-O','binary',str(elf),str(binary)],check=True,stdout=log,stderr=log)
    blob=binary.read_bytes();require(0<len(blob)<run.OUT_AT-run.CODE_AT,'code exceeds reserved slot')
    receipt.update(status='BUILT_NOT_RUN',binary_sha256=sha(binary),binary_bytes=len(blob),linker_sha256=sha(linker),native_entry=dict(call='P_CALL(code, out, work, 0x1000000, request)',request_words='magic, mode, host_call, host_state, session, nonce, secondary_config[20]',magic=hex(MAGIC),mode_1='CPU0 actual q1n1 host call; cpus all zero',mode_2='one secondary only; exact current secondary_config with mask=2',budget_seconds=2,unknown_call_rule='NO further target I/O after unknown call; no readback, restore, retries or discovery',restore_rule='Only after terminal call and reusable lifecycle, fresh PSCI OFF for launched CPUs, native register checks: restore exact saved scratch and verify bytes'))
    save()
    if not args.qemu:
        print(json.dumps({k:receipt[k] for k in ['status','binary_sha256','binary_bytes']}));return
    receipt['qemu_efi_sha256']=sha(R.parent/'q1n1/build/uefi/q1n1.efi');save()
    proxy=None;unknown=False
    try:
        with run.Qemu(R) as path:
            proxy=run.connect(path,tries=60);info=proxy.bootinfo();receipt['bootinfo']=info
            require(info['current_el']==2,'QEMU did not enter EL2')
            base=info['heap_base'];code=base+run.CODE_AT;result=base+run.OUT_AT;request=base+0x480000;work=base+run.WORK_AT
            require(work+WORK_BYTES<=base+info['heap_size'],'work exceeds QEMU heap')
            nonce=secrets.randbits(64) or 1;session=secrets.randbits(64) or 1
            mode={'normal':0,'reserved-peer':3,'thermal-retirement':4}[args.case]
            req=struct.pack('<26Q',MAGIC,mode,0,0,session,nonce,*([0]*20))
            (out/'request.bin').write_bytes(req)
            proxy.writemem(code,blob);require(proxy.readmem(code,len(blob))==blob,'upload mismatch');proxy.flush_code(code,len(blob))
            proxy.writemem(result,bytes(8192));proxy.writemem(request,req)
            receipt.update(status='CALL_IN_FLIGHT',nonce=nonce,session=session,addresses=dict(code=code,result=result,request=request,work=work));save()
            unknown=True;start=time.monotonic();status=proxy.call(code,result,work,WORK_BYTES,request,timeout=8);unknown=False
            receipt['host_elapsed_seconds']=time.monotonic()-start;receipt['call_status']=status
            raw=proxy.readmem(result,8192);(out/'result.bin').write_bytes(raw);receipt['report_sha256']=sha(out/'result.bin')
            d=decode(raw);receipt['report']=d
            # A stale pass or a watchdog fallback cannot satisfy this oracle.
            conditions=dict(call_returned=status==0,entered=d['entered']==1,identity=d['magic']==MAGIC and d['version']==1,
                host_stop=d['early']['state']==3 and d['early']['source']==2 and d['early']['detail']==nonce and d['early']['outcome']==1,
                timely=d.get('elapsed_seconds',99)<1,first_arm=d.get('first_arm_seconds',99)<0.1,
                real_irq=d['cpu'][0][0]>0,el1_loop=d['loop']<=d['cpu'][0][1]<d['loop_end'] and d['cpu'][0][2]&31==5,
                lifecycle=d['owner']==0 and d['reusable']==1 and d['stopped']==(1<<32|1) and d['finish']==0,
                no_fault=d['setup_error']==0 and all(c[3]==0 for c in d['cpu']),
                native_restored=d['native_before'][:2]==d['native_after'][:2] and d['native_before'][3]==d['native_after'][3] and d['native_before'][2]&3==d['native_after'][2]&3 and d['el1_before']==d['el1_after'])
            if args.case!='normal':
                # QEMU owns/discards this entire machine: inspect its known
                # quarantine result here. The native conductor freezes before
                # any such read on an actual target.
                conditions=dict(quarantine_status=status==d['status']==0x51554e01,
                    entered=d['entered']==1 and d['setup_error']==0,
                    identity=d['magic']==MAGIC and d['version']==1 and d['mode']==mode,
                    real_irq=d['cpu'][0][0]>0,
                    el1_loop=d['loop']<=d['cpu'][0][1]<d['loop_end'] and d['cpu'][0][2]&31==5,
                    reservation_retained=d['owner']==0 and d['lifecycle']==(1<<63|3|8) and d['reusable']==0 and d['retirement_ok']==0,
                    private_fault=d['cpu'][0][3]==9 and d['finish']==0,
                    native_restored=conditions['native_restored'],
                    bounded=(.9<=d['retirement_seconds']<1.25 if mode==3 else 0<=d['retirement_seconds']<.1),
                    no_shared_report=not any(d['early'].values()) and d['last_event']==0)
                if mode==4:conditions['thermal_trip_retained']=struct.unpack_from('<Q',raw,4096+10*8)[0]==1
            receipt['checks']=conditions;receipt['status']='QEMU_PASS' if all(conditions.values()) else 'QEMU_FAIL';save()
            print(json.dumps(dict(status=receipt['status'],checks=conditions,elapsed=d.get('elapsed_seconds'),first_arm=d.get('first_arm_seconds'),report_sha256=receipt['report_sha256'])))
            if not all(conditions.values()):raise RuntimeError('QEMU acceptance failed; inspect receipt/result')
    except BaseException as e:
        receipt['error']=str(e)
        if unknown:receipt['status']='UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO'
        elif receipt['status'] not in ('QEMU_PASS','QEMU_FAIL'):receipt['status']='FAILED'
        save();raise
    finally:
        # QEMU owns and closes the emulator process/socket. Never issue a
        # protocol operation as cleanup after an unknown call result.
        pass

if __name__=='__main__':main()
