#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded CPU0-only operator-stop integration; never boots XNU or uses the GPU.

--qemu checks the AArch64 ABI with local injection, not USB-NCM.
--idle --device udp://en6 --generation N --image-base BASE exercises actual
NCM. --delayed-host additionally requires replacement of an already delivered
120-second host request. All modes retain raw artifacts in a new directory.
Failure inventory: docs/OPERATOR-STOP-CONTROLS-20261018.md.
"""
import argparse, fcntl, hashlib, importlib.util, json, secrets, struct, subprocess, sys, threading, time
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'tools'),str(R/'probes')]
import run
from cycle_lib.common import Workspace, require_exclusive, need, serror_clear

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--qemu',action='store_true')
    ap.add_argument('--idle',action='store_true');ap.add_argument('--device');ap.add_argument('--generation',type=int)
    ap.add_argument('--image-base',type=lambda x:int(x,0));ap.add_argument('--delayed-host',action='store_true')
    args=ap.parse_args()
    if args.output.exists():ap.error('output exists')
    if not args.qemu and not(args.idle and args.device and args.generation is not None and args.image_base is not None):ap.error('hardware requires explicit idle identity')
    if args.qemu and args.delayed_host:ap.error('QEMU has no NCM host replacement test')
    out=args.output.resolve();out.mkdir(parents=True)
    sources=[R/'tools/operator-stop-probe.c',R/'compat/early-stop.c',R/'compat/service-lock.c']
    record=dict(status='BUILDING',scope='CPU0 EL2 polling/return; no guest timer, SMP, GPU or power-off qualification',qemu=args.qemu,source_sha256={str(p):sha(p) for p in [*sources,R/'tools/qualify-operator-stop.py',R/'compat/early-stop.h',R/'compat/service-lock.h',R/'tools/request-stop.py']})
    def save():(out/'receipt.json').write_text(json.dumps(record,indent=2)+'\n')
    save()
    with (out/'build.log').open('w') as log:
        objs=[]
        for src in sources:
            obj=out/(src.stem+'.o');objs.append(str(obj))
            subprocess.run([str(run.LLVM/'clang'),*run.FLAGS,'-I'+str(R/'compat'),'-c',str(src),'-o',str(obj)],check=True,stdout=log,stderr=log)
        elf=out/'probe.elf';binary=out/'probe.bin'
        subprocess.run([run.LLD,'-T',str(R/'probes/probe.ld'),*objs,'-o',str(elf)],check=True,stdout=log,stderr=log)
        subprocess.run([str(run.LLVM/'llvm-objcopy'),'-O','binary',str(elf),str(binary)],check=True,stdout=log,stderr=log)
    blob=binary.read_bytes();need(len(blob)<0x10000,'probe exceeds scratch code slot')
    record['binary_sha256']=sha(binary);save()
    qemu=run.Qemu(R) if args.qemu else None
    path=qemu.__enter__() if qemu else args.device
    proxy=None; saved=None;unknown=False; sender=None;sender_cancel=threading.Event()
    with open('/tmp/snapintosh-hardware.lock','a') as lock:
        if not args.qemu:
            require_exclusive(Workspace(R));fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            proxy=run.connect(path,tries=60 if args.qemu else 1)
            info=proxy.bootinfo();record['bootinfo']=info
            need(info['current_el']==2,'not EL2')
            if not args.qemu:need(info['stage_generation']==args.generation and info['image_base']==args.image_base,'identity mismatch')
            record['guard_before']=proxy.serror_state();need(serror_clear(record['guard_before']),'preexisting SError')
            entry,state=run.call_service(proxy,info);need(entry and state,'no call service')
            prior=struct.unpack('<32Q',proxy.readmem(state,256));need(prior[3]==0,'call service is already armed')
            base=info['heap_base']+0x4a0000;result=base+0x10000;span=0x11000
            need(base+span<=info['heap_base']+info['heap_size'],'scratch outside heap')
            saved=proxy.readmem(base,span);(out/'scratch-before.bin').write_bytes(saved)
            proxy.writemem(base,blob);need(proxy.readmem(base,len(blob))==blob,'probe upload mismatch')
            proxy.flush_code(base,len(blob));proxy.writemem(result,bytes(4096))
            need(proxy.readmem(result,4096)==bytes(4096),'result clear mismatch')
            session=secrets.randbits(64) or 1;urgent=secrets.randbits(64) or 1
            record.update(session=hex(session),urgent_nonce=urgent,host_messages=[])
            if not args.qemu:
                spec=importlib.util.spec_from_file_location('request_stop',R/'tools/request-stop.py');wire=importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)
                def send_stop():
                    link=None
                    try:
                        if sender_cancel.wait(0.3):return
                        link=wire.Link(wire.interface_of(args.device))
                        sequence=([(120,secrets.randbits(64) or 1)] if args.delayed_host else [])+[(0,urgent)]
                        for delay,nonce in sequence:
                            if sender_cancel.is_set():return
                            packet=wire.encode(wire.STOP,nonce,session,1,delay,'bounded native stop qualification')
                            (out/f'request-{delay}.bin').write_bytes(packet)
                            started=time.time();reply=link.exchange(packet,nonce,0.3,3)
                            record['host_messages'].append(dict(delay=delay,nonce=nonce,sent=started,received=time.time(),reply=reply))
                            if reply is None or reply['session']!=session or not reply['mine']:return
                            if delay and sender_cancel.wait(0.3):return
                    except BaseException as e:record['sender_error']=repr(e)
                    finally:
                        if link:link.close()
                sender=threading.Thread(target=send_stop);sender.start()
            record.update(status='CALL_IN_FLIGHT',started=time.time());save();unknown=True
            returned=proxy.call(base,result,entry,session,int(args.qemu),timeout=8)
            unknown=False;record.update(call_return=returned,returned=time.time());save()
            if sender:sender.join(3);need(not sender.is_alive(),'stop sender did not terminate')
            need(not proxy.exceptions,'proxy recorded an exception')
            raw=proxy.readmem(result,4096);(out/'report.bin').write_bytes(raw)
            w=struct.unpack('<42Q',raw[:336]);head=dict(zip('magic status hz start end polls delivered stop_word local_mode delayed_delivered delayed_ticks urgent_ticks'.split(),w[:12]))
            names='state source reason detail requested_delay accepted_delay request_ticks deadline fire_ticks request_cpu request_pc fire_cpu refusals last_refusal duplicates host_polls host_next_poll host_armed host_status host_errors host_in_call outcome'.split()
            stop=dict(zip(names,w[12:34]));record.update(report=head,stop=stop)
            record['guard_after']=proxy.serror_state();need(serror_clear(record['guard_after']),'SError after probe')
            record['call_service_after']=list(struct.unpack('<32Q',proxy.readmem(state,256)))
            need(record['call_service_after'][3]==0,'service not disarmed')
            # Terminal P_CALL and clean guard permit scratch restoration, even on failed assertions.
            proxy.writemem(base,saved);proxy.request(proxy.P_DC_CVAC,base,len(saved))
            need(proxy.readmem(base,len(saved))==saved,'scratch restore mismatch');record['scratch_restored']=True;saved=None
            need(head['magic']==0x31504f5453504f and returned==head['status']==0,'probe did not stop on the request')
            need(head['hz']>0 and 0<head['end']-head['start']<4*head['hz'],'fallback/invalid duration')
            need(stop['state']==3 and stop['source']==2 and stop['accepted_delay']==0 and stop['outcome']==1,'stop record is not host FIRED/STOPPED')
            need(stop['detail']==(0x1234 if args.qemu else urgent),'wrong winning nonce')
            need(head['stop_word']==(1<<32)|1,'service stop word mismatch')
            if args.delayed_host:need(head['delivered']==2 and head['delayed_delivered']==1 and head['delayed_ticks']<head['urgent_ticks'],'delayed host request was not delivered before replacement')
            record.update(status='PASS',elapsed_seconds=(head['end']-head['start'])/head['hz'],hardware_verified=not args.qemu)
        except BaseException as e:
            record.update(status='UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO' if unknown else 'FAILED',error=repr(e));raise
        finally:
            sender_cancel.set()
            if sender:sender.join(3)
            if proxy:proxy.link.close()
            if qemu:qemu.__exit__(None,None,None)
            record['scratch_retained']=saved is not None
            record['artifacts_sha256']={p.name:sha(p) for p in out.iterdir() if p.is_file() and p.name!='receipt.json'};save()
    print(json.dumps({k:record[k] for k in ['status','scope','elapsed_seconds','hardware_verified','scratch_restored']}))
if __name__=='__main__':main()
