#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Single-owner native CPU0 EL1 stop conductor. No SMP option is exposed.

`check --candidate DIR` is entirely offline. `run` requires explicit idle
identity, a retained stage image and a QEMU-qualified exact candidate. All
normal operations use a16-control-guard; only the existing stop sideband is
allowed during the single guest P_CALL. See GUEST-STOP-PROBE-20261018.md.
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
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'probes')]
import run
import a16_thermal
from cycle_lib.common import Workspace, require_exclusive, need, serror_clear

def digest(data):return hashlib.sha256(data).hexdigest()
def file_digest(path):return digest(Path(path).read_bytes())
def module(name):return runpy.run_path(str(ROOT/'tools'/name))
probe=module('qualify-guest-stop.py')

def admit_candidate(path):
    path=Path(path).resolve();receipt=path/'receipt.json';r=json.loads(receipt.read_text())
    expected={'call_returned','entered','identity','host_stop','timely','first_arm','real_irq','el1_loop','lifecycle','no_fault','native_restored'}
    need(r.get('status')=='QEMU_PASS' and set(r.get('checks',{}))==expected and
         all(v is True for v in r['checks'].values()),'candidate lacks passing QEMU integration')
    binary=path/'probe.bin';blob=binary.read_bytes()
    need(digest(blob)==r['binary_sha256'] and len(blob)==r['binary_bytes'],'candidate binary hash/size mismatch')
    need(file_digest(path/'result.bin')==r['report_sha256'],'candidate raw report hash mismatch')
    need(0<len(blob)<run.OUT_AT-run.CODE_AT,'candidate exceeds code reservation')
    changed=[]
    for name,sha in r['source_sha256'].items():
        p=Path(name)
        # Documentation can accumulate receipts without changing the executable.
        if p.suffix in ('.c','.S','.h','.py') and file_digest(p)!=sha:changed.append(name)
    need(not changed,'candidate source drift: '+', '.join(changed))
    return blob,dict(path=str(path),receipt_sha256=file_digest(receipt),binary_sha256=digest(blob),
                     qemu_report_sha256=r['report_sha256'],compiled_sources=r['source_sha256'])

def thermal_report_checks(thermal,end,hz):
    """Final observation follows the runtime per-sensor one-second grace.

    valid_count/ready describe only the most recent poll. Initial guest
    admission is separately proven by entered=1/setup_error=0 in this exact
    candidate, which refuses ERET without a complete healthy first sample.
    """
    counts=(13,9,13,8,13,8,13,15)
    expected=[(1<<n)-1 for n in counts]
    if not thermal or hz!=19200000:return dict(present_and_clock=False)
    ages=[(end-thermal['last_valid'][b*16+n])&((1<<64)-1)
          for b,count in enumerate(counts) for n in range(count)]
    count=sum((mask&expected[b]).bit_count() for b,mask in enumerate(thermal['valid_mask']))
    return dict(no_trip=thermal['reason']==0 and thermal['trip_ticks']==0,
        all_sensors_seen=thermal['seen_mask']==expected,
        sensors_fresh=all(age<hz for age in ages),
        poll_fresh=((end-thermal['last_poll'])&((1<<64)-1))<hz,
        last_poll_consistent=thermal['valid_count']==count and thermal['missing_count']==92-count and
                             thermal['ready']==int(count==92) and all(
                                 mask&~expected[b]==0 for b,mask in enumerate(thermal['valid_mask'])),
        reader_healthy=thermal['read_failures']==0 and thermal['read_inflight']==0 and thermal['polls']>=1,
        below_ceiling=thermal['peak_mc'] is not None and -40000<=thermal['peak_mc']<60000,
        timing=thermal['max_gap_ticks']<hz and thermal['max_poll_ticks']<hz//4)

def report_checks(raw,nonce):
    d=probe['decode'](raw);e=d['early'];cpu=d['cpu'][0]
    thermal=a16_thermal.decode(raw[4096:4096+a16_thermal.SIZE])
    thermal_checks=thermal_report_checks(thermal,d['end'],d['hz'])
    if thermal is not None:thermal['qualification']=thermal_checks
    checks=dict(identity=d['magic']==probe['MAGIC'] and d['version']==1 and d['mode']==1,
        entered=d['status']==0 and d['entered']==1 and d['setup_error']==0,
        clock=d['hz']==19200000,
        host_stop=e['state']==3 and e['source']==2 and e['reason']==1 and e['detail']==nonce and
                  e['accepted_delay']==0 and e['requested_delay']==0 and e['outcome']==1 and e['fire_cpu']==1,
        timely=0<d.get('elapsed_seconds',99)<1 and 0<d.get('first_arm_seconds',99)<.1,
        real_irq=cpu[0]>0 and e['host_polls']>0,
        el1_loop=d['loop']<=cpu[1]<d['loop_end'] and cpu[2]&0x3df==0x3c5 and cpu[5]>0,
        lifecycle=d['owner']==0 and d['reusable']==1 and d['retirement_ok']==1 and d['lifecycle']==(1<<63|3) and
                  d['stopped']==(1<<32|1) and d['finish']==0,
        no_fault=d['last_event']==52 and all(c[3]==0 and c[6]==0 for c in d['cpu']) and
                 e['host_errors']==0 and e['host_in_call']==0 and e['refusals']==0,
        native_restored=d['native_before'][:2]==d['native_after'][:2] and
                        d['native_before'][3]==d['native_after'][3] and
                        d['native_before'][2]&3==d['native_after'][2]&3 and d['el1_before']==d['el1_after'],
        no_secondary=all(not any(s) for s in d['secondary']) and all(c[0]==0 and c[4]==0 for c in d['cpu'][1:]),
        thermal=all(thermal_checks.values()))
    return d,thermal,checks

def admission_temperature(policy,proxy,record,name,save,guard):
    """Require a single complete sample, bounded by attempts and wall time."""
    started=time.monotonic();attempts=[]
    admission=dict(name=name,maximum_seconds=.5,maximum_attempts=20,attempts=attempts,status='SAMPLING')
    record.setdefault('thermal_admission',[]).append(admission);save()
    try:
        for attempt in range(20):
            if attempt and time.monotonic()-started>=.5:break
            row=dict(attempt=attempt+1,started_elapsed=time.monotonic()-started)
            attempts.append(row);save()
            snapshot=policy['temperature_snapshot'](proxy,record,f'{name}-{attempt+1}',save,guard,minimum_valid=0)
            row.update(finished_elapsed=time.monotonic()-started,valid=snapshot['valid'],maximum=snapshot['maximum'],
                       temperature_index=len(record['temperatures'])-1)
            if (row['finished_elapsed']<=.5 and snapshot['valid']==92 and
                    snapshot['maximum'] is not None and snapshot['maximum']<45000):
                admission.update(status='COMPLETE',elapsed=time.monotonic()-started);save();return snapshot
            save()
            remaining=.5-(time.monotonic()-started)
            if remaining<=0:break
            time.sleep(min(.01,remaining))
        admission['status']='INCOMPLETE'
        raise RuntimeError('no complete cool 92-sensor sample within 0.5 seconds / 20 attempts')
    except BaseException as error:
        if attempts:
            attempts[-1].update(finished_elapsed=time.monotonic()-started,error=f'{type(error).__name__}: {error}')
        admission.update(status='FROZEN' if guard.frozen else 'REFUSED',error=f'{type(error).__name__}: {error}',
                         elapsed=time.monotonic()-started);save();raise

def setup_refusal_checks(d,thermal,request):
    """Prove the exact candidate's cool partial first-sample refusal only."""
    hz=d['hz'];counts=(13,9,13,8,13,8,13,15);expected=[(1<<n)-1 for n in counts]
    checks=dict(identity=d['magic']==probe['MAGIC'] and d['version']==1 and d['mode']==1 and d['request']==request,
        known_refusal=d['status']==0 and d['entered']==0 and d['setup_error']==8,
        clock=hz==19200000,
        no_guest_timer=d['first_cval']==0 and d['budget']==0,
        no_cpu_activity=all(all(value==0 for value in cpu[:7]) and cpu[7]==i for i,cpu in enumerate(d['cpu'])),
        no_secondary=all(not any(s) for s in d['secondary']),
        no_host_stop=not any(d['early'].values()) and d['last_event']==0 and d['last_pc']==0,
        lifecycle=d['owner']==0 and d['reusable']==1 and d['retirement_ok']==1 and
                  d['lifecycle']==(1<<63|3) and d['stopped']==(1<<32|1) and d['finish']==0,
        private_restored=d['native_before'][:2]==d['native_after'][:2] and
                         d['native_before'][3]==d['native_after'][3] and
                         d['native_before'][2]&3==d['native_after'][2]&3 and d['el1_before']==d['el1_after'],
        bounded=0<d.get('elapsed_seconds',99)<1 and 0<=d.get('retirement_seconds',99)<1,
        thermal_present=thermal is not None)
    if not thermal:return checks
    valid=thermal['valid_count'];masks=thermal['valid_mask'];seen=thermal['seen_mask']
    checks['initial_partial_sample']=(thermal['reason']==0 and thermal['trip_ticks']==0 and thermal['polls']==1 and
        thermal['ready']==0 and 0<=valid<92 and thermal['missing_count']==92-valid and
        thermal['invalid_samples']==92-valid and sum(mask.bit_count() for mask in masks)==valid and masks==seen and
        all(mask&~expected[b]==0 for b,mask in enumerate(masks)) and thermal['read_failures']==0 and
        thermal['read_inflight']==0 and thermal['max_gap_ticks']==0 and thermal['max_poll_ticks']<hz//4 and
        thermal['started']==d['start'] and thermal['last_poll']==d['start'] and
        thermal['version']==[0x30020000]*8 and
        all(control&1 and not control&2 and control&(1<<21) and ((control>>3)&0xffff)==expected[b]
            for b,control in enumerate(thermal['control'])))
    checks['initial_temperatures_cool']=(valid==0 and thermal['peak_mc'] is None and thermal['current_mc'] is None or
        0<valid<92 and thermal['peak_mc']==thermal['current_mc'] and -40000<=thermal['peak_mc']<45000)
    checks['initial_sensor_times']=all(thermal['last_valid'][b*16+n]==(d['start'] if masks[b]&(1<<n) else 0)
        for b,count in enumerate(counts) for n in range(count))
    return checks

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode',choices=('check','run'));ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--device');ap.add_argument('--generation',type=int)
    ap.add_argument('--image-base',type=lambda x:int(x,0));ap.add_argument('--heap-base',type=lambda x:int(x,0))
    ap.add_argument('--stage',type=Path);ap.add_argument('--idle',action='store_true')
    ap.add_argument('--output',type=Path)
    args=ap.parse_args();blob,candidate=admit_candidate(args.candidate)
    if args.mode=='check':
        print(json.dumps(dict(status='OFFLINE_CANDIDATE_VERIFIED',candidate=candidate['path'],sha256=digest(blob),bytes=len(blob))))
        return 0
    need(args.idle and args.device and args.generation is not None and args.image_base is not None and
         args.heap_base is not None and args.stage and args.output,'run requires --idle, explicit device/generation/image-base/heap-base/stage/output')
    wire=module('request-stop.py');interface=wire['interface_of'](args.device)
    stage=args.stage.resolve().read_bytes();need(len(stage)>=8192,'stage reference is too short')
    out=args.output.resolve();need(not out.exists(),'output exists; captures cannot be overwritten')
    require_exclusive(Workspace(ROOT));out.mkdir(parents=True)
    policy=module('qualify-a16-cpu-policy.py');clock=policy['clock']
    guard_module=module('a16-control-guard.py');cpu_module=module('probe-a16-cpus.py')
    sources=['tools/run-guest-stop-native.py','tools/a16-control-guard.py','tools/request-stop.py',
             'tools/qualify-guest-stop.py','tools/qualify-a16-cpu-policy.py','tools/a16-thermal-survey.py',
             'tools/a16_thermal.py','tools/measure-a16-cpu-clock.py','tools/probe-a16-cpus.py',
             'tools/a16-cpu-perf.py','tools/cycle_lib/common.py','probes/psci-info.S','probes/run.py']
    record=dict(schema='guest-stop-native-v1',status='PREPARING',started=time.time(),
                scope='CPU0 real EL1 timer/stop only; no secondary/XNU/GPU',candidate=candidate,
                source_sha256={n:file_digest(ROOT/n) for n in sources},
                stage=dict(path=str(args.stage.resolve()),sha256=digest(stage)),
                requested_identity=dict(generation=args.generation,image_base=args.image_base,heap_base=args.heap_base),
                battery_policy='AC connected and plausible battery report required',host_messages=[])
    journal_lock=threading.RLock()
    def save():
        with journal_lock:
            path=out/'receipt.json';temporary=out/'receipt.tmp'
            with temporary.open('w') as stream:
                stream.write(json.dumps(record,indent=2)+'\n');stream.flush();os.fsync(stream.fileno())
            temporary.replace(path)
            fd=os.open(out,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)
    def artifact(name,data):
        with (out/name).open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        record.setdefault('artifacts_sha256',{})[name]=digest(data);save()
    save();artifact('probe.bin',blob)
    psci=run.build('psci-info',out/'inventory');record['inventory_binary_sha256']=digest(psci);save()
    guard=None;raw_proxy=None;close_raw_link=None;scratch=None;sender=None;cancel=threading.Event();guest_called=False;terminal=False;strict_changed=False
    with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            # Explicit single connection; no retries or subsequent discovery.
            raw_proxy=run.connect(args.device,tries=1)
            # Retain the original host-only close before the constructor wraps
            # the link. A constructor journal failure must not leak the socket.
            close_raw_link=raw_proxy.link.close
            guard=guard_module['ControlGuard'](raw_proxy,record,save)
            proxy=guard.proxy
            info=proxy.bootinfo();record['bootinfo']=info;a16_thermal.admit_target(info)
            need(info['stage_generation']==args.generation and info['image_base']==args.image_base and
                 info['heap_base']==args.heap_base and info['heap_size']>=0x1500000,'resident identity/heap mismatch')
            resident=proxy.readmem(info['image_base']+0x1000,4096,live=True)
            artifact('resident-code-page.bin',resident)
            record['resident_code_fingerprint']=dict(address=info['image_base']+0x1000,bytes=4096,
                stage_offset=0x1000,stage_end_offset=0x2000,sha256=digest(resident),
                stage_reference_sha256=digest(stage),scope='one immutable code page; not full resident byte identity')
            save()
            need(resident==stage[0x1000:0x2000],'resident immutable code page differs from stage')
            record['serror_before']=proxy.serror_state();need(serror_clear(record['serror_before']),'preexisting SError')
            proxy.serror_strict(True)
            strict_changed=True
            battery_status=proxy.call(info['battery_call'],0,0,0,0,0,timeout=12)
            if battery_status!=0:
                guard.freeze('native battery call returned unexpected status');raise RuntimeError(guard.reason)
            battery=proxy.live_battery_record(info['battery_result']);record['battery']=dict(battery,native_return=battery_status);save()
            need(battery['plausible'] and battery['ac'],'native EL1 qualification requires AC and plausible battery')
            admission_temperature(policy,proxy,record,'initial',save,guard)
            entry,state=run.call_service(proxy,info);need(entry and state,'call service is unavailable')
            record['call_service_before']=list(struct.unpack('<32Q',proxy.readmem(state,256)))
            need(record['call_service_before'][3]==0,'call service already armed')
            base=info['heap_base'];code=base+run.CODE_AT;result=base+run.OUT_AT;request=base+0x480000;work=base+run.WORK_AT
            scratch=clock['Scratch'](proxy,[(code,0x1500000-run.CODE_AT)])
            for i,(address,data) in enumerate(scratch.saved):
                artifact(f'scratch-before-{i}.bin',data)
            record['scratch_ranges']=[dict(address=a,bytes=len(d),sha256=digest(d)) for a,d in scratch.saved];save()
            try:inventory=cpu_module['collect'](proxy,psci,True)
            except BaseException as e:
                guard.freeze('native CPU inventory not verified: '+str(e));raise
            record['inventory']=inventory;states=clock['cpu_states'](inventory);save()
            if not (inventory['boot_mpidr']=='0x0' and len(states)==18 and
                    all(s==(0 if m==0 else 1) for m,s in states.items())):
                guard.freeze('idle claim contradicted: require boot CPU0 ON and 17 peers OFF');raise RuntimeError(guard.reason)
            session=secrets.randbits(64) or 1;nonce=secrets.randbits(64) or 1
            req=struct.pack('<26Q',probe['MAGIC'],1,entry,state,session,nonce,*([0]*20))
            artifact('request.bin',req)
            record.update(session=session,nonce=nonce,addresses=dict(code=code,result=result,request=request,work=work));save()
            proxy.writemem(code,blob);need(proxy.readmem(code,len(blob))==blob,'code readback mismatch');proxy.flush_code(code,len(blob))
            proxy.writemem(result,bytes(8192));need(proxy.readmem(result,8192)==bytes(8192),'result clear mismatch')
            proxy.writemem(request,req);need(proxy.readmem(request,len(req))==req,'request readback mismatch')
            admission_temperature(policy,proxy,record,'immediately-before-entry',save,guard)
            stop_packet=wire['encode'](wire['STOP'],nonce,session,1,0,'bounded native EL1 stop qualification')
            artifact('stop-request.bin',stop_packet)
            def send_stop():
                link=None
                try:
                    if cancel.wait(.3) or guard.frozen:return
                    link=wire['Link'](interface)
                    if cancel.is_set() or guard.frozen:return
                    sent=time.time();reply=link.exchange(stop_packet,nonce,.5,1)
                    with journal_lock:
                        record['host_messages'].append(dict(sent=sent,received=time.time(),reply=reply));save()
                except BaseException as e:
                    with journal_lock:record['sender_error']=repr(e);save()
                finally:
                    if link:link.close()
            scratch.keep('guest P_CALL issued; exact terminal/quiescence oracle not yet verified')
            record['status']='CALL_IN_FLIGHT';save()
            sender=threading.Thread(target=send_stop,name='guest-stop-sideband');sender.start()
            guest_called=True
            returned=proxy.call(code,result,work,probe['WORK_BYTES'],request,timeout=8)
            cancel.set();sender.join(2)
            if returned!=0 or sender.is_alive():
                guard.freeze('guest native completion or sideband termination not verified');raise RuntimeError(guard.reason)
            record['call_return']=returned;save()
            raw=proxy.readmem(result,8192);artifact('result.bin',raw)
            try:d,thermal,checks=report_checks(raw,nonce)
            except BaseException as e:
                guard.freeze('native report malformed: '+str(e));raise
            record.update(report=d,thermal=thermal,checks=checks);save()
            replies=record['host_messages']
            reply=replies[0]['reply'] if len(replies)==1 else None
            checks['sideband_ack']=bool(reply and reply['op']==wire['STOP'] and reply['nonce']==nonce and
                reply['session']==session and reply['status']==0 and reply['mine'] and reply['latched'] and reply['latch_nonce']==nonce)
            refusal=setup_refusal_checks(d,thermal,request)
            record['setup_refusal_checks']=refusal
            known_refusal=all(refusal.values()) and not replies and not record.get('sender_error')
            if not all(checks.values()) and not known_refusal:
                guard.freeze('native stop oracle failed: '+', '.join(k for k,v in checks.items() if not v));raise RuntimeError(guard.reason)
            record['serror_after']=proxy.serror_state()
            if not serror_clear(record['serror_after']) or proxy.exceptions or proxy.get_exc_count():
                guard.freeze('native report returned with exception evidence');raise RuntimeError(guard.reason)
            record['call_service_after']=list(struct.unpack('<32Q',proxy.readmem(state,256)))
            if record['call_service_after'][3]!=0:
                guard.freeze('call service was not disarmed');raise RuntimeError(guard.reason)
            terminal=True;scratch.release()
            record['status']='CPU0_NATIVE_ADMISSION_REFUSED' if known_refusal else 'CPU0_NATIVE_STOP_VERIFIED';save()
        except BaseException as e:
            record['status']='FROZEN_NO_FURTHER_TARGET_IO' if guard and guard.frozen else 'REFUSED_OR_FAILED'
            record['error']=f'{type(e).__name__}: {e}'
        finally:
            cancel.set()
            if sender:sender.join(2)
            if guard:
                try:
                    if guest_called and not terminal and not guard.frozen:
                        guard.freeze('guest did not reach a verified terminal state')
                    if scratch:record['scratch']=guard.restore_scratch(scratch)
                    if not guard.frozen and strict_changed:
                        proxy.serror_strict(bool(record.get('serror_before',{}).get('flags',0)&1))
                except BaseException as e:
                    record.setdefault('cleanup_errors',[]).append(str(e));record['status']='FROZEN_NO_FURTHER_TARGET_IO' if guard.frozen else 'REFUSED_OR_FAILED'
                finally:guard.close()
            elif close_raw_link is not None:
                try:close_raw_link() # host resource release only, including constructor failure
                except BaseException as e:record.setdefault('cleanup_errors',[]).append('local link close: '+str(e))
            record['finished']=time.time();save()
    print(json.dumps({k:record.get(k) for k in ('status','error','scratch','cleanup_errors')}))
    return 0 if record['status']=='CPU0_NATIVE_STOP_VERIFIED' and record.get('scratch',{}).get('restored') else 1

if __name__=='__main__':sys.exit(main())
