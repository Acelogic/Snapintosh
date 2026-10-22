# SPDX-License-Identifier: MIT
"""Single-peer admission/report helpers; no connection or CPU_ON operation."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import time

ROOT=Path(__file__).resolve().parents[1]
need=lambda condition,message:None if condition else (_ for _ in ()).throw(ValueError(message))
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
def module(name):return runpy.run_path(str(ROOT/'tools'/name))

def prerequisites(cpu0_path,policy_path):
    cpu0_path=Path(cpu0_path).resolve();policy_path=Path(policy_path).resolve()
    cpu0=json.loads(cpu0_path.read_text());policy=json.loads(policy_path.read_text())
    need(cpu0['status']=='CPU0_NATIVE_STOP_VERIFIED' and len(cpu0['checks'])==13 and
         all(v is True for v in cpu0['checks'].values()),'requires exact successful native CPU0 stop')
    need(sha(cpu0_path.parent/'result.bin')==cpu0['artifacts_sha256']['result.bin'],'CPU0 raw result changed')
    need(cpu0['call_return']==0 and cpu0['scratch']['restored'] and
         not cpu0['control_guard']['frozen'] and cpu0['control_guard']['closed'],'CPU0 terminal not healthy/restored')
    need(policy['status']=='CPU0_CHARACTERIZED_CAP_VERIFIED' and policy['final_conservative_policy_verified'] and
         policy['scratch']['restored'] and not policy['control_guard']['frozen'] and policy['control_guard']['closed'],
         'requires healthy conservative CPU0 policy characterization')
    final=policy['measurements']['final-cap']
    need(final['affinity']=='0x0' and final['stable'] and final['ghz_max']<=2 and
         all(final['pmu']['restored'].values()),'CPU0 current policy is not a measured conservative cap')
    identity=('stage_generation','image_base','heap_base','heap_size','timer_hz','current_el')
    need(all(cpu0['bootinfo'][k]==policy['bootinfo'][k] for k in identity),'prerequisites identify different stages')
    need(cpu0['resident_code_fingerprint']['sha256']==policy['resident_code']['sha256'],'prerequisite code fingerprint differs')
    need(0<=time.time()-policy['finished']<3600 and 0<=time.time()-cpu0['finished']<3600,
         'prerequisites exceed the one-hour bounded control-session window')
    for record,path,key in ((cpu0,cpu0_path,'source_sha256'),(policy,policy_path,'sources')):
        for name,digest in record[key].items():
            stored=path.parent/'sources'/name.replace('../','sibling/')
            need(stored.is_file() and sha(stored)==digest,'prerequisite source snapshot missing/changed: '+name)
    history=[]
    for name,target in [('gen1-coldboot-before-2.json',3.072),('gen1-after-setmax.json',3.6096)]:
        path=ROOT/'build/cpu-clock-records'/name;record=json.loads(path.read_text())
        cpus={c['affinity']:c for c in record['cpus']}
        need(record['scratch']['restored'] and all(abs(cpus[a]['ghz_median']-target)<.001 for a in ('0x0','0x100')),
             'retained CPU0/CPU1 domain correspondence missing')
        history.append(dict(path=str(path),sha256=sha(path),cpu0_ghz=cpus['0x0']['ghz_median'],cpu1_ghz=cpus['0x100']['ghz_median']))
    return dict(cpu0=dict(path=str(cpu0_path),sha256=sha(cpu0_path)),policy=dict(path=str(policy_path),sha256=sha(policy_path)),
        identity={k:cpu0['bootinfo'][k] for k in identity},code_page_sha256=cpu0['resident_code_fingerprint']['sha256'],
        policy_final=policy['final_policy'],cpu0_measured_ghz=final['ghz_median'],historical_domain_evidence=history,
        peer_frequency_scope='Affinity0x100 historically tracks PDP0; current peer frequency is inferred from shared domain, not physically measured in this run')

def gic_snapshot(proxy,redist):
    return dict(group=proxy.read32(redist+0x10080),priority=proxy.read8(redist+0x1041a),
        enable=proxy.read32(redist+0x10100),pending=proxy.read32(redist+0x10200),active=proxy.read32(redist+0x10300),
        config=proxy.read32(redist+0x10c04),waker=proxy.read32(redist+0x14))

def prepare(proxy,guard,inventory,info,memory_blob,addresses,code_bytes,work_bytes,record,save):
    need(os.environ.get('SNAP_SMP_PRIME','0')=='0','mode2 requires no Prime relocation')
    runtime=module('secondary-runtime.py');mapping=module('host-el2-mapping.py')
    try:memory=module('probe-el2-memory.py')['collect'](proxy,memory_blob)
    except BaseException as error:
        guard.freeze('SMP EL2 regime inventory not verified: '+str(error));raise
    words=runtime['config_words'](inventory,memory,mask=2)
    need(words[2]==0 and words[3]==2 and words[9]==0x100 and not any(words[10:14]),'unexpected physical CPU route')
    redist=words[15];before=gic_snapshot(proxy,redist)
    need(proxy.read64(redist+8)>>32==0x100 and proxy.read32(0x17000000)&0x80000012==0x12 and
         before['enable']==0 and not (before['pending']|before['active'])&(1<<26) and not before['config']&(1<<21),
         'peer GIC is not idle and affinity routed')
    stride,size=info['memory_map_stride'],info['memory_map_size']
    need(stride>=40 and 0<size<=1024*1024 and size%stride==0,'invalid firmware memory map')
    raw=proxy.readmem(info['memory_map'],size,live=True);ram=[]
    for offset in range(0,size,stride):
        kind,pa,_,pages,_=struct.unpack_from('<I4xQQQQ',raw,offset)
        if kind in (1,2,3,4,5,6,7,9,10) and pages:ram.append((pa,pa+pages*4096))
    cache={}
    def read(pa,length):
        page=pa&~4095
        if page not in cache:cache[page]=proxy.readmem(page,4096,live=True)
        return cache[page][pa-page:pa-page+length]
    ranges=[('code',addresses['code'],code_bytes,False),('report',addresses['result'],8192,False),
        ('request',addresses['request'],4096,False),('runtime',addresses['work'],work_bytes,False),
        ('GICD',0x17000000,4096,True),('GICR1',redist,4096,True),('GICR1-SGI',redist+0x10000,4096,True)]
    witness=mapping['verify'](read,memory,ranges,ram)
    if proxy.exceptions:
        guard.freeze('exception evidence during SMP mapping admission');raise RuntimeError(guard.reason)
    for page in witness['table_pages']:proxy.request(proxy.P_DC_CVAC,int(page,16),4096)
    result=dict(configuration=list(words),memory=memory,gic_before=before,host_mapping=witness,
        layout=dict(vcpus_offset=runtime['VCPUS_OFFSET'],vcpu_size=runtime['VCPU_SIZE']))
    record['smp_admission']=result;save();return result

def report_checks(d,thermal_checks,nonce,admission,addresses):
    fields=module('secondary-runtime.py')['FIELDS'];s=dict(zip(fields,d['secondary'][1]));words=admission['configuration']
    e=d['early'];hz=d['hz'];work=addresses['work'];layout=admission['layout']
    checks=dict(identity=d['mode']==2 and d['request']==addresses['request'],
        entered=d['status']==0 and d['entered']==1 and d['setup_error']==0,clock=hz==19200000,
        host_stop=e['state']==3 and e['source']==2 and e['reason']==1 and e['detail']==nonce and
            e['accepted_delay']==0 and e['requested_delay']==0 and e['outcome']==1 and e['fire_cpu'] in (1,2) and
            d['stopped']==(1<<32|e['fire_cpu']),
        timely=0<d.get('elapsed_seconds',99)<1 and 0<d.get('first_arm_seconds',99)<.15,
        both_el1=all(cpu[0]>0 and d['loop']<=cpu[1]<d['loop_end'] and cpu[2]&0x3df==0x3c5 and cpu[5]>0 for cpu in d['cpu'][:2]),
        lifecycle=d['owner']==0 and d['reusable']==1 and d['retirement_ok']==1 and d['lifecycle']==(1<<63|3) and d['finish']==0,
        no_fault=all(c[3]==0 and c[6]==0 for c in d['cpu']) and e['host_errors']==0 and e['host_in_call']==0 and e['refusals']==0,
        private_restored=d['native_before'][:2]==d['native_after'][:2] and d['native_before'][3]==d['native_after'][3] and
            d['native_before'][2]&3==d['native_after'][2]&3 and d['el1_before']==d['el1_after'],
        peer_identity=s['affinity']==words[9] and s['redistributor']==words[15] and s['observed_affinity']==words[9] and
            s['cpu']==work+layout['vcpus_offset']+layout['vcpu_size'] and
            work<=s['stack']-0x10000<=s['observed_sp']<s['stack']<=work+0x1000000 and s['observed_sp']%16==0,
        peer_regime=[s[k] for k in ('sctlr','tcr','ttbr0','mair')]==words[4:8] and
            [s[k] for k in ('observed_sctlr','observed_tcr','observed_ttbr0','observed_mair')]==words[4:8],
        peer_retired=s['phase']==4 and s['error']==0 and s['on_result']==0 and s['off_result']==(1<<64)-1 and
            s['affinity_result']==1 and s['prepare_result']==0 and s['entered']==1 and s['finish_result']==0 and s['gic_saved']==1 and s['cleanup']==1,
        no_extra_peer=all(not any(s) for i,s in enumerate(d['secondary']) if i!=1) and
            all(c[0]==0 and c[4]==0 for c in d['cpu'][2:]),thermal=all(thermal_checks.values()))
    return s,checks

def verify_after(proxy,guard,cpu_collect,psci_blob,clock,admission,record,save):
    try:inventory=cpu_collect(proxy,psci_blob,True)
    except BaseException as error:
        guard.freeze('SMP post-stop physical OFF query unverified: '+str(error));raise
    record['smp_post_inventory']=inventory;save();states=clock['cpu_states'](inventory)
    if inventory['boot_mpidr']!='0x0' or len(states)!=18 or not all(s==(0 if m==0 else 1) for m,s in states.items()):
        guard.freeze('SMP post-stop inventory does not prove CPU0 ON and all17 peers OFF');raise RuntimeError(guard.reason)
    after=gic_snapshot(proxy,admission['configuration'][15]);before=admission['gic_before']
    record['smp_gic_after']=after;save()
    if not (after['group']==before['group'] and after['priority']==before['priority'] and
            after['waker']&2==before['waker']&2 and after['enable']==0 and not (after['pending']|after['active'])&(1<<26)):
        guard.freeze('SMP peer GIC restoration not verified');raise RuntimeError(guard.reason)
