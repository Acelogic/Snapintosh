# SPDX-License-Identifier: MIT
"""Fresh A16 firmware/mapping admission and full-monitor secondary evidence.

Called by run.py on the same proxy connection; never issues CPU_ON itself.
The full monitor owns launch, stop and OFF collection during its single call.
"""
import json
import os
from pathlib import Path
import runpy
import struct

ROOT=Path(__file__).resolve().parents[1]
MAGIC=0x31504d5350414e53
LAYOUT=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
HOST_CPUS_OFFSET=LAYOUT.offset('context','host_cpus')
SECONDARY_BASE_OFFSET=LAYOUT.offset('context','secondary_base')
VCPUS_OFFSET=LAYOUT.offset('context','vcpus')
SERVICES_OFFSET=LAYOUT.offset('context','services')
VCPU_SIZE=LAYOUT.size('vcpu')
FIELDS=('sctlr','tcr','ttbr0','mair','cpu','stack','affinity','redistributor',
        'vectors','callback','stop_callback','phase','error','observed_affinity',
        'observed_sp','group','priority','waker','gic_saved','cleanup',
        'on_result','off_result','affinity_result','prepare_result','entered','finish_result',
        'observed_sctlr','observed_tcr','observed_ttbr0','observed_mair',
        'active_vncr','active_vmpidr','active_vttbr',
        'initial_cpacr','initial_cptr','final_cpacr','final_cptr')
PRIME_CLUSTER=0x10000     # SNAP_SMP_PRIME: the A16's first Prime cluster, six cores
CLUSTER=0xff00ff0000      # MPIDR Aff3:Aff2
# Record page 0 after the 37 record words (probes/xnuboot.c struct boot_relocation, -DSNAP_BOOT_RELOCATE=1):
# word offsets, checked against Clang's layout by tools/test-boot-relocate.py.
RELOCATION_WORDS=dict(armed=37,launched=38,handed_back=39,captured=40,launch_tick=41,handback_tick=42,
                      stop_requested=43,quarantined=44,wait_polls=45,id_mismatch=46,boot_cntvoff=47,
                      target_cntvoff=48,boot_cntfrq=49,target_cntfrq=50,host=51,boot_cache=62,
                      target_cache=64,boot_id=66,target_id=76,relay=88)
# compat/boot-relocate.h BOOT_RELOCATE_ID_REGS, in order (the test pins it); CACHE_NAMES: boot_cache/target_cache.
BOOT_ID_NAMES=('MIDR_EL1','ID_AA64PFR0_EL1','ID_AA64PFR1_EL1','ID_AA64DFR0_EL1','ID_AA64ISAR0_EL1',
               'ID_AA64ISAR1_EL1','ID_AA64ISAR2_EL1','ID_AA64MMFR0_EL1','ID_AA64MMFR1_EL1','ID_AA64MMFR2_EL1')
CACHE_NAMES=('ctr','dczid')
RELAY_FIELDS=('request','done','op','a1','a2','a3','result','abandoned','in_call','served','refused','max_ticks')
RELOCATION_SIZE=RELOCATION_WORDS['relay']+len(RELAY_FIELDS)


def decode_relocation(words):
    """struct boot_relocation from its first RELOCATION_SIZE words; None when record page 0 is not armed."""
    if len(words)<RELOCATION_SIZE or not words[RELOCATION_WORDS['armed']]:return None
    w=RELOCATION_WORDS;row=dict(zip(FIELDS,words[:37]))
    for name in ('armed','launched','handed_back','captured','launch_tick','handback_tick','stop_requested',
                 'quarantined','wait_polls','id_mismatch','boot_cntvoff','target_cntvoff','boot_cntfrq',
                 'target_cntfrq'):row[name]=words[w[name]]
    ids=len(BOOT_ID_NAMES)
    boot,target=words[w['boot_id']:w['boot_id']+ids],words[w['target_id']:w['target_id']+ids]
    row.update(host=list(words[w['host']:w['host']+11]),
               boot_cache=dict(zip(CACHE_NAMES,words[w['boot_cache']:w['boot_cache']+len(CACHE_NAMES)])),
               target_cache=dict(zip(CACHE_NAMES,words[w['target_cache']:w['target_cache']+len(CACHE_NAMES)])),
               boot_midr=boot[0],target_midr=target[0],
               id_differences={name:[boot[n],target[n]] for n,name in enumerate(BOOT_ID_NAMES)
                               if target[n]!=boot[n] and any(target)},
               relay=dict(zip(RELAY_FIELDS,words[w['relay']:w['relay']+len(RELAY_FIELDS)])))
    return row

def report_path(kind):
    stem=os.environ.get('SNAP_SMP_REPORT_PREFIX','secondary-runtime-20260920')
    if not stem or Path(stem).name!=stem:raise ValueError('invalid secondary report basename')
    return ROOT/'build'/f'{stem}-{kind}.json'


def config_words(inventory,memory,mask=2):
    api=runpy.run_path(str(ROOT/'tools/probe-a16-secondary.py'))
    mapping=runpy.run_path(str(ROOT/'tools/host-el2-mapping.py'))
    regime=mapping['validate_regime'](memory)
    if type(mask) is not int or not mask or mask&~0x3e:
        raise ValueError('only the five declared secondary CPU release bits are supported')
    affinity=[0]*6;redistributor=[0]*6
    # SNAP_SMP_PRIME=1 (opt-in): all six vCPUs run on Prime cluster 1 (0x10000-0x10500): vCPU 0 on 0x10000 through
    # mask bit 0 (a monitor built with -DSNAP_BOOT_RELOCATE=1 moves it off q1n1's CPU; any other monitor refuses the
    # bit), the secondaries on 0x10000+slot*0x100. On the A16 the MADT gives cluster 0 (0x0-0x500, q1n1's) efficiency
    # class 0, the six lower-power "Performance" cores, and clusters 1-2 class 1, the twelve Prime cores. v26 kept vCPU 0
    # on cluster 0 and failed: compat/boot-relocate.h.
    prime=os.environ.get('SNAP_SMP_PRIME','0')
    if prime not in ('0','1'):raise ValueError('SNAP_SMP_PRIME must be 0 or 1')
    classes=[c.get('efficiency_class') for c in inventory.get('cpus',[])]
    boot=int(inventory['boot_mpidr'],16)
    targets={slot:(PRIME_CLUSTER+slot*0x100 if prime=='1' else slot*0x100) for slot in range(1,6) if mask&(1<<slot)}
    if prime=='1':
        targets[0]=PRIME_CLUSTER;mask|=1
        for target in targets.values():
            entry=next((c for c in inventory.get('cpus',[]) if int(c['mpidr'],16)==target),None)
            if (entry is None or entry.get('efficiency_class') is None or
                    any(type(k) is not int for k in classes) or entry['efficiency_class']!=max(classes)):
                raise ValueError(f'SNAP_SMP_PRIME: {target:#x} is not a core of the highest efficiency class')
    # The service lock is a test-and-set word: a waiter in another cluster starves (v26, compat/boot-relocate.h).
    executors=[targets.get(0,boot),*(targets[s] for s in range(1,6) if s in targets)]
    if len({t&CLUSTER for t in executors})!=1:
        raise ValueError('vCPUs would span physical clusters; the service lock starves a remote waiter (v26)')
    for slot,target in sorted(targets.items()):
        api['validate_target'](inventory,target)
        affinity[slot]=target;redistributor[slot]=api['watchdog_target'](inventory,target)
    return (MAGIC,160,boot,mask,*regime,*affinity,*redistributor)


def validate_guest_profile(name):
    from guestprofile import (get_profile, J700_26A428, J700_26A428_NO_CLPC,
                              J700_26A428_SEP_PRELOAD, J700_26A428_BOOTFB,
                              J700_26A428_BOOTFB_NUB, J700_26A428_BOOTFB_NO_USB,
                              J700_26A428_BOOTFB_RTC, J700_26A428_BOOTFB_XARS,
                              J700_26A428_BOOTFB_XARS_UNIFORM,
                              J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO,
                              J700_26A428_BOOTFB_AUXKC, J700_26A428_BOOTFB_AUXKC_GPU,
                              J700_26A428_XARS_UNIFORM_AUXKC,
                              J700_26A428_XARS_UNIFORM_AUXKC_ADRENO,
                              J700_26A428_XARS_UNIFORM_AUXKC_ADRENO_NODART,
                              J700_26A428_XARS_UNIFORM_AUXKC_ANS,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT,
                              J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT_TOUCHPAD)
    if get_profile(name) not in (J700_26A428, J700_26A428_NO_CLPC,
                                J700_26A428_SEP_PRELOAD, J700_26A428_BOOTFB,
                                J700_26A428_BOOTFB_NUB, J700_26A428_BOOTFB_NO_USB,
                                J700_26A428_BOOTFB_RTC, J700_26A428_BOOTFB_XARS,
                                J700_26A428_BOOTFB_XARS_UNIFORM,
                                J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO,
                                J700_26A428_BOOTFB_AUXKC, J700_26A428_BOOTFB_AUXKC_GPU,
                                J700_26A428_XARS_UNIFORM_AUXKC,
                                J700_26A428_XARS_UNIFORM_AUXKC_ADRENO,
                                J700_26A428_XARS_UNIFORM_AUXKC_ADRENO_NODART,
                                J700_26A428_XARS_UNIFORM_AUXKC_ANS,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT,
                                J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT_TOUCHPAD):
        raise ValueError('secondary PMGR binding requires the selected J700 26A428 profile')


def prepare(proxy,info,code,code_size,work,work_size,guest_profile):
    import run
    validate_guest_profile(guest_profile)
    if info['current_el']!=2 or info['heap_size']<run.SECONDARY_CONFIG_AT+4096:
        raise ValueError('secondary config requires EL2 and reserved host scratch')
    mem=runpy.run_path(str(ROOT/'tools/probe-el2-memory.py'))['collect'](
        proxy,run.build('el2-memory',ROOT/'build/cpu-probe'))
    inventory=runpy.run_path(str(ROOT/'tools/probe-a16-cpus.py'))['collect'](
        proxy,run.build('psci-info',ROOT/'build/cpu-probe'),True)
    words=config_words(inventory,mem,int(os.environ.get('SNAP_SMP_CPU_MASK','0x3e'),0))
    gic={};gic_ranges=[('GICD',0x17000000,4096,True)]
    for slot in range(6):   # slot 0: vCPU 0's relocated CPU (mask bit 0), started like a secondary
        if not words[3]&(1<<slot):continue
        redist=words[14+slot];target=words[8+slot]
        state=dict(group=proxy.read32(redist+0x10080),priority=proxy.read8(redist+0x1041a),
            enable=proxy.read32(redist+0x10100),pending=proxy.read32(redist+0x10200),
            active=proxy.read32(redist+0x10300),config=proxy.read32(redist+0x10c04),
            waker=proxy.read32(redist+0x14))
        if (proxy.read64(redist+8)>>32 != target or
            proxy.read32(0x17000000)&0x80000012 != 0x12 or state['enable'] or
            (state['pending']|state['active'])&(1<<26) or state['config']&(1<<21)):
            raise ValueError('secondary GIC is not idle and affinity routed')
        gic[str(slot)]=state
        gic_ranges.extend([(f'GICR{slot}',redist,4096,True),(f'GICR{slot} SGI',redist+0x10000,4096,True)])
    stride,size=info['memory_map_stride'],info['memory_map_size']
    if stride<40 or not 0<size<=1024*1024 or size%stride:
        raise ValueError('invalid firmware memory map')
    raw=proxy.readmem(info['memory_map'],size,live=True);ram=[]
    for off in range(0,size,stride):
        kind,pa,_,pages,_=struct.unpack_from('<I4xQQQQ',raw,off)
        if kind in (1,2,3,4,5,6,7,9,10) and pages:ram.append((pa,pa+pages*4096))
    config=info['heap_base']+run.SECONDARY_CONFIG_AT
    # A secondary executor that traps an ANS2 access touches the virtual ANS2
    # reservation directly above the work arena (xnuboot.ans_reservation).
    from guestprofile import get_profile
    from devicemodel import ans_reservation_span
    ans=get_profile(guest_profile).ans_boot
    # Window mode (full-install M6): 1 MiB aligned, 4 MiB, exactly as xnuboot.ans_reservation().
    ans_base=((work+work_size+(1<<20)-1)&~((1<<20)-1)) if ans and ans.window else work+work_size
    ans_ranges=[('ans',ans_base,ans_reservation_span(ans.disk_bytes,ans.window),False)] if ans else []
    # agents/gpu-va-wide: a secondary that serves an Adreno DART MAP/UNMAP writes the wide GPU table pool, directly above
    # the ANS2 reservation (else the work arena) on the 64 KiB grid, exactly as xnuboot.gpu_pool_reservation().
    if os.environ.get('SNAP_ADRENO_VA_WIDE')=='1':
        import adreno
        below=ans_ranges[0][1]+ans_ranges[0][2] if ans_ranges else work+work_size
        pool=(below+adreno.POOL_RESERVATION_ALIGN-1)&~(adreno.POOL_RESERVATION_ALIGN-1)
        ans_ranges=ans_ranges+[('gpu tables',pool,adreno.pool_reservation_bytes(),False)]
    cache={}
    def read(pa,n):
        page=pa&~4095
        if page not in cache:cache[page]=proxy.readmem(page,4096,live=True)
        return cache[page][pa-page:pa-page+n]
    witness=runpy.run_path(str(ROOT/'tools/host-el2-mapping.py'))['verify'](
        read,mem,[('code',code,code_size,False),('runtime',work,work_size,False),
        ('config',config,4096,False),*ans_ranges,*gic_ranges],ram)
    if proxy.exceptions:raise ValueError('proxy fault during secondary admission')
    for page in witness['table_pages']:proxy.request(proxy.P_DC_CVAC,int(page,16),4096)
    data=struct.pack('<20Q',*words)
    proxy.writemem(config,data);proxy.request(proxy.P_DC_CVAC,config,len(data))
    if proxy.readmem(config,len(data),live=True)!=data:
        raise ValueError('secondary configuration readback mismatch')
    report=dict(memory=mem,inventory=inventory,gic_before=gic,configuration=list(words),
                host_mapping=witness,config=hex(config))
    report_path('admission').write_text(json.dumps(report,indent=2)+'\n')
    return config


def collect(proxy,work,work_size):
    base=proxy.read64(work+SECONDARY_BASE_OFFSET)
    if not base:return dict(prepared=False)
    if base&4095 or not work<=base<work+work_size-6*4096:
        raise ValueError('invalid secondary record region')
    rows=[]
    for slot in range(1,6):
        raw=struct.unpack('<37Q',proxy.readmem(base+slot*4096,37*8,live=True))
        row=dict(zip(FIELDS,raw));row['slot']=slot
        if row['cpu']:
            if row['cpu']!=work+VCPUS_OFFSET+slot*VCPU_SIZE:
                raise ValueError('secondary CPU record identity mismatch')
            output=proxy.read64(row['cpu']+8)
            if output&4095 or not work<=output<=work+work_size-4096:
                raise ValueError('secondary output outside monitor memory')
            row['output_words']=list(struct.unpack('<44Q',proxy.readmem(output,44*8,live=True)))
            row['service_acquires']=proxy.read64(row['cpu']+LAYOUT.offset('vcpu','service_acquires'))
            row['service_fault']=proxy.read64(row['cpu']+LAYOUT.offset('vcpu','service_fault'))
            r=row['redistributor']
            row['gic_after']=dict(group=proxy.read32(r+0x10080),priority=proxy.read8(r+0x1041a),
                enable=proxy.read32(r+0x10100),pending=proxy.read32(r+0x10200),
                active=proxy.read32(r+0x10300),waker=proxy.read32(r+0x14))
        rows.append(row)
    relocation=decode_relocation(struct.unpack(f'<{RELOCATION_SIZE}Q',proxy.readmem(base,RELOCATION_SIZE*8,live=True)))
    if relocation and relocation['cpu']!=work+VCPUS_OFFSET:
        raise ValueError('relocated vCPU 0 record identity mismatch')
    import run
    inventory=runpy.run_path(str(ROOT/'tools/probe-a16-cpus.py'))['collect'](
        proxy,run.build('psci-info',ROOT/'build/cpu-probe'),True)
    result=dict(prepared=True,base=hex(base),cpus=rows,post_inventory=inventory)
    if relocation:result['boot_relocation']=relocation
    report_path('result').write_text(json.dumps(result,indent=2)+'\n')
    return result
