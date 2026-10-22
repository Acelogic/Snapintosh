#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the actual target structs against the host report/parameter ABI."""
from pathlib import Path
import subprocess
import sys
import runpy
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run
import xnuboot as xb
from devicemodel import MODEL_MAX,MODEL_WORDS,RESET_WORDS
layout=runpy.run_path(str(ROOT/'tools/monitor_layout.py'))['MonitorLayout']()
secondary=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
for constant,field in [('HOST_CPUS_OFFSET','host_cpus'),('SECONDARY_BASE_OFFSET','secondary_base'),
                       ('VCPUS_OFFSET','vcpus'),('SERVICES_OFFSET','services')]:
    assert secondary[constant]==layout.offset('context',field)
assert secondary['VCPU_SIZE']==2368

assert MODEL_MAX==128 and RESET_WORDS==2
source=f'''
#include <stddef.h>
#include "probes/xnuboot.c"
_Static_assert(DEVICE_MODEL_MAX=={MODEL_MAX}, "capacity ABI");
_Static_assert(DEVICE_RESET_WORDS=={RESET_WORDS}, "reset bitmap ABI");
_Static_assert(sizeof(struct params)=={xb.PARAMS_WORDS}*8, "params ABI");
_Static_assert(offsetof(struct params,model_count)==90*8, "model count");
_Static_assert(offsetof(struct params,models)==91*8, "models");
_Static_assert(offsetof(struct params,clock_host_hz)==(91+{MODEL_MAX*MODEL_WORDS})*8, "clock");
_Static_assert(sizeof(struct context)=={layout.size('context')}, "auditor context layout");
_Static_assert(offsetof(struct context,shadow_tlb_syncs)=={layout.offset('context','shadow_tlb_syncs')}, "shared translation counters");
_Static_assert(offsetof(struct context,services)=={secondary['SERVICES_OFFSET']}, "service lock alignment");
_Static_assert(sizeof(struct guest_service_lock)==64, "service lock cache line");
_Static_assert(offsetof(struct guest_service_lock,lifecycle)==16, "executor lifecycle ABI");
_Static_assert(_Alignof(struct context)==64, "shared context alignment");
_Static_assert(sizeof(struct guest_cpu_registry)==64, "CPU registry report");
_Static_assert(offsetof(struct context,cpus)=={layout.offset('context','cpus')}, "CPU registry");
_Static_assert(offsetof(struct context,host_cpus)=={secondary['HOST_CPUS_OFFSET']}, "host CPU config pointer");
_Static_assert(offsetof(struct context,secondary_base)=={secondary['SECONDARY_BASE_OFFSET']}, "secondary record base");
_Static_assert(offsetof(struct context,cpu_release)=={layout.offset('context','cpu_release')}, "CPU release state");
_Static_assert(offsetof(struct context,vcpus)=={secondary['VCPUS_OFFSET']}, "private CPU records");
_Static_assert(sizeof(struct vcpu)==2368, "private CPU stride");
_Static_assert(_Alignof(struct vcpu)==64, "private CPU cache line alignment");
_Static_assert(offsetof(struct vcpu,context)==32, "shared owner");
_Static_assert(offsetof(struct vcpu,prepared)==64, "prepared marker");
_Static_assert(offsetof(struct vcpu,ipi)==2288, "private IPI state");
_Static_assert(offsetof(struct vcpu,service_acquires)==2352, "private service counter");
_Static_assert(offsetof(struct vcpu,service_fault)==2360, "private service fault");
_Static_assert(offsetof(struct context,model_state)=={layout.offset('context','model_state')}, "auditor states");
_Static_assert(sizeof(struct device_state)==13000, "auditor state stride");
_Static_assert(offsetof(struct device_sep_asc,ready)=={layout.offset('device_sep_asc','ready')}, "top-level ASC ready, not nested endpoint ready");
_Static_assert(offsetof(struct device_sep_asc,pnon)=={layout.offset('device_sep_asc','pnon')}, "endpoint state offset");
_Static_assert(sizeof(struct sep_pnon)==26*8, "endpoint report size");
_Static_assert(offsetof(struct device_state,gpio_pin)==6704, "auditor GPIO pads");
_Static_assert(OUT_DEVICE_FLOW*8=={run.DEVICE_FLOW_OFFSET}-16, "device report");
_Static_assert(OUT_CLOCK_ADAPTER*8=={run.CLOCK_ADAPTER_OFFSET}-16, "clock report");
_Static_assert(OUT_WATCHDOG_FLOW*8=={run.WATCHDOG_FLOW_OFFSET}-16, "watchdog report");
_Static_assert(OUT_OPTIONAL_FLOW*8=={run.OPTIONAL_FLOW_OFFSET}-16, "optional report");
_Static_assert(OUT_IPI_FLOW*8=={run.IPI_FLOW_OFFSET}-16, "IPI report");
_Static_assert(OUT_CPU_FLOW*8=={run.CPU_FLOW_OFFSET}-16, "CPU report");
_Static_assert(OUT_VCPU_FLOW*8=={run.VCPU_FLOW_OFFSET}-16, "private CPU report");
_Static_assert(OUT_SHARED_FLOW*8=={run.SHARED_FLOW_OFFSET}-16, "shared translation report");
_Static_assert(OUT_SERVICE_FLOW*8=={run.SERVICE_FLOW_OFFSET}-16, "service lock report");
_Static_assert(OUT_RUNTIME_STORAGE*8=={run.RUNTIME_STORAGE_OFFSET}-16, "CPU runtime storage report");
'''
subprocess.run(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
    '-mgeneral-regs-only','-I.','-Ishadow','-Icompat','-fsyntax-only','-x','c','-'],
    cwd=ROOT,input=source,text=True,check=True)
print('PASS: target device layout and host report offsets agree')
