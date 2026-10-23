#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Profile accounting and actual terminal-wrapper regression checks."""
from pathlib import Path
import os
import runpy
import struct
import subprocess
import tempfile
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
extract = runpy.run_path(str(ROOT / 'tools/test-guard-step.py'))['function']

HARNESS = r'''
#include "service-profile.h"
#include "native-call.h"
#define SNAP_NATIVE_CALLS 1
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static unsigned checks;
struct regs { uint64_t x0, esr, pc, far; };
struct vcpu { uint64_t async_captured,slot; struct regs async_regs; };
struct context { struct vcpu v; uint64_t kernel_view_failed; struct native_call_state native_calls[6]; };
static struct context context;
static int admission, handler_stop, leave_stop, entry_stop, preexisting;
static unsigned entered_category;
static unsigned native_snapshots;
static int native_private;
static struct context *context_of(void) { return &context; }
static struct vcpu *vcpu_of(struct context *c) { return &c->v; }
static void native_exception_snapshot(struct context *c) { (void)c;native_snapshots++; }
static int runtime_enter(struct context *c, const uint64_t *f, uint64_t pc, unsigned cat)
{ (void)c; (void)f; (void)pc; entered_category=cat; return admission; }
static int runtime_leave(struct context *c, int stop) { (void)c; return stop || leave_stop; }
static int secondary_wait_entry(struct context *c) { (void)c; return entry_stop; }
static int xnuboot_trap_locked(uint64_t *frame,uint64_t esr,uint64_t *elr)
{
    (void)esr; *elr+=4; frame[0]=0xbeef;
    if(preexisting) context.v.async_captured=2;
    if(native_private)context.native_calls[context.v.slot].calls++;
    return handler_stop;
}
static int xnuboot_async_locked(uint64_t elr,uint64_t which,const uint64_t *frame)
{ (void)elr; (void)which; (void)frame; if(preexisting)context.v.async_captured=3; return handler_stop; }
static void fill_regs(struct regs *r,const uint64_t *f,uint64_t esr,uint64_t pc,uint64_t far)
{ *r=(struct regs){f[0],esr,pc,far}; }
#define EV_SPRR_FAILED 1
#define SPRR_VIEW_FAILED 2
static void record(struct context *c,int k,uint64_t p,uint64_t a,uint64_t b,uint64_t d)
{ (void)c; (void)k; (void)p; (void)a; (void)b; (void)d; }
/* WRAPPERS */
static void reset(void)
{ context=(struct context){0}; admission=1; handler_stop=leave_stop=entry_stop=preexisting=0;
  native_snapshots=0;native_private=0; }
int main(void)
{
    struct service_profile a={0}, b={0};
    uint64_t tick=0;
    for(unsigned i=0;i<1000;i++) {
        unsigned cat=i%SERVICE_PROFILE_BUCKETS;
        service_profile_begin(&a,tick,cat);
        service_profile_wait_done(&a,tick+3,1,i%2);
        service_profile_end(&a,tick+10);
        tick+=17;
        CHECK(!a.stage && !a.errors && a.attempts==i+1 && a.acquired==i+1);
    }
    CHECK(a.first_tick==0 && a.last_tick==tick-7);
    CHECK(a.wait_ticks==3000 && a.hold_ticks==7000 && a.contended==500);
    CHECK(a.max_wait_ticks==3 && a.max_hold_ticks==7);
    uint64_t entries=0,wait=0,hold=0;
    for(unsigned i=0;i<SERVICE_PROFILE_BUCKETS;i++) {
        entries+=a.buckets[i].entries; wait+=a.buckets[i].wait_ticks; hold+=a.buckets[i].hold_ticks;
    }
    CHECK(entries==a.attempts && wait==a.wait_ticks && hold==a.hold_ticks);
    service_profile_begin(&a,tick,64);
    service_profile_begin(&b,tick+1,50);
    service_profile_wait_done(&a,tick+10,0,1); /* stop while waiting: no held time */
    service_profile_wait_done(&b,tick+12,1,1);
    service_profile_end(&b,tick+19);
    CHECK(a.cancelled==1 && a.wait_ticks==3010 && a.hold_ticks==7000 && !a.stage);
    CHECK(b.attempts==1 && b.wait_ticks==11 && b.hold_ticks==7 && !b.stage);
    CHECK(a.attempts==a.acquired+a.cancelled && !a.errors && !b.errors);
    service_profile_begin(&b,tick,68); CHECK(b.errors==1 && !b.stage);
    service_profile_end(&b,tick); CHECK(b.errors==2 && !b.stage);
    service_profile_wait_done(&b,tick,1,0); CHECK(b.errors==3 && !b.stage);
    struct service_profile wrap={0};
    service_profile_begin(&wrap,UINT64_MAX-3,24);
    service_profile_wait_done(&wrap,1,1,1); service_profile_end(&wrap,8);
    CHECK(wrap.wait_ticks==5 && wrap.hold_ticks==7);

    /* A peer stop during owned work must save the new return frame. */
    for(unsigned mode=0;mode<3;mode++) {
        reset(); uint64_t frame[31]={0},pc=0x1000;
        handler_stop=mode==0; leave_stop=mode==1; entry_stop=mode==2;
        CHECK(xnuboot_trap(frame,24UL<<26,&pc));
        CHECK(entered_category==24 && context.v.async_captured==1);
        CHECK(context.v.async_regs.pc==0x1004 && context.v.async_regs.x0==0xbeef);
        CHECK(context.v.async_regs.esr==(24UL<<26));
    }
    reset(); uint64_t frame[31]={0x123},pc=0x2000;
    CHECK(!xnuboot_trap(frame,50UL<<26,&pc) && !context.v.async_captured);
    CHECK(native_snapshots==1);
    reset();pc=0x2000;CHECK(!xnuboot_trap(frame,32UL<<26,&pc) && native_snapshots==1);
    reset();native_private=1;pc=0x2000;
    CHECK(!xnuboot_trap(frame,32UL<<26,&pc) && !native_snapshots && context.native_calls[0].calls==1);
    /* SNAP_ERET_SNAPSHOT: an ERET exit refreshes the snapshot (the unarmed
     * exception_return breakpoint no longer does); a stopping one does not. */
    reset();pc=0x2000;
    CHECK(!xnuboot_trap(frame,0x1aUL<<26,&pc) && native_snapshots==SNAP_ERET_SNAPSHOT);
    reset();handler_stop=1;pc=0x2000;
    CHECK(xnuboot_trap(frame,0x1aUL<<26,&pc) && !native_snapshots);
    reset(); leave_stop=preexisting=1; pc=0x2000;
    context.v.async_regs.pc=0xdead;
    CHECK(xnuboot_trap(frame,50UL<<26,&pc));
    CHECK(context.v.async_captured==2 && context.v.async_regs.pc==0xdead);
    reset(); context.kernel_view_failed=1; pc=0x3000;
    CHECK(xnuboot_trap(frame,24UL<<26,&pc));
    CHECK(context.v.async_captured==2 && context.v.async_regs.pc==0x3004);
    for(unsigned which=0;which<3;which++) {
        reset(); leave_stop=1;
        CHECK(xnuboot_async(0x4000,which,frame));
        CHECK(entered_category==64+which && context.v.async_captured==1);
        CHECK(context.v.async_regs.pc==0x4000 && !context.v.async_regs.esr);
    }
    reset(); leave_stop=preexisting=1; context.v.async_regs.pc=0xdead;
    CHECK(xnuboot_async(0x4000,0,frame));
    CHECK(context.v.async_captured==3 && context.v.async_regs.pc==0xdead);
    reset(); admission=0;
    CHECK(xnuboot_trap(frame,0,&pc) && !context.v.async_captured);
    CHECK(xnuboot_async(pc,0,frame) && !context.v.async_captured);
    printf("PASS: %u profile accounting and terminal-frame checks\n",checks);
}
'''


def main():
    source = read_source(ROOT / 'probes/xnuboot.c')
    wrappers = '\n'.join(extract(source, signature) for signature in (
        'int xnuboot_async(uint64_t elr, uint64_t which, const uint64_t *frame)\n{',
        'int xnuboot_trap(uint64_t *frame, uint64_t esr, uint64_t *elr)\n{'))
    with tempfile.TemporaryDirectory(prefix='service-profile-') as directory:
        src = Path(directory) / 'test.c'
        exe = Path(directory) / 'test'
        src.write_text(HARNESS.replace('/* WRAPPERS */', wrappers))
        for eret_snapshot in (0, 1):
            subprocess.run([os.environ.get('CC','cc'), '-std=c11', '-O1', '-Wall',
                            '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            f'-DSNAP_ERET_SNAPSHOT={eret_snapshot}',
                            '-I' + str(ROOT / 'compat'), str(src), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)
    reader = runpy.run_path(str(ROOT / 'tools/capture-service-profile.py'))
    layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
    raw = bytearray(layout.size('service_profile'))
    fields = dict(attempts=2, acquired=1, cancelled=1, contended=1,
                  wait_ticks=7, hold_ticks=13, max_wait_ticks=5, max_hold_ticks=13,
                  first_tick=100, last_tick=130, category=64)
    for name,value in fields.items():
        struct.pack_into('<Q',raw,layout.offset('service_profile',name),value)
    start = layout.offset('service_profile','buckets')
    struct.pack_into('<3Q',raw,start+24*24,1,2,13)
    struct.pack_into('<3Q',raw,start+64*24,1,5,0)
    result = reader['decode'](raw,layout,10,1)
    assert result['wait_seconds']==0.7 and result['hold_seconds']==1.3
    assert result['outside_instrumented_seconds']==1 and len(result['buckets'])==2
    for field,value in [('stage',1),('errors',1),('attempts',3),('acquired',2),
                        ('wait_ticks',8),('last_tick',110),('max_hold_ticks',14)]:
        bad = bytearray(raw)
        struct.pack_into('<Q',bad,layout.offset('service_profile',field),value)
        try:
            reader['decode'](bad,layout,10,1)
        except ValueError:
            pass
        else:
            raise AssertionError('corrupt profile accepted: '+field)
    print('PASS: profile reader totals, time boundaries and 7 corruption refusals')


if __name__ == '__main__':
    main()
