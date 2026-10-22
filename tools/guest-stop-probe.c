/* SPDX-License-Identifier: MIT */
/* The implementation under test is the monitor itself, including its static
 * runtime/timer routines. No synthetic EL2 polling loop appears here. */
#include "../probes/xnuboot.c"

#define GUEST_STOP_MAGIC UINT64_C(0x31504f5453474c45)
struct guest_stop_request {
    uint64_t magic, mode, host_call, host_state, session, nonce;
    struct secondary_config cpus;
};
struct guest_stop_result {
    uint64_t status, entered, magic, version, mode, start, end, hz;
    uint64_t context_bytes, request, owner, stopped, lifecycle, reusable;
    uint64_t loop, loop_end, last_event, last_pc, setup_error, finish;
    uint64_t first_cval, budget, native_before[4], native_after[4];
    struct early_stop_state early;
    uint64_t cpu[6][8]; /* IRQs, PC, SPSR, service fault, acquires, x0, live, slot */
    struct secondary secondary[6];
    uint64_t el1_before[2],el1_after[2]; /* SCTLR/TCR touched by minimal entry */
    uint64_t retirement_start,retirement_end,retirement_ok;
};
_Static_assert(sizeof(struct guest_stop_result)<4096,"compact probe result");
extern void guest_stop_loop(void);
static struct guest_stop_result *guest_stop_result_of(struct context *c)
{return (struct guest_stop_result *)c->vcpus[0].out_ptr;}
static uint64_t guest_stop_inject(uint64_t op,uint64_t a,uint64_t b,uint64_t d)
{
    (void)b;(void)d;
    struct context *c=context_of();struct guest_stop_result *r=guest_stop_result_of(c);
    const struct guest_stop_request *p=(const void *)r->request;
    if(op!=EARLY_STOP_HOST_POLL)return 0;
    uint64_t now=service_profile_clock();
    if(now-r->start<r->hz/5 || c->early_stop.source)return 0;
    struct early_stop_host_request *l=(void *)a;
    *l=(struct early_stop_host_request){.magic=EARLY_STOP_HOST_MAGIC,
        .session=p->session,.nonce=p->nonce,.reason=EARLY_STOP_REASON_OPERATOR,
        .delay_s=0,.latched_ticks=now};
    return 1;
}
static void guest_stop_native_timer(uint64_t out[4])
{
    __asm__ volatile("mrs %0,vbar_el2":"=r"(out[0]));
    __asm__ volatile("mrs %0,hcr_el2":"=r"(out[1]));
    __asm__ volatile("mrs %0,cnthp_ctl_el2":"=r"(out[2]));
    __asm__ volatile("mrs %0,cnthp_cval_el2":"=r"(out[3]));
}
static void guest_stop_secondary(struct secondary *s)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    __atomic_store_n(&s->phase,1,__ATOMIC_RELEASE);
    if(guest_service_arrive(&c->services,v->slot)!=SERVICE_OK)goto fail;
    if(!secondary_gic_start(s))goto fail;
    __atomic_store_n(&s->phase,2,__ATOMIC_RELEASE);
    if(!runtime_enter(c,0,0,SERVICE_PROFILE_BOOT))goto fail;
    clock_rate_init(&v->clock_rate,c->params->clock_host_hz,c->params->clock_guest_hz);
    __asm__ volatile("msr sctlr_el1,xzr; isb");
    xnuboot_watchdog(2);
    __asm__ volatile("msr hcr_el2,%0; isb"::"r"(UINT64_C(0x80000018)));
    if(runtime_leave(c,0))goto fail;
    s->prepare_result=0;s->entered=1;
    __atomic_store_n(&s->phase,3,__ATOMIC_RELEASE);
    secondary_guest_enter((uint64_t)guest_stop_loop,v->out_ptr);
fail:
    s->error=1;guest_service_stop(&c->services,v->slot,SERVICE_STOP_FAULT);
    xnuboot_secondary_stop();
}
uint64_t guest_stop_setup(uint64_t out,uint64_t work,uint64_t size,uint64_t request);
uint64_t guest_stop_setup(uint64_t out,uint64_t work,uint64_t size,uint64_t request)
{
    const struct guest_stop_request *q=(const void *)request;
    struct guest_stop_result *r=(void *)out;
    int native=q->mode==1 || q->mode==2;
    if(q->magic!=GUEST_STOP_MAGIC || q->mode>4 || !q->session || !q->nonce ||
       size<sizeof(struct context)+0x100000 || (work&4095) ||
       (native && (!q->host_call || !q->host_state)))return 1;
    if((q->mode==2 && q->cpus.mask!=2) || (q->mode!=2 && q->cpus.mask))return 2;
    struct params *p=(void *)(work+size-0x10000);
    for(unsigned i=0;i<sizeof(*p)/8;i++)((uint64_t *)p)[i]=0;
    __asm__ volatile("":::"memory");
    /* Native stages retain the surveyed physical TSENS policy. QEMU has no
     * A16 sensor fabric and must never dereference those register addresses. */
    p->early_stop.flags=EARLY_STOP_F_HOST|(native?EARLY_STOP_F_THERMAL:0);
    if(xnuboot_setup(work,size-0x10000,(uint64_t)p,out,
                      q->mode==2 ? &q->cpus:0))return 3;
    struct context *c=context_of();
    r->magic=GUEST_STOP_MAGIC;r->version=1;r->mode=q->mode;r->request=request;
    r->context_bytes=sizeof(*c);r->loop=(uint64_t)guest_stop_loop;r->loop_end=r->loop+8;
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(r->hz));
    p->clock_host_hz=p->clock_guest_hz=r->hz;p->entry=r->loop;
    p->early_stop=(struct early_stop_params){.flags=EARLY_STOP_F_HOST|(native?EARLY_STOP_F_THERMAL:0),
        .max_delay_s=2,.host_call=native?q->host_call:(uint64_t)guest_stop_inject,
        .host_state=q->host_state,.host_poll_ms=20,.session=q->session};
    if(guest_service_boot(&c->services)!=SERVICE_OK)return 4;
    clock_rate_init(&c->vcpus[0].clock_rate,r->hz,r->hz);
    guest_stop_native_timer(r->native_before);
    __asm__ volatile("mrs %0,sctlr_el1; mrs %1,tcr_el1":"=r"(r->el1_before[0]),"=r"(r->el1_before[1]));
    if(q->mode==2) {
        struct vcpu *v=&c->vcpus[1];
        c->next_table=(c->next_table+4095)&~UINT64_C(4095);
        v->out_ptr=c->next_table;c->next_table+=4096;
        v->el2_sp=c->next_table+0x10000;c->next_table+=0x10000;
        c->cpus.registered|=2;
        if(!secondary_prepare_records(c))return 5;
        secondary_of(c,1)->callback=(uint64_t)guest_stop_secondary;
        publish((uint64_t)p,(uint64_t)(p+1));
    } else if(q->mode>=3) {
        /* QEMU-only failure admission: real reservation, no CPU_ON or MMIO.
         * The collector must preserve it rather than pretend this CPU is OFF. */
        c->secondary_base=(c->next_table+4095)&~UINT64_C(4095);
        c->next_table=c->secondary_base+6*4096;
        for(uint64_t a=c->secondary_base;a<c->next_table;a+=8)*(uint64_t *)a=0;
    }
    return 0;
}
uint64_t guest_stop_prepare(void);
uint64_t guest_stop_prepare(void)
{
    struct context *c=context_of();struct guest_stop_result *r=guest_stop_result_of(c);
    r->start=service_profile_clock();
    if(c->thermal && (r->hz!=19200000 || thermal_tick(c,r->start) || !c->thermal->ready)) {
        r->setup_error=8;guest_service_stop(&c->services,0,SERVICE_STOP_NORMAL);return 1;
    }
    if(!runtime_enter(c,0,0,SERVICE_PROFILE_BOOT))return 1;
    if(r->mode>=3 && guest_service_reserve(&c->services,0,1)!=SERVICE_OK) {
        r->setup_error=9;runtime_leave(c,1);return 1;
    }
    if(c->host_cpus && !secondary_launch(c,1,(uint64_t)guest_stop_loop)) {
        r->setup_error=6;runtime_leave(c,1);return 1;
    }
    if(runtime_leave(c,0))return 1;
    if(c->host_cpus && secondary_wait_entry(c)){r->setup_error=7;return 1;}
    __asm__ volatile("msr sctlr_el1,xzr; isb");
    xnuboot_watchdog(2);
    __asm__ volatile("mrs %0,cnthp_cval_el2":"=r"(r->first_cval));
    r->budget=c->vcpus[0].watchdog_deadline;
    __asm__ volatile("msr hcr_el2,%0; isb"::"r"(UINT64_C(0x80000018)));
    return 0;
}
uint64_t guest_stop_report(uint64_t *out);
uint64_t guest_stop_report(uint64_t *out)
{
    (void)out;
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct guest_stop_result *r=guest_stop_result_of(c);
    watchdog_off(c);
    r->finish=guest_service_finish(&c->services,0);
    if(r->mode==4) {
        /* Inject a latched policy trip only after the real EL1 timer stop.
         * a16_thermal_poll returns it before any A16 register access. */
        c->thermal=(struct a16_thermal_state *)c->next_table;
        for(unsigned i=0;i<4096/8;i++)((uint64_t *)c->thermal)[i]=0;
        __asm__ volatile("":::"memory");
        c->thermal->magic=A16_THERMAL_MAGIC;c->thermal->abi=A16_THERMAL_ABI;
        c->thermal->bytes=sizeof(*c->thermal);c->thermal->reason=A16_THERMAL_HOT;
    }
    r->retirement_start=service_profile_clock();
    r->retirement_ok=secondary_collect(c);
    r->retirement_end=service_profile_clock();
    int quarantined=!r->retirement_ok || !guest_service_reusable(&c->services);
    uint64_t terminal=quarantined?XNUBOOT_TERMINAL_OWNERSHIP:XNUBOOT_TERMINAL_OK;
    r->status=terminal;
    if(!quarantined && c->early_stop.host_armed && !c->early_stop.host_in_call)
        early_stop_host_call(c,EARLY_STOP_HOST_DISARM,0,0,0);
    if(!quarantined)early_stop_finish(&c->early_stop,guest_service_stopped(&c->services));
    r->end=service_profile_clock();r->owner=guest_service_owner(&c->services);
    r->stopped=guest_service_stopped(&c->services);
    r->lifecycle=guest_service_lifecycle(&c->services);r->reusable=!quarantined;
    if(!quarantined){r->last_event=c->last.kind;r->last_pc=c->last.pc;r->early=c->early_stop;}
    if(c->thermal)
        for(unsigned i=0;i<A16_THERMAL_REPORT_WORDS;i++)
            ((uint64_t *)((uint8_t *)r+4096))[i]=((const uint64_t *)c->thermal)[i];
    for(unsigned i=0;i<(quarantined?1U:6U);i++) {
        struct vcpu *u=&c->vcpus[i];
        r->cpu[i][0]=u->timer_irqs;r->cpu[i][1]=u->async_regs.pc;
        r->cpu[i][2]=u->async_regs.spsr;r->cpu[i][3]=u->service_fault;
        r->cpu[i][4]=u->service_acquires;r->cpu[i][5]=u->async_regs.x[0];
        r->cpu[i][6]=u->watchdog_live;r->cpu[i][7]=u->slot;
        if(!quarantined && c->secondary_base)r->secondary[i]=*secondary_of(c,i);
    }
    /* This minimal guest changed no translation table or debug register. */
    __asm__ volatile("msr sctlr_el1,%0; msr tcr_el1,%1; isb"::"r"(v->save_sctlr),"r"(v->save_tcr));
    __asm__ volatile("mrs %0,sctlr_el1; mrs %1,tcr_el1":"=r"(r->el1_after[0]),"=r"(r->el1_after[1]));
    __asm__ volatile("msr vbar_el2,%0; msr hcr_el2,%1; isb"::"r"(v->save_vbar),"r"(v->save_hcr));
    guest_stop_native_timer(r->native_after);
    uint64_t tpidr=v->save_tpidr,daif=v->save_daif;
    __asm__ volatile("msr tpidr_el2,%0; msr daif,%1; isb"::"r"(tpidr),"r"(daif):"memory");
    return terminal;
}
