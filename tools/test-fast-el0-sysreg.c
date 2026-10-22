/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_EL0_SYSREG (compat/fast-vector.h fast_el0_sysreg, reached from
 * fast_cross_entry) and SNAP_SERVICE_SUBCLASS (compat/service-profile.h
 * service_sub_*, compat/perf-state.h fast_exit_*).
 *
 * The lock-free class must be the locked user_sysreg_access, as
 * xnuboot_trap_locked's vector branch reaches it for an EL0 entry, for every
 * read it emulates, and must decline everything else with nothing changed.
 * The oracle below transcribes that branch and user_sysreg_access in order,
 * calling the same compat functions (exception_user_return,
 * guest_clock_user_read, sprr_user_read, sprr_user_write);
 * tools/test-fast-el0-sysreg.py checks the transcription's order and tokens
 * against probes/xnuboot.c and runs the source mutants that must fail here.
 *
 * Failure modes, written down before the code:
 *  F1  wrong destination: a register other than the word's Rt written, Rt=31
 *      written instead of discarded, or any other frame register changed.
 *  F2  wrong EL0 return: SPSR other than exception_user_return(ERET, vHCR,
 *      pc+4, saved), ELR other than pc+4, or a return taken for a PC at or
 *      above 2^47-4, a misaligned PC, a saved PSTATE with IL, T, a mode or
 *      upper bits, or a virtual HCR without the nested-host bits.
 *  F3  the PAC keys not reloaded: returning to EL0 without SPSR_EL2 naming
 *      EL0 before xnuboot_pauth_resume (a source check in the .py).
 *  F4  a stale or invalid UPERM: after a same-vCPU locked UPERM write the
 *      lock-free read must return the new value; a state failing
 *      sprr_fixed_state_valid (never reset, PPERM/PMPRR/UMPRR off the fixed
 *      values, TPRO without its UMPRR policy) must decline; a concurrent
 *      reset must yield either whole value.
 *  F5  a crash-class entry swallowed: an EL0 EC 0 entry whose word is not
 *      accepted must return to the locked path (which notes it), crash ring
 *      on or off; an accepted one is never noted by the locked path either.
 *  F6  a concurrent remap during the lock-free walk: a second read that
 *      differs in either leaf, the PA, the root or the word, or fails, must
 *      decline; a consistent pair must emulate the word both reads saw
 *      (thread-sanitized build with a remapping lock holder).
 *  F7  the UPERM write (MSR S3_6_C15_C1_5, Xt) or a near-miss encoding (any
 *      one bit off either word outside Rt, the other counter alias
 *      S3_4_C15_C11_7, the PPERM/UMPRR/PMPRR reads, MSR forms) emulated.
 *  F8  a counter read emulated with EL0VCTEN clear or without a counter
 *      backend, or any read for another syndrome (IL clear, ISS bits, other
 *      EC), vector (0x480/0x500/0x580, EL1 slots) or origin (EL1 modes).
 *  F9  a decline that changed something: the clock sampled, SPRR readback
 *      counted, a record, the frame, ELR, SPSR or PAN evidence written. Only
 *      its outcome counter moves (none for a non-class entry).
 *  F10 a handled read that differs from the locked path in Rt, the clock
 *      (first/last/reads), SPRR readback (reads/last_reg/last_value), the
 *      user_clock/user_sprr record, PAN evidence, ELR or SPSR; or a read the
 *      locked path emulates declined without a cause (the repeat read).
 *  F11 the class disturbing the boundary's other classes: with the hooks
 *      installed every other entry must classify exactly as without them,
 *      and the class has no log bit (fast-trap bits 14.. share the word).
 *  F12 sub-class accounting: a charge outside a completed EC 0x20 entry, a
 *      tag outliving its entry, wait/hold other than the entry's own, or the
 *      buckets not summing to the EC 0x20 profile (hold exactly; entries and
 *      wait less the cancelled acquisitions). Native-call tags must follow
 *      monitor_call_impl's endpoint split.
 *  F13 exit timing: class 0 or an out-of-range class charged, a counter
 *      wrap mis-measured, an exit of 2^32 ticks or more polluting the sums,
 *      the count and tick fields mixing.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -DFAST_CROSS_EL0_SYSREG=1 -Icompat -Ishadow tools/test-fast-el0-sysreg.c \
 *    compat/clock.c compat/exception.c compat/service-lock.c -o build/test-fast-el0-sysreg
 * cc -std=gnu11 -O1 -g -fsanitize=thread -pthread -DFAST_EL0_THREADS=1 \
 *    -DFAST_CROSS_EL0_SYSREG=1 -Icompat -Ishadow tools/test-fast-el0-sysreg.c \
 *    compat/clock.c compat/exception.c compat/service-lock.c -o build/test-fast-el0-sysreg-tsan */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef FAST_EL0_PLAIN_UNIT
#define FAST_EL0_PLAIN_UNIT 0
#endif
/* F11's reference, the boundary without the class: this file compiled again
 * with -DFAST_EL0_PLAIN_UNIT=1 -DFAST_CROSS_EL0_SYSREG=0 -c is plain_cross_entry,
 * the header's fast_cross_entry as it is with the class compiled out. */
#if FAST_EL0_PLAIN_UNIT == !!FAST_CROSS_EL0_SYSREG
#error "the test unit needs -DFAST_CROSS_EL0_SYSREG=1, the plain unit =0"
#endif
#include "fast-vector.h"
#include "perf-state.h"
#include "service-profile.h"
#include "service-lock.h"
#ifndef FAST_EL0_THREADS
#define FAST_EL0_THREADS 0
#endif
#if FAST_EL0_THREADS
#include <pthread.h>
#endif

static unsigned long long checks __attribute__((unused));
#define CHECK(x) do {__atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); \
    if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)

#define VBAR_VA UINT64_C(0xfffffe000b86c000)
#define VBAR_PA UINT64_C(0x81a40c000)
#define MEM_LOW UINT64_C(0x800000000)
#define MEM_HIGH UINT64_C(0x900000000)
#define KERNEL_HCR ((UINT64_C(1)<<34)|(UINT64_C(1)<<31)|(UINT64_C(1)<<27))
#define CLOCK_WORD 0xd53cfac0u
#define UPERM_READ 0xd53ef1a0u
#define UPERM_WRITE 0xd51ef1a0u
#define ERET_WORD 0xd69f03e0u

static uint64_t rng=0x2545f4914f6cdd1dULL;
__attribute__((unused)) static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

/* One vCPU as the monitor keeps it: every field either path may write. */
struct cpu {
    uint64_t regs[31];
    struct guest_clock clock;
    struct sprr_state sprr;
    struct { uint64_t reads,pc,word,value,spsr,sp,root,cntkctl,raw,host_hz,guest_hz; } uclock;
    struct { uint64_t reads,pc,word,value,spsr,sp,root,umprr; } usprr;
    struct { uint64_t writes,changes; } uwrite;
    uint64_t user_vectors,protected_vectors,vector,saved_spsr,entry_spsr,entry_sctlr;
    uint64_t timer_vectors,model_irq_vectors,fault_esr,fault_far;
    uint64_t kernel_returns,last_kernel_return,returns,svcs,faults;
    uint64_t exceptions,last_esr,last_x30;
    uint64_t backend_reads,raw_last,view_el0,selects;
};
/* What the trap sees besides the vCPU. */
struct world {
    uint64_t esr,far,pc,saved,sctlr,vhcr,hcr,physical_spsr,counter,sp_el0;
    uint64_t host_hz,guest_hz;
    int root_ok,read_ok,read2_ok,has_counter,native,crash_ring,hooks;
    struct fetch_model { uint64_t source,hardware,pa,root;uint32_t word; } first,second;  /* the two word reads */
    uint32_t slot_word;
};
struct env { struct cpu *cpu;const struct world *w;unsigned fetches; };

static uint64_t hw_pa(void *ctx,uint64_t va) {(void)ctx;(void)va;return 0;}
static uint32_t hw_fetch(void *ctx,uint64_t pa)
{
    struct env *e=ctx;
    return (pa&~UINT64_C(0xfff))==VBAR_PA ? e->w->slot_word : 0;
}
static void hw_el1(void *ctx,struct fast_cross_el1 *r)
{
    const struct world *w=((struct env *)ctx)->w;
    r->esr=w->esr;r->far=w->far;r->elr=w->pc;r->spsr=w->saved;r->sctlr=w->sctlr;
}
static uint64_t hw_hcr(void *ctx) {return ((struct env *)ctx)->w->hcr;}
static uint64_t hw_vhcr(void *ctx) {return ((struct env *)ctx)->w->vhcr;}
static int hw_cross(void *ctx,int el0)
{
    struct cpu *c=((struct env *)ctx)->cpu;
    if(c->view_el0!=(uint64_t)el0) {c->view_el0=(uint64_t)el0;c->selects++;}
    return 1;
}
static int hw_root(void *ctx) {return ((struct env *)ctx)->w->root_ok;}
static void hw_capture(void *ctx,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far)
{
    struct cpu *c=((struct env *)ctx)->cpu;
    (void)elr;(void)far;c->exceptions++;c->last_esr=esr;c->last_x30=frame[30];
}

#if FAST_EL0_PLAIN_UNIT
unsigned plain_cross_entry(struct cpu *c,const struct world *w,uint64_t vector,uint64_t *elr,
                           uint64_t *logged,uint64_t *first);
unsigned plain_cross_entry(struct cpu *c,const struct world *w,uint64_t vector,uint64_t *elr,
                           uint64_t *logged,uint64_t *first)
{
    struct env e={c,w,0};
    const struct fast_cross_hw hw={.ctx=&e,.vbar_va=VBAR_VA,.vbar_pa=VBAR_PA,.mem_low=MEM_LOW,
        .mem_high=MEM_HIGH,.crash_ring=w->crash_ring,.guest_pa=hw_pa,.fetch=hw_fetch,.el1=hw_el1,
        .hcr=hw_hcr,.vhcr=hw_vhcr,.cross=w->native ? hw_cross : 0,.user_root=hw_root,.capture=hw_capture};
    const struct fast_cross_vcpu state={&c->user_vectors,&c->protected_vectors,&c->vector,
        &c->saved_spsr,&c->entry_spsr,&c->entry_sctlr,&c->timer_vectors,&c->model_irq_vectors,
        &c->fault_esr,&c->fault_far,&c->kernel_returns,&c->last_kernel_return,&c->returns,
        &c->svcs,&c->faults,logged,first};
    *elr=VBAR_VA+vector;
    return fast_cross_entry(&hw,&state,w->physical_spsr,c->regs,elr);
}
#else
unsigned plain_cross_entry(struct cpu *c,const struct world *w,uint64_t vector,uint64_t *elr,
                           uint64_t *logged,uint64_t *first);

/* The counter backend, as clock_counter keeps its raw sample. */
static uint64_t model_counter(void *ctx)
{
    struct env *e=ctx;
    e->cpu->backend_reads++;e->cpu->raw_last=e->w->counter^0x5a5a;
    return e->w->counter;
}
static int model_control(void *ctx,uint64_t value) {(void)ctx;(void)value;return 0;}
static struct clock_backend backend_of(struct env *e)
{
    return (struct clock_backend){e,e->w->has_counter ? model_counter : 0,model_control};
}
/* user_change_uperm: the proof and the flip succeed in this model. */
static int model_change(void *ctx,uint64_t value) {(void)ctx;(void)value;return 1;}

/* user_sysreg_access's records, statement for statement. */
static void record_clock(struct cpu *c,const struct world *w,uint64_t pc,uint32_t word,
                         uint64_t saved,uint64_t root)
{
    c->uclock.reads++;c->uclock.pc=pc;c->uclock.word=word;c->uclock.value=c->clock.last;
    c->uclock.spsr=saved;c->uclock.sp=w->sp_el0;c->uclock.root=root;
    c->uclock.cntkctl=c->clock.cntkctl;c->uclock.raw=c->raw_last;
    c->uclock.host_hz=w->host_hz;c->uclock.guest_hz=w->guest_hz;
}
static void record_sprr(struct cpu *c,const struct world *w,uint64_t pc,uint32_t word,
                        uint64_t saved,uint64_t root)
{
    c->usprr.reads++;c->usprr.pc=pc;c->usprr.word=word;c->usprr.value=c->sprr.uperm;
    c->usprr.spsr=saved;c->usprr.sp=w->sp_el0;c->usprr.root=root;c->usprr.umprr=c->sprr.umprr;
}

/* user_sysreg_access, in its order. 1 clock, 2 UPERM read, 3 UPERM write,
 * 0 not emulated (the vector branch continues; not modeled further). */
static int locked_sysreg_access(struct cpu *c,const struct world *w,uint64_t pc,uint64_t saved,
    uint64_t esr,uint64_t vector,uint64_t *elr,uint64_t *spsr_el2)
{
    if(vector!=0x400 || esr!=0x02000000 || pc>=(UINT64_C(1)<<47)-4)return 0;
    uint64_t vhcr=w->vhcr,translated;
    if(!exception_user_return(0xd69f03e0,vhcr,pc+4,saved,&translated))return 0;
    /* user_return_root, then user_instruction_read: one consistent read
     * under the lock. */
    if(!w->root_ok || !w->read_ok)return 0;
    uint32_t word=w->first.word;uint64_t root=w->first.root;
    struct env e={c,w,0};
    struct clock_backend backend=backend_of(&e);
    struct sprr_state *sprr=&c->sprr;
    enum clock_result clock_result=guest_clock_user_read(&c->clock,&backend,word,c->regs);
    int kind;
    if(clock_result==CLOCK_OK) {
        record_clock(c,w,pc,word,saved,root);kind=1;
    } else if(clock_result==CLOCK_UNHANDLED && (word&~31U)==0xd51ef1a0U) {
        uint64_t before=sprr->uperm,value=(word&31)==31 ? 0 : c->regs[word&31];
        if(sprr_user_write(sprr,word,c->regs,model_change,0)!=SPRR_OK)return 0;
        c->uwrite.writes++;c->uwrite.changes+=before!=value;kind=3;
    } else if(clock_result==CLOCK_UNHANDLED && sprr_user_read(sprr,word,c->regs)==SPRR_OK) {
        record_sprr(c,w,pc,word,saved,root);kind=2;
    } else return 0;
    /* step_arm(c,0);guards_close(c): no step or guard is active here. */
    *spsr_el2=translated;
    *elr=pc+4;
    return kind;
}
/* xnuboot_trap_locked's vector branch for an EL0 entry, up to the emulation:
 * the PAN evidence, then user_sysreg_access. */
static int locked_entry(struct cpu *c,const struct world *w,uint64_t vector,
                        uint64_t *elr,uint64_t *spsr_el2)
{
    uint64_t g_esr=w->esr,g_elr=w->pc,saved=w->saved;
    if(vector<0x800 && !(vector&0x7f)) {
        if(vector>=0x400 && vector<=0x580 && !(saved&31)) {
            c->user_vectors++;c->protected_vectors+=!!(w->physical_spsr&(UINT64_C(1)<<22));
            c->vector=vector;c->saved_spsr=saved;c->entry_spsr=w->physical_spsr;
            c->entry_sctlr=w->sctlr;
        }
    }
    return locked_sysreg_access(c,w,g_elr,saved,g_esr,vector,elr,spsr_el2);
}

/* The monitor side of the hooks (probes/xnuboot.c fast_el0_word/_note). */
static int hw_word(void *ctx,uint64_t pc,struct fast_el0_fetch *out)
{
    struct env *e=ctx;
    (void)pc;
    unsigned n=e->fetches++;
    if(!e->w->root_ok || !(n ? e->w->read2_ok : e->w->read_ok))return 0;
    const struct fetch_model *m=n ? &e->w->second : &e->w->first;
    *out=(struct fast_el0_fetch){m->source,m->hardware,m->pa,m->root,m->word};
    return 1;
}
static void hw_note(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root)
{
    struct env *e=ctx;
    if(kind==FAST_EL0_CLOCK)record_clock(e->cpu,e->w,pc,word,saved,root);
    else record_sprr(e->cpu,e->w,pc,word,saved,root);
}

/* fast_crossing's assembly of the two hook sets, as probes/xnuboot.c builds them. */
struct fast_side {
    struct env env;
    struct clock_backend clock;
    struct fast_el0_hw el0_hw;
    struct fast_el0_vcpu el0_state;
    struct fast_cross_hw hw;
    struct fast_cross_vcpu state;
    uint64_t logged,first,el0_spsr,outcomes[FAST_EL0_RESULTS-1];
};
static void fast_side_init(struct fast_side *s,struct cpu *c,const struct world *w,int hooks)
{
    memset(s,0,sizeof *s);
    s->env=(struct env){c,w,0};
    s->clock=backend_of(&s->env);
    s->el0_hw=(struct fast_el0_hw){.ctx=&s->env,.fetch=hw_word,.clock=&s->clock,.note=hw_note};
    s->el0_state=(struct fast_el0_vcpu){&c->clock,&c->sprr,c->regs,s->outcomes,&s->el0_spsr};
    s->el0_spsr=0xdead;s->logged=~UINT64_C(0);
    s->hw=(struct fast_cross_hw){.ctx=&s->env,.vbar_va=VBAR_VA,.vbar_pa=VBAR_PA,.mem_low=MEM_LOW,
        .mem_high=MEM_HIGH,.crash_ring=w->crash_ring,.guest_pa=hw_pa,.fetch=hw_fetch,.el1=hw_el1,
        .hcr=hw_hcr,.vhcr=hw_vhcr,.cross=w->native ? hw_cross : 0,.user_root=hw_root,
        .capture=hw_capture,.el0=hooks ? &s->el0_hw : 0};
    s->state=(struct fast_cross_vcpu){&c->user_vectors,&c->protected_vectors,&c->vector,
        &c->saved_spsr,&c->entry_spsr,&c->entry_sctlr,&c->timer_vectors,&c->model_irq_vectors,
        &c->fault_esr,&c->fault_far,&c->kernel_returns,&c->last_kernel_return,&c->returns,
        &c->svcs,&c->faults,&s->logged,&s->first,hooks ? &s->el0_state : 0};
}

/* Words: the two accepted reads, the UPERM write, one-bit near misses outside
 * Rt, named neighbours, anything. */
static uint32_t pick_word(void)
{
    uint32_t rt=rnd()%4==0 ? 31u : (uint32_t)(rnd()%31);
    switch(rnd()%20) {
    case 0: case 1: case 2: case 3: case 4: case 5: return CLOCK_WORD|rt;
    case 6: case 7: case 8: case 9: case 10: case 11: return UPERM_READ|rt;
    case 12: case 13: return UPERM_WRITE|rt;
    case 14: case 15: return ((rnd()&1 ? CLOCK_WORD : UPERM_READ)^(UINT32_C(1)<<(5+rnd()%27)))|rt;
    case 16: {
        static const uint32_t named[]={0xd53cfbe0u,0xd53ef1c0u,0xd53ef300u,0xd53ef320u,
            0xd51cfac0u,0xd53bec00u,0xd53be040u,0xd53ef1a0u^0x00200000u,0xd5000000u};
        return named[rnd()%(sizeof named/sizeof *named)]|rt;
    }
    default: return (uint32_t)rnd();
    }
}
static void pick_sprr(struct sprr_state *s)
{
    static const unsigned flags[]={0,1,8,9};
    memset(s,0,sizeof *s);
    sprr_root_reset(s,flags[rnd()%4]);
    s->reads=rnd()%1000;s->writes=rnd()%10;
    switch(rnd()%12) {
    case 0: memset(s,0,sizeof *s);break;                       /* never reset */
    case 1: s->pperm^=UINT64_C(1)<<(rnd()%64);break;           /* maybe a mutable bit */
    case 2: s->umprr|=UINT64_C(1)<<(rnd()%64);break;
    case 3: s->uperm|=SPRR_UPERM_TPRO_WRITE;break;             /* valid only with flags 8/9 */
    case 4: s->uperm^=UINT64_C(1)<<(rnd()%64);break;
    case 5: s->pmprr^=1;break;
    default: break;
    }
}
static void pick_world(struct world *w,uint64_t *vector)
{
    memset(w,0,sizeof *w);
    static const uint64_t others[]={0x480,0x500,0x580,0x000,0x080,0x100,0x200,0x280,0x300};
    *vector=rnd()%8 ? 0x400 : others[rnd()%(sizeof others/sizeof *others)];
    static const uint64_t syndromes[]={0,0x02000001,0x02000020,0x03000000,0x01000000,
        (UINT64_C(0x15)<<26)|(UINT64_C(1)<<25)|0x80,(UINT64_C(0x24)<<26)|(UINT64_C(1)<<25)|7,
        (UINT64_C(0x20)<<26)|(UINT64_C(1)<<25)|6,(UINT64_C(0x0e)<<26)|(UINT64_C(1)<<25),
        UINT64_C(1)<<25};
    w->esr=rnd()%8 ? 0x02000000 : syndromes[rnd()%(sizeof syndromes/sizeof *syndromes)];
    if(rnd()%64==0)w->esr=0x02000000|(rnd()&0x1ffffff);
    unsigned mode=*vector>=0x400 ? 0 : *vector>=0x200 ? 9 : 8;
    w->saved=mode|(rnd()&UINT64_C(0xf04013c0));
    switch(rnd()%16) {
    case 0: w->saved|=UINT64_C(1)<<20;break;                   /* IL */
    case 1: w->saved|=UINT64_C(1)<<5;break;                    /* T */
    case 2: w->saved|=UINT64_C(1)<<32;break;
    case 3: w->saved=(w->saved&~UINT64_C(31))|(unsigned[]){4,5,8,9,0x10}[rnd()%5];break;
    default: break;
    }
    w->pc=UINT64_C(0x100000000)+4*(rnd()%0x4000000);
    switch(rnd()%24) {
    case 0: w->pc=(UINT64_C(1)<<47)-4;break;
    case 1: w->pc=(UINT64_C(1)<<47)-8;break;
    case 2: w->pc|=1+rnd()%3;break;
    case 3: w->pc=0;break;
    case 4: w->pc=UINT64_C(0xfffffe0007000000);break;
    default: break;
    }
    w->far=rnd();w->sctlr=rnd()&UINT64_C(0xffffffff);
    w->vhcr=rnd()%12 ? KERNEL_HCR : rnd()&KERNEL_HCR;
    w->hcr=rnd()&((UINT64_C(1)<<6)|(UINT64_C(1)<<7));
    w->physical_spsr=(rnd()%2 ? 5 : 4)|(rnd()&(UINT64_C(1)<<22));
    w->counter=rnd();w->sp_el0=rnd();w->host_hz=19200000;w->guest_hz=24000000;
    w->root_ok=rnd()%24!=0;w->read_ok=rnd()%24!=0;w->has_counter=rnd()%24!=0;
    w->native=rnd()%16!=0;w->crash_ring=rnd()%2;w->hooks=rnd()%16!=0;
    w->first=(struct fetch_model){UINT64_C(0x00600000a1b2c7c3)|(rnd()&0xfff000),
        UINT64_C(0x00600000a1b2c7c3)|(rnd()&0xfff000),MEM_LOW+4*(rnd()%0x100000),
        MEM_LOW+0x4000*(rnd()%4096),pick_word()};
    w->second=w->first;w->read2_ok=1;
    switch(rnd()%16) {   /* a concurrent remap between the two reads */
    case 0: w->read2_ok=0;break;
    case 1: w->second.source^=UINT64_C(1)<<10;break;           /* AF */
    case 2: w->second.hardware^=UINT64_C(1)<<54;break;         /* UXN */
    case 3: w->second.pa+=0x4000;break;
    case 4: w->second.root+=0x4000;break;
    case 5: w->second.word=pick_word();break;
    default: break;
    }
    static const uint32_t slots[]={0x14000000u|0x9f2,0x14000000u|0x10,0xd503201fu};
    w->slot_word=slots[rnd()%3];
}
static void pick_cpu(struct cpu *c)
{
    memset(c,0,sizeof *c);
    for(unsigned i=0;i<31;i++)c->regs[i]=rnd();
    c->clock=(struct guest_clock){rnd()%100,rnd(),rnd(),rnd()%4,rnd()%5 ? 3 : rnd()&0xff};
    pick_sprr(&c->sprr);
    c->uclock.reads=rnd()%50;c->usprr.reads=rnd()%50;c->user_vectors=rnd()%9;
    c->view_el0=1;c->fault_esr=0x96000045u;c->fault_far=0xdead0000u;
}

static unsigned outcome_of(const struct fast_side *s)
{
    unsigned found=FAST_EL0_NONE,moved=0;
    for(unsigned k=0;k<FAST_EL0_RESULTS-1;k++)if(s->outcomes[k]) {found=k+1;moved+=(unsigned)s->outcomes[k];}
    CHECK(moved<=1);
    return found;
}

static unsigned long long handled[3],declined[FAST_EL0_RESULTS],caused,same_other;
static void differential(unsigned iterations)
{
    for(unsigned n=0;n<iterations;n++) {
        struct world w;uint64_t vector;
        pick_world(&w,&vector);
        struct cpu a,b;pick_cpu(&a);b=a;
        const struct cpu before=b;
        struct fast_side s;fast_side_init(&s,&b,&w,w.hooks);
        uint64_t elr=VBAR_VA+vector,eb=elr;
        unsigned cls=fast_cross_entry(&s.hw,&s.state,w.physical_spsr,b.regs,&eb);
        unsigned outcome=outcome_of(&s);
        uint64_t ea=elr,locked_spsr=0xdead;
        int kind=locked_entry(&a,&w,vector,&ea,&locked_spsr);
        int el0_class=vector==0x400 && w.esr==0x02000000 && !(w.saved&31) && !(w.saved>>32) &&
                      w.native;
        int consistent=w.read2_ok && w.first.source==w.second.source &&
            w.first.hardware==w.second.hardware && w.first.pa==w.second.pa &&
            w.first.root==w.second.root && w.first.word==w.second.word;
        if(cls==FAST_CROSS_EL0_SYSREG_CLASS) {
            /* F1/F2/F10: exactly the locked emulation. */
            CHECK(kind==1 || kind==2);
            CHECK(outcome==(kind==1 ? FAST_EL0_CLOCK : FAST_EL0_UPERM));
            CHECK(!memcmp(&a,&b,sizeof a) && ea==eb && s.el0_spsr==locked_spsr);
            CHECK(eb==w.pc+4 && s.el0_spsr==w.saved && consistent && s.env.fetches==2);
            uint32_t word=w.first.word;unsigned rt=word&31;
            for(unsigned i=0;i<31;i++)
                CHECK(i==rt ? b.regs[i]==(kind==1 ? w.counter : b.sprr.uperm) : b.regs[i]==before.regs[i]);
            CHECK(!b.selects && b.view_el0==before.view_el0);   /* no kernel regime selected */
            CHECK(s.logged==~UINT64_C(0) && !s.first);
            handled[kind]++;
            continue;
        }
        if(el0_class && w.hooks) {
            /* F5/F7/F8/F9: a class entry declined: only its counter moved. */
            CHECK(cls==FAST_CROSS_NONE && outcome!=FAST_EL0_NONE);
            CHECK(!memcmp(&before,&b,sizeof b) && eb==elr && s.el0_spsr==0xdead);
            if(kind==1 || kind==2) {
                /* The locked path emulates it: the repeat read is the only cause. */
                CHECK(!consistent && outcome==FAST_EL0_GUARD);
                caused++;
            }
            if(kind==3)CHECK(outcome==FAST_EL0_WORD);
            if(outcome==FAST_EL0_WORD)CHECK(fast_el0_word_kind(w.first.word)==FAST_EL0_WORD);
            declined[outcome]++;
            continue;
        }
        /* Not this class (or no hooks, no native selection): no EL0 outcome,
         * and the boundary classifies exactly as it does without the hooks. */
        CHECK(outcome==FAST_EL0_NONE && s.el0_spsr==0xdead);
        CHECK(cls!=FAST_CROSS_EL0_SYSREG_CLASS);
        struct cpu c=before;
        uint64_t ec,logged=~UINT64_C(0),first=0;
        unsigned plain=plain_cross_entry(&c,&w,vector,&ec,&logged,&first);
        CHECK(plain==cls && ec==eb && !memcmp(&c,&b,sizeof c) && logged==s.logged && first==s.first);
        if(vector==0x400 && w.esr==0x02000000)CHECK(cls==FAST_CROSS_NONE);
        declined[FAST_EL0_NONE]++;
        same_other++;
    }
    CHECK(handled[1]>=2000 && handled[2]>=2000 && caused>=200);
    CHECK(declined[FAST_EL0_WORD]>=2000 && declined[FAST_EL0_GUARD]>=2000 && same_other>=20000);
    printf("differential: %u entries; emulated counter %llu UPERM %llu; declined other word %llu, "
           "guard %llu (%llu by the repeat read); not the class %llu\n",iterations,handled[1],
           handled[2],declined[FAST_EL0_WORD],declined[FAST_EL0_GUARD],caused,same_other);
}

static void sane_world(struct world *w,struct cpu *c,uint32_t word)
{
    memset(w,0,sizeof *w);
    w->esr=0x02000000;w->pc=UINT64_C(0x180000000);w->saved=0x20000000;w->vhcr=KERNEL_HCR;
    w->physical_spsr=5|(UINT64_C(1)<<22);w->counter=UINT64_C(0x123456789);w->sp_el0=0x16f000000;
    w->host_hz=19200000;w->guest_hz=24000000;
    w->root_ok=w->read_ok=w->read2_ok=w->has_counter=w->native=w->hooks=1;
    w->first=(struct fetch_model){0x60000a00000403,0x60000a00000403,MEM_LOW+0x1000,MEM_LOW+0x8000,word};
    w->second=w->first;w->slot_word=0x14000000u|0x9f2;
    memset(c,0,sizeof *c);
    for(unsigned i=0;i<31;i++)c->regs[i]=0x1000+i;
    c->clock.cntkctl=3;sprr_root_reset(&c->sprr,8);c->view_el0=1;
}
static unsigned run_fast(struct cpu *c,const struct world *w,uint64_t *elr,uint64_t *spsr,unsigned *outcome)
{
    struct fast_side s;fast_side_init(&s,c,w,1);
    *elr=VBAR_VA+0x400;
    unsigned cls=fast_cross_entry(&s.hw,&s.state,w->physical_spsr,c->regs,elr);
    *spsr=s.el0_spsr;*outcome=outcome_of(&s);
    return cls;
}
/* Directed cases the random mix might under-sample. */
static void directed(void)
{
    struct world w;struct cpu c;uint64_t elr,spsr;unsigned outcome;
    /* Rt=31 (XZR): emulated, no register written (F1). */
    sane_world(&w,&c,UPERM_READ|31);struct cpu before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS && outcome==FAST_EL0_UPERM);
    CHECK(!memcmp(c.regs,before.regs,sizeof c.regs) && elr==w.pc+4 && spsr==w.saved);
    CHECK(c.sprr.reads==1 && c.usprr.reads==1 && c.usprr.value==SPRR_UPERM_INITIAL);
    sane_world(&w,&c,CLOCK_WORD|31);before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS && outcome==FAST_EL0_CLOCK);
    CHECK(!memcmp(c.regs,before.regs,sizeof c.regs) && c.clock.reads==1 && c.uclock.value==w.counter);
    /* x8 for dyld's TPRO check (0xd53ef1a8): x8 alone. */
    sane_world(&w,&c,0xd53ef1a8u);
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS && c.regs[8]==SPRR_UPERM_INITIAL);
    CHECK(c.regs[7]==0x1007 && c.regs[9]==0x1009);
    /* F4: a locked UPERM write on this vCPU, then the lock-free read sees it. */
    sane_world(&w,&c,UPERM_WRITE|3);c.regs[3]=SPRR_UPERM_INITIAL|SPRR_UPERM_TPRO_WRITE;
    uint64_t le=0,ls=0;
    CHECK(locked_entry(&c,&w,0x400,&le,&ls)==3 && c.sprr.uperm==(SPRR_UPERM_INITIAL|SPRR_UPERM_TPRO_WRITE));
    w.first.word=w.second.word=UPERM_READ|4;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS &&
          c.regs[4]==(SPRR_UPERM_INITIAL|SPRR_UPERM_TPRO_WRITE));
    /* ...and after this CPU's root reset, the reset value. */
    sprr_root_reset(&c.sprr,8);
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS && c.regs[4]==SPRR_UPERM_INITIAL);
    /* TPRO set without its UMPRR policy: invalid, declined unchanged. */
    sprr_root_reset(&c.sprr,0);c.sprr.uperm|=SPRR_UPERM_TPRO_WRITE;before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_GUARD &&
          !memcmp(&before,&c,sizeof c));
    /* The UPERM write itself never runs lock-free (F7). */
    sane_world(&w,&c,UPERM_WRITE|3);before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_WORD &&
          !memcmp(&before,&c,sizeof c));
    /* The other counter alias (C11_7) is guest_clock_user_read's UNHANDLED: locked. */
    sane_world(&w,&c,0xd53cfbe0u|2);before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_WORD);
    CHECK(locked_entry(&before,&w,0x400,&le,&ls)==0);
    /* Every one-bit neighbour of both words outside Rt declines (F7). */
    for(unsigned base=0;base<2;base++)for(unsigned bit=5;bit<32;bit++) {
        sane_world(&w,&c,(base ? UPERM_READ : CLOCK_WORD)^(UINT32_C(1)<<bit));before=c;
        CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    }
    /* EL0VCTEN clear, or no counter backend: declined like the locked path (F8). */
    sane_world(&w,&c,CLOCK_WORD|1);c.clock.cntkctl=1;before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_GUARD &&
          !memcmp(&before,&c,sizeof c));
    CHECK(locked_entry(&before,&w,0x400,&le,&ls)==0);
    sane_world(&w,&c,CLOCK_WORD|1);w.has_counter=0;before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_GUARD &&
          !memcmp(&before,&c,sizeof c));
    /* The last two user words of the address space: refused (F2). */
    sane_world(&w,&c,CLOCK_WORD|1);w.pc=(UINT64_C(1)<<47)-4;before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_GUARD);
    w.pc=(UINT64_C(1)<<47)-8;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS && elr==(UINT64_C(1)<<47)-4);
    /* A crash-class EL0 EC 0 entry with the crash ring on stays locked (F5). */
    sane_world(&w,&c,0x00201420u);w.crash_ring=1;before=c;
    CHECK(user_crash_classify(w.esr,w.far,c.regs[16],c.regs[1])!=0);
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_WORD &&
          !memcmp(&before,&c,sizeof c));
    /* ...an accepted word is emulated whatever the crash ring says. */
    sane_world(&w,&c,UPERM_READ|8);w.crash_ring=1;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_EL0_SYSREG_CLASS);
    /* EL1 origin at 0x000/0x200 with the same syndrome: never this class (F8). */
    sane_world(&w,&c,UPERM_READ|8);w.saved=9;
    struct fast_side s;fast_side_init(&s,&c,&w,1);elr=VBAR_VA+0x200;
    CHECK(fast_cross_entry(&s.hw,&s.state,5,c.regs,&elr)==FAST_CROSS_NONE && outcome_of(&s)==FAST_EL0_NONE);
    /* No native selection: EL0 entries decline before any read (F11). */
    sane_world(&w,&c,UPERM_READ|8);w.native=0;before=c;
    CHECK(run_fast(&c,&w,&elr,&spsr,&outcome)==FAST_CROSS_NONE && outcome==FAST_EL0_NONE &&
          !memcmp(&before,&c,sizeof c));
    /* No log bit for the class, and the logged classes' bits unchanged (F11). */
    CHECK(fast_cross_log_bit(FAST_CROSS_EL0_SYSREG_CLASS)==0);
    for(unsigned k=1;k<FAST_CROSS_CLASSES;k++)CHECK(fast_cross_log_bit(k)==UINT64_C(1)<<(7+k));
    CHECK(FAST_EXIT_CROSS_SLOT(FAST_CROSS_EL0_SYSREG_CLASS)==FAST_EXIT_CLASSES-1);
    CHECK(FAST_EXIT_CROSS_SLOT(1)==FAST_EXIT_TRAP_SLOT(FAST_TRAP_CLASSES-1)+1);
}

/* F12: the sub-class profile against the per-CPU EC 0x20 bucket. */
static void subclass(void)
{
    static struct service_profile p[GUEST_CPU_COUNT];
    static struct service_sub_profile s;
    memset(p,0,sizeof p);memset(&s,0,sizeof s);
    uint64_t now=1000,cancelled_entries=0,cancelled_wait=0;
    unsigned untagged=0;
    for(unsigned n=0;n<200000;n++) {
        unsigned cpu=(unsigned)(rnd()%GUEST_CPU_COUNT);
        struct service_profile *q=&p[cpu];
        unsigned category=rnd()%3 ? 0x20 : (unsigned[]){0x18,0x24,0x09,64,65,67}[rnd()%6];
        service_profile_begin(q,now,category);
        now+=rnd()%50;
        int acquired=rnd()%200!=0;
        uint64_t wait_start=q->enter_tick;
        service_profile_wait_done(q,now,acquired,rnd()%2);
        if(!acquired) {
            if(category==0x20) {cancelled_entries++;cancelled_wait+=now-wait_start;}
            continue;     /* a stop: no handler, no runtime_leave */
        }
        unsigned tag=SERVICE_SUB_OTHER;
        if(rnd()%5) {
            tag=(unsigned)(rnd()%SERVICE_SUB_BUCKETS);
            service_sub_tag(&s,cpu,tag);
            if(rnd()%4==0) {tag=(unsigned)(rnd()%SERVICE_SUB_BUCKETS);service_sub_tag(&s,cpu,tag);}
            if(rnd()%16==0)service_sub_tag(&s,cpu,SERVICE_SUB_BUCKETS+(unsigned)(rnd()%9)); /* ignored */
        } else untagged++;
        CHECK(s.current[cpu]==tag);
        now+=rnd()%400;
        struct service_sub_profile copy=s;
        int completed=q->stage==2;
        service_profile_end(q,now);
        service_sub_charge(&s,cpu,q,completed);
        CHECK(!s.current[cpu]);
        if(category==0x20) {
            struct service_profile_bucket *b=&s.buckets[tag],*o=&copy.buckets[tag];
            CHECK(b->entries==o->entries+1 && b->hold_ticks-o->hold_ticks==q->last_tick-q->acquire_tick &&
                  b->wait_ticks-o->wait_ticks==q->acquire_tick-q->enter_tick);
        } else CHECK(!memcmp(copy.buckets,s.buckets,sizeof s.buckets));
    }
    /* An end without an acquired entry (stage 0) charges nothing and clears the tag. */
    service_sub_tag(&s,1,SERVICE_SUB_VECTOR);
    struct service_sub_profile copy=s;
    struct service_profile idle=p[1];
    int completed=idle.stage==2;
    service_profile_end(&idle,now+5);
    service_sub_charge(&s,1,&idle,completed);
    CHECK(!completed && !memcmp(copy.buckets,s.buckets,sizeof s.buckets) && !s.current[1]);
    service_sub_charge(&s,9,&p[0],1);   /* out of range: nothing */
    uint64_t entries=0,wait=0,hold=0,sub_entries=0,sub_wait=0,sub_hold=0;
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++) {
        CHECK(!p[cpu].errors || cpu==1);
        entries+=p[cpu].buckets[0x20].entries;wait+=p[cpu].buckets[0x20].wait_ticks;
        hold+=p[cpu].buckets[0x20].hold_ticks;
    }
    for(unsigned k=0;k<SERVICE_SUB_BUCKETS;k++) {
        sub_entries+=s.buckets[k].entries;sub_wait+=s.buckets[k].wait_ticks;sub_hold+=s.buckets[k].hold_ticks;
    }
    CHECK(sub_hold==hold && sub_entries+cancelled_entries==entries && sub_wait+cancelled_wait==wait);
    CHECK(s.buckets[SERVICE_SUB_OTHER].entries>=untagged/4 && cancelled_entries>0);
    /* Native-call tags: monitor_call_impl's endpoint split, below 32. */
    for(unsigned n=0;n<100000;n++) {
        uint64_t x16=rnd();
        switch(rnd()%4) {
        case 0: x16&=0x3f;break;
        case 1: x16&=UINT64_C(0xff000000000000ff);break;
        case 2: x16&=UINT64_C(0x00ff0000ffffffff);break;
        default: break;
        }
        uint32_t cmd=(uint32_t)((x16>>56)&0xff),domain=(uint32_t)((x16>>48)&0xff);
        uint32_t table=(uint32_t)((x16>>32)&0xffff),endpoint=(uint32_t)x16;
        int counted=cmd==0 && domain==0 && table==0 && endpoint<64;   /* endpoint_calls[endpoint] */
        unsigned tag=service_sub_call(x16,0);
        CHECK(tag==(counted && endpoint<SERVICE_SUB_ENDPOINTS ? SERVICE_SUB_ENDPOINT+endpoint :
                    SERVICE_SUB_CALL_OTHER));
    }
    printf("subclass: 200000 entries over %u CPUs; hold %llu ticks in %u buckets, %llu cancelled\n",
           GUEST_CPU_COUNT,(unsigned long long)sub_hold,SERVICE_SUB_BUCKETS,
           (unsigned long long)cancelled_entries);
}

/* F13: the exit timing word. */
static void timing(void)
{
    struct fast_exit_cpu p;memset(&p,0,sizeof p);
    uint64_t start=UINT64_C(0x00ffffffffffff00);          /* wraps at 2^56 */
    p.timing[3]=0;
    fast_exit_charge(&p,fast_exit_mark(start,3),start+0x40);
    CHECK(p.timing[3]==((UINT64_C(1)<<FAST_EXIT_COUNT_SHIFT)|0x40) && p.max==0x40);
    fast_exit_charge(&p,fast_exit_mark(start,3),(start+0x140)&((UINT64_C(1)<<56)-1));
    CHECK(p.timing[3]==((UINT64_C(2)<<FAST_EXIT_COUNT_SHIFT)|0x180) && p.max==0x140);
    struct fast_exit_cpu q=p;
    fast_exit_charge(&p,start,start+9);                      /* class 0: the locked path */
    fast_exit_charge(&p,start|((uint64_t)(FAST_EXIT_CLASSES+1)<<56),start+9);
    fast_exit_charge(&p,2,start);                            /* async: the vector kind */
    CHECK(!memcmp(&p,&q,sizeof p));
    fast_exit_charge(&p,fast_exit_mark(start,0),start+FAST_EXIT_TICK_LIMIT);
    CHECK(p.slow==1 && p.timing[0]==0 && p.max==0x140);
    for(unsigned k=0;k<FAST_EXIT_CLASSES;k++) {
        uint64_t sum=0;
        for(unsigned n=0;n<1000;n++) {
            uint64_t t=rnd()%5000,at=rnd()&((UINT64_C(1)<<56)-1);
            sum+=t;fast_exit_charge(&p,fast_exit_mark(at,k),at+t);
        }
        if(k==3)sum+=0x180;
        uint64_t count=p.timing[k]>>FAST_EXIT_COUNT_SHIFT;
        CHECK(count==(k==3 ? 1002u : 1000u) && (p.timing[k]&((UINT64_C(1)<<FAST_EXIT_COUNT_SHIFT)-1))==sum);
    }
    printf("timing: %u classes, class 0 and out-of-range marks ignored, wrap and slow exits\n",
           FAST_EXIT_CLASSES);
}

#if FAST_EL0_THREADS
/* F6 under the thread sanitizer: five vCPUs emulate lock-free from private
 * state while a sixth CPU, holding the service lock as an SPTM call does,
 * remaps the page between a counter word and a UPERM word (break, then the
 * source leaf, then the hardware leaf). A read is user_instruction_read's
 * rule: both leaves valid and naming one PA. */
struct mapping { uint64_t source,hardware; };
static struct mapping live;              /* written under the lock, read lock-free (atomics) */
static const uint32_t page_words[2]={CLOCK_WORD|3,UPERM_READ|5};
static struct guest_service_lock remap_lock;
static int done_remapping;
static int thread_word(void *ctx,uint64_t pc,struct fast_el0_fetch *out)
{
    (void)ctx;(void)pc;
    uint64_t s=__atomic_load_n(&live.source,__ATOMIC_ACQUIRE);
    uint64_t h=__atomic_load_n(&live.hardware,__ATOMIC_ACQUIRE);
    if(!(s&1) || !(h&1) || (s&~UINT64_C(0xfff))!=(h&~UINT64_C(0xfff)))return 0;
    uint64_t pa=s&~UINT64_C(0xfff);
    *out=(struct fast_el0_fetch){s,h,pa,MEM_LOW,page_words[(pa>>14)&1]};
    return 1;
}
struct vthread { struct cpu cpu;uint64_t outcomes[FAST_EL0_RESULTS-1],fast,declined; };
static void thread_note(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root)
{
    struct vthread *t=ctx;(void)pc;(void)saved;(void)root;
    CHECK(word==page_words[kind==FAST_EL0_UPERM]);
    if(kind==FAST_EL0_CLOCK)t->cpu.uclock.reads++;else t->cpu.usprr.reads++;
}
static uint64_t thread_counter(void *ctx) {(void)ctx;return 77;}
static void *vcpu_thread(void *arg)
{
    struct vthread *t=arg;
    struct clock_backend clock={t,thread_counter,model_control};
    const struct fast_el0_hw hw={.ctx=t,.fetch=thread_word,.clock=&clock,.note=thread_note};
    uint64_t spsr=0;
    const struct fast_el0_vcpu v={&t->cpu.clock,&t->cpu.sprr,t->cpu.regs,t->outcomes,&spsr};
    while(!__atomic_load_n(&done_remapping,__ATOMIC_ACQUIRE)) {
        uint64_t elr=0;
        t->cpu.regs[3]=t->cpu.regs[5]=1;
        unsigned r=fast_el0_sysreg(&hw,&v,0x400,0x02000000,UINT64_C(0x180000000),0,KERNEL_HCR,&elr);
        if(r==FAST_EL0_CLOCK)CHECK(t->cpu.regs[3]==77 && t->cpu.regs[5]==1 && elr==UINT64_C(0x180000004));
        else if(r==FAST_EL0_UPERM)CHECK(t->cpu.regs[5]==SPRR_UPERM_INITIAL && t->cpu.regs[3]==1);
        else CHECK(r==FAST_EL0_GUARD && t->cpu.regs[3]==1 && t->cpu.regs[5]==1 && !elr);
        if(r==FAST_EL0_GUARD)t->declined++;else t->fast++;
    }
    return 0;
}
static void *remap_thread(void *arg)
{
    (void)arg;
    for(unsigned n=0;n<200000;n++) {
        while(guest_service_try(&remap_lock,5)!=SERVICE_OK) {}
        uint64_t leaf=(MEM_LOW+0x4000*(n&1))|0x403;
        if(n%3==0) {   /* break before make */
            __atomic_store_n(&live.source,0,__ATOMIC_RELEASE);
            __atomic_store_n(&live.hardware,0,__ATOMIC_RELEASE);
        }
        __atomic_store_n(&live.source,leaf,__ATOMIC_RELEASE);
        __atomic_store_n(&live.hardware,leaf,__ATOMIC_RELEASE);
        CHECK(guest_service_release(&remap_lock,5)==SERVICE_OK);
    }
    __atomic_store_n(&done_remapping,1,__ATOMIC_RELEASE);
    return 0;
}
static void threads(void)
{
    CHECK(guest_service_boot(&remap_lock)==SERVICE_OK);
    for(unsigned cpu=1;cpu<GUEST_CPU_COUNT;cpu++) {
        CHECK(guest_service_try(&remap_lock,0)==SERVICE_OK);
        CHECK(guest_service_reserve(&remap_lock,0,cpu)==SERVICE_OK);
        CHECK(guest_service_release(&remap_lock,0)==SERVICE_OK);
        CHECK(guest_service_arrive(&remap_lock,cpu)==SERVICE_OK);
    }
    live.source=live.hardware=MEM_LOW|0x403;
    static struct vthread t[GUEST_CPU_COUNT-1];
    pthread_t th[GUEST_CPU_COUNT];
    for(unsigned i=0;i<GUEST_CPU_COUNT-1;i++) {
        memset(&t[i],0,sizeof t[i]);t[i].cpu.clock.cntkctl=3;sprr_root_reset(&t[i].cpu.sprr,8);
        CHECK(!pthread_create(&th[i],0,vcpu_thread,&t[i]));
    }
    CHECK(!pthread_create(&th[GUEST_CPU_COUNT-1],0,remap_thread,0));
    uint64_t fast=0,declined_n=0;
    for(unsigned i=0;i<GUEST_CPU_COUNT;i++)CHECK(!pthread_join(th[i],0));
    for(unsigned i=0;i<GUEST_CPU_COUNT-1;i++) {
        CHECK(t[i].cpu.uclock.reads+t[i].cpu.usprr.reads==t[i].fast);
        CHECK(t[i].outcomes[FAST_EL0_CLOCK-1]+t[i].outcomes[FAST_EL0_UPERM-1]==t[i].fast);
        CHECK(t[i].outcomes[FAST_EL0_GUARD-1]==t[i].declined);
        fast+=t[i].fast;declined_n+=t[i].declined;
    }
    guest_service_stop(&remap_lock,0,SERVICE_STOP_NORMAL);
    printf("threads: %llu emulated, %llu declined while a lock holder remapped the page\n",
           (unsigned long long)fast,(unsigned long long)declined_n);
    CHECK(fast>0);
}
#endif

int main(void)
{
    directed();
    differential(600000);
    subclass();
    timing();
#if FAST_EL0_THREADS
    threads();
#endif
    printf("PASS: %llu fast-EL0-sysreg checks\n",checks);
    return 0;
}
#endif
