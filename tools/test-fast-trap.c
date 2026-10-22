/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_VCPU_TRAPS (compat/fast-trap.h): the lock-free emulation must be
 * the locked handler minus shared bookkeeping, for every register tuple and
 * every trap it accepts, and must decline everything else without changing
 * anything. The oracle below transcribes xnuboot_trap_locked's EC 0x09 and
 * EC 0x18 chain in order, calling the same compat handlers (pauth_pacga,
 * pauth_user_reg, guest_clock_access, sprr_access_with); tools/test-fast-trap.py
 * checks the transcription's register sets and order against probes/xnuboot.c.
 *
 * Failure inventory this covers: a register the locked path routes elsewhere
 * (ID group, IPI, timer writes, SPRR writes, switch cases) classified fast; a
 * timer, SPRR or GXF read answering other than the locked route (docs/
 * FAST-TRAP-BATCH-20261016.md); an ignored register the locked path claims; a
 * key write not
 * reaching the GA shadow a later PACGA signs with; a counter read skipping the
 * per-vCPU clock sample or the architectural read count; rt==31 / EL0 /
 * AArch32 origins; a declined trap leaving partial state; admission while
 * stopped/closed/not running; fast traps still taking the service lock; data
 * races between fast vCPUs and a lock holder (thread-sanitizer build).
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Icompat -Ishadow tools/test-fast-trap.c compat/pauth.c compat/pauth-user.c \
 *    compat/clock.c compat/service-lock.c -o build/test-fast-trap && build/test-fast-trap
 * cc -std=gnu11 -O1 -g -fsanitize=thread -pthread -DFAST_TRAP_THREADS=1 -Icompat -Ishadow \
 *    tools/test-fast-trap.c compat/pauth.c compat/pauth-user.c compat/clock.c \
 *    compat/service-lock.c -o build/test-fast-trap-tsan && build/test-fast-trap-tsan
 * -DFAST_TRAP_PRE_CHANGE=1 removes the fast path from the trap-entry model: the
 * lock-count regression must then fail (the pre-change behavior). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-trap.h"
#include "sprr.h"
#include "ipi.h"
#include "service-lock.h"
#ifndef FAST_TRAP_THREADS
#define FAST_TRAP_THREADS 0
#endif
#ifndef FAST_TRAP_PRE_CHANGE
#define FAST_TRAP_PRE_CHANGE 0
#endif
#if FAST_TRAP_THREADS
#include <pthread.h>
#endif

static unsigned long long checks;
#define CHECK(x) do {__atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); \
    if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)

#define SR(op0,op1,crn,crm,op2) FAST_TRAP_SYSREG(op0,op1,crn,crm,op2)
/* xnuboot.c's switch cases (tools/test-fast-trap.py compares these). */
#define SR_SCTLR_EL1 SR(3,0,1,0,0)
#define SR_TTBR0_EL1 SR(3,0,2,0,0)
#define SR_TTBR1_EL1 SR(3,0,2,0,1)
#define SR_TCR_EL1 SR(3,0,2,0,2)
#define SR_MAIR_EL1 SR(3,0,10,2,0)
#define SR_ESR_EL1 SR(3,0,5,2,0)
#define SR_FAR_EL1 SR(3,0,6,0,0)
#define SR_AMXIDR_EL1 SR(3,6,15,2,7)
#define SR_GXF_STATUS_EL1 SR(3,6,15,8,0)
#define SR_CONST_LOWER SR(3,0,11,1,2)
#define SR_CONST_UPPER SR(3,0,11,1,3)

#define MEM_LOW UINT64_C(0x80000000)
#define MEM_WORDS 4096u
#define MEM_HIGH (MEM_LOW+4*MEM_WORDS)

/* One vCPU as the monitor keeps it, plus its hardware registers. */
struct cpu {
    struct pauth_user_state pauth;
    uint64_t apga_lo,apga_hi,pacga_calls,arch_counter_reads;
    struct guest_clock clock;
    uint64_t ticks,samples;              /* clock backend: counter value, reads */
    uint64_t esr,far,sp_el0,sp_el1,esr_writes;
    struct sprr_state sprr;
    struct guest_timer timer;
    uint64_t timer_pending;              /* the line timer_sync last synced */
};
struct shared { uint64_t traps,records,last_reg; };
static uint32_t ram[MEM_WORDS];

static uint64_t rng=0x243f6a8885a308d3ULL;
static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

static uint64_t counter(void *ctx) {struct cpu *c=ctx;c->samples++;return c->ticks+=17;}
static int control(void *ctx,uint64_t value) {(void)ctx;(void)value;return 0;}
static uint64_t hw_pa(void *ctx,uint64_t va)
{(void)ctx;return va>=MEM_LOW && va<MEM_HIGH+64 ? va : 0;}
static uint32_t hw_fetch(void *ctx,uint64_t pa) {(void)ctx;return ram[(pa-MEM_LOW)/4];}
static uint64_t hw_stack(void *ctx,uint64_t spsr) {struct cpu *c=ctx;return spsr&1 ? c->sp_el1 : c->sp_el0;}
/* Deterministic stand-in for the native PACGA: depends on the GA shadow. */
static uint64_t hw_sign(void *ctx,uint64_t data,uint64_t modifier)
{
    struct cpu *c=ctx;
    uint64_t h=data*0x9e3779b97f4a7c15ULL^modifier^c->apga_lo*0xbf58476d1ce4e5b9ULL^c->apga_hi;
    h^=h>>31;h*=0x94d049bb133111ebULL;return h^(h>>29);
}
static uint64_t hw_esr(void *ctx) {return ((struct cpu *)ctx)->esr;}
static uint64_t hw_far(void *ctx) {return ((struct cpu *)ctx)->far;}

static void cpu_init(struct cpu *c,unsigned seed)
{
    memset(c,0,sizeof(*c));pauth_user_init(&c->pauth);
    c->apga_lo=c->pauth.key[PAUTH_GA].lo;c->apga_hi=c->pauth.key[PAUTH_GA].hi;
    c->ticks=1000*seed;c->esr=0x96000000|seed;c->far=0xfffffe0000001000ULL+seed;
    c->sp_el0=0xfffffe1000000000ULL+seed;c->sp_el1=0xfffffe2000000000ULL+seed;
    sprr_root_reset(&c->sprr,0);
    c->timer.ctl=seed&1;c->timer.cval=c->ticks+400+seed;
    c->timer_pending=(uint64_t)guest_timer_pending(&c->timer,c->ticks);
}
static struct fast_trap_hw hw_of(struct cpu *c,struct clock_backend *b,int pac)
{
    *b=(struct clock_backend){c,counter,control};
    return (struct fast_trap_hw){.ctx=c,.mem_low=MEM_LOW,.mem_high=MEM_HIGH,.pac_supported=pac,
        .guest_pa=hw_pa,.fetch=hw_fetch,.stack=hw_stack,.sign=hw_sign,.esr=hw_esr,.far=hw_far,
        .clock=b};
}
static struct fast_trap_vcpu state_of(struct cpu *c)
{return (struct fast_trap_vcpu){&c->pauth,&c->apga_lo,&c->apga_hi,&c->pacga_calls,
                                &c->clock,&c->arch_counter_reads,&c->timer,&c->sprr,
                                &c->timer_pending};}

/* Where xnuboot_trap_locked sends an EC 0x09/0x18 trap. */
enum route {R_STOP,R_PACGA,R_ID,R_PAUTH,R_IPI,R_CNTP,R_TIMER,R_CLOCK,R_SPRR,R_CASE,R_ESR,R_FAR,R_DEFAULT,
            R_TIMER_READ,R_SPRR_READ,R_ZERO,R_TIMER_WRITE};
static int is_case(uint64_t reg)
{
    return reg==SR_CONST_LOWER || reg==SR_CONST_UPPER || reg==SR_TTBR0_EL1 ||
        reg==SR_TTBR1_EL1 || reg==SR_TCR_EL1 || reg==SR_MAIR_EL1 || reg==SR_SCTLR_EL1 ||
        reg==SR_AMXIDR_EL1 || reg==SR_GXF_STATUS_EL1;
}
/* The locked handler, in xnuboot_trap_locked's order. Emulates only routes a
 * fast class could share (PACGA, key registers, counters, ESR/FAR, timer and
 * SPRR reads, GXF_STATUS and the default); other routes are reported without
 * emulation. A timer access's timer_sync and device-reset check are shared
 * state, outside this per-vCPU model. */
static enum route locked(struct cpu *c,struct shared *sh,int pac,uint64_t esr,uint64_t spsr,
                         uint64_t *frame,uint64_t *elr)
{
    uint64_t ec=esr>>26,iss=esr&0x1ffffff;
    if(ec==0x09 && pac) {
        uint64_t pa=hw_pa(c,*elr);
        if(pa>=MEM_LOW && pa<=MEM_HIGH-4) {
            uint64_t sp=hw_stack(c,spsr);uint32_t word=hw_fetch(c,pa);
            if(pauth_pacga(word,frame,sp,hw_sign,c)) {
                c->pacga_calls++;sh->records++;*elr+=4;return R_PACGA;
            }
        }
    }
    if(ec!=0x18)return R_STOP;
    sh->traps++;
    uint64_t reg=iss&~((UINT64_C(0x1f)<<5)|1),rt=(iss>>5)&0x1f;
    unsigned op0=(unsigned)((iss>>20)&3),op1=(unsigned)((iss>>14)&7);
    unsigned crn=(unsigned)((iss>>10)&15),crm=(unsigned)((iss>>1)&15);
    if(op0==3 && op1==0 && crn==0 && crm<8 && (iss&1))return R_ID;
    uint64_t value=rt==31 ? 0 : frame[rt];int is_read=(int)(iss&1);
    if(pauth_user_reg(&c->pauth,reg,is_read,&value)) {
        c->apga_lo=c->pauth.key[PAUTH_GA].lo;c->apga_hi=c->pauth.key[PAUTH_GA].hi;
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return R_PAUTH;
    }
    if(reg==IPI_RR_LOCAL || reg==IPI_RR_GLOBAL || reg==IPI_SR)return R_IPI;
    if(reg==CLOCK_ARCH_CNTP_CTL)return R_CNTP;
    if(op0==3 && op1==3 && crn==14 && reg!=CLOCK_ARCH_CNTVCT && reg!=CLOCK_ARCH_CNTVCTSS)
        return R_STOP;
    if(reg==CLOCK_ARCH_CNTVCT || reg==CLOCK_ARCH_CNTVCTSS)c->arch_counter_reads+=(unsigned)is_read;
    if(reg==CLOCK_CNTV_CTL || reg==CLOCK_CNTV_TVAL) {
        if(!is_read && reg==CLOCK_CNTV_CTL)return R_TIMER;
        uint64_t now=counter(c);
        if(guest_timer_access(&c->timer,reg,is_read,&value,now)!=CLOCK_OK)return R_STOP;
        if(!is_read) {
            /* timer_sync's per-vCPU result: the line after the write. A read
             * changes no timer state, so its resync only reflects elapsed time,
             * which the armed EL2 timer delivers (not modeled). */
            c->timer_pending=(uint64_t)guest_timer_pending(&c->timer,now);
            *elr+=4;return R_TIMER_WRITE;
        }
        if(rt!=31)frame[rt]=value;
        *elr+=4;return R_TIMER_READ;
    }
    struct clock_backend b={c,counter,control};
    enum clock_result cr=guest_clock_access(&c->clock,&b,reg,is_read,&value);
    if(cr!=CLOCK_UNHANDLED) {
        if(cr!=CLOCK_OK)return R_STOP;
        if(is_read && rt!=31)frame[rt]=value;
        *elr+=4;return R_CLOCK;
    }
    if(reg==SPRR_UPERM && !is_read && value!=c->sprr.uperm)return R_SPRR;
    if(is_read) {
        enum sprr_result sr=sprr_access_with(&c->sprr,reg,is_read,&value,0,0);
        if(sr!=SPRR_UNHANDLED) {
            if(sr!=SPRR_OK)return R_STOP;
            if(rt!=31)frame[rt]=value;
            *elr+=4;return R_SPRR_READ;
        }
    } else {
        struct sprr_state probe=c->sprr;uint64_t probe_value=value;
        if(sprr_access_with(&probe,reg,is_read,&probe_value,0,0)!=SPRR_UNHANDLED)return R_SPRR;
    }
    enum route route=R_DEFAULT;
    if(reg==SR_ESR_EL1) {
        if(is_read)value=c->esr;else {c->esr=value;c->esr_writes++;}
        route=R_ESR;
    } else if(reg==SR_FAR_EL1) {
        if(is_read)value=c->far;else c->far=value;
        route=R_FAR;
    } else if(reg==SR_GXF_STATUS_EL1) {
        if(is_read)value=0;             /* xnuboot.c's case: no record */
        route=R_ZERO;
    } else if(is_case(reg))return R_CASE;
    else {sh->records++;sh->last_reg=reg;if(is_read)value=0;}
    if(is_read && rt!=31)frame[rt]=value;
    *elr+=4;return route;
}
static uint64_t esr_sysreg(uint64_t reg,unsigned rt,int is_read)
{return (UINT64_C(0x18)<<26)|(UINT64_C(1)<<25)|reg|((uint64_t)rt<<5)|(unsigned)is_read;}
static uint64_t esr_pacga(void) {return (UINT64_C(0x09)<<26)|(UINT64_C(1)<<25);}

/* Every Op0=3 tuple in both directions: each fast class is exactly the
 * locked route it replaces, and every key register pauth_user_reg claims is
 * classified KEY. */
static unsigned class_counts[FAST_TRAP_CLASSES];
static void classification_exhaustive(void)
{
    for(unsigned op1=0;op1<8;op1++)for(unsigned crn=0;crn<16;crn++)
    for(unsigned crm=0;crm<16;crm++)for(unsigned op2=0;op2<8;op2++)
    for(int is_read=0;is_read<2;is_read++) {
        uint64_t reg=SR(3,op1,crn,crm,op2);
        struct pauth_user_state scratch;pauth_user_init(&scratch);uint64_t value=5;
        CHECK(fast_trap_key_reg(reg)==pauth_user_reg(&scratch,reg,is_read,&value));
        unsigned cls=fast_trap_sysreg_class(reg,is_read);
        class_counts[cls]++;
        struct cpu c;cpu_init(&c,1);struct shared sh={0};
        uint64_t frame[31]={0},elr=0xfffffe0000100000ULL;
        for(unsigned i=0;i<31;i++)frame[i]=0x1111111111111111ULL*(i+1);
        enum route r=locked(&c,&sh,1,esr_sysreg(reg,3,is_read),5,frame,&elr);
        switch(cls) {
        case FAST_TRAP_KEY: CHECK(r==R_PAUTH);break;
        case FAST_TRAP_COUNTER: CHECK(r==R_CLOCK && is_read && fast_trap_counter_reg(reg));break;
        case FAST_TRAP_ESR: CHECK(r==R_ESR && is_read);break;
        case FAST_TRAP_FAR: CHECK(r==R_FAR && is_read);break;
        case FAST_TRAP_IGNORE: CHECK(r==R_DEFAULT && sh.records==1);break;
        case FAST_TRAP_TIMER: CHECK(r==R_TIMER_READ && is_read);break;
        case FAST_TRAP_SPRR: CHECK(r==R_SPRR_READ && is_read);break;
        case FAST_TRAP_ZERO: CHECK(r==R_ZERO && sh.records==0);break;
        case FAST_TRAP_TIMER_WRITE: CHECK(r==R_TIMER_WRITE && !is_read && reg==CLOCK_CNTV_TVAL);break;
        case FAST_TRAP_NONE: CHECK(r!=R_PAUTH && r!=R_TIMER_READ && r!=R_SPRR_READ && r!=R_ZERO &&
                                   r!=R_TIMER_WRITE);break;
        default: CHECK(0);
        }
    }
    CHECK(class_counts[FAST_TRAP_KEY]==2*13 && class_counts[FAST_TRAP_COUNTER]==4 &&
          class_counts[FAST_TRAP_ESR]==1 && class_counts[FAST_TRAP_FAR]==1 &&
          class_counts[FAST_TRAP_IGNORE]==2*FAST_TRAP_IGNORED && FAST_TRAP_IGNORED==20 &&
          class_counts[FAST_TRAP_TIMER]==2 && class_counts[FAST_TRAP_SPRR]==4 &&
          class_counts[FAST_TRAP_ZERO]==2 && class_counts[FAST_TRAP_TIMER_WRITE]==1 &&
          class_counts[FAST_TRAP_IDLE_POLL]==0);
    /* Ignored registers 0..6 keep bits 1..7; 7..19 take 14..26, above the
     * exception boundary's 8..13. */
    uint64_t bits=0;
    for(unsigned i=0;i<FAST_TRAP_IGNORED;i++) {
        uint64_t bit=fast_trap_log_bit(FAST_TRAP_IGNORE,fast_trap_ignored[i]);
        CHECK(bit==(i<7 ? UINT64_C(2)<<i : UINT64_C(1)<<(14+i-7)) && !(bits&bit));
        bits|=bit;
    }
    CHECK(!(bits&UINT64_C(0x3f01)) && bits<(UINT64_C(1)<<27));
    CHECK(fast_trap_log_bit(FAST_TRAP_PACGA,0)==1 && !fast_trap_log_bit(FAST_TRAP_KEY,SR(3,0,2,1,0)));
    CHECK(!fast_trap_log_bit(FAST_TRAP_TIMER,CLOCK_CNTV_CTL) && !fast_trap_log_bit(FAST_TRAP_SPRR,SPRR_PPERM) &&
          !fast_trap_log_bit(FAST_TRAP_ZERO,SR_GXF_STATUS_EL1) &&
          !fast_trap_log_bit(FAST_TRAP_TIMER_WRITE,CLOCK_CNTV_TVAL));
}

/* A trap for the differential: fast-class registers, their neighbours,
 * random tuples and PACGA (valid, wrong word, unmapped, outside RAM). */
static uint64_t pick_trap(uint64_t *spsr,uint64_t *elr,int *pac)
{
    static const uint64_t hot[]={SR(3,0,2,1,2),SR(3,0,2,1,3),SR(3,0,2,2,2),SR(3,0,2,2,3),
        SR(3,0,2,3,0),SR(3,0,2,3,1),SR(3,4,15,1,0),SR(3,4,15,1,1),SR(3,4,15,0,4),
        SR(3,0,2,1,0),SR(3,0,2,2,0),SR(3,4,15,11,7),SR(3,4,15,10,6),SR(3,3,14,0,2),
        SR(3,3,14,0,6),SR(3,4,15,9,6),SR(3,1,15,0,5),SR(3,1,15,15,4),SR_ESR_EL1,SR_FAR_EL1,
        SR(3,0,13,0,1),SR(3,4,15,13,6),SR(3,4,15,13,7),SR(3,2,15,0,0),SR(3,2,15,1,0),
        SR(3,2,15,2,0),SR(3,4,15,1,2),SR(3,4,15,1,3),SR(3,6,15,1,5),SR(3,6,15,1,6),
        SR(3,5,15,0,0),SR(3,5,15,1,1),SR(3,3,14,2,1),SR_TTBR0_EL1,SR_SCTLR_EL1,
        SR(3,1,15,0,0),SR(3,7,15,6,4),SR(3,1,15,0,1),SR(3,7,15,6,5),
        SR(3,0,0,1,0),SR(3,0,0,7,7),SR_GXF_STATUS_EL1,SR(3,6,15,3,0),SR(3,6,15,3,1),
        SR(3,2,15,9,0),SR(3,2,15,10,0),SR(3,2,15,8,0),SR(3,4,15,15,6),SR(3,4,15,1,3),
        SR(3,4,15,10,4),SR(3,1,15,1,5),SR(3,4,15,1,4),SR(3,1,15,0,4)};
    static const uint64_t modes[]={5,5,5,4,4,0,0x10|5,9};
    *spsr=modes[rnd()%8]|(rnd()&UINT64_C(0xf0000000));
    *pac=(rnd()%16)!=0;
    unsigned kind=(unsigned)(rnd()%8);
    if(kind<2) {
        unsigned w=(unsigned)(rnd()%MEM_WORDS);
        *elr=kind ? MEM_LOW+4ull*w : (rnd()&1 ? MEM_HIGH-2 : 0x40000000ULL+4*w);
        return esr_pacga();
    }
    *elr=0xfffffe0000200000ULL+4*(rnd()%1024);
    uint64_t reg=kind<7 ? hot[rnd()%(sizeof hot/sizeof *hot)] :
        SR(3,rnd()%8,rnd()%16,rnd()%16,rnd()%8);
    unsigned rt=(unsigned)(rnd()%32);if(rnd()%8==0)rt=31;
    return esr_sysreg(reg,rt,(int)(rnd()&1));
}
static void differential(unsigned iterations)
{
    for(unsigned i=0;i<MEM_WORDS;i++) {
        uint32_t w=(uint32_t)rnd();
        /* PACGA Xd,Xn,Xm|SP: 0x9ac03000 | Rm<<16 | Rn<<5 | Rd; some other words. */
        if(i%3)w=0x9ac03000u|((w&31)<<16)|(((w>>5)&31)<<5)|((w>>10)&31);
        ram[i]=w;
    }
    struct cpu a,b;cpu_init(&a,3);cpu_init(&b,3);
    struct shared sa={0},sb={0};
    unsigned handled[FAST_TRAP_CLASSES]={0},declined=0;
    for(unsigned n=0;n<iterations;n++) {
        uint64_t spsr,elr,esr;int pac;esr=pick_trap(&spsr,&elr,&pac);
        uint64_t fa[31],fb[31];
        for(unsigned i=0;i<31;i++)fa[i]=fb[i]=rnd();
        uint64_t ea=elr,eb=elr,original[31];
        memcpy(original,fb,sizeof original);
        struct cpu before=b;
        struct clock_backend back;struct fast_trap_hw hw=hw_of(&b,&back,pac);
        struct fast_trap_vcpu st=state_of(&b);
        unsigned cls=fast_trap_emulate(&hw,&st,esr,spsr,fb,&eb);
        enum route r=locked(&a,&sa,pac,esr,spsr,fa,&ea);
        if(cls==FAST_TRAP_NONE) {
            /* Declined: nothing changed; the locked path runs instead. */
            CHECK(!memcmp(&before,&b,sizeof b) && eb==elr && !memcmp(original,fb,sizeof fb));
            enum route rb=locked(&b,&sb,pac,esr,spsr,fb,&eb);
            CHECK(rb==r);declined++;
        } else {
            unsigned mode=(unsigned)(spsr&31);
            CHECK(mode==4 || mode==5);
            static const enum route want[FAST_TRAP_CLASSES]={R_STOP,R_PACGA,R_PAUTH,
                R_CLOCK,R_ESR,R_FAR,R_DEFAULT,R_TIMER_READ,R_SPRR_READ,R_ZERO,R_TIMER_WRITE,R_STOP};
            CHECK(r==want[cls]);handled[cls]++;
        }
        CHECK(ea==eb && !memcmp(fa,fb,sizeof fa));
        CHECK(!memcmp(&a,&b,sizeof a));
        /* Only the shared bookkeeping differs: traps and log records. */
        if(sa.traps!=sb.traps || sa.records!=sb.records) {
            CHECK(cls!=FAST_TRAP_NONE);
            sb.traps=sa.traps;sb.records=sa.records;sb.last_reg=sa.last_reg;
        }
    }
    for(unsigned k=1;k<FAST_TRAP_CLASSES;k++)CHECK(k==FAST_TRAP_IDLE_POLL ? !handled[k] : handled[k]>=64);
    CHECK(declined>=iterations/8);
    printf("differential: %u traps, fast pacga %u key %u counter %u esr %u far %u ignore %u "
           "timer %u sprr %u zero %u timer-write %u, declined %u\n",iterations,handled[1],handled[2],
           handled[3],handled[4],handled[5],handled[6],handled[7],handled[8],handled[9],handled[10],declined);
}

/* guest_service_admitted never admits a CPU guest_service_try would refuse
 * as STOPPED, BAD_CPU or BAD_STATE, and admits every CPU try would accept
 * (owner free) while the stop word is clear. */
static void admission_exhaustive(void)
{
    unsigned admitted=0;
    for(unsigned code=0;code<4096;code++)for(unsigned variant=0;variant<6;variant++) {
        uint64_t life=0;
        for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)life|=(uint64_t)((code>>(2*cpu))&3)<<(3*cpu);
        if(variant==1)life|=SERVICE_ADMISSION_CLOSED;
        if(variant==2)life|=UINT64_C(5)<<(3*(code%6));          /* invalid state 5..7 */
        if(variant==3)life|=UINT64_C(1)<<40;                      /* stray bit */
        for(unsigned cpu=0;cpu<=GUEST_CPU_COUNT;cpu++)for(unsigned stop=0;stop<2;stop++) {
            struct guest_service_lock lock={0,0,life};
            if(stop) {lock.stop=(UINT64_C(1)<<32)|1;lock.lifecycle|=SERVICE_ADMISSION_CLOSED;}
            if(variant==4 && !stop)lock.stop=(UINT64_C(2)<<32)|2; /* stop word alone: stricter */
            int a=guest_service_admitted(&lock,cpu);
            struct guest_service_lock copy=lock;
            enum guest_service_result r=guest_service_try(&copy,cpu);
            if(a)CHECK(r==SERVICE_OK && copy.owner==cpu+1);
            else if(!lock.stop)CHECK(r!=SERVICE_OK);
            if(variant==5 && !stop) {   /* owner held by another CPU: still admitted, try busy */
                struct guest_service_lock held=lock;held.owner=cpu<GUEST_CPU_COUNT-1 ? cpu+2 : 1;
                CHECK(guest_service_admitted(&held,cpu)==a);
                if(a)CHECK(guest_service_try(&held,cpu)==SERVICE_BUSY);
            }
            admitted+=(unsigned)a;
        }
    }
    CHECK(guest_service_admitted(0,0)==0);
    CHECK(admitted>0);
}

/* The trap entry, modeled on xnuboot_trap: census, fast path (unless the
 * pre-change model is built), then the locked path. Counts lock acquisitions. */
struct entry {
    struct guest_service_lock *lock;struct cpu *cpu;struct shared *shared;
    struct fast_trap_cpu fast;uint64_t acquisitions;unsigned slot;
};
static int trap_entry(struct entry *e,uint64_t esr,uint64_t spsr,uint64_t *frame,uint64_t *elr)
{
#if !FAST_TRAP_PRE_CHANGE
    uint64_t ec=esr>>26,reg=0;unsigned cls=FAST_TRAP_NONE;
    if(ec==0x09)cls=FAST_TRAP_PACGA;
    else if(ec==0x18) {reg=(esr&0x1ffffff)&~((UINT64_C(0x1f)<<5)|1);
        cls=fast_trap_sysreg_class(reg,(int)(esr&1));}
    if(cls!=FAST_TRAP_NONE) {
        uint64_t bit=fast_trap_log_bit(cls,reg);
        if(bit && !(e->fast.logged&bit)) {e->fast.logged|=bit;e->fast.first++;e->fast.declined++;}
        else if(guest_service_admitted(e->lock,e->slot)) {
            struct clock_backend b;struct fast_trap_hw hw=hw_of(e->cpu,&b,1);
            struct fast_trap_vcpu st=state_of(e->cpu);
            unsigned done=fast_trap_emulate(&hw,&st,esr,spsr,frame,elr);
            if(done!=FAST_TRAP_NONE) {e->fast.handled[done]++;if(ec==0x18)e->fast.sysreg++;return 0;}
            e->fast.declined++;
        } else e->fast.declined++;
    }
#endif
    for(;;) {
        enum guest_service_result r=guest_service_try(e->lock,e->slot);
        if(r==SERVICE_OK)break;
        if(r!=SERVICE_BUSY)return 1;
    }
    e->acquisitions++;
    enum route route=locked(e->cpu,e->shared,1,esr,spsr,frame,elr);
    CHECK(guest_service_release(e->lock,e->slot)==SERVICE_OK);
    return route==R_STOP;
}
/* Regression: steady-state fast-class traps take no service lock. The
 * pre-change model takes it for every trap and fails here. */
static void lock_regression(void)
{
    struct guest_service_lock lock={0};
    CHECK(guest_service_boot(&lock)==SERVICE_OK);
    struct cpu c;cpu_init(&c,9);struct shared sh={0};
    struct entry e={.lock=&lock,.cpu=&c,.shared=&sh,.slot=0};
    for(unsigned i=0;i<MEM_WORDS;i++)ram[i]=0x9ac33020u|(i%29);  /* pacga x0|..,x1,x3 */
    static const uint64_t regs[]={SR(3,0,2,1,2),SR(3,4,15,11,7),SR(3,0,13,0,1),
        SR(3,2,15,0,0),SR(3,2,15,1,0),SR(3,4,15,13,6),SR_ESR_EL1};
    const unsigned traps=7000;
    for(unsigned n=0;n<traps;n++) {
        uint64_t frame[31]={0},elr;
        uint64_t esr=n%2 ? esr_pacga() : esr_sysreg(regs[(n/2)%7],2,regs[(n/2)%7]!=SR(3,0,13,0,1));
        elr=n%2 ? MEM_LOW+4ull*(n%MEM_WORDS) : 0xfffffe0000300000ULL;
        CHECK(!trap_entry(&e,esr,5,frame,&elr));
    }
    printf("lock regression: %u fast-class traps, %llu lock acquisitions, %llu first-occurrence\n",
           traps,(unsigned long long)e.acquisitions,(unsigned long long)e.fast.first);
    /* Only first occurrences of recording classes (PACGA, 4 ignored) lock. */
    CHECK(e.acquisitions<=5);
    /* A stop closes the fast path: every later trap goes to the lock and stops. */
    guest_service_stop(&lock,1,SERVICE_STOP_NORMAL);
    uint64_t frame[31]={0},elr=0xfffffe0000300000ULL;
    CHECK(trap_entry(&e,esr_sysreg(SR(3,0,2,1,2),2,1),5,frame,&elr)==1);
}

#if FAST_TRAP_THREADS
/* Six vCPUs emulate fast traps on private state while a seventh CPU holds
 * and releases the service lock and mutates shared state, then stops. The
 * sanitizer must see no race; each vCPU's final state must equal a
 * sequential replay of its own trap sequence. */
struct worker { struct entry e;struct cpu cpu;uint64_t seed,frames,fast,locked; };
static struct guest_service_lock shared_lock;
static struct shared shared_state;
static volatile int stop_flag;
/* CPU0 boots; it reserves each secondary while owning the token, as
 * secondary_launch does, and each secondary arrives. All six then run. */
static void admit_all(struct guest_service_lock *lock)
{
    CHECK(guest_service_boot(lock)==SERVICE_OK);
    for(unsigned cpu=1;cpu<GUEST_CPU_COUNT;cpu++) {
        CHECK(guest_service_try(lock,0)==SERVICE_OK);
        CHECK(guest_service_reserve(lock,0,cpu)==SERVICE_OK);
        CHECK(guest_service_release(lock,0)==SERVICE_OK);
        CHECK(guest_service_arrive(lock,cpu)==SERVICE_OK);
    }
}
static void *vcpu_thread(void *arg)
{
    struct worker *w=arg;uint64_t local=w->seed;
    for(unsigned n=0;n<20000;n++) {
        local^=local<<13;local^=local>>7;local^=local<<17;
        static const uint64_t regs[]={SR(3,0,2,1,2),SR(3,0,2,3,0),SR(3,4,15,11,7),
            SR(3,0,13,0,1),SR(3,2,15,0,0),SR_ESR_EL1,SR_FAR_EL1};
        uint64_t frame[31]={0},elr=MEM_LOW+4*(local%MEM_WORDS),esr;
        frame[1]=local;frame[3]=~local;
        if(local&1)esr=esr_pacga();
        else {uint64_t reg=regs[(local>>1)%7];
              esr=esr_sysreg(reg,2,reg==SR(3,0,2,1,2) || reg==SR(3,0,2,3,0) ? (int)((local>>9)&1) :
                                    reg!=SR(3,0,13,0,1));}
        uint64_t before=w->e.acquisitions;
        if(trap_entry(&w->e,esr,5,frame,&elr))break;
        if(w->e.acquisitions==before)w->fast++;else w->locked++;
        w->frames^=frame[0]^frame[2]^elr;
    }
    return 0;
}
static void *lock_thread(void *arg)
{
    (void)arg;
    for(unsigned n=0;n<20000 && !stop_flag;n++) {
        while(guest_service_try(&shared_lock,5)!=SERVICE_OK) {}
        shared_state.traps++;shared_state.records+=2;
        CHECK(guest_service_release(&shared_lock,5)==SERVICE_OK);
    }
    return 0;
}
static void threads(void)
{
    admit_all(&shared_lock);
    static struct worker w[GUEST_CPU_COUNT-1];
    pthread_t t[GUEST_CPU_COUNT];
    for(unsigned i=0;i<GUEST_CPU_COUNT-1;i++) {
        cpu_init(&w[i].cpu,i+1);w[i].seed=0x9e3779b97f4a7c15ULL*(i+1);
        w[i].e=(struct entry){.lock=&shared_lock,.cpu=&w[i].cpu,.shared=&shared_state,.slot=i};
        CHECK(!pthread_create(&t[i],0,vcpu_thread,&w[i]));
    }
    CHECK(!pthread_create(&t[GUEST_CPU_COUNT-1],0,lock_thread,0));
    for(unsigned i=0;i<GUEST_CPU_COUNT;i++)CHECK(!pthread_join(t[i],0));
    uint64_t fast=0,locked_n=0;
    for(unsigned i=0;i<GUEST_CPU_COUNT-1;i++) {
        /* Sequential replay of the same seed on a fresh private state. */
        struct worker r={0};cpu_init(&r.cpu,i+1);r.seed=w[i].seed;
        struct guest_service_lock solo={0};admit_all(&solo);
        struct shared ss={0};
        r.e=(struct entry){.lock=&solo,.cpu=&r.cpu,.shared=&ss,.slot=i};
        vcpu_thread(&r);
        CHECK(!memcmp(&r.cpu,&w[i].cpu,sizeof r.cpu) && r.frames==w[i].frames);
        fast+=w[i].fast;locked_n+=w[i].locked;
    }
    guest_service_stop(&shared_lock,0,SERVICE_STOP_NORMAL);
    for(unsigned cpu=0;cpu<GUEST_CPU_COUNT;cpu++)CHECK(!guest_service_admitted(&shared_lock,cpu));
    printf("threads: %llu fast, %llu locked traps across 5 vCPUs with a contending lock holder\n",
           (unsigned long long)fast,(unsigned long long)locked_n);
    CHECK(fast>locked_n*100);
}
#endif

int main(void)
{
    classification_exhaustive();
    differential(400000);
    admission_exhaustive();
    lock_regression();
#if FAST_TRAP_THREADS
    threads();
#endif
    printf("PASS: %llu fast-trap checks (key %u, counter %u, esr %u, far %u, ignore %u, timer %u, "
           "sprr %u, zero %u tuples)\n",checks,class_counts[FAST_TRAP_KEY],class_counts[FAST_TRAP_COUNTER],
           class_counts[FAST_TRAP_ESR],class_counts[FAST_TRAP_FAR],class_counts[FAST_TRAP_IGNORE],
           class_counts[FAST_TRAP_TIMER],class_counts[FAST_TRAP_SPRR],class_counts[FAST_TRAP_ZERO]);
    return 0;
}
