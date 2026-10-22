/* SPDX-License-Identifier: MIT */
/* SNAP_VECTOR_BRANCH / SNAP_FAST_CROSSINGS (compat/fast-vector.h) and the
 * SNAP_ERET_SNAPSHOT window proof (compat/native-writer.h): the lock-free
 * boundary must be the locked vector and ERET branches minus their shared
 * bookkeeping, for every entry and return it accepts, and must decline
 * everything else without changing anything. The oracle below transcribes
 * xnuboot_trap_locked's vector-page branch and ERET branch in order, calling
 * the same compat helpers (exception_*, user_crash_classify, native_call_word);
 * tools/test-fast-vector.py checks the transcription's order and tokens
 * against probes/xnuboot.c.
 *
 * Failure inventory this covers: a vector slot that is not a B out of the
 * page performed anyway (in-page, user-half, NOP, AArch32 slots); an SPTM
 * call, EL0 system-register emulation, skipped encoding, BRK-reflected signal,
 * crash-class entry, SError, interrupt without its virtual line or stop taken
 * without the lock; the kernel entry whose stale syndrome is the SPTM call's;
 * a saved mode that does not match its slot group; an EL0 crossing without a
 * native selection, or a declined selection leaving partial state; a
 * kernel/user return mis-translated, a first user return (entry probe) or a
 * refused return taken without the lock; counters, PAN evidence, fault
 * registers or register captures differing from the locked path; fast
 * boundaries still taking the service lock (pre-change model must fail); data
 * races between fast vCPUs and a lock holder (thread-sanitizer build); an
 * ERET window admitting a call, an indirect branch, an exception generator,
 * a call word, another ELR/SPSR writer or a backward/escaping branch.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *    -Icompat -Ishadow tools/test-fast-vector.c compat/exception.c \
 *    compat/service-lock.c -o build/test-fast-vector && build/test-fast-vector
 * cc -std=gnu11 -O1 -g -fsanitize=thread -pthread -DFAST_VECTOR_THREADS=1 -Icompat \
 *    -Ishadow tools/test-fast-vector.c compat/exception.c compat/service-lock.c \
 *    -o build/test-fast-vector-tsan && build/test-fast-vector-tsan
 * build/test-fast-vector --window FILE checks a little-endian word dump of the
 * live exception_return window (tools/test-fast-vector.py extracts it from the
 * pinned kernelcache) and prints the ERET index.
 * -DFAST_VECTOR_PRE_CHANGE=1 removes the fast path from the trap-entry model:
 * the lock-count regression must then fail (the pre-change behavior). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-vector.h"
#include "native-call.h"
#include "native-writer.h"
#include "service-lock.h"
#ifndef FAST_VECTOR_THREADS
#define FAST_VECTOR_THREADS 0
#endif
#ifndef FAST_VECTOR_PRE_CHANGE
#define FAST_VECTOR_PRE_CHANGE 0
#endif
#if FAST_VECTOR_THREADS
#include <pthread.h>
#endif

static unsigned long long checks;
#define CHECK(x) do {__atomic_fetch_add(&checks,1,__ATOMIC_RELAXED); \
    if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(1);}}while(0)

#define VBAR_VA UINT64_C(0xfffffe000b86c000)
#define VBAR_PA UINT64_C(0x81a40c000)
#define MEM_LOW UINT64_C(0x800000000)
#define MEM_HIGH UINT64_C(0x900000000)
#define CALL_PAGE UINT64_C(0x81a3f0000)
#define ERET_VA UINT64_C(0xfffffe000b870048)
#define KERNEL_HCR ((UINT64_C(1)<<34)|(UINT64_C(1)<<31)|(UINT64_C(1)<<27))

static uint64_t rng=0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

/* One vCPU as the monitor keeps it (every field either path may write). */
struct cpu {
    uint64_t user_vectors,protected_vectors,vector,saved_spsr,entry_spsr,entry_sctlr;
    uint64_t timer_vectors,model_irq_vectors,fault_esr,fault_far;
    uint64_t kernel_returns,last_kernel_return,returns,svcs,faults,pending;
    uint64_t exceptions,first_esr,last_esr,last_elr,last_far,last_x30;
    uint64_t view_el0,selects;    /* the native selection native_cross keeps */
};
/* What the trap sees besides the vCPU; flags select the build and profile. */
struct world {
    uint64_t esr,far,elr1,spsr1,sctlr,hcr,vhcr;
    uint32_t slot_word,eret_word,call_word;
    uint64_t eret_pa,elr1_pa;
    int native,installed,root_ok,probe_ok,sysreg_ok,skip_undef,permissive,let_panic;
    int crash_ring,brk_reflect;
};
struct shared { uint64_t records,stops,native_calls,sysreg,signals,crash_notes,skips; };
struct env { struct cpu *cpu;const struct world *w;uint64_t trap_pc; };

static uint64_t hw_pa(void *ctx,uint64_t va)
{
    struct env *e=ctx;
    if(va==e->trap_pc)return e->w->eret_pa;
    if(va==e->w->elr1)return e->w->elr1_pa;
    return 0;
}
static uint32_t hw_fetch(void *ctx,uint64_t pa)
{
    struct env *e=ctx;
    if(pa==(VBAR_PA|(e->trap_pc&0xfff)))return e->w->slot_word;
    if(pa==e->w->eret_pa)return e->w->eret_word;
    if(pa==e->w->elr1_pa)return e->w->call_word;
    return 0;
}
static void hw_el1(void *ctx,struct fast_cross_el1 *r)
{
    const struct world *w=((struct env *)ctx)->w;
    r->esr=w->esr;r->far=w->far;r->elr=w->elr1;r->spsr=w->spsr1;r->sctlr=w->sctlr;
}
static uint64_t hw_hcr(void *ctx) {return ((struct env *)ctx)->w->hcr;}
static uint64_t hw_vhcr(void *ctx) {return ((struct env *)ctx)->w->vhcr;}
/* native_cross: declines unchanged when no native address space is installed;
 * an equal regime is already selected. */
static int model_cross(struct cpu *c,const struct world *w,int el0)
{
    if(!w->native || !w->installed)return 0;
    if(c->view_el0==(uint64_t)el0)return 1;
    c->view_el0=(uint64_t)el0;c->selects++;return 1;
}
static int hw_cross(void *ctx,int el0) {struct env *e=ctx;return model_cross(e->cpu,e->w,el0);}
static int hw_root(void *ctx) {return ((struct env *)ctx)->w->root_ok;}
static void model_capture(struct cpu *c,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far)
{
    if(!c->exceptions)c->first_esr=esr;
    c->last_esr=esr;c->last_elr=elr;c->last_far=far;c->last_x30=frame[30];c->exceptions++;
}
static void hw_capture(void *ctx,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far)
{model_capture(((struct env *)ctx)->cpu,frame,esr,elr,far);}

static struct fast_cross_hw hw_of(struct env *e)
{
    return (struct fast_cross_hw){.ctx=e,.vbar_va=VBAR_VA,.vbar_pa=VBAR_PA,.mem_low=MEM_LOW,
        .mem_high=MEM_HIGH,.crash_ring=e->w->crash_ring,.guest_pa=hw_pa,.fetch=hw_fetch,
        .el1=hw_el1,.hcr=hw_hcr,.vhcr=hw_vhcr,.cross=e->w->native ? hw_cross : 0,
        .user_root=hw_root,.capture=hw_capture};
}
static struct fast_cross_vcpu state_of(struct cpu *c,uint64_t *logged,uint64_t *first)
{
    return (struct fast_cross_vcpu){&c->user_vectors,&c->protected_vectors,&c->vector,
        &c->saved_spsr,&c->entry_spsr,&c->entry_sctlr,&c->timer_vectors,&c->model_irq_vectors,
        &c->fault_esr,&c->fault_far,&c->kernel_returns,&c->last_kernel_return,&c->returns,
        &c->svcs,&c->faults,logged,first};
}

/* Where xnuboot_trap_locked sends a vector-page abort or an ERET. */
enum route {R_NATIVE,R_SYSREG,R_STOP,R_TIMER,R_DEVICE,R_SKIP,R_CONTINUE,R_KRET,R_URET,R_REFUSED};
/* user_enter_mode: native tables select through native_cross, where a
 * decline is a failure; otherwise the view sync (not modeled) succeeds. */
static int locked_cross(struct cpu *c,const struct world *w,int el0)
{
    if(w->native)return model_cross(c,w,el0);
    c->view_el0=(uint64_t)el0;return 1;
}
/* SNAP_VECTOR_BRANCH's vector_branch, or the old open-and-step. */
static void locked_continue(const struct world *w,uint64_t *elr,int *opened)
{
    uint64_t target;
    if(*elr-VBAR_VA<0x800 && fast_vector_branch(w->slot_word,*elr,&target))*elr=target;
    else *opened=1;
}
/* The vector-page branch, in xnuboot_trap_locked's order, for an abort whose
 * IPA page is the vector page, with no step, guard or probe active. */
static enum route locked_entry(struct cpu *c,struct shared *sh,const struct world *w,
    uint64_t physical_spsr,const uint64_t *frame,uint64_t *elr,int *opened)
{
    uint64_t g_esr=w->esr,g_far=w->far,g_elr=w->elr1,saved=w->spsr1;
    uint64_t vector=*elr-VBAR_VA;
    if(g_esr==(UINT64_C(1)<<25) && ((saved&31)==8 || (saved&31)==9) && !(g_elr&3) &&
       g_elr>=UINT64_C(0xffff800000000000)) {
        uint64_t pa=w->elr1_pa;
        uint32_t word=(pa&~UINT64_C(0xfff))==CALL_PAGE ? w->call_word : 0;
        if(native_call_word(word)) {sh->native_calls++;return R_NATIVE;}
    }
    if(vector<0x800 && !(vector&0x7f)) {
        if(vector>=0x400 && vector<=0x580 && !(saved&31)) {
            c->user_vectors++;c->protected_vectors+=!!(physical_spsr&(UINT64_C(1)<<22));
            c->vector=vector;c->saved_spsr=saved;c->entry_spsr=physical_spsr;
            c->entry_sctlr=w->sctlr;
        }
    }
    if(vector==0x400 && g_esr==0x02000000 && g_elr<(UINT64_C(1)<<47)-4 && w->sysreg_ok) {
        sh->sysreg++;return R_SYSREG;
    }
    if(vector>=0x400 && vector<=0x580 && !(vector&0x7f) &&
       !(saved&31) && !locked_cross(c,w,0)) {sh->stops++;return R_STOP;}
    uint64_t hcr=w->hcr;
    if((vector==0x100 || vector==0x300 ||
        (vector==0x500 && !(saved&31))) && (hcr&(UINT64_C(1)<<6))) {
        c->timer_vectors++;sh->records++;
        c->fault_esr=c->fault_far=0;
        locked_continue(w,elr,opened);return R_TIMER;
    }
    if((vector==0x80 || vector==0x280 ||
        (vector==0x480 && !(saved&31))) && (hcr&(UINT64_C(1)<<7))) {
        c->model_irq_vectors++;sh->records++;
        c->fault_esr=c->fault_far=0;
        locked_continue(w,elr,opened);return R_DEVICE;
    }
    if((g_esr>>26)==0 && w->skip_undef) {sh->records++;sh->skips++;return R_SKIP;}
    model_capture(c,frame,g_esr,g_elr,g_far);
    sh->records+=5;
    c->fault_esr=g_esr;c->fault_far=g_far;
    int user_sync=exception_user_sync(vector,saved,g_esr);
    if(user_sync) {
        if((g_esr>>26)==0x15)c->svcs++;else c->faults++;
    }
    if(w->brk_reflect && !user_sync && vector==0x400 && !(saved&31) && !(saved&(UINT64_C(1)<<4))) {
        unsigned uec=(unsigned)(g_esr>>26)&63;
        if(uec==0x3c || uec==0x00 || uec==0x0e || uec==0x1c || uec==0x22 || uec==0x26) {
            user_sync=1;sh->signals++;
        }
    }
    if(w->crash_ring && vector==0x400 && !(saved&31)) {
        unsigned crash=user_crash_classify(g_esr,g_far,frame[16],frame[1]);
        if(crash)sh->crash_notes++;
    }
    if(exception_kernel_page_fault(g_esr) || user_sync || w->permissive || w->let_panic) {
        c->fault_esr=0;
        c->fault_far=0;
        locked_continue(w,elr,opened);return R_CONTINUE;
    }
    sh->stops++;return R_STOP;
}
/* The ERET branch, in xnuboot_trap_locked's order. */
static enum route locked_return(struct cpu *c,struct shared *sh,const struct world *w,
    uint64_t physical_spsr,uint64_t *elr,uint64_t *spsr_el2)
{
    uint64_t target=w->elr1,spsr=w->spsr1,translated,pa=w->eret_pa;
    uint32_t word=pa>=MEM_LOW && pa<=MEM_HIGH-4 ? w->eret_word : 0;
    uint64_t vhcr=w->vhcr,target_pa=w->elr1_pa;
    if(target_pa>=MEM_LOW && target_pa<=MEM_HIGH-4 &&
       exception_kernel_return(word,vhcr,target,spsr,&translated)) {
        *spsr_el2=translated;sh->records++;
        c->kernel_returns++;c->last_kernel_return=target;
        *elr=target;return R_KRET;
    }
    if(exception_monitor_origin(*elr,physical_spsr) &&
       exception_user_return(word,vhcr,target,spsr,&translated) && w->root_ok) {
        if(!locked_cross(c,w,1)) {sh->stops++;return R_STOP;}
        int probe=!c->returns && w->probe_ok;
        c->returns++;
        *spsr_el2=translated;sh->records++;
        *elr=target;
        if(probe)c->pending=1;
        return R_URET;
    }
    sh->stops++;return R_REFUSED;
}

/* A fresh branch word: out of the page (valid), inside it, to the user half,
 * a NOP (the AArch32 slots) or anything. */
static uint32_t pick_slot_word(void)
{
    switch(rnd()%6) {
    case 0: case 1: return 0x14000000u|(uint32_t)(0x9f2+rnd()%0x400);   /* +0x27c8.. forward */
    case 2: return 0x14000000u|(uint32_t)(rnd()%0x100);               /* stays in the page */
    case 3: return 0x14000000u|0x2000000u|(uint32_t)(rnd()&0x1ffffff);  /* backward, maybe far */
    case 4: return 0xd503201fu;                                        /* NOP */
    default: return (uint32_t)rnd();
    }
}
static uint64_t pick_esr(void)
{
    static const unsigned ecs[]={0x15,0x15,0x20,0x24,0x24,0x21,0x25,0x25,0x00,0x3c,0x0e,
                                 0x1c,0x22,0x26,0x18,0x07,0x2f};
    if(rnd()%12==0)return UINT64_C(1)<<25;
    if(rnd()%16==0)return 0x02000000;
    unsigned ec=ecs[rnd()%(sizeof ecs/sizeof *ecs)];
    uint64_t iss=rnd()%3 ? 4+rnd()%12 : rnd()&0x1ffffff;
    if(ec==0x15 && rnd()%2)iss=0x80;
    return ((uint64_t)ec<<26)|(UINT64_C(1)<<25)|iss;
}
static void pick_world(struct world *w,uint64_t *elr,uint64_t *physical_spsr,uint64_t *frame,int entry)
{
    memset(w,0,sizeof *w);
    static const uint64_t vectors[]={0x000,0x080,0x100,0x180,0x200,0x280,0x300,0x380,
        0x400,0x480,0x500,0x580,0x600,0x780,0x404,0x800,0xfff};
    uint64_t vector=vectors[rnd()%(sizeof vectors/sizeof *vectors)];
    unsigned modes[]={0,4,5,8,9,6,0x10};
    unsigned mode=vector>=0x400 ? 0 : vector>=0x200 ? 9 : 8;
    if(rnd()%6==0)mode=modes[rnd()%7];
    w->spsr1=mode|(rnd()&UINT64_C(0xf03003c0))|(rnd()%24==0 ? UINT64_C(1)<<32 : 0);
    if(entry) {
        *elr=VBAR_VA+vector;
        w->esr=pick_esr();
        w->far=rnd()%3 ? UINT64_C(0x100000000)+(rnd()&UINT64_C(0x3fffffff000)) : rnd()%0x100000000;
        w->elr1=rnd()%2 ? UINT64_C(0xfffffe0007000000)+4*(rnd()%0x100000) :
                          UINT64_C(0x100000000)+4*(rnd()%0x1000000);
        if(rnd()%16==0)w->elr1|=rnd()%4;
    } else {
        *elr=rnd()%8 ? ERET_VA : UINT64_C(0xfffffe000b870000)+4*(rnd()%64);
        if(rnd()%16==0)*elr=UINT64_C(0x100000000)+4*(rnd()%1024);
        unsigned target=(unsigned)(rnd()%4);
        w->elr1=target==0 ? UINT64_C(0x100000000)+4*(rnd()%0x1000000) :
                target==1 ? UINT64_C(0xfffffe0007000000)+4*(rnd()%0x100000) :
                target==2 ? rnd() : UINT64_C(0x100000000)+rnd()%16;
        w->spsr1=(rnd()%3 ? (unsigned[]){0,8,9,5,4}[rnd()%5] : (unsigned)rnd()%32)|
                 (rnd()&UINT64_C(0xf00003c0))|(rnd()%16==0 ? UINT64_C(1)<<20 : 0)|
                 (rnd()%16==0 ? UINT64_C(1)<<5 : 0)|(rnd()%24==0 ? UINT64_C(1)<<33 : 0);
    }
    w->sctlr=rnd()&UINT64_C(0xffffff);
    w->hcr=rnd()&((UINT64_C(1)<<6)|(UINT64_C(1)<<7));
    w->vhcr=rnd()%8 ? KERNEL_HCR : rnd()&KERNEL_HCR;
    w->slot_word=pick_slot_word();
    w->eret_word=rnd()%6 ? 0xd69f03e0u : (uint32_t)rnd();
    w->eret_pa=rnd()%8 ? MEM_LOW+4*(rnd()%0x100000) : rnd()%2 ? MEM_HIGH-2 : 0;
    w->elr1_pa=rnd()%5==0 ? CALL_PAGE+4*(rnd()%1024) : rnd()%6 ? MEM_LOW+0x400000+4*(rnd()%0x100000) :
               rnd()%2 ? MEM_HIGH : 0;
    w->call_word=rnd()%2 ? (rnd()%2 ? 0x00201420u : 0xd4e00000u) : (uint32_t)rnd();
    w->native=(rnd()%4)!=0;w->installed=(rnd()%6)!=0;
    w->root_ok=(rnd()%8)!=0;w->probe_ok=rnd()%2;w->sysreg_ok=rnd()%2;
    w->skip_undef=rnd()%4==0;w->permissive=rnd()%16==0;w->let_panic=rnd()%16==0;
    w->crash_ring=rnd()%4!=0;w->brk_reflect=rnd()%4!=0;
    *physical_spsr=(rnd()%10 ? 5 : (unsigned[]){4,0,9}[rnd()%3])|(rnd()&(UINT64_C(1)<<22));
    for(unsigned i=0;i<31;i++)frame[i]=rnd();
    static const uint64_t calls[]={37,328,520,521,529,3,4};
    if(rnd()%2)frame[16]=calls[rnd()%7];
    frame[1]=rnd()%2 ? rnd()%16 : rnd();
    if(w->elr1==*elr)w->elr1+=4;   /* the model's translations are per address */
}
static void cpu_init(struct cpu *c,unsigned seed)
{
    memset(c,0,sizeof *c);
    c->returns=seed%3;c->view_el0=seed&1;c->exceptions=seed%2;c->kernel_returns=seed;
    /* An earlier refused access or exception may have left these. */
    c->fault_esr=0x96000045u^seed;c->fault_far=UINT64_C(0xdead0000)+seed;
}

/* fast_vector_branch against an independent decode over the whole imm26
 * range (strided) and every boundary. */
static void branch_decode(void)
{
    unsigned accepted=0;
    for(uint64_t imm=0;imm<(UINT64_C(1)<<26);imm+=(imm<0x10000 || imm>(UINT64_C(1)<<26)-0x10000) ? 1 : 997) {
        for(unsigned p=0;p<3;p++) {
            uint64_t pc=p==0 ? VBAR_VA+0x400 : p==1 ? VBAR_VA+0xffc : UINT64_C(0xffff800000000800);
            int64_t words=imm>=(UINT64_C(1)<<25) ? (int64_t)imm-((int64_t)1<<26) : (int64_t)imm;
            uint64_t want=pc+(uint64_t)(words*4),target=0;
            int ok=(want&~UINT64_C(0xfff))!=(pc&~UINT64_C(0xfff)) && want>=UINT64_C(0xffff800000000000);
            int got=fast_vector_branch(0x14000000u|(uint32_t)imm,pc,&target);
            CHECK(got==ok);
            if(got)CHECK(target==want);
            accepted+=(unsigned)got;
        }
    }
    uint64_t t;
    CHECK(!fast_vector_branch(0x94000000u|0x9f2,VBAR_VA,&t));     /* BL */
    CHECK(!fast_vector_branch(0x54000000u|(0x9f2<<5),VBAR_VA,&t)); /* B.cond */
    CHECK(!fast_vector_branch(0xd503201fu,VBAR_VA+0x600,&t));      /* NOP (AArch32 slot) */
    CHECK(!fast_vector_branch(0x14000000u|0x9f2,VBAR_VA+2,&t));    /* misaligned PC */
    for(unsigned n=0;n<200000;n++) {
        uint32_t w=(uint32_t)rnd();
        if((w&0xfc000000u)==0x14000000u)continue;
        CHECK(!fast_vector_branch(w,VBAR_VA,&t));
    }
    CHECK(accepted>100000);
}

static unsigned entry_handled[FAST_CROSS_CLASSES],return_handled[FAST_CROSS_CLASSES];
static unsigned entry_declined,return_declined,first_declines;
static void differential(unsigned iterations)
{
    for(unsigned n=0;n<iterations;n++) {
        int entry=(int)(rnd()&1);
        struct world w;uint64_t elr,physical_spsr,frame[31];
        pick_world(&w,&elr,&physical_spsr,frame,entry);
        struct cpu a,b;cpu_init(&a,(unsigned)n);b=a;
        uint64_t logged=rnd()%8 ? ~UINT64_C(0) : rnd(),first=0,logged_before=logged;
        struct env eb={&b,&w,elr};
        struct fast_cross_hw hw=hw_of(&eb);
        struct fast_cross_vcpu st=state_of(&b,&logged,&first);
        struct cpu before=b;
        uint64_t eb_elr=elr,fb[31];memcpy(fb,frame,sizeof fb);
        uint64_t fast_spsr=0xdead;
        unsigned cls=entry ? fast_cross_entry(&hw,&st,physical_spsr,fb,&eb_elr) :
                             fast_cross_return(&hw,&st,physical_spsr,&eb_elr,&fast_spsr);
        CHECK(!memcmp(fb,frame,sizeof fb));   /* the frame is never written */
        struct shared sa={0};int opened=0;
        uint64_t ea_elr=elr,locked_spsr=0xdead;
        enum route r=entry ? locked_entry(&a,&sa,&w,physical_spsr,frame,&ea_elr,&opened) :
                             locked_return(&a,&sa,&w,physical_spsr,&ea_elr,&locked_spsr);
        if(cls==FAST_CROSS_NONE) {
            /* Declined: nothing changed but a first-occurrence mark. */
            CHECK(!memcmp(&before,&b,sizeof b) && eb_elr==elr && fast_spsr==0xdead);
            CHECK(logged==logged_before || (first==1 && (logged&~logged_before) &&
                  !((logged&~logged_before)&((logged&~logged_before)-1))));
            first_declines+=(unsigned)first;
            if(entry)entry_declined++;else return_declined++;
            continue;
        }
        CHECK(logged==logged_before && !first);
        /* Handled: the locked path takes the same route to the same state. */
        static const enum route want[FAST_CROSS_CLASSES]={R_STOP,R_CONTINUE,R_CONTINUE,
            R_TIMER,R_DEVICE,R_KRET,R_URET};
        CHECK(r==want[cls] && !opened && !a.pending);
        CHECK(!sa.stops && !sa.native_calls && !sa.sysreg && !sa.signals && !sa.crash_notes && !sa.skips);
        CHECK(!memcmp(&a,&b,sizeof a) && ea_elr==eb_elr);
        if(entry) {
            CHECK(eb_elr!=elr && (eb_elr&~UINT64_C(0xfff))!=(VBAR_VA&~UINT64_C(0xfff)));
            CHECK(cls!=FAST_CROSS_USER_SYNC || exception_user_sync(elr-VBAR_VA,w.spsr1,w.esr));
            CHECK(cls!=FAST_CROSS_KERNEL_FAULT || exception_kernel_page_fault(w.esr));
            CHECK(!(elr-VBAR_VA>=0x400) || (w.native && w.installed && b.view_el0==0));
            entry_handled[cls]++;
        } else {
            CHECK(fast_spsr==locked_spsr);
            CHECK(cls!=FAST_CROSS_USER_RETURN || (w.native && w.installed && b.view_el0==1 && before.returns));
            return_handled[cls]++;
        }
    }
    for(unsigned k=FAST_CROSS_KERNEL_FAULT;k<=FAST_CROSS_DEVICE;k++)CHECK(entry_handled[k]>=200);
    CHECK(return_handled[FAST_CROSS_KERNEL_RETURN]>=200 && return_handled[FAST_CROSS_USER_RETURN]>=200);
    CHECK(entry_declined>=iterations/8 && return_declined>=iterations/8 && first_declines>=100);
    printf("differential: %u boundaries; entries kernel-fault %u user-sync %u timer %u device %u, "
           "returns kernel %u user %u; declined %u entries %u returns (%u first occurrences)\n",
           iterations,entry_handled[1],entry_handled[2],entry_handled[3],entry_handled[4],
           return_handled[5],return_handled[6],entry_declined,return_declined,first_declines);
}

/* Directed cases the random mix might under-sample. */
static void directed(void)
{
    struct world w;memset(&w,0,sizeof w);
    uint64_t frame[31]={0},logged=~UINT64_C(0),first=0,elr,spsr_el2=0;
    struct cpu c;cpu_init(&c,1);
    struct env e={&c,&w,0};
    struct fast_cross_hw hw=hw_of(&e);
    struct fast_cross_vcpu st=state_of(&c,&logged,&first);
    w.native=w.installed=w.root_ok=1;w.vhcr=KERNEL_HCR;w.slot_word=0x14000000u|0x9f2;
    hw.cross=hw_cross;
    /* EL0 SVC at 0x400: handled, one crossing to EL1. */
    w.esr=(UINT64_C(0x15)<<26)|(UINT64_C(1)<<25)|0x80;w.spsr1=0;c.view_el0=1;
    elr=e.trap_pc=VBAR_VA+0x400;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_USER_SYNC);
    CHECK(elr==VBAR_VA+0x400+0x9f2*4 && c.view_el0==0 && c.svcs==1 && c.user_vectors==1);
    /* The same with no native address space: declined, unchanged. */
    struct cpu before;w.installed=0;c.view_el0=1;before=c;elr=VBAR_VA+0x400;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    w.installed=1;
    /* No native tables at all: no selection, declined before anything is
     * read, first-occurrence marks included. */
    uint64_t keep_logged=logged;logged=0;hw.cross=0;before=c;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    CHECK(!logged && !first);
    logged=keep_logged;hw.cross=hw_cross;
    /* abort()'s pthread_kill(self, SIGABRT): a crash-class SVC stays locked. */
    frame[16]=328;frame[1]=6;hw.crash_ring=1;before=c;elr=VBAR_VA+0x400;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    hw.crash_ring=0;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_USER_SYNC && c.svcs==2);
    frame[16]=0;
    /* Kernel page fault at 0x200 (EL2h), and its stale-syndrome FIQ twin at
     * 0x300 whose ESR is the SPTM call's: the first is fast, the second not. */
    w.esr=(UINT64_C(0x25)<<26)|(UINT64_C(1)<<25)|7;w.spsr1=9;elr=e.trap_pc=VBAR_VA+0x200;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_KERNEL_FAULT && c.fault_esr==0);
    w.esr=UINT64_C(1)<<25;w.hcr=UINT64_C(1)<<6;elr=e.trap_pc=VBAR_VA+0x300;before=c;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    /* ...but the same stale syndrome at an EL0 FIQ (0x500) is a timer entry. */
    w.spsr1=0;elr=e.trap_pc=VBAR_VA+0x500;c.view_el0=1;
    CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_TIMER && c.timer_vectors==1);
    /* SError slots are no class, whatever their syndrome says: kept locked
     * for their evidence even where the locked path would continue. */
    static const uint64_t serror[]={0x180,0x380,0x580};
    static const uint64_t syndromes[]={(UINT64_C(0x25)<<26)|(UINT64_C(1)<<25)|7,
        (UINT64_C(0x24)<<26)|(UINT64_C(1)<<25)|6,(UINT64_C(0x15)<<26)|(UINT64_C(1)<<25)|0x80,
        UINT64_C(0x2f)<<26};
    for(unsigned i=0;i<3;i++)for(unsigned k=0;k<4;k++) {
        w.esr=syndromes[k];w.spsr1=i==2 ? 0 : i ? 9 : 8;w.hcr=(UINT64_C(1)<<6)|(UINT64_C(1)<<7);
        elr=e.trap_pc=VBAR_VA+serror[i];before=c;
        CHECK(fast_cross_entry(&hw,&st,5,frame,&elr)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    }
    /* Kernel return: EL2h -> physical EL1h, NZCV/DAIF kept. */
    w.eret_word=0xd69f03e0u;w.eret_pa=MEM_LOW+0x1000;w.elr1=UINT64_C(0xfffffe0007001000);
    w.elr1_pa=MEM_LOW+0x2000;w.spsr1=0x600003c9;elr=e.trap_pc=ERET_VA;
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_KERNEL_RETURN);
    CHECK(elr==w.elr1 && spsr_el2==0x600003c5 && c.last_kernel_return==w.elr1);
    /* User return after the first: fast; the first (entry probe): locked. */
    w.elr1=UINT64_C(0x100004000);w.spsr1=0x20000000;elr=e.trap_pc=ERET_VA;c.view_el0=0;
    c.returns=0;before=c;
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    c.returns=7;
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_USER_RETURN);
    CHECK(elr==UINT64_C(0x100004000) && spsr_el2==0x20000000 && c.returns==8 && c.view_el0==1);
    /* A refused return (virtual HCR not the nested host) stays locked. */
    w.vhcr=0;elr=e.trap_pc=ERET_VA;c.view_el0=0;before=c;
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    /* First occurrence: declined once per class, with the bit and count. */
    logged=0;w.vhcr=KERNEL_HCR;w.spsr1=0x3c9;w.elr1=UINT64_C(0xfffffe0007001000);elr=ERET_VA;before=c;
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_NONE && !memcmp(&before,&c,sizeof c));
    CHECK(logged==fast_cross_log_bit(FAST_CROSS_KERNEL_RETURN) && first==1);
    CHECK(fast_cross_return(&hw,&st,5,&elr,&spsr_el2)==FAST_CROSS_KERNEL_RETURN && first==1);
    /* One bit per class, clear of the fast-trap log bits 0..5 sharing the word. */
    for(unsigned k=0;k<=FAST_CROSS_CLASSES;k++) {
        CHECK(fast_cross_log_bit(k)==(k && k<FAST_CROSS_CLASSES ? UINT64_C(1)<<(7+k) : 0));
        CHECK(!(fast_cross_log_bit(k)&0xff));
    }
}

/* The ERET window proof. */
static uint32_t wb(int64_t words) {return 0x14000000u|((uint32_t)words&0x3ffffffu);}
static void window_cases(void)
{
    uint32_t v[64];
    unsigned n=40;
    for(unsigned i=0;i<n;i++)v[i]=0xf94003e0u|(i<<10);   /* ldr x0,[sp,#8i] */
    v[0]=native_writer_sites[NATIVE_WRITER_RETURN_SITE].word;
    v[39]=NATIVE_WRITER_ERET;
    v[5]=0x54000000u|(10u<<5);                             /* b.eq +10 */
    v[8]=0xb4000000u|(3u<<5)|2;                            /* cbz x2,+3 */
    v[12]=0x36000000u|(20u<<5)|3;                          /* tbz w3,#0,+20 */
    v[20]=wb(19);                                          /* b to the ERET */
    CHECK(native_writer_return_window(v,n)==39);
    CHECK(!native_writer_return_window(v,39));             /* no ERET */
    CHECK(!native_writer_return_window(v,1) && !native_writer_return_window(0,n));
    CHECK(!native_writer_return_window(v,NATIVE_WRITER_RETURN_WINDOW+1));
    static const uint32_t bad[]={0x94000001u,0xd63f0000u,0xd61f0040u,0xd65f03c0u,0xd65f0bffu,
        0xd73f0821u,0xd69f0bffu,0xd4000001u,0xd4000002u,0xd4000003u,0xd4200000u,0xd4400000u,
        0xd4a00001u,0xd4e00000u,0x00201420u,0x00201400u,0x00000000u,0x0000beefu,0x00a00000u,
        0xe0000000u,
        0xd5184000u|3,0xd5184020u|7,0xd6bf03e0u};
    for(unsigned k=0;k<sizeof bad/sizeof *bad;k++) {
        uint32_t keep=v[17];v[17]=bad[k];
        CHECK(!native_writer_return_window(v,n));
        v[17]=keep;
    }
    uint32_t keep=v[20];
    v[20]=wb(-3);CHECK(!native_writer_return_window(v,n));     /* backward */
    v[20]=wb(0);CHECK(!native_writer_return_window(v,n));      /* self */
    v[20]=wb(20);CHECK(!native_writer_return_window(v,n));     /* past the ERET */
    v[20]=0x54000000u|((uint32_t)(-2)&0x7ffff)<<5;CHECK(!native_writer_return_window(v,n));
    v[20]=keep;
    v[0]^=1;CHECK(!native_writer_return_window(v,n));v[0]^=1;
    CHECK(native_writer_return_window(v,n)==39);
    /* TBZ/TBNZ keep the tested bit's number in bits 23:19 and b5 in bit 31:
     * neither is part of the offset. */
    keep=v[12];
    v[12]=0xb7000000u|(0x1fu<<19)|(20u<<5)|3;CHECK(native_writer_return_window(v,n)==39);
    v[12]=0x36000000u|(1u<<19)|(0x3ffcu<<5)|3;CHECK(!native_writer_return_window(v,n));
    v[12]=keep;
    /* The earliest ERET ends the window, even with another after it, and a
     * branch past it is refused. */
    v[30]=NATIVE_WRITER_ERET;v[20]=wb(10);
    CHECK(!native_writer_return_window(v,n));               /* tbz at 12 reaches 32 */
    v[12]=0x36000000u|(15u<<5)|3;
    CHECK(native_writer_return_window(v,n)==30);
}

/* The trap entry, modeled on xnuboot_trap: fast boundary (unless the
 * pre-change model is built), then the locked path. Counts acquisitions. */
struct entry {
    struct guest_service_lock *lock;struct cpu *cpu;struct shared *shared;
    uint64_t logged,first,acquisitions;unsigned slot;
};
static int trap_entry(struct entry *e,const struct world *w,int is_entry,uint64_t physical_spsr,
                      const uint64_t *frame,uint64_t *elr)
{
    uint64_t next=0;
#if !FAST_VECTOR_PRE_CHANGE
    if(guest_service_admitted(e->lock,e->slot) && !e->cpu->pending) {
        struct env env={e->cpu,w,*elr};
        struct fast_cross_hw hw=hw_of(&env);
        struct fast_cross_vcpu st=state_of(e->cpu,&e->logged,&e->first);
        unsigned done=is_entry ? fast_cross_entry(&hw,&st,physical_spsr,frame,elr) :
                                 fast_cross_return(&hw,&st,physical_spsr,elr,&next);
        if(done!=FAST_CROSS_NONE)return 0;
    }
#endif
    for(;;) {
        enum guest_service_result r=guest_service_try(e->lock,e->slot);
        if(r==SERVICE_OK)break;
        if(r!=SERVICE_BUSY)return 1;
    }
    e->acquisitions++;
    int opened=0;
    enum route route=is_entry ? locked_entry(e->cpu,e->shared,w,physical_spsr,frame,elr,&opened) :
                                locked_return(e->cpu,e->shared,w,physical_spsr,elr,&next);
    e->cpu->pending=0;   /* the probe step completes before the next boundary */
    CHECK(guest_service_release(e->lock,e->slot)==SERVICE_OK);
    return route==R_STOP || route==R_REFUSED || route==R_NATIVE;
}
/* A syscall, a kernel fault and both interrupts, entered and returned. */
static void boundary_world(struct world *w,unsigned kind,int is_entry,uint64_t *elr)
{
    memset(w,0,sizeof *w);
    w->native=w->installed=w->root_ok=1;w->vhcr=KERNEL_HCR;w->slot_word=0x14000000u|0x9f2;
    w->eret_word=0xd69f03e0u;w->eret_pa=MEM_LOW+0x1000;w->hcr=(UINT64_C(1)<<6)|(UINT64_C(1)<<7);
    int user=kind==0 || kind==3;
    if(is_entry) {
        static const uint64_t vectors[]={0x400,0x200,0x300,0x480};
        *elr=VBAR_VA+vectors[kind];
        w->spsr1=user ? 0 : 9;
        w->esr=kind==0 ? (UINT64_C(0x15)<<26)|(UINT64_C(1)<<25)|0x80 :
               kind==1 ? (UINT64_C(0x25)<<26)|(UINT64_C(1)<<25)|7 : (UINT64_C(0x24)<<26)|6;
        w->far=UINT64_C(0x1f0000000);
    } else {
        *elr=ERET_VA;
        w->elr1=user ? UINT64_C(0x100004000) : UINT64_C(0xfffffe0007001000);
        w->elr1_pa=MEM_LOW+0x2000;
        w->spsr1=user ? 0 : 0x3c9;
    }
}
static void lock_regression(void)
{
    struct guest_service_lock lock={0};
    CHECK(guest_service_boot(&lock)==SERVICE_OK);
    struct cpu c;cpu_init(&c,0);struct shared sh={0};
    struct entry e={.lock=&lock,.cpu=&c,.shared=&sh,.slot=0};
    const unsigned traps=8000;
    for(unsigned n=0;n<traps;n++) {
        struct world w;uint64_t elr,frame[31]={0};
        unsigned kind=(n/2)%4;int is_entry=!(n&1);
        boundary_world(&w,kind,is_entry,&elr);
        CHECK(!trap_entry(&e,&w,is_entry,5,frame,&elr));
    }
    printf("lock regression: %u boundary exits, %llu lock acquisitions, %llu first-occurrence\n",
           traps,(unsigned long long)e.acquisitions,(unsigned long long)e.first);
    /* Only the first of each class, and the first user return (probe). */
    CHECK(e.acquisitions<=FAST_CROSS_CLASSES);
    guest_service_stop(&lock,0,SERVICE_STOP_NORMAL);
    struct world w;uint64_t elr,frame[31]={0};
    boundary_world(&w,1,1,&elr);
    CHECK(trap_entry(&e,&w,1,5,frame,&elr)==1);
}

#if FAST_VECTOR_THREADS
/* Five vCPUs cross boundaries on private state while a sixth CPU holds and
 * releases the service lock and mutates shared state. The sanitizer must see
 * no race; each vCPU's final state must equal a sequential replay. */
struct worker { struct entry e;struct cpu cpu;uint64_t seed,trace,fast,locked; };
static struct guest_service_lock shared_lock;
static struct shared shared_state;
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
        struct world world;uint64_t elr,frame[31]={0};
        unsigned kind=(unsigned)(local%4);int is_entry=!(n&1);
        boundary_world(&world,kind,is_entry,&elr);
        if(!(local&0x70))world.native=0;   /* a build without native tables */
        uint64_t before=w->e.acquisitions;
        if(trap_entry(&w->e,&world,is_entry,5,frame,&elr))break;
        if(w->e.acquisitions==before)w->fast++;else w->locked++;
        w->trace^=elr*(n+1);
    }
    return 0;
}
static void *lock_thread(void *arg)
{
    (void)arg;
    for(unsigned n=0;n<20000;n++) {
        while(guest_service_try(&shared_lock,5)!=SERVICE_OK) {}
        shared_state.records++;shared_state.stops+=0;
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
        struct worker r={0};cpu_init(&r.cpu,i+1);r.seed=w[i].seed;
        struct guest_service_lock solo={0};admit_all(&solo);
        struct shared ss={0};
        r.e=(struct entry){.lock=&solo,.cpu=&r.cpu,.shared=&ss,.slot=i};
        vcpu_thread(&r);
        CHECK(!memcmp(&r.cpu,&w[i].cpu,sizeof r.cpu) && r.trace==w[i].trace);
        fast+=w[i].fast;locked_n+=w[i].locked;
    }
    guest_service_stop(&shared_lock,0,SERVICE_STOP_NORMAL);
    printf("threads: %llu fast, %llu locked boundary exits across 5 vCPUs with a contending lock holder\n",
           (unsigned long long)fast,(unsigned long long)locked_n);
    CHECK(fast>locked_n*4);
}
#endif

static int window_file(const char *path)
{
    FILE *f=fopen(path,"rb");
    if(!f)return 2;
    uint32_t words[NATIVE_WRITER_RETURN_WINDOW];
    size_t n=fread(words,4,NATIVE_WRITER_RETURN_WINDOW,f);
    fclose(f);
    printf("%u\n",native_writer_return_window(words,(unsigned)n));
    return 0;
}

int main(int argc,char **argv)
{
    if(argc==3 && !strcmp(argv[1],"--window"))return window_file(argv[2]);
    branch_decode();
    directed();
    window_cases();
    differential(400000);
    lock_regression();
#if FAST_VECTOR_THREADS
    threads();
#endif
    printf("PASS: %llu fast-vector checks\n",checks);
    return 0;
}
