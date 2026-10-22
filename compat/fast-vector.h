/* SPDX-License-Identifier: MIT */
/* The two exits every guest exception still takes, the vector entry and the
 * ERET (probes/xnuboot.c):
 *   - SNAP_VECTOR_BRANCH performs the first instruction of XNU's vector slot,
 *     an unconditional B out of the execute-never vector page, instead of
 *     opening the page and single-stepping it (no step exit, no stage-2
 *     write, no broadcast TLBI);
 *   - SNAP_FAST_CROSSINGS handles the common entries and returns without the
 *     service lock.
 * Nothing here touches hardware: the monitor supplies the per-CPU operations
 * through fast_cross_hw, so tools/test-fast-vector.c runs this exact code
 * natively against a transcription of xnuboot_trap_locked's vector and ERET
 * branches.
 *
 * Why the classes below need no service lock. For them the locked branches
 * read or write only:
 *   - this CPU's registers (ESR/FAR/ELR/SPSR/SCTLR_EL1, HCR_EL2, ELR/SPSR_EL2),
 *     its VNCR page and its exception frame;
 *   - this vCPU's own state: timer_vectors, model_irq_vectors, fault_esr/far,
 *     kernel_returns, last_kernel_return, first_exc/last_exc/exceptions,
 *     pan_entry[cpu], user_execution[cpu] and native_calls[cpu], each written
 *     only by its own CPU (the final report reads them after every executor
 *     has quiesced);
 *   - immutable configuration (vector base and page, owned RAM) and
 *     const-sealed kernel text (the vector slot, the ERET);
 *   - at a crossing between EL0 and EL1 only: the native-tables selection
 *     (native_cross, per-CPU by its contract) and the read-only return check
 *     user_return_root (the active root's cache entry cannot change while it
 *     is active and roots are unique in the cache).
 * What the locked branches do beyond that is exactly what this path drops or
 * declines: record() into the shared log (the first entry of each class per
 * vCPU still takes the locked path, so the log keeps its first-occurrence
 * evidence), SPTM calls, EL0 instruction emulation, user crash notes, the
 * first user return's entry probe, every stop, and any trap while a step, a
 * guard, a probe or a latched failure is present or while a virtual FIQ/IRQ
 * line disagrees with its sources (step_arm's guest_interrupt_sync, which is
 * where another CPU's posted IPI is raised): the caller declines those
 * before calling here.
 *
 * FAST_CROSS_EL0_SYSREG (probes/xnuboot.c sets it from SNAP_FAST_EL0_SYSREG)
 * adds the one EL0 instruction emulation that is lock-free: the two Apple
 * IMPDEF reads this silicon cannot execute at EL0, the ordered counter alias
 * (guest_clock_user_read) and SPRR_UPERM (sprr_user_read), exactly as the
 * locked user_sysreg_access performs them; see fast_el0_sysreg below. */
#pragma once
#include <stdint.h>
#include "exception.h"
#include "user-crash.h"
#ifndef FAST_CROSS_EL0_SYSREG
#define FAST_CROSS_EL0_SYSREG 0
#endif
#ifndef FAST_CROSS_EL0_MEMO
#define FAST_CROSS_EL0_MEMO 0
#endif
#if FAST_CROSS_EL0_SYSREG
#include "clock.h"
#include "sprr.h"
#endif

/* XNU's AArch64 vector slots start with an unconditional B (the pinned
 * 26A428 kernelcache: slots 0x000-0x580; the AArch32 slots hold NOP and never
 * branch). Executing it changes the PC and nothing else: exception entry
 * already cleared PSTATE.BTYPE and a direct branch leaves it clear. The
 * target must leave the 4K page holding the slot, which stays execute-never
 * at stage 2, and stay in the kernel half. */
static inline int fast_vector_branch(uint32_t word,uint64_t pc,uint64_t *target)
{
    if((word&UINT32_C(0xfc000000))!=UINT32_C(0x14000000) || (pc&3))return 0;
    uint64_t t=pc+(uint64_t)((int64_t)((uint64_t)word<<38)>>36);
    if(!((t^pc)&~UINT64_C(0xfff)) || t<UINT64_C(0xffff800000000000))return 0;
    *target=t;
    return 1;
}

enum fast_cross_class {
    FAST_CROSS_NONE, FAST_CROSS_KERNEL_FAULT, FAST_CROSS_USER_SYNC, FAST_CROSS_TIMER,
    FAST_CROSS_DEVICE, FAST_CROSS_KERNEL_RETURN, FAST_CROSS_USER_RETURN, FAST_CROSS_CLASSES
};
/* The locked record each class stands in for: one bit per class, bits 8..13
 * of the per-vCPU word compat/fast-trap.h's log bits (0..7) also use. */
#define FAST_CROSS_LOG_SHIFT 7u
static inline uint64_t fast_cross_log_bit(unsigned cls)
{return cls && cls<FAST_CROSS_CLASSES ? UINT64_C(1)<<(FAST_CROSS_LOG_SHIFT+cls) : 0;}

struct fast_cross_el1 { uint64_t esr,far,elr,spsr,sctlr; };

#if FAST_CROSS_EL0_SYSREG
/* SNAP_FAST_EL0_SYSREG. Installed GUI runs execute two Apple IMPDEF reads at
 * EL0 that this silicon does not implement: dyld's TPRO check reads
 * SPRR_UPERM (MRS Xt, S3_6_C15_C1_5) and mach_absolute_time the ordered
 * counter alias (MRS Xt, S3_4_C15_C10_6). Each is UNDEFINED at EL0, enters
 * XNU's EL1 vector with ESR_EL1 0x02000000 and faults on the execute-never
 * vector page, where the locked user_sysreg_access emulates it: the saved EL0
 * PSTATE restored, ELR+4 and Rt written, no EL1 instruction executed and the
 * UPERM view kept. This class does exactly that without the service lock.
 *
 * Why it needs no lock. It reads or writes only:
 *   - this CPU's EL1 exception registers (read) and SPSR_EL2/ELR_EL2;
 *   - this vCPU's frame register Rt; its guest_clock (the EL1
 *     FAST_TRAP_COUNTER class's state, written only by this CPU); its SPRR
 *     readback state user_roots.sprr[cpu] (reset only by this CPU's own
 *     SWITCH_ROOT; a read changes only readback bookkeeping, and a state that
 *     fails sprr_fixed_state_valid declines, the EL1 FAST_TRAP_SPRR guard);
 *     its user_clock/user_sprr records and pan_entry evidence (each written
 *     only by this CPU);
 *   - the active root's cache entry and metadata (user_return_root, which the
 *     lock-free user return already reads) and its source and hardware tables
 *     (user_instruction_read), which another CPU's SPTM call may be changing
 *     under the lock: the word is read twice and accepted only when both reads
 *     give the same leaves, root and word, so a walk torn by a concurrent
 *     remap declines and a consistent one reads the word the thread executes
 *     next.
 * It records nothing in the shared log (the locked emulation records nothing
 * either), so it has no first-occurrence bit; every other EL0 EC 0 entry,
 * the UPERM write included, declines to the locked path. */
#define FAST_EL0_SYSREG_ESR UINT64_C(0x02000000)   /* EC 0 (unknown), IL */
#define FAST_EL0_ERET 0xd69f03e0u                    /* the return user_sysreg_access checks */
#define FAST_EL0_CLOCK_WORD 0xd53cfac0u   /* MRS Xt, S3_4_C15_C10_6: guest_clock_user_read's word */
#define FAST_EL0_UPERM_WORD 0xd53ef1a0u   /* MRS Xt, S3_6_C15_C1_5: sprr_user_read's word */
/* fast_el0_sysreg's outcome; the per-CPU counters are indexed by outcome-1. */
enum fast_el0_result {
    FAST_EL0_NONE,     /* not an EL0 EC 0 entry at 0x400: not this class */
    FAST_EL0_CLOCK,    /* emulated: the ordered counter alias */
    FAST_EL0_UPERM,    /* emulated: SPRR_UPERM */
    FAST_EL0_WORD,     /* declined: a word that is neither (UPERM write, AMX, ...) */
    FAST_EL0_GUARD,    /* declined: an accepted word whose PC, return, root,
                        * walk, repeat read, clock or SPRR state declined */
    FAST_EL0_RESULTS
};
static inline unsigned fast_el0_word_kind(uint32_t word)
{
    if((word&~31u)==FAST_EL0_CLOCK_WORD)return FAST_EL0_CLOCK;
    if((word&~31u)==FAST_EL0_UPERM_WORD)return FAST_EL0_UPERM;
    return FAST_EL0_WORD;
}
/* One read of the word at pc under user_instruction_read's rules: both
 * leaves, the PA, the active root and the word. */
struct fast_el0_fetch { uint64_t source,hardware,pa,root;uint32_t word; };
#if FAST_CROSS_EL0_MEMO
/* SNAP_EL0_MEMO (compat/el0-memo.h): the fetch was answered from a memo way
 * that an earlier agreeing double read kept, after re-reading every value
 * that read loaded (both walks' descriptors, the code frame's type, the word)
 * and finding it unchanged: it already is the second read of a pair, so the
 * repeat read is skipped. Every other check still runs. */
#define FAST_EL0_FETCH_PROVEN 2
#endif
struct fast_el0_hw {
    void *ctx;
    /* user_return_root, then user_instruction_read for pc: 1 with *out, 0
     * when either declines. Reads only (FAST_CROSS_EL0_MEMO: also
     * FAST_EL0_FETCH_PROVEN with *out, from the memo). */
    int (*fetch)(void *ctx,uint64_t pc,struct fast_el0_fetch *out);
    const struct clock_backend *clock;   /* the vCPU's counter backend */
    /* user_sysreg_access's user_clock/user_sprr record, after the emulation. */
    void (*note)(void *ctx,unsigned kind,uint64_t pc,uint32_t word,uint64_t saved,uint64_t root);
};
struct fast_el0_vcpu {
    struct guest_clock *clock;
    struct sprr_state *sprr;
    uint64_t *regs;        /* the trap frame's x0..x30: only Rt is written */
    uint64_t *outcomes;    /* [FAST_EL0_RESULTS-1], by outcome-1 */
    uint64_t *spsr_el2;    /* out: the EL0 PSTATE to install */
};
/* One EL0 entry at vector 0x400 whose saved mode is EL0t (fast_cross_entry
 * has checked that and the vector fetch). user_sysreg_access's decisions in
 * its order, with every decline before the first write: the vector, syndrome
 * and PC range; the return it would install (exception_user_return); the
 * active root and the word (read twice); then guest_clock_user_read for the
 * counter word (EL0VCTEN and a counter backend checked first, so it cannot
 * fail) or sprr_user_read for the UPERM word (sprr_fixed_state_valid first).
 * Returns FAST_EL0_CLOCK or FAST_EL0_UPERM with Rt, the record, *elr and
 * *v->spsr_el2 written, or another outcome with nothing changed but its
 * counter (FAST_EL0_NONE counts nothing). */
static inline unsigned fast_el0_sysreg(const struct fast_el0_hw *hw,const struct fast_el0_vcpu *v,
    uint64_t vector,uint64_t esr,uint64_t pc,uint64_t saved,uint64_t vhcr,uint64_t *elr)
{
    if(vector!=0x400 || esr!=FAST_EL0_SYSREG_ESR)return FAST_EL0_NONE;
    unsigned result=FAST_EL0_GUARD;
    uint64_t translated=0;
    struct fast_el0_fetch a={0},b={0};
#if FAST_CROSS_EL0_MEMO
    int fetched=0;
    if(pc<(UINT64_C(1)<<47)-4 && exception_user_return(FAST_EL0_ERET,vhcr,pc+4,saved,&translated) &&
       (fetched=hw->fetch(hw->ctx,pc,&a))) {
#else
    if(pc<(UINT64_C(1)<<47)-4 && exception_user_return(FAST_EL0_ERET,vhcr,pc+4,saved,&translated) &&
       hw->fetch(hw->ctx,pc,&a)) {
#endif
        result=fast_el0_word_kind(a.word);
        if(result==FAST_EL0_CLOCK ?
               !v->clock || !hw->clock || !hw->clock->counter || !(v->clock->cntkctl&2) :
           result==FAST_EL0_UPERM ? !sprr_fixed_state_valid(v->sprr) : 0)
            result=FAST_EL0_GUARD;
        else if(result!=FAST_EL0_WORD &&
#if FAST_CROSS_EL0_MEMO
                fetched!=FAST_EL0_FETCH_PROVEN &&
#endif
                (!hw->fetch(hw->ctx,pc,&b) || a.source!=b.source || a.hardware!=b.hardware ||
                 a.pa!=b.pa || a.root!=b.root || a.word!=b.word))
            result=FAST_EL0_GUARD;
    }
    /* Neither read fails past its guard; a failure would have changed nothing. */
    if(result==FAST_EL0_CLOCK && guest_clock_user_read(v->clock,hw->clock,a.word,v->regs)!=CLOCK_OK)
        result=FAST_EL0_GUARD;
    else if(result==FAST_EL0_UPERM && sprr_user_read(v->sprr,a.word,v->regs)!=SPRR_OK)
        result=FAST_EL0_GUARD;
    v->outcomes[result-1]++;
    if(result!=FAST_EL0_CLOCK && result!=FAST_EL0_UPERM)return result;
    hw->note(hw->ctx,result,pc,a.word,saved,a.root);
    *v->spsr_el2=translated;*elr=pc+4;
    return result;
}
/* fast_cross_entry's return for this class: past the logged classes, so
 * fast_cross_log_bit gives it no bit (the fast-trap bits 14.. stay clear). */
#define FAST_CROSS_EL0_SYSREG_CLASS FAST_CROSS_CLASSES
#endif

/* Everything the boundary needs from the CPU, supplied by the monitor. */
struct fast_cross_hw {
    void *ctx;
    uint64_t vbar_va,vbar_pa;       /* params->vbar_va and the vector page PA */
    uint64_t mem_low,mem_high;      /* owned guest RAM */
    int crash_ring;                 /* SNAP_USER_CRASH_RING: crash-class entries decline */
    uint64_t (*guest_pa)(void *ctx,uint64_t va);     /* AT S1E1R, 0 = fault */
    uint32_t (*fetch)(void *ctx,uint64_t pa);        /* word at an owned PA */
    void (*el1)(void *ctx,struct fast_cross_el1 *out);
    uint64_t (*hcr)(void *ctx);                      /* HCR_EL2 (VI/VF) */
    uint64_t (*vhcr)(void *ctx);                     /* the guest's HCR_EL2 in VNCR */
    /* Select the variant of the regime about to run (native_cross): 1 done;
     * 0 declined with nothing changed, or with a failure latched that stops
     * the run on the locked path. Null when a crossing needs the lock (no
     * native tables): every EL0 entry and user return then declines. */
    int (*cross)(void *ctx,int el0);
    int (*user_root)(void *ctx);                     /* user_return_root(c) != 0 */
    void (*capture)(void *ctx,const uint64_t *frame,uint64_t esr,uint64_t elr,uint64_t far);
#if FAST_CROSS_EL0_SYSREG
    const struct fast_el0_hw *el0;                   /* null: the EL0 class declines */
#endif
};
/* The trapping vCPU's private state, exactly the fields the locked branches
 * use; logged/first are the per-vCPU first-occurrence bookkeeping. */
struct fast_cross_vcpu {
    uint64_t *user_vectors,*protected_vectors,*vector,*saved_spsr,*entry_spsr,*entry_sctlr;
    uint64_t *timer_vectors,*model_irq_vectors,*fault_esr,*fault_far;
    uint64_t *kernel_returns,*last_kernel_return;
    uint64_t *returns,*svcs,*faults;
    uint64_t *logged,*first;
#if FAST_CROSS_EL0_SYSREG
    const struct fast_el0_vcpu *el0;                 /* null: the EL0 class declines */
#endif
};

/* The first of each class per vCPU keeps its shared-log record by declining. */
static inline int fast_cross_first(const struct fast_cross_vcpu *v,unsigned cls)
{
    uint64_t bit=fast_cross_log_bit(cls);
    if(!v->logged || (*v->logged&bit))return 0;
    *v->logged|=bit;(*v->first)++;
    return 1;
}

/* One instruction abort on the vector page from AArch64 EL1 (the caller has
 * matched the faulting IPA's page to vbar_pa with S1PTW clear, and declined
 * any step, guard, probe or latched failure). Handled exactly as the locked
 * vector branch handles these classes, minus record():
 *   TIMER   FIQ slot with HCR_EL2.VF: the virtual timer or an IPI;
 *   DEVICE  IRQ slot with HCR_EL2.VI: a modeled device interrupt;
 *   USER_SYNC   EL0 SVC or EL0 instruction/data abort with a translation,
 *               access or permission status (exception_user_sync);
 *   KERNEL_FAULT  EL1 instruction/data abort of the same statuses.
 * Returns the class, with *elr at the slot's branch target and the vCPU state
 * updated, or FAST_CROSS_NONE; apart from a first-occurrence mark, a decline
 * has changed nothing. With FAST_CROSS_EL0_SYSREG, FAST_CROSS_EL0_SYSREG_CLASS
 * is the emulated EL0 read: *elr at the next user instruction, Rt written and
 * the EL0 PSTATE in *v->el0->spsr_el2 (a decline then also counts its
 * outcome). */
static inline unsigned fast_cross_entry(const struct fast_cross_hw *hw,
    const struct fast_cross_vcpu *v,uint64_t physical_spsr,const uint64_t *frame,uint64_t *elr)
{
    uint64_t vector=*elr-hw->vbar_va,target;
    int el0=vector>=0x400;
    if(vector>=0x600 || (vector&0x7f) || (el0 && !hw->cross))return FAST_CROSS_NONE;
    struct fast_cross_el1 r;
    hw->el1(hw->ctx,&r);
    /* The saved mode must be the origin the slot group names: nested EL1
     * entries save virtual EL2t (0x000) or EL2h (0x200), EL0 entries EL0t. */
    unsigned mode=(unsigned)(r.spsr&31);
    if(mode!=(el0 ? 0u : vector>=0x200 ? 9u : 8u) || (r.spsr>>32))return FAST_CROSS_NONE;
#if FAST_CROSS_EL0_SYSREG
    /* SNAP_FAST_EL0_SYSREG, ahead of every other class and of the crash-class
     * check (which would decline any EC 0 entry): an EL0 synchronous entry
     * with the undefined-instruction syndrome is this class or nothing, as no
     * other class admits EC 0. Like the locked branch, it notes the PAN
     * evidence and then returns to EL0 without selecting the kernel regime. */
    if(vector==0x400 && r.esr==FAST_EL0_SYSREG_ESR) {
        unsigned done=hw->el0 && v->el0 ? fast_el0_sysreg(hw->el0,v->el0,vector,r.esr,r.elr,r.spsr,
                                                          hw->vhcr(hw->ctx),elr) : FAST_EL0_NONE;
        if(done!=FAST_EL0_CLOCK && done!=FAST_EL0_UPERM)return FAST_CROSS_NONE;
        (*v->user_vectors)++;*v->protected_vectors+=!!(physical_spsr&(UINT64_C(1)<<22));
        *v->vector=vector;*v->saved_spsr=r.spsr;
        *v->entry_spsr=physical_spsr;*v->entry_sctlr=r.sctlr;
        return FAST_CROSS_EL0_SYSREG_CLASS;
    }
#endif
    /* A kernel entry with the SPTM call's syndrome (EC 0, IL; stale for an
     * interrupt) may be a native call, which the locked path looks up. */
    if(!el0 && r.esr==(UINT64_C(1)<<25))return FAST_CROSS_NONE;
    unsigned cls=FAST_CROSS_NONE,slot=(unsigned)(vector&0x180);
    uint64_t hcr=hw->hcr(hw->ctx);
    if(slot==0x100) {if(hcr&(UINT64_C(1)<<6))cls=FAST_CROSS_TIMER;}
    else if(slot==0x080) {if(hcr&(UINT64_C(1)<<7))cls=FAST_CROSS_DEVICE;}
    /* Neither synchronous class admits EC 0 (an SPTM call, an EL0
     * system-register emulation or a skipped encoding), and an SError slot
     * is no class: all of those stay locked. */
    else if(!slot) {
        if(exception_user_sync(vector,r.spsr,r.esr))cls=FAST_CROSS_USER_SYNC;
        else if(exception_kernel_page_fault(r.esr))cls=FAST_CROSS_KERNEL_FAULT;
        /* A crash-class EL0 entry takes the locked path, which notes it. */
        if(hw->crash_ring && vector==0x400 &&
           user_crash_classify(r.esr,r.far,frame[16],frame[1]))return FAST_CROSS_NONE;
    }
    if(!cls || !fast_vector_branch(hw->fetch(hw->ctx,hw->vbar_pa|(*elr&0xfff)),*elr,&target) ||
       fast_cross_first(v,cls))return FAST_CROSS_NONE;
    /* The last decision: entering EL1 from EL0 selects the kernel regime's
     * variant; a declined selection has changed nothing. */
    if(el0 && !hw->cross(hw->ctx,0))return FAST_CROSS_NONE;
    if(el0) {
        (*v->user_vectors)++;*v->protected_vectors+=!!(physical_spsr&(UINT64_C(1)<<22));
        *v->vector=vector;*v->saved_spsr=r.spsr;
        *v->entry_spsr=physical_spsr;*v->entry_sctlr=r.sctlr;
    }
    if(cls==FAST_CROSS_TIMER)(*v->timer_vectors)++;
    else if(cls==FAST_CROSS_DEVICE)(*v->model_irq_vectors)++;
    else {
        hw->capture(hw->ctx,frame,r.esr,r.elr,r.far);
        if(cls==FAST_CROSS_USER_SYNC) {
            if((r.esr>>26)==0x15)(*v->svcs)++;
            else (*v->faults)++;
        }
    }
    *v->fault_esr=0;*v->fault_far=0;
    *elr=target;
    return cls;
}

/* One ERET trap (EC 0x1a) from AArch64 EL1, handled exactly as the locked
 * ERET branch handles a kernel return, or a user return after this CPU's
 * first (whose entry probe stays locked), minus record(). Returns the class
 * with *elr at the target and *spsr_el2 the physical PSTATE to install, or
 * FAST_CROSS_NONE; apart from a first-occurrence mark, a decline has changed
 * nothing. */
static inline unsigned fast_cross_return(const struct fast_cross_hw *hw,
    const struct fast_cross_vcpu *v,uint64_t physical_spsr,uint64_t *elr,uint64_t *spsr_el2)
{
    uint64_t pa=hw->guest_pa(hw->ctx,*elr),translated;
    uint32_t word=pa>=hw->mem_low && pa<=hw->mem_high-4 ? hw->fetch(hw->ctx,pa) : 0;
    struct fast_cross_el1 r;
    hw->el1(hw->ctx,&r);
    uint64_t vhcr=hw->vhcr(hw->ctx),target=r.elr,target_pa=hw->guest_pa(hw->ctx,target);
    if(target_pa>=hw->mem_low && target_pa<=hw->mem_high-4 &&
       exception_kernel_return(word,vhcr,target,r.spsr,&translated)) {
        if(fast_cross_first(v,FAST_CROSS_KERNEL_RETURN))return FAST_CROSS_NONE;
        (*v->kernel_returns)++;*v->last_kernel_return=target;
        *spsr_el2=translated;*elr=target;
        return FAST_CROSS_KERNEL_RETURN;
    }
    if(!exception_monitor_origin(*elr,physical_spsr) ||
       !exception_user_return(word,vhcr,target,r.spsr,&translated) ||
       !hw->cross || !*v->returns || !hw->user_root(hw->ctx) ||
       fast_cross_first(v,FAST_CROSS_USER_RETURN) || !hw->cross(hw->ctx,1))
        return FAST_CROSS_NONE;
    (*v->returns)++;
    *spsr_el2=translated;*elr=target;
    return FAST_CROSS_USER_RETURN;
}
