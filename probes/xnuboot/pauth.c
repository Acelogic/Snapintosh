/* SPDX-License-Identifier: MIT */
/* PAuth: generic signing, native PACGA, lean-trap FGT state, native batch/pointer
 * signing, the user pointer calls and the failure/resume path.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */
/* During guest EL1 execution HCR.API/APK remain clear. This trap backend
 * handles kernel PACGA and restores the host key inside one assembly block.
 * EL0 uses the separate scoped pauth_switch bank and native instructions;
 * the batch user-pointer signing service has not yet been connected to it. */
static uint64_t generic_sign(void *opaque, uint64_t data, uint64_t modifier)
{
    struct context *c = opaque;
    uint64_t lo, hi, result;
    __asm__ volatile(
        "mrs %0, s3_0_c2_c3_0\n\t"
        "mrs %1, s3_0_c2_c3_1\n\t"
        "msr s3_0_c2_c3_0, %5\n\t"
        "msr s3_0_c2_c3_1, %6\n\tisb\n\t"
        ".arch_extension pauth\n\tpacga %2, %3, %4\n\t"
        "msr s3_0_c2_c3_0, %0\n\t"
        "msr s3_0_c2_c3_1, %1\n\tisb"
        : "=&r"(lo), "=&r"(hi), "=&r"(result)
        : "r"(data), "r"(modifier), "r"(vcpu_of(c)->guest_apga_lo),
          "r"(vcpu_of(c)->guest_apga_hi) : "memory");
    return result;
}

static int generic_pauth_supported(void)
{
    uint64_t isar1 = id_register(6, 1), isar2 = id_register(6, 2);
    unsigned gpa = (isar1 >> 24) & 15, gpi = (isar1 >> 28) & 15;
    unsigned gpa3 = (isar2 >> 8) & 15;
    return gpa == 1 || gpi == 1 || gpa3 == 1;
}

#if SNAP_NATIVE_PACGA
/* APGAKey := the guest kernel's GA key, the one generic_sign would load. Only
 * while EL1's bank is installed (pauth_switch_leave has run, as it has before
 * any C); the ERET back to the guest synchronizes the write. */
static void native_pacga_load(struct context *c, struct vcpu *v)
{
    __asm__ volatile("msr s3_0_c2_c3_0, %0; msr s3_0_c2_c3_1, %1"
                     :: "r"(v->guest_apga_lo), "r"(v->guest_apga_hi) : "memory");
    c->pauth_bank[v->slot].ga_loads++;
}
/* After an emulated key write: reload only when the GA key changed. */
static void native_pacga_sync(struct context *c, struct vcpu *v, uint64_t lo, uint64_t hi)
{
    if (v->guest_apga_lo != lo || v->guest_apga_hi != hi) native_pacga_load(c, v);
}
/* This CPU's first prepare saves its host APGAKey (private bank, owner =
 * this MPIDR), then loads the guest key and sets HCR_EL2.API for EL1. */
static int native_pacga_prepare(struct context *c, struct vcpu *v)
{
    if (!generic_pauth_supported()) return -29;
    struct pauth_switch *bank = &c->pauth_bank[v->slot];
    uint64_t mpidr, hcr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!bank->ga_owner) {
        __asm__ volatile("mrs %0, s3_0_c2_c3_0; mrs %1, s3_0_c2_c3_1"
                         : "=r"(bank->ga_host_lo), "=r"(bank->ga_host_hi));
        bank->ga_owner = mpidr;
    } else if (bank->ga_owner != mpidr) return -29;
    native_pacga_load(c, v);
    __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
    __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr | (1UL << 41)));
    return 0;
}
/* A terminal path: the saving CPU puts its host APGAKey back, once. */
static void native_pacga_restore(struct context *c, struct vcpu *v)
{
    struct pauth_switch *bank = &c->pauth_bank[v->slot];
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!bank->ga_owner || bank->ga_owner != mpidr) return;
    __asm__ volatile("msr s3_0_c2_c3_0, %0; msr s3_0_c2_c3_1, %1; isb"
                     :: "r"(bank->ga_host_lo), "r"(bank->ga_host_hi) : "memory");
    bank->ga_host_lo = bank->ga_host_hi = 0;
    bank->ga_owner = 0;
}
#endif

#if SNAP_LEAN_TRAPS == 2
/* This CPU's TVM/TRVM as FEAT_FGT traps of the same registers, minus ESR_EL1
 * and FAR_EL1 reads and CONTEXTIDR_EL1 writes (compat/lean-trap.h). The host's
 * HFGRTR/HFGWTR/CONTEXTIDR are saved once, owned by this MPIDR. TVM/TRVM are
 * cleared only after both FGT registers read back exactly as written; any
 * other outcome leaves this CPU's traps as they were. EV_OTHER pc 3: a = the
 * HFGRTR_EL2 read back, b = HFGWTR_EL2, c = slot | status << 8. */
static void lean_fgt_prepare(struct context *c, struct vcpu *v)
{
    struct lean_trap_cpu *l = &c->root_ext->lean[v->slot];
    uint64_t mmfr0, mmfr3, mpidr, r = 0, w = 0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    __asm__ volatile("mrs %0, s3_0_c0_c7_3" : "=r"(mmfr3));     /* ID_AA64MMFR3_EL1 */
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    unsigned status = lean_fgt_admit(mmfr0, mmfr3);
    if (status == LEAN_FGT_ACTIVE && l->owner && l->owner != mpidr) status = LEAN_FGT_OWNER;
    if (status == LEAN_FGT_ACTIVE) {
        if (!l->owner) {
            /* HFGRTR_EL2, HFGWTR_EL2 by encoding (FEAT_FGT). */
            __asm__ volatile("mrs %0, s3_4_c1_c1_4; mrs %1, s3_4_c1_c1_5; mrs %2, contextidr_el1"
                             : "=r"(l->host_hfgrtr), "=r"(l->host_hfgwtr), "=r"(l->host_contextidr));
            l->owner = mpidr;
        }
        uint64_t want_r = lean_fgt_read(l->host_hfgrtr), want_w = lean_fgt_write(l->host_hfgwtr);
        __asm__ volatile("msr s3_4_c1_c1_4, %2; msr s3_4_c1_c1_5, %3; isb; "
                         "mrs %0, s3_4_c1_c1_4; mrs %1, s3_4_c1_c1_5"
                         : "=&r"(r), "=&r"(w) : "r"(want_r), "r"(want_w) : "memory");
        if (r != want_r || w != want_w) {
            __asm__ volatile("msr s3_4_c1_c1_4, %0; msr s3_4_c1_c1_5, %1; isb"
                             :: "r"(l->host_hfgrtr), "r"(l->host_hfgwtr) : "memory");
            status = LEAN_FGT_READBACK;
        } else {
            uint64_t hcr;
            __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
            __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr & ~LEAN_HCR_TVM_TRVM));
        }
    }
    l->status = status;
    record(c, EV_OTHER, 3, r, w, v->slot | ((uint64_t)status << 8));
}
/* A terminal path: the saving CPU puts its host FGT registers and CONTEXTIDR
 * back, once. HCR_EL2 is the caller's (q1n1's CPU restores its saved value). */
static void lean_fgt_restore(struct context *c, struct vcpu *v)
{
    struct lean_trap_cpu *l = &c->root_ext->lean[v->slot];
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    if (!l->owner || l->owner != mpidr) return;
    __asm__ volatile("msr s3_4_c1_c1_4, %0; msr s3_4_c1_c1_5, %1; msr contextidr_el1, %2; isb"
                     :: "r"(l->host_hfgrtr), "r"(l->host_hfgwtr), "r"(l->host_contextidr) : "memory");
    l->owner = 0;
}
#endif

struct pauth_batch_native { struct pauth_key_pair keys[PAUTH_KEYS]; };
static int pauth_batch_native_sign(void *opaque,const struct pauth_batch_entry *entry,
                                   uint64_t tbi,uint64_t tbid,uint64_t *out)
{
    struct pauth_batch_native *ctx=opaque;
    if(entry->key!=PAUTH_IA && entry->key!=PAUTH_DA)return 0;
    struct pauth_native_request request={entry->pointer,entry->modifier,
        ctx->keys[entry->key].lo,ctx->keys[entry->key].hi,entry->key,tbi,tbid};
    struct pauth_native_result result={0};
    int ok=!pauth_native_user(&request,&result) && result.restored==15 &&
           result.authenticated==entry->pointer;
    if(ok)*out=result.signed_pointer;
    aes_clear(&request,sizeof(request));return ok;
}

static int pauth_pointer_native_sign(void *opaque,const struct pauth_batch_entry *entry,
                                     uint64_t tbi,uint64_t tbid,uint64_t *out)
{
    struct pauth_batch_native *ctx=opaque;
    if(entry->key!=PAUTH_IA && entry->key!=PAUTH_DA)return 0;
    struct pauth_native_request request={entry->pointer,entry->modifier,
        ctx->keys[entry->key].lo,ctx->keys[entry->key].hi,entry->key,tbi,tbid};
    struct pauth_native_result result={0};
    int ok=!pauth_native_sign_user(&request,&result) && result.restored==15 &&
           result.authenticated==0;
    if(ok)*out=result.signed_pointer;
    aes_clear(&request,sizeof(request));return ok;
}

#if SNAP_FAST_PAUTH_CALLS
/* SIGN_USER_POINTER/AUTH_USER_POINTER and BATCH_SIGN_USER_POINTER: the body
 * of monitor_call_impl's cases (whose define-off text is the same statements
 * inline: a default build stays byte-identical), run by those cases and by
 * the converted calls (fine_pauth_pointer, fine_pauth_batch), so the two
 * answers cannot diverge. They read this CPU's TCR_EL1, PAC bank, key operands
 * and derivation cache and write its pauth_pointer or pauth_batch record (a
 * batch also its scratch page, through memory->publish); the rest is
 * boot-fixed (pauth_domain, aes_hardware). The native helpers mask DAIF and
 * restore this PE's TCR/SCTLR_EL2 and key registers. SPTM_BAD_CONFIG with
 * *ran still 0: the configuration refused before anything changed (the
 * derivation refuses without touching its cache); otherwise *ran is 1 and the
 * result is the engine's, which has counted the attempt. */
static enum sptm_result user_pointer_call(struct context *c,const uint64_t *frame,uint32_t endpoint,int *ran)
{
    struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
    __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
    if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
       !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                 &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
        aes_clear(&native,sizeof(native));return SPTM_BAD_CONFIG;
    }
    *ran=1;
    enum sptm_result result=pauth_pointer(frame[0],frame[1],frame[2],
        endpoint==SPTM_FN_AUTH_USER_POINTER,(tcr>>37)&1,(tcr>>51)&1,
        pauth_pointer_native_sign,&native,&c->pauth_pointer[v->slot]);
    aes_clear(&native,sizeof(native));
    return result;
}
static enum sptm_result user_pointer_batch(struct context *c,const struct sptm_memory *memory,
                                           const uint64_t *frame,const struct guest_cpu_buffer *scratch,int *ran)
{
    struct vcpu *v=vcpu_of(c);struct pauth_batch_native native;uint64_t tcr;
    __asm__ volatile("mrs %0,tcr_el1":"=r"(tcr));
    if((tcr&((3UL<<14)|(1UL<<7)|63))!=17 || c->pauth_bank[v->slot].active ||
       !pauth_domain_user_cached(&c->pauth_domain,&c->user_pauth[v->slot],
                                 &c->pauth_derive[v->slot],native.keys,(int)c->aes_hardware)) {
        aes_clear(&native,sizeof(native));return SPTM_BAD_CONFIG;
    }
    *ran=1;
    enum sptm_result result=pauth_batch_sign(memory,&c->pauth_batch[v->slot],
        frame[0],frame[1],scratch->pa,scratch->va,(tcr>>37)&1,(tcr>>51)&1,
        pauth_batch_native_sign,&native);
    aes_clear(&native,sizeof(native));
    return result;
}
#endif

int xnuboot_pauth_failed(const uint64_t *frame);
int xnuboot_pauth_failed(const uint64_t *frame)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    v->service_fault=0x504143;
    fill_regs(&v->async_regs,frame,0,frame[32],0);v->async_captured=1;
    guest_service_stop(&c->services,v->slot,SERVICE_STOP_FAULT);
    watchdog_off(c);return 1;
}

/* Called after C handling but before restoring the guest's register frame.
 * Every exception path restores keys in assembly before it calls any C
 * (SNAP_PAUTH_EL0_LIVE: except sync_lower's EL0-read entry, which
 * el0_live_trap answers or restores before any other C).
 * All C here is built without PAC prologues and uses general registers only. */
int xnuboot_pauth_resume(const uint64_t *frame);
int xnuboot_pauth_resume(const uint64_t *frame)
{
    struct context *c=context_of();struct vcpu *v=vcpu_of(c);
    struct pauth_switch *bank=&c->pauth_bank[v->slot];uint64_t spsr;
#if SNAP_PAUTH_EL0_LIVE
    /* el0_live_trap answered an EL0 read with the EL0 bank still installed (the
     * only way the bank is live here): EL0 resumes with it, exactly as it ran,
     * without a key check or an enter (no EL1 instruction ran, so the key
     * operands and enables are the ones installed); never EL1. */
    int live=bank->active==1 && !bank->failures;
    if(!live && (bank->failures || bank->active))return xnuboot_pauth_failed(frame);
#else
    if(bank->failures || bank->active)return xnuboot_pauth_failed(frame);
#endif
    __asm__ volatile("mrs %0,spsr_el2":"=r"(spsr));
#if SNAP_PAUTH_EL0_LIVE
    if(live && (spsr&31))return xnuboot_pauth_failed(frame);
#endif
    if(spsr&31) {FAST_EXIT_END(c,v,frame);return 0;}
#if SNAP_PAUTH_EL0_LIVE
    if(!live) {
#endif
    struct pauth_user_state *state=&c->user_pauth[v->slot];
    if(!c->pauth_key_valid[v->slot] || c->pauth_key_version[v->slot]!=state->writes) {
#if SNAP_EL0_MEMO
        /* Behind the 8-entry memo, this vCPU's second level (both flushed when
         * the domain epoch moves). */
        if(!pauth_domain_user_cached_wide(&c->pauth_domain,state,&c->pauth_derive[v->slot],
                                          &c->root_ext->derive_wide[v->slot],c->root_ext->pauth_epoch,
                                          bank->guest,(int)c->aes_hardware))
#else
        if(!pauth_domain_user_cached(&c->pauth_domain,state,&c->pauth_derive[v->slot],
                                     bank->guest,(int)c->aes_hardware))
#endif
            return xnuboot_pauth_failed(frame);
        c->pauth_key_version[v->slot]=state->writes;
        c->pauth_key_valid[v->slot]=1;
    }
    bank->enables=v->guest_sctlr&0xc8002000UL;
    if(pauth_switch_enter(bank))return xnuboot_pauth_failed(frame);
#if SNAP_PAUTH_EL0_LIVE
    }
#endif
    FAST_EXIT_END(c,v,frame);
    return 0;
}

