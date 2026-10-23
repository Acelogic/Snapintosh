/* SPDX-License-Identifier: MIT */
/* Boot preparation: PAuth domain, boot-relocation capture, xnuboot_prepare, the
 * ERET window proof and per-vCPU architectural state.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

/* Build everything and program EL1. Returns 0 when the guest may be entered,
 * negative with the step identified when it may not. */
/* int64_t, not int: probes/xnuboot.S stores the whole of x0 into the status
 * word and the host reads it as a signed 64-bit value, so a 32-bit -6 arrives
 * as 0x00000000fffffffa and reads as an EL2 fault with a nonsense ESR. */
static int64_t vcpu_arch_prepare(struct context *c);
static int secondary_prepare_records(struct context *c);
int64_t xnuboot_prepare(void);
static int pauth_domain_prepare(struct context *c)
{
    uint64_t isar0,isar1,isar2,seed[4]={0};
    __asm__ volatile("mrs %0,id_aa64isar0_el1; mrs %1,id_aa64isar1_el1; mrs %2,id_aa64isar2_el1"
                     :"=r"(isar0),"=r"(isar1),"=r"(isar2));
    if(!(isar0>>60) || !(((isar1>>4)&255)|((isar2>>12)&15)))return 0;
    /* PAC key derivation runs 15 AES blocks per key install or user sign.
     * The AES path saves/restores v0/v1 only; with SVE or SME a NEON write
     * would clear live Z-register bits above 128, so keep software AES there. */
    uint64_t pfr0,pfr1;
    __asm__ volatile("mrs %0,id_aa64pfr0_el1; mrs %1,id_aa64pfr1_el1":"=r"(pfr0),"=r"(pfr1));
    c->aes_hardware=(uint64_t)(aes_hardware_supported(isar0) &&
        !((pfr0>>32)&15) && !((pfr1>>24)&15));
    for(unsigned i=0;i<4;i++) {
        unsigned ok=0;
        for(unsigned retry=0;retry<64 && !ok;retry++)
            __asm__ volatile("mrs %0,s3_3_c2_c4_0; cset %w1,ne"
                             :"=r"(seed[i]),"=r"(ok)::"cc");
        if(!ok) {aes_clear(seed,sizeof(seed));return 0;}
    }
    int ok=pauth_domain_init(&c->pauth_domain,(const uint8_t *)seed);
    aes_clear(seed,sizeof(seed));return ok;
}

#if SNAP_BOOT_RELOCATE
/* Allocated encodings only (compat/boot-relocate.h), never id_register: its
 * unallocated CRm=0 cases trap on the A16 (v48). Not inlined, so the build
 * check can read every MRS it contains. */
static __attribute__((noinline)) void boot_relocation_ids(uint64_t id[BOOT_ID_COUNT], uint64_t cache[2])
{
#define BOOT_ID_READ(name, op1, crn, crm, op2, shared) \
    __asm__ volatile("mrs %0, s3_" #op1 "_c" #crn "_c" #crm "_" #op2 : "=r"(id[BOOT_ID_##name]));
    BOOT_RELOCATE_ID_REGS(BOOT_ID_READ)
#undef BOOT_ID_READ
    __asm__ volatile("mrs %0, ctr_el0":"=r"(cache[0]));
    __asm__ volatile("mrs %0, dczid_el0":"=r"(cache[1]));
}
/* On q1n1's CPU, in place of vcpu_arch_prepare: what the report will restore
 * here, read here, and the ID registers the shared preparation just used. */
static int64_t boot_relocation_capture(struct boot_relocation *r)
{
    uint64_t *h=r->host;
    __asm__ volatile("mrs %0, vttbr_el2":"=r"(h[0]));
    __asm__ volatile("mrs %0, vtcr_el2":"=r"(h[1]));
    __asm__ volatile("mrs %0, vmpidr_el2":"=r"(h[2]));
    __asm__ volatile("mrs %0, cntkctl_el1":"=r"(h[3]));
    __asm__ volatile("mrs %0, cnthctl_el2":"=r"(h[4]));
    __asm__ volatile("mrs %0, mdcr_el2":"=r"(h[5]));
    __asm__ volatile("mrs %0, mdscr_el1":"=r"(h[6]));
    __asm__ volatile("mrs %0, oslsr_el1":"=r"(h[7]));
    __asm__ volatile("mrs %0, ttbr0_el1":"=r"(h[8]));
    __asm__ volatile("mrs %0, ttbr1_el1":"=r"(h[9]));
    __asm__ volatile("mrs %0, mair_el1":"=r"(h[10]));
    boot_relocation_ids(r->boot_id,r->boot_cache);
    __asm__ volatile("mrs %0, cntvoff_el2":"=r"(r->boot_cntvoff));
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(r->boot_cntfrq));
    r->captured=1;
    return 0;
}
#endif

int64_t xnuboot_prepare(void)
{
    struct context *c = context_of();
    const struct params *p = c->params;
    if(!pauth_domain_prepare(c))return -24;
#if SNAP_EL0_MEMO
    /* A new master key: every derivation kept in either level is another
     * domain's (pauth_domain_user_cached_wide flushes on the epoch). */
    c->root_ext->pauth_epoch++;
#endif
    uint64_t physical_hz, mmfr0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(physical_hz));
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    if (physical_hz != p->clock_host_hz || !(mmfr0 >> 60) ||
        clock_rate_init(&vcpu_of(c)->clock_rate, physical_hz, p->clock_guest_hz)) return -15;
    if(c->thermal && (physical_hz!=19200000 || thermal_admit(c)))return -28;
    if (p->device_count > 4 || p->mem_high <= p->mem_low) return -14;
    uint64_t panic_page=p->scratch_pa-SPTM_PANIC_PAGE_SIZE;
    if((p->scratch_pa&0x3fff) || panic_page<p->mem_low || p->scratch_pa>p->mem_high ||
       panic_page<p->txm_aspace_pa+TXM_ASPACE_SIZE+3*0x4000 || p->watch_pa<p->mem_low ||
       p->watch_pa>p->mem_high-0x1000 ||
       *(volatile uint64_t *)(p->watch_pa+SPTM_PANIC_HANDOFF_OFFSET)!=
            p->ram_aperture_va+panic_page-p->mem_low)return -22;
#if SNAP_TXM_ASPACE_WIDE
    /* compat/txm.h A2: the loader's 64-page layout puts UAT right after the
     * whole arena; the 8-page one would leave UAT inside it. */
    if(p->uat.reserved_pa!=p->txm_aspace_pa+TXM_ASPACE_SIZE)return -22;
#endif
    for(unsigned i=0;i<SPTM_PANIC_PAGE_SIZE;i++)
        if(*(volatile uint8_t *)(panic_page+i))return -22;
    sptm_panic_init(&c->panic_state);
    if(p->trust_cache.pa) {
        uint64_t span=0x4000+((p->trust_cache.size+0x3fff)&~0x3fffUL),pa=p->trust_cache.pa;
        /* Either the window between the TXM address space and the panic page (BaseSystem's
         * cache), or -- for the installed OS's larger cache -- the payload area above the
         * per-CPU scratch buffers and below XNU's allocator, clear of the SEP preload. */
        int window=pa>=p->txm_aspace_pa+TXM_ASPACE_SIZE+3*0x4000 && pa<=UINT64_MAX-span &&
                   pa+span<=panic_page;
        int payload=pa>=p->scratch_pa+GUEST_CPU_COUNT*0x8000UL && pa<=UINT64_MAX-span &&
                    pa+span<=p->alloc_low &&
                    !(p->sep_firmware_size && pa<p->sep_firmware_pa+p->sep_firmware_size &&
                      p->sep_firmware_pa<pa+span);
        if(p->trust_cache.size<24 || p->trust_cache.size>TXM_TRUST_MAX_BYTES ||
           !(window || payload) ||
           pa<p->mem_low || pa+span>p->mem_high)return -21;
    }
    struct sptm_memory trust_memory=sptm_context_memory(c);
    if (!sptm_sep_firmware_valid(&trust_memory) ||
        (p->sep_firmware_size && (p->sep_firmware_pa<p->mem_low ||
         p->sep_firmware_pa<p->scratch_pa+GUEST_CPU_COUNT*0x8000UL))) return -25;
    struct txm_service trust_service={.stacks_pa=p->txm_stacks_pa,
        .stack_count=p->txm_stack_count,.log_pa=p->txm_log_pa,
        .rw_pa=p->txm_rw_pa,.ro_pa=p->txm_ro_pa};
    if(txm_trust_bootstrap(&trust_memory,&trust_service,&p->trust_cache,&c->trust_state))return -21;
    if(p->txm_native.image && (!p->trust_cache.pa ||
       txm_native_init(&p->txm_native,&c->txm_native,
           id_forge(4,0,id_register(4,0)),id_forge(4,1,id_register(4,1)))))return -26;
    thermal_prepare_tick(c);
    if (p->vmpidr != 0x80000000 ||
        !guest_cpu_buffers_valid(p->scratch_pa,p->scratch_va,p->mem_low,p->mem_high))
        return -16;
    struct device_range excluded[7] = {
        {p->mem_low, p->mem_high-p->mem_low}, {p->fb_pa, p->fb_span},
        {c->work_start, c->work_end-c->work_start}
    };
    for (uint64_t n=0; n<p->device_count; n++)
        excluded[3+n] = (struct device_range){p->device_pa[n], p->device_span[n]};
    if (!device_models_valid(p->models, p->model_count, excluded, 3+p->device_count))
        return -14;
    if (!device_models_boot_cpu_valid(p->models, p->model_count, p->vmpidr)) return -14;
    for (unsigned i=0;i<p->model_count;i++)
        if(p->models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 && p->models[i].config[4] &&
           !p->sep_firmware_size)return -25;
    if (p->sep_firmware_size) {
        unsigned bindings=0;
        for (unsigned i=0;i<p->model_count;i++)
            if (p->models[i].kind==DEVICE_DART_T8110_V1 &&
                p->models[i].config[1]==DEVICE_DART_SEP_BOOT_V1 &&
                p->models[i].config[4]==(1U<<20)) bindings++;
        if (bindings!=1) return -25;
    }
    uint64_t device_now = clock_counter(c);
    if (device_models_start(p->models,c->model_state,(unsigned)p->model_count,
                            device_now,p->clock_guest_hz)!=DEVICE_OK) return -14;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1)
            ans_reset((struct ans_state *)p->models[i].config[0],p->models[i].config[1]);
    thermal_prepare_tick(c);

    /* 1. The shadow: the guest's 16K upper half, re-translated into 4K. */
    uint32_t t1sz = (uint32_t)((p->tcr >> 16) & 0x3f);
    struct mmu_config guest = {.granule_shift = 14, .txsz = t1sz, .root = p->ttbr1_root};
    struct shadow shadow = {.txsz = t1sz, .alloc = prepare_table_alloc, .read = mem_read,
                            .write = mem_write, .ctx = c,
                            .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_high:0};
    shadow.root = table_alloc(c);
    if (!shadow.root) return -1;
    long leaves = shadow_build(&shadow, &guest, 0, 1UL << (64 - t1sz), mem_read, c);
    if (leaves < 0) return -2;
    vcpu_of(c)->shadow_root = shadow.root;
    c->leaves = (uint64_t)leaves;
    if (t1sz!=17 || p->slide.begin>=p->slide.end ||
        p->slide.end-p->slide.begin>0x4000000 ||
        shadow_reserve(&shadow,p->slide.begin&((1UL<<47)-1),
                       p->slide.end-p->slide.begin)) return -13;

    /* The low regime. The guest's own 16K tables already describe these
     * addresses -- the loader maps the reserve identity, and the kernel's
     * software walker finds them there because it masks rather than asking
     * which half it is in. What was missing is a table base for the hardware to
     * use when the kernel stops walking and starts loading. So this is the same
     * guest tables shadowed a second time, over the low range only, rather than
     * a second description of the same memory that could drift from the first. */
    struct shadow low = {.txsz = t1sz, .alloc = prepare_table_alloc, .read = mem_read,
                         .write = mem_write, .ctx = c,
                         .admit=SNAP_NATIVE_WRITER_ADMISSION ? native_writer_admit_low:0};
    low.root = table_alloc(c);
    if (!low.root) return -8;
    long low_leaves = shadow_build(&low, &guest, p->low_base,
                                   p->low_base + p->low_span, mem_read, c);
    if (low_leaves < 0) return -9;
    vcpu_of(c)->low_root = low.root;
    vcpu_of(c)->low_leaves = (uint64_t)low_leaves;

    struct shadow canonical=kernel_shadow(c);
    if(!sprr_views_init(&c->kernel_views,&canonical) || !kernel_refresh(c))return -22;
    thermal_prepare_tick(c);

    /* 2. Stage 2: exactly what we own, then execute-never on the pages we want
     * to hear about -- every page holding a monitor call, and XNU's own vectors
     * -- so a fault XNU takes is delivered here instead of disappearing into
     * its handler.
     *
     * Three ranges, each mapped to itself, and nothing else:
     *   - the DRAM we declared and the reserve above it, read-write;
     *   - the panel, when it is handed over, read-write;
     *   - this probe's table arena, read-only. The private context and PA
     *     keys before work_base remain completely absent from stage 2.
     *     The hardware walks the 4K shadow
     *     tables through stage 2 -- at EL1, and for the AT S1E1R at the end of
     *     this function, since HCR_EL2.VM is already set -- so they must be
     *     reachable. The guest must never write them, and a write is a fault
     *     we want to see. The walker itself never writes: the TCR the shadow
     *     runs under has HA and HD clear, and a guest TCR write is stored, not
     *     applied.
     * Every other intermediate address is absent. A touch is a stage-2 fault
     * that arrives in xnuboot_trap with the IPA, and the run stops there. The
     * list is checked before a descriptor is written -- empty, unaligned,
     * past 36 bits or overlapping is -10 -- because a map that is quietly
     * partial would read like the identity map this replaces, minus whatever
     * it lost. */
    for (unsigned n = 0; n < GUEST_CPU_COUNT; n++) {
        int built = vcpu_stage2_prepare(c, &c->vcpus[n]);
        if (built) return built;
        thermal_prepare_tick(c);
    }
#if SNAP_USER_HW_WALK_S2RO
    /* Guest RAM in level-3 leaves in every tree before any vCPU runs: a
     * RETYPE then changes only a leaf's S2AP, never a block size under a
     * running CPU (compat/user-hw-walk.h hw_s2_presplit, v62). */
    if (hw_s2_presplit_all(c)) return -27;
#endif

    /* Allocate CPU-local runtime memory after every stage-2 tree, preserving
     * their existing addresses. Six VNCR pages and five stacks/output pages
     * remain inside monitor-owned RAM, read-only to the guest at stage 2. */
    struct guest_cpu_storage storage[GUEST_CPU_COUNT];
    uint64_t storage_end;
    if (!p->vncr_va || p->vncr_va&0xfff || p->vncr_va<p->mem_low ||
        p->vncr_va>p->mem_high-GUEST_RUNTIME_PAGE ||
        guest_cpu_storage_plan(c->next_table,c->work_end,storage,&storage_end)) return -17;
    uint64_t seed_hcr=*(const volatile uint64_t *)(p->vncr_va+0x78);
#if SNAP_ROOT_DIRTY_PUBLISH
    c->root_publish.always_first=c->next_table;
#endif
    for (uint64_t address=c->next_table; address<storage_end; address+=8)
        *(volatile uint64_t *)address=0;
    c->next_table=storage_end;
    c->vcpus[0].vncr_va=storage[0].vncr;
    for (unsigned n=0; n<GUEST_RUNTIME_PAGE/8; n++)
        *(volatile uint64_t *)(storage[0].vncr+n*8)=
            *(const volatile uint64_t *)(p->vncr_va+n*8);
    for (unsigned n=1; n<GUEST_CPU_COUNT; n++) {
        struct vcpu *v=&c->vcpus[n];
        const struct guest_cpu_storage *s=&storage[n];
        v->vncr_va=s->vncr;
        v->out_ptr=s->output;
        v->el2_sp=s->stack_high;
        v->shadow_root=c->vcpus[0].shadow_root;
        v->low_root=c->vcpus[0].low_root;
        *(volatile uint64_t *)(v->vncr_va+0x78)=seed_hcr;
    }
    if (!secondary_prepare_records(c)) return -19;
#if SNAP_ROOT_DIRTY_PUBLISH
    c->root_publish.always_end=c->next_table;
#endif
    /* Long preparation is not silently exempt from the sample-gap policy. */
    if(c->thermal && thermal_admit(c))return -28;
    int64_t gpu=gpu_prepare(c);
    if (gpu) return gpu;
    thermal_prepare_tick(c);
    int64_t window=ans_window_prepare(c);
    if (window) return window;
    if(c->thermal && thermal_admit(c))return -28;
#if SNAP_BOOT_RELOCATE
    /* The CPU that runs vCPU 0 installs its own state (boot_relocated_run). */
    struct boot_relocation *relocated=boot_relocation_of(c);
    if (relocated) return boot_relocation_capture(relocated);
#endif
    return vcpu_arch_prepare(c);
}

#if SNAP_ERET_SNAPSHOT
/* The live translation of exception_return from its SPSR write (writer site
 * 5) to the first ERET, in const-sealed kernel text, must pass
 * native_writer_return_window before site 5's comparator may stay unarmed. */
static int eret_window_proof(struct context *c)
{
    const struct params *p=c->params;
    uint32_t words[NATIVE_WRITER_RETURN_WINDOW];
    uint64_t va=native_writer_sites[NATIVE_WRITER_RETURN_SITE].va;
    for(unsigned i=0;i<NATIVE_WRITER_RETURN_WINDOW;i++) {
        uint64_t pa=guest_pa(va+4*i);
        if(pa<p->const_begin || pa+4>p->const_end)return 0;
        words[i]=*(const volatile uint32_t *)pa;
        if(words[i]==NATIVE_WRITER_ERET)return i && native_writer_return_window(words,i+1)==i;
    }
    return 0;
}
#endif

#if SNAP_NATIVE_PACGA
static int native_pacga_prepare(struct context *c, struct vcpu *v);
static void native_pacga_restore(struct context *c, struct vcpu *v);
#endif
#if SNAP_LEAN_TRAPS == 2
static void lean_fgt_prepare(struct context *c, struct vcpu *v);
static void lean_fgt_restore(struct context *c, struct vcpu *v);
#endif
/* Shared model/table construction runs only once above. This portion installs
 * the current CPU's own hardware state. A secondary caller must already have
 * its physical EL2 stack, TPIDR, vectors, interrupt backend and service token. */
static int64_t vcpu_arch_prepare(struct context *c)
{
    const struct params *p=c->params;
    struct vcpu *v=vcpu_of(c);
    if (v->slot) {
        uint64_t physical_hz,mmfr0;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(physical_hz));
        __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
        if (physical_hz!=p->clock_host_hz || !(mmfr0>>60) ||
            clock_rate_init(&v->clock_rate,physical_hz,p->clock_guest_hz)) return -15;
    }
    uint64_t root = vcpu_vttbr(vcpu_of(c));

    uint64_t parange;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(parange));
    parange &= 0xf;
    if (parange > 5) parange = 5;
    uint64_t vtcr = S2_TXSZ | (1UL << 6) | (1UL << 8) | (1UL << 10)
                  | (3UL << 12) | (0UL << 14) | (parange << 16);
    __asm__ volatile("mrs %0, vttbr_el2" : "=r"(vcpu_of(c)->save_vttbr));
    __asm__ volatile("mrs %0, vtcr_el2" : "=r"(vcpu_of(c)->save_vtcr));
    __asm__ volatile("msr vtcr_el2, %0" :: "r"(vtcr));
    __asm__ volatile("msr vttbr_el2, %0" :: "r"(root));
    __asm__ volatile("dsb ish; tlbi vmalls12e1is; dsb ish; isb");

    /* What this CPU actually says about itself, logged once. XNU is configuring
     * SME unconditionally for this board, so whether the silicon under it has
     * SME at all decides whether that is deniable or has to be emulated. */
    if (!v->slot) record(c, EV_OTHER, 0, id_register(4, 0), id_register(4, 1), id_register(0, 0));
    /* ID_AA64MMFR2_EL1.NV at [27:24] and ID_AA64MMFR4_EL1.NV_frac at [27:24]:
     * 2 (or 1 + frac) means FEAT_NV2, which redirects a guest's EL2 register
     * accesses into memory instead of leaving them undefined. XNU writes EL2
     * registers, so whether this silicon has NV2 decides whether it can be run
     * at all without pretending to be something it is not. */
    if (!v->slot) record(c, EV_OTHER, 1, id_register(7, 2), id_register(7, 4), id_register(7, 0));
#if SNAP_IDREG_MMFR3
    /* Every vCPU: S1PIE/S1POE (MMFR3) and HAFDBS/HPDS/PAN (MMFR1), per core. */
    record(c, EV_OTHER, 2, id_register(7, 3), id_register(7, 1), v->slot);
#endif

    /* Nested virtualization.
     *
     * XNU is not an EL1 kernel. It writes EL2 registers -- SMPRIMAP_EL2 at
     * 0xfffffe000c245030, and Apple IMPDEF registers with op1=4 before that --
     * because on Apple silicon HCR_EL2.E2H is RES1 and the kernel runs at EL2
     * under VHE, with SPTM in the guarded shadow of EL2. `genter` from ELn
     * enters GLn, and XNU's calls land in SPTM at GL2, which says the same
     * thing. Run at EL1, every one of those accesses is simply undefined.
     *
     * FEAT_NV2 is exactly the mechanism for this, and this silicon has it
     * (ID_AA64MMFR2_EL1.NV == 2, measured). With NV and NV2 set, EL1 accesses
     * to EL2 registers become memory accesses at VNCR_EL2 instead of faulting,
     * so a kernel that believes it is the hypervisor runs unmodified and its
     * idea of EL2 state is left somewhere we can read. */
    /* MPIDR_EL1 is read 22 times in __TEXT_EXEC -- it is how XNU asks which core
     * it is, and it has to answer with the affinity the device tree gives cpu0,
     * not with Qualcomm's. VMPIDR_EL2 is the architectural way to say so: it
     * supplies the value EL1 sees, leaving the real register alone for EL2. (The
     * matching VPIDR_EL2 is deliberately left at the true MIDR: there is exactly
     * one MIDR_EL1 read in the whole kernel, so nothing is gained by lying about
     * the part number, and the truth is easier to debug.) */
    __asm__ volatile("mrs %0, vmpidr_el2" : "=r"(vcpu_of(c)->save_vmpidr));
    __asm__ volatile("msr vmpidr_el2, %0" :: "r"(vcpu_of(c)->vmpidr));

    /* Non-VHE host: CNTKCTL_EL1 governs the EL1 guest event stream. The Apple
     * alias below programs this register, not the host CNTHCTL_EL2. Save even
     * the unsupported fields so every run restores q1n1's original state. */
    __asm__ volatile("mrs %0, cntkctl_el1" : "=r"(vcpu_of(c)->save_cntkctl));
    __asm__ volatile("mrs %0, cnthctl_el2" : "=r"(vcpu_of(c)->save_cnthctl));
    vcpu_of(c)->clock_hz = p->clock_guest_hz;
    /* Non-VHE EL1TVCT/EL1TVT trap virtual reads/timers. Withhold physical
     * counter/timer access: unsupported alternate domains must stop rather
     * than silently use an unscaled counter. ECV was checked above. */
    vcpu_of(c)->guest_cnthctl = (vcpu_of(c)->save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13);
    __asm__ volatile("msr cnthctl_el2, %0; isb" :: "r"(vcpu_of(c)->guest_cnthctl));
    vcpu_of(c)->clock_saved = 1;
    __asm__ volatile("msr cntkctl_el1, xzr; isb");

    if (vcpu_of(c)->vncr_va) {
        uint64_t hcr;
        /* VNCR_EL2 by encoding: the assembler only knows the name with an
         * explicit -march that the rest of this blob does not want. */
        __asm__ volatile("msr s3_4_c2_c2_0, %0" :: "r"(vcpu_of(c)->vncr_va));
        __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
        hcr |= (1UL << 42) | (1UL << 45);          /* NV, NV2 */
        __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr));
    }
    if (SNAP_NATIVE_WFE) {
        /* TWE off: the guest's WFE sleeps natively until the event stream
         * clock_control programs, a SEV, a cleared monitor or any interrupt,
         * physical IRQs to EL2 (timer, watchdog, IPI poll) included. */
        uint64_t hcr;
        __asm__ volatile("mrs %0, hcr_el2" : "=r"(hcr));
        __asm__ volatile("msr hcr_el2, %0; isb" :: "r"(hcr & ~(1UL << 14)));
    }
#if SNAP_NATIVE_PACGA
    /* The guest GA key in APGAKey and HCR_EL2.API for EL1; every later HCR
     * write is read-modify-write. */
    {
        int pacga = native_pacga_prepare(c, v);
        if (pacga) return pacga;
    }
#endif
#if SNAP_LEAN_TRAPS == 2
    /* FEAT_FGT for TVM/TRVM, or this CPU unchanged (compat/lean-trap.h). */
    lean_fgt_prepare(c, v);
#endif

    /* 3. Debug exceptions to EL2, with the OS Lock opened if firmware left it
     * shut, so the single-step fallback can run at all. */
    __asm__ volatile("mrs %0, mdcr_el2" : "=r"(vcpu_of(c)->save_mdcr));
    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(vcpu_of(c)->save_mdscr));
    __asm__ volatile("msr mdcr_el2, %0; isb" :: "r"(vcpu_of(c)->save_mdcr | (1UL << 8)));
    __asm__ volatile("mrs %0, oslsr_el1" : "=r"(vcpu_of(c)->dbg_oslsr));
    if (vcpu_of(c)->dbg_oslsr & (1UL << 1))
        __asm__ volatile("msr oslar_el1, xzr; isb");

    /* 4. EL1's translation regime, pointed at the shadow rather than at what
     * the guest believes. The guest's own values are kept so TRVM can hand them
     * back unchanged. */
    vcpu_of(c)->guest_ttbr1 = p->ttbr1_root;
    vcpu_of(c)->guest_tcr = p->tcr;
    vcpu_of(c)->guest_mair = p->mair;
    publish(c->work_base, c->next_table);

    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(vcpu_of(c)->save_ttbr0));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(vcpu_of(c)->save_ttbr1));
    __asm__ volatile("mrs %0, mair_el1" : "=r"(vcpu_of(c)->save_mair));
    __asm__ volatile("msr mair_el1, %0" :: "r"(p->mair));
    __asm__ volatile("msr tcr_el1, %0" :: "r"(shadow_tcr(p->tcr)));
    uint64_t kernel_root=sprr_views_root(&c->kernel_views,(unsigned)v->slot);
    if(!kernel_root)return -22;
    __asm__ volatile("msr ttbr1_el1, %0; isb" :: "r"(kernel_root));
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(c->kernel_installed[v->slot]));
    if(c->kernel_installed[v->slot]!=kernel_root)return -22;
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(vcpu_of(c)->low_root));
    /* XNU installs its own vectors 35 instructions in. Until then a fault would
     * go to whatever VBAR_EL1 happened to hold -- zero, on this machine, which
     * turns the first mistake into an unreadable loop at address 0x200. Pointing
     * it at XNU's own vectors early costs nothing (XNU writes the same value)
     * and makes that window reportable, because the page is execute-never. */
    if (p->vbar_va) __asm__ volatile("msr vbar_el1, %0" :: "r"(p->vbar_va));
    /* EL1's fault registers survive between runs of this probe, so a watchdog
     * report would otherwise show the previous run's abort and read as a fault
     * that is still happening. Cleared so anything reported is from this run. */
    __asm__ volatile("msr esr_el1, xzr");
    __asm__ volatile("msr far_el1, xzr");
    __asm__ volatile("dsb ish; tlbi vmalle1is; dsb ish; isb");

    /* 5. Translation and normal-memory caches on, and then checked. The loader
     * already publishes the image; guest table updates are also published.
     * Leaving I/C clear made native allocator type sorting consume seconds
     * without another monitor call. Device attributes still control MMIO.
     * AT S1E1R reports PA == VA with
     * SCTLR_EL1.M clear, so asking before enabling is a check that always
     * passes and means nothing. */
    /* The reached libsystem_platform zeroing loop uses native 64-byte DC ZVA.
     * Qualify that physical geometry on every CPU before allowing it at EL0.
     * Leave translation, write permissions and faults to the hardware: this
     * enables the instruction, it does not emulate a write or skip a fault. */
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0":"=r"(dczid));
    if(dczid!=4)return -26;
    vcpu_of(c)->guest_sctlr = 1UL | (1UL << 2) | (1UL << 11) | (1UL << 12) | (1UL << 14)
                   | (1UL << 20) | (1UL << 22)
                   | (1UL << 28) | (1UL << 29) | EL0_SCTLR_GRANTS;
    /* SPAN=0 lets hardware set PAN when an EL0 exception enters physical EL1.
     * SPAN=1 preserved the user's PAN=0, triggering XNU's pcb.c context-switch
     * assertion during its first instruction fault. Do not alter the saved
     * user PSTATE: ERET must restore it exactly. */
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(vcpu_of(c)->guest_sctlr));
    __asm__ volatile("isb");
    struct pan_entry_state *pan=&c->pan_entry[v->slot];
    __asm__ volatile("mrs %0, id_aa64mmfr1_el1":"=r"(pan->mmfr1));
    __asm__ volatile("mrs %0, sctlr_el1":"=r"(pan->installed_sctlr));
    if(!((pan->mmfr1>>20)&15) || (pan->installed_sctlr&(1UL<<23)))return -23;
    if(!(pan->installed_sctlr&(1UL<<14)))return -26;
#if SNAP_EL0_WFE || SNAP_EL0_CACHE_MAINT
    /* The EL0 grants must read back; a PE that drops one keeps the SIGILL. */
    if((pan->installed_sctlr&EL0_SCTLR_GRANTS)!=EL0_SCTLR_GRANTS)return -26;
#endif

    uint64_t par;
    __asm__ volatile("at s1e1r, %0; isb" :: "r"(p->entry));
    __asm__ volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1) {
        __asm__ volatile("msr sctlr_el1, xzr; isb");
        vcpu_of(c)->fault_esr = par;
        return -6;
    }
    if (!v->slot && p->fb_span) {
        c->fb_before = framebuffer_hash(p);
        c->fb_observed = p->fb_span;
    }
    if (!v->slot && guest_service_boot(&c->services) != SERVICE_OK) return -7;
    if(SNAP_NATIVE_WRITER_BREAKPOINTS) {
        /* The instruction inventory and live architectural translation must
         * agree before exposing unguarded writer pages to this physical CPU. */
        for(unsigned i=0;i<NATIVE_WRITER_SITE_COUNT;i++) {
            const struct native_writer_site *site=&native_writer_sites[i];
            uint64_t expected=p->stub_pa[NATIVE_CALL_PAGES+site->page]+(site->va&4095);
            if(guest_pa(site->va)!=expected ||
               *(const volatile uint32_t *)expected!=site->word)return -35;
        }
#if SNAP_ERET_SNAPSHOT
        if(!eret_window_proof(c))return -38;
#endif
        uint64_t dfr0,mdscr;
        __asm__ volatile("mrs %0, id_aa64dfr0_el1":"=r"(dfr0));
        if(!native_writer_debug_install_armed(&c->writer_debug[v->slot],&writer_debug_ops,dfr0,
               SNAP_ERET_SNAPSHOT ? NATIVE_WRITER_ARMED_ALL&~(1u<<NATIVE_WRITER_RETURN_SITE) :
                                    NATIVE_WRITER_ARMED_ALL))return -36;
        __asm__ volatile("mrs %0, mdscr_el1":"=r"(mdscr));
        mdscr|=NATIVE_WRITER_MDSCR;
        __asm__ volatile("msr mdscr_el1, %0; isb"::"r"(mdscr):"memory");
        __asm__ volatile("mrs %0, mdscr_el1":"=r"(mdscr));
        if((mdscr&NATIVE_WRITER_MDSCR)!=NATIVE_WRITER_MDSCR)return -37;
    }
    vcpu_of(c)->prepared = 1;
    if (SNAP_NATIVE_CALLS) native_exception_snapshot(c);
    return 0;
}

int64_t xnuboot_prepare_cpu(void);
int64_t xnuboot_prepare_cpu(void)
{
    struct context *c=context_of();
    struct vcpu *v=vcpu_of(c);
    if (!v->slot || v->slot>=GUEST_CPU_COUNT || v->prepared ||
        guest_service_owner(&c->services)!=v->slot+1 ||
        (guest_service_lifecycle(&c->services)&SERVICE_ADMISSION_CLOSED) ||
        ((guest_service_lifecycle(&c->services)>>(v->slot*3))&7)!=EXECUTOR_RUNNING)
        return -18;
    return vcpu_arch_prepare(c);
}
