/* SPDX-License-Identifier: MIT */
#pragma once
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* agents/dvfs: the governors' hardware words through q1n1's EL2 identity map (device and DRAM alike, as
 * compat/adreno.c's ADRENO_DIRECT). Each header's allow-list admits only its own addresses. */
static uint32_t dvfs_rd32(void *ctx,uint64_t pa)
{
    (void)ctx;
    uint32_t v=*(const volatile uint32_t *)pa;
    __asm__ volatile("dsb sy" ::: "memory");
    return v;
}
static void dvfs_wr32(void *ctx,uint64_t pa,uint32_t value)
{
    (void)ctx;
    *(volatile uint32_t *)pa=value;
    __asm__ volatile("dsb sy" ::: "memory");
}
/* The thermal guard's latest maximum (C4: no reading clamps to the floor). A poll with a brief VALID clear on
 * some sensor (docs/A16-THERMAL-GUARD-20261018.md, failure mode 3: most polls) still has a maximum over the
 * others, and the guard itself trips a sensor invalid for 1 s; so any poll with one valid reading counts, not
 * only the all-92 polls the guard calls ready (that would clamp the governors on most windows). */
static int64_t dvfs_thermal(const struct context *c,int *ready)
{
    const struct a16_thermal_state *t=c->thermal;
    *ready=t && !t->reason && t->polls && t->current_mc!=INT64_MIN;
    return t ? t->current_mc : INT64_MIN;
}
#endif
#if SNAP_CPU_DVFS
/* The physical CPU of each vCPU slot (compat/cpu-dvfs.h maps its affinity to an SCMI domain). */
static void cpu_dvfs_affinity(const struct context *c,uint64_t aff[CPU_DVFS_SLOTS])
{
    const struct secondary_config *h=c->host_cpus;
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1":"=r"(mpidr));
    for (unsigned n=0;n<CPU_DVFS_SLOTS;n++) aff[n]=~UINT64_C(0);
    if (!h) { aff[0]=mpidr&UINT64_C(0xff00ffffff); return; }
    for (unsigned n=0;n<CPU_DVFS_SLOTS && n<6;n++) if (h->mask&(1U<<n)) aff[n]=h->affinity[n];
    if (!(h->mask&1U)) aff[0]=h->boot_affinity;   /* vCPU 0 on q1n1's CPU unless relocated (bit 0) */
}
#endif
#if SNAP_GPU_DVFS
static void dvfs_clean(void *ctx,uint64_t pa,uint64_t size)
{
    (void)ctx;
    for (uint64_t line=pa&~UINT64_C(63);line<pa+size;line+=64)
        __asm__ volatile("dc civac, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint64_t dvfs_now(void *ctx)
{
    uint64_t t;(void)ctx;
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t) :: "memory");
    return t;
}
static int gpu_dvfs_in_flight(const struct context *c)
{
#if SNAP_ADRENO_IB_ASYNC
    return !!IB_FLIGHT(c)->active;
#else
    (void)c;
    return 0;   /* synchronous IBs: the ring is idle whenever the tick holds the token */
#endif
}
/* G20: the hottest valid sensor of the guard's last poll outside the CPU-core banks (tsens0 and tsens2 are
 * cpu-0-x-x and cpu-1-x-x in Linux glymur.dtsi; tsens4 has their 13-sensor layout, cluster 2). b12v5-v12 ended
 * with the hotspot on a vCPU-cluster core (68-73 C) and every other sensor at or below 65.4 C. INT64_MIN: none. */
static int64_t gpu_dvfs_die_mc(const struct context *c)
{
    const struct a16_thermal_state *t=c->thermal;
    int64_t best=INT64_MIN;
    if (!t || t->reason || !t->polls) return best;
    for (unsigned b=0;b<8;b++) {
        if (b==0 || b==2 || b==4) continue;
        for (unsigned n=0;n<16;n++) {
            if (!(t->valid_mask[b]>>n&1)) continue;
            int32_t code=(int32_t)(t->raw[b*16+n]&0xfff);
            if (code&0x800) code-=4096;
            if ((int64_t)code*100>best) best=(int64_t)code*100;
        }
    }
    return best;
}
/* G18: the HVC path, just before an IB's or a START's doorbell (no flight active, the service lock held). */
static void dvfs_gpu_kick(struct context *c)
{
    if (!c->root_ext) return;
    struct gpu_dvfs_state *g=&c->root_ext->gpu_dvfs;
    if (g->status!=GPU_DVFS_RUNNING) return;
    const struct gpu_dvfs_io io={c,dvfs_rd32,dvfs_wr32,dvfs_clean,dvfs_now,c->params->clock_host_hz};
    (void)gpu_dvfs_kick(g,&io,dvfs_now(c));
}
/* The flight the governor races on (compat/gpu-dvfs.h struct gpu_dvfs_load); zero with synchronous IBs. */
static struct gpu_dvfs_load gpu_dvfs_load_of(const struct context *c)
{
    struct gpu_dvfs_load l={0};
#if SNAP_ADRENO_IB_ASYNC
    const struct adreno_ib_flight *f=IB_FLIGHT(c);
    l.active=f->active;
    l.start=f->start;
    l.flights=f->flights;
    l.ended=f->finished+f->abandoned+f->stopped;
    l.sum_ticks=f->sum_ticks;
#else
    (void)c;
#endif
    return l;
}
#endif
#if SNAP_CPU_DVFS
/* U14: the clock of the core that runs vCPU 0's tick, independent of what LEVEL_GET means: 512 x 64 dependent
 * ADDs (one per cycle; the loop's SUBS/B.NE run beside the chain) between two CNTPCT reads, IRQs masked (the
 * tick's handler). ~10 us at 3.4 GHz, once a second (CPU_DVFS_MEASURE_WINDOWS). No PMU, no MMIO. */
static uint32_t dvfs_cpu_khz(void *ctx)
{
    const struct context *c=ctx;
    uint64_t hz=c->params->clock_host_hz,n=512,x=0,t0,t1;
    __asm__ volatile("isb; mrs %0, cntpct_el0; isb" : "=r"(t0) :: "memory");
    __asm__ volatile("1:\n\t.rept 64\n\tadd %0, %0, #1\n\t.endr\n\tsubs %1, %1, #1\n\tb.ne 1b"
                     : "+r"(x), "+r"(n) :: "cc");
    __asm__ volatile("isb; mrs %0, cntpct_el0" : "=r"(t1) :: "memory");
    uint64_t dt=t1-t0;
    if (!dt || !hz || x!=512*64) return 0;
    return (uint32_t)(UINT64_C(512)*64*hz/dt/1000);
}
#endif
#if SNAP_CPU_DVFS || SNAP_GPU_DVFS
/* vCPU 0's locked tick, after the thermal sample and the GPU tick. Each governor starts at its first tick (the
 * guest runs, secondaries and the relocation are settled, the GPU is adopted) and stays OFF without the thermal
 * guard. */
static void dvfs_tick(struct context *c,uint64_t physical)
{
    if (vcpu_of(c)->slot || !c->root_ext) return;
    int ready;
    int64_t mc=dvfs_thermal(c,&ready);
#if SNAP_CPU_DVFS
    struct cpu_dvfs_state *u=&c->root_ext->cpu_dvfs;
    /* built here: the image is not linked where it runs */
    const struct cpu_dvfs_io ops={c,dvfs_rd32,dvfs_wr32,dvfs_cpu_khz};
    if (!u->magic) {
        uint64_t aff[CPU_DVFS_SLOTS];
        cpu_dvfs_affinity(c,aff);
        cpu_dvfs_start(u,&ops,c->params->clock_host_hz,aff,c->thermal!=0,physical);
    }
    const volatile uint32_t *wfi[CPU_DVFS_SLOTS];
    for (unsigned n=0;n<CPU_DVFS_SLOTS;n++) wfi[n]=n<GUEST_CPU_COUNT?c->perf.fast[n].wfi:0;
    (void)cpu_dvfs_tick(u,&ops,physical,wfi,mc,ready);
#endif
#if SNAP_GPU_DVFS
    struct gpu_dvfs_state *g=&c->root_ext->gpu_dvfs;
    const struct gpu_dvfs_load load=gpu_dvfs_load_of(c);
    const struct gpu_dvfs_io io={c,dvfs_rd32,dvfs_wr32,dvfs_clean,dvfs_now,c->params->clock_host_hz};
    if (!g->magic && c->params->gpu.flags && (c->gpu.status&ADRENO_S_ADOPTED) &&
        !(c->gpu.status&ADRENO_S_QUIESCED))   /* O4: the start reads the table size q1n1 sent (host record) */
        gpu_dvfs_start(g,c->params->clock_host_hz,c->params->gpu.arena_base,c->thermal!=0,physical,&load,&io);
    if (g->magic) {
        const struct gpu_dvfs_thermal th={mc,gpu_dvfs_die_mc(c),ready};
        (void)gpu_dvfs_tick(g,&io,physical,&th,&load);
    }
#endif
}
/* The restores (C5): the CPU's at a thermal trip and at the stop (any CPU may make the one MMIO write); the
 * GPU's at the stop, before gpu_quiesce, with the GPU still adopted and no IB in flight. */
static void dvfs_cpu_restore(struct context *c)
{
#if SNAP_CPU_DVFS
    const struct cpu_dvfs_io ops={c,dvfs_rd32,dvfs_wr32,0};
    if (c->root_ext) (void)cpu_dvfs_stop(&c->root_ext->cpu_dvfs,&ops);
#else
    (void)c;
#endif
}
static void dvfs_stop(struct context *c,uint64_t *out)
{
    if (!c->root_ext) return;
    dvfs_cpu_restore(c);
#if SNAP_GPU_DVFS
    struct gpu_dvfs_state *g=&c->root_ext->gpu_dvfs;
    if (g->magic && (c->gpu.status&ADRENO_S_ADOPTED) && !(c->gpu.status&ADRENO_S_QUIESCED) &&
        !gpu_dvfs_in_flight(c)) {
        const struct gpu_dvfs_io io={c,dvfs_rd32,dvfs_wr32,dvfs_clean,dvfs_now,c->params->clock_host_hz};
        (void)gpu_dvfs_stop(g,&io);
    }
#endif
    out[OUT_DVFS]=DVFS_REPORT_MAGIC;
    out[OUT_DVFS+1]=(uint64_t)SNAP_CPU_DVFS|(uint64_t)SNAP_GPU_DVFS<<1|
                    (uint64_t)DVFS_CPU_WORDS<<16|(uint64_t)DVFS_GPU_WORDS<<32;
#if SNAP_CPU_DVFS
    for (unsigned n=0;n<DVFS_CPU_WORDS;n++)
        out[OUT_DVFS+2+n]=((const uint64_t *)&c->root_ext->cpu_dvfs)[n];
#endif
#if SNAP_GPU_DVFS
    for (unsigned n=0;n<DVFS_GPU_WORDS;n++)
        out[OUT_DVFS+2+DVFS_CPU_WORDS+n]=((const uint64_t *)&c->root_ext->gpu_dvfs)[n];
#endif
}
#endif
