/* SPDX-License-Identifier: MIT */
/* Virtual ANS2 glue: frame references, the NVMe window backend, routing and the
 * SNAP_ANS_ASYNC poll schedule.
 * Part of probes/xnuboot.c's translation unit, included in order; not compiled on its own. */

/* Virtual ANS2 glue. The state lives at the start of the loader's reservation
 * (config[0]), outside guest memory and stage 2; DMA reaches only guest RAM
 * frames admitted with SPTM reference counts under the DART data-leaf rule
 * (XNU_DEFAULT only, clear metadata; ans_frame_ref). */
_Static_assert(ANS_DMA_FRAME_TYPE==SPTM_MAC_DEFAULT,"ANS DMA admits the DART data-leaf type");
static struct ans_state *ans_state_of(const struct context *c)
{
    const struct params *p=c->params;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1)
            return (struct ans_state *)p->models[i].config[0];
    return 0;
}
static int ans_frame_ref(void *ctx,uint64_t pa,int writable,int release)
{
    struct sptm_memory m=sptm_context_memory(ctx);
    uint64_t f=pa&~0x3fffUL;
    if (!sptm_managed_frame(&m,f)) return 1;
    if (!release) {
        /* sptm_refs_dart counts references but leaves type checks to its
         * caller (delta() also accepts ROZONE, KERNEL_RESTRICTED and
         * COMMPAGE frames): admit only what ans_dma_frame does, the DART
         * data-leaf rule (XNU_DEFAULT, clear metadata). A release never
         * re-checks, so a held reference can always be dropped. */
        volatile uint8_t *e=m.map(m.ctx,m.frame_map_pa+((f-m.frame_low)>>14)*16,16);
        if (!e || !ans_dma_frame(e)) return 1;
    }
    sptm_refs_begin(m.refs);
    enum sptm_result r=release ? sptm_refs_dart_remove(&m,f,!writable) :
                                 sptm_refs_dart(&m,f,!writable);
    if (!r) r=sptm_refs_validate(&m);
    if (r) return 1;
    sptm_refs_commit(&m);
    return 0;
}
/* Window mode (full-install M6, compat/ans.h ANS_WINDOW_*): the synthesized GPT's first and last
 * MiB come from the reservation; every other virtual block is the M4 partition on the SSD, read
 * through the controller q1n1 left running (compat/nvme-host.h) at real LBA first + 8 * block. */
static const struct device_model *ans_nvme_model(const struct context *c)
{
    const struct params *p=c->params;
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_ANS_NVME_V1) return &p->models[i];
    return 0;
}
static int ans_window(const struct context *c)
{
    const struct device_model *m=ans_nvme_model(c);
    return m && m->config[3]==ANS_WINDOW_MODE;
}
static const struct nvmeh_ops nvmeh_direct;   /* NVMEH_DIRECT: the monitor reaches the SSD itself */
#define ANS_NVMEH_PARAMS(res) ((struct nvmeh_params *)((res)+ANS_WINDOW_NVMEH))
#define ANS_NVMEH_STATE(res) ((struct nvmeh_state *)((res)+ANS_WINDOW_NVMEH+0x80))
/* agents/nvme-async: the window flight (compat/ans-window.h) and the asynchronous callbacks, initializers that
 * expand to nothing without SNAP_ANS_ASYNC (the define-off text stays the base's). */
#if SNAP_ANS_ASYNC
#define ANS_WINDOW_FLIGHT(res) ,(struct ans_window_flight *)((struct ans_state *)(res))->async.backend
#define ANS_ASYNC_OPS(window) .disk_start=(window) ? ans_window_start_cb : 0,\
    .disk_poll=(window) ? ans_window_poll_cb : 0,.disk_quiesce=(window) ? ans_window_quiesce_cb : 0,
#else
#define ANS_WINDOW_FLIGHT(res)
#define ANS_ASYNC_OPS(window)
#endif
_Static_assert(sizeof(struct nvmeh_params)<=0x80 && sizeof(struct nvmeh_state)<=0xc0,"window params/state slots");
static struct ans_window_backend ans_window_backend(const struct context *c)
{
    const struct device_model *m=ans_nvme_model(c);
    uint64_t res=m->config[0];
    return (struct ans_window_backend){m->config[1]/ANS_BLOCK,
        (const volatile uint8_t *)(res+ANS_WINDOW_HEAD),
        (const volatile uint8_t *)(res+ANS_WINDOW_TAIL),
        (volatile uint8_t *)(res+ANS_WINDOW_STAGE),
        (volatile uint8_t *)(res+ANS_WINDOW_DMA+NVMEH_DATA),
        &nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res)ANS_WINDOW_FLIGHT(res)};
}
static int ans_window_read(void *ctx,uint64_t lba,uint64_t n,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_read_blocks(&b,lba,n,data);
}
static int ans_window_write_buffer(void *ctx,uint64_t lba,uint64_t n,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_prepare_write(&b,lba,n,data);
}
static int ans_window_write(void *ctx,uint64_t lba,uint64_t n)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_write_blocks(&b,lba,n);
}
static int ans_window_flush(void *ctx)
{
    uint64_t res=ans_nvme_model(ctx)->config[0];
    return nvmeh_flush(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res));
}
/* Before the guest runs: adopt the SSD q1n1 left running, or refuse the launch. */
static int64_t ans_window_prepare(struct context *c)
{
    if (!ans_window(c)) return 0;
    const struct device_model *m=ans_nvme_model(c);
    uint64_t res=m->config[0];
#if SNAP_ANS_ASYNC
    /* The schedule's lock-free readers (timer_arm, the fast tick) find the state here; window mode only. */
    c->root_ext->ans=(struct ans_state *)res;
#endif
    return nvmeh_adopt(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res),
                       c->params->mem_low,c->params->mem_high);
}
static void ans_window_stop(struct context *c)
{
    if (!ans_window(c)) return;
    uint64_t res=ans_nvme_model(c)->config[0];
    nvmeh_stop(&nvmeh_direct,ANS_NVMEH_PARAMS(res),ANS_NVMEH_STATE(res));
}
#if SNAP_ANS_ASYNC
/* compat/ans-window.h's flight, for compat/ans.c's asynchronous backend (ans_ops.disk_start/disk_poll). */
static int ans_window_start_cb(void *ctx,unsigned op,uint64_t lba,uint64_t n)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_start(&b,op,lba,n);
}
static int ans_window_poll_cb(void *ctx,volatile uint8_t **data)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    return ans_window_poll(&b,data);
}
static void ans_window_quiesce_cb(void *ctx)
{
    struct ans_window_backend b=ans_window_backend(ctx);
    (void)ans_window_quiesce(&b);
}
#endif
static struct ans_ops ans_ops_of(struct context *c)
{
    int window=ans_window(c);
    return (struct ans_ops){ANS_ASYNC_OPS(window).ctx=c,.map=sptm_map,.frame_ref=ans_frame_ref,.publish=sptm_publish,
        .disk_read=window ? ans_window_read : 0,
        .disk_write_buffer=window ? ans_window_write_buffer : 0,
        .disk_write=window ? ans_window_write : 0,.disk_flush=window ? ans_window_flush : 0};
}
/* After a successful ANS mutation: the three ASC/NVMe interrupt levels. */
static enum device_result ans_route(struct context *c)
{
    const struct params *p=c->params;
    const struct ans_state *s=ans_state_of(c);
    int level[3];
    ans_levels(s,level);
    for (unsigned i=0;i<p->model_count;i++)
        if (p->models[i].kind==DEVICE_AIC3_FLAT_V1) {
            static const uint16_t irq[3]={1007,1010,1039};
            for (unsigned n=0;n<3;n++)
                if (device_irq_set_level(&p->models[i],&c->model_state[i],irq[n],level[n])!=DEVICE_OK)
                    return DEVICE_BAD_CONFIG;
            return DEVICE_OK;
        }
    return DEVICE_BAD_CONFIG;
}
#if SNAP_ANS_ASYNC
/* ---- SNAP_ANS_ASYNC: the poll schedule (agents/nvme-async N3, N11, N18, N19) ----
 * One deadline for the physical command in flight (CNTPCT ticks), owned by the
 * vCPU whose ANS operation started it: timer_arm arms that vCPU's EL2 timer for
 * it and its fast tick peeks at the completion. Every other ANS operation polls
 * anyway; any vCPU's locked tick polls a command ANS_ASYNC_BACKSTOP_US past its
 * deadline. Written under ANS exclusion, and the deadline also by the owner's
 * fast tick (a push); atomic words, so a race moves one poll, never loses one. */
#define ANS_ASYNC_MIN_US 15u
#define ANS_ASYNC_MAX_US 1000u
#define ANS_ASYNC_FIRST_US 30u          /* the first deadline before any latency was measured */
#define ANS_ASYNC_BACKSTOP_US 1000u
/* tests/gain-model.py (agents/nvme-async): with the first deadline at a quarter of the latency average and then
 * an eighth of the command's age, a 177 us command (gamma, cv^2 1..3) completes 20-31 us later than the busy-poll
 * would have seen it, after 7-8 peeks; the owner's peeks cost no token (its fast tick). */
static uint64_t ans_async_us(const struct context *c,uint64_t us) {return c->params->clock_host_hz*us/1000000;}
/* The next deadline of a command still running: an eighth of its age, within [MIN, MAX]. */
static uint64_t ans_async_next(const struct context *c,uint64_t now,uint64_t start)
{
    uint64_t gap=(now-start)/8,lo=ans_async_us(c,ANS_ASYNC_MIN_US),hi=ans_async_us(c,ANS_ASYNC_MAX_US);
    return now+(gap<lo ? lo : gap>hi ? hi : gap);
}
/* Under ANS exclusion, after any ANS operation (every one polled first). */
static void ans_async_schedule(struct context *c)
{
    struct ans_state *s=c->root_ext->ans;
    if(!s)return;
    struct ans_async *a=&s->async;
    uint64_t seq,now=service_profile_clock();
    /* The latency average: physical commands reaped since the last call, by nvme-host's own tick sums
     * (submit to reap, so it includes the poll granularity it is used to set). */
    const struct nvmeh_state *ns=ANS_NVMEH_STATE((uint64_t)s);
    uint64_t done=ns->reads+ns->writes+ns->flushes+ns->errors,ticks=ns->total_ticks;
    if(done>a->sched[7] && ticks>=a->sched[6]) {
        uint64_t avg=(ticks-a->sched[6])/(done-a->sched[7]);
        a->ewma=a->ewma ? a->ewma-a->ewma/8+avg/8 : avg;
        a->sched[4]+=ticks-a->sched[6];a->sched[5]+=done-a->sched[7];
    }
    a->sched[6]=ticks;a->sched[7]=done;
    uint64_t me=(uint64_t)vcpu_of(c)->slot+1;
    if(!ans_async_busy(s,&seq)) {__atomic_store_n(&a->due,0,__ATOMIC_RELAXED);return;}
    if(!a->phys) {
        /* Work queued and nothing in flight (a progress budget ran out): poll at once. */
        __atomic_store_n(&a->owner,me,__ATOMIC_RELAXED);__atomic_store_n(&a->due,now,__ATOMIC_RELAXED);
        return;
    }
    if(seq!=a->sched_seq) {
        uint64_t lo=ans_async_us(c,ANS_ASYNC_MIN_US),hi=ans_async_us(c,ANS_ASYNC_MAX_US);
        uint64_t first=a->ewma ? a->ewma/4 : ans_async_us(c,ANS_ASYNC_FIRST_US);
        a->sched_seq=seq;a->start=now;
        __atomic_store_n(&a->owner,me,__ATOMIC_RELAXED);
        __atomic_store_n(&a->due,now+(first<lo ? lo : first>hi ? hi : first),__ATOMIC_RELAXED);
        return;
    }
    __atomic_store_n(&a->due,ans_async_next(c,now,a->start),__ATOMIC_RELAXED);
}
/* timer_arm's, lock-free: this vCPU's deadline when it owns the command in flight. */
static int ans_async_due_of(const struct context *c,uint64_t slot,uint64_t *due)
{
    const struct ans_state *s=c->root_ext ? c->root_ext->ans : 0;
    if(!s || __atomic_load_n(&s->async.owner,__ATOMIC_RELAXED)!=slot+1)return 0;
    *due=__atomic_load_n(&s->async.due,__ATOMIC_RELAXED);
    return *due!=0;
}
/* After an ANS operation that may have posted (N3): the lines, then this vCPU's view of them. */
static enum device_result ans_async_lines(struct context *c)
{
    enum device_result r=ans_route(c);
    if(r!=DEVICE_OK)return r;
    vcpu_of(c)->model_irq_pending=0;
    for (unsigned i=0;i<c->params->model_count;i++)
        vcpu_of(c)->model_irq_pending|=device_irq_pending(&c->params->models[i],&c->model_state[i]);
    return DEVICE_OK;
}
#endif

