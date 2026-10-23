/* SPDX-License-Identifier: MIT */
/* Resolution, ring packaging, submission and the kernel-command entry points.
 * Part of compat/adreno-ib-command.c's translation unit, included in order; not compiled on its own. */
struct resolver {
    const struct adreno_resource_list *list;
    int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *);
    void *context;
};
/* Admit a RESOURCE relocation: the ID is in this command buffer's prepared list (repeated IDs share one resource
 * and preparation), WRITE needs Write usage, READ needs Read or Sample usage; then the kext's range check. */
static int resolve_entry(void *c, uint32_t id, unsigned access, uint64_t offset, uint64_t length, uint64_t *address)
{
    const struct resolver *rs = c;
    const struct adreno_resource_entry *selected = 0;
    unsigned usage = 0;
    for (uint64_t i = 0; i < rs->list->count; i++) {
        const struct adreno_resource_entry *e = &rs->list->entries[i];
        if (e->id != id) continue;
        if (!e->resource || !e->preparation || e->reserved ||
            (selected && (e->resource != selected->resource || e->preparation != selected->preparation)))
            return -1;
        selected = e;
        usage |= e->usage;
    }
    if (!selected || ((access & ADRENO_IB_ACCESS_WRITE) && !(usage & ADRENO_USAGE_WRITE)) ||
        ((access & ADRENO_IB_ACCESS_READ) && !(usage & (ADRENO_USAGE_READ | ADRENO_USAGE_SAMPLE))))
        return -1;
    *address = 0;
    return rs->resolve(rs->context, selected->resource, selected->preparation, offset, length, address) ? -1 : 0;
}

#if !ADRENO_PIPELINE
struct ring_call {
    struct adreno_ib_work *w;
    int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *);
    void *context;
    int outcome;
};
static int ring_package(void *c)
{
    struct ring_call *call = c;
    struct adreno_ib_work *w = call->w;
    struct adreno_ib_reply reply = {ADRENO_IB_E_UNCERTAIN, 0, 0, 0};
    int e = call->ring(call->context, w->package_gpu, w->command.ib_dwords, w->package_bytes, &reply);
    w->reply = reply;
    call->outcome = e ? ADRENO_SUBMIT_E_UNCERTAIN : adreno_ib_classify(&reply);
    /* GPU_ERROR: retired and idle, so the list's FROM_DEVICE still runs and the list is not frozen. */
#if ADRENO_GPU_RECOVER
    if (call->outcome == ADRENO_IB_E_RESET || call->outcome == ADRENO_IB_E_RESET_FAULT) return 0;   /* as GPU_ERROR */
#endif
    return call->outcome == ADRENO_IB_E_GPU_ERROR ? 0 : call->outcome;
}
#endif

#if ADRENO_PIPELINE
/* --pipeline: adreno_ib_submit below, split at the doorbell (adreno-ib-command.h). Same checks, order and results. */
int adreno_ib_submit_begin(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                           const void *command, uint64_t available,
                           int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *), void *context,
                           struct adreno_ib_pending *p)
{
    if (!w || !list || !ops || !command || !resolve || !p) return ADRENO_LIST_E_ARGUMENT;
    p->armed = 0; p->marker = 0;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)))
        return ADRENO_SUBMIT_E_INACTIVE;
    if (list->ready & ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready != (ADRENO_LIST_READY | ADRENO_LIST_PREPARED) || list->prepared_count != list->count ||
        (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    const struct resolver rs = {list, resolve, context};
    int e = adreno_ib_stage(w, command, available);
    if (!e) e = adreno_ib_relocate(w, resolve_entry, (void *)&rs);
    if (!e) e = adreno_ib_validate(w);
    if (e) { w->refused++; return e; }
    e = adreno_resource_list_begin(list, ops, &p->list);
    if (e) return fail(w, e, 0);   /* list/cache refusal before the doorbell */
    p->armed = 1;
    return 0;
}
int adreno_ib_submit_finish(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                            struct adreno_ib_pending *p, const struct adreno_ib_reply *final, int transport_error)
{
    if (!w || !list || !ops || !p || !p->armed || !final) return ADRENO_LIST_E_ARGUMENT;
    p->armed = 0; p->marker = 0;
    w->reply = *final;
    const int outcome = transport_error ? ADRENO_SUBMIT_E_UNCERTAIN : adreno_ib_classify(final);
    /* GPU_ERROR: retired and idle, so the list's FROM_DEVICE still runs and the list is not frozen. */
#if ADRENO_GPU_RECOVER
    const int reset = outcome == ADRENO_IB_E_RESET || outcome == ADRENO_IB_E_RESET_FAULT;   /* the same (R14) */
    const int e = adreno_resource_list_end(list, ops, &p->list, outcome == ADRENO_IB_E_GPU_ERROR || reset ? 0 : outcome);
#else
    const int e = adreno_resource_list_end(list, ops, &p->list, outcome == ADRENO_IB_E_GPU_ERROR ? 0 : outcome);
#endif
    if (e == ADRENO_SUBMIT_E_UNCERTAIN || e == ADRENO_LIST_E_VISIBILITY) {
        w->state |= ADRENO_IB_STATE_UNCERTAIN;   /* the arena keeps this package until reset */
        w->uncertain++;
        return fail(w, e, 0);
    }
    if (e == ADRENO_SUBMIT_E_INACTIVE && outcome == ADRENO_SUBMIT_E_INACTIVE) {
        w->refused++;
        if (w->reply.status == ADRENO_IB_E_STICKY) w->state |= ADRENO_IB_STATE_DISABLED;  /* only a reset clears it */
        return fail(w, (int)w->reply.status, 0);
    }
    if (e) return fail(w, e, 0);
    if (outcome == ADRENO_IB_E_GPU_ERROR) {
        w->gpu_errors++;
        w->state |= ADRENO_IB_STATE_DISABLED;
        return fail(w, ADRENO_IB_E_GPU_ERROR, 0);
    }
#if ADRENO_GPU_RECOVER
    if (reset) { w->resets++; return fail(w, outcome, 0); }   /* this IB failed; the GPU and the work stay usable */
#endif
    w->submitted++;
    return 0;
}
int adreno_ib_submit_ring(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                          struct adreno_ib_pending *p, int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *),
                          void *context)
{
    if (!w || !list || !ops || !p || !p->armed || !ring) return ADRENO_LIST_E_ARGUMENT;
    struct adreno_ib_reply reply = {ADRENO_IB_E_UNCERTAIN, 0, 0, 0};
    const int transport = ring(context, w->package_gpu, w->command.ib_dwords, w->package_bytes, &reply);
    if (!transport && reply.status == ADRENO_IB_PENDING) {
        if (reply.marker && !(reply.marker >> 32)) {   /* in flight: the caller polls for the final reply */
            w->reply = reply;
            p->marker = reply.marker;
            return ADRENO_IB_IN_FLIGHT;
        }
        reply.status = ADRENO_IB_E_UNCERTAIN;          /* rung, without a marker to poll (async-ib A9) */
        reply.marker = 0;
    }
    return adreno_ib_submit_finish(w, list, ops, p, &reply, transport);
}
int adreno_ib_submit(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                     const void *command, uint64_t available,
                     int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *),
                     int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context)
{
    if (!w || !list || !ops || !command || !resolve || !ring) return ADRENO_LIST_E_ARGUMENT;
    struct adreno_ib_pending p;
    int e = adreno_ib_submit_begin(w, list, ops, command, available, resolve, context, &p);
    if (e) return e;
    e = adreno_ib_submit_ring(w, list, ops, &p, ring, context);
    if (e == ADRENO_IB_IN_FLIGHT) {                    /* a synchronous caller's ring answered PENDING: not final */
        const struct adreno_ib_reply uncertain = {ADRENO_IB_E_UNCERTAIN, 0, w->reply.ticks, w->reply.wptr};
        e = adreno_ib_submit_finish(w, list, ops, &p, &uncertain, 0);
    }
    return e;
}
#else
int adreno_ib_submit(struct adreno_ib_work *w, struct adreno_resource_list *list, const struct adreno_resource_list_ops *ops,
                     const void *command, uint64_t available,
                     int (*resolve)(void *, void *, void *, uint64_t, uint64_t, uint64_t *),
                     int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context)
{
    if (!w || !list || !ops || !command || !resolve || !ring) return ADRENO_LIST_E_ARGUMENT;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & (ADRENO_IB_STATE_DISABLED | ADRENO_IB_STATE_UNCERTAIN)))
        return ADRENO_SUBMIT_E_INACTIVE;
    if (list->ready & ADRENO_LIST_FROZEN) return ADRENO_LIST_E_BUSY;
    if (list->ready != (ADRENO_LIST_READY | ADRENO_LIST_PREPARED) || list->prepared_count != list->count ||
        (list->count && !list->entries))
        return ADRENO_LIST_E_STATE;
    const struct resolver rs = {list, resolve, context};
    int e = adreno_ib_stage(w, command, available);
    if (!e) e = adreno_ib_relocate(w, resolve_entry, (void *)&rs);
    if (!e) e = adreno_ib_validate(w);
    if (e) { w->refused++; return e; }
    struct ring_call call = {w, ring, context, 0};
    e = adreno_resource_list_submit(list, ops, ring_package, &call);
    if (e == ADRENO_SUBMIT_E_UNCERTAIN || e == ADRENO_LIST_E_VISIBILITY) {
        w->state |= ADRENO_IB_STATE_UNCERTAIN;   /* the arena keeps this package until reset */
        w->uncertain++;
        return fail(w, e, 0);
    }
    if (e == ADRENO_SUBMIT_E_INACTIVE && call.outcome == ADRENO_SUBMIT_E_INACTIVE) {
        w->refused++;
        if (w->reply.status == ADRENO_IB_E_STICKY) w->state |= ADRENO_IB_STATE_DISABLED;  /* only a reset clears it */
        return fail(w, (int)w->reply.status, 0);
    }
    if (e) return fail(w, e, 0);   /* list/cache refusal before the doorbell */
    if (call.outcome == ADRENO_IB_E_GPU_ERROR) {
        w->gpu_errors++;
        w->state |= ADRENO_IB_STATE_DISABLED;
        return fail(w, ADRENO_IB_E_GPU_ERROR, 0);
    }
#if ADRENO_GPU_RECOVER
    if (call.outcome == ADRENO_IB_E_RESET || call.outcome == ADRENO_IB_E_RESET_FAULT) {   /* R14 */
        w->resets++;
        return fail(w, call.outcome, 0);
    }
#endif
    w->submitted++;
    return 0;
}
#endif

int adreno_ib_probe(struct adreno_ib_work *w, uint64_t *package_gpu, uint64_t *ib_dwords, uint64_t *package_bytes)
{
    if (!w || !package_gpu || !ib_dwords || !package_bytes) return ADRENO_LIST_E_ARGUMENT;
    if (!(w->state & ADRENO_IB_STATE_READY) || (w->state & ADRENO_IB_STATE_UNCERTAIN)) return ADRENO_SUBMIT_E_INACTIVE;
    struct adreno_ib_command c = {{ADRENO_KCMD_IB, (uint32_t)adreno_ib_command_bytes(1, 0, 0)},
                                  ADRENO_IB_COMMAND_VERSION, 0, 1, 0, 0, 0, {0, 0}};
    stage_fields(w, &c);
    for (uint64_t i = 0; i < w->package_bytes; i++) w->package[i] = 0;
    wr32(w->package, a8xx_pkt7_hdr(A8XX_E_CP_NOP, 0));
    w->targets[0] = 0;
    int e = adreno_ib_validate(w);
    if (e) return e;
    *package_gpu = w->package_gpu;
    *ib_dwords = w->command.ib_dwords;
    *package_bytes = w->package_bytes;
    return 0;
}

int adreno_fence_classify(int64_t status, uint64_t reply, uint32_t value, uint32_t observed)
{
    if (!status) return reply == value && observed == value ? 0 : ADRENO_SUBMIT_E_UNCERTAIN;
    if (reply || observed != (uint32_t)~value) return ADRENO_SUBMIT_E_UNCERTAIN;
    switch (status) {
    case ADRENO_E_PARAMS: case ADRENO_E_TARGET: case ADRENO_E_CX: case ADRENO_E_GX: case ADRENO_E_SQE:
        return ADRENO_SUBMIT_E_INACTIVE;
    }
    return ADRENO_SUBMIT_E_UNCERTAIN;
}

int adreno_submit_gated(uint8_t *latch, int (*work)(void *), void *context)
{
    if (!latch || !work) return ADRENO_LIST_E_ARGUMENT;
    if (*latch) return ADRENO_SUBMIT_E_INACTIVE;
    int result = work(context);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) *latch = 1;
    return result;
}

int adreno_kernel_command(const void *command, uint64_t available, const struct adreno_kernel_ops *ops)
{
    if (!ops || !ops->fence) return ADRENO_SUBMIT_E_FORMAT;
    int result = adreno_submit_command(command, available, ops->fence, ops->context);
    if (result != ADRENO_SUBMIT_E_COMMAND) return result;
    struct adreno_fill32_request fill;
    result = adreno_fill32_decode(command, available, &fill);
    if (!result) return ops->fill ? ops->fill(ops->context, &fill) : ADRENO_SUBMIT_E_INACTIVE;
    if (result != ADRENO_SUBMIT_E_COMMAND) return result;
    uint8_t type[4];
    copy_in(type, command, sizeof type);
    if (rd32(type) != ADRENO_KCMD_IB) return ADRENO_SUBMIT_E_COMMAND;
    return ops->ib ? ops->ib(ops->context, command, available) : ADRENO_SUBMIT_E_INACTIVE;
}
