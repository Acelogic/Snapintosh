/* SPDX-License-Identifier: MIT */
/* Queue frames and DMA references through SPTM, the asynchronous I/O path and the
 * converted SPTM entry.
 * Part of compat/ans.c's translation unit, included in order; not compiled on its own. */
/* ---- SPTM tables 5 and 6 ----------------------------------------------- */
/* ADMIN_QUEUE_REGS, IOSQ_REG, IOCQ_REG (sptm.t8140.release ...c86c0, ...c819c,
 * ...c7e88): the first call per base stores it (+0xd90/+0xd98, +0xda8, +0xdb0)
 * and takes one DMA reference through ...ef64c(pa, 2); a repeat with the same
 * base takes none, a different base is a violation. No table-6 endpoint ever
 * releases it (the only ...efdd4 calls in table 6 are UNMAP_PAGES'), so the
 * reference is held for the boot, here as there. */
static int queue_base(struct ans_state *s, const struct ans_ops *o, uint64_t *slot, uint64_t pa)
{
    if (*slot) return *slot == pa ? ANS_OK : refuse(s, ANS_E_SPTM_ARG, pa, *slot);
    if (!pa || (pa & 0xfff) || !o->map(o->ctx, pa, 4096)) return refuse(s, ANS_E_ADDRESS, pa, 0);
    if (o->frame_ref(o->ctx, pa, 1, 0)) return refuse(s, ANS_E_FRAME, pa, 0);
    *slot = pa;
    return ANS_OK;
}

static int unref(const struct ans_ops *o, const struct ans_cid *c, unsigned n)
{
    for (unsigned i = 0; i < n; i++) o->frame_ref(o->ctx, c->prp[i], c->dir & 0x100, 1);
    return 0;
}

static int map_pages(struct ans_state *s, const struct ans_ops *o, const uint64_t *x)
{
    uint64_t qid = x[0], cid = x[1], count = x[4];
    if (qid > 1 || cid >= ANS_CIDS || count > ANS_PRPS) return refuse(s, ANS_E_SPTM_ARG, cid, count);
    struct ans_cid *c = &s->cid[cid];
    if (c->state) return refuse(s, ANS_E_CID, cid, c->state);
    volatile uint8_t *t = o->map(o->ctx, x[2], 0x80);
    volatile uint8_t *l = count ? o->map(o->ctx, x[3], count * 8) : 0;
    if (!t || (count && !l)) return refuse(s, ANS_E_ADDRESS, x[2], x[3]);
    uint16_t dir = (uint16_t)((t[0] | t[1] << 8) & 0x1f00), nlb = (uint16_t)(t[4] | t[5] << 8);
    if ((dir & 0x300) == 0x300) return refuse(s, ANS_E_DIRECTION, cid, dir);  /* nvme-tl-wa */
    c->dir = dir; c->nlb = nlb; c->qid = (uint8_t)qid; c->count = 0;
    if (!count) {
        if (nlb) return refuse(s, ANS_E_SPTM_ARG, cid, nlb);
    } else {
        uint64_t first = rd64(l);
        if ((first & 0xfff) && count == 1) return refuse(s, ANS_E_SPTM_ARG, first, count);
        if (count - ((first & 0xfff) ? 2 : 1) != nlb) return refuse(s, ANS_E_SPTM_ARG, count, nlb);
        for (unsigned i = 0; i < count; i++) {
            uint64_t pa = rd64(l + 8 * i);
            if ((i && (pa & 0xfff)) || !o->map(o->ctx, pa, 4096 - (pa & 0xfff)) ||
                o->frame_ref(o->ctx, pa, dir & 0x100, 0)) {
                unref(o, c, c->count); c->count = 0;
                return refuse(s, ANS_E_FRAME, pa, i);
            }
            c->prp[i] = pa; c->count = (uint16_t)(i + 1);
        }
    }
    c->state = 3;
    s->counter[ANS_C_MAPPED]++;
    return ANS_OK;
}

static int sptm6(struct ans_state *s, const struct ans_ops *o, unsigned ep,
                 const uint64_t *x, uint64_t *ret)
{
    if (ep > 9 || !(s->allowed >> ep & 1)) return refuse(s, ANS_E_SPTM_ORDER, ep, s->allowed);
    switch (ep) {
    case 0: s->allowed |= 1u << 4; return ANS_OK;               /* coastguard: admin next */
    case 1: return map_pages(s, o, x);
    case 2: {
        if (x[0] > 1 || x[1] >= ANS_CIDS || (x[2] & 1)) return refuse(s, ANS_E_SPTM_ARG, x[1], x[2]);
        struct ans_cid *c = &s->cid[x[1]];
        if (c->state != 3 || c->qid != x[0]) return refuse(s, ANS_E_CID, x[1], c->state);
        unref(o, c, c->count);
        if (s->aer_cid == x[1] + 1) s->aer_cid = 0;
        volatile uint8_t *p = (volatile uint8_t *)c;
        for (unsigned i = 0; i < sizeof(*c); i++) p[i] = 0;
        s->counter[ANS_C_UNMAPPED]++;
        *ret = 1;                                               /* 1 = idle (nvme_ioctl 0x8025) */
        return ANS_OK;
    }
    case 3:
        if (x[0] != ANS_CIDS || x[1] != 2) return refuse(s, ANS_E_SPTM_ARG, x[0], x[1]);
        return ANS_OK;
    case 4: {
        if (x[1] > 255 || x[3] > 255) return refuse(s, ANS_E_SPTM_ARG, x[1], x[3]);
        uint32_t aqa = (uint32_t)(x[1] | x[3] << 16);
        if (s->aqa && s->aqa != aqa) return refuse(s, ANS_E_SPTM_ARG, aqa, s->aqa);
        int r = queue_base(s, o, &s->asq, x[0]);
        if (!r) r = queue_base(s, o, &s->acq, x[2]);
        if (r) return r;
        s->aqa = aqa; s->cq[0].size = (uint32_t)x[3] + 1;
        s->allowed |= 1u << 1 | 1u << 2 | 1u << 5;
        return ANS_OK;
    }
    case 5: {
        if (x[0] > ANS_CIDS || x[1] > ANS_CIDS) return refuse(s, ANS_E_SPTM_ARG, x[0], x[1]);
        uint32_t ioqa = (uint32_t)(x[0] | x[1] << 16);
        if (s->ioqa && s->ioqa != ioqa) return refuse(s, ANS_E_SPTM_ARG, ioqa, s->ioqa);
        s->ioqa = ioqa; s->cq[1].size = (uint32_t)x[1] + 1;
        s->allowed |= 1u << 7;
        return ANS_OK;
    }
    case 6: return queue_base(s, o, &s->iosq, x[0]);
    case 7: {
        int r = queue_base(s, o, &s->iocq, x[0]);
        if (!r) s->allowed |= 1u << 6;
        return r;
    }
    }
    return refuse(s, ANS_E_SPTM_ORDER, ep, 0);                 /* SHA / SET_SQ_ENTRY */
}

/* SART (table 5; sptm.t8140.release SET_STATE ...cd4cc, MAP_REGION ...ccdb8,
 * UNMAP_REGION ...cc1f4): the region check ...cc9e8 requires a 16 KiB-aligned
 * base and a 16 KiB-multiple size; MAP_REGION takes one ...ef64c reference per
 * 16 KiB frame (2 for perm 1, else 1) and UNMAP_REGION releases the same;
 * SET_STATE takes and releases nothing. */
static int sptm5(struct ans_state *s, const struct ans_ops *o, unsigned ep, const uint64_t *x)
{
    if (ep == 0) { s->sart_active = (uint32_t)(x[0] & 1); return ANS_OK; }
    uint64_t pa = x[0], size = x[1];
    if (ep > 2 || !size || ((pa | size) & 0x3fff) || pa + size < pa || size > (32ULL << 20))
        return refuse(s, ANS_E_SART, pa, size);
    if (ep == 2) {
        for (unsigned i = 0; i < ANS_SART_REGIONS; i++) {
            struct ans_sart *r = &s->sart[i];
            if (r->size != size || r->pa != pa) continue;
            for (uint64_t f = pa; f < pa + size; f += 0x4000)
                o->frame_ref(o->ctx, f, (int)r->perm, 1);
            r->pa = r->size = 0; r->perm = r->guard = 0;
            return ANS_OK;
        }
        return refuse(s, ANS_E_SART, pa, size);
    }
    if (x[2] > 1 || x[3] > 1 || !o->map(o->ctx, pa, size)) return refuse(s, ANS_E_SART, pa, x[2]);
    for (unsigned i = 0; i < ANS_SART_REGIONS; i++) {
        struct ans_sart *r = &s->sart[i];
        if (r->size) continue;
        uint64_t f = pa;
        for (; f < pa + size; f += 0x4000)
            if (o->frame_ref(o->ctx, f, (int)x[2], 0)) {
                for (uint64_t g = pa; g < f; g += 0x4000) o->frame_ref(o->ctx, g, (int)x[2], 1);
                return refuse(s, ANS_E_FRAME, f, size);
            }
        r->pa = pa; r->size = size; r->perm = (uint32_t)x[2]; r->guard = (uint32_t)x[3];
        return ANS_OK;
    }
    return refuse(s, ANS_E_SART, pa, ANS_SART_REGIONS);
}

int ans_sptm(struct ans_state *s, const struct ans_ops *o, unsigned table,
             unsigned endpoint, const uint64_t x[6], uint64_t *ret)
{
    *ret = 0;
#if SNAP_ANS_ASYNC
    /* A poll point; UNMAP_PAGES of a queued or in-service CID completes it first (N1). */
    if (table == 6) {
        int r = endpoint == 2 && x[1] < ANS_CIDS && busy_cid(s, (uint32_t)x[1]) ? ans_async_drain(s, o) :
                ans_async_progress(s, o, ANS_ASYNC_STEP_MAX);
        if (r) return r;
    }
#endif
    if (table == 6) { s->counter[ANS_C_SPTM6]++; return sptm6(s, o, endpoint, x, ret); }
    if (table == 5) { s->counter[ANS_C_SPTM5]++; return sptm5(s, o, endpoint, x); }
    return refuse(s, ANS_E_SPTM_ORDER, table, endpoint);
}

#if SNAP_ANS_ASYNC
/* ---- SNAP_ANS_ASYNC: queue 1 served without waiting (ans.h) ------------
 * agents/nvme-async/FAILURE-MODES.md. The statements below repeat the
 * synchronous doorbell's (command(), doorbell()'s completion half) in the
 * same order; what moves is when they run. Callers hold ANS exclusion: the
 * token, or the gate shared and the ANS lock (probes/xnuboot.c). */
static int async_on(const struct ans_ops *o)
{
    return o->disk_read && o->disk_start && o->disk_poll;
}
static int busy_cid(const struct ans_state *s, uint32_t cid)
{
    const struct ans_async *a = &s->async;
    if (a->active && a->cur.cid == cid) return 1;
    for (uint32_t i = 0; i < a->count; i++)
        if (a->fifo[(a->head + i) % ANS_ASYNC_FIFO].cid == cid) return 1;
    return 0;
}
/* xfer() with word copies where both sides are 8-byte aligned (N10); the same
 * pages, the same publishes, the same refusals. */
static int xfer_async(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                      volatile uint8_t *local, uint64_t len, int write)
{
    uint64_t pos = 0, at = 0;
    for (unsigned i = 0; i < c->count && len; i++) {
        uint64_t pa = c->prp[i], chunk = 4096 - (pa & 0xfff);
        if (at >= pos + chunk) { pos += chunk; continue; }
        uint64_t skip = at > pos ? at - pos : 0, n = chunk - skip;
        if (n > len) n = len;
        volatile uint8_t *g = o->map(o->ctx, pa + skip, n);
        if (!g) return refuse(s, ANS_E_ADDRESS, pa + skip, n);
        uint64_t k = 0;
        if (!(((uintptr_t)g | (uintptr_t)local) & 7)) {
            volatile uint64_t *gw = (volatile uint64_t *)(volatile void *)g;
            volatile uint64_t *lw = (volatile uint64_t *)(volatile void *)local;
            for (; k + 8 <= n; k += 8) {
                if (write) gw[k / 8] = lw[k / 8];
                else lw[k / 8] = gw[k / 8];
            }
        }
        for (; k < n; k++) {
            if (write) g[k] = local[k];
            else local[k] = g[k];
        }
        if (write) o->publish(o->ctx, pa + skip, n);
        local += n;
        len -= n; at += n; pos += chunk;
    }
    return len ? refuse(s, ANS_E_DIRECTION, len, c->count) : ANS_OK;
}
/* The doorbell's own refusals for an I/O command, in command()'s order, so a
 * malformed command stops the run at its doorbell as before (N14). */
static int queue_io(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c, uint32_t cid,
                    const uint32_t q[16])
{
    struct ans_async *a = &s->async;
    unsigned op = q[0] & 0xff;
    if ((op == 0x01 || op == 0x02) && q[1] == 1) {
        uint64_t n = (q[12] & 0xffff) + 1ULL;
        if (n - 1 != c->nlb) return refuse(s, ANS_E_SQE, n - 1, c->nlb);
        if (n <= ANS_TRANSFER_BYTES / ANS_BLOCK && !(c->dir & (op == 0x02 ? 0x100 : 0x200)))
            return refuse(s, ANS_E_DIRECTION, op, c->dir);
    }
    if (a->count >= ANS_ASYNC_FIFO) return refuse(s, ANS_E_DOORBELL, 1, cid);
    if (busy_cid(s, cid)) a->counter[ANS_A_REQUEUED]++;
    struct ans_async_cmd *e = &a->fifo[(a->head + a->count) % ANS_ASYNC_FIFO];
    e->cid = cid; e->qid = 1;
    for (unsigned i = 0; i < 16; i++) e->q[i] = q[i];
    a->count++;
    a->counter[ANS_A_QUEUED]++;
    if (a->count > a->counter[ANS_A_MAX_DEPTH]) a->counter[ANS_A_MAX_DEPTH] = a->count;
    return ans_async_progress(s, o, ANS_ASYNC_STEP_MAX);
}
/* command()'s I/O half up to the backend: a final status now (*running 0), or
 * the backend running (*running 1); or a refusal. */
static int io_start(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                    const uint32_t *q, uint16_t *status, int *running)
{
    struct ans_async *a = &s->async;
    unsigned op = q[0] & 0xff;
    *status = 0; *running = 0;
    a->op = op; a->lba = a->n = 0;
    s->counter[ANS_C_IO]++;
    if (op == 0x00) {
        if (q[1] != 1 && q[1] != 0xffffffffu) { *status = STATUS_INVALID_NS; return ANS_OK; }
        int r = o->disk_flush ? o->disk_start(o->ctx, 0, 0, 0) : 1;
        if (r == ANS_ASYNC_PENDING) *running = 1;
        else if (!r) *running = 2;                                  /* done at once: poll now */
        else *status = 0x280;                                       /* Write Fault */
        return ANS_OK;
    }
    if (op != 0x01 && op != 0x02) {
        s->counter[ANS_C_INVALID_OPCODE]++;
        s->bad_opcode[1][op >> 6] |= 1ULL << (op & 63);
        *status = STATUS_INVALID_OPCODE;
        return ANS_OK;
    }
    if (q[1] != 1) { *status = STATUS_INVALID_NS; return ANS_OK; }
    uint64_t lba = q[10] | (uint64_t)q[11] << 32, n = (q[12] & 0xffff) + 1ULL;
    if (n - 1 != c->nlb) return refuse(s, ANS_E_SQE, n - 1, c->nlb);
    if (n > ANS_TRANSFER_BYTES / ANS_BLOCK) { *status = STATUS_INVALID_FIELD; return ANS_OK; }
    if (!(c->dir & (op == 0x02 ? 0x100 : 0x200))) return refuse(s, ANS_E_DIRECTION, op, c->dir);
    uint64_t blocks = s->disk_bytes / ANS_BLOCK;
    if (lba >= blocks || n > blocks - lba) {
        s->counter[ANS_C_OUT_OF_RANGE]++; *status = STATUS_LBA_RANGE; return ANS_OK;
    }
    a->lba = lba; a->n = n;
    int r;
    if (op == 0x01) {
        volatile uint8_t *disk = 0;
        if (!o->disk_write_buffer || !o->disk_write) { *status = STATUS_WRITE_PROTECTED; return ANS_OK; }
        int st = o->disk_write_buffer(o->ctx, lba, n, &disk);
        if (st) { *status = (uint16_t)st; return ANS_OK; }
        if (!disk) { *status = 0x280; return ANS_OK; }
        if ((r = xfer_async(s, o, c, disk, n * ANS_BLOCK, 0))) return r;
    }
    r = o->disk_start(o->ctx, op, lba, n);
    if (r == ANS_ASYNC_PENDING) *running = 1;
    else if (!r) *running = 2;                     /* done at once (an edge-only read): poll now */
    else *status = op == 0x02 ? STATUS_READ_ERROR : 0x280;
    return ANS_OK;
}
/* command()'s I/O half after the backend: result is disk_poll's (0 or a
 * failure), data a read's blocks. */
static int io_finish(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                     int result, volatile uint8_t *data, uint16_t *status)
{
    struct ans_async *a = &s->async;
    unsigned op = a->op;
    uint64_t lba = a->lba, n = a->n;
    if (op == 0x00) {
        if (result) *status = 0x280;
        else s->counter[ANS_C_FLUSHES]++;
        return ANS_OK;
    }
    if (result || (op == 0x02 && !data)) { *status = op == 0x02 ? STATUS_READ_ERROR : 0x280; return ANS_OK; }
    if (op == 0x02) {
        int r = xfer_async(s, o, c, data, n * ANS_BLOCK, 1);
        if (r) return r;
    }
    unsigned peak = op == 0x02 ? ANS_C_MAX_READ_BLOCKS : ANS_C_MAX_WRITE_BLOCKS;
    if (n > s->counter[peak]) s->counter[peak] = n;
    if (op == 0x02) { s->counter[ANS_C_READS]++; s->counter[ANS_C_READ_BYTES] += n * ANS_BLOCK; }
    else {
        s->counter[ANS_C_WRITES]++; s->counter[ANS_C_WRITE_BYTES] += n * ANS_BLOCK;
        if (lba < s->counter[ANS_C_LBA_LOW]) s->counter[ANS_C_LBA_LOW] = lba;
        if (lba + n - 1 > s->counter[ANS_C_LBA_HIGH] || s->counter[ANS_C_LBA_HIGH] == 0)
            s->counter[ANS_C_LBA_HIGH] = lba + n - 1;
    }
    return ANS_OK;
}
/* doorbell()'s completion half, unchanged (queue 1 holds no AER). */
static int post(struct ans_state *s, const struct ans_ops *o, unsigned qid, uint32_t cid,
                uint16_t status, const uint32_t *q)
{
    uint64_t cqpa = qid ? s->iocq : s->acq;
    struct ans_cq *cq = &s->cq[qid];
    if (status) {
        s->counter[ANS_C_STATUS_ERRORS]++;
        s->last_status = (uint64_t)status << 48 | (uint64_t)qid << 40 | (uint64_t)(q[0] & 0xff) << 32 | q[10];
    }
    if (!cq->size) return refuse(s, ANS_E_DOORBELL, qid, cid);
    uint32_t next = (cq->tail + 1) % cq->size;
    if (next == cq->head) return refuse(s, ANS_E_CQ_FULL, qid, cq->head);
    volatile uint8_t *ce = o->map(o->ctx, cqpa + (uint64_t)cq->tail * 16, 16);
    if (!ce) return refuse(s, ANS_E_ADDRESS, cqpa, cq->tail);
    wr32(ce, 0); wr32(ce + 4, 0); wr32(ce + 8, qid << 16);
    ANS_ORDER();
    wr32(ce + 12, cid | cq->phase << 16 | (uint32_t)status << 17);
    o->publish(o->ctx, cqpa + (uint64_t)cq->tail * 16, 16);
    cq->tail = next;
    if (!next) cq->phase ^= 1;
    s->counter[ANS_C_IRQ_NVME]++;             /* completions posted */
    return ANS_OK;
}
int ans_async_progress(struct ans_state *s, const struct ans_ops *o, unsigned budget)
{
    struct ans_async *a = &s->async;
    if (!async_on(o)) return ANS_OK;
    for (unsigned done = 0; done < budget;) {
        if (a->active) {
            struct ans_cid *c = &s->cid[a->cur.cid];
            uint16_t status = (uint16_t)a->status;
            if (a->phys) {
                volatile uint8_t *data = 0;
                a->counter[ANS_A_POLLS]++;
                int p = o->disk_poll(o->ctx, &data);
                if (p == ANS_ASYNC_PENDING) { a->counter[ANS_A_PENDING_POLLS]++; return ANS_OK; }
                a->phys = 0;
                int r = io_finish(s, o, c, p, data, &status);
                if (r) { a->active = 0; return r; }
            }
            a->active = 0;
            a->counter[ANS_A_COMPLETED]++;
            done++;
            int r = post(s, o, a->cur.qid, a->cur.cid, status, a->cur.q);
            if (r) return r;
            continue;
        }
        if (!a->count) return ANS_OK;
        a->cur = a->fifo[a->head];
        a->head = (a->head + 1) % ANS_ASYNC_FIFO;
        a->count--;
        a->active = 1; a->status = 0;
        a->counter[ANS_A_STARTED]++;
        uint16_t status = 0;
        int running = 0;
        int r = io_start(s, o, &s->cid[a->cur.cid], a->cur.q, &status, &running);
        if (r) { a->active = 0; return r; }
        a->status = status;
        if (running) a->phys = 1;
        if (running == 1) {                          /* a physical command in flight: reap it later */
            a->seq++;
            a->counter[ANS_A_PHYSICAL]++;
            return ANS_OK;
        }
    }
    return ANS_OK;
}
int ans_async_drain(struct ans_state *s, const struct ans_ops *o)
{
    struct ans_async *a = &s->async;
    if (!async_on(o) || (!a->active && !a->count)) return ANS_OK;
    a->counter[ANS_A_DRAINS]++;
    /* Each pass reaps or serves; the backend bounds every physical command by
     * its timeout, so this ends (N5). */
    while (a->active || a->count) {
        uint64_t before = a->counter[ANS_A_COMPLETED];
        int r = ans_async_progress(s, o, ANS_ASYNC_FIFO + 1);
        a->counter[ANS_A_DRAINED] += a->counter[ANS_A_COMPLETED] - before;
        if (r) return r;
    }
    return ANS_OK;
}
int ans_async_busy(const struct ans_state *s, uint64_t *physical)
{
    const struct ans_async *a = &s->async;
    if (physical) *physical = a->seq;
    return a->active || a->count;
}
void ans_async_stop(struct ans_state *s, const struct ans_ops *o)
{
    struct ans_async *a = &s->async;
    a->counter[ANS_A_STOPS]++;
    a->counter[ANS_A_ABANDONED] += a->count + a->active;
    if (a->phys && o->disk_quiesce) o->disk_quiesce(o->ctx);
    a->active = a->phys = 0;
    a->count = 0;
}
#endif

#if SNAP_ANS_CONVERTED
/* sptm6's MAP_PAGES and UNMAP_PAGES with their checks in the same order, every
 * refusal a DECLINE before any change (the token path repeats the call and
 * makes its own refusal), and the references as one all-or-nothing batch
 * (N9). The PRPs are read into the free CID's slots before the batch: state 0
 * slots are never read. */
int ans_sptm_converted(struct ans_state *s, const struct ans_ops *o, unsigned ep,
                       const uint64_t x[6], uint64_t *ret)
{
    *ret = 0;
    if ((ep != 1 && ep != 2) || !(s->allowed >> ep & 1) || !o->frame_refs) return ANS_DECLINE;
    int r = ans_async_progress(s, o, ANS_ASYNC_STEP_MAX);
    if (r) return r;
    if (ep == 2) {
        if (x[0] > 1 || x[1] >= ANS_CIDS || (x[2] & 1)) return ANS_DECLINE;
        struct ans_cid *c = &s->cid[x[1]];
        if (c->state != 3 || c->qid != x[0]) return ANS_DECLINE;
        if (busy_cid(s, (uint32_t)x[1])) return ANS_DECLINE_BUSY;
        if (c->count && o->frame_refs(o->ctx, c->prp, c->count, c->dir & 0x100, 1)) return ANS_DECLINE;
        s->counter[ANS_C_SPTM6]++;
        if (s->aer_cid == x[1] + 1) s->aer_cid = 0;
        volatile uint8_t *p = (volatile uint8_t *)c;
        for (unsigned i = 0; i < sizeof(*c); i++) p[i] = 0;
        s->counter[ANS_C_UNMAPPED]++;
        *ret = 1;                                               /* 1 = idle (nvme_ioctl 0x8025) */
        return ANS_OK;
    }
    uint64_t qid = x[0], cid = x[1], count = x[4];
    if (qid > 1 || cid >= ANS_CIDS || count > ANS_PRPS) return ANS_DECLINE;
    struct ans_cid *c = &s->cid[cid];
    if (c->state) return ANS_DECLINE;
    volatile uint8_t *t = o->map(o->ctx, x[2], 0x80);
    volatile uint8_t *l = count ? o->map(o->ctx, x[3], count * 8) : 0;
    if (!t || (count && !l)) return ANS_DECLINE;
    uint16_t dir = (uint16_t)((t[0] | t[1] << 8) & 0x1f00), nlb = (uint16_t)(t[4] | t[5] << 8);
    if ((dir & 0x300) == 0x300) return ANS_DECLINE;
    if (!count) {
        if (nlb) return ANS_DECLINE;
    } else {
        uint64_t first = rd64(l);
        if ((first & 0xfff) && count == 1) return ANS_DECLINE;
        if (count - ((first & 0xfff) ? 2 : 1) != nlb) return ANS_DECLINE;
        for (unsigned i = 0; i < count; i++) {
            uint64_t pa = rd64(l + 8 * i);
            if ((i && (pa & 0xfff)) || !o->map(o->ctx, pa, 4096 - (pa & 0xfff))) return ANS_DECLINE;
            c->prp[i] = pa;
        }
        if (o->frame_refs(o->ctx, c->prp, (unsigned)count, dir & 0x100, 0)) return ANS_DECLINE;
    }
    s->counter[ANS_C_SPTM6]++;
    c->dir = dir; c->nlb = nlb; c->qid = (uint8_t)qid; c->count = (uint16_t)count;
    c->state = 3;
    s->counter[ANS_C_MAPPED]++;
    return ANS_OK;
}
#endif
