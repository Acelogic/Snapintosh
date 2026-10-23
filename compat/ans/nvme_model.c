/* SPDX-License-Identifier: MIT */
/* The NVMe controller model: reset, RTKit mailbox, identify, I/O queues, commands,
 * doorbells and MMIO.
 * Part of compat/ans.c's translation unit, included in order; not compiled on its own. */
static int refuse(struct ans_state *s, int reason, uint64_t a, uint64_t b)
{
    if (!s->refusal[0]) {
        s->refusal[0] = (uint64_t)reason; s->refusal[1] = a; s->refusal[2] = b;
    }
    s->counter[ANS_C_REFUSALS]++;
    return reason;
}

int ans_dma_frame(const volatile uint8_t e[16])
{
    return e[2] == ANS_DMA_FRAME_TYPE && !(e[0] | e[1] | e[3] | e[4] | e[5] | e[6] | e[7]) &&
           !((e[11] | e[15]) & 0x80);
}

static uint32_t rd32(const volatile uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void wr32(volatile uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t rd64(const volatile uint8_t *p) { return rd32(p) | (uint64_t)rd32(p + 4) << 32; }

void ans_reset(struct ans_state *s, uint64_t disk_bytes)
{
    volatile uint8_t *p = (volatile uint8_t *)s;
    for (unsigned i = 0; i < sizeof(*s); i++) p[i] = 0;
    s->magic = ANS_MAGIC; s->version = ANS_VERSION; s->disk_bytes = disk_bytes;
    s->allowed = 1u << 0 | 1u << 3;   /* SPTM bootstrap: ENABLE_CG and INIT */
    s->in_enable = 1;
    s->cq[0].phase = s->cq[1].phase = 1;
    s->counter[ANS_C_LBA_LOW] = ~0ULL;
#if SNAP_ANS_ASYNC
    s->async.magic = ANS_ASYNC_MAGIC;
#endif
}

void ans_levels(const struct ans_state *s, int levels[3])
{
    levels[0] = !!s->in_enable;                 /* consumed synchronously: always empty */
    levels[1] = s->out_enable && s->out_count;
    levels[2] = (s->csts & 1) && !(s->intms & 1) &&
        (s->cq[0].tail != s->cq[0].head ||
         ((s->ioq & (ANS_IOQ_CQ | ANS_IOQ_IEN)) == (ANS_IOQ_CQ | ANS_IOQ_IEN) &&
          s->cq[1].tail != s->cq[1].head));
}

/* ---- RTKit ------------------------------------------------------------- */
static int push(struct ans_state *s, uint64_t msg)
{
    if (s->out_count >= ANS_OUTBOX) return refuse(s, ANS_E_MAILBOX, msg, s->out_count);
    s->outbox[s->out_count][0] = msg; s->outbox[s->out_count][1] = 0;
    s->out_count++; s->counter[ANS_C_MSG_OUT]++;
    return ANS_OK;
}
#define MGMT(type, low) ((uint64_t)(type) << 52 | (uint64_t)(low))

static int rtkit(struct ans_state *s, uint64_t msg, uint64_t ep)
{
    s->counter[ANS_C_MSG_IN]++;
    if (ep != 0) return refuse(s, ANS_E_ENDPOINT, msg, ep);  /* 0x20 carries no AP->IOP traffic */
    unsigned type = (unsigned)(msg >> 52) & 0xff;
    uint32_t low = (uint32_t)msg & 0xffff;
    switch (type) {
    case 6:                                     /* IOP power state */
        s->iop_power = low;
        if (low == 0x220 || low == 0x20) {
            if (s->iop == ANS_IOP_RUNNING) return push(s, MGMT(7, 0x20));
            if (s->iop != ANS_IOP_QUIESCED) break;
            s->iop = ANS_IOP_HELLO;
            return push(s, MGMT(1, 12u << 16 | 12u));  /* HELLO min 12, max 12 */
        }
        if (low != 0 && low != 1 && low != 0x10 && low != 0x201 && low != 0x202) break;
        s->iop = ANS_IOP_QUIESCED;
        return push(s, MGMT(7, low));
    case 2:                                     /* HELLO reply: version 12 */
        if (s->iop != ANS_IOP_HELLO || (msg & 0xffffffffu) != (12u << 16 | 12u)) break;
        s->iop = ANS_IOP_EPMAP;
        /* One group (1: endpoints 32..63), last, bitmap = endpoint 0x20. */
        return push(s, MGMT(8, 0) | 1ULL << 51 | 1ULL << 32 | 1);
    case 8:                                     /* EPMAP reply for the last group */
        if (s->iop != ANS_IOP_EPMAP || !(msg >> 51 & 1) || (msg >> 32 & 0x3f) != 1) break;
        s->iop = ANS_IOP_RUNNING; s->epmap_acked++;
        return push(s, MGMT(7, 0x20));
    case 5:                                     /* STARTEP */
        if (s->iop < ANS_IOP_EPMAP || (msg >> 32 & 0xffff) != 0x20) break;
        s->counter[ANS_C_STARTEP]++;
        return ANS_OK;
    case 0xb:                                   /* AP power state: echoed */
        s->ap_power = low; s->counter[ANS_C_AP_POWER]++;
        return push(s, MGMT(0xb, low));
    case 3:                                     /* ping */
        return push(s, MGMT(4, msg & 0xffffffffffffULL));
    }
    return refuse(s, ANS_E_RTKIT, msg, s->iop);
}

int ans_mailbox_pair(struct ans_state *s, const struct ans_ops *o, uint64_t off,
                     int write, uint64_t v[2])
{
    (void)o;
#if SNAP_ANS_ASYNC
    /* N8: an IOP power-state message (RTKit type 6) never overtakes queued I/O; anything else only polls. */
    {
        int r = write && (v[0] >> 52 & 0xff) == 6 ? ans_async_drain(s, o) : ans_async_progress(s, o, ANS_ASYNC_STEP_MAX);
        if (r) return r;
    }
#endif
    if (write) {
        if (off != 0x8800 || !s->in_enable || v[1] > 0xff)
            return refuse(s, ANS_E_MAILBOX, off, v[1]);
        return rtkit(s, v[0], v[1]);
    }
    if (off != 0x8830 || !s->out_enable || !s->out_count)
        return refuse(s, ANS_E_MAILBOX, off, s->out_count);
    /* Second word: endpoint 0, plus the pre-pop control snapshot that
     * getMailboxBulk reads (count 1 marks the last message of a burst). */
    v[0] = s->outbox[0][0];
    v[1] = (uint64_t)(s->out_enable | s->out_count << 20) << 32;
    for (unsigned i = 1; i < s->out_count; i++) {
        s->outbox[i - 1][0] = s->outbox[i][0]; s->outbox[i - 1][1] = s->outbox[i][1];
    }
    s->out_count--;
    s->outbox[s->out_count][0] = s->outbox[s->out_count][1] = 0;
    return ANS_OK;
}

/* ---- data movement through the SPTM-registered page list --------------- */
/* Copy between the command's admitted pages and `local` (write = device
 * writes guest memory). Byte offset `at` into the transfer. */
static int xfer(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                uint64_t at, volatile uint8_t *local, uint64_t len, int write)
{
    uint64_t pos = 0;
    for (unsigned i = 0; i < c->count && len; i++) {
        uint64_t pa = c->prp[i], chunk = 4096 - (pa & 0xfff);
        if (at >= pos + chunk) { pos += chunk; continue; }
        uint64_t skip = at > pos ? at - pos : 0, n = chunk - skip;
        if (n > len) n = len;
        volatile uint8_t *g = o->map(o->ctx, pa + skip, n);
        if (!g) return refuse(s, ANS_E_ADDRESS, pa + skip, n);
        for (uint64_t k = 0; k < n; k++) {
            if (write) g[k] = local ? local[k] : 0;
            else local[k] = g[k];
        }
        if (write) o->publish(o->ctx, pa + skip, n);
        if (local) local += n;
        len -= n; at += n; pos += chunk;
    }
    return len ? refuse(s, ANS_E_DIRECTION, len, c->count) : ANS_OK;
}
static int put32(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                 uint64_t at, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    return xfer(s, o, c, at, b, 4, 1);
}
static int put_str(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                   uint64_t at, const char *str, unsigned field)
{
    uint8_t b[40];
    unsigned n = 0;
    for (; n < field; n++) b[n] = ' ';
    for (n = 0; str[n] && n < field; n++) b[n] = (uint8_t)str[n];
    return xfer(s, o, c, at, b, field, 1);
}

/* Identify (IONVMeFamily ProcessIdentifyData/IdentifyNamespaces/
 * DetermineNamespaces/GetDeviceProperties): 4 KiB, device-to-memory. */
static int identify(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c,
                    unsigned cns, uint32_t nsid, uint16_t *status)
{
    if (cns > 1) { *status = STATUS_INVALID_FIELD; return ANS_OK; }
    if ((cns == 1 && nsid) || (cns == 0 && nsid != 1)) { *status = STATUS_INVALID_NS; return ANS_OK; }
    int r = xfer(s, o, c, 0, 0, 4096, 1);
    if (r) return r;
    uint64_t blocks = s->disk_bytes / ANS_BLOCK;
    if (cns == 1) {
        if ((r = put32(s, o, c, 0, 0x106b106b)) ||             /* VID, SSVID */
            (r = put_str(s, o, c, 4, "SNAPM2-0001", 20)) ||
            (r = put_str(s, o, c, 0x18, "Snapintosh virtual ANS2", 40)) ||
            (r = put_str(s, o, c, 0x40, "m2.1", 8)) ||
            (r = put32(s, o, c, 0x4c, (uint32_t)ANS_MDTS << 8)) ||  /* MDTS */
            (r = put32(s, o, c, 0x50, VERSION)) ||
            (r = put32(s, o, c, 0x200, 0x4466)) ||                 /* SQES/CQES */
            (r = put32(s, o, c, 0x204, 1)) ||                      /* NN: one namespace */
            (r = put32(s, o, c, 0x20c, 1u << 8))) return r;        /* VWC present */
        return ANS_OK;
    }
    uint32_t w[] = {(uint32_t)blocks, (uint32_t)(blocks >> 32)};
    for (unsigned f = 0; f < 3; f++)                               /* NSZE/NCAP/NUSE */
        if ((r = put32(s, o, c, 8u * f, w[0])) || (r = put32(s, o, c, 8u * f + 4, w[1]))) return r;
    if ((r = put32(s, o, c, 0x78, 0x50414e53u)) ||  /* EUI64 "SNAP" */
        (r = put32(s, o, c, 0x7c, 0x0100324du)) ||                          /* "M2\0\1" */
        (r = put32(s, o, c, 0x80, 12u << 16)) ||                            /* LBAF0: 4 KiB */
        (r = put32(s, o, c, 0x180, 1))) return r;                           /* Apple nstype 1 */
    return ANS_OK;
}

/* Create/Delete I/O queue 1 (IONVMeController::EnableCompletionQueue/
 * EnableSubmissionQueue and DisableCompletionQueue/DisableSubmissionQueue;
 * AppleNVMeRequest::BuildCommandCreateCQ/CreateSQ/DeleteCQ/DeleteSQ):
 * CDW10 = QID | (entries - 1) << 16, PRP1 = base; Create CQ CDW11 = PC | IEN << 1
 * | IV << 16 (the driver sends 3); Create SQ CDW11 = PC | QPRIO << 1 | CQID << 16.
 * Only queue 1 exists (SPTM INIT(64, 2)). Its memory belongs to the SPTM:
 * AppleANS2CGv2Controller registers it (IOCQ_REG/IOSQ_REG, which write BAR
 * 0x1208/0x1200 and take the DMA reference) before sending the admin command,
 * so PRP1 must be that base and the size the one IOQA_REG registered; any
 * other value is outside the contract (refused). Deleting touches no
 * reference: no SPTM endpoint releases a queue base. */
static uint16_t ioqueue(struct ans_state *s, unsigned op, const uint32_t *q, int *err)
{
    unsigned qid = q[10] & 0xffff, size = (q[10] >> 16) + 1, cq = op == 0x05 || op == 0x04;
    uint32_t bit = cq ? ANS_IOQ_CQ : ANS_IOQ_SQ;
    if (qid != 1) return STATUS_QID;
    if (op == 0x00 || op == 0x04) {                 /* Delete I/O SQ / CQ */
        if (!(s->ioq & bit)) return STATUS_QID;
        if (cq && (s->ioq & ANS_IOQ_SQ)) return STATUS_QDELETE;
        s->ioq &= cq ? ~(ANS_IOQ_CQ | ANS_IOQ_IEN) : ~ANS_IOQ_SQ;
        return 0;
    }
    if (s->ioq & bit) return STATUS_QID;            /* already exists */
    if (!(q[11] & 1)) return STATUS_INVALID_FIELD;  /* CAP.CQR: contiguous only */
    if (size < 2 || size > ANS_CIDS + 1) return STATUS_QSIZE;   /* MQES */
    if (cq) { if (q[11] >> 16) return STATUS_IV; }  /* one vector */
    else if ((q[11] >> 16) != 1 || !(s->ioq & ANS_IOQ_CQ)) return STATUS_CQ_INVALID;
    uint64_t base = q[6] | (uint64_t)q[7] << 32, reg = cq ? s->iocq : s->iosq;
    uint32_t want = cq ? s->cq[1].size : (s->ioqa & 0xffff) + 1;
    if (!reg || base != reg) { *err = refuse(s, ANS_E_SQE, base, reg); return 0; }
    if (size != want) { *err = refuse(s, ANS_E_SQE, size, want); return 0; }
    s->ioq |= bit | (cq && (q[11] & 2) ? ANS_IOQ_IEN : 0);
    if (cq) { s->cq[1].tail = s->cq[1].head = 0; s->cq[1].phase = 1; }
    return 0;
}

static uint16_t command(struct ans_state *s, const struct ans_ops *o, unsigned qid,
                        struct ans_cid *c, const uint32_t *q, int *hold, int *err)
{
    unsigned op = q[0] & 0xff;
    uint16_t status = 0;
    *err = ANS_OK;
    if (qid == 0) {
        s->counter[ANS_C_ADMIN]++;
        switch (op) {
        case 0x00: case 0x01: case 0x04: case 0x05:
            return ioqueue(s, op, q, err);
        case 0x06:
            if (!(c->dir & 0x100) || c->count == 0) { *err = refuse(s, ANS_E_DIRECTION, op, c->dir); return 0; }
            *err = identify(s, o, c, q[10] & 0xff, q[1], &status);
            return status;
        case 0x09: {                                /* Set Features */
            unsigned fid = q[10] & 0xff;
            static const uint8_t ok[] = {1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 0x80, 0xc3, 0xc7, 0xd0};
            for (unsigned i = 0; i < sizeof ok; i++) if (ok[i] == fid) return 0;
            return STATUS_INVALID_FIELD;
        }
        case 0x0a:                                  /* Get Features: queue count only */
            return (q[10] & 0xff) == 7 ? 0 : STATUS_INVALID_FIELD;
        case 0x02: {                                /* Get Log Page: SMART only */
            uint64_t len = ((uint64_t)(q[10] >> 16) + 1) * 4;
            if ((q[10] & 0xff) != 2) return STATUS_INVALID_FIELD;
            if (!(c->dir & 0x100) || len > 512) { *err = refuse(s, ANS_E_DIRECTION, op, len); return 0; }
            if ((*err = xfer(s, o, c, 0, 0, len, 1))) return 0;
            if (len >= 4) *err = put32(s, o, c, 0, 300u << 8);  /* 300 K composite temperature */
            return 0;
        }
        case 0x0c:                                  /* AER: held, never completed */
            if (s->aer_cid) return STATUS_AER_LIMIT;
            s->aer_cid = (uint32_t)(c - s->cid) + 1;
            *hold = 1;
            return 0;
        case 0xd8: {                                /* tunnel (ProcessTunnelCommand) */
            uint64_t buf = q[11] | (uint64_t)q[12] << 32;
            s->counter[ANS_C_TUNNEL]++;
            if (c->count) { *err = refuse(s, ANS_E_SART, buf, c->count); return 0; }
            int found = 0;
            for (unsigned i = 0; i < ANS_SART_REGIONS; i++) {
                const struct ans_sart *r = &s->sart[i];
                if (r->size && r->perm && buf >= r->pa && buf - r->pa <= r->size - 0x1000) found = 1;
            }
            volatile uint8_t *g = found && s->sart_active ? o->map(o->ctx, buf, 0x1000) : 0;
            if (!g) { *err = refuse(s, ANS_E_SART, buf, s->sart_active); return 0; }
            uint32_t sub = rd32(g + 0xc);           /* 6 SET_TIME, 0x52 ATV, 0x120 OS build */
            uint64_t data = q[13] | (uint64_t)q[14] << 32, bytes = q[15];
            if (data || bytes) {
                /* Native GetSanitizeCounters: CDW13/14 names a second SART
                 * buffer, not PRPs. We do not supply firmware statistics;
                 * result1 below takes the native error/cleanup path. */
                found = 0;
                if (sub == 0xd && q[10] == 1 && bytes == 0x100000 &&
                    data <= UINT64_MAX - bytes && buf <= UINT64_MAX - 0x1000 &&
                    (data + bytes <= buf || buf + 0x1000 <= data)) {
                    for (unsigned i = 0; i < ANS_SART_REGIONS; i++) {
                        const struct ans_sart *r = &s->sart[i];
                        if (r->perm && r->size >= bytes && data >= r->pa &&
                            data - r->pa <= r->size - bytes) found = 1;
                    }
                }
                if (!found || !o->map(o->ctx, data, bytes)) {
                    *err = refuse(s, ANS_E_SART, data, bytes); return 0;
                }
            }
            wr32(g + 0x4c, (sub == 6 || sub == 0x52 || sub == 0x120) ? 0 : 1);
            o->publish(o->ctx, buf + 0x4c, 4);
            return 0;
        }
        }
        s->counter[ANS_C_INVALID_OPCODE]++;
        s->bad_opcode[0][op >> 6] |= 1ULL << (op & 63);
        return STATUS_INVALID_OPCODE;
    }
    s->counter[ANS_C_IO]++;
    if (op == 0x00) {
        if (q[1] != 1 && q[1] != 0xffffffffu) return STATUS_INVALID_NS;
        if (o->disk_read && (!o->disk_flush || o->disk_flush(o->ctx))) return 0x280; /* Write Fault */
        s->counter[ANS_C_FLUSHES]++;
        return 0;
    }
    if (op != 0x01 && op != 0x02) {
        s->counter[ANS_C_INVALID_OPCODE]++;
        s->bad_opcode[1][op >> 6] |= 1ULL << (op & 63);
        return STATUS_INVALID_OPCODE;
    }
    if (q[1] != 1) return STATUS_INVALID_NS;
    uint64_t lba = q[10] | (uint64_t)q[11] << 32, n = (q[12] & 0xffff) + 1ULL;
    if (n - 1 != c->nlb) { *err = refuse(s, ANS_E_SQE, n - 1, c->nlb); return 0; }  /* SQE vs TCB */
    if (n > ANS_TRANSFER_BYTES / ANS_BLOCK) return STATUS_INVALID_FIELD;
    if (!(c->dir & (op == 0x02 ? 0x100 : 0x200))) { *err = refuse(s, ANS_E_DIRECTION, op, c->dir); return 0; }
    uint64_t blocks = s->disk_bytes / ANS_BLOCK;
    if (lba >= blocks || n > blocks - lba) { s->counter[ANS_C_OUT_OF_RANGE]++; return STATUS_LBA_RANGE; }
    volatile uint8_t *disk;
    if (o->disk_read) {
        disk = 0;
        if (op == 0x01) {
            if (!o->disk_write_buffer || !o->disk_write) return STATUS_WRITE_PROTECTED;
            int status = o->disk_write_buffer(o->ctx, lba, n, &disk);
            if (status) return status;
            if (!disk) return 0x280;
        } else if (o->disk_read(o->ctx, lba, n, &disk) || !disk) return STATUS_READ_ERROR;
    } else
        disk = (volatile uint8_t *)s + ANS_DISK_OFFSET + lba * ANS_BLOCK;
    if ((*err = xfer(s, o, c, 0, disk, n * ANS_BLOCK, op == 0x02))) return 0;
    if (op == 0x01 && o->disk_read && o->disk_write(o->ctx, lba, n)) return 0x280;
    unsigned peak = op == 0x02 ? ANS_C_MAX_READ_BLOCKS : ANS_C_MAX_WRITE_BLOCKS;
    if (n > s->counter[peak]) s->counter[peak] = n;
    if (op == 0x02) { s->counter[ANS_C_READS]++; s->counter[ANS_C_READ_BYTES] += n * ANS_BLOCK; }
    else {
        s->counter[ANS_C_WRITES]++; s->counter[ANS_C_WRITE_BYTES] += n * ANS_BLOCK;
        if (lba < s->counter[ANS_C_LBA_LOW]) s->counter[ANS_C_LBA_LOW] = lba;
        if (lba + n - 1 > s->counter[ANS_C_LBA_HIGH] || s->counter[ANS_C_LBA_HIGH] == 0)
            s->counter[ANS_C_LBA_HIGH] = lba + n - 1;
    }
    return 0;
}

#if SNAP_ANS_ASYNC
static int async_on(const struct ans_ops *o);
static int busy_cid(const struct ans_state *s, uint32_t cid);
static int queue_io(struct ans_state *s, const struct ans_ops *o, const struct ans_cid *c, uint32_t cid,
                    const uint32_t q[16]);
#endif
/* A linear-SQ doorbell: the value written is the command id. */
static int doorbell(struct ans_state *s, const struct ans_ops *o, unsigned qid, uint64_t cid)
{
    uint64_t sq = qid ? s->iosq : s->asq, cqpa = qid ? s->iocq : s->acq;
    struct ans_cq *cq = &s->cq[qid];
    /* I/O queue 1 takes commands only once both admin Creates completed. */
    if (!(s->csts & 1) || !sq || !cqpa || !cq->size || cid >= ANS_CIDS ||
        (qid && (s->ioq & (ANS_IOQ_CQ | ANS_IOQ_SQ)) != (ANS_IOQ_CQ | ANS_IOQ_SQ)))
        return refuse(s, ANS_E_DOORBELL, qid, cid);
    struct ans_cid *c = &s->cid[cid];
    if (c->state != 3 || c->qid != qid) return refuse(s, ANS_E_CID, cid, c->state);
    volatile uint8_t *e = o->map(o->ctx, sq + cid * 64, 64);
    if (!e) return refuse(s, ANS_E_ADDRESS, sq, cid);
    uint32_t q[16];
    for (unsigned i = 0; i < 16; i++) q[i] = rd32(e + 4 * i);
    /* CID in CDW0 must be the doorbell's; FUSE and PSDT unused. */
    if ((q[0] >> 16) != cid || (q[0] & 0xc300)) return refuse(s, ANS_E_SQE, q[0], cid);
#if SNAP_ANS_ASYNC
    if (qid && async_on(o)) return queue_io(s, o, c, (uint32_t)cid, q);
#endif
    int hold = 0, err;
    uint16_t status = command(s, o, qid, c, q, &hold, &err);
    if (err) return err;
    if (status) {
        s->counter[ANS_C_STATUS_ERRORS]++;
        s->last_status = (uint64_t)status << 48 | (uint64_t)qid << 40 | (uint64_t)(q[0] & 0xff) << 32 | q[10];
    }
    if (hold) return ANS_OK;
    uint32_t next = (cq->tail + 1) % cq->size;
    if (next == cq->head) return refuse(s, ANS_E_CQ_FULL, qid, cq->head);
    volatile uint8_t *ce = o->map(o->ctx, cqpa + (uint64_t)cq->tail * 16, 16);
    if (!ce) return refuse(s, ANS_E_ADDRESS, cqpa, cq->tail);
    wr32(ce, 0); wr32(ce + 4, 0);   /* DW0 0: SetNumQueues -> 1 SQ, 1 CQ */ wr32(ce + 8, qid << 16);
    ANS_ORDER();
    wr32(ce + 12, (uint32_t)cid | cq->phase << 16 | (uint32_t)status << 17);
    o->publish(o->ctx, cqpa + (uint64_t)cq->tail * 16, 16);
    cq->tail = next;
    if (!next) cq->phase ^= 1;
    s->counter[ANS_C_IRQ_NVME]++;             /* completions posted */
    return ANS_OK;
}

/* ---- MMIO -------------------------------------------------------------- */
int ans_mmio(struct ans_state *s, const struct ans_ops *o, unsigned window,
             uint64_t off, unsigned width, int write, uint64_t *value)
{
    s->counter[ANS_C_MMIO]++;
#if SNAP_ANS_ASYNC
    /* Every NVMe BAR access is a poll point (the I/O doorbell's is its queue_io); CC (reset, shutdown) and the
     * admin doorbell wait for queue 1 first: their effects and the admin CQE follow every earlier I/O completion
     * (N4, N8). */
    if (window == 1 && !(write && off == 0x24910)) {
        int r = write && (off == 0x14 || off == 0x2490c) ? ans_async_drain(s, o) :
                ans_async_progress(s, o, ANS_ASYNC_STEP_MAX);
        if (r) return r;
    }
#endif
    if (width != 4 || (off & 3)) return refuse(s, ANS_E_WIDTH, off, width);
    uint32_t v = (uint32_t)*value;
    if (window == 0) {                          /* ASC */
        if (off == 0x8110 || off == 0x8114) {
            uint32_t *en = off == 0x8110 ? &s->in_enable : &s->out_enable;
            if (write) {                        /* read-modify-write image permitted */
                if (*value & ~0x00f3ff01ULL) return refuse(s, ANS_E_VALUE, off, *value);
                *en = v & 1;
                return ANS_OK;
            }
            unsigned n = off == 0x8110 ? 0 : s->out_count;
            *value = *en | (n ? 0 : 1u << 17) | (n == ANS_OUTBOX ? 1u << 16 : 0) | n << 20;
            return ANS_OK;
        }
        /* CPU control: running. AppleASCWrapV6::_runCPU(true) writes back
         * the read value | 0x10, idempotent on a running IOP; stopping it
         * (bit 4 or 5 cleared) is not modeled and refused. */
        if (off == 0x44) {
            if (!write) { *value = 0x10; return ANS_OK; }
            if (v == 0x10) return ANS_OK;
        }
        return refuse(s, ANS_E_REGISTER, off, write);
    }
    if (window != 1) return refuse(s, ANS_E_REGISTER, off, window);
    if (!write) {
        uint64_t r;
        switch (off) {
        case 0x00: r = CAP_LO; break;
        case 0x04: r = CAP_HI; break;
        case 0x08: r = VERSION; break;
        case 0x0c: case 0x10: r = s->intms; break;
        case 0x14: r = s->cc; break;
        case 0x1c: r = s->csts; break;
        case 0x24: r = s->aqa; break;
        case 0x28: case 0x2c: r = s->asq >> (off == 0x2c ? 32 : 0); break;
        case 0x30: case 0x34: r = s->acq >> (off == 0x34 ? 32 : 0); break;
        case 0x1200: case 0x1204: r = s->iosq >> (off == 0x1204 ? 32 : 0); break;
        case 0x1208: case 0x120c: r = s->iocq >> (off == 0x120c ? 32 : 0); break;
        case 0x1210: r = s->ioqa; break;
        case 0x1300: r = BOOT_OK; break;
        case 0x1304: r = s->modesel; break;
        case 0x1308: case 0x1314: r = 0; break;  /* base command id; no sleep notifier */
        case 0x1318: r = s->ppm; break;
        case 0x13c8: r = s->aqm; break;
        case 0x13e8: r = s->sart_power; break;
        case 0x13f0: case 0x13f4: case 0x13f8: case 0x13fc: r = 0; break;  /* no fatal state */
        default: return refuse(s, ANS_E_REGISTER, off, 0);
        }
        *value = (uint32_t)r;
        return ANS_OK;
    }
    switch (off) {
    case 0x0c: s->intms |= v & 1; return ANS_OK;
    case 0x10: s->intms &= ~(v & 1); return ANS_OK;
    case 0x14:
        if (v & ~0x00ffc0f1u) return refuse(s, ANS_E_VALUE, off, v);
        if ((v & 1) && !(s->cc & 1)) {          /* enable: SPTM owns AQA/ASQ/ACQ */
            if (!s->asq || !s->acq || !s->aqa) return refuse(s, ANS_E_STATE, off, v);
            for (unsigned i = 0; i < 2; i++) { s->cq[i].tail = s->cq[i].head = 0; s->cq[i].phase = 1; }
            s->aer_cid = 0;
        }
        /* Reset (EN 1 -> 0) deletes the I/O queues (NVMe); the driver creates
         * them again after EnableController. The SPTM sees no CC write, so every
         * DMA reference (queue bases, mapped command ids, SART) stays held. */
        if (!(v & 1)) s->ioq = 0;
        s->cc = v;
        s->csts = (v & 1) | ((v >> 14 & 3) ? 2u << 2 : 0);  /* RDY; shutdown complete */
        return ANS_OK;
    case 0x1004: case 0x100c: {
        struct ans_cq *cq = &s->cq[off == 0x100c];
        if (!cq->size || v >= cq->size) return refuse(s, ANS_E_DOORBELL, off, v);
        cq->head = v;
        return ANS_OK;
    }
    case 0x2490c: case 0x24910: return doorbell(s, o, off == 0x24910, v);
    case 0x1304: if (v != 0 && v != 4) break; s->modesel = v; return ANS_OK;
    case 0x1318: s->ppm = v; return ANS_OK;
    case 0x13c8: if (v != 1) break; s->aqm = v; return ANS_OK;
    case 0x13e8: s->sart_power = v; return ANS_OK;
    default: return refuse(s, ANS_E_REGISTER, off, 1);
    }
    return refuse(s, ANS_E_VALUE, off, v);
}

