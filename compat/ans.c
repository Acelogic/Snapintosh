/* SPDX-License-Identifier: MIT */
/* Virtual ANS2 (compat/ans.h). Compact by design: the monitor has a fixed
 * code budget, and every branch here is a guest-reachable contract. */
#include "ans.h"

_Static_assert(sizeof(struct ans_state) <= ANS_STATE_BYTES, "state fits its reservation page");
_Static_assert(ANS_FW_OFFSET >= ANS_STATE_BYTES && ANS_DISK_OFFSET >= ANS_FW_OFFSET + 0x4000,
               "reservation layout: state, one reserved zero page, disk");

#if defined(__aarch64__) && !defined(ANS_HOST)
#define ANS_ORDER() __asm__ volatile("dmb ish" ::: "memory")
#else
#define ANS_ORDER() __asm__ volatile("" ::: "memory")
#endif

#define CAP_LO 0x14010040u        /* TO 20 (10 s), CQR, MQES 0x40 (65 entries) */
#define CAP_HI 0x00000020u        /* CSS NVM (bit 37); MPSMIN/MPSMAX 4 KiB, DSTRD 0 */
#define VERSION 0x00010100u       /* "NVMe Revision Supported" 1.10 */
#define BOOT_OK 0xde71ce55u       /* WaitDeviceActive (IONVMeFamily 0x1f190) */
#define STATUS_INVALID_OPCODE 0x01
#define STATUS_INVALID_FIELD 0x02
#define STATUS_INVALID_NS 0x0b
#define STATUS_LBA_RANGE 0x80
#define STATUS_WRITE_PROTECTED 0x20   /* Namespace is Write Protected */
#define STATUS_READ_ERROR 0x281       /* SCT 2: Unrecovered Read Error */
#define STATUS_AER_LIMIT 0x105
#define STATUS_CQ_INVALID 0x100   /* SCT 1: Completion Queue Invalid */
#define STATUS_QID 0x101          /* Invalid Queue Identifier */
#define STATUS_QSIZE 0x102        /* Invalid Queue Size */
#define STATUS_IV 0x108           /* Invalid Interrupt Vector */
#define STATUS_QDELETE 0x10c      /* Invalid Queue Deletion */

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
