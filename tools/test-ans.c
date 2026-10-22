/* SPDX-License-Identifier: MIT */
/* Host test for the virtual ANS2 (compat/ans.c). It drives the same sequence the
 * 26A428 kernelcache issues (docs/ANS2-M2-20260925.md, sections 2-4):
 *   RTBuddy: outbox enable, IOP_PWR_STATE 0x220, HELLO reply 0x000c000c, EPMAP
 *            reply, STARTEP 0x20, AP power 0x20;
 *   nvme_ioctl/SPTM table 6: INIT(64, 2), ENABLE_CG, ADMIN_QUEUE_REGS,
 *            IOQA(64, 64), CC.EN, per-command MAP_PAGES/UNMAP_PAGES around each
 *            linear-SQ doorbell, IOCQ then IOSQ;
 *   sart_ioctl/SPTM table 5 for the tunnel buffer (CORE_DEBUG_SET_TIME);
 *   IONVMeController::InitializeNVMe's I/O queue: IOCQ_REG then Create I/O CQ
 *            (0x05), IOSQ_REG then Create I/O SQ (0x01), and ShutdownNVMe's
 *            Delete I/O SQ (0x00) / CQ (0x04), CC.SHN, CC.EN 0;
 *   the 2026-09-25 A16 run (ans-m2-fw-300s-20260925) replayed command by
 *            command, and the failure/teardown path after it, with the audit's
 *            check: every DMA reference held is one the state names;
 * the DMA frame-type admission (ans_dma_frame, the DART data-leaf rule) for
 * every type and metadata byte, and through queue bases, MAP_PAGES and SART;
 * then malformed, out-of-range and out-of-order requests, and a random fuzz
 * pass whose only acceptable outcomes are completions or refusals.
 *
 *   clang -std=c11 -g -O1 -fsanitize=address,undefined -DANS_HOST -Icompat \
 *       tools/test-ans.c compat/ans.c -o build/test-ans && build/test-ans */
#include "ans.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

/* Fake guest RAM: [RAM, RAM+RAM_SIZE). The first 64 KiB is "not managed"
 * (an image frame): DMA references there are refused, as sptm_managed_frame
 * refuses them in the monitor. Every managed frame has a fake SPTM frame-map
 * entry (XNU_DEFAULT unless a test retypes it) that frame_ref admits through
 * ans_dma_frame exactly as the monitor's ans_frame_ref does. */
#define RAM 0x880000000ULL
#define RAM_SIZE (8ULL << 20)
#define UNMANAGED (64ULL << 10)
static uint8_t *ram;
static int refs_ro[RAM_SIZE / 0x4000], refs_rw[RAM_SIZE / 0x4000];
static unsigned publishes;
static uint8_t frame_map[RAM_SIZE / 0x4000][16];

static volatile uint8_t *map(void *ctx, uint64_t pa, uint64_t size)
{
    (void)ctx;
    if (pa < RAM || pa >= RAM + RAM_SIZE || size > RAM + RAM_SIZE - pa) return 0;
    return ram + (pa - RAM);
}
static int frame_ref(void *ctx, uint64_t pa, int writable, int release)
{
    (void)ctx;
    if (pa < RAM + UNMANAGED || pa >= RAM + RAM_SIZE) return 1;
    int *r = writable ? refs_rw : refs_ro;
    uint64_t f = (pa - RAM) / 0x4000;
    if (!release && !ans_dma_frame(frame_map[f])) return 1;
    if (release) { if (!r[f]) return 1; r[f]--; } else r[f]++;
    return 0;
}
static void publish(void *ctx, uint64_t pa, uint64_t size) { (void)ctx; (void)pa; (void)size; publishes++; }
static struct ans_ops ops = {.map=map, .frame_ref=frame_ref, .publish=publish};

#define DISK_BYTES (64ULL << 20)
static struct ans_state *s;
static uint8_t *disk;

/* Guest layout. The queue bases are variables: the replay of the A16 run
 * uses that run's frame layout (ASQ, I/O CQ and ACQ in three frames). */
static uint64_t ASQ = RAM + 0x100000, ACQ = RAM + 0x101000, IOSQ = RAM + 0x102000,
                IOCQ = RAM + 0x103000;
static void layout(uint64_t asq, uint64_t acq, uint64_t iosq, uint64_t iocq)
{
    ASQ = asq; ACQ = acq; IOSQ = iosq; IOCQ = iocq;
}
#define TPL (RAM + 0x104000)        /* 0x80-byte TCB template */
#define SEG (RAM + 0x104100)        /* page list */
#define DATA (RAM + 0x200000)       /* data pages */
#define TUNNEL (RAM + 0x300000)     /* 16 KiB SART buffer */

static uint64_t rd(uint64_t pa, unsigned n) { uint64_t v = 0; memcpy(&v, ram + pa - RAM, n); return v; }
static void wr(uint64_t pa, uint64_t v, unsigned n) { memcpy(ram + pa - RAM, &v, n); }

static int mmio(unsigned w, uint64_t off, int write, uint64_t *v) { return ans_mmio(s, &ops, w, off, 4, write, v); }
static int mmio_w(unsigned w, uint64_t off, uint64_t v) { return mmio(w, off, 1, &v); }
static uint64_t mmio_r(unsigned w, uint64_t off) { uint64_t v = 0; CHECK(!mmio(w, off, 0, &v)); return v; }
static int send(uint64_t msg, uint64_t ep) { uint64_t v[2] = {msg, ep}; return ans_mailbox_pair(s, &ops, 0x8800, 1, v); }
static int recv(uint64_t v[2]) { return ans_mailbox_pair(s, &ops, 0x8830, 0, v); }
static uint64_t sptm(unsigned t, unsigned ep, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, int *err)
{
    uint64_t x[6] = {a, b, c, d, e, 0}, ret = ~0ULL;
    *err = ans_sptm(s, &ops, t, ep, x, &ret);
    return ret;
}
static void reset_state(void)
{
    ans_reset(s, DISK_BYTES);
    memset(ram, 0, RAM_SIZE);
    memset(refs_ro, 0, sizeof refs_ro); memset(refs_rw, 0, sizeof refs_rw);
    memset(frame_map, 0, sizeof frame_map);
    for (unsigned i = 0; i < RAM_SIZE / 0x4000; i++) frame_map[i][2] = ANS_DMA_FRAME_TYPE;
}
static uint8_t *meta(uint64_t pa) { return frame_map[(pa - RAM) / 0x4000]; }
static int refs_total(void)
{
    int n = 0;
    for (unsigned i = 0; i < RAM_SIZE / 0x4000; i++) n += refs_ro[i] + refs_rw[i];
    return n;
}
/* The stopped-state audit's check (tools/audit-secondary-runtime.py with
 * probes/ansstate.py references()): each frame's DMA reference counts equal
 * what the model's state names -- the four SPTM queue bases (writable), every
 * mapped command id's pages (writable when its TCB has 0x100) and every SART
 * region's 16 KiB frames (writable for perm 1). Nothing held that the state
 * cannot explain, nothing named that is not held. */
static int refs_explained(void)
{
    static int ro[RAM_SIZE / 0x4000], rw[RAM_SIZE / 0x4000];
    memset(ro, 0, sizeof ro); memset(rw, 0, sizeof rw);
#define NAME(pa, w) do { uint64_t f_ = ((pa) - RAM) / 0x4000; \
    if ((pa) < RAM || f_ >= RAM_SIZE / 0x4000) return 0; if (w) rw[f_]++; else ro[f_]++; } while (0)
    const uint64_t base[4] = {s->asq, s->acq, s->iosq, s->iocq};
    for (unsigned i = 0; i < 4; i++) if (base[i]) NAME(base[i], 1);
    for (unsigned c = 0; c < ANS_CIDS; c++) {
        const struct ans_cid *k = &s->cid[c];
        if (k->state == 3) for (unsigned i = 0; i < k->count; i++) NAME(k->prp[i], k->dir & 0x100);
        else if (k->state || k->count) return 0;
    }
    for (unsigned i = 0; i < ANS_SART_REGIONS; i++)
        for (uint64_t f = s->sart[i].pa; s->sart[i].size && f < s->sart[i].pa + s->sart[i].size; f += 0x4000)
            NAME(f, s->sart[i].perm);
#undef NAME
    return memcmp(ro, refs_ro, sizeof ro) == 0 && memcmp(rw, refs_rw, sizeof rw) == 0;
}

/* ---- RTKit ------------------------------------------------------------ */
static void rtkit_boot(void)
{
    uint64_t v[2], ctl = mmio_r(0, 0x8114);
    CHECK((ctl & 1) == 0 && (ctl >> 17 & 1));          /* disabled, empty */
    CHECK(!mmio_w(0, 0x8114, (ctl & ~1ULL) | 1));      /* _enableOutbox RMW */
    CHECK(mmio_r(0, 0x8110) == (1 | 1u << 17));        /* inbox enabled and empty */
    CHECK(!send(0x0060000000000220ULL, 0));            /* wakeQuiesced(false) */
    CHECK(mmio_r(0, 0x8114) == (1 | 1u << 20));
    CHECK(!recv(v));
    CHECK(v[0] == 0x00100000000c000cULL && (v[1] & 0xffffffff) == 0 && (v[1] >> 32 & 0xf00000) == 0x100000);
    CHECK(!send(0x00200003000c000cULL, 0));            /* HELLO reply, debugger flags */
    CHECK(!recv(v));
    CHECK(v[0] == (0x0080000000000000ULL | 1ULL << 51 | 1ULL << 32 | 1));
    CHECK(!send(0x0080000000000000ULL | 1ULL << 51 | 1ULL << 32, 0));  /* EPMAP reply */
    CHECK(!recv(v));
    CHECK(v[0] == 0x0070000000000020ULL);              /* power ack: status 8 */
    CHECK(s->iop == ANS_IOP_RUNNING);
    CHECK(!send(0x0050002000000002ULL, 0));            /* STARTEP 0x20 */
    CHECK(!send(0x00b0000000000020ULL, 0));            /* AP power ON */
    CHECK(!recv(v) && v[0] == 0x00b0000000000020ULL);
    CHECK(s->out_count == 0);
}

static void rtkit_negative(void)
{
    uint64_t v[2];
    reset_state();
    CHECK(recv(v) == ANS_E_MAILBOX);                    /* outbox disabled */
    CHECK(!mmio_w(0, 0x8114, 1));
    CHECK(recv(v) == ANS_E_MAILBOX);                    /* empty */
    CHECK(send(0x00200000000c000cULL, 0) == ANS_E_RTKIT); /* reply before HELLO */
    reset_state(); CHECK(!mmio_w(0, 0x8114, 1));
    CHECK(!send(0x0060000000000220ULL, 0)); CHECK(!recv(v));
    CHECK(send(0x00200000000b000bULL, 0) == ANS_E_RTKIT); /* wrong version */
    CHECK(send(0x0060000000000220ULL, 5) == ANS_E_ENDPOINT);
    CHECK(send(0x0060000000000220ULL, 0x20) == ANS_E_ENDPOINT); /* no app traffic */
    uint64_t bad[2] = {0x0060000000000220ULL, 1ULL << 40};
    CHECK(ans_mailbox_pair(s, &ops, 0x8800, 1, bad) == ANS_E_MAILBOX);
    CHECK(send(0x00f0000000000000ULL, 0) == ANS_E_RTKIT); /* unknown type */
    CHECK(send(0x0060000000000333ULL, 0) == ANS_E_RTKIT); /* unknown power state */
    CHECK(mmio_w(0, 0x8114, 1ULL << 19) == ANS_E_VALUE);  /* underflow flag is RO */
    CHECK(mmio_w(0, 0x8800, 0) == ANS_E_REGISTER);        /* scalar send unsupported */
    CHECK(mmio_w(0, 0x44, 0x10) == 0);                    /* _runCPU(true): idempotent */
    CHECK(mmio_w(0, 0x44, 0) == ANS_E_REGISTER);          /* _runCPU(false): not modeled */
    CHECK(mmio_w(0, 0x44, 0x30) == ANS_E_REGISTER);
    CHECK(mmio_r(0, 0x44) == 0x10);
    /* A burst: two messages, the snapshot counts 2 then 1 (getMailboxBulk). */
    reset_state(); rtkit_boot();
    CHECK(!send(0x00b0000000000020ULL, 0) && !send(0x00b0000000000201ULL, 0));
    CHECK(!recv(v) && (v[1] >> 52 & 0xf) == 2 && !recv(v) && (v[1] >> 52 & 0xf) == 1);
    /* Outbox overflow is a refusal, never a lost message. */
    for (int i = 0; i < ANS_OUTBOX; i++) CHECK(!send(0x0030000000000000ULL | i, 0));
    CHECK(send(0x0030000000000000ULL, 0) == ANS_E_MAILBOX);
    CHECK(mmio_r(0, 0x8114) >> 16 & 1);
    /* Sleep then wake: a fresh handshake, as RTBuddy expects (status 4). */
    reset_state(); rtkit_boot();
    CHECK(!send(0x0060000000000201ULL, 0) && !recv(v) && v[0] == 0x0070000000000201ULL);
    CHECK(s->iop == ANS_IOP_QUIESCED);
    CHECK(!send(0x0060000000000220ULL, 0) && !recv(v) && v[0] == 0x00100000000c000cULL);
}

/* ---- NVMe ------------------------------------------------------------- */
#if SNAP_ANS_ASYNC
static unsigned async_csts_polls;
#endif
static unsigned cid_next;
static int issue(unsigned qid, const uint32_t sqe_in[16], uint16_t dir, uint16_t nlb,
                 const uint64_t *pages, unsigned count, int unmap);
/* An admin command without data (Create/Delete I/O queue, Set Features). */
static int admin(uint32_t op, uint32_t cdw10, uint32_t cdw11, uint64_t prp1)
{
    uint32_t q[16] = {0};
    q[0] = op; q[6] = (uint32_t)prp1; q[7] = (uint32_t)(prp1 >> 32); q[10] = cdw10; q[11] = cdw11;
    return issue(0, q, 0, 0, 0, 0, 1);
}
/* AppleANS2CGv2Controller::EnableCompletionQueue(1) then EnableSubmissionQueues:
 * SPTM IOCQ_REG, Create I/O CQ 1 (65 entries, PC | IEN, vector 0), SPTM
 * IOSQ_REG, Create I/O SQ 1 (65 entries, PC, QPRIO 0, CQ 1). */
static void ioqueues_up(void)
{
    int e;
    sptm(6, 7, IOCQ, 0, 0, 0, 0, &e); CHECK(!e);
    CHECK(admin(0x05, 0x00400001, 0x3, IOCQ) == 0);
    sptm(6, 6, IOSQ, 0, 0, 0, 0, &e); CHECK(!e);
    CHECK(admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0);
    CHECK(s->ioq == (ANS_IOQ_CQ | ANS_IOQ_SQ | ANS_IOQ_IEN));
}
static void sptm_setup(void)
{
    int e;
    CHECK(sptm(6, 1, 0, 0, TPL, SEG, 0, &e) == 0 && e == ANS_E_SPTM_ORDER);  /* map before admin */
    s->refusal[0] = 0;
    sptm(6, 3, 64, 2, 0, 0, 0, &e); CHECK(!e);         /* InitializePCI */
    sptm(6, 4, ASQ, 63, ACQ, 63, 0, &e); CHECK(e == ANS_E_SPTM_ORDER); /* before CG */
    sptm(6, 0, 0, 0, 0, 0, 0, &e); CHECK(!e);          /* SetupAdminQueue: CG */
    CHECK(mmio_w(1, 0x14, 0x460001) == ANS_E_STATE);   /* CC.EN before AQA */
    sptm(6, 4, ASQ, 63, ACQ, 63, 0, &e); CHECK(!e);
    CHECK(mmio_r(1, 0x24) == 0x003f003f && mmio_r(1, 0x28) == (uint32_t)ASQ);
    sptm(6, 5, 64, 64, 0, 0, 0, &e); CHECK(!e);        /* SetupIOQARegister */
    CHECK(mmio_r(1, 0x1210) == 0x00400040);
    CHECK(mmio_r(1, 0x1300) == 0xde71ce55);            /* WaitDeviceActive */
    uint64_t cap = mmio_r(1, 0) | mmio_r(1, 4) << 32;
    CHECK((cap & 0xffff) == 0x40 && (cap >> 37 & 1) && !(cap >> 48 & 0xf));
    CHECK(!mmio_w(1, 0x14, 0)); CHECK((mmio_r(1, 0x1c) & 1) == 0);
    CHECK(!mmio_w(1, 0x1304, 0));                      /* PreCCEnableHook */
    CHECK(!mmio_w(1, 0x14, 0x460001)); CHECK(mmio_r(1, 0x1c) & 1);
    CHECK(!mmio_w(1, 0x13c8, 1));                      /* EnableAutoQueueManage */
}

/* One command through the driver's path: MAP_PAGES, SQE, doorbell, CQE, head,
 * UNMAP_PAGES. Returns the CQE status field, or -refusal. */
static int issue(unsigned qid, const uint32_t sqe_in[16], uint16_t dir, uint16_t nlb,
                 const uint64_t *pages, unsigned count, int unmap)
{
    unsigned cid = cid_next++ % 60;
    int e;
    uint8_t tpl[0x80] = {0};
    uint32_t sqe[16];
    memcpy(sqe, sqe_in, sizeof sqe);
    sqe[0] = (sqe[0] & 0xffff) | cid << 16;
    memcpy(tpl, sqe, 4);                               /* TCB: CDW0 | dir, NLB */
    tpl[1] |= (uint8_t)(dir >> 8); tpl[4] = (uint8_t)nlb; tpl[5] = (uint8_t)(nlb >> 8);
    memcpy(ram + TPL - RAM, tpl, sizeof tpl);
    for (unsigned i = 0; i < count; i++) wr(SEG + 8 * i, pages[i], 8);
    sptm(6, 1, qid, cid, TPL, SEG, count, &e);
    if (e) return -e;
    memcpy(ram + (qid ? IOSQ : ASQ) - RAM + cid * 64, sqe, 64);
    struct ans_cq *cq = &s->cq[qid];
    uint32_t slot = cq->tail, phase = cq->phase;
    e = mmio_w(1, qid ? 0x24910 : 0x2490c, cid);
    if (e) return -e;
#if SNAP_ANS_ASYNC
    /* agents/nvme-async N3, N4: with an asynchronous backend the doorbell only queues; the CQE and the level
     * come at a later poll point (here: CSTS reads, as a polling driver would make). */
    if (qid && s->cq[qid].tail == slot) {
        int lv[3]; ans_levels(s, lv); CHECK(lv[2] == 0);
        for (unsigned n = 0; s->cq[qid].tail == slot && n < 64; n++) {
            uint64_t v = 0; e = mmio(1, 0x1c, 0, &v);
            if (e) return -e;
            async_csts_polls++;
        }
        CHECK(s->cq[qid].tail != slot);
    }
#endif
    uint64_t base = qid ? IOCQ : ACQ;
    uint32_t dw3 = (uint32_t)rd(base + slot * 16 + 12, 4);
    CHECK((dw3 & 0xffff) == cid && (dw3 >> 16 & 1) == phase);
    int levels[3]; ans_levels(s, levels); CHECK(levels[2] == 1);
    CHECK(!mmio_w(1, qid ? 0x100c : 0x1004, cq->tail));
    ans_levels(s, levels); CHECK(levels[2] == 0);
    if (unmap) { CHECK(sptm(6, 2, qid, cid, 0, 0, 0, &e) == 1 && !e); }
    return (int)(dw3 >> 17);
}

static void nvme_flow(void)
{
    uint32_t q[16];
    uint64_t page = DATA;
    /* IONVMeController::IdentifyController: CNS 1, 4 KiB, device writes. */
    memset(q, 0, sizeof q); q[0] = 0x06; q[10] = 1;
    CHECK(issue(0, q, 0x100, 0, &page, 1, 1) == 0);
    CHECK(rd(DATA, 2) == 0x106b && ram[DATA - RAM + 0x4d] == ANS_MDTS && rd(DATA + 0x204, 4) == 1);
    CHECK(memcmp(ram + DATA - RAM + 0x18, "Snapintosh virtual ANS2", 23) == 0);
    CHECK(rd(DATA + 0xe06, 2) == 0);                   /* no NAND capacity: no NAND properties */
    /* DetermineNamespaces / GetDeviceProperties: CNS 0 NSID 1. */
    memset(q, 0, sizeof q); q[0] = 0x06; q[1] = 1;
    CHECK(issue(0, q, 0x100, 0, &page, 1, 1) == 0);
    CHECK(rd(DATA, 8) == DISK_BYTES / 4096 && ram[DATA - RAM + 0x82] == 12 && ram[DATA - RAM + 0x180] == 1);
    CHECK(rd(DATA + 0x78, 8) != 0);
    q[1] = 2;
    CHECK(issue(0, q, 0x100, 0, &page, 1, 1) == 0x0b); /* only namespace 1 */
    /* SetNumQueues(1,1) and other Set Features. */
    memset(q, 0, sizeof q); q[0] = 0x09; q[10] = 7;
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0);
    q[10] = 0x33; CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0x02);
    /* An Apple vendor opcode we do not implement: Invalid Opcode, not a stop. */
    memset(q, 0, sizeof q); q[0] = 0xc2;
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0x01);
    /* EnableCompletionQueue(1) then EnableSubmissionQueues. */
    int e;
    sptm(6, 6, IOSQ, 0, 0, 0, 0, &e); CHECK(e == ANS_E_SPTM_ORDER); /* IOSQ before IOCQ */
    s->refusal[0] = 0;
    ioqueues_up();
    sptm(6, 7, IOCQ + 0x1000, 0, 0, 0, 0, &e); CHECK(e == ANS_E_SPTM_ARG); /* cached */
    sptm(6, 7, IOCQ, 0, 0, 0, 0, &e); CHECK(!e);         /* same base: no second reference */
    CHECK(refs_explained());
    /* Read 8 blocks at LBA 1 into 8 aligned pages. */
    uint64_t pages[ANS_PRPS + 1];
    for (unsigned i = 0; i <= ANS_PRPS; i++) pages[i] = DATA + 0x1000 * i;
    memset(q, 0, sizeof q); q[0] = 0x02; q[1] = 1; q[10] = 1; q[12] = 7;
    CHECK(issue(1, q, 0x100, 7, pages, 8, 1) == 0);
    CHECK(memcmp(ram + DATA - RAM, disk + 4096, 8 * 4096) == 0);
    /* Unaligned first PRP: count = NLB + 2. */
    uint64_t un[3] = {DATA + 0x800, DATA + 0x1000, DATA + 0x2000};
    q[10] = 0; q[12] = 1;
    CHECK(issue(1, q, 0x100, 1, un, 3, 1) == 0);
    CHECK(memcmp(ram + DATA - RAM + 0x800, disk, 2 * 4096) == 0);
    /* Write 2 blocks at LBA 100 and read them back through the RAM disk. */
    memset(ram + DATA - RAM, 0xa5, 2 * 4096);
    memset(q, 0, sizeof q); q[0] = 0x01; q[1] = 1; q[10] = 100; q[12] = 1;
    CHECK(issue(1, q, 0x200, 1, pages, 2, 1) == 0);
    CHECK(disk[100 * 4096] == 0xa5 && disk[102 * 4096 - 1] == 0xa5 && disk[102 * 4096] != 0xa5);
    CHECK(s->counter[ANS_C_LBA_LOW] == 100 && s->counter[ANS_C_LBA_HIGH] == 101);
    /* Flush. */
    memset(q, 0, sizeof q); q[1] = 1;
    CHECK(issue(1, q, 0, 0, 0, 0, 1) == 0);
    /* Past the end: LBA Out of Range completion, nothing moved. */
    memset(q, 0, sizeof q); q[0] = 0x02; q[1] = 1; q[10] = (uint32_t)(DISK_BYTES / 4096 - 1); q[12] = 1;
    CHECK(issue(1, q, 0x100, 1, pages, 2, 1) == 0x80);
    q[10] = 0xffffffff; q[11] = 0xffffffff; q[12] = 0;
    CHECK(issue(1, q, 0x100, 0, pages, 1, 1) == 0x80);  /* no wrap */
    /* Refusals: SQE NLB disagrees with the SPTM TCB; read into RO pages; write
     * from pages mapped for device writes. Each leaves the cid mapped; unmap. */
    q[10] = 0; q[11] = 0; q[12] = 3;
    unsigned before = cid_next;
    CHECK(issue(1, q, 0x100, 1, pages, 2, 0) == -ANS_E_SQE);
    CHECK(sptm(6, 2, 1, before % 60, 0, 0, 0, &e) == 1 && !e);
    q[12] = 0;
    before = cid_next;
    CHECK(issue(1, q, 0x200, 0, pages, 1, 0) == -ANS_E_DIRECTION);
    CHECK(sptm(6, 2, 1, before % 60, 0, 0, 0, &e) == 1 && !e);
    /* SPTM MAP_PAGES argument checks (Apple 0x3000003/4/5/11). */
    CHECK(issue(1, q, 0x100, 0, pages, ANS_PRPS + 1, 1) == -ANS_E_SPTM_ARG);
    CHECK(issue(1, q, 0x100, 3, pages, 2, 1) == -ANS_E_SPTM_ARG);   /* NLB mismatch */
    uint64_t one_unaligned = DATA + 8;
    CHECK(issue(1, q, 0x100, 0, &one_unaligned, 1, 1) == -ANS_E_SPTM_ARG);
    uint64_t bad2[2] = {DATA, DATA + 0x1008};
    CHECK(issue(1, q, 0x100, 1, bad2, 2, 1) == -ANS_E_FRAME);
    uint64_t image = RAM + 0x1000;                   /* unmanaged frame */
    CHECK(issue(1, q, 0x100, 0, &image, 1, 1) == -ANS_E_FRAME);
    uint64_t outside = RAM + RAM_SIZE;
    CHECK(issue(1, q, 0x100, 0, &outside, 1, 1) == -ANS_E_FRAME);
    CHECK(issue(1, q, 0x300, 0, pages, 1, 1) == -ANS_E_DIRECTION);  /* tl-wa: both bits */
    /* Doorbells: unmapped cid, wrong queue, out-of-range cid. */
    CHECK(mmio_w(1, 0x24910, 61) == ANS_E_CID);
    CHECK(mmio_w(1, 0x24910, 64) == ANS_E_DOORBELL);
    CHECK(mmio_w(1, 0x1004, 64) == ANS_E_DOORBELL);   /* CQ head beyond the queue */
    /* Double map and double unmap (an empty template: no data). */
    memset(ram + TPL - RAM, 0, 0x80);
    sptm(6, 1, 1, 62, TPL, SEG, 0, &e); CHECK(!e);
    sptm(6, 1, 1, 62, TPL, SEG, 0, &e); CHECK(e == ANS_E_CID);
    sptm(6, 2, 0, 62, 0, 0, 0, &e); CHECK(e == ANS_E_CID);           /* other queue */
    CHECK(sptm(6, 2, 1, 62, 0, 0, 0, &e) == 1 && !e);
    sptm(6, 2, 1, 62, 0, 0, 0, &e); CHECK(e == ANS_E_CID);
    sptm(6, 2, 1, 1, 1, 0, 0, &e); CHECK(e == ANS_E_SPTM_ARG);       /* retry never offered */
    sptm(6, 9, 0, 0, 0, 0, 0, &e); CHECK(e == ANS_E_SPTM_ORDER);     /* linear: no SET_SQ_ENTRY */
    sptm(6, 8, 0, 0, 0, 0, 0, &e); CHECK(e == ANS_E_SPTM_ORDER);     /* no ANS SHA */
    /* CQ full: the driver never rings a head doorbell. */
    memset(ram + TPL - RAM, 0, 0x80);
    int full = 0;
    for (unsigned i = 0; i < 70 && !full; i++) {
        sptm(6, 1, 1, i % 60, TPL, SEG, 0, &e);
        uint32_t f[16] = {0}; f[0] = (i % 60) << 16; f[1] = 1;
        memcpy(ram + IOSQ - RAM + (i % 60) * 64, f, 64);
        e = mmio_w(1, 0x24910, i % 60);
        if (e) { full = e; break; }
        sptm(6, 2, 1, i % 60, 0, 0, 0, &e);
    }
    CHECK(full == ANS_E_CQ_FULL && (s->cq[1].tail + 1) % s->cq[1].size == s->cq[1].head);
    /* Every data reference was released; only the four queue pages hold one. */
    int rw = 0, ro = 0;
    for (unsigned i = 0; i < RAM_SIZE / 0x4000; i++) { rw += refs_rw[i]; ro += refs_ro[i]; }
    CHECK(ro == 0 && rw == 4 && refs_explained());
}

/* A command the model refuses at its doorbell leaves its command id mapped
 * (the run would stop there); release it as UNMAP_PAGES would. */
static int admin_refused(uint32_t op, uint32_t cdw10, uint32_t cdw11, uint64_t prp1)
{
    unsigned cid = cid_next % 60;
    int r = admin(op, cdw10, cdw11, prp1), e;
    if (r < 0) {
        CHECK(sptm(6, 2, 0, cid, 0, 0, 0, &e) == 1 && !e);
        s->refusal[0] = 0;
    }
    return r;
}
static int io_read(uint64_t lba, unsigned blocks, int unmap)
{
    uint64_t pages[ANS_PRPS];
    uint32_t q[16] = {0};
    for (unsigned i = 0; i < blocks; i++) pages[i] = DATA + 0x1000 * i;
    q[0] = 0x02; q[1] = 1; q[10] = (uint32_t)lba; q[11] = (uint32_t)(lba >> 32); q[12] = blocks - 1;
    return issue(1, q, 0x100, (uint16_t)(blocks - 1), pages, blocks, unmap);
}

/* Create/Delete I/O queue contract (IONVMeController::Enable*Queue,
 * Disable*Queue; NVMe status codes for what a controller answers, refusals for
 * what only a broken SPTM contract could send). */
static void ioqueue_contract(void)
{
    int e;
    uint64_t before;
    CHECK(s->ioq == 0);
    /* Create I/O CQ before the SPTM registered its memory: outside the contract. */
    CHECK(admin_refused(0x05, 0x00400001, 0x3, IOCQ) == -ANS_E_SQE);
    sptm(6, 7, IOCQ, 0, 0, 0, 0, &e); CHECK(!e);
    CHECK(admin(0x05, 0x00400002, 0x3, IOCQ) == 0x101);          /* only queue 1 */
    CHECK(admin(0x05, 0x00400000, 0x3, IOCQ) == 0x101);          /* 0 is the admin queue */
    CHECK(admin(0x05, 0x00400001, 0x2, IOCQ) == 0x02);           /* PC = 0 */
    CHECK(admin(0x05, 0x00400001, 0x00010003, IOCQ) == 0x108);   /* vector 1 */
    CHECK(admin(0x05, 0x00410001, 0x3, IOCQ) == 0x102);          /* 66 > MQES + 1 */
    CHECK(admin(0x05, 0x00000001, 0x3, IOCQ) == 0x102);          /* 1 entry */
    CHECK(admin_refused(0x05, 0x00200001, 0x3, IOCQ) == -ANS_E_SQE);      /* not IOQA's 65 */
    CHECK(admin_refused(0x05, 0x00400001, 0x3, IOCQ + 0x1000) == -ANS_E_SQE); /* not IOCQ_REG's */
    CHECK(admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0x100);   /* SQ before its CQ */
    CHECK(s->ioq == 0 && refs_explained());
    CHECK(admin(0x05, 0x00400001, 0x3, IOCQ) == 0);
    CHECK(s->ioq == (ANS_IOQ_CQ | ANS_IOQ_IEN));
    CHECK(admin(0x05, 0x00400001, 0x3, IOCQ) == 0x101);          /* exists */
    /* No I/O before the SQ exists. */
    before = cid_next;
    CHECK(io_read(0, 1, 1) == -ANS_E_DOORBELL);
    CHECK(sptm(6, 2, 1, before % 60, 0, 0, 0, &e) == 1 && !e); s->refusal[0] = 0;
    CHECK(admin(0x01, 0x00400001, 0x00020001, IOSQ) == 0x100);   /* CQ 2 */
    CHECK(admin_refused(0x01, 0x00400001, 0x00010001, IOSQ) == -ANS_E_SQE); /* before IOSQ_REG */
    sptm(6, 6, IOSQ, 0, 0, 0, 0, &e); CHECK(!e);
    CHECK(admin(0x01, 0x00400001, 0x00010000, IOSQ) == 0x02);    /* PC = 0 */
    CHECK(admin(0x01, 0x00400001, 0x00010005, IOSQ) == 0);       /* QPRIO 2 accepted */
    CHECK(admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0x101);
    CHECK(io_read(1, 1, 1) == 0 && memcmp(ram + DATA - RAM, disk + 4096, 4096) == 0);
    /* Delete: SQ first (NVMe), then CQ; nothing about the SPTM changes. */
    int refs = refs_total();
    CHECK(admin(0x04, 1, 0, 0) == 0x10c);                        /* CQ still has its SQ */
    CHECK(admin(0x00, 2, 0, 0) == 0x101);
    CHECK(admin(0x00, 1, 0, 0) == 0 && s->ioq == (ANS_IOQ_CQ | ANS_IOQ_IEN));
    CHECK(admin(0x00, 1, 0, 0) == 0x101);
    before = cid_next;
    CHECK(io_read(0, 1, 1) == -ANS_E_DOORBELL);
    CHECK(sptm(6, 2, 1, before % 60, 0, 0, 0, &e) == 1 && !e); s->refusal[0] = 0;
    CHECK(admin(0x04, 1, 0, 0) == 0 && s->ioq == 0);
    CHECK(admin(0x04, 1, 0, 0) == 0x101);
    CHECK(refs_total() == refs && s->iosq == IOSQ && s->iocq == IOCQ && refs_explained());
    /* Created again on the same SPTM bases: no new reference. */
    CHECK(admin(0x05, 0x00400001, 0x1, IOCQ) == 0);              /* IEN clear this time */
    CHECK(admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0 && refs_total() == refs);
    /* CQ 1 without IEN posts completions but raises no interrupt. */
    unsigned cid = cid_next % 60;
    uint8_t tpl[0x80] = {0}; tpl[1] = 1;
    uint32_t q[16] = {0};
    memcpy(ram + TPL - RAM, tpl, sizeof tpl); wr(SEG, DATA, 8);
    sptm(6, 1, 1, cid, TPL, SEG, 1, &e); CHECK(!e);
    q[0] = 0x02 | cid << 16; q[1] = 1; memcpy(ram + IOSQ - RAM + cid * 64, q, 64);
    CHECK(!mmio_w(1, 0x24910, cid));
    int levels[3]; ans_levels(s, levels);
    CHECK(s->cq[1].tail == 1 && levels[2] == 0);
    CHECK(!mmio_w(1, 0x100c, 1) && sptm(6, 2, 1, cid, 0, 0, 0, &e) == 1 && !e);
    cid_next++;
    /* Controller reset deletes the I/O queues; every SPTM reference stays. */
    CHECK(!mmio_w(1, 0x14, 0) && s->ioq == 0 && refs_total() == refs && refs_explained());
    CHECK(!mmio_w(1, 0x14, 0x460001));
    CHECK(admin(0x05, 0x00400001, 0x3, IOCQ) == 0 && admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0);
    /* Diagnostics: an unimplemented opcode is named, the last status kept. */
    CHECK(admin(0xc2, 0x1234, 0, 0) == 0x01);
    CHECK(s->bad_opcode[0][3] == 1ULL << 2 && !s->bad_opcode[1][0]);
    CHECK(s->last_status == ((uint64_t)1 << 48 | (uint64_t)0xc2 << 32 | 0x1234));
    CHECK(s->refusal[0] == 0 && refs_explained());
}

/* The 2026-09-25 A16 run (ans-m2-fw-300s-20260925), command by command, on
 * that run's frame layout: ASQ 0x...6f0000, I/O CQ 0x...6fc000, ACQ
 * 0x...700000 (the three frames its audit found with one extra reference);
 * the I/O SQ, never registered there, in 0x...6f8000. AQA and IOQA 0x400040
 * (65 entries), CC 0x460001. There: SQ[2] Create I/O CQ answered Invalid
 * Opcode twice and the driver gave up. Here it completes, the I/O SQ follows
 * and a read reaches the disk. */
static void replay_20260925(void)
{
    int e;
    uint64_t page = DATA;
    reset_state();
    layout(RAM + 0x6f0000, RAM + 0x700000, RAM + 0x6f8000, RAM + 0x6fc000);
    rtkit_boot();
    sptm(6, 3, 64, 2, 0, 0, 0, &e); CHECK(!e);                   /* InitializePCI */
    sptm(6, 0, 0, 0, 0, 0, 0, &e); CHECK(!e);                    /* ENABLE_CG */
    CHECK(!mmio_w(1, 0x14, 0));                                  /* EnableController: EN 0 */
    sptm(6, 4, ASQ, 0x40, ACQ, 0x40, 0, &e); CHECK(!e);          /* SetupAdminQueue */
    sptm(6, 5, 0x40, 0x40, 0, 0, 0, &e); CHECK(!e);              /* SetupIOQARegister */
    CHECK(mmio_r(1, 0x24) == 0x00400040 && mmio_r(1, 0x1210) == 0x00400040);
    CHECK(!mmio_w(1, 0x1304, 0) && !mmio_w(1, 0x14, 0x460001) && (mmio_r(1, 0x1c) & 1));
    CHECK(!mmio_w(1, 0x13c8, 1));
    cid_next = 0;
    uint32_t q[16] = {0};
    q[0] = 0x06; q[10] = 1;                                      /* SQ[0] Identify CNS 1 */
    CHECK(issue(0, q, 0x100, 0, &page, 1, 1) == 0);
    memset(q, 0, sizeof q); q[0] = 0x09; q[10] = 7;              /* SQ[1] SetNumQueues(1, 1) */
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0);
    CHECK(rd(ACQ + 16, 4) == 0);                                 /* DW0: NSQA = NCQA = 0 */
    sptm(6, 7, IOCQ, 0, 0, 0, 0, &e); CHECK(!e);                 /* IOCQ_REG */
    CHECK(admin(0x05, 0x00400001, 0x3, IOCQ) == 0);              /* SQ[2] Create I/O CQ, cid 2 */
    CHECK((uint32_t)rd(ACQ + 2 * 16 + 12, 4) == (2u | 1u << 16)); /* cid 2, phase 1, status 0 */
    sptm(6, 6, IOSQ, 0, 0, 0, 0, &e); CHECK(!e);                 /* IOSQ_REG */
    CHECK(admin(0x01, 0x00400001, 0x00010001, IOSQ) == 0);       /* SQ[3] Create I/O SQ */
    CHECK(io_read(1, 1, 1) == 0 && memcmp(ram + DATA - RAM, disk + 4096, 4096) == 0);
    CHECK(s->counter[ANS_C_ADMIN] == 4 && s->counter[ANS_C_IO] == 1 && s->counter[ANS_C_READS] == 1);
    CHECK(s->counter[ANS_C_STATUS_ERRORS] == 0 && s->counter[ANS_C_INVALID_OPCODE] == 0);
    CHECK(s->counter[ANS_C_MAPPED] == 5 && s->counter[ANS_C_UNMAPPED] == 5);
    CHECK(s->counter[ANS_C_SPTM6] == 4 + 2 + 10 && s->counter[ANS_C_REFUSALS] == 0);
    /* INIT, ENABLE_CG, ADMIN_QUEUE_REGS, IOQA_REG; IOCQ_REG, IOSQ_REG; a MAP/UNMAP
     * pair per command (the A16 run: 13 = 5 + 4 pairs, then it stopped).
     * Held now: one writable reference on each queue frame, as Apple's SPTM. */
    CHECK(refs_total() == 4 && refs_explained());
    const uint64_t f[4] = {ASQ, IOCQ, ACQ, IOSQ};
    for (unsigned i = 0; i < 4; i++) CHECK(refs_rw[(f[i] - RAM) / 0x4000] == 1);
}

/* Teardown and failure after the replay. ShutdownNVMe: Delete I/O SQ, Delete
 * I/O CQ, SendShutdownNotification (CC.SHN), then EnableController's EN 0.
 * A failing bring-up (a command answered with an error, the driver gives up,
 * UninitializeController -> DeleteAllQueues frees the queue memory) makes no
 * SPTM call either. Either way every command's pages are released by its
 * UNMAP_PAGES, a still-mapped command id's pages by a later UNMAP_PAGES even
 * after the reset, SART regions by UNMAP_REGION; what remains are the four
 * queue bases, which Apple's SPTM also keeps for the boot (no table-6
 * endpoint releases them) and which the audit counts from the state. */
static void teardown(void)
{
    int e;
    /* A read whose pages are still mapped when the controller goes down. */
    unsigned cid = cid_next % 60;
    CHECK(io_read(2, 4, 0) == 0 && s->cid[cid].state == 3 && refs_total() == 4 + 4);
    CHECK(admin(0x00, 1, 0, 0) == 0);                            /* DisableSubmissionQueues */
    CHECK(admin(0x04, 1, 0, 0) == 0 && s->ioq == 0);             /* DisableCompletionQueue(1) */
    CHECK(!mmio_w(1, 0x14, 0x464001) && (mmio_r(1, 0x1c) >> 2 & 3) == 2); /* SHN normal */
    CHECK(!mmio_w(1, 0x14, 0) && (mmio_r(1, 0x1c) & 1) == 0);   /* EN 0 */
    CHECK(refs_total() == 8 && refs_explained());               /* the SPTM saw neither */
    CHECK(sptm(6, 2, 1, cid, 0, 0, 0, &e) == 1 && !e);           /* its UNMAP_PAGES */
    CHECK(refs_total() == 4 && refs_explained());
    /* A tunnel buffer in SART and its release. */
    sptm(5, 0, 1, 0, 0, 0, 0, &e); CHECK(!e);
    sptm(5, 1, TUNNEL, 0x8000, 1, 0, 0, &e); CHECK(!e && refs_total() == 6 && refs_explained());
    sptm(5, 2, TUNNEL, 0x8000, 0, 0, 0, &e); CHECK(!e && refs_total() == 4);
    sptm(5, 0, 0, 0, 0, 0, 0, &e); CHECK(!e && refs_total() == 4);   /* SET_STATE: none */
    /* The failed bring-up of the A16 run: re-enable, Create I/O CQ answered
     * with an error (here: a vector the driver never asks for), retried once
     * with the same command id, then the driver's teardown. */
    CHECK(!mmio_w(1, 0x14, 0x460001));
    CHECK(admin(0x05, 0x00400001, 0x00010003, IOCQ) == 0x108);
    CHECK(admin(0x05, 0x00400001, 0x00010003, IOCQ) == 0x108);
    CHECK(!mmio_w(1, 0x14, 0));
    CHECK(s->ioq == 0 && s->counter[ANS_C_MAPPED] == s->counter[ANS_C_UNMAPPED]);
    for (unsigned c = 0; c < ANS_CIDS; c++) CHECK(s->cid[c].state == 0);
    CHECK(refs_total() == 4 && refs_explained() && s->counter[ANS_C_REFUSALS] == 0);
    /* INIT again takes and releases nothing; the bases stay registered. */
    sptm(6, 3, 64, 2, 0, 0, 0, &e); CHECK(!e && refs_total() == 4 && s->asq == ASQ);
}

/* DMA frame-type admission (review must-fix): Apple's SPTM gates every queue
 * base and MAP_PAGES page through ...ef64c against the type descriptor's DMA
 * limit (table ...9e230, byte +0x30, read from sptm.t8140.release):
 *   2 (write): 0 11 17 26 36-40;  1 (read): 14 15 16 28;
 *   0 (none):  every other type, including ROZONE 25, COMMPAGE 29-31 and
 *              KERNEL_RESTRICTED 35, which sptm_refs_dart alone would count.
 * The monitor admits the DART data-leaf subset: XNU_DEFAULT, clear metadata. */
static void dma_frames(void)
{
    uint8_t e[16];
    for (unsigned type = 0; type < 256; type++) {
        memset(e, 0, sizeof e); e[2] = (uint8_t)type;
        CHECK(ans_dma_frame(e) == (type == 11));
    }
    static const uint8_t no_dma[] = {7, 13, 20, 21, 22, 23, 24, 25, 27, 29, 30, 31, 35};
    for (unsigned i = 0; i < sizeof no_dma; i++) {
        memset(e, 0, sizeof e); e[2] = no_dma[i]; CHECK(!ans_dma_frame(e));
    }
    for (unsigned b = 0; b < 16; b++) {
        if (b == 2) continue;
        memset(e, 0, sizeof e); e[2] = 11; e[b] = 0x7f;
        /* busy (+0/+1) and other state (+3..+7) refuse; reference counts
         * (+8/+12, as for a frame already mapped or DMA-referenced) do not */
        CHECK(ans_dma_frame(e) == (b >= 8));
        e[b] = 0x80;
        CHECK(ans_dma_frame(e) == (b >= 8 && b != 11 && b != 15));
    }

    /* Through the model: each refusal takes no reference and leaks none. */
    int e2, before = refs_total();
    s->refusal[0] = 0;                                  /* setup's order checks */
    uint64_t rozone = DATA + 0x4000, commpage = DATA + 0x8000, restricted = DATA + 0xc000;
    meta(rozone)[2] = 25; meta(commpage)[2] = 30; meta(restricted)[2] = 35;
    uint8_t tpl[0x80] = {0}; tpl[1] = 1;               /* device writes, NLB 1 */
    tpl[4] = 1;
    memcpy(ram + TPL - RAM, tpl, sizeof tpl);
    uint64_t bad[3] = {rozone, commpage, restricted};
    for (unsigned i = 0; i < 3; i++) {
        wr(SEG, DATA, 8); wr(SEG + 8, bad[i], 8);      /* second page refused */
        sptm(6, 1, 1, 40, TPL, SEG, 2, &e2);
        CHECK(e2 == ANS_E_FRAME && s->cid[40].state == 0 && refs_total() == before);
        CHECK(s->refusal[0] == ANS_E_FRAME && s->refusal[1] == bad[i]); s->refusal[0] = 0;
        tpl[1] = 2; memcpy(ram + TPL - RAM, tpl, sizeof tpl);  /* device reads too */
        sptm(6, 1, 1, 40, TPL, SEG, 2, &e2);
        CHECK(e2 == ANS_E_FRAME && refs_total() == before); s->refusal[0] = 0;
        tpl[1] = 1; memcpy(ram + TPL - RAM, tpl, sizeof tpl);
    }
    meta(DATA + 0x10000)[0] = 1;                        /* busy XNU_DEFAULT frame */
    wr(SEG + 8, DATA + 0x10000, 8);
    sptm(6, 1, 1, 40, TPL, SEG, 2, &e2); CHECK(e2 == ANS_E_FRAME && refs_total() == before);
    s->refusal[0] = 0; meta(DATA + 0x10000)[0] = 0;
    meta(DATA + 0x14000)[15] = 0x80;                    /* write count overflowed */
    wr(SEG + 8, DATA + 0x14000, 8);
    sptm(6, 1, 1, 40, TPL, SEG, 2, &e2); CHECK(e2 == ANS_E_FRAME && refs_total() == before);
    s->refusal[0] = 0; meta(DATA + 0x14000)[15] = 0;
    /* The same command on DEFAULT frames maps; its release never re-checks,
     * so a held reference is always dropped. */
    wr(SEG + 8, DATA + 0x1000, 8);
    sptm(6, 1, 1, 40, TPL, SEG, 2, &e2); CHECK(!e2 && refs_total() == before + 2);
    meta(DATA)[5] = 1;
    CHECK(sptm(6, 2, 1, 40, 0, 0, 0, &e2) == 1 && !e2 && refs_total() == before);
    meta(DATA)[5] = 0;
    /* Queue bases: the IOCQ in a COMMPAGE frame is refused and not cached. */
    sptm(6, 7, commpage, 0, 0, 0, 0, &e2);
    CHECK(e2 == ANS_E_FRAME && !s->iocq && refs_total() == before); s->refusal[0] = 0;
    sptm(6, 6, IOSQ, 0, 0, 0, 0, &e2); CHECK(e2 == ANS_E_SPTM_ORDER); s->refusal[0] = 0;
    /* SART: a 48 KiB region whose last frame is KERNEL_RESTRICTED releases the
     * two frames it had admitted. */
    sptm(5, 0, 1, 0, 0, 0, 0, &e2); CHECK(!e2);
    meta(DATA + 0x20000)[2] = 35;
    sptm(5, 1, DATA + 0x18000, 0xc000, 1, 0, 0, &e2);
    CHECK(e2 == ANS_E_FRAME && s->refusal[1] == DATA + 0x20000 && refs_total() == before);
    CHECK(s->sart[0].size == 0); s->refusal[0] = 0;
    sptm(5, 1, rozone, 0x4000, 0, 0, 0, &e2); CHECK(e2 == ANS_E_FRAME && refs_total() == before);
    s->refusal[0] = 0;
    meta(rozone)[2] = meta(commpage)[2] = meta(restricted)[2] = ANS_DMA_FRAME_TYPE;
    meta(DATA + 0x20000)[2] = ANS_DMA_FRAME_TYPE;
    sptm(5, 1, rozone, 0xc000, 1, 0, 0, &e2); CHECK(!e2 && refs_total() == before + 3);
    sptm(5, 2, rozone, 0xc000, 0, 0, 0, &e2); CHECK(!e2 && refs_total() == before);
    sptm(6, 7, IOCQ, 0, 0, 0, 0, &e2); CHECK(!e2 && s->iocq == IOCQ && refs_total() == before + 1);
}

static void interrupts(void)
{
    uint32_t q[16] = {0};
    uint64_t page = DATA;
    int levels[3];
    q[0] = 0x06; q[10] = 1;
    CHECK(!mmio_w(1, 0x0c, 1));                         /* FilterInterruptRequest masks */
    unsigned cid = cid_next++ % 60; int e;
    uint8_t tpl[0x80] = {0}; tpl[1] = 1;
    memcpy(ram + TPL - RAM, tpl, sizeof tpl); wr(SEG, page, 8);
    sptm(6, 1, 0, cid, TPL, SEG, 1, &e); CHECK(!e);
    q[0] |= cid << 16; memcpy(ram + ASQ - RAM + cid * 64, q, 64);
    CHECK(!mmio_w(1, 0x2490c, cid));
    ans_levels(s, levels); CHECK(levels[2] == 0);       /* masked */
    CHECK(!mmio_w(1, 0x10, 1));                         /* INTMC */
    ans_levels(s, levels); CHECK(levels[2] == 1);
    CHECK(!mmio_w(1, 0x1004, s->cq[0].tail));
    ans_levels(s, levels); CHECK(levels[2] == 0 && levels[0] == 1);
    CHECK(sptm(6, 2, 0, cid, 0, 0, 0, &e) == 1 && !e);
}

static int tunnel_attempt(uint32_t q[16])
{
    int r = issue(0, q, 0, 0, 0, 0, 1), e;
    if (r < 0) {
        s->refusal[0] = 0;
        sptm(6, 2, 0, (cid_next - 1) % 60, 0, 0, 0, &e); CHECK(!e);
    }
    return r;
}

static void tunnel(void)
{
    uint32_t q[16] = {0};
    int e;
    /* ProcessTunnelCommand before the buffer is in SART: refused. */
    q[0] = 0xd8; q[10] = 1; q[11] = (uint32_t)TUNNEL; q[12] = (uint32_t)(TUNNEL >> 32);
    wr(TUNNEL + 0xc, 6, 4); wr(TUNNEL + 0x4c, 0x77, 4);
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == -ANS_E_SART);
    s->refusal[0] = 0;
    sptm(6, 2, 0, (cid_next - 1) % 60, 0, 0, 0, &e); CHECK(e == 0);
    /* _setMapperActive(1), then sart_map of the 16 KiB tunnel buffer (perm 1). */
    sptm(5, 0, 1, 0, 0, 0, 0, &e); CHECK(!e && s->sart_active);
    sptm(5, 1, TUNNEL, 0x4000, 1, 0, 0, &e); CHECK(!e);
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0);
    CHECK(rd(TUNNEL + 0x4c, 4) == 0);                   /* CORE_DEBUG_SET_TIME ok */
    wr(TUNNEL + 0xc, 0x120, 4);                         /* OS build string */
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0 && rd(TUNNEL + 0x4c, 4) == 0);
    wr(TUNNEL + 0xc, 0x999, 4);                         /* unknown: tunnel status 1 */
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == 0 && rd(TUNNEL + 0x4c, 4) == 1);
    /* Captured native GetSanitizeCounters (generation18): registered1MiB
     * second buffer, no PRPs. Before the fix, the valid request stops the
     * monitor. Invalid shapes must still stop before changing either buffer;
     * the supported transport returns a nonzero diagnostic result, never
     * invented NAND counters. This is written before the model change. */
    uint64_t stats = RAM + 0x500000;
    memset(ram + stats - RAM, 0xa5, 1 << 20);
    q[13] = (uint32_t)stats; q[14] = (uint32_t)(stats >> 32); q[15] = 1 << 20;
    wr(TUNNEL + 0xc, 0xd, 4); wr(TUNNEL + 0x4c, 0x77, 4);
    CHECK(tunnel_attempt(q) == -ANS_E_SART);           /* no data SART mapping */
    sptm(5, 1, stats, 1 << 20, 0, 0, 0, &e); CHECK(!e);
    CHECK(tunnel_attempt(q) == -ANS_E_SART);           /* read-only data mapping */
    sptm(5, 2, stats, 1 << 20, 0, 0, 0, &e); CHECK(!e);
    sptm(5, 1, stats, 1 << 20, 1, 0, 0, &e); CHECK(!e);
    CHECK(tunnel_attempt(q) == 0 && rd(TUNNEL + 0x4c, 4) == 1);
    CHECK(refs_explained());
    for (unsigned bad = 0; bad < 5; bad++) {
        uint32_t saved[16]; memcpy(saved, q, sizeof q);
        wr(TUNNEL + 0x4c, 0x77, 4);
        if (bad == 0) q[15] += 4096;                  /* oversized */
        if (bad == 1) q[13] += 4096;                  /* crosses mapped end */
        if (bad == 2) q[10] = 2;                      /* wrong direction */
        if (bad == 3) { q[13] = (uint32_t)TUNNEL; q[14] = (uint32_t)(TUNNEL >> 32); }
        if (bad == 4) wr(TUNNEL + 0xc, 6, 4);         /* other data-bearing subcommand */
        CHECK(tunnel_attempt(q) == -ANS_E_SART && rd(TUNNEL + 0x4c, 4) == 0x77);
        memcpy(q, saved, sizeof q); wr(TUNNEL + 0xc, 0xd, 4);
    }
    CHECK(!s->counter[ANS_C_WRITES]);
    for (unsigned i = 0; i < 1 << 20; i++) if (ram[stats - RAM + i] != 0xa5) { CHECK(0); break; }
    sptm(5, 2, stats, 1 << 20, 0, 0, 0, &e); CHECK(!e && refs_explained());
    q[13] = q[14] = q[15] = 0;
    q[11] = (uint32_t)(TUNNEL + 0x3800);                /* runs past the region */
    CHECK(issue(0, q, 0, 0, 0, 0, 1) == -ANS_E_SART);
    s->refusal[0] = 0;
    sptm(6, 2, 0, (cid_next - 1) % 60, 0, 0, 0, &e);
    /* SART bounds. */
    sptm(5, 1, TUNNEL + 8, 0x4000, 1, 0, 0, &e); CHECK(e == ANS_E_SART);
    sptm(5, 1, TUNNEL + 0x1000, 0x4000, 1, 0, 0, &e); CHECK(e == ANS_E_SART); /* 4 KiB base */
    sptm(5, 1, TUNNEL, 0x1000, 1, 0, 0, &e); CHECK(e == ANS_E_SART);          /* 4 KiB size */
    sptm(5, 1, TUNNEL, 0x6000, 1, 0, 0, &e); CHECK(e == ANS_E_SART);
    sptm(5, 1, RAM, 0x4000, 1, 0, 0, &e); CHECK(e == ANS_E_FRAME);            /* unmanaged */
    sptm(5, 1, RAM + RAM_SIZE - 0x1000, 0x2000, 1, 0, 0, &e); CHECK(e == ANS_E_SART);
    sptm(5, 1, TUNNEL, 0x4000, 2, 0, 0, &e); CHECK(e == ANS_E_SART);
    sptm(5, 2, TUNNEL, 0x2000, 0, 0, 0, &e); CHECK(e == ANS_E_SART);   /* not exact */
    sptm(5, 2, TUNNEL, 0x4000, 0, 0, 0, &e); CHECK(!e);
    int rw = 0;
    for (unsigned i = 0; i < RAM_SIZE / 0x4000; i++) rw += refs_rw[i];
    CHECK(rw == 2);                                     /* ASQ and ACQ (one frame) */
    sptm(5, 3, 0, 0, 0, 0, 0, &e); CHECK(e == ANS_E_SART);
}

static void mmio_negative(void)
{
    uint64_t v = 0;
    CHECK(ans_mmio(s, &ops, 1, 0x14, 8, 0, &v) == ANS_E_WIDTH);
    CHECK(ans_mmio(s, &ops, 1, 0x15, 4, 0, &v) == ANS_E_WIDTH);
    CHECK(mmio(1, 0x24008, 0, &v) == ANS_E_REGISTER);   /* not in the secure contract */
    CHECK(mmio_w(1, 0x24, 0) == ANS_E_REGISTER);        /* AQA belongs to the SPTM */
    CHECK(mmio_w(1, 0x1000, 0) == ANS_E_REGISTER);      /* standard SQ doorbell unused */
    CHECK(mmio_w(1, 0x14, 1u << 1) == ANS_E_VALUE);
    CHECK(mmio_w(1, 0x1304, 7) == ANS_E_VALUE);
    CHECK(mmio(2, 0, 0, &v) == ANS_E_REGISTER);
    /* Shutdown notification completes immediately. */
    CHECK(!mmio_w(1, 0x14, 0x464001) && (mmio_r(1, 0x1c) >> 2 & 3) == 2);
}

/* Random traffic: only completions or refusals; canaries outside the
 * admitted pages never change (ASan/UBSan catch host-side memory errors).
 * Half the operations are raw (any register, message, SPTM call or SQE); the
 * other half are well-formed driver steps -- admin Create/Delete I/O queue and
 * Set Features with valid or random fields, reads and writes on I/O queue 1,
 * controller resets, CQ head doorbells -- so queue creation, deletion and reset
 * interleave with mapped commands. Throughout, every DMA reference held is one
 * the state names (the audit's check). */
static void fuzz(void)
{
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    uint8_t canary[4096];
    unsigned created = 0, deleted = 0, last_ioq = s->ioq;
    memset(canary, 0x5c, sizeof canary);
    memcpy(ram + RAM_SIZE - 4096, canary, 4096);
    for (unsigned n = 0; n < 200000; n++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        uint64_t r = seed, v = r >> 20, x[6] = {0}, ret;
        unsigned kind = r & 15;
        if (kind == 8 || kind == 9) {               /* admin: queues, features, vendor */
            static const uint32_t op[] = {0x00, 0x01, 0x04, 0x05, 0x09, 0xc2};
            static const uint32_t cdw11[] = {0x3, 0x1, 0x00010001, 0x00010005, 0x2};
            unsigned cid = r >> 5 & 63;
            uint32_t q[16] = {0};
            memset(ram + TPL - RAM, 0, 0x80);
            x[1] = cid; x[2] = TPL; x[3] = SEG; ans_sptm(s, &ops, 6, 1, x, &ret);
            uint32_t o = op[(r >> 11) % 6];
            int good = (r >> 16 & 3) != 0;          /* the driver's own fields */
            uint64_t prp = good ? (o == 0x05 ? IOCQ : IOSQ) : (r >> 26 & 1) ? IOCQ + 0x1000 :
                           RAM + (r >> 28 & 0x7ff) * 0x1000;
            q[0] = o | cid << 16; q[6] = (uint32_t)prp; q[7] = (uint32_t)(prp >> 32);
            q[10] = good ? (o == 0x00 || o == 0x04 ? 1 : 0x00400001) :
                    (r >> 14 & 1) ? (uint32_t)(r >> 32) : 0x00200001 + (uint32_t)(r >> 24 & 1);
            q[11] = good ? (o == 0x05 ? 0x3 : o == 0x01 ? 0x00010001 : 7) :
                    (r >> 18 & 7) < 5 ? cdw11[r >> 18 & 7] : (uint32_t)(r >> 40);
            memcpy(ram + ASQ - RAM + cid * 64, q, 64);
            ans_mmio(s, &ops, 1, 0x2490c, 4, 1, &(uint64_t){cid});
            ans_mmio(s, &ops, 1, 0x1004, 4, 1, &(uint64_t){s->cq[0].tail});
            if (r >> 20 & 7) { x[0] = 0; x[1] = cid; ans_sptm(s, &ops, 6, 2, x, &ret); }
        } else if (kind >= 10 && kind <= 12) {      /* I/O on queue 1 */
            unsigned cid = r >> 5 & 63, blocks = 1 + (r >> 11 & 7), write = r >> 14 & 1;
            uint8_t tpl[0x80] = {0};
            uint32_t q[16] = {0};
            uint64_t lba = r >> 15 & 0x3fff;
            tpl[1] = write ? 2 : 1; tpl[4] = (uint8_t)(blocks - 1);
            memcpy(ram + TPL - RAM, tpl, sizeof tpl);
            for (unsigned i = 0; i < blocks; i++) wr(SEG + 8 * i, DATA + 0x1000 * i, 8);
            x[0] = 1; x[1] = cid; x[2] = TPL; x[3] = SEG; x[4] = blocks;
            ans_sptm(s, &ops, 6, 1, x, &ret);
            q[0] = (write ? 0x01 : 0x02) | cid << 16; q[1] = 1; q[10] = (uint32_t)lba; q[12] = blocks - 1;
            memcpy(ram + IOSQ - RAM + cid * 64, q, 64);
            ans_mmio(s, &ops, 1, 0x24910, 4, 1, &(uint64_t){cid});
            if (s->cq[1].size) ans_mmio(s, &ops, 1, 0x100c, 4, 1, &(uint64_t){s->cq[1].tail});
            if (r >> 30 & 7) { x[0] = 1; x[1] = cid; ans_sptm(s, &ops, 6, 2, x, &ret); }
        } else if (kind == 13) {                    /* reset now and then, else enable */
            ans_mmio(s, &ops, 1, 0x14, 4, 1, &(uint64_t){(r >> 5 & 15) ? 0x460001 : 0});
        } else if (kind >= 14) {                    /* CQ heads catch up */
            ans_mmio(s, &ops, 1, 0x1004, 4, 1, &(uint64_t){s->cq[0].tail});
            if (s->cq[1].size) ans_mmio(s, &ops, 1, 0x100c, 4, 1, &(uint64_t){s->cq[1].tail});
        } else
        if (kind == 0) { ans_mmio(s, &ops, r >> 3 & 1, (r >> 4 & 0x3ffff) & ~3ULL, 4, r >> 30 & 1, &v); }
        else if (kind == 1) { uint64_t m[2] = {v << 20 | (r & 0xfffff), r >> 60};
            ans_mailbox_pair(s, &ops, r & 8 ? 0x8800 : 0x8830, r >> 4 & 1, m); }
        else if (kind == 2) { x[0] = r >> 3 & 1; x[1] = r >> 4 & 63; x[2] = TPL; x[3] = SEG; x[4] = r >> 10 & 3;
            wr(SEG, DATA + (r >> 12 & 0xff) * 0x1000, 8); wr(TPL, r >> 20, 8);
            ans_sptm(s, &ops, 6, 1, x, &ret); }
        else if (kind == 3) { x[0] = r >> 3 & 1; x[1] = r >> 4 & 63; ans_sptm(s, &ops, 6, 2, x, &ret); }
        else if (kind == 4) { uint32_t q[16]; for (unsigned i = 0; i < 16; i++) q[i] = (uint32_t)(seed >> (i % 32));
            unsigned cid = r >> 5 & 63; q[0] = (q[0] & 0xff) | cid << 16;
            memcpy(ram + (r & 8 ? IOSQ : ASQ) - RAM + cid * 64, q, 64);
            ans_mmio(s, &ops, 1, r & 8 ? 0x24910 : 0x2490c, 4, 1, &(uint64_t){cid}); }
        else if (kind == 5) { ans_mmio(s, &ops, 1, r & 8 ? 0x100c : 0x1004, 4, 1, &(uint64_t){r >> 20 & 0x7f}); }
        else if (kind == 6) { x[0] = (RAM + (r >> 8 & 0x7ff) * 0x1000) | (r & 0x800); x[1] = (r >> 20 & 7) * 0x1000;
            x[2] = r >> 24 & 1; ans_sptm(s, &ops, 5, r >> 3 & 3, x, &ret); }
        else { x[0] = v; x[1] = r >> 40; ans_sptm(s, &ops, r >> 3 & 1 ? 6 : 5, r >> 4 & 15, x, &ret); }
        CHECK(s->out_count <= ANS_OUTBOX && s->cq[0].tail < 256 && s->cq[1].tail < 256);
        CHECK(!(s->ioq & ~7u) && (!(s->ioq & ANS_IOQ_SQ) || (s->ioq & ANS_IOQ_CQ)));
        created += (s->ioq & 3) == 3 && (last_ioq & 3) != 3;
        deleted += (s->ioq & 3) != 3 && (last_ioq & 3) == 3;
        last_ioq = s->ioq;
        if (n % 997 == 0) CHECK(refs_explained());
        if (failures) break;
    }
    CHECK(memcmp(ram + RAM_SIZE - 4096, canary, 4096) == 0);
    CHECK(refs_explained());
    /* The structured half reached every transition and moved data. */
    CHECK(created > 10 && deleted > 10 && s->counter[ANS_C_READS] > 100 && s->counter[ANS_C_WRITES] > 100);
    for (unsigned i = 0; i < RAM_SIZE / 0x4000; i++) CHECK(refs_ro[i] >= 0 && refs_rw[i] >= 0);
}

/* Window mode (full-install M6): a read comes from the backend at the guest's own LBA and block
 * count and lands in the guest pages; a backend failure is a media error; a write is refused
 * Namespace Write Protected without reaching the backend or counting as a write. */
static uint64_t window_lba, window_n, window_calls;
static int window_fail;
static uint8_t window_buf[1 << 20];
static uint64_t window_writes, window_flushes;
static int window_prepare_status, window_write_fail, window_flush_fail;
static int window_write_buffer(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data)
{
    (void)ctx;
    window_lba = lba; window_n = n;
    if (window_prepare_status) return window_prepare_status;
    *data = window_buf;
    return 0;
}
static int window_write(void *ctx, uint64_t lba, uint64_t n)
{
    (void)ctx;
    CHECK(lba == window_lba && n == window_n);
    CHECK(memcmp(window_buf, ram + DATA - RAM, n * 4096) == 0);
    window_writes++;
    return window_write_fail;
}
static int window_flush(void *ctx)
{
    (void)ctx;
    window_flushes++;
    return window_flush_fail;
}
static int window_read(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data)
{
    (void)ctx;
    window_lba = lba; window_n = n; window_calls++;
    if (window_fail) return 1;
    for (uint64_t i = 0; i < n * 4096; i++) window_buf[i] = (uint8_t)(lba * 7 + i / 4096 * 3 + i);
    *data = window_buf;
    return 0;
}
static void window_mode(void)
{
    ops.disk_read = window_read;
    CHECK(io_read(3, 2, 1) == 0 && window_lba == 3 && window_n == 2);
    CHECK(memcmp(ram + DATA - RAM, window_buf, 2 * 4096) == 0);
    window_fail = 1;
    CHECK(io_read(4, 1, 1) == 0x281);                            /* Unrecovered Read Error */
    window_fail = 0;
    uint64_t calls = window_calls, writes = s->counter[ANS_C_WRITES], page = DATA;
    uint32_t q[16] = {0};
    q[0] = 0x01; q[1] = 1; q[10] = 5;                            /* Write, 1 block at LBA 5 */
    CHECK(issue(1, q, 0x200, 0, &page, 1, 1) == 0x20);           /* Namespace Write Protected */
    CHECK(window_calls == calls && s->counter[ANS_C_WRITES] == writes);
    CHECK((s->last_status >> 48) == 0x20 && ((s->last_status >> 32) & 0xff) == 0x01);
    /* M7 inventory: every admitted byte must reach the private buffer before commit;
     * rejected preparation and failed persistence may not report write/flush success. */
    ops.disk_write_buffer = window_write_buffer; ops.disk_write = window_write;
    ops.disk_flush = window_flush;
    memset(ram + DATA - RAM, 0xac, 4096);
    window_prepare_status = 0x20;
    CHECK(issue(1, q, 0x200, 0, &page, 1, 1) == 0x20 && !window_writes);
    window_prepare_status = 0;
    CHECK(issue(1, q, 0x200, 0, &page, 1, 1) == 0 && window_writes == 1);
    CHECK(s->counter[ANS_C_WRITES] == writes + 1 && window_calls == calls);
    window_write_fail = 1;
    CHECK(issue(1, q, 0x200, 0, &page, 1, 1) == 0x280);
    CHECK(s->counter[ANS_C_WRITES] == writes + 1);
    window_write_fail = 0;
    memset(q, 0, sizeof q); q[1] = 1;
    uint64_t flushes = s->counter[ANS_C_FLUSHES];
    window_flush_fail = 1;
    CHECK(issue(1, q, 0, 0, 0, 0, 1) == 0x280 && window_flushes == 1);
    CHECK(s->counter[ANS_C_FLUSHES] == flushes);
    window_flush_fail = 0;
    CHECK(issue(1, q, 0, 0, 0, 0, 1) == 0 && window_flushes == 2);
    CHECK(s->counter[ANS_C_FLUSHES] == flushes + 1);
    /* Native type1 publishes1MiB even when Identify MDTS is smaller. Protect
     * full scattered/unaligned PRP admission and exact release: the old34-slot
     * state refuses these real driver-sized transfers before the backend. */
    uint64_t pages[257];
    for (unsigned i = 0; i < 257; i++) pages[i] = DATA + (uint64_t)i * 8192;
    pages[0] += 512;
    memset(q, 0, sizeof q); q[0] = 2; q[1] = 1; q[10] = 512; q[12] = 255;
    int full_result = issue(1, q, 0x100, 255, pages, 257, 1);
    CHECK(full_result == 0);
    if (!full_result) {
        size_t offset = 0;
        for (unsigned i = 0; i < 257; i++) {
            size_t length = i == 0 ? 3584 : i == 256 ? 512 : 4096;
            CHECK(!memcmp(ram + pages[i] - RAM, window_buf + offset, length));
            offset += length;
        }
        CHECK(offset == sizeof window_buf && refs_explained());
        /* The same1MiB write must be staged in stream order despite gaps. */
        q[0] = 1;
        ops.disk_write = 0; /* read-only still refuses before any commit */
        CHECK(issue(1, q, 0x200, 255, pages, 257, 1) == 0x20);
        ops.disk_write = window_write;
        /* window_write compares contiguous input; populate it with the same stream. */
        memcpy(ram + DATA - RAM, window_buf, sizeof window_buf);
        for (unsigned i = 0; i < 256; i++) pages[i] = DATA + (uint64_t)i * 4096;
        CHECK(issue(1, q, 0x200, 255, pages, 256, 1) == 0);
        CHECK(refs_explained());
    } else s->refusal[0] = 0;
    ops.disk_read = 0;
    ops.disk_write_buffer = 0; ops.disk_write = 0; ops.disk_flush = 0;
}

#if SNAP_ANS_ASYNC
/* ---- SNAP_ANS_ASYNC (agents/nvme-async/FAILURE-MODES.md) ---------------
 * An asynchronous fake of the window backend: disk_start latches the request,
 * disk_poll answers PENDING `latency` times and then runs the synchronous fake
 * (window_read/window_write/window_flush) and returns its result. */
static unsigned async_latency = 2, async_left, async_op, async_inflight, async_starts, async_quiesces;
static uint64_t async_lba, async_n;
static int async_start_fail;
static int async_start(void *ctx, unsigned op, uint64_t lba, uint64_t n)
{
    (void)ctx;
    CHECK(!async_inflight);
    if (async_start_fail) return 1;
    async_op = op; async_lba = lba; async_n = n; async_left = async_latency; async_inflight = 1; async_starts++;
    return ANS_ASYNC_PENDING;
}
/* The synchronous backend under the asynchronous one: window_mode()'s fakes, or the RAM disk (the replay, the
 * fuzz pass). */
static int (*async_read)(void *, uint64_t, uint64_t, volatile uint8_t **) = window_read;
static int (*async_write)(void *, uint64_t, uint64_t) = window_write;
static int (*async_flush)(void *) = window_flush;
static unsigned async_jitter;                      /* latency varies 0..2 polls per command when set */
static int async_poll(void *ctx, volatile uint8_t **data)
{
    CHECK(async_inflight);
    if (async_left) { async_left--; return ANS_ASYNC_PENDING; }
    async_inflight = 0;
    if (async_jitter) async_latency = async_jitter++ % 3;
    return async_op == 2 ? async_read(ctx, async_lba, async_n, data) :
           async_op == 1 ? async_write(ctx, async_lba, async_n) : async_flush(ctx);
}
static int ramdisk_read(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data)
{
    (void)ctx; memcpy(window_buf, disk + lba * 4096, n * 4096); *data = window_buf; return 0;
}
static int ramdisk_buffer(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data)
{
    (void)ctx; (void)lba; (void)n; *data = window_buf; return 0;
}
static int ramdisk_write(void *ctx, uint64_t lba, uint64_t n)
{
    (void)ctx; memcpy(disk + lba * 4096, window_buf, n * 4096); return 0;
}
static int ramdisk_flush(void *ctx) { (void)ctx; return 0; }
static void async_quiesce(void *ctx) { (void)ctx; async_inflight = 0; async_quiesces++; }
static void async_ops(int on)
{
    ops.disk_start = on ? async_start : 0; ops.disk_poll = on ? async_poll : 0;
    ops.disk_quiesce = on ? async_quiesce : 0;
    async_inflight = 0;
}
static void window_ops(int on)
{
    ops.disk_read = on ? window_read : 0;
    ops.disk_write_buffer = on ? window_write_buffer : 0; ops.disk_write = on ? window_write : 0;
    ops.disk_flush = on ? window_flush : 0;
}
#if SNAP_ANS_CONVERTED
/* The converted batch (N9): all or nothing on the fake reference counts, the type rule per page. */
static int frame_refs(void *ctx, const uint64_t *pa, unsigned n, int writable, int release)
{
    (void)ctx;
    int *r = writable ? refs_rw : refs_ro;
    static int need[RAM_SIZE / 0x4000];
    memset(need, 0, sizeof need);
    for (unsigned i = 0; i < n; i++) {
        if (pa[i] < RAM + UNMANAGED || pa[i] >= RAM + RAM_SIZE) return 1;
        uint64_t f = (pa[i] - RAM) / 0x4000;
        if (!release && !ans_dma_frame(frame_map[f])) return 1;
        if (release && ++need[f] > r[f]) return 1;
    }
    for (unsigned i = 0; i < n; i++) r[(pa[i] - RAM) / 0x4000] += release ? -1 : 1;
    return 0;
}
static uint64_t sptm_cv(unsigned ep, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, int *err)
{
    uint64_t x[6] = {a, b, c, d, e, 0}, ret = ~0ULL;
    *err = ans_sptm_converted(s, &ops, ep, x, &ret);
    return ret;
}
#endif
/* The driver's steps one at a time: MAP_PAGES and the SQE (returns the CID), the doorbell, the CQ. */
static unsigned prepare(const uint32_t sqe_in[16], uint16_t dir, uint16_t nlb, const uint64_t *pages, unsigned count)
{
    unsigned cid = cid_next++ % 60;
    int e;
    uint8_t tpl[0x80] = {0};
    uint32_t sqe[16];
    memcpy(sqe, sqe_in, sizeof sqe);
    sqe[0] = (sqe[0] & 0xffff) | cid << 16;
    memcpy(tpl, sqe, 4);
    tpl[1] |= (uint8_t)(dir >> 8); tpl[4] = (uint8_t)nlb; tpl[5] = (uint8_t)(nlb >> 8);
    memcpy(ram + TPL - RAM, tpl, sizeof tpl);
    for (unsigned i = 0; i < count; i++) wr(SEG + 8 * i, pages[i], 8);
    sptm(6, 1, 1, cid, TPL, SEG, count, &e);
    CHECK(!e);
    memcpy(ram + IOSQ - RAM + cid * 64, sqe, 64);
    return cid;
}
static unsigned read_cmd(uint64_t lba, unsigned blocks, uint64_t data)
{
    uint64_t pages[ANS_PRPS];
    uint32_t q[16] = {0};
    for (unsigned i = 0; i < blocks; i++) pages[i] = data + 0x1000 * i;
    q[0] = 0x02; q[1] = 1; q[10] = (uint32_t)lba; q[12] = blocks - 1;
    return prepare(q, 0x100, (uint16_t)(blocks - 1), pages, blocks);
}
static uint32_t cqe(uint32_t slot) { return (uint32_t)rd(IOCQ + slot * 16 + 12, 4); }
static int level_nvme(void) { int lv[3]; ans_levels(s, lv); return lv[2]; }
static uint8_t expect(uint64_t lba, uint64_t i) { return (uint8_t)(lba * 7 + i / 4096 * 3 + i); }
static void consume(void) { CHECK(!mmio_w(1, 0x100c, s->cq[1].tail)); }
static void unmap(unsigned cid) { int e; CHECK(sptm(6, 2, 1, cid, 0, 0, 0, &e) == 1 && !e); }
static void fresh(void)
{
    reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up();
    window_ops(1); async_ops(1); async_latency = 2; async_start_fail = 0;
    window_fail = window_write_fail = window_flush_fail = window_prepare_status = 0;
    s->refusal[0] = 0;                                         /* sptm_setup's deliberate order refusals */
}
/* The same command sequence (window_mode's) synchronous and asynchronous: the same statuses, the same state
 * outside the async block, the same guest memory (N7). */
static void async_differential(void)
{
    static uint8_t ram_sync[RAM_SIZE];
    static struct ans_state st_sync;
    static int ro_sync[RAM_SIZE / 0x4000], rw_sync[RAM_SIZE / 0x4000];
    unsigned cid0 = cid_next;
    reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up(); async_ops(0);
    window_writes = window_flushes = 0;
    window_mode();
    memcpy(ram_sync, ram, RAM_SIZE); memcpy(&st_sync, s, sizeof st_sync);
    memcpy(ro_sync, refs_ro, sizeof ro_sync); memcpy(rw_sync, refs_rw, sizeof rw_sync);
    for (unsigned lat = 0; lat < 4; lat++) {
        cid_next = cid0;
        reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up();
        window_writes = window_flushes = 0;
        async_ops(1); async_latency = lat;
        unsigned polls = async_csts_polls;
        window_mode();
        async_ops(0);
        CHECK(!memcmp(ram, ram_sync, RAM_SIZE));
        /* The CSTS polls of issue()'s wait are MMIO accesses the synchronous run did not make. */
        CHECK(s->counter[ANS_C_MMIO] >= st_sync.counter[ANS_C_MMIO]);
        s->counter[ANS_C_MMIO] = st_sync.counter[ANS_C_MMIO];
        CHECK(!memcmp(s, &st_sync, offsetof(struct ans_state, async)));
        CHECK(!memcmp(refs_ro, ro_sync, sizeof ro_sync) && !memcmp(refs_rw, rw_sync, sizeof rw_sync));
        CHECK(s->async.counter[ANS_A_QUEUED] == s->async.counter[ANS_A_COMPLETED] && !s->async.count);
        CHECK(lat == 0 || async_csts_polls - polls >= lat);
    }
}
/* The A16 replay, the teardown after it and the fuzz pass through the asynchronous path over the RAM disk: the
 * replay's exact counters, data and references hold; the fuzz pass keeps its invariants, and after a drain every
 * queued command completed and every reference is explained. */
static void async_replay_and_fuzz(void)
{
    async_read = ramdisk_read; async_write = ramdisk_write; async_flush = ramdisk_flush;
    ops.disk_read = ramdisk_read; ops.disk_write_buffer = ramdisk_buffer; ops.disk_write = ramdisk_write;
    ops.disk_flush = ramdisk_flush;
    async_ops(1); async_latency = 2;
    replay_20260925();
    async_ops(1); async_latency = 2;
    teardown();
    layout(RAM + 0x100000, RAM + 0x101000, RAM + 0x102000, RAM + 0x103000);
    reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up();
    async_ops(1); async_jitter = 1;
    fuzz();
    CHECK(!ans_async_drain(s, &ops) || s->refusal[0]);
    if (!s->async.active && !s->async.count)
        CHECK(s->async.counter[ANS_A_QUEUED] == s->async.counter[ANS_A_COMPLETED]);
    CHECK(refs_explained());
    CHECK(s->async.counter[ANS_A_COMPLETED] > 1000 && s->async.counter[ANS_A_PHYSICAL] > 1000);
    async_jitter = 0;
    async_read = window_read; async_write = window_write; async_flush = window_flush;
    async_ops(0); window_ops(0);
}
static void async_scenarios(void)
{
    int e;
    /* N3, N4: three reads rung back to back with the backend slow: nothing posted at the doorbells, the
     * level low; then CQEs in doorbell order, each after its data, the level up; a CQ head write lowers it. */
    fresh(); async_latency = 3;
    unsigned a = read_cmd(10, 2, DATA), b = read_cmd(20, 1, DATA + 0x10000), c = read_cmd(30, 4, DATA + 0x20000);
    uint32_t t0 = s->cq[1].tail;
    CHECK(!mmio_w(1, 0x24910, a) && !mmio_w(1, 0x24910, b) && !mmio_w(1, 0x24910, c));
    CHECK(s->cq[1].tail == t0 && !level_nvme() && s->async.count == 2 && s->async.active);
    unsigned polls = 0;
    while (s->cq[1].tail != (t0 + 3) % s->cq[1].size && polls < 64) { mmio_r(1, 0x1c); polls++; }
    CHECK(s->cq[1].tail == (t0 + 3) % s->cq[1].size && level_nvme());
    CHECK((cqe(t0) & 0xffff) == a && (cqe(t0 + 1) & 0xffff) == b && (cqe(t0 + 2) & 0xffff) == c);
    CHECK(ram[DATA - RAM + 5] == expect(10, 5) && ram[DATA + 0x10000 - RAM + 7] == expect(20, 7) &&
          ram[DATA + 0x20000 - RAM + 3 * 4096 + 9] == expect(30, 3 * 4096 + 9));
    consume(); CHECK(!level_nvme());
    unmap(a); unmap(b); unmap(c); CHECK(refs_explained());
    /* INTMS masks the posted completion's level. */
    a = read_cmd(11, 1, DATA); CHECK(!mmio_w(1, 0x24910, a));
    CHECK(!mmio_w(1, 0x0c, 1));
    while (s->async.active) mmio_r(1, 0x1c);
    CHECK(!level_nvme()); CHECK(!mmio_w(1, 0x10, 1)); CHECK(level_nvme());
    consume(); unmap(a);
    /* N1: UNMAP_PAGES of a queued and of an in-service CID completes them first (data, CQE), then releases. */
    async_latency = 50;
    a = read_cmd(40, 1, DATA); b = read_cmd(41, 1, DATA + 0x10000);
    t0 = s->cq[1].tail;
    CHECK(!mmio_w(1, 0x24910, a) && !mmio_w(1, 0x24910, b));
    CHECK(sptm(6, 2, 1, b, 0, 0, 0, &e) == 1 && !e);          /* b queued: drains a and b */
    CHECK(s->cq[1].tail == (t0 + 2) % s->cq[1].size && !s->async.active && !s->async.count);
    CHECK((cqe(t0 + 1) & 0xffff) == b && ram[DATA + 0x10000 - RAM + 1] == expect(41, 1));
    CHECK(s->async.counter[ANS_A_DRAINS] >= 1 && s->async.counter[ANS_A_DRAINED] == 2);
    unmap(a); consume(); CHECK(refs_explained());
    /* N4, N8: an admin doorbell, a CC shutdown and an IOP power-down message drain queue 1 first. */
    a = read_cmd(42, 1, DATA); CHECK(!mmio_w(1, 0x24910, a)); CHECK(s->async.active);
    {   /* Set Features behind queued I/O: when its doorbell returns, the I/O CQE is posted, then its own. */
        unsigned acid = cid_next++ % 60;
        uint8_t tpl[0x80] = {0};
        memcpy(ram + TPL - RAM, tpl, sizeof tpl);
        sptm(6, 1, 0, acid, TPL, SEG, 0, &e); CHECK(!e);
        uint32_t q[16] = {0}; q[0] = 0x09 | acid << 16; q[10] = 7;
        memcpy(ram + ASQ - RAM + acid * 64, q, 64);
        t0 = s->cq[1].tail; uint32_t at0 = s->cq[0].tail;
        CHECK(!mmio_w(1, 0x2490c, acid));
        CHECK(!s->async.active && s->cq[1].tail == (t0 + 1) % s->cq[1].size &&
              s->cq[0].tail == (at0 + 1) % s->cq[0].size);
        CHECK(!mmio_w(1, 0x1004, s->cq[0].tail));
        CHECK(sptm(6, 2, 0, acid, 0, 0, 0, &e) == 1 && !e);
    }
    consume(); unmap(a);
    a = read_cmd(43, 1, DATA); b = read_cmd(44, 1, DATA + 0x10000);
    CHECK(!mmio_w(1, 0x24910, a) && !mmio_w(1, 0x24910, b));
    CHECK(!mmio_w(1, 0x14, 0x464001));                         /* CC.SHN normal */
    CHECK(!s->async.active && !s->async.count && (mmio_r(1, 0x1c) & 0xc) == 8);
    consume(); unmap(a); unmap(b);
    CHECK(!mmio_w(1, 0x14, 0x460001));
    fresh(); async_latency = 50;
    a = read_cmd(45, 1, DATA); CHECK(!mmio_w(1, 0x24910, a)); CHECK(s->async.active);
    CHECK(!send(0x0030000000000000ULL, 0) && s->async.active);    /* a ping only polls */
    uint64_t pv[2]; CHECK(!recv(pv));
    CHECK(!send(0x0060000000000201ULL, 0) && !s->async.active);   /* IOP power-down after the I/O */
    consume(); unmap(a);
    /* N13: a re-ring of a queued CID runs twice (two CQEs); the FIFO overflow is a refusal, once. */
    fresh(); async_latency = 1;
    a = read_cmd(46, 1, DATA); t0 = s->cq[1].tail;
    CHECK(!mmio_w(1, 0x24910, a) && !mmio_w(1, 0x24910, a));
    while (s->async.active || s->async.count) mmio_r(1, 0x1c);
    CHECK(s->cq[1].tail == (t0 + 2) % s->cq[1].size && s->async.counter[ANS_A_REQUEUED] == 1);
    consume();
    async_latency = 1000000;
    for (unsigned i = 0; i < ANS_ASYNC_FIFO + 1; i++) CHECK(!mmio_w(1, 0x24910, a));
    unsigned refusals = (unsigned)s->counter[ANS_C_REFUSALS];
    e = mmio_w(1, 0x24910, a);
    CHECK(e == ANS_E_DOORBELL && s->refusal[0] == ANS_E_DOORBELL);
    CHECK(s->counter[ANS_C_REFUSALS] == refusals + 1);
    /* N6: the stop reaps the command in flight and abandons the rest, posting nothing. */
    uint32_t tail = s->cq[1].tail; unsigned quiesces = async_quiesces;
    ans_async_stop(s, &ops);
    CHECK(async_quiesces == quiesces + 1 && s->cq[1].tail == tail && !s->async.active && !s->async.count);
    CHECK(s->async.counter[ANS_A_ABANDONED] == ANS_ASYNC_FIFO + 1);
    /* N14: the doorbell's own refusals keep their timing (NLB/TCB mismatch: refused, nothing queued). */
    fresh();
    uint64_t pg = DATA; uint32_t r[16] = {0};
    r[0] = 0x02; r[1] = 1; r[12] = 3;                          /* 4 blocks, the TCB says 1 */
    a = prepare(r, 0x100, 0, &pg, 1);
    unsigned queued = (unsigned)s->async.counter[ANS_A_QUEUED];
    CHECK(mmio_w(1, 0x24910, a) == ANS_E_SQE && s->async.counter[ANS_A_QUEUED] == queued);
    /* ... and a refusal found at completion (a data page no longer maps) is returned by the poll, once. */
    fresh();
    a = read_cmd(47, 1, DATA); CHECK(!mmio_w(1, 0x24910, a));
    s->cid[a].prp[0] = RAM + RAM_SIZE;                          /* what a broken map would answer */
    e = 0; for (unsigned i = 0; i < 8 && !e; i++) { uint64_t v; e = mmio(1, 0x1c, 0, &v); }
    CHECK(e == ANS_E_ADDRESS && s->refusal[0] == ANS_E_ADDRESS && !s->async.active);
    /* N4: a CQ that is full when the completion is posted is refused there. */
    fresh(); async_latency = 0;
    unsigned size = s->cq[1].size;
    for (unsigned i = 0; i + 1 < size; i++) {
        a = read_cmd(50 + i, 1, DATA); CHECK(!mmio_w(1, 0x24910, a));
        while (s->async.active) mmio_r(1, 0x1c);
        unmap(a);
    }
    a = read_cmd(49, 1, DATA); CHECK(!mmio_w(1, 0x24910, a));
    e = 0; for (unsigned i = 0; i < 8 && !e; i++) { uint64_t v; e = mmio(1, 0x1c, 0, &v); }
    CHECK(e == ANS_E_CQ_FULL);
    /* N5: failures map as the synchronous path does. */
    fresh();
    window_fail = 1; CHECK(io_read(60, 1, 1) == 0x281); window_fail = 0;
    async_start_fail = 1; CHECK(io_read(61, 1, 1) == 0x281); async_start_fail = 0;
    uint64_t page = DATA; uint32_t w[16] = {0}; w[0] = 0x01; w[1] = 1; w[10] = 5;
    window_write_fail = 1; CHECK(issue(1, w, 0x200, 0, &page, 1, 1) == 0x280); window_write_fail = 0;
    uint32_t f[16] = {0}; f[1] = 1;
    window_flush_fail = 1; CHECK(issue(1, f, 0, 0, 0, 0, 1) == 0x280); window_flush_fail = 0;
    CHECK(issue(1, f, 0, 0, 0, 0, 1) == 0 && refs_explained());
    /* N10: one progress call outside a drain posts at most ANS_ASYNC_STEP_MAX completions. */
    fresh(); async_latency = 1000000;
    a = read_cmd(70, 1, DATA); CHECK(!mmio_w(1, 0x24910, a));
    uint32_t bad[16] = {0}; bad[0] = 0xc7; bad[1] = 1;           /* invalid opcodes: status only */
    unsigned k[4];
    for (unsigned i = 0; i < 4; i++) { k[i] = prepare(bad, 0, 0, 0, 0); CHECK(!mmio_w(1, 0x24910, k[i])); }
    async_left = 0; t0 = s->cq[1].tail;
    CHECK(!ans_async_progress(s, &ops, ANS_ASYNC_STEP_MAX));
    CHECK(s->cq[1].tail == (t0 + ANS_ASYNC_STEP_MAX) % s->cq[1].size && s->async.count == 5 - ANS_ASYNC_STEP_MAX);
    CHECK(!ans_async_drain(s, &ops) && s->cq[1].tail == (t0 + 5) % s->cq[1].size);
    CHECK(((cqe(t0 + 1) >> 17) & 0xff) == 0x01);                  /* Invalid Opcode, in order */
    consume(); unmap(a); for (unsigned i = 0; i < 4; i++) unmap(k[i]);
    CHECK(refs_explained());
#if SNAP_ANS_CONVERTED
    /* N9: the converted MAP/UNMAP_PAGES. A success equals the token path's; any refusal of the token path
     * declines with nothing changed; an UNMAP of a busy CID declines BUSY; the progress runs first. */
    fresh(); ops.frame_refs = frame_refs;
    static struct ans_state before; static int ro0[RAM_SIZE / 0x4000], rw0[RAM_SIZE / 0x4000];
    uint64_t pages[4] = {DATA, DATA + 0x1000, DATA + 0x4000, DATA + 0x8000};
    uint8_t tpl[0x80] = {0}; tpl[1] = 0x01; tpl[4] = 3;           /* dir 0x100, NLB 3 */
    memcpy(ram + TPL - RAM, tpl, sizeof tpl);
    for (unsigned i = 0; i < 4; i++) wr(SEG + 8 * i, pages[i], 8);
    memcpy(&before, s, sizeof before); memcpy(ro0, refs_ro, sizeof ro0); memcpy(rw0, refs_rw, sizeof rw0);
    meta(DATA + 0x8000)[2] = 25;                                  /* page 3's frame: ROZONE */
    CHECK(sptm_cv(1, 1, 5, TPL, SEG, 4, &e) == 0 && e == ANS_DECLINE);
    CHECK(!memcmp(refs_ro, ro0, sizeof ro0) && !memcmp(refs_rw, rw0, sizeof rw0));
    CHECK(s->cid[5].state == 0 && s->counter[ANS_C_SPTM6] == before.counter[ANS_C_SPTM6] && !s->refusal[0]);
    sptm(6, 1, 1, 5, TPL, SEG, 4, &e); CHECK(e == ANS_E_FRAME);   /* the token path's own refusal */
    s->refusal[0] = 0;
    meta(DATA + 0x8000)[2] = ANS_DMA_FRAME_TYPE;
    memcpy(&before, s, sizeof before);
    CHECK(sptm_cv(1, 1, 5, TPL, SEG, 4, &e) == 0 && !e && refs_explained());
    struct ans_cid token_cid;
    {   /* the token path's MAP_PAGES of the same arguments, on a copy */
        static struct ans_state copy; memcpy(&copy, &before, sizeof copy);
        int saved_ro[RAM_SIZE / 0x4000], saved_rw[RAM_SIZE / 0x4000];
        memcpy(saved_ro, refs_ro, sizeof saved_ro); memcpy(saved_rw, refs_rw, sizeof saved_rw);
        uint64_t x[6] = {1, 5, TPL, SEG, 4, 0}, ret;
        CHECK(!ans_sptm(&copy, &ops, 6, 1, x, &ret));
        token_cid = copy.cid[5];
        CHECK(!memcmp(&copy.counter, &s->counter, sizeof copy.counter));
        memcpy(refs_ro, saved_ro, sizeof saved_ro); memcpy(refs_rw, saved_rw, sizeof saved_rw);
    }
    CHECK(!memcmp(&token_cid, &s->cid[5], sizeof token_cid));
    memcpy(ram + IOSQ - RAM + 5 * 64, (uint32_t[16]){0x02 | 5u << 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 90, 0, 3}, 64);
    async_latency = 1000000;
    CHECK(!mmio_w(1, 0x24910, 5));
    memcpy(&before, s, sizeof before); memcpy(ro0, refs_ro, sizeof ro0); memcpy(rw0, refs_rw, sizeof rw0);
    CHECK(sptm_cv(2, 1, 5, 0, 0, 0, &e) == 0 && e == ANS_DECLINE_BUSY);
    CHECK(s->cid[5].state == 3 && !memcmp(refs_rw, rw0, sizeof rw0));
    async_left = 0;                                               /* completed: the progress posts it first */
    CHECK(sptm_cv(2, 1, 5, 0, 0, 0, &e) == 1 && !e && s->cid[5].state == 0 && refs_explained());
    CHECK(!s->async.active && (cqe(s->cq[1].tail ? s->cq[1].tail - 1 : s->cq[1].size - 1) & 0xffff) == 5);
    CHECK(ram[DATA - RAM + 4096 + 3] == expect(90, 4096 + 3));
    CHECK(sptm_cv(2, 1, 5, 0, 0, 0, &e) == 0 && e == ANS_DECLINE);       /* not mapped: the token path refuses */
    CHECK(sptm_cv(3, 64, 2, 0, 0, 0, &e) == 0 && e == ANS_DECLINE);      /* other endpoints: not converted */
    consume();
    ops.frame_refs = 0;
#endif
    async_ops(0); window_ops(0);
}
#endif

int main(void)
{
    ram = aligned_alloc(0x4000, RAM_SIZE);
    s = aligned_alloc(0x4000, ANS_DISK_OFFSET + DISK_BYTES);
    CHECK(ram && s && sizeof(struct ans_state) <= ANS_STATE_BYTES);
    disk = (uint8_t *)s + ANS_DISK_OFFSET;
    for (uint64_t i = 0; i < DISK_BYTES; i++) disk[i] = (uint8_t)(i * 131 + (i >> 12));
    rtkit_negative();
    reset_state(); rtkit_boot(); sptm_setup(); nvme_flow();
    reset_state(); rtkit_boot(); sptm_setup(); interrupts(); tunnel(); mmio_negative();
    reset_state(); rtkit_boot(); sptm_setup(); dma_frames();
    reset_state(); rtkit_boot(); sptm_setup(); ioqueue_contract();
    replay_20260925(); teardown();
    layout(RAM + 0x100000, RAM + 0x101000, RAM + 0x102000, RAM + 0x103000);
    reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up(); fuzz();
    reset_state(); rtkit_boot(); sptm_setup(); ioqueues_up(); window_mode();
#if SNAP_ANS_ASYNC
    {
        int before = failures, n0 = checks;
        async_differential();
        async_scenarios();
        async_replay_and_fuzz();
        printf("test-ans async: %d checks, %d failures, %u CSTS polls\n", checks - n0, failures - before,
               async_csts_polls);
    }
#endif
    printf("test-ans: %d checks, %d failures, %u publishes\n", checks, failures, publishes);
    free(ram); free(s);
    return failures != 0;
}
