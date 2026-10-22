/* SPDX-License-Identifier: MIT */
/* Virtual ANS2: the monitor answers Apple's own ANS2 storage stack
 * (AppleASCWrapV6 -> RTBuddy -> AppleANS3CGv2Controller -> IONVMeFamily) on the
 * stock /arm-io/ans node, with a RAM backend in a monitor-private reservation.
 * Evidence (26A428, docs/ANS2-M2-20260925.md):
 *  - ASC mailbox (AppleASCWrapV6, KDK slice = kernelcache UUID ac0625c2): inbox
 *    control +0x8110, outbox control +0x8114 (enable bit0, full bit16, empty
 *    bit17, count 23:20), send STP +0x8800, receive LDP +0x8830. getMailboxBulk
 *    stops at the message whose snapshot word (bits 63:32 of the second word)
 *    carries count 1; RTBuddy dispatches on the low 32 bits (endpoint).
 *  - RTKit management (RTBuddyManagementEndpoint): HELLO type 1 with
 *    min <= 12 <= max, EPMAP type 8 (group 37:32, last bit 51), power ack type 7
 *    low byte 0x20 = running (status 8), AP power type 0xb echoed.
 *  - SPTM table 6 (sptm.t8140.release 0x...c763c..c9c08) and table 5 (kernel
 *    sart_ioctl/sart_map/sart_unmap), validated as Apple's SPTM does.
 *  - NVMe BAR (IONVMeFamily): CAP/VS/CC/CSTS/INTMS/INTMC, boot status 0x1300,
 *    linear SQ doorbells 0x2490c/0x24910 written with the command id, CQ head
 *    doorbells 0x1004/0x100c, SQEs at base + cid*64, 16-byte CQEs.
 *  - I/O queue 1 (IONVMeController::InitializeNVMe): the SPTM registers the
 *    queue memory first (IOCQ_REG/IOSQ_REG, AppleANS2CGv2Controller::Enable*
 *    Queue), then the admin Create I/O CQ (0x05) / SQ (0x01) name the same
 *    bases (BuildCommandCreateCQ/SQ); Delete I/O SQ (0x00) / CQ (0x04) on
 *    shutdown. The SPTM never releases a queue base (no table-6 endpoint does),
 *    so neither does the model: see docs/ANS2-QUEUES-20260925.md.
 * Nothing here reaches a physical device. Every guest-reachable input is
 * bounded; an access outside the contract is refused (the run stops). */
#ifndef SNAP_COMPAT_ANS_H
#define SNAP_COMPAT_ANS_H
#include <stdint.h>

#define ANS_MAGIC 0x32534e41504e5341ULL /* "ANSPANS2" */
#define ANS_VERSION 2
#define ANS_CIDS 64            /* DT nvme-queue-entries; SPTM +0x10 */
#define ANS_MDTS 8             /* native type1 publishes1MiB independently of MDTS */
#define ANS_TRANSFER_BYTES (4096u << ANS_MDTS)
#define ANS_PRPS 258           /* 256 pages, an unaligned head, one spare */
#define ANS_SART_REGIONS 16
#define ANS_OUTBOX 8
#define ANS_BLOCK 4096
#define ANS_STATE_BYTES 0x30000 /* expanded PRP state, reserved firmware page, disk */
#define ANS_FW_OFFSET 0x30000
#define ANS_DISK_OFFSET 0x34000
#define ANS_DISK_MAX (1ULL << 30)
/* Window mode (NVMe model config[3] = ANS_WINDOW_MODE): the reservation holds the synthesized
 * GPT's first and last MiB (served from memory), the adopted SSD's params and state
 * (compat/nvme-host.h) and its 1 MiB DMA window; the disk itself is the M4 partition. */
#define ANS_WINDOW_MODE 1u
#define ANS_WINDOW_HEAD ANS_DISK_OFFSET         /* virtual blocks 0..255 */
#define ANS_WINDOW_TAIL (ANS_DISK_OFFSET + 0x100000ULL)
#define ANS_WINDOW_NVMEH (ANS_DISK_OFFSET + 0x200000ULL)   /* params, then state at +0x80 */
#define ANS_WINDOW_DMA 0x300000ULL
#define ANS_WINDOW_STAGE 0x400000ULL
#define ANS_WINDOW_BYTES 0x500000ULL
#define ANS_WINDOW_EDGE_BLOCKS 256u

/* Refusals: the run stops with EV_ANS (a = reason << 32 | detail). */
enum ans_error {
    ANS_OK, ANS_E_STATE, ANS_E_WIDTH, ANS_E_REGISTER, ANS_E_VALUE,
    ANS_E_MAILBOX, ANS_E_RTKIT, ANS_E_ENDPOINT, ANS_E_SPTM_ORDER, ANS_E_SPTM_ARG,
    ANS_E_ADDRESS, ANS_E_FRAME, ANS_E_CID, ANS_E_DOORBELL, ANS_E_SQE, ANS_E_CQ_FULL,
    ANS_E_DIRECTION, ANS_E_SART, ANS_E_BACKEND
};

/* Counters (exported to the host from the reservation). */
enum ans_counter {
    ANS_C_MMIO, ANS_C_MSG_IN, ANS_C_MSG_OUT, ANS_C_SPTM6, ANS_C_SPTM5, ANS_C_ADMIN,
    ANS_C_IO, ANS_C_READS, ANS_C_WRITES, ANS_C_FLUSHES, ANS_C_READ_BYTES,
    ANS_C_WRITE_BYTES, ANS_C_STATUS_ERRORS, ANS_C_INVALID_OPCODE, ANS_C_OUT_OF_RANGE,
    ANS_C_TUNNEL, ANS_C_REFUSALS, ANS_C_LBA_LOW, ANS_C_LBA_HIGH, ANS_C_IRQ_NVME,
    ANS_C_STARTEP, ANS_C_AP_POWER, ANS_C_MAPPED, ANS_C_UNMAPPED,
    ANS_C_MAX_READ_BLOCKS, ANS_C_MAX_WRITE_BLOCKS, ANS_C_COUNT
};

#ifndef SNAP_ANS_ASYNC
#define SNAP_ANS_ASYNC 0
#endif
#ifndef SNAP_ANS_CONVERTED
#define SNAP_ANS_CONVERTED 0
#endif
#if SNAP_ANS_CONVERTED && !SNAP_ANS_ASYNC
#error "SNAP_ANS_CONVERTED requires SNAP_ANS_ASYNC (a converted doorbell must never wait for the SSD)"
#endif
#if SNAP_ANS_ASYNC
/* SNAP_ANS_ASYNC (opt-in, default 0; agents/nvme-async/FAILURE-MODES.md). With an asynchronous backend
 * (ans_ops.disk_start/disk_poll: the window backend), an I/O queue 1 doorbell checks what the synchronous doorbell
 * checks up to its refusals, snapshots the SQE and queues the command (doorbell order, N4). Commands are served
 * one at a time; the backend's physical command is reaped without waiting by ans_async_progress, which every ANS
 * entry point runs first and the monitor runs from its ticks. A served command's data, CQE and interrupt level
 * follow the synchronous path's order. Admin doorbells, CC writes, mailbox writes and an UNMAP_PAGES of a busy
 * CID drain queue 1 first (N1, N8). */
#define ANS_ASYNC_MAGIC 0x31434e595341414eULL   /* "NAASYNC1" */
#define ANS_ASYNC_FIFO 128u                      /* > ANS_CIDS: a re-ring is queued again (N13) */
#define ANS_ASYNC_STEP_MAX 2u                    /* completions per progress call outside a drain (N10) */
#define ANS_ASYNC_PENDING 0x7e                   /* disk_start/disk_poll: the backend is still running */
#define ANS_DECLINE 0x7f                         /* ans_sptm_converted: nothing changed, repeat on the token path */
#define ANS_DECLINE_BUSY 0x7d                    /* ... because the CID is queued or in service */
#define ANS_ASYNC_BACKEND_WORDS 16u
struct ans_async_cmd { uint32_t cid, qid; uint32_t q[16]; };
enum ans_async_counter {
    ANS_A_QUEUED, ANS_A_STARTED, ANS_A_COMPLETED, ANS_A_PHYSICAL, ANS_A_POLLS, ANS_A_PENDING_POLLS,
    ANS_A_DRAINS, ANS_A_DRAINED, ANS_A_MAX_DEPTH, ANS_A_REQUEUED, ANS_A_ABANDONED, ANS_A_STOPS,
    ANS_A_COUNT
};
struct ans_async {
    uint64_t magic;
    uint32_t head, count;          /* the FIFO of queued commands */
    uint32_t active, phys;         /* a command in service; its backend still running */
    uint32_t op, status;           /* the command in service: opcode, status so far */
    uint64_t lba, n, seq;          /* its blocks; backend starts that went pending (the monitor's schedule) */
    struct ans_async_cmd cur;
    struct ans_async_cmd fifo[ANS_ASYNC_FIFO];
    uint64_t counter[ANS_A_COUNT];
    uint64_t backend[ANS_ASYNC_BACKEND_WORDS];   /* the backend's flight (compat/ans-window.h) */
    /* The monitor's poll schedule (probes/xnuboot.c), CNTPCT ticks; atomic words. */
    uint64_t due, owner, sched_seq, start, ewma;
    uint64_t sched[8];             /* tick polls, backstops, peeks, peek declines, latency ticks, reaps, -, - */
};
#endif

enum ans_iop { ANS_IOP_QUIESCED, ANS_IOP_HELLO, ANS_IOP_EPMAP, ANS_IOP_RUNNING };
/* I/O queue 1, created by the admin commands (not by the SPTM registration). */
#define ANS_IOQ_CQ 1u                  /* Create I/O CQ 1 completed */
#define ANS_IOQ_SQ 2u                  /* Create I/O SQ 1 completed */
#define ANS_IOQ_IEN 4u                 /* CQ 1 raises the NVMe interrupt */

struct ans_cid {
    uint8_t state, qid;            /* 0 free, 3 mapped (SPTM (qid<<4)|3) */
    uint16_t dir, nlb, count;      /* TCB bits 12:8, template NLB, PRP count */
    uint64_t prp[ANS_PRPS];
};
struct ans_cq { uint32_t size, tail, head, phase; };
struct ans_sart { uint64_t pa, size; uint32_t perm, guard; };

struct ans_state {
    uint64_t magic, version, disk_bytes, reserved;
    /* RTKit over the ASC mailbox */
    uint64_t outbox[ANS_OUTBOX][2];
    uint32_t out_count, in_enable, out_enable, iop;
    uint32_t ap_power, iop_power, epmap_acked, pad0;
    /* SPTM table 6 */
    uint32_t allowed, aqa, ioqa, ioq; /* ioq: ANS_IOQ_* for I/O queue 1 */
    uint64_t asq, acq, iosq, iocq;
    struct ans_cid cid[ANS_CIDS];
    /* SPTM table 5 */
    uint32_t sart_active, pad2;
    struct ans_sart sart[ANS_SART_REGIONS];
    /* NVMe controller */
    uint32_t cc, csts, intms, modesel, aqm, ppm, sart_power, aer_cid;
    struct ans_cq cq[2];
    uint64_t counter[ANS_C_COUNT];
    uint64_t refusal[4];           /* first refusal: reason, a, b, c */
    /* Diagnostics: opcodes answered Invalid Opcode ([0] admin, [1] I/O, one
     * bit per opcode) and the last non-zero completion status:
     * status << 48 | qid << 40 | opcode << 32 | CDW10. */
    uint64_t bad_opcode[2][4];
    uint64_t last_status;
#if SNAP_ANS_ASYNC
    struct ans_async async;        /* appended: every earlier offset unchanged (probes/ansstate.py) */
#endif
};

/* Guest memory and DMA admission, supplied by the monitor (or a host test).
 * map returns the bytes only when [pa, pa+size) is ordinary guest RAM.
 * frame_ref admits/releases one DMA reference on the 16 KiB frame holding pa:
 * writable != 0 when the device writes memory. Nonzero return refuses. */
struct ans_ops {
    void *ctx;
    volatile uint8_t *(*map)(void *ctx, uint64_t pa, uint64_t size);
    int (*frame_ref)(void *ctx, uint64_t pa, int writable, int release);
    void (*publish)(void *ctx, uint64_t pa, uint64_t size);
    /* The window backend: when set, the disk is not the RAM disk in the
     * reservation. disk_read fills *data with n 4 KiB blocks from lba and returns 0; nonzero is
     * a media error for the guest. Without both write callbacks, writes are protected. */
    int (*disk_read)(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data);
    /* Preflight the entire write and return its private staging buffer, or a
     * guest NVMe status. No media mutation here. disk_write runs only after
     * xfer copied every guest byte; nonzero means Write Fault. */
    int (*disk_write_buffer)(void *ctx, uint64_t lba, uint64_t n, volatile uint8_t **data);
    int (*disk_write)(void *ctx, uint64_t lba, uint64_t n);
    int (*disk_flush)(void *ctx);         /* nonzero means Write Fault, never success */
#if SNAP_ANS_ASYNC
    /* The asynchronous backend (all four synchronous callbacks still set): op 2 read, 1 write (after
     * disk_write_buffer and the copy into its buffer), 0 flush. ANS_ASYNC_PENDING: running; 0: done (a read's
     * blocks at *data); anything else: the synchronous callback's failure. */
    int (*disk_start)(void *ctx, unsigned op, uint64_t lba, uint64_t n);
    int (*disk_poll)(void *ctx, volatile uint8_t **data);
    /* The stop: reap what the backend has in flight (N6). */
    void (*disk_quiesce)(void *ctx);
#endif
#if SNAP_ANS_CONVERTED
    /* MAP_PAGES/UNMAP_PAGES references as one batch, all or nothing (N9): 0 committed, nonzero nothing changed. */
    int (*frame_refs)(void *ctx, const uint64_t *pa, unsigned n, int writable, int release);
#endif
};

/* DMA admission for the 16-byte SPTM frame-map entry of the frame a reference
 * is taken on (+0/+1 busy, +2 type, +3..+7 other state, +8/+12 the read and
 * write DMA reference counts). Apple's SPTM gates every table-6 queue base and
 * MAP_PAGES page through sptm.t8140.release ...ef64c, which requires the type
 * descriptor's DMA limit (table ...9e230 + 0x90*type, byte +0x30) to cover the
 * access; ROZONE 25, COMMPAGE 29-31 and KERNEL_RESTRICTED 35 have limit 0.
 * sptm_refs_dart leaves type checks to its caller, so the monitor admits only
 * XNU_DEFAULT (11) with clear metadata: the DART data-leaf rule
 * (compat/sptm-dart.c data_frame). Returns 1 when admitted. */
#define ANS_DMA_FRAME_TYPE 11u
int ans_dma_frame(const volatile uint8_t e[16]);

void ans_reset(struct ans_state *s, uint64_t disk_bytes);
/* window 0: ASC (reg[0]); window 1: NVMe BAR (reg[3]). width 4 or 8. */
int ans_mmio(struct ans_state *s, const struct ans_ops *o, unsigned window,
             uint64_t off, unsigned width, int write, uint64_t *value);
/* STP to +0x8800 / LDP from +0x8830 of the ASC window. */
int ans_mailbox_pair(struct ans_state *s, const struct ans_ops *o, uint64_t off,
                     int write, uint64_t v[2]);
/* SPTM table 5/6 endpoint; x = x0..x5 in, *ret = x0 out. */
int ans_sptm(struct ans_state *s, const struct ans_ops *o, unsigned table,
             unsigned endpoint, const uint64_t x[6], uint64_t *ret);
/* Levels for interrupts[1] (inbox empty), [2] (outbox), [4] (NVMe). */
void ans_levels(const struct ans_state *s, int levels[3]);
#if SNAP_ANS_ASYNC
/* Under ANS exclusion. Serve queued commands without waiting: at most `budget` completions. A refusal found on
 * the way is returned (the caller stops the run). */
int ans_async_progress(struct ans_state *s, const struct ans_ops *o, unsigned budget);
/* Complete every queued and in-service command, waiting for the backend (token path only). */
int ans_async_drain(struct ans_state *s, const struct ans_ops *o);
/* 1 while a command is queued or in service; *physical: the backend's start count (the schedule's key). */
int ans_async_busy(const struct ans_state *s, uint64_t *physical);
/* The run stops: reap the backend's command in flight and abandon the rest (counted). */
void ans_async_stop(struct ans_state *s, const struct ans_ops *o);
#endif
#if SNAP_ANS_CONVERTED
/* The converted table-6 MAP_PAGES (1) / UNMAP_PAGES (2) under the ANS lock: ANS_OK, a refusal of the progress run
 * first, ANS_DECLINE (nothing changed: the token path repeats and refuses or answers), or ANS_DECLINE_BUSY. */
int ans_sptm_converted(struct ans_state *s, const struct ans_ops *o, unsigned endpoint,
                       const uint64_t x[6], uint64_t *ret);
#endif
#endif
