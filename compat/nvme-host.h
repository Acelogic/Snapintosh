/* SPDX-License-Identifier: MIT */
/* The A16's NVMe SSD behind the virtual ANS2 (full-install M6, docs/FULL-INSTALL-DESIGN.md §4).
 *
 * q1n1's tools/nvme_m3.py --adopt-dma takes the controller over from the host, creates its admin
 * queue and I/O queue 1 in a 1 MiB DMA window inside the loader's ANS reservation, checks the
 * Snapintosh partition and its window header, and leaves the controller running. The monitor
 * adopts that state: it re-proves the controller registers against the record, then reads the
 * window through I/O queue 1 on the guest's behalf.
 *
 * Read defaults to the window [first_lba, last_lba] (real 512-byte LBAs). Explicit
 * NVMEH_F_WRITE also admits FUA Write inside [write_first_lba, write_last_lba].
 * Namespace Flush is a real command in either mode. Completions have a bounded wait; the
 * controller raises no interrupt (Create I/O CQ without IEN).
 *
 * Coherency: the SSD's DMA goes through the PCIe SMMU's identity stage 2, not through the CPU
 * caches. Submission entries and PRP lists are cleaned to the point of coherency before the
 * doorbell; completion entries and read data are cleaned and invalidated before they are read.
 * The private payload is cleaned before every command and invalidated after reads;
 * the CPU never dirties a completion line after adoption. */
#ifndef SNAP_COMPAT_NVME_HOST_H
#define SNAP_COMPAT_NVME_HOST_H
#include <stdint.h>

/* The DMA window layout (q1n1 tools/nvme_m3.py ADOPT_LAYOUT, offsets from dma_base). */
#define NVMEH_WINDOW_BYTES 0x100000u
#define NVMEH_ASQ   0x0000u
#define NVMEH_ACQ   0x1000u
#define NVMEH_IOSQ  0x2000u
#define NVMEH_IOCQ  0x3000u
#define NVMEH_PRP   0x8000u        /* one 4 KiB PRP list page */
#define NVMEH_DATA  0x10000u       /* private read/write data */
#define NVMEH_DATA_BYTES 0x20000u  /* 128 KiB: one command, the virtual ANS2's MDTS */
#define NVMEH_ADMIN_ENTRIES 32u
#define NVMEH_IO_ENTRIES 64u

/* Controller registers (NVMe 2.0 base 3.1.4). */
#define NVMEH_CAP 0x00u
#define NVMEH_CC 0x14u
#define NVMEH_CSTS 0x1cu
#define NVMEH_AQA 0x24u
#define NVMEH_ASQ_REG 0x28u
#define NVMEH_ACQ_REG 0x30u

#define NVMEH_F_ENABLE 1u
#define NVMEH_F_WRITE 2u
#define NVMEH_F_ALL 3u

/* probes/nvmeh.py builds this word by word (NVMEH_PARAMS_WORDS) from q1n1's adopt record. */
struct nvmeh_params {
    uint64_t flags;
    uint64_t bar, stride;                 /* BAR0; CAP.DSTRD */
    uint64_t dma_base;                    /* NVMEH_WINDOW_BYTES, 1 MiB aligned */
    uint64_t io_tail, io_head, io_phase, io_next_cid;   /* I/O queue 1 as the tool left it */
    uint64_t lba_bytes;                   /* 512 */
    uint64_t first_lba, last_lba;         /* the window, real LBAs, inclusive */
    uint64_t max_transfer;                /* bytes per data command (MDTS) */
    uint64_t timeout_ticks;               /* per command, in CNTPCT ticks */
    uint64_t write_first_lba, write_last_lba; /* narrower real LBAs; zero when read-only */
    uint64_t reserved;
};
#define NVMEH_PARAMS_WORDS 16

/* context.nvme: decoded word by word by the host (probes/nvmeh.py STATE_FIELDS). */
struct nvmeh_state {
    uint64_t status;                      /* NVMEH_S_* */
    uint64_t prepare;                     /* 0 or the adopt refusal */
    uint64_t tail, head, phase, next_cid;
    uint64_t reads, read_bytes, errors, timeouts, refused;
    uint64_t last_status;                 /* status << 16 | cid of the last failed completion */
    uint64_t last_lba, max_ticks, total_ticks;
    uint64_t csts;                        /* CSTS at the last failure or at stop */
    uint64_t writes, write_bytes, flushes, last_opcode;
};
#define NVMEH_STATE_WORDS 20

#define NVMEH_S_ADOPTED 1u
#define NVMEH_S_FAILED 2u     /* a timeout or fatal status: no further commands */

enum {
    NVMEH_E_PARAMS = -80,     /* a params word is out of contract */
    NVMEH_E_GUEST = -81,      /* the DMA window overlaps guest memory */
    NVMEH_E_CTRL = -82,       /* CC/CSTS not enabled-and-ready, or fatal */
    NVMEH_E_QUEUES = -83,     /* AQA/ASQ/ACQ are not the adopted admin queue */
    NVMEH_E_RANGE = -84,      /* outside the relevant window or larger than one command */
    NVMEH_E_TIMEOUT = -85,    /* no completion within timeout_ticks */
    NVMEH_E_STATUS = -86,     /* the completion carried an error status */
    NVMEH_E_DEAD = -87,       /* an earlier timeout or fatal status stopped the queue */
    NVMEH_E_READONLY = -88    /* write flag absent; nothing submitted */
};

#ifndef NVMEH_DIRECT
#if defined(__aarch64__) && defined(__ELF__) && !defined(__APPLE__) && !defined(__linux__)
#define NVMEH_DIRECT 1
#else
#define NVMEH_DIRECT 0
#endif
#endif
struct nvmeh_ops {
    void *ctx;
    uint32_t (*rd)(void *ctx, uint64_t pa);               /* 32-bit, register or DRAM word */
    void (*wr)(void *ctx, uint64_t pa, uint32_t value);
    void (*clean)(void *ctx, uint64_t pa, uint64_t size); /* DC CIVAC to PoC, then DSB */
    uint64_t (*now)(void *ctx);                           /* CNTPCT */
};

/* Check params against guest memory [mem_low, mem_high) and re-prove the adopted controller from
 * its registers (read-only). 0 or NVMEH_E_*. */
int nvmeh_adopt(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                uint64_t mem_low, uint64_t mem_high);

/* Read `count` real LBAs starting `wlba` LBAs into the window into dma_base + NVMEH_DATA + at.
 * `at` is 4 KiB aligned and at + count * lba_bytes <= NVMEH_DATA_BYTES. 0 or NVMEH_E_*. */
int nvmeh_read(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
               uint64_t wlba, uint32_t count, uint32_t at);

/* Same buffer/range units as Read. Caller fills the entire private payload before
 * this call. Every Write uses FUA, even if the guest did not request it. */
int nvmeh_write(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                uint64_t wlba, uint32_t count, uint32_t at);
int nvmeh_flush(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s);

/* Record CSTS for the stop report. */
void nvmeh_stop(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s);

#ifndef SNAP_ANS_ASYNC
#define SNAP_ANS_ASYNC 0
#endif
#if SNAP_ANS_ASYNC
/* SNAP_ANS_ASYNC (opt-in; agents/nvme-async/FAILURE-MODES.md N5, N6): the synchronous command split at its SQ
 * doorbell. nvmeh_submit is the command up to and including the SQ 1 tail doorbell; nvmeh_reap is one pass of its
 * completion wait and, once the phase matches or timeout_ticks (from the submit) has passed, the rest of the
 * command unchanged: the same counters, the same NVMEH_S_FAILED rules, the same returns. One command at a time
 * (the 128 KiB data buffer and the PRP page are single); the flight is the caller's. tools/test-nvme-host.c runs
 * both against the synchronous command on the same fake controller. */
#define NVMEH_PENDING 1           /* nvmeh_reap: no completion yet, timeout not reached */
#define NVMEH_E_BUSY (-89)        /* nvmeh_submit: a command is already in flight; nothing submitted */
struct nvmeh_flight {
    uint64_t active, op, lba, bytes, data, cid, start;
};
int nvmeh_submit(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
                 struct nvmeh_flight *f, unsigned op, uint64_t wlba, uint32_t count, uint32_t at);
int nvmeh_reap(const struct nvmeh_ops *o, const struct nvmeh_params *p, struct nvmeh_state *s,
               struct nvmeh_flight *f);
/* Read-only peek, safe without exclusion: 1 when the completion entry at the current head carries the expected
 * phase (a stale answer only moves one poll). */
int nvmeh_ready(const struct nvmeh_ops *o, const struct nvmeh_params *p, const struct nvmeh_state *s);
#endif
#endif
