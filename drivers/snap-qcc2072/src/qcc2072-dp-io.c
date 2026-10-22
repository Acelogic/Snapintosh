/* SPDX-License-Identifier: MIT */
/* QCC2072 data frame TX/RX. Failure inventory: re/dp-io/FAILURES.md.
 * Independent implementation of pinned ath12k wire facts (wifi7/dp_tx.c,
 * wifi7/hal_tx.c, wifi7/dp_rx.c, wifi7/hal_rx.c, dp_rx.c, dp_tx.c, dp.c,
 * wifi7/hal_desc.h, wifi7/hal_rx_desc.h, dp_htt.h). re/dp-io/replay.c checks
 * every descriptor byte against structs compiled from the retained upstream
 * text; no upstream code is copied here. */
#include "qcc2072-dp-io.h"

/* ---- Geometry owned by qcc2072-datapath.c (init, begin, rx_prepare). ---- */
#define RING_SW2WBM 1U              /* WBM_SW0_RELEASE, ring id 121, src */
#define RING_TCL0 2U                /* SW2TCL1, ring id 24, src */
#define RING_COMP0 5U               /* WBM2SW0_RELEASE, ring id 128, dst */
#define RING_RXERR 8U               /* WBM2SW3_RELEASE, ring id 131, dst */
#define SW2WBM_DWORDS (64U * 8U)
#define TCL_DWORDS (512U * 8U)
#define COMP_DWORDS (32768U * 8U)
#define RXERR_DWORDS (16384U * 8U)
#define ENTRY_DWORDS 8U
#define ENTRY_BYTES 32U
#define REFILL_HP_WORD 0x400U       /* HTT ring 0 (HOST1_TO_FW_RXBUF) head */
#define REFILL_TP_WORD 0x440U
#define REFILL_RING 0xdd0000U
#define REFILL_DWORDS (4096U * 2U)
#define RECORDS 0x120000U
#define RECORD_COUNT (280U * 512U)
#define RECORD_MAGIC 0x2072cc01U
#define LINK_BASE 0x600000U
#define LINK_BYTES (32768U * 128U)
#define RX_BUF_BASE 0xe00000U
#define RX_COOKIE_BASE 131072U
#define RX_BUF_BYTES 2048U
#define RX_DESC_BYTES 392U          /* sizeof(struct hal_rx_desc_qcc2072) */
#define TX_DATA_OFFSET 128U         /* slot: ext descriptor [0,104), frame [128,) */
/* ---- REO arena (qcc2072-reo.c): index k<8 = REO2SW(k+1), 9 = REO2SW0. ---- */
#define REO_DST_RINGS 8U
#define REO_DST_DWORDS (2048U * 8U)
#define REO_EXC_INDEX 9U
#define REO_EXC_DWORDS (128U * 8U)
/* ---- Registers: absolute UMAC addresses through window select 0x3278. ---- */
#define REG_WINDOW 0x3278U
#define REG_TCL1_HP 0xa46000U       /* TCL base 0xa44000 + HAL_TCL1_RING_HP */
#define REG_SW2WBM_HP 0xa37010U     /* WBM base 0xa34000 + 0x3010 */
#define REG_WBM2SW0_TP 0xa370ccU    /* WBM2SW0 HP 0xa370c8 + 4 */
#define REG_WBM2SW3_TP 0xa370e4U
#define REG_REO_DST_TP0 0xa3b04cU   /* REO base 0xa38000 + HAL_REO1_RING_TP */
#define REG_REO_EXC_TP 0xa3b08cU
#define REG_BANK0 0xa4408cU         /* HAL_TCL_SW_CONFIG_BANK_ADDR */
#define REG_TCL_CMN_CTRL 0xa44020U
#define REG_DSCP0 0xa44240U
#define DSCP_PROG_EN (1U << 23)
#define DSCP_TABLES 32U
#define DSCP_WORDS 6U               /* HAL_DSCP_TID_TBL_SIZE / 4 */
#define TCL_BANKS 7U                /* hw_params num_tcl_banks for QCC2072 */
/* ---- Descriptor constants (enum values from hal.h / hal_desc.h). ---- */
#define RBM_IDLE_LINK 1U
#define RBM_SW0 5U
#define RBM_SW1 6U
#define RBM_SW3 8U
#define ENCAP_RAW 0U
#define ENCRYPT_CCMP_128 6U
#define ENCRYPT_OPEN 7U
#define DESC_BUFFER 0U
#define DESC_EXT 1U
#define SRC_TQM 0U
#define SRC_RXDMA 1U
#define SRC_REO 2U
#define SRC_FW 3U
#define SRC_SW 4U
#define WBM_TYPE_MSDU_LINK 1U
#define BM_PUT_IN_IDLE 0U
#define BM_REL_MSDU 1U
#define PUSH_ERROR 0U
#define PUSH_ROUTING 1U
#define REO_ERR_DESC_ADDR_ZERO 0U
#define NON_QOS_TID 16U

enum { TX_FREE = 0, TX_INFLIGHT = 1 };
enum { RX_POSTED = 1, RX_HELD = 2, RX_PENDING = 3 };

static void zero(void *v, size_t n) { uint8_t *p = v; for (size_t i = 0; i < n; i++) p[i] = 0; }
static void copy(uint8_t *d, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }
static void put32(uint8_t *p, uint32_t v) { for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32; }
static int same_mac(const uint8_t *a, const uint8_t *b)
{ unsigned d = 0; for (unsigned i = 0; i < 6; i++) d |= (unsigned)(a[i] ^ b[i]); return !d; }

static int fail(struct qcc2072_dpio *io, int rc)
{
    if (!io->quarantined) { io->quarantined = 1; io->quarantine_reason = rc; }
    return rc;
}
static int bad_entry(struct qcc2072_dpio *io, const uint32_t w[8])
{
    for (unsigned i = 0; i < 8; i++) io->stats.last_bad[i] = w[i];
    return fail(io, QCC2072_RUNTIME_RING);
}
static int owner(struct qcc2072_dpio *io)
{
    const struct qcc2072_datapath *d = io->dp;
    return d->ops.validate_owner(d->ops.context, d->admission->generation,
                                 d->admission->owner_cookie) ? fail(io, QCC2072_SESSION_STALE) : 0;
}
/* Only doorbells and the TCL bank/DSCP configuration are reachable. */
static int reg_ok(uint32_t a)
{
    if (a & 3U) return 0;
    if (a == REG_TCL1_HP || a == REG_SW2WBM_HP || a == REG_WBM2SW0_TP ||
        a == REG_WBM2SW3_TP || a == REG_REO_EXC_TP || a == REG_TCL_CMN_CTRL) return 1;
    if (a >= REG_REO_DST_TP0 && a < REG_REO_DST_TP0 + 8U * REO_DST_RINGS && !((a - REG_REO_DST_TP0) % 8U)) return 1;
    if (a >= REG_BANK0 && a < REG_BANK0 + 4U * TCL_BANKS) return 1;
    return a >= REG_DSCP0 && a < REG_DSCP0 + 4U * DSCP_WORDS * DSCP_TABLES;
}
static int access32(struct qcc2072_dpio *io, uint32_t a, uint32_t *v, int write)
{
    const struct qcc2072_reo_ops *o = &io->dp->ops;
    uint32_t old, sel, back; int rc;
    if (!reg_ok(a)) return fail(io, QCC2072_BAD_REGISTER);
    if ((rc = owner(io))) return rc;
    if (o->read32(o->context, REG_WINDOW, &old) || old == UINT32_MAX) return fail(io, QCC2072_RUNTIME_IO);
    sel = (old & 0xffffffc0U) | 0x40000000U | ((a >> 19) & 63U);
    if (old != sel && (o->write32(o->context, REG_WINDOW, sel) ||
        o->read32(o->context, REG_WINDOW, &back) || back != sel)) return fail(io, QCC2072_RUNTIME_IO);
    if ((rc = owner(io))) return rc;
    uint32_t offset = 0x80000U + (a & 0x7ffffU);
    rc = write ? o->write32(o->context, offset, *v) : o->read32(o->context, offset, v);
    return rc ? fail(io, QCC2072_RUNTIME_IO) : 0;
}
static int reg_write(struct qcc2072_dpio *io, uint32_t a, uint32_t v) { return access32(io, a, &v, 1); }
static int reg_read(struct qcc2072_dpio *io, uint32_t a, uint32_t *v) { return access32(io, a, v, 0); }

static int sync(struct qcc2072_dpio *io, const struct qcc2072_dma_buffer *b, size_t off,
                size_t n, uint32_t dir)
{
    if (!n) return 0;
    return io->dp->ops.sync(io->dp->ops.context, b, off, n, dir) ? fail(io, QCC2072_RUNTIME_IO) : 0;
}
/* Entries [from,to) of a ring (dword indices), split at the wrap. */
static int sync_entries(struct qcc2072_dpio *io, const struct qcc2072_dma_buffer *b,
                        uint32_t ring, uint32_t dwords, uint32_t from, uint32_t to, uint32_t dir)
{
    if (from == to) return 0;
    if (from < to) return sync(io, b, ring + from * 4U, (to - from) * 4U, dir);
    int rc = sync(io, b, ring + from * 4U, (dwords - from) * 4U, dir);
    return rc ? rc : sync(io, b, ring, to * 4U, dir);
}
static int index_ok(uint32_t v, uint32_t dwords, uint32_t step) { return v < dwords && !(v % step); }
static uint32_t distance(uint32_t from, uint32_t to, uint32_t dwords) { return (to + dwords - from) % dwords; }

static uint8_t *dp_cpu(struct qcc2072_dpio *io, uint32_t off) { return io->dp->arena.cpu + off; }
static uint32_t dp_iova(struct qcc2072_dpio *io, uint32_t off) { return (uint32_t)io->dp->arena.iova + off; }
static uint32_t rx_offset(uint32_t i) { return RX_BUF_BASE + i * RX_BUF_BYTES; }
static uint32_t tx_offset(uint32_t s) { return QCC2072_DPIO_TX_ARENA + s * QCC2072_DPIO_TX_SLOT_BYTES; }

/* A cookie record written by qcc2072_datapath_init and never synced back. */
static int record_ok(struct qcc2072_dpio *io, uint32_t c)
{
    if (c >= RECORD_COUNT) return 0;
    const uint8_t *p = dp_cpu(io, RECORDS + c * 32U);
    return get32(p) == c && get32(p + 4) == RECORD_MAGIC && get64(p + 8) == io->dp->admission->generation;
}
/* Hardware cookie conversion returns the SPT entry: the record's CPU VA. */
static int va_cookie(struct qcc2072_dpio *io, uint64_t va, uint32_t *c)
{
    uint64_t base = (uint64_t)(uintptr_t)dp_cpu(io, RECORDS);
    if (va < base || va - base >= (uint64_t)RECORD_COUNT * 32U || ((va - base) & 31U)) return 0;
    *c = (uint32_t)((va - base) / 32U);
    return record_ok(io, *c);
}

/* ---- RX buffer ownership. ---- */
static int rx_claim(struct qcc2072_dpio *io, const uint32_t w[8], uint64_t va, uint32_t cookie,
                    uint32_t paddr_lo, uint32_t paddr_hi, int pa_optional, uint32_t *idx)
{
    uint32_t c = cookie;
    if (va && (!va_cookie(io, va, &c) || c != cookie)) return bad_entry(io, w);
    if (!record_ok(io, c) || c < RX_COOKIE_BASE || c - RX_COOKIE_BASE >= QCC2072_DPIO_RX_BUFFERS)
        return bad_entry(io, w);
    uint32_t i = c - RX_COOKIE_BASE;
    /* buf_pa_lo of a cookie-converted WBM release may be absent (0); never elsewhere. */
    if (io->rx_state[i] != RX_POSTED || paddr_hi ||
        ((paddr_lo || !pa_optional) && paddr_lo != dp_iova(io, rx_offset(i))))
        return bad_entry(io, w);
    io->rx_state[i] = RX_HELD; *idx = i;
    return 0;
}
static void rx_recycle(struct qcc2072_dpio *io, uint32_t i)
{
    io->rx_state[i] = RX_PENDING;
    io->rx_pending[io->rx_pending_count++] = (uint16_t)i;
}
/* Repost held buffers (ath12k_dp_rx_bufs_replenish): clear msdu_done so a stale
 * TLV can never pass as complete, publish entries, then the head word. */
static int refill_flush(struct qcc2072_dpio *io)
{
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    if (!io->rx_pending_count) return 0;
    int rc = sync(io, a, REFILL_TP_WORD, 4, QCC2072_SYNC_CPU);
    if (rc) return rc;
    uint32_t tp = get32(dp_cpu(io, REFILL_TP_WORD)), hp = io->refill_hp, first = hp;
    if (!index_ok(tp, REFILL_DWORDS, 2)) return fail(io, QCC2072_RUNTIME_RING);
    while (io->rx_pending_count && (hp + 2U) % REFILL_DWORDS != tp) {
        uint32_t i = io->rx_pending[--io->rx_pending_count];
        uint8_t *b = dp_cpu(io, rx_offset(i));
        put32(b + 4 + 124, 0);  /* msdu_end.info14 (MSDU_DONE bit 31) */
        if ((rc = sync(io, a, rx_offset(i) + 4 + 124, 4, QCC2072_SYNC_DEVICE))) return rc;
        uint8_t *e = dp_cpu(io, REFILL_RING + hp * 4U);
        put32(e, dp_iova(io, rx_offset(i)));
        put32(e + 4, (RBM_SW1 << 8) | ((RX_COOKIE_BASE + i) << 12));
        io->rx_state[i] = RX_POSTED;
        hp = (hp + 2U) % REFILL_DWORDS;
        io->stats.refill_posted++;
    }
    if (io->rx_pending_count) io->stats.refill_deferred++;
    if (hp == first) return 0;
    if ((rc = sync_entries(io, a, REFILL_RING, REFILL_DWORDS, first, hp, QCC2072_SYNC_DEVICE))) return rc;
    put32(dp_cpu(io, REFILL_HP_WORD), hp);
    if ((rc = sync(io, a, REFILL_HP_WORD, 4, QCC2072_SYNC_DEVICE))) return rc;
    io->refill_hp = hp;
    return 0;
}

/* ---- RX TLV parsing and Ethernet II delivery (hal_rx_desc_qcc2072). ---- */
static int snap_ok(const uint8_t *p)
{ return p[0] == 0xaa && p[1] == 0xaa && p[2] == 3 && !p[3] && !p[4] && (!p[5] || p[5] == 0xf8); }
static uint8_t *to_ethernet(uint8_t *f, size_t *n, unsigned decap)
{
    if (decap == 2) return *n >= 14 ? f : 0;                  /* ETHERNET2_DIX */
    if (decap == 3) {                                         /* 802.3 + LLC/SNAP */
        if (*n < 22 || !snap_ok(f + 14)) return 0;
        for (unsigned i = 12; i-- > 0;) f[i + 8] = f[i];   /* type already at +20 */
        *n -= 8; return f + 8;
    }
    if (decap != 1 || *n < 24) return 0;                      /* NATIVE_WIFI */
    unsigned fc = get16(f), tods = fc & 0x100U, fromds = fc & 0x200U, hl = 24;
    if ((fc & 0x0cU) != 0x08U) return 0;
    if (tods && fromds) hl += 6;
    if (fc & 0x80U) { hl += 2; if (fc & 0x8000U) hl += 4; }
    if (*n < hl + 8U || !snap_ok(f + hl)) return 0;
    uint8_t mac[12];
    copy(mac, tods ? f + 16 : f + 4, 6);
    copy(mac + 6, fromds ? (tods ? f + 24 : f + 16) : f + 10, 6);
    uint8_t *e = f + hl + 8 - 14;                            /* ethertype stays in place */
    copy(e, mac, 12);
    *n -= hl + 8U - 14U; return e;
}
#define INFO13_ERRORS ((1U << 31) | (1U << 29) | (1U << 28) | (1U << 27) | (1U << 17) | (1U << 16) | (1U << 12))
static int rx_deliver(struct qcc2072_dpio *io, uint32_t i, struct qcc2072_dpio_rx_info *info)
{
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    uint8_t *b = dp_cpu(io, rx_offset(i));
    int rc = sync(io, a, rx_offset(i), RX_DESC_BYTES, QCC2072_SYNC_CPU);
    if (rc) return rc;
    const uint8_t *end = b + 4, *start = b + 144;           /* msdu_end, mpdu_start */
    uint32_t info5 = get16(end + 42), info10 = get32(end + 72), info11 = get32(end + 76);
    uint32_t info13 = get32(end + 120), info14 = get32(end + 124);
    uint32_t m2 = get32(start + 4), m4 = get32(start + 32);
    if (!(info14 >> 31)) { io->stats.rx_drop_not_done++; return 0; }
    uint32_t len = info10 & 0x3fffU, pad = (info5 >> 10) & 3U;
    if (RX_DESC_BYTES + pad + len > RX_BUF_BYTES || len < 14) { io->stats.rx_drop_length++; return 0; }
    if (info13 & INFO13_ERRORS) { io->stats.rx_drop_error++; return 0; }
    info->decap = (uint8_t)((info11 >> 8) & 3U);
    info->first_msdu = (uint8_t)((info5 >> 12) & 1U); info->last_msdu = (uint8_t)((info5 >> 13) & 1U);
    info->from_ds = (uint8_t)((info5 >> 14) & 1U); info->to_ds = (uint8_t)((info5 >> 2) & 1U);
    info->l3_pad = (uint8_t)pad; info->msdu_length = (uint16_t)len;
    info->mcast = (uint8_t)((info13 >> 2) & 1U);
    info->tid = (uint8_t)((m2 >> 15) & 15U);
    info->encrypt_type = (uint8_t)(((m4 >> 9) & 1U) ? (m2 >> 2) & 15U : ENCRYPT_OPEN);
    info->decrypted = (uint8_t)(info->encrypt_type != ENCRYPT_OPEN && !((info14 >> 10) & 7U));
    info->sw_peer_id = get16(start + 42);
    info->addr2_valid = (uint8_t)((m4 >> 3) & 1U);
    copy(info->addr2, start + 66, 6);
    if ((rc = sync(io, a, rx_offset(i) + RX_DESC_BYTES + pad, len, QCC2072_SYNC_CPU))) return rc;
    size_t n = len;
    const uint8_t *frame = to_ethernet(b + RX_DESC_BYTES + pad, &n, info->decap);
    if (!frame) { io->stats.rx_drop_decap++; return 0; }
    if (info->source == QCC2072_DPIO_RX_NULL_QUEUE) io->stats.rx_null_queue++;
    io->stats.rx_delivered++;
    if (io->cb.rx) { io->in_callback = 1; io->cb.rx(io->cb.context, frame, n, info); io->in_callback = 0; }
    return io->quarantined ? io->quarantine_reason : 0;
}
static uint16_t meta_peer(const struct qcc2072_dpio *io, uint32_t meta)
{   /* RX_MPDU_DESC_META_DATA_{V0,V1,V1A,V1B}_PEER_ID */
    return (uint16_t)(io->peer_metadata_version == 0 ? meta & 0xffffU : meta & 0x3fffU);
}

/* ---- REO destination rings (ath12k_wifi7_dp_rx_process). ---- */
static int reo_dest(struct qcc2072_dpio *io, unsigned k, unsigned budget)
{
    struct qcc2072_dma_buffer *r = &io->reo->arena;
    uint32_t hp = get32(r->cpu + k * 64U), tp = io->reo_tp[k];
    if (!index_ok(hp, REO_DST_DWORDS, ENTRY_DWORDS)) return fail(io, QCC2072_RUNTIME_RING);
    uint32_t m = distance(tp, hp, REO_DST_DWORDS) / ENTRY_DWORDS;
    if (!m) return 0;
    if (m > budget) m = budget;
    uint32_t ring = io->reo->ring_offset[k], stop = (tp + m * ENTRY_DWORDS) % REO_DST_DWORDS;
    int rc = sync_entries(io, r, ring, REO_DST_DWORDS, tp, stop, QCC2072_SYNC_CPU);
    while (!rc && tp != stop) {
        uint32_t w[8], idx;
        for (unsigned j = 0; j < 8; j++) w[j] = get32(r->cpu + ring + tp * 4U + j * 4U);
        tp = (tp + ENTRY_DWORDS) % REO_DST_DWORDS;
        if (w[7] & 1U) { rc = bad_entry(io, w); break; }    /* link descriptor in a data ring */
        uint64_t va = (uint64_t)w[5] | (uint64_t)w[6] << 32;  /* 0: no cookie conversion */
        if ((rc = rx_claim(io, w, va, w[1] >> 12, w[0], w[1] & 0xffU, 0, &idx))) break;
        unsigned cont = (w[4] >> 2) & 1U;
        if (((w[7] >> 1) & 3U) != PUSH_ROUTING) io->stats.rx_drop_push++;
        else if (io->reo_chain[k] || cont) { io->reo_chain[k] = (uint8_t)cont; io->stats.rx_drop_chain++; }
        else {
            struct qcc2072_dpio_rx_info info;
            zero(&info, sizeof(info));
            info.source = QCC2072_DPIO_RX_REO; info.ring = (uint8_t)k;
            info.peer_metadata = w[3]; info.peer_id = meta_peer(io, w[3]);
            info.cookie = RX_COOKIE_BASE + idx;
            rc = rx_deliver(io, idx, &info);
        }
        rx_recycle(io, idx);
    }
    if (rc) return rc;
    io->reo_tp[k] = tp;
    return reg_write(io, REG_REO_DST_TP0 + 8U * k, tp);
}

/* ---- WBM2SW3 RX error release (ath12k_wifi7_dp_rx_process_wbm_err). ---- */
static int rx_errors(struct qcc2072_dpio *io, unsigned budget)
{
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    uint32_t hp = get32(a->cpu + RING_RXERR * 64U), tp = io->rxerr_tp;
    if (!index_ok(hp, RXERR_DWORDS, ENTRY_DWORDS)) return fail(io, QCC2072_RUNTIME_RING);
    uint32_t m = distance(tp, hp, RXERR_DWORDS) / ENTRY_DWORDS;
    if (!m) return 0;
    if (m > budget) m = budget;
    uint32_t ring = io->dp->offsets[RING_RXERR], stop = (tp + m * ENTRY_DWORDS) % RXERR_DWORDS;
    int rc = sync_entries(io, a, ring, RXERR_DWORDS, tp, stop, QCC2072_SYNC_CPU);
    while (!rc && tp != stop) {
        uint32_t w[8], idx, rbm, cookie;
        for (unsigned j = 0; j < 8; j++) w[j] = get32(a->cpu + ring + tp * 4U + j * 4U);
        tp = (tp + ENTRY_DWORDS) % RXERR_DWORDS;
        unsigned src = w[2] & 7U, type = (w[2] >> 6) & 7U, cc = (w[2] >> 16) & 1U;
        /* Not an RXDMA/REO MSDU release: ath12k skips it without touching a buffer. */
        if (type != 0 || (src != SRC_RXDMA && src != SRC_REO)) { io->stats.rx_drop_wbm_other++; continue; }
        if (cc) {
            rbm = (w[2] >> 9) & 15U; cookie = (w[7] >> 8) & 0xfffffU;
            rc = rx_claim(io, w, (uint64_t)w[0] | (uint64_t)w[1] << 32, cookie, w[6], 0, 1, &idx);
        } else {
            rbm = (w[1] >> 8) & 15U; cookie = w[1] >> 12;
            rc = rx_claim(io, w, 0, cookie, w[0], w[1] & 0xffU, 0, &idx);
        }
        if (rc) break;
        unsigned push = src == SRC_REO ? (w[2] >> 24) & 3U : (w[2] >> 17) & 3U;
        unsigned err = src == SRC_REO ? (w[2] >> 26) & 31U : (w[2] >> 19) & 31U;
        unsigned cont = (w[5] >> 2) & 1U;
        if (rbm != RBM_SW3) io->stats.rx_drop_rbm++;
        else if (push != PUSH_ERROR) io->stats.rx_drop_push++;
        else if (io->wbm_chain || cont) { io->wbm_chain = (uint8_t)cont; io->stats.rx_drop_chain++; }
        else if (src != SRC_REO || err != REO_ERR_DESC_ADDR_ZERO) io->stats.rx_drop_error++;
        else {  /* NULL queue descriptor: ath12k_wifi7_dp_rx_h_null_q_desc delivers it */
            struct qcc2072_dpio_rx_info info;
            zero(&info, sizeof(info));
            info.source = QCC2072_DPIO_RX_NULL_QUEUE; info.ring = RING_RXERR;
            info.reo_error = (uint8_t)err; info.peer_metadata = w[4];
            info.peer_id = meta_peer(io, w[4]); info.cookie = cookie;
            rc = rx_deliver(io, idx, &info);
        }
        rx_recycle(io, idx);
    }
    if (rc) return rc;
    io->rxerr_tp = tp;
    return reg_write(io, REG_WBM2SW3_TP, tp);
}

/* ---- REO2SW0 exception ring (ath12k_wifi7_dp_rx_process_err). Fragments and
 * errors are dropped; link descriptors go back to WBM idle via SW2WBM. ---- */
static int link_return(struct qcc2072_dpio *io, uint32_t lo, uint32_t hi, unsigned act)
{
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    uint8_t *e = dp_cpu(io, io->dp->offsets[RING_SW2WBM] + io->sw2wbm_hp * 4U);
    zero(e, ENTRY_BYTES);
    put32(e, lo); put32(e + 4, hi);
    put32(e + 8, SRC_SW | (act << 3) | (WBM_TYPE_MSDU_LINK << 6));
    int rc = sync(io, a, io->dp->offsets[RING_SW2WBM] + io->sw2wbm_hp * 4U, ENTRY_BYTES, QCC2072_SYNC_DEVICE);
    if (rc) return rc;
    io->sw2wbm_hp = (io->sw2wbm_hp + ENTRY_DWORDS) % SW2WBM_DWORDS;
    io->stats.link_returned++;
    return reg_write(io, REG_SW2WBM_HP, io->sw2wbm_hp);
}
static int exceptions(struct qcc2072_dpio *io, unsigned budget)
{
    struct qcc2072_dma_buffer *r = &io->reo->arena, *a = &io->dp->arena;
    uint32_t hp = get32(r->cpu + REO_EXC_INDEX * 64U), tp = io->exc_tp, start = tp;
    if (!index_ok(hp, REO_EXC_DWORDS, ENTRY_DWORDS)) return fail(io, QCC2072_RUNTIME_RING);
    uint32_t m = distance(tp, hp, REO_EXC_DWORDS) / ENTRY_DWORDS;
    if (!m) return 0;
    if (m > budget) m = budget;
    uint32_t ring = io->reo->ring_offset[REO_EXC_INDEX], stop = (tp + m * ENTRY_DWORDS) % REO_EXC_DWORDS;
    uint32_t sw2wbm_tp = get32(a->cpu + RING_SW2WBM * 64U);
    if (!index_ok(sw2wbm_tp, SW2WBM_DWORDS, ENTRY_DWORDS)) return fail(io, QCC2072_RUNTIME_RING);
    int rc = sync_entries(io, r, ring, REO_EXC_DWORDS, tp, stop, QCC2072_SYNC_CPU);
    while (!rc && tp != stop) {
        uint32_t w[8], idx;
        for (unsigned j = 0; j < 8; j++) w[j] = get32(r->cpu + ring + tp * 4U + j * 4U);
        if (!(w[7] & 1U)) {   /* MSDU buffer: ath12k_dp_h_msdu_buffer_type frees it */
            uint64_t va = (uint64_t)w[5] | (uint64_t)w[6] << 32;
            if ((rc = rx_claim(io, w, va, w[1] >> 12, w[0], w[1] & 0xffU, 0, &idx))) break;
            rx_recycle(io, idx); io->stats.rx_exception_msdu++;
            tp = (tp + ENTRY_DWORDS) % REO_EXC_DWORDS;
            continue;
        }
        unsigned push = (w[7] >> 1) & 3U;
        if (push != PUSH_ERROR && push != PUSH_ROUTING) {   /* ath12k: warn, skip */
            io->stats.rx_exception_skipped++;
            tp = (tp + ENTRY_DWORDS) % REO_EXC_DWORDS;
            continue;
        }
        uint32_t link = w[0] - (uint32_t)a->iova;
        if ((w[1] & 0xffU) || w[0] < (uint32_t)a->iova || link < LINK_BASE ||
            link - LINK_BASE >= LINK_BYTES || (link & 127U)) { rc = bad_entry(io, w); break; }
        if ((io->sw2wbm_hp + ENTRY_DWORDS) % SW2WBM_DWORDS == sw2wbm_tp) {
            io->stats.link_deferred++;       /* retry this entry next poll */
            break;
        }
        if ((rc = sync(io, a, link, 128, QCC2072_SYNC_CPU))) break;
        const uint8_t *l = dp_cpu(io, link);
        unsigned rbm = (get32(l + 32 + 4) >> 8) & 15U;
        unsigned act = BM_PUT_IN_IDLE;
        if (rbm != RBM_IDLE_LINK && rbm != RBM_SW3 && rbm != RBM_SW1) act = BM_REL_MSDU;
        else for (unsigned j = 0; j < 6 && !rc; j++) {
            const uint8_t *d = l + 32 + j * 16U;
            uint32_t lo = get32(d), hi = get32(d + 4);
            if (!lo) break;
            if (!(rc = rx_claim(io, w, 0, hi >> 12, lo, hi & 0xffU, 0, &idx))) rx_recycle(io, idx);
        }
        if (rc) break;
        io->stats.rx_exception_link++;
        if ((rc = link_return(io, w[0], w[1], act))) break;
        tp = (tp + ENTRY_DWORDS) % REO_EXC_DWORDS;
    }
    if (rc) return rc;
    io->exc_tp = tp;
    return tp == start ? 0 : reg_write(io, REG_REO_EXC_TP, tp);
}

/* ---- TX completion (ath12k_wifi7_dp_tx_completion_handler). ---- */
static unsigned tx_status(unsigned src, unsigned reason)
{
    if (src == SRC_TQM) {
        if (reason == 0) return QCC2072_DPIO_TX_ACKED;              /* FRAME_ACKED */
        if (reason == 1 || reason == 2 || reason == 4 || reason == 10)
            return QCC2072_DPIO_TX_DROPPED;    /* REMOVE_MPDU/TX, AGED, DROP_THRESHOLD */
        return QCC2072_DPIO_TX_NOT_ACKED;
    }
    if (src == SRC_FW) {                                            /* HTT WBM status */
        if (reason == 0) return QCC2072_DPIO_TX_ACKED;
        if (reason <= 4 || reason == 6) return QCC2072_DPIO_TX_DROPPED;
    }
    return QCC2072_DPIO_TX_ERROR;
}
static int tx_completions(struct qcc2072_dpio *io, unsigned budget)
{
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    uint32_t hp = get32(a->cpu + RING_COMP0 * 64U), tp = io->comp_tp;
    if (!index_ok(hp, COMP_DWORDS, ENTRY_DWORDS)) return fail(io, QCC2072_RUNTIME_RING);
    uint32_t m = distance(tp, hp, COMP_DWORDS) / ENTRY_DWORDS;
    if (!m) return 0;
    if (m > budget) m = budget;
    uint32_t ring = io->dp->offsets[RING_COMP0], stop = (tp + m * ENTRY_DWORDS) % COMP_DWORDS;
    int rc = sync_entries(io, a, ring, COMP_DWORDS, tp, stop, QCC2072_SYNC_CPU);
    while (!rc && tp != stop) {
        uint32_t w[8], c;
        for (unsigned j = 0; j < 8; j++) w[j] = get32(a->cpu + ring + tp * 4U + j * 4U);
        tp = (tp + ENTRY_DWORDS) % COMP_DWORDS;
        unsigned cc = (w[2] >> 30) & 1U;
        if (cc) { if (!va_cookie(io, (uint64_t)w[0] | (uint64_t)w[1] << 32, &c)) { rc = bad_entry(io, w); break; } }
        else c = w[1] >> 12;   /* BUFFER_ADDR_INFO1_SW_COOKIE of word 1 */
        if (c >= QCC2072_DPIO_TX_SLOTS || !record_ok(io, c) || io->tx_state[c] != TX_INFLIGHT) {
            rc = bad_entry(io, w); break;
        }
        struct qcc2072_dpio_tx_result res;
        zero(&res, sizeof(res));
        unsigned src = w[2] & 7U, reason = (w[2] >> 13) & 15U;
        res.tag = io->tx_tag[c]; res.slot = (uint16_t)c; res.eapol = io->tx_eapol[c];
        res.status = (uint8_t)tx_status(src, reason);
        res.release_source = (uint8_t)src; res.reason = (uint8_t)reason;
        res.cookie_converted = (uint8_t)cc;
        res.transmit_count = (uint8_t)((w[3] >> 24) & 0x7fU);
        res.ack_rssi = (uint8_t)(src == SRC_FW ? w[4] >> 24 : w[4] & 0xffU);
        res.peer_id = (uint16_t)(w[7] & 0xffffU); res.tid = (uint8_t)((w[7] >> 16) & 15U);
        io->tx_state[c] = TX_FREE; io->tx_free[io->tx_free_count++] = (uint16_t)c;
        io->stats.tx_completed[res.status]++;
        if (io->cb.tx_done) { io->in_callback = 1; io->cb.tx_done(io->cb.context, &res); io->in_callback = 0; }
        if (io->quarantined) { rc = io->quarantine_reason; break; }
    }
    if (rc) return rc;
    io->comp_tp = tp;
    return reg_write(io, REG_WBM2SW0_TP, tp);
}

/* ---- TX enqueue (ath12k_wifi7_dp_tx + ath12k_wifi7_hal_tx_cmd_desc_setup). ---- */
static const struct qcc2072_dpio_peer *bss_peer(const struct qcc2072_dpio *io)
{
    if (!io->bss_set || !io->vdev_set) return 0;
    for (unsigned i = 0; i < QCC2072_DPIO_PEERS; i++) {
        const struct qcc2072_dpio_peer *p = &io->peers[i];
        if (p->valid && p->ast_valid && p->vdev_id == io->vdev.vdev_id && same_mac(p->mac, io->bssid)) return p;
    }
    return 0;
}
int qcc2072_dpio_peer_ready(const struct qcc2072_dpio *io) { return io && io->initialized && bss_peer(io) != 0; }
static size_t dot11_header(const struct qcc2072_dpio *io, uint8_t *h, const uint8_t *eth,
                           int qos, unsigned tid, int protect)
{
    h[0] = qos ? 0x88 : 0x08;                       /* data / QoS data */
    h[1] = (uint8_t)(0x01 | (protect ? 0x40 : 0));  /* ToDS (+Protected) */
    h[2] = h[3] = 0;
    copy(h + 4, io->bssid, 6); copy(h + 10, eth + 6, 6); copy(h + 16, eth, 6);
    h[22] = h[23] = 0;
    if (!qos) return 24;
    h[24] = (uint8_t)(tid & 15U); h[25] = 0;
    return 26;
}
static size_t snap_header(uint8_t *p, const uint8_t *type)
{   /* RFC1042, bridge-tunnel for AARP/IPX as mac80211 encapsulates */
    unsigned t = (unsigned)type[0] << 8 | type[1];
    p[0] = 0xaa; p[1] = 0xaa; p[2] = 3; p[3] = 0; p[4] = 0;
    p[5] = (uint8_t)((t == 0x80f3 || t == 0x8137) ? 0xf8 : 0);
    p[6] = type[0]; p[7] = type[1];
    return 8;
}
int qcc2072_dpio_tx(struct qcc2072_dpio *io, const uint8_t *f, size_t n, uint64_t tag,
                    unsigned tid, unsigned flags)
{
    if (!io || !io->initialized || io->in_tx || (io->busy && !io->in_callback)) return QCC2072_BAD_STATE;
    if (io->quarantined) return QCC2072_QUARANTINED;
    if (io->dp->quarantined || io->reo->quarantined) return fail(io, QCC2072_QUARANTINED);
    if (io->dp->in_call) return QCC2072_BAD_STATE;
    if (!f || n < 14 || n > QCC2072_DPIO_MAX_FRAME || tid > 7 || (flags & ~(unsigned)QCC2072_DPIO_TX_PROTECTED)) {
        io->stats.tx_refused++; return QCC2072_INVALID_ARGUMENT;
    }
    const struct qcc2072_dpio_peer *peer = bss_peer(io);
    if (!peer) { io->stats.tx_refused++; return QCC2072_BAD_STATE; }
    if (!io->tx_free_count) { io->stats.tx_full++; return QCC2072_RUNTIME_FULL; }
    int rc = owner(io);
    if (rc) return rc;
    io->in_tx = 1;
    struct qcc2072_dma_buffer *a = &io->dp->arena;
    uint32_t slot = io->tx_free[io->tx_free_count - 1];
    uint8_t *s = dp_cpu(io, tx_offset(slot)), *d = s + TX_DATA_OFFSET;
    int eapol = f[12] == 0x88 && f[13] == 0x8e, protect = (flags & QCC2072_DPIO_TX_PROTECTED) != 0;
    unsigned qos = io->vdev.qos != 0, type = DESC_BUFFER, to_fw = 0, htt = 0;
    /* Published range: the frame for BUFFER descriptors, ext descriptor + frame for EXT. */
    uint32_t len, buffer = dp_iova(io, tx_offset(slot) + TX_DATA_OFFSET);
    uint32_t sync_off = tx_offset(slot) + TX_DATA_OFFSET, sync_len;
    if (eapol) tid = qos ? 7 : 0;    /* mac80211 control port priority; non-QoS TID 16 -> 4-bit 0 */
    if (io->vdev.encap == QCC2072_DPIO_ENCAP_ETHERNET && !eapol) {
        copy(d, f, n); len = (uint32_t)n; sync_len = len;
    } else if (io->vdev.encap == QCC2072_DPIO_ENCAP_ETHERNET) {
        /* mac80211 hands EAPOL over as 802.11; ath12k sends it RAW via an MSDU
         * extension descriptor to firmware (HTT metadata while unprotected). */
        size_t h = dot11_header(io, d, f, (int)qos, tid, protect);
        if (protect) { zero(d + h, 8); h += 8; }               /* CCMP header (IV) */
        h += snap_header(d + h, f + 12);
        copy(d + h, f + 14, n - 14); h += n - 14;
        if (protect) { zero(d + h, 8); h += 8; }               /* CCMP MIC (ICV) */
        uint32_t frame = (uint32_t)h;
        zero(s, TX_DATA_OFFSET);
        put32(s + 24, buffer);                                 /* hal_tx_msdu_ext_desc.info0 */
        put32(s + 28, (1U << 8) | (ENCAP_RAW << 9) |
              ((protect ? ENCRYPT_CCMP_128 : ENCRYPT_OPEN) << 11) | (frame << 16));
        len = 72;
        if (!protect) { put32(s + 72, (1U << 8) | (1U << 31)); len = 104; htt = 1; }
        type = DESC_EXT; to_fw = 1;
        buffer = dp_iova(io, tx_offset(slot));
        sync_off = tx_offset(slot); sync_len = TX_DATA_OFFSET + frame;
    } else if (io->vdev.encap == QCC2072_DPIO_ENCAP_NATIVE_WIFI) {
        if (!qos) tid = 0;   /* ath12k_dp_tx_get_tid: non-QoS data -> TID 16, 4-bit field 0 */
        size_t h = dot11_header(io, d, f, 0, 0, protect);    /* nwifi: QoS removed */
        h += snap_header(d + h, f + 12);
        copy(d + h, f + 14, n - 14); len = (uint32_t)(h + n - 14); sync_len = len;
    } else { io->in_tx = 0; return fail(io, QCC2072_BAD_STATE); }
    if ((rc = sync(io, a, sync_off, sync_len, QCC2072_SYNC_DEVICE))) goto out;
    if ((rc = sync(io, a, RING_TCL0 * 64U, 4, QCC2072_SYNC_CPU))) goto out;
    uint32_t tp = get32(a->cpu + RING_TCL0 * 64U);
    if (!index_ok(tp, TCL_DWORDS, ENTRY_DWORDS)) { rc = fail(io, QCC2072_RUNTIME_RING); goto out; }
    if ((io->tcl_hp + ENTRY_DWORDS) % TCL_DWORDS == tp) { io->stats.tx_full++; rc = QCC2072_RUNTIME_FULL; goto out; }
    uint32_t meta = 1U | ((uint32_t)io->vdev.vdev_id << 3) | ((uint32_t)(io->vdev.pdev_id & 3U) << 11) | (htt ? 4U : 0);
    uint32_t off = io->dp->offsets[RING_TCL0] + io->tcl_hp * 4U;
    uint8_t *e = dp_cpu(io, off);
    put32(e, buffer);
    put32(e + 4, (RBM_SW0 << 8) | (slot << 12));
    put32(e + 8, (type << 1) | ((uint32_t)io->vdev.bank_id << 2));
    put32(e + 12, meta << 16);
    put32(e + 16, (len & 0xffffU) | (to_fw << 21));
    put32(e + 20, 1U | ((tid & 15U) << 4) | ((uint32_t)(io->vdev.lmac_id & 3U) << 9) |
                  ((uint32_t)io->vdev.vdev_id << 24));
    put32(e + 24, (peer->hw_peer_id & 0xfffffU) | ((uint32_t)(peer->ast_hash & 15U) << 20));
    put32(e + 28, 0);
    if ((rc = sync(io, a, off, ENTRY_BYTES, QCC2072_SYNC_DEVICE))) goto out;
    io->tx_free_count--;
    io->tx_state[slot] = TX_INFLIGHT; io->tx_tag[slot] = tag; io->tx_eapol[slot] = (uint8_t)eapol;
    io->tcl_hp = (io->tcl_hp + ENTRY_DWORDS) % TCL_DWORDS;
    io->stats.tx_enqueued++;
    if (eapol) io->stats.tx_eapol++;
    rc = reg_write(io, REG_TCL1_HP, io->tcl_hp);    /* failure quarantines; slot stays owned */
out:
    io->in_tx = 0;
    return rc;
}
unsigned qcc2072_dpio_tx_pending(const struct qcc2072_dpio *io)
{ return io ? QCC2072_DPIO_TX_SLOTS - io->tx_free_count : 0; }

/* ---- Configuration. ---- */
int qcc2072_dpio_init(struct qcc2072_dpio *io, struct qcc2072_datapath *dp, struct qcc2072_reo *reo,
                      const struct qcc2072_dpio_callbacks *cb, uint8_t peer_metadata_version)
{
    if (!io || !dp || !reo || !cb || peer_metadata_version > 3) return QCC2072_INVALID_ARGUMENT;
    if (!dp->initialized || !dp->active || !dp->rx_prepared || dp->in_call || dp->io_attached ||
        !reo->initialized || !reo->activated || reo->in_call || dp->admission != reo->admission)
        return QCC2072_BAD_STATE;
    if (dp->quarantined || reo->quarantined) return QCC2072_QUARANTINED;
    if (dp->arena.capacity < QCC2072_DATAPATH_ARENA_BYTES || reo->arena.capacity < QCC2072_REO_ARENA_BYTES ||
        QCC2072_DPIO_QDESC_ARENA + QCC2072_DPIO_TIDS * QCC2072_DPIO_QDESC_STRIDE > QCC2072_DATAPATH_ARENA_BYTES ||
        QCC2072_DPIO_TX_ARENA + QCC2072_DPIO_TX_SLOTS * QCC2072_DPIO_TX_SLOT_BYTES > QCC2072_DPIO_QDESC_ARENA)
        return QCC2072_DMA_INVALID;
    uint32_t hp = get32(dp->arena.cpu + REFILL_HP_WORD);
    if (!index_ok(hp, REFILL_DWORDS, 2) || hp != QCC2072_DPIO_RX_BUFFERS * 2U) return QCC2072_BAD_STATE;
    zero(io, sizeof(*io));
    io->dp = dp; io->reo = reo; io->cb = *cb; io->peer_metadata_version = peer_metadata_version;
    if (owner(io)) return QCC2072_SESSION_STALE;
    io->refill_hp = hp;
    for (uint32_t i = 0; i < QCC2072_DPIO_RX_BUFFERS; i++) io->rx_state[i] = RX_POSTED;
    for (uint32_t s = 0; s < QCC2072_DPIO_TX_SLOTS; s++)
        io->tx_free[s] = (uint16_t)(QCC2072_DPIO_TX_SLOTS - 1U - s);   /* slot 0 first */
    io->tx_free_count = QCC2072_DPIO_TX_SLOTS;
    zero(dp->arena.cpu + QCC2072_DPIO_TX_ARENA, QCC2072_DPIO_TX_SLOTS * QCC2072_DPIO_TX_SLOT_BYTES);
    dp->io_attached = 1;
    io->initialized = 1;
    return 0;
}
static int enter(struct qcc2072_dpio *io)
{
    if (!io || !io->initialized || io->busy || io->in_tx) return QCC2072_BAD_STATE;
    if (io->quarantined) return QCC2072_QUARANTINED;
    if (io->dp->quarantined || io->reo->quarantined) return fail(io, QCC2072_QUARANTINED);
    if (io->dp->in_call) return QCC2072_BAD_STATE;
    return owner(io);
}
/* ath12k_wifi7_hal_tx_set_dscp_tid_map for all 32 tables, then the bank. */
int qcc2072_dpio_set_vdev(struct qcc2072_dpio *io, const struct qcc2072_dpio_vdev *v)
{
    int rc = enter(io);
    if (rc) return rc;
    if (!v || (v->encap != QCC2072_DPIO_ENCAP_ETHERNET && v->encap != QCC2072_DPIO_ENCAP_NATIVE_WIFI) ||
        v->bank_id >= TCL_BANKS || v->pdev_id > 3 || v->lmac_id > 3) return QCC2072_INVALID_ARGUMENT;
    if (io->vdev_set && qcc2072_dpio_tx_pending(io)) return QCC2072_BAD_STATE;
    io->busy = 1;
    if (!io->dscp_done) {
        uint8_t map[24];
        for (unsigned g = 0; g < 8; g++) {               /* DSCP 8g..8g+7 -> TID g */
            uint32_t value = 0;
            for (unsigned k = 0; k < 8; k++) value |= (uint32_t)g << (3 * k);
            map[g * 3] = (uint8_t)value; map[g * 3 + 1] = (uint8_t)(value >> 8);
            map[g * 3 + 2] = (uint8_t)(value >> 16);
        }
        for (unsigned id = 0; !rc && id < DSCP_TABLES; id++) {
            uint32_t ctrl;
            if ((rc = reg_read(io, REG_TCL_CMN_CTRL, &ctrl))) break;
            if ((rc = reg_write(io, REG_TCL_CMN_CTRL, ctrl | DSCP_PROG_EN))) break;
            for (unsigned j = 0; !rc && j < DSCP_WORDS; j++)
                rc = reg_write(io, REG_DSCP0 + 4U * (id * DSCP_WORDS + j), get32(map + 4 * j));
            if (!rc) rc = reg_read(io, REG_TCL_CMN_CTRL, &ctrl);
            if (!rc) rc = reg_write(io, REG_TCL_CMN_CTRL, ctrl & ~DSCP_PROG_EN);
        }
        if (!rc) io->dscp_done = 1;
    }
    /* ath12k_wifi7_dp_tx_get_vdev_bank_config for a STA vdev (ADDRY search). */
    uint32_t bank = ((uint32_t)v->encap << 1) | (1U << 9) | (1U << 11) | (1U << 14), back = 0;
    if (!rc) rc = reg_write(io, REG_BANK0 + 4U * v->bank_id, bank);
    if (!rc) rc = reg_read(io, REG_BANK0 + 4U * v->bank_id, &back);
    if (!rc && back != bank) rc = fail(io, QCC2072_RUNTIME_IO);
    if (!rc) { io->vdev = *v; io->vdev_set = 1; }
    io->busy = 0;
    return rc;
}
int qcc2072_dpio_set_bss(struct qcc2072_dpio *io, const uint8_t bssid[6])
{
    int rc = enter(io);
    if (rc) return rc;
    if (!bssid || (bssid[0] & 1U)) return QCC2072_INVALID_ARGUMENT;
    copy(io->bssid, bssid, 6); io->bss_set = 1;
    return 0;
}
int qcc2072_dpio_clear_bss(struct qcc2072_dpio *io)
{
    if (!io || !io->initialized || io->busy || io->in_tx) return QCC2072_BAD_STATE;
    io->bss_set = 0; zero(io->bssid, 6);
    return 0;
}
/* HTT_T2H_MSG_TYPE_PEER_MAP(3)/MAP2(0x1e)/MAP3(0x2b), UNMAP(4)/UNMAP2(0x1f). */
int qcc2072_dpio_htt_t2h(struct qcc2072_dpio *io, const uint8_t *m, size_t n)
{
    if (!io || !io->initialized || io->in_tx) return QCC2072_BAD_STATE;
    if (io->quarantined) return QCC2072_QUARANTINED;
    if (!m || n < 4) return QCC2072_BAD_WIRE;
    unsigned type = m[0];
    uint16_t peer_id = get16(m + 2);
    if (type == 4 || type == 0x1f) {
        if (n < 12) return QCC2072_BAD_WIRE;
        for (unsigned i = 0; i < QCC2072_DPIO_PEERS; i++)
            if (io->peers[i].valid && io->peers[i].peer_id == peer_id) zero(&io->peers[i], sizeof(io->peers[i]));
        io->stats.peer_unmaps++;
        return 0;
    }
    if (type != 3 && type != 0x1e && type != 0x2b) { io->stats.htt_ignored++; return QCC2072_RUNTIME_UNSUPPORTED; }
    if (n < 16) return QCC2072_BAD_WIRE;
    struct qcc2072_dpio_peer p;
    zero(&p, sizeof(p));
    copy(p.mac, m + 4, 6); p.vdev_id = m[1]; p.peer_id = peer_id; p.valid = 1; p.map_type = (uint8_t)type;
    if (type == 0x1e) { p.hw_peer_id = get16(m + 10); p.ast_hash = get16(m + 12); p.ast_valid = 1; }
    if (type == 0x2b) { p.hw_peer_id = get16(m + 12); p.ast_hash = get16(m + 14); p.ast_valid = 1; }
    unsigned slot = QCC2072_DPIO_PEERS;
    for (unsigned i = 0; i < QCC2072_DPIO_PEERS && slot == QCC2072_DPIO_PEERS; i++)
        if (io->peers[i].valid && io->peers[i].vdev_id == p.vdev_id && same_mac(io->peers[i].mac, p.mac)) slot = i;
    for (unsigned i = 0; i < QCC2072_DPIO_PEERS && slot == QCC2072_DPIO_PEERS; i++)
        if (!io->peers[i].valid) slot = i;
    if (slot == QCC2072_DPIO_PEERS) slot = io->stats.peer_maps % QCC2072_DPIO_PEERS;
    io->peers[slot] = p;
    io->stats.peer_maps++;
    return 0;
}
/* ath12k_wifi7_hal_reo_qdesc_setup(tid, ba_window 1, ssn 0, HAL_PN_TYPE_NONE),
 * sized like ath12k_wifi7_dp_rx_assign_reoq (DP_BA_WIN_SZ_MAX for QoS TIDs). */
int qcc2072_dpio_reo_qdesc(struct qcc2072_dpio *io, unsigned tid, uint32_t *iova)
{
    int rc = enter(io);
    if (rc) return rc;
    if (tid > NON_QOS_TID || !iova) return QCC2072_INVALID_ARGUMENT;
    uint32_t off = QCC2072_DPIO_QDESC_ARENA + tid * QCC2072_DPIO_QDESC_STRIDE;
    uint32_t size = tid == NON_QOS_TID ? 128U : 128U + 10U * 128U + 128U;
    uint8_t *q = dp_cpu(io, off);
    unsigned ac = (tid == 0 || tid == 3) ? 0 : (tid == 1 || tid == 2) ? 1 : (tid == 4 || tid == 5) ? 2 : 3;
    unsigned ba = tid == NON_QOS_TID ? 1 : 2;      /* ba 1 bumped to 2 for QoS TIDs */
    zero(q, QCC2072_DPIO_QDESC_STRIDE);
    put32(q, 4U | (8U << 4) | (0xddbeefU << 8));   /* REO owned, queue desc, magic 0 */
    put32(q + 4, tid);
    put32(q + 8, 1U | (1U << 1) | (ac << 5) | (ba == 1 ? 1U << 8 : 0) | ((ba - 1U) << 11) | (1U << 27));
    if (tid != NON_QOS_TID) {
        static const uint32_t magic[3] = {0xadbeefU, 0xbdbeefU, 0xcdbeefU};
        for (unsigned i = 0; i < 3; i++) put32(q + 128 + 128 * i, 4U | (9U << 4) | (magic[i] << 8));
    }
    if ((rc = sync(io, &io->dp->arena, off, size, QCC2072_SYNC_DEVICE))) return rc;
    *iova = dp_iova(io, off);
    return 0;
}
static size_t wmi_frame(uint8_t *out, size_t cap, uint32_t cmd, uint32_t tag, size_t body)
{
    if (!out || cap < 8 + body) return 0;
    zero(out, 8 + body);
    put32(out, cmd); put32(out + 4, tag << 16 | (uint32_t)body);
    return 8 + body;
}
size_t qcc2072_dpio_wmi_reorder_setup(uint8_t *out, size_t cap, uint32_t vdev, const uint8_t mac[6],
                                      unsigned tid, uint32_t queue)
{
    if (!mac || tid > NON_QOS_TID || !queue || (queue & 127U)) return 0;
    size_t n = wmi_frame(out, cap, 0x6013U, 549U, 36);  /* PEER_REORDER_QUEUE_SETUP */
    if (!n) return 0;
    put32(out + 8, vdev); copy(out + 12, mac, 6);
    put32(out + 20, tid); put32(out + 24, queue); put32(out + 28, 0);
    put32(out + 32, tid); put32(out + 36, 1); put32(out + 40, 1);
    return n;
}
size_t qcc2072_dpio_wmi_default_routing(uint8_t *out, size_t cap, uint32_t vdev, const uint8_t mac[6])
{
    if (!mac) return 0;
    size_t n = wmi_frame(out, cap, 0x6004U, 100U, 20);  /* PEER_SET_PARAM */
    if (!n) return 0;
    put32(out + 8, vdev); copy(out + 12, mac, 6);
    put32(out + 20, 19); put32(out + 24, 1U | (1U << 1)); /* DEFAULT_ROUTING: hash, REO dest 1 */
    return n;
}
size_t qcc2072_dpio_wmi_vdev_encap(uint8_t *out, size_t cap, uint32_t vdev, int rx_decap, uint32_t value)
{
    if (value > 2) return 0;
    size_t n = wmi_frame(out, cap, 0x5008U, 95U, 12);   /* VDEV_SET_PARAM */
    if (!n) return 0;
    put32(out + 8, vdev); put32(out + 12, rx_decap ? 91U : 48U); put32(out + 16, value);
    return n;
}

/* ---- Poll: completions first (frees slots), then RX, then refill. ---- */
int qcc2072_dpio_poll(struct qcc2072_dpio *io, unsigned budget)
{
    int rc = enter(io);
    if (rc) return rc;
    if (!budget) budget = 64;
    io->busy = 1;
    rc = sync(io, &io->dp->arena, 0, 9U * 64U, QCC2072_SYNC_CPU);
    if (!rc) rc = sync(io, &io->reo->arena, 0, 10U * 64U, QCC2072_SYNC_CPU);
    if (!rc) rc = tx_completions(io, budget);
    for (unsigned k = 0; !rc && k < REO_DST_RINGS; k++) rc = reo_dest(io, k, budget);
    if (!rc) rc = rx_errors(io, budget);
    if (!rc) rc = exceptions(io, budget);
    if (!rc) rc = refill_flush(io);
    io->busy = 0;
    return rc;
}
int qcc2072_dpio_abort(struct qcc2072_dpio *io, int reason)
{
    if (!io || !io->initialized) return QCC2072_BAD_STATE;
    return fail(io, reason ? reason : QCC2072_QUARANTINED);
}
