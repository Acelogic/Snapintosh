/* SPDX-License-Identifier: MIT */
/* The A16's QCC2072 Wi-Fi endpoint and its DMA arena, passed through to the
 * SnapintoshQCC2072 kext: -DSNAP_QCC2072_WIFI=1 only. Without the define
 * probes/xnuboot.c does not include this header and the monitor is the same
 * binary as before. Loader: probes/qcc2072wifi.py (cycle.py installed-fresh
 * --qcc2072-wifi), which appends struct qcc2072_wifi_params to struct params
 * (after the i2c-input block when that is built too), writes the arena and the
 * control page, and adds the /arm-io/snap-qcc2072 node.
 *
 * Failure modes, written before the code:
 *  1. A default build changes. Everything here is behind the define; the loader
 *     appends nothing without SNAP_QCC2072_WIFI. tools/test-qcc2072-wifi.py
 *     --build compares the default monitor with one built from the base sources.
 *  2. The loader and the monitor disagree (a define without the appended words,
 *     words from another structure, a shifted block). Nothing is mapped from the
 *     loader's numbers: the block must carry the magic and exactly the five
 *     allow-listed windows below, and the control page must hold a provider
 *     record naming the same windows, or stage-2 preparation refuses the boot
 *     with -42 before any guest CPU runs.
 *  3. The guest reaches another device or memory: the root port's DBI/ATU at
 *     0x7_8000_0000, another function's configuration, the BAR0..BAR2 gap, the
 *     rest of a 16 KiB guest page around a 4 KiB window. Stage 2 maps exactly
 *     the five windows; any other touch is the ordinary stage-2 stop with its IPA.
 *  4. The guest rewrites configuration space (moves a BAR, programs MSI, puts
 *     the card in D3, turns memory decode off under a live BAR mapping). The
 *     endpoint page is read-only at stage 2; the only store the monitor performs
 *     is to the command register (offset 4, 16 or 32 bits with a zero status
 *     half) with the value 2 (memory decode) or 6 (memory decode and bus
 *     master). Anything else stops the run as a stage-2 fault.
 *  5. The guest rewrites its admission record. The control page is read-only
 *     at stage 2 and holds the same 256 bytes the device-tree property carries;
 *     the provider compares both at every call.
 *  6. A cacheable guest alias of DMA memory. The arena and the control page are
 *     Normal non-cacheable at stage 2, which wins over any stage-1 attribute; the
 *     loader cleans and invalidates both to PoC after writing them. q1n1's own
 *     EL2 identity map stays cacheable (not changed here; see REPORT).
 *  7. Card DMA outside the arena. NOT prevented by this header: the firmware's
 *     shared PCIe SMMU stage-2 table (VMID 3) translates for the card, and it maps
 *     all low Conventional RAM and guest RAM identity. The loader checks the arena
 *     is identity-mapped there, keeps bus mastering off until the kext enables it
 *     and has the launcher turn it off again once the stopped state is preserved.
 *  8. Capacity: the stage-2 range array grows by QCC2072_WIFI_STAGE2_MAX under
 *     the define; stage2_build still refuses overlap and misalignment.
 */
#pragma once
#include <stdint.h>
#include "stage2.h"

/* "SNAPQCC1", little-endian: the loader appended these words on purpose. */
#define QCC2072_WIFI_MAGIC        0x3143435150414e53ULL
#define QCC2072_WIFI_F_ENABLE     1u
#define QCC2072_WIFI_PARAMS_WORDS 12
#define QCC2072_WIFI_STAGE2_MAX   5u
/* The endpoint as UEFI leaves it (hardware 2026-10-21): ECAM bus 1, two BARs. */
#define QCC2072_WIFI_BAR0_PA      0x78000000ULL
#define QCC2072_WIFI_BAR0_BYTES   0x100000ULL
#define QCC2072_WIFI_BAR2_PA      0x78200000ULL
#define QCC2072_WIFI_BAR2_BYTES   0x1000ULL
#define QCC2072_WIFI_ECAM_PA      0x780100000ULL
#define QCC2072_WIFI_ECAM_BYTES   0x1000ULL
/* Conventional RAM below 4 GiB, identity-mapped by the PCIe SMMU's stage 2. */
#define QCC2072_WIFI_DMA_PA       0xdc000000ULL
#define QCC2072_WIFI_DMA_BYTES    0x4000000ULL
#define QCC2072_WIFI_CONTROL_PA   0xe0000000ULL
#define QCC2072_WIFI_CONTROL_BYTES 0x1000ULL
#define QCC2072_WIFI_COMMAND      4u          /* PCI command register offset */
#define QCC2072_WIFI_CMD_MEMORY   0x2u        /* memory space decode */
#define QCC2072_WIFI_CMD_MASTER   0x4u        /* bus master */
/* drivers/snap-qcc2072/src/qcc2072-provider-record.h (QCCOWN01, 32 words). */
#define QCC2072_WIFI_RECORD_MAGIC 0x31304e574f434351ULL
#define QCC2072_WIFI_RECORD_WORDS 32u
/* Normal non-cacheable (MemAttr 0b0101), for memory the card reads and writes. */
#define QCC2072_WIFI_S2_MEMATTR_NC (5UL << 2)
#define QCC2072_WIFI_S2_ATTRS_NC   (QCC2072_WIFI_S2_MEMATTR_NC | S2_SH_INNER | S2_AF)

struct qcc2072_wifi_params {
    uint64_t magic;                    /* QCC2072_WIFI_MAGIC */
    uint64_t flags;                    /* QCC2072_WIFI_F_ENABLE */
    uint64_t bar0_pa, bar0_end;        /* each window [pa, end), in reg order */
    uint64_t dma_pa, dma_end;
    uint64_t bar2_pa, bar2_end;
    uint64_t ecam_pa, ecam_end;
    uint64_t control_pa, control_end;
};
_Static_assert(sizeof(struct qcc2072_wifi_params) == 8 * QCC2072_WIFI_PARAMS_WORDS,
               "probes/qcc2072wifi.py PARAMS_WORDS");

/* The allow-list, in reg order: BAR0, DMA, BAR2, endpoint ECAM page, control. */
static inline int qcc2072_wifi_valid(const struct qcc2072_wifi_params *p)
{
    return p->magic == QCC2072_WIFI_MAGIC && p->flags == QCC2072_WIFI_F_ENABLE &&
           p->bar0_pa == QCC2072_WIFI_BAR0_PA &&
           p->bar0_end == QCC2072_WIFI_BAR0_PA + QCC2072_WIFI_BAR0_BYTES &&
           p->dma_pa == QCC2072_WIFI_DMA_PA &&
           p->dma_end == QCC2072_WIFI_DMA_PA + QCC2072_WIFI_DMA_BYTES &&
           p->bar2_pa == QCC2072_WIFI_BAR2_PA &&
           p->bar2_end == QCC2072_WIFI_BAR2_PA + QCC2072_WIFI_BAR2_BYTES &&
           p->ecam_pa == QCC2072_WIFI_ECAM_PA &&
           p->ecam_end == QCC2072_WIFI_ECAM_PA + QCC2072_WIFI_ECAM_BYTES &&
           p->control_pa == QCC2072_WIFI_CONTROL_PA &&
           p->control_end == QCC2072_WIFI_CONTROL_PA + QCC2072_WIFI_CONTROL_BYTES;
}

/* The provider record on the control page names the same windows the
 * allow-list does (words 0-3, 6-18 and 28-31 of the 32). Generation and
 * cookie must be nonzero; the firmware offsets are the provider's to check. */
static inline int qcc2072_wifi_record_valid(const volatile uint64_t *r)
{
    static const uint64_t fixed[][2] = {
        {0, QCC2072_WIFI_RECORD_MAGIC}, {1, 1}, {2, 8 * QCC2072_WIFI_RECORD_WORDS}, {3, 1},
        {6, 0x111217cbULL}, {7, 0xe14f105bULL}, {8, 0x40100ULL}, {9, 31},
        {10, QCC2072_WIFI_BAR0_PA}, {11, QCC2072_WIFI_BAR0_BYTES},
        {12, QCC2072_WIFI_BAR2_PA}, {13, QCC2072_WIFI_BAR2_BYTES}, {14, QCC2072_WIFI_ECAM_PA},
        {15, QCC2072_WIFI_DMA_PA}, {16, QCC2072_WIFI_DMA_PA}, {17, QCC2072_WIFI_DMA_BYTES},
        {18, QCC2072_WIFI_CONTROL_PA}, {28, 64}, {29, 0}, {30, 0}, {31, 0},
    };
    for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (r[fixed[i][0]] != fixed[i][1])
            return 0;
    return r[4] && r[5];
}

/* The stage-2 rows of a valid block whose control page holds a matching
 * record, written to out (room for QCC2072_WIFI_STAGE2_MAX). Returns 5, or -1
 * when the block or the record differs from the allow-list; writes nothing on
 * -1. `record` is the control page (the monitor passes its physical address). */
static inline int qcc2072_wifi_rows(const struct qcc2072_wifi_params *p,
                                    const volatile uint64_t *record, struct stage2_range *out)
{
    if (!qcc2072_wifi_valid(p) || !record || !qcc2072_wifi_record_valid(record))
        return -1;
    out[0] = (struct stage2_range){p->bar0_pa, p->bar0_end, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
    out[1] = (struct stage2_range){p->dma_pa, p->dma_end, S2_AP_RW | QCC2072_WIFI_S2_ATTRS_NC, S2_XN};
    out[2] = (struct stage2_range){p->bar2_pa, p->bar2_end, S2_AP_RW | S2_ATTRS_DEVICE, S2_XN};
    out[3] = (struct stage2_range){p->ecam_pa, p->ecam_end, S2_AP_RO | S2_ATTRS_DEVICE, S2_XN};
    out[4] = (struct stage2_range){p->control_pa, p->control_end, S2_AP_RO | QCC2072_WIFI_S2_ATTRS_NC, S2_XN};
    return (int)QCC2072_WIFI_STAGE2_MAX;
}

/* Whether pa lies in one of the five windows of a valid block (MAP_PAGE's
 * evidence classification only; nothing is admitted or refused by it). */
static inline int qcc2072_wifi_window(const struct qcc2072_wifi_params *p, uint64_t pa)
{
    if (!qcc2072_wifi_valid(p))
        return 0;
    return (pa >= p->bar0_pa && pa < p->bar0_end) || (pa >= p->dma_pa && pa < p->dma_end) ||
           (pa >= p->bar2_pa && pa < p->bar2_end) || (pa >= p->ecam_pa && pa < p->ecam_end) ||
           (pa >= p->control_pa && pa < p->control_end);
}

/* A guest store that faulted on the read-only endpoint page. Returns 1 and the
 * 16-bit command value to write when it is a store to the command register the
 * monitor performs on the guest's behalf: offset 4, two bytes, or four bytes
 * whose status half is zero (its bits are write-one-to-clear), and the value
 * memory decode only (2) or memory decode with bus mastering (6). Returns 0 for
 * anything else, and the run stops on it as on any other stage-2 fault. */
static inline int qcc2072_wifi_command_store(const struct qcc2072_wifi_params *p, uint64_t ipa,
                                             unsigned size, uint64_t value, uint16_t *command)
{
    uint64_t v;
    if (!qcc2072_wifi_valid(p) || ipa != p->ecam_pa + QCC2072_WIFI_COMMAND)
        return 0;
    if (size == 2)
        v = value & 0xffffu;
    else if (size == 4 && !(value >> 16))
        v = value;
    else
        return 0;
    if (v != QCC2072_WIFI_CMD_MEMORY && v != (QCC2072_WIFI_CMD_MEMORY | QCC2072_WIFI_CMD_MASTER))
        return 0;
    *command = (uint16_t)v;
    return 1;
}
