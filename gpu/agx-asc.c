/* SPDX-License-Identifier: MIT */
/* Portions (constants and expressions marked [M1N1]) from m1n1, https://github.com/AsahiLinux/m1n1:
 * Copyright The Asahi Linux Contributors, MIT. */
/* The GFX coprocessor's mailbox, the RTKit boot handshake on top of it, and
 * the MMIO decode for the whole device. See agx.h.
 *
 * The shape of this half is set by one string in the stock kernelcache:
 *
 *     AGXk: %s:%d:%s: !!! GFX firmware was not loaded by iBoot
 *
 * and by the method next to it,
 *
 *     AGXFirmwareKextG16RTBuddy::requestFirmwareBinary(const uint8_t **,
 *                                                      size_t *, ...)
 *
 * which hands back a pointer and a length rather than loading anything. The
 * AGX kext does not read firmware from a filesystem; it expects the boot loader
 * to have placed it in memory already. So the model's job at this layer is not
 * to serve a file -- it is to be a coprocessor that has already been started.
 *
 * What the AP then sees is an ASC mailbox (`iop,ascwrap-v6`) and, above it,
 * RTKit: HELLO, a version, an endpoint map, and START_EP per endpoint. That
 * sequence is implemented. Everything past it -- the shared-memory rings the
 * kext calls "kicks" -- is not, and is listed in agx_unmodelled().
 */
#include "agx.h"

/* ------------------------------------------------------------------- FIFOs */

int agx_fifo_push(struct agx_fifo *f, const struct agx_msg *m)
{
    if (f->count >= AGX_MBOX_DEPTH) {
        f->overflow++;
        return -1;
    }
    f->slot[f->tail] = *m;
    f->tail = (f->tail + 1) % AGX_MBOX_DEPTH;
    f->count++;
    return 0;
}

int agx_fifo_pop(struct agx_fifo *f, struct agx_msg *m)
{
    if (!f->count)
        return -1;
    *m = f->slot[f->head];
    f->head = (f->head + 1) % AGX_MBOX_DEPTH;
    f->count--;
    return 0;
}

static uint32_t fifo_control(const struct agx_fifo *f)
{
    uint32_t v = f->count;

    if (f->count == 0)
        v |= AGX_ASC_MBOX_CTRL_EMPTY;
    if (f->count >= AGX_MBOX_DEPTH)
        v |= AGX_ASC_MBOX_CTRL_FULL;
    return v;
}

/* ------------------------------------------------------------------- RTKit */

/* A management message packs its type into bits 59:52. [M1N1 rtkit.c:29] */
static uint64_t mgmt(uint64_t type, uint64_t payload)
{
    return ((type & 0xffULL) << 52) | payload;
}

static uint64_t mgmt_type(uint64_t msg)
{
    return (msg >> 52) & 0xffULL;
}

static void send(struct agx_asc *asc, uint32_t ep, uint64_t msg0)
{
    struct agx_msg m = { msg0, ep };
    agx_fifo_push(&asc->i2a, &m);
}

void agx_asc_init(struct agx_asc *asc, uint64_t base)
{
    for (unsigned i = 0; i < sizeof(*asc); i++)
        ((unsigned char *)asc)[i] = 0;
    asc->base = base;
    asc->state = AGX_ASC_OFF;
}

int agx_asc_booted(const struct agx_asc *asc)
{
    return asc->state == AGX_ASC_RUNNING;
}

/* The AP has set CPU_CONTROL.START. A real ASC begins executing the firmware
 * iBoot left in memory; here that means announcing ourselves with HELLO and the
 * version range we support. */
static void asc_start(struct agx_asc *asc)
{
    if (asc->state != AGX_ASC_OFF)
        return;
    asc->state = AGX_ASC_BOOTING;
    send(asc, AGX_RTKIT_EP_MGMT,
         mgmt(AGX_MGMT_MSG_HELLO,
              ((uint64_t)AGX_RTKIT_MAX_VERSION << 16) | AGX_RTKIT_MIN_VERSION));
}

static void asc_stop(struct agx_asc *asc)
{
    uint64_t base = asc->base;

    agx_asc_init(asc, base);
}

/* One management message from the AP. */
static void handle_mgmt(struct agx_asc *asc, uint64_t msg)
{
    uint64_t type = mgmt_type(msg);

    switch (type) {
    case AGX_MGMT_MSG_HELLO_ACK: {
        /* The AP picks a version inside the range we offered. A version
         * outside it is a protocol error, not something to accept quietly. */
        uint32_t version = (uint32_t)(msg & 0xffffULL);

        if (version < AGX_RTKIT_MIN_VERSION || version > AGX_RTKIT_MAX_VERSION) {
            asc->unknown_writes++;
            return;
        }
        asc->version = version;
        asc->state = AGX_ASC_EPMAP;
        /* Publish the endpoint map: one bitmap, base 0, DONE set. The bits are
         * the endpoints this coprocessor offers. */
        send(asc, AGX_RTKIT_EP_MGMT,
             mgmt(AGX_MGMT_MSG_EPMAP,
                  (1ULL << 51) |                       /* DONE */
                  (1ULL << AGX_RTKIT_EP_CRASHLOG) |
                  (1ULL << AGX_RTKIT_EP_SYSLOG) |
                  (1ULL << AGX_RTKIT_EP_DEBUG) |
                  (1ULL << AGX_RTKIT_EP_IOREPORT)));
        return;
    }
    case AGX_MGMT_MSG_EPMAP:
        /* The AP's reply to the map. MORE (bit 0) would ask for another
         * window; we published one window with DONE, so there is none. */
        return;

    case AGX_MGMT_MSG_START_EP: {
        uint32_t ep = (uint32_t)((msg >> 32) & 0xffULL);

        if (ep < 32)
            asc->ep_started |= 1U << ep;
        if (asc->state == AGX_ASC_EPMAP)
            asc->state = AGX_ASC_RUNNING;
        return;
    }
    case AGX_MGMT_MSG_IOP_PWR_STATE:
        send(asc, AGX_RTKIT_EP_MGMT,
             mgmt(AGX_MGMT_MSG_IOP_PWR_ACK, msg & 0xffffULL));
        return;

    case AGX_MGMT_MSG_AP_PWR_STATE:
        /* Acked with the same type. [M1N1 rtkit.c:63-64] */
        send(asc, AGX_RTKIT_EP_MGMT,
             mgmt(AGX_MGMT_MSG_AP_PWR_STATE, msg & 0xffffULL));
        return;

    default:
        asc->unknown_writes++;
        return;
    }
}

int agx_asc_step(struct agx_asc *asc)
{
    struct agx_msg m;
    int consumed = 0;

    if (asc->state == AGX_ASC_OFF)
        return 0;

    while (agx_fifo_pop(&asc->a2i, &m) == 0) {
        consumed++;
        if ((m.msg1 & 0xff) == AGX_RTKIT_EP_MGMT)
            handle_mgmt(asc, m.msg0);
        else
            asc->unknown_writes++;   /* traffic to an endpoint we do not serve */
    }
    return consumed;
}

/* -------------------------------------------------------------- MMIO decode */

static int asc_read(struct agx_asc *asc, uint64_t off, uint64_t *out)
{
    struct agx_msg m;

    *out = 0;
    if (off == AGX_ASC_CPU_CONTROL) {
        *out = asc->cpu_control;
        return 0;
    }
    if (off < AGX_ASC_MBOX_OFFSET)
        return -1;
    off -= AGX_ASC_MBOX_OFFSET;

    switch (off) {
    case AGX_ASC_MBOX_A2I_CONTROL:
        *out = fifo_control(&asc->a2i);
        return 0;
    case AGX_ASC_MBOX_I2A_CONTROL:
        *out = fifo_control(&asc->i2a);
        return 0;
    /* The AP reads what the coprocessor sent on the I2A RECV pair. Reading
     * RECV0 is what dequeues; RECV1 must be read first or the tag is lost, so
     * the message is held until RECV0 is read. */
    case AGX_ASC_MBOX_I2A_RECV0:
        if (agx_fifo_pop(&asc->i2a, &m) == 0)
            *out = m.msg0;
        return 0;
    case AGX_ASC_MBOX_I2A_RECV1:
        if (asc->i2a.count)
            *out = asc->i2a.slot[asc->i2a.head].msg1;
        return 0;
    default:
        return -1;
    }
}

static int asc_write(struct agx_asc *asc, uint64_t off, uint64_t value)
{
    if (off == AGX_ASC_CPU_CONTROL) {
        uint32_t was = asc->cpu_control;

        asc->cpu_control = (uint32_t)value;
        if (!(was & AGX_ASC_CPU_CONTROL_START) && (value & AGX_ASC_CPU_CONTROL_START))
            asc_start(asc);
        else if ((was & AGX_ASC_CPU_CONTROL_START) && !(value & AGX_ASC_CPU_CONTROL_START))
            asc_stop(asc);
        return 0;
    }
    if (off < AGX_ASC_MBOX_OFFSET)
        return -1;
    off -= AGX_ASC_MBOX_OFFSET;

    switch (off) {
    /* SEND1 carries the tag and is written second, so it is the write that
     * commits the message. SEND0 is latched. */
    case AGX_ASC_MBOX_A2I_SEND0:
        asc->a2i.slot[asc->a2i.tail].msg0 = value;
        return 0;
    case AGX_ASC_MBOX_A2I_SEND1: {
        struct agx_msg m = { asc->a2i.slot[asc->a2i.tail].msg0, (uint32_t)value };

        agx_fifo_push(&asc->a2i, &m);
        return 0;
    }
    case AGX_ASC_MBOX_A2I_CONTROL:
    case AGX_ASC_MBOX_I2A_CONTROL:
        return 0;                  /* status; writes are accepted and dropped */
    default:
        return -1;
    }
}

static struct agx_asc *window_of(struct agx_device *dev, uint64_t pa, uint64_t *off)
{
    for (unsigned i = 0; i < 2; i++) {
        uint64_t base = dev->asc[i].base;

        if (pa >= base && pa < base + AGX_ASC_SIZE) {
            *off = pa - base;
            return &dev->asc[i];
        }
    }
    return 0;
}

static int in_sgx(uint64_t pa)
{
    return pa >= AGX_SGX_BASE && pa < AGX_SGX_BASE + AGX_SGX_SIZE;
}

void agx_init(struct agx_device *dev, const struct agx_mem *mem)
{
    for (unsigned i = 0; i < sizeof(*dev); i++)
        ((unsigned char *)dev)[i] = 0;
    agx_asc_init(&dev->asc[0], AGX_ASC0_BASE);
    agx_asc_init(&dev->asc[1], AGX_ASC1_BASE);
    agx_uat_init(&dev->uat, mem);
}

int agx_mmio_read(struct agx_device *dev, uint64_t pa, unsigned size, uint64_t *out)
{
    struct agx_asc *asc;
    uint64_t off;

    *out = 0;
    if (size != 4 && size != 8)
        return -2;

    asc = window_of(dev, pa, &off);
    if (asc) {
        dev->mmio_reads++;
        if (asc_read(asc, off, out) != 0) {
            dev->mmio_undecoded++;
            return -1;
        }
        return 0;
    }
    if (in_sgx(pa)) {
        /* The sgx window is 64 MiB and this model claims no register in it.
         * Reads are answered zero and counted. Two offsets are named by the
         * ADT (`meta-sw-interrupt`) and even those are not decoded, because
         * what their fields mean is not established -- see agx_unmodelled(). */
        dev->mmio_reads++;
        dev->mmio_undecoded++;
        return -1;
    }
    return -2;
}

int agx_mmio_write(struct agx_device *dev, uint64_t pa, unsigned size, uint64_t value)
{
    struct agx_asc *asc;
    uint64_t off;

    if (size != 4 && size != 8)
        return -2;

    asc = window_of(dev, pa, &off);
    if (asc) {
        dev->mmio_writes++;
        if (asc_write(asc, off, value) != 0) {
            dev->mmio_undecoded++;
            return -1;
        }
        return 0;
    }
    if (in_sgx(pa)) {
        dev->mmio_writes++;
        dev->mmio_undecoded++;
        return -1;
    }
    return -2;
}

/* ------------------------------------------------------------------ honesty */

const char *const *agx_unmodelled(void)
{
    static const char *const list[] = {
        "sgx reg[0] is 64 MiB and no register in it is decoded; reads answer 0",
        "meta-sw-interrupt names offsets 0x1014048 and 0x1014248 inside sgx "
            "reg[0]; the field meanings and the trailing 0x4000 are unread",
        "gfx-asc reg[1] (8 bytes at 0x272050000) has no known purpose",
        "the 8 sgx and 4 gfx-asc interrupts are never raised",
        "the command rings ('kicks'): FW Ring read/write/cfi_index, the KSM "
            "kick queue, AGXCommandQueue -- shared memory, not modelled",
        "UAT MAP_BEGIN/MAP_CONTINUE and the segment-list walk behind them",
        "UAT PREP_FW_UNMAP_BEGIN/CONTINUE and UNMAP_BEGIN/CONTINUE",
        "UAT GET_INFO: the reply layout is unknown",
        "UAT endpoint 13: a stub exists in mac17p, no name anywhere",
        "the cache maintenance real SPTM performs on every mapped frame so the "
            "coprocessor sees the data (m1n1-j700 uat_publish_mapped_data_page)",
        "the GPU firmware itself: armfw_g17p.im4p is ARM code for the ASC and "
            "is not executed by this model",
        "power and perf: ~150 gpu-* ADT properties AGXG17P reads, none of "
            "which exist in the shipped DeviceTree.j700ap",
        0,
    };
    return list;
}
