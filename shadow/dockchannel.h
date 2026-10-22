/* SPDX-License-Identifier: MIT */
/* The J700's dock-channel UART, as much of it as XNU's boot console touches.
 *
 * This is the device the kernel writes its printf output to. It is not on this
 * laptop -- the addresses come out of Apple's device tree and name a bus that
 * does not exist here -- so the monitor answers for it at EL2 and copies every
 * transmitted byte into the console buffer the host already reads.
 *
 * Kept out of probes/xnuboot.c for one reason: everything here is a pure
 * function of a syndrome and an offset, so it compiles for the host and
 * tools/test-dockchannel.c can walk every register and every access width.
 * The probe supplies the context -- the console buffer, the counters, the
 * guest's register file -- and this supplies the answers.
 *
 * Every offset below was read out of the running kernel's own code
 * (downloads/extracted/j700ap/kernelcache.release.mac17p, which is the image
 * this device boots), not out of q1n1's driver. Where the two disagree, which
 * they do, the comment says so.
 */
#ifndef DOCKCHANNEL_H
#define DOCKCHANNEL_H

#include <stdint.h>

/* --------------------------------------------------------------------------
 * The access, as the stage-2 syndrome describes it.
 *
 * A data abort from EL1 with ISS.ISV set names the access completely: how wide
 * it was, which register it came from or goes to, which direction, and whether
 * a load sign-extends into a 32- or 64-bit destination. That is enough to
 * emulate it without fetching and decoding the instruction at the PC -- which
 * is the part that would otherwise have to be right about every load/store
 * form XNU might use, and silently wrong about one of them.
 *
 * ISV clear is the honest gap: pair loads and writeback forms do not describe
 * themselves, and then the syndrome says nothing about which registers moved.
 * `valid` is 0 and the caller must stop rather than guess.
 */
struct dc_access {
    uint8_t valid;  /* ISS.ISV: the syndrome describes the access */
    uint8_t write;  /* ISS.WnR: 1 is a store */
    uint8_t size;   /* 1, 2, 4 or 8 bytes, from ISS.SAS */
    uint8_t reg;    /* ISS.SRT: 0..31, where 31 is the zero register */
    uint8_t sign;   /* ISS.SSE: the load sign-extends its result */
    uint8_t wide;   /* ISS.SF:  the destination is an X, not a W */
};

/* Pull the six fields out of ESR_EL2. The caller has already established this
 * is a data abort from a lower EL (EC 0x24); on any other syndrome the ISS
 * bits mean other things, and `valid` comes back 0 rather than plausible. */
struct dc_access dc_decode(uint64_t esr);

/* A value the device produced, in the destination register's terms: narrowed
 * to the access width, sign-extended when the load said so, then narrowed to
 * 32 bits when the destination is a W register -- which zeroes bits 63:32,
 * exactly as the hardware would. */
uint64_t dc_extend(const struct dc_access *a, uint64_t value);

/* A value the guest is storing, narrowed to the access width. */
uint64_t dc_narrow(const struct dc_access *a, uint64_t value);

/* --------------------------------------------------------------------------
 * The device.
 *
 * Two register windows, in the order `/arm-io/dockchannel-uart`'s `reg`
 * property lists them -- which is the order the loader derives them in, the
 * order they arrive in `struct params`, and the order XNU maps them in:
 *
 *   window 0   0x10000   four 0x4000-strided blocks. Block 0 is a config
 *                        block, block 1 the data block the console transmits
 *                        and receives on, blocks 2 and 3 the same pair for the
 *                        other direction of the link.
 *   window 1    0x1000   the interrupt block: two (mask, flag) pairs.
 *
 * The 0x4000 stride and the block roles are q1n1's
 * (proxyclient/m1n1/hw/dockchannel.py); the device tree confirms them, because
 * /arm-io/dockchannel-mtp lists the same blocks as six separate 0x1000
 * windows at exactly those strides off its own base.
 *
 * Identified by index rather than by address, so a device tree that puts the
 * node somewhere else still works. dc_shape() checks the windows are the size
 * this model was written against, because a tree with a differently shaped
 * node should stop the run rather than be answered with offsets that mean
 * something else there.
 */
#define DC_WINDOW_DATA 0
#define DC_WINDOW_IRQ  1

/* The smallest windows this model can be right about: window 0 must reach the
 * last block-3 register we answer, window 1 its second (mask, flag) pair. */
#define DC_DATA_SPAN_MIN 0xc030
#define DC_IRQ_SPAN_MIN  0x10

/* The block stride inside window 0, and the registers within a data block.
 * Named here because the test walks them and the probe reports them. */
#define DC_BLOCK          0x4000
#define DC_CFG_TX_THRESH  0x00   /* XNU writes 0xff */
#define DC_CFG_RX_THRESH  0x04
#define DC_CFG_DIVIDER    0x08   /* XNU writes a value it computes from the
                                  * tree's max-aop-clk; q1n1 does not name it */
#define DC_DATA_TX8       0x04
#define DC_DATA_TX16      0x08
#define DC_DATA_TX24      0x0c
#define DC_DATA_TX32      0x10
#define DC_DATA_TX_FREE   0x14
#define DC_DATA_RX_COUNT  0x18   /* XNU's rx count, masked to 7 bits. q1n1 calls
                                  * 0x2c RX_COUNT and names nothing at 0x18 --
                                  * the kernel is the authority on which one its
                                  * own driver polls, and it polls this one. */
#define DC_DATA_RX8       0x1c   /* the byte is in bits 15:8 */
#define DC_DATA_RX16      0x20
#define DC_DATA_RX24      0x24
#define DC_DATA_RX32      0x28   /* deliberately NOT modelled: see dockchannel.c */
#define DC_DATA_RX_COUNT2 0x2c   /* q1n1's RX_COUNT */

/* What the transmit-free register answers. Any non-zero value satisfies both
 * shapes of poll -- q1n1's `while (tx_free == 0)` and its `while (tx_free < 4)`
 * -- and XNU masks this register with 0xfff before using it (the tree's
 * `dock-wstat-mask`), so 0xfff is "as much room as this register can report". */
#define DC_TX_FREE_ANSWER 0xfff

/* What a register remembers between accesses. Only the config words and the
 * interrupt masks do; every other answer is computed. */
struct dockchannel {
    uint32_t cfg[3];      /* window 0 block 0: +0x0, +0x4, +0x8 */
    uint32_t irq_mask[2]; /* window 1: +0x0 and +0x8 */
};

/* Answers. DC_UNMODELLED is not something the guest ever sees: it stops the
 * run, because a register we cannot account for is exactly the thing this
 * project has learned not to paper over. */
#define DC_OK          0
#define DC_UNMODELLED (-1)

/* Are these windows the shape this model describes? `span` is the loader's
 * device_span[], `count` its device_count. */
int dc_shape(const uint64_t *span, uint64_t count);

/* Which window an intermediate address falls in, and where inside it; -1 for
 * none. `pa` and `span` are the loader's device_pa[]/device_span[], derived
 * from the guest's own device tree at build time -- which is what makes this
 * survive a tree that puts the UART somewhere else. Nothing here knows an
 * address. */
int dc_window(const uint64_t *pa, const uint64_t *span, uint64_t count,
              uint64_t ipa, uint64_t *off);

/* Read a register. `*value` is left untouched unless DC_OK comes back. */
int dc_read(const struct dockchannel *d, int window, uint64_t off,
            uint64_t *value);

/* Write a register. Bytes the device would have put on the wire come back in
 * `tx[0..*tx_len)`, low-order byte first, for the caller to append to the
 * console buffer; `*tx_len` is 0 for every register that is not a transmit
 * register. `tx` must have room for four. */
int dc_write(struct dockchannel *d, int window, uint64_t off, uint64_t value,
             uint8_t *tx, unsigned *tx_len);

/* --------------------------------------------------------------------------
 * Receive, when a launch asks for it (docs/GUEST-SHELL-DESIGN-20261016.md).
 *
 * XNU's serial_keyboard_poll (KDK 0xfffffe0007502fa8) reads block 1's RX_COUNT
 * every 16 ms and, while it is non-zero, takes one byte from RX_8. With a ring
 * of host input those two registers answer from it: RX_COUNT the bytes waiting
 * (XNU masks it to 7 bits), RX_8 one byte in bits 15:8 with a count of 1 in
 * bits 7:0 (q1n1's R_RX_DATA). Both come from the one count, so they cannot
 * disagree. RX_16, RX_24 and RX_32 would take several bytes at once; nothing
 * in the kernel reads them, so while input waits they stop the run instead of
 * answering something the count does not support. An empty ring, or none,
 * answers exactly as dc_read does.
 */
#define DC_RX_RING 1024u
struct dc_rx {
    uint32_t head, count;            /* buf[head] is the oldest waiting byte */
    uint64_t pushed, popped, refused;
    uint8_t buf[DC_RX_RING];
};

/* Room for this many more bytes. */
unsigned dc_rx_free(const struct dc_rx *r);
/* 0, or -1 when the ring is full (counted in `refused`). */
int dc_rx_push(struct dc_rx *r, uint8_t byte);
/* dc_read, with block 1's receive registers answered from `rx` (NULL: none). */
int dc_read_rx(const struct dockchannel *d, struct dc_rx *rx, int window,
               uint64_t off, uint64_t *value);

#endif /* DOCKCHANNEL_H */
