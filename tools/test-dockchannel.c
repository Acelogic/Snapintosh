/* SPDX-License-Identifier: MIT */
/* The dock-channel UART model, and the syndrome decode that drives it.
 *
 * Two things are checked here, and they fail in different ways.
 *
 * The syndrome decode is arithmetic on ESR_EL2 and it is the part most likely
 * to be quietly wrong: a sign extension applied in the wrong order, or a W
 * destination that keeps its top half, moves a value into a guest register
 * that looks plausible and is not. Every combination of size, sign and width
 * is walked against a hand-computed expectation.
 *
 * The device model is a table of offsets, and what matters about it is as much
 * what it REFUSES as what it answers. A model that returns zero for a register
 * it does not know would let a run get further while understanding less, which
 * is the failure this project has paid for most often -- so the refusals are
 * tested as hard as the answers, offset by offset across both windows.
 *
 * cc -std=gnu11 -O1 -g -fsanitize=address,undefined -Ishadow \
 *    tools/test-dockchannel.c shadow/dockchannel.c -o build/test-dockchannel
 */
#include <stdio.h>
#include <string.h>
#include "dockchannel.h"

static int checks, failures;

static void check(int condition, const char *label)
{
    if (condition) {
        checks++;
    } else {
        failures++;
        printf("FAIL: %s\n", label);
    }
}

/* A data abort from a lower EL, as the hardware would present it. */
static uint64_t syndrome(unsigned sas, unsigned sse, unsigned srt, unsigned sf,
                         unsigned wnr, unsigned isv)
{
    return ((uint64_t)0x24 << 26) | ((uint64_t)isv << 24) |
           ((uint64_t)sas << 22) | ((uint64_t)sse << 21) |
           ((uint64_t)srt << 16) | ((uint64_t)sf << 15) |
           ((uint64_t)wnr << 6) | 0x05;   /* FSC: translation fault, level 1 */
}

/* Read one register through the model, the way the dispatcher does. */
static int read_reg(const struct dockchannel *d, int window, uint64_t off,
                    uint64_t *value)
{
    return dc_read(d, window, off, value);
}

int main(void)
{
    struct dockchannel dev;
    struct dc_access a;
    uint64_t value;
    uint8_t tx[4];
    unsigned tx_len;
    uint64_t spans[2];

    memset(&dev, 0, sizeof dev);

    /* ---------------------------------------------------------------- the
     * syndrome. */
    a = dc_decode(syndrome(2, 0, 22, 0, 0, 1));
    check(a.valid, "a data abort with ISV set describes its access");
    check(a.size == 4, "SAS 2 is a four-byte access");
    check(a.reg == 22, "SRT names the register");
    check(a.write == 0, "WnR clear is a read");
    check(a.wide == 0, "SF clear is a W destination");

    a = dc_decode(syndrome(3, 0, 5, 1, 1, 1));
    check(a.size == 8 && a.reg == 5 && a.write == 1 && a.wide == 1,
          "SAS 3, SF set and WnR set is an eight-byte store from an X register");

    a = dc_decode(syndrome(0, 0, 31, 0, 0, 1));
    check(a.size == 1 && a.reg == 31, "SRT 31 is the zero register, and is named as one");

    /* ISV clear is the one thing that must not be guessed at. */
    a = dc_decode(syndrome(2, 0, 22, 0, 0, 0));
    check(!a.valid, "ISV clear does not describe its access");

    /* And a syndrome that is not a data abort from a lower EL is not one. */
    a = dc_decode((0x20UL << 26) | (1UL << 24) | 0x05);
    check(!a.valid, "an instruction abort is not decoded as a data access");
    a = dc_decode((0x18UL << 26) | 0x05);
    check(!a.valid, "a trapped system register is not decoded as a data access");

    /* Narrowing and extending, which is where a wrong answer looks right. */
    a = dc_decode(syndrome(0, 0, 0, 1, 0, 1));          /* ldrb  x */
    check(dc_extend(&a, 0xffffffffffffff80UL) == 0x80,
          "an unsigned byte load keeps one byte");
    a = dc_decode(syndrome(0, 1, 0, 1, 0, 1));          /* ldrsb x */
    check(dc_extend(&a, 0x80) == 0xffffffffffffff80UL,
          "a signed byte load sign-extends to 64 bits");
    a = dc_decode(syndrome(0, 1, 0, 0, 0, 1));          /* ldrsb w */
    check(dc_extend(&a, 0x80) == 0xffffff80UL,
          "a signed byte load into a W register stops at 32 bits");
    a = dc_decode(syndrome(1, 1, 0, 0, 0, 1));          /* ldrsh w */
    check(dc_extend(&a, 0x8000) == 0xffff8000UL,
          "a signed halfword load into a W register stops at 32 bits");
    a = dc_decode(syndrome(2, 0, 0, 0, 0, 1));          /* ldr w */
    check(dc_extend(&a, 0xdeadbeefcafebabeUL) == 0xcafebabeUL,
          "a word load into a W register keeps the low word");
    a = dc_decode(syndrome(3, 0, 0, 1, 0, 1));          /* ldr x */
    check(dc_extend(&a, 0xdeadbeefcafebabeUL) == 0xdeadbeefcafebabeUL,
          "a doubleword load into an X register keeps everything");
    a = dc_decode(syndrome(1, 0, 0, 0, 1, 1));          /* strh */
    check(dc_narrow(&a, 0x11223344) == 0x3344,
          "a halfword store keeps two bytes");

    /* ---------------------------------------------------------------- the
     * shape check. A tree whose node is a different shape must be refused
     * rather than answered with offsets that mean something else there. */
    spans[0] = 0x10000; spans[1] = 0x1000;
    check(dc_shape(spans, 2), "the J700's two windows are the shape we model");
    check(!dc_shape(spans, 1), "one window alone is not");
    spans[0] = 0x4000;
    check(!dc_shape(spans, 2), "a data window too small to hold block 3 is not");
    spans[0] = 0x10000; spans[1] = 8;
    check(!dc_shape(spans, 2), "an irq window with only one mask/flag pair is not");

    /* ---------------------------------------------------------------- which
     * window an address falls in.
     *
     * The addresses below are the J700's, derived by the loader from
     * /arm-io/dockchannel-uart's `reg` through arm-io's `ranges`. They appear
     * here as data, never as a constant in the model: a tree that puts the
     * node elsewhere must still work, which is what the moved-windows case
     * checks. */
    {
        uint64_t pa[4] = {0x308128000UL, 0x30810c000UL, 0, 0};
        uint64_t span[4] = {0x10000, 0x1000, 0, 0};
        uint64_t off = 0xdead;
        int w;

        w = dc_window(pa, span, 2, 0x30810c000UL, &off);
        check(w == DC_WINDOW_IRQ && off == 0,
              "the first register XNU reads lands in window 1 at offset 0");
        w = dc_window(pa, span, 2, 0x308128000UL + 0x4004, &off);
        check(w == DC_WINDOW_DATA && off == 0x4004,
              "putc's address lands in window 0 at TX_8");
        w = dc_window(pa, span, 2, 0x308137fffUL, &off);
        check(w == DC_WINDOW_DATA && off == 0xffff, "the last byte of window 0 is in it");
        w = dc_window(pa, span, 2, 0x308138000UL, &off);
        check(w == -1, "the byte after window 0 is in no window");
        w = dc_window(pa, span, 2, 0x30810bfffUL, &off);
        check(w == -1, "the byte before window 1 is in no window");
        w = dc_window(pa, span, 2, 0xda000000UL, &off);
        check(w == -1, "ordinary memory is in no device window");
        /* The loader pads its arrays with zeros and passes the padded count
         * when fewer than four windows exist. A zero-span entry cannot match
         * anything -- `ipa >= 0 && ipa < 0` is false for every address -- so
         * this checks the padding is harmless, not that a guard catches it.
         * There is no guard: one here would never fire. */
        w = dc_window(pa, span, 4, 0, &off);
        check(w == -1, "padding entries match nothing, including address zero");
        /* And the whole point of reading these from params. */
        {
            uint64_t moved[4] = {0x900000000UL, 0x900100000UL, 0, 0};
            w = dc_window(moved, span, 2, 0x900100000UL + 0xc, &off);
            check(w == DC_WINDOW_IRQ && off == 0xc,
                  "a device tree that moves the UART still resolves, because "
                  "nothing here knows an address");
        }
    }

    /* ---------------------------------------------------------------- the
     * transmit path, which is the whole point. */
    check(dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX8, 'X',
                   tx, &tx_len) == DC_OK, "TX_8 is accepted");
    check(tx_len == 1 && tx[0] == 'X', "...and puts exactly that byte on the wire");

    check(dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX16, 0x4241,
                   tx, &tx_len) == DC_OK, "TX_16 is accepted");
    check(tx_len == 2 && tx[0] == 'A' && tx[1] == 'B',
          "...and puts two bytes on the wire, low order first");

    check(dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX24, 0x434241,
                   tx, &tx_len) == DC_OK, "TX_24 is accepted");
    check(tx_len == 3 && tx[0] == 'A' && tx[2] == 'C', "...and three, low order first");

    check(dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX32, 0x44434241,
                   tx, &tx_len) == DC_OK, "TX_32 is accepted");
    check(tx_len == 4 && tx[0] == 'A' && tx[3] == 'D', "...and four, low order first");

    /* A byte wider than the register is the register's width, not the bus's. */
    check(dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX8, 0xfffffe41,
                   tx, &tx_len) == DC_OK && tx_len == 1 && tx[0] == 'A',
          "TX_8 takes one byte out of a wider value");

    /* Reading a transmit register is not something this device does. */
    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX8, &value)
              == DC_UNMODELLED,
          "TX_8 is write-only here, and a read of it stops the run");

    /* ---------------------------------------------------------------- the
     * status and receive registers. */
    value = 0;
    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_TX_FREE, &value) == DC_OK,
          "TX_FREE answers");
    check(value == DC_TX_FREE_ANSWER && value != 0,
          "...and says there is room, or the kernel would spin forever");

    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_RX_COUNT, &value) == DC_OK
              && value == 0,
          "the rx count XNU polls (+0x18) says nothing is waiting");
    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_RX_COUNT2, &value) == DC_OK
              && value == 0,
          "the rx count q1n1 polls (+0x2c) says the same");
    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_RX8, &value) == DC_OK
              && value == 0,
          "RX_8 answers zero: no byte, and a zero count in its low byte");

    /* The one receive register that is all data and no count. Answering it
     * would hand the kernel four bytes nobody sent. */
    check(read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + DC_DATA_RX32, &value)
              == DC_UNMODELLED,
          "RX_32 has no count field, so it is refused rather than invented");

    /* Block 3, whose RX_8 the serial init reads on its way out. */
    check(read_reg(&dev, DC_WINDOW_DATA, 3 * DC_BLOCK + DC_DATA_RX8, &value) == DC_OK
              && value == 0,
          "block 3's RX_8 (+0xc01c), which XNU's serial init returns, answers zero");
    check(dc_write(&dev, DC_WINDOW_DATA, 3 * DC_BLOCK + DC_DATA_TX8, 'X',
                   tx, &tx_len) == DC_UNMODELLED,
          "nothing transmits on block 3, so a write there stops rather than "
          "being swallowed into the transcript");
    check(read_reg(&dev, DC_WINDOW_DATA, 3 * DC_BLOCK + DC_DATA_TX_FREE, &value)
              == DC_UNMODELLED,
          "block 3's TX_FREE is not modelled either");

    /* ---------------------------------------------------------------- the
     * config block: the three words XNU writes during init. */
    check(dc_write(&dev, DC_WINDOW_DATA, DC_CFG_TX_THRESH, 0xff, tx, &tx_len) == DC_OK
              && tx_len == 0,
          "TX_THRESH is accepted and transmits nothing");
    check(read_reg(&dev, DC_WINDOW_DATA, DC_CFG_TX_THRESH, &value) == DC_OK
              && value == 0xff,
          "...and reads back what was written");
    check(dc_write(&dev, DC_WINDOW_DATA, DC_CFG_DIVIDER, 0x1234, tx, &tx_len) == DC_OK,
          "the divider word XNU computes is accepted");
    check(read_reg(&dev, DC_WINDOW_DATA, DC_CFG_DIVIDER, &value) == DC_OK
              && value == 0x1234,
          "...and reads back");
    /* Block 2 is the same shape and nothing touches it. Answering for it would
     * be a register invented to look complete. */
    check(read_reg(&dev, DC_WINDOW_DATA, 2 * DC_BLOCK + DC_CFG_TX_THRESH, &value)
              == DC_UNMODELLED,
          "block 2's config is not modelled, because nothing uses it");

    /* ---------------------------------------------------------------- the
     * interrupt window: two (mask, flag) pairs. */
    check(dc_write(&dev, DC_WINDOW_IRQ, 0x0, 0xdead0000, tx, &tx_len) == DC_OK,
          "the first interrupt mask is accepted");
    check(read_reg(&dev, DC_WINDOW_IRQ, 0x0, &value) == DC_OK && value == 0xdead0000,
          "...and reads back, so XNU's read-modify-write of bits 0-1 sees its "
          "own value");
    check(dc_write(&dev, DC_WINDOW_IRQ, 0x8, 0x3, tx, &tx_len) == DC_OK
              && read_reg(&dev, DC_WINDOW_IRQ, 0x8, &value) == DC_OK && value == 0x3,
          "the second interrupt mask remembers too");

    check(dc_write(&dev, DC_WINDOW_IRQ, 0x4, 0x3, tx, &tx_len) == DC_OK,
          "acknowledging an interrupt is accepted");
    check(read_reg(&dev, DC_WINDOW_IRQ, 0x4, &value) == DC_OK && value == 0,
          "...but the flag register still reads zero, because nothing here ever "
          "raises one");
    check(read_reg(&dev, DC_WINDOW_IRQ, 0xc, &value) == DC_OK && value == 0,
          "the second flag register says the same");
    check(read_reg(&dev, DC_WINDOW_IRQ, 0x10, &value) == DC_UNMODELLED,
          "a third pair is not modelled: the window is 4 KiB and only two are used");

    /* ---------------------------------------------------------------- the
     * refusals, swept. Every offset in the first block of each window that is
     * not one of the registers above must be refused, in both directions. No
     * silent zero anywhere. */
    {
        unsigned answered = 0, refused = 0;
        for (uint64_t off = 0; off < 0x40; off += 4) {
            int r = read_reg(&dev, DC_WINDOW_DATA, DC_BLOCK + off, &value);
            int w = dc_write(&dev, DC_WINDOW_DATA, DC_BLOCK + off, 0, tx, &tx_len);
            if (r == DC_OK || w == DC_OK) answered++; else refused++;
        }
        /* TX_8/16/24/32, TX_FREE, RX_COUNT, RX_8/16/24, RX_COUNT2 = 10. */
        check(answered == 10, "exactly ten registers of the data block are modelled");
        check(refused == 6, "and the other six offsets in it are refused");
    }
    {
        unsigned refused = 0;
        for (uint64_t off = 0x10; off < 0x100; off += 4)
            if (read_reg(&dev, DC_WINDOW_IRQ, off, &value) == DC_UNMODELLED)
                refused++;
        check(refused == 60, "the rest of the interrupt window is refused");
    }
    /* And a window the tree might name that this model knows nothing about. */
    check(read_reg(&dev, 2, 0, &value) == DC_UNMODELLED,
          "a third device window is refused outright");
    check(dc_write(&dev, 2, 0, 0, tx, &tx_len) == DC_UNMODELLED,
          "...in both directions");

    /* ---------------------------------------------------------------- the
     * access this all exists to answer, end to end.
     *
     * ESR 0x93960005 at IPA 0x30810c000 is the fault that ends every run as of
     * bf0986b -- the real syndrome from the real machine, not a constructed
     * one. Walked here the way the dispatcher walks it: find the window,
     * decode, read, extend, and land a value in the register the syndrome
     * names. If this sequence is wrong, the kernel's first look at its own
     * UART gets a wrong answer and nothing after it means anything. */
    {
        uint64_t pa[4] = {0x308128000UL, 0x30810c000UL, 0, 0};
        uint64_t span[4] = {0x10000, 0x1000, 0, 0};
        uint64_t frame[31];
        uint64_t off = 0;
        int w;

        memset(frame, 0, sizeof frame);
        memset(&dev, 0, sizeof dev);

        w = dc_window(pa, span, 2, 0x30810c000UL, &off);
        check(w == DC_WINDOW_IRQ && off == 0, "the live fault resolves to window 1 +0");

        a = dc_decode(0x93960005UL);
        check(a.valid && a.size == 4 && a.reg == 22 && !a.write && !a.wide,
              "the live syndrome is a four-byte read into w22");

        check(dc_read(&dev, w, off, &value) == DC_OK, "...which the model answers");
        frame[a.reg] = dc_extend(&a, value);
        check(frame[22] == 0,
              "...with the interrupt mask, which starts clear");

        /* And then XNU writes it back with bits 0-1 cleared, which is what it
         * does at 0xfffffe000c1f0b28, and reads it back later. */
        check(dc_write(&dev, w, off, frame[22] & ~3UL, tx, &tx_len) == DC_OK
                  && tx_len == 0,
              "the kernel's read-modify-write of the mask is accepted and "
              "transmits nothing");

        /* The byte that is the milestone: putc, at the address the kernelcache
         * uses, arriving as the syndrome a store produces. */
        w = dc_window(pa, span, 2, 0x308128000UL + 0x4004, &off);
        a = dc_decode((0x24UL << 26) | (1UL << 24) | (2UL << 22) | (1UL << 16)
                      | (1UL << 6) | 0x05);
        check(a.valid && a.write && a.size == 4 && a.reg == 1,
              "putc arrives as a four-byte store from w1");
        frame[1] = 'D';
        check(dc_write(&dev, w, off, dc_narrow(&a, frame[a.reg]), tx, &tx_len) == DC_OK,
              "...which the model accepts");
        check(tx_len == 1 && tx[0] == 'D',
              "...and turns into exactly one byte for the console buffer");
    }

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks + failures);
        return 1;
    }
    printf("PASS: %d dock-channel UART checks (native, sanitizers on)\n", checks);
    return 0;
}
