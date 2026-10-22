/* SPDX-License-Identifier: MIT */
/* Polled GENI I2C master; the contract and its sources are in geni-i2c.h. */
#include "geni-i2c.h"

#include <stddef.h>
#include <string.h>

#define CLEANUP_TIMEOUT_US   500000u   /* cancel, then abort: 0.5 s each, as the tools used */
#define COMPLETION_MARGIN_US 100000u   /* device clock stretching beyond the nominal bus time */
#define MIN_POLL_US          20u
#define MAX_POLL_US          1000u
#define SETTLE_US            20000u    /* any leftover transfer (<= 144 bytes) ends well inside this */

static uint32_t rd(struct geni_i2c *c, uint32_t offset)
{
    return c->io.read32(c->io.ctx, offset);
}

static void wr(struct geni_i2c *c, uint32_t offset, uint32_t value)
{
    c->io.write32(c->io.ctx, offset, value);
}

static uint64_t now(struct geni_i2c *c)
{
    return c->io.now_us(c->io.ctx);
}

static void delay(struct geni_i2c *c, uint32_t us)
{
    if (us)
        c->io.delay_us(c->io.ctx, us);
}

/* Nominal wire time of len bytes plus the address byte, nine clocks each. */
static uint32_t wire_us(const struct geni_i2c *c, uint32_t len)
{
    uint64_t bits = ((uint64_t)len + 1u) * 9u;
    return (uint32_t)((bits * 1000000u + c->bus_hz - 1u) / c->bus_hz);
}

/* Poll roughly every eight FIFO words (32 bytes) so a transfer longer than
 * the FIFO is serviced before the engine has to hold the clock for long. */
static uint32_t poll_us(const struct geni_i2c *c)
{
    uint32_t us = wire_us(c, 32) / 4u;
    if (us < MIN_POLL_US)
        us = MIN_POLL_US;
    if (us > MAX_POLL_US)
        us = MAX_POLL_US;
    return us;
}

static int active(struct geni_i2c *c)
{
    return (rd(c, GENI_STATUS) & GENI_M_ACTIVE) != 0;
}

static void acknowledge(struct geni_i2c *c, uint32_t status)
{
    if (status & GENI_IRQ_EVENTS)
        wr(c, GENI_M_IRQ_CLEAR, status & GENI_IRQ_EVENTS);
}

static int classify(uint32_t status, int fallback)
{
    if (status & GENI_IRQ_NACK)
        return GENI_I2C_NACK;
    if (status & (GENI_IRQ_BUS_PROTO | GENI_IRQ_ARB_LOST))
        return GENI_I2C_BUS_ERROR;
    if (status & GENI_IRQ_ERRORS)
        return GENI_I2C_CONTROLLER;
    return fallback;
}

static void count(struct geni_i2c *c, int result)
{
    switch (result) {
    case GENI_I2C_NACK: c->stats.nacks++; break;
    case GENI_I2C_BUS_ERROR: c->stats.bus_errors++; break;
    case GENI_I2C_CONTROLLER: c->stats.controller_errors++; break;
    case GENI_I2C_TIMEOUT: c->stats.timeouts++; break;
    case GENI_I2C_SHORT: c->stats.shorts++; break;
    case GENI_I2C_EXCESS: c->stats.excess++; break;
    case GENI_I2C_BUSY: c->stats.busy++; break;
    default: break;
    }
}

/* Wait until any of bits appears in M_IRQ_STATUS; 0 on timeout. */
static uint32_t wait_status(struct geni_i2c *c, uint32_t bits, uint32_t timeout_us)
{
    uint64_t deadline = now(c) + timeout_us;
    for (;;) {
        uint32_t status = rd(c, GENI_M_IRQ_STATUS);
        if (status & bits)
            return status;
        if (now(c) >= deadline)
            return 0;
        delay(c, poll_us(c));
    }
}

/* A transfer failed. Return the engine to idle with empty FIFOs, or declare
 * it wedged and never touch it again. Only words belonging to the failed
 * READ are ever discarded; nothing is replayed. */
static int fail(struct geni_i2c *c, uint32_t status, int result)
{
    uint32_t pops = 0;

    c->last_status = status;
    c->last_result = (uint32_t)result;
    count(c, result);
    if (active(c)) {
        wr(c, GENI_M_CMD_CTRL, GENI_CMD_CANCEL);
        c->stats.cancels++;
        status |= wait_status(c, GENI_IRQ_CANCEL | GENI_IRQ_DONE, CLEANUP_TIMEOUT_US);
        if (active(c)) {
            wr(c, GENI_M_CMD_CTRL, GENI_CMD_ABORT);
            c->stats.aborts++;
            status |= wait_status(c, GENI_IRQ_ABORT, CLEANUP_TIMEOUT_US);
        }
        if (active(c))
            goto wedged;
    }
    for (;;) {
        uint32_t words = rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK;
        if (!words)
            break;
        if (words > c->rx_fifo_words || pops + words > 2u * c->rx_fifo_words)
            goto wedged;
        for (uint32_t i = 0; i < words; i++)
            (void)rd(c, GENI_RX_FIFO);
        pops += words;
        c->stats.discarded_words += words;
    }
    c->last_tx_fifo = rd(c, GENI_TX_FIFO_STATUS);
    c->last_rx_fifo = rd(c, GENI_RX_FIFO_STATUS);
    /* Unsent transmit words would lead the next WRITE. The engine is idle,
     * so no cancel applies; stop driving the controller instead. */
    if (c->last_tx_fifo & GENI_TX_FIFO_WC_MASK)
        goto wedged;
    acknowledge(c, status | rd(c, GENI_M_IRQ_STATUS));
    if (rd(c, GENI_M_IRQ_STATUS) & GENI_IRQ_ERRORS)
        goto wedged;
    return result;
wedged:
    c->wedged = 1;
    c->last_tx_fifo = rd(c, GENI_TX_FIFO_STATUS);
    c->last_rx_fifo = rd(c, GENI_RX_FIFO_STATUS);
    return GENI_I2C_WEDGED;
}

/* Every transfer begins with an idle engine, empty FIFOs and no pending
 * error. Stale non-error events from an earlier transfer are acknowledged. */
static int begin(struct geni_i2c *c)
{
    uint32_t status;

    if (!c->started)
        return GENI_I2C_INVALID;
    if (c->wedged)
        return GENI_I2C_WEDGED;
    if (active(c) || (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK) ||
        (rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK)) {
        /* Nothing of ours is in flight: someone else is driving the engine. */
        c->wedged = 1;
        c->stats.busy++;
        return GENI_I2C_BUSY;
    }
    status = rd(c, GENI_M_IRQ_STATUS);
    if (status & GENI_IRQ_EVENTS) {
        c->stats.stale_events++;
        acknowledge(c, status);
        if (rd(c, GENI_M_IRQ_STATUS) & GENI_IRQ_ERRORS) {
            c->wedged = 1;
            return GENI_I2C_WEDGED;
        }
    }
    return GENI_I2C_OK;
}

/* DONE was observed with the engine's data fully accounted for: check the
 * engine stopped, then recheck for an error that arrived after DONE. */
static int finish(struct geni_i2c *c, uint32_t status)
{
    uint32_t late;

    if (active(c))
        return fail(c, status, GENI_I2C_CONTROLLER);
    late = rd(c, GENI_M_IRQ_STATUS);
    if (late & GENI_IRQ_ERRORS) {
        c->stats.late_errors++;
        return fail(c, status | late, classify(late, GENI_I2C_CONTROLLER));
    }
    acknowledge(c, status | late);
    c->stats.ok++;
    return GENI_I2C_OK;
}

/* Discard the receive words the FIFO reports, at most two FIFOs' worth in
 * all; 0, or -1 for an impossible count. */
static int drain_reported(struct geni_i2c *c, uint32_t *pops)
{
    for (;;) {
        uint32_t words = rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK;
        if (!words)
            return 0;
        if (words > c->rx_fifo_words || *pops + words > 2u * c->rx_fifo_words)
            return -1;
        for (uint32_t i = 0; i < words; i++)
            (void)rd(c, GENI_RX_FIFO);
        *pops += words;
    }
}

/* A previous run's leftover (see geni-i2c.h). Nothing is written before the
 * transmit FIFO and secondary engine are known to be clear. */
static int recover(struct geni_i2c *c)
{
    uint32_t pops = 0, status;
    uint64_t deadline;

    c->stats.recoveries++;
    if ((rd(c, GENI_STATUS) & GENI_S_ACTIVE) || (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK))
        return GENI_I2C_BUSY;                /* not a state this driver leaves: refuse, no write */
    /* An in-flight read ends on its own unless its words fill the FIFO. */
    deadline = now(c) + SETTLE_US;
    while (active(c) && now(c) < deadline) {
        uint32_t words = rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK;
        if (words >= c->rx_fifo_words / 2u) {
            if (words > c->rx_fifo_words || pops + words > 2u * c->rx_fifo_words)
                goto wedged;
            for (uint32_t i = 0; i < words; i++)
                (void)rd(c, GENI_RX_FIFO);
            pops += words;
        } else {
            delay(c, poll_us(c));
        }
    }
    if (active(c)) {
        wr(c, GENI_M_CMD_CTRL, GENI_CMD_CANCEL);
        c->stats.cancels++;
        (void)wait_status(c, GENI_IRQ_CANCEL | GENI_IRQ_DONE, CLEANUP_TIMEOUT_US);
        if (active(c)) {
            wr(c, GENI_M_CMD_CTRL, GENI_CMD_ABORT);
            c->stats.aborts++;
            (void)wait_status(c, GENI_IRQ_ABORT, CLEANUP_TIMEOUT_US);
        }
        if (active(c))
            goto wedged;
    }
    if (drain_reported(c, &pops))
        goto wedged;
    if (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK)
        goto wedged;                         /* an aborted write kept words: cannot discard them */
    status = rd(c, GENI_M_IRQ_STATUS);
    if (status & GENI_IRQ_EVENTS)
        wr(c, GENI_M_IRQ_CLEAR, status & GENI_IRQ_EVENTS);
    if (active(c) || (rd(c, GENI_M_IRQ_STATUS) & GENI_IRQ_ERRORS) ||
        (rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK) ||
        (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK))
        goto wedged;
    c->stats.recovered_words = pops;
    c->stats.discarded_words += pops;
    c->recovered = 1;
    return GENI_I2C_OK;
wedged:
    c->wedged = 1;
    c->stats.recovered_words = pops;
    return GENI_I2C_WEDGED;
}

int geni_i2c_start(struct geni_i2c *c, const struct geni_i2c_io *io, uint32_t bus_hz,
                   uint32_t irq_policy)
{
    uint32_t fw, clk, p0, p1, status;

    if (!c || !io || !io->read32 || !io->write32 || !io->now_us || !io->delay_us ||
        irq_policy > GENI_I2C_IRQ_MASKED || bus_hz < 10000u || bus_hz > 3400000u)
        return GENI_I2C_INVALID;
    memset(c, 0, sizeof(*c));
    c->io = *io;
    c->bus_hz = bus_hz;
    c->irq_policy = irq_policy;

    fw = rd(c, GENI_FW_REVISION_RO);
    if (((fw >> 8) & 0xffu) != GENI_PROTOCOL_I2C)
        return GENI_I2C_CONFIG;
    if (rd(c, GENI_IF_DISABLE_RO) & 1u)
        return GENI_I2C_CONFIG;             /* FIFO interface disabled */
    if (rd(c, GENI_DMA_MODE_EN) & 1u)
        return GENI_I2C_CONFIG;             /* DMA mode: not driven here */
    clk = rd(c, GENI_SER_M_CLK_CFG);
    if (!(clk & 1u) || !((clk >> 4) & 0xfffu))
        return GENI_I2C_CONFIG;             /* serial clock off or no divider */
    if (rd(c, GENI_BYTE_GRAN) != 0u ||
        rd(c, GENI_TX_PACKING_CFG0) != GENI_PACKING_CFG0 ||
        rd(c, GENI_TX_PACKING_CFG1) != GENI_PACKING_CFG1 ||
        rd(c, GENI_RX_PACKING_CFG0) != GENI_PACKING_CFG0 ||
        rd(c, GENI_RX_PACKING_CFG1) != GENI_PACKING_CFG1)
        return GENI_I2C_CONFIG;             /* byte order below depends on it */
    p0 = rd(c, GENI_HW_PARAM_0);
    p1 = rd(c, GENI_HW_PARAM_1);
    if (((p0 >> 24) & 63u) != 32u || ((p1 >> 24) & 63u) != 32u)
        return GENI_I2C_CONFIG;             /* 32-bit FIFO words */
    c->tx_fifo_words = (p0 >> 16) & 63u;
    c->rx_fifo_words = (p1 >> 16) & 63u;
    if (c->tx_fifo_words < 8u || c->rx_fifo_words < 8u)
        return GENI_I2C_CONFIG;
    c->found_status = rd(c, GENI_STATUS);
    c->found_tx_fifo = rd(c, GENI_TX_FIFO_STATUS);
    c->found_rx_fifo = rd(c, GENI_RX_FIFO_STATUS);
    c->found_irq = rd(c, GENI_M_IRQ_STATUS);
    c->found_irq_en = rd(c, GENI_M_IRQ_EN);
    if ((c->found_status & (GENI_M_ACTIVE | GENI_S_ACTIVE)) ||
        (c->found_tx_fifo & GENI_TX_FIFO_WC_MASK) || (c->found_rx_fifo & GENI_RX_FIFO_WC_MASK) ||
        (c->found_irq & GENI_IRQ_ERRORS)) {
        int r;
        /* Firmware's state, or anyone else's: never consume data we did not
         * request, never guess past an error. Only our own leftover is recovered. */
        if (irq_policy != GENI_I2C_IRQ_MASKED || c->found_irq_en != 0u)
            return GENI_I2C_BUSY;
        r = recover(c);
        if (r)
            return r;
    }
    status = rd(c, GENI_M_IRQ_STATUS);

    c->clock_cfg = clk;
    c->scl_counters = rd(c, GENI_I2C_SCL_COUNTERS);
    c->initial_status = status;
    c->initial_ios = rd(c, GENI_IOS);
    c->saved_irq_en = rd(c, GENI_M_IRQ_EN);
    c->saved_tx_len = rd(c, GENI_I2C_TX_TRANS_LEN);
    c->saved_rx_len = rd(c, GENI_I2C_RX_TRANS_LEN);
    wr(c, GENI_M_IRQ_EN, irq_policy == GENI_I2C_IRQ_MASKED ? 0u
                                                            : c->saved_irq_en | GENI_IRQ_EVENTS);
    acknowledge(c, status);
    c->started = 1;
    return GENI_I2C_OK;
}

int geni_i2c_stop(struct geni_i2c *c)
{
    if (!c || !c->started)
        return GENI_I2C_INVALID;
    if (c->wedged)
        return GENI_I2C_WEDGED;
    if (active(c) || (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK) ||
        (rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK))
        return GENI_I2C_BUSY;
    acknowledge(c, rd(c, GENI_M_IRQ_STATUS));
    wr(c, GENI_I2C_TX_TRANS_LEN, c->saved_tx_len);
    wr(c, GENI_I2C_RX_TRANS_LEN, c->saved_rx_len);
    wr(c, GENI_M_IRQ_EN, c->saved_irq_en);
    c->started = 0;
    return GENI_I2C_OK;
}

int geni_i2c_write(struct geni_i2c *c, uint8_t addr, const uint8_t *data, uint32_t len,
                   int stop_stretch)
{
    uint64_t deadline;
    int r;

    if (!c || !data || !len || addr > 0x7fu || !c->started || len > 4u * c->tx_fifo_words)
        return GENI_I2C_INVALID;
    r = begin(c);
    if (r)
        return r;
    c->stats.writes++;
    wr(c, GENI_I2C_TX_TRANS_LEN, len);
    wr(c, GENI_M_CMD0, (GENI_I2C_OP_WRITE << GENI_OPCODE_SHIFT) |
                       ((uint32_t)addr << GENI_I2C_ADDR_SHIFT) |
                       (stop_stretch ? GENI_I2C_STOP_STRETCH : 0u));
    for (uint32_t i = 0; i < len; i += 4) {
        uint32_t word = 0;
        for (uint32_t b = 0; b < 4 && i + b < len; b++)
            word |= (uint32_t)data[i + b] << (8 * b);
        wr(c, GENI_TX_FIFO, word);
    }
    deadline = now(c) + 4u * wire_us(c, len) + COMPLETION_MARGIN_US;
    delay(c, wire_us(c, len));
    for (;;) {
        uint32_t status = rd(c, GENI_M_IRQ_STATUS);
        if (status & GENI_IRQ_ERRORS)
            return fail(c, status, classify(status, GENI_I2C_CONTROLLER));
        if (status & GENI_IRQ_DONE) {
            if (rd(c, GENI_TX_FIFO_STATUS) & GENI_TX_FIFO_WC_MASK)
                return fail(c, status, GENI_I2C_SHORT);
            return finish(c, status);
        }
        if (now(c) >= deadline)
            return fail(c, status, GENI_I2C_TIMEOUT);
        delay(c, poll_us(c));
    }
}

int geni_i2c_read(struct geni_i2c *c, uint8_t addr, uint8_t *data, uint32_t len)
{
    uint32_t wanted, got = 0;
    uint64_t deadline;
    int r;

    if (!c || !data || !len || len > 0xffffu || addr > 0x7fu || !c->started)
        return GENI_I2C_INVALID;
    r = begin(c);
    if (r)
        return r;
    c->stats.reads++;
    wanted = (len + 3u) / 4u;
    wr(c, GENI_I2C_RX_TRANS_LEN, len);
    wr(c, GENI_M_CMD0, (GENI_I2C_OP_READ << GENI_OPCODE_SHIFT) |
                       ((uint32_t)addr << GENI_I2C_ADDR_SHIFT));
    deadline = now(c) + 4u * wire_us(c, len) + COMPLETION_MARGIN_US;
    /* Wait for the first FIFO's worth (or the whole transfer if shorter). */
    delay(c, wire_us(c, len < 4u * c->rx_fifo_words / 2u ? len : 4u * c->rx_fifo_words / 2u));
    for (;;) {
        /* Status first: data delivered before DONE is then already counted. */
        uint32_t status = rd(c, GENI_M_IRQ_STATUS);
        uint32_t fifo, words;

        if (status & GENI_IRQ_ERRORS)
            return fail(c, status, classify(status, GENI_I2C_CONTROLLER));
        fifo = rd(c, GENI_RX_FIFO_STATUS);
        words = fifo & GENI_RX_FIFO_WC_MASK;
        if (words > c->rx_fifo_words || got + words > wanted)
            return fail(c, status, GENI_I2C_EXCESS);
        if (words && (fifo & GENI_RX_LAST)) {
            uint32_t last = (fifo >> GENI_RX_LAST_BYTES_SHIFT) & GENI_RX_LAST_BYTES_MASK;
            uint32_t tail = len & 3u;
            if (got + words != wanted)
                return fail(c, status, GENI_I2C_SHORT);
            /* A zero count means a full final word (Linux's GENI serial driver
             * reads it that way); a partial word must match the request. */
            if (tail ? last != tail : (last != 0u && last != 4u))
                return fail(c, status, GENI_I2C_EXCESS);
        }
        for (uint32_t i = 0; i < words; i++, got++) {
            uint32_t word = rd(c, GENI_RX_FIFO);
            for (uint32_t b = 0; b < 4; b++) {
                uint32_t at = got * 4u + b;
                if (at < len)
                    data[at] = (uint8_t)(word >> (8 * b));
            }
        }
        if (status & GENI_IRQ_DONE) {
            if (got != wanted)
                return fail(c, status, GENI_I2C_SHORT);
            if (rd(c, GENI_RX_FIFO_STATUS) & GENI_RX_FIFO_WC_MASK)
                return fail(c, status, GENI_I2C_EXCESS);
            return finish(c, status);
        }
        /* Acknowledge only service events seen before draining; a newly
         * arriving LAST/DONE stays pending for the next poll. */
        if (status & (GENI_IRQ_RX_WM | GENI_IRQ_RX_LAST))
            wr(c, GENI_M_IRQ_CLEAR, status & (GENI_IRQ_RX_WM | GENI_IRQ_RX_LAST));
        if (now(c) >= deadline)
            return fail(c, status, GENI_I2C_TIMEOUT);
        if (!words)
            delay(c, poll_us(c));
    }
}

const char *geni_i2c_result_name(int result)
{
    static const char *const names[GENI_I2C_RESULT_COUNT] = {
        "ok", "nack", "bus-error", "controller-error", "timeout", "short", "excess",
        "busy", "config", "wedged", "invalid",
    };
    if (result < 0 || result >= GENI_I2C_RESULT_COUNT)
        return "unknown";
    return names[result];
}
