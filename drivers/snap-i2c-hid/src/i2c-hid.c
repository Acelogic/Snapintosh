/* SPDX-License-Identifier: MIT */
/* HID over I2C transport and state machine; see i2c-hid.h for sources. */
#include "i2c-hid.h"

#include <stddef.h>
#include <string.h>

#define POWER_RETRY_US 500u   /* Linux: one PWR_ON retry after 400-500 us */

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

int i2c_hid_parse_desc(const uint8_t *raw, uint32_t len, struct i2c_hid_desc *o)
{
    if (!raw || !o || len != I2C_HID_DESC_BYTES)
        return I2C_HID_DESC_LENGTH;
    o->desc_length = le16(raw + 0);
    o->version = le16(raw + 2);
    o->rdesc_length = le16(raw + 4);
    o->rdesc_register = le16(raw + 6);
    o->input_register = le16(raw + 8);
    o->max_input = le16(raw + 10);
    o->output_register = le16(raw + 12);
    o->max_output = le16(raw + 14);
    o->command_register = le16(raw + 16);
    o->data_register = le16(raw + 18);
    o->vendor_id = le16(raw + 20);
    o->product_id = le16(raw + 22);
    o->device_version = le16(raw + 24);
    o->reserved = (uint32_t)raw[26] | (uint32_t)raw[27] << 8 | (uint32_t)raw[28] << 16 |
                  (uint32_t)raw[29] << 24;
    if (o->desc_length != I2C_HID_DESC_BYTES)
        return I2C_HID_DESC_LENGTH;
    if (o->version != 0x0100u)
        return I2C_HID_DESC_VERSION;
    if (!o->rdesc_length || o->rdesc_length > I2C_HID_MAX_RDESC ||
        o->max_input <= 2u || o->max_input > I2C_HID_MAX_INPUT ||
        o->max_output > I2C_HID_MAX_OUTPUT || o->command_register == o->data_register)
        return I2C_HID_DESC_BOUNDS;
    if (o->reserved)
        return I2C_HID_DESC_RESERVED;
    return I2C_HID_DESC_OK;
}

uint32_t i2c_hid_encode_command(const struct i2c_hid_desc *d, uint8_t opcode, uint8_t type,
                                uint8_t id, uint8_t *out, uint32_t cap)
{
    uint32_t n = id < 0x0fu ? 4u : 5u;
    if (!d || !out || cap < n || opcode > 0x0fu || type > 3u)
        return 0;
    put16(out, d->command_register);
    out[2] = (uint8_t)(((uint32_t)type << 4) | (id < 0x0fu ? id : 0x0fu));
    out[3] = opcode;
    if (n == 5u)
        out[4] = id;
    return n;
}

uint32_t i2c_hid_encode_set_power(const struct i2c_hid_desc *d, uint8_t state, uint8_t *out,
                                  uint32_t cap)
{
    if (state > I2C_HID_POWER_SLEEP)
        return 0;
    return i2c_hid_encode_command(d, I2C_HID_OP_SET_POWER, 0, state, out, cap);
}

uint32_t i2c_hid_encode_reset(const struct i2c_hid_desc *d, uint8_t *out, uint32_t cap)
{
    return i2c_hid_encode_command(d, I2C_HID_OP_RESET, 0, 0, out, cap);
}

uint32_t i2c_hid_encode_get_report(const struct i2c_hid_desc *d, uint8_t type, uint8_t id,
                                   uint8_t *out, uint32_t cap)
{
    uint32_t n = i2c_hid_encode_command(d, I2C_HID_OP_GET_REPORT, type, id, out, cap);
    if (!n || cap - n < 2u)
        return 0;
    put16(out + n, d->data_register);
    return n + 2u;
}

/* [length][id when numbered][data], length counting itself. */
static uint32_t format_report(uint8_t id, const uint8_t *data, uint32_t len, uint8_t *out,
                              uint32_t cap)
{
    uint32_t n = 2u + (id ? 1u : 0u) + len;
    if (n > cap || n > 0xffffu || (len && !data))
        return 0;
    put16(out, (uint16_t)n);
    if (id)
        out[2] = id;
    if (len)
        memcpy(out + 2u + (id ? 1u : 0u), data, len);
    return n;
}

uint32_t i2c_hid_encode_set_report(const struct i2c_hid_desc *d, uint8_t type, uint8_t id,
                                   const uint8_t *data, uint32_t len, uint8_t *out, uint32_t cap)
{
    uint32_t n = i2c_hid_encode_command(d, I2C_HID_OP_SET_REPORT, type, id, out, cap), m;
    if (!n || cap - n < 2u)
        return 0;
    put16(out + n, d->data_register);
    n += 2u;
    m = format_report(id, data, len, out + n, cap - n);
    return m ? n + m : 0;
}

uint32_t i2c_hid_encode_output(const struct i2c_hid_desc *d, uint8_t id, const uint8_t *data,
                               uint32_t len, uint8_t *out, uint32_t cap)
{
    uint32_t m;
    if (!d || !out || cap < 2u)
        return 0;
    put16(out, d->output_register);
    m = format_report(id, data, len, out + 2, cap - 2u);
    return m ? m + 2u : 0;
}

int i2c_hid_classify_input(const struct hid_rdesc_info *r, const uint8_t *buf, uint32_t got,
                           struct i2c_hid_input *o)
{
    uint32_t expected;

    memset(o, 0, sizeof(*o));
    if (!r || !buf || got < 2u)
        return o->kind = I2C_HID_IN_BAD_LENGTH;
    o->length = le16(buf);
    if (o->length == 0u || o->length == 2u)
        return o->kind = I2C_HID_IN_EMPTY;
    if (o->length == 0xffffu)
        return o->kind = I2C_HID_IN_BOGUS;
    if (o->length < 2u || o->length > got)
        return o->kind = I2C_HID_IN_BAD_LENGTH;
    o->report = buf + 2;
    o->report_bytes = o->length - 2u;
    o->id = r->numbered ? o->report[0] : 0u;
    expected = hid_rdesc_report_bytes(r, HID_REPORT_INPUT, o->id);
    if (!expected)
        return o->kind = I2C_HID_IN_UNKNOWN_ID;
    if (o->report_bytes != expected)
        return o->kind = I2C_HID_IN_WRONG_SIZE;
    return o->kind = I2C_HID_IN_REPORT;
}

static uint8_t hid_type(uint8_t i2c_type)
{
    return i2c_type == I2C_HID_TYPE_INPUT ? HID_REPORT_INPUT
         : i2c_type == I2C_HID_TYPE_OUTPUT ? HID_REPORT_OUTPUT : HID_REPORT_FEATURE;
}

int i2c_hid_classify_response(const struct hid_rdesc_info *r, uint8_t type, uint8_t id,
                              const uint8_t *buf, uint32_t got, struct i2c_hid_input *o)
{
    uint32_t expected;

    memset(o, 0, sizeof(*o));
    if (!r || !buf || got < 2u || type < I2C_HID_TYPE_INPUT || type > I2C_HID_TYPE_FEATURE)
        return o->kind = I2C_HID_IN_BAD_LENGTH;
    o->length = le16(buf);
    /* Linux i2c_hid_get_report: a length of 2 or less is an empty report. */
    if (o->length <= 2u)
        return o->kind = I2C_HID_IN_EMPTY;
    if (o->length > got)
        return o->kind = I2C_HID_IN_BAD_LENGTH;
    o->report = buf + 2;
    o->report_bytes = o->length - 2u;
    o->id = r->numbered ? o->report[0] : 0u;
    if (o->id != id)
        return o->kind = I2C_HID_IN_UNKNOWN_ID;
    expected = hid_rdesc_report_bytes(r, hid_type(type), id);
    if (!expected)
        return o->kind = I2C_HID_IN_UNKNOWN_ID;
    if (o->report_bytes != expected)
        return o->kind = I2C_HID_IN_WRONG_SIZE;
    return o->kind = I2C_HID_IN_REPORT;
}

void i2c_hid_default_config(struct i2c_hid_config *c, uint8_t address, uint16_t desc_register)
{
    memset(c, 0, sizeof(*c));
    c->address = address;
    c->desc_register = desc_register;
    c->power_on_after_reset = 1;
    c->poll_us = 8000;
    c->power_settle_us = 60000;
    c->reset_settle_us = 100000;
    c->reset_deadline_us = 1000000;
    c->reset_retry_us = 10000;
    c->init_retry_us = 100000;
    c->max_init_errors = 3;
    c->max_consecutive_errors = 8;
    c->max_reinit = 3;
    c->max_reads_per_tick = 4;
}

static uint64_t now(struct i2c_hid_dev *d)
{
    return d->bus->io.now_us(d->bus->io.ctx);
}

static uint32_t fail(struct i2c_hid_dev *d, uint32_t failure)
{
    d->failed_in = d->state;
    d->failure = failure;
    d->state = I2C_HID_S_FAILED;
    return I2C_HID_NO_WAKE;
}

static int fatal_bus(int r)
{
    return r == GENI_I2C_WEDGED || r == GENI_I2C_BUSY || r == GENI_I2C_INVALID ||
           r == GENI_I2C_CONFIG;
}

/* A failed initialisation transfer: retry the same step later, a bounded
 * number of times. SET_POWER and RESET are idempotent requests. */
static uint32_t init_error(struct i2c_hid_dev *d, int r)
{
    d->last_result = r;
    d->stats.transfer_errors++;
    if (r == GENI_I2C_NACK)
        d->stats.nacks++;
    if (fatal_bus(r))
        return fail(d, I2C_HID_F_BUS);
    if (++d->init_errors > d->cfg.max_init_errors)
        return fail(d, I2C_HID_F_INIT_ERRORS);
    return d->cfg.init_retry_us;
}

/* Select a register (WRITE with STOP_STRETCH), then READ with a repeated START. */
static int read_register(struct i2c_hid_dev *d, uint16_t reg, uint8_t *buf, uint32_t len)
{
    uint8_t sel[2];
    int r;
    put16(sel, reg);
    r = geni_i2c_write(d->bus, d->cfg.address, sel, 2, 1);
    if (r)
        return r;
    return geni_i2c_read(d->bus, d->cfg.address, buf, len);
}

static int set_power(struct i2c_hid_dev *d, uint8_t state)
{
    uint8_t cmd[5];
    uint32_t n = i2c_hid_encode_set_power(&d->desc, state, cmd, sizeof(cmd));
    int r = geni_i2c_write(d->bus, d->cfg.address, cmd, n, 0);
    if (r == GENI_I2C_NACK && state == I2C_HID_POWER_ON) {
        /* Some devices need a moment after a clock edge to wake. */
        d->stats.nacks++;
        d->bus->io.delay_us(d->bus->io.ctx, POWER_RETRY_US);
        r = geni_i2c_write(d->bus, d->cfg.address, cmd, n, 0);
    }
    return r;
}

static uint32_t step_desc(struct i2c_hid_dev *d)
{
    uint8_t raw[I2C_HID_DESC_BYTES];
    struct i2c_hid_desc desc;
    int r = read_register(d, d->cfg.desc_register, raw, sizeof(raw));

    if (r)
        return init_error(d, r);
    if (i2c_hid_parse_desc(raw, sizeof(raw), &desc) != I2C_HID_DESC_OK)
        return fail(d, I2C_HID_F_DESCRIPTOR);
    if ((d->cfg.expect_vendor && desc.vendor_id != d->cfg.expect_vendor) ||
        (d->cfg.expect_product && desc.product_id != d->cfg.expect_product) ||
        (d->have_desc && memcmp(raw, d->desc_raw, sizeof(raw))))
        return fail(d, I2C_HID_F_IDENTITY);
    memcpy(d->desc_raw, raw, sizeof(raw));
    d->desc = desc;
    d->have_desc = 1;
    d->state = I2C_HID_S_POWER_ON;
    return 0;
}

static uint32_t step_power_on(struct i2c_hid_dev *d)
{
    int r = set_power(d, I2C_HID_POWER_ON);
    if (r)
        return init_error(d, r);
    d->state = d->cfg.skip_reset ? I2C_HID_S_RDESC : I2C_HID_S_RESET;
    return d->cfg.power_settle_us;
}

static uint32_t step_reset(struct i2c_hid_dev *d)
{
    uint8_t cmd[5];
    uint32_t n = i2c_hid_encode_reset(&d->desc, cmd, sizeof(cmd));
    int r = geni_i2c_write(d->bus, d->cfg.address, cmd, n, 0);
    if (r)
        return init_error(d, r);
    d->reset_at_us = now(d);
    d->state = I2C_HID_S_RESET_WAIT;
    return d->cfg.reset_settle_us;
}

/* Without the attention line a reset acknowledgment (length 0) looks like an
 * empty input register, so the first acknowledged read after the settle time
 * is taken as "the device is back". NACKs are tolerated until the deadline. */
static uint32_t step_reset_wait(struct i2c_hid_dev *d)
{
    int within = now(d) - d->reset_at_us < d->cfg.reset_deadline_us;
    int r;

    /* With the attention line the acknowledgment is real: wait for it. */
    if (d->attention) {
        if (!d->attention(d->attention_ctx)) {
            if (within)
                return d->cfg.reset_retry_us;
            d->stats.reset_without_attention++;   /* Linux proceeds after 1 s */
        } else {
            d->stats.reset_acks++;
        }
    }
    r = geni_i2c_read(d->bus, d->cfg.address, d->inbuf, d->desc.max_input);
    if (r == GENI_I2C_NACK && within) {
        d->stats.reset_retries++;
        d->stats.nacks++;
        return d->cfg.reset_retry_us;
    }
    if (r == GENI_I2C_NACK)
        return fail(d, I2C_HID_F_RESET);
    if (r)
        return init_error(d, r);
    /* The report descriptor is not known yet on first initialisation, so only
     * the length prefix can be judged here. */
    {
        uint16_t length = le16(d->inbuf);
        if (length == 0u || length == 2u || length == 0xffffu) {
            /* acknowledged, nothing pending */
        } else if (length > 2u && length <= d->desc.max_input) {
            d->stats.early_reports++;      /* a key report before RDESC: dropped */
        } else if (within) {
            d->stats.bad_length++;
            return d->cfg.reset_retry_us;
        } else {
            return fail(d, I2C_HID_F_RESET);
        }
    }
    d->state = d->cfg.power_on_after_reset ? I2C_HID_S_POWER_ON2 : I2C_HID_S_RDESC;
    return 0;
}

static uint32_t step_power_on2(struct i2c_hid_dev *d)
{
    int r = set_power(d, I2C_HID_POWER_ON);
    if (r)
        return init_error(d, r);
    d->state = I2C_HID_S_RDESC;
    return d->cfg.power_settle_us;
}

static uint32_t step_rdesc(struct i2c_hid_dev *d)
{
    struct hid_rdesc_info info;
    uint32_t len = d->desc.rdesc_length;
    /* A re-initialisation reads into scratch so a changed descriptor can never
     * replace the one IOHIDFamily already parsed. */
    uint8_t *buf = d->have_rdesc ? d->scratch : d->rdesc;
    int r;

    if (d->have_rdesc && d->rdesc_len != len)
        return fail(d, I2C_HID_F_IDENTITY);
    r = read_register(d, d->desc.rdesc_register, buf, len);
    if (r)
        return init_error(d, r);
    if (d->have_rdesc && memcmp(buf, d->rdesc, len))
        return fail(d, I2C_HID_F_IDENTITY);
    if (hid_rdesc_parse(d->rdesc, len, &info) != HID_RDESC_OK)
        return fail(d, I2C_HID_F_REPORT_DESCRIPTOR);
    /* wMaxInputLength bounds every input read. A report the descriptor declares larger can never
     * arrive whole (the A16 touchpad, 2808:0219, declares a 64-byte vendor input report 6 beside
     * wMaxInputLength 52); one that ever claims to is classified BAD_LENGTH. At least one input
     * report, with its length prefix, must fit. */
    {
        uint32_t fit = 0, over = 0;
        for (uint32_t i = 0; i < info.nreports; i++) {
            const struct hid_report_shape *rep = &info.reports[i];
            uint32_t bytes = (rep->bits + 7u) / 8u + (rep->id ? 1u : 0u);
            if (rep->type != HID_REPORT_INPUT)
                continue;
            if (bytes + 2u <= d->desc.max_input)
                fit++;
            else
                over++;
        }
        if (!fit)
            return fail(d, I2C_HID_F_REPORT_DESCRIPTOR);
        d->stats.oversize_inputs = over;
    }
    d->rinfo = info;
    d->rdesc_len = len;
    d->have_rdesc = 1;
    if (d->cfg.re_power_on) {
        r = set_power(d, I2C_HID_POWER_ON);
        if (r)
            return init_error(d, r);
    }
    d->init_errors = 0;
    if (d->published) {
        d->state = I2C_HID_S_RUNNING;
        return d->cfg.poll_us;
    }
    d->state = I2C_HID_S_READY;
    return I2C_HID_NO_WAKE;
}

static uint32_t step_running(struct i2c_hid_dev *d)
{
    for (uint32_t i = 0; i < d->cfg.max_reads_per_tick; i++) {
        struct i2c_hid_input in;
        int r;

        if (d->attention && !d->attention(d->attention_ctx)) {
            if (!i)
                d->stats.attention_skips++;
            break;                           /* nothing pending: no bus traffic */
        }
        d->stats.polls++;
        r = geni_i2c_read(d->bus, d->cfg.address, d->inbuf, d->desc.max_input);
        if (r) {
            d->last_result = r;
            d->stats.transfer_errors++;
            if (r == GENI_I2C_NACK)
                d->stats.nacks++;
            if (fatal_bus(r))
                return fail(d, I2C_HID_F_BUS);
            if (++d->consecutive_errors >= d->cfg.max_consecutive_errors) {
                if (++d->reinits > d->cfg.max_reinit)
                    return fail(d, I2C_HID_F_REINIT);
                d->stats.reinits++;
                d->consecutive_errors = 0;
                d->state = I2C_HID_S_DESC;
                return d->cfg.init_retry_us;
            }
            break;
        }
        d->consecutive_errors = 0;
        switch (i2c_hid_classify_input(&d->rinfo, d->inbuf, d->desc.max_input, &in)) {
        case I2C_HID_IN_REPORT:
            d->stats.reports++;
            if (in.report_bytes == d->last_report_len &&
                !memcmp(in.report, d->last_report, in.report_bytes))
                d->stats.identical++;
            memcpy(d->last_report, in.report, in.report_bytes);
            d->last_report_len = in.report_bytes;
            if (d->deliver)
                d->deliver(d->deliver_ctx, in.report, in.report_bytes);
            continue;                        /* drain whatever else is queued */
        case I2C_HID_IN_EMPTY:
            d->stats.empty++;
            break;
        case I2C_HID_IN_BOGUS:
            d->stats.bogus++;
            break;
        default:
            if (in.kind == I2C_HID_IN_BAD_LENGTH)
                d->stats.bad_length++;
            else if (in.kind == I2C_HID_IN_UNKNOWN_ID)
                d->stats.unknown_id++;
            else
                d->stats.wrong_size++;
            memcpy(d->rejected, d->inbuf, d->desc.max_input);
            d->rejected_len = d->desc.max_input;
            break;
        }
        break;
    }
    return d->cfg.poll_us;
}

int i2c_hid_begin(struct i2c_hid_dev *d, struct geni_i2c *bus, const struct i2c_hid_config *cfg,
                  i2c_hid_deliver_fn deliver, void *ctx)
{
    if (!d || !bus || !cfg || !bus->started || cfg->address > 0x7fu || !cfg->poll_us ||
        !cfg->max_reads_per_tick || !cfg->max_consecutive_errors)
        return I2C_HID_R_INVALID;
    memset(d, 0, sizeof(*d));
    d->bus = bus;
    d->cfg = *cfg;
    d->deliver = deliver;
    d->deliver_ctx = ctx;
    d->state = I2C_HID_S_DESC;
    return I2C_HID_R_OK;
}

void i2c_hid_set_attention(struct i2c_hid_dev *d, i2c_hid_attention_fn fn, void *ctx)
{
    if (d) {
        d->attention = fn;
        d->attention_ctx = ctx;
    }
}

uint32_t i2c_hid_step(struct i2c_hid_dev *d)
{
    if (!d)
        return I2C_HID_NO_WAKE;
    switch (d->state) {
    case I2C_HID_S_DESC: return step_desc(d);
    case I2C_HID_S_POWER_ON: return step_power_on(d);
    case I2C_HID_S_RESET: return step_reset(d);
    case I2C_HID_S_RESET_WAIT: return step_reset_wait(d);
    case I2C_HID_S_POWER_ON2: return step_power_on2(d);
    case I2C_HID_S_RDESC: return step_rdesc(d);
    case I2C_HID_S_RUNNING: return step_running(d);
    default: return I2C_HID_NO_WAKE;
    }
}

int i2c_hid_run(struct i2c_hid_dev *d)
{
    if (!d || d->state != I2C_HID_S_READY)
        return I2C_HID_R_NOT_READY;
    d->published = 1;
    d->state = I2C_HID_S_RUNNING;
    return I2C_HID_R_OK;
}

void i2c_hid_stop(struct i2c_hid_dev *d)
{
    if (d && d->state != I2C_HID_S_FAILED)
        d->state = I2C_HID_S_OFF;
}

static int ready(struct i2c_hid_dev *d)
{
    return d && d->have_rdesc &&
           (d->state == I2C_HID_S_RUNNING || d->state == I2C_HID_S_READY);
}

static int request_bus(struct i2c_hid_dev *d, int r)
{
    d->last_result = r;
    d->stats.request_errors++;
    if (fatal_bus(r))
        fail(d, I2C_HID_F_BUS);
    return I2C_HID_R_BUS;
}

/* Split a HID report into (id, data) using the descriptor's numbering. */
static int split(struct i2c_hid_dev *d, uint8_t type, const uint8_t *report, uint32_t len,
                 uint8_t *id, const uint8_t **data, uint32_t *dlen)
{
    uint32_t expected;
    if (!report || !len)
        return I2C_HID_R_INVALID;
    *id = d->rinfo.numbered ? report[0] : 0u;
    expected = hid_rdesc_report_bytes(&d->rinfo, type, *id);
    if (!expected || len != expected)
        return I2C_HID_R_INVALID;
    *data = d->rinfo.numbered ? report + 1 : report;
    *dlen = d->rinfo.numbered ? len - 1u : len;
    return I2C_HID_R_OK;
}

int i2c_hid_send_output(struct i2c_hid_dev *d, const uint8_t *report, uint32_t len)
{
    uint8_t buf[I2C_HID_MAX_OUTPUT + 4];
    const uint8_t *data;
    uint32_t dlen, n;
    uint8_t id;
    int r;

    if (!ready(d))
        return I2C_HID_R_NOT_READY;
    r = split(d, HID_REPORT_OUTPUT, report, len, &id, &data, &dlen);
    if (r)
        return r;
    n = i2c_hid_encode_output(&d->desc, id, data, dlen, buf, sizeof(buf));
    if (!n || n > 4u * d->bus->tx_fifo_words)
        return I2C_HID_R_INVALID;
    d->stats.requests++;
    r = geni_i2c_write(d->bus, d->cfg.address, buf, n, 0);
    if (r)
        return request_bus(d, r);
    d->stats.outputs++;
    return I2C_HID_R_OK;
}

int i2c_hid_set_report(struct i2c_hid_dev *d, uint8_t type, const uint8_t *report, uint32_t len)
{
    uint8_t buf[I2C_HID_MAX_OUTPUT + 16];
    const uint8_t *data;
    uint32_t dlen, n;
    uint8_t id;
    int r;

    if (!ready(d) || type < I2C_HID_TYPE_INPUT || type > I2C_HID_TYPE_FEATURE)
        return I2C_HID_R_NOT_READY;
    r = split(d, hid_type(type), report, len, &id, &data, &dlen);
    if (r)
        return r;
    n = i2c_hid_encode_set_report(&d->desc, type, id, data, dlen, buf, sizeof(buf));
    if (!n || n > 4u * d->bus->tx_fifo_words)
        return I2C_HID_R_INVALID;
    d->stats.requests++;
    r = geni_i2c_write(d->bus, d->cfg.address, buf, n, 0);
    return r ? request_bus(d, r) : I2C_HID_R_OK;
}

int i2c_hid_get_report(struct i2c_hid_dev *d, uint8_t type, uint8_t id, uint8_t *buf,
                       uint32_t cap, uint32_t *got)
{
    uint8_t cmd[8];
    uint8_t *resp;
    struct i2c_hid_input in;
    uint32_t expected, n, want;
    int r;

    if (got)
        *got = 0;
    if (!ready(d))
        return I2C_HID_R_NOT_READY;
    if (!buf || !got || type < I2C_HID_TYPE_INPUT || type > I2C_HID_TYPE_FEATURE)
        return I2C_HID_R_INVALID;
    resp = d->scratch;
    expected = hid_rdesc_report_bytes(&d->rinfo, hid_type(type), id);
    want = expected + 2u;
    if (!expected || want > sizeof(d->scratch) || expected > cap)
        return I2C_HID_R_INVALID;
    n = i2c_hid_encode_get_report(&d->desc, type, id, cmd, sizeof(cmd));
    d->stats.requests++;
    r = geni_i2c_write(d->bus, d->cfg.address, cmd, n, 1);
    if (r)
        return request_bus(d, r);
    r = geni_i2c_read(d->bus, d->cfg.address, resp, want);
    if (r)
        return request_bus(d, r);
    switch (i2c_hid_classify_response(&d->rinfo, type, id, resp, want, &in)) {
    case I2C_HID_IN_EMPTY:
        return I2C_HID_R_EMPTY;
    case I2C_HID_IN_REPORT:
        memcpy(buf, in.report, in.report_bytes);
        *got = in.report_bytes;
        return I2C_HID_R_OK;
    default:
        d->stats.request_errors++;
        return I2C_HID_R_BAD_RESPONSE;
    }
}

const char *i2c_hid_state_name(uint32_t state)
{
    static const char *const names[I2C_HID_S_COUNT] = {
        "off", "descriptor", "power-on", "reset", "reset-wait", "power-on-after-reset",
        "report-descriptor", "ready", "running", "failed",
    };
    return state < I2C_HID_S_COUNT ? names[state] : "unknown";
}

const char *i2c_hid_failure_name(uint32_t failure)
{
    static const char *const names[I2C_HID_F_COUNT] = {
        "none", "bus", "descriptor", "identity", "reset", "report-descriptor",
        "init-errors", "reinit",
    };
    return failure < I2C_HID_F_COUNT ? names[failure] : "unknown";
}

const char *i2c_hid_input_kind_name(uint32_t kind)
{
    static const char *const names[I2C_HID_IN_KIND_COUNT] = {
        "empty", "report", "bogus", "bad-length", "unknown-id", "wrong-size",
    };
    return kind < I2C_HID_IN_KIND_COUNT ? names[kind] : "unknown";
}
