/* SPDX-License-Identifier: MIT */
/*
 * HID over I2C transport and device state machine on top of geni-i2c.
 *
 * Protocol facts: Microsoft's HID over I2C enumeration sequence (read the HID
 * descriptor, SET_POWER(ON), RESET, the device signals and returns 0x00 0x00
 * from the input register, read the report descriptor) and the command
 * encodings, timings and quirks of Linux drivers/hid/i2c-hid/i2c-hid-core.c
 * (SHA256 bd907b7a...): SET_POWER(ON) is retried once after a NACK and
 * followed by 60 ms, a device without a reset interrupt is given 100 ms,
 * a reset acknowledgment is awaited for at most 1 s, SET_POWER(ON) is sent
 * again after reset, and a GET_REPORT length of 2 or less is an empty report.
 * No Linux code is copied.
 *
 * Live input is a plain I2C read (no register write first) of wMaxInputLength
 * bytes: a little-endian length, then one report. Length 0 means nothing is
 * pending (or a reset completed). This module polls that read on a timer,
 * optionally gated by a sampled attention level; it uses no interrupt.
 */
#ifndef SNAP_I2C_HID_H
#define SNAP_I2C_HID_H

#include <stdint.h>

#include "geni-i2c.h"
#include "hid-rdesc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define I2C_HID_DESC_BYTES      30u
#define I2C_HID_MAX_RDESC       4096u
#define I2C_HID_MAX_INPUT       512u
#define I2C_HID_MAX_OUTPUT      512u
#define I2C_HID_NO_WAKE         0xffffffffu

#define I2C_HID_OP_RESET        0x1u
#define I2C_HID_OP_GET_REPORT   0x2u
#define I2C_HID_OP_SET_REPORT   0x3u
#define I2C_HID_OP_SET_POWER    0x8u
#define I2C_HID_POWER_ON        0x0u
#define I2C_HID_POWER_SLEEP     0x1u
#define I2C_HID_TYPE_INPUT      0x1u
#define I2C_HID_TYPE_OUTPUT     0x2u
#define I2C_HID_TYPE_FEATURE    0x3u

struct i2c_hid_desc {
    uint16_t desc_length, version, rdesc_length, rdesc_register, input_register, max_input;
    uint16_t output_register, max_output, command_register, data_register;
    uint16_t vendor_id, product_id, device_version;
    uint32_t reserved;
};

enum i2c_hid_desc_result {
    I2C_HID_DESC_OK = 0, I2C_HID_DESC_LENGTH, I2C_HID_DESC_VERSION, I2C_HID_DESC_BOUNDS,
    I2C_HID_DESC_RESERVED,
};
int i2c_hid_parse_desc(const uint8_t *raw, uint32_t len, struct i2c_hid_desc *out);

/* Command encoders. Each returns the byte count written, 0 if cap is short. */
uint32_t i2c_hid_encode_command(const struct i2c_hid_desc *d, uint8_t opcode, uint8_t type,
                                uint8_t id, uint8_t *out, uint32_t cap);
uint32_t i2c_hid_encode_set_power(const struct i2c_hid_desc *d, uint8_t state, uint8_t *out,
                                  uint32_t cap);
uint32_t i2c_hid_encode_reset(const struct i2c_hid_desc *d, uint8_t *out, uint32_t cap);
uint32_t i2c_hid_encode_get_report(const struct i2c_hid_desc *d, uint8_t type, uint8_t id,
                                   uint8_t *out, uint32_t cap);
/* data excludes the report ID; the ID is inserted after the length. */
uint32_t i2c_hid_encode_set_report(const struct i2c_hid_desc *d, uint8_t type, uint8_t id,
                                   const uint8_t *data, uint32_t len, uint8_t *out, uint32_t cap);
uint32_t i2c_hid_encode_output(const struct i2c_hid_desc *d, uint8_t id, const uint8_t *data,
                               uint32_t len, uint8_t *out, uint32_t cap);

enum i2c_hid_input_kind {
    I2C_HID_IN_EMPTY = 0,     /* length 0 (nothing pending or reset done) or 2 */
    I2C_HID_IN_REPORT,        /* a declared input report of exactly its size */
    I2C_HID_IN_BOGUS,         /* length 0xffff: no data (Linux I2C_HID_QUIRK_BOGUS_IRQ) */
    I2C_HID_IN_BAD_LENGTH,    /* length 1 or beyond the bytes read */
    I2C_HID_IN_UNKNOWN_ID,    /* report ID absent from the report descriptor */
    I2C_HID_IN_WRONG_SIZE,    /* declared ID, different size */
    I2C_HID_IN_KIND_COUNT
};

struct i2c_hid_input {
    uint32_t kind;
    uint16_t length;          /* the device's length prefix */
    uint8_t id, reserved;
    const uint8_t *report;    /* report bytes after the prefix, ID first when numbered */
    uint32_t report_bytes;
};

/* Input-register data (got = bytes read, normally wMaxInputLength). */
int i2c_hid_classify_input(const struct hid_rdesc_info *r, const uint8_t *buf, uint32_t got,
                           struct i2c_hid_input *out);
/* A GET_REPORT response for (type, id); type is an I2C_HID_TYPE_* value. */
int i2c_hid_classify_response(const struct hid_rdesc_info *r, uint8_t type, uint8_t id,
                              const uint8_t *buf, uint32_t got, struct i2c_hid_input *out);

struct i2c_hid_config {
    uint8_t address;                 /* 7-bit */
    uint8_t power_on_after_reset;    /* Linux default; 0 = I2C_HID_QUIRK_NO_WAKEUP_AFTER_RESET */
    uint8_t re_power_on;             /* I2C_HID_QUIRK_RE_POWER_ON (QTEC vendor 0x6243 only) */
    uint8_t skip_reset;              /* never RESET (bring-up diagnosis only) */
    uint16_t desc_register;          /* ACPI _DSM / DT hid-descr-addr */
    uint16_t expect_vendor, expect_product;   /* 0: any */
    uint32_t poll_us;                /* RUNNING poll period */
    uint32_t power_settle_us;        /* after SET_POWER(ON) */
    uint32_t reset_settle_us;        /* after RESET, before the first input read */
    uint32_t reset_deadline_us;      /* NACKs tolerated after RESET until then */
    uint32_t reset_retry_us;         /* spacing of input reads while the device NACKs */
    uint32_t init_retry_us;          /* spacing of retried initialisation steps */
    uint32_t max_init_errors;
    uint32_t max_consecutive_errors; /* in RUNNING, before re-initialising */
    uint32_t max_reinit;
    uint32_t max_reads_per_tick;     /* drain queued reports */
};
void i2c_hid_default_config(struct i2c_hid_config *cfg, uint8_t address, uint16_t desc_register);

enum i2c_hid_state {
    I2C_HID_S_OFF = 0, I2C_HID_S_DESC, I2C_HID_S_POWER_ON, I2C_HID_S_RESET, I2C_HID_S_RESET_WAIT,
    I2C_HID_S_POWER_ON2, I2C_HID_S_RDESC, I2C_HID_S_READY, I2C_HID_S_RUNNING, I2C_HID_S_FAILED,
    I2C_HID_S_COUNT
};

enum i2c_hid_failure {
    I2C_HID_F_NONE = 0, I2C_HID_F_BUS, I2C_HID_F_DESCRIPTOR, I2C_HID_F_IDENTITY, I2C_HID_F_RESET,
    I2C_HID_F_REPORT_DESCRIPTOR, I2C_HID_F_INIT_ERRORS, I2C_HID_F_REINIT, I2C_HID_F_COUNT
};

enum i2c_hid_request_result {
    I2C_HID_R_OK = 0, I2C_HID_R_EMPTY, I2C_HID_R_BAD_RESPONSE, I2C_HID_R_NOT_READY,
    I2C_HID_R_INVALID, I2C_HID_R_BUS, I2C_HID_R_COUNT
};

struct i2c_hid_stats {
    uint32_t polls, empty, bogus, reports, bad_length, unknown_id, wrong_size, identical;
    uint32_t transfer_errors, nacks, reinits, reset_retries, early_reports;
    uint32_t outputs, requests, request_errors;
    uint32_t attention_skips, reset_acks, reset_without_attention;
    uint32_t oversize_inputs;        /* declared input reports longer than wMaxInputLength allows */
};

typedef void (*i2c_hid_deliver_fn)(void *ctx, const uint8_t *report, uint32_t len);
/* Optional attention-line sampler: 1 asserted (report pending), 0 idle.
 * Phase 2 of docs/A16-INPUT-DRIVER-20260928.md reads the TLMM GPIO input
 * level through a read-only page; without it every poll reads the bus. */
typedef int (*i2c_hid_attention_fn)(void *ctx);

struct i2c_hid_dev {
    struct geni_i2c *bus;
    struct i2c_hid_config cfg;
    uint32_t state, failure, failed_in;
    int last_result;                 /* last geni_i2c result */
    uint64_t reset_at_us;
    uint32_t init_errors, consecutive_errors, reinits;
    uint8_t have_desc, have_rdesc, published, reserved;
    uint8_t desc_raw[I2C_HID_DESC_BYTES];
    struct i2c_hid_desc desc;
    uint32_t rdesc_len;
    uint8_t rdesc[I2C_HID_MAX_RDESC];
    struct hid_rdesc_info rinfo;
    uint8_t inbuf[I2C_HID_MAX_INPUT];
    uint32_t last_report_len;
    uint8_t last_report[I2C_HID_MAX_INPUT];
    uint32_t rejected_len;           /* the last rejected input, for diagnosis */
    uint8_t rejected[I2C_HID_MAX_INPUT];
    uint8_t scratch[I2C_HID_MAX_RDESC];   /* re-read descriptors, GET_REPORT responses */
    i2c_hid_deliver_fn deliver;
    void *deliver_ctx;
    i2c_hid_attention_fn attention;
    void *attention_ctx;
    struct i2c_hid_stats stats;
};

int i2c_hid_begin(struct i2c_hid_dev *d, struct geni_i2c *bus, const struct i2c_hid_config *cfg,
                  i2c_hid_deliver_fn deliver, void *ctx);
/* Optional; call after i2c_hid_begin. */
void i2c_hid_set_attention(struct i2c_hid_dev *d, i2c_hid_attention_fn fn, void *ctx);
/* Advance one step. Returns microseconds until the next call, or
 * I2C_HID_NO_WAKE in READY (publish, then i2c_hid_run), FAILED and OFF. */
uint32_t i2c_hid_step(struct i2c_hid_dev *d);
int i2c_hid_run(struct i2c_hid_dev *d);
/* Stop polling; sends nothing to the device. */
void i2c_hid_stop(struct i2c_hid_dev *d);
/* report starts with its ID when the descriptor numbers reports. */
int i2c_hid_send_output(struct i2c_hid_dev *d, const uint8_t *report, uint32_t len);
int i2c_hid_set_report(struct i2c_hid_dev *d, uint8_t type, const uint8_t *report, uint32_t len);
/* On OK, buf holds the report (ID first when numbered) and *got its size. */
int i2c_hid_get_report(struct i2c_hid_dev *d, uint8_t type, uint8_t id, uint8_t *buf,
                       uint32_t cap, uint32_t *got);

const char *i2c_hid_state_name(uint32_t state);
const char *i2c_hid_failure_name(uint32_t failure);
const char *i2c_hid_input_kind_name(uint32_t kind);

#ifdef __cplusplus
}
#endif

#endif
