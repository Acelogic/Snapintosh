/* SPDX-License-Identifier: MIT */
/*
 * Bounded HID report-descriptor scan: the structural checks of
 * tools/read-a16-hid-report-descriptor.py (describe_items) in C, plus the
 * top-level application collections. It derives report sizes so the I2C-HID
 * transport can validate every input report's length prefix. It maps no
 * usage to an event; IOHIDFamily parses the descriptor itself.
 */
#ifndef SNAP_HID_RDESC_H
#define SNAP_HID_RDESC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HID_RDESC_MAX_REPORTS  64
#define HID_RDESC_MAX_APPS     16
#define HID_RDESC_MAX_DEPTH    32   /* nested collections */
#define HID_RDESC_MAX_STACK    16   /* Push depth */

enum hid_report_type { HID_REPORT_INPUT = 0, HID_REPORT_OUTPUT = 1, HID_REPORT_FEATURE = 2 };

enum hid_rdesc_result {
    HID_RDESC_OK = 0,
    HID_RDESC_TRUNCATED,    /* item header or payload runs past the end */
    HID_RDESC_BAD_ITEM,     /* reserved item type or unknown main item */
    HID_RDESC_STACK,        /* Push overflow or Pop without Push */
    HID_RDESC_COLLECTION,   /* nesting overflow or unbalanced End Collection */
    HID_RDESC_REPORT_ID,    /* Report ID not a one-byte value 1..255 */
    HID_RDESC_FIELD,        /* field outside a collection, missing size/count, unbounded */
    HID_RDESC_MIXED_IDS,    /* numbered and unnumbered reports together */
    HID_RDESC_TOO_MANY,     /* more reports or applications than the tables hold */
    HID_RDESC_EMPTY,        /* no report field at all */
};

struct hid_report_shape {
    uint8_t type;           /* enum hid_report_type */
    uint8_t id;             /* 0: unnumbered */
    uint16_t reserved;
    uint32_t bits;          /* sum of size * count of the report's fields */
};

struct hid_app_usage {
    uint16_t page, usage;
};

struct hid_rdesc_info {
    uint32_t items;
    uint32_t nreports;
    struct hid_report_shape reports[HID_RDESC_MAX_REPORTS];
    uint32_t napps;
    struct hid_app_usage apps[HID_RDESC_MAX_APPS];
    uint8_t numbered;
    uint32_t error_offset;  /* item offset of the first failure */
};

int hid_rdesc_parse(const uint8_t *desc, uint32_t len, struct hid_rdesc_info *out);
/* Report bytes as HID transports carry them: data rounded up to bytes, plus
 * the report-ID byte for numbered reports. 0 when the report is not declared. */
uint32_t hid_rdesc_report_bytes(const struct hid_rdesc_info *info, uint8_t type, uint8_t id);
/* The largest report of a type, same units. */
uint32_t hid_rdesc_max_report_bytes(const struct hid_rdesc_info *info, uint8_t type);

#ifdef __cplusplus
}
#endif

#endif
