/* SPDX-License-Identifier: MIT */
/*
 * The touchpad's mouse-mode pointer for SnapI2CHIDPointer (src/SnapI2CHID.cpp), our own
 * IOHIDEventService: a Precision Touchpad stays in mouse mode until its Input Mode feature
 * is set, and in that mode it reports a Generic Desktop / Mouse (1/2) application
 * collection: buttons (page 9), relative X/Y (1/0x30, 1/0x31), optionally a wheel (1/0x38)
 * and AC Pan (0x0c/0x238). The layout is read from the device's own report descriptor
 * (the A16 touchpad's has not been read yet: tools/qualify-a16-touchpad.py), not assumed.
 *
 * Hardware independent: the host test compiles it.
 */
#ifndef SNAP_HID_POINTER_H
#define SNAP_HID_POINTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hid_pointer_field {
    uint16_t offset;          /* bit offset in the report, after the ID byte */
    uint8_t size;             /* bits, 0 = absent */
    uint8_t is_signed;        /* logical minimum below zero */
};

struct hid_pointer_layout {
    uint8_t report_id;        /* 0: unnumbered */
    uint16_t report_bytes;    /* including the ID byte when numbered */
    uint16_t buttons_offset;
    uint8_t buttons;          /* button bits from button 1, at most 16 */
    struct hid_pointer_field x, y, wheel, pan;
};

enum hid_pointer_result {
    HID_POINTER_OK = 0,
    HID_POINTER_NO_MOUSE,     /* no 1/2 application collection with relative X and Y */
    HID_POINTER_MALFORMED,    /* truncated item, stack or collection imbalance, oversize report */
};

/* The first mouse collection's input report, or an error. */
int hid_pointer_layout(const uint8_t *rdesc, uint32_t len, struct hid_pointer_layout *out);

struct hid_pointer_state {
    uint32_t buttons;
};

typedef void (*hid_pointer_move_fn)(void *ctx, int32_t dx, int32_t dy, uint32_t buttons);
typedef void (*hid_pointer_scroll_fn)(void *ctx, int32_t vertical, int32_t horizontal);

enum hid_pointer_translate_result { HID_POINTER_EVENTS = 0, HID_POINTER_OTHER_REPORT, HID_POINTER_BAD_LENGTH };

/* One input report: a move event when it moves or the buttons change, a scroll event when the
 * wheel or pan is non-zero. Reports of other IDs are left alone. */
int hid_pointer_translate(const struct hid_pointer_layout *l, struct hid_pointer_state *s,
                          const uint8_t *report, uint32_t len, hid_pointer_move_fn move,
                          hid_pointer_scroll_fn scroll, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
