/* SPDX-License-Identifier: MIT */
/*
 * Report-to-key translation for SnapI2CHIDKeyboard, our own IOHIDEventService
 * (src/SnapI2CHID.cpp). 26A428's generic keyboard drivers are all IOMatchDefer
 * and none attached in v40/v41 (docs/A16-INPUT-INSTALLED-20261017.md sections
 * 11-12), so the kext turns the A16 keyboard's reports into key events itself.
 *
 * Layouts, from the keyboard's 144-byte report descriptor (SHA256 0887190d...):
 *   report 54 (9 bytes): ID, modifier bits E0..E7, a constant byte, six key
 *                        usages (page 7, array, logical 0..0x65);
 *   report 55 (3 bytes): ID, one 16-bit Consumer usage (array, 0 = none).
 * Report 90 (ASUS vendor page) and anything else produce no event.
 *
 * Hardware independent, like the rest of src/: the host test compiles it.
 */
#ifndef SNAP_HID_KEYBOARD_H
#define SNAP_HID_KEYBOARD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HID_KBD_REPORT_KEYS      0x36u
#define HID_KBD_REPORT_CONSUMER  0x37u
#define HID_KBD_KEYS_BYTES       9u
#define HID_KBD_CONSUMER_BYTES   3u
#define HID_KBD_PAGE_KEYBOARD    0x07u
#define HID_KBD_PAGE_CONSUMER    0x0cu
#define HID_KBD_MAX_KEY          0x65u   /* the array's logical maximum */
#define HID_KBD_ROLLOVER         0x01u   /* ErrorRollOver: the whole report is unusable */

struct hid_kbd_state {
    uint8_t modifiers;
    uint8_t keys[6];
    uint16_t consumer;
};

/* One key transition: down 1 or 0. */
typedef void (*hid_kbd_emit_fn)(void *ctx, uint32_t page, uint32_t usage, uint32_t down);

enum hid_kbd_result { HID_KBD_EVENTS = 0, HID_KBD_IGNORED, HID_KBD_ROLLOVER_REPORT, HID_KBD_BAD_LENGTH };

/* Emit the transitions from *state to this report, in a fixed order (modifier
 * releases, key releases, modifier presses, key presses; consumer release then
 * press), and update *state. Returns how the report was taken. */
int hid_kbd_translate(struct hid_kbd_state *state, const uint8_t *report, uint32_t len,
                      hid_kbd_emit_fn emit, void *ctx);
/* Release everything held (stop, or a re-initialised device). */
void hid_kbd_release_all(struct hid_kbd_state *state, hid_kbd_emit_fn emit, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
