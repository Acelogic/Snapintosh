/* SPDX-License-Identifier: MIT */
/*
 * The touchpad as a Windows Precision Touchpad for SnapI2CHIDPointer (src/SnapI2CHID.cpp): the
 * Touch Pad (13/5) collection's multi-contact input report and the Device Configuration (13/14)
 * features, read from the device's own report descriptor, the mode switch that makes the device
 * send them (Input Mode = 3, Surface and Button Switch on), and a gesture engine that turns the
 * frames into pointer, click and phased scroll events (docs/A16-INPUT-PTP-20261020.md; failure
 * modes F1-F22 there).
 *
 * Protocol facts are from the HID 1.11 item encoding, the HID Usage Tables (Digitizers page 0x0D)
 * and Microsoft's Precision Touchpad collection requirements; Linux drivers/hid/hid-multitouch.c
 * supplied the device quirks (read the 0xff0000c5 blob once, skip a second Input Mode). No code is
 * copied. Integer arithmetic only (kernel). Hardware independent: the host tests compile it.
 */
#ifndef SNAP_HID_PTP_H
#define SNAP_HID_PTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HID_PTP_MAX_FINGERS   10u     /* finger collections in the input report */
#define HID_PTP_MAX_CONTACTS  10u     /* contacts tracked at once (Contact Count is clamped) */
#define HID_PTP_MAX_BUTTONS   3u
#define HID_PTP_MODE_TOUCHPAD 3u      /* Input Mode value for "touchpad" */

/* Engine constants (section 4.3 of the design). Distances in micrometres, times in microseconds. */
#define HID_PTP_SETTLE_US        40000u   /* pointer held after a finger-count change or a button edge */
#define HID_PTP_SCROLL_START_UM   1200u   /* mean two-finger travel before a scroll begins */
#define HID_PTP_SCROLL_EACH_UM     500u   /* and each finger's own, so a resting thumb never scrolls */
#define HID_PTP_REST_MOVE_UM      2500u   /* one finger this far while the other stays within */
#define HID_PTP_REST_STILL_UM      500u   /* ... this: the still one is a resting thumb */
#define HID_PTP_LIFT_WINDOW_US   60000u   /* 2 -> 1 during a scroll: wait this long for the second lift */
#define HID_PTP_TAP_MAX_US      180000u   /* first contact to last lift */
#define HID_PTP_TAP_TRAVEL_UM     1500u   /* per finger */
#define HID_PTP_TAP_RELEASE_US   12000u   /* tap click held this long (released on a tick) */
#define HID_PTP_TYPING_US       300000u   /* no tap within this of a key-down */
#define HID_PTP_JUMP_UM          20000u   /* a track moving more in one frame is a new contact */
#define HID_PTP_MOMENTUM_RECENT_US 50000u /* scroll motion this close to the lift for momentum */
#define HID_PTP_MOMENTUM_MAX_US 3000000u
#define HID_PTP_MOMENTUM_START   300u     /* release speed, 1/400 inch per second (0.75 in/s) */
#define HID_PTP_MOMENTUM_STOP     60u     /* (0.15 in/s) */
#define HID_PTP_MOMENTUM_DECAY_Q16 65372u /* per millisecond: exp(-1/400) */
#define HID_PTP_UNITS_PER_INCH   400u     /* output deltas, IOFixed, in 1/400 inch of finger travel */

/* Scroll dispatch options: the values of IOHIDEventService.h's kHIDDispatchOption* (26A428), which
 * src/SnapI2CHID.cpp checks with static_assert. */
#define HID_PTP_SCROLL_MOMENTUM_CONTINUE (1u << 1)
#define HID_PTP_SCROLL_MOMENTUM_START    (1u << 2)
#define HID_PTP_SCROLL_MOMENTUM_END      (1u << 3)
#define HID_PTP_SCROLL_PHASE_BEGAN       (1u << 4)
#define HID_PTP_SCROLL_PHASE_CHANGED     (1u << 5)
#define HID_PTP_SCROLL_PHASE_ENDED       (1u << 6)

struct hid_ptp_field {
    uint16_t offset;          /* bit offset after the report-ID byte */
    uint8_t size;             /* bits, 0 = absent */
    uint8_t is_signed;
    int32_t min, max;         /* logical range */
};

struct hid_ptp_finger {
    struct hid_ptp_field tip, confidence, id, x, y;
};

/* One field of a feature report; report_id 0 = absent (Precision Touchpad reports are numbered). */
struct hid_ptp_feature {
    uint8_t report_id;
    uint16_t report_bytes;    /* including the ID byte */
    struct hid_ptp_field field;
};

struct hid_ptp_layout {
    uint8_t report_id;
    uint16_t report_bytes;    /* the input report, ID byte included */
    uint8_t fingers;
    uint8_t has_confidence;   /* every finger has Confidence */
    struct hid_ptp_finger finger[HID_PTP_MAX_FINGERS];
    struct hid_ptp_field contact_count, scan_time;
    uint8_t buttons;          /* page 9 buttons 1..buttons in the report */
    struct hid_ptp_field button[HID_PTP_MAX_BUTTONS];
    uint32_t width_um, height_um;          /* physical extent of finger 0's X and Y */
    int32_t x_min, x_max, y_min, y_max;    /* finger 0's logical range */
    struct hid_ptp_feature input_mode, surface_switch, button_switch, contact_max, pad_type, blob;
};

enum hid_ptp_layout_result {
    HID_PTP_OK = 0,
    HID_PTP_NO_TOUCHPAD,      /* no Digitizer / Touch Pad (13/5) application collection */
    HID_PTP_NO_FINGERS,       /* no finger collection with Tip Switch and absolute X and Y */
    HID_PTP_NO_INPUT_MODE,    /* no Input Mode (13/0x52) feature: the mode cannot be switched */
    HID_PTP_NO_UNITS,         /* X or Y without a usable physical extent and length unit */
    HID_PTP_UNSUPPORTED,      /* more fingers than HID_PTP_MAX_FINGERS, fields over 32 bits, ... */
    HID_PTP_MALFORMED,        /* truncated item, collection or stack imbalance, oversize report */
};

int hid_ptp_layout(const uint8_t *rdesc, uint32_t len, struct hid_ptp_layout *out);
const char *hid_ptp_layout_name(int result);

/* Feature-report access for the mode switch. Reports start with their ID byte. Both return 0 on
 * success; get_feature returns nonzero when the report is unavailable (empty, bad response, bus). */
struct hid_ptp_io {
    void *ctx;
    int (*get_feature)(void *ctx, uint8_t id, uint8_t *buf, uint32_t cap, uint32_t *got);
    int (*set_feature)(void *ctx, const uint8_t *report, uint32_t len);
};

enum hid_ptp_enable_result {
    HID_PTP_ENABLED = 0,            /* written, and Input Mode reads back 3 */
    HID_PTP_ENABLED_UNVERIFIED,     /* written; the readback was unavailable */
    HID_PTP_REFUSED_WRITE,          /* the Input Mode write failed: nothing more was sent */
    HID_PTP_REFUSED_READBACK,       /* written, but Input Mode reads back another value */
    HID_PTP_ENABLE_INVALID,         /* no Input Mode in the layout, or no buffer */
};

struct hid_ptp_setup {
    int result;
    uint8_t mode_before, mode_before_read;   /* Input Mode before the write, if it could be read */
    uint8_t mode_after, mode_after_read;
    uint8_t blob_read;                       /* the 0xff0000c5 report was read */
    uint16_t blob_bytes;
    uint8_t caps_read, max_contacts, pad_type;
    uint8_t selective_written;               /* Surface/Button Switch report written */
    uint8_t requests;                        /* feature requests issued */
};

/* The sequence of section 4.2: blob, capabilities, Input Mode = 3, Surface/Button Switch, readback.
 * scratch holds the largest feature report (cap bytes). Returns setup->result. */
int hid_ptp_enable(const struct hid_ptp_layout *l, const struct hid_ptp_io *io, uint8_t *scratch,
                   uint32_t cap, struct hid_ptp_setup *setup);
const char *hid_ptp_enable_name(int result);

/* A field into / out of report bytes (body = after the ID byte). */
void hid_ptp_put(uint8_t *body, uint32_t bytes, const struct hid_ptp_field *f, uint32_t value);
uint32_t hid_ptp_get(const uint8_t *body, uint32_t bytes, const struct hid_ptp_field *f);

/* ------------------------------------------------------------------------------ engine ---- */

struct hid_ptp_contact {
    uint32_t id;
    uint8_t tip, confident;
    int32_t x, y;
};

struct hid_ptp_frame {
    uint8_t slots;                                /* finger slots decoded (= layout fingers) */
    struct hid_ptp_contact c[HID_PTP_MAX_FINGERS];
    uint32_t count;                               /* Contact Count, when the layout has it */
    uint32_t scan;                                /* Scan Time, when the layout has it */
    uint32_t buttons;                             /* bit n = button n+1 */
};

enum hid_ptp_decode_result { HID_PTP_FRAME = 0, HID_PTP_OTHER_REPORT, HID_PTP_BAD_LENGTH };
int hid_ptp_decode(const struct hid_ptp_layout *l, const uint8_t *report, uint32_t len,
                   struct hid_ptp_frame *f);

/* Callbacks, on the caller's thread. Deltas are IOFixed (16.16) in 1/400 inch; buttons bit 0 is
 * the primary button, bit 1 the secondary. scroll's options are HID_PTP_SCROLL_* bits. */
typedef void (*hid_ptp_pointer_fn)(void *ctx, int32_t dx, int32_t dy, uint32_t buttons);
typedef void (*hid_ptp_scroll_fn)(void *ctx, int32_t vertical, int32_t horizontal, uint32_t options);
/* Optional: every complete frame (after the hybrid merge), before the gestures: the contacts as
 * decoded (tip 0 = lifting), the PTP buttons, and Scan Time when has_scan. */
typedef void (*hid_ptp_frame_fn)(void *ctx, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons,
                                 uint32_t scan, int has_scan);
struct hid_ptp_sink {
    void *ctx;
    hid_ptp_pointer_fn pointer;
    hid_ptp_scroll_fn scroll;
    hid_ptp_frame_fn frame;
};

/* IDLE: nothing down. POINTER: one finger (or a press). TWO: two fingers, not yet scrolling.
 * SCROLL / SCROLL_LIFT: scrolling, and the window after one of the two lifted. REST: two fingers,
 * one a resting thumb: the other moves the pointer. MULTI: three or more. */
enum hid_ptp_mode {
    HID_PTP_IDLE = 0, HID_PTP_POINTER, HID_PTP_TWO, HID_PTP_SCROLL, HID_PTP_SCROLL_LIFT, HID_PTP_REST,
    HID_PTP_MULTI,
};

struct hid_ptp_track {
    uint8_t used, palm, moved, seen;   /* moved: present last frame too (dx/dy valid) */
    uint32_t id;
    int32_t x, y, x0, y0;     /* last and landing position, counts */
    int32_t xe, ye;           /* position when the current two-finger configuration began */
    uint32_t travel_um;       /* largest distance from the landing point */
    int32_t dx, dy;           /* this frame's motion, counts */
};

struct hid_ptp_stats {
    uint32_t reports, frames, bad_length, contacts, palms, reused_ids, duplicate_ids, jumps;
    uint32_t pointer_events, button_edges, taps, secondary_taps, typing_blocked_taps;
    uint32_t scrolls, scroll_events, momentum, momentum_events, hybrid_partial, hybrid_dropped;
    uint32_t scan_fallbacks, max_fingers;
};

struct hid_ptp_engine {
    struct hid_ptp_layout l;
    uint64_t q16_x, q16_y;        /* output units (Q16) per count, times 2^16 */
    uint64_t um_x, um_y;          /* micrometres per count, times 2^16 */
    struct hid_ptp_track t[HID_PTP_MAX_CONTACTS];
    uint32_t mode, fingers;       /* fingers: tracks that are not palms, last frame */
    uint64_t settle_until, lift_at, last_us, last_scroll_us;
    /* the touch session: first contact to all lifted */
    uint8_t session, s_max, s_palm, s_press, s_scrolled, s_far, s_typing;
    uint64_t s_start;
    uint32_t ended[8], nended;    /* IDs that ended this session (reuse is counted) */
    /* scrolling */
    int64_t acc_v, acc_h;         /* travel before the scroll began, Q16 */
    int64_t vel_v, vel_h;         /* Q16 units per second, smoothed */
    uint8_t have_vel;
    uint32_t last_scan;
    uint8_t have_scan;
    /* momentum */
    uint8_t momentum, momentum_started;
    int64_t mom_v, mom_h, mom_frac_v, mom_frac_h;
    uint64_t mom_at, mom_start;
    /* buttons */
    uint32_t phys, mapped, tap, last_buttons;
    uint64_t tap_release_at;
    /* hybrid frames */
    struct hid_ptp_frame pending;
    uint32_t pending_want;
    struct hid_ptp_stats stats;
};

void hid_ptp_engine_init(struct hid_ptp_engine *e, const struct hid_ptp_layout *l);
/* One input report. last_key_us: the latest key-down (0 = none). Returns hid_ptp_decode's result. */
int hid_ptp_engine_report(struct hid_ptp_engine *e, const uint8_t *report, uint32_t len, uint64_t now_us,
                          uint64_t last_key_us, const struct hid_ptp_sink *s);
/* Every poll: tap release, the lift window and momentum. */
void hid_ptp_engine_tick(struct hid_ptp_engine *e, uint64_t now_us, const struct hid_ptp_sink *s);
/* Whether tick has anything to do (momentum, a tap release, a lift window). */
int hid_ptp_engine_busy(const struct hid_ptp_engine *e);
/* End everything (scroll, momentum, buttons) with the events that say so, and forget all contacts. */
void hid_ptp_engine_reset(struct hid_ptp_engine *e, uint64_t now_us, const struct hid_ptp_sink *s);

#ifdef __cplusplus
}
#endif

#endif
