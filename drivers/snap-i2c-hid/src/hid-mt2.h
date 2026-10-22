/* SPDX-License-Identifier: MIT */
/*
 * The touchpad as an Apple multitouch device, for SnapI2CHIDMultitouch (src/SnapI2CHID.cpp): the
 * Precision Touchpad contacts that hid-ptp.c decodes become the contact frames and the feature
 * replies that 26A428's own trackpad stack expects, so AppleMultitouchTrackpadHIDEventDriver,
 * AppleMultitouchDevice and the user-space gesture engine (HSTouchHIDService, MultitouchSupport) do
 * pointer, scroll, clicks and the system gestures (failure modes M1-M20 in the gestures agent's
 * FAILURE-MODES.md; the stage-1 notes in docs/A16-INPUT-GESTURES-20261021.md).
 *
 * Every format here was read from 26A428 binaries on the KDK and on a 26A428 host, for
 * interoperability with this driver:
 *  - the J700 BootKC personality "Mac SPI MT - TopCase - 641" (AppleTopCaseDriverV2) matches an
 *    IOHIDInterface with VendorID 0x05ac, ProductID 641 and usage pair 1/2, and is not IOMatchDefer;
 *  - AppleMultitouchTrackpadHIDEventDriver::handleInterruptReport takes input report 2 longer than
 *    8 bytes, reads its first 8 bytes as a mouse header (byte 7 bit 1: tracking, the header is then
 *    ignored), strips them and passes the rest, a report 0x31 frame, to the multitouch device;
 *  - AppleMultitouchDevice::_cacheDeviceProperties reads feature 0xDB (version 1, then entries of
 *    u16 length, report ID, payload) and fetches D1, D3, D0, A1, D9 and 7F one by one for any entry
 *    missing; decodeDeviceProperty gives their layouts (D1 family, D3 endianness/rows/columns/bcd/
 *    max packet, D0 and A1 raw, D9 width/height in 0.01 mm plus the 16-byte surface descriptor);
 *  - MultitouchSupport MTCompactV7HeaderUnpack / MTCompactV7BinaryContactUnpack and HSTouch
 *    -[HSTFrameParser unpackFrame31Header:/unpackFrame31Contact:] unpack the 0x31 frame identically:
 *    byte 1 bit 0 button, bit 2 host click, bits 3.. 21-bit millisecond timestamp; then 9 bytes per
 *    contact: X and Y 13-bit signed (output X = 2x, Y = 2y + 5000, in 0.01 mm), finger 3 bits,
 *    path stage 3 bits, major, minor, size, pressure codes, ID 4 bits, angle 3 bits;
 *  - HSTPipeline::SurfaceCoordinates::fromService reads the surface descriptor's four int16 as
 *    xmin, ymin, xmax, ymax (x10, micrometres), and TrackpadAlgStage counts stages 1..4 as down.
 * The frame layout is also the Magic Trackpad 2's wire format, which public projects (Linux
 * hid-magicmouse, VoodooInput) document; no code is copied. Integer arithmetic only (kernel).
 * Hardware independent: the host tests compile it.
 */
#ifndef SNAP_HID_MT2_H
#define SNAP_HID_MT2_H

#include <stdint.h>
#include "hid-ptp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HID_MT2_VENDOR          0x05acu
#define HID_MT2_PRODUCT         0x0281u   /* 641: the "Mac SPI MT - TopCase - 641" personality */
#define HID_MT2_VERSION         0x0100u
#define HID_MT2_FAMILY          0x81u     /* a family MultitouchSupport's path algorithms know */
#define HID_MT2_ROWS            22u
#define HID_MT2_COLUMNS         30u
#define HID_MT2_BCD             0x0100u
#define HID_MT2_MAX_PACKET      0x400u    /* AMD's own default */

#define HID_MT2_REPORT_ID       0x02u     /* the outer input report */
#define HID_MT2_FRAME_ID        0x31u     /* the inner contact frame */
#define HID_MT2_VENDOR_REPORT   0x3fu     /* declared only, so MaxInputReportSize covers a frame */
#define HID_MT2_HEADER_BYTES    8u
#define HID_MT2_FRAME_HEADER    4u
#define HID_MT2_CONTACT_BYTES   9u
#define HID_MT2_MAX_TRACKS      16u       /* contacts in one frame: down and lifting */
#define HID_MT2_MAX_REPORT      (HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER + HID_MT2_MAX_TRACKS * HID_MT2_CONTACT_BYTES)
#define HID_MT2_DECLARED_INPUT  256u      /* report 0x3f: ID + 255 bytes */
#define HID_MT2_MAX_FEATURE     80u       /* the longest feature reply, 0xDB, ID included */
#define HID_MT2_LIVE_IDS        15u       /* MT contact IDs 1..15 */

/* The 0x31 frame header's flags (byte 1). Host click off: the physical button is the device button
 * bit, which HSTouch's TrackpadAlgStage takes as the raw button state (and does its own secondary
 * click); host click on would make it detect clicks from contact force instead. */
#define HID_MT2_FLAG_BUTTON     0x01u
#define HID_MT2_FLAG_HOST_CLICK 0x04u
#define HID_MT2_HOST_CLICK      0u

/* Path stages (MTTouch stage numbering): HSTouch counts 1..4 as touching. */
#define HID_MT2_STAGE_MAKE      3u
#define HID_MT2_STAGE_TOUCH     4u
#define HID_MT2_STAGE_BREAK     5u
#define HID_MT2_STAGE_OUT       7u

/* Finger types; the parser turns 7 into 12, invalid (a palm). */
#define HID_MT2_FINGER_THUMB    1u
#define HID_MT2_FINGER_INDEX    2u
#define HID_MT2_FINGER_PALM     7u

/* Size codes for a touching contact (the PTP report has no contact size): a finger of about 6 mm
 * major radius in MultitouchSupport's code mapping. Lifting contacts send zeros. */
#define HID_MT2_CODE_MAJOR      20u
#define HID_MT2_CODE_MINOR      20u
#define HID_MT2_CODE_SIZE       10u
#define HID_MT2_CODE_PRESSURE   5u
#define HID_MT2_CODE_ANGLE      4u        /* pi/2 */

/* Geometry: X and Y are 13-bit signed in 0.02 mm, so a side may not exceed 163.8 mm. */
#define HID_MT2_MIN_SIDE_HMM    3000u     /* 30 mm, in 0.01 mm */
#define HID_MT2_MAX_SIDE_HMM    16380u
#define HID_MT2_Y_CENTRE        5000      /* the parsers add it to 2y */
#define HID_MT2_JUMP_UM         20000u    /* one frame's travel above this is a new touch (F6) */
#define HID_MT2_TICK_US         8000u     /* trailing frames at most this often (one poll) */

enum hid_mt2_init_result {
    HID_MT2_OK = 0,
    HID_MT2_NO_LAYOUT,        /* no Precision Touchpad layout */
    HID_MT2_BAD_RANGE,        /* X or Y logical range empty */
    HID_MT2_BAD_SIZE,         /* a side outside 30 .. 163.8 mm */
};

enum hid_mt2_track_state { HID_MT2_FREE = 0, HID_MT2_DOWN, HID_MT2_BREAKING, HID_MT2_BROKEN };

struct hid_mt2_track {
    uint8_t state, mt_id, finger, palm, fresh, seen;
    uint32_t ptp_id;
    int32_t x, y;             /* last position, logical counts */
    int16_t x13, y13;         /* last position, frame units */
};

struct hid_mt2_stats {
    uint32_t frames, tick_frames, empty_frames, contacts, touches, palms, lifts, vanished, jumps;
    uint32_t dropped, duplicate_ids, max_contacts, time_fallbacks, resets;
};

struct hid_mt2 {
    int32_t lx_min, lx_max, ly_min, ly_max;   /* PTP logical ranges */
    uint32_t width_um, height_um;
    int32_t wq, hq;                           /* half-extents in frame units (0.02 mm) */
    struct hid_mt2_track t[HID_MT2_MAX_TRACKS];
    uint8_t next_id;                          /* round robin over 1..15 */
    uint8_t button, idle_pending, have_time, have_scan;
    uint32_t last_scan;
    uint64_t dev_us, frame_us, last_host_us, last_ms;   /* device clock: now, at the last report */
    struct hid_mt2_stats stats;
};

int hid_mt2_init(struct hid_mt2 *m, const struct hid_ptp_layout *l);
const char *hid_mt2_init_name(int result);

/* The report descriptor: a mouse collection with input report 2 (8 bytes) and a Touch Pad
 * collection with a 256-byte vendor input report (never sent). */
const uint8_t *hid_mt2_report_descriptor(uint32_t *len);

/* A feature report's bytes, its ID first. Returns the length, 0 for a report the device does not
 * have or a buffer too small. Report 1 is the indirect query: set it to [1, id], then get it for
 * [1, id, 0, payload length (u16)]. */
uint32_t hid_mt2_feature(const struct hid_mt2 *m, uint8_t id, uint8_t query, uint8_t *buf, uint32_t cap);

/* One decoded Precision Touchpad frame (hid-ptp.c's contacts after the hybrid merge) to one input
 * report 2. buttons: the PTP buttons (any = pressed). scan: Scan Time (100 us units) when has_scan.
 * Returns the report length (<= HID_MT2_MAX_REPORT), 0 if cap is too small. */
uint32_t hid_mt2_frame(struct hid_mt2 *m, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons,
                       uint32_t scan, int has_scan, uint64_t now_us, uint8_t *out, uint32_t cap);
/* The bus tick: a trailing frame when lifted contacts still need their last stages, or the empty
 * frame after a touch ended, and the device sent nothing for HID_MT2_TICK_US. 0 = nothing to send. */
uint32_t hid_mt2_tick(struct hid_mt2 *m, uint64_t now_us, uint8_t *out, uint32_t cap);
/* An empty frame (no contacts), to make the driver build its multitouch device before a touch. */
uint32_t hid_mt2_empty(struct hid_mt2 *m, uint64_t now_us, uint8_t *out, uint32_t cap);
/* End every touch (the PTP switch was re-applied): the next ticks send them lifted. */
void hid_mt2_reset(struct hid_mt2 *m);
int hid_mt2_busy(const struct hid_mt2 *m);

#ifdef __cplusplus
}
#endif

#endif
