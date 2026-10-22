/* SPDX-License-Identifier: MIT */
/* Precision Touchpad frames as Apple multitouch frames; the contract and its sources are in hid-mt2.h. */
#include "hid-mt2.h"

#include <stddef.h>
#include <string.h>

/* Report 2 (8 bytes) in a mouse collection, so the interface has usage pair 1/2 and the driver's
 * 8-byte header is a declared report; report 0x3f (ID + 255 bytes) in a Touch Pad collection, so
 * MaxInputReportSize covers the longest frame (HID_MT2_MAX_REPORT). Our own bytes. */
static const uint8_t kDescriptor[] = {
    0x05, 0x01,                   /* Usage Page (Generic Desktop) */
    0x09, 0x02,                   /* Usage (Mouse) */
    0xa1, 0x01,                   /* Collection (Application) */
    0x09, 0x01,                   /*   Usage (Pointer) */
    0xa1, 0x00,                   /*   Collection (Physical) */
    0x85, HID_MT2_REPORT_ID,      /*     Report ID (2) */
    0x05, 0x09,                   /*     Usage Page (Button) */
    0x19, 0x01, 0x29, 0x03,       /*     Usage Minimum (1), Maximum (3) */
    0x15, 0x00, 0x25, 0x01,       /*     Logical Minimum (0), Maximum (1) */
    0x95, 0x03, 0x75, 0x01,       /*     Report Count (3), Size (1) */
    0x81, 0x02,                   /*     Input (Data, Variable, Absolute) */
    0x95, 0x01, 0x75, 0x05,       /*     Report Count (1), Size (5) */
    0x81, 0x01,                   /*     Input (Constant) */
    0x05, 0x01,                   /*     Usage Page (Generic Desktop) */
    0x09, 0x30, 0x09, 0x31,       /*     Usage (X), Usage (Y) */
    0x15, 0x81, 0x25, 0x7f,       /*     Logical Minimum (-127), Maximum (127) */
    0x75, 0x08, 0x95, 0x02,       /*     Report Size (8), Count (2) */
    0x81, 0x06,                   /*     Input (Data, Variable, Relative) */
    0x95, 0x04, 0x75, 0x08,       /*     Report Count (4), Size (8) */
    0x81, 0x01,                   /*     Input (Constant) */
    0xc0,                         /*   End Collection */
    0xc0,                         /* End Collection */
    0x05, 0x0d,                   /* Usage Page (Digitizer) */
    0x09, 0x05,                   /* Usage (Touch Pad) */
    0xa1, 0x01,                   /* Collection (Application) */
    0x85, HID_MT2_VENDOR_REPORT,  /*   Report ID (0x3f) */
    0x06, 0x00, 0xff,             /*   Usage Page (Vendor 0xff00) */
    0x09, 0x0c,                   /*   Usage (0x0c) */
    0x15, 0x00, 0x26, 0xff, 0x00, /*   Logical Minimum (0), Maximum (255) */
    0x75, 0x08, 0x96, 0xff, 0x00, /*   Report Size (8), Count (255) */
    0x81, 0x02,                   /*   Input (Data, Variable, Absolute) */
    0xc0,                         /* End Collection */
};

/* The sensor description AMD and MultitouchSupport cache for a family 0x81 sensor: the region
 * descriptor (two regions) equals the one this 26A428 host's own trackpad publishes; the region
 * parameters are those a family 0x81 sensor reports. They describe image frames, which this
 * device never sends; the path frames use the surface descriptor (D9) only. */
static const uint8_t kRegions[15] = {0x02, 0x01, 0x00, 0x14, 0x01, 0x00, 0x1e, 0x00,
                                     0x02, 0x14, 0x02, 0x01, 0x0e, 0x02, 0x00};
static const uint8_t kRegionParam[6] = {0x00, 0x00, 0x05, 0x00, 0xfc, 0x01};

/* Order of the 0xDB entries: the six reports AMD fetches. */
static const uint8_t kInitReports[6] = {0xd1, 0xd3, 0xd0, 0xa1, 0xd9, 0x7f};

const uint8_t *hid_mt2_report_descriptor(uint32_t *len)
{
    if (len)
        *len = (uint32_t)sizeof(kDescriptor);
    return kDescriptor;
}

const char *hid_mt2_init_name(int r)
{
    switch (r) {
    case HID_MT2_OK: return "ok";
    case HID_MT2_NO_LAYOUT: return "no touchpad layout";
    case HID_MT2_BAD_RANGE: return "empty logical range";
    case HID_MT2_BAD_SIZE: return "pad size outside 30..163.8 mm";
    default: return "?";
    }
}

int hid_mt2_init(struct hid_mt2 *m, const struct hid_ptp_layout *l)
{
    uint32_t w, h;
    memset(m, 0, sizeof(*m));
    if (!l || !l->fingers)
        return HID_MT2_NO_LAYOUT;
    if (l->x_max <= l->x_min || l->y_max <= l->y_min)
        return HID_MT2_BAD_RANGE;
    w = l->width_um / 10u;
    h = l->height_um / 10u;
    if (w < HID_MT2_MIN_SIDE_HMM || w > HID_MT2_MAX_SIDE_HMM || h < HID_MT2_MIN_SIDE_HMM ||
        h > HID_MT2_MAX_SIDE_HMM)
        return HID_MT2_BAD_SIZE;
    m->lx_min = l->x_min;
    m->lx_max = l->x_max;
    m->ly_min = l->y_min;
    m->ly_max = l->y_max;
    m->width_um = l->width_um;
    m->height_um = l->height_um;
    m->wq = (int32_t)(w / 4u);              /* X spans -wq..wq in 0.02 mm: 13 bits hold 4095 */
    m->hq = (int32_t)(h / 4u);
    m->next_id = 1;
    return HID_MT2_OK;
}

static void put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, v);
    put16(p + 2, v >> 16);
}

/* A report's payload (after its ID byte): the layouts AMD's decodeDeviceProperty reads. */
static uint32_t payload(const struct hid_mt2 *m, uint8_t id, uint8_t *p)
{
    switch (id) {
    case 0xd1:                                   /* Family ID */
        p[0] = HID_MT2_FAMILY;
        return 1;
    case 0xd3:                                   /* endianness, rows, columns, bcd (big endian), max packet */
        memset(p, 0, 12);
        p[0] = 1;                                /* little endian: no swaps in the parsers */
        p[1] = HID_MT2_ROWS;
        p[2] = HID_MT2_COLUMNS;
        p[3] = (uint8_t)(HID_MT2_BCD >> 8);
        p[4] = (uint8_t)HID_MT2_BCD;
        put32(p + 8, HID_MT2_MAX_PACKET);
        return 12;
    case 0xd0:                                   /* Sensor Region Descriptor */
        memcpy(p, kRegions, sizeof(kRegions));
        return (uint32_t)sizeof(kRegions);
    case 0xa1:                                   /* Sensor Region Param */
        memcpy(p, kRegionParam, sizeof(kRegionParam));
        return (uint32_t)sizeof(kRegionParam);
    case 0xd9:                                   /* width, height (0.01 mm), xmin, ymin, xmax, ymax */
        put32(p, (uint32_t)(4 * m->wq));
        put32(p + 4, (uint32_t)(4 * m->hq));
        put16(p + 8, (uint32_t)(uint16_t)(int16_t)(-2 * m->wq));
        put16(p + 10, (uint32_t)(uint16_t)(int16_t)(HID_MT2_Y_CENTRE - 2 * m->hq));
        put16(p + 12, (uint32_t)(uint16_t)(int16_t)(2 * m->wq));
        put16(p + 14, (uint32_t)(uint16_t)(int16_t)(HID_MT2_Y_CENTRE + 2 * m->hq));
        return 16;
    case 0x7f:                                   /* Multitouch Status: no critical error */
        memset(p, 0, 4);
        return 4;
    default:
        return 0;
    }
}

uint32_t hid_mt2_feature(const struct hid_mt2 *m, uint8_t id, uint8_t query, uint8_t *buf, uint32_t cap)
{
    uint8_t p[HID_MT2_MAX_FEATURE];
    uint32_t n, at;
    if (!m || !buf || !m->wq)
        return 0;
    if (id == 0x01) {                            /* indirect query: [1, id, 0, payload length] */
        if (query == 0xdb) {
            n = hid_mt2_feature(m, 0xdb, 0, p, sizeof(p));
            n = n ? n - 1u : 0u;
        } else {
            n = query == 0x01 ? 0u : payload(m, query, p);
        }
        if (cap < 5u || !n)
            return 0;
        buf[0] = 0x01;
        buf[1] = query;
        buf[2] = 0;
        put16(buf + 3, n);
        return 5;
    }
    if (id == 0xdb) {                            /* version 1, then [u16 length][ID][payload] */
        if (cap < HID_MT2_MAX_FEATURE)
            return 0;
        buf[0] = 0xdb;
        buf[1] = 0x01;
        at = 2;
        for (uint32_t i = 0; i < sizeof(kInitReports); i++) {
            n = payload(m, kInitReports[i], p);
            put16(buf + at, n + 1u);
            buf[at + 2] = kInitReports[i];
            memcpy(buf + at + 3, p, n);
            at += 3u + n;
        }
        return at;
    }
    n = payload(m, id, p);
    if (!n || cap < n + 1u)
        return 0;
    buf[0] = id;
    memcpy(buf + 1, p, n);
    return n + 1u;
}

/* ----------------------------------------------------------------------------- frames ---- */

static int16_t to_x13(const struct hid_mt2 *m, int32_t x)
{
    int64_t r = (int64_t)m->lx_max - m->lx_min;
    if (x < m->lx_min)
        x = m->lx_min;
    if (x > m->lx_max)
        x = m->lx_max;
    return (int16_t)((((int64_t)x - m->lx_min) * (2 * m->wq) + r / 2) / r - m->wq);
}

/* The touchpad's Y grows downwards; the frame's grows upwards. */
static int16_t to_y13(const struct hid_mt2 *m, int32_t y)
{
    int64_t r = (int64_t)m->ly_max - m->ly_min;
    if (y < m->ly_min)
        y = m->ly_min;
    if (y > m->ly_max)
        y = m->ly_max;
    return (int16_t)(m->hq - (((int64_t)y - m->ly_min) * (2 * m->hq) + r / 2) / r);
}

static uint32_t travel_um(const struct hid_mt2 *m, const struct hid_mt2_track *t, int32_t x, int32_t y)
{
    int64_t dx = (int64_t)x - t->x, dy = (int64_t)y - t->y;
    uint64_t ux, uy;
    if (dx < 0)
        dx = -dx;
    if (dy < 0)
        dy = -dy;
    ux = (uint64_t)dx * m->width_um / (uint64_t)((int64_t)m->lx_max - m->lx_min);
    uy = (uint64_t)dy * m->height_um / (uint64_t)((int64_t)m->ly_max - m->ly_min);
    ux = ux > uy ? ux : uy;
    return ux > 0xffffffffu ? 0xffffffffu : (uint32_t)ux;
}

/* M11: every frame at least 1 ms after the previous one, on the device's clock when it has one.
 * device: a touchpad report (scan time valid if has_scan): its time is the previous report's plus
 * the Scan Time delta (0.1..100 ms), else the host's delta clamped to 1..100 ms; a tick (device 0)
 * advances by the host's delta. Returns the frame's 21-bit millisecond field. */
static uint32_t stamp(struct hid_mt2 *m, int device, uint32_t scan, int has_scan, uint64_t now)
{
    uint64_t host = now > m->last_host_us ? now - m->last_host_us : 0, t, ms;
    uint64_t host_dt = host < 1000u ? 1000u : host > 100000u ? 100000u : host;
    uint32_t d = (scan - m->last_scan) & 0xffffu;
    if (!m->have_time) {
        m->have_time = 1;
        t = 1000000u;
    } else if (device && has_scan && m->have_scan && d >= 1u && d <= 1000u) {
        t = m->frame_us + (uint64_t)d * 100u;
    } else {
        if (device && has_scan && m->have_scan)
            m->stats.time_fallbacks++;
        t = m->dev_us + host_dt;
    }
    if (t < m->dev_us + 1000u)
        t = m->dev_us + 1000u;                       /* a tick may have gone out since the last report */
    ms = t / 1000u;
    if (m->last_ms && ms <= m->last_ms) {
        ms = m->last_ms + 1u;
        t = ms * 1000u;
    }
    m->dev_us = t;
    m->last_ms = ms;
    m->last_host_us = now;
    if (device) {
        m->frame_us = t;
        m->last_scan = scan;
        m->have_scan = (uint8_t)(has_scan != 0);
    }
    return (uint32_t)(ms & 0x1fffffu);
}

static void header(const struct hid_mt2 *m, uint8_t *out, uint32_t ts, int active)
{
    memset(out, 0, HID_MT2_HEADER_BYTES);
    out[0] = HID_MT2_REPORT_ID;
    /* M2: no motion and no buttons in the mouse header; bit 1 of byte 7 tells the driver to ignore
     * it (tracking), bit 0 says touching. */
    out[7] = (uint8_t)(active ? 0x03u : 0x02u);
    out[8] = HID_MT2_FRAME_ID;
    out[9] = (uint8_t)(((ts & 0x1fu) << 3) | (HID_MT2_HOST_CLICK ? HID_MT2_FLAG_HOST_CLICK : 0u) |
                       (m->button ? HID_MT2_FLAG_BUTTON : 0u));
    out[10] = (uint8_t)(ts >> 5);
    out[11] = (uint8_t)(ts >> 13);
}

static void contact(uint8_t *p, const struct hid_mt2_track *t, uint32_t stage)
{
    uint32_t x = (uint32_t)(uint16_t)t->x13 & 0x1fffu, y = (uint32_t)(uint16_t)t->y13 & 0x1fffu;
    int down = stage <= HID_MT2_STAGE_TOUCH;
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(((x >> 8) & 0x1fu) | ((y & 7u) << 5));
    p[2] = (uint8_t)(y >> 3);
    p[3] = (uint8_t)(((y >> 11) & 3u) | ((t->finger & 7u) << 2) | ((stage & 7u) << 5));
    p[4] = (uint8_t)(down ? HID_MT2_CODE_MAJOR : 0u);
    p[5] = (uint8_t)(down ? HID_MT2_CODE_MINOR : 0u);
    p[6] = (uint8_t)(down ? HID_MT2_CODE_SIZE : 0u);
    p[7] = (uint8_t)(down ? HID_MT2_CODE_PRESSURE : 0u);
    p[8] = (uint8_t)((t->mt_id & 0xfu) | (HID_MT2_CODE_ANGLE << 5));
}

/* The stage each live track reports now, and its next state. device: a touchpad frame (tracks not
 * seen in it lifted); a tick reports the down ones unchanged. Returns the report length. */
static uint32_t emit(struct hid_mt2 *m, uint8_t *out, uint32_t ts, int device)
{
    uint32_t k = 0, down = 0;
    uint8_t *p = out + HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER;
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++) {
        struct hid_mt2_track *t = &m->t[i];
        uint32_t stage;
        switch (t->state) {
        case HID_MT2_DOWN:
            if (!device || t->seen == 1) {
                stage = t->fresh ? HID_MT2_STAGE_MAKE : HID_MT2_STAGE_TOUCH;
                t->fresh = 0;
                down++;
            } else {
                stage = HID_MT2_STAGE_BREAK;     /* lifted (tip 0), vanished or jumped */
                if (t->seen == 0)
                    m->stats.vanished++;
                else
                    m->stats.lifts++;
                t->state = HID_MT2_BROKEN;
            }
            break;
        case HID_MT2_BREAKING:
            stage = HID_MT2_STAGE_BREAK;
            t->state = HID_MT2_BROKEN;
            break;
        case HID_MT2_BROKEN:
            stage = HID_MT2_STAGE_OUT;
            t->state = HID_MT2_FREE;
            break;
        default:
            continue;
        }
        contact(p + k * HID_MT2_CONTACT_BYTES, t, stage);
        k++;
    }
    header(m, out, ts, down || m->button);
    if (k > m->stats.max_contacts)
        m->stats.max_contacts = k;
    m->stats.contacts += k;
    /* After the frame in which the last tracks went out, one empty frame (the tick sends it). */
    m->idle_pending = 0;
    if (k && !hid_mt2_busy(m))
        m->idle_pending = 1;
    return HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER + k * HID_MT2_CONTACT_BYTES;
}

static struct hid_mt2_track *live(struct hid_mt2 *m, uint32_t ptp_id)
{
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        if (m->t[i].state == HID_MT2_DOWN && m->t[i].ptp_id == ptp_id)
            return &m->t[i];
    return NULL;
}

static int id_used(const struct hid_mt2 *m, uint8_t id)
{
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        if (m->t[i].state != HID_MT2_FREE && m->t[i].mt_id == id)
            return 1;
    return 0;
}

/* M9: a fresh MT ID per touch, round robin over 1..15, never one a live track holds. */
static uint8_t new_id(struct hid_mt2 *m)
{
    for (uint32_t n = 0; n < HID_MT2_LIVE_IDS; n++) {
        uint8_t id = m->next_id;
        m->next_id = (uint8_t)(m->next_id % HID_MT2_LIVE_IDS + 1u);
        if (!id_used(m, id))
            return id;
    }
    return 0;
}

/* Index, middle, ring, little, then thumb: the first one no other finger down has. */
static uint8_t new_finger(const struct hid_mt2 *m)
{
    static const uint8_t order[5] = {2, 3, 4, 5, 1};
    for (uint32_t o = 0; o < 5; o++) {
        int taken = 0;
        for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
            if (m->t[i].state == HID_MT2_DOWN && !m->t[i].palm && m->t[i].finger == order[o])
                taken = 1;
        if (!taken)
            return order[o];
    }
    return HID_MT2_FINGER_INDEX;
}

uint32_t hid_mt2_frame(struct hid_mt2 *m, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons,
                       uint32_t scan, int has_scan, uint64_t now_us, uint8_t *out, uint32_t cap)
{
    uint32_t ts;
    if (!m || !m->wq || !out || cap < HID_MT2_MAX_REPORT)
        return 0;
    ts = stamp(m, 1, scan, has_scan, now_us);
    m->button = (uint8_t)(buttons != 0);
    m->stats.frames++;
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        m->t[i].seen = 0;
    for (uint32_t i = 0; c && i < n; i++) {
        struct hid_mt2_track *t = live(m, c[i].id);
        if (t && t->seen) {
            m->stats.duplicate_ids++;                /* the first slot with an ID wins */
            continue;
        }
        if (!c[i].tip) {
            if (t) {
                t->seen = 2;                         /* lifting: the frame reports it once more, broken */
                t->x = c[i].x;
                t->y = c[i].y;
                t->x13 = to_x13(m, c[i].x);
                t->y13 = to_y13(m, c[i].y);
            }
            continue;
        }
        if (t && travel_um(m, t, c[i].x, c[i].y) > HID_MT2_JUMP_UM) {
            t->seen = 3;                             /* M9: a new touch under an old ID */
            m->stats.jumps++;
            t = NULL;
        }
        if (t) {
            t->seen = 1;
            t->x = c[i].x;
            t->y = c[i].y;
            t->x13 = to_x13(m, c[i].x);
            t->y13 = to_y13(m, c[i].y);
            if (!c[i].confident && !t->palm) {       /* M10: a palm for the rest of its life */
                t->palm = 1;
                t->finger = HID_MT2_FINGER_PALM;
                m->stats.palms++;
            }
            continue;
        }
        for (uint32_t j = 0; j < HID_MT2_MAX_TRACKS && !t; j++)
            if (m->t[j].state == HID_MT2_FREE)
                t = &m->t[j];
        if (!t) {
            m->stats.dropped++;                      /* M13 */
            continue;
        }
        memset(t, 0, sizeof(*t));
        t->mt_id = new_id(m);
        if (!t->mt_id) {
            m->stats.dropped++;
            continue;                                /* still FREE */
        }
        t->palm = (uint8_t)!c[i].confident;
        t->finger = t->palm ? (uint8_t)HID_MT2_FINGER_PALM : new_finger(m);
        t->state = HID_MT2_DOWN;
        t->fresh = 1;
        t->seen = 1;
        t->ptp_id = c[i].id;
        t->x = c[i].x;
        t->y = c[i].y;
        t->x13 = to_x13(m, c[i].x);
        t->y13 = to_y13(m, c[i].y);
        m->stats.touches++;
        if (t->palm)
            m->stats.palms++;
    }
    return emit(m, out, ts, 1);
}

int hid_mt2_busy(const struct hid_mt2 *m)
{
    if (!m)
        return 0;
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        if (m->t[i].state != HID_MT2_FREE)
            return 1;
    return m->idle_pending;
}

uint32_t hid_mt2_tick(struct hid_mt2 *m, uint64_t now_us, uint8_t *out, uint32_t cap)
{
    int lifting = 0;
    uint32_t ts, len;
    if (!m || !m->wq || !out || cap < HID_MT2_MAX_REPORT || !m->have_time)
        return 0;
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        if (m->t[i].state == HID_MT2_BREAKING || m->t[i].state == HID_MT2_BROKEN)
            lifting = 1;
    if (!lifting && !m->idle_pending)
        return 0;
    if (now_us >= m->last_host_us && now_us - m->last_host_us < HID_MT2_TICK_US)
        return 0;                                    /* a frame went out recently: wait for the device */
    ts = stamp(m, 0, 0, 0, now_us);
    if (!lifting) {                                  /* the empty frame after the last touch */
        m->idle_pending = 0;
        m->stats.empty_frames++;
        m->stats.tick_frames++;
        header(m, out, ts, m->button);
        return HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER;
    }
    len = emit(m, out, ts, 0);
    m->stats.tick_frames++;
    return len;
}

uint32_t hid_mt2_empty(struct hid_mt2 *m, uint64_t now_us, uint8_t *out, uint32_t cap)
{
    uint32_t ts;
    if (!m || !m->wq || !out || cap < HID_MT2_MAX_REPORT || hid_mt2_busy(m))
        return 0;
    ts = stamp(m, 0, 0, 0, now_us);
    m->stats.empty_frames++;
    header(m, out, ts, 0);
    return HID_MT2_HEADER_BYTES + HID_MT2_FRAME_HEADER;
}

void hid_mt2_reset(struct hid_mt2 *m)
{
    if (!m)
        return;
    m->stats.resets++;
    m->button = 0;
    for (uint32_t i = 0; i < HID_MT2_MAX_TRACKS; i++)
        if (m->t[i].state == HID_MT2_DOWN)
            m->t[i].state = HID_MT2_BREAKING;
}
