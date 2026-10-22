/* SPDX-License-Identifier: MIT */
/* Precision Touchpad layout, mode switch and gesture engine; the contract is in hid-ptp.h. */
#include "hid-ptp.h"

#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------------------ layout ---- */

#define MAX_USAGES   32u
#define MAX_DEPTH    16u
#define MAX_STACK    8u
#define MAX_IDS      256u
#define MAX_INPUT_BITS   (512u * 8u)      /* I2C_HID_MAX_INPUT */
#define MAX_FEATURE_BITS (1024u * 8u)

#define U_TOUCHPAD   0x000d0005u
#define U_CONFIG     0x000d000eu
#define U_FINGER     0x000d0022u
#define U_TIP        0x000d0042u
#define U_CONFIDENCE 0x000d0047u
#define U_INPUT_MODE 0x000d0052u
#define U_CONTACT_ID 0x000d0051u
#define U_COUNT      0x000d0054u
#define U_COUNT_MAX  0x000d0055u
#define U_SCAN_TIME  0x000d0056u
#define U_SURFACE    0x000d0057u
#define U_BUTTON_SW  0x000d0058u
#define U_PAD_TYPE   0x000d0059u
#define U_X          0x00010030u
#define U_Y          0x00010031u
#define U_BLOB       0xff0000c5u

struct globals {
    uint32_t page, unit, size, count, id;
    int32_t lmin, lmax, pmin, pmax, uexp;
    uint32_t lmax_raw;
    uint8_t lmax_bytes;
};

struct axis_units { int32_t pmin, pmax, uexp; uint32_t unit; uint8_t have; };

/* About 1.1 KiB on the caller's stack (re-entrant: two buses publish on their own threads). */
struct parse {
    uint16_t in_bits[MAX_IDS];    /* bits so far per report ID (MAX_*_BITS fit) */
    uint16_t feat_bits[MAX_IDS];
    uint32_t fingers_seen;        /* finger collections, including any beyond the table */
    uint8_t finger_bad[HID_PTP_MAX_FINGERS];
    uint8_t input_id_set, touchpad_seen, oversize;
    struct axis_units ux, uy;     /* finger 0's X and Y */
};

static uint32_t uvalue(const uint8_t *p, uint32_t n)
{
    uint32_t v = 0;
    for (uint32_t i = 0; i < n; i++)
        v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static int32_t svalue(const uint8_t *p, uint32_t n)
{
    uint32_t v = uvalue(p, n);
    if (n == 1)
        return (int8_t)v;
    if (n == 2)
        return (int16_t)v;
    return (int32_t)v;
}

static void set_field(struct hid_ptp_field *f, uint32_t offset, const struct globals *g)
{
    f->offset = (uint16_t)offset;
    f->size = (uint8_t)g->size;
    f->min = g->lmin;
    /* A logical maximum below the minimum was meant unsigned (a common descriptor slip). */
    f->max = g->lmax < g->lmin && g->lmax_bytes < 4 ? (int32_t)g->lmax_raw : g->lmax;
    f->is_signed = g->lmin < 0;
}

static void set_feature(struct hid_ptp_feature *f, uint32_t id, uint32_t offset, const struct globals *g)
{
    if (f->report_id)
        return;                   /* the first one counts (Linux: a second Input Mode is skipped) */
    f->report_id = (uint8_t)id;
    set_field(&f->field, offset, g);
}

static int extent_um(const struct axis_units *u, uint32_t *um)
{
    int64_t span = (int64_t)u->pmax - u->pmin;
    uint64_t v, base;
    int32_t e = u->uexp;
    if (!u->have || span <= 0 || (u->unit >> 8) || ((u->unit >> 4) & 0xfu) != 1u)
        return 0;
    if ((u->unit & 0xfu) == 1u)
        base = 10000u;            /* SI linear: centimetres */
    else if ((u->unit & 0xfu) == 3u)
        base = 25400u;            /* English linear: inches */
    else
        return 0;
    v = (uint64_t)span * base;
    for (; e > 0; e--) {
        v *= 10u;
        if (v > 100000000000ull)
            return 0;
    }
    for (; e < 0; e++)
        v /= 10u;
    if (v < 10000u || v > 1000000u)   /* 10 mm .. 1 m */
        return 0;
    *um = (uint32_t)v;
    return 1;
}

int hid_ptp_layout(const uint8_t *d, uint32_t len, struct hid_ptp_layout *out)
{
    struct parse pp, *p = &pp;
    struct globals g, stack[MAX_STACK];
    uint32_t usages[MAX_USAGES], nusages = 0, umin = 0, umax = 0, have_range = 0;
    uint32_t depth = 0, sp = 0;
    uint32_t touchpad_depth = 0, finger_depth = 0, finger = 0;
    struct hid_ptp_layout *l = out;          /* filled in place; only HID_PTP_OK makes it valid */
    int unsupported = 0;

    if (!d || !out)
        return HID_PTP_MALFORMED;
    memset(p, 0, sizeof(*p));
    memset(l, 0, sizeof(*l));
    memset(&g, 0, sizeof(g));
    for (uint32_t at = 0; at < len;) {
        uint8_t prefix = d[at];
        uint32_t size = prefix & 3u, type = (prefix >> 2) & 3u, tag = prefix >> 4, u;
        const uint8_t *data;
        if (prefix == 0xfe) {                                /* long item: skipped */
            if (len - at < 3u || len - at - 3u < d[at + 1])
                return HID_PTP_MALFORMED;
            at += 3u + d[at + 1];
            continue;
        }
        if (size == 3u)
            size = 4u;
        if (len - at < 1u + size)
            return HID_PTP_MALFORMED;
        data = d + at + 1;
        u = uvalue(data, size);
        at += 1u + size;
        if (type == 1u) {                                    /* global */
            switch (tag) {
            case 0x0: g.page = u; break;
            case 0x1: g.lmin = svalue(data, size); break;
            case 0x2: g.lmax = svalue(data, size); g.lmax_raw = u; g.lmax_bytes = (uint8_t)size; break;
            case 0x3: g.pmin = svalue(data, size); break;
            case 0x4: g.pmax = svalue(data, size); break;
            case 0x5:                                        /* 4-bit two's complement in one byte */
                g.uexp = size == 1u && u <= 0xfu ? (u > 7u ? (int32_t)u - 16 : (int32_t)u) : svalue(data, size);
                break;
            case 0x6: g.unit = u; break;
            case 0x7: g.size = u; break;
            case 0x8:
                if (size != 1u || !u)
                    return HID_PTP_MALFORMED;
                g.id = u;
                break;
            case 0x9: g.count = u; break;
            case 0xa:
                if (sp == MAX_STACK)
                    return HID_PTP_MALFORMED;
                stack[sp++] = g;
                break;
            case 0xb:
                if (!sp)
                    return HID_PTP_MALFORMED;
                g = stack[--sp];
                break;
            default: break;
            }
            continue;
        }
        if (type == 2u) {                                    /* local */
            uint32_t usage = size == 4u ? u : (g.page << 16) | u;
            if (tag == 0x0 && nusages < MAX_USAGES)
                usages[nusages++] = usage;
            else if (tag == 0x1) { umin = usage; have_range |= 1u; }
            else if (tag == 0x2) { umax = usage; have_range |= 2u; }
            continue;
        }
        if (type != 0u)
            return HID_PTP_MALFORMED;
        /* main */
        if (tag == 0xa) {                                    /* Collection */
            uint32_t first = nusages ? usages[0] : (have_range & 1u) ? umin : 0u;
            if (depth == MAX_DEPTH)
                return HID_PTP_MALFORMED;
            depth++;
            if (u == 1u && first == U_TOUCHPAD && !touchpad_depth && !p->touchpad_seen) {
                touchpad_depth = depth;
                p->touchpad_seen = 1;
            } else if (touchpad_depth && !finger_depth && first == U_FINGER && u != 1u) {
                finger_depth = depth;
                finger = p->fingers_seen++;
            }
        } else if (tag == 0xc) {                             /* End Collection */
            if (!depth)
                return HID_PTP_MALFORMED;
            if (finger_depth == depth)
                finger_depth = 0;
            if (touchpad_depth == depth)
                touchpad_depth = 0;
            depth--;
        } else if (tag == 0x8 || tag == 0xb || tag == 0x9) { /* Input, Feature, Output */
            uint32_t id = g.id, total = g.size * g.count;
            uint16_t *bits = tag == 0x8 ? p->in_bits : tag == 0xb ? p->feat_bits : NULL;
            uint32_t limit = tag == 0x8 ? MAX_INPUT_BITS : MAX_FEATURE_BITS;
            if (!depth || !g.size || g.size > 4096u || g.count > 4096u || id >= MAX_IDS)
                return HID_PTP_MALFORMED;
            if (bits && (uint32_t)bits[id] + total > limit)
                return HID_PTP_MALFORMED;
            if (bits && !(u & 1u) && (u & 2u)) {             /* data, variable */
                for (uint32_t i = 0; i < g.count; i++) {
                    uint32_t usage = i < nusages ? usages[i]
                                   : (have_range == 3u && umin + i <= umax) ? umin + i
                                   : nusages ? usages[nusages - 1] : 0u;
                    uint32_t off = bits[id] + i * g.size;
                    int wanted = 0;
                    if (tag == 0x8 && touchpad_depth) {
                        if (!p->input_id_set) {
                            l->report_id = (uint8_t)id;
                            p->input_id_set = 1;
                        }
                        if (id != l->report_id)
                            continue;                        /* not the multi-contact report */
                        if (finger_depth && finger < HID_PTP_MAX_FINGERS) {
                            struct hid_ptp_finger *f = &l->finger[finger];
                            struct hid_ptp_field *slot = usage == U_TIP ? &f->tip
                                                       : usage == U_CONFIDENCE ? &f->confidence
                                                       : usage == U_CONTACT_ID ? &f->id
                                                       : usage == U_X ? &f->x : usage == U_Y ? &f->y : NULL;
                            if (slot && !slot->size) {
                                wanted = 1;
                                set_field(slot, off, &g);
                                if ((usage == U_X || usage == U_Y) && (u & 4u))
                                    p->finger_bad[finger] = 1;   /* relative: not a touchpad contact */
                                if (finger == 0 && (usage == U_X || usage == U_Y)) {
                                    struct axis_units *a = usage == U_X ? &p->ux : &p->uy;
                                    a->pmin = g.pmin;
                                    a->pmax = g.pmax;
                                    a->uexp = g.uexp;
                                    a->unit = g.unit;
                                    a->have = 1;
                                }
                            }
                        } else if (!finger_depth) {
                            if (usage == U_COUNT && !l->contact_count.size) {
                                wanted = 1;
                                set_field(&l->contact_count, off, &g);
                            } else if (usage == U_SCAN_TIME && !l->scan_time.size) {
                                wanted = 1;
                                set_field(&l->scan_time, off, &g);
                            } else if ((usage >> 16) == 0x9u && (usage & 0xffffu) >= 1u &&
                                       (usage & 0xffffu) <= HID_PTP_MAX_BUTTONS) {
                                struct hid_ptp_field *b = &l->button[(usage & 0xffffu) - 1u];
                                if (!b->size) {
                                    wanted = 1;
                                    set_field(b, off, &g);
                                    if ((usage & 0xffffu) > l->buttons)
                                        l->buttons = (uint8_t)(usage & 0xffffu);
                                }
                            }
                        }
                    } else if (tag == 0xb) {
                        struct hid_ptp_feature *f = usage == U_INPUT_MODE ? &l->input_mode
                                                  : usage == U_SURFACE ? &l->surface_switch
                                                  : usage == U_BUTTON_SW ? &l->button_switch
                                                  : usage == U_COUNT_MAX ? &l->contact_max
                                                  : usage == U_PAD_TYPE ? &l->pad_type
                                                  : usage == U_BLOB && i == 0 ? &l->blob : NULL;
                        if (f && id) {
                            wanted = 1;
                            set_feature(f, id, off, &g);
                        }
                    }
                    if (wanted && g.size > 32u && usage != U_BLOB)
                        unsupported = 1;
                }
            }
            if (bits)
                bits[id] = (uint16_t)(bits[id] + total);
        }
        if (type == 0u) {                                    /* every main item clears the locals */
            nusages = 0;
            have_range = 0;
        }
    }
    if (depth || sp)
        return HID_PTP_MALFORMED;
    if (!p->touchpad_seen)
        return HID_PTP_NO_TOUCHPAD;
    if (p->fingers_seen > HID_PTP_MAX_FINGERS || unsupported || !l->report_id)
        return HID_PTP_UNSUPPORTED;
    l->fingers = (uint8_t)p->fingers_seen;
    if (!l->fingers)
        return HID_PTP_NO_FINGERS;
    l->has_confidence = 1;
    for (uint32_t i = 0; i < l->fingers; i++) {
        const struct hid_ptp_finger *f = &l->finger[i];
        if (p->finger_bad[i] || !f->tip.size || !f->x.size || !f->y.size || f->x.max <= f->x.min ||
            f->y.max <= f->y.min)
            return HID_PTP_NO_FINGERS;
        if (!f->confidence.size)
            l->has_confidence = 0;
    }
    if (!l->input_mode.report_id)
        return HID_PTP_NO_INPUT_MODE;
    if (!extent_um(&p->ux, &l->width_um) || !extent_um(&p->uy, &l->height_um))
        return HID_PTP_NO_UNITS;
    l->x_min = l->finger[0].x.min;
    l->x_max = l->finger[0].x.max;
    l->y_min = l->finger[0].y.min;
    l->y_max = l->finger[0].y.max;
    l->report_bytes = (uint16_t)((p->in_bits[l->report_id] + 7u) / 8u + 1u);
    {
        struct hid_ptp_feature *fs[6] = {&l->input_mode, &l->surface_switch, &l->button_switch,
                                         &l->contact_max, &l->pad_type, &l->blob};
        for (uint32_t i = 0; i < 6; i++)
            if (fs[i]->report_id)
                fs[i]->report_bytes = (uint16_t)((p->feat_bits[fs[i]->report_id] + 7u) / 8u + 1u);
    }
    if (l->input_mode.report_bytes < 2u)
        return HID_PTP_NO_INPUT_MODE;
    return HID_PTP_OK;
}

const char *hid_ptp_layout_name(int r)
{
    switch (r) {
    case HID_PTP_OK: return "ok";
    case HID_PTP_NO_TOUCHPAD: return "no touch pad collection";
    case HID_PTP_NO_FINGERS: return "no usable finger collection";
    case HID_PTP_NO_INPUT_MODE: return "no input mode feature";
    case HID_PTP_NO_UNITS: return "no physical units";
    case HID_PTP_UNSUPPORTED: return "unsupported layout";
    case HID_PTP_MALFORMED: return "malformed descriptor";
    default: return "unknown";
    }
}

uint32_t hid_ptp_get(const uint8_t *body, uint32_t bytes, const struct hid_ptp_field *f)
{
    uint32_t v = 0;
    for (uint32_t i = 0; f && i < f->size && i < 32u; i++) {
        uint32_t bit = f->offset + i;
        if (bit / 8u < bytes && (body[bit / 8u] >> (bit % 8u) & 1u))
            v |= 1u << i;
    }
    return v;
}

static int32_t sget(const uint8_t *body, uint32_t bytes, const struct hid_ptp_field *f)
{
    uint32_t v = hid_ptp_get(body, bytes, f);
    if (f->is_signed && f->size && f->size < 32u && (v >> (f->size - 1u)) & 1u)
        v |= ~0u << f->size;
    return (int32_t)v;
}

void hid_ptp_put(uint8_t *body, uint32_t bytes, const struct hid_ptp_field *f, uint32_t value)
{
    for (uint32_t i = 0; f && i < f->size && i < 32u; i++) {
        uint32_t bit = f->offset + i;
        if (bit / 8u >= bytes)
            break;
        if ((value >> i) & 1u)
            body[bit / 8u] = (uint8_t)(body[bit / 8u] | (1u << (bit % 8u)));
        else
            body[bit / 8u] = (uint8_t)(body[bit / 8u] & ~(1u << (bit % 8u)));
    }
}

/* ---------------------------------------------------------------------------- the switch ---- */

static int read_feature(const struct hid_ptp_io *io, const struct hid_ptp_feature *f, uint8_t *buf,
                        uint32_t cap, struct hid_ptp_setup *s)
{
    uint32_t got = 0;
    if (!f->report_id || f->report_bytes > cap)
        return 0;
    s->requests++;
    return !io->get_feature(io->ctx, f->report_id, buf, cap, &got) && got == f->report_bytes &&
           buf[0] == f->report_id;
}

int hid_ptp_enable(const struct hid_ptp_layout *l, const struct hid_ptp_io *io, uint8_t *scratch,
                   uint32_t cap, struct hid_ptp_setup *s)
{
    const struct hid_ptp_feature *m;
    uint32_t n;
    if (!s)
        return HID_PTP_ENABLE_INVALID;
    memset(s, 0, sizeof(*s));
    s->result = HID_PTP_ENABLE_INVALID;
    if (!l || !io || !io->get_feature || !io->set_feature || !scratch || !l->input_mode.report_id ||
        l->input_mode.report_bytes < 2u || l->input_mode.report_bytes > cap)
        return s->result;
    m = &l->input_mode;
    n = m->report_bytes;
    /* 1. The certification blob, once: some devices switch only after it was read. */
    if (read_feature(io, &l->blob, scratch, cap, s)) {
        s->blob_read = 1;
        s->blob_bytes = l->blob.report_bytes;
    }
    /* 2. Capabilities. */
    {
        const struct hid_ptp_feature *c = l->contact_max.report_id ? &l->contact_max : &l->pad_type;
        if (read_feature(io, c, scratch, cap, s)) {
            s->caps_read = 1;
            if (l->contact_max.report_id == c->report_id)
                s->max_contacts = (uint8_t)hid_ptp_get(scratch + 1, c->report_bytes - 1u, &l->contact_max.field);
            if (l->pad_type.report_id == c->report_id)
                s->pad_type = (uint8_t)hid_ptp_get(scratch + 1, c->report_bytes - 1u, &l->pad_type.field);
        }
    }
    /* 3. Input Mode = touchpad, on the report as read (other fields kept) or on zeros. */
    if (read_feature(io, m, scratch, cap, s)) {
        s->mode_before = (uint8_t)hid_ptp_get(scratch + 1, n - 1u, &m->field);
        s->mode_before_read = 1;
    } else {
        memset(scratch, 0, n);
        scratch[0] = m->report_id;
    }
    hid_ptp_put(scratch + 1, n - 1u, &m->field, HID_PTP_MODE_TOUCHPAD);
    s->requests++;
    if (io->set_feature(io->ctx, scratch, n))
        return s->result = HID_PTP_REFUSED_WRITE;
    /* 4. Surface and Button Switch on (their own report, or two). */
    {
        const struct hid_ptp_feature *sw[2] = {&l->surface_switch, &l->button_switch};
        for (uint32_t i = 0; i < 2; i++) {
            uint32_t bytes = sw[i]->report_bytes;
            if (!sw[i]->report_id || bytes < 2u || bytes > cap || (i && sw[1]->report_id == sw[0]->report_id))
                continue;
            memset(scratch, 0, bytes);
            scratch[0] = sw[i]->report_id;
            for (uint32_t j = 0; j < 2; j++)
                if (sw[j]->report_id == sw[i]->report_id)
                    hid_ptp_put(scratch + 1, bytes - 1u, &sw[j]->field, 1u);
            s->requests++;
            if (!io->set_feature(io->ctx, scratch, bytes))
                s->selective_written = 1;
        }
    }
    /* 5. Read Input Mode back. */
    if (read_feature(io, m, scratch, cap, s)) {
        s->mode_after = (uint8_t)hid_ptp_get(scratch + 1, n - 1u, &m->field);
        s->mode_after_read = 1;
        return s->result = s->mode_after == HID_PTP_MODE_TOUCHPAD ? HID_PTP_ENABLED : HID_PTP_REFUSED_READBACK;
    }
    return s->result = HID_PTP_ENABLED_UNVERIFIED;
}

const char *hid_ptp_enable_name(int r)
{
    switch (r) {
    case HID_PTP_ENABLED: return "enabled";
    case HID_PTP_ENABLED_UNVERIFIED: return "enabled, unverified";
    case HID_PTP_REFUSED_WRITE: return "refused: write";
    case HID_PTP_REFUSED_READBACK: return "refused: readback";
    case HID_PTP_ENABLE_INVALID: return "no input mode";
    default: return "unknown";
    }
}

/* ------------------------------------------------------------------------------ engine ---- */

int hid_ptp_decode(const struct hid_ptp_layout *l, const uint8_t *report, uint32_t len,
                   struct hid_ptp_frame *f)
{
    const uint8_t *body;
    uint32_t bytes;
    if (!l || !report || !len || !f)
        return HID_PTP_BAD_LENGTH;
    if (report[0] != l->report_id)
        return HID_PTP_OTHER_REPORT;
    if (len != l->report_bytes)
        return HID_PTP_BAD_LENGTH;
    body = report + 1;
    bytes = len - 1u;
    memset(f, 0, sizeof(*f));
    f->slots = l->fingers;
    for (uint32_t i = 0; i < l->fingers; i++) {
        const struct hid_ptp_finger *fi = &l->finger[i];
        struct hid_ptp_contact *c = &f->c[i];
        c->tip = hid_ptp_get(body, bytes, &fi->tip) != 0;
        c->confident = l->has_confidence ? hid_ptp_get(body, bytes, &fi->confidence) != 0 : 1;
        c->id = fi->id.size ? hid_ptp_get(body, bytes, &fi->id) : i;
        c->x = sget(body, bytes, &fi->x);
        c->y = sget(body, bytes, &fi->y);
    }
    f->count = hid_ptp_get(body, bytes, &l->contact_count);
    f->scan = hid_ptp_get(body, bytes, &l->scan_time);
    for (uint32_t b = 0; b < l->buttons && b < HID_PTP_MAX_BUTTONS; b++)
        if (l->button[b].size && hid_ptp_get(body, bytes, &l->button[b]))
            f->buttons |= 1u << b;
    return HID_PTP_FRAME;
}

void hid_ptp_engine_init(struct hid_ptp_engine *e, const struct hid_ptp_layout *l)
{
    uint64_t xr, yr;
    memset(e, 0, sizeof(*e));
    e->l = *l;
    xr = l->x_max > l->x_min ? (uint64_t)((int64_t)l->x_max - l->x_min) : 1u;
    yr = l->y_max > l->y_min ? (uint64_t)((int64_t)l->y_max - l->y_min) : 1u;
    e->q16_x = ((uint64_t)l->width_um * HID_PTP_UNITS_PER_INCH << 32) / (25400u * xr);
    e->q16_y = ((uint64_t)l->height_um * HID_PTP_UNITS_PER_INCH << 32) / (25400u * yr);
    e->um_x = ((uint64_t)l->width_um << 16) / xr;
    e->um_y = ((uint64_t)l->height_um << 16) / yr;
}

static int64_t iabs64(int64_t v) { return v < 0 ? -v : v; }

/* Counts to output units (Q16 of 1/400 inch). */
static int32_t qx(const struct hid_ptp_engine *e, int64_t counts) { return (int32_t)((counts * (int64_t)e->q16_x) / 65536); }
static int32_t qy(const struct hid_ptp_engine *e, int64_t counts) { return (int32_t)((counts * (int64_t)e->q16_y) / 65536); }

/* Distance in micrometres (the larger axis). */
static uint32_t um(const struct hid_ptp_engine *e, int64_t dx, int64_t dy)
{
    uint64_t ux = ((uint64_t)iabs64(dx) * e->um_x) >> 16, uy = ((uint64_t)iabs64(dy) * e->um_y) >> 16;
    uint64_t m = ux > uy ? ux : uy;
    return m > 0xffffffffu ? 0xffffffffu : (uint32_t)m;
}

/* Output units (Q16) to micrometres. */
static uint32_t units_um(int64_t q16)
{
    return (uint32_t)(((uint64_t)iabs64(q16) * 25400u / HID_PTP_UNITS_PER_INCH) >> 16);
}

static void emit_buttons(struct hid_ptp_engine *e, const struct hid_ptp_sink *s)
{
    uint32_t b = e->mapped | e->tap;
    if (b == e->last_buttons)
        return;
    e->last_buttons = b;
    s->pointer(s->ctx, 0, 0, b);
}

static void release_tap(struct hid_ptp_engine *e, const struct hid_ptp_sink *s)
{
    e->tap = 0;
    emit_buttons(e, s);
}

static void end_momentum(struct hid_ptp_engine *e, const struct hid_ptp_sink *s)
{
    if (e->momentum && e->momentum_started)
        s->scroll(s->ctx, 0, 0, HID_PTP_SCROLL_MOMENTUM_END);
    e->momentum = e->momentum_started = 0;
}

/* Ended; then momentum when allowed and the release was quick (motion near `ref`). */
static void end_scroll(struct hid_ptp_engine *e, uint64_t now, uint64_t ref, int momentum,
                       const struct hid_ptp_sink *s)
{
    int64_t speed = iabs64(e->vel_v) > iabs64(e->vel_h) ? iabs64(e->vel_v) : iabs64(e->vel_h);
    s->scroll(s->ctx, 0, 0, HID_PTP_SCROLL_PHASE_ENDED);
    if (momentum && e->have_vel && ref >= e->last_scroll_us && ref - e->last_scroll_us <= HID_PTP_MOMENTUM_RECENT_US &&
        speed >= ((int64_t)HID_PTP_MOMENTUM_START << 16)) {
        e->momentum = 1;
        e->momentum_started = 0;
        e->mom_v = e->vel_v;
        e->mom_h = e->vel_h;
        e->mom_at = e->mom_start = now;
        e->stats.momentum++;
    }
}

static struct hid_ptp_track *find(struct hid_ptp_engine *e, uint32_t id)
{
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS; i++)
        if (e->t[i].used && e->t[i].id == id)
            return &e->t[i];
    return NULL;
}

static void note_ended(struct hid_ptp_engine *e, uint32_t id)
{
    e->ended[e->nended % 8u] = id;
    e->nended++;
}

static int ended_before(const struct hid_ptp_engine *e, uint32_t id)
{
    for (uint32_t i = 0; i < e->nended && i < 8u; i++)
        if (e->ended[i] == id)
            return 1;
    return 0;
}

/* Frame time from Scan Time (100 us units, wrapping at its field size), else the host clock. */
static uint64_t frame_dt(struct hid_ptp_engine *e, uint32_t scan, uint64_t now)
{
    uint64_t host = e->last_us && now > e->last_us ? now - e->last_us : 0, dt;
    if (host && host < 1000u)
        host = 1000u;
    if (host > 100000u)
        host = 100000u;
    if (!e->l.scan_time.size)
        return host;
    if (!e->have_scan) {
        dt = host;
    } else {
        uint32_t mask = e->l.scan_time.size >= 32u ? 0xffffffffu : (1u << e->l.scan_time.size) - 1u;
        uint32_t d = (scan - e->last_scan) & mask;
        if (!d) {
            dt = 0;                                          /* the same frame again */
        } else if (d >= 10u && d <= 1000u) {
            dt = (uint64_t)d * 100u;
        } else {
            e->stats.scan_fallbacks++;
            dt = host;
        }
    }
    e->last_scan = scan;
    e->have_scan = 1;
    return dt;
}

static void pointer_frame(struct hid_ptp_engine *e, uint64_t now, int pick_most_moved, const struct hid_ptp_sink *s)
{
    struct hid_ptp_track *best = NULL;
    int64_t best_m = -1;
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS; i++) {
        struct hid_ptp_track *t = &e->t[i];
        int64_t m;
        if (!t->used || t->palm || !t->moved)
            continue;
        m = iabs64(t->dx) + iabs64(t->dy);
        if (!best || (pick_most_moved && m > best_m)) {
            best = t;
            best_m = m;
        }
    }
    if (!best || (!best->dx && !best->dy) || now < e->settle_until)
        return;
    e->last_buttons = e->mapped | e->tap;
    e->stats.pointer_events++;
    s->pointer(s->ctx, qx(e, best->dx), qy(e, best->dy), e->last_buttons);
}

/* Two fingers: the mean motion of the pair, both present in the last frame too. */
static int pair_motion(struct hid_ptp_engine *e, int64_t *v, int64_t *h, struct hid_ptp_track **pair)
{
    uint32_t n = 0;
    int64_t sx = 0, sy = 0;
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS && n < 2; i++) {
        struct hid_ptp_track *t = &e->t[i];
        if (!t->used || t->palm)
            continue;
        pair[n++] = t;
        sx += t->dx;
        sy += t->dy;
    }
    if (n != 2 || !pair[0]->moved || !pair[1]->moved)
        return 0;
    *v = -(int64_t)qy(e, sy) / 2;                            /* fingers up: wheel up (positive) */
    *h = -(int64_t)qx(e, sx) / 2;
    return 1;
}

static void two_finger_frame(struct hid_ptp_engine *e, uint64_t now, uint64_t dt, const struct hid_ptp_sink *s)
{
    struct hid_ptp_track *pair[2];
    int64_t v, h;
    if (!pair_motion(e, &v, &h, pair))
        return;
    if (dt) {
        int64_t sv = v * 1000000 / (int64_t)dt, sh = h * 1000000 / (int64_t)dt;
        if (!e->have_vel) {
            e->vel_v = sv;
            e->vel_h = sh;
            e->have_vel = 1;
        } else {
            e->vel_v = (e->vel_v + sv) / 2;
            e->vel_h = (e->vel_h + sh) / 2;
        }
    }
    if (e->mode == HID_PTP_TWO) {
        uint32_t m0 = um(e, pair[0]->x - pair[0]->xe, pair[0]->y - pair[0]->ye);
        uint32_t m1 = um(e, pair[1]->x - pair[1]->xe, pair[1]->y - pair[1]->ye);
        uint32_t still = m0 < m1 ? m0 : m1, moving = m0 < m1 ? m1 : m0;
        e->acc_v += v;
        e->acc_h += h;
        if (moving >= HID_PTP_REST_MOVE_UM && still <= HID_PTP_REST_STILL_UM) {
            e->mode = HID_PTP_REST;                          /* F23: the still one is a resting thumb */
            return;
        }
        if ((units_um(e->acc_v) >= HID_PTP_SCROLL_START_UM || units_um(e->acc_h) >= HID_PTP_SCROLL_START_UM) &&
            still >= HID_PTP_SCROLL_EACH_UM && (v || h)) {
            e->mode = HID_PTP_SCROLL;
            e->s_scrolled = 1;
            e->stats.scrolls++;
            e->stats.scroll_events++;
            e->last_scroll_us = now;
            s->scroll(s->ctx, (int32_t)v, (int32_t)h, HID_PTP_SCROLL_PHASE_BEGAN);
        }
        return;
    }
    if (v || h) {                                            /* SCROLL */
        e->last_scroll_us = now;
        e->stats.scroll_events++;
        s->scroll(s->ctx, (int32_t)v, (int32_t)h, HID_PTP_SCROLL_PHASE_CHANGED);
    }
}

static void enter_two(struct hid_ptp_engine *e)
{
    e->mode = HID_PTP_TWO;
    e->acc_v = e->acc_h = 0;
    e->vel_v = e->vel_h = 0;
    e->have_vel = 0;
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS; i++) {
        e->t[i].xe = e->t[i].x;
        e->t[i].ye = e->t[i].y;
    }
}

static void end_session(struct hid_ptp_engine *e, uint64_t now, const struct hid_ptp_sink *s)
{
    if (e->session && !e->s_press && !e->s_scrolled && !e->s_palm && !e->s_far && e->s_max >= 1 &&
        e->s_max <= 2 && now - e->s_start <= HID_PTP_TAP_MAX_US) {
        if (e->s_typing) {
            e->stats.typing_blocked_taps++;
        } else {
            e->tap = e->s_max == 2 ? 2u : 1u;
            e->tap_release_at = now + HID_PTP_TAP_RELEASE_US;
            e->stats.taps++;
            if (e->s_max == 2)
                e->stats.secondary_taps++;
            emit_buttons(e, s);
        }
    }
    e->session = 0;
    e->nended = 0;
    e->have_scan = 0;
    e->settle_until = 0;                                     /* a settle never outlives its touch */
    e->mode = HID_PTP_IDLE;
}

static void process(struct hid_ptp_engine *e, const struct hid_ptp_contact *c, uint32_t n, uint32_t scan,
                    uint32_t phys, uint64_t now, uint64_t last_key, const struct hid_ptp_sink *s)
{
    uint32_t fingers = 0, prev = e->fingers, any = 0, used = 0;
    uint64_t dt;
    e->stats.frames++;
    if (s->frame)
        s->frame(s->ctx, c, n, phys, scan, e->l.scan_time.size != 0);
    for (uint32_t i = 0; i < n; i++)
        any |= c[i].tip;
    if (e->tap && (any || now >= e->tap_release_at))
        release_tap(e, s);
    if (e->momentum && any)
        end_momentum(e, s);
    dt = frame_dt(e, scan, now);
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS; i++) {
        e->t[i].seen = 0;
        e->t[i].moved = 0;
        e->t[i].dx = e->t[i].dy = 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        struct hid_ptp_track *t = find(e, c[i].id);
        if (t && t->seen) {
            e->stats.duplicate_ids++;
            continue;
        }
        if (!c[i].tip) {
            if (t)
                t->seen = 2;                                 /* lifting: ends below */
            continue;
        }
        e->stats.contacts++;
        if (t) {
            int32_t dx = c[i].x - t->x, dy = c[i].y - t->y;
            t->seen = 1;
            if (um(e, dx, dy) > HID_PTP_JUMP_UM) {           /* F6: a new contact under an old ID */
                e->stats.jumps++;
                e->s_far = 1;
                t->x = t->x0 = t->xe = c[i].x;
                t->y = t->y0 = t->ye = c[i].y;
            } else {
                uint32_t far;
                t->dx = dx;
                t->dy = dy;
                t->moved = 1;
                t->x = c[i].x;
                t->y = c[i].y;
                far = um(e, t->x - t->x0, t->y - t->y0);
                if (far > t->travel_um)
                    t->travel_um = far;
                if (t->travel_um > HID_PTP_TAP_TRAVEL_UM)
                    e->s_far = 1;
            }
            if (!c[i].confident && !t->palm) {               /* F5: a palm for the rest of its life */
                t->palm = 1;
                e->stats.palms++;
                e->s_palm = 1;
            }
            continue;
        }
        for (uint32_t j = 0; j < HID_PTP_MAX_CONTACTS; j++) {
            if (e->t[j].used)
                continue;
            t = &e->t[j];
            memset(t, 0, sizeof(*t));
            t->used = 1;
            t->seen = 1;
            t->id = c[i].id;
            t->x = t->x0 = t->xe = c[i].x;
            t->y = t->y0 = t->ye = c[i].y;
            if (!c[i].confident) {
                t->palm = 1;
                e->stats.palms++;
                e->s_palm = 1;
            }
            if (!e->session) {
                e->session = 1;
                e->s_start = now;
                e->s_max = e->s_press = e->s_scrolled = e->s_far = 0;
                e->s_palm = t->palm;
                e->s_typing = last_key && (last_key >= now || now - last_key < HID_PTP_TYPING_US);
            } else if (ended_before(e, t->id)) {
                e->stats.reused_ids++;
            }
            break;
        }
    }
    for (uint32_t i = 0; i < HID_PTP_MAX_CONTACTS; i++) {
        struct hid_ptp_track *t = &e->t[i];
        if (!t->used)
            continue;
        if (t->seen != 1) {                                  /* lifted, or vanished from the frame */
            note_ended(e, t->id);
            t->used = 0;
            continue;
        }
        used++;
        if (!t->palm)
            fingers++;
    }
    if (fingers > e->stats.max_fingers)
        e->stats.max_fingers = fingers;
    if (fingers > e->s_max)
        e->s_max = (uint8_t)fingers;
    if (prev && fingers && fingers != prev)
        e->settle_until = now + HID_PTP_SETTLE_US;            /* F8: 1 <-> 2, not a touch's first or last frame */
    /* Physical buttons (F18, F19). */
    if (phys && !e->phys) {
        e->mapped = e->l.buttons >= 2u ? phys : fingers >= 2u ? 2u : 1u;
        e->s_press = 1;
        e->settle_until = now + HID_PTP_SETTLE_US;
        e->stats.button_edges++;
        if (e->mode == HID_PTP_SCROLL || e->mode == HID_PTP_SCROLL_LIFT) {
            end_scroll(e, now, now, 0, s);
            e->mode = HID_PTP_POINTER;
        }
        emit_buttons(e, s);
    } else if (!phys && e->phys) {
        e->mapped = 0;
        e->settle_until = now + HID_PTP_SETTLE_US;
        e->stats.button_edges++;
        emit_buttons(e, s);
    } else if (phys && e->l.buttons >= 2u && phys != e->mapped) {
        e->mapped = phys;
        emit_buttons(e, s);
    }
    e->phys = phys;
    /* What the fingers do. */
    if (e->mode == HID_PTP_SCROLL) {
        if (fingers == 2 && !phys) {
            two_finger_frame(e, now, prev == 2 ? dt : 0, s);
        } else if (fingers == 1 && !phys) {
            e->mode = HID_PTP_SCROLL_LIFT;                   /* F7: wait for the other lift */
            e->lift_at = now;
        } else if (!fingers) {
            end_scroll(e, now, now, 1, s);
            e->mode = HID_PTP_IDLE;
        } else {
            end_scroll(e, now, now, 0, s);
            e->mode = fingers >= 3 ? HID_PTP_MULTI : HID_PTP_POINTER;
        }
    } else if (e->mode == HID_PTP_SCROLL_LIFT) {
        if (!fingers) {
            end_scroll(e, now, e->lift_at, 1, s);
            e->mode = HID_PTP_IDLE;
        } else if (fingers == 2 && !phys) {
            e->mode = HID_PTP_SCROLL;                        /* the finger came back */
        } else if (fingers != 1 || phys || now - e->lift_at >= HID_PTP_LIFT_WINDOW_US) {
            end_scroll(e, now, now, 0, s);                   /* the pointer starts from the next frame */
            e->mode = fingers >= 3 ? HID_PTP_MULTI : HID_PTP_POINTER;
        }
    } else if (phys) {
        e->mode = HID_PTP_POINTER;
        pointer_frame(e, now, 1, s);                         /* a drag: the finger that moves */
    } else if (fingers == 1) {
        e->mode = HID_PTP_POINTER;
        pointer_frame(e, now, 0, s);
    } else if (fingers == 2) {
        if (prev != 2 || (e->mode != HID_PTP_TWO && e->mode != HID_PTP_REST))
            enter_two(e);
        if (e->mode == HID_PTP_REST)
            pointer_frame(e, now, 1, s);
        else
            two_finger_frame(e, now, prev == 2 ? dt : 0, s);
    } else {
        e->mode = fingers ? HID_PTP_MULTI : HID_PTP_IDLE;
    }
    e->fingers = fingers;
    e->last_us = now;
    if (!used)
        end_session(e, now, s);
}

int hid_ptp_engine_report(struct hid_ptp_engine *e, const uint8_t *report, uint32_t len, uint64_t now,
                          uint64_t last_key, const struct hid_ptp_sink *s)
{
    struct hid_ptp_frame f;
    int r = hid_ptp_decode(&e->l, report, len, &f);
    if (r == HID_PTP_OTHER_REPORT)
        return r;
    e->stats.reports++;
    if (r != HID_PTP_FRAME) {
        e->stats.bad_length++;
        return r;
    }
    if (!e->l.contact_count.size) {                          /* no count: the slots touching */
        struct hid_ptp_contact c[HID_PTP_MAX_FINGERS];
        uint32_t n = 0;
        for (uint32_t i = 0; i < f.slots; i++)
            if (f.c[i].tip)
                c[n++] = f.c[i];
        process(e, c, n, f.scan, f.buttons, now, last_key, s);
        return r;
    }
    if (f.count) {
        uint32_t want = f.count < HID_PTP_MAX_CONTACTS ? f.count : HID_PTP_MAX_CONTACTS;
        if (e->pending_want) {                               /* F13: a partial frame never completed */
            e->stats.hybrid_dropped++;
            e->pending_want = 0;
        }
        if (want > f.slots) {
            e->pending = f;
            e->pending.slots = f.slots;
            e->pending_want = want;
            e->stats.hybrid_partial++;
            return r;
        }
        process(e, f.c, want, f.scan, f.buttons, now, last_key, s);
        return r;
    }
    if (e->pending_want) {                                   /* continuation: Contact Count 0 */
        uint32_t need = e->pending_want - e->pending.slots;
        uint32_t take = need < f.slots ? need : f.slots;
        for (uint32_t i = 0; i < take; i++)
            e->pending.c[e->pending.slots + i] = f.c[i];
        e->pending.slots = (uint8_t)(e->pending.slots + take);
        if (e->pending.slots < e->pending_want)
            return r;
        e->pending_want = 0;
        process(e, e->pending.c, e->pending.slots, e->pending.scan, e->pending.buttons, now, last_key, s);
        return r;
    }
    process(e, f.c, 0, f.scan, f.buttons, now, last_key, s);
    return r;
}

void hid_ptp_engine_tick(struct hid_ptp_engine *e, uint64_t now, const struct hid_ptp_sink *s)
{
    if (e->tap && now >= e->tap_release_at)
        release_tap(e, s);
    if (e->mode == HID_PTP_SCROLL_LIFT && now - e->lift_at >= HID_PTP_LIFT_WINDOW_US) {
        end_scroll(e, now, now, 0, s);
        e->mode = HID_PTP_POINTER;
    }
    if (e->momentum && now > e->mom_at) {
        uint64_t dt = now - e->mom_at;
        int64_t speed, dv, dh;
        if (dt > 100000u)
            dt = 100000u;
        for (uint64_t ms = 0; ms < dt / 1000u; ms++) {
            e->mom_v = e->mom_v * HID_PTP_MOMENTUM_DECAY_Q16 / 65536;
            e->mom_h = e->mom_h * HID_PTP_MOMENTUM_DECAY_Q16 / 65536;
        }
        e->mom_at = now;
        speed = iabs64(e->mom_v) > iabs64(e->mom_h) ? iabs64(e->mom_v) : iabs64(e->mom_h);
        if (speed < ((int64_t)HID_PTP_MOMENTUM_STOP << 16) || now - e->mom_start >= HID_PTP_MOMENTUM_MAX_US) {
            end_momentum(e, s);
            return;
        }
        dv = e->mom_v * (int64_t)dt / 1000000;
        dh = e->mom_h * (int64_t)dt / 1000000;
        s->scroll(s->ctx, (int32_t)dv, (int32_t)dh,
                  e->momentum_started ? HID_PTP_SCROLL_MOMENTUM_CONTINUE : HID_PTP_SCROLL_MOMENTUM_START);
        e->momentum_started = 1;
        e->stats.momentum_events++;
    }
}

int hid_ptp_engine_busy(const struct hid_ptp_engine *e)
{
    return e->tap || e->momentum || e->mode == HID_PTP_SCROLL_LIFT;
}

void hid_ptp_engine_reset(struct hid_ptp_engine *e, uint64_t now, const struct hid_ptp_sink *s)
{
    (void)now;
    if (e->mode == HID_PTP_SCROLL || e->mode == HID_PTP_SCROLL_LIFT)
        s->scroll(s->ctx, 0, 0, HID_PTP_SCROLL_PHASE_ENDED);
    end_momentum(e, s);
    e->mapped = e->tap = e->phys = 0;
    emit_buttons(e, s);
    memset(e->t, 0, sizeof(e->t));
    e->mode = HID_PTP_IDLE;
    e->fingers = 0;
    e->session = 0;
    e->nended = 0;
    e->pending_want = 0;
    e->settle_until = 0;
    e->have_scan = 0;
    e->have_vel = 0;
    e->last_us = 0;
}
