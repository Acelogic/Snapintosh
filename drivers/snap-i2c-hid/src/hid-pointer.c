/* SPDX-License-Identifier: MIT */
/* Mouse-collection layout and pointer translation; the contract is in hid-pointer.h.
 * Item encoding facts are from the USB HID 1.11 specification (short items only). */
#include "hid-pointer.h"

#include <string.h>

#define MAX_USAGES   16u
#define MAX_DEPTH    8u
#define MAX_IDS      256u
#define MAX_BITS     (512u * 8u)

struct globals {
    uint32_t page;
    int32_t logical_min;
    uint32_t report_size, report_count, report_id;
};

static uint32_t unsigned_value(const uint8_t *p, uint32_t n)
{
    uint32_t v = 0;
    for (uint32_t i = 0; i < n; i++)
        v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static int32_t signed_value(const uint8_t *p, uint32_t n)
{
    uint32_t v = unsigned_value(p, n);
    if (n == 1)
        return (int8_t)v;
    if (n == 2)
        return (int16_t)v;
    return (int32_t)v;
}

static void place(struct hid_pointer_field *f, uint32_t offset, uint32_t size, int32_t logical_min)
{
    if (f->size || size == 0 || size > 32)
        return;
    f->offset = (uint16_t)offset;
    f->size = (uint8_t)size;
    f->is_signed = logical_min < 0;
}

int hid_pointer_layout(const uint8_t *d, uint32_t len, struct hid_pointer_layout *out)
{
    struct globals g = {0}, stack[MAX_DEPTH];
    uint32_t usages[MAX_USAGES], nusages = 0, umin = 0, umax = 0, have_range = 0;
    uint32_t depth = 0, gdepth = 0, mouse_depth = 0, in_mouse = 0, found = 0, numbered = 0;
    uint32_t mouse_id = 0;
    uint16_t bits[MAX_IDS];                  /* input bits so far, per report ID (MAX_BITS fits) */
    struct hid_pointer_layout l;

    if (!d || !out)
        return HID_POINTER_MALFORMED;
    memset(&l, 0, sizeof(l));
    memset(bits, 0, sizeof(bits));
    for (uint32_t at = 0; at < len;) {
        uint8_t prefix = d[at];
        uint32_t size = prefix & 3u, type = (prefix >> 2) & 3u, tag = prefix >> 4;
        const uint8_t *data;
        uint32_t u;
        if (prefix == 0xfe)
            return HID_POINTER_MALFORMED;      /* long items: not used by these devices */
        if (size == 3)
            size = 4;
        if (at + 1 + size > len)
            return HID_POINTER_MALFORMED;
        data = d + at + 1;
        u = unsigned_value(data, size);
        at += 1 + size;
        if (type == 1) {                       /* global */
            switch (tag) {
            case 0x0: g.page = u; break;
            case 0x1: g.logical_min = signed_value(data, size); break;
            case 0x7: g.report_size = u; break;
            case 0x8:
                if (!u || u >= MAX_IDS)
                    return HID_POINTER_MALFORMED;
                g.report_id = u;
                numbered = 1;
                break;
            case 0x9: g.report_count = u; break;
            case 0xa:
                if (gdepth >= MAX_DEPTH)
                    return HID_POINTER_MALFORMED;
                stack[gdepth++] = g;
                break;
            case 0xb:
                if (!gdepth)
                    return HID_POINTER_MALFORMED;
                g = stack[--gdepth];
                break;
            default: break;
            }
            continue;
        }
        if (type == 2) {                       /* local */
            uint32_t usage = size == 4 ? u : (g.page << 16) | u;
            if (tag == 0x0 && nusages < MAX_USAGES)
                usages[nusages++] = usage;
            else if (tag == 0x1) { umin = usage; have_range |= 1; }
            else if (tag == 0x2) { umax = usage; have_range |= 2; }
            continue;
        }
        if (type != 0)
            return HID_POINTER_MALFORMED;
        /* main */
        if (tag == 0xa) {                      /* Collection */
            uint32_t first = nusages ? usages[0] : (have_range & 1) ? umin : 0;
            if (depth >= MAX_DEPTH)
                return HID_POINTER_MALFORMED;
            depth++;
            if (!found && !in_mouse && u == 1 && first == 0x00010002u) {
                in_mouse = 1;
                mouse_depth = depth;
            }
        } else if (tag == 0xc) {               /* End Collection */
            if (!depth)
                return HID_POINTER_MALFORMED;
            if (in_mouse && depth == mouse_depth) {
                in_mouse = 0;
                if (l.x.size && l.y.size)
                    found = 1;
            }
            depth--;
        } else if (tag == 0x8) {               /* Input */
            uint32_t id = g.report_id, total = g.report_size * g.report_count;
            if (g.report_size > 32 || total > MAX_BITS || bits[id] + total > MAX_BITS)
                return HID_POINTER_MALFORMED;
            if (in_mouse && !found && !(u & 1)) {   /* data, not constant */
                if (!mouse_id && !l.x.size && !l.buttons)
                    mouse_id = id;
                if (id == mouse_id) {
                    for (uint32_t i = 0; i < g.report_count; i++) {
                        uint32_t usage = i < nusages ? usages[i]
                                       : (have_range == 3 && umin + i <= umax) ? umin + i
                                       : nusages ? usages[nusages - 1] : 0;
                        uint32_t off = bits[id] + i * g.report_size;
                        int relative = (u & 4u) != 0;
                        if ((usage >> 16) == 0x9 && g.report_size == 1 && (usage & 0xffffu) >= 1 &&
                            (usage & 0xffffu) <= 16 && (u & 2u)) {
                            if (!l.buttons)
                                l.buttons_offset = (uint16_t)(off - ((usage & 0xffffu) - 1));
                            if ((usage & 0xffffu) > l.buttons)
                                l.buttons = (uint8_t)(usage & 0xffffu);
                        } else if (usage == 0x00010030u && relative) {
                            place(&l.x, off, g.report_size, g.logical_min);
                        } else if (usage == 0x00010031u && relative) {
                            place(&l.y, off, g.report_size, g.logical_min);
                        } else if (usage == 0x00010038u && relative) {
                            place(&l.wheel, off, g.report_size, g.logical_min);
                        } else if (usage == 0x000c0238u && relative) {
                            place(&l.pan, off, g.report_size, g.logical_min);
                        }
                    }
                }
            }
            bits[id] = (uint16_t)(bits[id] + total);
        }
        if (type == 0) {                       /* every main item clears the locals */
            nusages = 0;
            have_range = 0;
        }
    }
    if (depth || gdepth)
        return HID_POINTER_MALFORMED;
    if (!found)
        return HID_POINTER_NO_MOUSE;
    l.report_id = (uint8_t)mouse_id;
    l.report_bytes = (uint16_t)((bits[mouse_id] + 7u) / 8u + (numbered ? 1u : 0u));
    *out = l;
    return HID_POINTER_OK;
}

static int32_t field(const uint8_t *r, uint32_t bytes, const struct hid_pointer_field *f)
{
    uint32_t v = 0;
    if (!f->size)
        return 0;
    for (uint32_t i = 0; i < f->size; i++) {
        uint32_t bit = f->offset + i;
        if (bit / 8u < bytes && (r[bit / 8u] >> (bit % 8u) & 1u))
            v |= 1u << i;
    }
    if (f->is_signed && f->size < 32 && (v >> (f->size - 1)) & 1u)
        v |= ~0u << f->size;
    return (int32_t)v;
}

int hid_pointer_translate(const struct hid_pointer_layout *l, struct hid_pointer_state *s,
                          const uint8_t *report, uint32_t len, hid_pointer_move_fn move,
                          hid_pointer_scroll_fn scroll, void *ctx)
{
    const uint8_t *body;
    uint32_t bytes, buttons = 0;
    int32_t dx, dy, v, h;

    if (!l || !s || !report || !len || !move || !scroll)
        return HID_POINTER_BAD_LENGTH;
    if (l->report_id && report[0] != l->report_id)
        return HID_POINTER_OTHER_REPORT;
    if (len != l->report_bytes)
        return HID_POINTER_BAD_LENGTH;
    body = l->report_id ? report + 1 : report;
    bytes = l->report_id ? len - 1u : len;
    for (uint32_t i = 0; i < l->buttons; i++) {
        uint32_t bit = l->buttons_offset + i;
        if (bit / 8u < bytes && (body[bit / 8u] >> (bit % 8u) & 1u))
            buttons |= 1u << i;
    }
    dx = field(body, bytes, &l->x);
    dy = field(body, bytes, &l->y);
    v = field(body, bytes, &l->wheel);
    h = field(body, bytes, &l->pan);
    if (dx || dy || buttons != s->buttons)
        move(ctx, dx, dy, buttons);
    if (v || h)
        scroll(ctx, v, h);
    s->buttons = buttons;
    return HID_POINTER_EVENTS;
}
