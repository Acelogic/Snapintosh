/* SPDX-License-Identifier: MIT */
/* Bounded HID report-descriptor scan; see hid-rdesc.h. Item encoding is the
 * USB HID 1.11 short/long item format. */
#include "hid-rdesc.h"

#include <stddef.h>
#include <string.h>

struct globals {
    uint32_t page, size, count, id;
    uint8_t has_size, has_count;
};

static int add_bits(struct hid_rdesc_info *out, uint8_t type, uint8_t id, uint32_t bits)
{
    for (uint32_t i = 0; i < out->nreports; i++) {
        struct hid_report_shape *r = &out->reports[i];
        if (r->type == type && r->id == id) {
            if (r->bits > 0xffffffffu - bits)
                return HID_RDESC_FIELD;
            r->bits += bits;
            return HID_RDESC_OK;
        }
    }
    if (out->nreports == HID_RDESC_MAX_REPORTS)
        return HID_RDESC_TOO_MANY;
    out->reports[out->nreports].type = type;
    out->reports[out->nreports].id = id;
    out->reports[out->nreports].reserved = 0;
    out->reports[out->nreports].bits = bits;
    out->nreports++;
    return HID_RDESC_OK;
}

int hid_rdesc_parse(const uint8_t *d, uint32_t len, struct hid_rdesc_info *out)
{
    struct globals g, stack[HID_RDESC_MAX_STACK];
    uint32_t depth = 0, sp = 0, pos = 0;
    uint32_t usage = 0, usage_size = 0;
    uint8_t has_usage = 0, saw_unnumbered = 0, saw_numbered = 0;
    int r = HID_RDESC_OK;

    if (!out)
        return HID_RDESC_EMPTY;
    memset(out, 0, sizeof(*out));
    memset(&g, 0, sizeof(g));
    if (!d || !len)
        return HID_RDESC_EMPTY;
    while (pos < len) {
        uint32_t start = pos, size, kind, tag, value = 0;
        uint8_t prefix = d[pos++];

        out->error_offset = start;
        out->items++;
        if (prefix == 0xfe) {                   /* long item: size, tag, data */
            if (len - pos < 2u)
                return HID_RDESC_TRUNCATED;
            size = d[pos];
            pos += 2;
            if (len - pos < size)
                return HID_RDESC_TRUNCATED;
            pos += size;
            continue;
        }
        size = (prefix & 3u) == 3u ? 4u : (prefix & 3u);
        kind = (prefix >> 2) & 3u;
        tag = prefix >> 4;
        if (len - pos < size)
            return HID_RDESC_TRUNCATED;
        for (uint32_t i = 0; i < size; i++)
            value |= (uint32_t)d[pos + i] << (8 * i);
        pos += size;

        if (kind == 3u)
            return HID_RDESC_BAD_ITEM;
        if (kind == 1u) {                       /* global */
            switch (tag) {
            case 0: g.page = value; break;
            case 7: g.size = value; g.has_size = 1; break;
            case 8:
                if (size != 1u || value < 1u || value > 255u)
                    return HID_RDESC_REPORT_ID;
                g.id = value;
                break;
            case 9: g.count = value; g.has_count = 1; break;
            case 10:
                if (size != 0u || sp == HID_RDESC_MAX_STACK)
                    return HID_RDESC_STACK;
                stack[sp++] = g;
                break;
            case 11:
                if (size != 0u || sp == 0u)
                    return HID_RDESC_STACK;
                g = stack[--sp];
                break;
            default: break;                     /* logical/physical ranges, units */
            }
            continue;
        }
        if (kind == 2u) {                       /* local */
            if (tag == 0u) {
                usage = value;
                usage_size = size;
                has_usage = 1;
            }
            continue;
        }
        /* main */
        switch (tag) {
        case 8: case 9: case 11: {              /* Input, Output, Feature */
            uint64_t bits;
            uint8_t type = tag == 8u ? HID_REPORT_INPUT : tag == 9u ? HID_REPORT_OUTPUT
                                                                     : HID_REPORT_FEATURE;
            if (!depth || !size || !g.has_size || !g.has_count)
                return HID_RDESC_FIELD;
            bits = (uint64_t)g.size * g.count;
            if (!bits || bits > 65533ull * 8ull)
                return HID_RDESC_FIELD;
            if (g.id)
                saw_numbered = 1;
            else
                saw_unnumbered = 1;
            r = add_bits(out, type, (uint8_t)g.id, (uint32_t)bits);
            if (r)
                return r;
            break;
        }
        case 10:                                /* Collection */
            if (size != 1u || depth == HID_RDESC_MAX_DEPTH)
                return HID_RDESC_COLLECTION;
            if (depth == 0u && value == 1u) {   /* top-level Application */
                if (out->napps == HID_RDESC_MAX_APPS)
                    return HID_RDESC_TOO_MANY;
                if (has_usage && usage_size == 4u) {
                    out->apps[out->napps].page = (uint16_t)(usage >> 16);
                    out->apps[out->napps].usage = (uint16_t)usage;
                } else {
                    out->apps[out->napps].page = (uint16_t)g.page;
                    out->apps[out->napps].usage = has_usage ? (uint16_t)usage : 0u;
                }
                out->napps++;
            }
            depth++;
            break;
        case 12:                                /* End Collection */
            if (size != 0u || depth == 0u)
                return HID_RDESC_COLLECTION;
            depth--;
            break;
        default:
            return HID_RDESC_BAD_ITEM;
        }
        has_usage = 0;                          /* locals end at each main item */
        usage = 0;
        usage_size = 0;
    }
    out->error_offset = 0;
    if (depth || sp)
        return depth ? HID_RDESC_COLLECTION : HID_RDESC_STACK;
    if (!out->nreports)
        return HID_RDESC_EMPTY;
    if (saw_numbered && saw_unnumbered)
        return HID_RDESC_MIXED_IDS;
    out->numbered = saw_numbered;
    return HID_RDESC_OK;
}

uint32_t hid_rdesc_report_bytes(const struct hid_rdesc_info *info, uint8_t type, uint8_t id)
{
    if (!info)
        return 0;
    for (uint32_t i = 0; i < info->nreports; i++) {
        const struct hid_report_shape *r = &info->reports[i];
        if (r->type == type && r->id == id)
            return (r->bits + 7u) / 8u + (id ? 1u : 0u);
    }
    return 0;
}

uint32_t hid_rdesc_max_report_bytes(const struct hid_rdesc_info *info, uint8_t type)
{
    uint32_t best = 0;
    if (!info)
        return 0;
    for (uint32_t i = 0; i < info->nreports; i++) {
        const struct hid_report_shape *r = &info->reports[i];
        if (r->type == type) {
            uint32_t bytes = (r->bits + 7u) / 8u + (r->id ? 1u : 0u);
            if (bytes > best)
                best = bytes;
        }
    }
    return best;
}
