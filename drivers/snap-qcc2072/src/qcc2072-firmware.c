/* SPDX-License-Identifier: MIT */
#include "qcc2072-firmware.h"

struct cursor { const uint8_t *bytes; size_t length, pos; uint32_t *budget; };

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

static int container(struct cursor *c, const void *bytes, size_t length,
                     const char *magic, size_t magic_length, uint32_t *budget)
{
    size_t prefix = (magic_length + 1U + 3U) & ~(size_t)3U;
    if (length < prefix) return QCC2072_TRUNCATED;
    if (!equal(bytes, (const uint8_t *)magic, magic_length) ||
        ((const uint8_t *)bytes)[magic_length] != 0)
        return QCC2072_BAD_CONTAINER;
    c->bytes = bytes; c->length = length; c->pos = prefix; c->budget = budget;
    return QCC2072_OK;
}

/* A shared budget bounds outer plus nested records. 1=item, 0=end, negative=error. */
static int next(struct cursor *c, uint32_t *kind, struct qcc2072_slice *body)
{
    size_t padded, remaining;
    uint32_t length;
    if (c->pos == c->length) return 0;
    if (*c->budget == 0) return QCC2072_TOO_LARGE;
    --*c->budget;
    remaining = c->length - c->pos;
    if (remaining < 8U) return QCC2072_TRUNCATED;
    *kind = le32(c->bytes + c->pos);
    length = le32(c->bytes + c->pos + 4U);
    c->pos += 8U;
    remaining -= 8U;
    if ((size_t)length > remaining) return QCC2072_TRUNCATED;
    /* All admitted containers are much smaller than SIZE_MAX, even on 32-bit. */
    padded = ((size_t)length + 3U) & ~(size_t)3U;
    if (padded > remaining) return QCC2072_TRUNCATED;
    body->bytes = c->bytes + c->pos; body->length = length;
    c->pos += padded;
    return 1;
}

int qcc2072_parse_firmware(const void *bytes, size_t length,
                          struct qcc2072_firmware *out)
{
    struct qcc2072_firmware f = {0};
    struct cursor c;
    struct qcc2072_slice body;
    uint32_t kind, seen = 0, budget = QCC2072_MAX_IES;
    int r;
    if (!out) return QCC2072_INVALID_ARGUMENT;
    *out = f;
    if (!bytes) return QCC2072_INVALID_ARGUMENT;
    if (length > QCC2072_MAX_FIRMWARE_BYTES) return QCC2072_TOO_LARGE;
    r = container(&c, bytes, length, "QCOM-ATH12K-FW", sizeof("QCOM-ATH12K-FW") - 1U, &budget);
    if (r != QCC2072_OK) return r;
    while ((r = next(&c, &kind, &body)) > 0) {
        ++f.ie_count;
        if (kind > 5U) continue;
        if (seen & (1U << kind)) return QCC2072_DUPLICATE;
        seen |= 1U << kind;
        switch (kind) {
        case 0:
            if (body.length != 4U) return QCC2072_BAD_CONTAINER;
            f.timestamp = le32(body.bytes); f.timestamp_present = 1; break;
        case 1:
            if (body.length == 0U || body.length > 256U)
                return QCC2072_BAD_CONTAINER;
            f.features = body; break;
        case 2: f.amss = body; break;
        case 3: f.m3 = body; break;
        case 5: f.aux = body; break;
        default: break; /* AMSS_DUALMAC is not selected by this station-only path. */
        }
    }
    if (r < 0) return r;
    if (!f.amss.length || !f.m3.length || !f.aux.length)
        return QCC2072_MISSING_IMAGE;
    *out = f;
    return QCC2072_OK;
}

struct name_builder { uint8_t bytes[QCC2072_MAX_BOARD_NAME]; size_t length; };
static int append(struct name_builder *b, const char *s)
{
    while (*s) {
        if (b->length == sizeof(b->bytes)) return QCC2072_TOO_LARGE;
        b->bytes[b->length++] = (uint8_t)*s++;
    }
    return QCC2072_OK;
}
static int number(struct name_builder *b, uint32_t n, unsigned base, unsigned width)
{
    char digits[10]; unsigned count = 0;
    do { digits[count++] = "0123456789abcdef"[n % base]; n /= base; } while (n);
    while (count < width) digits[count++] = '0';
    if (b->length + count > sizeof(b->bytes)) return QCC2072_TOO_LARGE;
    while (count) b->bytes[b->length++] = (uint8_t)digits[--count];
    return QCC2072_OK;
}
static int board_name(const struct qcc2072_board_identity *id, struct name_builder *b)
{
    size_t i;
    if (id->vendor != QCC2072_VENDOR_ID || id->device != QCC2072_DEVICE_ID ||
        id->subsystem_vendor != QCC2072_SUBVENDOR_ID ||
        id->subsystem_device != QCC2072_SUBDEVICE_ID) return QCC2072_WRONG_DEVICE;
    if (!id->qmi_chip_id_known || !id->qmi_board_id_known)
        return QCC2072_IDENTITY_UNKNOWN;
    if (id->variant_length > 64U || (id->variant_length && !id->variant))
        return QCC2072_INVALID_ARGUMENT;
    b->length = 0;
    /* The fixed portion is at most 120 bytes; variant is bounded to 64. */
    append(b, "bus=pci,vendor="); number(b, id->vendor, 16, 4);
    append(b, ",device="); number(b, id->device, 16, 4);
    append(b, ",subsystem-vendor="); number(b, id->subsystem_vendor, 16, 4);
    append(b, ",subsystem-device="); number(b, id->subsystem_device, 16, 4);
    append(b, ",qmi-chip-id="); number(b, id->qmi_chip_id, 10, 0);
    append(b, ",qmi-board-id="); number(b, id->qmi_board_id, 10, 0);
    if (id->variant_length) {
        append(b, ",variant=");
        for (i = 0; i < id->variant_length; ++i) {
            uint8_t ch = (uint8_t)id->variant[i];
            if (ch < 0x21U || ch > 0x7eU || ch == ',')
                return QCC2072_INVALID_ARGUMENT;
            b->bytes[b->length++] = ch;
        }
    }
    return QCC2072_OK;
}

int qcc2072_find_board(const void *bytes, size_t length,
                       const struct qcc2072_board_identity *identity,
                       struct qcc2072_board_match *out)
{
    struct qcc2072_board_match result = {0};
    struct name_builder wanted;
    struct cursor outer, inner;
    struct qcc2072_slice group, body, name, data;
    uint32_t kind, subkind, budget = QCC2072_MAX_IES, matched = 0;
    int r, n;
    if (!out) return QCC2072_INVALID_ARGUMENT;
    *out = result;
    if (!bytes || !identity) return QCC2072_INVALID_ARGUMENT;
    if (length > QCC2072_MAX_BOARD_FILE_BYTES) return QCC2072_TOO_LARGE;
    r = board_name(identity, &wanted);
    if (r) return r;
    r = container(&outer, bytes, length, "QCA-ATH12K-BOARD", sizeof("QCA-ATH12K-BOARD") - 1U, &budget);
    if (r) return r;
    while ((r = next(&outer, &kind, &group)) > 0) {
        uint32_t names = 0, data_count = 0, matching_names = 0;
        if (kind > 1U) continue;
        inner.bytes = group.bytes; inner.length = group.length;
        inner.pos = 0; inner.budget = &budget;
        name.bytes = data.bytes = 0; name.length = data.length = 0;
        while ((n = next(&inner, &subkind, &body)) > 0) {
            if (subkind == 0U) {
                size_t i, name_length = body.length;
                if (name_length && body.bytes[name_length - 1U] == 0) --name_length;
                if (name_length == 0U || name_length > QCC2072_MAX_BOARD_NAME || data_count)
                    return QCC2072_BAD_CONTAINER;
                for (i = 0; i < name_length; ++i)
                    if (body.bytes[i] < 0x20U || body.bytes[i] > 0x7eU)
                        return QCC2072_BAD_CONTAINER;
                ++names;
                if (kind == 0U && name_length == wanted.length &&
                    equal(body.bytes, wanted.bytes, wanted.length)) {
                    ++matching_names; name = body;
                }
            } else if (subkind == 1U) {
                if (++data_count != 1U) return QCC2072_DUPLICATE;
                if (!names || !body.length || body.length > QCC2072_MAX_BOARD_BYTES)
                    return QCC2072_BAD_CONTAINER;
                data = body;
            }
        }
        if (n < 0) return n;
        if (!names || data_count != 1U) return QCC2072_BAD_CONTAINER;
        if (kind == 0U) { ++result.board_records; result.board_names += names; }
        if (matching_names) {
            if (matching_names != 1U || ++matched != 1U) return QCC2072_DUPLICATE;
            result.name = name; result.data = data;
        }
    }
    if (r < 0) return r;
    *out = result; /* Counts describe a fully parsed container even when no match. */
    return matched ? QCC2072_OK : QCC2072_BOARD_NOT_FOUND;
}

const char *qcc2072_result_name(int result)
{
    switch (result) {
    case QCC2072_OK: return "OK";
    case QCC2072_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
    case QCC2072_TOO_LARGE: return "TOO_LARGE";
    case QCC2072_BAD_CONTAINER: return "BAD_CONTAINER";
    case QCC2072_TRUNCATED: return "TRUNCATED";
    case QCC2072_DUPLICATE: return "DUPLICATE";
    case QCC2072_MISSING_IMAGE: return "MISSING_IMAGE";
    case QCC2072_IDENTITY_UNKNOWN: return "IDENTITY_UNKNOWN";
    case QCC2072_WRONG_DEVICE: return "WRONG_DEVICE";
    case QCC2072_BOARD_NOT_FOUND: return "BOARD_NOT_FOUND";
    case QCC2072_READ_FAILED: return "READ_FAILED";
    case QCC2072_BAD_REGISTER: return "BAD_REGISTER";
    case QCC2072_BAR_MISMATCH: return "BAR_MISMATCH";
    case QCC2072_DEVICE_NOT_QUIESCENT: return "DEVICE_NOT_QUIESCENT";
    default: return "UNKNOWN_ERROR";
    }
}

int qcc2072_find_pci_regdb(const void *bytes, size_t length, struct qcc2072_slice *out)
{
    struct cursor c; struct qcc2072_slice record, data = {0};
    uint32_t kind, budget = QCC2072_MAX_IES; int r, found = 0;
    if (!out || !bytes) return QCC2072_INVALID_ARGUMENT;
    *out = data;
    if (length > QCC2072_MAX_BOARD_FILE_BYTES) return QCC2072_TOO_LARGE;
    r = container(&c, bytes, length, "QCA-ATH12K-BOARD", sizeof("QCA-ATH12K-BOARD")-1, &budget);
    if (r) return r;
    while ((r = next(&c, &kind, &record)) > 0) {
        if (kind != 1) continue;
        struct cursor inner = {record.bytes, record.length, 0, &budget};
        struct qcc2072_slice item, candidate = {0}; uint32_t tag; int match = 0, x;
        while ((x = next(&inner, &tag, &item)) > 0) {
            if (tag == 0 && item.length == 7 && equal(item.bytes, (const uint8_t *)"bus=pci", 7)) {
                if (match) return QCC2072_DUPLICATE;
                match = 1;
            } else if (tag == 1) {
                if (candidate.bytes || !item.length || item.length > QCC2072_MAX_BOARD_BYTES) return QCC2072_BAD_CONTAINER;
                candidate = item;
            }
        }
        if (x < 0) return x;
        if (match) {
            if (found) return QCC2072_DUPLICATE;
            if (!candidate.bytes) return QCC2072_BAD_CONTAINER;
            data = candidate; found = 1;
        }
    }
    if (r < 0) return r;
    if (!found) return QCC2072_BOARD_NOT_FOUND;
    *out = data; return 0;
}
