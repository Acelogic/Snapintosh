/* SPDX-License-Identifier: MIT */
#include "qcc2072-qmi.h"
static uint16_t get16(const uint8_t *p)
{ return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static uint64_t get64(const uint8_t *p)
{ return (uint64_t)get32(p) | ((uint64_t)get32(p+4)<<32); }
static void put16(uint8_t *p, uint16_t v)
{ p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{ put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void copy(uint8_t *d, const uint8_t *s, size_t n)
{ size_t i; for (i = 0; i < n; ++i) d[i] = s[i]; }
static int quarantine(struct qcc2072_qmi_session *s, int reason)
{ s->state = QCC2072_QMI_QUARANTINE; s->quarantine_reason = reason; return reason; }
static int waiting(enum qcc2072_qmi_state state)
{ return state == QCC2072_QMI_WAIT_MEMORY || state == QCC2072_QMI_WAIT_CAP || state == QCC2072_QMI_WAIT_BDF_ACK; }
int qcc2072_qmi_init(struct qcc2072_qmi_session *s, uint32_t node, uint32_t port,
                     uint64_t generation, uint64_t owner, uint64_t now, uint32_t timeout)
{
    struct qcc2072_qmi_session initial = {0};
    if (!s) return QCC2072_INVALID_ARGUMENT;
    /* Failed initialization cannot leave a usable zero-initialized WAIT_MEMORY. */
    initial.state = QCC2072_QMI_QUARANTINE; *s = initial;
    if (node >= 0xfffffffeU || !port || port >= 0xfffffffeU ||
        !generation || !owner || !timeout || timeout > 120000U || now > UINT64_MAX - timeout)
        return QCC2072_INVALID_ARGUMENT;
    initial.state = QCC2072_QMI_WAIT_MEMORY;
    initial.node = node; initial.port = port; initial.generation = generation;
    initial.owner_cookie = owner; initial.last_ms = now; initial.deadline_ms = now + timeout;
    initial.timeout_ms = timeout; initial.next_transaction = 1;
    *s = initial; return QCC2072_OK;
}
int qcc2072_qmi_tick(struct qcc2072_qmi_session *s, uint64_t now)
{
    if (!s) return QCC2072_INVALID_ARGUMENT;
    if (s->state == QCC2072_QMI_QUARANTINE) return QCC2072_QUARANTINED;
    if (now < s->last_ms || now > UINT64_MAX - s->timeout_ms)
        return quarantine(s, QCC2072_SESSION_STALE);
    if (waiting(s->state) && now >= s->deadline_ms)
        return quarantine(s, QCC2072_DEADLINE);
    s->last_ms = now; return QCC2072_OK;
}
int qcc2072_qmi_abort(struct qcc2072_qmi_session *s)
{ return s ? quarantine(s, QCC2072_QUARANTINED) : QCC2072_INVALID_ARGUMENT; }
static int request_start(struct qcc2072_qmi_session *s, uint64_t now,
                         uint8_t *p, uint16_t message, uint16_t payload,
                         enum qcc2072_qmi_state next)
{
    if (!s->next_transaction) return quarantine(s, QCC2072_STALE_TRANSACTION);
    p[0] = 0; put16(p + 1, s->next_transaction); put16(p + 3, message); put16(p + 5, payload);
    s->pending_transaction = s->next_transaction++;
    s->pending_message = message; s->deadline_ms = now + s->timeout_ms;
    s->state = next; return QCC2072_OK;
}
int qcc2072_qmi_cap_request(struct qcc2072_qmi_session *s, uint64_t now,
                            void *packet, size_t capacity, size_t *written)
{
    int r;
    if (!written) return QCC2072_INVALID_ARGUMENT;
    *written = 0;
    if (!s || !packet) return QCC2072_INVALID_ARGUMENT;
    r = qcc2072_qmi_tick(s, now); if (r) return r;
    if (s->state != QCC2072_QMI_MEMORY_OBSERVED) return QCC2072_BAD_STATE;
    if (capacity < 7U) return QCC2072_OUTPUT_TOO_SMALL;
    r = request_start(s, now, packet, QCC2072_QMI_CAP, 0, QCC2072_QMI_WAIT_CAP);
    if (!r) *written = 7U;
    return r;
}
int qcc2072_qmi_receive(struct qcc2072_qmi_session *s, uint32_t node, uint32_t port,
                        uint64_t generation, uint64_t owner, uint64_t now,
                        const void *packet, size_t length)
{
    const uint8_t *p = packet;
    uint32_t seen[8] = {0};
    uint32_t chip = 0, family = 0, board = 0;
    struct qcc2072_qmi_device_memory memory[4]={{0}};
    uint8_t has_memory=0;
    uint16_t result = 0, error = 0, message, transaction;
    size_t pos = 7U;
    int r, has_result = 0, has_chip = 0, has_board = 0;
    if (!s || !p) return QCC2072_INVALID_ARGUMENT;
    if (s->state == QCC2072_QMI_QUARANTINE) return QCC2072_QUARANTINED;
    if (node != s->node || port != s->port) return QCC2072_FOREIGN_PEER;
    if (generation != s->generation || owner != s->owner_cookie)
        return QCC2072_SESSION_STALE;
    r = qcc2072_qmi_tick(s, now); if (r) return r;
    if (length < 7U || length > QCC2072_QMI_PACKET_MAX ||
        (size_t)get16(p + 5) != length - 7U) return QCC2072_BAD_WIRE;
    message = get16(p + 3); transaction = get16(p + 1);
    if (p[0] == 4U) {
        if (transaction || length != 7U) return QCC2072_BAD_WIRE;
        if (message == QCC2072_QMI_MEM_READY && s->state == QCC2072_QMI_WAIT_MEMORY) {
            s->state = QCC2072_QMI_MEMORY_OBSERVED; return QCC2072_OK;
        }
        /* Firmware ready is deliberately a later, unsupported admission gate. */
        return QCC2072_BAD_STATE;
    }
    if (p[0] != 2U) return QCC2072_BAD_WIRE;
    if ((s->state != QCC2072_QMI_WAIT_CAP && s->state != QCC2072_QMI_WAIT_BDF_ACK) ||
        !transaction || transaction != s->pending_transaction || message != s->pending_message)
        return QCC2072_STALE_TRANSACTION;
    while (pos < length) {
        uint8_t type;
        uint16_t n;
        const uint8_t *value;
        if (length - pos < 3U) return QCC2072_BAD_WIRE;
        type = p[pos]; n = get16(p + pos + 1U); pos += 3U;
        if ((size_t)n > length - pos || (seen[type >> 5] & (1U << (type & 31U))))
            return QCC2072_BAD_WIRE;
        seen[type >> 5] |= 1U << (type & 31U); value = p + pos; pos += n;
        if (type == 2U) {
            if (n != 4U) return QCC2072_BAD_WIRE;
            result = get16(value); error = get16(value + 2); has_result = 1;
        } else if (message == QCC2072_QMI_CAP && type == 0x10U) {
            if (n != 8U) return QCC2072_BAD_WIRE;
            chip = get32(value); family = get32(value + 4); has_chip = 1;
        } else if (message == QCC2072_QMI_CAP && type == 0x11U) {
            if (n != 4U) return QCC2072_BAD_WIRE;
            board = get32(value); has_board = 1;
        } else if (message == QCC2072_QMI_CAP && type == 0x1cU) {
            if(n!=64U)return QCC2072_BAD_WIRE;
            for(unsigned i=0;i<4;i++) {
                memory[i].start=get64(value+i*16);memory[i].size=get64(value+i*16+8);
                if(memory[i].start>UINT64_MAX-memory[i].size)return QCC2072_BAD_WIRE;
            }
            has_memory=1;
        }
    }
    if (!has_result) return QCC2072_BAD_WIRE;
    if (result || error) {
        s->last_peer_result = result; s->last_peer_error = error;
        return quarantine(s, QCC2072_PEER_FAILED);
    }
    if (message == QCC2072_QMI_CAP) {
        /* The A16's QCC2072 sends no board_info TLV; ath12k then uses
         * ATH12K_BOARD_ID_DEFAULT (0xff) as the BDF file id. */
        if (!has_board) board = 0xffU;
        if (!has_chip || chip == UINT32_MAX || board == UINT32_MAX)
            return QCC2072_BAD_WIRE;
        for(unsigned i=0;i<4;i++)s->device_memory[i]=memory[i];
        s->device_memory_observed=has_memory;
        s->chip_id = chip; s->chip_family = family; s->board_id = board;
        s->state = QCC2072_QMI_CAP_OBSERVED;
    } else {
        if (!s->board || !s->pending_bytes || s->acknowledged_bytes > s->board_size ||
            s->pending_bytes > s->board_size - s->acknowledged_bytes)
            return quarantine(s, QCC2072_BAD_STATE);
        s->acknowledged_bytes += s->pending_bytes; s->pending_bytes = 0; ++s->segment_id;
        s->state = s->acknowledged_bytes == s->board_size ? QCC2072_QMI_BDF_ACKED : QCC2072_QMI_BDF_NEXT;
    }
    s->pending_transaction = 0; s->pending_message = 0;
    return QCC2072_OK;
}
int qcc2072_qmi_board_begin(struct qcc2072_qmi_session *s, const void *board,
                            size_t length, uint32_t pci, uint32_t subsystem, uint8_t verified)
{
    if (!s || !board || !length || length > QCC2072_MAX_BOARD_BYTES ||
        (uintptr_t)board > UINTPTR_MAX - length) return QCC2072_INVALID_ARGUMENT;
    if (s->state == QCC2072_QMI_QUARANTINE) return QCC2072_QUARANTINED;
    if (s->state != QCC2072_QMI_CAP_OBSERVED && s->state != QCC2072_QMI_BDF_ACKED) return QCC2072_BAD_STATE;
    if (pci != 0x111217cbU || subsystem != 0xe14f105bU) return QCC2072_WRONG_DEVICE;
    if (verified != 1U) return QCC2072_IDENTITY_UNKNOWN;
    s->board = board; s->board_size = length; s->acknowledged_bytes = 0;
    s->pending_bytes = 0; s->segment_id = 0; s->bdf_type = 1; s->state = QCC2072_QMI_BDF_NEXT;
    return QCC2072_OK;
}
static size_t scalar(uint8_t *p, uint8_t type, uint32_t value, unsigned bytes)
{
    p[0] = type; put16(p + 1, (uint16_t)bytes);
    if (bytes == 1U) p[3] = (uint8_t)value; else put32(p + 3, value);
    return 3U + bytes;
}
int qcc2072_qmi_board_request(struct qcc2072_qmi_session *s, uint64_t now,
                              void *packet, size_t capacity, size_t *written)
{
    uint8_t *p = packet;
    size_t remaining, chunk, pos = 7U;
    int r;
    if (!written) return QCC2072_INVALID_ARGUMENT;
    *written = 0;
    if (!s || !p) return QCC2072_INVALID_ARGUMENT;
    r = qcc2072_qmi_tick(s, now); if (r) return r;
    if (s->state != QCC2072_QMI_BDF_NEXT || !s->board || s->acknowledged_bytes >= s->board_size)
        return QCC2072_BAD_STATE;
    remaining = s->board_size - s->acknowledged_bytes;
    chunk = remaining > QCC2072_QMI_DATA_MAX ? QCC2072_QMI_DATA_MAX : remaining;
    if (capacity < chunk + 45U) return QCC2072_OUTPUT_TOO_SMALL;
    /* Refuse overlapping immutable source/output, which would corrupt later segments. */
    if ((uintptr_t)p > UINTPTR_MAX - (chunk + 45U) ||
        ((uintptr_t)p < (uintptr_t)s->board + s->board_size &&
         (uintptr_t)s->board < (uintptr_t)p + chunk + 45U)) return QCC2072_INVALID_ARGUMENT;
    r = request_start(s, now, p, QCC2072_QMI_BDF, (uint16_t)(chunk + 38U), QCC2072_QMI_WAIT_BDF_ACK);
    if (r) return r;
    pos += scalar(p + pos, 1U, 1U, 1U);
    pos += scalar(p + pos, 0x10U, s->board_id, 4U);
    pos += scalar(p + pos, 0x11U, (uint32_t)remaining, 4U);
    pos += scalar(p + pos, 0x12U, s->segment_id, 4U);
    p[pos] = 0x13U; put16(p + pos + 1U, (uint16_t)(chunk + 2U));
    put16(p + pos + 3U, (uint16_t)chunk); copy(p + pos + 5U, s->board + s->acknowledged_bytes, chunk);
    pos += chunk + 5U;
    pos += scalar(p + pos, 0x14U, remaining == chunk, 1U);
    pos += scalar(p + pos, 0x15U, s->bdf_type, 1U);
    s->pending_bytes = chunk; *written = pos;
    return QCC2072_OK;
}

int qcc2072_qmi_regdb_begin(struct qcc2072_qmi_session *s, const void *data,
                            size_t length, uint8_t verified)
{
    int r = qcc2072_qmi_board_begin(s, data, length, 0x111217cbU, 0xe14f105bU, verified);
    if (!r) s->bdf_type = 4;
    return r;
}
