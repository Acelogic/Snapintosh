/* SPDX-License-Identifier: MIT */
#include "native-rsn.h"

const uint8_t snap_rsn_own[SNAP_RSN_OWN_LENGTH] = {
    48, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0};
#define SUITE(type) (0x000fac00U | (type))
enum { CCMP = SUITE(4), AKM_PSK = SUITE(2), IEEE8021X = SUITE(1), BIP_CMAC = SUITE(6) };

static uint32_t suite(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static void zero(void *v, size_t n) { uint8_t *p = (uint8_t *)v; while (n--) *p++ = 0; }

int snap_rsn_parse(const uint8_t *e, size_t n, struct snap_rsn *o)
{
    if (!o) return SNAP_RSN_MALFORMED;
    zero(o, sizeof(*o));
    if (!e || n < 2 || e[0] != 48 || (size_t)e[1] + 2U != n) return SNAP_RSN_MALFORMED;
    const uint8_t *p = e + 2;
    size_t left = e[1];
    if (left < 2) return SNAP_RSN_MALFORMED;
    o->version = le16(p); p += 2; left -= 2;
    if (o->version != 1) return SNAP_RSN_VERSION;
    /* IEEE 802.11-2020 9.4.2.24.1 defaults for omitted trailing fields */
    o->group = CCMP; o->pairwise_count = 1; o->pairwise_ccmp = 1; o->akm_count = 1; o->akm_other = 1;
    o->group_mgmt = BIP_CMAC;
    if (!left) return SNAP_RSN_OK;
    if (left < 4) return SNAP_RSN_MALFORMED;
    o->group = suite(p); p += 4; left -= 4;
    if (!left) return SNAP_RSN_OK;
    if (left < 2) return SNAP_RSN_MALFORMED;
    unsigned count = le16(p); p += 2; left -= 2;
    if (!count || count > left / 4) return SNAP_RSN_MALFORMED;      /* wpa_supplicant: count 0 is invalid */
    o->pairwise_count = (uint16_t)count; o->pairwise_ccmp = 0;
    for (unsigned i = 0; i < count; i++, p += 4, left -= 4) {
        if (suite(p) == CCMP) o->pairwise_ccmp = 1; else o->pairwise_other = 1;
    }
    if (!left) return SNAP_RSN_OK;
    if (left < 2) return SNAP_RSN_MALFORMED;
    count = le16(p); p += 2; left -= 2;
    if (!count || count > left / 4) return SNAP_RSN_MALFORMED;
    o->akm_count = (uint16_t)count; o->akm_other = 0;
    for (unsigned i = 0; i < count; i++, p += 4, left -= 4) {
        if (suite(p) == AKM_PSK) o->akm_psk = 1; else o->akm_other = 1;
    }
    if (!left) return SNAP_RSN_OK;
    if (left < 2) return SNAP_RSN_MALFORMED;
    o->capabilities = le16(p); p += 2; left -= 2;
    if (left < 2) return SNAP_RSN_OK;                                 /* one trailing byte is ignored */
    count = le16(p); p += 2; left -= 2;
    if (count > left / 16) return SNAP_RSN_MALFORMED;
    o->pmkid_count = (uint16_t)count; p += 16U * count; left -= 16U * count;
    if (left >= 4) { o->group_mgmt = suite(p); o->has_group_mgmt = 1; }
    return SNAP_RSN_OK;   /* any further bytes are ignored (wpa_parse_wpa_ie_rsn) */
}

int snap_rsn_ap_policy(const uint8_t *e, size_t n, uint16_t *bits)
{
    struct snap_rsn r;
    if (bits) *bits = 0;
    if (n > SNAP_RSN_MAX_ELEMENT) return SNAP_RSN_TOO_LONG;
    int rc = snap_rsn_parse(e, n, &r);
    if (rc) return rc;
    if (r.group != CCMP) return SNAP_RSN_GROUP_CIPHER;
    if (!r.pairwise_ccmp) return SNAP_RSN_NO_CCMP_PAIRWISE;
    if (!r.akm_psk) return SNAP_RSN_NO_PSK;
    if (r.capabilities & SNAP_RSN_CAP_MFPR) { if (bits) *bits = SNAP_RSN_CAP_MFPR; return SNAP_RSN_PMF_REQUIRED; }
    uint16_t extra = (uint16_t)(r.capabilities & ~(SNAP_RSN_CAP_ALLOWED | SNAP_RSN_CAP_MFPC));
    if (extra) { if (bits) *bits = extra; return SNAP_RSN_CAPABILITY; }
    return SNAP_RSN_OK;
}

int snap_rsn_is_own(const uint8_t *e, size_t n)
{
    if (!e || n != SNAP_RSN_OWN_LENGTH) return 0;
    unsigned d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned)(e[i] ^ snap_rsn_own[i]);
    return !d;
}

int snap_rsn_find(const uint8_t *ies, size_t n, const uint8_t **rsn, size_t *rsn_length,
                  const uint8_t **rsnxe, size_t *rsnxe_length)
{
    const uint8_t *r = 0, *x = 0;
    size_t rn = 0, xn = 0, at = 0;
    unsigned count = 0, wpa1 = 0;
    if (rsn) *rsn = 0;
    if (rsn_length) *rsn_length = 0;
    if (rsnxe) *rsnxe = 0;
    if (rsnxe_length) *rsnxe_length = 0;
    if (!ies && n) return SNAP_RSN_MALFORMED;
    while (at < n) {
        if (n - at < 2 || (size_t)ies[at + 1] > n - at - 2) return SNAP_RSN_MALFORMED;
        const uint8_t *e = ies + at;
        size_t len = (size_t)e[1] + 2U;
        if (e[0] == 48) { if (!count++) { r = e; rn = len; } }
        else if (e[0] == 244 && !x) { x = e; xn = len; }
        else if (e[0] == 221 && len >= 6 && e[2] == 0x00 && e[3] == 0x50 && e[4] == 0xf2 && e[5] == 1) wpa1 = 1;
        at += len;
    }
    if (rsn) *rsn = r;
    if (rsn_length) *rsn_length = rn;
    if (rsnxe) *rsnxe = x;
    if (rsnxe_length) *rsnxe_length = xn;
    if (count > 1) return SNAP_RSN_DUPLICATE;
    if (wpa1) return SNAP_RSN_WPA1;
    return count ? SNAP_RSN_OK : SNAP_RSN_ABSENT;
}

const char *snap_rsn_reason(int reason)
{
    static const char *const names[SNAP_RSN_REASONS] = {
        "ok", "no RSN element", "malformed RSN element", "RSN version is not 1", "two RSN elements",
        "WPA1 element present (WPA/WPA2 mixed mode)", "group cipher is not CCMP",
        "no CCMP pairwise cipher", "no PSK AKM (SAE-only or enterprise)",
        "PMF required (MFPR) and PMF is not supported", "RSN capability bits we cannot honour",
        "RSN element longer than kept"};
    return reason >= 0 && reason < SNAP_RSN_REASONS ? names[reason] : "unknown";
}
