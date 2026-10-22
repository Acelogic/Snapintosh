/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_RSN_H
#define SNAP_NATIVE_RSN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* RSN element policy shared by native-station, qcc2072-assoc, snap_wpa2 and the bridges
 * (re/connect/FAILURES.md 7-16). We join WPA2-PSK with CCMP-128 and no PMF,
 * the way wpa_supplicant does with pmf=0:
 *  - our own (re)association/M2 element is always SNAP_RSN_OWN (capabilities 0);
 *  - an AP element is joinable when its group cipher is CCMP, its pairwise list holds CCMP
 *    and its AKM list holds PSK (other AKMs such as SAE are ignored: WPA3 transition mode);
 *  - AP capabilities may set pre-auth, no-pairwise and the replay-counter fields (0x003f) and
 *    MFPC (0x0080: PMF capable, not negotiated by us); MFPR (0x0040) and every other bit
 *    are refused with the bits named. Trailing bytes are ignored, as wpa_supplicant does. */
enum {
    SNAP_RSN_OK = 0, SNAP_RSN_ABSENT, SNAP_RSN_MALFORMED, SNAP_RSN_VERSION, SNAP_RSN_DUPLICATE,
    SNAP_RSN_WPA1, SNAP_RSN_GROUP_CIPHER, SNAP_RSN_NO_CCMP_PAIRWISE, SNAP_RSN_NO_PSK,
    SNAP_RSN_PMF_REQUIRED, SNAP_RSN_CAPABILITY, SNAP_RSN_TOO_LONG, SNAP_RSN_REASONS
};
#define SNAP_RSN_OWN_LENGTH 22U
#define SNAP_RSN_MAX_ELEMENT 80U   /* longest AP element a bridge keeps (beacons carry no PMKIDs) */
#define SNAP_RSN_MAX_RSNXE 16U
#define SNAP_RSN_CAP_ALLOWED 0x003fU
#define SNAP_RSN_CAP_MFPR 0x0040U
#define SNAP_RSN_CAP_MFPC 0x0080U
extern const uint8_t snap_rsn_own[SNAP_RSN_OWN_LENGTH];
struct snap_rsn {
    uint16_t version, capabilities, pairwise_count, akm_count, pmkid_count;
    uint32_t group, group_mgmt;          /* suite selectors, big-endian OUI<<8|type */
    uint8_t pairwise_ccmp, pairwise_other, akm_psk, akm_other, has_group_mgmt;
};
/* element = id 48, length, body. Fills defaults for absent optional fields (IEEE 802.11). */
int snap_rsn_parse(const uint8_t *element, size_t length, struct snap_rsn *out);
/* SNAP_RSN_OK if we can join this AP element; bits gets the refused capability bits. */
int snap_rsn_ap_policy(const uint8_t *element, size_t length, uint16_t *bits);
int snap_rsn_is_own(const uint8_t *element, size_t length);
/* Walks a BSS's elements: the RSN element (exactly one), the first RSNXE (244) if any; a WPA1
 * vendor element is reported. Pointers point into ies; lengths are whole elements. */
int snap_rsn_find(const uint8_t *ies, size_t length, const uint8_t **rsn, size_t *rsn_length,
                  const uint8_t **rsnxe, size_t *rsnxe_length);
/* Short fixed text for logs; never secret material. */
const char *snap_rsn_reason(int reason);
#ifdef __cplusplus
}
#endif
#endif
