/* SPDX-License-Identifier: MIT */
#ifndef SNAP_NATIVE_WPA2_CRYPTO_H
#define SNAP_NATIVE_WPA2_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void snap_wpa2_hmac(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t[20]);
int snap_wpa2_unwrap(const uint8_t[16], const uint8_t *, size_t, uint8_t *);
void snap_wpa2_clear(void *, size_t);
#ifdef __cplusplus
}
#endif
#endif
