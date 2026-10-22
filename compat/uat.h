/* SPDX-License-Identifier: MIT */
#pragma once
#include "sptm.h"

/* Read-only UAT information adapter for the audited sptm-mac-v1 private
 * address-space mode. The loader reserves three 16K pages: state, L1, L2.
 * This does not implement GPU mappings, command submission or DMA. */
struct uat_config {
    uint64_t reserved_pa, mode, va_bits, segment_limit;
};
enum sptm_result uat_get_info(const struct uat_config *config,
    const struct sptm_aperture *aperture, uint64_t query, uint64_t *value);
/* Read-only admission retaining the three initial private-mode pages.
 * Changed state/tables require a graphics ownership/drain contract. */
enum sptm_result uat_power_idle(const struct uat_config *config,
    const struct sptm_aperture *aperture, const struct sptm_memory *memory);
