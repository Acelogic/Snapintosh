/* SPDX-License-Identifier: MIT */
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct air_sampler {
  uint64_t word;
  unsigned s_address, t_address, r_address, mag_linear, min_linear, mip_filter, pixel_coords, compare, aniso, border;
  float lod_min, lod_max;
};
void air_sampler_decode(uint64_t w, struct air_sampler *s);
void air_sampler_a8xx(const struct air_sampler *s, uint32_t d[4]);
unsigned air_sampler_compare_to_adreno(unsigned air_compare);   /* 0xffffffff for an invalid value */
int air_sampler_json(const struct air_sampler *s, char *out, size_t n);
#ifdef __cplusplus
}
#endif
