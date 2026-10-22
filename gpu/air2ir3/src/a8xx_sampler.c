/* SPDX-License-Identifier: MIT */
/* The descriptor packing follows Mesa's fd6_sampler_state_create<A8XX>
 * (src/gallium/drivers/freedreno/a6xx/fd6_texture.cc), which carries:
 *   Copyright © 2016 Rob Clark <robclark@freedesktop.org>
 *   Copyright © 2018 Google, Inc.
 *   SPDX-License-Identifier: MIT
 */
/* a8xx_sampler.c - decode an AIR constexpr sampler word (@__air_sampler_state = [2 x i64] [W, 0])
 * and build the Adreno A8XX TEX_SAMP descriptor for it, following Mesa gallium
 * fd6_sampler_state_create<A8XX> (src/gallium/drivers/freedreno/a6xx/fd6_texture.cc).
 *
 * AIR bit layout: scratchpad/adreno/local-cts/re/sampler/AIR-CONSTEXPR-SAMPLER.txt
 * (PROVEN for address/filter/mip/coord/aniso-4x/lod clamps/border; the rest INFERRED).
 *
 * compare_func (bits 16-19) is in MSL enum order, PROVEN for all 9 values with this Mac's
 * toolchain (tests/regress.py "compare_funcs"): 1 less, 2 less_equal, 3 greater, 4 greater_equal,
 * 5 equal, 6 not_equal, 7 always, 8 never.  The front end also writes 8 for "no compare_func":
 * none and never are the same AIR word.  Metal (M3 Max) returns 0 from sample_compare with such a
 * sampler, i.e. never semantics, and the field is ignored by non-compare sampling, so 8 maps to
 * FUNC_NEVER.  Adreno's COMPARE_FUNC uses a different order (adreno_compare_func), so every other
 * value has to be translated; the prototype copied the AIR value and got 5 of 7 wrong.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "a8xx_sampler.h"
#include "adreno_common.xml.h"
#include "a6xx_enums.xml.h"
#include "a8xx_enums.xml.h"
#include "a8xx_descriptors.xml.h"

static float half_to_float(uint16_t h) {
  uint32_t s = (h >> 15) & 1, e = (h >> 10) & 0x1f, m = h & 0x3ff;
  float v;
  if (e == 0) v = ldexpf((float)m, -24);
  else if (e == 31) v = m ? NAN : INFINITY;
  else v = ldexpf((float)(m | 0x400), (int)e - 25);
  return s ? -v : v;
}

static const char *addr_name[8] = {"clamp_to_zero_or_border", "clamp_to_edge", "repeat", "mirrored_repeat",
                                   "mirror_clamp_to_edge", "addr5", "addr6", "addr7"};
/* AIR / MSL compare_func order -> name and Adreno COMPARE_FUNC.  0 is never emitted by the front end;
 * it is treated like 8. */
static const char *cmp_name[9] = {"none_or_never", "less", "less_equal", "greater", "greater_equal", "equal",
                                  "not_equal", "always", "none_or_never"};
static const enum adreno_compare_func cmp_adreno[9] = {FUNC_NEVER, FUNC_LESS, FUNC_LEQUAL, FUNC_GREATER, FUNC_GEQUAL,
                                                       FUNC_EQUAL, FUNC_NOTEQUAL, FUNC_ALWAYS, FUNC_NEVER};
unsigned air_sampler_compare_to_adreno(unsigned air_compare) {
  return air_compare < 9 ? (unsigned)cmp_adreno[air_compare] : 0xffffffffu;
}
static const char *border_name[4] = {"transparent_black", "opaque_black", "opaque_white", "border3"};

static enum a6xx_tex_clamp clamp_of(unsigned a, int *needs_border) {
  switch (a) {
  case 0: *needs_border = 1; return A6XX_TEX_CLAMP_TO_BORDER;   /* clamp_to_zero / clamp_to_border */
  case 1: return A6XX_TEX_CLAMP_TO_EDGE;
  case 2: return A6XX_TEX_REPEAT;
  case 3: return A6XX_TEX_MIRROR_REPEAT;
  case 4: return A6XX_TEX_MIRROR_CLAMP;
  default: return A6XX_TEX_CLAMP_TO_EDGE;
  }
}

void air_sampler_decode(uint64_t w, struct air_sampler *s) {
  memset(s, 0, sizeof(*s));
  s->word = w;
  s->s_address = w & 7; s->t_address = (w >> 3) & 7; s->r_address = (w >> 6) & 7;
  s->mag_linear = (w >> 9) & 1; s->min_linear = (w >> 11) & 1;
  s->mip_filter = (w >> 13) & 3; s->pixel_coords = (w >> 15) & 1;
  s->compare = (w >> 16) & 0xf; s->aniso = ((w >> 20) & 0xf) + 1;
  s->lod_min = half_to_float((w >> 24) & 0xffff); s->lod_max = half_to_float((w >> 40) & 0xffff);
  s->border = (w >> 56) & 3;
}

void air_sampler_a8xx(const struct air_sampler *s, uint32_t d[4]) {
  int needs_border = 0;
  unsigned aniso = s->aniso > 1 ? (unsigned)(32 - __builtin_clz((s->aniso >> 1) < 8 ? (s->aniso >> 1) : 8)) : 0;
  const float MAX_LOD = 4095.0f / 256.0f;
  enum a6xx_tex_filter mag = s->mag_linear ? (aniso ? A6XX_TEX_ANISO : A6XX_TEX_LINEAR) : A6XX_TEX_NEAREST;
  enum a6xx_tex_filter min = s->min_linear ? (aniso ? A6XX_TEX_ANISO : A6XX_TEX_LINEAR) : A6XX_TEX_NEAREST;
  d[0] = (s->mip_filter == 2 ? A8XX_TEX_SAMP_0_MIPFILTER_LINEAR_NEAR : 0) |
         (s->mip_filter == 0 ? A8XX_TEX_SAMP_0_MIPMAPING_DIS : 0) |
         A8XX_TEX_SAMP_0_XY_MAG(mag) | A8XX_TEX_SAMP_0_XY_MIN(min) |
         A8XX_TEX_SAMP_0_WRAP_S(clamp_of(s->s_address, &needs_border)) |
         A8XX_TEX_SAMP_0_WRAP_T(clamp_of(s->t_address, &needs_border)) |
         A8XX_TEX_SAMP_0_WRAP_R(clamp_of(s->r_address, &needs_border)) |
         A8XX_TEX_SAMP_0_LOD_BIAS(0.0f) | A8XX_TEX_SAMP_0_ANISO((enum a6xx_tex_aniso)aniso);
  float lo, hi;
  if (s->pixel_coords) lo = hi = 0;                       /* unnormalised coordinates sample level 0 only */
  else if (s->mip_filter != 0) { lo = fminf(fmaxf(s->lod_min, 0), MAX_LOD); hi = fminf(fmaxf(s->lod_max, 0), MAX_LOD); }
  else { lo = fminf(fmaxf(s->lod_min, 0), 0.25f); hi = fminf(fmaxf(s->lod_max, 0), 0.25f); }
  int chroma_linear = s->mag_linear && s->min_linear;
  d[1] = A8XX_TEX_SAMP_1_MAX_LOD(hi) | A8XX_TEX_SAMP_1_MIN_LOD(lo) |
         A8XX_TEX_SAMP_1_REDUCTION_MODE(A6XX_REDUCTION_MODE_AVERAGE) |
         A8XX_TEX_SAMP_1_COMPARE_FUNC(cmp_adreno[s->compare < 9 ? s->compare : 8]) |
         (chroma_linear ? A8XX_TEX_SAMP_1_CHROMA_LINEAR : 0) |
         (s->pixel_coords ? A8XX_TEX_SAMP_1_UNNORM_COORDS : 0);
  d[2] = 0; d[3] = 0;
  if (needs_border) {
    /* Metal's three border colours all have a fast-border encoding: no border-colour table needed. */
    enum a6xx_fast_border_color fb = s->border == 2 ? A6XX_BORDER_COLOR_1_1_1_1
                                   : s->border == 1 ? A6XX_BORDER_COLOR_0_0_0_1 : A6XX_BORDER_COLOR_0_0_0_0;
    d[2] |= A8XX_TEX_SAMP_2_FASTBORDERCOLOR(fb) | A8XX_TEX_SAMP_2_FASTBORDERCOLOREN;
  }
}

int air_sampler_json(const struct air_sampler *s, char *out, size_t n) {
  return snprintf(out, n,
    "{\"s_address\":\"%s\",\"t_address\":\"%s\",\"r_address\":\"%s\",\"mag_filter\":\"%s\",\"min_filter\":\"%s\","
    "\"mip_filter\":\"%s\",\"coord\":\"%s\",\"compare_func\":\"%s\",\"air_compare\":%u,\"adreno_compare_func\":%u,\"max_anisotropy\":%u,"
    "\"lod_min_clamp\":%g,\"lod_max_clamp\":%g,\"border_color\":\"%s\"}",
    addr_name[s->s_address], addr_name[s->t_address], addr_name[s->r_address],
    s->mag_linear ? "linear" : "nearest", s->min_linear ? "linear" : "nearest",
    s->mip_filter == 0 ? "none" : s->mip_filter == 1 ? "nearest" : "linear",
    s->pixel_coords ? "pixel" : "normalized", s->compare < 9 ? cmp_name[s->compare] : "?", s->compare,
    s->compare < 9 ? (unsigned)cmp_adreno[s->compare] : 99u,
    s->aniso, s->lod_min, s->lod_max, border_name[s->border]);
}
