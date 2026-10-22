/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayCopy.h - layer-0 IOSurface -> firmware (GOP) framebuffer copy.
 *
 * Header-only C so the kext (AdrenoDisplay.cpp) and the host E2E test
 * (tools/test-adreno-display-present.c, driven by tools/test-adreno-display.py)
 * run the same bytes. No kernel or libc dependency beyond memcpy.
 *
 * Contract:
 *   - The source is a CPU mapping of the whole surface allocation: `length`
 *     bytes at `base`; the image starts at `offset`, rows are `row_bytes`
 *     apart. The destination is the scanout mapping: `length` bytes, rows
 *     `row_bytes` apart, 32-bit little-endian BGRX (the A16 GOP, format 1).
 *   - The copied rectangle is the top-left overlap of the two images, 1:1.
 *     Nothing outside it is read or written.
 *   - Every byte range is proven inside its mapping before the first access,
 *     with overflow-checked arithmetic; a refused copy touches nothing.
 *   - `maintain` (optional) is called for exactly the source bytes of a row
 *     immediately before that row is read (FROM_DEVICE for GPU producers).
 *
 * Formats (IOSurface pixel-format FourCC):
 *   'BGRA' 32bpp, bytes B,G,R,A: copied 1:1 (A lands in the ignored X byte).
 *   'l10r' 32bpp little-endian ARGB2101010, B in bits 0-9 (INFERRED from the
 *          CoreVideo kCVPixelFormatType_ARGB2101010LEPacked definition):
 *          each 10-bit channel is rounded to 8 bits, X = 0xff.
 *   'RGhA' 64bpp, half-float R,G,B,A: each channel is clamped to [0,1] and
 *          rounded to 8 bits with integer arithmetic (NaN -> 0), X = 0xff.
 *          The values are taken as already transfer-encoded (INFERRED); a
 *          linear-light surface would look dark, never corrupt memory.
 */
#ifndef ADRENO_DISPLAY_COPY_H
#define ADRENO_DISPLAY_COPY_H

#include <stdint.h>
#include <string.h>   /* memcpy: libkern in the kext, libc on the host */

#ifdef __cplusplus
extern "C" {
#endif

#define ADRENO_DISPLAY_FORMAT_BGRA 0x42475241u /* 'BGRA' */
#define ADRENO_DISPLAY_FORMAT_L10R 0x6c313072u /* 'l10r' */
#define ADRENO_DISPLAY_FORMAT_RGHA 0x52476841u /* 'RGhA' */

enum {
    ADRENO_DISPLAY_OK = 0,
    ADRENO_DISPLAY_E_ARGS = -1,     /* null pointers, zero geometry */
    ADRENO_DISPLAY_E_FORMAT = -2,   /* unsupported FourCC */
    ADRENO_DISPLAY_E_SOURCE = -3,   /* image does not fit its own rows or allocation */
    ADRENO_DISPLAY_E_DEST = -4,     /* scanout rows do not fit the mapping */
};

struct adreno_display_surface {
    const uint8_t *base;   /* CPU mapping of the whole allocation */
    uint64_t length;       /* bytes mapped at base */
    uint64_t offset;       /* image start within the allocation */
    uint64_t row_bytes;
    uint64_t width, height;
    uint32_t format;
};

struct adreno_display_scanout {
    uint8_t *base;
    uint64_t length;
    uint64_t row_bytes;
    uint64_t width, height;
};

struct adreno_display_copy_result {
    uint64_t width, height;   /* the rectangle actually copied */
    uint64_t bytes_read;      /* source bytes read (== bytes maintained) */
};

typedef void (*adreno_display_maintain_fn)(void *context, const void *address, uint64_t bytes);

static inline uint32_t adreno_display_bytes_per_pixel(uint32_t format)
{
    switch (format) {
    case ADRENO_DISPLAY_FORMAT_BGRA:
    case ADRENO_DISPLAY_FORMAT_L10R:
        return 4;
    case ADRENO_DISPLAY_FORMAT_RGHA:
        return 8;
    default:
        return 0;
    }
}

/* a*b+c <= limit without wrapping. */
static inline int adreno_display_span_fits(uint64_t a, uint64_t b, uint64_t c, uint64_t limit)
{
    if (b && a > UINT64_MAX / b)
        return 0;
    uint64_t product = a * b;
    if (product > UINT64_MAX - c)
        return 0;
    return product + c <= limit;
}

static inline uint8_t adreno_display_unorm10_to_8(uint32_t v)
{
    return (uint8_t)((v * 255u + 511u) / 1023u);
}

static inline uint8_t adreno_display_half_to_8(uint16_t h)
{
    uint32_t e = (h >> 10) & 31u, m = h & 0x3ffu;
    if (h & 0x8000u)
        return 0;                       /* negative (and -0, -inf, negative NaN) */
    if (e == 31)
        return m ? 0 : 255;             /* NaN -> 0, +inf -> 255 */
    if (e >= 15)
        return 255;                     /* >= 1.0 */
    if (e == 0)
        return 0;                       /* subnormal: < 2^-14, rounds to 0 */
    /* value = (1024 + m) * 2^(e - 25); result = round(value * 255). */
    uint32_t num = (1024u + m) * 255u, shift = 25u - e;   /* shift 11..24 */
    return (uint8_t)((num + (1u << (shift - 1))) >> shift);
}

static inline void adreno_display_convert_row(uint32_t format, const uint8_t *src, uint8_t *dst,
                                              uint64_t width)
{
    if (format == ADRENO_DISPLAY_FORMAT_BGRA) {
        memcpy(dst, src, (size_t)(width * 4));
        return;
    }
    if (format == ADRENO_DISPLAY_FORMAT_L10R) {
        for (uint64_t x = 0; x < width; x++) {
            const uint8_t *p = src + x * 4;
            uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                         ((uint32_t)p[3] << 24);
            dst[x * 4 + 0] = adreno_display_unorm10_to_8(v & 0x3ffu);
            dst[x * 4 + 1] = adreno_display_unorm10_to_8((v >> 10) & 0x3ffu);
            dst[x * 4 + 2] = adreno_display_unorm10_to_8((v >> 20) & 0x3ffu);
            dst[x * 4 + 3] = 0xff;
        }
        return;
    }
    /* RGhA */
    for (uint64_t x = 0; x < width; x++) {
        const uint8_t *p = src + x * 8;
        uint16_t r = (uint16_t)(p[0] | (p[1] << 8)), g = (uint16_t)(p[2] | (p[3] << 8)),
                 b = (uint16_t)(p[4] | (p[5] << 8));
        dst[x * 4 + 0] = adreno_display_half_to_8(b);
        dst[x * 4 + 1] = adreno_display_half_to_8(g);
        dst[x * 4 + 2] = adreno_display_half_to_8(r);
        dst[x * 4 + 3] = 0xff;
    }
}

struct adreno_display_plan {
    uint64_t width, height;   /* top-left overlap, 1:1 */
    uint32_t bytes_per_pixel; /* source */
};

/* Validate everything a copy would touch. Returns ADRENO_DISPLAY_OK or a
 * negative error; touches no pixel memory. */
static inline int adreno_display_plan(const struct adreno_display_surface *s,
                                      const struct adreno_display_scanout *d,
                                      struct adreno_display_plan *plan)
{
    if (!s || !d || !plan || !s->base || !d->base || !s->width || !s->height || !s->row_bytes ||
        !d->width || !d->height || !d->row_bytes)
        return ADRENO_DISPLAY_E_ARGS;
    uint32_t bpp = adreno_display_bytes_per_pixel(s->format);
    if (!bpp)
        return ADRENO_DISPLAY_E_FORMAT;
    uint64_t w = s->width < d->width ? s->width : d->width;
    uint64_t h = s->height < d->height ? s->height : d->height;
    /* Source: one row's pixels fit its stride; the last row ends inside the allocation. */
    if (!adreno_display_span_fits(w, bpp, 0, s->row_bytes))
        return ADRENO_DISPLAY_E_SOURCE;
    if (s->offset > s->length ||
        !adreno_display_span_fits(h - 1, s->row_bytes, w * bpp, s->length - s->offset))
        return ADRENO_DISPLAY_E_SOURCE;
    /* Destination: 4 bytes per pixel, same rule. */
    if (!adreno_display_span_fits(w, 4, 0, d->row_bytes) ||
        !adreno_display_span_fits(h - 1, d->row_bytes, w * 4, d->length))
        return ADRENO_DISPLAY_E_DEST;
    plan->width = w;
    plan->height = h;
    plan->bytes_per_pixel = bpp;
    return ADRENO_DISPLAY_OK;
}

/* Plan, then copy row by row. On error nothing was read, maintained or written. */
static inline int adreno_display_copy(const struct adreno_display_surface *s,
                                      const struct adreno_display_scanout *d,
                                      adreno_display_maintain_fn maintain, void *context,
                                      struct adreno_display_copy_result *out)
{
    struct adreno_display_plan plan;
    if (out)
        out->width = out->height = out->bytes_read = 0;
    int error = adreno_display_plan(s, d, &plan);
    if (error)
        return error;
    uint64_t row_read = plan.width * plan.bytes_per_pixel;
    for (uint64_t y = 0; y < plan.height; y++) {
        const uint8_t *src = s->base + s->offset + y * s->row_bytes;
        if (maintain)
            maintain(context, src, row_read);
        adreno_display_convert_row(s->format, src, d->base + y * d->row_bytes, plan.width);
    }
    if (out) {
        out->width = plan.width;
        out->height = plan.height;
        out->bytes_read = row_read * plan.height;
    }
    return ADRENO_DISPLAY_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* ADRENO_DISPLAY_COPY_H */
