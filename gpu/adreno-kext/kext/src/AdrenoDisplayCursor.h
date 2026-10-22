/* SPDX-License-Identifier: MIT */
/* AdrenoDisplayCursor.h - the cursor (overlay) layer, alpha-composited onto the scanout.
 *
 * Header-only C, shared by the kext (AdrenoDisplay.cpp) and the host E2E test
 * (tools/test-adreno-display-present.c), like AdrenoDisplayCopy.h.
 * docs/ADRENO-DISPLAY-CURSOR-20261018.md.
 *
 * QuartzCore 26A428 sends the hardware cursor as its own IOMFB layer (the cursor plane,
 * layer 1 here) in swaps of its own; layer 0 is not part of them and stays on screen.
 * The kext keeps one cursor:
 *   - capture: a layer that carries a surface is copied (its source rectangle, 1:1) into
 *     `image`, so later swaps that do not mention the layer can redraw it;
 *   - place/hide: the destination rectangle's origin is where image pixel (0,0) lands
 *     (display pixels, int32, may be negative); a layer switched off hides the cursor;
 *   - begin (every present, first): put back the scanout pixels under the cursor drawn
 *     by the previous present (`save`), so moving it leaves no trail and a cursor-only
 *     swap never needs the full layer-0 copy;
 *   - finish (every present, last): save the pixels under the clipped cursor rectangle,
 *     then composite the image over them, premultiplied source-over.
 * With no cursor ever captured, begin and finish touch nothing: layer-0 output is the
 * same bytes as without this file.
 *
 * Failure inventory, written before the code (each has a case in the host test):
 *   C1  cursor written outside the scanout (negative position, past an edge)
 *   C2  cursor source read outside its surface or allocation
 *   C3  negative or wrapping source-rectangle arithmetic
 *   C4  a moved cursor leaves a trail (save-under not restored, or restored over a
 *       newer layer-0 copy)
 *   C5  the save-under taken with the cursor already drawn (cursor burnt in)
 *   C6  alpha treated as straight, unrounded, or overflowing 255
 *   C7  an unknown pixel format composited as if BGRA (refused, nothing changes)
 *   C8  a cursor larger than the buffers (refused)
 *   C9  a layer switched off leaves the cursor on screen
 *   C10 a swap without the cursor layer removes it, or a layer-0 copy erases it for good
 *   C11 no cursor layer: output differs from the layer-0-only path
 *   C12 stale CPU cache lines of the cursor surface (FROM_DEVICE per row read)
 *   C13 a cursor wholly off screen writes or saves anything
 *   C14 a refused capture changes the cached image or its geometry
 *
 * Pixels: the cursor surface is 'BGRA' (QuartzCore allocates it so for the cursor plane,
 * IOMFBDisplay::set_cursor_surface 0x18b38e0ec; PV refuses any other format,
 * program_hardware_cursor_gated 0x11004), premultiplied alpha. Each of the four bytes is
 *   out = min(255, src + round(under * (255 - a) / 255)),   a = src byte 3,
 * which is source-over for premultiplied colour and leaves the ignored X byte at the
 * composited alpha. a = 255 copies the source; a = 0 adds it (0 for a transparent pixel).
 */
#ifndef ADRENO_DISPLAY_CURSOR_H
#define ADRENO_DISPLAY_CURSOR_H

#include "AdrenoDisplayCopy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer bound: QuartzCore's IOMFBDisplay::maximum_cursor_size() is 128x128 (0x18b3a04f4),
 * scaled by the display scale; 512 covers scale 4. */
#define ADRENO_DISPLAY_CURSOR_MAX_WIDTH 512u
#define ADRENO_DISPLAY_CURSOR_MAX_HEIGHT 512u
#define ADRENO_DISPLAY_CURSOR_BYTES (ADRENO_DISPLAY_CURSOR_MAX_WIDTH * ADRENO_DISPLAY_CURSOR_MAX_HEIGHT * 4u)

enum {
    ADRENO_DISPLAY_E_SIZE = -5,     /* cursor larger than the buffers */
    ADRENO_DISPLAY_E_RECT = -6,     /* source rectangle negative or outside the surface */
};

/* IOMFBSwapIORequest srcRect / destRect layout: four int32 (IOMFBSwapFields::Rect). */
struct adreno_display_rect {
    int32_t x, y, w, h;
};

struct adreno_display_cursor {
    uint8_t *image;             /* ADRENO_DISPLAY_CURSOR_BYTES, captured pixels, rows width*4 apart */
    uint8_t *save;              /* ADRENO_DISPLAY_CURSOR_BYTES, scanout pixels under the drawn cursor */
    uint32_t width, height;     /* captured image; 0 = none */
    int32_t x, y;               /* scanout position of image pixel (0,0) */
    int visible;                /* finish draws it */
    int drawn;                  /* save holds the rectangle below; begin puts it back */
    uint64_t sx, sy, sw, sh;    /* drawn rectangle, clipped to the scanout */
    uint32_t layer;             /* IOMFB layer the image came from; 0 = none yet */
};

/* round(v / 255) for 0 <= v <= 65535 (no ties: v/255 is never k + 1/2). */
static inline uint32_t adreno_display_div255(uint32_t v)
{
    v += 128u;
    return (v + (v >> 8)) >> 8;
}

/* Premultiplied source-over of n pixels: out may alias under. */
static inline void adreno_display_blend_row(const uint8_t *src, const uint8_t *under, uint8_t *out, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *s = src + i * 4, *u = under + i * 4;
        uint8_t *o = out + i * 4;
        uint32_t a = s[3];
        if (a == 255u) {
            o[0] = s[0]; o[1] = s[1]; o[2] = s[2]; o[3] = 255u;
            continue;
        }
        for (int c = 0; c < 4; c++) {
            uint32_t v = s[c] + adreno_display_div255((uint32_t)u[c] * (255u - a));
            o[c] = (uint8_t)(v > 255u ? 255u : v);
        }
    }
}

/* The scanout rows [sy, sy+sh) x bytes [sx*4, (sx+sw)*4) lie inside the mapping. */
static inline int adreno_display_scanout_rect_fits(const struct adreno_display_scanout *d, uint64_t sx,
                                                   uint64_t sy, uint64_t sw, uint64_t sh)
{
    if (!d || !d->base || !d->row_bytes || !sw || !sh)
        return 0;
    if (sx > d->width || sw > d->width - sx || sy > d->height || sh > d->height - sy)
        return 0;
    return adreno_display_span_fits(sx + sw, 4, 0, d->row_bytes) &&
           adreno_display_span_fits(sy + sh - 1, d->row_bytes, (sx + sw) * 4, d->length);
}

/* Copy the source rectangle of a cursor surface into c->image. A zero-sized rectangle
 * means the whole surface. On error nothing was read, maintained or changed (C14). */
static inline int adreno_display_cursor_capture(struct adreno_display_cursor *c,
                                                const struct adreno_display_surface *s,
                                                struct adreno_display_rect src,
                                                adreno_display_maintain_fn maintain, void *context)
{
    if (!c || !s)
        return ADRENO_DISPLAY_E_ARGS;
    if (s->format != ADRENO_DISPLAY_FORMAT_BGRA)
        return ADRENO_DISPLAY_E_FORMAT;                                   /* C7, before any mapping */
    if (!c->image || !s->base || !s->width || !s->height || !s->row_bytes)
        return ADRENO_DISPLAY_E_ARGS;
    if (!src.w || !src.h) {
        if (s->width > 0x7fffffffu || s->height > 0x7fffffffu)
            return ADRENO_DISPLAY_E_SIZE;
        src.x = 0; src.y = 0; src.w = (int32_t)s->width; src.h = (int32_t)s->height;
    }
    if (src.x < 0 || src.y < 0 || src.w < 0 || src.h < 0)
        return ADRENO_DISPLAY_E_RECT;                                     /* C3 */
    uint64_t x = (uint64_t)src.x, y = (uint64_t)src.y, w = (uint64_t)src.w, h = (uint64_t)src.h;
    if (x + w > s->width || y + h > s->height)
        return ADRENO_DISPLAY_E_RECT;                                     /* C2 */
    if (w > ADRENO_DISPLAY_CURSOR_MAX_WIDTH || h > ADRENO_DISPLAY_CURSOR_MAX_HEIGHT)
        return ADRENO_DISPLAY_E_SIZE;                                     /* C8 */
    /* One row's bytes fit its stride; the last row ends inside the allocation (C2). */
    if (!adreno_display_span_fits(x + w, 4, 0, s->row_bytes))
        return ADRENO_DISPLAY_E_SOURCE;
    if (s->offset > s->length ||
        !adreno_display_span_fits(y + h - 1, s->row_bytes, (x + w) * 4, s->length - s->offset))
        return ADRENO_DISPLAY_E_SOURCE;
    for (uint64_t j = 0; j < h; j++) {
        const uint8_t *row = s->base + s->offset + (y + j) * s->row_bytes + x * 4;
        if (maintain)
            maintain(context, row, w * 4);                                /* C12 */
        memcpy(c->image + j * w * 4, row, (size_t)(w * 4));
    }
    c->width = (uint32_t)w;
    c->height = (uint32_t)h;
    return ADRENO_DISPLAY_OK;
}

/* The captured image goes to (x, y) on the next finish. */
static inline void adreno_display_cursor_place(struct adreno_display_cursor *c, int32_t x, int32_t y)
{
    c->x = x;
    c->y = y;
    c->visible = c->width && c->height;
}

/* The cursor layer was switched off, or its new contents were refused (C9). */
static inline void adreno_display_cursor_hide(struct adreno_display_cursor *c)
{
    c->visible = 0;
}

/* One layer 1..3 whose bit is set in the swap's mask. s == NULL: the layer was switched off
 * (surface ID 0), which hides the cursor if it came from that layer (or none yet). Otherwise
 * the surface becomes the cursor: captured, its pixel (0,0) placed at (x, y) = the layer's
 * destRect origin. A refused surface hides the cursor -- never the old image at the new
 * place -- and the error is returned. Layers whose bit is clear are not passed: the cursor
 * keeps its state (C10). */
static inline int adreno_display_cursor_layer(struct adreno_display_cursor *c, uint32_t layer,
                                              const struct adreno_display_surface *s,
                                              struct adreno_display_rect src, int32_t x, int32_t y,
                                              adreno_display_maintain_fn maintain, void *context)
{
    if (!s) {
        if (layer == c->layer || !c->layer)
            adreno_display_cursor_hide(c);
        return ADRENO_DISPLAY_OK;
    }
    c->layer = layer;
    int error = adreno_display_cursor_capture(c, s, src, maintain, context);
    if (error) {
        adreno_display_cursor_hide(c);
        return error;
    }
    adreno_display_cursor_place(c, x, y);
    return ADRENO_DISPLAY_OK;
}

/* The scanout rectangle the cursor covers; 0 when it is wholly off screen (C1, C13). */
static inline int adreno_display_cursor_clip(const struct adreno_display_cursor *c,
                                             const struct adreno_display_scanout *d, uint64_t *sx,
                                             uint64_t *sy, uint64_t *sw, uint64_t *sh)
{
    if (!c->width || !c->height || !d->width || !d->height || d->width > INT64_MAX || d->height > INT64_MAX)
        return 0;
    int64_t x0 = c->x, y0 = c->y, x1 = (int64_t)c->x + c->width, y1 = (int64_t)c->y + c->height;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int64_t)d->width) x1 = (int64_t)d->width;
    if (y1 > (int64_t)d->height) y1 = (int64_t)d->height;
    if (x1 <= x0 || y1 <= y0)
        return 0;
    *sx = (uint64_t)x0; *sy = (uint64_t)y0;
    *sw = (uint64_t)(x1 - x0); *sh = (uint64_t)(y1 - y0);
    return 1;
}

/* First thing of every present: undo the previous present's cursor (C4). Returns the
 * number of pixels restored. */
static inline uint64_t adreno_display_cursor_begin(struct adreno_display_cursor *c,
                                                   const struct adreno_display_scanout *d)
{
    if (!c->drawn)
        return 0;
    c->drawn = 0;
    if (!c->save || !adreno_display_scanout_rect_fits(d, c->sx, c->sy, c->sw, c->sh))
        return 0;
    for (uint64_t j = 0; j < c->sh; j++)
        memcpy(d->base + (c->sy + j) * d->row_bytes + c->sx * 4, c->save + j * c->sw * 4, (size_t)(c->sw * 4));
    return c->sw * c->sh;
}

/* Last thing of every present: save under, then composite (C5, C6, C10). Returns the
 * number of pixels composited (0: hidden, off screen, or nothing captured). */
static inline uint64_t adreno_display_cursor_finish(struct adreno_display_cursor *c,
                                                    const struct adreno_display_scanout *d)
{
    uint64_t sx, sy, sw, sh;
    if (c->drawn)
        adreno_display_cursor_begin(c, d);              /* never save over a drawn cursor */
    if (!c->visible || !c->image || !c->save || !adreno_display_cursor_clip(c, d, &sx, &sy, &sw, &sh) ||
        !adreno_display_scanout_rect_fits(d, sx, sy, sw, sh))
        return 0;
    /* Image pixel of scanout (sx, sy): both offsets are >= 0 after clipping. */
    uint64_t col = (uint64_t)((int64_t)sx - (int64_t)c->x), line0 = (uint64_t)((int64_t)sy - (int64_t)c->y);
    for (uint64_t j = 0; j < sh; j++) {
        uint8_t *dst = d->base + (sy + j) * d->row_bytes + sx * 4;
        uint8_t *under = c->save + j * sw * 4;
        const uint8_t *src = c->image + ((line0 + j) * c->width + col) * 4;
        memcpy(under, dst, (size_t)(sw * 4));
        adreno_display_blend_row(src, under, dst, sw);
    }
    c->sx = sx; c->sy = sy; c->sw = sw; c->sh = sh;
    c->drawn = 1;
    return sw * sh;
}

#ifdef __cplusplus
}
#endif

#endif /* ADRENO_DISPLAY_CURSOR_H */
