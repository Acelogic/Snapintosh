/* SPDX-License-Identifier: MIT */
/* Compose before publishing: never erase a stationary cursor into live scanout.
 * The old save-under is immutable until every row is published. A separate save
 * buffer is necessary when old/new rectangles overlap in different rows.
 * This removes the erase/copy/redraw gap; GOP writes are NOT vblank atomic.
 * Failure inventory and replay: docs/GRAPHICS-CORRECTNESS-20261018.md.
 *
 * Present cost (2026-10-20; failure modes P1-P24 and the ARM ordering rules R1-R5 are in
 * the batch's FAILURES-AND-DESIGN.md, replayed by tools/replay-adreno-presentation.c):
 *   1. maintenance pass: ops->maintain for exactly the source bytes of every row read, no
 *      barrier per row, then ops->barrier once. A DC CIVAC is not ordered against later
 *      loads of Normal-NC (write-combined) memory without a DMB/DSB, and the layer-0
 *      IOSurface is write-combined (QuartzCore IOMFBDisplay::create_surface, mode 0x400);
 *   2. per chunk of ADRENO_DISPLAY_STAGE_ROWS rows, phase A: each source row is read and
 *      converted once into a cacheable stage slot, then given a 128-bit signature;
 *   3. phase B: a row is published only when its signature differs from the one recorded
 *      for that scanout row, the row is unknown, or it is in the rolling-refresh window
 *      (ceil(height / refresh_period) rows per layer-0 present), plus every cursor row, as
 *      before. WindowServer 26A428 sends no dirty region (no image imports
 *      IOMobileFramebufferSwapDirtyRegion), so the comparison is the damage.
 * Signatures describe the layer-0 bytes on the scanout over [0, width): the cursor never
 * enters them, because every cursor composition restores layer-0 bytes under it. */
#ifndef ADRENO_DISPLAY_PRESENT_H
#define ADRENO_DISPLAY_PRESENT_H
#include "AdrenoDisplayCursor.h"
/* --present-beam (agents/tear-free FAILURE-MODES.md C3 C7): -DADRENO_BEAM=1 adds ops->gate, called before the first
 * scanout write of each ADRENO_DISPLAY_STAGE_ROWS chunk, with the chunk's rows. Off by default; without it this header
 * compiles as before. */
#ifndef ADRENO_BEAM
#define ADRENO_BEAM 0
#endif
/* Cursor rows without write-combined readback (agents/tear-free, the dvfs finding: b11v1 read the live scanout at
 * 313 MB/s under the cursor): -DADRENO_PRESENT_CURSOR_STAGE=1 composes the background under the cursor from the stage,
 * which holds every layer-0 row of the chunk whether it changed or not, and in a cursor-only present reads the live
 * scanout only outside the old cursor's save-under. Off by default; without it this header compiles as before.
 * ADRENO_DISPLAY_LIVE_READ lets the replay count the bytes read back. */
#ifndef ADRENO_PRESENT_CURSOR_STAGE
#define ADRENO_PRESENT_CURSOR_STAGE 0
#endif
#if ADRENO_PRESENT_CURSOR_STAGE && !defined(ADRENO_DISPLAY_LIVE_READ)
#define ADRENO_DISPLAY_LIVE_READ(dst, src, n) memcpy((dst), (src), (n))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ADRENO_DISPLAY_STAGE_ROWS 16u       /* rows read before they are published (one clock pair) */
#define ADRENO_DISPLAY_REFRESH_PERIOD 64u   /* layer-0 presents per full rewrite of every row */

/* Per scanout row: what layer 0 last put there. */
struct adreno_display_damage {
    uint64_t *sig;              /* 2 words per row */
    uint8_t *known;             /* 1: sig[2y], sig[2y+1] describe scanout row y over [0, width) */
    uint64_t rows;              /* entries; must cover the scanout height */
    uint64_t width;             /* copy width the signatures describe; 0 = none */
    uint64_t refresh_next;      /* first row of the next refresh window */
    uint32_t refresh_period;    /* layer-0 presents per full refresh; 0 = never */
};

/* Every row unknown: the next layer-0 present writes every source row (P2, P11). */
static inline void adreno_display_damage_forget(struct adreno_display_damage *g)
{
    if (!g)
        return;
    if (g->known)
        memset(g->known, 0, (size_t)g->rows);
    g->width = 0;
}

struct adreno_display_present_workspace {
    uint8_t *row;               /* one scanout row: cursor composition */
    uint64_t row_bytes;
    uint8_t *next_save;         /* ADRENO_DISPLAY_CURSOR_BYTES; must differ from cursor.save */
    uint8_t *stage;             /* ADRENO_DISPLAY_STAGE_ROWS converted source rows, stage_row_bytes apart */
    uint64_t stage_row_bytes;
    struct adreno_display_damage *damage;   /* NULL: every source row is published */
};
struct adreno_display_present_result {
    uint64_t bytes_read, bytes_written, regions, cursor_pixels;
    uint64_t rows_compared, rows_written, rows_skipped, rows_refreshed;
    uint64_t maint_ticks, barrier_ticks, read_ticks, hash_ticks, write_ticks;
    uint32_t forgot;            /* the copy width changed: every signature was dropped first */
};
typedef void (*adreno_display_publish_fn)(void *, uint64_t x, uint64_t y, uint64_t width);
typedef void (*adreno_display_barrier_fn)(void *);
typedef uint64_t (*adreno_display_clock_fn)(void *);
struct adreno_display_present_ops {
    adreno_display_maintain_fn maintain;    /* source range; need not order or complete it */
    adreno_display_barrier_fn barrier;      /* once, after the last maintenance, before the first source read */
    adreno_display_clock_fn clock;          /* optional: phase ticks */
    void *context;                          /* maintain, barrier and clock */
    adreno_display_publish_fn observe;      /* optional: every span, right after it reaches the scanout */
    void *observer;
#if ADRENO_BEAM
    adreno_display_publish_fn gate;         /* optional: before a chunk's first write, (x = 0, y = first row, w = end row) */
    void *gate_context;
#endif
};
struct adreno_display_interval { uint64_t a,b; };

/* Four independent 32-bit lanes over the 8-byte words (word i feeds lane i % 4), alternating
 * CRC32C and CRC32, so adjacent words use different polynomials. A change inside one lane's
 * words escapes with probability about 2^-32 (CRC detects every burst up to 32 bits in its
 * lane outright); the rolling refresh bounds what an escape costs to one refresh period.
 * One CRC per word: about half the cost of two (0.7-1.0 vs 1.4-2.0 ms a frame on an M3).
 * n is a multiple of 4. */
static inline void adreno_display_row_signature(const uint8_t *p, uint64_t n, uint64_t out[2])
{
    uint64_t words = n / 8, i = 0, w0, w1, w2, w3;
#if defined(__ARM_FEATURE_CRC32)
    uint32_t a = 0xffffffffu, b = 0xffffffffu, c = 0x9e3779b9u, d = 0x7f4a7c15u;
    for (; i + 4 <= words; i += 4) {
        memcpy(&w0, p + i * 8, 8);
        memcpy(&w1, p + i * 8 + 8, 8);
        memcpy(&w2, p + i * 8 + 16, 8);
        memcpy(&w3, p + i * 8 + 24, 8);
        a = __builtin_arm_crc32cd(a, w0); b = __builtin_arm_crc32d(b, w1);
        c = __builtin_arm_crc32cd(c, w2); d = __builtin_arm_crc32d(d, w3);
    }
    for (unsigned lane = 0; i < words; i++, lane++) {
        memcpy(&w0, p + i * 8, 8);
        if (lane == 0) a = __builtin_arm_crc32cd(a, w0);
        else if (lane == 1) b = __builtin_arm_crc32d(b, w0);
        else c = __builtin_arm_crc32cd(c, w0);
    }
    if (n & 4) {
        uint32_t t;
        memcpy(&t, p + words * 8, 4);
        d = __builtin_arm_crc32w(d, t);
    }
    out[0] = (uint64_t)a << 32 | b;
    out[1] = (uint64_t)c << 32 | d;
#else
    uint64_t a = 0x243f6a8885a308d3ull, c = 0x13198a2e03707344ull;
    (void)w2; (void)w3;
    for (; i + 2 <= words; i += 2) {
        memcpy(&w0, p + i * 8, 8);
        memcpy(&w1, p + i * 8 + 8, 8);
        a = (a ^ w0) * 0x9e3779b97f4a7c15ull; a ^= a >> 31;
        c = (c ^ w1) * 0xc2b2ae3d27d4eb4full; c ^= c >> 29;
    }
    if (i < words) {
        memcpy(&w0, p + i * 8, 8);
        a = (a ^ w0) * 0x9e3779b97f4a7c15ull; a ^= a >> 31;
    }
    if (n & 4) {
        uint32_t t;
        memcpy(&t, p + words * 8, 4);
        c = (c ^ t) * 0xc2b2ae3d27d4eb4full; c ^= c >> 29;
    }
    out[0] = a;
    out[1] = c;
#endif
}

/* Row y is in the refresh window [first, first + count) taken modulo height. */
static inline int adreno_display_refresh_row(uint64_t y, uint64_t first, uint64_t count, uint64_t height)
{
    if (!count)
        return 0;
    if (count >= height)
        return 1;
    uint64_t end = first + count;
    if (end <= height)
        return y >= first && y < end;
    return y >= first || y < end - height;
}

static inline int adreno_display_present(struct adreno_display_cursor *c,
    const struct adreno_display_scanout *d, const struct adreno_display_surface *s,
    struct adreno_display_present_workspace *ws, const struct adreno_display_present_ops *ops,
    struct adreno_display_present_result *out)
{
    struct adreno_display_present_result result;
    struct adreno_display_plan plan = {0,0,0};
#if ADRENO_BEAM
    static const struct adreno_display_present_ops none = {0,0,0,0,0,0,0,0};
#else
    static const struct adreno_display_present_ops none = {0,0,0,0,0,0};
#endif
    uint64_t nx=0,ny=0,nw=0,nh=0;
    memset(&result,0,sizeof result);
    if (out) *out=result;
    if (!ops) ops=&none;
    if (!c || !d || !d->base || !ws) return ADRENO_DISPLAY_E_ARGS;
    if (s) { int error=adreno_display_plan(s,d,&plan); if(error)return error; }
    int next=c->visible && adreno_display_cursor_clip(c,d,&nx,&ny,&nw,&nh);
    if (c->width>ADRENO_DISPLAY_CURSOR_MAX_WIDTH || c->height>ADRENO_DISPLAY_CURSOR_MAX_HEIGHT ||
        c->sw>ADRENO_DISPLAY_CURSOR_MAX_WIDTH || c->sh>ADRENO_DISPLAY_CURSOR_MAX_HEIGHT)
        return ADRENO_DISPLAY_E_SIZE;
    if (c->drawn && (!c->save || !adreno_display_scanout_rect_fits(d,c->sx,c->sy,c->sw,c->sh)))
        return ADRENO_DISPLAY_E_DEST;
    if (next && (!c->image || !c->save || !ws->next_save || ws->next_save==c->save ||
                 !adreno_display_scanout_rect_fits(d,nx,ny,nw,nh))) return ADRENO_DISPLAY_E_DEST;
    if ((next || c->drawn) && (!ws->row || !adreno_display_span_fits(d->width,4,0,ws->row_bytes)))
        return ADRENO_DISPLAY_E_SIZE;
    struct adreno_display_damage *g = s ? ws->damage : 0;
    if (s && (!ws->stage || !adreno_display_span_fits(plan.width,4,0,ws->stage_row_bytes)))
        return ADRENO_DISPLAY_E_SIZE;                                         /* P14 */
    if (g && (!g->sig || !g->known || g->rows < d->height || g->rows > UINT64_MAX / 2))
        return ADRENO_DISPLAY_E_SIZE;                                         /* P15 */
    /* All bounds and allocations are checked before any read, maintenance or publication. */
    adreno_display_clock_fn clock = ops->clock;
    uint64_t refresh_first = 0, refresh_count = 0;
    if (g) {
        if (g->width != plan.width) {                                         /* P10 */
            adreno_display_damage_forget(g);
            g->width = plan.width;
            result.forgot = 1;
        }
        if (g->refresh_period) {
            refresh_count = (plan.height + g->refresh_period - 1) / g->refresh_period;
            refresh_first = g->refresh_next % plan.height;
        }
    }
    if (s) {                                                                  /* P6 P7 */
        uint64_t row_read = plan.width * plan.bytes_per_pixel;
        uint64_t t0 = clock ? clock(ops->context) : 0;
        if (ops->maintain)
            for (uint64_t y=0;y<plan.height;y++)
                ops->maintain(ops->context,s->base+s->offset+y*s->row_bytes,row_read);
        uint64_t t1 = clock ? clock(ops->context) : 0;
        if (ops->barrier) ops->barrier(ops->context);
        uint64_t t2 = clock ? clock(ops->context) : 0;
        result.maint_ticks = t1 - t0;
        result.barrier_ticks = t2 - t1;
    }
    uint64_t first=s?0:d->height,last=plan.height;
    if(c->drawn){if(c->sy<first)first=c->sy;if(c->sy+c->sh>last)last=c->sy+c->sh;}
    if(next){if(ny<first)first=ny;if(ny+nh>last)last=ny+nh;}
    /* P13: one clock read per phase edge; a chunk's end is the next chunk's start. */
    uint64_t ta = (clock && first<last) ? clock(ops->context) : 0;
    for(uint64_t y0=first;y0<last;y0+=ADRENO_DISPLAY_STAGE_ROWS) {
        uint64_t y1=last-y0>ADRENO_DISPLAY_STAGE_ROWS?y0+ADRENO_DISPLAY_STAGE_ROWS:last;
        uint8_t changed[ADRENO_DISPLAY_STAGE_ROWS];
        uint64_t sig[ADRENO_DISPLAY_STAGE_ROWS][2];
        /* Phase A: each source row is read once, into the stage (P23: slot y - y0) ... */
        for(uint64_t y=y0;y<y1 && s && y<plan.height;y++) {
            adreno_display_convert_row(s->format,s->base+s->offset+y*s->row_bytes,
                                       ws->stage+(y-y0)*ws->stage_row_bytes,plan.width);
            result.bytes_read+=plan.width*plan.bytes_per_pixel;
        }
        uint64_t th = clock ? clock(ops->context) : 0;
        /* ... then compared with what the scanout row holds. */
        for(uint64_t y=y0;y<y1;y++) {
            unsigned k=(unsigned)(y-y0);
            changed[k]=0;
            if(!s || y>=plan.height) continue;
            const uint8_t *stage=ws->stage+k*ws->stage_row_bytes;
            if(!g){changed[k]=1;continue;}
            adreno_display_row_signature(stage,plan.width*4,sig[k]);
            result.rows_compared++;
            int same=g->known[y] && g->sig[2*y]==sig[k][0] && g->sig[2*y+1]==sig[k][1];
            int refresh=adreno_display_refresh_row(y,refresh_first,refresh_count,plan.height);  /* P3 P21 */
            changed[k]=(uint8_t)(!same || refresh);
            if(same && refresh) result.rows_refreshed++;
            if(!changed[k]) result.rows_skipped++;
        }
        uint64_t tb = clock ? clock(ops->context) : 0;
        /* Phase B: publish changed rows and every cursor row, composed before the live write (P4 P5). */
#if ADRENO_BEAM
        int gated=0;
#endif
        for(uint64_t y=y0;y<y1;y++) {
            unsigned k=(unsigned)(y-y0);
            const uint8_t *stage=ws->stage?ws->stage+k*ws->stage_row_bytes:0;
            struct adreno_display_interval spans[3];unsigned count=0;
            int old=c->drawn && y>=c->sy && y<c->sy+c->sh;
            int fresh=next && y>=ny && y<ny+nh;
            int source=s && y<plan.height && changed[k];
            if(!source && !old && !fresh) continue;                          /* unchanged, no cursor */
#if ADRENO_BEAM
            if(!gated && ops->gate){ops->gate(ops->gate_context,0,y0,y1);gated=1;}   /* C3: the beam, before any write */
#endif
            if(source){spans[count].a=0;spans[count++].b=plan.width;}
            if(old){spans[count].a=c->sx;spans[count++].b=c->sx+c->sw;}
            if(fresh){spans[count].a=nx;spans[count++].b=nx+nw;}
            for(unsigned i=1;i<count;i++)for(unsigned j=i;j && spans[j].a<spans[j-1].a;j--){
                struct adreno_display_interval tmp=spans[j];spans[j]=spans[j-1];spans[j-1]=tmp;
            }
            unsigned merged=0;
            for(unsigned i=0;i<count;i++) {
                if(merged && spans[i].a<=spans[merged-1].b){if(spans[i].b>spans[merged-1].b)spans[merged-1].b=spans[i].b;}
                else spans[merged++]=spans[i];
            }
            for(unsigned i=0;i<merged;i++) {
                uint64_t a=spans[i].a,b=spans[i].b;uint8_t *live=d->base+y*d->row_bytes+a*4;
                int hasOld=old && a<c->sx+c->sw && b>c->sx;
                int hasNew=fresh && a<nx+nw && b>nx;
                /* The source covers [a, srcEnd) of this span. */
                uint64_t srcEnd=(source && a<plan.width)?(b<plan.width?b:plan.width):a;
                if(!hasOld && !hasNew) {
                    /* Only the source span: stage to scanout. */
                    if(srcEnd>a)memcpy(live,stage+a*4,(size_t)((srcEnd-a)*4));
                } else {
                    uint8_t *dst=ws->row;
#if ADRENO_PRESENT_CURSOR_STAGE
                    /* P24: the background comes from the stage wherever it holds this row (layer-0 bytes, changed or
                     * not); the live scanout is read only beyond it, and never under the old cursor's save-under. */
                    const uint64_t bgEnd=(s && y<plan.height && a<plan.width && stage)?(b<plan.width?b:plan.width):srcEnd;
                    if(bgEnd<b) {
                        const uint64_t o0=hasOld && c->sx>bgEnd?c->sx:bgEnd, o1=hasOld && c->sx+c->sw>bgEnd?c->sx+c->sw:bgEnd;
                        if(o0>bgEnd)ADRENO_DISPLAY_LIVE_READ(dst+(bgEnd-a)*4,live+(bgEnd-a)*4,(size_t)((o0-bgEnd)*4));
                        if(b>o1)ADRENO_DISPLAY_LIVE_READ(dst+(o1-a)*4,live+(o1-a)*4,(size_t)((b-o1)*4));
                    }
                    if(hasOld)memcpy(dst+(c->sx-a)*4,c->save+(y-c->sy)*c->sw*4,(size_t)(c->sw*4));
                    if(bgEnd>a)memcpy(dst,stage+a*4,(size_t)((bgEnd-a)*4));
#else
                    /* P24: the live scanout is read only where the source does not rewrite it. */
                    if(srcEnd<b)memcpy(dst+(srcEnd-a)*4,live+(srcEnd-a)*4,(size_t)((b-srcEnd)*4));
                    if(hasOld)memcpy(dst+(c->sx-a)*4,c->save+(y-c->sy)*c->sw*4,(size_t)(c->sw*4));
                    if(srcEnd>a)memcpy(dst,stage+a*4,(size_t)((srcEnd-a)*4));
#endif
                    if(hasNew) {
                        uint8_t *under=ws->next_save+(y-ny)*nw*4;
                        uint64_t col=(uint64_t)((int64_t)nx-c->x),line=(uint64_t)((int64_t)y-c->y);
                        memcpy(under,dst+(nx-a)*4,(size_t)(nw*4));
                        adreno_display_blend_row(c->image+(line*c->width+col)*4,under,dst+(nx-a)*4,nw);
                    }
                    memcpy(live,dst,(size_t)((b-a)*4));
                }
                result.bytes_written+=(b-a)*4;result.regions++;
                if(ops->observe)ops->observe(ops->observer,a,y,b-a);
            }
            if(source) {
                result.rows_written++;
                if(g){g->sig[2*y]=sig[k][0];g->sig[2*y+1]=sig[k][1];g->known[y]=1;}
            }
        }
        uint64_t tc = clock ? clock(ops->context) : 0;
        result.read_ticks+=th-ta;
        result.hash_ticks+=tb-th;
        result.write_ticks+=tc-tb;
        ta=tc;
    }
    if(g && refresh_count) g->refresh_next=(refresh_first+refresh_count)%plan.height;
    c->drawn=next;
    if(next) {
        uint8_t *oldSave=c->save;c->save=ws->next_save;ws->next_save=oldSave;
        c->sx=nx;c->sy=ny;c->sw=nw;c->sh=nh;result.cursor_pixels=nw*nh;
    }
    if(out)*out=result;
    return ADRENO_DISPLAY_OK;
}

#ifdef __cplusplus
}
#endif
#endif
