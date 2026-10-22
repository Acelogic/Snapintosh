/* SPDX-License-Identifier: MIT */
/*
 * drivers/snap-i2c-hid/src/hid-mt2.c against Apple's own parsers, on a 26A428 host, offline: the
 * frames and feature replies the guest's SnapI2CHIDMultitouch sends go through the code that will
 * receive them in the guest (failure modes M4, M5 in the gestures agent's FAILURE-MODES.md):
 *
 *  - MultitouchSupport (dyld shared cache): MTCompactV7HeaderUnpack, MTCompactV7BinaryContactUnpack,
 *    MTParseSensorSurfaceDescriptor and MTParseSensorRegionsReport, which are not exported. They are
 *    found through the symbol table of the same image extracted from this host's cache (ipsw dyld
 *    extract), and called only when their first 48 code bytes in this process equal the extracted
 *    image's; MTParseSensorRegionParam is exported.
 *  - HSTouchHIDService.plugin (the 26A428 trackpad gesture engine): -[HSTFrameParser
 *    parseContactFrame31:] on a parser whose surface coordinates are set as
 *    HSTPipeline::SurfaceCoordinates::fromService derives them from our 0xD9 reply.
 *
 * Nothing is installed, no device is opened, nothing touches the system: two images are loaded into
 * this process and pure functions are called. Build and run from the repository root:
 *   ipsw dyld extract /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
 *       MultitouchSupport --output DIR
 *   clang -fobjc-arc -Wall -Wextra -Werror -Idrivers/snap-i2c-hid/src -Itools tools/test-mt2-apple-parser.m \
 *       drivers/snap-i2c-hid/src/hid-mt2.c drivers/snap-i2c-hid/src/hid-ptp.c -framework Foundation -o OUT
 *   OUT DIR/MultitouchSupport
 */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hid-mt2.h"
#include "hid-ptp.h"
#include "test-snap-i2c-hid-fixture.h"

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #x); exit(1); } } while (0)

/* ------------------------------------------------------------ the extracted image ---- */
struct image { uint8_t *data; size_t len; uint64_t text_vm, text_off; };

static struct image load_image(const char *path)
{
    struct image im = {0};
    FILE *f = fopen(path, "rb");
    CHECK(f != NULL);
    fseek(f, 0, SEEK_END);
    im.len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    im.data = malloc(im.len);
    CHECK(im.data && fread(im.data, 1, im.len, f) == im.len);
    fclose(f);
    const struct mach_header_64 *h = (const void *)im.data;
    CHECK(h->magic == MH_MAGIC_64);
    const uint8_t *lc = im.data + sizeof(*h);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)c)->segname, "__TEXT")) {
            im.text_vm = ((const struct segment_command_64 *)c)->vmaddr;
            im.text_off = ((const struct segment_command_64 *)c)->fileoff;
        }
        lc += c->cmdsize;
    }
    CHECK(im.text_vm != 0);
    return im;
}

static uint64_t symbol(const struct image *im, const char *name)
{
    const struct mach_header_64 *h = (const void *)im->data;
    const uint8_t *lc = im->data + sizeof(*h);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_SYMTAB) {
            const struct symtab_command *s = (const void *)c;
            const struct nlist_64 *nl = (const void *)(im->data + s->symoff);
            const char *str = (const char *)im->data + s->stroff;
            for (uint32_t k = 0; k < s->nsyms; k++)
                if (nl[k].n_un.n_strx && !strcmp(str + nl[k].n_un.n_strx, name) && (nl[k].n_type & N_TYPE) == N_SECT)
                    return nl[k].n_value;
        }
        lc += c->cmdsize;
    }
    return 0;
}

/* The function in this process, only if its code is the extracted image's. */
static void *resolve(const struct image *im, const uint8_t *base, const char *name)
{
    uint64_t vm = symbol(im, name);
    CHECK(vm != 0);
    const uint8_t *live = base + (vm - im->text_vm);
    CHECK(memcmp(live, im->data + (vm - im->text_vm + im->text_off), 48) == 0);
    return (void *)live;
}

typedef uint64_t (*v7_header_fn)(uint8_t *out, const uint8_t *p, unsigned len);
typedef uint64_t (*v7_contact_fn)(uint8_t *out, const uint8_t *p, unsigned len);
typedef int (*surface_fn)(const void *d, int len, void *out, long device);
typedef int (*param_fn)(const void *d, int len, void *out, long device);
typedef int (*regions_fn)(const uint8_t *d, unsigned len, uint8_t *out, unsigned max);

static v7_header_fn mt_header;
static v7_contact_fn mt_contact;

/* ------------------------------------------------------------------- HSTouch ---- */
static id parser;
static ptrdiff_t contacts_ivar, timestamp_ivar, state_ivar;

static ptrdiff_t ivar_like(Class c, const char *part)
{
    unsigned n = 0;
    Ivar *list = class_copyIvarList(c, &n);
    ptrdiff_t at = -1;
    for (unsigned i = 0; i < n && at < 0; i++)
        if (strstr(ivar_getName(list[i]), part))
            at = ivar_getOffset(list[i]);
    free(list);
    return at;
}

static void hstouch_open(const uint8_t *d9)
{
    void *h = dlopen("/System/Library/HIDPlugins/ServicePlugins/HSTouchHIDService.plugin/Contents/MacOS/HSTouchHIDService",
                     RTLD_NOW | RTLD_LOCAL);
    CHECK(h != NULL);
    Class p = objc_getClass("HSTFrameParser"), f = objc_getClass("HSTContactFrame");
    CHECK(p && f);
    parser = class_createInstance(p, 0);
    Ivar config = class_getInstanceVariable(p, "_config");
    CHECK(parser && config);
    /* SurfaceCoordinates::fromService: (xmin, xmax, ymin, ymax) x 10 from the descriptor's int16s. */
    int32_t *cfg = (int32_t *)((uint8_t *)(__bridge void *)parser + ivar_getOffset(config));
    int16_t xmin, ymin, xmax, ymax;
    memcpy(&xmin, d9 + 8, 2); memcpy(&ymin, d9 + 10, 2); memcpy(&xmax, d9 + 12, 2); memcpy(&ymax, d9 + 14, 2);
    cfg[0] = xmin * 10; cfg[1] = xmax * 10; cfg[2] = ymin * 10; cfg[3] = ymax * 10;
    contacts_ivar = ivar_like(f, "contacts");
    timestamp_ivar = ivar_like(f, "firmwareTimestamp");
    state_ivar = ivar_like(f, "deviceOperatingState");
    CHECK(contacts_ivar >= 0 && timestamp_ivar >= 0 && state_ivar >= 0);
}

/* One HSTouch contact: ID, stage, finger, position in micrometres from the surface origin. */
struct hc { unsigned id, stage, finger; int32_t x, y; };

static unsigned hstouch_parse(const uint8_t *frame, uint32_t len, struct hc *out, unsigned max, int64_t *ts,
                              unsigned *state)
{
    NSData *data = [NSData dataWithBytes:frame length:len];
    id fr = ((id (*)(id, SEL, id))objc_msgSend)(parser, sel_registerName("parseContactFrame31:"), data);
    CHECK(fr != nil);
    uint8_t *base = (uint8_t *)(__bridge void *)fr;
    uint8_t **vec = (uint8_t **)(base + contacts_ivar);   /* std::vector<HSTPipeline::Contact>: begin, end */
    unsigned n = (unsigned)((vec[1] - vec[0]) / 0x40);
    CHECK(n <= max);
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *c = vec[0] + 0x40 * i;
        out[i].id = c[0];
        out[i].stage = c[1];
        out[i].finger = c[2];
        memcpy(&out[i].x, c + 0x10, 4);
        memcpy(&out[i].y, c + 0x14, 4);
    }
    memcpy(ts, base + timestamp_ivar, 8);
    memcpy(state, base + state_ivar, 4);
    return n;
}

/* ------------------------------------------------------------------- frames ---- */
static struct hid_mt2 MT;
static uint64_t now = 1000000;

/* One report through both parsers; returns the HSTouch contacts. The MultitouchSupport unpack must
 * agree with HSTouch contact for contact. */
static unsigned feed(const struct hid_ptp_contact *c, unsigned n, unsigned buttons, struct hc *hc, int tick)
{
    uint8_t r[HID_MT2_MAX_REPORT], hdr[16];
    int64_t ts;
    unsigned state, k;
    uint32_t len;
    now += 8000;
    len = tick ? hid_mt2_tick(&MT, now, r, sizeof(r)) : hid_mt2_frame(&MT, c, n, buttons, 0, 0, now, r, sizeof(r));
    CHECK(len > HID_MT2_HEADER_BYTES && r[0] == HID_MT2_REPORT_ID && (r[7] & 2));
    const uint8_t *f = r + HID_MT2_HEADER_BYTES;
    uint32_t flen = len - HID_MT2_HEADER_BYTES;
    memset(hdr, 0xaa, sizeof(hdr));
    CHECK(mt_header(hdr, f, flen) != 0 && hdr[0] == 0x31 && hdr[1] == (buttons ? 1 : 0) && hdr[3] == 0);
    k = hstouch_parse(f, flen, hc, 32, &ts, &state);
    CHECK(k == (flen - 4) / 9 && (state & 1) == 0);           /* host click off */
    for (unsigned i = 0; i < k; i++) {
        uint8_t u[32];
        int16_t x, y;
        memset(u, 0xaa, sizeof(u));
        CHECK(mt_contact(u, f + 4 + 9 * i, 9) != 0);
        memcpy(&x, u, 2);
        memcpy(&y, u + 2, 2);
        /* MultitouchSupport and HSTouch agree: ID, stage, finger, and position. */
        CHECK(u[0xa] == hc[i].id && u[0xf] == hc[i].stage && u[0xe] == hc[i].finger);
        CHECK(hc[i].x == (int32_t)x * 10 - (-2 * MT.wq) * 10 && hc[i].y == (int32_t)y * 10 - (5000 - 2 * MT.hq) * 10);
    }
    return k;
}

static const struct hc *by_stage(const struct hc *h, unsigned n, unsigned stage, unsigned which)
{
    for (unsigned i = 0; i < n; i++)
        if (h[i].stage == stage && !which--)
            return &h[i];
    return NULL;
}

/* Micrometres the touchpad itself would give (147.5 x 96.0 mm, Y up). */
static int at(const struct hc *h, int32_t x, int32_t y)
{
    int64_t wx = (int64_t)x * 147500 / 4762, wy = 96000 - (int64_t)y * 96000 / 3099;
    return h && llabs(h->x - wx) <= 50 && llabs(h->y - wy) <= 50;
}

int main(int argc, char **argv)
{
    struct hid_ptp_layout l;
    struct hc h[32];
    uint8_t d9[32], d0[32], a1[16], out[64], regions[64];
    unsigned n;
    @autoreleasepool {
        CHECK(argc == 2);
        struct image im = load_image(argv[1]);
        void *lib = dlopen("/System/Library/PrivateFrameworks/MultitouchSupport.framework/MultitouchSupport", RTLD_NOW);
        CHECK(lib != NULL);
        void *anchor = dlsym(lib, "MTDeviceGetFamilyID");
        Dl_info info;
        CHECK(anchor && dladdr(anchor, &info) && info.dli_fbase);
        const uint8_t *base = info.dli_fbase;
        CHECK((const uint8_t *)anchor == base + (symbol(&im, "_MTDeviceGetFamilyID") - im.text_vm));   /* the same image */
        mt_header = (v7_header_fn)resolve(&im, base, "__Z23MTCompactV7HeaderUnpackP28MTCompactBinaryFrameHeaderV7Phj");
        mt_contact = (v7_contact_fn)resolve(&im, base, "__Z30MTCompactV7BinaryContactUnpackP24MTCompactBinaryContactV7Phj");
        surface_fn surface = (surface_fn)resolve(&im, base, "_MTParseSensorSurfaceDescriptor");
        regions_fn region_report = (regions_fn)resolve(&im, base, "_MTParseSensorRegionsReport");
        param_fn param = (param_fn)dlsym(lib, "MTParseSensorRegionParam");
        CHECK(param != NULL);

        CHECK(hid_ptp_layout(a16_tpad_report_desc, sizeof(a16_tpad_report_desc), &l) == HID_PTP_OK);
        CHECK(hid_mt2_init(&MT, &l) == HID_MT2_OK);

        /* M4: the sensor description through Apple's parsers (a device whose Endianness is 1). */
        uint8_t device[256] = {0};
        device[100] = 1;
        CHECK(hid_mt2_feature(&MT, 0xd9, 0, d9, sizeof(d9)) == 17);
        memset(out, 0xaa, sizeof(out));
        CHECK(surface(d9 + 1, 16, out, (long)device));
        uint32_t w, hgt;
        int16_t s[4];
        memcpy(&w, out, 4); memcpy(&hgt, out + 4, 4); memcpy(s, out + 8, 8);
        CHECK(w == 14748 && hgt == 9600 && s[0] == -7374 && s[1] == 200 && s[2] == 7374 && s[3] == 9800);
        CHECK(hid_mt2_feature(&MT, 0xa1, 0, a1, sizeof(a1)) == 7);
        memset(out, 0xaa, sizeof(out));
        CHECK(param(a1 + 1, 6, out, (long)device));
        uint16_t pr[3];
        memcpy(pr, out, 6);
        CHECK(pr[0] == 0 && pr[1] == 5 && pr[2] == 0x1fc);
        CHECK(hid_mt2_feature(&MT, 0xd0, 0, d0, sizeof(d0)) == 16);
        memset(regions, 0, sizeof(regions));
        CHECK(region_report(d0 + 1, 15, regions, 4) == 2);
        hstouch_open(d9 + 1);

        /* M5: one finger at both corners and the middle (each a new touch: a jump is one, M9). */
        struct hid_ptp_contact a = {1, 1, 1, 0, 0};
        n = feed(&a, 1, 0, h, 0);
        CHECK(n == 1 && h[0].stage == 3 && h[0].finger == 2 && at(&h[0], 0, 0));
        a.x = 15; a.y = 15;
        n = feed(&a, 1, 0, h, 0);
        CHECK(n == 1 && h[0].stage == 4 && at(&h[0], 15, 15));
        a.tip = 0;
        n = feed(&a, 1, 0, h, 0);
        CHECK(n == 1 && h[0].stage == 5);
        n = feed(NULL, 0, 0, h, 1);
        CHECK(n == 1 && h[0].stage == 7);
        a = (struct hid_ptp_contact){2, 1, 1, 4762, 3099};
        n = feed(&a, 1, 0, h, 0);
        CHECK(n == 1 && at(&h[0], 4762, 3099));
        a = (struct hid_ptp_contact){3, 1, 1, 2381, 1550};
        n = feed(&a, 1, 0, h, 0);
        CHECK(n == 2 && at(by_stage(h, n, 3, 0), 2381, 1550) && by_stage(h, n, 5, 0));
        a.tip = 0;
        feed(&a, 1, 0, h, 0);
        feed(NULL, 0, 0, h, 1);
        feed(NULL, 0, 0, h, 1);                       /* the empty frame */

        /* A three-finger swipe left, then a four-finger swipe up, then a pinch: Apple's parsers see every
         * finger, in order, down then moving then lifted, in micrometres of the real surface. */
        struct hid_ptp_contact f3[3], f4[4], p2[2];
        for (unsigned i = 0; i < 3; i++)
            f3[i] = (struct hid_ptp_contact){10 + i, 1, 1, 3000, (int32_t)(1000 + 500 * i)};
        n = feed(f3, 3, 0, h, 0);
        CHECK(n == 3 && by_stage(h, n, 3, 2) && h[0].finger == 2 && h[1].finger == 3 && h[2].finger == 4);
        for (unsigned i = 0; i < n; i++)              /* evidence: what HSTouch itself made of a frame */
            printf("HSTouch contact %u: id %u stage %u finger %u at %.3f, %.3f mm (touchpad: %.3f, %.3f mm)\n", i,
                   h[i].id, h[i].stage, h[i].finger, h[i].x / 1000.0, h[i].y / 1000.0, f3[i].x * 147.5 / 4762,
                   96.0 - f3[i].y * 96.0 / 3099);
        for (int step = 0; step < 20; step++) {
            for (unsigned i = 0; i < 3; i++)
                f3[i].x -= 100;                        /* 3.1 mm per frame */
            n = feed(f3, 3, 0, h, 0);
            CHECK(n == 3 && by_stage(h, n, 4, 2) && at(&h[0], f3[0].x, f3[0].y) && at(&h[2], f3[2].x, f3[2].y));
        }
        for (unsigned i = 0; i < 3; i++)
            f3[i].tip = 0;
        n = feed(f3, 3, 0, h, 0);
        CHECK(n == 3 && by_stage(h, n, 5, 2));
        feed(NULL, 0, 0, h, 1);
        feed(NULL, 0, 0, h, 1);
        for (unsigned i = 0; i < 4; i++)
            f4[i] = (struct hid_ptp_contact){20 + i, 1, 1, (int32_t)(1200 + 700 * i), 2600};
        n = feed(f4, 4, 0, h, 0);
        CHECK(n == 4 && h[3].finger == 5);
        for (int step = 0; step < 15; step++) {
            for (unsigned i = 0; i < 4; i++)
                f4[i].y -= 100;
            n = feed(f4, 4, 0, h, 0);
            CHECK(n == 4 && by_stage(h, n, 4, 3) && at(&h[1], f4[1].x, f4[1].y));
        }
        for (unsigned i = 0; i < 4; i++)
            f4[i].tip = 0;
        feed(f4, 4, 0, h, 0);
        feed(NULL, 0, 0, h, 1);
        feed(NULL, 0, 0, h, 1);
        p2[0] = (struct hid_ptp_contact){30, 1, 1, 2200, 1500};
        p2[1] = (struct hid_ptp_contact){31, 1, 1, 2600, 1500};
        feed(p2, 2, 0, h, 0);
        for (int step = 0; step < 15; step++) {
            p2[0].x -= 40;
            p2[1].x += 40;
            n = feed(p2, 2, 0, h, 0);
            CHECK(n == 2 && at(&h[0], p2[0].x, p2[0].y) && at(&h[1], p2[1].x, p2[1].y));
        }
        /* A physical click while two fingers rest: the button bit in Apple's header. */
        n = feed(p2, 2, 1, h, 0);
        CHECK(n == 2);
        /* A palm: finger 12 (invalid) in both parsers. */
        struct hid_ptp_contact palm[3] = {p2[0], p2[1], {32, 1, 0, 4000, 2800}};
        n = feed(palm, 3, 0, h, 0);
        CHECK(n == 3 && by_stage(h, n, 3, 0) && by_stage(h, n, 3, 0)->finger == 12);
    }
    printf("test-mt2-apple-parser: %u checks passed (MultitouchSupport and HSTouchHIDService, 26A428)\n", checks);
    return 0;
}
