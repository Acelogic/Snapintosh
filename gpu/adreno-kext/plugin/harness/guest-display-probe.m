/* SPDX-License-Identifier: MIT */
// Guest display probe: one CPU-drawn 2880x1800 BGRA IOSurface -> IOMobileFramebuffer main
// display swap -> AdrenoDisplay copies it into the A16 GOP framebuffer.
// Build: tools/build-adreno-display-probe.py. Host E2E (no swap): tools/test-adreno-display.py.
//
// Failure inventory (each ends in exactly one ADRENO-VERDICT line, never a hang):
//   no IOMobileFramebuffer.framework / symbol        status=NO_FRAMEWORK
//   GetMainDisplay never succeeds within --wait      status=NO_MAIN_DISPLAY kr=<last>
//   the main display is not AdrenoDisplay            reported as service=<class>; status=WRONG_SERVICE
//   display size is not 2880x1800                    status=WRONG_SIZE size=<w>x<h>
//   IOSurface create/lock fails                      status=NO_SURFACE
//   pattern too weak (<64 distinct pixels, symmetric) status=WEAK_PATTERN (a probe bug)
//   SwapBegin/SetLayer/SwapEnd returns an error      status=SWAP_FAILED stage=<call> kr=<kr>
//   SwapWait errors or does not return in 15 s       status=SWAP_WAIT_FAILED / SWAP_WAIT_TIMEOUT
//   swap completed                                   status=PRESENTED
// The expected panel hashes are printed in every verdict that got as far as the surface:
//   surface_sha256   SHA-256 of the 2880x1800 pixels as B,G,R,A bytes, rows tightly packed
//                    (= the raw GOP region, whose pitch is 11520 = 2880*4 on the A16)
//   panel_rgb_sha256 SHA-256 of the same pixels as R,G,B triplets, row-major
//                    (= hashlib.sha256(PIL.Image.open(capture-panel.png).convert('RGB').tobytes()))
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurface.h>
#import <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { Width = 2880, Height = 1800, PixelBytes = 4 };
static const uint32_t FormatBGRA = 0x42475241;   // 'BGRA'

typedef struct __IOMobileFramebuffer *IOMobileFramebufferRef;
// Register use of the 26A428 wrappers (each tail-calls a per-connection function pointer
// loaded into the first free argument register): SwapBegin x2 -> (fb, int *token);
// SwapSetLayer x4 -> (fb, int layer, IOSurfaceRef, CGRect src, CGRect dst, int flags);
// SwapEnd x1 -> (fb); SwapWait x3 -> (fb, token, uint32) = selector 6 {token, a, 0};
// SwapWaitWithTimeout x3 + d0 -> selector 6 {token, a, seconds * 1000.0} (constant at
// 0x18ff13bc0); GetDisplaySize x2 -> (fb, CGSize *); GetServiceObject reads fb+0x10.
typedef kern_return_t (*GetMainDisplayFn)(IOMobileFramebufferRef *);
typedef io_service_t (*GetServiceObjectFn)(IOMobileFramebufferRef);
typedef kern_return_t (*GetDisplaySizeFn)(IOMobileFramebufferRef, CGSize *);
typedef kern_return_t (*SwapBeginFn)(IOMobileFramebufferRef, int *);
typedef kern_return_t (*SwapSetLayerFn)(IOMobileFramebufferRef, int, IOSurfaceRef, CGRect, CGRect, int);
typedef kern_return_t (*SwapEndFn)(IOMobileFramebufferRef);
typedef kern_return_t (*SwapWaitFn)(IOMobileFramebufferRef, int, int);
typedef kern_return_t (*SwapWaitTimeoutFn)(IOMobileFramebufferRef, int, int, double);

static double seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) abort();
    return value.tv_sec + value.tv_nsec / 1e9;
}

static BOOL consoleEnabled = YES;   // --no-swap (host E2E) writes stdout only
static void emit(NSString *text) {
    fprintf(stdout, "%s\n", text.UTF8String);
    fflush(stdout);
    int fd = consoleEnabled ? open("/dev/console", O_WRONLY | O_NOCTTY) : -1;
    if (fd >= 0) { dprintf(fd, "%s\n", text.UTF8String); close(fd); }
}

// Deterministic, asymmetric test image. Orientation blocks: top-left red, top-right green,
// bottom-left blue (bottom-right keeps the gradient), so a flip, transpose-like crop or
// R/B swap is visible and changes both hashes. Everything else is a mixed gradient with
// thousands of distinct values.
static void pattern(uint32_t x, uint32_t y, uint8_t px[4]) {
    uint8_t b = (uint8_t)(x + 3 * y);
    uint8_t g = (uint8_t)((x >> 2) ^ (y >> 1));
    uint8_t r = (uint8_t)((x * x + 7 * y) >> 5);
    const uint32_t block = 120;
    if (y < block && x < block) { r = 0xff; g = 0; b = 0; }
    else if (y < block && x >= Width - block) { r = 0; g = 0xff; b = 0; }
    else if (y >= Height - block && x < block) { r = 0; g = 0; b = 0xff; }
    px[0] = b; px[1] = g; px[2] = r; px[3] = 0xff;
}

static NSString *hex(const unsigned char *hash) {
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (unsigned i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [text appendFormat:@"%02x", hash[i]];
    return text;
}

typedef struct {
    NSString *surfaceSHA, *panelSHA;
    unsigned distinct;
    BOOL asymmetric;
} Expected;

// Hashes and pattern-strength checks computed from the surface bytes actually written.
static Expected measure(const uint8_t *base, size_t rowBytes) {
    Expected e = {0};
    CC_SHA256_CTX raw, rgb;
    CC_SHA256_Init(&raw); CC_SHA256_Init(&rgb);
    uint8_t *line = malloc(Width * 3);
    NSMutableSet *seen = [NSMutableSet set];
    for (uint32_t y = 0; y < Height; y++) {
        const uint8_t *row = base + (size_t)y * rowBytes;
        CC_SHA256_Update(&raw, row, Width * PixelBytes);
        for (uint32_t x = 0; x < Width; x++) {
            line[x * 3 + 0] = row[x * 4 + 2];
            line[x * 3 + 1] = row[x * 4 + 1];
            line[x * 3 + 2] = row[x * 4 + 0];
            if (seen.count < 4096 && !(x % 7) && !(y % 5)) {
                uint32_t v; memcpy(&v, row + x * 4, 4); [seen addObject:@(v)];
            }
        }
        CC_SHA256_Update(&rgb, line, Width * 3);
    }
    free(line);
    unsigned char h[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(h, &raw); e.surfaceSHA = hex(h);
    CC_SHA256_Final(h, &rgb); e.panelSHA = hex(h);
    e.distinct = (unsigned)seen.count;
    // Horizontal flip, vertical flip and R<->B swap must each change at least one pixel.
    BOOL hflip = NO, vflip = NO, swap = NO;
    for (uint32_t y = 0; y < Height && !(hflip && vflip && swap); y += 37)
        for (uint32_t x = 0; x < Width; x += 41) {
            const uint8_t *p = base + (size_t)y * rowBytes + x * 4;
            const uint8_t *h1 = base + (size_t)y * rowBytes + (Width - 1 - x) * 4;
            const uint8_t *v1 = base + (size_t)(Height - 1 - y) * rowBytes + x * 4;
            if (memcmp(p, h1, 4)) hflip = YES;
            if (memcmp(p, v1, 4)) vflip = YES;
            if (p[0] != p[2]) swap = YES;
        }
    e.asymmetric = hflip && vflip && swap;
    return e;
}

static int finish(NSMutableDictionary *report, NSString *path, NSString *line, int code) {
    report[@"verdict"] = line;
    if (path) {
        NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                       options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
                                                         error:nil];
        if (data) [data writeToFile:path atomically:YES];
    }
    emit(line);
    return code;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        double waitSeconds = 120, holdSeconds = 0;
        BOOL swapEnabled = YES;
        NSString *emitPath = nil, *base = @"/var/db/Snapintosh/display-probe";
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "--no-swap")) swapEnabled = consoleEnabled = NO;
            else if (!strcmp(argv[i], "--emit-surface") && i + 1 < argc) emitPath = @(argv[++i]);
            else if (!strcmp(argv[i], "--report-base") && i + 1 < argc) base = @(argv[++i]);
            else if ((!strcmp(argv[i], "--wait") || !strcmp(argv[i], "--hold")) && i + 1 < argc) {
                const char *flag = argv[i];
                char *end = NULL;
                double value = strtod(argv[++i], &end);
                if (!end || *end || !isfinite(value) || value < 0 || value > 3600) return 64;
                if (!strcmp(flag, "--wait")) waitSeconds = value; else holdSeconds = value;
            } else {
                fprintf(stderr, "usage: %s [--no-swap] [--emit-surface PATH] [--report-base PATH] "
                                "[--wait S] [--hold S]\n", argv[0]);
                return 64;
            }
        }
        NSString *path = nil;
        if (swapEnabled) {
            if (!base.isAbsolutePath) return 64;
            [[NSFileManager defaultManager] createDirectoryAtPath:base.stringByDeletingLastPathComponent
                                      withIntermediateDirectories:YES attributes:nil error:nil];
            path = [NSString stringWithFormat:@"%@-%@.json", base, NSUUID.UUID.UUIDString];
        }
        NSMutableDictionary *report = [@{@"schema": @"snapintosh-display-probe/1", @"pid": @(getpid()),
            @"width": @(Width), @"height": @(Height), @"format": @"BGRA",
            @"boundary": @"CPU-drawn IOSurface through IOMobileFramebuffer to the GOP panel; proves "
                         @"the display path, not GPU rendering or WindowServer."} mutableCopy];
        emit(@"SnapintoshDisplayProbe: start");

        // 1. The surface and its expected panel image (identical in --no-swap mode).
        NSDictionary *props = @{(id)kIOSurfaceWidth: @(Width), (id)kIOSurfaceHeight: @(Height),
                                (id)kIOSurfaceBytesPerElement: @(PixelBytes),
                                (id)kIOSurfacePixelFormat: @(FormatBGRA)};
        IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        if (!surface || IOSurfaceLock(surface, 0, NULL))
            return finish(report, path, @"ADRENO-VERDICT display status=NO_SURFACE", 3);
        uint8_t *pixels = IOSurfaceGetBaseAddress(surface);
        size_t rowBytes = IOSurfaceGetBytesPerRow(surface), allocSize = IOSurfaceGetAllocSize(surface);
        memset(pixels, 0, allocSize);
        for (uint32_t y = 0; y < Height; y++)
            for (uint32_t x = 0; x < Width; x++)
                pattern(x, y, pixels + (size_t)y * rowBytes + x * 4);
        Expected expected = measure(pixels, rowBytes);
        if (emitPath) {
            // 'ADSF' header (u32 magic, width, height, format; u64 row_bytes, offset, length) + bytes.
            NSMutableData *dump = [NSMutableData data];
            uint32_t head32[4] = {0x46534441u, Width, Height, FormatBGRA};
            uint64_t head64[3] = {rowBytes, 0, allocSize};
            [dump appendBytes:head32 length:sizeof head32];
            [dump appendBytes:head64 length:sizeof head64];
            [dump appendBytes:pixels length:allocSize];
            if (![dump writeToFile:emitPath atomically:YES]) return 73;
        }
        IOSurfaceUnlock(surface, 0, NULL);
        report[@"row_bytes"] = @(rowBytes);
        report[@"surface_sha256"] = expected.surfaceSHA;
        report[@"panel_rgb_sha256"] = expected.panelSHA;
        report[@"distinct_sampled"] = @(expected.distinct);
        NSString *hashes = [NSString stringWithFormat:@"row_bytes=%zu distinct=%u surface_sha256=%@ panel_rgb_sha256=%@",
                            rowBytes, expected.distinct, expected.surfaceSHA, expected.panelSHA];
        if (expected.distinct < 64 || !expected.asymmetric)
            return finish(report, path, [@"ADRENO-VERDICT display status=WEAK_PATTERN " stringByAppendingString:hashes], 4);
        if (!swapEnabled)
            return finish(report, path, [@"ADRENO-VERDICT display status=NO_SWAP_REQUESTED " stringByAppendingString:hashes], 0);

        // 2. The main display, as QuartzCore finds it.
        void *framework = dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer",
                                 RTLD_NOW | RTLD_LOCAL);
        GetMainDisplayFn getMain = framework ? (GetMainDisplayFn)dlsym(framework, "IOMobileFramebufferGetMainDisplay") : NULL;
        GetServiceObjectFn getService = framework ? (GetServiceObjectFn)dlsym(framework, "IOMobileFramebufferGetServiceObject") : NULL;
        GetDisplaySizeFn getSize = framework ? (GetDisplaySizeFn)dlsym(framework, "IOMobileFramebufferGetDisplaySize") : NULL;
        SwapBeginFn swapBegin = framework ? (SwapBeginFn)dlsym(framework, "IOMobileFramebufferSwapBegin") : NULL;
        SwapSetLayerFn swapSetLayer = framework ? (SwapSetLayerFn)dlsym(framework, "IOMobileFramebufferSwapSetLayer") : NULL;
        SwapEndFn swapEnd = framework ? (SwapEndFn)dlsym(framework, "IOMobileFramebufferSwapEnd") : NULL;
        SwapWaitFn swapWait = framework ? (SwapWaitFn)dlsym(framework, "IOMobileFramebufferSwapWait") : NULL;
        SwapWaitTimeoutFn swapWaitTimeout = framework ? (SwapWaitTimeoutFn)dlsym(framework, "IOMobileFramebufferSwapWaitWithTimeout") : NULL;
        if (!getMain || !getService || !getSize || !swapBegin || !swapSetLayer || !swapEnd || (!swapWait && !swapWaitTimeout))
            return finish(report, path, [@"ADRENO-VERDICT display status=NO_FRAMEWORK " stringByAppendingString:hashes], 5);
        IOMobileFramebufferRef fb = NULL;
        kern_return_t kr = KERN_FAILURE;
        double start = seconds();
        emit(@"SnapintoshDisplayProbe: waiting for IOMobileFramebufferGetMainDisplay");
        while ((kr = getMain(&fb)) != KERN_SUCCESS || !fb) {
            if (seconds() - start >= waitSeconds) break;
            sleep(1);
        }
        report[@"main_display_seconds"] = @(seconds() - start);
        if (kr != KERN_SUCCESS || !fb)
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=NO_MAIN_DISPLAY kr=0x%x %@", kr, hashes], 6);
        io_service_t service = getService(fb);
        io_name_t className = "?";
        uint64_t registryID = 0;
        if (service) { IOObjectGetClass(service, className); IORegistryEntryGetRegistryEntryID(service, &registryID); }
        CGSize size = {0, 0};
        kern_return_t sizeKR = getSize(fb, &size);
        NSString *identity = [NSString stringWithFormat:@"service=%s id=0x%llx size=%.0fx%.0f", className,
                              registryID, size.width, size.height];
        report[@"service_class"] = @(className);
        report[@"registry_id"] = @(registryID);
        if (strcmp(className, "AdrenoDisplay") && strcmp(className, "AppleParavirtDisplay"))
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=WRONG_SERVICE %@ %@", identity, hashes], 7);
        if (sizeKR != KERN_SUCCESS || size.width != Width || size.height != Height)
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=WRONG_SIZE kr=0x%x %@ %@", sizeKR, identity, hashes], 8);

        // 3. One swap of layer 0, full screen, 1:1.
        int token = 0;
        CGRect full = CGRectMake(0, 0, Width, Height);
        emit([@"SnapintoshDisplayProbe: swapping " stringByAppendingString:identity]);
        if ((kr = swapBegin(fb, &token)))
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=SWAP_FAILED stage=begin kr=0x%x %@ %@", kr, identity, hashes], 9);
        if ((kr = swapSetLayer(fb, 0, surface, full, full, 0)))
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=SWAP_FAILED stage=set_layer kr=0x%x %@ %@", kr, identity, hashes], 9);
        if ((kr = swapEnd(fb)))
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=SWAP_FAILED stage=end kr=0x%x %@ %@", kr, identity, hashes], 9);
        // SwapWait in the background so a swap that never retires still ends in a verdict.
        __block kern_return_t waitKR = KERN_FAILURE;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            waitKR = swapWaitTimeout ? swapWaitTimeout(fb, token, 0, 10.0) : swapWait(fb, token, 0);
            dispatch_semaphore_signal(done);
        });
        double swapStart = seconds();
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)))
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=SWAP_WAIT_TIMEOUT token=%d %@ %@", token, identity, hashes], 10);
        report[@"swap_wait_seconds"] = @(seconds() - swapStart);
        if (waitKR)
            return finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=SWAP_WAIT_FAILED kr=0x%x token=%d %@ %@", waitKR, token, identity, hashes], 11);
        int code = finish(report, path, [NSString stringWithFormat:@"ADRENO-VERDICT display status=PRESENTED token=%d %@ %@", token, identity, hashes], 0);
        if (holdSeconds > 0) sleep((unsigned)holdSeconds);   // keep the client (and surface) alive
        CFRelease(surface);
        return code;
    }
}
