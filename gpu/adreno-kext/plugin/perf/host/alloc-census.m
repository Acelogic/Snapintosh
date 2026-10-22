/* SPDX-License-Identifier: MIT */
// alloc-census: how many GPU buffers the AdrenoMetal plug-in allocates and frees per frame, and with which storage and
// CPU cache modes, under a WindowServer-like frame pattern (agents/gpu-perf FAILURE-MODES.md R1-R6).
//
//   alloc-census BUNDLE OUT.json [busy_frames idle_frames burst_frames]
//
// b12v16: SPTM UPDATE_DISJOINT_MULTIPAGE (XNU changing the attributes of many pages at once: cache attributes of
// memory being wired or mapped, ref/mod tracking) went from 1,146 calls (b12v12) to 14,880, each holding the global token
// ~7.8 ms. Every buffer the plug-in creates is new IOGPU memory the kernel wires, maps and later frees; this counts them.
//
// Workload (no GPU: commits are intercepted, as desktop-scenes does; completion is delivered CENSUS_COMPLETE_MS later on
// another queue, like a pipelined GPU): each frame is one command buffer of 6 render passes x 6 draws whose constants
// come from one 256 KiB ring at 16-byte-aligned offsets that advance through the ring (phase 32 mod 64), with a
// known-extent argument and two pointer arguments, as Core Animation binds them. Phases:
//   busy   frames 16 ms apart (60 Hz)
//   idle   frames 500 ms apart (a clock tick, a cursor blink: longer than the staging pool's 300 ms idle release)
//   burst  frames 16 ms apart again
// Counted per phase: -[device newBuffer*] calls by the plug-in's device (bytes, storage mode, CPU cache mode), buffers
// freed (IOGPUMetalBuffer dealloc), setPurgeableState: calls, and the plug-in's own staging and mirror counters.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <os/lock.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (Census)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (void)didScheduleWithStartTime:(uint64_t)s endTime:(uint64_t)e error:(id)error;
- (void)didCompleteWithStartTime:(uint64_t)s endTime:(uint64_t)e error:(id)error;
@end

static _Atomic uint64_t gAllocs, gAllocBytes, gFrees, gFreeBytes, gPurgeable, gNonDefaultCache, gNonShared;
static NSMapTable *gLive;                 // buffer pointer -> length (buffers the device created)
static os_unfair_lock gLiveLock = OS_UNFAIR_LOCK_INIT;
static NSMutableDictionary<NSString *, NSNumber *> *gBySize;
static int gCompleteMs = 8;

static void noteAlloc(id buffer, NSUInteger length, MTLResourceOptions options) {
    if (!buffer) return;
    atomic_fetch_add(&gAllocs, 1); atomic_fetch_add(&gAllocBytes, length);
    if ((options & MTLResourceCPUCacheModeMask) != MTLResourceCPUCacheModeDefaultCache) atomic_fetch_add(&gNonDefaultCache, 1);
    if ((options & MTLResourceStorageModeMask) != MTLResourceStorageModeShared) atomic_fetch_add(&gNonShared, 1);
    os_unfair_lock_lock(&gLiveLock);
    [gLive setObject:@(length) forKey:buffer];
    NSString *key = [NSString stringWithFormat:@"%lu/cache%lu/storage%lu", (unsigned long)length,
                     (unsigned long)((options & MTLResourceCPUCacheModeMask) >> MTLResourceCPUCacheModeShift),
                     (unsigned long)((options & MTLResourceStorageModeMask) >> MTLResourceStorageModeShift)];
    gBySize[key] = @(gBySize[key].unsignedLongLongValue + 1);
    os_unfair_lock_unlock(&gLiveLock);
}

static void InstallHooks(NSBundle *bundle) {
    Class cb = [bundle classNamed:@"AdrenoCommandBuffer"], dc = [bundle classNamed:@"AdrenoMTLDevice"];
    class_replaceMethod(cb, @selector(adrenoDrawAvailable), imp_implementationWithBlock(^BOOL(id c) { (void)c; return YES; }), "B16@0:8");
    class_replaceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"),
                        imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }), "B16@0:8");
    // buffer creation by the plug-in's device (its own arenas and the clients' buffers alike)
    for (Class c = dc; c && c != [NSObject class]; c = class_getSuperclass(c)) {
        Method m = class_getInstanceMethod(c, @selector(newBufferWithLength:options:));
        if (!m) continue;
        IMP old = method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^id(id d, NSUInteger length, MTLResourceOptions options) {
            id b = ((id (*)(id, SEL, NSUInteger, MTLResourceOptions))old)(d, @selector(newBufferWithLength:options:), length, options);
            noteAlloc(b, length, options);
            return b;
        }));
        break;
    }
    for (Class c = dc; c && c != [NSObject class]; c = class_getSuperclass(c)) {
        Method m = class_getInstanceMethod(c, @selector(newBufferWithBytes:length:options:));
        if (!m) continue;
        IMP old = method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^id(id d, const void *p, NSUInteger length, MTLResourceOptions options) {
            id b = ((id (*)(id, SEL, const void *, NSUInteger, MTLResourceOptions))old)(d, @selector(newBufferWithBytes:length:options:), p, length, options);
            noteAlloc(b, length, options);
            return b;
        }));
        break;
    }
    Class nb = NSClassFromString(@"IOGPUMetalBuffer");
    Method dm = class_getInstanceMethod(nb, NSSelectorFromString(@"dealloc"));
    IMP oldDealloc = method_getImplementation(dm);
    method_setImplementation(dm, imp_implementationWithBlock(^(__unsafe_unretained id b) {
        os_unfair_lock_lock(&gLiveLock);
        NSNumber *length = [gLive objectForKey:b];
        if (length) [gLive removeObjectForKey:b];
        os_unfair_lock_unlock(&gLiveLock);
        if (length) { atomic_fetch_add(&gFrees, 1); atomic_fetch_add(&gFreeBytes, length.unsignedLongLongValue); }
        ((void (*)(id, SEL))oldDealloc)(b, NSSelectorFromString(@"dealloc"));
    }));
    Method pm = class_getInstanceMethod(nb, @selector(setPurgeableState:));
    if (pm) {
        IMP old = method_getImplementation(pm);
        method_setImplementation(pm, imp_implementationWithBlock(^MTLPurgeableState(id b, MTLPurgeableState s) {
            atomic_fetch_add(&gPurgeable, 1);
            return ((MTLPurgeableState (*)(id, SEL, MTLPurgeableState))old)(b, @selector(setPurgeableState:), s);
        }));
    }
    // intercept the kernel submission; complete later on another queue (a pipelined GPU)
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method commit = class_getInstanceMethod(native, @selector(commit));
    dispatch_queue_t gpu = dispatch_queue_create("census.gpu", DISPATCH_QUEUE_SERIAL);
    method_setImplementation(commit, imp_implementationWithBlock(^(id c) {
        [c didScheduleWithStartTime:0 endTime:0 error:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)gCompleteMs * NSEC_PER_MSEC), gpu, ^{
            [c didCompleteWithStartTime:0 endTime:0 error:nil];
        });
    }));
}

typedef void (*CountersFn)(uint64_t *);
static NSDictionary *snapshot(CountersFn staging, CountersFn mirror) {
    uint64_t s[4] = {0}, m[7] = {0};
    if (staging) staging(s);
    if (mirror) mirror(m);
    return @{@"allocs":@(atomic_load(&gAllocs)), @"alloc_bytes":@(atomic_load(&gAllocBytes)), @"frees":@(atomic_load(&gFrees)),
             @"free_bytes":@(atomic_load(&gFreeBytes)), @"purgeable_calls":@(atomic_load(&gPurgeable)),
             @"non_default_cache":@(atomic_load(&gNonDefaultCache)), @"non_shared":@(atomic_load(&gNonShared)),
             @"staging_new":@(s[0]), @"staging_reused":@(s[1]), @"staging_pooled":@(s[2]), @"staging_released":@(s[3]),
             @"mirror_copies":@(m[0]), @"mirror_reads":@(m[2]), @"mirror_fallbacks":@(m[3]), @"inpass":@(m[4])};
}
static NSDictionary *delta(NSDictionary *a, NSDictionary *b, NSUInteger frames) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (NSString *k in b) {
        double v = [b[k] doubleValue] - [a[k] doubleValue];
        d[k] = @(v); d[[k stringByAppendingString:@"_per_frame"]] = @(frames ? v / frames : 0);
    }
    d[@"frames"] = @(frames);
    return d;
}

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc < 3) { fprintf(stderr, "usage: alloc-census BUNDLE OUT.json [busy idle burst]\n"); return 64; }
    NSUInteger busy = argc > 3 ? strtoul(argv[3], 0, 10) : 180, idle = argc > 4 ? strtoul(argv[4], 0, 10) : 12,
               burst = argc > 5 ? strtoul(argv[5], 0, 10) : 60;
    if (getenv("CENSUS_COMPLETE_MS")) gCompleteMs = atoi(getenv("CENSUS_COMPLETE_MS"));
    gLive = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsOpaqueMemory | NSPointerFunctionsOpaquePersonality
                                  valueOptions:NSPointerFunctionsStrongMemory];
    gBySize = [NSMutableDictionary dictionary];
    (void)MTLCopyAllDevices();
    NSError *error = nil;
    NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])];
    if (![bundle loadAndReturnError:&error]) { fprintf(stderr, "bundle: %s\n", error.description.UTF8String); return 65; }
    InstallHooks(bundle);
    void *h = dlopen(bundle.executablePath.UTF8String, RTLD_NOLOAD | RTLD_LAZY);
    CountersFn staging = h ? (CountersFn)dlsym(h, "AdrenoStagingCounters") : NULL;
    CountersFn mirror = h ? (CountersFn)dlsym(h, "AdrenoUBOMirrorCounters") : NULL;
    io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:acc];
    if (!device) return 67;
    MTLAddDevice(device);
    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "struct U { float4 tint; float4 extra; };\n"
        "vertex float4 vs(uint i [[vertex_id]], constant float4 *pts [[buffer(1)]]) { return float4(pts[i].xy, 0, 1); }\n"
        "fragment float4 fs(constant U &u [[buffer(0)]], constant float4 *p [[buffer(2)]]) { return u.tint * u.extra + p[1] + p[0]; }\n";
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
    if (!library) { fprintf(stderr, "library: %s\n", error.description.UTF8String); return 68; }
    MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
    pd.vertexFunction = [library newFunctionWithName:@"vs"];
    pd.fragmentFunction = [library newFunctionWithName:@"fs"];
    pd.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    id<MTLRenderPipelineState> pipe = [device newRenderPipelineStateWithDescriptor:pd error:&error];
    if (!pipe) return 69;
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:256 height:256 mipmapped:NO];
    td.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    td.storageMode = MTLStorageModeShared;
    id<MTLTexture> target = [device newTextureWithDescriptor:td];
    id<MTLBuffer> ring = [device newBufferWithLength:256 * 1024 options:MTLResourceStorageModeShared];
    for (NSUInteger i = 0; i < ring.length / 4; i++) ((float *)ring.contents)[i] = (float)(i % 97) * 0.01f;
    id<MTLCommandQueue> queue = [device newCommandQueue];
    __block NSUInteger cursor = 0;
    void (^frame)(void) = ^{
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [queue commandBuffer];
            for (int p = 0; p < 6; p++) {
                MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
                rp.colorAttachments[0].texture = target;
                rp.colorAttachments[0].loadAction = p ? MTLLoadActionLoad : MTLLoadActionClear;
                rp.colorAttachments[0].storeAction = MTLStoreActionStore;
                id<MTLRenderCommandEncoder> e = [cb renderCommandEncoderWithDescriptor:rp];
                [e setRenderPipelineState:pipe];
                for (int d = 0; d < 6; d++) {
                    NSUInteger base = 32 + 64 * (cursor % 3800);     // stays below the ring's end with room for 160 B
                    cursor += 3;
                    [e setVertexBuffer:ring offset:base + 96 atIndex:1];
                    [e setFragmentBuffer:ring offset:base atIndex:0];
                    [e setFragmentBuffer:ring offset:base + 64 atIndex:2];
                    [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
                }
                [e endEncoding];
            }
            [cb commit];
        }
    };
    NSMutableDictionary *phases = [NSMutableDictionary dictionary];
    NSArray *plan = @[@[@"warmup", @(20), @(16)], @[@"busy", @(busy), @(16)], @[@"idle", @(idle), @(500)],
                      @[@"burst", @(burst), @(16)], @[@"idle2", @(idle), @(500)]];
    for (NSArray *ph in plan) {
        NSUInteger n = [ph[1] unsignedIntegerValue]; int gap = [ph[2] intValue];
        NSDictionary *a = snapshot(staging, mirror);
        for (NSUInteger i = 0; i < n; i++) { frame(); usleep((useconds_t)gap * 1000); }
        usleep(50 * 1000);                                    // let the last completions land
        phases[ph[0]] = delta(a, snapshot(staging, mirror), n);
    }
    NSDictionary *report = @{@"bundle":@(argv[1]), @"complete_ms":@(gCompleteMs), @"phases":phases, @"by_size":gBySize,
                             @"totals":snapshot(staging, mirror)};
    NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    [json writeToFile:@(argv[2]) atomically:YES];
    for (NSString *p in @[@"busy", @"idle", @"burst", @"idle2"]) {
        NSDictionary *d = phases[p];
        printf("%-6s frames %3.0f  allocs/frame %6.2f  frees/frame %6.2f  KiB allocated/frame %8.1f  staging new %4.0f reused %5.0f  mirror copies %5.0f fallbacks %3.0f inpass %5.0f\n",
               p.UTF8String, [d[@"frames"] doubleValue], [d[@"allocs_per_frame"] doubleValue], [d[@"frees_per_frame"] doubleValue],
               [d[@"alloc_bytes_per_frame"] doubleValue] / 1024, [d[@"staging_new"] doubleValue], [d[@"staging_reused"] doubleValue],
               [d[@"mirror_copies"] doubleValue], [d[@"mirror_fallbacks"] doubleValue], [d[@"inpass"] doubleValue]);
    }
    printf("non-default cache-mode buffers %llu, non-shared %llu, setPurgeableState calls %llu\n",
           (unsigned long long)atomic_load(&gNonDefaultCache), (unsigned long long)atomic_load(&gNonShared),
           (unsigned long long)atomic_load(&gPurgeable));
    return 0;
} }
