/* SPDX-License-Identifier: MIT */
// CoreAnimation's generic pipeline on a device without framebuffer fetch (docs/USERSPACE-GRAPHICS-20261019.md, "Why
// rounded rects, blur and backdrop render black"). Renders the glass probe's scenes (glass-probe.js: 96x64 CARenderer
// targets on a 0xcccccc root) and records, for every draw, the label of the pipeline Core Animation bound.
//   ca-generic --host-caps BUNDLE OUT SCENE...   this Mac's GPU renders, answering every capability selector the way the
//                                                plug-in device does (the device is created from BUNDLE and asked), so
//                                                Core Animation picks the plug-in's pipelines; pixels are real
//   DYLD_INSERT_LIBRARIES=default-device-interpose.dylib ca-generic --adreno BUNDLE OUT SCENE...
//                                                the plug-in device renders; commits are intercepted and marked complete
//                                                (OUT/commit-NNN/commands.bin for the kext validator); no pixels
//   ca-generic --host BUNDLE OUT SCENE...        this Mac's GPU with its own answers (the reference for the clip scenes)
// CA_BENCH=1: a 2880x1800 target, and the bench-desk / bench-glass / bench-blurfull scenes (four rounded windows with
// shadows and sublayers over a gradient; plus a backdrop blur; a full-target blur) render CA_BENCH_FRAMES frames each
// (default 23), printing "BENCH scene mean ms min ms" over all but the first three (the plug-in's per-frame CPU cost
// with --adreno, whose commits complete at once).
// Drag-shaped bench scenes (docs/PLUGIN-DRAG-SPEED-20261020.md; CA_BENCH only): drag-window (a rounded, shadowed window
// with a title bar and rows moving 24,12 px per frame across three others), drag-glass (a rounded 640x420 backdrop
// blur moving across the windows), scroll-list (a clipped window whose 24 recycled rows move 30 px per frame, as a
// table view's; CoreAnimation draws the damaged rows once per damage rectangle, about 520 draws in one pass, past what
// one IB package holds, so the plug-in drops the draws beyond it), drag-surfaces (windows as
// WindowServer composites them: image layers with the app's content, rounded and clipped, over rounded shadows; one
// moves 24,12 px per frame). Each
// frame moves its layer in a transaction, then renders only CARenderer's own damage (the first frame renders all), as a
// compositor does. The BENCH line adds "cpu" (the render thread's CPU time per frame) and "proc" (the process's CPU
// time per frame, every thread). CA_BENCH_NOCAPTURE=1 keeps the commit hook from writing commands.bin (file writes
// inside the timed frame); CA_BENCH_FULL=1 renders the whole target every frame in the drag scenes too.
// CA_TEST_FETCH=0|1 makes the plug-in device answer isFramebufferReadSupported that way (after it is created), so a
// control run can ask for the profile without framebuffer fetch. Scenes clip-cont / clip-circ: a window-like box that
// clips its sublayers with rounded corners, which Core Animation draws by restoring the backdrop outside the corners
// (Tbds), a pipeline that reads the destination by framebuffer fetch (docs/USERSPACE-GRAPHICS-20261019.md, "Window
// corner wedges").
// CA_GENERIC_TEST_DELAY_MS (default 2000) slows every specialised pipeline compile, as the A16's compiles are slow
// (Core Animation times its compiles and, when they are slow, builds the next ones on a background queue and draws with
// its generic pipeline meanwhile); the generic pipeline itself is never slowed.
// First a warm-up frame (CA_GENERIC_TEST_WARMUP, default "square") is rendered and every pipeline request is let finish,
// as in a long-running WindowServer whose generic pipeline is already built; then the scenes.
// OUT/report.json: per scene the draws (pipeline label, generic or not), commits and work reports; OUT/SCENE.bgra.
// UBO staging arenas (docs/PLUGIN-ARENA-TRIM-20261021.md; --adreno with CA_BENCH only; without these variables the
// harness behaves as before):
//   CA_BENCH_LAG=N            a command buffer committed during frame f completes at the end of frame f+N-1 (on the
//                             render thread, between frames, in commit order), as the A16's slow GPU keeps frames in
//                             flight; a watchdog completes one pending for 250 ms (Core Animation waiting on it) and
//                             counts it; each scene's end completes the rest. The bench's own fence is not waited on.
//   CA_BENCH_ARENAS=1         an independent gauge of the plug-in's staging arenas: the device's
//                             newBufferWithLength:options: called from the plug-in's staging code (dladdr of the return
//                             address) gets a dealloc sentinel. Per scene an ARENAS line (peak, end and idle live arenas
//                             and KiB; new arenas after the warm-up frames); report.json gains the arena events and each
//                             commit's frame, sequence and completion; PLUGIN-STAGING prints the plug-in's own counters.
//   CA_BENCH_IDLE_MS=N        after each scene and its completions, N ms without a plug-in call, then the gauge again
//   CA_BENCH_RELIEVE_EVERY=K  every K frames, the plug-in's AdrenoStagingRelieve() (a forced drain), when exported
//   CA_BENCH_FAULTS=1         after the scenes, allocation failures injected into IOGPU buffer and texture creation
//   CA_BENCH_FINAL_IDLE_MS=N  at the end, N ms idle, the gauge and the plug-in's timer fire count, then 1.5 s more
//   clang -arch arm64e -fobjc-arc -O1 ca-generic.m -o ca-generic -framework Foundation -framework Metal \
//     -framework QuartzCore -framework IOSurface -framework IOKit -framework CoreGraphics
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <ptrauth.h>
#import <pthread.h>
#import <stdatomic.h>
#import <sys/resource.h>
#import <time.h>

extern void MTLAddDevice(id<MTLDevice>);
extern void *objc_autoreleasePoolPush(void);
extern void objc_autoreleasePoolPop(void *);
@interface NSObject (CAGenericHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (void)didScheduleWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (void)didCompleteWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
+ (instancetype)filterWithType:(NSString *)type;
- (BOOL)isFramebufferReadSupported;
@end

static NSString *Out, *Scene = @"";
static NSMutableArray *Draws, *Commits, *Pipelines;
static NSMapTable *Labels;            // pipeline state -> label
static NSString *Bound = @"";
static NSMutableSet *Hooked;
static void *ReservedStart; static NSUInteger ReservedLength;
static useconds_t DelayUs = 2000000;
static _Atomic int InFlight;

// ---- staging arenas: lagged completion and the independent gauge (see the header) ----
static BOOL once(Method m);
static int LagFrames, ArenaMode;
static uint64_t FrameNo;                        // frames ended (render thread)
static NSMutableArray *Pending;                 // {cb, frame, index, t}, commit order
static pthread_mutex_t PendingLock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;
static _Atomic uint64_t Seq, Completed, ArenaLive, ArenaLiveBytes, ArenaPeak, ArenaPeakBytes, ArenaNew, Watchdogs;
static _Atomic uint64_t ArenaPeakAll, ArenaPeakAllBytes;   // over the whole run (ArenaPeak* restart with each scene)
static NSMutableArray *ArenaEvents, *FrameStarts;   // FrameStarts: each frame's first sequence number (index = frame)
static uint64_t nextSeq(void) { return atomic_fetch_add(&Seq, 1) + 1; }
static void raisePeak(_Atomic uint64_t *peak, uint64_t v) {
    uint64_t p = atomic_load(peak);
    while (v > p && !atomic_compare_exchange_weak(peak, &p, v)) {}
}
static uint32_t resourceIDOf(id r) {
    SEL s = sel_registerName("resourceID");
    return [r respondsToSelector:s] ? ((uint32_t (*)(id, SEL))objc_msgSend)(r, s) : 0;
}
// Command buffers still alive (they keep their arenas): one sentinel per committed command buffer.
static _Atomic uint64_t LiveCommandBuffers;
@interface HarnessCBSentinel : NSObject @end
@implementation HarnessCBSentinel
- (void)dealloc { atomic_fetch_sub(&LiveCommandBuffers, 1); }
@end
@interface HarnessArenaSentinel : NSObject { @public uint32_t rid; uint64_t bytes; } @end
@implementation HarnessArenaSentinel
- (void)dealloc {
    atomic_fetch_sub(&ArenaLive, 1); atomic_fetch_sub(&ArenaLiveBytes, bytes);
    NSDictionary *e = @{@"event":@"free", @"rid":@(rid), @"bytes":@(bytes), @"seq":@(nextSeq()),
                        @"completed":@(atomic_load(&Completed))};
    @synchronized (ArenaEvents) { [ArenaEvents addObject:e]; }
}
@end
// Complete pending command buffers from the front while `due` holds, in commit order; record how.
static void completePending(BOOL (^due)(NSDictionary *p), NSString *how) {
    pthread_mutex_lock(&PendingLock);
    while (Pending.count && due(Pending[0])) {
        NSDictionary *p = Pending[0];
        [Pending removeObjectAtIndex:0];
        // The GPU is done before the handlers run: the completion's sequence number comes first.
        const uint64_t seq = nextSeq();
        atomic_fetch_add(&Completed, 1);
        @synchronized (Commits) {
            NSMutableDictionary *c = Commits[[p[@"index"] unsignedIntegerValue]];
            c[@"completed_seq"] = @(seq); c[@"completed_by"] = how;
        }
        [p[@"cb"] didCompleteWithStartTime:0 endTime:0 error:nil];
        if ([how isEqual:@"watchdog"]) atomic_fetch_add(&Watchdogs, 1);
    }
    pthread_mutex_unlock(&PendingLock);
}
static void startLagWatchdog(void) {
    static dispatch_source_t t;
    t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), 50 * NSEC_PER_MSEC, 10 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(t, ^{
        double now = CACurrentMediaTime();
        completePending(^BOOL(NSDictionary *p) { return now - [p[@"t"] doubleValue] > 0.25; }, @"watchdog");
    });
    dispatch_resume(t);
}
// The gauge: a staging arena is a buffer the plug-in's staging code asks the device for.
static void hookArenaGauge(id device) {
    SEL sel = @selector(newBufferWithLength:options:);
    Method m = class_getInstanceMethod(object_getClass(device), sel);
    if (!once(m)) return;
    id (*o)(id, SEL, NSUInteger, MTLResourceOptions) = (void *)method_getImplementation(m);
    method_setImplementation(m, imp_implementationWithBlock(^id(id s, NSUInteger length, MTLResourceOptions options) {
        void *ra = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
        id b = o(s, sel, length, options);
        Dl_info info;
        if (!b || !dladdr(ra, &info) || !info.dli_fname || !strstr(info.dli_fname, "AdrenoMetal.bundle") || !info.dli_sname ||
            (!strstr(info.dli_sname, "AdrenoUBOBindingAddr") && !strstr(info.dli_sname, "AdrenoStagingArena")))
            return b;
        HarnessArenaSentinel *sentinel = [HarnessArenaSentinel new];
        sentinel->rid = resourceIDOf(b); sentinel->bytes = [(id<MTLBuffer>)b length];
        objc_setAssociatedObject(b, (__bridge const void *)[HarnessArenaSentinel class], sentinel, OBJC_ASSOCIATION_RETAIN);
        uint64_t live = atomic_fetch_add(&ArenaLive, 1) + 1;
        uint64_t liveBytes = atomic_fetch_add(&ArenaLiveBytes, sentinel->bytes) + sentinel->bytes;
        raisePeak(&ArenaPeak, live); raisePeak(&ArenaPeakAll, live);
        raisePeak(&ArenaPeakBytes, liveBytes); raisePeak(&ArenaPeakAllBytes, liveBytes);
        atomic_fetch_add(&ArenaNew, 1);
        NSDictionary *e = @{@"event":@"new", @"rid":@(sentinel->rid), @"bytes":@(sentinel->bytes), @"seq":@(nextSeq()),
                            @"completed":@(atomic_load(&Completed)), @"frame":@(FrameNo), @"scene":Scene};
        @synchronized (ArenaEvents) { [ArenaEvents addObject:e]; }
        return b;
    }));
}
// The plug-in's own counters (AdrenoStagingStatistics; absent from builds before the arena trim).
static NSArray *PluginStatNames;
static NSDictionary *pluginStaging(void) {
    unsigned (*f)(uint64_t *, unsigned) = dlsym(RTLD_DEFAULT, "AdrenoStagingStatistics");
    if (!f) return nil;
    uint64_t v[64] = {0};
    unsigned n = f(v, 64);
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    for (unsigned i = 0; i < n && i < PluginStatNames.count; i++) d[PluginStatNames[i]] = @(v[i]);
    return d;
}
// Allocation failures injected into IOGPU resource creation (the nil a refused GPU address allocation gives).
static _Atomic int FailBuffers, FailTextures;
static void hookFaults(void) {
    Class buffer = NSClassFromString(@"IOGPUMetalBuffer"), texture = NSClassFromString(@"IOGPUMetalTexture");
    SEL sb = NSSelectorFromString(@"initWithDevice:pointer:length:alignment:options:sysMemSize:gpuAddress:args:argsSize:deallocator:");
    SEL st = NSSelectorFromString(@"initWithDevice:descriptor:sysMemSize:sysMemRowBytes:vidMemSize:vidMemRowBytes:args:argsSize:");
    Method mb = class_getInstanceMethod(buffer, sb), mt = class_getInstanceMethod(texture, st);
    if (!mb || !mt) { fprintf(stderr, "fault hooks: IOGPU initialisers not found\n"); exit(69); }
    id (*ob)(id, SEL, id, void *, NSUInteger, unsigned, NSUInteger, NSUInteger, uint64_t, void *, unsigned, id) =
        (void *)method_getImplementation(mb);
    method_setImplementation(mb, imp_implementationWithBlock(^id(id s, id d, void *p, NSUInteger len, unsigned al,
            NSUInteger o, NSUInteger sms, uint64_t ga, void *args, unsigned sz, id dealloc) {
        int armed = atomic_load(&FailBuffers);
        if (armed > 0 && atomic_compare_exchange_strong(&FailBuffers, &armed, armed - 1)) return nil;
        return ob(s, sb, d, p, len, al, o, sms, ga, args, sz, dealloc);
    }));
    id (*ot)(id, SEL, id, id, uint64_t, uint64_t, uint64_t, uint64_t, void *, unsigned) = (void *)method_getImplementation(mt);
    method_setImplementation(mt, imp_implementationWithBlock(^id(id s, id d, id td, uint64_t sms, uint64_t rb, uint64_t vms,
            uint64_t vrb, void *args, unsigned sz) {
        int armed = atomic_load(&FailTextures);
        if (armed > 0 && atomic_compare_exchange_strong(&FailTextures, &armed, armed - 1)) return nil;
        return ot(s, st, d, td, sms, rb, vms, vrb, args, sz);
    }));
}
static NSNumber *delta(NSDictionary *a, NSDictionary *b, NSString *k) {
    return @([b[k] longLongValue] - [a[k] longLongValue]);
}
// A8/A16: with arenas pooled, a failed allocation drains the pool and is retried once; with the pool empty it is not.
static NSDictionary *runFaults(id<MTLDevice> device) {
    hookFaults();
    void (*recycle)(NSArray *) = dlsym(RTLD_DEFAULT, "AdrenoStagingArenasRecycle");
    NSMutableDictionary *r = [NSMutableDictionary dictionary];
    // Something pooled: one class-size buffer handed to the pool as a completed command buffer would.
    void (^seed)(void) = ^{ id<MTLBuffer> b = [device newBufferWithLength:1u << 20 options:MTLResourceStorageModeShared];
                            if (b && recycle) recycle(@[b]); };
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:64 height:64 mipmapped:NO];
    td.storageMode = MTLStorageModeShared;
    seed();
    NSDictionary *s0 = pluginStaging();
    atomic_store(&FailTextures, 1);
    id t = [device newTextureWithDescriptor:td];
    NSDictionary *s1 = pluginStaging();
    r[@"texture_pooled"] = @{@"pooled_before":s0[@"pooled_count"] ?: @0, @"ok":@(t != nil), @"armed_left":@(atomic_load(&FailTextures)),
        @"drains":delta(s0, s1, @"drains"), @"retries":delta(s0, s1, @"retries"), @"failures":delta(s0, s1, @"alloc_failures"),
        @"pooled_after":s1[@"pooled_count"] ?: @0};
    atomic_store(&FailBuffers, 1);
    id b = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    NSDictionary *s2 = pluginStaging();
    r[@"buffer_empty"] = @{@"pooled_before":s1[@"pooled_count"] ?: @0, @"ok":@(b != nil), @"armed_left":@(atomic_load(&FailBuffers)),
        @"drains":delta(s1, s2, @"drains"), @"retries":delta(s1, s2, @"retries"), @"failures":delta(s1, s2, @"alloc_failures")};
    usleep(700000);                                    // the pressure window (500 ms) ends
    seed();
    NSDictionary *s3 = pluginStaging();
    atomic_store(&FailBuffers, 1);
    b = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    NSDictionary *s4 = pluginStaging();
    r[@"buffer_pooled"] = @{@"pooled_before":s3[@"pooled_count"] ?: @0, @"ok":@(b != nil), @"armed_left":@(atomic_load(&FailBuffers)),
        @"drains":delta(s3, s4, @"drains"), @"retries":delta(s3, s4, @"retries"), @"failures":delta(s3, s4, @"alloc_failures"),
        @"pooled_after":s4[@"pooled_count"] ?: @0};
    atomic_store(&FailBuffers, 0); atomic_store(&FailTextures, 0);
    return r;
}

static BOOL once(Method m) {
    if (!m) return NO;
    NSValue *k = [NSValue valueWithPointer:m];
    @synchronized (Hooked) { if ([Hooked containsObject:k]) return NO; [Hooked addObject:k]; }
    return YES;
}
// Core Animation's generic pipeline: vertex function fixed_vert_lph_gen, label com.apple.coreanimation.P..._Xg... (PBGRA_Xgc
// without framebuffer fetch, PBGRAXm_A2Xghfc with it).
static BOOL isGeneric(MTLRenderPipelineDescriptor *d) {
    return [d.vertexFunction.name hasPrefix:@"fixed_vert_lph_gen"] || [d.label containsString:@"_Xg"] ||
           [d.label containsString:@"_A2Xg"] || [d.label containsString:@"_A3Xg"];
}
static void recordDraw(NSString *kind) {
    @synchronized (Draws) {
        [Draws addObject:@{@"scene":Scene, @"kind":kind, @"label":Bound,
                           @"generic":@([Bound hasPrefix:@"GENERIC "])}];
    }
}
static void hookEncoder(Class cls) {
    Method m = class_getInstanceMethod(cls, @selector(setRenderPipelineState:));
    if (once(m)) {
        void (*o)(id, SEL, id) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^(id s, id p) {
            @synchronized (Labels) { Bound = [Labels objectForKey:p] ?: @"?"; }
            o(s, @selector(setRenderPipelineState:), p); }));
    }
    // Only the outermost draw entry points are counted (the 5-argument indexed draw forwards to the 6-argument one).
    SEL d4 = @selector(drawPrimitives:vertexStart:vertexCount:instanceCount:);
    if (once((m = class_getInstanceMethod(cls, d4)))) {
        void (*o)(id, SEL, MTLPrimitiveType, NSUInteger, NSUInteger, NSUInteger) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^(id s, MTLPrimitiveType t, NSUInteger a, NSUInteger c, NSUInteger n) {
            recordDraw(@"draw"); o(s, d4, t, a, c, n); }));
    }
    SEL d3 = @selector(drawPrimitives:vertexStart:vertexCount:);
    if (once((m = class_getInstanceMethod(cls, d3)))) {
        void (*o)(id, SEL, MTLPrimitiveType, NSUInteger, NSUInteger) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^(id s, MTLPrimitiveType t, NSUInteger a, NSUInteger c) {
            recordDraw(@"draw"); o(s, d3, t, a, c); }));
    }
    SEL i6 = @selector(drawIndexedPrimitives:indexCount:indexType:indexBuffer:indexBufferOffset:instanceCount:);
    SEL i5 = @selector(drawIndexedPrimitives:indexCount:indexType:indexBuffer:indexBufferOffset:);
    Method m6 = class_getInstanceMethod(cls, i6), m5 = class_getInstanceMethod(cls, i5);
    static __thread BOOL inIndexed;
    if (once(m5)) {
        void (*o)(id, SEL, MTLPrimitiveType, NSUInteger, MTLIndexType, id, NSUInteger) = (void *)method_getImplementation(m5);
        method_setImplementation(m5, imp_implementationWithBlock(^(id s, MTLPrimitiveType t, NSUInteger c, MTLIndexType it, id b, NSUInteger off) {
            recordDraw(@"indexed"); BOOL was = inIndexed; inIndexed = YES; o(s, i5, t, c, it, b, off); inIndexed = was; }));
    }
    if (once(m6)) {
        void (*o)(id, SEL, MTLPrimitiveType, NSUInteger, MTLIndexType, id, NSUInteger, NSUInteger) = (void *)method_getImplementation(m6);
        method_setImplementation(m6, imp_implementationWithBlock(^(id s, MTLPrimitiveType t, NSUInteger c, MTLIndexType it, id b, NSUInteger off, NSUInteger n) {
            if (!inIndexed) recordDraw(@"indexed"); o(s, i6, t, c, it, b, off, n); }));
    }
}
static void hookCommandBuffer(Class cls) {
    Method m = class_getInstanceMethod(cls, @selector(renderCommandEncoderWithDescriptor:));
    if (once(m)) {
        id (*o)(id, SEL, id) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^id(id s, id rp) {
            id e = o(s, @selector(renderCommandEncoderWithDescriptor:), rp); hookEncoder(object_getClass(e)); return e; }));
    }
}
static void registerPipeline(id p, MTLRenderPipelineDescriptor *d, NSString *thread) {
    NSString *label = [NSString stringWithFormat:@"%@%@", isGeneric(d) ? @"GENERIC " : @"", d.label ?: d.fragmentFunction.name ?: @"?"];
    @synchronized (Labels) {
        if (p) [Labels setObject:label forKey:p];
        [Pipelines addObject:@{@"scene":Scene, @"label":label, @"thread":thread, @"ok":@(p != nil)}];
    }
}
static void hookDevice(Class cls) {
    SEL s1 = @selector(newRenderPipelineStateWithDescriptor:error:);
    Method m = class_getInstanceMethod(cls, s1);
    if (once(m)) {
        id (*o)(id, SEL, id, NSError **) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^id(id s, MTLRenderPipelineDescriptor *d, NSError **e) {
            BOOL main = NSThread.isMainThread;
            InFlight++;
            if (!isGeneric(d)) usleep(DelayUs);              // the A16's slow compiles
            id p = o(s, s1, d, e); registerPipeline(p, d, main ? @"render" : @"background"); InFlight--; return p; }));
    }
    SEL s2 = @selector(newRenderPipelineStateWithDescriptor:options:reflection:error:);
    if (once((m = class_getInstanceMethod(cls, s2)))) {
        id (*o)(id, SEL, id, NSUInteger, id *, NSError **) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^id(id s, MTLRenderPipelineDescriptor *d, NSUInteger opt, id *r, NSError **e) {
            BOOL main = NSThread.isMainThread;
            InFlight++;
            if (!isGeneric(d)) usleep(DelayUs);
            id p = o(s, s2, d, opt, r, e); registerPipeline(p, d, main ? @"render" : @"background"); InFlight--; return p; }));
    }
}
// The host GPU answers like the plug-in device: every capability selector Core Animation's pipeline choice depends on
// is forwarded to the plug-in device object itself.
static void answerLike(id<MTLDevice> host, id adreno) {
    NSArray *selectors = @[@"supportsTileShaders", @"supportsImageBlocks", @"areRasterOrderGroupsSupported",
        @"supportsRasterOrderGroups", @"supportsSIMDGroup", @"supportsSIMDReduction", @"supportsSIMDShuffleAndFill",
        @"isFramebufferReadSupported", @"supportsMemorylessRenderTargets", @"supportsNativeHardwareFP16",
        @"supportsBinaryArchives", @"supportsDynamicLibraries", @"supportsFunctionPointers", @"supportsRaytracing"];
    for (Class c = object_getClass(host); c; c = class_getSuperclass(c)) {
        for (NSString *n in selectors) {
            SEL sel = NSSelectorFromString(n);
            Method m = class_getInstanceMethod(c, sel);
            if (!m || strcmp(method_getTypeEncoding(m) ?: "", "B16@0:8") || ![adreno respondsToSelector:sel]) continue;
            BOOL answer = ((BOOL (*)(id, SEL))objc_msgSend)(adreno, sel);
            method_setImplementation(m, imp_implementationWithBlock(^BOOL(id s) { (void)s; return answer; }));
        }
        Method f = class_getInstanceMethod(c, @selector(supportsFamily:));
        if (f) method_setImplementation(f, imp_implementationWithBlock(^BOOL(id s, MTLGPUFamily fam) { (void)s; return [adreno supportsFamily:fam]; }));
        Method a = class_getInstanceMethod(c, @selector(argumentBuffersSupport));
        MTLArgumentBuffersTier tier = [adreno argumentBuffersSupport];
        if (a) method_setImplementation(a, imp_implementationWithBlock(^MTLArgumentBuffersTier(id s) { (void)s; return tier; }));
    }
}
static id createAdrenoDevice(NSString *bundlePath, BOOL interceptCommits) {
    (void)MTLCopyAllDevices();
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath]; NSError *e = nil;
    if (![bundle loadAndReturnError:&e]) { fprintf(stderr, "bundle: %s\n", e.description.UTF8String); exit(65); }
    Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
    if (!dc) exit(66);
    if (interceptCommits) {
        Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDrawAvailable"));
        Method copyAvailable = class_getInstanceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"));
        Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
        Method reserve = class_getInstanceMethod(native, NSSelectorFromString(@"_reserveKernelCommandBufferSpace:"));
        Method commit = class_getInstanceMethod(native, @selector(commit));
        if (!available || !copyAvailable || !reserve || !commit) { fprintf(stderr, "missing plug-in or native hooks\n"); exit(66); }
        // This Mac's accelerator publishes neither the kext's IB ABI nor its CopyABI (as in the other harnesses).
        method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
        method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }));
        IMP reserveIMP = method_getImplementation(reserve);
        SEL reserveSel = method_getName(reserve);
        method_setImplementation(reserve, imp_implementationWithBlock(^void *(id cb, NSUInteger length) {
            void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(cb, reserveSel, length);
            ReservedStart = p; ReservedLength = length; return p; }));
        BOOL noCapture = getenv("CA_BENCH_NOCAPTURE") && atoi(getenv("CA_BENCH_NOCAPTURE"));
        method_setImplementation(commit, imp_implementationWithBlock(^(id cb) {
            NSString *dir = [Out stringByAppendingPathComponent:[NSString stringWithFormat:@"commit-%03lu", (unsigned long)Commits.count]];
            if (!noCapture) {
                [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
                if (ReservedStart && ReservedLength)
                    [[NSData dataWithBytes:ReservedStart length:ReservedLength] writeToFile:[dir stringByAppendingPathComponent:@"commands.bin"] atomically:NO];
            }
            NSDictionary *r = [cb respondsToSelector:@selector(adrenoWorkReport)] ? [cb adrenoWorkReport] : @{};
            NSMutableDictionary *entry = [@{@"scene":Scene, @"dir":dir.lastPathComponent, @"encoded":r[@"encoded"] ?: @0,
                @"omitted":r[@"omitted"] ?: @0, @"encoding_failed":r[@"encoding_failed"] ?: @NO,
                @"has_commands":@(ReservedStart && ReservedLength)} mutableCopy];
            if (ArenaMode) {
                entry[@"seq"] = @(nextSeq()); entry[@"frame"] = @(FrameNo);
                atomic_fetch_add(&LiveCommandBuffers, 1);
                objc_setAssociatedObject(cb, &LiveCommandBuffers, [HarnessCBSentinel new], OBJC_ASSOCIATION_RETAIN);
            }
            NSUInteger index;
            @synchronized (Commits) { index = Commits.count; [Commits addObject:entry]; }
            ReservedStart = NULL; ReservedLength = 0;
            // No GPU runs this: report the buffer scheduled and complete so Core Animation's waits proceed.
            // The real commit (bypassed here) takes an enqueued command buffer off its queue's pending list; without that
            // the queue keeps every command buffer Core Animation enqueued, and with it every arena, until exit.
            if (LagFrames || ArenaMode) {
                id q = [cb commandQueue];
                Ivar iv = class_getInstanceVariable(NSClassFromString(@"_MTLCommandQueue"), "_pendingQueue");
                NSMutableArray *pq = q && iv ? object_getIvar(q, iv) : nil;
                if ([pq isKindOfClass:[NSMutableArray class]]) [pq removeObjectIdenticalTo:cb];
            }
            [cb didScheduleWithStartTime:0 endTime:0 error:nil];
            if (LagFrames) {
                pthread_mutex_lock(&PendingLock);
                [Pending addObject:@{@"cb":cb, @"frame":@(FrameNo), @"index":@(index), @"t":@(CACurrentMediaTime())}];
                pthread_mutex_unlock(&PendingLock);
                return;
            }
            if (ArenaMode) @synchronized (Commits) { entry[@"completed_seq"] = @(nextSeq()); entry[@"completed_by"] = @"commit"; }
            atomic_fetch_add(&Completed, 1);
            [cb didCompleteWithStartTime:0 endTime:0 error:nil]; }));
    }
    io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    id device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
    if (!device) exit(67);
    return device;
}

static CGColorRef color(double r, double g, double b, double a) { return CGColorCreateSRGB(r, g, b, a); }
static CALayer *stripes(CGRect frame) {
    CALayer *layer = [CALayer layer]; layer.frame = frame;
    for (int i = 0; i < 12; i++) { CALayer *s = [CALayer layer]; s.frame = CGRectMake(i * 8, 0, 4, frame.size.height);
        s.backgroundColor = i % 2 ? color(0.9, 0.2, 0.1, 1) : color(0.1, 0.2, 0.9, 1); [layer addSublayer:s]; }
    return layer;
}
static id gaussian(double radius) { id f = [NSClassFromString(@"CAFilter") filterWithType:@"gaussianBlur"]; [f setValue:@(radius) forKey:@"inputRadius"]; return f; }
// The drag scenes: the layer that moves each frame (a window group, a backdrop, a list) and its per-frame step.
static CALayer *Mover;
static CGPoint MoverStep;
static CGRect MoverLimit;
static CALayer *Recycled;       // scroll-list: the list whose rows move instead of the list
// A bench window (as bench-desk's): a shadow layer with a rounded shadow path, then a clipped, continuous-cornered window
// with a title bar and `rows` rounded rows, both in one group layer at (x, y) so the pair moves together.
static CALayer *dragWindow(double x, double y, double w, double h, int rows) {
    CALayer *group = [CALayer layer]; group.frame = CGRectMake(x, y, w, h);
    CALayer *sh = [CALayer layer]; sh.frame = CGRectMake(0, 0, w, h); sh.backgroundColor = color(1, 1, 1, 1); sh.cornerRadius = 32;
    sh.shadowColor = color(0, 0, 0, 1); sh.shadowOpacity = 0.35; sh.shadowRadius = 40; sh.shadowOffset = CGSizeMake(0, -20);
    sh.shadowPath = CGPathCreateWithRoundedRect(CGRectMake(0, 0, w, h), 32, 32, NULL); [group addSublayer:sh];
    CALayer *win = [CALayer layer]; win.frame = CGRectMake(0, 0, w, h); win.backgroundColor = color(0.98, 0.98, 0.98, 1);
    win.cornerRadius = 32; win.cornerCurve = kCACornerCurveContinuous; win.masksToBounds = YES;
    CALayer *bar = [CALayer layer]; bar.frame = CGRectMake(0, h - 104, w, 104); bar.backgroundColor = color(0.93, 0.93, 0.93, 1);
    [win addSublayer:bar];
    for (int r = 0; r < rows; r++) { CALayer *row = [CALayer layer]; row.frame = CGRectMake(40, h - 180 - r * 70, w - 80, 48);
        row.backgroundColor = color(0.9, 0.92, 0.96, 1); row.cornerRadius = 12; [win addSublayer:row]; }
    [group addSublayer:win];
    return group;
}
// A window as WindowServer composites it: the app's backing store as an image layer (here a drawn CGImage), clipped to
// rounded corners, over a shadow layer with a rounded shadow path.
static CGImageRef windowImage(int w, int h, double hue) {
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef c = CGBitmapContextCreate(NULL, w, h, 8, 0, cs, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGContextSetRGBFillColor(c, 0.98, 0.98, 0.98, 1); CGContextFillRect(c, CGRectMake(0, 0, w, h));
    CGContextSetRGBFillColor(c, 0.93, 0.93, 0.93, 1); CGContextFillRect(c, CGRectMake(0, h - 104, w, 104));
    for (int r = 0; r < 12; r++) {
        CGContextSetRGBFillColor(c, hue, 0.92 - 0.02 * (r % 3), 0.96, 1);
        CGContextFillRect(c, CGRectMake(40, h - 180 - r * 70, w - 80, 48));
    }
    CGImageRef image = CGBitmapContextCreateImage(c);
    CGContextRelease(c); CGColorSpaceRelease(cs);
    return image;
}
static CALayer *surfaceWindow(double x, double y, double w, double h, double hue) {
    CALayer *group = [CALayer layer]; group.frame = CGRectMake(x, y, w, h);
    CALayer *sh = [CALayer layer]; sh.frame = CGRectMake(0, 0, w, h); sh.backgroundColor = color(1, 1, 1, 1); sh.cornerRadius = 32;
    sh.shadowColor = color(0, 0, 0, 1); sh.shadowOpacity = 0.35; sh.shadowRadius = 40; sh.shadowOffset = CGSizeMake(0, -20);
    sh.shadowPath = CGPathCreateWithRoundedRect(CGRectMake(0, 0, w, h), 32, 32, NULL); [group addSublayer:sh];
    CALayer *win = [CALayer layer]; win.frame = CGRectMake(0, 0, w, h); win.cornerRadius = 32;
    win.cornerCurve = kCACornerCurveContinuous; win.masksToBounds = YES;
    CGImageRef image = windowImage((int)w, (int)h, hue); win.contents = (__bridge id)image; CGImageRelease(image);
    [group addSublayer:win];
    return group;
}
static void buildDrag(NSString *scene, CALayer *root) {
    CAGradientLayer *g = [CAGradientLayer layer]; g.frame = CGRectMake(0, 0, 2880, 1800);
    g.colors = @[(__bridge id)color(0.85, 0.55, 0.35, 1), (__bridge id)color(0.25, 0.35, 0.55, 1)]; [root addSublayer:g];
    if ([scene isEqual:@"drag-surfaces"]) {
        double rects[3][4] = {{200, 300, 1400, 1100}, {1700, 200, 1000, 900}, {400, 150, 900, 600}};
        for (int i = 0; i < 3; i++) [root addSublayer:surfaceWindow(rects[i][0], rects[i][1], rects[i][2], rects[i][3], 0.85 + 0.04 * i)];
        Mover = surfaceWindow(300, 400, 1500, 1050, 0.7); [root addSublayer:Mover];
        MoverStep = CGPointMake(24, 12); MoverLimit = CGRectMake(0, 0, 2880 - 1500, 1800 - 1050);
        Recycled = nil;
        return;
    }
    double rects[3][4] = {{200, 300, 1400, 1100}, {1700, 200, 1000, 900}, {400, 150, 900, 600}};
    int n = [scene isEqual:@"scroll-list"] ? 2 : 3;
    Recycled = nil;
    for (int i = 0; i < n; i++) [root addSublayer:dragWindow(rects[i][0], rects[i][1], rects[i][2], rects[i][3], 12)];
    if ([scene isEqual:@"drag-window"]) {
        Mover = dragWindow(300, 400, 1500, 1050, 12); [root addSublayer:Mover];
        MoverStep = CGPointMake(24, 12); MoverLimit = CGRectMake(0, 0, 2880 - 1500, 1800 - 1050);
    } else if ([scene isEqual:@"drag-glass"]) {
        CALayer *b = [NSClassFromString(@"CABackdropLayer") layer]; b.frame = CGRectMake(600, 500, 640, 420); b.filters = @[gaussian(30)];
        b.cornerRadius = 24; b.masksToBounds = YES; [root addSublayer:b];
        Mover = b; MoverStep = CGPointMake(24, 12); MoverLimit = CGRectMake(0, 0, 2880 - 640, 1800 - 420);
    } else if ([scene isEqual:@"scroll-list"]) {    // a clipped window whose rows scroll
        const int rows = 24;
        CALayer *win = [CALayer layer]; win.frame = CGRectMake(900, 300, 1500, 1200); win.backgroundColor = color(0.98, 0.98, 0.98, 1);
        win.cornerRadius = 32; win.cornerCurve = kCACornerCurveContinuous; win.masksToBounds = YES;
        win.shadowColor = color(0, 0, 0, 1); win.shadowOpacity = 0.35; win.shadowRadius = 40;
        win.shadowPath = CGPathCreateWithRoundedRect(CGRectMake(0, 0, 1500, 1200), 32, 32, NULL);
        CALayer *list = [CALayer layer]; list.frame = CGRectMake(0, 1200 - rows * 56, 1500, rows * 56);
        for (int r = 0; r < rows; r++) {
            CALayer *row = [CALayer layer]; row.frame = CGRectMake(24, r * 56 + 4, 1452, 48); row.cornerRadius = 10;
            row.backgroundColor = r % 2 ? color(0.9, 0.92, 0.96, 1) : color(0.96, 0.96, 0.97, 1);
            CALayer *icon = [CALayer layer]; icon.frame = CGRectMake(12, 8, 32, 32); icon.cornerRadius = 8;
            icon.backgroundColor = color(0.2 + 0.6 * (r % 5) / 4.0, 0.5, 0.8, 1); [row addSublayer:icon];
            CALayer *text = [CALayer layer]; text.frame = CGRectMake(60, 18, 400 + 37 * (r % 11), 12);
            text.backgroundColor = color(0.3, 0.3, 0.32, 1); [row addSublayer:text];
            [list addSublayer:row];
        }
        [win addSublayer:list]; [root addSublayer:win];
        Mover = list;
        // Like a table view that recycles its row views: 24 rows (the visible 21 and some overscan) shift by 30 px per
        // frame, wrapping, so every visible row moves each frame.
        Recycled = list;
    } else { fprintf(stderr, "unknown scene %s\n", scene.UTF8String); exit(64); }
}
static void stepDrag(void) {
    if (Recycled) {
        [CATransaction begin]; [CATransaction setDisableActions:YES];
        const double span = Recycled.sublayers.count * 56;
        for (CALayer *row in Recycled.sublayers) {
            CGRect f = row.frame; f.origin.y += 30; if (f.origin.y >= span) f.origin.y -= span; row.frame = f;
        }
        [CATransaction commit]; [CATransaction flush];
        return;
    }
    CGPoint p = Mover.frame.origin;
    if (p.x + MoverStep.x < MoverLimit.origin.x || p.x + MoverStep.x > CGRectGetMaxX(MoverLimit)) MoverStep.x = -MoverStep.x;
    if (p.y + MoverStep.y < MoverLimit.origin.y || p.y + MoverStep.y > CGRectGetMaxY(MoverLimit)) MoverStep.y = -MoverStep.y;
    [CATransaction begin]; [CATransaction setDisableActions:YES];
    CGRect f = Mover.frame; f.origin = CGPointMake(p.x + MoverStep.x, p.y + MoverStep.y); Mover.frame = f;
    [CATransaction commit]; [CATransaction flush];
}
static BOOL isDrag(NSString *scene) { return [scene hasPrefix:@"drag-"] || [scene isEqual:@"scroll-list"]; }
static void build(NSString *scene, CALayer *root) {         // glass-probe.js build()
    if ([scene hasPrefix:@"shadow"] || [scene hasPrefix:@"window"]) {
        CALayer *box = [CALayer layer];
        BOOL win = [scene hasPrefix:@"window"];
        box.frame = win ? CGRectMake(20, 18, 56, 32) : CGRectMake(24, 22, 48, 24);
        box.backgroundColor = color(1, 1, 1, 1);
        box.shadowColor = color(0, 0, 0, 1); box.shadowOpacity = 0.5; box.shadowRadius = 6; box.shadowOffset = CGSizeMake(0, -4);
        if (win) box.cornerRadius = 8;
        if ([scene isEqual:@"window-masked"]) box.masksToBounds = YES;
        if ([scene isEqual:@"shadow-path"]) box.shadowPath = CGPathCreateWithRect(CGRectMake(0, 0, 48, 24), NULL);
        [root addSublayer:box];
    } else if ([scene hasPrefix:@"clip"]) {
        [root addSublayer:stripes(CGRectMake(0, 0, 96, 64))];
        CALayer *box = [CALayer layer]; box.frame = CGRectMake(12, 8, 72, 48);
        box.backgroundColor = color(1, 1, 1, 1); box.cornerRadius = 12; box.masksToBounds = YES;
        if ([scene isEqual:@"clip-cont"]) box.cornerCurve = kCACornerCurveContinuous;
        CALayer *band = [CALayer layer]; band.frame = CGRectMake(0, 36, 72, 12); band.backgroundColor = color(0.2, 0.5, 0.2, 1);
        CALayer *foot = [CALayer layer]; foot.frame = CGRectMake(0, 0, 72, 10); foot.backgroundColor = color(0.8, 0.1, 0.1, 1);
        [box addSublayer:band]; [box addSublayer:foot];
        [root addSublayer:box];
    } else if (isDrag(scene) && getenv("CA_BENCH")) {
        buildDrag(scene, root);
    } else if ([scene hasPrefix:@"bench-"]) {
        CAGradientLayer *g = [CAGradientLayer layer]; g.frame = CGRectMake(0, 0, 2880, 1800);
        g.colors = @[(__bridge id)color(0.85, 0.55, 0.35, 1), (__bridge id)color(0.25, 0.35, 0.55, 1)]; [root addSublayer:g];
        double rects[4][4] = {{200, 300, 1400, 1100}, {900, 450, 1500, 1050}, {1700, 200, 1000, 900}, {400, 150, 900, 600}};
        for (int i = 0; i < 4; i++) {
            double x = rects[i][0], y = rects[i][1], w = rects[i][2], h = rects[i][3];
            CALayer *sh = [CALayer layer]; sh.frame = CGRectMake(x, y, w, h); sh.backgroundColor = color(1, 1, 1, 1); sh.cornerRadius = 32;
            sh.shadowColor = color(0, 0, 0, 1); sh.shadowOpacity = 0.35; sh.shadowRadius = 40; sh.shadowOffset = CGSizeMake(0, -20);
            sh.shadowPath = CGPathCreateWithRoundedRect(CGRectMake(0, 0, w, h), 32, 32, NULL); [root addSublayer:sh];
            CALayer *win = [CALayer layer]; win.frame = CGRectMake(x, y, w, h); win.backgroundColor = color(0.98, 0.98, 0.98, 1);
            win.cornerRadius = 32; win.cornerCurve = kCACornerCurveContinuous; win.masksToBounds = YES;
            CALayer *bar = [CALayer layer]; bar.frame = CGRectMake(0, h - 104, w, 104); bar.backgroundColor = color(0.93, 0.93, 0.93, 1);
            [win addSublayer:bar];
            for (int r = 0; r < 12; r++) { CALayer *row = [CALayer layer]; row.frame = CGRectMake(40, h - 180 - r * 70, w - 80, 48);
                row.backgroundColor = color(0.9, 0.92, 0.96, 1); row.cornerRadius = 12; [win addSublayer:row]; }
            [root addSublayer:win];
        }
        if ([scene isEqual:@"bench-glass"]) {
            CALayer *b = [NSClassFromString(@"CABackdropLayer") layer]; b.frame = CGRectMake(900, 450, 420, 1050); b.filters = @[gaussian(30)];
            [root addSublayer:b];
        }
        if ([scene isEqual:@"bench-blurfull"]) root.filters = @[gaussian(20)];
    } else if ([scene isEqual:@"square"]) {
        CALayer *box = [CALayer layer]; box.frame = CGRectMake(24, 22, 48, 24); box.backgroundColor = color(1, 1, 1, 1);
        [root addSublayer:box];
    } else if ([scene isEqual:@"blur"]) {
        CALayer *s = stripes(CGRectMake(16, 12, 64, 40)); s.filters = @[gaussian(4)]; [root addSublayer:s];
    } else if ([scene isEqual:@"backdrop"]) {
        [root addSublayer:stripes(CGRectMake(0, 0, 96, 64))];
        CALayer *b = [NSClassFromString(@"CABackdropLayer") layer]; b.frame = CGRectMake(16, 12, 64, 40); b.filters = @[gaussian(6)];
        [root addSublayer:b];
    } else { fprintf(stderr, "unknown scene %s\n", scene.UTF8String); exit(64); }
}

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc < 5) return 64;
    BOOL hostCaps = !strcmp(argv[1], "--host-caps"), adrenoMode = !strcmp(argv[1], "--adreno"), hostOwn = !strcmp(argv[1], "--host");
    if (!hostCaps && !adrenoMode && !hostOwn) return 64;
    Out = @(argv[3]);
    if ([[NSFileManager defaultManager] fileExistsAtPath:Out]) return 64;
    [[NSFileManager defaultManager] createDirectoryAtPath:Out withIntermediateDirectories:YES attributes:nil error:NULL];
    if (getenv("CA_GENERIC_TEST_DELAY_MS")) DelayUs = (useconds_t)atoi(getenv("CA_GENERIC_TEST_DELAY_MS")) * 1000;
    Draws = [NSMutableArray array]; Commits = [NSMutableArray array]; Pipelines = [NSMutableArray array];
    Labels = [NSMapTable weakToStrongObjectsMapTable]; Hooked = [NSMutableSet set];
    // The plug-in device is created first in both modes, before Core Animation is used, as Metal does in a client.
    id adreno = createAdrenoDevice(@(argv[2]), adrenoMode);
    if (getenv("CA_TEST_FETCH")) {
        BOOL fetch = atoi(getenv("CA_TEST_FETCH")) != 0;
        Method fm = class_getInstanceMethod(object_getClass(adreno), @selector(isFramebufferReadSupported));
        if (!fm) exit(66);
        method_setImplementation(fm, imp_implementationWithBlock(^BOOL(id s) { (void)s; return fetch; }));
    }
    id<MTLDevice> device;
    if (adrenoMode) {
        MTLAddDevice(adreno);
        void (*setDefault)(id) = dlsym(RTLD_DEFAULT, "AdrenoSetDefaultDevice");
        if (!setDefault) { fprintf(stderr, "default-device-interpose.dylib is not inserted\n"); return 68; }
        setDefault(adreno);
        device = adreno;
    } else {
        device = MTLCreateSystemDefaultDevice();
        if (hostCaps) answerLike(device, adreno);
    }
    hookDevice(object_getClass(device));
    // Staging arenas (header): only with --adreno and CA_BENCH.
    BOOL bench = getenv("CA_BENCH") != NULL;
    LagFrames = adrenoMode && bench && getenv("CA_BENCH_LAG") ? MAX(0, atoi(getenv("CA_BENCH_LAG"))) : 0;
    ArenaMode = adrenoMode && bench && getenv("CA_BENCH_ARENAS") && atoi(getenv("CA_BENCH_ARENAS"));
    int idleMs = ArenaMode && getenv("CA_BENCH_IDLE_MS") ? atoi(getenv("CA_BENCH_IDLE_MS")) : 0;
    int relieveEvery = adrenoMode && bench && getenv("CA_BENCH_RELIEVE_EVERY") ? atoi(getenv("CA_BENCH_RELIEVE_EVERY")) : 0;
    void (*relieve)(void) = relieveEvery > 0 ? dlsym(RTLD_DEFAULT, "AdrenoStagingRelieve") : NULL;
    NSMutableArray *arenaScenes = [NSMutableArray array];
    PluginStatNames = @[@"new", @"reused", @"pooled", @"released", @"live", @"live_bytes", @"peak_live", @"peak_live_bytes",
        @"pooled_count", @"pooled_bytes", @"peak_pooled_bytes", @"aged", @"capped", @"drained", @"drains", @"alloc_failures",
        @"retries", @"retry_successes", @"timer_fires", @"refused", @"continued"];
    if (LagFrames) { Pending = [NSMutableArray array]; startLagWatchdog(); }
    if (ArenaMode) { ArenaEvents = [NSMutableArray array]; FrameStarts = [NSMutableArray array]; hookArenaGauge(device); printf("PID %d\n", (int)getpid()); fflush(stdout); }
    id<MTLCommandQueue> queue = [device newCommandQueue];
    hookCommandBuffer(object_getClass([queue commandBuffer]));
    NSUInteger W = 96, H = 64;
    if (getenv("CA_BENCH")) { W = 2880; H = 1800; }
    NSString *warmup = @(getenv("CA_GENERIC_TEST_WARMUP") ?: "square");
    NSMutableArray *scenes = [NSMutableArray array];
    for (NSString *w in [warmup componentsSeparatedByString:@","]) if (w.length) [scenes addObject:[@"warmup:" stringByAppendingString:w]];
    for (int i = 4; i < argc; i++) [scenes addObject:@(argv[i])];
    double waited = 0;
    for (NSString *entry in scenes) {
        BOOL warm = [entry hasPrefix:@"warmup:"];
        if (!warm && waited == 0) {
            // Let every pipeline request of the warm-up finish (at most 600 s), then a quiet second.
            for (int quiet = 0; quiet < 10 && waited < 600; waited += 0.1) { usleep(100000); quiet = InFlight ? 0 : quiet + 1; }
            waited = MAX(waited, 0.1);
        }
        Scene = entry;
        IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@(W), (id)kIOSurfaceHeight:@(H),
            (id)kIOSurfaceBytesPerRow:@(W * 4), (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfacePixelFormat:@(0x42475241)});
        MTLTextureDescriptor *desc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:W height:H mipmapped:NO];
        desc.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
        id<MTLTexture> target = [device newTextureWithDescriptor:desc iosurface:surface plane:0];
        CARenderer *r = [CARenderer rendererWithMTLTexture:target options:@{kCARendererMetalCommandQueue:queue}];
        CALayer *root = [CALayer layer]; root.frame = CGRectMake(0, 0, W, H);
        root.backgroundColor = color(0.8, 0.8, 0.8, 1); root.opaque = YES;
        build(warm ? [entry substringFromIndex:7] : entry, root);
        r.layer = root; r.bounds = root.bounds;
        [CATransaction flush];
        int frames = (getenv("CA_BENCH") && !warm) ? (getenv("CA_BENCH_FRAMES") ? atoi(getenv("CA_BENCH_FRAMES")) : 23) : 1;
        BOOL drag = isDrag(warm ? [entry substringFromIndex:7] : entry) && getenv("CA_BENCH") && !(getenv("CA_BENCH_FULL") && atoi(getenv("CA_BENCH_FULL")));
        double total = 0, best = 1e9, cpu = 0, proc = 0, area = 0;
        uint64_t newAtWarm = atomic_load(&ArenaNew);
        if (ArenaMode) { atomic_store(&ArenaPeak, atomic_load(&ArenaLive)); atomic_store(&ArenaPeakBytes, atomic_load(&ArenaLiveBytes)); }
        for (int f = 0; f < frames; f++) {
            // With lagged completion or the gauge, each frame drains its own autorelease pool (as a compositor's run
            // loop does), so completed command buffers and what they hold are freed; before, they lived until exit.
            void *framePool = (LagFrames || ArenaMode) ? objc_autoreleasePoolPush() : NULL;
            if (ArenaMode) [FrameStarts addObject:@(nextSeq())];   // completions only run between frames
            if (drag && f) stepDrag();
            if (f == 3) newAtWarm = atomic_load(&ArenaNew);
            struct rusage u0, u1; getrusage(RUSAGE_SELF, &u0);
            struct timespec c0, c1; clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c0);
            double t0 = CACurrentMediaTime();
            [r beginFrameAtTime:t0 timeStamp:NULL];
            CGRect damage = r.updateBounds;
            if (!drag || !f) { [r addUpdateRect:root.bounds]; damage = root.bounds; }
            [r render];
            [r endFrame];
            id<MTLCommandBuffer> cb = [queue commandBuffer]; [cb commit];
            if (!LagFrames) [cb waitUntilCompleted];
            double ms = (CACurrentMediaTime() - t0) * 1000;
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c1); getrusage(RUSAGE_SELF, &u1);
            if (f >= 3) {
                total += ms; if (ms < best) best = ms;
                cpu += (c1.tv_sec - c0.tv_sec) * 1e3 + (c1.tv_nsec - c0.tv_nsec) / 1e6;
                proc += (u1.ru_utime.tv_sec - u0.ru_utime.tv_sec + u1.ru_stime.tv_sec - u0.ru_stime.tv_sec) * 1e3 +
                        (u1.ru_utime.tv_usec - u0.ru_utime.tv_usec + u1.ru_stime.tv_usec - u0.ru_stime.tv_usec) / 1e3;
                area += CGRectIsNull(damage) ? 0 : damage.size.width * damage.size.height;
            }
            // Lagged completions run between frames, outside the timed frame (the A16 completes on IOGPU's thread).
            FrameNo++;
            if (LagFrames) {
                uint64_t now = FrameNo;
                completePending(^BOOL(NSDictionary *p) { return [p[@"frame"] unsignedLongLongValue] + LagFrames <= now; }, @"frame");
            }
            if (relieve && FrameNo % (uint64_t)relieveEvery == 0) relieve();
            if (framePool) objc_autoreleasePoolPop(framePool);
        }
        if (LagFrames) @autoreleasepool { completePending(^BOOL(NSDictionary *p) { (void)p; return YES; }, @"flush"); }
        if (frames > 3) printf("BENCH %s mean %.2f ms min %.2f ms cpu %.2f ms proc %.2f ms damage %.0f%%\n", Scene.UTF8String,
                               total / (frames - 3), best, cpu / (frames - 3), proc / (frames - 3),
                               100 * area / (frames - 3) / (W * H));
        if (ArenaMode && frames > 3) {
            uint64_t peak = atomic_load(&ArenaPeak), peakBytes = atomic_load(&ArenaPeakBytes);
            uint64_t end = atomic_load(&ArenaLive), endBytes = atomic_load(&ArenaLiveBytes);
            uint64_t fresh = atomic_load(&ArenaNew) - newAtWarm;
            if (idleMs > 0) usleep((useconds_t)idleMs * 1000);
            uint64_t idle = atomic_load(&ArenaLive), idleBytes = atomic_load(&ArenaLiveBytes);
            NSDictionary *plugin = pluginStaging();
            uint64_t idlePooled = [plugin[@"pooled_bytes"] unsignedLongLongValue], cbs = atomic_load(&LiveCommandBuffers);
            printf("ARENAS %s peak %llu peak_kib %llu end %llu end_kib %llu idle %llu idle_kib %llu idle_pooled_kib %s "
                   "idle_live_command_buffers %llu new_after_warmup %llu watchdog %llu\n", Scene.UTF8String, peak, peakBytes >> 10,
                   end, endBytes >> 10, idle, idleBytes >> 10, plugin ? [@(idlePooled >> 10) description].UTF8String : "-",
                   cbs, fresh, atomic_load(&Watchdogs));
            [arenaScenes addObject:@{@"scene":Scene, @"peak":@(peak), @"peak_bytes":@(peakBytes), @"end":@(end),
                @"end_bytes":@(endBytes), @"idle":@(idle), @"idle_bytes":@(idleBytes), @"idle_ms":@(idleMs),
                @"idle_pooled_bytes":plugin ? @(idlePooled) : [NSNull null], @"idle_live_command_buffers":@(cbs),
                @"new_after_warmup":@(fresh), @"frames":@(frames), @"lag":@(LagFrames)}];
        }
        IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL);
        [[NSData dataWithBytes:IOSurfaceGetBaseAddress(surface) length:W * H * 4]
            writeToFile:[Out stringByAppendingPathComponent:[[Scene stringByReplacingOccurrencesOfString:@":" withString:@"-"] stringByAppendingString:@".bgra"]] atomically:NO];
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        CFRelease(surface);
    }
    // The plug-in's UBO staging arenas (allocated / reused from its pool / pooled / released), when it exports them.
    void (*stagingCounters)(uint64_t *) = dlsym(RTLD_DEFAULT, "AdrenoStagingCounters");
    uint64_t staging[4] = {0};
    if (stagingCounters) {
        stagingCounters(staging);
        if (getenv("CA_BENCH")) printf("STAGING new %llu reused %llu pooled %llu released %llu\n", staging[0], staging[1], staging[2], staging[3]);
    }
    NSMutableDictionary *arenaReport = nil;
    if (ArenaMode) {
        arenaReport = [NSMutableDictionary dictionary];
        arenaReport[@"scenes"] = arenaScenes;
        arenaReport[@"lag"] = @(LagFrames); arenaReport[@"relieve_every"] = @(relieveEvery);
        arenaReport[@"relieve_exported"] = @((BOOL)(relieve != NULL || dlsym(RTLD_DEFAULT, "AdrenoStagingRelieve") != NULL));
        arenaReport[@"plugin_end"] = pluginStaging() ?: [NSNull null];
        arenaReport[@"gauge_end"] = @{@"live":@(atomic_load(&ArenaLive)), @"live_bytes":@(atomic_load(&ArenaLiveBytes)),
                                      @"new":@(atomic_load(&ArenaNew)), @"watchdog":@(atomic_load(&Watchdogs)),
                                      @"peak":@(atomic_load(&ArenaPeakAll)), @"peak_bytes":@(atomic_load(&ArenaPeakAllBytes)),
                                      @"live_command_buffers":@(atomic_load(&LiveCommandBuffers))};
        if (getenv("CA_BENCH_FAULTS") && atoi(getenv("CA_BENCH_FAULTS"))) arenaReport[@"faults"] = runFaults(device);
        int finalIdle = getenv("CA_BENCH_FINAL_IDLE_MS") ? atoi(getenv("CA_BENCH_FINAL_IDLE_MS")) : 0;
        if (finalIdle > 0) {
            usleep((useconds_t)finalIdle * 1000);
            NSDictionary *a = pluginStaging();
            uint64_t live = atomic_load(&ArenaLive), liveBytes = atomic_load(&ArenaLiveBytes);
            usleep(1500000);
            NSDictionary *b = pluginStaging();
            arenaReport[@"final_idle"] = @{@"ms":@(finalIdle), @"live":@(live), @"live_bytes":@(liveBytes),
                @"plugin":a ?: [NSNull null], @"plugin_later":b ?: [NSNull null],
                @"live_later":@(atomic_load(&ArenaLive))};
            printf("FINAL-IDLE %d ms live %llu live_kib %llu timer_fires %s -> %s\n", finalIdle, live, liveBytes >> 10,
                   [[a[@"timer_fires"] description] UTF8String] ?: "-", [[b[@"timer_fires"] description] UTF8String] ?: "-");
        }
        NSDictionary *p = pluginStaging();
        if (p) {
            NSMutableString *line = [NSMutableString stringWithString:@"PLUGIN-STAGING"];
            for (NSString *k in PluginStatNames) if (p[k]) [line appendFormat:@" %@ %@", k, p[k]];
            printf("%s\n", line.UTF8String);
        }
        @synchronized (ArenaEvents) { arenaReport[@"events"] = [ArenaEvents copy]; }
        arenaReport[@"frame_starts"] = FrameStarts;
    }
    NSDictionary *report;
    @synchronized (Draws) {
        NSMutableDictionary *m = [@{@"mode":hostOwn ? @"host" : hostCaps ? @"host-caps" : @"adreno", @"device":device.name ?: @"",
            @"framebuffer_fetch":@([adreno isFramebufferReadSupported]), @"delay_ms":@(DelayUs / 1000),
            @"env_disable_generic":@(getenv("CA_DISABLE_GENERIC_SHADERS") ?: ""),
            @"env_force_generic":@(getenv("CA_FORCE_GENERIC_SHADERS") ?: ""), @"warmup":warmup, @"warmup_wait_s":@(waited),
            @"draws":Draws, @"pipelines":Pipelines, @"commits":Commits} mutableCopy];
        if (arenaReport) m[@"arenas"] = arenaReport;
        report = m;
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (![json writeToFile:[Out stringByAppendingPathComponent:@"report.json"] atomically:YES]) return 73;
    return 0;
} }
