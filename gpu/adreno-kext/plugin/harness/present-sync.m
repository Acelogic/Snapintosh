/* SPDX-License-Identifier: MIT */
// present-sync.m - the plug-in's submission waits on this Mac (agents/present-sync FAILURE-MODES.md S1-S7; the host runs
// 26A428, the guest's build).
//
// Core Animation ends a WindowServer frame with commitAndWaitUntilSubmitted (MetalContext::flush(true)) and swaps after
// it returns. The plug-in device is created against this Mac's IOAccelerator. -[IOGPUMetalCommandQueue
// submitCommandBuffers:count:], the method that issues the kernel submission (IOGPUCommandQueueSubmitCommandBuffers), is
// replaced by a stand-in for the Adreno kext's synchronous kernel path: per command buffer it parses the kernel commands,
// sleeps PS_KERNEL_US (the IB, default 4000), marks the command buffer "kernel done", and then reports it scheduled and
// completed on a separate queue (IOGPU's notifications). Nothing reaches this Mac's GPU.
//
//   DYLD_INSERT_LIBRARIES=default-device-interpose.dylib present-sync BUNDLE OUT
//   clang -arch arm64e -fobjc-arc -O1 present-sync.m -o present-sync -framework Foundation -framework Metal \
//     -framework QuartzCore -framework IOSurface -framework IOKit -framework CoreGraphics
//
// Cases (OUT/report.json; one line per case on stdout):
//   ws-queue        a queue with a submission queue, as WindowServer's: 100 x (clear pass into an IOSurface texture,
//                   commitAndWaitUntilSubmitted); at each return the kernel stand-in must have finished that command
//                   buffer (S1), and its kernel commands hold encoded work and exactly one FENCE, last (S3)
//   ws-deadline     the same with commitAndWaitUntilSubmittedWithDeadline:
//   async-commit    the submission queue blocked 600 ms: plain -commit still returns at once (S4)
//   blocked-queue   the submission queue blocked 600 ms: commitAndWaitUntilSubmitted returns at the bound (S2)
//   self-queue      commitAndWaitUntilSubmitted called on the submission queue itself: returns at the bound (S2)
//   refused         an encoder left open: commitAndWaitUntilSubmitted raises at once, no wait (S7)
//   ca-renderer     CARenderer frames on the plug-in device through the same kind of queue: which commit variants Core
//                   Animation uses (CARenderer's context commits plainly; WindowServer's IOMFBDisplay context, created
//                   with flags 0, waits), and that each command buffer it committed with a wait was finished at the end
//                   of its frame (S1, end to end)
// With PS_PIPELINE=1 (agents/gpu-pipeline FAILURE-MODES.md U1-U3, C1) the cases above run first, then the same plug-in
// against the pipelined kext's stand-in: one IB on the "GPU" at a time; the submission waits only for the previous
// command buffer's GPU end, "starts" this one and returns; IOGPU's scheduled and completed notifications follow, the
// completed one at the GPU end (PS_KERNEL_US later):
//   ws-queue-pipe   commitAndWaitUntilSubmitted returns once the stand-in queued the command buffer (U1), before its GPU
//                   end; every one completes afterwards, in order
//   complete-pipe   a completed handler and waitUntilCompleted run only after the GPU end (C1); the encoding state (the
//                   staging arenas' recycling) is dropped only then (U3)
//   overlap-fps     5 ms of CPU then a frame of 13.4 ms GPU, 40 frames, pipelined against the synchronous stand-in:
//                   the frame rate approaches 1000 / max(gpu, cpu) instead of 1000 / (gpu + cpu)
//   shadow-pipe     an IOSurface whose rows are not 64-byte multiples (its aligned shadow): one command buffer writes the shadow (60 ms of
//                   GPU), the CPU then writes the surface, the next command buffer encodes a pass on it: no refill of the
//                   shadow while the first is on the GPU, the second's encoding waits for its end (U2), and the first's
//                   write-back runs after that end (U3)
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <stdatomic.h>
#import <time.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (PresentSyncHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (void)didScheduleWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (void)didCompleteWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (BOOL)commitAndWaitUntilSubmitted;
- (BOOL)commitAndWaitUntilSubmittedWithDeadline:(uint64_t)deadline;
- (void)setSubmissionQueue:(dispatch_queue_t)queue;
@end

enum { KCMD_FENCE = 0x1000, KCMD_FILL32 = 0x1001, KCMD_IB = 0x1002 };
static useconds_t KernelUs = 4000;
static int PipeMode;                                  // the pipelined kext's stand-in (PS_PIPELINE=1 cases)
static double GpuFreeAt;                              // ms: the stand-in GPU's end of the last started command buffer
static char KQueuedKey, KGpuEndKey;
static NSObject *GpuLock;
static dispatch_queue_t Notify;                       // IOGPU's notifications, off the submission queue
static char KDoneKey, KCmdKey, ReserveKey;
static _Atomic uint64_t Submitted, BadCommands;
static double now_ms(void) { return CACurrentMediaTime() * 1000.0; }
static BOOL kernelDone(id cb) { return objc_getAssociatedObject(cb, &KDoneKey) != nil; }

// The kernel commands at the submission boundary: {type, size} headers back to back (compat/adreno-submit.h).
static NSDictionary *parseCommands(id cb) {
    NSValue *v = objc_getAssociatedObject(cb, &ReserveKey);
    NSRange r = v ? v.rangeValue : NSMakeRange(0, 0);
    const uint8_t *p = (const uint8_t *)(uintptr_t)r.location;
    unsigned fences = 0, fills = 0, ibs = 0, other = 0; BOOL fenceLast = NO, ok = p && r.length;
    for (NSUInteger at = 0; ok && at + 8 <= r.length;) {
        uint32_t type, size; memcpy(&type, p + at, 4); memcpy(&size, p + at + 4, 4);
        if (size < 8 || at + size > r.length) { ok = NO; break; }
        if (type == KCMD_FENCE) fences++; else if (type == KCMD_FILL32) fills++; else if (type == KCMD_IB) ibs++; else other++;
        fenceLast = type == KCMD_FENCE;
        at += size;
    }
    return @{@"ok":@(ok), @"fences":@(fences), @"fills":@(fills), @"ibs":@(ibs), @"other":@(other), @"fence_last":@(fenceLast)};
}

static void hookPlugin(Class deviceClass) {
    Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDrawAvailable"));
    Method copyAvailable = class_getInstanceMethod(deviceClass, NSSelectorFromString(@"adrenoBufferCopyAvailable"));
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, NSSelectorFromString(@"_reserveKernelCommandBufferSpace:"));
    Method submit = class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandQueue"), NSSelectorFromString(@"submitCommandBuffers:count:"));
    if (!available || !copyAvailable || !reserve || !submit) { fprintf(stderr, "missing plug-in or native hooks\n"); exit(66); }
    // This Mac's accelerator publishes neither the kext's IB ABI nor its CopyABI (as in the other harnesses).
    method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
    method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }));
    IMP reserveIMP = method_getImplementation(reserve); SEL reserveSel = method_getName(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id cb, NSUInteger length) {
        void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(cb, reserveSel, length);
        objc_setAssociatedObject(cb, &ReserveKey, [NSValue valueWithRange:NSMakeRange((NSUInteger)(uintptr_t)p, length)],
                                 OBJC_ASSOCIATION_RETAIN);
        return p; }));
    // The kernel submission: this kext runs every command buffer to completion inside the syscall; the pipelined kext
    // waits only for the previous command buffer's GPU end, starts this one and returns (completion follows later).
    method_setImplementation(submit, imp_implementationWithBlock(^(id q, __unsafe_unretained id *cbs, NSUInteger n) {
        (void)q;
        if (PipeMode) {
            for (NSUInteger i = 0; i < n; i++) {
                id cb = cbs[i];
                NSDictionary *k = parseCommands(cb);
                objc_setAssociatedObject(cb, &KCmdKey, k, OBJC_ASSOCIATION_RETAIN);
                if (![k[@"ok"] boolValue]) atomic_fetch_add(&BadCommands, 1);
                double start, end;
                @synchronized (GpuLock) {
                    const double wait = GpuFreeAt - now_ms();
                    if (wait > 0) usleep((useconds_t)(wait * 1000.0));
                    start = now_ms(); end = start + KernelUs / 1000.0; GpuFreeAt = end;
                }
                objc_setAssociatedObject(cb, &KQueuedKey, @(start), OBJC_ASSOCIATION_RETAIN);
                objc_setAssociatedObject(cb, &KGpuEndKey, @(end), OBJC_ASSOCIATION_RETAIN);
                atomic_fetch_add(&Submitted, 1);
                dispatch_async(Notify, ^{ [cb didScheduleWithStartTime:0 endTime:0 error:nil]; });
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((end - now_ms()) * NSEC_PER_MSEC)), Notify, ^{
                    objc_setAssociatedObject(cb, &KDoneKey, @(now_ms()), OBJC_ASSOCIATION_RETAIN);
                    [cb didCompleteWithStartTime:0 endTime:0 error:nil];
                });
            }
            return;
        }
        NSMutableArray *batch = [NSMutableArray arrayWithCapacity:n];
        for (NSUInteger i = 0; i < n; i++) {
            id cb = cbs[i];
            NSDictionary *k = parseCommands(cb);
            objc_setAssociatedObject(cb, &KCmdKey, k, OBJC_ASSOCIATION_RETAIN);
            if (![k[@"ok"] boolValue]) atomic_fetch_add(&BadCommands, 1);
            usleep(KernelUs);
            objc_setAssociatedObject(cb, &KDoneKey, @(now_ms()), OBJC_ASSOCIATION_RETAIN);
            atomic_fetch_add(&Submitted, 1);
            [batch addObject:cb];
        }
        dispatch_async(Notify, ^{
            for (id cb in batch) { [cb didScheduleWithStartTime:0 endTime:0 error:nil]; [cb didCompleteWithStartTime:0 endTime:0 error:nil]; }
        });
    }));
}

static id<MTLTexture> surfaceTexture(id<MTLDevice> device, NSUInteger w, NSUInteger h) {
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@(w), (id)kIOSurfaceHeight:@(h),
        (id)kIOSurfaceBytesPerRow:@(w * 4), (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfacePixelFormat:@(0x42475241)});
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:w height:h mipmapped:NO];
    d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    id<MTLTexture> t = [device newTextureWithDescriptor:d iosurface:s plane:0];
    CFRelease(s);
    return t;
}
static id<MTLCommandBuffer> clearFrame(id<MTLCommandQueue> q, id<MTLTexture> t, unsigned k) {
    id<MTLCommandBuffer> cb = [q commandBuffer];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture = t; rp.colorAttachments[0].loadAction = MTLLoadActionClear;
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    rp.colorAttachments[0].clearColor = MTLClearColorMake((k % 7) / 7.0, (k % 5) / 5.0, (k % 3) / 3.0, 1);
    [[cb renderCommandEncoderWithDescriptor:rp] endEncoding];
    return cb;
}
static void drain(id<MTLCommandQueue> q) { id<MTLCommandBuffer> cb = [q commandBuffer]; [cb commit]; [cb waitUntilCompleted]; }

static NSMutableDictionary *Report; static unsigned Checks, Failures;
static void check(NSMutableDictionary *c, NSString *name, BOOL ok) {
    Checks++; if (!ok) Failures++;
    NSMutableArray *f = c[@"failed"] ?: (c[@"failed"] = [NSMutableArray array]);
    if (!ok) [f addObject:name];
}
static void finish(NSString *name, NSMutableDictionary *c) {
    Report[name] = c;
    NSArray *f = c[@"failed"];
    printf("%s %s %s\n", f.count ? "FAIL" : "PASS", name.UTF8String,
           [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:c options:NSJSONWritingSortedKeys error:NULL]
                                 encoding:NSUTF8StringEncoding].UTF8String);
    fflush(stdout);
}

static void wsQueue(id<MTLDevice> device, BOOL deadline) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.ws.submit", DISPATCH_QUEUE_SERIAL)];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    const unsigned n = 100; unsigned doneAtReturn = 0, yes = 0, cmdsOk = 0, encoded = 0; double maxMs = 0, sumMs = 0;
    NSMutableArray *cbs = [NSMutableArray array];
    for (unsigned i = 0; i < n; i++) @autoreleasepool {
        id<MTLCommandBuffer> cb = clearFrame(q, t, i);
        const double t0 = now_ms();
        BOOL ok = deadline ? [(id)cb commitAndWaitUntilSubmittedWithDeadline:UINT64_MAX] : [(id)cb commitAndWaitUntilSubmitted];
        const double ms = now_ms() - t0;
        if (kernelDone(cb)) doneAtReturn++;
        if (ok) yes++;
        sumMs += ms; if (ms > maxMs) maxMs = ms;
        [cbs addObject:cb];
    }
    for (id<MTLCommandBuffer> cb in cbs) [cb waitUntilCompleted];
    for (id cb in cbs) {
        NSDictionary *k = objc_getAssociatedObject(cb, &KCmdKey);
        if ([k[@"ok"] boolValue] && [k[@"fences"] unsignedIntValue] == 1 && [k[@"fence_last"] boolValue] &&
            [k[@"fills"] unsignedIntValue] + [k[@"ibs"] unsignedIntValue] > 0) cmdsOk++;
        if ([[cb adrenoWorkReport][@"encoded"] unsignedLongLongValue] > 0) encoded++;
    }
    c[@"command_buffers"] = @(n); c[@"kernel_done_at_return"] = @(doneAtReturn); c[@"returned_yes"] = @(yes);
    c[@"kernel_commands_ok"] = @(cmdsOk); c[@"encoded"] = @(encoded);
    c[@"mean_wait_ms"] = @(sumMs / n); c[@"max_wait_ms"] = @(maxMs); c[@"kernel_us"] = @(KernelUs);
    check(c, @"S1 kernel work finished at every return", doneAtReturn == n);
    check(c, @"returned YES", yes == n);
    check(c, @"S3 one FENCE, last, after encoded work", cmdsOk == n);
    check(c, @"S3 work report encoded", encoded == n);
    check(c, @"S2 no wait reached the bound", maxMs < 200);
    finish(deadline ? @"ws-deadline" : @"ws-queue", c);
}

static void blockedQueue(id<MTLDevice> device, int mode) {    // 0 async-commit, 1 blocked-queue, 2 self-queue
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    dispatch_queue_t sq = dispatch_queue_create("present-sync.blocked.submit", DISPATCH_QUEUE_SERIAL);
    [(id)q setSubmissionQueue:sq];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    id<MTLCommandBuffer> cb = clearFrame(q, t, 1);
    __block double ms = 0; __block BOOL ok = NO, doneAtReturn = NO;
    if (mode == 2) {
        dispatch_sync(sq, ^{ const double t0 = now_ms(); ok = [(id)cb commitAndWaitUntilSubmitted]; ms = now_ms() - t0;
                             doneAtReturn = kernelDone(cb); });
    } else {
        dispatch_async(sq, ^{ usleep(600000); });
        usleep(20000);
        const double t0 = now_ms();
        if (mode == 0) { [cb commit]; ok = YES; } else ok = [(id)cb commitAndWaitUntilSubmitted];
        ms = now_ms() - t0; doneAtReturn = kernelDone(cb);
    }
    const double t1 = now_ms();
    [cb waitUntilCompleted];
    c[@"return_ms"] = @(ms); c[@"returned_yes"] = @(ok); c[@"kernel_done_at_return"] = @(doneAtReturn);
    c[@"completed_after_ms"] = @(now_ms() - t1);
    c[@"status"] = @((unsigned long)cb.status);
    if (mode == 0) check(c, @"S4 plain commit returns at once", ms < 5);
    else {
        check(c, @"S2 returns at the bound (250 ms), not with the queue", ms >= 220 && ms <= 330);
        check(c, @"S2 returns YES", ok);
    }
    check(c, @"the command buffer completes afterwards", cb.status == MTLCommandBufferStatusCompleted);
    finish(mode == 0 ? @"async-commit" : mode == 1 ? @"blocked-queue" : @"self-queue", c);
}

static void refused(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.refused.submit", DISPATCH_QUEUE_SERIAL)];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    id<MTLCommandBuffer> cb = [q commandBuffer];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture = t; rp.colorAttachments[0].loadAction = MTLLoadActionClear;
    id<MTLRenderCommandEncoder> open = [cb renderCommandEncoderWithDescriptor:rp];   // never ended
    (void)open;
    BOOL raised = NO; const double t0 = now_ms();
    @try { (void)[(id)cb commitAndWaitUntilSubmitted]; } @catch (NSException *e) { raised = YES; c[@"reason"] = e.reason ?: @""; }
    const double ms = now_ms() - t0;
    c[@"raised"] = @(raised); c[@"return_ms"] = @(ms);
    check(c, @"S7 the refusal raises as before", raised);
    check(c, @"S7 no wait after a refusal", ms < 50);
    finish(@"refused", c);
    @try { [open endEncoding]; } @catch (NSException *e) { (void)e; }
}

// Core Animation end to end: count the commit variants it sends, and whether the command buffers it committed with a
// wait were finished when its frame ended.
static NSMutableArray *CACommits; static _Atomic uint64_t CAWaitCommits, CAPlainCommits, CAScheduledWaits;
static void hookCountingCommits(Class cls) {
    Method w = class_getInstanceMethod(cls, @selector(commitAndWaitUntilSubmitted));
    IMP wi = method_getImplementation(w);
    method_setImplementation(w, imp_implementationWithBlock(^BOOL(id cb) {
        atomic_fetch_add(&CAWaitCommits, 1);
        BOOL r = ((BOOL (*)(id, SEL))wi)(cb, @selector(commitAndWaitUntilSubmitted));
        @synchronized (CACommits) { [CACommits addObject:@{@"cb":cb, @"done_at_return":@(kernelDone(cb))}]; }
        return r; }));
    Method p = class_getInstanceMethod(cls, @selector(commit));
    IMP pi = method_getImplementation(p);
    method_setImplementation(p, imp_implementationWithBlock(^(id cb) { atomic_fetch_add(&CAPlainCommits, 1);
        ((void (*)(id, SEL))pi)(cb, @selector(commit)); }));
    Method s = class_getInstanceMethod(cls, @selector(waitUntilScheduled));
    IMP si = method_getImplementation(s);
    method_setImplementation(s, imp_implementationWithBlock(^(id cb) { atomic_fetch_add(&CAScheduledWaits, 1);
        ((void (*)(id, SEL))si)(cb, @selector(waitUntilScheduled)); }));
}
static void caRenderer(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    CACommits = [NSMutableArray array];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.ca.submit", DISPATCH_QUEUE_SERIAL)];
    hookCountingCommits(object_getClass([q commandBuffer]));
    const uint64_t plain0 = atomic_load(&CAPlainCommits);   // our own probe command buffer above is not counted below
    id<MTLTexture> target = surfaceTexture(device, 96, 64);
    CARenderer *r = [CARenderer rendererWithMTLTexture:target options:@{kCARendererMetalCommandQueue:q}];
    CALayer *root = [CALayer layer]; root.frame = CGRectMake(0, 0, 96, 64); root.opaque = YES;
    CGColorRef grey = CGColorCreateSRGB(0.8, 0.8, 0.8, 1), white = CGColorCreateSRGB(1, 1, 1, 1);
    root.backgroundColor = grey;
    CALayer *box = [CALayer layer]; box.frame = CGRectMake(24, 22, 48, 24); box.backgroundColor = white; [root addSublayer:box];
    r.layer = root; r.bounds = root.bounds;
    [CATransaction flush];
    const unsigned frames = 12; unsigned framesDone = 0, waitedFinished = 0, waited = 0;
    for (unsigned f = 0; f < frames; f++) @autoreleasepool {
        [CATransaction begin]; [CATransaction setDisableActions:YES];
        box.frame = CGRectMake(4 + 4 * f, 22, 48, 24);
        [CATransaction commit]; [CATransaction flush];
        NSUInteger before; @synchronized (CACommits) { before = CACommits.count; }
        [r beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
        [r addUpdateRect:root.bounds];
        [r render];
        [r endFrame];
        @synchronized (CACommits) {
            for (NSUInteger i = before; i < CACommits.count; i++) {
                waited++;
                if (kernelDone(CACommits[i][@"cb"])) waitedFinished++;
            }
        }
        framesDone++;
    }
    c[@"frames"] = @(framesDone);
    // ca_commits: every -commit, including the one each commitAndWaitUntilSubmitted sends itself
    c[@"ca_commit_and_wait"] = @(atomic_load(&CAWaitCommits)); c[@"ca_commits"] = @(atomic_load(&CAPlainCommits) - plain0);
    c[@"ca_wait_until_scheduled"] = @(atomic_load(&CAScheduledWaits));
    drain(q);
    c[@"waited_commits_finished_at_frame_end"] = @(waitedFinished); c[@"waited_commits"] = @(waited);
    // CARenderer's context (its flags from the renderer) ends frames with a plain commit on 26A428; WindowServer's
    // IOMFBDisplay context (new_metal_context flags 0) flushes with commitAndWaitUntilSubmitted. Recorded, and every
    // command buffer Core Animation did wait for must be finished at the frame's end.
    check(c, @"Core Animation rendered every frame", framesDone == frames);
    check(c, @"S1 every command buffer it waited for was finished at the frame's end", waitedFinished == waited);
    finish(@"ca-renderer", c);
    CGColorRelease(grey); CGColorRelease(white);
}

// ---- the pipelined kext's stand-in (PS_PIPELINE=1) ----
static double assocMs(id cb, const void *key) { NSNumber *v = objc_getAssociatedObject(cb, key); return v ? v.doubleValue : -1; }
static void wsQueuePipe(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.pipe.submit", DISPATCH_QUEUE_SERIAL)];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    const unsigned n = 100; unsigned queuedAtReturn = 0, doneAtReturn = 0, yes = 0, inOrder = 1, completed = 0;
    double maxMs = 0, sumMs = 0, lastDone = 0;
    NSMutableArray *cbs = [NSMutableArray array];
    for (unsigned i = 0; i < n; i++) @autoreleasepool {
        id<MTLCommandBuffer> cb = clearFrame(q, t, i);
        const double t0 = now_ms();
        if ([(id)cb commitAndWaitUntilSubmitted]) yes++;
        const double ms = now_ms() - t0;
        if (assocMs(cb, &KQueuedKey) >= 0) queuedAtReturn++;
        if (kernelDone(cb)) doneAtReturn++;
        sumMs += ms; if (ms > maxMs) maxMs = ms;
        [cbs addObject:cb];
    }
    for (id<MTLCommandBuffer> cb in cbs) {
        [cb waitUntilCompleted];
        const double done = assocMs(cb, &KDoneKey);
        if (cb.status == MTLCommandBufferStatusCompleted) completed++;
        if (done < lastDone) inOrder = 0;
        lastDone = done;
    }
    c[@"command_buffers"] = @(n); c[@"queued_at_return"] = @(queuedAtReturn); c[@"gpu_done_at_return"] = @(doneAtReturn);
    c[@"returned_yes"] = @(yes); c[@"completed"] = @(completed); c[@"mean_wait_ms"] = @(sumMs / n); c[@"max_wait_ms"] = @(maxMs);
    check(c, @"U1 queued to the GPU at every return", queuedAtReturn == n);
    check(c, @"U1 the return did not wait for the GPU end (at most a tenth finished)", doneAtReturn <= n / 10);
    check(c, @"returned YES", yes == n);
    check(c, @"C1 every one completes afterwards, in order", completed == n && inOrder);
    finish(@"ws-queue-pipe", c);
}
static NSMutableArray *Drops;                         // -[AdrenoCommandBuffer adrenoDropEncodingState] times
static NSMutableArray *Fills, *WriteBacks;            // -[AdrenoSurfaceShadow fillLocked] / -writeBack times
static void hookTimes(void) {
    Drops = [NSMutableArray array]; Fills = [NSMutableArray array]; WriteBacks = [NSMutableArray array];
    struct { Class cls; SEL sel; NSMutableArray *__unsafe_unretained log; } h[] = {
        {NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDropEncodingState"), Drops},
        {NSClassFromString(@"AdrenoSurfaceShadow"), NSSelectorFromString(@"fillLocked"), Fills},
        {NSClassFromString(@"AdrenoSurfaceShadow"), NSSelectorFromString(@"writeBack"), WriteBacks}};
    for (unsigned i = 0; i < 3; i++) {
        Method m = h[i].cls ? class_getInstanceMethod(h[i].cls, h[i].sel) : NULL;
        if (!m) { fprintf(stderr, "no %s\n", sel_getName(h[i].sel)); exit(66); }
        IMP orig = method_getImplementation(m); SEL sel = h[i].sel; NSMutableArray *log = h[i].log;
        method_setImplementation(m, imp_implementationWithBlock(^(id obj) {
            const double t = now_ms();
            @synchronized (log) { [log addObject:@{@"t":@(t), @"obj":@((uintptr_t)(__bridge void *)obj)}]; }
            ((void (*)(id, SEL))orig)(obj, sel);
        }));
    }
}
static void completePipe(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.complete.submit", DISPATCH_QUEUE_SERIAL)];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    const useconds_t saved = KernelUs; KernelUs = 30000;
    id<MTLCommandBuffer> cb = clearFrame(q, t, 3);
    __block double handlerAt = -1;
    [cb addCompletedHandler:^(id<MTLCommandBuffer> b) { (void)b; handlerAt = now_ms(); }];
    NSUInteger drops0; @synchronized (Drops) { drops0 = Drops.count; }
    const double t0 = now_ms();
    [(id)cb commitAndWaitUntilSubmitted];
    const double returned = now_ms() - t0;
    [cb waitUntilCompleted];
    const double waited = now_ms(), gpuEnd = assocMs(cb, &KGpuEndKey);
    usleep(20000);                                     // the handlers ran on the notification queue
    double dropAt = -1; @synchronized (Drops) { if (Drops.count > drops0) dropAt = [Drops.lastObject[@"t"] doubleValue]; }
    KernelUs = saved;
    c[@"return_ms"] = @(returned); c[@"gpu_end_after_return_ms"] = @(gpuEnd - (t0 + returned));
    c[@"wait_until_completed_minus_gpu_end_ms"] = @(waited - gpuEnd); c[@"handler_minus_gpu_end_ms"] = @(handlerAt - gpuEnd);
    c[@"drop_minus_gpu_end_ms"] = @(dropAt - gpuEnd);
    check(c, @"U1 commitAndWaitUntilSubmitted returned before the GPU end", returned < 25);
    check(c, @"C1 waitUntilCompleted returned after the GPU end", waited >= gpuEnd);
    check(c, @"C1 the completed handler ran after the GPU end", handlerAt >= gpuEnd);
    check(c, @"U3 the encoding state (staging arenas) was dropped after the GPU end", dropAt >= gpuEnd);
    check(c, @"completed", cb.status == MTLCommandBufferStatusCompleted);
    finish(@"complete-pipe", c);
}
static double frameLoop(id<MTLDevice> device, int pipe, unsigned frames, useconds_t cpuUs, useconds_t gpuUs) {
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.fps.submit", DISPATCH_QUEUE_SERIAL)];
    id<MTLTexture> t = surfaceTexture(device, 64, 64);
    const int savedMode = PipeMode; const useconds_t savedUs = KernelUs;
    PipeMode = pipe; KernelUs = gpuUs;
    id<MTLCommandBuffer> last = nil;
    double first = 0;
    for (unsigned f = 0; f < frames; f++) @autoreleasepool {
        usleep(cpuUs);                                 // WindowServer's CPU part of the frame
        id<MTLCommandBuffer> cb = clearFrame(q, t, f);
        [(id)cb commitAndWaitUntilSubmitted];          // then it swaps
        if (f == 4) first = now_ms();
        last = cb;
    }
    const double span = now_ms() - first;
    [last waitUntilCompleted];
    PipeMode = savedMode; KernelUs = savedUs;
    return (frames - 5) * 1000.0 / span;
}
static void overlapFps(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    const double sync = frameLoop(device, 0, 40, 5000, 13400), pipe = frameLoop(device, 1, 40, 5000, 13400);
    c[@"sync_fps"] = @(sync); c[@"pipelined_fps"] = @(pipe); c[@"serial_bound"] = @(1000.0 / 18.4); c[@"overlap_bound"] = @(1000.0 / 13.4);
    check(c, @"synchronous: CPU and GPU in series (at most 1000 / 18.4)", sync <= 1000.0 / 18.4 * 1.03);
    check(c, @"pipelined: at least 85% of 1000 / max(gpu, cpu) (host timers)", pipe >= 1000.0 / 13.4 * 0.85);
    check(c, @"pipelined: faster than synchronous by a fifth", pipe >= sync * 1.2);
    finish(@"overlap-fps", c);
}
static void shadowPipe(id<MTLDevice> device) {
    NSMutableDictionary *c = [NSMutableDictionary dictionary];
    id<MTLCommandQueue> q = [device newCommandQueue];
    [(id)q setSubmissionQueue:dispatch_queue_create("present-sync.shadow.submit", DISPATCH_QUEUE_SERIAL)];
    const NSUInteger w = 68, h = 32;                   // 272-byte rows: 16-aligned, not 64: an aligned shadow
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@(w), (id)kIOSurfaceHeight:@(h),
        (id)kIOSurfaceBytesPerRow:@(w * 4), (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfacePixelFormat:@(0x42475241)});
    MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:w height:h mipmapped:NO];
    d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    id<MTLTexture> t = [device newTextureWithDescriptor:d iosurface:s plane:0];
    const useconds_t saved = KernelUs; KernelUs = 60000;
    NSUInteger fills0, wb0; @synchronized (Fills) { fills0 = Fills.count; } @synchronized (WriteBacks) { wb0 = WriteBacks.count; }
    id<MTLCommandBuffer> first = clearFrame(q, t, 1);  // writes the shadow on the "GPU" for 60 ms
    [(id)first commitAndWaitUntilSubmitted];
    const double firstEnd = assocMs(first, &KGpuEndKey);
    IOSurfaceLock(s, 0, NULL);                         // the CPU writes the surface: its seed changes
    ((uint32_t *)IOSurfaceGetBaseAddress(s))[0] = 0x11223344u;
    IOSurfaceUnlock(s, 0, NULL);
    const double encodeAt = now_ms();
    id<MTLCommandBuffer> second = clearFrame(q, t, 2);   // binds the shadow again: refilled from the surface
    const double encoded = now_ms();
    [(id)second commitAndWaitUntilSubmitted];
    [second waitUntilCompleted];
    usleep(20000);
    KernelUs = saved;
    unsigned inFlight = 0, after = 0;
    double writeBack = -1;
    @synchronized (Fills) {
        for (NSUInteger i = fills0; i < Fills.count; i++) {
            const double ft = [Fills[i][@"t"] doubleValue];
            if (ft >= encodeAt && ft < firstEnd) inFlight++; else if (ft >= firstEnd) after++;
        }
    }
    @synchronized (WriteBacks) { if (WriteBacks.count > wb0) writeBack = [WriteBacks[wb0][@"t"] doubleValue]; }
    c[@"first_gpu_end_minus_encode_ms"] = @(firstEnd - encodeAt); c[@"refills_in_flight"] = @(inFlight);
    c[@"refills_after"] = @(after); c[@"write_back_minus_first_gpu_end_ms"] = @(writeBack - firstEnd);
    c[@"second_encode_ms"] = @(encoded - encodeAt); c[@"second_encode_end_minus_first_gpu_end_ms"] = @(encoded - firstEnd);
    // The first command buffer's GPU write raced the CPU's; its write-back at completion makes the surface current again,
    // so the second may need no refill at all. What must never happen is a refill while the first is on the GPU.
    check(c, @"the CPU write came while the first command buffer was on the GPU", firstEnd > encodeAt + 20);
    check(c, @"U2 no shadow refill while a command buffer using it was on the GPU", inFlight == 0);
    check(c, @"U2 the second command buffer's encoding waited for the first's GPU end", encoded >= firstEnd);
    check(c, @"U3 the first command buffer's write-back ran after its GPU end", writeBack >= firstEnd);
    finish(@"shadow-pipe", c);
    CFRelease(s);
}

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 3) return 64;
        NSString *out = @(argv[2]);
        if ([[NSFileManager defaultManager] fileExistsAtPath:out]) return 64;
        [[NSFileManager defaultManager] createDirectoryAtPath:out withIntermediateDirectories:YES attributes:nil error:NULL];
        if (getenv("PS_KERNEL_US")) KernelUs = (useconds_t)atoi(getenv("PS_KERNEL_US"));
        Notify = dispatch_queue_create("present-sync.notify", DISPATCH_QUEUE_SERIAL);
        Report = [NSMutableDictionary dictionary];
        (void)MTLCopyAllDevices();
        NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])]; NSError *e = nil;
        if (![bundle loadAndReturnError:&e]) { fprintf(stderr, "bundle: %s\n", e.description.UTF8String); return 65; }
        Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
        if (!dc) return 66;
        hookPlugin(dc);
        io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
        id device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
        if (!device) return 67;
        MTLAddDevice(device);
        void (*setDefault)(id) = dlsym(RTLD_DEFAULT, "AdrenoSetDefaultDevice");
        if (!setDefault) { fprintf(stderr, "default-device-interpose.dylib is not inserted\n"); return 68; }
        setDefault(device);
        const char *only = getenv("PS_CASES");
#define RUN(name, stmt) if (!only || strstr(only, name)) { stmt; }
        RUN("ws-queue", wsQueue(device, NO));
        RUN("ws-deadline", wsQueue(device, YES));
        RUN("async-commit", blockedQueue(device, 0));
        RUN("blocked-queue", blockedQueue(device, 1));
        RUN("self-queue", blockedQueue(device, 2));
        RUN("refused", refused(device));
        RUN("ca-renderer", caRenderer(device));
        if (getenv("PS_PIPELINE")) {
            GpuLock = [NSObject new];
            hookTimes();
            PipeMode = 1;
            RUN("ws-queue-pipe", wsQueuePipe(device));
            RUN("complete-pipe", completePipe(device));
            RUN("overlap-fps", overlapFps(device));
            RUN("shadow-pipe", shadowPipe(device));
            PipeMode = 0;
        }
        Report[@"checks"] = @(Checks); Report[@"failures"] = @(Failures); Report[@"bad_kernel_commands"] = @(atomic_load(&BadCommands));
        Report[@"kernel_submissions"] = @(atomic_load(&Submitted));
        NSData *json = [NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingSortedKeys | NSJSONWritingPrettyPrinted error:NULL];
        [json writeToFile:[out stringByAppendingPathComponent:@"report.json"] atomically:NO];
        printf("%s: %u checks, %u failures\n", Failures ? "FAIL" : "PASS", Checks, Failures);
        return Failures ? 1 : 0;
    }
}
