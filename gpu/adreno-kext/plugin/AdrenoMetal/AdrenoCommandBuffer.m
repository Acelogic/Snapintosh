/* SPDX-License-Identifier: MIT */
// AdrenoCommandBuffer.m - command queue, command buffer and synchronous fence transport.
//
// Ordinary commits append a driver fence to native IOGPU segment storage.
// Bounded linear render-pass clears and buffer fills emit native GPU writes.
// With the kext's IB ABI, render passes become ADRENO_KCMD_IB packages (AdrenoDrawCommands.h) placed between the
// FILL32 commands in encoder order; compute dispatches share those packages and the fence stays last.
#import "AdrenoMTLObjectsPrivate.h"
#import <os/log.h>
#import "AdrenoResourceUsage.h"
#import "AdrenoFillCommands.h"
#import "AdrenoDrawCommands.h"
#import "AdrenoShader.h"
#include <fcntl.h>
#include <sys/resource.h>
#import <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

// =============================== queue / command buffer ===============================
// The kernel submission (agents/present-sync FAILURE-MODES.md S1): IOGPUMetalCommandQueue issues the syscall here, and
// the Adreno kext runs each command buffer to completion inside it (IOGPUCommandQueue::submitCommandBuffer ->
// processCommandBuffer -> submitIB, which returns after the IB retired).
@interface IOGPUMetalCommandQueue (AdrenoPresentSync)
- (void)submitCommandBuffers:(id __unsafe_unretained *)buffers count:(NSUInteger)count;
@end
@interface AdrenoCommandBuffer (AdrenoPresentSync)
- (void)adrenoDidSubmit;
@end
@implementation AdrenoCommandQueue
// Mark each command buffer once its kernel submission returned: commitAndWaitUntilSubmitted waits for this mark.
- (void)submitCommandBuffers:(id __unsafe_unretained *)buffers count:(NSUInteger)count {
    [super submitCommandBuffers:buffers count:count];
    for (NSUInteger i = 0; i < count; i++)
        if ([buffers[i] isKindOfClass:[AdrenoCommandBuffer class]]) [(AdrenoCommandBuffer *)buffers[i] adrenoDidSubmit];
}
// Same shape as AGXG15XFamilyCommandQueue -initWithDevice:descriptor: (calls the IOGPU args: variant with a
// vendor-sized struct). The generic -initWithDevice:descriptor: sends only 0x408 bytes and has no vendor tail.
- (instancetype)initWithDevice:(id<MTLDevice>)d descriptor:(MTLCommandQueueDescriptor *)desc {
    AdrenoNewCommandQueueArgs a; memset(&a, 0, sizeof a);
    return [super initWithDevice:d descriptor:desc args:&a argsSize:sizeof a];
}
- (id<MTLCommandBuffer>)commandBuffer {
    return [[AdrenoCommandBuffer alloc] initWithQueue:self retainedReferences:YES];
}
- (id<MTLCommandBuffer>)commandBufferWithUnretainedReferences {
    return [[AdrenoCommandBuffer alloc] initWithQueue:self retainedReferences:NO];
}
- (id<MTLCommandBuffer>)commandBufferWithDescriptor:(MTLCommandBufferDescriptor *)d {
    return [[AdrenoCommandBuffer alloc] initWithQueue:self retainedReferences:d.retainedReferences];
}
@end

// The diagnostics file (AdrenoMTLObjectsPrivate.h). Opened once per process; writes stop after 2 MiB.
static _Atomic uint64_t gAdrenoDiag[AdrenoDiagCounterCount];
static _Atomic uint64_t gAdrenoDiagBytes, gAdrenoDiagLastStats, gAdrenoWorkID;
static _Atomic unsigned gAdrenoTraceLost;
static double AdrenoDiagNow(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void AdrenoDiagStartSampler(void) __attribute__((unused));   // opt-in thread profiler
static int AdrenoDiagFD(void) {
    static int fd = -1; static dispatch_once_t once;
    dispatch_once(&once, ^{
        char path[256];
        snprintf(path, sizeof path, "/private/var/tmp/adreno-%s-%d.log", getprogname(), (int)getpid());
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            char line[160]; int n = snprintf(line, sizeof line, "open pid %d %s wall %ld\n", (int)getpid(), getprogname(), (long)time(NULL));
            if (n > 0) (void)write(fd, line, (size_t)n);
            if (getenv("ADRENO_DIAG_PROFILE")) AdrenoDiagStartSampler();
        }
    });
    return fd;
}

// Optional CPU profile (ADRENO_DIAG_PROFILE): every 50 ms each running thread is suspended just long enough to
// read its PC and LR (no allocation while any thread is suspended), symbolised afterwards with dladdr; every 30 s
// the top functions and callers go to the diagnostics file.
enum { AdrenoSampleSlots = 256 };
static void AdrenoDiagSymbol(uint64_t address, char *out, size_t size) {
    Dl_info info;
    if (address && dladdr((const void *)address, &info) && info.dli_fname) {
        const char *image = strrchr(info.dli_fname, '/') ? strrchr(info.dli_fname, '/') + 1 : info.dli_fname;
        if (info.dli_sname) snprintf(out, size, "%s!%s", image, info.dli_sname);
        else snprintf(out, size, "%s+0x%llx", image, (unsigned long long)(address - (uint64_t)info.dli_fbase));
    } else snprintf(out, size, "?0x%llx", (unsigned long long)address);
}
static void AdrenoDiagTop(NSMutableDictionary<NSString *, NSNumber *> *counts, NSString *title, uint64_t total, unsigned limit) {
    NSArray<NSString *> *keys = [counts keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        return [b compare:a];
    }];
    NSMutableString *line = [NSMutableString stringWithFormat:@"%@ (%llu samples):", title, total];
    for (NSUInteger i = 0; i < keys.count && i < limit; i++)
        [line appendFormat:@"\n  %5.1f%% %@", 100.0 * counts[keys[i]].doubleValue / (double)MAX(total, 1ull), keys[i]];
    AdrenoDiagLine(line);
}
static void *AdrenoDiagSampler(void *unused) {
    (void)unused;
    pthread_setname_np("adreno-diag-sampler");
    thread_act_t me = mach_thread_self();
    NSMutableDictionary<NSString *, NSNumber *> *pcs = [NSMutableDictionary dictionary], *lrs = [NSMutableDictionary dictionary];
    uint64_t samples = 0, rounds = 0, idle = 0;
    double last = AdrenoDiagNow();
    static uint64_t pc[AdrenoSampleSlots], lr[AdrenoSampleSlots];
    for (;;) {
        usleep(50000);
        @autoreleasepool {
            thread_act_array_t threads = NULL;
            mach_msg_type_number_t count = 0;
            if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) continue;
            unsigned taken = 0;
            for (mach_msg_type_number_t i = 0; i < count; i++) {
                thread_basic_info_data_t basic;
                mach_msg_type_number_t n = THREAD_BASIC_INFO_COUNT;
                BOOL running = threads[i] != me &&
                    thread_info(threads[i], THREAD_BASIC_INFO, (thread_info_t)&basic, &n) == KERN_SUCCESS &&
                    basic.run_state == TH_STATE_RUNNING && !(basic.flags & TH_FLAGS_IDLE);
                if (running && taken < AdrenoSampleSlots && thread_suspend(threads[i]) == KERN_SUCCESS) {
                    arm_thread_state64_t state;
                    mach_msg_type_number_t sn = ARM_THREAD_STATE64_COUNT;
                    kern_return_t got = thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&state, &sn);
                    thread_resume(threads[i]);
                    if (got == KERN_SUCCESS) {
                        pc[taken] = (uint64_t)__builtin_ptrauth_strip((void *)arm_thread_state64_get_pc(state), 0);
                        lr[taken] = (uint64_t)__builtin_ptrauth_strip((void *)arm_thread_state64_get_lr(state), 0);
                        taken++;
                    }
                }
                mach_port_deallocate(mach_task_self(), threads[i]);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof *threads);
            rounds++;
            if (!taken) idle++;
            char name[512];
            for (unsigned i = 0; i < taken; i++) {
                AdrenoDiagSymbol(pc[i], name, sizeof name);
                NSString *key = @(name);
                pcs[key] = @(pcs[key].unsignedLongLongValue + 1);
                AdrenoDiagSymbol(lr[i], name, sizeof name);
                key = @(name);
                lrs[key] = @(lrs[key].unsignedLongLongValue + 1);
            }
            samples += taken;
            double now = AdrenoDiagNow();
            if (now - last >= 30) {
                last = now;
                AdrenoDiagLine([NSString stringWithFormat:@"profile rounds=%llu idle_rounds=%llu running_samples=%llu",
                                rounds, idle, samples]);
                AdrenoDiagTop(pcs, @"profile pc", samples, 30);
                AdrenoDiagTop(lrs, @"profile caller", samples, 20);
                (void)fsync(AdrenoDiagFD());
            }
        }
    }
    return NULL;
}
static void AdrenoDiagStartSampler(void) {
    pthread_t t;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &a, AdrenoDiagSampler, NULL) != 0) AdrenoDiagLine(@"profile sampler did not start");
    pthread_attr_destroy(&a);
}
void AdrenoDiagLine(NSString *line) {
    int fd = AdrenoDiagFD();
    if (!line) return;
    if (fd < 0) { atomic_store(&gAdrenoTraceLost, 1); return; }
    // Wall time and pid first: a RAM scan of a stopped guest also finds earlier boots' lines (pids repeat).
    NSData *bytes = [[NSString stringWithFormat:@"w%ld p%d %.1f %@\n", (long)time(NULL), (int)getpid(), AdrenoDiagNow(), line]
                     dataUsingEncoding:NSUTF8StringEncoding];
    if (atomic_fetch_add(&gAdrenoDiagBytes, bytes.length) + bytes.length > (2u << 20)) {
        if (!atomic_exchange(&gAdrenoTraceLost, 1)) {
            const char marker[]="work-trace-incomplete: byte budget exhausted\n";
            (void)write(fd, marker, sizeof marker-1);
        }
        return;
    }
    if (write(fd, bytes.bytes, bytes.length) != (ssize_t)bytes.length) atomic_store(&gAdrenoTraceLost, 1);
}
// The file is open and its byte budget is spent: AdrenoDiagLine refuses every further line (the call that crossed the
// budget already set the trace-lost flag and wrote the marker), so a caller need not build one.
static BOOL AdrenoDiagSpent(void) {
    return AdrenoDiagFD() >= 0 && atomic_load(&gAdrenoDiagBytes) >= (2u << 20);
}
void AdrenoDiagAdd(AdrenoDiagCounter counter, uint64_t amount) {
    if (counter < AdrenoDiagCounterCount) atomic_fetch_add(&gAdrenoDiag[counter], amount);
}
// AdrenoDisplay's "AdrenoDisplayStats" (Presents, Blank, CopyErrors, LastFormat): what reached the panel.
static NSString *AdrenoDiagDisplay(void) {
    io_service_t display = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AdrenoDisplay"));
    if (!display) return @"none";
    CFTypeRef value = IORegistryEntryCreateCFProperty(display, CFSTR("AdrenoDisplayStats"), kCFAllocatorDefault, 0);
    IOObjectRelease(display);
    NSDictionary *stats = CFBridgingRelease(value);
    if (![stats isKindOfClass:[NSDictionary class]]) return @"unpublished";
    // Layer-0 copy cost (speed batch): copies timed / mean / longest, in microseconds; absent from older kexts.
    NSNumber *timed = stats[@"CopyTimed"], *micros = stats[@"CopyMicros"], *maxMicros = stats[@"CopyMaxMicros"],
             *maint = stats[@"CopyMaintMicros"];
    NSString *copy = timed.unsignedLongLongValue ?
        [NSString stringWithFormat:@" copy(n/mean_us/max_us/maint_mean_us)=%@/%llu/%@/%llu", timed,
         micros.unsignedLongLongValue / timed.unsignedLongLongValue, maxMicros,
         maint.unsignedLongLongValue / timed.unsignedLongLongValue] : @"";
    return [NSString stringWithFormat:@"%@/%@/%@/%@ fmt=%@%@", stats[@"Presents"], stats[@"Drops"], stats[@"Blank"],
            stats[@"CopyErrors"], stats[@"LastFormat"], copy];
}
static void AdrenoDiagMaybeStats(void) {
    if (AdrenoDiagFD() < 0) return;
    uint64_t now = (uint64_t)AdrenoDiagNow(), last = atomic_load(&gAdrenoDiagLastStats);
    if (now < last + 15 || !atomic_compare_exchange_strong(&gAdrenoDiagLastStats, &last, now)) return;
    uint64_t c[AdrenoDiagCounterCount];
    for (unsigned i = 0; i < AdrenoDiagCounterCount; i++) c[i] = atomic_load(&gAdrenoDiag[i]);
    struct rusage u; getrusage(RUSAGE_SELF, &u);
    double cpu = (double)u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 + (double)u.ru_stime.tv_sec + u.ru_stime.tv_usec / 1e6;
    NSDictionary *sc = [AdrenoShader cacheStatistics];
    uint64_t staging[4]; AdrenoStagingCounters(staging);
    uint64_t arenas[21]; unsigned narenas = AdrenoStagingStatistics(arenas, 21);
    AdrenoDiagLine([NSString stringWithFormat:@"stats commits=%llu packages=%llu drops=%llu refusals=%llu cpu_copies=%llu "
                    "cpu_copy_bytes=%llu compute_dispatches=%llu tile_dispatches=%llu commit_ms=%.0f cpu_s=%.1f "
                    "shader_hits=%@/%@/%@ shader_misses=%@ compile_ms=%.0f waits=%@ write_errors=%@ dir=%@ "
                    "display(presents/drops/blank/copy_errors)=%@ staging(new/reused/pooled/released)=%llu/%llu/%llu/%llu "
                    "arenas(live/live_kib/peak/peak_kib/pooled_kib/aged/capped/drains/failures/retries_ok/continued)="
                    "%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu/%llu",
                    c[AdrenoDiagCommits], c[AdrenoDiagPackages], c[AdrenoDiagDrops], c[AdrenoDiagRefusals],
                    c[AdrenoDiagCPUCopies], c[AdrenoDiagCPUCopyBytes], c[AdrenoDiagComputeDispatches],
                    c[AdrenoDiagTileDispatches], c[AdrenoDiagCommitMicros] / 1000.0, cpu, sc[@"hits_memory"], sc[@"hits_pack"],
                    sc[@"hits_disk"], sc[@"misses"], [sc[@"miss_compile_ms"] doubleValue], sc[@"waits"], sc[@"write_errors"],
                    [sc[@"directory"] length] ? @"yes" : @"none", AdrenoDiagDisplay(), staging[0], staging[1], staging[2],
                    staging[3], arenas[4], arenas[5] >> 10, arenas[6], arenas[7] >> 10, arenas[9] >> 10, arenas[11], arenas[12],
                    arenas[14], arenas[15], arenas[17], narenas > 20 ? arenas[20] : 0]);
#if ADRENO_UBO_MIRROR || ADRENO_PERF_COUNTERS
    {   // agents/gpu-perf: what the GPU was given (FAILURE-MODES.md U6, T)
        uint64_t u[7] = {0}, w[4] = {0};
#if ADRENO_UBO_MIRROR
        AdrenoUBOMirrorCounters(u);
#endif
#if ADRENO_PERF_COUNTERS
        AdrenoPerfCounters(w);
#endif
#if ADRENO_UBO_MIRROR && ADRENO_UBO_MIRROR_SLABS
        uint64_t sl[5] = {0};
        AdrenoMirrorSlabCounters(sl);
        AdrenoDiagLine([NSString stringWithFormat:@"gpu-perf work(render_passes/draws/other_passes/ib_kdw)=%llu/%llu/%llu/%llu "
                        "ubo(mirror_copies/mirror_kib/mirror_reads/fallbacks/inpass/inpass_kib/drops)=%llu/%llu/%llu/%llu/%llu/%llu/%llu "
                        "slabs(live/allocated/takes/returns/exhausted)=%llu/%llu/%llu/%llu/%llu",
                        w[0], w[1], w[2], w[3], u[0], u[1], u[2], u[3], u[4], u[5], u[6], sl[0], sl[1], sl[2], sl[3], sl[4]]);
#else
        AdrenoDiagLine([NSString stringWithFormat:@"gpu-perf work(render_passes/draws/other_passes/ib_kdw)=%llu/%llu/%llu/%llu "
                        "ubo(mirror_copies/mirror_kib/mirror_reads/fallbacks/inpass/inpass_kib/drops)=%llu/%llu/%llu/%llu/%llu/%llu/%llu",
                        w[0], w[1], w[2], w[3], u[0], u[1], u[2], u[3], u[4], u[5], u[6]]);
#endif
    }
#endif
    (void)fsync(AdrenoDiagFD());   // survives the run's stop: an unflushed tail is rolled back at the next mount
}

// Every pass the IB builder refuses, once per distinct reason (at most 64 per process), to org.snapintosh.adreno:render.
// The reasons carry target metadata only (AdrenoDescribeTarget), so they are public: log show reads them from any
// client, including a Load pass that is refused without an exception (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md).
static void AdrenoLogPassRefusal(NSString *reason) {
    static os_log_t log; static NSMutableSet<NSString *> *seen; static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("org.snapintosh.adreno", "render"); seen = [NSMutableSet set]; });
    AdrenoDiagAdd(AdrenoDiagRefusals, 1);
    @synchronized (seen) {
        if (!reason || [seen containsObject:reason] || seen.count >= 64) return;
        [seen addObject:reason];
    }
    os_log_error(log, "render pass not built: %{public}@", reason);
    AdrenoDiagLine([@"refused: " stringByAppendingString:reason]);
}
// ADRENO_LENIENT: what was dropped instead of failing the command buffer, once per distinct reason (at most 64).
void AdrenoLogDropped(NSString *reason) {
    static os_log_t log; static NSMutableSet<NSString *> *seen; static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("org.snapintosh.adreno", "render"); seen = [NSMutableSet set]; });
    AdrenoDiagAdd(AdrenoDiagDrops, 1);
    @synchronized (seen) {
        if (!reason || [seen containsObject:reason] || seen.count >= 64) return;
        [seen addObject:reason];
    }
    os_log_error(log, "dropped: %{public}@", reason);
    AdrenoDiagLine([@"dropped: " stringByAppendingString:reason]);
}

void AdrenoLogZeroTexture(NSString *function, NSString *argument, NSInteger index) {
    static os_log_t log; static NSMutableSet<NSString *> *seen; static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("org.snapintosh.adreno", "render"); seen = [NSMutableSet set]; });
    NSString *line = [NSString stringWithFormat:@"zero texture: %@ texture(%ld) '%@' is used but unbound; it reads transparent black",
                      function ?: @"?", (long)index, argument ?: @"?"];
    @synchronized (seen) {
        if ([seen containsObject:line] || seen.count >= 64) return;
        [seen addObject:line];
    }
    os_log_error(log, "%{public}@", line);
    AdrenoDiagLine(line);
}

@interface AdrenoShadowWriteBackOnce : NSObject
- (instancetype)initWithShadows:(NSArray *)shadows;
- (void)run;
@end
@implementation AdrenoShadowWriteBackOnce { NSArray *_shadows; BOOL _done; }
- (instancetype)initWithShadows:(NSArray *)shadows { if ((self=[super init])) _shadows=shadows; return self; }
- (void)run {
    NSArray *todo=nil;
    @synchronized(self) { if (!_done) { _done=YES; todo=_shadows; _shadows=nil; } }
    for (id shadow in todo) AdrenoShadowWriteBack(shadow);
}
@end

@implementation AdrenoCommandBuffer {
    AdrenoResourceUsage *_adrenoResources;
    AdrenoFillCommands *_adrenoFills;
    BOOL _adrenoEncodingFailed;
    uint64_t _adrenoWorkID, _adrenoEncoderNext, _adrenoRenderEncoderID, _adrenoActiveEncoder, _adrenoEncoded, _adrenoOmitted;
    NSMutableDictionary<NSNumber *,NSMutableDictionary *> *_adrenoEncoders;
    NSMutableArray *_adrenoOmissions;
    BOOL _adrenoTraceIncomplete;
    NSMutableArray<AdrenoIBPackage *> *_adrenoPackages;   // encoder order; each knows the FILL32 bytes before it
    AdrenoRenderPass *_adrenoOpenPass;
    NSMapTable *_adrenoPackageUsage;                       // resource -> usage already published for the packages
    NSMutableSet *_adrenoShadowWrites;                     // IOSurface shadows these packages write (write-back on completion)
    id _adrenoShadowWriteBack;                             // AdrenoShadowWriteBackOnce, after commit
    NSMutableArray *_adrenoStagingArenas;                  // the packages' UBO staging arenas, pooled after completion
    id<MTLBuffer> _adrenoStagingCursor;                    // the last appended pass's staging arena and bytes used: the
    uint64_t _adrenoStagingCursorUsed;                     //   next render pass continues there (AdrenoPassContinueStaging)
    uint64_t _adrenoEntryID;                               // adrenoRecordWork's last ledger entry (owned by _adrenoEncoders)
    __unsafe_unretained NSMutableDictionary *_adrenoEntry;
    uint32_t _adrenoSubmitted;                             // the kernel submission returned (adrenoDidSubmit; atomic)
    dispatch_semaphore_t _adrenoSubmitSignal;              // created before a waiting commit; signalled by adrenoDidSubmit
}
- (uint64_t)adrenoBeginEncoder:(NSString *)kind details:(NSDictionary *)details {
    if (_adrenoEncodingFailed || self.status>=MTLCommandBufferStatusCommitted || _adrenoActiveEncoder) {
        _adrenoEncodingFailed=YES;
        [NSException raise:NSInternalInconsistencyException format:@"Adreno command buffer cannot begin an overlapping or late encoder"];
    }
    if (!_adrenoWorkID) _adrenoWorkID=atomic_fetch_add(&gAdrenoWorkID,1)+1;
    if (!_adrenoEncoders) _adrenoEncoders=[NSMutableDictionary dictionary];
    uint64_t ident=++_adrenoEncoderNext;
    if (_adrenoEncoders.count>=4096) {
        _adrenoEncodingFailed=YES;_adrenoTraceIncomplete=YES;
        [NSException raise:NSInvalidArgumentException format:@"Adreno work ledger encoder limit"];
    }
    _adrenoEncoders[@(ident)]=[@{@"kind":kind,@"details":details,@"encoded":@0,@"omitted":@0,@"ended":@NO} mutableCopy];
    _adrenoActiveEncoder=ident;
    if ([kind isEqual:@"render"]) _adrenoRenderEncoderID=ident;
    return ident;
}
- (void)adrenoEndEncoder:(uint64_t)encoder {
    if (!encoder || _adrenoActiveEncoder!=encoder) {
        _adrenoEncodingFailed=YES;
        [NSException raise:NSInternalInconsistencyException format:@"Adreno encoder ended out of order"];
    }
    _adrenoEncoders[@(encoder)][@"ended"]=@YES;
    _adrenoActiveEncoder=0;
}
- (NSDictionary *)adrenoWorkReport {
    if (!_adrenoWorkID) _adrenoWorkID=atomic_fetch_add(&gAdrenoWorkID,1)+1;
    NSMutableDictionary *encoders=[NSMutableDictionary dictionary];
    for(NSNumber *key in _adrenoEncoders)encoders[key.stringValue]=_adrenoEncoders[key];
    return @{@"schema":@1,@"pid":@(getpid()),@"command_buffer":@(_adrenoWorkID),
        @"encoded":@(_adrenoEncoded),@"omitted":@(_adrenoOmitted),@"encoding_failed":@(_adrenoEncodingFailed),
        @"trace_incomplete":@(_adrenoTraceIncomplete || atomic_load(&gAdrenoTraceLost)),
        @"encoders":encoders,@"omissions":_adrenoOmissions ?: @[],
        @"qualification":(_adrenoOmitted || _adrenoEncodingFailed || _adrenoTraceIncomplete || atomic_load(&gAdrenoTraceLost))?@"incomplete-work":@"encoding-only"};
}
- (void)adrenoRecordWork:(NSString *)operation encoder:(uint64_t)encoder omitted:(BOOL)omitted details:(NSDictionary *)details {
    // Entries are never removed from _adrenoEncoders, which owns them: the last one looked up stays valid.
    NSMutableDictionary *entry=encoder && encoder==_adrenoEntryID ? _adrenoEntry : _adrenoEncoders[@(encoder)];
    if (!entry) { _adrenoEncodingFailed=YES;[NSException raise:NSInternalInconsistencyException format:@"Adreno work without an encoder"]; }
    _adrenoEntryID=encoder; _adrenoEntry=entry;
    NSString *key=omitted?@"omitted":@"encoded";
    entry[key]=@([entry[key] unsignedLongLongValue]+1);
    if(omitted) _adrenoOmitted++; else _adrenoEncoded++;
    if(!omitted)return;
    NSDictionary *event=@{@"event":@"omitted",@"command_buffer":@(_adrenoWorkID),@"encoder":@(encoder),
        @"ordinal":@(_adrenoEncoded+_adrenoOmitted),@"operation":operation,@"details":details};
    if(!_adrenoOmissions)_adrenoOmissions=[NSMutableArray array];
    if(_adrenoOmissions.count<256)[_adrenoOmissions addObject:event];else _adrenoTraceIncomplete=YES;
    AdrenoLogDropped(details[@"reason"] ?: operation);
    if (!AdrenoDiagSpent()) {
        NSData *json=[NSJSONSerialization dataWithJSONObject:event options:NSJSONWritingSortedKeys error:NULL];
        if(json)AdrenoDiagLine([[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]);
        else {_adrenoTraceIncomplete=YES;AdrenoDiagLine(@"work-trace-incomplete: omission serialization failed");}
    }
#if !ADRENO_LENIENT
    _adrenoEncodingFailed=YES;
    [NSException raise:NSInvalidArgumentException format:@"%@",details[@"reason"] ?: operation];
#endif
}
- (AdrenoResourceUsage *)adrenoResourceUses {
    if (_adrenoEncodingFailed || self.status>=MTLCommandBufferStatusCommitted)
        [NSException raise:NSInternalInconsistencyException format:@"Adreno command buffer is no longer encodable"];
    if (!_adrenoResources) {
        id retained=self.retainedReferences ? [self akResourceList] : nil;
        if (self.retainedReferences && !retained)
            [NSException raise:NSInternalInconsistencyException format:@"Missing Adreno retained-resource list"];
        _adrenoResources=[[AdrenoResourceUsage alloc] initWithDevice:self.device retainedList:retained];
    }
    return _adrenoResources;
}
- (void)adrenoUseResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage {
    [[self adrenoResourceUses] recordResource:resource usage:usage];
}
- (void)adrenoFillBuffer:(id<MTLBuffer>)buffer range:(NSRange)range value:(uint8_t)value {
    AdrenoResourceUsage *resources=[self adrenoResourceUses];
    if (!_adrenoFills) _adrenoFills=[[AdrenoFillCommands alloc] initWithResources:resources];
    @try { [_adrenoFills recordBuffer:buffer range:range value:value]; }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
#if ADRENO_UBO_MIRROR
    AdrenoMirrorsWritten(self, buffer);                 // gpu-perf U1(d): a FILL32 writes the buffer
#endif
}
- (void)adrenoClearPass:(MTLRenderPassDescriptor *)pass { [self adrenoClearPass:pass refusal:nil]; }
- (void)adrenoClearPass:(MTLRenderPassDescriptor *)pass refusal:(NSString *)refusal {
    @try {
        AdrenoResourceUsage *resources=[self adrenoResourceUses];
        if(!_adrenoFills) _adrenoFills=[[AdrenoFillCommands alloc] initWithResources:resources];
        [_adrenoFills recordClearPass:pass refusal:refusal];
#if ADRENO_UBO_MIRROR
        AdrenoMirrorsDropAll(self);                     // gpu-perf U1(d): FILL32 clears of whatever the pass attaches
#endif
        [self adrenoRecordWork:@"render-pass-clear-fallback" encoder:_adrenoRenderEncoderID omitted:NO details:@{}];
    }
    @catch (NSException *error) {
        _adrenoEncodingFailed=YES;
        [self adrenoRecordWork:@"render-pass" encoder:_adrenoRenderEncoderID omitted:YES details:@{@"reason":error.reason ?: @"clear refused"}];
        @throw;
    }
}
- (void)adrenoRejectShaderDraw {
    _adrenoEncodingFailed=YES;
    [NSException raise:NSInternalInconsistencyException
                format:@"Adreno shader draws need the kext's IB ABI (" ADRENO_IB_REGISTRY_PROPERTY " = %d), which this accelerator does not publish",
                       ADRENO_GUEST_IB_ABI];
}
- (void)adrenoFailEncoding { _adrenoEncodingFailed=YES; }

// ---- draw packages
- (BOOL)adrenoDrawAvailable { return AdrenoDrawSubmissionAvailable(self.device); }
- (NSUInteger)adrenoFillBytes {
    return _adrenoFills ? [_adrenoFills commandBytes]-sizeof(struct adreno_submit_header) : 0;
}
- (AdrenoRenderPass *)adrenoBeginRenderPass:(MTLRenderPassDescriptor *)descriptor refusal:(NSString **)refusal {
    *refusal=nil;
    @try {
        (void)[self adrenoResourceUses];
        if (_adrenoOpenPass)
            [NSException raise:NSInternalInconsistencyException format:@"Adreno render pass began before the previous one ended"];
        @try {
            _adrenoOpenPass=[[AdrenoRenderPass alloc] initWithDescriptor:descriptor device:self.device];
            // Stage after the previous pass's slices in its arena (docs/PLUGIN-ARENA-TRIM-20261021.md, A10).
            AdrenoPassContinueStaging(_adrenoOpenPass, _adrenoStagingCursor, _adrenoStagingCursorUsed);
#if ADRENO_UBO_MIRROR
            AdrenoPassUseMirrors(_adrenoOpenPass, self);    // gpu-perf U: this command buffer's UBO mirrors
#endif
        }
        @catch (NSException *error) {
            // A pass the IB builder does not build yet (target format, row alignment, attachments) keeps exactly the
            // FILL32 clear path it has without the IB ABI (RGBA8 clears, Load passes on any target); only its shader
            // draws are refused, with this reason. Builder bugs (NSInternalInconsistencyException) still propagate.
            if (![error.name isEqualToString:NSInvalidArgumentException]) @throw;
            *refusal=error.reason;
            AdrenoLogPassRefusal(error.reason);
#if ADRENO_LENIENT
            // A pass the FILL32 path cannot record either (depth/stencil, layers, MSAA, attachments it does not
            // clear) is dropped: its clears and draws do not run, and the command buffer still commits.
            if(!_adrenoFills) _adrenoFills=[[AdrenoFillCommands alloc] initWithResources:[self adrenoResourceUses]];
            @try { [_adrenoFills recordClearPass:descriptor refusal:error.reason];
#if ADRENO_UBO_MIRROR
                AdrenoMirrorsDropAll(self);                 // gpu-perf U1(d)
#endif
                [self adrenoRecordWork:@"render-pass-clear-fallback" encoder:_adrenoRenderEncoderID omitted:NO details:@{}]; }
            @catch (NSException *fill) {
                if (![fill.name isEqualToString:NSInvalidArgumentException]) @throw;
                [self adrenoRecordWork:@"render-pass" encoder:_adrenoRenderEncoderID omitted:YES details:@{@"reason":fill.reason ?: @"render pass refused"}];
            }
#else
            [self adrenoClearPass:descriptor refusal:error.reason];
#endif
            return nil;
        }
        [self adrenoRecordWork:@"render-pass" encoder:_adrenoRenderEncoderID omitted:NO details:@{}];
        return _adrenoOpenPass;
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
}
- (void)adrenoRejectShaderDrawInPass:(NSString *)refusal {
    _adrenoEncodingFailed=YES;
    [NSException raise:NSInvalidArgumentException format:@"Adreno shader draws in this render pass: %@", refusal];
}
- (void)adrenoEndRenderPass:(AdrenoRenderPass *)pass {
    @try {
        if (!pass || pass!=_adrenoOpenPass)
            [NSException raise:NSInternalInconsistencyException format:@"Adreno render pass ended out of order"];
        _adrenoOpenPass=nil;
        if (_adrenoEncodingFailed) return;           // the command buffer can no longer be committed anyway
        [pass finish];
        // A pass larger than one IB package: its earlier segments first, in order (turnip-audit P2).
        for (id<AdrenoFinishedPass> segment in [pass adrenoSegments]) [self adrenoAppendFinishedPass:segment];
        [self adrenoAppendFinishedPass:pass];
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
}
- (void)adrenoAppendComputePass:(AdrenoComputePass *)pass {
    @try {
        if (!_adrenoActiveEncoder || ![_adrenoEncoders[@(_adrenoActiveEncoder)][@"kind"] isEqual:@"compute"])
            [NSException raise:NSInternalInconsistencyException format:@"Adreno compute work has no active compute encoder"];
        [self adrenoAppendFinishedPass:pass];
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
}
- (void)adrenoAppendBlitPass:(AdrenoBlitPass *)pass {
    @try {
        if (!_adrenoActiveEncoder || ![_adrenoEncoders[@(_adrenoActiveEncoder)][@"kind"] isEqual:@"blit"])
            [NSException raise:NSInternalInconsistencyException format:@"Adreno copy work has no active blit encoder"];
        [self adrenoAppendFinishedPass:pass];
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
}
- (void)adrenoAppendFinishedPass:(id<AdrenoFinishedPass>)pass {
    @try {
        if (!pass || !pass.finished)
            [NSException raise:NSInternalInconsistencyException format:@"Adreno package requires a finished pass"];
        if (pass.empty) return;
        // Publish what the kext must admit: every relocated resource with the union of its accesses.
        AdrenoResourceUsage *resources=[self adrenoResourceUses];
        if (!_adrenoPackageUsage) _adrenoPackageUsage=[NSMapTable mapTableWithKeyOptions:NSPointerFunctionsStrongMemory |
            NSPointerFunctionsObjectPointerPersonality valueOptions:NSPointerFunctionsStrongMemory];
        [pass enumerateResources:^(id resource, MTLResourceUsage usage) {
            id shadow=(usage&MTLResourceUsageWrite) ? AdrenoShadowOfBuffer(resource) : nil;
            if (shadow) {
                if (!self->_adrenoShadowWrites) self->_adrenoShadowWrites=[NSMutableSet set];
                [self->_adrenoShadowWrites addObject:shadow];
            }
            MTLResourceUsage published=[[self->_adrenoPackageUsage objectForKey:resource] unsignedIntegerValue];
            if ((usage|published)==published) return;
            [resources recordResource:resource usage:usage|published];
            [self->_adrenoPackageUsage setObject:@(usage|published) forKey:resource];
        }];
        // A FILL32 recorded after the current package started must run before this pass: open a new package.
        NSUInteger fills=[self adrenoFillBytes];
        AdrenoIBPackage *package=_adrenoPackages.lastObject;
        if (!package || package.fillsBefore!=fills || ![package canAppendPass:pass]) {
            package=[[AdrenoIBPackage alloc] initWithFillsBefore:fills];
            if (![package canAppendPass:pass])
                [NSException raise:NSInvalidArgumentException format:@"Adreno pass exceeds one IB package"];
            if (!_adrenoPackages) _adrenoPackages=[NSMutableArray array];
            [_adrenoPackages addObject:package];
        }
        [package appendPass:pass];
#if ADRENO_UBO_MIRROR
        AdrenoMirrorsAfterPass(self, pass);               // gpu-perf U1(c): what a blit, mipmap or compute pass writes
#endif
        NSArray *arenas=AdrenoFinishedPassArenas(pass);
        if (arenas.count) {
            if (!_adrenoStagingArenas) _adrenoStagingArenas=[NSMutableArray array];
            [_adrenoStagingArenas addObjectsFromArray:arenas];
        }
        uint64_t used=0;
        id<MTLBuffer> cursor=AdrenoFinishedPassStagingCursor(pass, &used);
        if (cursor) { _adrenoStagingCursor=cursor; _adrenoStagingCursorUsed=used; }
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES;@throw; }
}

- (void)commit {
    const double started = AdrenoDiagNow();
    @try { [self adrenoCommit]; }
    @finally {
        AdrenoDiagAdd(AdrenoDiagCommitMicros, (uint64_t)((AdrenoDiagNow() - started) * 1e6));
        if (!AdrenoDiagSpent()) {
            NSMutableDictionary *record=[[self adrenoWorkReport] mutableCopy];record[@"event"]=@"commit-encoding";
            record[@"commit_us"]=@((uint64_t)((AdrenoDiagNow()-started)*1e6));
            NSData *json=[NSJSONSerialization dataWithJSONObject:record options:NSJSONWritingSortedKeys error:NULL];
            if(json)AdrenoDiagLine([[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]);
            else {_adrenoTraceIncomplete=YES;AdrenoDiagLine(@"work-trace-incomplete: summary serialization failed");}
        }
    }
}
// RenderBox (IconRendering's icon renderer) commits with commitAndWaitUntilSubmitted (docs/USERSPACE-GRAPHICS-20261019.md),
// and Core Animation ends a WindowServer frame with it (MetalContext::flush(true)), then swaps. -commit only enqueues
// when the queue has a submission queue, as WindowServer's has, so these variants then wait for the kernel submission
// (agents/present-sync FAILURE-MODES.md S1-S7). With this kext the command buffer has finished drawing when that
// returns, so the swap can no longer overtake its frame. The wait is bounded (S2): at the bound it returns YES and the
// submission still happens later. It also ends at status Scheduled or later (hosts' harnesses that complete -commit).
#if ADRENO_PIPELINE
// --pipeline (agents/gpu-pipeline FAILURE-MODES.md U1): the kext returns a pipelined client's submission once its IB is
// in flight (IB_START), with the IOSurfaces it writes marked until it retires and IOGPU's completion following the GPU.
// The wait below is unchanged and now ends when the command buffer is queued to the GPU, as on Apple hardware; the swap
// that follows waits in AdrenoDisplay for the marks, and completion handlers and waitUntilCompleted for the GPU.
#endif
static const uint64_t kAdrenoSubmitWaitMs = 250;
static _Atomic uint64_t gAdrenoSubmitWaitTimeouts;
- (void)adrenoDidSubmit {
    __atomic_store_n(&_adrenoSubmitted, 1u, __ATOMIC_RELEASE);
    dispatch_semaphore_t signal = _adrenoSubmitSignal;
    if (signal) dispatch_semaphore_signal(signal);
}
- (void)adrenoWaitUntilSubmitted {
    const uint64_t start = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    while (!__atomic_load_n(&_adrenoSubmitted, __ATOMIC_ACQUIRE) && self.status < MTLCommandBufferStatusScheduled) {
        const uint64_t waited = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - start;
        if (waited >= kAdrenoSubmitWaitMs * NSEC_PER_MSEC) {
            const uint64_t n = atomic_fetch_add(&gAdrenoSubmitWaitTimeouts, 1) + 1;
            if (n <= 8 || !(n & 255))
                os_log_error(OS_LOG_DEFAULT, "AdrenoMetal: commit not submitted after %llu ms (%llu times); not waiting longer",
                             (unsigned long long)kAdrenoSubmitWaitMs, (unsigned long long)n);
            return;
        }
        dispatch_semaphore_wait(_adrenoSubmitSignal, dispatch_time(DISPATCH_TIME_NOW, (int64_t)NSEC_PER_MSEC));
    }
}
- (BOOL)commitAndWaitUntilSubmitted {
    if (!_adrenoSubmitSignal) _adrenoSubmitSignal = dispatch_semaphore_create(0);   // before the submission can signal it
    [self commit];
    [self adrenoWaitUntilSubmitted];
    return self.status != MTLCommandBufferStatusError;
}
- (BOOL)commitAndWaitUntilSubmittedWithDeadline:(uint64_t)deadline { (void)deadline; return [self commitAndWaitUntilSubmitted]; }
- (void)commitWithDeadline:(uint64_t)deadline { (void)deadline; [self commit]; }
- (void)adrenoCommit {
    // Let the native implementation reject repeated commits without touching
    // storage that may already be in flight or retired.
    if (self.status >= MTLCommandBufferStatusCommitted) { [super commit]; return; }
    if (_adrenoEncodingFailed)
        [NSException raise:NSInternalInconsistencyException format:@"Adreno command buffer encoding previously failed"];
    if (_adrenoOpenPass || _adrenoActiveEncoder) {
        _adrenoEncodingFailed=YES;
        [NSException raise:NSInternalInconsistencyException format:@"Adreno encoder was not ended before commit"];
    }
    // Kernel commands in encoder order: FILL32s before each package that follows them, then the fence.
    const struct adreno_submit_header fence={ADRENO_KCMD_FENCE,sizeof fence};
    NSData *fills=nil;
    NSUInteger bytes=sizeof fence;
    @try {
        if (_adrenoFills) {
            NSMutableData *encoded=[NSMutableData dataWithLength:[_adrenoFills commandBytes]];
            [_adrenoFills encodeInto:encoded.mutableBytes capacity:encoded.length];
            fills=[encoded subdataWithRange:NSMakeRange(0, encoded.length-sizeof fence)];
            bytes+=fills.length;
        }
        for (AdrenoIBPackage *package in _adrenoPackages) {
            if (package.fillsBefore>fills.length)
                [NSException raise:NSInternalInconsistencyException format:@"Adreno package precedes unrecorded fills"];
            bytes+=package.commandBytes;
        }
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES; @throw; }
    uint8_t *command = [self _reserveKernelCommandBufferSpace:bytes];
    if (!command)
        [NSException raise:NSInternalInconsistencyException format:@"Adreno fence command allocation failed"];
    [self beginSegment:command];
    // BeginSegment clears IOGPU's descriptors. Publish the deferred resource
    // uses afterwards so EndSegment includes them in the kernel submission.
    @try {
        NSUInteger at=0, fillAt=0;
        for (AdrenoIBPackage *package in _adrenoPackages) {
            memcpy(command+at, (const uint8_t *)fills.bytes+fillAt, package.fillsBefore-fillAt);
            at+=package.fillsBefore-fillAt; fillAt=package.fillsBefore;
            [package encodeInto:command+at capacity:package.commandBytes];
            at+=package.commandBytes;
        }
        if (fills.length>fillAt) memcpy(command+at, (const uint8_t *)fills.bytes+fillAt, fills.length-fillAt);
        at+=fills.length-fillAt;
        memcpy(command+at, &fence, sizeof fence);
        if (at+sizeof fence!=bytes)
            [NSException raise:NSInternalInconsistencyException format:@"Adreno kernel command layout differs from its reservation"];
        [_adrenoResources encodeIntoIOGPUList:[self ioGPUResourceList]];
        [self endCurrentSegment];
    }
    @catch (NSException *error) { _adrenoEncodingFailed=YES; @throw; }
    AdrenoDiagAdd(AdrenoDiagCommits, 1);
    AdrenoDiagAdd(AdrenoDiagPackages, _adrenoPackages.count);
    AdrenoDiagMaybeStats();
    // Shadows this buffer wrote go back to their IOSurfaces when it completes: the completion handler or
    // waitUntilCompleted, whichever comes first, once (docs/USERSPACE-GRAPHICS-20261019.md).
    if (_adrenoShadowWrites.count) {
        AdrenoShadowWriteBackOnce *once=[[AdrenoShadowWriteBackOnce alloc] initWithShadows:_adrenoShadowWrites.allObjects];
        _adrenoShadowWriteBack=once;
        [super addCompletedHandler:^(id<MTLCommandBuffer> cb) { (void)cb; [once run]; }];
    }
    // The staging arenas go back to the process's pool only when the GPU finished this command buffer without error; a
    // failed or uncertain completion keeps the old path (released with the command buffer). After a clean completion the
    // encoding state is dropped too: the packages (their streams' usage maps hold every resource they relocate), the
    // staging list and cursor. Nothing reads them after this commit, and a client that keeps the command buffer (Core
    // Animation keeps its last one) no longer keeps its arenas and their GPU address space
    // (docs/PLUGIN-ARENA-TRIM-20261021.md, A20).
    if (_adrenoStagingArenas.count || _adrenoPackages.count) {
        NSArray *arenas=[_adrenoStagingArenas copy];
        [super addCompletedHandler:^(id<MTLCommandBuffer> cb) {
            if (cb.status!=MTLCommandBufferStatusCompleted || cb.error) return;
            if ([(id)cb isKindOfClass:[AdrenoCommandBuffer class]]) [(AdrenoCommandBuffer *)cb adrenoDropEncodingState];
            if (arenas.count) AdrenoStagingArenasRecycle(arenas);
        }];
    }
#if ADRENO_PIPELINE
    // agents/gpu-pipeline U2: with the pipelined kext the next command buffer is encoded while this one still runs on the
    // GPU. The IOSurface shadows it uses count it until it completes (this handler runs after the write-back above), and
    // a CPU refill of one waits for that (AdrenoSurfaceShadow -syncIfNeeded).
    NSArray *gpuShadows=AdrenoShadowsForResourceIDs([_adrenoResources adrenoResourceIDs]);
    if (gpuShadows.count) {
        AdrenoShadowsGPUBegin(gpuShadows);
        [super addCompletedHandler:^(id<MTLCommandBuffer> cb) { (void)cb; AdrenoShadowsGPUEnd(gpuShadows); }];
    }
    @try { [super commit]; }
    @catch (NSException *error) { if (gpuShadows.count) AdrenoShadowsGPUEnd(gpuShadows); @throw; }
#else
    [super commit];
#endif
}
- (void)adrenoDropEncodingState {
    _adrenoPackages=nil; _adrenoPackageUsage=nil; _adrenoStagingArenas=nil; _adrenoStagingCursor=nil; _adrenoStagingCursorUsed=0;
}
- (void)adrenoRunShadowWriteBack { [(AdrenoShadowWriteBackOnce *)_adrenoShadowWriteBack run]; }
- (void)waitUntilCompleted {
    [super waitUntilCompleted];
    [self adrenoRunShadowWriteBack];
}
// Handlers run in the order they were added, and callers add theirs before commit: each runs the write-back first, so
// no completion handler reads a surface before the GPU's writes reach it.
- (void)addCompletedHandler:(MTLCommandBufferHandler)block {
    if (!block) { [super addCompletedHandler:block]; return; }
    MTLCommandBufferHandler handler=[block copy];
    [super addCompletedHandler:^(id<MTLCommandBuffer> cb) {
        if ([(id)cb isKindOfClass:[AdrenoCommandBuffer class]]) [(AdrenoCommandBuffer *)cb adrenoRunShadowWriteBack];
        handler(cb);
    }];
}
- (id<MTLRenderCommandEncoder>)renderCommandEncoderWithDescriptor:(MTLRenderPassDescriptor *)rp {
    return [[AdrenoRenderCommandEncoder alloc] initWithCommandBuffer:self descriptor:rp];
}
- (id<MTLBlitCommandEncoder>)blitCommandEncoder {
    return [[AdrenoBlitCommandEncoder alloc] initWithCommandBuffer:self];
}
- (id<MTLComputeCommandEncoder>)computeCommandEncoder {
    return [[AdrenoComputeCommandEncoder alloc] initWithCommandBuffer:self];
}
- (id<MTLComputeCommandEncoder>)computeCommandEncoderWithDispatchType:(MTLDispatchType)t {
    return [[AdrenoComputeCommandEncoder alloc] initWithCommandBuffer:self];
}
- (id<MTLComputeCommandEncoder>)computeCommandEncoderWithDescriptor:(MTLComputePassDescriptor *)d {
    return [[AdrenoComputeCommandEncoder alloc] initWithCommandBuffer:self];
}
// Completion handlers, waits and shared events remain native IOGPU/_MTL.
@end
