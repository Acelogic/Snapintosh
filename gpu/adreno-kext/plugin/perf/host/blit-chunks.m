/* SPDX-License-Identifier: MIT */
// blit-chunks: end-to-end host test of the CP_MEMCPY size cap (agents/gpu-perf FAILURE-MODES.md C1-C4).
//
//   blit-chunks BUNDLE OUTDIR
//
// Buffer-to-buffer blit copies of 4 KiB, 1 MiB, 1 MiB + 4 and 4 MiB + 12 bytes between two patterned buffers in one
// command buffer, captured as ubo-mirror does; report.json lists every copy. tools/blit-chunk-check.py executes the
// stream over a byte model and requires the destination to equal the source over every copied range, every CP_MEMCPY
// to be at most ADRENO_BLIT_CHUNK_BYTES, and no byte outside the ranges to be written.
// (The capture code below is ubo-mirror.m's.)
//
//
// Drives the AdrenoMetal plug-in device on this Mac (commits intercepted, nothing executes; as desktop-scenes and
// native-texture do) through a scripted workload whose constant-buffer contents are known, and writes per commit
// commands.bin plus snapshots of its own buffers, and report.json with the bytes every draw must read at GPU time
// (Metal semantics: CPU writes before commit, then the GPU copies and fills in encoding order).
// tools/ubo-mirror-check.py executes the streams symbolically and compares.
//
// One 256 KiB "ring" R holds every draw's constants at offsets that are not 64-byte aligned (phases 16, 32 and 48),
// as Core Animation's uniform buffer does:
//   fs  constant U &u        [[buffer(0)]]  32 bytes at base + 32   (known extent)
//   fs  constant float4 *p   [[buffer(2)]]  p[0..1] at base + 112    (pointer: the rest of the buffer)
//   vs  constant float4 *pts [[buffer(1)]]  pts[0..2] at base + 144  (pointer)
// Command buffer 1:
//   pass A: draws 0-3; the CPU then rewrites draw 0's u (before commit: the GPU must see the new bytes)
//   blit:   copyFromBuffer S -> R over draw 4's u                 (U1(c): mirrors of R must go)
//   pass B: draws 4-6
//   fill:   fillBuffer R over draw 7's u                          (U1(d))
//   pass C: draws 7-8
//   pass D: draw 9 with a fragment function that stores to a device buffer bound over R, then draw 10   (U1(a))
//   pass E: draws 11-12
// Command buffer 2: pass F: draws 13-14 (U11: a table per command buffer).
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <IOKit/IOKitLib.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (UBOMirror)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (uint32_t)resourceID;
- (void)didScheduleWithStartTime:(uint64_t)s endTime:(uint64_t)e error:(id)error;
- (void)didCompleteWithStartTime:(uint64_t)s endTime:(uint64_t)e error:(id)error;
@end

static NSString *Out;
static void *ReservedStart;
static NSUInteger ReservedLength;
static NSMutableArray<id<MTLBuffer>> *Tracked;
static NSMutableArray *Commits;
static int Scene;

static void InstallCapture(NSBundle *bundle) {
    Class cb = [bundle classNamed:@"AdrenoCommandBuffer"], dc = [bundle classNamed:@"AdrenoMTLDevice"];
    class_replaceMethod(cb, @selector(adrenoDrawAvailable), imp_implementationWithBlock(^BOOL(id c) { (void)c; return YES; }), "B16@0:8");
    class_replaceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"),
                        imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }), "B16@0:8");
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, NSSelectorFromString(@"_reserveKernelCommandBufferSpace:"));
    Method commit = class_getInstanceMethod(native, @selector(commit));
    IMP reserveIMP = method_getImplementation(reserve);
    SEL reserveSel = method_getName(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id c, NSUInteger length) {
        void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(c, reserveSel, length);
        ReservedStart = p; ReservedLength = length; return p; }));
    method_setImplementation(commit, imp_implementationWithBlock(^(id c) {
        NSString *name = [NSString stringWithFormat:@"commit-%04lu", (unsigned long)Commits.count];
        NSString *dir = [Out stringByAppendingPathComponent:name];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
        NSMutableArray *resources = [NSMutableArray array];
        if (ReservedStart && ReservedLength)
            [[NSData dataWithBytes:ReservedStart length:ReservedLength] writeToFile:[dir stringByAppendingPathComponent:@"commands.bin"] atomically:NO];
        for (id<MTLBuffer> b in Tracked) {     // the CPU's bytes at commit
            uint32_t rid = [(id)b resourceID];
            NSString *file = [NSString stringWithFormat:@"res-%u.bin", rid];
            [[NSData dataWithBytes:b.contents length:b.length] writeToFile:[dir stringByAppendingPathComponent:file] atomically:NO];
            [resources addObject:@{@"id":@(rid), @"file":file, @"size":@(b.length)}];
        }
        [Commits addObject:@{@"dir":name, @"scene":@"ubo-mirror", @"frame":@(Scene), @"has_commands":@(ReservedStart && ReservedLength),
                             @"resources":resources}];
        ReservedStart = NULL; ReservedLength = 0;
        [c didScheduleWithStartTime:0 endTime:0 error:nil];
        [c didCompleteWithStartTime:0 endTime:0 error:nil];
    }));
}


int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 3) { fprintf(stderr, "usage: blit-chunks BUNDLE OUTDIR\n"); return 64; }
    Out = @(argv[2]);
    [[NSFileManager defaultManager] createDirectoryAtPath:Out withIntermediateDirectories:YES attributes:nil error:NULL];
    (void)MTLCopyAllDevices();
    NSError *error = nil;
    NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])];
    if (![bundle loadAndReturnError:&error]) { fprintf(stderr, "bundle: %s\n", error.description.UTF8String); return 65; }
    InstallCapture(bundle);
    io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:acc];
    if (!device) return 67;
    MTLAddDevice(device);
    Tracked = [NSMutableArray array]; Commits = [NSMutableArray array];
    const NSUInteger total = 12u << 20;
    id<MTLBuffer> S = [device newBufferWithLength:total options:MTLResourceStorageModeShared];
    id<MTLBuffer> D = [device newBufferWithLength:total options:MTLResourceStorageModeShared];
    if (!S || !D) return 70;
    [Tracked addObject:S]; [Tracked addObject:D];
    for (NSUInteger i = 0; i < total / 4; i++) { ((uint32_t *)S.contents)[i] = (uint32_t)(i * 2654435761u); ((uint32_t *)D.contents)[i] = 0xdeadbeefu; }
    const NSUInteger sizes[4] = {4096, 1u << 20, (1u << 20) + 4, (4u << 20) + 12};
    NSUInteger src = 64, dst = 128;
    NSMutableArray *copies = [NSMutableArray array];
    Scene = 1;
    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLCommandBuffer> cb = [queue commandBuffer];
    id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
    for (int i = 0; i < 4; i++) {
        [b copyFromBuffer:S sourceOffset:src toBuffer:D destinationOffset:dst size:sizes[i]];
        [copies addObject:@{@"source":@([(id)S resourceID]), @"source_offset":@(src), @"destination":@([(id)D resourceID]),
                            @"destination_offset":@(dst), @"bytes":@(sizes[i])}];
        src += sizes[i] + 256; dst += sizes[i] + 512;
    }
    [b endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    NSDictionary *report = @{@"commits":Commits, @"copies":copies, @"scenes":@[@{@"scene":@"blit-chunks"}]};
    NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    [json writeToFile:[Out stringByAppendingPathComponent:@"report.json"] atomically:YES];
    printf("blit-chunks: %lu commits, %lu copies -> %s\n", (unsigned long)Commits.count, (unsigned long)copies.count, Out.UTF8String);
    return 0;
} }
