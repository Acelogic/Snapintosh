/* SPDX-License-Identifier: MIT */
// ubo-mirror: end-to-end host test of the per-command-buffer UBO mirror (agents/gpu-perf FAILURE-MODES.md U1-U13).
//
//   ubo-mirror BUNDLE OUTDIR
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

static void put(id<MTLBuffer> b, NSUInteger at, const float *v, NSUInteger n) { memcpy((uint8_t *)b.contents + at, v, 4 * n); }
static NSString *hex(const void *p, NSUInteger n) {
    NSMutableString *s = [NSMutableString string];
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%02x", ((const uint8_t *)p)[i]];
    return s;
}

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 3) { fprintf(stderr, "usage: ubo-mirror BUNDLE OUTDIR\n"); return 64; }
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

    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "struct U { float4 tint; float4 extra; };\n"
        "vertex float4 vs(uint i [[vertex_id]], constant float4 *pts [[buffer(1)]]) { return float4(pts[i].xy, 0, 1); }\n"
        "fragment float4 fs(constant U &u [[buffer(0)]], constant float4 *p [[buffer(2)]]) { return u.tint * u.extra + p[1] + p[0]; }\n"
        "fragment float4 fs_store(constant U &u [[buffer(0)]], device float4 *out [[buffer(3)]]) { out[0] = u.tint; return u.tint; }\n";
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
    if (!library) { fprintf(stderr, "library: %s\n", error.description.UTF8String); return 68; }
    id<MTLRenderPipelineState> pipes[2], pipe0, pipe1;
    for (int i = 0; i < 2; i++) {
        MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
        pd.vertexFunction = [library newFunctionWithName:@"vs"];
        pd.fragmentFunction = [library newFunctionWithName:i ? @"fs_store" : @"fs"];
        pd.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        pipes[i] = [device newRenderPipelineStateWithDescriptor:pd error:&error];
        if (!pipes[i]) { fprintf(stderr, "pipeline %d: %s\n", i, error.description.UTF8String); return 69; }
    }
    pipe0 = pipes[0]; pipe1 = pipes[1];
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:64 height:64 mipmapped:NO];
    td.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    td.storageMode = MTLStorageModeShared;
    id<MTLTexture> target = [device newTextureWithDescriptor:td];
    id<MTLBuffer> R = [device newBufferWithLength:256 * 1024 options:MTLResourceStorageModeShared];
    id<MTLBuffer> S = [device newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    if (!target || !R || !S) return 70;
    [Tracked addObject:R]; [Tracked addObject:S];
    memset(R.contents, 0xA5, R.length);
    for (NSUInteger i = 0; i < S.length / 4; i++) ((float *)S.contents)[i] = 9000.0f + (float)i;

    // The draws' constants: draw k at base 4096 + 256 k.
    enum { DRAWS = 15 };
    float *shadow = malloc(256 * 1024);             // R as the GPU must see it (Metal semantics), per draw
    NSMutableArray *expected = [NSMutableArray array];
    NSUInteger (^base)(int) = ^NSUInteger(int k) { return 4096 + 256 * (NSUInteger)k; };
    void (^fillDraw)(int) = ^(int k) {
        float u[8], p[8], pts[12];
        for (int j = 0; j < 8; j++) { u[j] = 100.0f * k + j; p[j] = 100.0f * k + 50 + j; }
        for (int j = 0; j < 12; j++) pts[j] = (j % 4 < 2) ? ((j / 4) == 0 ? -0.5f : (j / 4) == 1 ? 0.5f : 0.0f) + 0.001f * k : 100.0f * k + 80 + j;
        put(R, base(k) + 32, u, 8); put(R, base(k) + 112, p, 8); put(R, base(k) + 144, pts, 12);
    };
    for (int k = 0; k < DRAWS; k++) fillDraw(k);
    void (^expect)(int, NSString *) = ^(int k, NSString *pass) {   // R's bytes as the GPU reads them for draw k
        const uint8_t *g = (const uint8_t *)shadow;
        NSMutableArray *blobs = [@[hex(g + base(k) + 32, 32), hex(g + base(k) + 144, 48)] mutableCopy];
        if (k != 9) [blobs addObject:hex(g + base(k) + 112, 32)];              // draw 9 (fs_store) binds no p
        [expected addObject:@{@"draw":@(k), @"pass":pass, @"blobs":blobs}];
    };
    __block id<MTLCommandBuffer> cb = nil;
    id<MTLCommandQueue> queue = [device newCommandQueue];
    void (^pass)(NSString *, int, int, int) = ^(NSString *name, int first, int last, int storeAt) {
        MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
        rp.colorAttachments[0].texture = target;
        rp.colorAttachments[0].loadAction = MTLLoadActionLoad;
        rp.colorAttachments[0].storeAction = MTLStoreActionStore;
        id<MTLRenderCommandEncoder> e = [cb renderCommandEncoderWithDescriptor:rp];
        for (int k = first; k <= last; k++) {
            BOOL store = k == storeAt;
            [e setRenderPipelineState:store ? pipe1 : pipe0];
            [e setVertexBuffer:R offset:base(k) + 144 atIndex:1];
            [e setFragmentBuffer:R offset:base(k) + 32 atIndex:0];
            if (store) [e setFragmentBuffer:R offset:64 atIndex:3];      // the store lands below every draw's constants
            else [e setFragmentBuffer:R offset:base(k) + 112 atIndex:2];
            [e drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        }
        [e endEncoding];
    };

    Scene = 1;
    cb = [queue commandBuffer];
    pass(@"A", 0, 3, -1);
    float rewritten[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    put(R, base(0) + 32, rewritten, 8);                                         // CPU write after encoding, before commit
    id<MTLBlitCommandEncoder> b = [cb blitCommandEncoder];
    [b copyFromBuffer:S sourceOffset:0 toBuffer:R destinationOffset:base(4) + 32 size:32];
    [b endEncoding];
    pass(@"B", 4, 6, -1);
    b = [cb blitCommandEncoder];
    [b fillBuffer:R range:NSMakeRange(base(7) + 32, 32) value:0x3c];
    [b endEncoding];
    pass(@"C", 7, 8, -1);
    pass(@"D", 9, 10, 9);
    pass(@"E", 11, 12, -1);
    memcpy(shadow, R.contents, R.length);                                       // the CPU's bytes at commit
    memcpy((uint8_t *)shadow + base(4) + 32, S.contents, 32);                   // the blit, before pass B
    memset((uint8_t *)shadow + base(7) + 32, 0x3c, 32);                         // the fill, before pass C
    const char *names = "AAAABBBCCDDEE";
    for (int k = 0; k <= 12; k++) expect(k, [NSString stringWithFormat:@"%c", names[k]]);
    [cb commit];
    [cb waitUntilCompleted];

    Scene = 2;
    cb = [queue commandBuffer];
    pass(@"F", 13, 14, -1);
    memcpy(shadow, R.contents, R.length);
    for (int k = 13; k <= 14; k++) expect(k, @"F");
    [cb commit];
    [cb waitUntilCompleted];

    NSDictionary *report = @{@"commits":Commits, @"expected":expected, @"scenes":@[@{@"scene":@"ubo-mirror"}],
                             @"environment_off":@(getenv("ADRENO_GPU_PERF_OFF") ?: "")};
    NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    [json writeToFile:[Out stringByAppendingPathComponent:@"report.json"] atomically:YES];
    printf("ubo-mirror: %lu commits, %lu draws expected -> %s\n", (unsigned long)Commits.count, (unsigned long)expected.count, Out.UTF8String);
    return 0;
} }
