/* SPDX-License-Identifier: MIT */
// regtest.m - host (M3 Max, 26A428) conformance harness for AdrenoMetal.bundle's registration contract.
//
// It reproduces Metal's own plug-in load path step by step, then calls the exported MTLAddDevice(), so the
// real -initLimits / -initFeatureQueries / -initWorkarounds run on our class. The only host substitution:
// the io_service_t is this Mac's AGX IOAccelerator (the guest will pass our AdrenoGPU kext's service).
//
//   regtest <bundle>                 full run with the bundle's built-in featureProfile
//   regtest <bundle> --sweep A B     spawn one child per featureProfile in [A,B], report accept/crash
//   regtest <bundle> --one N         (child) register with featureProfile N and print the derived limits
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurface.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <spawn.h>
#import <sys/wait.h>
#import "ws_selectors.h"
extern char **environ;
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (AdrenoHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (unsigned long long)featureProfile;
- (id)compiler;
@end

static int fails;
static void coverage(Class c, const char *outPath);
#define CHECK(c, ...) do { if (c) printf("  PASS "); else { printf("  FAIL "); fails++; } printf(__VA_ARGS__); printf("\n"); } while (0)

static Class loadPluginClass(NSString *path) {
    // == getMetalPluginClassForService (Metal 0x18b840688) after gpu_bundle_find_trusted resolved the path
    NSBundle *b = [NSBundle bundleWithPath:path];
    NSError *e = nil;
    if (![b loadAndReturnError:&e]) { printf("bundle load failed: %s\n", e.description.UTF8String); return nil; }
    Class c = [b classNamed:@"AdrenoMTLDevice"] ?: [b principalClass];
    return [c isSubclassOfClass:NSClassFromString(@"_MTLDevice")] ? c : nil;
}
static io_service_t hostAccelerator(void) {
    return IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
}
static const char *owner(Class c, SEL s) {
    Method m = class_getInstanceMethod(c, s);
    if (!m) return "(none)";
    for (Class k = c; k; k = class_getSuperclass(k)) {
        unsigned n; Method *ml = class_copyMethodList(k, &n);
        for (unsigned i = 0; i < n; i++) if (ml[i] == m) { free(ml); return class_getName(k); }
        free(ml);
    }
    return "?";
}

static void printLimits(id<MTLDevice> d) {
    printf("  name=%s featureProfile=%llu argbuf=%lu\n", d.name.UTF8String, [(id)d featureProfile], (unsigned long)d.argumentBuffersSupport);
    printf("  maxTex1D=%lu maxTex2D=%lu maxTex3D=%lu maxColorAtt=%lu maxVtxBuf=%lu maxVtxAttr=%lu\n",
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxTextureWidth1D")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxTextureWidth2D")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxTextureWidth3D")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxColorAttachments")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxVertexBuffers")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxVertexAttributes")));
    printf("  fragTex=%lu fragSamp=%lu fragBuf=%lu vtxTex=%lu vtxSamp=%lu minConstAlign=%lu maxThreadgroupMem=%lu\n",
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxFragmentTextures")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxFragmentSamplers")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxFragmentBuffers")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxVertexTextures")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("maxVertexSamplers")),
        ((NSUInteger(*)(id,SEL))objc_msgSend)(d, sel_registerName("minConstantBufferAlignmentBytes")),
        (unsigned long)d.maxThreadgroupMemoryLength);
    printf("  families:");
    long fams[] = {1001,1002,1003,1004,1005,1006,1007,1008,1009,1010, 2002, 3001,3002,3003, 4001, 5001};
    for (unsigned i = 0; i < sizeof fams / sizeof *fams; i++) if ([d supportsFamily:fams[i]]) printf(" %ld", fams[i]);
    printf("\n");
}

static id<MTLDevice> registerDevice(NSString *bundle) {
    (void)MTLCopyAllDevices();                          // Metal/IOGPU up, _deviceArray exists
    Class c = loadPluginClass(bundle);
    if (!c) { printf("  FAIL plug-in class\n"); fails++; return nil; }
    id<MTLDevice> d = [[c alloc] initWithAcceleratorPort:hostAccelerator()];
    if (!d) { printf("  FAIL initWithAcceleratorPort\n"); fails++; return nil; }
    MTLAddDevice(d);                                    // initLimits / initFeatureQueries / initWorkarounds
    return d;
}

static void fullRun(NSString *bundle) {
    printf("[1] load path\n");
    (void)MTLCopyAllDevices();
    Class c = loadPluginClass(bundle);
    CHECK(c != nil, "bundle principal/named class is an _MTLDevice subclass: %s", c ? class_getName(c) : "nil");
    if (!c) return;
    for (Class k = c; k; k = class_getSuperclass(k)) printf("    %s\n", class_getName(k));
    CHECK(class_conformsToProtocol(c, objc_getProtocol("MTLDeviceSPI")), "conforms to MTLDeviceSPI (MTLAddDevice asserts this)");
    CHECK(class_getInstanceMethod(c, sel_registerName("_setAcceleratorService:")) != NULL,
          "answers _setAcceleratorService: (sent by -[MTLIOAccelService initWithAcceleratorPort:deviceClass:]) via %s",
          owner(c, sel_registerName("_setAcceleratorService:")));

    printf("[2] init + MTLAddDevice\n");
    id<MTLDevice> d = registerDevice(bundle);
    if (!d) return;
    NSArray *all = MTLCopyAllDevices();
    CHECK([all containsObject:d], "device listed by MTLCopyAllDevices (count %lu) - this is what ___WSSystemCanCompositeWithMetal counts", (unsigned long)all.count);
    printLimits(d);
    coverage(object_getClass(d), getenv("ADRENO_COVERAGE_OUT") ?: "/dev/null");
    printf("    compiler=%s\n", [(id)d compiler] ? class_getName([[(id)d compiler] class]) : "nil");

    printf("[3] selectors WindowServer reads at startup (impl owner)\n");
    const char *sels[] = {"name","registryID","isLowPower","isHeadless","isRemovable","location","maxBufferLength",
        "recommendedMaxWorkingSetSize","peerGroupID","acceleratorPort","vendorName","familyName","productName",
        "featureProfile","supportsFamily:","newCommandQueue","newCommandQueueWithMaxCommandBufferCount:",
        "newBufferWithLength:options:","newTextureWithDescriptor:iosurface:plane:","newSamplerStateWithDescriptor:",
        "newRenderPipelineStateWithDescriptor:error:","newLibraryWithURL:error:","newSharedEvent",
        "targetDeviceArchitecture","llvmVersion","compiler"};
    for (unsigned i = 0; i < sizeof sels / sizeof *sels; i++)
        printf("    %-46s %s\n", sels[i], owner(object_getClass(d), sel_registerName(sels[i])));

    unsigned wsMissing = 0;
    for (unsigned i = 0; i < sizeof kWSSends / sizeof *kWSSends; i++) {
        Class k = NSClassFromString(@(kWSSends[i][0]));
        if (!k || !class_getInstanceMethod(k, sel_registerName(kWSSends[i][1]))) { wsMissing++; printf("    unanswered: %s %s\n", kWSSends[i][0], kWSSends[i][1]); }
    }
    CHECK(wsMissing == 0, "all %lu (class, selector) pairs WindowServer's stack sends are answered (%u missing)",
          sizeof kWSSends / sizeof *kWSSends, wsMissing);

    printf("[4] objects (null executor)\n");
    id<MTLCommandQueue> q = [d newCommandQueue];
    CHECK(q != nil, "newCommandQueue -> %s", q ? class_getName([(id)q class]) : "nil");
    id<MTLCommandBuffer> cb = [q commandBuffer];
    CHECK(cb != nil, "commandBuffer -> %s", cb ? class_getName([(id)cb class]) : "nil");
    [cb commit]; [cb waitUntilCompleted];
    CHECK(cb.status == MTLCommandBufferStatusCompleted, "empty commit completes (status %ld err %s)", (long)cb.status, cb.error.description.UTF8String ?: "-");

    id<MTLBuffer> b = [d newBufferWithLength:65536 options:MTLResourceStorageModeShared];
    CHECK(b && b.contents && b.length == 65536, "newBufferWithLength:65536 -> %s contents %p", b ? class_getName([(id)b class]) : "nil", b.contents);
    uint32_t pat[64]; for (int i = 0; i < 64; i++) pat[i] = 0xA0000000u | i;
    id<MTLBuffer> b2 = [d newBufferWithBytes:pat length:sizeof pat options:0];
    CHECK(b2 && !memcmp(b2.contents, pat, sizeof pat), "newBufferWithBytes copies data");

    struct { MTLPixelFormat f; uint32_t fourcc; int bpe; const char *n; } fmts[] = {
        {MTLPixelFormatBGRA8Unorm, 'BGRA', 4, "BGRA8"}, {MTLPixelFormatR8Unorm, 'L008', 1, "R8"},
        {MTLPixelFormatBGR10A2Unorm, 'l10r', 4, "BGR10A2"}, {MTLPixelFormatRGBA16Float, 'RGhA', 8, "RGBA16F"},
        {MTLPixelFormatRGBA16Unorm, 'l64r', 8, "RGBA16Unorm"}, {MTLPixelFormatRGBA32Float, 'RGfA', 16, "RGBA32F"},
        {MTLPixelFormatBGR10_XR, 'w30r', 4, "BGR10_XR"}, {MTLPixelFormatBGRA10_XR, 'w40a', 8, "BGRA10_XR"}};
    for (unsigned i = 0; i < sizeof fmts / sizeof *fmts; i++) {
        IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth: @640, (id)kIOSurfaceHeight: @480,
            (id)kIOSurfaceBytesPerElement: @(fmts[i].bpe), (id)kIOSurfacePixelFormat: @(fmts[i].fourcc)});
        MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:fmts[i].f width:640 height:480 mipmapped:NO];
        td.usage = MTLTextureUsageShaderRead | MTLTextureUsageRenderTarget; td.storageMode = MTLStorageModeShared;
        id<MTLTexture> t = s ? [d newTextureWithDescriptor:td iosurface:s plane:0] : nil;
        CHECK(t != nil, "IOSurface texture %-11s -> %s", fmts[i].n, t ? class_getName([(id)t class]) : "nil (WindowServer would abort)");
        if (s) CFRelease(s);
    }
    MTLTextureDescriptor *pd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:256 height:256 mipmapped:NO];
    pd.storageMode = MTLStorageModePrivate; pd.usage = MTLTextureUsageShaderRead | MTLTextureUsageRenderTarget;
    id<MTLTexture> pt = [d newTextureWithDescriptor:pd];
    CHECK(pt != nil, "private texture 256x256 -> %s", pt ? class_getName([(id)pt class]) : "nil");

    int samplersOK = 0;
    for (int i = 0; i < 5; i++) {
        MTLSamplerDescriptor *sd = [MTLSamplerDescriptor new];
        sd.minFilter = sd.magFilter = i ? MTLSamplerMinMagFilterLinear : MTLSamplerMinMagFilterNearest;
        if (i == 4) { sd.maxAnisotropy = 8; sd.mipFilter = MTLSamplerMipFilterLinear; }
        samplersOK += [d newSamplerStateWithDescriptor:sd] != nil;
    }
    CHECK(samplersOK == 5, "5 new_compositor-style sampler states (one maxAnisotropy 8): %d non-nil", samplersOK);
    @try {
        id<MTLSharedEvent> ev = [d newSharedEvent];
        CHECK(ev != nil, "newSharedEvent -> %s", ev ? class_getName([(id)ev class]) : "nil");
        id<MTLFence> fe = [d newFence];
        CHECK(fe != nil, "newFence -> %s", fe ? class_getName([(id)fe class]) : "nil");
    } @catch (NSException *x) { CHECK(0, "event/fence threw %s", x.reason.UTF8String); }
    MTLDepthStencilDescriptor *dsd = [MTLDepthStencilDescriptor new];
    CHECK([d newDepthStencilStateWithDescriptor:dsd] != nil, "depth-stencil state");

    if (pt) {
        id<MTLCommandBuffer> cb2 = [q commandBuffer];
        MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
        rp.colorAttachments[0].texture = pt; rp.colorAttachments[0].loadAction = MTLLoadActionClear;
        rp.colorAttachments[0].storeAction = MTLStoreActionStore;
        id<MTLRenderCommandEncoder> re = [cb2 renderCommandEncoderWithDescriptor:rp];
        CHECK(re != nil, "renderCommandEncoderWithDescriptor -> %s", re ? class_getName([(id)re class]) : "nil");
        [re setViewport:(MTLViewport){0, 0, 256, 256, 0, 1}];
        [re drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        [re endEncoding];
        id<MTLBlitCommandEncoder> be = [cb2 blitCommandEncoder];
        [be copyFromBuffer:b2 sourceOffset:0 toBuffer:b destinationOffset:0 size:sizeof pat];
        [be endEncoding];
        [cb2 commit]; [cb2 waitUntilCompleted];
        CHECK(cb2.status == MTLCommandBufferStatusCompleted, "render+blit command buffer completes (status %ld err %s)", (long)cb2.status, cb2.error.description.UTF8String ?: "-");
    }

    printf("[5] libraries / compiler\n");
    NSURL *u = [NSURL fileURLWithPath:@"/System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib"];
    NSError *le = nil;
    id<MTLLibrary> lib = [d newLibraryWithURL:u error:&le];
    CHECK(lib != nil, "newLibraryWithURL QuartzCore default.metallib (fat: AIR + 20 AGX slices) -> %lu functions %s",
          (unsigned long)lib.functionNames.count, le ? le.localizedDescription.UTF8String : "");

    printf("[6] pipeline through MTLCompilerService (pluginPath %s)\n", getenv("ADRENO_COMPILER_PLUGIN") ?: "simulatorDummyPlugin");
    NSString *src = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "struct V { float4 p [[position]]; float2 uv; };\n"
        "vertex V vs(uint i [[vertex_id]], constant float4 *pos [[buffer(0)]]) { V o; o.p = pos[i]; o.uv = pos[i].xy; return o; }\n"
        "fragment float4 fs(V in [[stage_in]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) { return t.sample(s, in.uv); }\n";
    NSError *ce = nil;
    id<MTLLibrary> sl = [d newLibraryWithSource:src options:nil error:&ce];
    CHECK(sl != nil, "newLibraryWithSource (front end in MTLCompilerService) %s", ce ? ce.localizedDescription.UTF8String : "");
    if (sl) {
        MTLRenderPipelineDescriptor *pd2 = [MTLRenderPipelineDescriptor new];
        pd2.vertexFunction = [sl newFunctionWithName:@"vs"]; pd2.fragmentFunction = [sl newFunctionWithName:@"fs"];
        pd2.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        NSError *pe = nil;
        id<MTLRenderPipelineState> ps = [d newRenderPipelineStateWithDescriptor:pd2 error:&pe];
        CHECK(ps != nil, "newRenderPipelineStateWithDescriptor -> %s %s", ps ? class_getName([(id)ps class]) : "nil", pe ? pe.localizedDescription.UTF8String : "");
        if (ps) {
            for (NSString *k in @[@"vertex", @"fragment"]) {
                id v = [(id)ps valueForKey:k]; id o = [v valueForKey:@"compilerOutput"];
                const void *bytes = NULL; size_t len = 0; NSData *nd = nil;
                if ([o isKindOfClass:[NSData class]]) nd = o;
                else if (o) { dispatch_data_t dd = dispatch_data_create_map(o, &bytes, &len); (void)dd; nd = [NSData dataWithBytes:bytes length:len]; }
                const uint8_t *b8 = nd.bytes;
                printf("    %s variant: output class %s, %lu bytes, head %02x%02x%02x%02x %02x%02x%02x%02x\n", k.UTF8String,
                       o ? class_getName([o class]) : "nil", (unsigned long)nd.length,
                       nd.length > 7 ? b8[0] : 0, nd.length > 7 ? b8[1] : 0, nd.length > 7 ? b8[2] : 0, nd.length > 7 ? b8[3] : 0,
                       nd.length > 7 ? b8[4] : 0, nd.length > 7 ? b8[5] : 0, nd.length > 7 ? b8[6] : 0, nd.length > 7 ? b8[7] : 0);
                const char *dump = getenv("ADRENO_DUMP_VARIANTS");
                if (dump && nd) [nd writeToFile:[NSString stringWithFormat:@"%s/%@.bin", dump, k] atomically:NO];
            }
        }
    }
}

// Every required+optional instance method of Metal's own MTLDevice/MTLDeviceSPI protocol objects that the
// class does not answer (these raise "unrecognized selector" if anything sends them).
static void coverage(Class c, const char *outPath) {
    FILE *f = fopen(outPath, "w");
    const char *protos[] = {"MTLDevice", "MTLDeviceSPI"};
    unsigned missing = 0, total = 0;
    for (int p = 0; p < 2; p++) {
        Protocol *pr = objc_getProtocol(protos[p]);
        for (int req = 1; req >= 0; req--) {
            unsigned n; struct objc_method_description *m = protocol_copyMethodDescriptionList(pr, req, YES, &n);
            for (unsigned i = 0; i < n; i++) {
                total++;
                if (!class_getInstanceMethod(c, m[i].name)) { missing++; if (f) fprintf(f, "%s %s %s\n", protos[p], req ? "required" : "optional", sel_getName(m[i].name)); }
            }
            free(m);
        }
    }
    if (f) fclose(f);
    printf("    protocol coverage: %u of %u MTLDevice/MTLDeviceSPI selectors unanswered (list: %s)\n", missing, total, outPath);
}

static int sweep(const char *self_, const char *bundle, int a, int b) {
    for (int fp = a; fp <= b; fp++) {
        char n[16]; snprintf(n, sizeof n, "%d", fp);
        char *argv[] = {(char *)self_, (char *)bundle, "--one", n, NULL};
        pid_t pid; int st = 0;
        fflush(stdout);
        if (posix_spawn(&pid, self_, NULL, NULL, argv, environ)) { perror("spawn"); return 1; }
        waitpid(pid, &st, 0);
        if (WIFSIGNALED(st)) printf("featureProfile %2d: REJECTED (signal %d - initLimits/initFeatureQueries assertion)\n", fp, WTERMSIG(st));
        else printf("featureProfile %2d: exit %d\n", fp, WEXITSTATUS(st));
    }
    return 0;
}

int main(int argc, char **argv) { @autoreleasepool {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: regtest <AdrenoMetal.bundle> [--sweep A B | --one N]\n"); return 2; }
    NSString *bundle = @(argv[1]);
    if (argc >= 5 && !strcmp(argv[2], "--sweep")) return sweep(argv[0], argv[1], atoi(argv[3]), atoi(argv[4]));
    if (argc >= 4 && !strcmp(argv[2], "--one")) {
        setenv("ADRENO_FEATURE_PROFILE", argv[3], 1);
        id<MTLDevice> d = registerDevice(bundle);
        if (!d) return 3;
        printf("featureProfile %s: ACCEPTED\n", argv[3]);
        printLimits(d);
        // What Metal itself derives from this profile (bypassing our overrides): base-class IMPs + raw _limits.
        Class base = NSClassFromString(@"_MTLDevice");
        BOOL (*fam)(id, SEL, long) = (void *)class_getMethodImplementation(base, @selector(supportsFamily:));
        printf("  _MTLDevice families:");
        long fams[] = {1001,1002,1003,1004,1005,1006,1007,1008,1009,1010, 2002, 3001,3002,3003, 4001, 5001, 5002};
        for (unsigned i = 0; i < sizeof fams / sizeof *fams; i++) if (fam(d, @selector(supportsFamily:), fams[i])) printf(" %ld", fams[i]);
        const uint32_t *L = ((const uint32_t *(*)(id, SEL))objc_msgSend)(d, sel_registerName("limits"));
        printf("\n  _limits u32[0..63]:");
        for (int i = 0; i < 64; i++) printf("%s%u", i % 16 ? " " : "\n    ", L[i]);
        printf("\n");
        return 0;
    }
    fullRun(bundle);
    printf("RESULT: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}}
