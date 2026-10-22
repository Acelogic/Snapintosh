/* SPDX-License-Identifier: MIT */
// AdrenoMTLDevice.m - minimal third-party Metal device for the Adreno X2-90 (Snapintosh).
//
// Load path (Metal, 26A428):
//   MTLRegisterDevices -> MTLIOAccelServiceGlobalContext (IOServiceMatching("IOAccelerator"))
//   -> getMetalPluginClassForService(svc)                       Metal 0x18b840688
//        name  = IORegistry "MetalPluginName"  (CFString)       e.g. "AdrenoMetal"
//        path  = gpu_bundle_find_trusted(name)                  libsystem_sandbox 0x18cbc11dc
//                tries "/Library/GPUBundles/%s.bundle", "/System/Library/Extensions/%s.bundle"
//                (then "/AppleInternal/Library/Extensions" only on internal builds)
//        cls   = [[NSBundle bundleWithPath:path] classNamed: IORegistry "MetalPluginClassName"]
//                ?: [bundle principalClass]
//        require [cls isSubclassOfClass:_MTLDevice]
//   -> -[MTLIOAccelService initWithAcceleratorPort:deviceClass:]  Metal 0x18b841188
//        dev = [[cls alloc] initWithAcceleratorPort:svc]; [dev _setAcceleratorService:]; MTLAddDevice(dev)
//   -> MTLAddDevice (Metal 0x18b67a5ec): assert conformsToProtocol MTLDevice + MTLDeviceSPI,
//        [dev initLimits] [dev initFeatureQueries] [dev initWorkarounds], append to _deviceArray.
//
// -initLimits (Metal 0x18b67a8fc) derives every limit from -featureProfile and asserts
// (MTLReleaseAssertionFailure -> brk) when the derived sums at +0x28/+0xcc/+0xd0/+0xd4/+0xd8 are 0, or when
// -argumentBuffersSupport is neither 0 (Tier1) nor 1 (Tier2). Values accepted: see ../out/profile-sweep.txt.
#import "AdrenoMetalSPI.h"
#import "AdrenoMTLObjects.h"
#import "AdrenoMTLDevice.h"
#import "AdrenoEarlyStop.h"
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <os/log.h>
#import <dlfcn.h>

// featureProfile: 0..13 are Apple GPU family ordinals (10 = Apple9). 10000..10002 are the Mac-family (non-Apple GPU)
// profiles: 10000 = Common1/2, 10001 = Mac2 + Common1-3, 10002 = 10001 + Metal3 (host sweep, plugin-abi-review).
// 10001 makes _MTLDevice's own family view equal to our supportsFamily: override, so Metal-internal checks and
// external callers agree; the full host harness passes with it. Overridable for experiments.
#ifndef ADRENO_FEATURE_PROFILE
#define ADRENO_FEATURE_PROFILE 10001ull
#endif

static os_log_t adreno_log(void) {
    static os_log_t l; static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("org.snapintosh.adreno", "metal"); });
    return l;
}

// CoreAnimation's generic pipeline (docs/USERSPACE-GRAPHICS-20261019.md, "Why rounded rects, blur and backdrop render
// black"). While a blended specialised pipeline compiles, CoreAnimation draws with its generic pipeline, which blends in
// the shader through framebuffer fetch. On a device without it that pipeline is built with blending off and every such
// draw overwrites the destination with unblended premultiplied colour: black corners, blur and backdrop (the M3 Max does
// the same when it answers that way). This device now answers fetch YES, so this runs only for a profile that answers
// NO. CoreAnimation's CA_DISABLE_GENERIC_SHADERS option makes it wait for the specialised pipeline instead. An explicit
// setting of either generic-shader switch is left alone. Refusing the generic pipeline instead aborts CoreAnimation.
//
// AdrenoSetCAOption turns one of CoreAnimation's boolean debug options on. It sets it in the environment (QuartzCore
// reads its options once, at first use) and, because QuartzCore may already have read them, as the live option:
// CASetDebugOption with the index of that name, found with CAGetDebugOptionEnvVariableName (QuartzCore SPI, exported;
// looked up only if QuartzCore is already loaded). The live option is set from a global queue: device creation can run
// inside CoreAnimation's own calls. An explicit environment setting of the option, or of `opposite`, is left alone.
static void AdrenoSetCAOption(const char *option, const char *opposite, const char *what) {
    if (getenv(option) || (opposite && getenv(opposite))) {
        os_log(adreno_log(), "CoreAnimation %{public}s: explicit setting kept", what);
        return;
    }
    setenv(option, "1", 0);
    const char *(*optionName)(int) = (const char *(*)(int))dlsym(RTLD_DEFAULT, "CAGetDebugOptionEnvVariableName");
    void (*setOption)(int, bool) = (void (*)(int, bool))dlsym(RTLD_DEFAULT, "CASetDebugOption");
    if (!optionName || !setOption) {
        os_log(adreno_log(), "CoreAnimation %{public}s: disabled through the environment (QuartzCore not loaded)", what);
        return;
    }
    for (int i = 0; i < 4096; i++) {
        const char *name = optionName(i);
        if (!name) break;
        if (strcmp(name, option)) continue;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{ setOption(i, true); });
        os_log(adreno_log(), "CoreAnimation %{public}s: disabled (option %d)", what, i);
        return;
    }
    os_log_error(adreno_log(), "CoreAnimation %{public}s: no %{public}s option in this QuartzCore", what, option);
}
static void AdrenoDisableCAGenericShaders(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ AdrenoSetCAOption("CA_DISABLE_GENERIC_SHADERS", "CA_FORCE_GENERIC_SHADERS", "generic shaders"); });
}
// CoreAnimation's average-pixel-luminance limiter (filter limitAveragePixelLuminance, docs/WINDOWSERVER-APL-ABORT-20261020.md).
// It runs two compute kernels, compute_apl and sum_apl_and_compute_dimming_factor, then scales the filtered pixels by
// the factor they write. The compute builder cannot run those kernels yet (dynamic threadgroup memory, device buffers
// and a texture read in a kernel; BINDING-ABI 3.8), so it omits their dispatches and the factor stays 0: black output
// (measured on this Mac). With CA_DISABLE_APL_FILTER CoreAnimation runs no compute and binds factor 1. Remove this
// once the compute builder runs both kernels on the A16.
static void AdrenoDisableCAAPLFilter(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ AdrenoSetCAOption("CA_DISABLE_APL_FILTER", NULL, "APL filter"); });
}

@implementation AdrenoMTLDevice {
    MTLCompiler *_compiler;
    unsigned long long _featureProfile;
    BOOL _adrenoBufferCopyAvailable;
}

- (instancetype)initWithAcceleratorPort:(io_service_t)port {
    // Decide the profile before super-init: IOGPUMetalDevice init does not call featureProfile, but
    // everything after MTLAddDevice does.
    _featureProfile = ADRENO_FEATURE_PROFILE;
    const char *e = getenv("ADRENO_FEATURE_PROFILE");     // host experiments only
    if (e) _featureProfile = strtoull(e, NULL, 0);

    self = [super initWithAcceleratorPort:port];          // IOGPUDeviceCreateWithOptions + shmem pools
    if (!self) { os_log_error(adreno_log(), "IOGPUMetalDevice init failed for port 0x%x", port); return nil; }
    [AdrenoEarlyStop bindAccelerator:port];               // inert unless this launch opted into early stop
    if (![self setupSegmentByteThreshold]) return nil;
    CFTypeRef copyABI = IORegistryEntryCreateCFProperty(port, CFSTR("AdrenoIBCopyABI"), kCFAllocatorDefault, 0);
    long long copyVersion = 0;
    if (copyABI && CFGetTypeID(copyABI) == CFNumberGetTypeID())
        CFNumberGetValue((CFNumberRef)copyABI, kCFNumberLongLongType, &copyVersion);
    if (copyABI) CFRelease(copyABI);
    _adrenoBufferCopyAvailable = copyVersion == 1;
    [self setupCompiler];                                 // failure is not fatal for the stage-2 gate
    if (![self isFramebufferReadSupported]) AdrenoDisableCAGenericShaders();
    AdrenoDisableCAAPLFilter();
    os_log(adreno_log(), "AdrenoMTLDevice up: port 0x%x featureProfile %llu", port, _featureProfile);
    return self;
}

- (BOOL)adrenoBufferCopyAvailable { return _adrenoBufferCopyAvailable; }

// IOGPU's device initializer (26A428 IOGPU 0x1a7f71f90) stores 0 in _segmentByteThreshold. Command-buffer
// storage passes it to IOGPUResourceListInit as the per-segment resource byte budget, and
// _ioGPUResourceListAddResourceEntry returns UINT32_MAX once a resource's KiB-rounded size exceeds it, so a
// zero budget refuses the first resource (generation46: "Adreno segment resource threshold exceeded").
// Apple's paravirtual plug-in sets it to sysctl hw.memsize right after super-init (AppleParavirtGPUMetal
// IOGPUFamily arm64e 0x1d18c-0x1d1c4); do the same.
- (BOOL)setupSegmentByteThreshold {
    Ivar ivar = class_getInstanceVariable([IOGPUMetalDevice class], "_segmentByteThreshold");
    const char *type = ivar ? ivar_getTypeEncoding(ivar) : NULL;
    ptrdiff_t offset = ivar ? ivar_getOffset(ivar) : 0;
    uint64_t memsize = 0;
    size_t length = sizeof memsize;
    if (!type || strcmp(type, "Q") || offset <= 0 ||
        (size_t)offset + sizeof memsize > class_getInstanceSize([IOGPUMetalDevice class]) ||
        sysctlbyname("hw.memsize", &memsize, &length, NULL, 0) || length != sizeof memsize || !memsize) {
        os_log_error(adreno_log(), "cannot set IOGPU segment byte threshold (ivar type %{public}s)", type ?: "missing");
        return NO;
    }
    *(uint64_t *)((char *)(__bridge void *)self + offset) = memsize;
    return YES;
}

// ---------- registration contract (what MTLAddDevice / initLimits read) ----------
- (unsigned long long)featureProfile { return _featureProfile; }
- (MTLArgumentBuffersTier)argumentBuffersSupport { return MTLArgumentBuffersTier1; } // must be 0 or 1

// ---------- identity (SkyLight/QuartzCore/CoreDisplay read these; ws-essential-metal.txt) ----------
- (NSString *)name { return @"Adreno X2-90"; }
- (NSString *)vendorName { return @"Qualcomm"; }     // must not contain "intel" (QuartzCore Intel paths)
- (NSString *)familyName { return @"Adreno"; }
- (NSString *)productName { return @"Adreno X2-90"; }

// No Apple GPU families, no tile shaders / imageblocks / raster order groups / SIMD-group ops in v1.
- (BOOL)supportsFamily:(MTLGPUFamily)f {
    switch (f) {
        case MTLGPUFamilyCommon1: case MTLGPUFamilyCommon2: case MTLGPUFamilyCommon3:
        case MTLGPUFamilyMac2:
            return YES;
        default:
            return NO;
    }
}
- (BOOL)supportsTileShaders { return NO; }
- (BOOL)supportsImageBlocks { return NO; }
- (BOOL)areRasterOrderGroupsSupported { return NO; }
- (BOOL)supportsRasterOrderGroups { return NO; }
- (BOOL)supportsSIMDGroup { return NO; }
- (BOOL)supportsSIMDReduction { return NO; }
- (BOOL)supportsSIMDShuffleAndFill { return NO; }
// Framebuffer fetch YES: CoreAnimation 26A428 restores the backdrop outside a clipping layer's rounded corners (Tbds,
// every window) by reading the destination, and on a device without fetch it still takes that path and writes the
// corner triangles 00000000 (docs/USERSPACE-GRAPHICS-20261019.md, "Window corner wedges"). Reads of [[color(n)]] are
// rewritten to T#s of the attachments with SINGLE_PRIM_MODE ordering and the feedback barrier (AdrenoDrawCommands.m).
// With fetch YES the generic pipeline blends in the shader, so AdrenoDisableCAGenericShaders no longer runs.
- (BOOL)isFramebufferReadSupported { return YES; }
- (BOOL)supportsMemorylessRenderTargets { return NO; }   // no tile memory (never memoryless YES with fetch NO)
- (BOOL)supportsNativeHardwareFP16 { return NO; }       // plan m5: match the validated minimum profile
- (BOOL)supportsBinaryArchives { return NO; }            // QuartzCore tolerates nil newBinaryArchiveWithDescriptor:
- (BOOL)supportsDynamicLibraries { return NO; }
- (BOOL)supportsFunctionPointers { return NO; }
- (BOOL)supportsRaytracing { return NO; }
- (NSUInteger)maxFragmentTextures { return 16; }         // plan: 16/16 matches Adreno + WS usage
- (NSUInteger)maxFragmentSamplers { return 16; }
- (NSUInteger)maxTextureLayers { return 2048; }
- (NSUInteger)linearTextureAlignmentBytes { return 64; } // Adreno linear pitch alignment (A6xx+: 64 B)
// Not answered on purpose: iosurfaceTextureAlignmentBytes / iosurfaceReadOnlyTextureAlignmentBytes /
// deviceLinear*AlignmentBytes = 64 sent CoreImage's blur into MPSImageGaussianBlur with a nil source (assertion abort
// in the client, ci-compute harness 2026-10-19). Unaligned IOSurface rows need GPU shadows instead
// (docs/USERSPACE-GRAPHICS-20261019.md).
// Not implemented by _MTLDevice/IOGPUMetalDevice (unrecognized selector otherwise); PV implements them too.
- (NSUInteger)maxThreadgroupMemoryLength { return 32768; }
- (MTLSize)maxThreadsPerThreadgroup { return MTLSizeMake(1024, 1024, 1024); }
- (NSUInteger)maxTotalComputeThreadsPerThreadgroup { return 1024; }

// ---------- MTLDevice/MTLDeviceSPI *required* selectors that neither base class answers (runtime coverage,
// ../out/unanswered-selectors.txt). Metal itself sends some of these, e.g. supportsSampleCount: from
// -[MTLRenderPipelineDescriptorInternal validateWithDevice:error:] on every pipeline creation. ----------
- (BOOL)supportsSampleCount:(NSUInteger)n { return n == 1 || n == 2 || n == 4; }   // PV: mask 0x10116 & device info
- (unsigned long long)halfFPConfig { return 0xe; }     // same bits AGX reports on 26A428
- (unsigned long long)singleFPConfig { return 0x54; }
- (unsigned long long)doubleFPConfig { return 0; }     // no fp64
- (BOOL)metalAssertionsEnabled { return NO; }           // PV returns 0
- (void)setMetalAssertionsEnabled:(BOOL)e {}
- (BOOL)isDepth24Stencil8PixelFormatSupported { return NO; }   // v1: D32F/S8 only, like AGX
- (NSUInteger)minimumTextureBufferAlignmentForPixelFormat:(MTLPixelFormat)f { return 64; }
// Linear textures over buffers and IOSurfaces use 64-byte pitches and offsets (kAdrenoPitchAlign in AdrenoResources.m);
// v80: CoreImage sized its RGBA16F intermediates from the base class's answer (140 px -> 1,120-byte rows), which no
// linear layout admits (docs/USERSPACE-GRAPHICS-20261019.md).
- (NSUInteger)minimumLinearTextureAlignmentForPixelFormat:(MTLPixelFormat)f { return 64; }
- (MTLSizeAndAlign)heapBufferSizeAndAlignWithLength:(NSUInteger)len options:(MTLResourceOptions)o {
    return (MTLSizeAndAlign){(len + 16383) & ~(NSUInteger)16383, 16384};
}
- (MTLSizeAndAlign)heapTextureSizeAndAlignWithDescriptor:(MTLTextureDescriptor *)d {
    NSUInteger rb = (d.width * 16 + 63) & ~(NSUInteger)63;          // worst-case 16 B/px, linear
    NSUInteger sz = rb * d.height * MAX(d.depth, 1) * MAX(d.arrayLength, 1) * 2;
    return (MTLSizeAndAlign){(sz + 16383) & ~(NSUInteger)16383, 16384};
}
- (MTLSize)sparseTileSizeWithTextureType:(MTLTextureType)t pixelFormat:(MTLPixelFormat)f sampleCount:(NSUInteger)n {
    return MTLSizeMake(0, 0, 0);                        // no sparse textures
}
- (MTLSize)sparseTileSizeWithTextureType:(MTLTextureType)t pixelFormat:(MTLPixelFormat)f sampleCount:(NSUInteger)n
                          sparsePageSize:(MTLSparsePageSize)p { return MTLSizeMake(0, 0, 0); }
- (id)newIndirectCommandBufferWithDescriptor:(id)d maxCount:(NSUInteger)n options:(MTLResourceOptions)o { return nil; }
- (id)newIndirectComputeCommandEncoderWithBuffer:(id)b { return nil; }
- (id)newIndirectRenderCommandEncoderWithBuffer:(id)b { return nil; }
- (id)newVisibleFunctionTableWithDescriptor:(id)d { return nil; }

// ---------- shader compiler hook ----------
// Two options, both keep third-party code OUT of MTLCompilerService:
//  (a) pluginPath = "simulatorDummyPlugin": MTLCompilerPluginInterface::init (MTLCompiler 0x1b3b73518)
//      skips dlopen; the service hands back AIR, and -new{Vertex,Fragment,Compute}VariantWithCompilerOutput:
//      below receive it; air2ir3 then runs in-process (in WindowServer, which already loads us).
//  (b) our own lib<Vendor>CompilerPlugin.dylib in Resources: dlopen()ed by MTLCompilerService (platform,
//      library-validated) -> needs its CDHash in the trust cache as well.
- (BOOL)setupCompiler {
    unsigned long long target = 0x44070041ull;           // X2-90 runtime chip id; opaque to Metal
    dispatch_data_t td = dispatch_data_create(&target, sizeof target, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    unsigned char uuid[CC_SHA256_DIGEST_LENGTH];
    // PV hashes __DATE__ __TIME__; we hash a version string instead so builds are reproducible (the CDHash
    // goes into the guest trust cache). Metal keys its on-disk function cache with SHA-256(Metal's build
    // date and time + this UUID) (docs/SHADER-COMPILE-PATH-20260928.md). With simulatorDummyPlugin that
    // cache holds only the service's specialised AIR, which does not depend on our back end, so keep this
    // string stable: changing it discards every compile WindowServer has kept on the SSD. Back-end changes
    // are covered by AdrenoShader's own cache, which is namespaced by the air2ir3 compiler identity.
    const char *stamp = "AdrenoMetal compiler cache v0.1";
    CC_SHA256(stamp, (CC_LONG)strlen(stamp), uuid);
    NSString *plugin = @"simulatorDummyPlugin";
    const char *p = getenv("ADRENO_COMPILER_PLUGIN");     // host experiments only
    if (p) plugin = @(p);
    _compiler = [[MTLCompiler alloc] initWithTargetData:td cacheUUID:uuid pluginPath:plugin device:self compilerFlags:0x24];
    if (!_compiler) os_log_error(adreno_log(), "MTLCompiler init failed (pluginPath %{public}@)", plugin);
    return _compiler != nil;
}
- (id)compiler { return _compiler; }

// ---------- object creation: the 11 MTLDevice selectors WindowServer's stack needs that neither
// IOGPUMetalDevice nor _MTLDevice implements (adreno-must-implement.txt). Bodies live in
// AdrenoResources.m and AdrenoCommandBuffer.m; the stage-2 null executor backs them with IOGPU resources / IOSurfaces. ----------
- (id<MTLCommandQueue>)newCommandQueueWithDescriptor:(MTLCommandQueueDescriptor *)d {
    // REQUIRED: _MTLDevice's newCommandQueue / newCommandQueueWithMaxCommandBufferCount: /
    // newCommandQueueWithDescriptor: defaults call each other forever (hang.sample in macos-gpu-abi-review).
    return [[AdrenoCommandQueue alloc] initWithDevice:self descriptor:d];
}
- (id<MTLCommandQueue>)newCommandQueue {
    return [self newCommandQueueWithDescriptor:[MTLCommandQueueDescriptor new]];
}
- (id<MTLCommandQueue>)newCommandQueueWithMaxCommandBufferCount:(NSUInteger)n {
    MTLCommandQueueDescriptor *d = [MTLCommandQueueDescriptor new]; d.maxCommandBufferCount = n;
    return [self newCommandQueueWithDescriptor:d];
}
- (id<MTLBuffer>)newBufferWithLength:(NSUInteger)len options:(MTLResourceOptions)o {
    return AdrenoNewBuffer(self, NULL, len, o, nil);
}
- (id<MTLBuffer>)newBufferWithBytes:(const void *)b length:(NSUInteger)len options:(MTLResourceOptions)o {
    id<MTLBuffer> buf = AdrenoNewBuffer(self, NULL, len, o, nil);
    if (buf && b && buf.contents) memcpy(buf.contents, b, len);
    return buf;
}
- (id<MTLBuffer>)newBufferWithBytesNoCopy:(void *)b length:(NSUInteger)len options:(MTLResourceOptions)o
                              deallocator:(void (^)(void *, NSUInteger))dealloc {
    return AdrenoNewBuffer(self, b, len, o, dealloc);
}
- (id<MTLBuffer>)newBufferWithIOSurface:(IOSurfaceRef)s { return AdrenoNewBufferWithIOSurface(self, s); }
- (id<MTLTexture>)newTextureWithDescriptor:(MTLTextureDescriptor *)d { return AdrenoNewTexture(self, d, NULL, 0); }
- (id<MTLTexture>)newTextureWithDescriptor:(MTLTextureDescriptor *)d iosurface:(IOSurfaceRef)s plane:(NSUInteger)plane {
    return AdrenoNewTexture(self, d, s, plane);           // nil here aborts WindowServer (AbortWithTextureInfo)
}
- (id<MTLTexture>)newTextureWithBytesNoCopy:(void *)b length:(NSUInteger)len descriptor:(MTLTextureDescriptor *)d
                                deallocator:(void (^)(void *, NSUInteger))dealloc {
    return AdrenoNewTextureNoCopy(self, d, b, len, dealloc);
}
- (id<MTLSamplerState>)newSamplerStateWithDescriptor:(MTLSamplerDescriptor *)d {
    return [[AdrenoSamplerState alloc] initWithDevice:self samplerDescriptor:d];   // must be non-nil (5 in new_compositor)
}
- (id<MTLDepthStencilState>)newDepthStencilStateWithDescriptor:(MTLDepthStencilDescriptor *)d {
    return [[AdrenoDepthStencilState alloc] initWithDevice:self depthStencilDescriptor:d];
}
- (id<MTLHeap>)newHeapWithDescriptor:(MTLHeapDescriptor *)d { return nil; }       // v1: QuartzCore falls back
- (id<MTLBinaryArchive>)newBinaryArchiveWithDescriptor:(MTLBinaryArchiveDescriptor *)d error:(NSError **)e {
    return nil;                                           // safe: QuartzCore handles nil (research: windowserver-metal-usage)
}
@end
