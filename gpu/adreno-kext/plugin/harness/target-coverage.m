/* SPDX-License-Identifier: MIT */
// target-coverage.m - WindowServer-shaped render targets through AdrenoMetal on the host.
// docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md. No Adreno hardware, no GPU submission: the plug-in's whole commit
// override runs, and only -[IOGPUMetalCommandBuffer commit] is replaced by a capture of the reserved kernel commands
// (as in native-texture.m). The IB ABI is simulated (the host AGX provider does not publish AdrenoIBABI).
//
// Usage: target-coverage BUNDLE REPORT.json --out DIR --kind surface|private|view --format F --size W H [options]
//   --kind surface   newTextureWithDescriptor:iosurface:plane:0 on an IOSurface of --fourcc, --bpe, --row R
//                    (default align64(W * bpe)), --planes 0|1, --surface-size SW SH (default W H)
//   --kind private   newTextureWithDescriptor: (shared storage, render target and shader read)
//   --kind view      a surface-kind parent in --parent-format, then newTextureViewWithPixelFormat:F
//                    (--view4: the textureType:levels:slices: variant, 2D, level 0, slice 0)
//   --draw           also draw one triangle with a pipeline whose colour attachment is F
//   --load           MTLLoadActionLoad instead of Clear (clear colour 0.25, 0.5, 0.75, 1)
// Depth/stencil (docs/ADRENO-DEPTH-STENCIL-20261017.md):
//   --zs F           a private depth/stencil render target of format F, the colour target's size; attached as
//                    --zs-attach depth|stencil|both (default: every aspect F has), Clear (depth 0.5, stencil 0x5a)
//                    or --zs-load (depth --zs-load-depth / stencil --zs-load-stencil only), stored DontCare
//   --ds depth|stencil|both   with --draw: a depth-stencil state (depth LessEqual + write; stencil front Always/
//                    IncrementWrap, back NotEqual/DecrementWrap, read 0xf0/0x0f, write 0x3c/0xc3), references 0x12/0x34
//   --write-mask N   the pipeline's colour write mask (Metal bits)
//   --index32        draw through a UInt32 index buffer
//   --frag-depth     the fragment function also writes [[depth(any)]]
//   --mrt N          N colour attachments (2..8): attachment 0 is the target, 1..N-1 private textures of
//                    --mrt-format F (default: the target's format), cleared to (n/8, 0.875, 0.5, 1) or loaded with --load;
//                    the fragment function writes every attachment ([[color(n)]] = (x * (n+1)/64, y, 0.25, 1))
//   --mrt-blend      with --draw: attachment 1 blends (SourceAlpha, OneMinusSourceAlpha, Add), the others do not
//   --mrt-gap        attachment 1 stays empty, attachment N-1 is set (a pass with a gap)
//   --sample F       with --draw: the fragment function samples a shared 64x32 texture of format F (filled with a
//                    byte pattern) at the position; --swizzle CCCC (each of 0 1 r g b a) sets that texture's
//                    descriptor swizzle (red, green, blue, alpha)
//   --mips N         the target (kind private) has N mip levels; --level L renders into level L, or --view-level L
//                    into a single-level 2D view of level L (the pass covers that level)
//   --sample-mips N  with --sample: the sampled texture has N levels (all named in its T#); --sample-view-level L
//                    samples a single-level view of level L instead
//   --blend S D      with --draw: attachment 0 blends with RGB and alpha source factor S and destination factor D
//                    (Metal MTLBlendFactor numbers), operation Add, blend colour (0.5, 0.25, 0.125, 1)
//   --element W H    IOSurface element width/height (with --bpe as bytes per element), e.g. '&BGA' 16 16 / 1024
//   --primitive P    with --draw: line (a 2-vertex line list) or line-strip (3 vertices) instead of a triangle
//                    (v80: WindowServer dropped line draws, "primitive type 1 is not supported yet")
//   --sampler-edge   with --sample: lodMaxClamp INFINITY, lodAverage, maxAnisotropy 3, linear filters with linear mips
//   --readback       before the pass: fill the target on the CPU, copy it to a shared buffer with a blit
//                    (copyFromTexture:...toBuffer:), and report whether the buffer holds the same bytes
// Framebuffer fetch (docs/ADRENO-DEPTH-STENCIL-20261017.md, "Plug-in: framebuffer fetch"):
//   --fb-fetch M     with --draw: the fragment function reads colour attachments ([[color(n)]] inputs). M = blend
//                    (float4 color(0), blended in the shader), half (half4 color(0), swizzled), mrt1 (with --mrt: reads
//                    color(1)), mrt01 (with --mrt: reads color(0) and color(1)); with --sample the function also samples
//                    texture(0) (the fetch then takes the T# after it)
//   --fb-draws N     issue the framebuffer-fetch draw N times (each later one reads what the earlier wrote)
//   --fb-sequence    first draw with a plain pipeline (no fetch) that writes the attachments, then the fetch draw(s)
//   --qc-fb F        the real CoreAnimation fragment function F of QuartzCore's default.metallib (path_blit_frag_lph,
//                    path_blit_frag_eo_lph: vertex path_blit_vert_lph, a 24-byte rect at vertex buffer(1), the matrix
//                    at buffer(2), the 4-byte uniform at fragment buffer(1), a 4-vertex strip; inplace_copy_lph: a
//                    source vertex function with its varyings), compiled through the same Metal path the Dock uses
//   --attachment-format N F   colour attachment N (1..7, with --mrt) has format F instead of --mrt-format
//   --dump-code      write the fragment program export (fs-program.json), its machine code (fs-original.bin) and
//                    the draw program's code buffer (fs-patched.bin) into --out
// Declared but unsupplied bindings (v38: com.apple.dock.extra and loginwindow dropped these draws):
//   --fs-shape S     with --draw and --sample F: unbound-texture (samples texture(0) behind a buffer(0) flag; the draw
//                    binds the sampler and the flag, no texture), unbound-sampler (texture(0) bound, sampler(0) not),
//                    unused-texture1 (declares texture(1), samples only texture(0)), unused-device-buffer (declares
//                    device buffer(1), reads only constant buffer(0)), unused-constant-buffer (declares constant
//                    buffer(2), reads only buffer(0)); --dump-code writes fs-program.json
//                    Bindings made through the range/LOD-clamp setters (v78's blank Dock icons): range-texture (texture(0)
//                    and sampler(0) through setFragmentTextures:withRange: / setFragmentSamplerStates:withRange:),
//                    lod-sampler (sampler(0) through setFragmentSamplerState:lodMinClamp:lodMaxClamp:atIndex:),
//                    range-buffer (a buffer object at constant buffer(0) through setFragmentBuffers:offsets:withRange:)
// Status: TARGET_COMMIT_CAPTURED_NOT_SUBMITTED, or TARGET_EXCEPTION with the exception's name and reason.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import "../AdrenoMetal/AdrenoLinearTexture.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (TargetCapture)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (uint32_t)resourceID;
- (uint64_t)resourceSize;
@end

static NSData *CapturedCommands;
static void *ReservedStart;
static NSUInteger ReservedLength;
static void InstallCommitCapture(void) {
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, @selector(_reserveKernelCommandBufferSpace:));
    Method commit = class_getInstanceMethod(native, @selector(commit));
    if (!commit || !reserve) @throw [NSException exceptionWithName:@"CommitCapture" reason:@"no native commit/reserve" userInfo:nil];
    IMP reserveIMP = method_getImplementation(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id command, NSUInteger length) {
        void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(command, @selector(_reserveKernelCommandBufferSpace:), length);
        ReservedStart = p; ReservedLength = length;
        return p;
    }));
    method_setImplementation(commit, imp_implementationWithBlock(^(id command) {
        if (ReservedStart && ReservedLength) CapturedCommands = [NSData dataWithBytes:ReservedStart length:ReservedLength];
    }));
}

static void save(NSDictionary *report, NSString *path) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!data || ![data writeToFile:path atomically:YES]) { fprintf(stderr, "report write failed\n"); exit(73); }
}

static uint32_t FourCC(const char *s) {
    return strlen(s) == 4 ? ((uint32_t)(uint8_t)s[0] << 24) | ((uint32_t)(uint8_t)s[1] << 16) | ((uint32_t)(uint8_t)s[2] << 8) | (uint8_t)s[3] : 0;
}

static NSDictionary *Layout(id<MTLTexture> texture) {
    AdrenoLinearTextureLayout l = {0};
    BOOL known = [texture respondsToSelector:@selector(adrenoGetLinearLayout:)] &&
                 [(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&l];
    return @{@"known":@(known), @"offset":@(l.offset), @"row_bytes":@(l.rowBytes), @"width":@(l.width),
             @"height":@(l.height), @"allocation":@(l.allocationBytes), @"format":@(l.format)};
}

// --fb-fetch: the fragment function of a framebuffer-fetch case.
static NSString *FetchSource(const char *mode, unsigned long mrt, id<MTLTexture> const *extra, BOOL sampled) {
    NSMutableString *s = [@"#include <metal_stdlib>\nusing namespace metal;\n"
        "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
        "fragment float4 fs_plain() { return float4(1,0.25,0.125,1); }\n" mutableCopy];
    if (mrt > 1) {
        BOOL read0 = !strcmp(mode, "mrt01"), read1 = !strcmp(mode, "mrt1") || read0;
        [s appendString:@"struct O {"];
        for (unsigned long n = 0; n < mrt; n++) if (n == 0 || extra[n]) [s appendFormat:@" float4 c%lu [[color(%lu)]];", n, n];
        [s appendString:@" };\nstruct OP {"];
        for (unsigned long n = 0; n < mrt; n++) if (n == 0 || extra[n]) [s appendFormat:@" float4 c%lu [[color(%lu)]];", n, n];
        [s appendString:@" };\nfragment OP fs_plain_mrt() { OP o;"];
        for (unsigned long n = 0; n < mrt; n++) if (n == 0 || extra[n]) [s appendFormat:@" o.c%lu = float4(0.5, 0.25, %g, 1);", n, n / 8.0];
        [s appendString:@" return o; }\nfragment O fs(float4 p [[position]]"];
        if (read0) [s appendString:@", float4 d0 [[color(0)]]"];
        if (read1) [s appendString:@", float4 d1 [[color(1)]]"];
        [s appendString:@") { O o;"];
        for (unsigned long n = 0; n < mrt; n++)
            if (n == 0 || extra[n])
                [s appendFormat:@" o.c%lu = %@ * 0.5 + float4(p.x * %g, 0.25, 0.125, 0.5);", n,
                    read0 && n == 1 ? @"d0" : read1 ? @"d1" : @"float4(0)", (n + 1) / 64.0];
        [s appendString:@" return o; }\n"];
    } else if (sampled) {
        [s appendString:@"fragment float4 fs(float4 p [[position]], texture2d<float> t [[texture(0)]], sampler sm [[sampler(0)]], "
                        "float4 d [[color(0)]]) { return t.sample(sm, p.xy / float2(64, 32)) * 0.5 + d * 0.5; }\n"];
    } else if (!strcmp(mode, "half")) {
        [s appendString:@"fragment half4 fs(half4 d [[color(0)]]) { return d.bgra * 0.75h + half4(0.25h); }\n"];
    } else {
        [s appendString:@"fragment float4 fs(float4 d [[color(0)]]) { return float4(0.5, 0.25, 0.125, 0.5) + d * 0.5; }\n"];
    }
    return s;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 3) return 64;
        NSString *bundlePath = @(argv[1]), *path = @(argv[2]), *outDir = nil, *kind = nil;
        const char *fourcc = "BGRA";
        unsigned long format = 0, parentFormat = 80, bpe = 4, row = 0, planes = 0, w = 0, h = 0, sw = 0, sh = 0;
        BOOL draw = NO, load = NO, view4 = NO, zsLoadDepth = NO, zsLoadStencil = NO, index32 = NO, fragDepth = NO, readback = NO;
        BOOL mrtBlend = NO, mrtGap = NO;
        long blendSrc = -1, blendDst = -1;
        unsigned long elementW = 0, elementH = 0;
        BOOL samplerEdge = NO;
        const char *primitive = NULL;
        unsigned long sampleFormat = 0, mips = 1, level = 0, viewLevel = ~0ul, sampleMips = 1, sampleViewLevel = ~0ul;
        const char *swizzleText = NULL;
        unsigned long zsFormat = 0, writeMask = MTLColorWriteMaskAll, mrt = 1, mrtFormat = 0;
        const char *zsAttach = NULL, *dsMode = NULL;
        const char *fbMode = NULL, *qcFragment = NULL;
        unsigned long fbDraws = 1, attachmentFormat[8] = {0};
        BOOL fbSequence = NO, dumpCode = NO;
        const char *fsShape = NULL;
        for (int i = 3; i < argc; i++) {
            const char *a = argv[i];
            if (!strcmp(a, "--out") && i + 1 < argc) outDir = @(argv[++i]);
            else if (!strcmp(a, "--kind") && i + 1 < argc) kind = @(argv[++i]);
            else if (!strcmp(a, "--format") && i + 1 < argc) format = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--parent-format") && i + 1 < argc) parentFormat = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--fourcc") && i + 1 < argc) fourcc = argv[++i];
            else if (!strcmp(a, "--bpe") && i + 1 < argc) bpe = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--row") && i + 1 < argc) row = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--planes") && i + 1 < argc) planes = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--size") && i + 2 < argc) { w = strtoul(argv[i + 1], NULL, 10); h = strtoul(argv[i + 2], NULL, 10); i += 2; }
            else if (!strcmp(a, "--surface-size") && i + 2 < argc) { sw = strtoul(argv[i + 1], NULL, 10); sh = strtoul(argv[i + 2], NULL, 10); i += 2; }
            else if (!strcmp(a, "--draw")) draw = YES;
            else if (!strcmp(a, "--load")) load = YES;
            else if (!strcmp(a, "--view4")) view4 = YES;
            else if (!strcmp(a, "--zs") && i + 1 < argc) zsFormat = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--zs-attach") && i + 1 < argc) zsAttach = argv[++i];
            else if (!strcmp(a, "--zs-load")) zsLoadDepth = zsLoadStencil = YES;
            else if (!strcmp(a, "--zs-load-depth")) zsLoadDepth = YES;
            else if (!strcmp(a, "--zs-load-stencil")) zsLoadStencil = YES;
            else if (!strcmp(a, "--ds") && i + 1 < argc) dsMode = argv[++i];
            else if (!strcmp(a, "--write-mask") && i + 1 < argc) writeMask = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--index32")) index32 = YES;
            else if (!strcmp(a, "--frag-depth")) fragDepth = YES;
            else if (!strcmp(a, "--readback")) readback = YES;
            else if (!strcmp(a, "--mrt") && i + 1 < argc) mrt = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--mrt-format") && i + 1 < argc) mrtFormat = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--mrt-blend")) mrtBlend = YES;
            else if (!strcmp(a, "--mrt-gap")) mrtGap = YES;
            else if (!strcmp(a, "--sample") && i + 1 < argc) sampleFormat = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--swizzle") && i + 1 < argc) swizzleText = argv[++i];
            else if (!strcmp(a, "--mips") && i + 1 < argc) mips = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--sampler-edge")) samplerEdge = YES;
            else if (!strcmp(a, "--primitive") && i + 1 < argc) primitive = argv[++i];
            else if (!strcmp(a, "--element") && i + 2 < argc) { elementW = strtoul(argv[i + 1], NULL, 10); elementH = strtoul(argv[i + 2], NULL, 10); i += 2; }
            else if (!strcmp(a, "--blend") && i + 2 < argc) { blendSrc = strtol(argv[i + 1], NULL, 10); blendDst = strtol(argv[i + 2], NULL, 10); i += 2; }
            else if (!strcmp(a, "--level") && i + 1 < argc) level = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--view-level") && i + 1 < argc) viewLevel = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--sample-mips") && i + 1 < argc) sampleMips = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--sample-view-level") && i + 1 < argc) sampleViewLevel = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--fb-fetch") && i + 1 < argc) fbMode = argv[++i];
            else if (!strcmp(a, "--fb-draws") && i + 1 < argc) fbDraws = strtoul(argv[++i], NULL, 10);
            else if (!strcmp(a, "--fb-sequence")) fbSequence = YES;
            else if (!strcmp(a, "--qc-fb") && i + 1 < argc) qcFragment = argv[++i];
            else if (!strcmp(a, "--dump-code")) dumpCode = YES;
            else if (!strcmp(a, "--fs-shape") && i + 1 < argc) fsShape = argv[++i];
            else if (!strcmp(a, "--attachment-format") && i + 2 < argc) {
                unsigned long n = strtoul(argv[i + 1], NULL, 10);
                if (n < 1 || n > 7) return 64;
                attachmentFormat[n] = strtoul(argv[i + 2], NULL, 10); i += 2;
            }
            else return 64;
        }
        NSFileManager *fm = [NSFileManager defaultManager];
        if (!mrtFormat) mrtFormat = format;
        if ((fbMode || qcFragment) && !draw) return 64;
        if (fsShape && (!draw || !sampleFormat || fbMode || qcFragment || mrt > 1)) return 64;
        if (fbMode && strcmp(fbMode, "blend") && strcmp(fbMode, "half") && strcmp(fbMode, "mrt1") && strcmp(fbMode, "mrt01")) return 64;
        if (fbMode && ((mrt > 1) != (!strcmp(fbMode, "mrt1") || !strcmp(fbMode, "mrt01")))) return 64;
        if (fbDraws < 1 || fbDraws > 4) return 64;
        if (!kind || !format || !w || !h || planes > 1 || mrt < 1 || mrt > 8 || (mrtGap && mrt < 3) || !FourCC(fourcc) || !outDir || !outDir.isAbsolutePath ||
            !path.isAbsolutePath || [fm fileExistsAtPath:path] || [fm fileExistsAtPath:outDir] ||
            ![fm createDirectoryAtPath:outDir withIntermediateDirectories:NO attributes:nil error:NULL]) return 64;
        if (!sw) { sw = w; sh = h; }
        MTLPixelFormat surfaceFormat = [kind isEqualToString:@"view"] ? parentFormat : format;
        if (!row) row = (sw * bpe + 63) & ~63ul;
        NSMutableDictionary *report = [@{@"status":@"RUNNING", @"kind":kind, @"format":@(format), @"size":@[@(w), @(h)],
            @"draw":@(draw), @"load":@(load), @"gpu_submission":@NO, @"ib_abi_simulated":@YES,
            @"boundary":@"Host native allocation using an AGX provider. No Adreno hardware execution."} mutableCopy];
        io_service_t accelerator = 0;
        IOSurfaceRef surface = NULL;
        int result = 1;
        @try {
            (void)MTLCopyAllDevices();
            NSError *error = nil;
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            if (![bundle loadAndReturnError:&error]) @throw [NSException exceptionWithName:@"BundleLoad" reason:error.description userInfo:nil];
            Class commandBuffer = [bundle classNamed:@"AdrenoCommandBuffer"];
            if (!commandBuffer) @throw [NSException exceptionWithName:@"BundleLoad" reason:@"no AdrenoCommandBuffer" userInfo:nil];
            class_replaceMethod(commandBuffer, @selector(adrenoDrawAvailable), imp_implementationWithBlock(^BOOL(id c) { return YES; }), "B16@0:8");
            accelerator = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            if (!accelerator) @throw [NSException exceptionWithName:@"Provider" reason:@"no host accelerator" userInfo:nil];
            id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:accelerator];
            if (!device) @throw [NSException exceptionWithName:@"DeviceInit" reason:@"nil device" userInfo:nil];
            MTLAddDevice(device);
            id<MTLTexture> texture = nil, parent = nil;
            MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:surfaceFormat width:w height:h mipmapped:NO];
            d.storageMode = MTLStorageModeShared;
            d.mipmapLevelCount = mips;
            d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead | ([kind isEqualToString:@"view"] ? MTLTextureUsagePixelFormatView : 0);
            if ([kind isEqualToString:@"surface"] || [kind isEqualToString:@"view"]) {
                NSMutableDictionary *p = [@{(id)kIOSurfaceWidth:@(sw), (id)kIOSurfaceHeight:@(sh),
                    (id)kIOSurfacePixelFormat:@(FourCC(fourcc)), (id)kIOSurfaceAllocSize:@(row * sh)} mutableCopy];
                if (planes) {
                    p[(id)kIOSurfacePlaneInfo] = @[@{(id)kIOSurfacePlaneWidth:@(sw), (id)kIOSurfacePlaneHeight:@(sh),
                        (id)kIOSurfacePlaneBytesPerElement:@(bpe), (id)kIOSurfacePlaneBytesPerRow:@(row),
                        (id)kIOSurfacePlaneOffset:@0, (id)kIOSurfacePlaneSize:@(row * sh)}];
                } else {
                    p[(id)kIOSurfaceBytesPerElement] = @(bpe);
                    p[(id)kIOSurfaceBytesPerRow] = @(row);
                    if (elementW) { p[(id)kIOSurfaceElementWidth] = @(elementW); p[(id)kIOSurfaceElementHeight] = @(elementH); }
                }
                surface = IOSurfaceCreate((__bridge CFDictionaryRef)p);
                if (!surface) @throw [NSException exceptionWithName:@"Surface" reason:@"nil IOSurface" userInfo:nil];
                report[@"surface"] = @{@"width":@(IOSurfaceGetWidth(surface)), @"height":@(IOSurfaceGetHeight(surface)),
                    @"bpe":@(IOSurfaceGetBytesPerElement(surface)), @"row_bytes":@(IOSurfaceGetBytesPerRow(surface)),
                    @"planes":@(IOSurfaceGetPlaneCount(surface)), @"alloc":@(IOSurfaceGetAllocSize(surface))};
                texture = [device newTextureWithDescriptor:d iosurface:surface plane:0];
            } else if ([kind isEqualToString:@"private"]) {
                texture = [device newTextureWithDescriptor:d];
            } else {
                @throw [NSException exceptionWithName:@"Usage" reason:@"unknown --kind" userInfo:nil];
            }
            if (!texture) @throw [NSException exceptionWithName:@"Texture" reason:@"native texture creation returned nil" userInfo:nil];
            if ([kind isEqualToString:@"view"]) {
                parent = texture;
                report[@"parent_layout"] = Layout(parent);
                texture = view4 ? [parent newTextureViewWithPixelFormat:format textureType:MTLTextureType2D levels:NSMakeRange(0, 1) slices:NSMakeRange(0, 1)]
                                : [parent newTextureViewWithPixelFormat:format];
                if (!texture) @throw [NSException exceptionWithName:@"View" reason:@"texture view returned nil" userInfo:nil];
                report[@"view_resource"] = @{@"parent_id":@([(id)parent resourceID]), @"view_id":@([(id)texture resourceID]),
                    @"parent_size":@([(id)parent resourceSize]), @"view_size":@([(id)texture resourceSize])};
            }
            id<MTLTexture> mipped = nil;
            if (viewLevel != ~0ul) {
                mipped = texture;
                texture = [mipped newTextureViewWithPixelFormat:format textureType:MTLTextureType2D levels:NSMakeRange(viewLevel, 1)
                                                         slices:NSMakeRange(0, 1)];
                if (!texture) @throw [NSException exceptionWithName:@"View" reason:@"level view returned nil" userInfo:nil];
            }
            report[@"mips"] = @{@"levels":@(mips), @"level":@(level), @"view_level":viewLevel == ~0ul ? @(-1) : @(viewLevel)};
            report[@"texture"] = @{@"class":@(object_getClassName(texture)), @"format":@(texture.pixelFormat),
                @"width":@(texture.width), @"height":@(texture.height), @"id":@([(id)texture resourceID]),
                @"size":@([(id)texture resourceSize])};
            report[@"layout"] = Layout(texture);
            id<MTLTexture> zs = nil;
            BOOL zsDepth = NO, zsStencil = NO;
            if (zsFormat) {
                BOOL hasDepth = zsFormat == MTLPixelFormatDepth16Unorm || zsFormat == MTLPixelFormatDepth32Float ||
                                zsFormat == MTLPixelFormatDepth32Float_Stencil8;
                BOOL hasStencil = zsFormat == MTLPixelFormatStencil8 || zsFormat == MTLPixelFormatDepth32Float_Stencil8;
                zsDepth = hasDepth && (!zsAttach || !strcmp(zsAttach, "depth") || !strcmp(zsAttach, "both"));
                zsStencil = hasStencil && (!zsAttach || !strcmp(zsAttach, "stencil") || !strcmp(zsAttach, "both"));
                MTLTextureDescriptor *zd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:zsFormat width:w height:h mipmapped:NO];
                zd.storageMode = MTLStorageModePrivate;
                zd.usage = MTLTextureUsageRenderTarget;
                zs = [device newTextureWithDescriptor:zd];
                if (!zs) @throw [NSException exceptionWithName:@"Texture" reason:@"depth/stencil texture creation returned nil" userInfo:nil];
                report[@"zs"] = @{@"format":@(zsFormat), @"id":@([(id)zs resourceID]), @"size":@([(id)zs resourceSize]),
                                  @"depth":@(zsDepth), @"stencil":@(zsStencil), @"load_depth":@(zsLoadDepth),
                                  @"load_stencil":@(zsLoadStencil)};
            }
            id<MTLTexture> extra[8] = {nil};
            NSMutableArray *extraReport = [NSMutableArray array];
            for (unsigned long n = 1; n < mrt; n++) {
                if (mrtGap && n < mrt - 1) continue;
                const unsigned long af = attachmentFormat[n] ? attachmentFormat[n] : mrtFormat;
                MTLTextureDescriptor *md = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:af width:w height:h mipmapped:NO];
                md.storageMode = MTLStorageModePrivate;
                md.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
                extra[n] = [device newTextureWithDescriptor:md];
                if (!extra[n]) @throw [NSException exceptionWithName:@"Texture" reason:@"colour attachment creation returned nil" userInfo:nil];
                [extraReport addObject:@{@"index":@(n), @"format":@(af), @"id":@([(id)extra[n] resourceID]),
                                         @"size":@([(id)extra[n] resourceSize]), @"layout":Layout(extra[n])}];
            }
            id<MTLTexture> sampled = nil;
            id<MTLSamplerState> sampler = nil;
            if (sampleFormat) {
                MTLTextureDescriptor *sd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:sampleFormat width:64 height:32 mipmapped:NO];
                sd.storageMode = MTLStorageModeShared;
                sd.usage = MTLTextureUsageShaderRead;
                if (swizzleText) {
                    if (strlen(swizzleText) != 4) @throw [NSException exceptionWithName:@"Usage" reason:@"--swizzle needs 4 channels" userInfo:nil];
                    MTLTextureSwizzle c[4];
                    for (int k = 0; k < 4; k++) {
                        const char *at = strchr("01rgba", swizzleText[k]);
                        if (!at || !swizzleText[k]) @throw [NSException exceptionWithName:@"Usage" reason:@"--swizzle channel" userInfo:nil];
                        c[k] = (MTLTextureSwizzle)(at - "01rgba");   // Zero, One, Red, Green, Blue, Alpha
                    }
                    sd.swizzle = MTLTextureSwizzleChannelsMake(c[0], c[1], c[2], c[3]);
                }
                sd.mipmapLevelCount = sampleMips;
                sampled = [device newTextureWithDescriptor:sd];
                if (!sampled) @throw [NSException exceptionWithName:@"Texture" reason:@"sampled texture creation returned nil" userInfo:nil];
                id<MTLTexture> sampledRoot = sampled;
                NSUInteger row = 64 * 16;
                NSMutableData *bytes = [NSMutableData dataWithLength:row * 32];
                uint8_t *sb = bytes.mutableBytes;
                for (NSUInteger k = 0; k < bytes.length; k++) sb[k] = (uint8_t)(k * 13 + 7);
                [sampled replaceRegion:MTLRegionMake2D(0, 0, 64, 32) mipmapLevel:0 withBytes:sb bytesPerRow:row];
                if (sampleViewLevel != ~0ul) {
                    sampled = [sampledRoot newTextureViewWithPixelFormat:sampleFormat textureType:MTLTextureType2D
                                                                  levels:NSMakeRange(sampleViewLevel, 1) slices:NSMakeRange(0, 1)];
                    if (!sampled) @throw [NSException exceptionWithName:@"View" reason:@"sampled level view returned nil" userInfo:nil];
                }
                MTLSamplerDescriptor *sdesc = [MTLSamplerDescriptor new];
                if (samplerEdge) {
                    sdesc.lodMaxClamp = INFINITY; sdesc.lodAverage = YES; sdesc.maxAnisotropy = 3;
                    sdesc.minFilter = sdesc.magFilter = MTLSamplerMinMagFilterLinear; sdesc.mipFilter = MTLSamplerMipFilterLinear;
                }
                sampler = [device newSamplerStateWithDescriptor:sdesc];
                report[@"sampled"] = @{@"format":@(sampleFormat), @"id":@([(id)sampled resourceID]),
                                       @"swizzle":swizzleText ? @(swizzleText) : @"rgba"};
            }
            if (mrt > 1) report[@"mrt"] = @{@"count":@(mrt), @"blend":@(mrtBlend), @"gap":@(mrtGap), @"attachments":extraReport};
            id<MTLRenderPipelineState> pipeline = nil, plainPipeline = nil;
            NSDictionary *qcBytes = nil;   // --qc-fb: {stage: {index: bytes}}
            if (draw && fsShape) {
                NSString *fs = nil;
                if (!strcmp(fsShape, "unbound-texture"))
                    fs = @"fragment float4 fs(float4 p [[position]], texture2d<float> t [[texture(0)]], sampler sm [[sampler(0)]], "
                          "constant uint &on [[buffer(0)]]) { return on ? t.sample(sm, p.xy / float2(64, 32)) : float4(1, 0.25, 0.125, 1); }\n";
                else if (!strcmp(fsShape, "unbound-sampler") || !strcmp(fsShape, "range-texture") || !strcmp(fsShape, "lod-sampler"))
                    fs = @"fragment float4 fs(float4 p [[position]], texture2d<float> t [[texture(0)]], sampler sm [[sampler(0)]]) "
                          "{ return t.sample(sm, p.xy / float2(64, 32)); }\n";
                else if (!strcmp(fsShape, "unused-texture1"))
                    fs = @"fragment float4 fs(float4 p [[position]], texture2d<float> t [[texture(0)]], texture2d<float> u [[texture(1)]], "
                          "sampler sm [[sampler(0)]]) { return t.sample(sm, p.xy / float2(64, 32)); }\n";
                else if (!strcmp(fsShape, "unused-device-buffer"))
                    fs = @"fragment float4 fs(constant float4 &c [[buffer(0)]], device float4 *d [[buffer(1)]]) { return c; }\n";
                else if (!strcmp(fsShape, "unused-constant-buffer") || !strcmp(fsShape, "range-buffer"))
                    fs = @"fragment float4 fs(constant float4 &c [[buffer(0)]], constant float4 &e [[buffer(2)]]) { return c; }\n";
                else @throw [NSException exceptionWithName:@"Usage" reason:@"unknown --fs-shape" userInfo:nil];
                NSString *source = [@"#include <metal_stdlib>\nusing namespace metal;\n"
                    "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
                    stringByAppendingString:fs];
                id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
                if (!library) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
                pd.vertexFunction = [library newFunctionWithName:@"vs"];
                pd.fragmentFunction = [library newFunctionWithName:@"fs"];
                pd.colorAttachments[0].pixelFormat = format;
                pipeline = [device newRenderPipelineStateWithDescriptor:pd error:&error];
                if (!pipeline) @throw [NSException exceptionWithName:@"Pipeline" reason:error.description userInfo:nil];
                report[@"fs_shape"] = @(fsShape);
                if (dumpCode) {
                    NSDictionary *program = [[(id)pipeline valueForKey:@"fragmentCode"] valueForKey:@"program"];
                    NSData *json = [NSJSONSerialization dataWithJSONObject:program options:NSJSONWritingSortedKeys error:NULL];
                    if (!json || ![json writeToFile:[outDir stringByAppendingPathComponent:@"fs-program.json"] atomically:NO])
                        @throw [NSException exceptionWithName:@"Artifact" reason:@"fragment program dump" userInfo:nil];
                }
            } else if (draw && (fbMode || qcFragment)) {
                // The fetch pipeline (and with --fb-sequence a plain one for the same attachments).
                id<MTLLibrary> library = [device newLibraryWithSource:FetchSource(fbMode ?: "blend", qcFragment ? 1 : mrt, extra, sampled != nil)
                                                              options:nil error:&error];
                if (!library) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                id<MTLFunction> vertexFunction = [library newFunctionWithName:@"vs"], fragmentFunction = [library newFunctionWithName:@"fs"];
                if (qcFragment) {
                    NSString *qcPath = @"/System/Library/Frameworks/QuartzCore.framework/Versions/A/Resources/default.metallib";
                    id<MTLLibrary> qc = [device newLibraryWithURL:[NSURL fileURLWithPath:qcPath] error:&error];
                    if (!qc) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                    fragmentFunction = [qc newFunctionWithName:@(qcFragment)];
                    if (!fragmentFunction) @throw [NSException exceptionWithName:@"Library" reason:@"no such QuartzCore function" userInfo:nil];
                    if (!strncmp(qcFragment, "path_blit_frag", 14)) {
                        vertexFunction = [qc newFunctionWithName:@"path_blit_vert_lph"];
                        // CA::OGL::AxisAlignedRect {float2 min, max; half4 colour} and an identity float4x4.
                        const float rect[6] = {-0.75f, -0.5f, 0.75f, 0.5f, 0, 0};
                        NSMutableData *r = [NSMutableData dataWithBytes:rect length:sizeof rect];
                        const uint16_t colour[4] = {0x3c00, 0x3800, 0x3400, 0x3c00};
                        memcpy((uint8_t *)r.mutableBytes + 16, colour, 8);
                        const float m[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
                        const float u[1] = {0.5f};
                        qcBytes = @{@"vertex":@{@1:r, @2:[NSData dataWithBytes:m length:sizeof m]},
                                    @"fragment":@{@1:[NSData dataWithBytes:u length:sizeof u]}};
                    } else {
                        id<MTLLibrary> vl = [device newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\n"
                            "struct V { float4 position [[position]]; half4 color; float2 texcoord0_0; };\n"
                            "vertex V vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; "
                            "V v; v.position = float4(p[i],0,1); v.color = half4(1); v.texcoord0_0 = p[i]; return v; }\n" options:nil error:&error];
                        if (!vl) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                        vertexFunction = [vl newFunctionWithName:@"vs"];
                        qcBytes = @{@"vertex":@{}, @"fragment":@{}};
                    }
                }
                for (int k = 0; k < (fbSequence ? 2 : 1); k++) {
                    MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
                    pd.vertexFunction = vertexFunction;
                    pd.fragmentFunction = k ? [library newFunctionWithName:mrt > 1 ? @"fs_plain_mrt" : @"fs_plain"] : fragmentFunction;
                    if (k && qcFragment) @throw [NSException exceptionWithName:@"Usage" reason:@"--fb-sequence with --qc-fb" userInfo:nil];
                    pd.colorAttachments[0].pixelFormat = format;
                    pd.colorAttachments[0].writeMask = writeMask;
                    for (unsigned long n = 1; n < mrt; n++)
                        if (extra[n]) pd.colorAttachments[n].pixelFormat = attachmentFormat[n] ? attachmentFormat[n] : mrtFormat;
                    if (zsDepth) pd.depthAttachmentPixelFormat = zsFormat;
                    if (zsStencil) pd.stencilAttachmentPixelFormat = zsFormat;
                    id<MTLRenderPipelineState> p = [device newRenderPipelineStateWithDescriptor:pd error:&error];
                    if (!p) @throw [NSException exceptionWithName:@"Pipeline" reason:error.description userInfo:nil];
                    if (k) plainPipeline = p; else pipeline = p;
                }
                report[@"fb"] = @{@"mode":fbMode ? @(fbMode) : @"", @"qc":qcFragment ? @(qcFragment) : @"", @"draws":@(fbDraws),
                                  @"sequence":@(fbSequence)};
                if (dumpCode) {
                    id code = [(id)pipeline valueForKey:@"fragmentCode"];
                    NSDictionary *program = [code valueForKey:@"program"];
                    NSData *json = [NSJSONSerialization dataWithJSONObject:program options:NSJSONWritingSortedKeys error:NULL];
                    if (!json || ![json writeToFile:[outDir stringByAppendingPathComponent:@"fs-program.json"] atomically:NO] ||
                        ![[code valueForKey:@"machineCode"] writeToFile:[outDir stringByAppendingPathComponent:@"fs-original.bin"] atomically:NO])
                        @throw [NSException exceptionWithName:@"Artifact" reason:@"fragment program dump" userInfo:nil];
                }
            } else if (draw && mrt > 1) {
                NSMutableString *source = [@"#include <metal_stdlib>\nusing namespace metal;\n"
                    "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
                    "struct O {" mutableCopy];
                for (unsigned long n = 0; n < mrt; n++)
                    if (n == 0 || extra[n]) [source appendFormat:@" float4 c%lu [[color(%lu)]];", n, n];
                [source appendString:@" };\nfragment O fs(float4 p [[position]]) { O o;"];
                for (unsigned long n = 0; n < mrt; n++)
                    if (n == 0 || extra[n]) [source appendFormat:@" o.c%lu = float4(p.x * %g, p.y, 0.25, 1);", n, (n + 1) / 64.0];
                [source appendString:@" return o; }\n"];
                id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
                if (!library) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
                pd.vertexFunction = [library newFunctionWithName:@"vs"];
                pd.fragmentFunction = [library newFunctionWithName:@"fs"];
                pd.colorAttachments[0].pixelFormat = format;
                pd.colorAttachments[0].writeMask = writeMask;
                for (unsigned long n = 1; n < mrt; n++) {
                    if (!extra[n]) continue;
                    pd.colorAttachments[n].pixelFormat = attachmentFormat[n] ? attachmentFormat[n] : mrtFormat;
                    if (mrtBlend && n == 1) {
                        pd.colorAttachments[n].blendingEnabled = YES;
                        pd.colorAttachments[n].sourceRGBBlendFactor = pd.colorAttachments[n].sourceAlphaBlendFactor = MTLBlendFactorSourceAlpha;
                        pd.colorAttachments[n].destinationRGBBlendFactor = pd.colorAttachments[n].destinationAlphaBlendFactor =
                            MTLBlendFactorOneMinusSourceAlpha;
                    }
                }
                if (zsDepth) pd.depthAttachmentPixelFormat = zsFormat;
                if (zsStencil) pd.stencilAttachmentPixelFormat = zsFormat;
                pipeline = [device newRenderPipelineStateWithDescriptor:pd error:&error];
                if (!pipeline) @throw [NSException exceptionWithName:@"Pipeline" reason:error.description userInfo:nil];
            } else if (draw && sampled) {
                NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
                    "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
                    "fragment float4 fs(float4 p [[position]], texture2d<float> t [[texture(0)]], sampler s [[sampler(0)]]) "
                    "{ return t.sample(s, p.xy / float2(64, 32)); }\n";
                id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
                if (!library) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
                pd.vertexFunction = [library newFunctionWithName:@"vs"];
                pd.fragmentFunction = [library newFunctionWithName:@"fs"];
                pd.colorAttachments[0].pixelFormat = format;
                pipeline = [device newRenderPipelineStateWithDescriptor:pd error:&error];
                if (!pipeline) @throw [NSException exceptionWithName:@"Pipeline" reason:error.description userInfo:nil];
            } else if (draw) {
                NSString *source = fragDepth ? @"#include <metal_stdlib>\nusing namespace metal;\n"
                    "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
                    "struct O { float4 c [[color(0)]]; float d [[depth(any)]]; };\n"
                    "fragment O fs() { O o; o.c = float4(1,0.25,0.125,1); o.d = 0.25; return o; }\n"
                  : @"#include <metal_stdlib>\nusing namespace metal;\n"
                    "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
                    "fragment float4 fs() { return float4(1,0.25,0.125,1); }\n";
                id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
                if (!library) @throw [NSException exceptionWithName:@"Library" reason:error.description userInfo:nil];
                MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
                pd.vertexFunction = [library newFunctionWithName:@"vs"];
                pd.fragmentFunction = [library newFunctionWithName:@"fs"];
                pd.colorAttachments[0].pixelFormat = format;
                pd.colorAttachments[0].writeMask = writeMask;
                if (blendSrc >= 0) {
                    pd.colorAttachments[0].blendingEnabled = YES;
                    pd.colorAttachments[0].sourceRGBBlendFactor = pd.colorAttachments[0].sourceAlphaBlendFactor = (MTLBlendFactor)blendSrc;
                    pd.colorAttachments[0].destinationRGBBlendFactor = pd.colorAttachments[0].destinationAlphaBlendFactor = (MTLBlendFactor)blendDst;
                }
                if (zsDepth) pd.depthAttachmentPixelFormat = zsFormat;
                if (zsStencil) pd.stencilAttachmentPixelFormat = zsFormat;
                pipeline = [device newRenderPipelineStateWithDescriptor:pd error:&error];
                if (!pipeline) @throw [NSException exceptionWithName:@"Pipeline" reason:error.description userInfo:nil];
            }
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (readback) {
                NSUInteger bpp = texture.pixelFormat == MTLPixelFormatRGBA16Float ? 8 : 4, row = w * bpp;
                NSMutableData *pattern = [NSMutableData dataWithLength:row * h];
                uint8_t *pb = pattern.mutableBytes;
                for (NSUInteger i = 0; i < pattern.length; i++) pb[i] = (uint8_t)(i * 37 + 11);
                [texture replaceRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0 withBytes:pb bytesPerRow:row];
                id<MTLBuffer> out = [device newBufferWithLength:row * h + 64 options:MTLResourceStorageModeShared];
                memset(out.contents, 0xcd, out.length);
                id<MTLCommandBuffer> rb = [queue commandBuffer];
                id<MTLBlitCommandEncoder> blit = [rb blitCommandEncoder];
                [blit copyFromTexture:texture sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0)
                           sourceSize:MTLSizeMake(w, h, 1) toBuffer:out destinationOffset:64 destinationBytesPerRow:row
             destinationBytesPerImage:row * h];
                [blit endEncoding];
                const uint8_t *ob = out.contents;
                BOOL guard = YES;
                for (int i = 0; i < 64; i++) guard &= ob[i] == 0xcd;
                report[@"readback"] = @{@"bytes":@(row * h), @"equal":@(!memcmp(ob + 64, pb, row * h)), @"guard_untouched":@(guard)};
            }
            id<MTLCommandBuffer> command = [queue commandBuffer];
            MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
            pass.colorAttachments[0].texture = texture;
            pass.colorAttachments[0].level = level;
            pass.colorAttachments[0].loadAction = load ? MTLLoadActionLoad : MTLLoadActionClear;
            pass.colorAttachments[0].storeAction = MTLStoreActionStore;
            pass.colorAttachments[0].clearColor = MTLClearColorMake(0.25, 0.5, 0.75, 1);
            for (unsigned long n = 1; n < mrt; n++) {
                if (!extra[n]) continue;
                pass.colorAttachments[n].texture = extra[n];
                pass.colorAttachments[n].loadAction = load ? MTLLoadActionLoad : MTLLoadActionClear;
                pass.colorAttachments[n].storeAction = MTLStoreActionStore;
                pass.colorAttachments[n].clearColor = MTLClearColorMake(n / 8.0, 0.875, 0.5, 1);
            }
            if (zsDepth) {
                pass.depthAttachment.texture = zs;
                pass.depthAttachment.loadAction = zsLoadDepth ? MTLLoadActionLoad : MTLLoadActionClear;
                pass.depthAttachment.storeAction = MTLStoreActionDontCare;
                pass.depthAttachment.clearDepth = 0.5;
            }
            if (zsStencil) {
                pass.stencilAttachment.texture = zs;
                pass.stencilAttachment.loadAction = zsLoadStencil ? MTLLoadActionLoad : MTLLoadActionClear;
                pass.stencilAttachment.storeAction = MTLStoreActionDontCare;
                pass.stencilAttachment.clearStencil = 0x5a;
            }
            id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:pass];
            if (!encoder) @throw [NSException exceptionWithName:@"Encoder" reason:@"nil render encoder" userInfo:nil];
            if (draw && fsShape) {
                [encoder setRenderPipelineState:pipeline];
                const uint32_t on = 1;
                const float c[4] = {1, 0.25f, 0.125f, 1};
                if (!strcmp(fsShape, "unbound-texture")) {
                    [encoder setFragmentSamplerState:sampler atIndex:0];
                    [encoder setFragmentBytes:&on length:sizeof on atIndex:0];
                } else if (!strcmp(fsShape, "unbound-sampler")) {
                    [encoder setFragmentTexture:sampled atIndex:0];
                } else if (!strcmp(fsShape, "unused-texture1")) {
                    [encoder setFragmentTexture:sampled atIndex:0];
                    [encoder setFragmentSamplerState:sampler atIndex:0];
                } else if (!strcmp(fsShape, "range-texture")) {
                    id<MTLTexture> ts[1] = {sampled};
                    id<MTLSamplerState> ss[1] = {sampler};
                    [encoder setFragmentTextures:ts withRange:NSMakeRange(0, 1)];
                    [encoder setFragmentSamplerStates:ss withRange:NSMakeRange(0, 1)];
                } else if (!strcmp(fsShape, "lod-sampler")) {
                    [encoder setFragmentTexture:sampled atIndex:0];
                    [encoder setFragmentSamplerState:sampler lodMinClamp:0 lodMaxClamp:INFINITY atIndex:0];
                } else if (!strcmp(fsShape, "range-buffer")) {
                    id<MTLBuffer> b = [device newBufferWithBytes:c length:sizeof c options:MTLResourceStorageModeShared];
                    id<MTLBuffer> bs[1] = {b};
                    const NSUInteger offs[1] = {0};
                    [encoder setFragmentBuffers:bs offsets:offs withRange:NSMakeRange(0, 1)];
                } else {
                    [encoder setFragmentBytes:c length:sizeof c atIndex:0];
                }
                [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
            } else if (draw && (fbMode || qcFragment)) {
                if (sampled) {
                    [encoder setFragmentTexture:sampled atIndex:0];
                    [encoder setFragmentSamplerState:sampler atIndex:0];
                }
                if (plainPipeline) {
                    [encoder setRenderPipelineState:plainPipeline];
                    [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
                }
                [encoder setRenderPipelineState:pipeline];
                for (NSNumber *k in qcBytes[@"vertex"]) {
                    NSData *b = qcBytes[@"vertex"][k];
                    [encoder setVertexBytes:b.bytes length:b.length atIndex:k.unsignedIntegerValue];
                }
                for (NSNumber *k in qcBytes[@"fragment"]) {
                    NSData *b = qcBytes[@"fragment"][k];
                    [encoder setFragmentBytes:b.bytes length:b.length atIndex:k.unsignedIntegerValue];
                }
                for (unsigned long k = 0; k < fbDraws; k++) {
                    if (qcBytes && [qcBytes[@"vertex"] count])
                        [encoder drawPrimitives:MTLPrimitiveTypeTriangleStrip vertexStart:0 vertexCount:4 instanceCount:1];
                    else
                        [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
                }
                if (dumpCode) {
                    id program = [(id)pipeline valueForKey:@"adrenoDrawProgram"];
                    id<MTLBuffer> buffer = [program valueForKey:@"fragmentCodeBuffer"];
                    NSData *patched = buffer ? [NSData dataWithBytes:buffer.contents length:buffer.length] : nil;
                    if (!patched || ![patched writeToFile:[outDir stringByAppendingPathComponent:@"fs-patched.bin"] atomically:NO])
                        @throw [NSException exceptionWithName:@"Artifact" reason:@"fragment code buffer dump" userInfo:nil];
                }
            } else if (draw) {
                [encoder setRenderPipelineState:pipeline];
                if (blendSrc >= 0) [encoder setBlendColorRed:0.5 green:0.25 blue:0.125 alpha:1];
                if (sampled) {
                    [encoder setFragmentTexture:sampled atIndex:0];
                    [encoder setFragmentSamplerState:sampler atIndex:0];
                }
                if (dsMode) {
                    MTLDepthStencilDescriptor *dd = [MTLDepthStencilDescriptor new];
                    if (!strcmp(dsMode, "depth") || !strcmp(dsMode, "both")) {
                        dd.depthCompareFunction = MTLCompareFunctionLessEqual;
                        dd.depthWriteEnabled = YES;
                    }
                    if (!strcmp(dsMode, "stencil") || !strcmp(dsMode, "both")) {
                        MTLStencilDescriptor *f = [MTLStencilDescriptor new], *b = [MTLStencilDescriptor new];
                        f.stencilCompareFunction = MTLCompareFunctionAlways;
                        f.depthStencilPassOperation = MTLStencilOperationIncrementWrap;
                        f.readMask = 0xf0; f.writeMask = 0x3c;
                        b.stencilCompareFunction = MTLCompareFunctionNotEqual;
                        b.stencilFailureOperation = MTLStencilOperationZero;
                        b.depthFailureOperation = MTLStencilOperationInvert;
                        b.depthStencilPassOperation = MTLStencilOperationDecrementWrap;
                        b.readMask = 0x0f; b.writeMask = 0xc3;
                        dd.frontFaceStencil = f; dd.backFaceStencil = b;
                    }
                    id<MTLDepthStencilState> state = [device newDepthStencilStateWithDescriptor:dd];
                    if (!state) @throw [NSException exceptionWithName:@"DepthStencil" reason:@"nil depth-stencil state" userInfo:nil];
                    [encoder setDepthStencilState:state];
                    [encoder setStencilFrontReferenceValue:0x12 backReferenceValue:0x34];
                }
                MTLPrimitiveType prim = MTLPrimitiveTypeTriangle;
                NSUInteger primCount = 3;
                if (primitive && !strcmp(primitive, "line")) { prim = MTLPrimitiveTypeLine; primCount = 2; }
                else if (primitive && !strcmp(primitive, "line-strip")) prim = MTLPrimitiveTypeLineStrip;
                else if (primitive) @throw [NSException exceptionWithName:@"Usage" reason:@"unknown --primitive" userInfo:nil];
                if (primitive) report[@"primitive"] = @(primitive);
                if (index32) {
                    const uint32_t indices[3] = {0, 1, 2};
                    id<MTLBuffer> ib = [device newBufferWithBytes:indices length:sizeof indices options:MTLResourceStorageModeShared];
                    report[@"index_buffer"] = @{@"id":@([(id)ib resourceID])};
                    [encoder drawIndexedPrimitives:prim indexCount:primCount indexType:MTLIndexTypeUInt32
                                       indexBuffer:ib indexBufferOffset:0];
                } else {
                    [encoder drawPrimitives:prim vertexStart:0 vertexCount:primCount];
                }
            }
            [encoder endEncoding];
            InstallCommitCapture();
            [command commit];
            if (!CapturedCommands) @throw [NSException exceptionWithName:@"CommitCapture" reason:@"no kernel commands captured" userInfo:nil];
            if (![CapturedCommands writeToFile:[outDir stringByAppendingPathComponent:@"commands.bin"] atomically:NO])
                @throw [NSException exceptionWithName:@"Artifact" reason:@"commands.bin" userInfo:nil];
            report[@"status"] = @"TARGET_COMMIT_CAPTURED_NOT_SUBMITTED";
            result = 0;
        } @catch (NSException *e) {
            report[@"status"] = @"TARGET_EXCEPTION";
            report[@"exception"] = @{@"name":e.name ?: @"", @"reason":e.reason ?: @""};
            result = 2;
        } @finally {
            save(report, path);
            if (surface) CFRelease(surface);
            if (accelerator) IOObjectRelease(accelerator);
        }
        return result;
    }
}
