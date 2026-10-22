/* SPDX-License-Identifier: MIT */
// Native allocation reproduction; no Adreno GPU submission.
// --commit runs the plug-in's whole commit override (kernel command reservation, segment begin/end and the
// native resource-list publication that failed on generation46) and replaces only the final
// -[IOGPUMetalCommandBuffer commit] with a capture, so nothing reaches the host GPU's kernel queue.
//
// Usage: native-texture BUNDLE REPORT.json [mode flags]
//   (none)            clear pass encoded, not committed                       NATIVE_CLEAR_ENCODED_NOT_SUBMITTED
//   --incompatible    shader-read-only texture, the clear must be refused      NATIVE_TEXTURE_EXCEPTION
//   --draw            clear pass plus one triangle encoded, not committed      NATIVE_DRAW_ENCODED_NOT_SUBMITTED
//   --commit [--out DIR]  clear pass committed into the capture (DIR: commands.bin)  NATIVE_CLEAR_COMMIT_CAPTURED_NOT_SUBMITTED
//   --commit --out DIR [--ib-abi] [--rgba8]  the same clear-only commit, optionally with the IB ABI simulated and/or an
//                     RGBA8Unorm target (a format the IB builder refuses and the FILL32 clear path supports)
//   --draw --commit --out DIR [scene flags] [--ib-abi]
//                     the scene committed into the capture; DIR receives the reserved kernel-command bytes
//                     (commands.bin), the published resource records (resources.json), the pipeline's code
//                     buffers and program exports                            NATIVE_DRAW_COMMIT_CAPTURED_NOT_SUBMITTED
//   --golden --out DIR [scene flags]
//                     the same scene rendered by the host's own Metal device (AGX) into an identical IOSurface;
//                     the Adreno bundle is not loaded                          HOST_METAL_GOLDEN_RENDERED
// Scene flags: --source triangle|plan-v2|varyings|uniforms|device, --load (MTLLoadActionLoad instead of Clear),
//   --size W H (target size; rows align64(4 * W), no padding), --indexed (UInt16 indices 0,1,2), --instances N,
//   --draws N (per pass), --sequence draw|fill-draw|draw-fill|
//   draw-fill-draw|draw-draw (blit fillBuffer and render passes in that encoder order; a second pass loads).
// Sources: triangle (the S5 guest-draw scene), plan-v2 (draw-plan-v2's pipeline: compiler-output.m --constants,
//   scale 0.5, indexBias 13), varyings (compiler-output.m --varyings, same constants), uniforms (vertex_id
//   positions from setVertexBytes at buffer(1), a fragment tint MTLBuffer at buffer(0), premultiplied
//   source-over blending; passes after the first bind other positions), device (vertex_id positions read from a device MTLBuffer at buffer(1) through the
//   driver table, a setFragmentBytes tint at buffer(0), no blending). A stage_in source is not offered: with a vertex descriptor the compiler service hands
//   the vertex hook only air.vertexFetchFunction, which AdrenoPipeline.m refuses.
// --ib-abi replaces -[AdrenoCommandBuffer adrenoDrawAvailable] with YES: it stands in for the kext's AdrenoIBABI
// registry property, which the host AGX provider does not publish (the report records that it was simulated).
// Without it the plug-in reads the real (absent) property and must refuse shader draws.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import "../AdrenoMetal/AdrenoLinearTexture.h"
#include <stdlib.h>
#include <unistd.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (TextureCapture)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (void *)ioGPUResourceList;
- (uint32_t)resourceID;
- (uint64_t)resourceSize;
@end

// The target: 37x23 BGRA8, 1024-byte rows, 32 KiB (the S5 scene) unless --size W H picks rows of align64(4 * W).
static NSUInteger kWidth = 37, kHeight = 23, kRowBytes = 1024, kAllocation = 32768;
static MTLPixelFormat kFormat = MTLPixelFormatBGRA8Unorm;   // --rgba8 (clear-only commit): MTLPixelFormatRGBA8Unorm
static const NSUInteger kFillBytes = 256;
static const float kPoints[12] = {-0.6f, -0.7f, 0.0f, 0.0f,   0.7f, -0.5f, 0.0f, 0.0f,   0.0f, 0.8f, 0.0f, 0.0f};
static const float kPoints2[12] = {-0.5f, 0.6f, 0.0f, 0.0f,   0.6f, 0.7f, 0.0f, 0.0f,   0.1f, -0.8f, 0.0f, 0.0f};  // later passes
static const float kTint[4] = {0.9f, 0.8f, 0.7f, 0.75f};

// 26A428 IOGPUResourceList (IOGPU IOGPUResourceListInit 0x1a7f88924, _ioGPUResourceListAddResourceEntry
// 0x1a7f88e0c): +0x208 remaining segment bytes, +0x210 segment byte threshold, +0x220 resource entries.
static NSDictionary *CapturedCommit;
static NSData *CapturedCommands;
static void *ReservedStart;
static NSUInteger ReservedLength, ReservedCalls;
static void InstallCommitCapture(void) {
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, @selector(_reserveKernelCommandBufferSpace:));
    Method commit = class_getInstanceMethod(native, @selector(commit));
    if (!commit || !reserve) @throw [NSException exceptionWithName:@"CommitCapture" reason:@"no native commit/reserve" userInfo:nil];
    IMP reserveIMP = method_getImplementation(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id command, NSUInteger length) {
        void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(command, @selector(_reserveKernelCommandBufferSpace:), length);
        ReservedStart = p; ReservedLength = length; ReservedCalls++;
        return p;
    }));
    method_setImplementation(commit, imp_implementationWithBlock(^(id command) {
        const char *list = [command ioGPUResourceList];
        CapturedCommit = @{@"reached_native_commit":@YES,
            @"remaining_bytes":@(*(const uint64_t *)(list + 0x208)),
            @"threshold_bytes":@(*(const uint64_t *)(list + 0x210)),
            @"resource_entries":@(*(const uint32_t *)(list + 0x220)),
            @"reserve_calls":@(ReservedCalls), @"reserved_bytes":@(ReservedLength)};
        // The plug-in wrote every kernel command into the reservation before calling this native commit.
        if (ReservedStart && ReservedLength) CapturedCommands = [NSData dataWithBytes:ReservedStart length:ReservedLength];
    }));
}

static NSString *digest(NSData *data) {
    unsigned char d[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, d);
    NSMutableString *s = [NSMutableString string];
    for (unsigned i = 0; i < sizeof d; i++) [s appendFormat:@"%02x", d[i]];
    return s;
}

static void save(NSMutableDictionary *report, NSString *path, NSString *stage) {
    report[@"stage"] = stage;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:&error]) {
        fprintf(stderr, "report write: %s\n", error.description.UTF8String); exit(73);
    }
    fprintf(stderr, "stage: %s\n", stage.UTF8String); fflush(stderr);
}

static NSMutableDictionary *Artifacts;
static void artifact(NSString *dir, NSString *name, NSData *data) {
    NSError *error = nil;
    if (!data || ![data writeToFile:[dir stringByAppendingPathComponent:name] options:NSDataWritingWithoutOverwriting error:&error])
        @throw [NSException exceptionWithName:@"Artifact" reason:[NSString stringWithFormat:@"%@: %@", name, error] userInfo:nil];
    Artifacts[name] = @{@"bytes":@(data.length), @"sha256":digest(data)};
}

// What a run encodes: the same for the Adreno plug-in and for the host golden.
@interface Scene : NSObject
@property (nonatomic, copy) NSString *source, *sequence;
@property (nonatomic) BOOL load, indexed;
@property (nonatomic) NSUInteger instances, draws;
@property (nonatomic, strong) NSMutableDictionary<NSString *, id<MTLBuffer>> *buffers;
@end
@implementation Scene
@end

// The Metal sources. plan-v2 and varyings are compiler-output.m's --constants and --varyings sources verbatim,
// so their programs are the ones tools/plan-adreno-native-triangle.py planned (draw-plan-v2, draw-plan-varyings-v1).
static NSString *SourceNamed(NSString *name) {
    if ([name isEqualToString:@"triangle"]) return @"#include <metal_stdlib>\nusing namespace metal;\n"
        "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-0.8,-0.8),float2(0.8,-0.8),float2(0,0.8)}; return float4(p[i],0,1); }\n"
        "fragment float4 fs() { return float4(1,0.25,0.125,1); }\n";
    if ([name isEqualToString:@"plan-v2"]) return @"#include <metal_stdlib>\nusing namespace metal;\n"
        "constant float scale [[function_constant(0)]];\n"
        "constant uint indexBias [[function_constant(1)]];\n"
        "vertex float4 vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-1,-1),float2(1,-1),float2(0,1)}; return float4(p[i]*scale,0,1); }\n"
        "fragment float4 fs() { return float4(scale,0.5,0.75,1); }\n"
        "kernel void cs(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { out[i]=i+indexBias; }\n";
    if ([name isEqualToString:@"varyings"]) return @"#include <metal_stdlib>\nusing namespace metal;\n"
        "constant float scale [[function_constant(0)]];\n"
        "constant uint indexBias [[function_constant(1)]];\n"
        "struct V { float4 position [[position]]; float3 rgb; float2 uv; uint id [[flat]]; };\n"
        "vertex V vs(uint i [[vertex_id]]) { const float2 p[3]={float2(-1,-1),float2(1,-1),float2(0,1)}; V o; o.position=float4(p[i]*scale,0,1); o.rgb=float3(float(i)*0.25,scale,0.75); o.uv=p[i]; o.id=i; return o; }\n"
        "fragment float4 fs(V i [[stage_in]]) { return float4(i.rgb+float3(i.uv*0.125,float(i.id)*scale),1); }\n"
        "kernel void cs(device uint *out [[buffer(0)]], uint i [[thread_position_in_grid]]) { out[i]=i+indexBias; }\n";
    if ([name isEqualToString:@"uniforms"]) return @"#include <metal_stdlib>\nusing namespace metal;\n"
        "vertex float4 vs(uint i [[vertex_id]], constant float4 *points [[buffer(1)]]) { return float4(points[i].xy,0,1); }\n"
        "fragment float4 fs(constant float4 &tint [[buffer(0)]]) { return tint; }\n";
    if ([name isEqualToString:@"device"]) return @"#include <metal_stdlib>\nusing namespace metal;\n"
        "vertex float4 vs(uint i [[vertex_id]], device const float4 *points [[buffer(1)]]) { return float4(points[i].xy,0,1); }\n"
        "fragment float4 fs(constant float4 &tint [[buffer(0)]]) { return tint; }\n";
    return nil;
}

static id<MTLRenderPipelineState> Pipeline(id<MTLDevice> device, NSString *sourceName, NSMutableDictionary *report) {
    NSError *error = nil;
    NSString *source = SourceNamed(sourceName);
    report[@"metal_source"] = source;
    report[@"source_name"] = sourceName;
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
    if (!library) @throw [NSException exceptionWithName:@"TriangleLibrary" reason:error.description userInfo:nil];
    MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new];
    if ([sourceName isEqualToString:@"triangle"] || [sourceName isEqualToString:@"uniforms"] ||
        [sourceName isEqualToString:@"device"]) {
        pd.vertexFunction = [library newFunctionWithName:@"vs"];
        pd.fragmentFunction = [library newFunctionWithName:@"fs"];
    } else {
        MTLFunctionConstantValues *values = [MTLFunctionConstantValues new];
        float scale = 0.5f; uint32_t bias = 13;
        [values setConstantValue:&scale type:MTLDataTypeFloat atIndex:0];
        [values setConstantValue:&bias type:MTLDataTypeUInt atIndex:1];
        report[@"function_constants"] = @{@"0":@0.5, @"1":@13};
        pd.vertexFunction = [library newFunctionWithName:@"vs" constantValues:values error:&error];
        if (pd.vertexFunction) pd.fragmentFunction = [library newFunctionWithName:@"fs" constantValues:values error:&error];
        if (!pd.vertexFunction || !pd.fragmentFunction)
            @throw [NSException exceptionWithName:@"FunctionSpecialization" reason:error.description userInfo:nil];
    }
    pd.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    if ([sourceName isEqualToString:@"uniforms"]) {
        MTLRenderPipelineColorAttachmentDescriptor *a = pd.colorAttachments[0];     // premultiplied source-over
        a.blendingEnabled = YES;
        a.rgbBlendOperation = a.alphaBlendOperation = MTLBlendOperationAdd;
        a.sourceRGBBlendFactor = a.sourceAlphaBlendFactor = MTLBlendFactorOne;
        a.destinationRGBBlendFactor = a.destinationAlphaBlendFactor = MTLBlendFactorOneMinusSourceAlpha;
    }
    id<MTLRenderPipelineState> pipeline = [device newRenderPipelineStateWithDescriptor:pd error:&error];
    if (!pipeline) @throw [NSException exceptionWithName:@"TrianglePipeline" reason:error.description userInfo:nil];
    return pipeline;
}

static IOSurfaceRef NewSurface(NSMutableDictionary *report) {
    NSDictionary *properties = @{(id)kIOSurfaceWidth:@(kWidth), (id)kIOSurfaceHeight:@(kHeight),
        (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfaceBytesPerRow:@(kRowBytes),
        (id)kIOSurfaceAllocSize:@(kAllocation),
        (id)kIOSurfacePixelFormat:@(kFormat == MTLPixelFormatRGBA8Unorm ? 0x52474241u : 0x42475241u)};
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)properties);
    if (!surface) @throw [NSException exceptionWithName:@"Surface" reason:@"nil IOSurface" userInfo:nil];
    report[@"surface"] = @{@"width":@(IOSurfaceGetWidth(surface)), @"height":@(IOSurfaceGetHeight(surface)),
        @"row_bytes":@(IOSurfaceGetBytesPerRow(surface)), @"bytes":@(IOSurfaceGetAllocSize(surface))};
    return surface;
}

static void SeedSurface(IOSurfaceRef surface) {
    if (IOSurfaceLock(surface, 0, NULL)) @throw [NSException exceptionWithName:@"Lock" reason:@"IOSurfaceLock failed" userInfo:nil];
    void *bytes = IOSurfaceGetBaseAddress(surface);
    if (!bytes) @throw [NSException exceptionWithName:@"Base" reason:@"IOSurface CPU view absent" userInfo:nil];
    memset(bytes, 0x69, kAllocation);
    if (IOSurfaceUnlock(surface, 0, NULL)) @throw [NSException exceptionWithName:@"Unlock" reason:@"IOSurfaceUnlock failed" userInfo:nil];
}

static MTLRenderPassDescriptor *Pass(id<MTLTexture> texture, BOOL load) {
    MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor renderPassDescriptor];
    pass.colorAttachments[0].texture = texture;
    pass.colorAttachments[0].loadAction = load ? MTLLoadActionLoad : MTLLoadActionClear;
    pass.colorAttachments[0].storeAction = MTLStoreActionStore;
    pass.colorAttachments[0].clearColor = MTLClearColorMake(0.25, 0.5, 0.75, 1);
    return pass;
}

static id<MTLBuffer> Buffer(id<MTLDevice> device, const void *bytes, NSUInteger length, NSString *what) {
    id<MTLBuffer> b = bytes ? [device newBufferWithBytes:bytes length:length options:MTLResourceStorageModeShared]
                            : [device newBufferWithLength:length options:MTLResourceStorageModeShared];
    if (!b) @throw [NSException exceptionWithName:@"Buffer" reason:[what stringByAppendingString:@": nil buffer"] userInfo:nil];
    return b;
}
static void PrepareBuffers(id<MTLDevice> device, Scene *scene) {
    scene.buffers = [NSMutableDictionary dictionary];
    if ([scene.source isEqualToString:@"uniforms"])
        scene.buffers[@"fragment_buffer"] = Buffer(device, kTint, sizeof kTint, @"fragment tint buffer");
    if ([scene.source isEqualToString:@"device"]) {
        scene.buffers[@"vertex_buffer"] = Buffer(device, kPoints, sizeof kPoints, @"vertex device buffer");
    }
    if (scene.indexed) {
        const uint16_t indices[3] = {0, 1, 2};
        scene.buffers[@"index_buffer"] = Buffer(device, indices, sizeof indices, @"index buffer");
    }
    if ([scene.sequence containsString:@"fill"]) scene.buffers[@"fill_buffer"] = Buffer(device, NULL, kFillBytes, @"fill buffer");
}

// One render pass: pipeline, the source's bindings, then `draws` draws.
static void EncodePass(id<MTLCommandBuffer> command, id<MTLTexture> texture, id<MTLRenderPipelineState> pipeline,
                       Scene *scene, BOOL load, BOOL draw, BOOL later, NSMutableDictionary *report, NSString *path) {
    save(report, path, @"render-encoder-create");
    id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:Pass(texture, load)];
    if (!encoder) @throw [NSException exceptionWithName:@"Encoder" reason:@"nil encoder" userInfo:nil];
    @try {
        if (draw) {
            save(report, path, @"encode-triangle");
            [encoder setRenderPipelineState:pipeline];
            if ([scene.source isEqualToString:@"uniforms"]) {
                [encoder setVertexBytes:later ? kPoints2 : kPoints length:sizeof kPoints atIndex:1];
                [encoder setFragmentBuffer:scene.buffers[@"fragment_buffer"] offset:0 atIndex:0];
            }
            if ([scene.source isEqualToString:@"device"]) {
                [encoder setVertexBuffer:scene.buffers[@"vertex_buffer"] offset:0 atIndex:1];
                [encoder setFragmentBytes:kTint length:sizeof kTint atIndex:0];
            }
            for (NSUInteger n = 0; n < scene.draws; n++) {
                if (scene.indexed)
                    [encoder drawIndexedPrimitives:MTLPrimitiveTypeTriangle indexCount:3 indexType:MTLIndexTypeUInt16
                                       indexBuffer:scene.buffers[@"index_buffer"] indexBufferOffset:0 instanceCount:scene.instances];
                else if (scene.instances != 1)
                    [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3 instanceCount:scene.instances];
                else
                    [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
            }
        }
    } @finally {
        save(report, path, @"end-encoding");
        [encoder endEncoding];
    }
}
static void EncodeFill(id<MTLCommandBuffer> command, Scene *scene) {
    id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
    if (!blit) @throw [NSException exceptionWithName:@"Blit" reason:@"nil blit encoder" userInfo:nil];
    @try { [blit fillBuffer:scene.buffers[@"fill_buffer"] range:NSMakeRange(0, kFillBytes) value:0x5a]; }
    @finally { [blit endEncoding]; }
}
// The scene's encoder sequence; every pass after the first loads.
static void EncodeScene(id<MTLCommandBuffer> command, id<MTLTexture> texture, id<MTLRenderPipelineState> pipeline,
                        Scene *scene, NSMutableDictionary *report, NSString *path) {
    BOOL first = YES;
    for (NSString *step in [scene.sequence componentsSeparatedByString:@"-"]) {
        if ([step isEqualToString:@"fill"]) { EncodeFill(command, scene); continue; }
        EncodePass(command, texture, pipeline, scene, first ? scene.load : YES, YES, !first, report, path);
        first = NO;
    }
}

// --golden: the same scene on the host's own Metal device; the Adreno plug-in is not involved.
static void RenderGolden(Scene *scene, NSString *outDir, NSMutableDictionary *report, NSString *path) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) @throw [NSException exceptionWithName:@"HostDevice" reason:@"no host Metal device" userInfo:nil];
    report[@"golden_device"] = device.name;
    save(report, path, @"golden-pipeline");
    id<MTLRenderPipelineState> pipeline = Pipeline(device, scene.source, report);
    PrepareBuffers(device, scene);
    IOSurfaceRef surface = NewSurface(report);
    @try {
        MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:kWidth height:kHeight mipmapped:NO];
        d.storageMode = MTLStorageModeShared;
        d.usage = MTLTextureUsageRenderTarget;
        id<MTLTexture> texture = [device newTextureWithDescriptor:d iosurface:surface plane:0];
        if (!texture) @throw [NSException exceptionWithName:@"Texture" reason:@"host IOSurface texture is nil" userInfo:nil];
        SeedSurface(surface);
        save(report, path, @"golden-render");
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> command = [queue commandBuffer];
        EncodeScene(command, texture, pipeline, scene, report, path);
        [command commit];
        [command waitUntilCompleted];
        report[@"golden_command_status"] = @(command.status);
        if (command.status != MTLCommandBufferStatusCompleted)
            @throw [NSException exceptionWithName:@"HostRender" reason:command.error.description ?: @"not completed" userInfo:nil];
        if (IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL)) @throw [NSException exceptionWithName:@"Lock" reason:@"readback lock" userInfo:nil];
        NSData *all = [NSData dataWithBytes:IOSurfaceGetBaseAddress(surface) length:kAllocation];
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        NSMutableData *tight = [NSMutableData data];
        for (NSUInteger y = 0; y < kHeight; y++) [tight appendBytes:(const char *)all.bytes + y * kRowBytes length:kWidth * 4];
        artifact(outDir, @"golden.surface.bin", all);
        artifact(outDir, @"golden.bgra", tight);
    } @finally {
        CFRelease(surface);
    }
}

static NSDictionary *Role(id<MTLResource> resource, NSUInteger length) {
    return @{@"id":@([(id)resource resourceID]), @"size":@([(id)resource resourceSize]), @"length":@(length)};
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 3) return 64;
        BOOL incompatible = NO, draw = NO, commit = NO, ibABI = NO, golden = NO, rgba8 = NO;
        Scene *scene = [Scene new];
        scene.instances = scene.draws = 1;
        NSString *outDir = nil;
        BOOL instancesSet = NO, drawsSet = NO, sizeSet = NO;
        for (int i = 3; i < argc; i++) {
            const char *a = argv[i];
            if (!strcmp(a, "--incompatible") && !incompatible) incompatible = YES;
            else if (!strcmp(a, "--draw") && !draw) draw = YES;
            else if (!strcmp(a, "--commit") && !commit) commit = YES;
            else if (!strcmp(a, "--load") && !scene.load) scene.load = YES;
            else if (!strcmp(a, "--ib-abi") && !ibABI) ibABI = YES;
            else if (!strcmp(a, "--rgba8") && !rgba8) rgba8 = YES;
            else if (!strcmp(a, "--golden") && !golden) golden = YES;
            else if (!strcmp(a, "--indexed") && !scene.indexed) scene.indexed = YES;
            else if (!strcmp(a, "--source") && i + 1 < argc && !scene.source) scene.source = @(argv[++i]);
            else if (!strcmp(a, "--sequence") && i + 1 < argc && !scene.sequence) scene.sequence = @(argv[++i]);
            else if (!strcmp(a, "--out") && i + 1 < argc && !outDir) outDir = @(argv[++i]);
            else if (!strcmp(a, "--size") && i + 2 < argc && !sizeSet) {
                char *end1 = NULL, *end2 = NULL;
                unsigned long w = strtoul(argv[i + 1], &end1, 10), h = strtoul(argv[i + 2], &end2, 10);
                if (!end1 || *end1 || !end2 || *end2 || !w || !h || w > 4096 || h > 4096) return 64;
                kWidth = w; kHeight = h; kRowBytes = (4 * w + 63) & ~63ul; kAllocation = (kRowBytes * h + 16383) & ~16383ul;
                sizeSet = YES; i += 2;
            }
            else if ((!strcmp(a, "--instances") && !instancesSet) || (!strcmp(a, "--draws") && !drawsSet)) {
                BOOL instances = !strcmp(a, "--instances");
                if (i + 1 >= argc) return 64;
                char *end = NULL; unsigned long n = strtoul(argv[++i], &end, 10);
                if (!end || *end || !n || n > 1024) return 64;
                if (instances) { scene.instances = n; instancesSet = YES; } else { scene.draws = n; drawsSet = YES; }
            } else return 64;
        }
        // The single-flag modes keep their original meaning; the extended flags need an output directory.
        BOOL extended = scene.load || ibABI || scene.indexed || scene.source || scene.sequence || outDir || instancesSet ||
                        drawsSet || sizeSet || golden || (draw && commit) || rgba8;
        if (incompatible && argc != 4) return 64;
        // --commit --out DIR (no --draw): the clear-only commit also saves its kernel commands.
        BOOL clearCapture = commit && !draw && outDir && !golden && !scene.load && !scene.indexed && !scene.source &&
                            !scene.sequence && !instancesSet && !drawsSet && !sizeSet;
        if (rgba8 && !clearCapture) return 64;
        if (rgba8) kFormat = MTLPixelFormatRGBA8Unorm;
        if (extended && !clearCapture &&
            (!outDir || incompatible || (golden && (draw || commit || ibABI)) || (!golden && !(draw && commit))))
            return 64;
        if (!scene.source) scene.source = @"triangle";
        if (!scene.sequence) scene.sequence = @"draw";
        if (!SourceNamed(scene.source) ||
            ![@[@"draw", @"fill-draw", @"draw-fill", @"draw-fill-draw", @"draw-draw"] containsObject:scene.sequence]) return 64;
        NSString *bundlePath = @(argv[1]), *path = @(argv[2]);
        NSFileManager *fm = [NSFileManager defaultManager];
        if (!bundlePath.isAbsolutePath || !path.isAbsolutePath || [fm fileExistsAtPath:path]) return 64;
        if (outDir && (!outDir.isAbsolutePath || [fm fileExistsAtPath:outDir] ||
                       ![fm createDirectoryAtPath:outDir withIntermediateDirectories:NO attributes:nil error:NULL])) return 64;
        Artifacts = [NSMutableDictionary dictionary];
        NSMutableDictionary *report = [@{@"status":@"RUNNING", @"pid":@(getpid()),
            @"bundle":bundlePath, @"gpu_submission":@NO,
            @"draw_requested":@(draw), @"commit_requested":@(commit), @"golden_requested":@(golden),
            @"load_action":scene.load ? @"load" : @"clear", @"ib_abi_simulated":@(ibABI),
            @"indexed_draw":@(scene.indexed), @"instance_count":@(scene.instances), @"draws_per_pass":@(scene.draws),
            @"sequence":scene.sequence, @"artifacts":Artifacts,
            @"target":@{@"width":@(kWidth), @"height":@(kHeight), @"row_bytes":@(kRowBytes), @"allocation":@(kAllocation),
                       @"format":@(kFormat)},
            @"boundary":golden ? @"Host Metal device render of the same scene (the golden). No Adreno plug-in, no Adreno hardware."
                               : @"Host native allocation using an AGX provider. No Adreno hardware execution."} mutableCopy];
        if (outDir) report[@"out"] = outDir;
        io_service_t accelerator = 0;
        IOSurfaceRef surface = NULL;
        int result = 1;
        @try {
            if (golden) {
                RenderGolden(scene, outDir, report, path);
                report[@"status"] = @"HOST_METAL_GOLDEN_RENDERED";
                result = 0;
                return result;
            }
            save(report, path, @"device-init");
            (void)MTLCopyAllDevices();
            NSError *error = nil;
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            if (![bundle loadAndReturnError:&error]) @throw [NSException exceptionWithName:@"BundleLoad" reason:error.description userInfo:nil];
            if (ibABI) {
                Class commandBuffer = [bundle classNamed:@"AdrenoCommandBuffer"];
                if (!commandBuffer) @throw [NSException exceptionWithName:@"BundleLoad" reason:@"no AdrenoCommandBuffer" userInfo:nil];
                BOOL implemented = class_getInstanceMethod(commandBuffer, @selector(adrenoDrawAvailable)) != NULL;
                class_replaceMethod(commandBuffer, @selector(adrenoDrawAvailable), imp_implementationWithBlock(^BOOL(id command) {
                    return YES;
                }), "B16@0:8");
                report[@"ib_abi_hook"] = implemented ? @"adrenoDrawAvailable replaced" : @"adrenoDrawAvailable absent (added, unused)";
            }
            accelerator = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            if (!accelerator) @throw [NSException exceptionWithName:@"Provider" reason:@"no host accelerator" userInfo:nil];
            id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:accelerator];
            if (!device) @throw [NSException exceptionWithName:@"DeviceInit" reason:@"nil device" userInfo:nil];
            MTLAddDevice(device);
            report[@"device_class"] = @(object_getClassName(device));
            save(report, path, @"iosurface-create");
            surface = NewSurface(report);
            save(report, path, @"texture-descriptor");
            MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:kFormat width:kWidth height:kHeight mipmapped:NO];
            d.storageMode = MTLStorageModeShared;
            d.usage = incompatible ? MTLTextureUsageShaderRead : MTLTextureUsageRenderTarget;
            save(report, path, @"texture-create");
            id<MTLTexture> texture = [device newTextureWithDescriptor:d iosurface:surface plane:0];
            if (!texture) @throw [NSException exceptionWithName:@"Texture" reason:@"native allocation returned nil; host provider may reject vendor args" userInfo:nil];
            save(report, path, @"texture-identity");
            report[@"texture"] = @{@"class":@(object_getClassName(texture)), @"width":@(texture.width),
                @"height":@(texture.height), @"format":@(texture.pixelFormat), @"storage":@(texture.storageMode)};
            if (texture.device != device || texture.width != kWidth || texture.height != kHeight ||
                texture.pixelFormat != kFormat || texture.storageMode != MTLStorageModeShared)
                @throw [NSException exceptionWithName:@"TextureIdentity" reason:@"unexpected native texture metadata" userInfo:nil];
            save(report, path, @"texture-label");
            texture.label = @"Snapintosh GPU image clear with padded rows";
            save(report, path, @"iosurface-lock");
            SeedSurface(surface);
            save(report, path, @"queue-create");
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (!queue) @throw [NSException exceptionWithName:@"Queue" reason:@"nil queue" userInfo:nil];
            save(report, path, @"command-create");
            id<MTLCommandBuffer> command = [queue commandBuffer];
            if (!command || !command.retainedReferences) @throw [NSException exceptionWithName:@"Command" reason:@"nil/unretained command" userInfo:nil];
            command.label = @"Snapintosh public Metal GPU texture clear";
            report[@"native_texture_properties"] = @{@"type":@(texture.textureType), @"samples":@(texture.sampleCount),
                @"mips":@(texture.mipmapLevelCount), @"array_length":@(texture.arrayLength),
                @"depth":@(texture.depth), @"usage":@(texture.usage),
                @"native_class":@([texture isKindOfClass:NSClassFromString(@"IOGPUMetalTexture")]),
                @"linear_selector":@([texture respondsToSelector:@selector(adrenoGetLinearLayout:)])};
            AdrenoLinearTextureLayout layout = {0};
            BOOL linear = [(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&layout];
            report[@"linear_layout"] = @{@"known":@(linear), @"row_bytes":@(layout.rowBytes),
                @"width":@(layout.width), @"height":@(layout.height), @"allocation":@(layout.allocationBytes)};
            id<MTLRenderPipelineState> pipeline = nil;
            if (draw) {
                save(report, path, @"compile-triangle");
                pipeline = Pipeline(device, scene.source, report);
                report[@"pipeline_class"] = @(object_getClassName(pipeline));
                id vertex = [(id)pipeline valueForKey:@"vertexCode"], fragment = [(id)pipeline valueForKey:@"fragmentCode"];
                report[@"shader_bytes"] = @{@"vertex":@([[vertex valueForKey:@"machineCode"] length]),
                    @"fragment":@([[fragment valueForKey:@"machineCode"] length])};
                report[@"program_linkage"] = [(id)pipeline valueForKey:@"programLinkage"];
                PrepareBuffers(device, scene);
                EncodeScene(command, texture, pipeline, scene, report, path);
            } else {
                EncodePass(command, texture, nil, scene, scene.load, NO, NO, report, path);
            }
            report[@"command_status"] = @(command.status);
            report[@"status"] = draw ? @"NATIVE_DRAW_ENCODED_NOT_SUBMITTED" : @"NATIVE_CLEAR_ENCODED_NOT_SUBMITTED";
            if (draw && commit) {
                // What the kext would resolve: the pipeline's code buffers, the target and the scene's buffers,
                // by IOGPU resource ID.
                id program = [(id)pipeline valueForKey:@"adrenoDrawProgram"];
                id<MTLBuffer> vsCode = [program valueForKey:@"vertexCodeBuffer"], fsCode = [program valueForKey:@"fragmentCodeBuffer"];
                if (!vsCode || !fsCode) @throw [NSException exceptionWithName:@"DrawProgram" reason:@"pipeline has no code buffers" userInfo:nil];
                artifact(outDir, @"vs.code.bin", [NSData dataWithBytes:vsCode.contents length:vsCode.length]);
                artifact(outDir, @"fs.code.bin", [NSData dataWithBytes:fsCode.contents length:fsCode.length]);
                artifact(outDir, @"vertex.program.json", [[(id)pipeline valueForKey:@"vertexCode"] valueForKey:@"programData"]);
                artifact(outDir, @"fragment.program.json", [[(id)pipeline valueForKey:@"fragmentCode"] valueForKey:@"programData"]);
                artifact(outDir, @"linkage.json", [NSJSONSerialization dataWithJSONObject:report[@"program_linkage"] options:NSJSONWritingSortedKeys error:NULL]);
                NSMutableDictionary *roles = [@{@"target":@{@"id":@([(id)texture resourceID]), @"size":@([(id)texture resourceSize]),
                        @"row_bytes":@(kRowBytes), @"width":@(kWidth), @"height":@(kHeight)},
                    @"vs_code":Role(vsCode, vsCode.length), @"fs_code":Role(fsCode, fsCode.length)} mutableCopy];
                for (NSString *name in scene.buffers) {
                    id<MTLBuffer> b = scene.buffers[name];
                    roles[name] = Role(b, b.length);
                    artifact(outDir, [name stringByAppendingString:@".bin"], [NSData dataWithBytes:b.contents length:b.length]);
                }
                report[@"resource_roles"] = roles;
                save(report, path, @"commit-captured");
                InstallCommitCapture();
                [command commit];
                uint64_t memsize = 0; size_t length = sizeof memsize;
                if (sysctlbyname("hw.memsize", &memsize, &length, NULL, 0)) memsize = 0;
                report[@"commit"] = CapturedCommit ?: @{@"reached_native_commit":@NO};
                if (![CapturedCommit[@"reached_native_commit"] boolValue] || !CapturedCommands ||
                    [CapturedCommit[@"threshold_bytes"] unsignedLongLongValue] != memsize)
                    @throw [NSException exceptionWithName:@"CommitCapture" reason:@"no native commit or kernel commands captured" userInfo:nil];
                artifact(outDir, @"commands.bin", CapturedCommands);
                // The records AdrenoResourceUsage published into this segment's IOGPU resource list, in order.
                Ivar usageIvar = class_getInstanceVariable(object_getClass(command), "_adrenoResources");
                id usage = usageIvar ? object_getIvar(command, usageIvar) : nil;
                Ivar recordsIvar = usage ? class_getInstanceVariable(object_getClass(usage), "_records") : NULL;
                NSData *records = recordsIvar ? object_getIvar(usage, recordsIvar) : nil;
                if (!records || records.length % 32) @throw [NSException exceptionWithName:@"ResourceRecords" reason:@"no published resource records" userInfo:nil];
                NSMutableArray *published = [NSMutableArray array];
                uint64_t consumed = 0;
                for (NSUInteger at = 0; at < records.length; at += 32) {
                    const uint8_t *r = (const uint8_t *)records.bytes + at;
                    uint64_t sizeAndField; uint32_t rid, use;
                    memcpy(&sizeAndField, r + 8, 8); memcpy(&rid, r + 16, 4); memcpy(&use, r + 24, 4);
                    uint64_t size = sizeAndField & 0x00ffffffffffffffull;
                    consumed += (size + 1023) & ~1023ull;
                    [published addObject:@{@"id":@(rid), @"size":@(size), @"usage":@(use)}];
                }
                artifact(outDir, @"resources.json", [NSJSONSerialization dataWithJSONObject:@{@"published":published, @"roles":roles}
                                                                                     options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL]);
                report[@"published_resources"] = published;
                // +0x220 counts descriptor groups, not resources: a group carries at most six entries
                // (docs/ADRENO-SUBMISSION-RESOURCES-20260926.md); the one-texture clear's 1 is both.
                if ([CapturedCommit[@"resource_entries"] unsignedIntegerValue] != (published.count + 5) / 6 ||
                    [CapturedCommit[@"remaining_bytes"] unsignedLongLongValue] != memsize - consumed)
                    @throw [NSException exceptionWithName:@"CommitCapture" reason:@"native segment list differs from the published records" userInfo:nil];
                report[@"status"] = @"NATIVE_DRAW_COMMIT_CAPTURED_NOT_SUBMITTED";
            } else if (commit) {
                save(report, path, @"commit-captured");
                InstallCommitCapture();
                [command commit];
                uint64_t memsize = 0; size_t length = sizeof memsize;
                if (sysctlbyname("hw.memsize", &memsize, &length, NULL, 0)) memsize = 0;
                report[@"commit"] = CapturedCommit ?: @{@"reached_native_commit":@NO};
                // One 32768-byte IOSurface texture: budget = hw.memsize, one entry, KiB-rounded size consumed.
                if (![CapturedCommit[@"reached_native_commit"] boolValue] ||
                    [CapturedCommit[@"resource_entries"] unsignedIntValue] != 1 ||
                    [CapturedCommit[@"threshold_bytes"] unsignedLongLongValue] != memsize ||
                    [CapturedCommit[@"remaining_bytes"] unsignedLongLongValue] != memsize - 32768)
                    @throw [NSException exceptionWithName:@"CommitCapture" reason:@"unexpected native segment resource list" userInfo:nil];
                if (outDir && CapturedCommands) artifact(outDir, @"commands.bin", CapturedCommands);
                report[@"status"] = @"NATIVE_CLEAR_COMMIT_CAPTURED_NOT_SUBMITTED";
            }
            report[@"gpu_submission"] = @NO;
            result = 0;
        } @catch (NSException *e) {
            report[@"status"] = @"NATIVE_TEXTURE_EXCEPTION";
            report[@"exception"] = @{@"name":e.name?:@"", @"reason":e.reason?:@""};
            result = 2;
        } @finally {
            save(report, path, @"finished");
            if (surface) CFRelease(surface);
            if (accelerator) IOObjectRelease(accelerator);
        }
        return result;
    }
}
