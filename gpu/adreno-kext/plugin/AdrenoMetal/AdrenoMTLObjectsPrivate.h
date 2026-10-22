/* SPDX-License-Identifier: MIT */
// AdrenoMTLObjectsPrivate.h - declarations shared between the plug-in's object files
// (AdrenoResources.m, AdrenoCommandBuffer.m, AdrenoRenderEncoder.m, AdrenoBlitEncoder.m,
// AdrenoComputeEncoder.m). Not part of the plug-in's exported contract.
#pragma once
#import "AdrenoMTLObjects.h"

NS_ASSUME_NONNULL_BEGIN

@class AdrenoComputePass, AdrenoBlitPass;

// Command-buffer entry points the encoders record into (implemented in AdrenoCommandBuffer.m).
@interface AdrenoCommandBuffer (ResourceEncoding)
- (void)adrenoUseResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage;
- (void)adrenoFillBuffer:(id<MTLBuffer>)buffer range:(NSRange)range value:(uint8_t)value;
- (void)adrenoClearPass:(MTLRenderPassDescriptor *)pass;
- (void)adrenoClearPass:(MTLRenderPassDescriptor *)pass refusal:(nullable NSString *)refusal;
- (void)adrenoRejectShaderDraw;
- (void)adrenoAppendComputePass:(AdrenoComputePass *)pass;
- (void)adrenoAppendBlitPass:(AdrenoBlitPass *)pass;
@end

// Per-command-buffer work accounting. Encoded is not GPU-complete or presented.
@interface AdrenoCommandBuffer (WorkAccounting)
- (void)adrenoFailEncoding;
- (uint64_t)adrenoBeginEncoder:(NSString *)kind details:(NSDictionary *)details;
- (void)adrenoEndEncoder:(uint64_t)encoder;
- (void)adrenoRecordWork:(NSString *)operation encoder:(uint64_t)encoder omitted:(BOOL)omitted details:(NSDictionary *)details;
- (NSDictionary *)adrenoWorkReport;
@end

// ---- private IOGPU initialisers we call (selectors from the 26A428 class-dump; struct args passed as void*)
@interface IOGPUMetalCommandQueue (AdrenoPrivate)
- (nullable instancetype)initWithDevice:(id)d descriptor:(MTLCommandQueueDescriptor *)desc
                                   args:(void *)args argsSize:(unsigned)sz;
@end
@interface IOGPUMetalBuffer (AdrenoPrivate)
- (nullable instancetype)initWithDevice:(id)d pointer:(nullable void *)p length:(NSUInteger)len alignment:(unsigned)al
                                options:(NSUInteger)o sysMemSize:(NSUInteger)sms gpuAddress:(uint64_t)ga
                                   args:(void *)args argsSize:(unsigned)sz deallocator:(nullable id)dealloc;
- (nullable instancetype)initWithDevice:(id)d iosurface:(IOSurfaceRef)s args:(void *)args argsSize:(unsigned)sz;
@end
@interface IOGPUMetalTexture (AdrenoPrivate)
- (MTLTextureUsage)usage;
- (nullable instancetype)initWithDevice:(id)d descriptor:(MTLTextureDescriptor *)td iosurface:(IOSurfaceRef)s
                                  plane:(unsigned)plane field:(unsigned)field args:(void *)args argsSize:(unsigned)sz;
- (nullable instancetype)initWithDevice:(id)d descriptor:(MTLTextureDescriptor *)td sysMemSize:(uint64_t)sms
                         sysMemRowBytes:(uint64_t)rb vidMemSize:(uint64_t)vms vidMemRowBytes:(uint64_t)vrb
                                   args:(void *)args argsSize:(unsigned)sz;
- (nullable instancetype)initWithDevice:(id)d descriptor:(MTLTextureDescriptor *)td sysMemPointer:(void *)p
                             sysMemSize:(uint64_t)s sysMemLength:(uint64_t)l sysMemRowBytes:(uint64_t)rb
                                   args:(void *)a argsSize:(unsigned)sz deallocator:(nullable id)dealloc;
- (nullable instancetype)initWithTexture:(id)t pixelFormat:(MTLPixelFormat)f textureType:(MTLTextureType)tt
                                  levels:(NSRange)lv slices:(NSRange)sl;
- (nullable instancetype)initWithTexture:(id)t pixelFormat:(MTLPixelFormat)f;
- (nullable instancetype)initWithBuffer:(id)b descriptor:(MTLTextureDescriptor *)td offset:(NSUInteger)o bytesPerRow:(NSUInteger)bpr;
@end
@interface IOGPUMetalResource (AdrenoPrivate)
- (nullable void *)virtualAddress;   // CPU mapping of a sysmem allocation; NULL for private storage
@end
@interface AdrenoTexture (DescriptorUsage)
- (void)adrenoSetUsage:(MTLTextureUsage)usage;
- (void)adrenoSetLinearDescriptor:(MTLTextureDescriptor *)descriptor rowBytes:(NSUInteger)rowBytes
                          offset:(NSUInteger)offset available:(NSUInteger)bytes;
- (void)adrenoSetLinearSurface:(IOSurfaceRef)surface descriptor:(MTLTextureDescriptor *)descriptor plane:(NSUInteger)plane;
- (void)adrenoInheritLinearFrom:(AdrenoTexture *)parent format:(MTLPixelFormat)format whole:(BOOL)whole;
- (void)adrenoSetLinearUnknown:(NSString *)why;
- (NSString *)adrenoLayoutDescription;
@end

// ---- Linear subresource layout of a texture allocation (AdrenoResources.m).
// This is the plug-in's definition of where each (level, slice) of a linear texture lives; the CPU copy
// paths use it today, and any GPU texture/attachment descriptor for level > 0 or slice > 0 must use it too.
//   rowBytes(L)   = L == 0 && rowBytes0 ? rowBytes0 : align(max(1, width >> L) * bpp, 64)
//   levelBytes(L) = rowBytes(L) * max(1, height >> L) * (3D ? max(1, depth >> L) : 1)
//   chainBytes    = sum of levelBytes over all levels
//   sliceStride   = slices > 1 ? align(chainBytes, 4096) : chainBytes   (slices = arrayLength, x6 for cubes)
//   offset(L, s)  = s * sliceStride + sum of levelBytes(l < L)
// Level 0 of slice 0 is at offset 0 with rowBytes0, which is the AdrenoLinearTextureLayout the clear path uses.
typedef struct {
    MTLTextureType type;
    NSUInteger width, height, depth, levels, slices, bytesPerPixel, rowBytes0;
} AdrenoTextureGeometry;
typedef struct {
    NSUInteger offset, rowBytes, imageBytes, width, height, depth;
} AdrenoSubresourceLayout;
AdrenoSubresourceLayout AdrenoTextureSubresource(const AdrenoTextureGeometry *g, NSUInteger level, NSUInteger slice);
NSUInteger AdrenoTextureAllocationBytes(const AdrenoTextureGeometry *g);

@interface AdrenoTexture (CPUView)
// Root allocation CPU view: p is (level 0, slice 0) of geometry g, with `bytes` addressable bytes.
- (void)adrenoSetCPU:(nullable void *)p bytes:(NSUInteger)bytes geometry:(const AdrenoTextureGeometry *)g;
@end

NS_ASSUME_NONNULL_END

// ADRENO_LENIENT (AdrenoCommandBuffer.m): log a dropped pass or draw once per reason.
void AdrenoLogDropped(NSString *_Nullable reason);
// A used fragment texture left unbound reads the zero page's transparent black: logged once per function and argument.
void AdrenoLogZeroTexture(NSString *_Nullable function, NSString *_Nullable argument, NSInteger index);
// Work diagnostics (AdrenoCommandBuffer.m): the per-process diagnostics file /private/var/tmp/adreno-NAME-PID.log, readable
// from the next boot's single-user shell without launchd or logd: drop and refusal reasons once each, and every 15 s a
// stats line of these counters. Work records are active in strict and lenient builds.
typedef NS_ENUM(unsigned, AdrenoDiagCounter) {
    AdrenoDiagCommits, AdrenoDiagPackages, AdrenoDiagDrops, AdrenoDiagRefusals, AdrenoDiagCPUCopies, AdrenoDiagCPUCopyBytes,
    AdrenoDiagComputeDispatches, AdrenoDiagTileDispatches, AdrenoDiagCommitMicros, AdrenoDiagCounterCount
};
void AdrenoDiagAdd(AdrenoDiagCounter counter, uint64_t amount);
void AdrenoDiagLine(NSString *_Nullable line);
