/* SPDX-License-Identifier: MIT */
// AdrenoMTLObjects.h - the object classes a third-party IOGPU-family Metal driver provides.
// Hierarchy mirrors what Apple's own IOGPU-family plug-ins use (AppleParavirt*, AGX*):
//   AdrenoCommandQueue          : IOGPUMetalCommandQueue          : _MTLCommandQueue
//   AdrenoCommandBuffer         : IOGPUMetalCommandBuffer         : _MTLCommandBuffer
//   AdrenoRenderCommandEncoder  : IOGPUMetalRenderCommandEncoder  : IOGPUMetalCommandEncoder : _MTLCommandEncoder
//   AdrenoBlitCommandEncoder    : IOGPUMetalBlitCommandEncoder
//   AdrenoComputeCommandEncoder : IOGPUMetalComputeCommandEncoder
//   AdrenoBuffer                : IOGPUMetalBuffer  : IOGPUMetalResource : _MTLResource
//   AdrenoTexture               : IOGPUMetalTexture : IOGPUMetalResource
//   AdrenoSamplerState          : _MTLSamplerState
//   AdrenoDepthStencilState     : _MTLDepthStencilState
#pragma once
#import "AdrenoMetalSPI.h"
#import "AdrenoLinearTexture.h"
#include "../../include/AdrenoContract.h"

NS_ASSUME_NONNULL_BEGIN

// Resource, queue and vendor command layouts are shared with the kext.

@interface AdrenoCommandQueue : IOGPUMetalCommandQueue <MTLCommandQueue> @end
@interface AdrenoCommandBuffer : IOGPUMetalCommandBuffer <MTLCommandBuffer> @end
@interface AdrenoRenderCommandEncoder : IOGPUMetalRenderCommandEncoder <MTLRenderCommandEncoder> @end
@interface AdrenoBlitCommandEncoder : IOGPUMetalBlitCommandEncoder <MTLBlitCommandEncoder> @end
@interface AdrenoComputeCommandEncoder : IOGPUMetalComputeCommandEncoder <MTLComputeCommandEncoder> @end
@interface AdrenoBuffer : IOGPUMetalBuffer <MTLBuffer> @end
@interface AdrenoTexture : IOGPUMetalTexture <MTLTexture, AdrenoLinearTexture> @end
@interface AdrenoSamplerState : _MTLSamplerState <MTLSamplerState> @end
@interface AdrenoDepthStencilState : _MTLDepthStencilState <MTLDepthStencilState> @end

id<MTLBuffer> _Nullable AdrenoNewBuffer(id<MTLDevice> dev, void *_Nullable bytesNoCopy, NSUInteger len,
                                        MTLResourceOptions opts, void (^_Nullable dealloc)(void *, NSUInteger));
id<MTLBuffer> _Nullable AdrenoNewBufferWithIOSurface(id<MTLDevice> dev, IOSurfaceRef s);
id<MTLTexture> _Nullable AdrenoNewTexture(id<MTLDevice> dev, MTLTextureDescriptor *d, IOSurfaceRef _Nullable s, NSUInteger plane);
id<MTLTexture> _Nullable AdrenoNewTextureNoCopy(id<MTLDevice> dev, MTLTextureDescriptor *d, void *bytes, NSUInteger len,
                                                void (^_Nullable dealloc)(void *, NSUInteger));
// IOGPU returned nil for a plausible allocation: under GPU address exhaustion that is the kext's refused allocation
// (-82). Drains the UBO staging-arena pool (AdrenoDrawCommands.m) and starts its pressure window; YES when something
// was released, so one retry may succeed (docs/PLUGIN-ARENA-TRIM-20261021.md, A8). AdrenoStagingRetried counts the retry.
BOOL AdrenoStagingRelieveAfterFailure(void);
void AdrenoStagingRetried(BOOL succeeded);

NS_ASSUME_NONNULL_END
