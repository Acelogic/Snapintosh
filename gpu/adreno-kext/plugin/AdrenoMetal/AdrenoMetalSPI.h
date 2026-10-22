/* SPDX-License-Identifier: MIT */
// AdrenoMetalSPI.h - private Metal / IOGPU declarations a third-party Metal driver bundle builds against.
//
// Source of truth: macOS 27 26A428 (host = guest build). Class/selector shapes come from
//   scratchpad/adreno/macos-gpu-abi/{metal,iogpu}-headers (ipsw class-dump of the 26A428 dyld cache)
// and were checked at runtime on the M3 Max (see ../harness/regtest.m).
//
// Linking: _MTLDevice/_MTLCommandQueue/... and _MTLAddDevice are exported by the SDK Metal.tbd.
// IOGPUMetal* classes are exported by IOGPU.framework (private); link with ./IOGPU.tbd.
#pragma once
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>

NS_ASSUME_NONNULL_BEGIN

// ---- Protocols. conformsToProtocol: matches protocols by name, so this local re-declaration satisfies the
// MTLDeviceSPI checks in IOGPUMetalDevice init and MTLAddDevice once the concrete class adopts it.
@protocol MTLDeviceSPI <MTLDevice>
@end

// ---- Metal.framework base classes (abstract; the plug-in never instantiates them directly).
@interface _MTLDevice : NSObject
- (void)initLimits;            // called by MTLAddDevice (Metal 0x18b67a68c)
- (void)initFeatureQueries;    // called by MTLAddDevice (Metal 0x18b67a698)
- (void)initWorkarounds;       // called by MTLAddDevice (Metal 0x18b67a6a4)
- (unsigned long long)featureProfile;
@end
@interface _MTLCommandQueue : NSObject @end
@interface _MTLCommandBuffer : NSObject @end
@interface _MTLCommandEncoder : NSObject @end
@interface _MTLSamplerState : NSObject
- (instancetype)initWithDevice:(id<MTLDevice>)device samplerDescriptor:(MTLSamplerDescriptor *)desc;
@end
@interface _MTLDepthStencilState : NSObject
- (instancetype)initWithDevice:(id<MTLDevice>)device depthStencilDescriptor:(MTLDepthStencilDescriptor *)desc;
@end

// MTLCompiler: the in-process front half of the shader compiler; it talks XPC to MTLCompilerService,
// which dlopen()s `pluginPath` (or runs pass-through when pluginPath == "simulatorDummyPlugin").
// AppleParavirtDevice -setupCompiler (bundle +0x1d408) is the template:
//   targetData = dispatch_data(8 bytes of device target info), cacheUUID = SHA256(__DATE__ __TIME__),
//   pluginPath = <bundle>/Contents/Resources/lib<Vendor>CompilerPlugin.dylib, compilerFlags = 0x24.
@interface MTLCompiler : NSObject
- (nullable instancetype)initWithTargetData:(dispatch_data_t)targetData
                                  cacheUUID:(const unsigned char *)uuid32
                                 pluginPath:(NSString *)pluginPath
                                     device:(id<MTLDevice>)device
                              compilerFlags:(unsigned int)flags;
@end

// ---- IOGPU.framework base classes (the IOGPU-family user-space driver layer).
@interface IOGPUMetalDevice : _MTLDevice
// Opens the IOGPUDeviceUserClient on `port` (an io_service_t for our IOAccelerator subclass),
// creates shmem pools, dispatch queues, suballocator. Returns nil if IOGPUDeviceCreateWithOptions fails.
- (nullable instancetype)initWithAcceleratorPort:(io_service_t)port;
- (nullable instancetype)initWithAcceleratorPort:(io_service_t)port options:(unsigned long long)options;
- (io_service_t)acceleratorPort;
@end
@interface IOGPUMetalCommandQueue : _MTLCommandQueue
- (nullable instancetype)initWithDevice:(id<MTLDevice>)device descriptor:(MTLCommandQueueDescriptor *)desc;
@end
@interface IOGPUMetalCommandBuffer : _MTLCommandBuffer
- (nullable instancetype)initWithQueue:(id<MTLCommandQueue>)queue retainedReferences:(BOOL)retained;
// 26A428 runtime encodings/code: build/adreno-guest-submit-20260926/user-abi-v2.json.
- (void)commit;
- (void)waitUntilCompleted;                                     // _MTLCommandBuffer's
- (void)addCompletedHandler:(MTLCommandBufferHandler)block;     // _MTLCommandBuffer's
- (void)endCurrentSegment;
- (nullable void *)_reserveKernelCommandBufferSpace:(NSUInteger)length;
- (void)beginSegment:(void *)start;
- (void *)ioGPUResourceList;
- (nullable id)akResourceList;
@end
@interface IOGPUMetalCommandEncoder : _MTLCommandEncoder
- (nullable instancetype)initWithCommandBuffer:(id<MTLCommandBuffer>)cb;
- (void)endEncoding;
@end
@interface IOGPUMetalRenderCommandEncoder : IOGPUMetalCommandEncoder
- (nullable instancetype)initWithCommandBuffer:(id<MTLCommandBuffer>)cb descriptor:(MTLRenderPassDescriptor *)rp;
@end
@interface IOGPUMetalBlitCommandEncoder : IOGPUMetalCommandEncoder @end
@interface IOGPUMetalComputeCommandEncoder : IOGPUMetalCommandEncoder @end
@interface IOGPUMetalResource : NSObject
- (id)device;
- (uint32_t)resourceID;
- (uint64_t)resourceSize;
@end
@interface IOGPUMetalBuffer : IOGPUMetalResource @end
@interface IOGPUMetalTexture : IOGPUMetalResource @end
@interface IOGPUMetalHeap : NSObject @end

// Exported by Metal (SDK Metal.tbd lists _MTLAddDevice). Asserts MTLDevice + MTLDeviceSPI conformance,
// then runs initLimits / initFeatureQueries / initWorkarounds and appends to the process device array.
extern void MTLAddDevice(id<MTLDevice> device);

NS_ASSUME_NONNULL_END
