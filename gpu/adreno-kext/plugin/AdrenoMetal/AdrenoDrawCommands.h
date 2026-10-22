/* SPDX-License-Identifier: MIT */
// AdrenoDrawCommands.h - a8xx sysmem draw packets for ADRENO_KCMD_IB packages (design S3, plug-in side).
//
// A function-for-function port of q1n1's hardware-proven command builder (tools/a16gpu_render.py build_ib and
// its helpers in tools/a16gpu_p6p7.py: emit_restore, emit_gmem_cache_cntl_sysmem, emit_static_binning_regs,
// emit_lrz_off, emit_flushes, emit_2d_clear, program_config, shader_regs, program_linkage, interp_regs, guardband)
// and of BINDING-ABI v6's command-stream half (tools/a16gpu_bindings.py: ubo_table, driver_table, texture_counts,
// vertex_attributes), plus plan-adreno-native-triangle.py's separate driver constant-data UBO load and
// build_p7_ib's sysmem 2D clear. Every register, field, packet dword, descriptor and enum comes from the generated
// AdrenoA8xxRegs.h; values are range-checked the way q1n1's pack() refuses them.
//
// Differences from q1n1's single-draw IB, by design (compat/adreno-submit.h, design 5.3):
//  - no batch fence (emit_ib_fence): user IBs carry no CP memory write; the monitor's ring words fence;
//  - every GPU address is a zero placeholder plus an adreno_ib_reloc naming an IOGPU resource ID, the package
//    itself or the kext zero page (border colours, empty bindless sets); the kext resolves and patches it;
//  - a render pass is one prologue (restore, sysmem prep, sysmem, the 2D clear for MTLLoadActionClear), then the
//    draw section once per draw, then one epilogue.
// Built: one linear BGRA8 colour attachment (level 0, 64-byte rows), Clear/Load/DontCare, Store/DontCare; triangle
// lists and strips, instancing, UInt16 indices, vertexStart; vertex_id/instance_id, varyings (smooth and flat);
// application UBOs from MTLBuffers (64-byte aligned offsets) or setBytes (copied into the package), device buffers
// through the driver table, the driver constant-data UBO; float stage_in attributes from one per-vertex buffer
// (ported, not yet reachable: pipelines with a vertex descriptor are refused before this, see AdrenoPipeline.m);
// blending with zero/one/src-alpha/dst-alpha factors; viewport, scissor, winding, blend colour.
// Explicitly refused ("not yet"): fragment textures and samplers, framebuffer fetch, XR/lowered attachments,
// depth/stencil attachments, MSAA, layered rendering, more than one colour attachment or non-BGRA8 targets, culling,
// line fill, depth clamp, depth bias, visibility results, write masks other than All, 32-bit indices, non-triangle
// primitives, attributes from several vertex buffers or non-float formats, a render pass larger than one package
// (design 2.3b's mid-pass split), and everything B.check_variant refuses (private memory, driver params, SSBOs...).
#pragma once
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import "AdrenoMTLObjects.h"

NS_ASSUME_NONNULL_BEGIN

// The kext publishes AdrenoIBABI = ADRENO_GUEST_IB_ABI on the accelerator only when the monitor's IB HVC and the
// start-time probe work (AdrenoContract.h). Without it render pipelines stay refused. Read once per device.
BOOL AdrenoDrawSubmissionAvailable(id<MTLDevice> device);

#define ADRENO_DRAW_BUFFER_SLOTS 31u
#define ADRENO_DRAW_TEXTURE_SLOTS 31u
#define ADRENO_DRAW_SAMPLER_SLOTS 16u
// Two relocations and six packet dwords per copy. The implementation pins this
// bound to the shared 16384-relocation and IB-size limits before any emission.
#define ADRENO_BLIT_MAX_SPANS 8192u

// One setVertex*/setFragment* buffer slot. The encoder owns the objects; a draw only borrows them.
typedef struct {
    __unsafe_unretained id<MTLBuffer> _Nullable buffer;   // setBuffer:offset:atIndex:
    __unsafe_unretained NSData *_Nullable bytes;          // setBytes:length:atIndex: (copied by the encoder)
    NSUInteger offset;
} AdrenoBufferBinding;

// Everything the render encoder records between draws.
typedef struct {
    __unsafe_unretained id<MTLRenderPipelineState> _Nullable pipeline;
    AdrenoBufferBinding vertex[ADRENO_DRAW_BUFFER_SLOTS], fragment[ADRENO_DRAW_BUFFER_SLOTS];
    uint32_t fragmentTextureMask;          // bound fragment textures (bit per index; the builder refuses
    uint32_t fragmentSamplerMask;          //   functions that sample, so bound-but-unused ones are harmless)
    BOOL viewportSet, scissorSet;
    MTLViewport viewport;
    MTLScissorRect scissor;
    MTLCullMode cullMode;
    MTLWinding winding;
    MTLTriangleFillMode fillMode;
    MTLDepthClipMode depthClipMode;
    float blendColor[4];
    float depthBias, depthSlopeScale, depthBiasClamp;
    MTLVisibilityResultMode visibilityMode;
} AdrenoDrawBindings;
void AdrenoDrawBindingsInit(AdrenoDrawBindings *bindings);

// The per-pipeline half of a draw: the owned programs, their code in shared-storage MTLBuffers (the machine code
// zero-padded to max(size, instrlen * 128) rounded to 256 bytes; the vertex buffer also carries the constant
// data the driver UBO points at), and the fixed-function state of the MTLRenderPipelineDescriptor.
// -[AdrenoRenderPipelineState adrenoDrawProgram] creates it once (raising for a pipeline the builder refuses).
@interface AdrenoDrawProgram : NSObject
@property (nonatomic, readonly) NSDictionary *vertexProgram, *fragmentProgram, *linkage;
@property (nonatomic, readonly) id<MTLBuffer> vertexCodeBuffer, fragmentCodeBuffer;
@end

@class AdrenoCS;
// Package construction shares only this completed-pass contract. The command
// stream accessor is internal; resource ownership remains with the pass.
@protocol AdrenoFinishedPass <NSObject>
@property (nonatomic, readonly) BOOL finished;
@property (nonatomic, readonly) BOOL empty;
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block;
- (AdrenoCS *)adrenoCS;
@end

// One render pass: prologue at creation, one draw section per draw, epilogue at -finish.
@interface AdrenoRenderPass : NSObject <AdrenoFinishedPass>
- (instancetype)initWithDescriptor:(MTLRenderPassDescriptor *)descriptor device:(id<MTLDevice>)device;   // raises
- (AdrenoDrawProgram *)programForPipeline:(id<MTLRenderPipelineState>)pipeline;                          // raises
- (void)drawPrimitives:(MTLPrimitiveType)type vertexStart:(NSUInteger)start vertexCount:(NSUInteger)count
         instanceCount:(NSUInteger)instances bindings:(const AdrenoDrawBindings *)bindings;
- (void)drawIndexedPrimitives:(MTLPrimitiveType)type indexCount:(NSUInteger)count indexType:(MTLIndexType)indexType
                  indexBuffer:(id<MTLBuffer>)indexBuffer indexBufferOffset:(NSUInteger)offset
                instanceCount:(NSUInteger)instances bindings:(const AdrenoDrawBindings *)bindings;
- (void)finish;
@property (nonatomic, readonly) BOOL finished;
@property (nonatomic, readonly) BOOL empty;          // no clear and no draw: nothing to submit
// The IOGPU resources the pass's relocations name, each with the MTLResourceUsage the kext must admit.
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block;
// A pass larger than one IB package (turnip-audit P2): its earlier, finished segments, in order, each its own package
// and resource uses. They are appended before the pass itself, which is the last segment. Empty for a pass that fits.
- (NSArray<id<AdrenoFinishedPass>> *)adrenoSegments;
@end

typedef struct {
    __unsafe_unretained id<MTLComputePipelineState> _Nullable pipeline;
    AdrenoBufferBinding buffers[ADRENO_DRAW_BUFFER_SLOTS];
    __unsafe_unretained id<MTLTexture> _Nullable textures[ADRENO_DRAW_TEXTURE_SLOTS];
    __unsafe_unretained id<MTLSamplerState> _Nullable samplers[ADRENO_DRAW_SAMPLER_SLOTS];
} AdrenoComputeBindings;
void AdrenoComputeBindingsInit(AdrenoComputeBindings *bindings);

@interface AdrenoComputeProgram : NSObject
@property (nonatomic, readonly) NSDictionary *kernelProgram;
@property (nonatomic, readonly) id<MTLBuffer> codeBuffer;
// The sampled texture's T# and the write image's UAV slot (each equal to its Metal texture index).
@property (nonatomic, readonly) NSInteger textureSlot, imageSlot;
@end

// One explicit dispatch snapshot. Encoding is transactional; inline constants
// are copied and code/resources retained before dispatchThreadgroups returns.
@interface AdrenoComputePass : NSObject <AdrenoFinishedPass>
- (instancetype)initWithDevice:(id<MTLDevice>)device;
- (AdrenoComputeProgram *)programForPipeline:(id<MTLComputePipelineState>)pipeline;
- (void)dispatchThreadgroups:(MTLSize)groups threadsPerThreadgroup:(MTLSize)threads
                    bindings:(const AdrenoComputeBindings *)bindings;
- (void)finish;
@property (nonatomic, readonly) BOOL finished;
@property (nonatomic, readonly) BOOL empty;
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block;
@end

typedef struct {
    __unsafe_unretained id<MTLResource> source, destination;
    uint64_t sourceOffset, destinationOffset, bytes;
} AdrenoBlitCopySpan;

// One copy API call, including all its rows. Validates the complete span vector
// before encoding, retains every backing resource, and never copies CPU bytes.
// Source and destination backing allocations must be disjoint in this scope.
@interface AdrenoBlitPass : NSObject <AdrenoFinishedPass>
- (instancetype)initWithDevice:(id<MTLDevice>)device copies:(const AdrenoBlitCopySpan *)copies count:(NSUInteger)count;
// generateMipmapsForTexture: levels 1..n-1, each a filtered 2D-engine copy of the level above (raises for a texture or
// format it does not build; agents/gfx-correctness FAILURE-MODES.md F1).
+ (instancetype)adrenoMipmapPassWithDevice:(id<MTLDevice>)device texture:(id<MTLTexture>)texture;
- (void)finish;
@property (nonatomic, readonly) BOOL finished;
@property (nonatomic, readonly) BOOL empty;
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block;
@end

// One ADRENO_KCMD_IB kernel command: consecutive finished passes of a command buffer.
@interface AdrenoIBPackage : NSObject
- (instancetype)initWithFillsBefore:(NSUInteger)fills;
@property (nonatomic, readonly) NSUInteger fillsBefore;   // FILL32 kernel commands that precede this package
- (BOOL)canAppendPass:(id<AdrenoFinishedPass>)pass;
- (void)appendPass:(id<AdrenoFinishedPass>)pass;
@property (nonatomic, readonly) NSUInteger passCount;
@property (nonatomic, readonly) NSUInteger commandBytes;
- (void)encodeInto:(void *)destination capacity:(NSUInteger)capacity;   // exactly commandBytes
@end

// UBO staging arenas (AdrenoDrawCommands.m; docs/PLUGIN-ARENA-TRIM-20261021.md): the 64 KiB / 256 KiB / 1 MiB arenas a
// finished pass took; once the command buffer that carries them completed without error, AdrenoStagingArenasRecycle
// returns them to the process's pool for later streams, which keeps them while they are in use and gives idle ones back.
// AdrenoStagingCounters: arenas allocated, reused from the pool, pooled, released instead of kept.
NSArray *AdrenoFinishedPassArenas(id<AdrenoFinishedPass> pass);
void AdrenoStagingArenasRecycle(NSArray *arenas);
void AdrenoStagingCounters(uint64_t counters[_Nonnull 4]);
// Continuation inside a command buffer: the staging cursor (arena, bytes used) a finished pass ended with, and a new
// render pass of the same command buffer starting its staging there instead of taking an arena of its own.
id<MTLBuffer> _Nullable AdrenoFinishedPassStagingCursor(id<AdrenoFinishedPass> pass, uint64_t *_Nonnull used);
void AdrenoPassContinueStaging(AdrenoRenderPass *pass, id<MTLBuffer> _Nullable arena, uint64_t used);
// The pool's counters, in this order (as many as fit): new, reused, pooled, released, live, live_bytes, peak_live,
// peak_live_bytes, pooled_count, pooled_bytes, peak_pooled_bytes, aged, capped, drained, drains, alloc_failures,
// retries, retry_successes, timer_fires, refused, continued. Returns the number written.
unsigned AdrenoStagingStatistics(uint64_t *_Nonnull out, unsigned capacity);
// Drain the pool now (and start its pressure window); the bytes released.
uint64_t AdrenoStagingRelieve(void);

// The per-command-buffer UBO mirror (agents/gpu-perf FAILURE-MODES.md U). 0: an unaligned constant buffer is copied
// inside its pass, draw by draw, as before (the build is then byte-identical to the combined 043dbf2d).
#ifndef ADRENO_UBO_MIRROR
#define ADRENO_UBO_MIRROR 1
#endif
#if ADRENO_UBO_MIRROR
// A render pass of `commandBuffer` mirrors through the command buffer's table (created on first use).
void AdrenoPassUseMirrors(AdrenoRenderPass *pass, id commandBuffer);
// U1(c)(d): a finished blit, mipmap or compute pass, or a FILL32, may have written these resources: their mirrors go.
void AdrenoMirrorsAfterPass(id commandBuffer, id<AdrenoFinishedPass> pass);
void AdrenoMirrorsWritten(id commandBuffer, id _Nullable resource);
void AdrenoMirrorsDropAll(id commandBuffer);
// Process counters: mirror copies, mirrored KiB, mirror reads, fallbacks, in-pass stagings, in-pass KiB, drops.
void AdrenoUBOMirrorCounters(uint64_t out[_Nonnull 7]);
// gpu-perf FAILURE-MODES.md R: mirror regions come from 1 MiB slabs allocated once per device (shared, default write-back
// cache mode) and never released; 0: from the staging pool (which releases arenas idle for 300 ms), as before.
#ifndef ADRENO_UBO_MIRROR_SLABS
#define ADRENO_UBO_MIRROR_SLABS 1
#endif
#if ADRENO_UBO_MIRROR_SLABS
// Slabs alive, allocated in all, takes, returns, takes refused at the cap.
void AdrenoMirrorSlabCounters(uint64_t out[_Nonnull 5]);
#endif
#endif
// gpu-perf FAILURE-MODES.md C: a blit copy span becomes CP_MEMCPYs of at most this many bytes (dword aligned). On the
// A16 a 1 MiB CP_MEMCPY completed in 1.6 ms and a 4 MiB one never finished inside the monitor's 1 s IB budget. 0: one
// CP_MEMCPY per span, as before.
#ifndef ADRENO_BLIT_CHUNK_BYTES
#define ADRENO_BLIT_CHUNK_BYTES (1u << 20)
#endif
// gpu-perf: what the packages of this process held, for the diagnostics stats line (calibrates the offline cost model
// against real WindowServer frames): render passes, draws, other passes (blit, mipmap, compute, preludes), IB kdwords.
#ifndef ADRENO_PERF_COUNTERS
#define ADRENO_PERF_COUNTERS 1
#endif
#if ADRENO_PERF_COUNTERS
void AdrenoPerfCounters(uint64_t out[_Nonnull 4]);
#endif

// Command-buffer entry points of the draw path (implemented in AdrenoCommandBuffer.m). Kernel commands keep
// encoder order: FILL32 commands recorded before a package precede it; FENCE stays last.
@interface AdrenoCommandBuffer (AdrenoDrawEncoding)
- (BOOL)adrenoDrawAvailable;
// nil with *refusal set: the IB builder refused the pass descriptor, which was recorded on the FILL32 clear path
// instead (as without the IB ABI). Other failures raise and fail the command buffer.
- (nullable AdrenoRenderPass *)adrenoBeginRenderPass:(MTLRenderPassDescriptor *)pass
                                             refusal:(NSString *_Nullable *_Nonnull)refusal;
- (void)adrenoRejectShaderDrawInPass:(NSString *)refusal;   // raises and fails the command buffer
- (void)adrenoEndRenderPass:(AdrenoRenderPass *)pass;
- (void)adrenoFailEncoding;           // an encoder call raised: the command buffer can no longer be committed
@end

NS_ASSUME_NONNULL_END
