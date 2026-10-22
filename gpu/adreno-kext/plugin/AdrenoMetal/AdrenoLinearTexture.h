/* SPDX-License-Identifier: MIT */
#pragma once
#import <Metal/Metal.h>

// Allocation geometry recorded by our texture constructors, never inferred
// from an arbitrary native texture or view. No CPU address is carried here.
typedef struct {
    uint64_t offset, rowBytes, width, height, allocationBytes;
    MTLPixelFormat format;
} AdrenoLinearTextureLayout;

@protocol AdrenoLinearTexture
- (BOOL)adrenoGetLinearLayout:(AdrenoLinearTextureLayout *)layout;
@end

// Aligned shadows (docs/USERSPACE-GRAPHICS-20261019.md): an IOSurface whose rows are not 64-byte multiples is read and
// written by the GPU through one aligned shadow buffer per surface. AdrenoGPUBacking: the IOGPU resource the GPU uses
// for `resource` (a shadowed texture's shadow buffer, filled from its surface first when the CPU wrote the surface; any
// other resource itself). AdrenoGPUBackingSize: that resource's size, without filling. AdrenoShadowOfBuffer: the shadow a
// shadow buffer belongs to (nil otherwise). AdrenoShadowWriteBack: copy a shadow's rows back into its surface.
id AdrenoGPUBacking(id resource);
uint64_t AdrenoGPUBackingSize(id resource);
id AdrenoShadowOfBuffer(id resource);
void AdrenoShadowWriteBack(id shadow);
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
#if ADRENO_PIPELINE
// --pipeline (agents/gpu-pipeline FAILURE-MODES.md U2): a command buffer's completion now follows the GPU, and the next
// one is encoded while the GPU still runs the previous. The shadows a committed command buffer uses (found by its
// resource records' IDs) count it from its commit to its completion; a CPU refill of a shadow waits until no committed
// command buffer uses it (bounded, 250 ms; then it refills and counts the overrun).
NSArray *AdrenoShadowsForResourceIDs(NSData *resourceIDs);
void AdrenoShadowsGPUBegin(NSArray *shadows);
void AdrenoShadowsGPUEnd(NSArray *shadows);
uint64_t AdrenoShadowRefillOverruns(void);
#endif

// One line of metadata for a refused render target (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md): class, format,
// size, usage, storage, view parent, IOSurface, buffer backing, resource size, and the recorded layout or why none
// was recorded. Never reads pixel contents and never throws.
NSString *AdrenoDescribeTarget(id<MTLTexture> texture);
