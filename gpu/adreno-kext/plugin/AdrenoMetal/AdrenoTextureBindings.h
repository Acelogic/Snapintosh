/* SPDX-License-Identifier: MIT */
#pragma once
#import "AdrenoDrawCommands.h"

// Keep the installed draw-binding header immutable while extending the private
// encoder/pass interface. These objects are retained by the pass during encoding.
@interface AdrenoRenderPass (AdrenoTextureBindings)
- (void)adrenoSetFragmentTextures:(id<MTLTexture> const __strong *)textures
                         samplers:(id<MTLSamplerState> const __strong *)samplers;
@end

@interface NSObject (AdrenoSamplerDescriptor)
- (MTLSamplerDescriptor *)adrenoSamplerDescriptor;
@end

// Depth/stencil (docs/ADRENO-DEPTH-STENCIL-20261017.md). The encoder hands the pass the bound
// MTLDepthStencilState (nil: Metal's default, no test and no write) and the stencil reference values per draw.
@interface AdrenoRenderPass (AdrenoDepthStencil)
- (void)adrenoSetDepthStencil:(id<MTLDepthStencilState>)state front:(uint32_t)front back:(uint32_t)back;
@end

@interface NSObject (AdrenoDepthStencilDescriptor)
- (MTLDepthStencilDescriptor *)adrenoDepthStencilDescriptor;
@end

// The depth/stencil buffer of a Metal depth or stencil pixel format. Linear depth/stencil is not supported by the
// hardware (Mesa fdl6_layout_image), so the buffer is TILE6_3 with fdl6_tile_alignment's alignment: pitch 256 bytes
// (cpp 4: 64 pixels, cpp 2: 128 pixels), height 16 rows, base 4096. Stencil8 and Depth32Float_Stencil8 are one packed
// DEPTH6_24_8 buffer (stencil in the top byte): the kext's IB register set has no separate-stencil registers, so
// Depth32Float_Stencil8 keeps 24-bit unorm depth.
typedef struct {
    uint64_t depthFormat;      // a6xx_depth_format (RB_DEPTH_BUFFER_INFO, GRAS_SU_DEPTH_BUFFER_INFO)
    uint64_t destFormat;       // RB_A2D_DEST_BUFFER_INFO format of a 2D clear (emit_blit_dst)
    uint64_t blitFormat;       // RB/GRAS_A2D_BLT_CNTL and SP_A2D_OUTPUT_INFO format (emit_blit_setup)
    uint64_t ifmt;             // fd6_ifmt(blitFormat)
    uint64_t cpp, pitch, layerBytes;
    BOOL hasDepth, hasStencil, packed;
} AdrenoZSLayout;
BOOL AdrenoZSLayoutOf(MTLPixelFormat format, NSUInteger width, NSUInteger height, AdrenoZSLayout *out);

// The linear layout of mip level `level` of a 2D texture (or view) whose level-0 layout is recorded: the levels follow
// level 0 in the same allocation, back to back, each with the pitch the GPU derives from level 0's
// (AdrenoTextureSubresource, AdrenoMipLineShift), the same layout the CPU copies and render passes use. Level 0 is
// adrenoGetLinearLayout:'s. NO for any other texture or level.
BOOL AdrenoLinearLayoutAtLevel(id<MTLTexture> texture, NSUInteger level, AdrenoLinearTextureLayout *out);
// The lower mip levels' pitch alignment for a level-0 pitch, as log2(bytes) - 6 (the T#'s MIN_LINE_OFFSET).
NSUInteger AdrenoMipLineShift(NSUInteger rowBytes0);
// Apple's lossless-compressed IOSurfaces ('&BGA' with BGRA8, '&RhA' with RGBA16Float) are used as one linear image of
// that format: the row in bytes, else 0.
NSUInteger AdrenoCompressedSurfaceRow(IOSurfaceRef surface, MTLTextureDescriptor *descriptor);

// ADRENO_LENIENT: run one draw; if the builder refuses it (NSInvalidArgumentException), roll the pass's IB, data and
// relocations back to where they were and return the reason (nil: the draw was recorded).
@interface AdrenoRenderPass (AdrenoLenient)
- (NSString *)adrenoDropRefusedDraw:(void (^)(void))draw;
@end
