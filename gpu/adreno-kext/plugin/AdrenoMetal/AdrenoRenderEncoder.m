/* SPDX-License-Identifier: MIT */
// AdrenoRenderEncoder.m - render command encoder.
//
// With the kext's IB ABI (AdrenoIBABI, AdrenoDrawCommands.h) a render pass is one AdrenoRenderPass of the command
// buffer's ADRENO_KCMD_IB package: the pass prologue (and a Clear load action's 2D clear) at creation, one draw
// section per draw from the state recorded here, the epilogue at endEncoding. Without it, or for a pass the builder
// refuses (target format, row alignment, attachments), the pass keeps the bounded FILL32 clear path and shader draws
// are refused explicitly.
#import "AdrenoMTLObjectsPrivate.h"
#import "AdrenoDrawCommands.h"
#import "AdrenoTextureBindings.h"

@implementation AdrenoRenderCommandEncoder {
    __weak AdrenoCommandBuffer *_adrenoCommandBuffer;
    BOOL _adrenoEnded;
    uint64_t _adrenoEncoder;
    AdrenoRenderPass *_adrenoPass;          // nil: no IB ABI or a refused pass (FILL32 clear path), or the pass has ended
    NSString *_adrenoPassRefusal;           // why the IB builder refused this pass (IB ABI present, FILL32 clear path)
    AdrenoDrawBindings _adrenoBindings;     // borrows the objects the strong slots below own
    id<MTLRenderPipelineState> _adrenoPipeline;
    id<MTLBuffer> _adrenoVertexBuffers[ADRENO_DRAW_BUFFER_SLOTS], _adrenoFragmentBuffers[ADRENO_DRAW_BUFFER_SLOTS];
    NSData *_adrenoVertexBytes[ADRENO_DRAW_BUFFER_SLOTS], *_adrenoFragmentBytes[ADRENO_DRAW_BUFFER_SLOTS];
    id<MTLTexture> _adrenoFragmentTextures[ADRENO_DRAW_TEXTURE_SLOTS];
    id<MTLSamplerState> _adrenoFragmentSamplers[ADRENO_DRAW_SAMPLER_SLOTS];
    id<MTLDepthStencilState> _adrenoDepthStencil;
    uint32_t _adrenoStencilFront, _adrenoStencilBack;
    NSString *_adrenoPipelineRefused;            // ADRENO_LENIENT: the bound pipeline was refused; its draws are dropped
    NSUInteger _adrenoDynamicStride[ADRENO_DRAW_BUFFER_SLOTS];   // a vertex buffer bound with a dynamic attribute stride
}
- (instancetype)initWithCommandBuffer:(id<MTLCommandBuffer>)cb descriptor:(MTLRenderPassDescriptor *)rp {
    if ((self=[super initWithCommandBuffer:cb descriptor:rp])) {
        _adrenoCommandBuffer=(AdrenoCommandBuffer *)cb;
        @try {
            _adrenoEncoder=[_adrenoCommandBuffer adrenoBeginEncoder:@"render" details:
                @{@"target_width":@(rp.colorAttachments[0].texture.width),@"target_height":@(rp.colorAttachments[0].texture.height),
                  @"format":@(rp.colorAttachments[0].texture.pixelFormat),@"load":@(rp.colorAttachments[0].loadAction),@"store":@(rp.colorAttachments[0].storeAction)}];
            AdrenoDrawBindingsInit(&_adrenoBindings);
            if ([_adrenoCommandBuffer adrenoDrawAvailable]) {
                NSString *refusal=nil;
                _adrenoPass=[_adrenoCommandBuffer adrenoBeginRenderPass:rp refusal:&refusal];
                _adrenoPassRefusal=refusal;
            } else [_adrenoCommandBuffer adrenoClearPass:rp];
        }
        @catch (NSException *error) {
            // Even a rejected ledger admission follows a successful native
            // initializer. Balance it without ending another encoder's ledger.
            [_adrenoCommandBuffer adrenoFailEncoding];
            if (_adrenoEncoder) [self endEncoding];
            else { _adrenoEnded=YES; [super endEncoding]; }
            @throw;
        }
    }
    return self;
}
- (void)adrenoCheckOpen {
    if (_adrenoEnded || !_adrenoCommandBuffer)
        [NSException raise:NSInternalInconsistencyException format:@"Adreno render encoder has ended"];
}
// Runs one encoding step; a refusal fails the whole command buffer (no partial submission) and propagates.
- (void)adrenoEncode:(void (^)(void))step {
    @try { step(); }
    @catch (NSException *error) { [_adrenoCommandBuffer adrenoFailEncoding]; @throw; }
}
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage {
    [self adrenoCheckOpen];
    [_adrenoCommandBuffer adrenoUseResource:resource usage:usage];
}
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages {
    [self useResource:resource usage:usage];
}
- (void)useResources:(const id<MTLResource>[])resources count:(NSUInteger)count usage:(MTLResourceUsage)usage {
    if (count && !resources) [NSException raise:NSInvalidArgumentException format:@"Missing Adreno resource array"];
    for (NSUInteger n=0;n<count;n++) [self useResource:resources[n] usage:usage];
}
- (void)useResources:(const id<MTLResource>[])resources count:(NSUInteger)count usage:(MTLResourceUsage)usage stages:(MTLRenderStages)stages {
    [self useResources:resources count:count usage:usage];
}
- (void)endEncoding {
    [self adrenoCheckOpen];
    AdrenoRenderPass *pass=_adrenoPass;
    _adrenoPass=nil;
    _adrenoEnded=YES;
    @try {
        [_adrenoCommandBuffer adrenoEndEncoder:_adrenoEncoder];
        if (pass) [_adrenoCommandBuffer adrenoEndRenderPass:pass];
    }
    @finally { [super endEncoding]; }
}

// ---- state capture
- (const AdrenoDrawBindings *)adrenoBindings {
    _adrenoBindings.pipeline=_adrenoPipeline;
    for (NSUInteger i=0;i<ADRENO_DRAW_BUFFER_SLOTS;i++) {
        _adrenoBindings.vertex[i].buffer=_adrenoVertexBuffers[i];
        _adrenoBindings.vertex[i].bytes=_adrenoVertexBytes[i];
        _adrenoBindings.fragment[i].buffer=_adrenoFragmentBuffers[i];
        _adrenoBindings.fragment[i].bytes=_adrenoFragmentBytes[i];
    }
    uint32_t textures=0, samplers=0;
    for (NSUInteger i=0;i<ADRENO_DRAW_TEXTURE_SLOTS;i++) if (_adrenoFragmentTextures[i]) textures|=1u<<i;
    for (NSUInteger i=0;i<ADRENO_DRAW_SAMPLER_SLOTS;i++) if (_adrenoFragmentSamplers[i]) samplers|=1u<<i;
    _adrenoBindings.fragmentTextureMask=textures;
    _adrenoBindings.fragmentSamplerMask=samplers;
    [_adrenoPass adrenoSetFragmentTextures:_adrenoFragmentTextures samplers:_adrenoFragmentSamplers];
    [_adrenoPass adrenoSetDepthStencil:_adrenoDepthStencil front:_adrenoStencilFront back:_adrenoStencilBack];
    return &_adrenoBindings;
}
- (void)adrenoCheckSlot:(NSUInteger)index limit:(NSUInteger)limit {
    [self adrenoCheckOpen];
    if (index>=limit) {
        [_adrenoCommandBuffer adrenoFailEncoding];
        [NSException raise:NSInvalidArgumentException format:@"Adreno encoder slot %lu is outside 0..%lu",
            (unsigned long)index, (unsigned long)limit-1];
    }
}
- (void)setRenderPipelineState:(id<MTLRenderPipelineState>)s {
    [self adrenoCheckOpen];
    // A state bind is not a draw; account for any omission at the draw entry point.
    _adrenoPipelineRefused=nil;
#if ADRENO_LENIENT
    if (s && _adrenoPass) {
        @try { (void)[_adrenoPass programForPipeline:s]; }
        @catch (NSException *e) {
            if (![e.name isEqualToString:NSInvalidArgumentException]) { [_adrenoCommandBuffer adrenoFailEncoding]; @throw; }
            _adrenoPipelineRefused=e.reason ?: @"pipeline refused";
        }
    }
#else
    // Validates the pipeline once (programs, fixed-function state) and creates its code buffers.
    if (s) [self adrenoEncode:^{ (void)[self->_adrenoPass programForPipeline:s]; }];
#endif
    _adrenoPipeline=s;
}
- (void)setVertexBuffer:(id<MTLBuffer>)b offset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    _adrenoVertexBuffers[i]=b; _adrenoVertexBytes[i]=nil; _adrenoBindings.vertex[i].offset=o; _adrenoDynamicStride[i]=0;
}
- (void)setVertexBytes:(const void *)b length:(NSUInteger)l atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (l && !b) [NSException raise:NSInvalidArgumentException format:@"Missing Adreno vertex bytes"];
    _adrenoVertexBuffers[i]=nil; _adrenoVertexBytes[i]=[NSData dataWithBytes:b length:l]; _adrenoBindings.vertex[i].offset=0;
    _adrenoDynamicStride[i]=0;
}
- (void)setVertexBufferOffset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    _adrenoBindings.vertex[i].offset=o;
}
- (void)setFragmentBuffer:(id<MTLBuffer>)b offset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    _adrenoFragmentBuffers[i]=b; _adrenoFragmentBytes[i]=nil; _adrenoBindings.fragment[i].offset=o;
}
- (void)setFragmentBytes:(const void *)b length:(NSUInteger)l atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (l && !b) [NSException raise:NSInvalidArgumentException format:@"Missing Adreno fragment bytes"];
    _adrenoFragmentBuffers[i]=nil; _adrenoFragmentBytes[i]=[NSData dataWithBytes:b length:l]; _adrenoBindings.fragment[i].offset=0;
}
- (void)setFragmentBufferOffset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    _adrenoBindings.fragment[i].offset=o;
}
- (void)setFragmentTexture:(id<MTLTexture>)t atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_TEXTURE_SLOTS];
    _adrenoFragmentTextures[i]=t;
}
- (void)setFragmentSamplerState:(id<MTLSamplerState>)s atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_SAMPLER_SLOTS];
    _adrenoFragmentSamplers[i]=s;
}
- (void)setFragmentTexture:(id<MTLTexture>)t atTextureIndex:(NSUInteger)ti samplerState:(id<MTLSamplerState>)s atSamplerIndex:(NSUInteger)si {
    [self setFragmentTexture:t atIndex:ti];
    [self setFragmentSamplerState:s atIndex:si];
}
// docs/USERSPACE-GRAPHICS-20261019.md (unbound bindings): the range, LOD-clamp and attribute-stride setters. Apple's
// base encoder does not implement them (a client calling one raised), so each is the single-slot setters slot by slot.
- (void)adrenoCheckRange:(NSRange)r limit:(NSUInteger)limit {
    [self adrenoCheckOpen];
    if (r.length && (r.location>=limit || r.length>limit-r.location)) {
        [_adrenoCommandBuffer adrenoFailEncoding];
        [NSException raise:NSInvalidArgumentException format:@"Adreno encoder range %lu+%lu is outside 0..%lu",
            (unsigned long)r.location, (unsigned long)r.length, (unsigned long)limit-1];
    }
}
- (void)adrenoInvalid:(NSString *)reason {
    [_adrenoCommandBuffer adrenoFailEncoding];
    [NSException raise:NSInvalidArgumentException format:@"%@", reason];
}
- (void)setVertexBuffers:(const id<MTLBuffer>[])b offsets:(const NSUInteger[])o withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (r.length && (!b || !o)) [self adrenoInvalid:@"Missing Adreno vertex buffers or offsets"];
    for (NSUInteger n=0;n<r.length;n++) [self setVertexBuffer:b[n] offset:o[n] atIndex:r.location+n];
}
- (void)setFragmentBuffers:(const id<MTLBuffer>[])b offsets:(const NSUInteger[])o withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (r.length && (!b || !o)) [self adrenoInvalid:@"Missing Adreno fragment buffers or offsets"];
    for (NSUInteger n=0;n<r.length;n++) [self setFragmentBuffer:b[n] offset:o[n] atIndex:r.location+n];
}
- (void)setFragmentTextures:(const id<MTLTexture>[])t withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_TEXTURE_SLOTS];
    if (r.length && !t) [self adrenoInvalid:@"Missing Adreno fragment textures"];
    for (NSUInteger n=0;n<r.length;n++) [self setFragmentTexture:t[n] atIndex:r.location+n];
}
- (void)setFragmentSamplerStates:(const id<MTLSamplerState>[])s withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (r.length && !s) [self adrenoInvalid:@"Missing Adreno fragment samplers"];
    for (NSUInteger n=0;n<r.length;n++) [self setFragmentSamplerState:s[n] atIndex:r.location+n];
}
// The clamps become a sampler of their own, as in the compute encoder: the sampler's descriptor with them applied.
- (void)setFragmentSamplerState:(id<MTLSamplerState>)s lodMinClamp:(float)lo lodMaxClamp:(float)hi atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (isnan(lo) || isnan(hi) || lo<0 || hi<lo) [self adrenoInvalid:@"Invalid Adreno fragment sampler LOD clamps"];
    if (s) {
        if (![(id)s respondsToSelector:@selector(adrenoSamplerDescriptor)])
            [self adrenoInvalid:@"Adreno fragment sampler has no descriptor"];
        MTLSamplerDescriptor *d=[[(id)s adrenoSamplerDescriptor] copy];
        if (!d) [self adrenoInvalid:@"Adreno fragment sampler descriptor is absent"];
        d.lodMinClamp=lo; d.lodMaxClamp=hi;
        s=[_adrenoCommandBuffer.device newSamplerStateWithDescriptor:d];
        if (!s) [self adrenoInvalid:@"Adreno fragment sampler clamp allocation failed"];
    }
    [self setFragmentSamplerState:s atIndex:i];
}
- (void)setFragmentSamplerStates:(const id<MTLSamplerState>[])s lodMinClamps:(const float[])lo lodMaxClamps:(const float[])hi
                       withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (r.length && (!s || !lo || !hi)) [self adrenoInvalid:@"Missing Adreno fragment sampler clamps"];
    for (NSUInteger n=0;n<r.length;n++) [self setFragmentSamplerState:s[n] lodMinClamp:lo[n] lodMaxClamp:hi[n] atIndex:r.location+n];
}
// A dynamic stride is kept per slot and refuses the draws that follow (adrenoDraw); it is never silently dropped.
- (void)setVertexBuffer:(id<MTLBuffer>)b offset:(NSUInteger)o attributeStride:(NSUInteger)st atIndex:(NSUInteger)i {
    [self setVertexBuffer:b offset:o atIndex:i];
    _adrenoDynamicStride[i]=st==MTLAttributeStrideStatic ? 0 : st+1;
}
- (void)setVertexBytes:(const void *)b length:(NSUInteger)l attributeStride:(NSUInteger)st atIndex:(NSUInteger)i {
    [self setVertexBytes:b length:l atIndex:i];
    _adrenoDynamicStride[i]=st==MTLAttributeStrideStatic ? 0 : st+1;
}
- (void)setVertexBufferOffset:(NSUInteger)o attributeStride:(NSUInteger)st atIndex:(NSUInteger)i {
    [self setVertexBufferOffset:o atIndex:i];
    _adrenoDynamicStride[i]=st==MTLAttributeStrideStatic ? 0 : st+1;
}
- (void)setVertexBuffers:(const id<MTLBuffer>[])b offsets:(const NSUInteger[])o attributeStrides:(const NSUInteger[])st
               withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (r.length && (!b || !o || !st)) [self adrenoInvalid:@"Missing Adreno vertex buffers, offsets or strides"];
    for (NSUInteger n=0;n<r.length;n++) [self setVertexBuffer:b[n] offset:o[n] attributeStride:st[n] atIndex:r.location+n];
}
- (void)setViewport:(MTLViewport)v { [self adrenoCheckOpen]; _adrenoBindings.viewport=v; _adrenoBindings.viewportSet=YES; }
- (void)setScissorRect:(MTLScissorRect)r { [self adrenoCheckOpen]; _adrenoBindings.scissor=r; _adrenoBindings.scissorSet=YES; }
- (void)setCullMode:(MTLCullMode)m { [self adrenoCheckOpen]; _adrenoBindings.cullMode=m; }
- (void)setFrontFacingWinding:(MTLWinding)w { [self adrenoCheckOpen]; _adrenoBindings.winding=w; }
- (void)setTriangleFillMode:(MTLTriangleFillMode)m { [self adrenoCheckOpen]; _adrenoBindings.fillMode=m; }
- (void)setDepthClipMode:(MTLDepthClipMode)m { [self adrenoCheckOpen]; _adrenoBindings.depthClipMode=m; }
- (void)setDepthBias:(float)b slopeScale:(float)s clamp:(float)c {
    [self adrenoCheckOpen];
    _adrenoBindings.depthBias=b; _adrenoBindings.depthSlopeScale=s; _adrenoBindings.depthBiasClamp=c;
}
// The pass applies the state and the reference values to the aspects it attaches (AdrenoDrawCommands.m ZSA).
- (void)setDepthStencilState:(id<MTLDepthStencilState>)s { [self adrenoCheckOpen]; _adrenoDepthStencil=s; }
- (void)setStencilReferenceValue:(uint32_t)v { [self adrenoCheckOpen]; _adrenoStencilFront=_adrenoStencilBack=v; }
- (void)setStencilFrontReferenceValue:(uint32_t)f backReferenceValue:(uint32_t)b {
    [self adrenoCheckOpen]; _adrenoStencilFront=f; _adrenoStencilBack=b;
}
- (void)setBlendColorRed:(float)r green:(float)g blue:(float)b alpha:(float)a {
    [self adrenoCheckOpen];
    _adrenoBindings.blendColor[0]=r; _adrenoBindings.blendColor[1]=g; _adrenoBindings.blendColor[2]=b; _adrenoBindings.blendColor[3]=a;
}
- (void)setVisibilityResultMode:(MTLVisibilityResultMode)m offset:(NSUInteger)o { [self adrenoCheckOpen]; _adrenoBindings.visibilityMode=m; }
- (void)setLineWidth:(float)w {}

// ---- draws: each attempted draw receives its own outcome, including repeated pipeline refusals. The draw's details
// are built only for an omitted or failed draw (an encoded draw's record only bumps the ledger's counters).
- (void)adrenoDraw:(NSString *)operation details:(NSDictionary *(NS_NOESCAPE ^)(void))details encode:(void (^)(void))encode {
    [self adrenoCheckOpen];
    NSString *strideRefusal=nil;
    for (NSUInteger i=0;i<ADRENO_DRAW_BUFFER_SLOTS && !strideRefusal;i++)
        if (_adrenoDynamicStride[i])
            strideRefusal=[NSString stringWithFormat:@"Adreno draw: vertex buffer(%lu) has dynamic attribute stride %lu, which is not supported yet",
                           (unsigned long)i, (unsigned long)(_adrenoDynamicStride[i]-1)];
    NSString *reason=_adrenoPipelineRefused ?: strideRefusal ?: (!_adrenoPass ? (_adrenoPassRefusal ?: [NSString stringWithFormat:@"Adreno shader draws need the kext's IB ABI (" ADRENO_IB_REGISTRY_PROPERTY " = %d), which this accelerator does not publish", ADRENO_GUEST_IB_ABI]) : nil);
    if(!reason) {
        @try {
#if ADRENO_LENIENT
            reason=[_adrenoPass adrenoDropRefusedDraw:encode];
#else
            encode();
#endif
        } @catch(NSException *e) {
            [_adrenoCommandBuffer adrenoFailEncoding];
            [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:YES details:@{@"reason":e.reason ?: @"draw failed",@"draw":details()}];
            @throw;
        }
    }
    if (!reason) { [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:NO details:@{}]; return; }
    NSMutableDictionary *record=[details() mutableCopy];
    record[@"pipeline"]=_adrenoPipeline.label ?: @"unset";
    record[@"reason"]=reason;
    [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:YES details:record];
}
- (void)drawPrimitives:(MTLPrimitiveType)t vertexStart:(NSUInteger)s vertexCount:(NSUInteger)c instanceCount:(NSUInteger)n {
    [self adrenoCheckOpen];if(!c || !n)return;
    [self adrenoDraw:@"draw" details:^NSDictionary *{ return @{@"primitive":@(t),@"start":@(s),@"count":@(c),@"instances":@(n)}; } encode:^{
        [self->_adrenoPass drawPrimitives:t vertexStart:s vertexCount:c instanceCount:n bindings:[self adrenoBindings]];
    }];
}
- (void)drawPrimitives:(MTLPrimitiveType)t vertexStart:(NSUInteger)s vertexCount:(NSUInteger)c {
    [self drawPrimitives:t vertexStart:s vertexCount:c instanceCount:1];
}
- (void)drawIndexedPrimitives:(MTLPrimitiveType)t indexCount:(NSUInteger)c indexType:(MTLIndexType)it
                  indexBuffer:(id<MTLBuffer>)ib indexBufferOffset:(NSUInteger)o instanceCount:(NSUInteger)n {
    [self adrenoCheckOpen];if(!c || !n)return;
    [self adrenoDraw:@"draw-indexed" details:^NSDictionary *{ return @{@"primitive":@(t),@"count":@(c),@"instances":@(n),@"index_type":@(it),@"index_offset":@(o)}; } encode:^{
        [self->_adrenoPass drawIndexedPrimitives:t indexCount:c indexType:it indexBuffer:ib indexBufferOffset:o
                                   instanceCount:n bindings:[self adrenoBindings]];
    }];
}
- (void)drawIndexedPrimitives:(MTLPrimitiveType)t indexCount:(NSUInteger)c indexType:(MTLIndexType)it
                  indexBuffer:(id<MTLBuffer>)ib indexBufferOffset:(NSUInteger)o {
    [self drawIndexedPrimitives:t indexCount:c indexType:it indexBuffer:ib indexBufferOffset:o instanceCount:1];
}
// Tile-shading entry points: unreachable while supportsTileShaders==NO, explicitly accounted if a client sends them.
- (NSUInteger)tileWidth { return 16; }
- (NSUInteger)tileHeight { return 16; }
- (void)setTileBuffer:(id<MTLBuffer>)b offset:(NSUInteger)o atIndex:(NSUInteger)i {}
- (void)setTileBytes:(const void *)b length:(NSUInteger)l atIndex:(NSUInteger)i {}
- (void)setTileTexture:(id<MTLTexture>)t atIndex:(NSUInteger)i {}
- (void)dispatchThreadsPerTile:(MTLSize)s { [self adrenoCheckOpen]; AdrenoDiagAdd(AdrenoDiagTileDispatches, 1); [_adrenoCommandBuffer adrenoRecordWork:@"tile-dispatch" encoder:_adrenoEncoder omitted:YES details:@{@"reason":@"tile dispatch has no qualified executor",@"threads":@[@(s.width),@(s.height),@(s.depth)]}]; }
- (void)dispatchThreadsPerTile:(MTLSize)s inRegion:(MTLRegion)r {
    [self adrenoCheckOpen]; AdrenoDiagAdd(AdrenoDiagTileDispatches,1);
    [_adrenoCommandBuffer adrenoRecordWork:@"tile-dispatch" encoder:_adrenoEncoder omitted:YES details:
        @{@"reason":@"tile dispatch has no qualified executor",@"threads":@[@(s.width),@(s.height),@(s.depth)],
          @"origin":@[@(r.origin.x),@(r.origin.y),@(r.origin.z)],@"size":@[@(r.size.width),@(r.size.height),@(r.size.depth)]}];
}
@end
