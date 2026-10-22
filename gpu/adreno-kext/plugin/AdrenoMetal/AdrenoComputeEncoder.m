/* SPDX-License-Identifier: MIT */
// Compute dispatches snapshot their bindings into the same ordered IB packages as render passes.
#import "AdrenoMTLObjectsPrivate.h"
#import "AdrenoDrawCommands.h"
#import "AdrenoTextureBindings.h"
#import <math.h>

@interface NSObject (AdrenoComputeWork)
- (NSDictionary *)adrenoWorkDescriptor;
@end
static NSNumber *AdrenoWorkResourceID(id resource) {
    return @([resource respondsToSelector:@selector(resourceID)] ? [(IOGPUMetalResource *)resource resourceID] : 0);
}
@implementation AdrenoComputeCommandEncoder {
    __weak AdrenoCommandBuffer *_adrenoCommandBuffer;
    BOOL _adrenoEnded;
    uint64_t _adrenoEncoder;
    NSDictionary *_adrenoPipelineInfo;
    NSMutableDictionary *_adrenoBindings;
    id<MTLComputePipelineState> _adrenoPipeline;
    id<MTLBuffer> _adrenoBuffers[ADRENO_DRAW_BUFFER_SLOTS];
    NSData *_adrenoBytes[ADRENO_DRAW_BUFFER_SLOTS];
    id<MTLTexture> _adrenoTextures[ADRENO_DRAW_TEXTURE_SLOTS];
    id<MTLSamplerState> _adrenoSamplers[ADRENO_DRAW_SAMPLER_SLOTS];
    AdrenoComputeBindings _adrenoValues;
    NSUInteger _adrenoThreadgroupMemory[ADRENO_DRAW_BUFFER_SLOTS];
    NSUInteger _adrenoImageblockWidth, _adrenoImageblockHeight;
}
- (instancetype)initWithCommandBuffer:(id<MTLCommandBuffer>)cb {
    if ((self=[super initWithCommandBuffer:cb])) {
        _adrenoCommandBuffer=(AdrenoCommandBuffer *)cb;
        @try {
            _adrenoEncoder=[_adrenoCommandBuffer adrenoBeginEncoder:@"compute" details:@{}];
            _adrenoBindings=[NSMutableDictionary dictionary];
            AdrenoComputeBindingsInit(&_adrenoValues);
        } @catch (NSException *error) {
            _adrenoEnded=YES;
            [_adrenoCommandBuffer adrenoFailEncoding];
            @try { if (_adrenoEncoder) [_adrenoCommandBuffer adrenoEndEncoder:_adrenoEncoder]; }
            @finally { [super endEncoding]; }
            @throw;
        }
    }
    return self;
}
- (void)adrenoInvalid:(NSString *)reason {
    [_adrenoCommandBuffer adrenoFailEncoding];
    [NSException raise:NSInvalidArgumentException format:@"%@",reason];
}
- (void)adrenoCheckOpen {
    if (_adrenoEnded || !_adrenoCommandBuffer) {
        [_adrenoCommandBuffer adrenoFailEncoding];
        [NSException raise:NSInternalInconsistencyException format:@"Adreno compute encoder has ended"];
    }
}
- (void)adrenoCheckSlot:(NSUInteger)i limit:(NSUInteger)limit {
    [self adrenoCheckOpen];
    if (i>=limit) [self adrenoInvalid:@"Adreno compute binding slot out of range"];
}
- (void)adrenoCheckRange:(NSRange)r limit:(NSUInteger)limit {
    [self adrenoCheckOpen];
    if (r.location>limit || r.length>limit-r.location)
        [self adrenoInvalid:@"Adreno compute binding range out of range"];
}
- (void)useResource:(id<MTLResource>)resource usage:(MTLResourceUsage)usage {
    [self adrenoCheckOpen];[_adrenoCommandBuffer adrenoUseResource:resource usage:usage];
}
- (void)useResources:(const id<MTLResource>[])resources count:(NSUInteger)count usage:(MTLResourceUsage)usage {
    [self adrenoCheckOpen];
    if (count && !resources) [self adrenoInvalid:@"Missing Adreno resource array"];
    for (NSUInteger n=0;n<count;n++) [self useResource:resources[n] usage:usage];
}
- (void)endEncoding {
    [self adrenoCheckOpen];
    _adrenoEnded=YES;
    @try { [_adrenoCommandBuffer adrenoEndEncoder:_adrenoEncoder]; }
    @finally { [super endEncoding]; }
}
- (void)setComputePipelineState:(id<MTLComputePipelineState>)s {
    [self adrenoCheckOpen];
    _adrenoPipeline=s;
    _adrenoPipelineInfo=[(id)s respondsToSelector:@selector(adrenoWorkDescriptor)] ? [(id)s adrenoWorkDescriptor] :
        @{@"label":s.label ?: @"unset",@"class":s ? NSStringFromClass([(id)s class]) : @"unset"};
}
- (void)adrenoBinding:(NSString *)kind index:(NSUInteger)i details:(NSDictionary *)details {
    _adrenoBindings[[NSString stringWithFormat:@"%@:%lu",kind,(unsigned long)i]]=details;
}
- (void)setBuffer:(id<MTLBuffer>)b offset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (o>b.length) [self adrenoInvalid:@"Adreno compute buffer offset exceeds its length"];
    _adrenoBuffers[i]=b; _adrenoBytes[i]=nil; _adrenoValues.buffers[i].offset=o;
    [self adrenoBinding:@"buffer" index:i details:@{@"length":@(b.length),@"offset":@(o),@"bound":@(b!=nil),@"resource":AdrenoWorkResourceID(b)}];
}
- (void)setBufferOffset:(NSUInteger)o atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (!_adrenoBuffers[i]) [self adrenoInvalid:@"Adreno compute buffer offset requires a bound buffer"];
    [self setBuffer:_adrenoBuffers[i] offset:o atIndex:i];
}
- (void)setBytes:(const void *)b length:(NSUInteger)l atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (l && !b) [self adrenoInvalid:@"Missing Adreno compute inline bytes"];
    NSData *snapshot=[NSData dataWithBytes:b length:l];
    _adrenoBytes[i]=snapshot; _adrenoBuffers[i]=nil; _adrenoValues.buffers[i].offset=0;
    [self adrenoBinding:@"buffer" index:i details:@{@"inline_bytes":@(l)}];
}
- (void)setTexture:(id<MTLTexture>)t atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_TEXTURE_SLOTS];
    _adrenoTextures[i]=t;
    [self adrenoBinding:@"texture" index:i details:@{@"width":@(t.width),@"height":@(t.height),@"format":@(t.pixelFormat),@"bound":@(t!=nil),@"resource":AdrenoWorkResourceID(t)}];
}
- (void)setSamplerState:(id<MTLSamplerState>)s atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_SAMPLER_SLOTS];
    _adrenoSamplers[i]=s;
    [self adrenoBinding:@"sampler" index:i details:@{@"label":s.label ?: @"",@"bound":@(s!=nil)}];
}
- (void)setBuffers:(const id<MTLBuffer>[])b offsets:(const NSUInteger[])o withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_BUFFER_SLOTS];
    if (r.length && (!b || !o)) [self adrenoInvalid:@"Missing compute buffers or offsets"];
    for (NSUInteger n=0;n<r.length;n++) [self setBuffer:b[n] offset:o[n] atIndex:r.location+n];
}
- (void)setTextures:(const id<MTLTexture>[])t withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_TEXTURE_SLOTS];
    if (r.length && !t) [self adrenoInvalid:@"Missing compute textures"];
    for (NSUInteger n=0;n<r.length;n++) [self setTexture:t[n] atIndex:r.location+n];
}
- (void)setSamplerStates:(const id<MTLSamplerState>[])s withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (r.length && !s) [self adrenoInvalid:@"Missing compute samplers"];
    for (NSUInteger n=0;n<r.length;n++) [self setSamplerState:s[n] atIndex:r.location+n];
}
- (void)setSamplerState:(id<MTLSamplerState>)s lodMinClamp:(float)lo lodMaxClamp:(float)hi atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (!isfinite(lo) || !isfinite(hi) || lo<0 || hi<lo)
        [self adrenoInvalid:@"Invalid Adreno compute sampler LOD clamps"];
    if (s) {
        if (![(id)s respondsToSelector:@selector(adrenoSamplerDescriptor)])
            [self adrenoInvalid:@"Adreno compute sampler has no descriptor"];
        MTLSamplerDescriptor *d=[[(id)s adrenoSamplerDescriptor] copy];
        if (!d) [self adrenoInvalid:@"Adreno compute sampler descriptor is absent"];
        d.lodMinClamp=lo; d.lodMaxClamp=hi;
        s=[_adrenoCommandBuffer.device newSamplerStateWithDescriptor:d];
        if (!s) [self adrenoInvalid:@"Adreno compute sampler clamp allocation failed"];
    }
    [self setSamplerState:s atIndex:i];
    [self adrenoBinding:@"sampler" index:i details:@{@"label":s.label ?: @"",@"bound":@(s!=nil),@"lod_min":@(lo),@"lod_max":@(hi)}];
}
- (void)setSamplerStates:(const id<MTLSamplerState>[])s lodMinClamps:(const float[])lo lodMaxClamps:(const float[])hi withRange:(NSRange)r {
    [self adrenoCheckRange:r limit:ADRENO_DRAW_SAMPLER_SLOTS];
    if (r.length && (!s || !lo || !hi)) [self adrenoInvalid:@"Missing compute sampler clamps"];
    for (NSUInteger n=0;n<r.length;n++) [self setSamplerState:s[n] lodMinClamp:lo[n] lodMaxClamp:hi[n] atIndex:r.location+n];
}
- (void)setThreadgroupMemoryLength:(NSUInteger)l atIndex:(NSUInteger)i {
    [self adrenoCheckSlot:i limit:ADRENO_DRAW_BUFFER_SLOTS];
    _adrenoThreadgroupMemory[i]=l;
    [self adrenoBinding:@"threadgroup" index:i details:@{@"bytes":@(l)}];
}
- (void)setImageblockWidth:(NSUInteger)w height:(NSUInteger)h {
    [self adrenoCheckOpen];
    _adrenoImageblockWidth=w; _adrenoImageblockHeight=h;
    [self adrenoBinding:@"imageblock" index:0 details:@{@"width":@(w),@"height":@(h)}];
}
- (const AdrenoComputeBindings *)adrenoSnapshotBindings {
    _adrenoValues.pipeline=_adrenoPipeline;
    for (NSUInteger i=0;i<ADRENO_DRAW_BUFFER_SLOTS;i++) {
        _adrenoValues.buffers[i].buffer=_adrenoBuffers[i];
        _adrenoValues.buffers[i].bytes=_adrenoBytes[i];
    }
    for (NSUInteger i=0;i<ADRENO_DRAW_TEXTURE_SLOTS;i++) _adrenoValues.textures[i]=_adrenoTextures[i];
    for (NSUInteger i=0;i<ADRENO_DRAW_SAMPLER_SLOTS;i++) _adrenoValues.samplers[i]=_adrenoSamplers[i];
    return &_adrenoValues;
}
- (void)adrenoDispatch:(NSString *)kind grid:(MTLSize)g threads:(MTLSize)t indirect:(NSDictionary *)indirect {
    [self adrenoCheckOpen];AdrenoDiagAdd(AdrenoDiagComputeDispatches,1);
    NSMutableDictionary *details=[@{@"pipeline":_adrenoPipelineInfo ?: @{},
        @"grid":@[@(g.width),@(g.height),@(g.depth)],@"threads":@[@(t.width),@(t.height),@(t.depth)],
        @"bindings":[_adrenoBindings copy],@"indirect":indirect} mutableCopy];
    AdrenoComputePass *pass=nil;
    @try {
        if (!_adrenoPipeline) [NSException raise:NSInvalidArgumentException format:@"Compute pipeline is not bound"];
        if (!t.width || !t.height || !t.depth)
            [NSException raise:NSInvalidArgumentException format:@"Compute local dimensions must be nonzero"];
        if (indirect.count) [NSException raise:NSInvalidArgumentException format:@"Indirect compute dispatch is not implemented"];
        if (_adrenoImageblockWidth || _adrenoImageblockHeight)
            [NSException raise:NSInvalidArgumentException format:@"Compute imageblock memory is not implemented"];
        for (NSUInteger i=0;i<ADRENO_DRAW_BUFFER_SLOTS;i++) if (_adrenoThreadgroupMemory[i])
            [NSException raise:NSInvalidArgumentException format:@"Dynamic compute threadgroup memory is not implemented"];
        MTLSize groups=g;
        if ([kind isEqualToString:@"compute-threads"]) {
            if (g.width%t.width || g.height%t.height || g.depth%t.depth)
                [NSException raise:NSInvalidArgumentException format:@"Partial compute threadgroups are not implemented"];
            groups=MTLSizeMake(g.width/t.width,g.height/t.height,g.depth/t.depth);
        }
        if (![_adrenoCommandBuffer adrenoDrawAvailable])
            [NSException raise:NSInvalidArgumentException format:@"Compute submission requires the Adreno IB ABI"];
        pass=[[AdrenoComputePass alloc] initWithDevice:_adrenoCommandBuffer.device];
        [pass dispatchThreadgroups:groups threadsPerThreadgroup:t bindings:[self adrenoSnapshotBindings]];
        [pass finish];
    } @catch (NSException *error) {
        if ([error.name isEqualToString:NSInvalidArgumentException]) {
            details[@"reason"]=error.reason ?: @"Compute builder refused dispatch";
            [_adrenoCommandBuffer adrenoRecordWork:kind encoder:_adrenoEncoder omitted:YES details:details];
            return;
        }
        [_adrenoCommandBuffer adrenoFailEncoding];
        @throw;
    }
    // Nothing from a refused dispatch reaches a package. Insertion failures are
    // fatal, even in lenient mode: resource/package mutation is not rollbackable.
    @try { [_adrenoCommandBuffer adrenoAppendComputePass:pass]; }
    @catch (NSException *error) { [_adrenoCommandBuffer adrenoFailEncoding]; @throw; }
    [_adrenoCommandBuffer adrenoRecordWork:kind encoder:_adrenoEncoder omitted:NO details:details];
}
- (void)dispatchThreadgroups:(MTLSize)g threadsPerThreadgroup:(MTLSize)t {
    [self adrenoDispatch:@"compute-threadgroups" grid:g threads:t indirect:@{}];
}
- (void)dispatchThreads:(MTLSize)g threadsPerThreadgroup:(MTLSize)t {
    [self adrenoDispatch:@"compute-threads" grid:g threads:t indirect:@{}];
}
- (void)dispatchThreadgroupsWithIndirectBuffer:(id<MTLBuffer>)b indirectBufferOffset:(NSUInteger)o threadsPerThreadgroup:(MTLSize)t {
    [self adrenoDispatch:@"compute-indirect" grid:MTLSizeMake(0,0,0) threads:t indirect:@{@"length":@(b.length),@"offset":@(o),@"resource":AdrenoWorkResourceID(b)}];
}
@end
