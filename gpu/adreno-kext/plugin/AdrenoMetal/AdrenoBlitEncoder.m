/* SPDX-License-Identifier: MIT */
// GPU copies share the ordered package stream with compute, render and fills.
#import "AdrenoMTLObjectsPrivate.h"
#import "AdrenoDrawCommands.h"

@interface NSObject (AdrenoBlitCapability)
- (BOOL)adrenoBufferCopyAvailable;
@end
static void AdrenoBlitRefuse(NSString *reason) {
    [NSException raise:NSInvalidArgumentException format:@"%@",reason];
}
static NSNumber *AdrenoBlitResourceID(id resource) {
    return @([resource respondsToSelector:@selector(resourceID)] ? [(IOGPUMetalResource *)resource resourceID] : 0);
}
static NSUInteger AdrenoBlitBytesPerPixel(MTLPixelFormat f) {
    switch (f) {
        case MTLPixelFormatA8Unorm: case MTLPixelFormatR8Unorm: case MTLPixelFormatR8Uint: return 1;
        case MTLPixelFormatRG8Unorm: case MTLPixelFormatR16Float: case MTLPixelFormatR16Unorm: return 2;
        case MTLPixelFormatBGRA8Unorm: case MTLPixelFormatBGRA8Unorm_sRGB: case MTLPixelFormatRGBA8Unorm:
        case MTLPixelFormatRGBA8Unorm_sRGB: case MTLPixelFormatR32Float: case MTLPixelFormatRG16Float:
        case MTLPixelFormatBGR10A2Unorm: case MTLPixelFormatRGB10A2Unorm: return 4;
        case MTLPixelFormatRGBA16Float: case MTLPixelFormatRG32Float: return 8;
        case MTLPixelFormatRGBA32Float: return 16;
        default: return 0;
    }
}
static void AdrenoBlitBuffer(id<MTLBuffer> b, id<MTLDevice> device, uint64_t offset, uint64_t bytes) {
    if (![b isKindOfClass:[IOGPUMetalBuffer class]] || b.device!=device ||
        offset>b.length || bytes>b.length-offset)
        AdrenoBlitRefuse(@"GPU blit buffer is foreign, absent or outside its logical length");
}
// Only constructor-recorded layouts are usable. Never infer layout from CPU contents.
static AdrenoLinearTextureLayout AdrenoBlitTexture(id<MTLTexture> t, id<MTLDevice> device,
        NSUInteger slice, NSUInteger level, MTLOrigin origin, MTLSize size) {
    AdrenoLinearTextureLayout l={0};
    NSUInteger bpp=AdrenoBlitBytesPerPixel(t.pixelFormat);
    if (![t isKindOfClass:[IOGPUMetalTexture class]] || t.device!=device || !bpp ||
        t.textureType!=MTLTextureType2D || t.sampleCount!=1 || t.arrayLength!=1 || t.depth!=1 ||
        slice || level || origin.z || size.depth>1 || ![t respondsToSelector:@selector(adrenoGetLinearLayout:)] ||
        ![(id<AdrenoLinearTexture>)t adrenoGetLinearLayout:&l])
        AdrenoBlitRefuse(@"GPU blit requires a recorded uncompressed linear 2D level-zero texture");
    if (l.width!=t.width || l.height!=t.height || l.format!=t.pixelFormat ||
        !l.width || !l.height || l.width>UINT64_MAX/bpp || l.rowBytes<l.width*bpp ||
        l.allocationBytes!=AdrenoGPUBackingSize(t) || l.offset>l.allocationBytes ||
        l.height>(l.allocationBytes-l.offset)/l.rowBytes ||
        origin.x>l.width || size.width>l.width-origin.x || origin.y>l.height || size.height>l.height-origin.y)
        AdrenoBlitRefuse(@"GPU blit texture layout or region is outside its allocation");
    return l;
}
static uint64_t AdrenoBlitBufferRows(id<MTLBuffer> b, id<MTLDevice> device, uint64_t offset,
        uint64_t pitch, uint64_t rowBytes, uint64_t rows) {
    AdrenoBlitBuffer(b,device,offset,0);
    if (!rows || !rowBytes) return 0;
    if (pitch<rowBytes || rowBytes>b.length-offset || (rows-1)>(b.length-offset-rowBytes)/pitch)
        AdrenoBlitRefuse(@"GPU blit buffer row pitch or final row exceeds its logical length");
    return (rows-1)*pitch+rowBytes;
}
static NSData *AdrenoBlitRows(id<MTLResource> source, uint64_t sourceOffset, uint64_t sourcePitch,
        id<MTLResource> destination, uint64_t destinationOffset, uint64_t destinationPitch,
        uint64_t bytes, NSUInteger rows) {
    if (!bytes || !rows) return [NSData data]; // explicitly recorded empty API copy; no packet needed
#if ADRENO_BLIT_CHUNK_BYTES
    // gpu-perf C1-C3: each row as CP_MEMCPYs of at most ADRENO_BLIT_CHUNK_BYTES (rows of that size or less: one, as before).
    _Static_assert(!(ADRENO_BLIT_CHUNK_BYTES & 3), "blit chunks stay dword aligned");
    const uint64_t chunks=(bytes+ADRENO_BLIT_CHUNK_BYTES-1)/ADRENO_BLIT_CHUNK_BYTES;
    if (rows>ADRENO_BLIT_MAX_SPANS || chunks>ADRENO_BLIT_MAX_SPANS/rows)
        AdrenoBlitRefuse(@"GPU blit row count exceeds one atomic copy package");
    NSMutableData *data=[NSMutableData dataWithLength:rows*chunks*sizeof(AdrenoBlitCopySpan)];
    AdrenoBlitCopySpan *spans=data.mutableBytes;
    for (NSUInteger row=0;row<rows;row++)
        for (uint64_t k=0;k<chunks;k++) {
            // The two complete row ranges were checked by the caller before allocation.
            const uint64_t at=k*ADRENO_BLIT_CHUNK_BYTES, n=MIN((uint64_t)ADRENO_BLIT_CHUNK_BYTES,bytes-at);
            spans[row*chunks+k]=(AdrenoBlitCopySpan){.source=source,.destination=destination,
                .sourceOffset=sourceOffset+row*sourcePitch+at,.destinationOffset=destinationOffset+row*destinationPitch+at,.bytes=n};
        }
#else
    if (rows>ADRENO_BLIT_MAX_SPANS) AdrenoBlitRefuse(@"GPU blit row count exceeds one atomic copy package");
    NSMutableData *data=[NSMutableData dataWithLength:rows*sizeof(AdrenoBlitCopySpan)];
    AdrenoBlitCopySpan *spans=data.mutableBytes;
    for (NSUInteger row=0;row<rows;row++) {
        // The two complete row ranges were checked by the caller before allocation.
        spans[row]=(AdrenoBlitCopySpan){.source=source,.destination=destination,
            .sourceOffset=sourceOffset+row*sourcePitch,.destinationOffset=destinationOffset+row*destinationPitch,.bytes=bytes};
    }
#endif
    return data;
}

@implementation AdrenoBlitCommandEncoder {
    __weak AdrenoCommandBuffer *_adrenoCommandBuffer;
    BOOL _adrenoEnded;
    uint64_t _adrenoEncoder;
}
- (instancetype)initWithCommandBuffer:(id<MTLCommandBuffer>)cb {
    if ((self=[super initWithCommandBuffer:cb])) {
        _adrenoCommandBuffer=(AdrenoCommandBuffer *)cb;
        @try { _adrenoEncoder=[_adrenoCommandBuffer adrenoBeginEncoder:@"blit" details:@{}]; }
        @catch (NSException *error) {
            [_adrenoCommandBuffer adrenoFailEncoding];_adrenoEnded=YES;
            [super endEncoding];@throw;
        }
    }
    return self;
}
- (void)adrenoCheckOpen {
    if (_adrenoEnded || !_adrenoCommandBuffer) {
        [_adrenoCommandBuffer adrenoFailEncoding];
        [NSException raise:NSInternalInconsistencyException format:@"Adreno blit encoder has ended"];
    }
}
- (void)endEncoding {
    [self adrenoCheckOpen];_adrenoEnded=YES;
    @try { [_adrenoCommandBuffer adrenoEndEncoder:_adrenoEncoder]; }
    @finally { [super endEncoding]; }
}
- (void)adrenoCopy:(NSString *)operation details:(NSDictionary *)input plan:(NSData *(^)(void))plan {
    [self adrenoCheckOpen];
    NSMutableDictionary *details=[input mutableCopy];
    AdrenoBlitPass *pass=nil;
    @try {
        NSData *spans=plan();
        if (!spans || spans.length%sizeof(AdrenoBlitCopySpan))
            [NSException raise:NSInternalInconsistencyException format:@"GPU blit row plan is malformed"];
        details[@"spans"]=@(spans.length/sizeof(AdrenoBlitCopySpan));
        if (spans.length) {
            id<MTLDevice> device=_adrenoCommandBuffer.device;
            if (![_adrenoCommandBuffer adrenoDrawAvailable] ||
                ![(id)device respondsToSelector:@selector(adrenoBufferCopyAvailable)] ||
                ![(id)device adrenoBufferCopyAvailable])
                AdrenoBlitRefuse(@"GPU blit requires Adreno IB and CopyABI availability");
            pass=[[AdrenoBlitPass alloc] initWithDevice:device copies:spans.bytes count:spans.length/sizeof(AdrenoBlitCopySpan)];
            [pass finish];
        } else if (!details[@"no_op"]) details[@"no_op"]=@"zero extent";
    } @catch (NSException *error) {
        if ([error.name isEqualToString:NSInvalidArgumentException]) {
            details[@"reason"]=error.reason ?: @"GPU blit refused";
            [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:YES details:details];
            return;
        }
        [_adrenoCommandBuffer adrenoFailEncoding];@throw;
    }
    @try { if (pass) [_adrenoCommandBuffer adrenoAppendBlitPass:pass]; }
    @catch (NSException *error) { [_adrenoCommandBuffer adrenoFailEncoding];@throw; }
    [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:NO details:details];
}
- (void)fillBuffer:(id<MTLBuffer>)buffer range:(NSRange)range value:(uint8_t)value {
    [self adrenoCheckOpen];
    NSMutableDictionary *details=[@{@"resource":AdrenoBlitResourceID(buffer),@"offset":@(range.location),
        @"bytes":@(range.length),@"value":@(value)} mutableCopy];
    @try { [_adrenoCommandBuffer adrenoFillBuffer:buffer range:range value:value]; }
    @catch (NSException *error) {
        [_adrenoCommandBuffer adrenoFailEncoding];details[@"reason"]=error.reason ?: @"Blit fill refused";
        [_adrenoCommandBuffer adrenoRecordWork:@"blit-fill" encoder:_adrenoEncoder omitted:YES details:details];@throw;
    }
    [_adrenoCommandBuffer adrenoRecordWork:@"blit-fill" encoder:_adrenoEncoder omitted:NO details:details];
}
- (void)copyFromBuffer:(id<MTLBuffer>)s sourceOffset:(NSUInteger)so toBuffer:(id<MTLBuffer>)d destinationOffset:(NSUInteger)dest size:(NSUInteger)n {
    [self adrenoCopy:@"blit-buffer-copy" details:@{@"source":AdrenoBlitResourceID(s),@"destination":AdrenoBlitResourceID(d),
        @"source_offset":@(so),@"destination_offset":@(dest),@"bytes":@(n)} plan:^NSData *{
        AdrenoBlitBuffer(s,self->_adrenoCommandBuffer.device,so,n);AdrenoBlitBuffer(d,self->_adrenoCommandBuffer.device,dest,n);
        return AdrenoBlitRows(s,so,0,d,dest,0,n,1);
    }];
}
- (void)copyFromTexture:(id<MTLTexture>)t sourceSlice:(NSUInteger)ss sourceLevel:(NSUInteger)sl sourceOrigin:(MTLOrigin)so
             sourceSize:(MTLSize)sz toBuffer:(id<MTLBuffer>)b destinationOffset:(NSUInteger)off
 destinationBytesPerRow:(NSUInteger)bpr destinationBytesPerImage:(NSUInteger)bpi options:(MTLBlitOption)o {
    [self adrenoCopy:@"blit-texture-to-buffer" details:@{@"source":AdrenoBlitResourceID(t),@"destination":AdrenoBlitResourceID(b),
        @"destination_offset":@(off),@"destination_pitch":@(bpr),@"bytes_per_image":@(bpi),@"options":@(o),
        @"source_origin":@[@(so.x),@(so.y),@(so.z)],@"size":@[@(sz.width),@(sz.height),@(sz.depth)],@"slice":@(ss),@"level":@(sl)} plan:^NSData *{
        if (o!=MTLBlitOptionNone) AdrenoBlitRefuse(@"GPU blit texture options are not implemented");
        id<MTLDevice> device=self->_adrenoCommandBuffer.device;
        AdrenoLinearTextureLayout l=AdrenoBlitTexture(t,device,ss,sl,so,sz);
        uint64_t bytes=sz.width*AdrenoBlitBytesPerPixel(t.pixelFormat), rows=sz.depth?sz.height:0;
        (void)AdrenoBlitBufferRows(b,device,off,bpr,bytes,rows);
        if (!bytes || !rows) return [NSData data];
        return AdrenoBlitRows(t,l.offset+so.y*l.rowBytes+so.x*AdrenoBlitBytesPerPixel(t.pixelFormat),l.rowBytes,b,off,bpr,bytes,rows);
    }];
}
- (void)copyFromTexture:(id<MTLTexture>)t sourceSlice:(NSUInteger)ss sourceLevel:(NSUInteger)sl sourceOrigin:(MTLOrigin)so
             sourceSize:(MTLSize)sz toBuffer:(id<MTLBuffer>)b destinationOffset:(NSUInteger)off
 destinationBytesPerRow:(NSUInteger)bpr destinationBytesPerImage:(NSUInteger)bpi {
    [self copyFromTexture:t sourceSlice:ss sourceLevel:sl sourceOrigin:so sourceSize:sz toBuffer:b destinationOffset:off
        destinationBytesPerRow:bpr destinationBytesPerImage:bpi options:MTLBlitOptionNone];
}
- (void)copyFromBuffer:(id<MTLBuffer>)b sourceOffset:(NSUInteger)off sourceBytesPerRow:(NSUInteger)bpr
   sourceBytesPerImage:(NSUInteger)bpi sourceSize:(MTLSize)sz toTexture:(id<MTLTexture>)t destinationSlice:(NSUInteger)ds
      destinationLevel:(NSUInteger)dl destinationOrigin:(MTLOrigin)origin options:(MTLBlitOption)o {
    [self adrenoCopy:@"blit-buffer-to-texture" details:@{@"source":AdrenoBlitResourceID(b),@"destination":AdrenoBlitResourceID(t),
        @"source_offset":@(off),@"source_pitch":@(bpr),@"bytes_per_image":@(bpi),@"options":@(o),
        @"destination_origin":@[@(origin.x),@(origin.y),@(origin.z)],@"size":@[@(sz.width),@(sz.height),@(sz.depth)],@"slice":@(ds),@"level":@(dl)} plan:^NSData *{
        if (o!=MTLBlitOptionNone) AdrenoBlitRefuse(@"GPU blit texture options are not implemented");
        id<MTLDevice> device=self->_adrenoCommandBuffer.device;
        AdrenoLinearTextureLayout l=AdrenoBlitTexture(t,device,ds,dl,origin,sz);
        uint64_t bytes=sz.width*AdrenoBlitBytesPerPixel(t.pixelFormat),rows=sz.depth?sz.height:0;
        (void)AdrenoBlitBufferRows(b,device,off,bpr,bytes,rows);
        if (!bytes || !rows) return [NSData data];
        return AdrenoBlitRows(b,off,bpr,t,l.offset+origin.y*l.rowBytes+origin.x*AdrenoBlitBytesPerPixel(t.pixelFormat),l.rowBytes,bytes,rows);
    }];
}
- (void)copyFromBuffer:(id<MTLBuffer>)b sourceOffset:(NSUInteger)off sourceBytesPerRow:(NSUInteger)bpr
   sourceBytesPerImage:(NSUInteger)bpi sourceSize:(MTLSize)sz toTexture:(id<MTLTexture>)t destinationSlice:(NSUInteger)ds
      destinationLevel:(NSUInteger)dl destinationOrigin:(MTLOrigin)origin {
    [self copyFromBuffer:b sourceOffset:off sourceBytesPerRow:bpr sourceBytesPerImage:bpi sourceSize:sz toTexture:t
        destinationSlice:ds destinationLevel:dl destinationOrigin:origin options:MTLBlitOptionNone];
}
- (void)copyFromTexture:(id<MTLTexture>)s sourceSlice:(NSUInteger)ss sourceLevel:(NSUInteger)sl sourceOrigin:(MTLOrigin)so
             sourceSize:(MTLSize)sz toTexture:(id<MTLTexture>)d destinationSlice:(NSUInteger)ds destinationLevel:(NSUInteger)dl
      destinationOrigin:(MTLOrigin)dest {
    [self adrenoCopy:@"blit-texture-copy" details:@{@"source":AdrenoBlitResourceID(s),@"destination":AdrenoBlitResourceID(d),
        @"source_origin":@[@(so.x),@(so.y),@(so.z)],@"destination_origin":@[@(dest.x),@(dest.y),@(dest.z)],
        @"size":@[@(sz.width),@(sz.height),@(sz.depth)],@"source_slice":@(ss),@"source_level":@(sl),@"destination_slice":@(ds),@"destination_level":@(dl)} plan:^NSData *{
        id<MTLDevice> device=self->_adrenoCommandBuffer.device;
        AdrenoLinearTextureLayout a=AdrenoBlitTexture(s,device,ss,sl,so,sz),b=AdrenoBlitTexture(d,device,ds,dl,dest,sz);
        if (s.pixelFormat!=d.pixelFormat) AdrenoBlitRefuse(@"GPU blit format conversion is not implemented");
        uint64_t cpp=AdrenoBlitBytesPerPixel(s.pixelFormat),bytes=sz.width*cpp,rows=sz.depth?sz.height:0;
        if (!bytes || !rows) return [NSData data];
        return AdrenoBlitRows(s,a.offset+so.y*a.rowBytes+so.x*cpp,a.rowBytes,
            d,b.offset+dest.y*b.rowBytes+dest.x*cpp,b.rowBytes,bytes,rows);
    }];
}
- (void)copyFromTexture:(id<MTLTexture>)s sourceSlice:(NSUInteger)ss sourceLevel:(NSUInteger)sl toTexture:(id<MTLTexture>)d
       destinationSlice:(NSUInteger)ds destinationLevel:(NSUInteger)dl sliceCount:(NSUInteger)sc levelCount:(NSUInteger)lc {
    [self adrenoCheckOpen];
    if (sc==1 && lc==1 && !ss && !sl && !ds && !dl) {
        [self copyFromTexture:s sourceSlice:ss sourceLevel:sl sourceOrigin:MTLOriginMake(0,0,0)
            sourceSize:MTLSizeMake(s.width,s.height,1) toTexture:d destinationSlice:ds destinationLevel:dl destinationOrigin:MTLOriginMake(0,0,0)];
        return;
    }
    [self adrenoCopy:@"blit-texture-subresources" details:@{@"slices":@(sc),@"levels":@(lc)} plan:^NSData *{
        AdrenoBlitRefuse(@"GPU blit subresource ranges require exactly slice zero and level zero");return nil;
    }];
}
- (void)copyFromTexture:(id<MTLTexture>)s toTexture:(id<MTLTexture>)d {
    [self adrenoCheckOpen];
    if (s.mipmapLevelCount==1 && d.mipmapLevelCount==1 && s.width==d.width && s.height==d.height) {
        [self copyFromTexture:s sourceSlice:0 sourceLevel:0 toTexture:d destinationSlice:0 destinationLevel:0 sliceCount:1 levelCount:1];
        return;
    }
    [self adrenoCopy:@"blit-texture-whole" details:@{@"source":AdrenoBlitResourceID(s),@"destination":AdrenoBlitResourceID(d)} plan:^NSData *{
        AdrenoBlitRefuse(@"Whole texture GPU blit requires matching single-level 2D extents");return nil;
    }];
}
// Levels 1..n-1 from level 0 on the GPU, in encoder order (agents/gfx-correctness FAILURE-MODES.md F1): one blit pass of
// filtered 2D-engine copies. Before, this was omitted, and trilinear sampling blended level 0 with never-written levels.
- (void)generateMipmapsForTexture:(id<MTLTexture>)t {
    [self adrenoCheckOpen];
    NSMutableDictionary *details=[@{@"texture":AdrenoBlitResourceID(t),@"levels":@(t.mipmapLevelCount),
        @"format":@(t.pixelFormat),@"width":@(t.width),@"height":@(t.height)} mutableCopy];
    id<MTLDevice> device=_adrenoCommandBuffer.device;
    if ([t isKindOfClass:[IOGPUMetalTexture class]] && t.device==device && t.mipmapLevelCount==1) {
        details[@"no_op"]=@"single mip level";
        [_adrenoCommandBuffer adrenoRecordWork:@"blit-generate-mipmaps" encoder:_adrenoEncoder omitted:NO details:details];
        return;
    }
    AdrenoBlitPass *pass=nil;
    @try {
        if (![_adrenoCommandBuffer adrenoDrawAvailable])
            AdrenoBlitRefuse(@"GPU mipmap generation requires the Adreno IB ABI");
        pass=[AdrenoBlitPass adrenoMipmapPassWithDevice:device texture:t];
        [pass finish];
    } @catch (NSException *error) {
        if ([error.name isEqualToString:NSInvalidArgumentException]) {
            details[@"reason"]=error.reason ?: @"GPU mipmap generation refused";
            [_adrenoCommandBuffer adrenoRecordWork:@"blit-generate-mipmaps" encoder:_adrenoEncoder omitted:YES details:details];
            return;
        }
        [_adrenoCommandBuffer adrenoFailEncoding];@throw;
    }
    @try { [_adrenoCommandBuffer adrenoAppendBlitPass:pass]; }
    @catch (NSException *error) { [_adrenoCommandBuffer adrenoFailEncoding];@throw; }
    [_adrenoCommandBuffer adrenoRecordWork:@"blit-generate-mipmaps" encoder:_adrenoEncoder omitted:NO details:details];
}
// Optimization selectors are hints. Shared coherent allocations need no
// managed-storage transfer; submitted producer passes already flush before fences.
- (void)adrenoCoherentHint:(NSString *)operation resource:(id<MTLResource>)resource {
    [self adrenoCheckOpen];
    if (![resource isKindOfClass:[IOGPUMetalResource class]] || resource.device!=_adrenoCommandBuffer.device) {
        [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:YES
            details:@{@"reason":@"Coherent resource hint requires this device's native allocation"}];return;
    }
    [_adrenoCommandBuffer adrenoRecordWork:operation encoder:_adrenoEncoder omitted:NO details:@{@"resource":AdrenoBlitResourceID(resource),@"no_op":@"shared coherent allocation"}];
}
- (void)optimizeContentsForGPUAccess:(id<MTLTexture>)t { [self adrenoCoherentHint:@"blit-optimize-gpu" resource:t]; }
- (void)optimizeContentsForCPUAccess:(id<MTLTexture>)t { [self adrenoCoherentHint:@"blit-optimize-cpu" resource:t]; }
- (void)synchronizeResource:(id<MTLResource>)resource { [self adrenoCoherentHint:@"blit-synchronize" resource:resource]; }
- (void)synchronizeTexture:(id<MTLTexture>)t slice:(NSUInteger)slice level:(NSUInteger)level {
    [self adrenoCheckOpen];
    NSUInteger slices=t.arrayLength;
    if (t.textureType==MTLTextureTypeCube || t.textureType==MTLTextureTypeCubeArray) {
        if (slices>NSUIntegerMax/6) slices=0; else slices*=6;
    }
    if (slice>=slices || level>=t.mipmapLevelCount) {
        [_adrenoCommandBuffer adrenoRecordWork:@"blit-synchronize-texture" encoder:_adrenoEncoder omitted:YES
            details:@{@"reason":@"Texture synchronization subresource out of range"}];return;
    }
    [self adrenoCoherentHint:@"blit-synchronize-texture" resource:t];
}
@end
