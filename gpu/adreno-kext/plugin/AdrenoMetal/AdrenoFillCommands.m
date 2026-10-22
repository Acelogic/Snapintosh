/* SPDX-License-Identifier: MIT */
#import "AdrenoFillCommands.h"
#import "AdrenoLinearTexture.h"
#define ADRENO_EARLY_STOP_FILE 1u   /* early-stop failure site tag (AdrenoEarlyStop.h) */
#import "AdrenoEarlyStop.h"
#include <math.h>
#include "../../../../compat/adreno-fill-command.h"

struct FillCommand {
    struct adreno_submit_header header;
    uint32_t resourceID,pattern;
    uint64_t offset,bytes;
};
_Static_assert(sizeof(struct FillCommand)==32,"Adreno fill wire size");
_Static_assert(offsetof(struct FillCommand,offset)==16,"Adreno fill offset layout");

static uint32_t clearChannel(double value) {
    if (!isfinite(value))
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear requires finite color components");
    // The measured Metal clear path converts to float before UNorm packing.
    float clipped=(float)fmin(1.0,fmax(0.0,value));
    float scaled=clipped*255.0f;
    return (uint32_t)floorf(scaled+0.5f);
}

@implementation AdrenoFillCommands {
    AdrenoResourceUsage *_resources;
    NSMutableData *_commands;
    NSUInteger _fillBytes;
    BOOL _sealed,_failed;
}
- (instancetype)initWithResources:(AdrenoResourceUsage *)resources {
    if (!resources) ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Missing Adreno fill resource recorder");
    if ((self=[super init])) { _resources=resources;_commands=[NSMutableData data]; }
    return self;
}
- (void)recordBuffer:(id<MTLBuffer>)buffer range:(NSRange)range value:(uint8_t)value {
    if (_sealed || _failed)
        ADRENO_RAISE_FATAL(NSInternalInconsistencyException, @"Adreno fill encoding has ended");
    if (![buffer isKindOfClass:[IOGPUMetalBuffer class]])
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno fill requires a native Metal buffer");
    NSUInteger length=buffer.length;
    if (range.location>length || range.length>length-range.location ||
        ((range.location|range.length)&3) || range.length>ADRENO_FILL32_MAX_BYTES)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno fill requires an in-bounds dword-aligned range of at most16KiB");
    if (!range.length) return;
    if (_commands.length/sizeof(struct FillCommand)>=64 ||
        range.length>ADRENO_FILL32_MAX_BYTES-_fillBytes)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno command buffer fill budget exceeded");
    IOGPUMetalBuffer *native=(IOGPUMetalBuffer *)buffer;
    uint32_t rid=[native resourceID];
    if (!rid) ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno fill resource has no identifier");
    struct FillCommand command={{ADRENO_KCMD_FILL32,sizeof command},rid,
        (uint32_t)value*0x01010101u,range.location,range.length};
    // This validates device and native resource metadata and retains through
    // the ordinary Metal list if the command buffer requested retention.
    [_resources recordResource:buffer usage:MTLResourceUsageWrite];
    @try { [_commands appendBytes:&command length:sizeof command]; }
    @catch (NSException *error) { _failed=YES;@throw; }
    _fillBytes+=range.length;
}
- (void)recordClearPass:(MTLRenderPassDescriptor *)pass { [self recordClearPass:pass refusal:nil]; }
// refusal: why the IB builder did not build this pass (AdrenoCommandBuffer), carried into every refusal here.
- (void)recordClearPass:(MTLRenderPassDescriptor *)pass refusal:(NSString *)refusal {
    NSString *passWhy = refusal ? [@"; render pass: " stringByAppendingString:refusal] : @"";
    if (_sealed || _failed)
        ADRENO_RAISE_FATAL(NSInternalInconsistencyException, @"Adreno clear encoding has ended");
    if (!pass || pass.depthAttachment.texture || pass.stencilAttachment.texture ||
        pass.renderTargetArrayLength>1 || pass.defaultRasterSampleCount>1)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Unsupported Adreno render-pass attachments%@", passWhy);
    for (NSUInteger n=1;n<8;n++)
        if (pass.colorAttachments[n].texture)
            ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear currently supports color attachment0 only%@", passWhy);
    MTLRenderPassColorAttachmentDescriptor *attachment=pass.colorAttachments[0];
    if (!attachment.texture || attachment.loadAction!=MTLLoadActionClear) return;
    id<MTLTexture> texture=attachment.texture;
    if (![texture isKindOfClass:[IOGPUMetalTexture class]] ||
        ![texture respondsToSelector:@selector(adrenoGetLinearLayout:)] ||
        attachment.level || attachment.slice || attachment.depthPlane || attachment.resolveTexture ||
        (attachment.storeAction!=MTLStoreActionStore && attachment.storeAction!=MTLStoreActionDontCare) ||
        texture.textureType!=MTLTextureType2D || texture.sampleCount!=1 ||
        texture.mipmapLevelCount!=1 || texture.arrayLength!=1 || texture.depth!=1 ||
        !(texture.usage&MTLTextureUsageRenderTarget))
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear requires a recorded linear2D texture; target %@%@",
                           AdrenoDescribeTarget(texture), passWhy);
    // docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md A: the same conditions as before, each named.
    AdrenoLinearTextureLayout geometry={0};
    NSString *why=nil;
    if (![(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&geometry]) why=@"no recorded linear layout";
    else if (geometry.width!=texture.width || geometry.height!=texture.height || !geometry.width || !geometry.height)
        why=[NSString stringWithFormat:@"layout %llux%llu differs from the texture",geometry.width,geometry.height];
    else if (geometry.format!=texture.pixelFormat)
        why=[NSString stringWithFormat:@"layout format %lu differs from the texture's",(unsigned long)geometry.format];
    else if (geometry.format!=MTLPixelFormatRGBA8Unorm && geometry.format!=MTLPixelFormatBGRA8Unorm)
        why=[NSString stringWithFormat:@"format %lu has no FILL32 clear",(unsigned long)geometry.format];
    else if (geometry.allocationBytes!=AdrenoGPUBackingSize(texture))
        why=[NSString stringWithFormat:@"layout allocation %llu differs from the resource size",geometry.allocationBytes];
    else if (pass.renderTargetWidth>geometry.width || pass.renderTargetHeight>geometry.height)
        why=[NSString stringWithFormat:@"render target area %lux%lu exceeds the texture",(unsigned long)pass.renderTargetWidth,
             (unsigned long)pass.renderTargetHeight];
    if (why)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear texture geometry is unavailable or inconsistent: %@; target %@%@",
                           why, AdrenoDescribeTarget(texture), passWhy);
    uint64_t width=pass.renderTargetWidth ?: geometry.width;
    uint64_t height=pass.renderTargetHeight ?: geometry.height;
    uint64_t widthBytes=width*4;
    uint64_t allocationWidthBytes=geometry.width*4;
    if (geometry.width>UINT64_MAX/4 || geometry.rowBytes<allocationWidthBytes ||
        ((geometry.offset|geometry.rowBytes)&3) || geometry.offset>geometry.allocationBytes ||
        allocationWidthBytes>geometry.allocationBytes-geometry.offset ||
        geometry.height-1>(geometry.allocationBytes-geometry.offset-allocationWidthBytes)/geometry.rowBytes ||
        height>ADRENO_FILL32_MAX_BYTES/widthBytes)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear exceeds its linear allocation or16KiB limit; target %@%@",
                           AdrenoDescribeTarget(texture), passWhy);
    uint64_t bytes=widthBytes*height;
    NSUInteger count=geometry.rowBytes==widthBytes ? 1 : (NSUInteger)height;
    if (count>64-_commands.length/sizeof(struct FillCommand) || bytes>ADRENO_FILL32_MAX_BYTES-_fillBytes)
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno command buffer clear budget exceeded");
    // A shadowed IOSurface texture is cleared in its aligned shadow (docs/USERSPACE-GRAPHICS-20261019.md).
    id backing=AdrenoGPUBacking(texture);
    uint32_t rid=[(IOGPUMetalResource *)backing resourceID];
    if (!rid) ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno clear resource has no identifier");
    MTLClearColor color=attachment.clearColor;
    uint32_t r=clearChannel(color.red),g=clearChannel(color.green),b=clearChannel(color.blue),a=clearChannel(color.alpha);
    uint32_t pattern=geometry.format==MTLPixelFormatBGRA8Unorm ? b|(g<<8)|(r<<16)|(a<<24) : r|(g<<8)|(b<<16)|(a<<24);
    NSMutableData *pending=[NSMutableData dataWithCapacity:count*sizeof(struct FillCommand)];
    for(NSUInteger row=0;row<count;row++) {
        struct FillCommand command={{ADRENO_KCMD_FILL32,sizeof command},rid,pattern,
            geometry.offset+row*geometry.rowBytes,count==1 ? bytes : widthBytes};
        [pending appendBytes:&command length:sizeof command];
    }
    // Complete preflight precedes retention or publication. Native BeginSegment
    // later publishes one write-use descriptor for the entire texture.
    [_resources recordResource:backing usage:MTLResourceUsageWrite];
    @try { [_commands appendData:pending]; }
    @catch (NSException *error) { _failed=YES;@throw; }
    _fillBytes+=bytes;
}
- (NSUInteger)commandBytes { return _commands.length+sizeof(struct adreno_submit_header); }
- (void)encodeInto:(void *)destination capacity:(NSUInteger)capacity {
    if (_sealed || _failed)
        ADRENO_RAISE_FATAL(NSInternalInconsistencyException, @"Adreno fill commands were already emitted or failed");
    if (!destination || capacity!=[self commandBytes])
        ADRENO_RAISE_FATAL(NSInvalidArgumentException, @"Adreno fill command reservation differs");
    _sealed=YES;
    if (_commands.length) memcpy(destination,_commands.bytes,_commands.length);
    struct adreno_submit_header fence={ADRENO_KCMD_FENCE,sizeof fence};
    memcpy((char *)destination+_commands.length,&fence,sizeof fence);
}
@end
