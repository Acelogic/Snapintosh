/* SPDX-License-Identifier: MIT */
// Failure inventory: docs/ADRENO-BLIT-ENCODING-E2E-20261019.md.
// Reuse the already qualified real MPS capture/interception machinery unchanged.
#define main AdrenoMPSCaptureMain
#include "mps-integral-encoding.m"
#undef main
#import "../AdrenoMetal/AdrenoLinearTexture.h"

@interface NSObject (BlitCapture)
- (BOOL)adrenoBufferCopyAvailable;
@end
static BOOL CopyGate=YES;
static NSMutableDictionary *ActiveCopy;
static NSPointerArray *ObservedBuffers;
static NSMutableArray *ObservedMetadata;
static NSMutableDictionary<NSNumber *,NSMutableData *> *ExpectedBuffers;

static NSDictionary *linear(id<MTLTexture> texture) {
    AdrenoLinearTextureLayout l={0};
    require([(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&l],@"recorded texture layout");
    NSMutableDictionary *r=[resource(texture) mutableCopy];
    r[@"layout"]=@{@"offset":@(l.offset),@"row_bytes":@(l.rowBytes),@"width":@(l.width),
        @"height":@(l.height),@"allocation_bytes":@(l.allocationBytes),@"format":@(l.format)};
    return r;
}
static NSString *memoryFile(uint32_t rid,NSString *suffix,NSData *data) {
    NSString *folder=[NSString stringWithFormat:@"memory/%@",Report[@"active_case"]];
    require([[NSFileManager defaultManager] createDirectoryAtPath:[Output stringByAppendingPathComponent:folder]
        withIntermediateDirectories:YES attributes:nil error:NULL],@"memory evidence folder");
    NSString *file=[folder stringByAppendingPathComponent:[NSString stringWithFormat:@"resource-%x.%@.bin",rid,suffix]];
    require([data writeToFile:[Output stringByAppendingPathComponent:file] atomically:YES],@"memory evidence");return file;
}
static void beginObservation(void) {
    ObservedBuffers=[NSPointerArray weakObjectsPointerArray];ObservedMetadata=[NSMutableArray array];
    ExpectedBuffers=[NSMutableDictionary dictionary];
}
static void observe(id<MTLBuffer> buffer) {
    uint32_t rid=[(id)buffer resourceID];
    for(NSDictionary *r in ObservedMetadata)if([r[@"id"] unsignedIntValue]==rid)return;
    require(buffer.contents && buffer.length,@"observable shared allocation");
    NSData *bytes=[NSData dataWithBytes:buffer.contents length:buffer.length];
    [ObservedBuffers addPointer:(__bridge void *)buffer];
    NSMutableDictionary *r=[resource(buffer) mutableCopy];r[@"logical_bytes"]=@(buffer.length);
    r[@"initial_file"]=memoryFile(rid,@"initial",bytes);r[@"initial_sha256"]=digest(bytes);
    [ObservedMetadata addObject:r];ExpectedBuffers[@(rid)]=[bytes mutableCopy];
}
static void unchanged(NSString *phase) {
    NSMutableArray *hashes=[NSMutableArray array];
    for(NSUInteger i=0;i<ObservedMetadata.count;i++) {
        id<MTLBuffer> b=(__bridge id)[ObservedBuffers pointerAtIndex:i];
        require(b!=nil,@"queued copy did not retain its observable allocation");
        NSString *hash=digest([NSData dataWithBytes:b.contents length:b.length]);
        require([hash isEqual:ObservedMetadata[i][@"initial_sha256"]],
            [NSString stringWithFormat:@"CPU bytes changed while encoding %@ %@",Report[@"active_case"],phase]);
        [hashes addObject:hash];
    }
    [Report[@"memory_checks"] addObject:@{@"case":Report[@"active_case"],@"phase":phase,@"hashes":hashes}];save();
}
static id<MTLBuffer> seeded(id<MTLDevice> device,NSUInteger length,uint8_t seed) {
    id<MTLBuffer> b=[device newBufferWithLength:length options:MTLResourceStorageModeShared];
    require(b.contents!=NULL,@"shared buffer allocation");
    for(NSUInteger i=0;i<length;i++)((uint8_t *)b.contents)[i]=(uint8_t)(seed+37*i+(i>>7));
    observe(b);return b;
}
static id<MTLTexture> backed(id<MTLBuffer> buffer,MTLPixelFormat format,NSUInteger width,NSUInteger height,
                           NSUInteger offset,NSUInteger pitch) {
    MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:format width:width height:height mipmapped:NO];
    d.storageMode=MTLStorageModeShared;d.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite|MTLTextureUsageRenderTarget;
    id<MTLTexture> t=[buffer newTextureWithDescriptor:d offset:offset bytesPerRow:pitch];require(t!=nil,@"buffer-backed linear texture");return t;
}
static NSDictionary *span(id source,uint64_t so,id destination,uint64_t dO,uint64_t bytes) {
    return @{@"source":@([source resourceID]),@"source_offset":@(so),@"destination":@([destination resourceID]),
             @"destination_offset":@(dO),@"bytes":@(bytes)};
}
static NSArray *rowSpans(id source,uint64_t so,uint64_t sp,id destination,uint64_t dO,uint64_t dp,uint64_t bytes,NSUInteger rows) {
    NSMutableArray *a=[NSMutableArray array];for(NSUInteger i=0;i<rows;i++)[a addObject:span(source,so+i*sp,destination,dO+i*dp,bytes)];return a;
}
static void referenceCopy(NSArray *spans) {
    for(NSDictionary *s in spans) {
        NSMutableData *src=ExpectedBuffers[s[@"source"]],*dst=ExpectedBuffers[s[@"destination"]];
        uint64_t so=[s[@"source_offset"] unsignedLongLongValue],dO=[s[@"destination_offset"] unsignedLongLongValue],n=[s[@"bytes"] unsignedLongLongValue];
        require(src && dst && so<=src.length && n<=src.length-so && dO<=dst.length && n<=dst.length-dO,@"independent API reference bounds");
        NSData *snapshot=[src subdataWithRange:NSMakeRange(so,n)];[dst replaceBytesInRange:NSMakeRange(dO,n) withBytes:snapshot.bytes];
    }
}
static void callCopy(NSString *kind,NSDictionary *arguments,NSArray *expected,BOOL model,void (^call)(void)) {
    NSMutableDictionary *r=[@{@"case":Report[@"active_case"],@"ordinal":@([Report[@"copies"] count]),@"kind":kind,
        @"arguments":arguments,@"expected_spans":expected,@"model_expected":@(model)} mutableCopy];
    [Report[@"copies"] addObject:r];ActiveCopy=r;
    @try { call();if(model)referenceCopy(expected); }
    @catch(NSException *e){r[@"exception"]=e.reason?:e.name;@throw;}
    @finally {ActiveCopy=nil;}
    unchanged(@"after-copy-call");
}
static void finishCase(id<MTLCommandBuffer> cb,NSString *name,BOOL modeled) {
    unchanged(@"after-external-owners-released");[cb commit];unchanged(@"intercepted-native-commit");
    NSMutableArray *memory=[NSMutableArray array];
    for(NSDictionary *item in ObservedMetadata) {
        NSMutableDictionary *r=[item mutableCopy];
        if(modeled){NSData *expected=ExpectedBuffers[r[@"id"]];r[@"expected_file"]=memoryFile([r[@"id"] unsignedIntValue],@"expected",expected);r[@"expected_sha256"]=digest(expected);}
        [memory addObject:r];
    }
    [Report[@"cases"] addObject:@{@"name":name,@"work":[(id)cb adrenoWorkReport],@"memory":memory,
        @"copy_only_model":@(modeled),@"released_external_owners_before_commit":@YES}];save();
}
static void copyCases(id<MTLDevice> device) {
    for(NSString *name in @[@"buffer-offsets",@"texture-buffer-rows",@"buffer-texture-rows",@"texture-texture-rows",@"whole-texture",@"rebound-buffer-chain",@"fill-copy-buffer",@"copy-fill-buffer"]) {
        Report[@"active_case"]=name;beginObservation();id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
        @autoreleasepool {
            id<MTLBuffer> source=seeded(device,16384,0x31),destination=seeded(device,16384,0xb9);
            id<MTLBlitCommandEncoder> blit=[cb blitCommandEncoder];
            if([name isEqual:@"buffer-offsets"] || [name isEqual:@"rebound-buffer-chain"] || [name hasSuffix:@"-copy-buffer"] || [name isEqual:@"copy-fill-buffer"]) {
                if([name isEqual:@"fill-copy-buffer"]) {
                    [blit fillBuffer:source range:NSMakeRange(16,8) value:0x5a];
                    memset((uint8_t *)ExpectedBuffers[@([(id)source resourceID])].mutableBytes+16,0x5a,8);unchanged(@"after-fill-before-copy");
                }
                callCopy(@"buffer-buffer",@{@"source":resource(source),@"destination":resource(destination),@"source_offset":@12,@"destination_offset":@28,@"bytes":@36},
                    @[span(source,12,destination,28,36)],YES,^{[blit copyFromBuffer:source sourceOffset:12 toBuffer:destination destinationOffset:28 size:36];});
                if([name isEqual:@"copy-fill-buffer"]) {
                    [blit fillBuffer:destination range:NSMakeRange(40,8) value:0x5a];
                    memset((uint8_t *)ExpectedBuffers[@([(id)destination resourceID])].mutableBytes+40,0x5a,8);unchanged(@"after-copy-before-fill");
                }
                if([name isEqual:@"rebound-buffer-chain"]) {
                    id<MTLBuffer> third=seeded(device,16384,0x63);
                    callCopy(@"buffer-buffer",@{@"source":resource(destination),@"destination":resource(third),@"source_offset":@28,@"destination_offset":@44,@"bytes":@36},
                        @[span(destination,28,third,44,36)],YES,^{[blit copyFromBuffer:destination sourceOffset:28 toBuffer:third destinationOffset:44 size:36];});
                }
            } else {
                BOOL whole=[name isEqual:@"whole-texture"];
                id<MTLTexture> src=backed(source,MTLPixelFormatRGBA8Unorm,13,7,64,64);
                id<MTLTexture> dst=backed(destination,MTLPixelFormatRGBA8Unorm,whole?13:17,whole?7:9,128,128);
                NSDictionary *args=@{@"source_texture":linear(src),@"destination_texture":linear(dst),
                    @"source_buffer":resource(source),@"destination_buffer":resource(destination),
                    @"source_origin":@[@2,@1,@0],@"destination_origin":@[@4,@2,@0],@"size":@[@5,@3,@1]};
                if([name isEqual:@"texture-buffer-rows"])
                    callCopy(@"texture-buffer",args,rowSpans(src,64+64+8,64,destination,20,40,20,3),YES,^{
                        [blit copyFromTexture:src sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(2,1,0) sourceSize:MTLSizeMake(5,3,1)
                            toBuffer:destination destinationOffset:20 destinationBytesPerRow:40 destinationBytesPerImage:160 options:MTLBlitOptionNone];});
                else if([name isEqual:@"buffer-texture-rows"])
                    callCopy(@"buffer-texture",args,rowSpans(source,12,36,dst,128+256+16,128,20,3),YES,^{
                        [blit copyFromBuffer:source sourceOffset:12 sourceBytesPerRow:36 sourceBytesPerImage:144 sourceSize:MTLSizeMake(5,3,1)
                            toTexture:dst destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(4,2,0) options:MTLBlitOptionNone];});
                else if(whole)
                    callCopy(@"whole-texture",args,rowSpans(src,64,64,dst,128,128,52,7),YES,^{[blit copyFromTexture:src toTexture:dst];});
                else
                    callCopy(@"texture-texture",args,rowSpans(src,64+64+8,64,dst,128+256+16,128,20,3),YES,^{
                        [blit copyFromTexture:src sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(2,1,0) sourceSize:MTLSizeMake(5,3,1)
                            toTexture:dst destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(4,2,0)];});
            }
            [blit endEncoding];unchanged(@"after-end-encoding");
        }
        finishCase(cb,name,YES);
    }
}
static void mixedCase(id<MTLDevice> device) {
    NSString *name=@"mps-copy-fill-render";Report[@"active_case"]=name;beginObservation();
    id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
    @autoreleasepool {
        id<MTLBuffer> a=seeded(device,16384,0x19),b=seeded(device,16384,0x43),c=seeded(device,16384,0xd1),fill=seeded(device,16384,0x85),color=seeded(device,16384,0x97);
        id<MTLTexture> src=backed(a,MTLPixelFormatRGBA32Float,9,11,64,192),dst=backed(b,MTLPixelFormatRGBA32Float,9,11,64,192);
        id<MTLTexture> copied=backed(c,MTLPixelFormatRGBA32Float,9,11,128,256);
        MPSImageIntegral *integral=[[MPSImageIntegral alloc] initWithDevice:device];
        [integral encodeToCommandBuffer:cb sourceTexture:src destinationTexture:dst];unchanged(@"after-mps-producer");
        id<MTLBlitCommandEncoder> blit=[cb blitCommandEncoder];
        callCopy(@"texture-texture",@{@"source_texture":linear(dst),@"destination_texture":linear(copied),@"size":@[@9,@11,@1]},
            rowSpans(dst,64,192,copied,128,256,144,11),NO,^{[blit copyFromTexture:dst toTexture:copied];});
        [blit fillBuffer:fill range:NSMakeRange(32,64) value:0x5a];[blit endEncoding];unchanged(@"after-copy-fill");
        MTLRenderPassDescriptor *render=[MTLRenderPassDescriptor renderPassDescriptor];
        render.colorAttachments[0].texture=backed(color,MTLPixelFormatBGRA8Unorm,9,11,64,64);
        render.colorAttachments[0].loadAction=MTLLoadActionClear;render.colorAttachments[0].storeAction=MTLStoreActionStore;
        render.colorAttachments[0].clearColor=MTLClearColorMake(.2,.3,.4,1);id<MTLRenderCommandEncoder> re=[cb renderCommandEncoderWithDescriptor:render];[re endEncoding];
        unchanged(@"after-render");
    }
    finishCase(cb,name,NO);
}
static void refusedCases(id<MTLDevice> device) {
    for(NSString *name in @[@"bad-buffer-range",@"overflow-offset",@"unaligned-offset",@"overlap",@"short-row-pitch",@"bad-texture-origin",@"format-mismatch",@"unsupported-option",@"unsupported-level",@"unsupported-slice",@"missing-copy-abi",@"mipmap-refusal"]) {
        Report[@"active_case"]=name;beginObservation();id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
        id<MTLBuffer> source=seeded(device,4096,0x17),destination=seeded(device,4096,0xb3);
        id<MTLTexture> src=backed(source,MTLPixelFormatRGBA8Unorm,13,7,64,64);
        id<MTLTexture> dst=backed(destination,[name isEqual:@"format-mismatch"]?MTLPixelFormatBGRA8Unorm:MTLPixelFormatRGBA8Unorm,17,9,128,128);
        id<MTLBlitCommandEncoder> blit=[cb blitCommandEncoder];NSUInteger passCount=[Report[@"passes"] count];NSString *exception=nil;
        CopyGate=![name isEqual:@"missing-copy-abi"];
        @try {
            if([name isEqual:@"mipmap-refusal"]) {
                MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:8 height:8 mipmapped:YES];
                d.storageMode=MTLStorageModeShared;d.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite;
                [blit generateMipmapsForTexture:[device newTextureWithDescriptor:d]];
            } else if([@[@"bad-buffer-range",@"overflow-offset",@"unaligned-offset",@"overlap",@"missing-copy-abi"] containsObject:name]) {
                NSUInteger off=[name isEqual:@"bad-buffer-range"]?4092:[name isEqual:@"overflow-offset"]?NSUIntegerMax:[name isEqual:@"unaligned-offset"]?1:0;
                [blit copyFromBuffer:source sourceOffset:off toBuffer:[name isEqual:@"overlap"]?source:destination destinationOffset:4 size:8];
            } else if([name isEqual:@"short-row-pitch"] || [name isEqual:@"unsupported-option"])
                [blit copyFromTexture:src sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0,0,0) sourceSize:MTLSizeMake(5,3,1)
                    toBuffer:destination destinationOffset:0 destinationBytesPerRow:[name isEqual:@"short-row-pitch"]?16:40 destinationBytesPerImage:160
                    options:[name isEqual:@"unsupported-option"]?MTLBlitOptionDepthFromDepthStencil:MTLBlitOptionNone];
            else [blit copyFromTexture:src sourceSlice:[name isEqual:@"unsupported-slice"]?1:0 sourceLevel:[name isEqual:@"unsupported-level"]?1:0
                sourceOrigin:MTLOriginMake([name isEqual:@"bad-texture-origin"]?14:0,0,0) sourceSize:MTLSizeMake(5,3,1)
                toTexture:dst destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(0,0,0)];
        } @catch(NSException *e){exception=e.reason?:e.name;} @finally {CopyGate=YES;}
        [blit endEncoding];unchanged(@"refused-encoding");NSDictionary *work=[(id)cb adrenoWorkReport];
        require([work[@"omitted"] unsignedIntegerValue]==1 && [work[@"encoded"] unsignedIntegerValue]==0 && [Report[@"passes"] count]==passCount,
            [NSString stringWithFormat:@"unsupported copy/mipmap was not explicitly omitted: %@",name]);
        [Report[@"controls"] addObject:@{@"name":name,@"refused":@YES,@"exception":exception?:@"",@"work":work,@"partial_passes":@0,
            @"memory":[ObservedMetadata copy]}];save();
    }
}
int main(int argc,const char **argv) { @autoreleasepool {
    if(argc!=3)return 64;
    int prelude=AdrenoMPSCaptureMain(argc,argv);if(prelude)return prelude;
    NSDictionary *prior=[Report copy];
    require([[NSFileManager defaultManager] copyItemAtPath:[Output stringByAppendingPathComponent:@"capture.json"]
        toPath:[Output stringByAppendingPathComponent:@"mps-baseline-capture.json"] error:NULL],@"preserve MPS prelude");
    Report=[@{@"status":@"RUNNING",@"boundary":@"Host API and queued GPU copy encoding; native commit intercepted; no GPU execution or A16 access",
        @"pipelines":[prior[@"pipelines"] mutableCopy],@"inline_bytes":[NSMutableArray array],@"samplers":[NSMutableArray array],
        @"cases":[NSMutableArray array],@"dispatches":[NSMutableArray array],@"passes":[NSMutableArray array],@"packages":[NSMutableArray array],
        @"streams":[NSMutableArray array],@"published_resources":[NSMutableArray array],@"controls":[NSMutableArray array],
        @"copies":[NSMutableArray array],@"memory_checks":[NSMutableArray array],@"completion_handlers":[NSMutableArray array],
        @"intercepted_commits":@0,@"forced_availability_gates":@YES,@"gpu_submission":@NO} mutableCopy];save();
    @try {
        id<MTLDevice> device=[(id<MTLComputePipelineState>)PipelineHandles[@"sum_rgba_columns"] device];require(device!=nil,@"retained real MPS device");
        Method gate=class_getInstanceMethod([device class],@selector(adrenoBufferCopyAvailable));require(gate!=NULL,@"CopyABI gate");
        method_setImplementation(gate,imp_implementationWithBlock(^BOOL(id d){(void)d;return CopyGate;}));
        Class pc=NSClassFromString(@"AdrenoIBPackage");SEL selector=NSSelectorFromString(@"appendPass:");
        Method am=class_getInstanceMethod(pc,selector);IMP append=method_getImplementation(am);
        method_setImplementation(am,imp_implementationWithBlock(^(id package,id pass){
            ((void(*)(id,SEL,id))append)(package,selector,pass);
            if(ActiveCopy)[Report[@"passes"] lastObject][@"copy_ordinal"]=ActiveCopy[@"ordinal"];
        }));
        Class cc=NSClassFromString(@"AdrenoCommandBuffer");SEL completed=@selector(addCompletedHandler:);
        Method cm=class_getInstanceMethod(cc,completed);IMP oldCompleted=method_getImplementation(cm);
        IMP trackCompleted=imp_implementationWithBlock(^(id cb,id handler){
            if(ActiveCopy)[Report[@"completion_handlers"] addObject:@{@"case":Report[@"active_case"],@"copy_ordinal":ActiveCopy[@"ordinal"]}];
            ((void(*)(id,SEL,id))oldCompleted)(cb,completed,handler);
        });
        if(!class_addMethod(cc,completed,trackCompleted,method_getTypeEncoding(cm)))method_setImplementation(cm,trackCompleted);
        copyCases(device);mixedCase(device);refusedCases(device);
        require([Report[@"completion_handlers"] count]==0,@"copy registered CPU completion replay");
        Report[@"status"]=@"QUEUED_BLIT_ENCODING_CAPTURE_ONLY";save();return 0;
    } @catch(NSException *e){Report[@"status"]=@"CAPTURE_FAILED";Report[@"exception"]=e.reason?:e.name;save();return 1;}
} }
