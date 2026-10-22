/* SPDX-License-Identifier: MIT */
// Real MPSImageIntegral -> Adreno pipeline/encoder capture. Never submits GPU work.
// Failure inventory: docs/ADRENO-COMPUTE-RECOVERY-20261018.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <MetalPerformanceShaders/MetalPerformanceShaders.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (Capture)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (MTLSamplerDescriptor *)adrenoSamplerDescriptor;
@end
static NSMutableDictionary *Report;
static NSString *Output;
static NSString *digest(NSData *d) {
    unsigned char h[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(d.bytes,(CC_LONG)d.length,h);
    NSMutableString *s=[NSMutableString string]; for(unsigned i=0;i<sizeof h;i++)[s appendFormat:@"%02x",h[i]];
    return s;
}
static void save(void) {
    NSData *d=[NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:NULL];
    if(!d || ![d writeToFile:[Output stringByAppendingPathComponent:@"capture.json"] atomically:YES]) _exit(73);
}
static void require(BOOL b, NSString *s) {
    if(!b)[NSException raise:@"CaptureFailure" format:@"%@",s];
}
int main(int argc,const char **argv) { @autoreleasepool {
    if(argc!=3)return 64;
    Output=@(argv[2]);
    if(!Output.isAbsolutePath || [[NSFileManager defaultManager] fileExistsAtPath:Output])return 64;
    require([[NSFileManager defaultManager] createDirectoryAtPath:Output withIntermediateDirectories:YES attributes:nil error:NULL],@"create output");
    Report=[@{@"status":@"RUNNING",@"boundary":@"Host MPS API and Adreno compiler/encoder; no GPU submission or A16 access",
        @"host_version":NSProcessInfo.processInfo.operatingSystemVersionString,@"pipelines":[NSMutableArray array],
        @"inline_bytes":[NSMutableArray array],@"samplers":[NSMutableArray array],
        @"cases":[NSMutableArray array],@"intercepted_commits":@0} mutableCopy];
    save();
    @try {
        (void)MTLCopyAllDevices();
        NSBundle *bundle=[NSBundle bundleWithPath:@(argv[1])]; NSError *e=nil;
        require([bundle loadAndReturnError:&e],e.description);
        Class dc=[bundle classNamed:@"AdrenoMTLDevice"];
        Class ce=[bundle classNamed:@"AdrenoComputeCommandEncoder"];
        require(dc && ce,@"Adreno classes");
        Method commit=class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandBuffer"),@selector(commit));
        require(commit!=NULL,@"Native commit boundary");
        method_setImplementation(commit,imp_implementationWithBlock(^(id cb){
            (void)cb;Report[@"intercepted_commits"]=@([Report[@"intercepted_commits"] unsignedIntegerValue]+1);save();
        }));
        SEL ps=NSSelectorFromString(@"newComputePipelineWithDescriptor:variant:errorMessage:");
        Method pm=class_getInstanceMethod(dc,ps);require(pm!=NULL,@"Compute pipeline callback");
        IMP original=method_getImplementation(pm);
        method_setImplementation(pm,imp_implementationWithBlock(^id(id dev,MTLComputePipelineDescriptor *desc,id variant,NSString **err){
            id input=[variant valueForKey:@"input"];NSData *air=[input valueForKey:@"airModule"];
            NSString *entry=[input valueForKey:@"entry"];
            require(air && entry,@"Compiler input");NSString *hash=digest(air);
            NSString *file=[NSString stringWithFormat:@"%@.bc",hash];
            require([air writeToFile:[Output stringByAppendingPathComponent:file] atomically:YES],@"Save AIR");
            NSMutableDictionary *row=[@{@"entry":entry,@"air_file":file,@"air_sha256":hash,@"air_bytes":@(air.length)} mutableCopy];
            [Report[@"pipelines"] addObject:row];save();
            id p=((id(*)(id,SEL,id,id,NSString **))original)(dev,ps,desc,variant,err);
            row[@"compiled"]=@(p!=nil);
            if(p){ id code=[p valueForKey:@"kernelCode"];row[@"program"]=[code valueForKey:@"program"];
                row[@"sidecar"]=[code valueForKey:@"sidecar"]; }
            else row[@"error"]=(err && *err)?*err:@"unknown";
            save();return p;
        }));
        Method bm=class_getInstanceMethod(ce,@selector(setBytes:length:atIndex:));
        require(bm!=NULL,@"Compute inline constant boundary");IMP oldBytes=method_getImplementation(bm);
        method_setImplementation(bm,imp_implementationWithBlock(^(id enc,const void *b,NSUInteger n,NSUInteger i){
            require(n<=4096 && (b || !n),@"Bounded inline constants");
            NSMutableString *hex=[NSMutableString string];for(NSUInteger k=0;k<n;k++)[hex appendFormat:@"%02x",((const uint8_t *)b)[k]];
            [Report[@"inline_bytes"] addObject:@{@"case":Report[@"active_case"]?:@"",@"index":@(i),@"hex":hex}];
            ((void(*)(id,SEL,const void *,NSUInteger,NSUInteger))oldBytes)(enc,@selector(setBytes:length:atIndex:),b,n,i);
        }));
        Method sm=class_getInstanceMethod(ce,@selector(setSamplerState:atIndex:));
        require(sm!=NULL,@"Compute sampler boundary");IMP oldSampler=method_getImplementation(sm);
        method_setImplementation(sm,imp_implementationWithBlock(^(id enc,id sampler,NSUInteger i){
            MTLSamplerDescriptor *d=[sampler adrenoSamplerDescriptor];require(d!=nil,@"Sampler descriptor");
            [Report[@"samplers"] addObject:@{@"case":Report[@"active_case"]?:@"",@"index":@(i),
                @"normalized":@(d.normalizedCoordinates),@"min":@(d.minFilter),@"mag":@(d.magFilter),
                @"mip":@(d.mipFilter),@"s":@(d.sAddressMode),@"t":@(d.tAddressMode)}];
            ((void(*)(id,SEL,id,NSUInteger))oldSampler)(enc,@selector(setSamplerState:atIndex:),sampler,i);
        }));
        io_service_t accelerator=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("IOAccelerator"));
        require(accelerator!=0,@"Host registration provider");
        id<MTLDevice> device=[[dc alloc] initWithAcceleratorPort:accelerator];IOObjectRelease(accelerator);
        require(device!=nil,@"Adreno device");MTLAddDevice(device);
        // 63x65 crosses a workgroup boundary on only one axis: this detects a
        // row dispatch that accidentally reuses the column group count.
        for(NSNumber *size in @[@1,@2,@3,@4,@5,@17,@63,@65,@129,@0]) {
            BOOL offset=size.unsignedIntegerValue==0;
            NSUInteger w=offset?9:size.unsignedIntegerValue,h=w+2;
            NSString *name=offset?@"offset-clip":[NSString stringWithFormat:@"%lux%lu",(unsigned long)w,(unsigned long)h];Report[@"active_case"]=name;
            MTLTextureDescriptor *td=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA32Float width:w height:h mipmapped:NO];
            td.storageMode=MTLStorageModeShared;td.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite;
            id<MTLTexture> src=[device newTextureWithDescriptor:td],dst=[device newTextureWithDescriptor:td];
            require(src && dst,@"Textures");
            id<MTLCommandQueue> queue=[device newCommandQueue];id<MTLCommandBuffer> cb=[queue commandBuffer];
            MPSImageIntegral *integral=[[MPSImageIntegral alloc] initWithDevice:device];
            require(integral!=nil,@"MPS integral");
            if(offset){integral.offset=(MPSOffset){1,2,0};integral.clipRect=MTLRegionMake2D(2,1,5,7);}
            [integral encodeToCommandBuffer:cb sourceTexture:src destinationTexture:dst];
            [cb commit];
            [Report[@"cases"] addObject:@{@"name":name,@"work":[(id)cb adrenoWorkReport]}];save();
        }
        Report[@"status"]=@"ENCODING_CAPTURE_ONLY";save();return 0;
    } @catch(NSException *e) {
        Report[@"status"]=@"CAPTURE_FAILED";Report[@"exception"]=e.reason?:e.name;save();return 1;
    }
} }
