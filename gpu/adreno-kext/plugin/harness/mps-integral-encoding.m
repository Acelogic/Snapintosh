/* SPDX-License-Identifier: MIT */
// Actual MPS -> encoder -> finished compute pass -> ordered IB package.
// Failure inventory: docs/ADRENO-MPS-ENCODING-E2E-20261019.md. No GPU submission.
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
- (BOOL)adrenoDrawAvailable;
- (uint32_t)resourceID;
- (uint64_t)resourceSize;
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block;
- (id)adrenoCS;
- (NSUInteger)fillsBefore;
- (NSUInteger)passCount;
@end
static NSMutableDictionary *Report;
static NSString *Output;
static NSMapTable *EncoderStates;
static NSMapTable *CommandStorage;
static NSMutableDictionary *PipelineHandles, *PipelineNames;
static NSMutableDictionary *PendingDispatch;
static NSString *saveBytes(NSData *data,NSString *prefix);
static NSString *digest(NSData *d);
static NSString *identity(id object) { return [NSString stringWithFormat:@"%p",(__bridge void *)object]; }
static NSDictionary *resource(id object) {
    if(!object)return @{};
    NSMutableDictionary *d=[@{@"object":identity(object),@"class":NSStringFromClass([object class]),
        @"id":@([object resourceID]),@"bytes":@([object resourceSize])} mutableCopy];
    if([object conformsToProtocol:@protocol(MTLTexture)]) {
        id<MTLTexture> t=object;d[@"width"]=@(t.width);d[@"height"]=@(t.height);d[@"format"]=@(t.pixelFormat);
    }
    if([object conformsToProtocol:@protocol(MTLBuffer)]) {
        id<MTLBuffer> b=object;
        if(b.contents && b.length && b.length<=(16u<<20)) {
            NSData *bytes=[NSData dataWithBytes:b.contents length:b.length];
            d[@"contents_file"]=saveBytes(bytes,@"resource-buffer");d[@"contents_sha256"]=digest(bytes);
        }
    }
    return d;
}
static NSMutableDictionary *bindings(id encoder) {
    NSMutableDictionary *state=[EncoderStates objectForKey:encoder];
    if(!state){state=[@{@"buffers":[NSMutableDictionary dictionary],@"textures":[NSMutableDictionary dictionary],
        @"samplers":[NSMutableDictionary dictionary]} mutableCopy];[EncoderStates setObject:state forKey:encoder];}
    return state;
}
static NSArray *sizeArray(MTLSize s) { return @[@(s.width),@(s.height),@(s.depth)]; }
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
static NSString *saveBytes(NSData *data,NSString *prefix) {
    NSString *name=[NSString stringWithFormat:@"%@-%@.bin",prefix,digest(data)];
    require([data writeToFile:[Output stringByAppendingPathComponent:name] atomically:YES],@"save encoded bytes");
    return name;
}
static void installEncodingHooks(Class ce) {
    EncoderStates=[NSMapTable weakToStrongObjectsMapTable];PipelineHandles=[NSMutableDictionary dictionary];
    CommandStorage=[NSMapTable weakToStrongObjectsMapTable];
    PipelineNames=[NSMutableDictionary dictionary];
    Method available=class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"),@selector(adrenoDrawAvailable));
    require(available!=NULL,@"host-only hardware availability gate");
    method_setImplementation(available,imp_implementationWithBlock(^BOOL(id cb){(void)cb;return YES;}));
    Class cbc=NSClassFromString(@"AdrenoCommandBuffer");
    SEL reserveSelector=NSSelectorFromString(@"_reserveKernelCommandBufferSpace:");
    Method rm=class_getInstanceMethod(cbc,reserveSelector);require(rm!=NULL,@"native command reservation boundary");
    IMP reserve=method_getImplementation(rm);
    IMP recordReservation=imp_implementationWithBlock(^void *(id cb,NSUInteger capacity){
        void *pointer=((void *(*)(id,SEL,NSUInteger))reserve)(cb,reserveSelector,capacity);
        if(pointer)[CommandStorage setObject:@{@"pointer":[NSValue valueWithPointer:pointer],@"bytes":@(capacity)} forKey:cb];
        return pointer;
    });
    if(!class_addMethod(cbc,reserveSelector,recordReservation,method_getTypeEncoding(rm)))
        method_setImplementation(rm,recordReservation);
    Class usageClass=NSClassFromString(@"AdrenoResourceUsage");
    SEL usageSelector=NSSelectorFromString(@"recordResource:usage:");
    Method um=class_getInstanceMethod(usageClass,usageSelector);require(um!=NULL,@"resource publication boundary");
    IMP use=method_getImplementation(um);
    method_setImplementation(um,imp_implementationWithBlock(^(id recorder,id object,MTLResourceUsage usage){
        ((void(*)(id,SEL,id,MTLResourceUsage))use)(recorder,usageSelector,object,usage);
        NSMutableDictionary *row=[resource(object) mutableCopy];row[@"usage"]=@(usage);
        row[@"case"]=Report[@"active_case"]?:@"";[Report[@"published_resources"] addObject:row];
    }));
    Method pm=class_getInstanceMethod(ce,@selector(setComputePipelineState:));IMP pipeline=method_getImplementation(pm);
    method_setImplementation(pm,imp_implementationWithBlock(^(id enc,id p){
        bindings(enc)[@"pipeline"]=PipelineNames[identity(p)]?:@"unknown";
        ((void(*)(id,SEL,id))pipeline)(enc,@selector(setComputePipelineState:),p);
    }));
    Method tm=class_getInstanceMethod(ce,@selector(setTexture:atIndex:));IMP texture=method_getImplementation(tm);
    method_setImplementation(tm,imp_implementationWithBlock(^(id enc,id value,NSUInteger index){
        bindings(enc)[@"textures"][@(index).stringValue]=resource(value);
        ((void(*)(id,SEL,id,NSUInteger))texture)(enc,@selector(setTexture:atIndex:),value,index);
    }));
    Method bm=class_getInstanceMethod(ce,@selector(setBuffer:offset:atIndex:));IMP buffer=method_getImplementation(bm);
    method_setImplementation(bm,imp_implementationWithBlock(^(id enc,id value,NSUInteger offset,NSUInteger index){
        bindings(enc)[@"buffers"][@(index).stringValue]=@{@"resource":resource(value),@"offset":@(offset)};
        ((void(*)(id,SEL,id,NSUInteger,NSUInteger))buffer)(enc,@selector(setBuffer:offset:atIndex:),value,offset,index);
    }));
    Method dm=class_getInstanceMethod(ce,@selector(dispatchThreadgroups:threadsPerThreadgroup:));IMP dispatch=method_getImplementation(dm);
    method_setImplementation(dm,imp_implementationWithBlock(^(id enc,MTLSize groups,MTLSize threads){
        NSData *json=[NSJSONSerialization dataWithJSONObject:bindings(enc) options:0 error:NULL];
        NSMutableDictionary *row=[[NSJSONSerialization JSONObjectWithData:json options:NSJSONReadingMutableContainers error:NULL] mutableCopy];
        row[@"case"]=Report[@"active_case"]?:@"";row[@"ordinal"]=@([Report[@"dispatches"] count]);
        row[@"groups"]=sizeArray(groups);row[@"threads"]=sizeArray(threads);
        [Report[@"dispatches"] addObject:row];PendingDispatch=row;
        @try {((void(*)(id,SEL,MTLSize,MTLSize))dispatch)(enc,@selector(dispatchThreadgroups:threadsPerThreadgroup:),groups,threads);}
        @catch(NSException *error){row[@"exception"]=error.reason?:error.name;@throw;}
        @finally {PendingDispatch=nil;save();}
    }));
    Class pc=NSClassFromString(@"AdrenoIBPackage");
    Method am=class_getInstanceMethod(pc,NSSelectorFromString(@"appendPass:"));IMP append=method_getImplementation(am);
    method_setImplementation(am,imp_implementationWithBlock(^(id package,id pass){
        NSMutableArray *uses=[NSMutableArray array];
        [pass enumerateResources:^(id object,MTLResourceUsage usage){
            NSMutableDictionary *r=[resource(object) mutableCopy];r[@"usage"]=@(usage);[uses addObject:r];
        }];
        id cs=[pass adrenoCS];NSData *words=[[cs valueForKey:@"w"] copy],*data=[[cs valueForKey:@"data"] copy];
        ((void(*)(id,SEL,id))append)(package,NSSelectorFromString(@"appendPass:"),pass);
        NSMutableDictionary *row=[@{@"case":Report[@"active_case"]?:@"",@"package":identity(package),
            @"kind":NSStringFromClass([pass class]),@"pass_count":@([package passCount]),
            @"fills_before":@([package fillsBefore]),@"resources":uses,
            @"words_file":saveBytes(words,@"pass-words"),@"words_sha256":digest(words),
            @"data_file":saveBytes(data,@"pass-data"),@"data_sha256":digest(data)} mutableCopy];
        if(PendingDispatch)row[@"dispatch"]=PendingDispatch[@"ordinal"];
        [Report[@"passes"] addObject:row];save();
    }));
    Method em=class_getInstanceMethod(pc,NSSelectorFromString(@"encodeInto:capacity:"));IMP encode=method_getImplementation(em);
    method_setImplementation(em,imp_implementationWithBlock(^(id package,void *destination,NSUInteger capacity){
        ((void(*)(id,SEL,void *,NSUInteger))encode)(package,NSSelectorFromString(@"encodeInto:capacity:"),destination,capacity);
        NSData *data=[NSData dataWithBytes:destination length:capacity];
        [Report[@"packages"] addObject:@{@"case":Report[@"active_case"]?:@"",@"package":identity(package),
            @"pass_count":@([package passCount]),@"fills_before":@([package fillsBefore]),
            @"file":saveBytes(data,@"package"),@"sha256":digest(data),@"bytes":@(capacity)}];save();
    }));
}
static id<MTLTexture> textureFor(id<MTLDevice> device,MTLPixelFormat format) {
    MTLTextureDescriptor *d=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:format width:9 height:11 mipmapped:NO];
    d.storageMode=MTLStorageModeShared;d.usage=MTLTextureUsageShaderRead|MTLTextureUsageShaderWrite|MTLTextureUsageRenderTarget;
    return [device newTextureWithDescriptor:d];
}
static id<MTLSamplerState> samplerFor(id<MTLDevice> device) {
    MTLSamplerDescriptor *d=[MTLSamplerDescriptor new];d.normalizedCoordinates=NO;
    d.minFilter=d.magFilter=MTLSamplerMinMagFilterNearest;d.mipFilter=MTLSamplerMipFilterNotMipmapped;
    d.sAddressMode=d.tAddressMode=MTLSamplerAddressModeClampToZero;
    return [device newSamplerStateWithDescriptor:d];
}
static void bindKernel(id<MTLComputeCommandEncoder> encoder,id pipeline,id source,id destination,id sampler,
                       const void *bytes,NSUInteger length) {
    [encoder setComputePipelineState:pipeline];[encoder setTexture:source atIndex:0];[encoder setTexture:destination atIndex:1];
    [encoder setSamplerState:sampler atIndex:0];[encoder setBytes:bytes length:length atIndex:0];
}
static void manualCases(id<MTLDevice> device) {
    id columns=PipelineHandles[@"sum_rgba_columns"],rows=PipelineHandles[@"sum_rgba_rows"];
    require(columns && rows,@"actual MPS pipelines for API controls");
    for(NSNumber *mixed in @[@NO,@YES]) {
        NSString *name=mixed.boolValue?@"compute-fill-render-compute":@"app-bytes-snapshot";Report[@"active_case"]=name;
        id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
        __weak id weakSource,weakIntermediate,weakDestination;
        @autoreleasepool {
            id src=textureFor(device,MTLPixelFormatRGBA32Float),tmp=textureFor(device,MTLPixelFormatRGBA32Float),dst=textureFor(device,MTLPixelFormatRGBA32Float);
            weakSource=src;weakIntermediate=tmp;weakDestination=dst;id sampler=samplerFor(device);
            id<MTLComputeCommandEncoder> encoder=[cb computeCommandEncoder];uint16_t constants[6]={0,0,0,0,9,11};
            bindKernel(encoder,columns,src,tmp,sampler,constants,sizeof constants);
            memset(constants,0xed,sizeof constants); // caller storage no longer contains the bound bytes
            [encoder dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(64,1,1)];
            if(mixed.boolValue) {
                [encoder endEncoding];
                id<MTLBuffer> buffer=[device newBufferWithLength:64 options:MTLResourceStorageModeShared];
                id<MTLBlitCommandEncoder> blit=[cb blitCommandEncoder];[blit fillBuffer:buffer range:NSMakeRange(0,64) value:0x5a];[blit endEncoding];
                MTLRenderPassDescriptor *render=[MTLRenderPassDescriptor renderPassDescriptor];
                render.colorAttachments[0].texture=textureFor(device,MTLPixelFormatBGRA8Unorm);
                render.colorAttachments[0].loadAction=MTLLoadActionClear;render.colorAttachments[0].storeAction=MTLStoreActionStore;
                render.colorAttachments[0].clearColor=MTLClearColorMake(.2,.3,.4,1);
                id<MTLRenderCommandEncoder> re=[cb renderCommandEncoderWithDescriptor:render];[re endEncoding];
                encoder=[cb computeCommandEncoder];
            }
            uint16_t second[6]={0,0,0,0,9,11};bindKernel(encoder,rows,tmp,dst,sampler,second,sizeof second);
            memset(second,0xa7,sizeof second);
            [encoder dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(64,1,1)];
            [encoder setBuffer:nil offset:0 atIndex:0];[encoder setTexture:nil atIndex:0];[encoder setTexture:nil atIndex:1];
            [encoder endEncoding];
        }
        require(weakSource && weakIntermediate && weakDestination,@"resource retention after external owners and encoder bindings released");
        [cb commit];
        [Report[@"cases"] addObject:@{@"name":name,@"work":[(id)cb adrenoWorkReport],@"released_external_owners_before_commit":@YES,
            @"mutated_inline_storage_before_dispatch":@YES,@"cleared_bindings_before_commit":@YES}];save();
    }
    for(NSString *name in @[@"short-inline",@"missing-source",@"zero-grid",@"overflow-grid",@"oversized-local",@"commit-open-encoder"]) {
        Report[@"active_case"]=name;id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
        id<MTLComputeCommandEncoder> encoder=[cb computeCommandEncoder];NSUInteger before=[Report[@"intercepted_commits"] unsignedIntegerValue];
        NSString *exception=nil;
        @try {
            uint16_t constants[6]={0,0,0,0,9,11};
            bindKernel(encoder,columns,[name isEqual:@"missing-source"]?nil:textureFor(device,MTLPixelFormatRGBA32Float),
                textureFor(device,MTLPixelFormatRGBA32Float),samplerFor(device),constants,[name isEqual:@"short-inline"]?11:12);
            if([name isEqual:@"commit-open-encoder"])[cb commit];
            else [encoder dispatchThreadgroups:MTLSizeMake([name isEqual:@"overflow-grid"]?NSUIntegerMax:([name isEqual:@"zero-grid"]?0:1),1,1)
                threadsPerThreadgroup:MTLSizeMake([name isEqual:@"oversized-local"]?2048:64,1,1)];
        } @catch(NSException *error){exception=error.reason?:error.name;}
        [encoder endEncoding];
        NSDictionary *work=[(id)cb adrenoWorkReport];
        BOOL refused=exception!=nil || [work[@"omitted"] unsignedIntegerValue]>0;
        require(refused && [Report[@"intercepted_commits"] unsignedIntegerValue]==before,@"negative control escaped refusal/commit interception");
        [Report[@"controls"] addObject:@{@"name":name,@"refused":@(refused),@"exception":exception?:@"",
            @"work":work,@"native_commits":@([Report[@"intercepted_commits"] unsignedIntegerValue]-before)}];save();
    }
}
static void lifecycleCases(id<MTLDevice> device) {
    for(NSString *name in @[@"compute-blit-overlap",@"blit-compute-overlap",@"blit-render-overlap",@"commit-open-blit"]) {
        Report[@"active_case"]=name;id<MTLCommandBuffer> cb=[[device newCommandQueue] commandBuffer];
        NSUInteger before=[Report[@"intercepted_commits"] unsignedIntegerValue];
        id<MTLCommandEncoder> first=[name isEqual:@"compute-blit-overlap"]?(id<MTLCommandEncoder>)[cb computeCommandEncoder]:(id<MTLCommandEncoder>)[cb blitCommandEncoder];
        id<MTLCommandEncoder> unexpected=nil;NSString *exception=nil;
        @try {
            if([name isEqual:@"commit-open-blit"])[cb commit];
            else if([name isEqual:@"compute-blit-overlap"])unexpected=[cb blitCommandEncoder];
            else if([name isEqual:@"blit-compute-overlap"])unexpected=[cb computeCommandEncoder];
            else {
                MTLRenderPassDescriptor *render=[MTLRenderPassDescriptor renderPassDescriptor];
                render.colorAttachments[0].texture=textureFor(device,MTLPixelFormatBGRA8Unorm);
                render.colorAttachments[0].loadAction=MTLLoadActionClear;render.colorAttachments[0].storeAction=MTLStoreActionStore;
                unexpected=[cb renderCommandEncoderWithDescriptor:render];
            }
        } @catch(NSException *error){exception=error.reason?:error.name;}
        if(unexpected)[unexpected endEncoding];
        [first endEncoding]; // rejected constructors must leave this ledger intact
        NSDictionary *work=[(id)cb adrenoWorkReport];
        require(exception!=nil && [work[@"encoding_failed"] boolValue] &&
            [Report[@"intercepted_commits"] unsignedIntegerValue]==before,@"lifecycle refusal or native balance failed");
        [Report[@"controls"] addObject:@{@"name":name,@"refused":@YES,@"exception":exception,
            @"work":work,@"native_commits":@0,@"original_encoder_ended":@YES}];save();
    }
}
int main(int argc,const char **argv) { @autoreleasepool {
    if(argc!=3 && !(argc==4 && strcmp(argv[3],"--lifecycle-only")==0))return 64;
    Output=@(argv[2]);
    if(!Output.isAbsolutePath || [[NSFileManager defaultManager] fileExistsAtPath:Output])return 64;
    require([[NSFileManager defaultManager] createDirectoryAtPath:Output withIntermediateDirectories:YES attributes:nil error:NULL],@"create output");
    Report=[@{@"status":@"RUNNING",@"boundary":@"Host MPS API and Adreno compiler/encoder; no GPU submission or A16 access",
        @"host_version":NSProcessInfo.processInfo.operatingSystemVersionString,@"pipelines":[NSMutableArray array],
        @"inline_bytes":[NSMutableArray array],@"samplers":[NSMutableArray array],
        @"cases":[NSMutableArray array],@"dispatches":[NSMutableArray array],@"passes":[NSMutableArray array],
        @"packages":[NSMutableArray array],@"streams":[NSMutableArray array],@"published_resources":[NSMutableArray array],
        @"controls":[NSMutableArray array],@"intercepted_commits":@0,
        @"forced_availability_gate":@YES,@"gpu_submission":@NO} mutableCopy];
    save();
    @try {
        (void)MTLCopyAllDevices();
        NSBundle *bundle=[NSBundle bundleWithPath:@(argv[1])]; NSError *e=nil;
        require([bundle loadAndReturnError:&e],e.description);
        Class dc=[bundle classNamed:@"AdrenoMTLDevice"];
        Class ce=[bundle classNamed:@"AdrenoComputeCommandEncoder"];
        require(dc && ce,@"Adreno classes");
        installEncodingHooks(ce);
        Method commit=class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandBuffer"),@selector(commit));
        require(commit!=NULL,@"Native commit boundary");
        method_setImplementation(commit,imp_implementationWithBlock(^(id cb){
            NSDictionary *storage=[CommandStorage objectForKey:cb];require(storage!=nil,@"native command stream reservation");
            NSData *data=[NSData dataWithBytes:[storage[@"pointer"] pointerValue] length:[storage[@"bytes"] unsignedIntegerValue]];
            [Report[@"streams"] addObject:@{@"case":Report[@"active_case"]?:@"",@"file":saveBytes(data,@"stream"),
                @"sha256":digest(data),@"bytes":@(data.length)}];
            Report[@"intercepted_commits"]=@([Report[@"intercepted_commits"] unsignedIntegerValue]+1);save();
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
            if(p){ PipelineHandles[entry]=p;PipelineNames[identity(p)]=entry;
                id code=[p valueForKey:@"kernelCode"];row[@"program"]=[code valueForKey:@"program"];
                NSData *machine=[code valueForKey:@"machineCode"];
                row[@"machine_file"]=saveBytes(machine,@"shader-code");row[@"machine_sha256"]=digest(machine);
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
            bindings(enc)[@"buffers"][@(i).stringValue]=@{@"hex":hex,@"length":@(n)};
            ((void(*)(id,SEL,const void *,NSUInteger,NSUInteger))oldBytes)(enc,@selector(setBytes:length:atIndex:),b,n,i);
        }));
        Method sm=class_getInstanceMethod(ce,@selector(setSamplerState:atIndex:));
        require(sm!=NULL,@"Compute sampler boundary");IMP oldSampler=method_getImplementation(sm);
        method_setImplementation(sm,imp_implementationWithBlock(^(id enc,id sampler,NSUInteger i){
            MTLSamplerDescriptor *d=[sampler adrenoSamplerDescriptor];require(d!=nil,@"Sampler descriptor");
            [Report[@"samplers"] addObject:@{@"case":Report[@"active_case"]?:@"",@"index":@(i),
                @"normalized":@(d.normalizedCoordinates),@"min":@(d.minFilter),@"mag":@(d.magFilter),
                @"mip":@(d.mipFilter),@"s":@(d.sAddressMode),@"t":@(d.tAddressMode)}];
            bindings(enc)[@"samplers"][@(i).stringValue]=@{@"normalized":@(d.normalizedCoordinates),
                @"min":@(d.minFilter),@"mag":@(d.magFilter),@"mip":@(d.mipFilter),@"s":@(d.sAddressMode),@"t":@(d.tAddressMode)};
            ((void(*)(id,SEL,id,NSUInteger))oldSampler)(enc,@selector(setSamplerState:atIndex:),sampler,i);
        }));
        io_service_t accelerator=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("IOAccelerator"));
        require(accelerator!=0,@"Host registration provider");
        id<MTLDevice> device=[[dc alloc] initWithAcceleratorPort:accelerator];IOObjectRelease(accelerator);
        require(device!=nil,@"Adreno device");MTLAddDevice(device);
        if(argc==4){lifecycleCases(device);Report[@"status"]=@"LIFECYCLE_CAPTURE_ONLY";save();return 0;}
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
        manualCases(device);lifecycleCases(device);
        Report[@"status"]=@"ORDERED_ENCODING_CAPTURE_ONLY";save();return 0;
    } @catch(NSException *e) {
        Report[@"status"]=@"CAPTURE_FAILED";Report[@"exception"]=e.reason?:e.name;save();return 1;
    }
} }
