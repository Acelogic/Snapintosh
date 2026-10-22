/* SPDX-License-Identifier: MIT */
// Production Metal clear recorder -> native resource packing -> driver stream.
// Texture backing and destruction are fixtures; no host GPU is opened here.
#import "../AdrenoMetal/AdrenoFillCommands.h"
#import "../AdrenoMetal/AdrenoLinearTexture.h"
#import <objc/runtime.h>
#import <dlfcn.h>
#include <assert.h>
#include "../../../../compat/adreno-fill-command.h"

// Declare the requested behavior before implementing it, so the baseline
// compiles and fails on the missing clear operation rather than a missing file.
@interface AdrenoFillCommands (ClearExpected)
- (void)recordClearPass:(MTLRenderPassDescriptor *)pass;
@end
@protocol ClearRetentionList
- (instancetype)initWithCapacity:(int)capacity;
- (void)releaseAllObjectsAndReset;
@end
@interface ClearTextureFixture : IOGPUMetalTexture <AdrenoLinearTexture>
@property(nonatomic,strong) id fixtureDevice;
@property(nonatomic) AdrenoLinearTextureLayout geometry;
@property(nonatomic) BOOL geometryValid;
@end
@implementation ClearTextureFixture
- (id)device { return self.fixtureDevice; }
- (BOOL)adrenoGetLinearLayout:(AdrenoLinearTextureLayout *)layout {
    if (!self.geometryValid) return NO;
    *layout=self.geometry; return YES;
}
- (NSUInteger)width { return self.geometry.width; }
- (NSUInteger)height { return self.geometry.height; }
- (NSUInteger)depth { return 1; }
- (NSUInteger)arrayLength { return 1; }
- (NSUInteger)mipmapLevelCount { return 1; }
- (NSUInteger)sampleCount { return 1; }
- (MTLTextureType)textureType { return MTLTextureType2D; }
- (MTLPixelFormat)pixelFormat { return self.geometry.format; }
- (MTLTextureUsage)usage { return MTLTextureUsageRenderTarget; }
- (void *)contents { abort(); }
- (void *)iosurface { abort(); }
@end
static ClearTextureFixture *texture(id device,NSUInteger format) {
    ClearTextureFixture *t=[ClearTextureFixture new];
    t.fixtureDevice=device;t.geometryValid=YES;
    t.geometry=(AdrenoLinearTextureLayout){0x3f00,256,37,23,0x8000,format};
    Ivar ivar=class_getInstanceVariable(objc_getClass("IOGPUMetalResource"),"_res");
    assert(ivar && ivar_getOffset(ivar)==24);
    struct {uint64_t surface,size;uint32_t rid,padding;} info={0,0x8000,7,0};
    memcpy((char *)(__bridge void *)t+ivar_getOffset(ivar)+32,&info,sizeof info);
    return t;
}
static BOOL refuses(void (^work)(void)) {
    @try {work();return NO;} @catch(NSException *e) {return YES;}
}
static void unexpectedGrowth(void *context) { abort(); }
static MTLRenderPassDescriptor *passFor(ClearTextureFixture *texture,NSArray *color) {
    MTLRenderPassDescriptor *p=[MTLRenderPassDescriptor renderPassDescriptor];
    p.colorAttachments[0].texture=(id<MTLTexture>)texture;
    p.colorAttachments[0].loadAction=MTLLoadActionClear;
    p.colorAttachments[0].storeAction=MTLStoreActionStore;
    p.colorAttachments[0].clearColor=MTLClearColorMake([color[0] doubleValue],[color[1] doubleValue],
        [color[2] doubleValue],[color[3] doubleValue]);
    return p;
}
int main(int argc,char **argv) {
    @autoreleasepool {
        assert(argc==3);
        NSData *raw=[NSData dataWithContentsOfFile:@(argv[1])];
        NSDictionary *reference=[NSJSONSerialization JSONObjectWithData:raw options:0 error:nil];
        assert([reference[@"status"] isEqual:@"APPLE_GPU_CLEAR_REFERENCE_COMPLETE"]);
        NSString *out=@(argv[2]);
        assert(![[NSFileManager defaultManager] fileExistsAtPath:out]);
        assert([[NSFileManager defaultManager] createDirectoryAtPath:out withIntermediateDirectories:YES attributes:nil error:nil]);
        void *iogpu=dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU",RTLD_NOW);
        assert(iogpu);
        SEL dealloc=sel_registerName("dealloc");
        Method root=class_getInstanceMethod([NSObject class],dealloc);
        for (NSString *name in @[@"IOGPUMetalResource",@"IOGPUMetalTexture"])
            class_replaceMethod(objc_getClass(name.UTF8String),dealloc,
                method_getImplementation(root),method_getTypeEncoding(root));
        void (*init)(void *,void *,uint64_t,uint64_t,uint32_t,void (*)(void *),void *)=dlsym(iogpu,"IOGPUResourceListInit");
        void (*reset)(void *,void *,uint64_t,uint32_t)=dlsym(iogpu,"IOGPUResourceListReset");
        assert(init && reset);
        id device=[NSObject new];
        NSMutableArray *results=[NSMutableArray array];
        for (NSDictionary *expected in reference[@"cases"]) {
            id<ClearRetentionList> retained=[(id<ClearRetentionList>)[objc_getClass("MTLResourceList") alloc] initWithCapacity:32];
            AdrenoResourceUsage *uses=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:retained];
            AdrenoFillCommands *fills=[[AdrenoFillCommands alloc] initWithResources:uses];
            assert([fills respondsToSelector:@selector(recordClearPass:)] && "render-pass clear is missing");
            __weak ClearTextureFixture *weak;
            @autoreleasepool {
                ClearTextureFixture *t=texture(device,[expected[@"format"] unsignedIntegerValue]);weak=t;
                MTLRenderPassDescriptor *pass=passFor(t,expected[@"color"]);
                AdrenoLinearTextureLayout good=t.geometry;
                t.geometryValid=NO;
                assert(refuses(^{[fills recordClearPass:pass];}));t.geometryValid=YES;
                AdrenoLinearTextureLayout bad=good;bad.rowBytes=144;t.geometry=bad;
                assert(refuses(^{[fills recordClearPass:pass];}));
                bad=good;bad.offset=UINT64_MAX-3;t.geometry=bad;
                assert(refuses(^{[fills recordClearPass:pass];}));
                bad=good;bad.height=65;t.geometry=bad;
                assert(refuses(^{[fills recordClearPass:pass];}));t.geometry=good;
                pass.colorAttachments[0].level=1;
                assert(refuses(^{[fills recordClearPass:pass];}));pass.colorAttachments[0].level=0;
                pass.colorAttachments[0].resolveTexture=(id<MTLTexture>)t;
                assert(refuses(^{[fills recordClearPass:pass];}));pass.colorAttachments[0].resolveTexture=nil;
                pass.colorAttachments[1].texture=(id<MTLTexture>)t;
                assert(refuses(^{[fills recordClearPass:pass];}));pass.colorAttachments[1].texture=nil;
                assert([fills commandBytes]==8);
                [fills recordClearPass:pass];
            }
            @autoreleasepool {assert(weak);}
            assert([fills commandBytes]==23*32+8);
            NSMutableData *stream=[NSMutableData dataWithLength:[fills commandBytes]];
            [fills encodeInto:stream.mutableBytes capacity:stream.length];
            for(NSUInteger row=0;row<23;row++) {
                struct adreno_fill32_request req;
                assert(adreno_fill32_decode((const char *)stream.bytes+row*32,stream.length-row*32,&req)==0);
                assert(req.resource_id==7 && req.offset==0x3f00+row*256 && req.bytes==37*4);
                assert(req.pattern==[expected[@"pixel_word"] unsignedIntValue]);
            }
            void *list=calloc(1,4096),*groups=calloc(1,4096),*context=calloc(1,256);
            *(void **)((char *)context+0x70)=(char *)groups+4096;
            init(list,groups,4096,1ull<<30,7,unexpectedGrowth,context);
            reset(list,groups,4096,1);
            [uses encodeIntoIOGPUList:list];
            uint32_t count=*(uint32_t *)((char *)list+0x220);assert(count==1);
            uint8_t descriptors[96]={0};memcpy(descriptors+28,&count,4);memcpy(descriptors+32,groups,64);
            NSString *stem=[NSString stringWithFormat:@"case-%lu",(unsigned long)results.count];
            NSString *commands=[stem stringByAppendingString:@"-commands.bin"];
            NSString *metadata=[stem stringByAppendingString:@"-descriptors.bin"];
            assert([stream writeToFile:[out stringByAppendingPathComponent:commands] atomically:YES]);
            assert([[NSData dataWithBytes:descriptors length:sizeof descriptors]
                writeToFile:[out stringByAppendingPathComponent:metadata] atomically:YES]);
            NSMutableDictionary *result=[expected mutableCopy];result[@"commands"]=commands;result[@"descriptors"]=metadata;
            result[@"offset"]=@(0x3f00);result[@"row_bytes"]=@256;
            [results addObject:result];
            [retained releaseAllObjectsAndReset];assert(!weak);
            free(list);free(groups);free(context);
        }
        NSData *result=[NSJSONSerialization dataWithJSONObject:@{@"status":@"CLEAR_ENCODING_MATCHES_APPLE_GPU_REFERENCE",
            @"cases":results,@"boundary":@"Native packing and production encoder; texture backing/deallocation fixtures, no Adreno execution."}
            options:NSJSONWritingPrettyPrinted error:nil];
        assert([result writeToFile:[out stringByAppendingPathComponent:@"encoding.json"] atomically:YES]);
        puts("Production clear encoding matches all Apple GPU references; native descriptors retained.");
    }
    return 0;
}
