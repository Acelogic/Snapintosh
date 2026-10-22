/* SPDX-License-Identifier: MIT */
// Production Metal command/resource encoding without creating a host GPU.
// Synthetic buffer backing/destruction are explicit fixtures.
#import "../AdrenoMetal/AdrenoFillCommands.h"
#import <objc/runtime.h>
#import <dlfcn.h>
#include <assert.h>
#include "../../../../compat/adreno-fill-command.h"

@protocol FillRetentionList
- (instancetype)initWithCapacity:(int)capacity;
- (void)releaseAllObjectsAndReset;
@end
static unsigned destroyed;
@interface FillBufferFixture : IOGPUMetalBuffer
@property(nonatomic,strong) id fixtureDevice;
@property(nonatomic) NSUInteger fixtureLength;
@end
@implementation FillBufferFixture
- (id)device { return self.fixtureDevice; }
- (NSUInteger)length { return self.fixtureLength; }
- (void *)contents { abort(); } // An encoder must never write the destination on the CPU.
- (void)dealloc { destroyed++; }
@end
static FillBufferFixture *buffer(id device,uint32_t rid,NSUInteger length) {
    FillBufferFixture *b=[FillBufferFixture new]; b.fixtureDevice=device;b.fixtureLength=length;
    Ivar ivar=class_getInstanceVariable(objc_getClass("IOGPUMetalResource"),"_res");
    assert(ivar && ivar_getOffset(ivar)==24);
    struct {uint64_t surface,size;uint32_t rid,padding;} info={0,length,rid,0};
    memcpy((char *)(__bridge void *)b+ivar_getOffset(ivar)+32,&info,sizeof info);
    return b;
}
static BOOL refuses(void (^work)(void)) {
    @try {work();return NO;} @catch(NSException *e) {return YES;}
}
static void unexpectedGrowth(void *context) { abort(); }
int main(int argc,char **argv) {
    @autoreleasepool {
        assert(argc==3);
        void *iogpu=dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU",RTLD_NOW);
        assert(iogpu);
        SEL dealloc=sel_registerName("dealloc");
        Method root=class_getInstanceMethod([NSObject class],dealloc);
        for (NSString *name in @[@"IOGPUMetalResource",@"IOGPUMetalBuffer"])
            class_replaceMethod(objc_getClass(name.UTF8String),dealloc,
                                method_getImplementation(root),method_getTypeEncoding(root));
        void (*init)(void *,void *,uint64_t,uint64_t,uint32_t,void (*)(void *),void *)=dlsym(iogpu,"IOGPUResourceListInit");
        void (*reset)(void *,void *,uint64_t,uint32_t)=dlsym(iogpu,"IOGPUResourceListReset");
        assert(init && reset);
        id device=[NSObject new],other=[NSObject new];
        id<FillRetentionList> retained=[(id<FillRetentionList>)[objc_getClass("MTLResourceList") alloc] initWithCapacity:16];
        AdrenoResourceUsage *uses=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:retained];
        AdrenoFillCommands *fills=[[AdrenoFillCommands alloc] initWithResources:uses];
        assert([fills commandBytes]==8);
        __weak FillBufferFixture *weak;
        @autoreleasepool {
            FillBufferFixture *b=buffer(device,7,0x8000);weak=b;
            assert(refuses(^{[fills recordBuffer:(id)[NSObject new] range:NSMakeRange(0,4) value:1];}));
            assert(refuses(^{[fills recordBuffer:(id<MTLBuffer>)buffer(other,8,0x8000) range:NSMakeRange(0,4) value:1];}));
            for (NSValue *v in @[[NSValue valueWithRange:NSMakeRange(1,4)],
                                [NSValue valueWithRange:NSMakeRange(0,3)],
                                [NSValue valueWithRange:NSMakeRange(0x7ffc,8)],
                                [NSValue valueWithRange:NSMakeRange(NSUIntegerMax-3,8)],
                                [NSValue valueWithRange:NSMakeRange(0,0x4004)]])
                assert(refuses(^{[fills recordBuffer:(id<MTLBuffer>)b range:v.rangeValue value:1];}));
            [fills recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(0,0) value:0];
            assert([fills commandBytes]==8);
            [fills recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(0x3f00,0x4000) value:0x3c];
            assert(refuses(^{[fills recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(0,4) value:1];}));
        }
        @autoreleasepool { assert(weak); }
        assert([fills commandBytes]==40);
        uint8_t stream[40];memset(stream,0xa5,sizeof stream);
        uint8_t *target=stream;
        assert(refuses(^{[fills encodeInto:target capacity:39];}));
        for (unsigned i=0;i<sizeof stream;i++) assert(stream[i]==0xa5);
        [fills encodeInto:stream capacity:sizeof stream];
        assert(refuses(^{[fills encodeInto:target capacity:40];}));
        @autoreleasepool {
            assert(refuses(^{[fills recordBuffer:(id<MTLBuffer>)weak range:NSMakeRange(0,4) value:1];}));
        }
        struct adreno_fill32_request request;
        assert(adreno_fill32_decode(stream,sizeof stream,&request)==0);
        assert(request.resource_id==7 && request.offset==0x3f00 && request.bytes==0x4000 && request.pattern==0x3c3c3c3c);
        struct adreno_submit_header last;memcpy(&last,stream+32,sizeof last);
        assert(last.type==ADRENO_KCMD_FENCE && last.size==8);
        void *list=calloc(1,4096),*groups=calloc(1,4096),*context=calloc(1,256);
        *(void **)((char *)context+0x70)=(char *)groups+4096;
        init(list,groups,4096,1ull<<30,7,unexpectedGrowth,context);
        reset(list,groups,4096,1); // Native BeginSegment's reset before publication.
        [uses encodeIntoIOGPUList:list];
        uint32_t count=*(uint32_t *)((char *)list+0x220);assert(count==1);
        uint8_t payload[96]={0};memcpy(payload+28,&count,4);memcpy(payload+32,groups,64);
        assert([[NSData dataWithBytes:payload length:sizeof payload] writeToFile:@(argv[1]) atomically:YES]);
        assert([[NSData dataWithBytes:stream length:sizeof stream] writeToFile:@(argv[2]) atomically:YES]);
        [retained releaseAllObjectsAndReset];
        assert(!weak);
        // Unretained encoding stores metadata only.
        AdrenoResourceUsage *unretained=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:nil];
        AdrenoFillCommands *unretainedFills=[[AdrenoFillCommands alloc] initWithResources:unretained];
        __weak FillBufferFixture *unretainedWeak;
        @autoreleasepool {
            FillBufferFixture *b=buffer(device,9,0x8000);unretainedWeak=b;
            [unretainedFills recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(0,4) value:7];
        }
        assert(!unretainedWeak);
        uint8_t small[40];[unretainedFills encodeInto:small capacity:sizeof small];
        assert(adreno_fill32_decode(small,sizeof small,&request)==0 && request.pattern==0x07070707);
        AdrenoFillCommands *many=[[AdrenoFillCommands alloc] initWithResources:unretained];
        FillBufferFixture *b=buffer(device,10,0x8000);
        for(unsigned n=0;n<64;n++) [many recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(n*4,4) value:(uint8_t)n];
        assert(refuses(^{[many recordBuffer:(id<MTLBuffer>)b range:NSMakeRange(256,4) value:0];}));
        assert([many commandBytes]==64*32+8);
        puts("{\"status\":\"ADRENO_FILL_ENCODING_PASS\",\"fill_commands\":1,\"command_bytes\":40,\"descriptor_bytes\":96,\"destination_cpu_accesses\":0,\"boundary\":\"Native retention/packing and production command encoder/decoder; synthetic buffers, no host GPU\"}");
        free(list);free(groups);free(context);
    }
    return 0;
}
