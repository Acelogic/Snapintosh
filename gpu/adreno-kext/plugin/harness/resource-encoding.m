/* SPDX-License-Identifier: MIT */
// Native producer -> production Adreno parser, with synthetic resource backing.
// No host GPU device/queue is created. Failure inventory precedes implementation
// in docs/ADRENO-FIRST-METAL-IMAGE-20260926.md.
#import "../AdrenoMetal/AdrenoResourceUsage.h"
#import <objc/runtime.h>
#import <dlfcn.h>
#include "../../../../compat/adreno-resource-list.h"
#include <assert.h>

@protocol NativeRetentionList
- (instancetype)initWithCapacity:(int)capacity;
- (void)releaseAllObjectsAndReset;
@end

static unsigned destroyed;
@interface EncodingResourceFixture : IOGPUMetalResource
@property(nonatomic, strong) id fixtureDevice;
@end
@implementation EncodingResourceFixture
// Deliberately bypass native allocation: no kernel resource or GPU is created.
- (instancetype)init { return [super init]; }
- (id)device { return self.fixtureDevice; }
- (void)dealloc { destroyed++; }
@end

static EncodingResourceFixture *resource(id device, uint32_t rid, uint64_t bytes) {
    EncodingResourceFixture *r=[EncodingResourceFixture new];
    r.fixtureDevice=device;
    Ivar ivar=class_getInstanceVariable(objc_getClass("IOGPUMetalResource"),"_res");
    assert(ivar && ivar_getOffset(ivar)==24);
    struct { uint64_t surface, size; uint32_t rid, padding; } info={0,bytes,rid,0};
    memcpy((char *)(__bridge void *)r+ivar_getOffset(ivar)+32,&info,sizeof(info));
    return r;
}

static BOOL refuses(void (^work)(void)) {
    @try { work(); return NO; } @catch (NSException *e) { return YES; }
}
static void *retainID(void *ctx, uint32_t rid) { return (void *)(uintptr_t)(rid+1); }
static void releaseID(void *ctx, void *r) { (*(unsigned *)ctx)++; }
static void unexpectedGrowth(void *ctx) { abort(); }

int main(int argc, char **argv) {
    @autoreleasepool {
        assert(argc==2);
        void *iogpu=dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU",RTLD_NOW);
        assert(iogpu);
        // Native resource destruction expects GPU-device initialization. These
        // objects have no native allocation: use NSObject's destruction path
        // in this process only, retaining the witness and ARC destructors.
        SEL deallocSelector=sel_registerName("dealloc");
        Method rootDealloc=class_getInstanceMethod([NSObject class],deallocSelector);
        assert(rootDealloc);
        class_replaceMethod(objc_getClass("IOGPUMetalResource"),deallocSelector,
                            method_getImplementation(rootDealloc),method_getTypeEncoding(rootDealloc));
        void (*init)(void *,void *,uint64_t,uint64_t,uint32_t,void (*)(void *),void *)=dlsym(iogpu,"IOGPUResourceListInit");
        void (*reset)(void *,void *,uint64_t,uint32_t)=dlsym(iogpu,"IOGPUResourceListReset");
        assert(init && reset);
        id device=[NSObject new], other=[NSObject new];
        id<NativeRetentionList> retained=[(id<NativeRetentionList>)[objc_getClass("MTLResourceList") alloc] initWithCapacity:16];
        assert(retained);
        AdrenoResourceUsage *uses=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:retained];
        __weak EncodingResourceFixture *weak;
        unsigned before=destroyed;
        @autoreleasepool {
            EncodingResourceFixture *r=resource(device,1,16384);weak=r;
            [uses recordResource:r usage:MTLResourceUsageRead];
            [uses recordResource:r usage:MTLResourceUsageWrite];
            assert(refuses(^{ [uses recordResource:r usage:0]; }));
            assert(refuses(^{ [uses recordResource:r usage:8]; }));
        }
        @autoreleasepool {
            // A weak read itself may autorelease a temporary strong reference.
            assert(weak && destroyed==before);
            for (unsigned rid=2;rid<=7;rid++) [uses recordResource:resource(device,rid,16384) usage:MTLResourceUsageRead];
            assert(refuses(^{ [uses recordResource:(id)[NSObject new] usage:1]; }));
            assert(refuses(^{ [uses recordResource:resource(other,8,16384) usage:1]; }));
            assert(refuses(^{ [uses recordResource:resource(device,9,0) usage:1]; }));
        }
        void *list=calloc(1,4096), *groups=calloc(1,4096), *context=calloc(1,256);
        *(void **)((char *)context+0x70)=(char *)groups+4096;
        init(list,groups,4096,1ull<<30,7,unexpectedGrowth,context);
        // Mirrors native BeginSegment's clear before the production encoder.
        reset(list,groups,4096,1);
        [uses encodeIntoIOGPUList:list];
        assert(refuses(^{ [uses encodeIntoIOGPUList:list]; }));
        assert(refuses(^{ [uses recordResource:resource(device,10,16384) usage:1]; }));
        unsigned count=*(uint32_t *)((char *)list+0x220);
        assert(count==2);
        size_t length=32+count*64;
        uint8_t *payload=calloc(1,length), *snapshot=calloc(1,length);
        memcpy(payload+28,&count,4);memcpy(payload+32,groups,count*64);
        struct adreno_resource_entry entries[12]={0};struct adreno_resource_list parsed={0};
        unsigned released=0;
        struct adreno_resource_list_ops ops={&released,retainID,releaseID,0,0,0};
        assert(adreno_resource_list_acquire(&parsed,payload,length,snapshot,length,entries,12,&ops)==0);
        assert(parsed.count==7);
        for (unsigned i=0;i<7;i++) assert(entries[i].id==i+1 && entries[i].usage==(i ? 1 : 3));
        assert(adreno_resource_list_release(&parsed,&ops)==0 && released==7);
        assert([[NSData dataWithBytes:payload length:length] writeToFile:@(argv[1]) atomically:YES]);
        [retained releaseAllObjectsAndReset];
        assert(weak==nil);
        unsigned after=destroyed;[retained releaseAllObjectsAndReset];assert(destroyed==after);
        // Metadata recording does not retain an unretained command's object.
        AdrenoResourceUsage *unretained=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:nil];
        @autoreleasepool {
            EncodingResourceFixture *r=resource(device,20,16384);weak=r;
            [unretained recordResource:r usage:1];
        }
        assert(weak==nil);
        // A threshold refusal poisons this encoding rather than dropping a row.
        AdrenoResourceUsage *limited=[[AdrenoResourceUsage alloc] initWithDevice:device retainedList:nil];
        [limited recordResource:resource(device,21,16384) usage:1];
        void *limitedList=calloc(1,4096), *limitedGroups=calloc(1,4096), *limitedContext=calloc(1,256);
        *(void **)((char *)limitedContext+0x70)=(char *)limitedGroups+4096;
        init(limitedList,limitedGroups,4096,1024,7,unexpectedGrowth,limitedContext);
        assert(refuses(^{ [limited encodeIntoIOGPUList:limitedList]; }));
        assert(*(uint32_t *)((char *)limitedList+0x220)==0);
        assert(refuses(^{ [limited encodeIntoIOGPUList:list]; }));
        puts("{\"status\":\"ADRENO_NATIVE_RESOURCE_ENCODING_PASS\",\"resources\":7,\"groups\":2,\"retention\":\"retained and unretained checked\",\"refusals\":\"foreign type, device, zero size, usage, reuse, threshold\",\"boundary\":\"Synthetic resource objects; native packing and retention; production parser; no host GPU or guest execution\"}");
        // Native hash allocations are process-local; this bounded harness exits.
        free(payload);free(snapshot);free(groups);free(context);free(list);
        free(limitedList);free(limitedGroups);free(limitedContext);
    }
    return 0;
}
