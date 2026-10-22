/* SPDX-License-Identifier: MIT */
#import "AdrenoResourceUsage.h"
#import <objc/runtime.h>
#import <dlfcn.h>

// 26A428 IOGPUResourceInfo, from the original producer and runtime ivar type.
// resourceRef is a different object and must never be passed to the producer.
struct AdrenoResourceInfo {
    void *surface;
    uint64_t sizeAndField;
    uint32_t resourceID, padding;
};
struct AdrenoResourceUse {
    struct AdrenoResourceInfo info;
    uint32_t usage, reserved;
};
_Static_assert(sizeof(struct AdrenoResourceInfo)==24, "native resource information ABI");
_Static_assert(sizeof(struct AdrenoResourceUse)==32, "deferred resource record ABI");

static void (*NativeRetainResource)(id,id);
static uint32_t (*NativeAddResource)(void *,const struct AdrenoResourceInfo *,uint32_t);
static ptrdiff_t ResourceInfoOffset;

static void AdrenoLoadResourceABI(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Ivar ivar=class_getInstanceVariable([IOGPUMetalResource class],"_res");
        const char *type=ivar ? ivar_getTypeEncoding(ivar) : NULL;
        const char *prefix="{_IOGPUMetalResource=\"vendor\"(?=\"reserved\"[4Q])\"info\"{IOGPUResourceInfo=\"iosurface\"^{__IOSurface}\"resourceSize\"b56\"iosurfaceField\"b8\"resourceID\"I}";
        if (!type || strncmp(type,prefix,strlen(prefix))) return;
        ptrdiff_t offset=ivar_getOffset(ivar)+32;
        if (offset<32 || (size_t)offset+sizeof(struct AdrenoResourceInfo)>
            class_getInstanceSize([IOGPUMetalResource class])) return;
        ResourceInfoOffset=offset;
        NativeRetainResource=dlsym(RTLD_DEFAULT,"MTLResourceListAddResource");
        NativeAddResource=dlsym(RTLD_DEFAULT,"IOGPUResourceListAddResource");
    });
    if (!ResourceInfoOffset || !NativeRetainResource || !NativeAddResource)
        [NSException raise:NSInternalInconsistencyException format:@"Unsupported Adreno native resource-list ABI"];
}

@implementation AdrenoResourceUsage {
    id _device, _retainedList;
    NSMutableData *_records;
    BOOL _sealed;
}
- (instancetype)initWithDevice:(id)device retainedList:(id)retainedList {
    if (!device) [NSException raise:NSInvalidArgumentException format:@"Missing Adreno resource device"];
    AdrenoLoadResourceABI();
    if ((self=[super init])) {
        _device=device;
        _retainedList=retainedList;
        _records=[NSMutableData data];
    }
    return self;
}
- (void)recordResource:(id)resource usage:(MTLResourceUsage)usage {
    if (_sealed) [NSException raise:NSInternalInconsistencyException format:@"Adreno resource encoding has already ended"];
    // Bit 2 is the legacy Sample usage, still accepted by this native ABI.
    const MTLResourceUsage supported=MTLResourceUsageRead|MTLResourceUsageWrite|(1u<<2);
    if (![resource isKindOfClass:[IOGPUMetalResource class]] || !usage || (usage&~supported))
        [NSException raise:NSInvalidArgumentException format:@"Invalid Adreno resource or usage"];
    IOGPUMetalResource *native=resource;
    if ([native device]!=_device)
        [NSException raise:NSInvalidArgumentException format:@"Adreno resource belongs to a different device"];
    struct AdrenoResourceUse record={0};
    memcpy(&record.info,(const char *)(__bridge const void *)native+ResourceInfoOffset,sizeof(record.info));
    uint64_t size=record.info.sizeAndField&0x00ffffffffffffffull;
    if (!size || size!=[native resourceSize] || record.info.resourceID!=[native resourceID])
        [NSException raise:NSInvalidArgumentException format:@"Adreno resource information is empty or inconsistent"];
    record.usage=(uint32_t)usage;
    // Native completion owns the retention list's reset. For unretained
    // command buffers, only metadata is stored; the caller keeps objects alive.
    if (_retainedList) NativeRetainResource(_retainedList,resource);
    [_records appendBytes:&record length:sizeof(record)];
}
#if ADRENO_PIPELINE
- (NSData *)adrenoResourceIDs {
    const struct AdrenoResourceUse *records=_records.bytes;
    const NSUInteger n=_records.length/sizeof(*records);
    NSMutableData *ids=[NSMutableData dataWithLength:n*sizeof(uint32_t)];
    uint32_t *out=ids.mutableBytes;
    for (NSUInteger i=0;i<n;i++) out[i]=records[i].info.resourceID;
    return ids;
}
#endif
- (void)encodeIntoIOGPUList:(void *)list {
    if (_sealed) [NSException raise:NSInternalInconsistencyException format:@"Adreno resource publication cannot be repeated"];
    _sealed=YES;
    if (!list) [NSException raise:NSInternalInconsistencyException format:@"Missing Adreno native resource list"];
    const struct AdrenoResourceUse *records=_records.bytes;
    for (NSUInteger n=0;n<_records.length/sizeof(*records);n++) {
        if (NativeAddResource(list,&records[n].info,records[n].usage)==UINT32_MAX)
            [NSException raise:NSInternalInconsistencyException format:@"Adreno segment resource threshold exceeded"];
    }
}
@end
