/* SPDX-License-Identifier: MIT */
// Native presentation of verified GPU readback in a separate CPU-owned surface.
// Included after the triangle probe's identity/report/retention helpers.
#import <CoreGraphics/CoreGraphics.h>
#include <dlfcn.h>

enum { PresentWidth=2880, PresentHeight=1800 };
typedef struct __IOMobileFramebuffer *TriangleFramebuffer;
typedef kern_return_t (*TriangleGetMain)(TriangleFramebuffer *);
typedef io_service_t (*TriangleGetService)(TriangleFramebuffer);
typedef kern_return_t (*TriangleGetSize)(TriangleFramebuffer, CGSize *);
typedef kern_return_t (*TriangleSwapBegin)(TriangleFramebuffer, int *);
typedef kern_return_t (*TriangleSwapSetLayer)(TriangleFramebuffer, int, IOSurfaceRef, CGRect, CGRect, int);
typedef kern_return_t (*TriangleSwapEnd)(TriangleFramebuffer);
typedef kern_return_t (*TriangleSwapWait)(TriangleFramebuffer, int, int, double);
static TriangleFramebuffer heldFramebuffer;
static void *heldFramebufferFramework;

static int prepareTrianglePresentation(NSMutableDictionary *report,NSString *path,
                                      NSString *stem,NSData *pixels) {
    if(pixels.length!=PixelBytes)return fail(report,path,@"PRESENT_SOURCE_GEOMETRY",16);
    NSDictionary *props=@{(id)kIOSurfaceWidth:@(PresentWidth),(id)kIOSurfaceHeight:@(PresentHeight),
        (id)kIOSurfaceBytesPerElement:@4,(id)kIOSurfacePixelFormat:@(0x42475241u)};
    heldPresentationSurface=IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if(!heldPresentationSurface || IOSurfaceGetPlaneCount(heldPresentationSurface) ||
       IOSurfaceGetWidth(heldPresentationSurface)!=PresentWidth ||
       IOSurfaceGetHeight(heldPresentationSurface)!=PresentHeight)
        return fail(report,path,@"PRESENT_SURFACE_GEOMETRY",16);
    size_t row=IOSurfaceGetBytesPerRow(heldPresentationSurface),length=IOSurfaceGetAllocSize(heldPresentationSurface);
    if(row<PresentWidth*4 || row>65536 || length<row*PresentHeight || length>64*1024*1024)
        return fail(report,path,@"PRESENT_SURFACE_BOUNDS",16);
    if(IOSurfaceLock(heldPresentationSurface,0,NULL))return fail(report,path,@"PRESENT_LOCK_FAILED",16);
    uint8_t *dst=IOSurfaceGetBaseAddress(heldPresentationSurface);
    if(!dst){IOSurfaceUnlock(heldPresentationSurface,0,NULL);return fail(report,path,@"PRESENT_VIEW_FAILED",16);}
    memset(dst,0,length);
    const uint8_t *src=pixels.bytes;
    for(size_t y=0;y<PresentHeight;y++)for(size_t x=0;x<PresentWidth;x++)
        memcpy(dst+y*row+x*4,src+((y*Height/PresentHeight)*Width+x*Width/PresentWidth)*4,4);
    NSData *copy=[NSData dataWithBytes:dst length:length];
    if(IOSurfaceUnlock(heldPresentationSurface,0,NULL))return fail(report,path,@"PRESENT_UNLOCK_FAILED",16);
    NSString *dump=[stem stringByAppendingString:@"-presentation.bgra"];
    NSError *error=nil;
    if(![copy writeToFile:dump options:NSDataWritingAtomic error:&error])return fail(report,path,@"PRESENT_ARTIFACT_FAILED",16);
    report[@"presentation"]=@{@"width":@(PresentWidth),@"height":@(PresentHeight),
        @"row_bytes":@(row),@"allocation_length":@(length),@"path":dump,
        @"sha256":digest(copy.bytes,copy.length),@"source_sha256":digest(pixels.bytes,pixels.length),
        @"method":@"CPU nearest-neighbour scaling of verified GPU readback into a separate IOSurface"};
    return save(report,path,@"presentation-prepared") ? 0 : 73;
}

static int presentTriangle(NSMutableDictionary *report,NSString *path,double waitSeconds) {
    // Host-reference builds can exercise preparation, never a framebuffer swap.
    if(SNAP_TRIANGLE_HOST_REFERENCE)return fail(report,path,@"HOST_SWAP_REFUSED",64);
    heldFramebufferFramework=dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer",RTLD_NOW|RTLD_LOCAL);
    if(!heldFramebufferFramework)return fail(report,path,@"NO_PRESENT_FRAMEWORK",17);
    TriangleGetMain getMain=(TriangleGetMain)dlsym(heldFramebufferFramework,"IOMobileFramebufferGetMainDisplay");
    TriangleGetService getService=(TriangleGetService)dlsym(heldFramebufferFramework,"IOMobileFramebufferGetServiceObject");
    TriangleGetSize getSize=(TriangleGetSize)dlsym(heldFramebufferFramework,"IOMobileFramebufferGetDisplaySize");
    TriangleSwapBegin begin=(TriangleSwapBegin)dlsym(heldFramebufferFramework,"IOMobileFramebufferSwapBegin");
    TriangleSwapSetLayer layer=(TriangleSwapSetLayer)dlsym(heldFramebufferFramework,"IOMobileFramebufferSwapSetLayer");
    TriangleSwapEnd end=(TriangleSwapEnd)dlsym(heldFramebufferFramework,"IOMobileFramebufferSwapEnd");
    TriangleSwapWait wait=(TriangleSwapWait)dlsym(heldFramebufferFramework,"IOMobileFramebufferSwapWaitWithTimeout");
    if(!getMain||!getService||!getSize||!begin||!layer||!end||!wait)
        return fail(report,path,@"MISSING_PRESENT_API",17);
    double start=seconds();kern_return_t kr=KERN_FAILURE;
    while((kr=getMain(&heldFramebuffer))!=KERN_SUCCESS || !heldFramebuffer) {
        if(seconds()-start>=waitSeconds)break;
        sleep(1);
    }
    if(kr || !heldFramebuffer)return fail(report,path,@"NO_MAIN_DISPLAY",18);
    io_service_t service=getService(heldFramebuffer),provider=IO_OBJECT_NULL;
    io_name_t cls={0};uint64_t providerID=0;
    if(!service || IOObjectGetClass(service,cls) || strcmp(cls,"AdrenoDisplay"))
        return fail(report,path,@"WRONG_DISPLAY_CLASS",18);
    if(IORegistryEntryGetParentEntry(service,kIOServicePlane,&provider))
        return fail(report,path,@"NO_DISPLAY_PROVIDER",18);
    kr=IORegistryEntryGetRegistryEntryID(provider,&providerID);IOObjectRelease(provider);
    if(kr || providerID!=[report[@"registry_id"] unsignedLongLongValue])
        return fail(report,path,@"WRONG_DISPLAY_PROVIDER",18);
    CGSize size={0,0};
    if(getSize(heldFramebuffer,&size) || size.width!=PresentWidth || size.height!=PresentHeight)
        return fail(report,path,@"WRONG_DISPLAY_SIZE",18);
    report[@"presentation_requested"]=@YES;
    if(!save(report,path,@"presenting"))return 73;
    CGRect full=CGRectMake(0,0,PresentWidth,PresentHeight);int token=0;
    presentationUncertain=YES;
    if((kr=begin(heldFramebuffer,&token)) ||
       (kr=layer(heldFramebuffer,0,heldPresentationSurface,full,full,0)) ||
       (kr=end(heldFramebuffer))) {
        report[@"presentation_return"]=@((uint32_t)kr);
        return fail(report,path,@"SWAP_FAILED",19);
    }
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    __block kern_return_t queueResult=KERN_FAILURE;
    // Native 26A428 wait options0 also waits while token is the last displayed
    // ID. Options1 waits for it to leave the pending/current queues. Neither
    // result proves panel pixels or permits releasing the visible surface.
    report[@"presentation_wait_options"]=@1;
    report[@"surface_retirement_proven"]=@NO;
    report[@"presentation_retained_until_reset"]=@YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        queueResult=wait(heldFramebuffer,token,1,10.0);dispatch_semaphore_signal(done);
    });
    if(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,15LL*NSEC_PER_SEC)))
        return fail(report,path,@"SWAP_WAIT_TIMEOUT",19);
    report[@"presentation_return"]=@((uint32_t)queueResult);
    if(queueResult)return fail(report,path,@"SWAP_WAIT_FAILED",19);
    // Keep presentationUncertain set: queue completion does not retire the
    // displayed surface. main retains it even after this successful report.
    report[@"presentation_queue_completed"]=@YES;
    CFTypeRef raw=IORegistryEntryCreateCFProperty(service,CFSTR("AdrenoDisplayStats"),kCFAllocatorDefault,0);
    if(raw) {
        if(CFGetTypeID(raw)==CFDictionaryGetTypeID())report[@"display_stats"]=[(__bridge NSDictionary *)raw copy];
        CFRelease(raw);
    }
    // Completion of the API alone cannot prove the panel contains these pixels.
    report[@"result"]=@"METAL_TRIANGLE_PIXELS_VERIFIED_QUEUE_COMPLETED_PANEL_UNVERIFIED";
    if(!save(report,path,@"queue-completed"))
        return fail(report,path,@"PRESENT_REPORT_FAILED",73);
    return 0;
}
