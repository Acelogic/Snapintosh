/* SPDX-License-Identifier: MIT */
// Public Metal triangle -> Adreno GPU -> complete IOSurface image readback.
// Failure inventory: docs/ADRENO-GUI-INTEGRATION-20260927.md.
#include "SnapTriangleReference.h"
#ifndef SNAP_TRIANGLE_HOST_REFERENCE
#define SNAP_TRIANGLE_HOST_REFERENCE 0
#endif
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef SNAP_TRIANGLE_PLUGIN_SHA
#error Build with tools/build-adreno-triangle-probe.py and a qualified plug-in.
#endif
static NSString *const expectedPluginSHA=@SNAP_TRIANGLE_PLUGIN_SHA;
static id<MTLCommandBuffer> heldCommand;
static id<MTLCommandQueue> heldQueue;
static id<MTLTexture> heldTexture;
static id<MTLLibrary> heldLibrary;
static id<MTLRenderPipelineState> heldPipeline;
static IOSurfaceRef heldSurface;
static IOSurfaceRef heldPresentationSurface;
static BOOL presentationUncertain;
static BOOL attemptedSubmission,knownCompleted;
enum { AllocationLength=0x8000,Width=37,Height=23,RowBytes=1024,PixelBytes=Width*Height*4 };
static const uint32_t ClearPattern=0xff4080bfu;
_Static_assert(sizeof(SnapTriangleGolden)==PixelBytes,"triangle reference geometry");

static double seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)) abort();
    return value.tv_sec+value.tv_nsec/1e9;
}
static void marker(NSString *text) {
    fprintf(stdout,"SnapintoshTriangleProbe: %s\n",text.UTF8String);fflush(stdout);
#if !SNAP_TRIANGLE_HOST_REFERENCE
    int fd=open("/dev/console",O_WRONLY|O_NOCTTY);
    if(fd>=0){dprintf(fd,"SnapintoshTriangleProbe: %s\n",text.UTF8String);close(fd);}
#endif
}
static BOOL save(NSMutableDictionary *report,NSString *path,NSString *stage) {
    report[@"stage"]=stage;
    NSError *error=nil;
    NSData *data=[NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:&error];
    if(!data || ![data writeToFile:path options:NSDataWritingAtomic error:&error]) {
        marker([NSString stringWithFormat:@"report write failed: %@",error]);return NO;
    }
    marker([NSString stringWithFormat:@"%@ result=%@ report=%@",stage,report[@"result"],path]);return YES;
}
static NSString *digest(const void *bytes,NSUInteger length) {
    if(length>UINT32_MAX)return nil;
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];CC_SHA256(bytes,(CC_LONG)length,hash);
    NSMutableString *text=[NSMutableString stringWithCapacity:64];
    for(unsigned i=0;i<sizeof hash;i++)[text appendFormat:@"%02x",hash[i]];
    return text;
}
static unsigned char pattern(NSUInteger offset) { (void)offset;return 0x69; }
static int fail(NSMutableDictionary *report,NSString *path,NSString *result,int code) {
    report[@"result"]=result;BOOL saved=save(report,path,@"failed");
    if((attemptedSubmission && !knownCompleted) || presentationUncertain) {
        marker(@"Command, queue, texture and IOSurface retained until reset; retirement is unproven.");
        for(;;)pause();
    }
    return saved ? code : 73;
}
#include "SnapintoshTrianglePresent.h"

int main(int argc,const char **argv) {
    @autoreleasepool {
        double waitSeconds=600,holdSeconds=0;
        BOOL preparePresentation=NO,present=NO;
        NSString *base=@"/var/db/Snapintosh/metal-triangle-probe";
        for(int i=1;i<argc;i++) {
            if(!strcmp(argv[i],"--prepare-presentation"))preparePresentation=YES;
            else if(!strcmp(argv[i],"--present"))present=preparePresentation=YES;
            else if(!strcmp(argv[i],"--hold") && i+1<argc) {
                char *end=NULL;holdSeconds=strtod(argv[++i],&end);
                if(!end || *end || !isfinite(holdSeconds) || holdSeconds<0 || holdSeconds>3600)return 64;
            }
            else if(!strcmp(argv[i],"--report-base") && i+1<argc)base=[NSString stringWithUTF8String:argv[++i]];
            else if(!strcmp(argv[i],"--wait") && i+1<argc) {
                char *end=NULL;waitSeconds=strtod(argv[++i],&end);
                if(!end || *end || !isfinite(waitSeconds) || waitSeconds<0 || waitSeconds>900)return 64;
            } else return 64;
        }
        if(!base.isAbsolutePath || (SNAP_TRIANGLE_HOST_REFERENCE && present))return 64;
        NSError *error=nil;
        if(![[NSFileManager defaultManager] createDirectoryAtPath:base.stringByDeletingLastPathComponent
            withIntermediateDirectories:YES attributes:nil error:&error])return 73;
        NSString *runID=NSUUID.UUID.UUIDString;
        NSString *stem=[NSString stringWithFormat:@"%@-%@",base,runID];
        NSString *path=[stem stringByAppendingString:@".json"];
        int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL,0644);
        if(fd<0)return 73;close(fd);
        NSMutableDictionary *report=[@{@"schema":@"snapintosh-metal-triangle-probe/1",@"run_id":runID,
            @"pid":@(getpid()),@"result":@"RUNNING",@"image_produced":@NO,
            @"expected_plugin_sha256":expectedPluginSHA,@"allocation_length":@(AllocationLength),
            @"width":@(Width),@"height":@(Height),@"row_bytes":@(RowBytes),@"pixel_pattern":@(ClearPattern),
            @"screen_presented":@NO,@"host_reference":@(SNAP_TRIANGLE_HOST_REFERENCE),
            @"golden_sha256":@SNAP_TRIANGLE_GOLDEN_SHA,@"pixel_rgb_tolerance":@1,
            @"boundary":@"Public Metal triangle and IOSurface readback; requires matching physical driver/map/IB evidence. A host-reference build proves only AGX probe behavior. No screen presentation."} mutableCopy];
        if(!save(report,path,@"waiting-for-driver"))return 73;
        double start=seconds();
        @try {
            id<MTLDevice> target=nil;
#if SNAP_TRIANGLE_HOST_REFERENCE
            target=MTLCreateSystemDefaultDevice();
            if(!target)return fail(report,path,@"NO_HOST_REFERENCE_DEVICE",4);
            report[@"devices"]=@[@{@"name":target.name?:@"",@"class":NSStringFromClass([target class]),
                                  @"registry_id":@(target.registryID)}];
#else
            io_service_t service=IO_OBJECT_NULL;
            do {
                service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("AdrenoAcceleratorX2"));
                if(service || seconds()-start>=waitSeconds)break;
                usleep(1000000);
            }while(1);
            if(!service)return fail(report,path,@"NO_ADRENO_SERVICE",2);
            uint64_t registryID=0;io_name_t className={0};
            kern_return_t idStatus=IORegistryEntryGetRegistryEntryID(service,&registryID);
            kern_return_t classStatus=IOObjectGetClass(service,className);IOObjectRelease(service);
            if(idStatus || classStatus || !registryID || strcmp(className,"AdrenoAcceleratorX2"))
                return fail(report,path,@"DRIVER_IDENTITY_FAILED",3);
            report[@"registry_id"]=@(registryID);
            if(!save(report,path,@"driver-found"))return 73;
            NSMutableArray *inventory=[NSMutableArray array];
            for(id<MTLDevice> device in MTLCopyAllDevices()) {
                [inventory addObject:@{@"name":device.name?:@"",@"class":NSStringFromClass([device class]),
                                       @"registry_id":@(device.registryID)}];
                if(device.registryID==registryID &&
                    [NSStringFromClass([device class]) isEqualToString:@"AdrenoMTLDevice"])target=device;
            }
            report[@"devices"]=inventory;
            if(!target)return fail(report,path,@"NO_ADRENO_METAL_DEVICE",4);
            const char *imageName=class_getImageName([target class]);
            NSString *imagePath=imageName ? [NSString stringWithUTF8String:imageName] : nil;
            NSData *image=imagePath ? [NSData dataWithContentsOfFile:imagePath options:0 error:&error] : nil;
            NSString *imageSHA=image ? digest(image.bytes,image.length) : nil;
            report[@"plugin_path"]=imagePath?:@"";report[@"plugin_sha256"]=imageSHA?:@"";
            if(![imageSHA isEqualToString:expectedPluginSHA])return fail(report,path,@"TRIANGLE_PLUGIN_IDENTITY_FAILED",5);
            if(!save(report,path,@"triangle-plugin-qualified"))return 73;
#endif
            NSDictionary *properties=@{(id)kIOSurfaceWidth:@(Width),(id)kIOSurfaceHeight:@(Height),
                (id)kIOSurfaceBytesPerElement:@4,(id)kIOSurfaceBytesPerRow:@(RowBytes),
                (id)kIOSurfaceAllocSize:@(AllocationLength),(id)kIOSurfacePixelFormat:@(0x42475241u)};
            heldSurface=IOSurfaceCreate((__bridge CFDictionaryRef)properties);
            if(!heldSurface || IOSurfaceGetPlaneCount(heldSurface)!=0 ||
                IOSurfaceGetWidth(heldSurface)!=Width || IOSurfaceGetHeight(heldSurface)!=Height ||
                IOSurfaceGetBytesPerRow(heldSurface)!=RowBytes ||
                IOSurfaceGetAllocSize(heldSurface)!=AllocationLength)
                return fail(report,path,@"IOSURFACE_GEOMETRY_FAILED",6);
            MTLTextureDescriptor *descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:Width height:Height mipmapped:NO];
            descriptor.storageMode=MTLStorageModeShared;descriptor.usage=MTLTextureUsageRenderTarget;
            heldTexture=[target newTextureWithDescriptor:descriptor iosurface:heldSurface plane:0];
            if(!heldTexture || heldTexture.device!=target || heldTexture.width!=Width ||
                heldTexture.height!=Height || heldTexture.pixelFormat!=MTLPixelFormatBGRA8Unorm ||
                heldTexture.storageMode!=MTLStorageModeShared)
                return fail(report,path,@"TEXTURE_IDENTITY_FAILED",6);
            heldTexture.label=@"Snapintosh GPU triangle with padded rows";
            if(IOSurfaceLock(heldSurface,0,NULL))return fail(report,path,@"SURFACE_SEED_LOCK_FAILED",6);
            unsigned char *bytes=IOSurfaceGetBaseAddress(heldSurface);
            if(!bytes) { IOSurfaceUnlock(heldSurface,0,NULL);return fail(report,path,@"SURFACE_CPU_VIEW_FAILED",6); }
            for(NSUInteger i=0;i<AllocationLength;i++)bytes[i]=pattern(i);
            NSData *before=[NSData dataWithBytes:bytes length:AllocationLength];
            if(IOSurfaceUnlock(heldSurface,0,NULL))return fail(report,path,@"SURFACE_SEED_UNLOCK_FAILED",6);
            NSString *beforePath=[stem stringByAppendingString:@"-before.bin"];
            report[@"before_sha256"]=digest(before.bytes,before.length);report[@"before_path"]=beforePath;
            if(![before writeToFile:beforePath options:NSDataWritingAtomic error:&error])
                return fail(report,path,@"BEFORE_ARTIFACT_FAILED",7);
            heldLibrary=[target newLibraryWithSource:@SNAP_TRIANGLE_METAL_SOURCE options:nil error:&error];
            if(!heldLibrary){report[@"library_error"]=error.description?:@"";return fail(report,path,@"LIBRARY_FAILED",15);}
            MTLFunctionConstantValues *constants=[MTLFunctionConstantValues new];
            float scale=0.5f;uint32_t indexBias=13;
            [constants setConstantValue:&scale type:MTLDataTypeFloat atIndex:0];
            [constants setConstantValue:&indexBias type:MTLDataTypeUInt atIndex:1];
            id<MTLFunction> vertex=[heldLibrary newFunctionWithName:@"vs" constantValues:constants error:&error];
            id<MTLFunction> fragment=[heldLibrary newFunctionWithName:@"fs" constantValues:constants error:&error];
            if(!vertex||!fragment){report[@"function_error"]=error.description?:@"";return fail(report,path,@"FUNCTION_FAILED",15);}
            MTLRenderPipelineDescriptor *pipeline=[MTLRenderPipelineDescriptor new];
            pipeline.vertexFunction=vertex;pipeline.fragmentFunction=fragment;
            pipeline.colorAttachments[0].pixelFormat=MTLPixelFormatBGRA8Unorm;
            heldPipeline=[target newRenderPipelineStateWithDescriptor:pipeline error:&error];
            if(!heldPipeline){report[@"pipeline_error"]=error.description?:@"";return fail(report,path,@"PIPELINE_FAILED",15);}
            if(!save(report,path,@"triangle-pipeline-created"))return 73;
            heldQueue=[target newCommandQueue];heldCommand=[heldQueue commandBuffer];
            if(!heldQueue || !heldCommand || !heldCommand.retainedReferences)
                return fail(report,path,@"NO_RETAINED_COMMAND_BUFFER",8);
            heldCommand.label=@"Snapintosh public Metal GPU triangle";
            MTLRenderPassDescriptor *pass=[MTLRenderPassDescriptor renderPassDescriptor];
            pass.colorAttachments[0].texture=heldTexture;
            pass.colorAttachments[0].loadAction=MTLLoadActionClear;
            pass.colorAttachments[0].storeAction=MTLStoreActionStore;
            pass.colorAttachments[0].clearColor=MTLClearColorMake(0.25,0.5,0.75,1.0);
            id<MTLRenderCommandEncoder> encoder=[heldCommand renderCommandEncoderWithDescriptor:pass];
            if(!encoder)return fail(report,path,@"NO_RENDER_ENCODER",9);
            [encoder setRenderPipelineState:heldPipeline];
            [encoder setViewport:(MTLViewport){0,0,Width,Height,0,1}];
            [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
            [encoder endEncoding];
            if(!save(report,path,@"triangle-encoded"))return 73;
            dispatch_semaphore_t done=dispatch_semaphore_create(0);
            [heldCommand addCompletedHandler:^(id<MTLCommandBuffer> command){(void)command;dispatch_semaphore_signal(done);}];
            if(!save(report,path,@"submitting"))return 73;
            attemptedSubmission=YES;[heldCommand commit];
            if(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,180LL*NSEC_PER_SEC))) {
                report[@"command_status"]=@(heldCommand.status);return fail(report,path,@"COMPLETION_TIMEOUT",10);
            }
            report[@"command_status"]=@(heldCommand.status);report[@"command_error"]=heldCommand.error.description?:@"";
            if(heldCommand.status!=MTLCommandBufferStatusCompleted || heldCommand.error)
                return fail(report,path,@"COMMAND_FAILED",11);
            knownCompleted=YES;
            // No CPU stores to the GPU render target occur after encoding/submission.
            if(IOSurfaceLock(heldSurface,kIOSurfaceLockReadOnly,NULL))
                return fail(report,path,@"SURFACE_READBACK_LOCK_FAILED",12);
            const void *cpu=IOSurfaceGetBaseAddress(heldSurface);
            NSData *captured=cpu ? [NSData dataWithBytes:cpu length:AllocationLength] : nil;
            if(IOSurfaceUnlock(heldSurface,kIOSurfaceLockReadOnly,NULL))
                return fail(report,path,@"SURFACE_READBACK_UNLOCK_FAILED",12);
            if(!captured)return fail(report,path,@"SURFACE_READBACK_VIEW_FAILED",12);
            const unsigned char *readback=captured.bytes;
            NSString *afterPath=[stem stringByAppendingString:@"-after.bin"];
            report[@"after_sha256"]=digest(readback,AllocationLength);report[@"after_path"]=afterPath;
            if(![[NSData dataWithBytes:readback length:AllocationLength] writeToFile:afterPath options:NSDataWritingAtomic error:&error])
                return fail(report,path,@"READBACK_ARTIFACT_FAILED",12);
            NSUInteger mismatches=0,changed=0,maxPixelError=0;
            for(NSUInteger i=0;i<AllocationLength;i++) {
                NSUInteger row=i/RowBytes,column=i%RowBytes;
                BOOL pixel=row<Height && column<Width*4;
                unsigned char expected=pixel ? SnapTriangleGolden[row*Width*4+column] : pattern(i);
                unsigned delta=readback[i]>expected ? readback[i]-expected : expected-readback[i];
                unsigned tolerance=pixel && (column&3)!=3 ? 1 : 0;
                if(pixel && delta>maxPixelError)maxPixelError=delta;
                changed+=readback[i]!=pattern(i);
                if(delta>tolerance) {
                    if(!mismatches)report[@"first_mismatch"]=@{@"offset":@(i),@"expected":@(expected),@"actual":@(readback[i])};
                    mismatches++;
                }
            }
            report[@"mismatches"]=@(mismatches);report[@"changed_bytes"]=@(changed);
            report[@"max_pixel_error"]=@(maxPixelError);
            if(mismatches || !changed)return fail(report,path,@"TRIANGLE_READBACK_MISMATCH",13);
            NSMutableData *pixels=[NSMutableData dataWithLength:PixelBytes];
            for(NSUInteger y=0;y<Height;y++)
                memcpy((char *)pixels.mutableBytes+y*Width*4,readback+y*RowBytes,Width*4);
            NSString *pixelsPath=[stem stringByAppendingString:@"-pixels.bgra"];
            report[@"image_path"]=pixelsPath;report[@"image_sha256"]=digest(pixels.bytes,pixels.length);
            if(![pixels writeToFile:pixelsPath options:NSDataWritingAtomic error:&error])
                return fail(report,path,@"IMAGE_ARTIFACT_FAILED",12);
            report[@"image_produced"]=@YES;
            report[@"elapsed_seconds"]=@(seconds()-start);
            report[@"result"]=SNAP_TRIANGLE_HOST_REFERENCE ? @"HOST_METAL_TRIANGLE_REFERENCE_MATCHED" : @"METAL_TRIANGLE_COMPLETED_PIXELS_VERIFIED";
            if(!save(report,path,@"finished"))return 73;
            if(preparePresentation) {
                int code=prepareTrianglePresentation(report,path,stem,pixels);
                if(code)return code;
            }
            if(present) {
                int code=presentTriangle(report,path,waitSeconds);
                if(code)return code;
                if(holdSeconds>0)sleep((unsigned)holdSeconds);
                marker(@"Queue completion observed; visible IOSurface retained until reset. Surface retirement and panel pixels need separate evidence.");
                for(;;)pause();
            }
            return 0;
        }@catch(NSException *exception) {
            report[@"exception"]=@{@"name":exception.name?:@"",@"reason":exception.reason?:@""};
            return fail(report,path,@"OBJC_EXCEPTION",14);
        }
    }
}
