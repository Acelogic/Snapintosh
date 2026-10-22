/* SPDX-License-Identifier: MIT */
// Public Metal -> native command storage -> Adreno GPU -> CPU readback E2E.
// Failure inventory: docs/ADRENO-FILL-INTEGRATION-20260927.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef SNAP_FILL_PLUGIN_SHA
#error Build with tools/build-adreno-fill-probe.py and a qualified plug-in.
#endif
static NSString *const expectedPluginSHA=@SNAP_FILL_PLUGIN_SHA;
static id<MTLCommandBuffer> heldCommand;
static id<MTLCommandQueue> heldQueue;
static id<MTLBuffer> heldBuffer;
static BOOL attemptedSubmission,knownCompleted;
enum { BufferLength=0x8000,FillOffset=0x3f00,FillLength=0x4000,FillValue=0x3c };

static double seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)) abort();
    return value.tv_sec+value.tv_nsec/1e9;
}
static void marker(NSString *text) {
    fprintf(stdout,"SnapintoshFillProbe: %s\n",text.UTF8String);fflush(stdout);
    int fd=open("/dev/console",O_WRONLY|O_NOCTTY);
    if(fd>=0){dprintf(fd,"SnapintoshFillProbe: %s\n",text.UTF8String);close(fd);}
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
static unsigned char pattern(NSUInteger offset) {
    unsigned char value=(unsigned char)((offset*17u+(offset>>8)*7u)^0xa5u);
    return value==FillValue ? 0xc3 : value;
}
static int fail(NSMutableDictionary *report,NSString *path,NSString *result,int code) {
    report[@"result"]=result;BOOL saved=save(report,path,@"failed");
    if(attemptedSubmission && !knownCompleted) {
        marker(@"Command, queue and buffer retained until reset; retirement is unproven.");
        for(;;)pause();
    }
    return saved ? code : 73;
}
int main(int argc,const char **argv) {
    @autoreleasepool {
        double waitSeconds=600;
        NSString *base=@"/var/db/Snapintosh/metal-fill-probe";
        for(int i=1;i<argc;i++) {
            if(!strcmp(argv[i],"--report-base") && i+1<argc)base=[NSString stringWithUTF8String:argv[++i]];
            else if(!strcmp(argv[i],"--wait") && i+1<argc) {
                char *end=NULL;waitSeconds=strtod(argv[++i],&end);
                if(!end || *end || !isfinite(waitSeconds) || waitSeconds<0 || waitSeconds>900)return 64;
            } else return 64;
        }
        if(!base.isAbsolutePath)return 64;
        NSError *error=nil;
        if(![[NSFileManager defaultManager] createDirectoryAtPath:base.stringByDeletingLastPathComponent
            withIntermediateDirectories:YES attributes:nil error:&error])return 73;
        NSString *runID=NSUUID.UUID.UUIDString;
        NSString *stem=[NSString stringWithFormat:@"%@-%@",base,runID];
        NSString *path=[stem stringByAppendingString:@".json"];
        int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL,0644);
        if(fd<0)return 73;close(fd);
        NSMutableDictionary *report=[@{@"schema":@"snapintosh-metal-fill-probe/1",@"run_id":runID,
            @"pid":@(getpid()),@"result":@"RUNNING",@"image_produced":@NO,
            @"expected_plugin_sha256":expectedPluginSHA,@"buffer_length":@(BufferLength),
            @"fill_offset":@(FillOffset),@"fill_length":@(FillLength),@"fill_value":@(FillValue),
            @"boundary":@"Public Metal fill and shared-buffer readback. Requires matching physical driver/map/command evidence; no shader rendering or screen presentation."} mutableCopy];
        if(!save(report,path,@"waiting-for-driver"))return 73;
        double start=seconds();
        @try {
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
            id<MTLDevice> target=nil;
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
            if(![imageSHA isEqualToString:expectedPluginSHA])return fail(report,path,@"FILL_PLUGIN_IDENTITY_FAILED",5);
            if(!save(report,path,@"fill-plugin-qualified"))return 73;
            heldBuffer=[target newBufferWithLength:BufferLength options:MTLResourceStorageModeShared];
            if(!heldBuffer || heldBuffer.device!=target || heldBuffer.length!=BufferLength ||
                heldBuffer.storageMode!=MTLStorageModeShared || !heldBuffer.contents)
                return fail(report,path,@"BUFFER_IDENTITY_FAILED",6);
            heldBuffer.label=@"Snapintosh GPU fill and surrounding canaries";
            unsigned char *bytes=heldBuffer.contents;
            for(NSUInteger i=0;i<BufferLength;i++)bytes[i]=pattern(i);
            NSString *beforePath=[stem stringByAppendingString:@"-before.bin"];
            report[@"before_sha256"]=digest(bytes,BufferLength);report[@"before_path"]=beforePath;
            if(![[NSData dataWithBytes:bytes length:BufferLength] writeToFile:beforePath options:NSDataWritingAtomic error:&error])
                return fail(report,path,@"BEFORE_ARTIFACT_FAILED",7);
            heldQueue=[target newCommandQueue];heldCommand=[heldQueue commandBuffer];
            if(!heldQueue || !heldCommand || !heldCommand.retainedReferences)
                return fail(report,path,@"NO_RETAINED_COMMAND_BUFFER",8);
            heldCommand.label=@"Snapintosh public Metal GPU fill32";
            id<MTLBlitCommandEncoder> encoder=[heldCommand blitCommandEncoder];
            if(!encoder)return fail(report,path,@"NO_BLIT_ENCODER",9);
            [encoder fillBuffer:heldBuffer range:NSMakeRange(FillOffset,FillLength) value:FillValue];
            [encoder endEncoding];
            if(!save(report,path,@"fill-encoded"))return 73;
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
            // No CPU destination stores occur after encoding/submission.
            const unsigned char *readback=heldBuffer.contents;
            NSString *afterPath=[stem stringByAppendingString:@"-after.bin"];
            report[@"after_sha256"]=digest(readback,BufferLength);report[@"after_path"]=afterPath;
            if(![[NSData dataWithBytes:readback length:BufferLength] writeToFile:afterPath options:NSDataWritingAtomic error:&error])
                return fail(report,path,@"READBACK_ARTIFACT_FAILED",12);
            NSUInteger mismatches=0,changed=0;
            for(NSUInteger i=0;i<BufferLength;i++) {
                unsigned char expected=(i>=FillOffset && i<FillOffset+FillLength) ? FillValue : pattern(i);
                changed+=readback[i]!=pattern(i);
                if(readback[i]!=expected) {
                    if(!mismatches)report[@"first_mismatch"]=@{@"offset":@(i),@"expected":@(expected),@"actual":@(readback[i])};
                    mismatches++;
                }
            }
            report[@"mismatches"]=@(mismatches);report[@"changed_bytes"]=@(changed);
            if(mismatches || changed!=FillLength)return fail(report,path,@"FILL_READBACK_MISMATCH",13);
            report[@"elapsed_seconds"]=@(seconds()-start);
            report[@"result"]=@"METAL_FILL_COMPLETED_BYTES_VERIFIED";
            return save(report,path,@"finished") ? 0 : 73;
        }@catch(NSException *exception) {
            report[@"exception"]=@{@"name":exception.name?:@"",@"reason":exception.reason?:@""};
            return fail(report,path,@"OBJC_EXCEPTION",14);
        }
    }
}
