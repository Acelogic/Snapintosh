/* SPDX-License-Identifier: MIT */
// Installed-guest application-to-Adreno fence probe; not a rendering test.
// Failure inventory: docs/INSTALLED-ADRENO-METAL-20260926.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <dispatch/dispatch.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static id<MTLCommandBuffer> retainedCommand;
static double seconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void marker(NSString *text) {
    const char *s = text.UTF8String;
    fprintf(stdout, "SnapintoshMetalProbe: %s\n", s);
    fflush(stdout);
    int fd = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (fd >= 0) { dprintf(fd, "SnapintoshMetalProbe: %s\n", s); close(fd); }
}
static BOOL save(NSMutableDictionary *report, NSString *path, NSString *stage) {
    report[@"stage"] = stage;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:&error]) {
        marker([NSString stringWithFormat:@"report write failed: %@", error]);
        return NO;
    }
    marker([NSString stringWithFormat:@"%@ report=%@", stage, path]);
    return YES;
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        double waitSeconds = 600;
        NSString *base = @"/var/db/Snapintosh/metal-probe";
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "--report-base") && i + 1 < argc) {
                base = [NSString stringWithUTF8String:argv[++i]];
            } else if (!strcmp(argv[i], "--wait") && i + 1 < argc) {
                char *end = NULL;
                waitSeconds = strtod(argv[++i], &end);
                if (!end || *end || !isfinite(waitSeconds) || waitSeconds < 0 || waitSeconds > 900) return 64;
            } else return 64;
        }
        if (![base isAbsolutePath]) return 64;
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:base.stringByDeletingLastPathComponent
            withIntermediateDirectories:YES attributes:nil error:&error]) return 73;
        NSString *runID = NSUUID.UUID.UUIDString;
        NSString *path = [NSString stringWithFormat:@"%@-%@.json", base, runID];
        int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) return 73;
        close(fd);
        NSMutableDictionary *report = [@{@"schema": @"snapintosh-metal-probe/1", @"run_id": runID,
            @"pid": @(getpid()), @"result": @"RUNNING", @"image_produced": @NO,
            @"expected_driver": @"AdrenoAcceleratorX2", @"expected_plugin": @"AdrenoMTLDevice",
            @"boundary": @"Ordinary application command-buffer fence; no rendering or GUI proof."} mutableCopy];
        if (!save(report,path,@"waiting-for-driver")) return 73;
        double start = seconds();
        io_service_t service = IO_OBJECT_NULL;
        do {
            service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AdrenoAcceleratorX2"));
            if (service || seconds()-start >= waitSeconds) break;
            usleep(1000000);
        } while (1);
        if (!service) {
            report[@"result"] = @"NO_ADRENO_SERVICE";
            save(report,path,@"discovery-failed");
            return 2;
        }
        uint64_t registryID = 0;
        io_name_t className = {0};
        kern_return_t idStatus = IORegistryEntryGetRegistryEntryID(service,&registryID);
        kern_return_t classStatus = IOObjectGetClass(service,className);
        IOObjectRelease(service);
        if (idStatus || classStatus || !registryID || strcmp(className,"AdrenoAcceleratorX2")) {
            report[@"result"] = @"DRIVER_IDENTITY_FAILED";
            report[@"registry_id_status"] = @(idStatus);
            report[@"class_status"] = @(classStatus);
            save(report,path,@"driver-identity-failed");
            return 3;
        }
        report[@"registry_id"] = @(registryID);
        report[@"driver_class"] = [NSString stringWithUTF8String:className];
        if (!save(report,path,@"driver-found")) return 73;
        NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();
        id<MTLDevice> target = nil;
        NSMutableArray *inventory = [NSMutableArray array];
        for (id<MTLDevice> device in devices) {
            [inventory addObject:@{@"name":device.name ?: @"", @"class":NSStringFromClass([device class]),
                                   @"registry_id":@(device.registryID)}];
            if (device.registryID == registryID &&
                [NSStringFromClass([device class]) isEqualToString:@"AdrenoMTLDevice"]) target = device;
        }
        report[@"devices"] = inventory;
        if (!target) {
            report[@"result"] = @"NO_ADRENO_METAL_DEVICE";
            save(report,path,@"plugin-discovery-failed");
            return 4;
        }
        if (!save(report,path,@"metal-device-found")) return 73;
        id<MTLCommandQueue> queue = [target newCommandQueue];
        retainedCommand = [queue commandBuffer];
        if (!queue || !retainedCommand) {
            report[@"result"] = @"NO_COMMAND_BUFFER";
            save(report,path,@"command-creation-failed");
            return 5;
        }
        retainedCommand.label = @"Snapintosh application GPU fence";
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        [retainedCommand addCompletedHandler:^(id<MTLCommandBuffer> buffer) {
            (void)buffer;
            dispatch_semaphore_signal(done);
        }];
        if (!save(report,path,@"submitting")) return 73;
        [retainedCommand commit];
        if (dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,60LL*NSEC_PER_SEC))) {
            report[@"result"] = @"COMPLETION_TIMEOUT";
            report[@"command_status"] = @(retainedCommand.status);
            save(report,path,@"submitted-command-retained-until-reset");
            for (;;) pause();
        }
        report[@"command_status"] = @(retainedCommand.status);
        report[@"command_error"] = retainedCommand.error.description ?: @"";
        report[@"elapsed_seconds"] = @(seconds()-start);
        BOOL passed = retainedCommand.status == MTLCommandBufferStatusCompleted && !retainedCommand.error;
        report[@"result"] = passed ? @"APPLICATION_FENCE_COMPLETED" : @"COMMAND_FAILED";
        if (!save(report,path,@"finished")) return 73;
        return passed ? 0 : 6;
    }
}
