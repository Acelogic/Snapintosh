/* SPDX-License-Identifier: MIT */
// Installed-guest E2E resource submission. No rendering or presentation.
// Failure inventory: docs/ADRENO-FIRST-METAL-IMAGE-20260926.md.
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

static NSString *const expectedPluginSHA =
    @"12b774c3022e6fd1f5a684fff21256337e0e0ef4551a1a7d12559a9eb4b55dc1";
static id<MTLCommandBuffer> heldCommand;
static NSMutableArray<id<MTLBuffer>> *heldBuffers;
static BOOL attemptedSubmission;
static BOOL knownCompleted;

static double seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) abort();
    return value.tv_sec + value.tv_nsec / 1e9;
}

static void marker(NSString *text) {
    fprintf(stdout, "SnapintoshResourceProbe: %s\n", text.UTF8String);
    fflush(stdout);
    int fd = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (fd >= 0) { dprintf(fd, "SnapintoshResourceProbe: %s\n", text.UTF8String); close(fd); }
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
    marker([NSString stringWithFormat:@"%@ result=%@ report=%@", stage, report[@"result"], path]);
    return YES;
}

static NSString *digest(const void *bytes, NSUInteger length) {
    if (length > UINT32_MAX) return nil;
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes, (CC_LONG)length, hash);
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (unsigned i = 0; i < sizeof hash; i++) [text appendFormat:@"%02x", hash[i]];
    return text;
}

static unsigned char pattern(NSUInteger buffer, NSUInteger offset) {
    return (unsigned char)((buffer * 53u + offset * 17u + (offset >> 8) * 7u) ^ 0xa5u);
}

static int fail(NSMutableDictionary *report, NSString *path, NSString *result, int code) {
    report[@"result"] = result;
    BOOL saved = save(report, path, @"failed");
    if (attemptedSubmission && !knownCompleted) {
        marker(@"Command and resources retained until reset; submission retirement is unproven.");
        for (;;) pause();
    }
    return saved ? code : 73;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        double waitSeconds = 600;
        NSString *base = @"/var/db/Snapintosh/metal-resource-probe";
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
        NSMutableDictionary *report = [@{@"schema": @"snapintosh-metal-resource-probe/1",
            @"run_id": runID, @"pid": @(getpid()), @"result": @"RUNNING", @"image_produced": @NO,
            @"expected_plugin_sha256": expectedPluginSHA,
            @"boundary": @"Resource-bearing application fence and CPU canary integrity only. Requires corroborating physical mapper/driver capture; no drawing, dispatch or GUI proof."} mutableCopy];
        if (!save(report, path, @"waiting-for-driver")) return 73;
        double start = seconds();
        @try {
            io_service_t service = IO_OBJECT_NULL;
            do {
                service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AdrenoAcceleratorX2"));
                if (service || seconds() - start >= waitSeconds) break;
                usleep(1000000);
            } while (1);
            if (!service) return fail(report, path, @"NO_ADRENO_SERVICE", 2);
            uint64_t registryID = 0;
            io_name_t className = {0};
            kern_return_t idStatus = IORegistryEntryGetRegistryEntryID(service, &registryID);
            kern_return_t classStatus = IOObjectGetClass(service, className);
            IOObjectRelease(service);
            if (idStatus || classStatus || !registryID || strcmp(className, "AdrenoAcceleratorX2"))
                return fail(report, path, @"DRIVER_IDENTITY_FAILED", 3);
            report[@"registry_id"] = @(registryID);
            report[@"driver_class"] = [NSString stringWithUTF8String:className];
            if (!save(report, path, @"driver-found")) return 73;
            id<MTLDevice> target = nil;
            NSMutableArray *inventory = [NSMutableArray array];
            for (id<MTLDevice> device in MTLCopyAllDevices()) {
                [inventory addObject:@{@"name": device.name ?: @"", @"class": NSStringFromClass([device class]),
                                       @"registry_id": @(device.registryID)}];
                if (device.registryID == registryID &&
                    [NSStringFromClass([device class]) isEqualToString:@"AdrenoMTLDevice"]) target = device;
            }
            report[@"devices"] = inventory;
            if (!target) return fail(report, path, @"NO_ADRENO_METAL_DEVICE", 4);
            const char *imageName = class_getImageName([target class]);
            NSString *imagePath = imageName ? [NSString stringWithUTF8String:imageName] : nil;
            NSData *image = imagePath ? [NSData dataWithContentsOfFile:imagePath options:0 error:&error] : nil;
            NSString *imageSHA = image ? digest(image.bytes, image.length) : nil;
            report[@"plugin_path"] = imagePath ?: @"";
            report[@"plugin_sha256"] = imageSHA ?: @"";
            if (![imageSHA isEqualToString:expectedPluginSHA])
                return fail(report, path, @"RESOURCE_PLUGIN_IDENTITY_FAILED", 5);
            if (!save(report, path, @"resource-plugin-qualified")) return 73;

            heldBuffers = [NSMutableArray array];
            NSMutableArray *bufferRecords = [NSMutableArray array];
            report[@"buffers"] = bufferRecords;
            for (NSUInteger i = 0; i < 7; i++) {
                NSUInteger length = (i + 1) * 16384;
                id<MTLBuffer> buffer = [target newBufferWithLength:length options:MTLResourceStorageModeShared];
                if (!buffer) return fail(report, path, @"BUFFER_ALLOCATION_FAILED", 6);
                [heldBuffers addObject:buffer];
                if (buffer.device != target || buffer.length != length ||
                    buffer.storageMode != MTLStorageModeShared || !buffer.contents)
                    return fail(report, path, @"BUFFER_IDENTITY_FAILED", 7);
                buffer.label = [NSString stringWithFormat:@"Snapintosh resource probe %lu", (unsigned long)i];
                unsigned char *bytes = buffer.contents;
                for (NSUInteger j = 0; j < length; j++) bytes[j] = pattern(i, j);
                [bufferRecords addObject:[@{@"index": @(i), @"length": @(length),
                    @"class": NSStringFromClass([buffer class]), @"before_sha256": digest(bytes, length),
                    @"encoded_usage": @(MTLResourceUsageRead | MTLResourceUsageWrite)} mutableCopy]];
                if (!save(report, path, @"allocating-resources")) return 73;
            }
            id<MTLCommandQueue> queue = [target newCommandQueue];
            heldCommand = [queue commandBuffer];
            if (!queue || !heldCommand || !heldCommand.retainedReferences)
                return fail(report, path, @"NO_RETAINED_COMMAND_BUFFER", 8);
            heldCommand.label = @"Snapintosh seven-resource GPU fence";
            id<MTLComputeCommandEncoder> encoder = [heldCommand computeCommandEncoder];
            if (!encoder) return fail(report, path, @"NO_RESOURCE_ENCODER", 9);
            // No dispatch is requested. The production plug-in emits its fence
            // after publishing these real resources into native IOGPU storage.
            for (id<MTLBuffer> buffer in heldBuffers) [encoder useResource:buffer usage:MTLResourceUsageRead];
            for (id<MTLBuffer> buffer in heldBuffers) [encoder useResource:buffer usage:MTLResourceUsageWrite];
            [encoder useResource:heldBuffers[0] usage:MTLResourceUsageRead | MTLResourceUsageWrite];
            [encoder endEncoding];
            report[@"use_resource_calls"] = @15;
            if (!save(report, path, @"resources-encoded")) return 73;
            dispatch_semaphore_t done = dispatch_semaphore_create(0);
            [heldCommand addCompletedHandler:^(id<MTLCommandBuffer> command) {
                (void)command;
                dispatch_semaphore_signal(done);
            }];
            if (!save(report, path, @"submitting")) return 73;
            attemptedSubmission = YES;
            [heldCommand commit];
            if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 60LL * NSEC_PER_SEC))) {
                report[@"command_status"] = @(heldCommand.status);
                return fail(report, path, @"COMPLETION_TIMEOUT", 10);
            }
            report[@"command_status"] = @(heldCommand.status);
            report[@"command_error"] = heldCommand.error.description ?: @"";
            if (heldCommand.status != MTLCommandBufferStatusCompleted || heldCommand.error)
                return fail(report, path, @"COMMAND_FAILED", 11);
            knownCompleted = YES;
            for (NSUInteger i = 0; i < heldBuffers.count; i++) {
                id<MTLBuffer> buffer = heldBuffers[i];
                const unsigned char *bytes = buffer.contents;
                NSMutableDictionary *item = bufferRecords[i];
                item[@"after_sha256"] = digest(bytes, buffer.length);
                for (NSUInteger j = 0; j < buffer.length; j++) {
                    if (bytes[j] != pattern(i, j)) {
                        item[@"first_mismatch"] = @(j);
                        return fail(report, path, @"RESOURCE_CANARY_CHANGED", 12);
                    }
                }
                item[@"canary_unchanged"] = @YES;
            }
            report[@"elapsed_seconds"] = @(seconds() - start);
            report[@"result"] = @"RESOURCE_FENCE_COMPLETED_CANARIES_UNCHANGED";
            return save(report, path, @"finished") ? 0 : 73;
        } @catch (NSException *exception) {
            report[@"exception"] = @{@"name": exception.name ?: @"", @"reason": exception.reason ?: @""};
            return fail(report, path, @"OBJC_EXCEPTION", 13);
        }
    }
}
