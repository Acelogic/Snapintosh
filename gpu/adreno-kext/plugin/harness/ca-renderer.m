/* SPDX-License-Identifier: MIT */
// Real CARenderer through Adreno, with native submission captured on the host.
// Failure inventory: docs/ADRENO-CA-RENDERER-20260928.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#include <unistd.h>

extern void MTLAddDevice(id<MTLDevice>);
typedef struct {
    uint64_t offset, rowBytes, width, height, allocationBytes;
    MTLPixelFormat format;
} CaptureLinearLayout;
@interface NSObject (CARenderCapture)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (uint32_t)resourceID;
- (void *)virtualAddress;
- (BOOL)adrenoGetLinearLayout:(CaptureLinearLayout *)layout;
- (MTLSamplerDescriptor *)adrenoSamplerDescriptor;
@end

static NSMutableDictionary *Report;
static NSString *Output;
static NSMutableArray *Commits;
static NSMapTable *Reservations;
static unsigned int CommitCount;
static BOOL SimulateCopyABI;

static void require(BOOL value, NSString *reason) {
    if (!value) @throw [NSException exceptionWithName:@"CARenderCapture" reason:reason userInfo:nil];
}
static NSString *digest(NSData *data) {
    require(data != nil, @"Missing hash input");
    unsigned char value[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, value);
    NSMutableString *result = [NSMutableString string];
    for (unsigned i = 0; i < sizeof value; ++i) [result appendFormat:@"%02x", value[i]];
    return result;
}
static void save(NSString *stage) {
    @synchronized (Report) {
        if (stage) Report[@"stage"] = stage;
        NSData *data = [NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingPrettyPrinted error:NULL];
        if (!data || ![data writeToFile:Output options:NSDataWritingAtomic error:NULL]) _exit(73);
    }
}
static void recordException(NSException *exception) {
    @synchronized (Report) {
        Report[@"status"] = @"CA_RENDER_EXCEPTION";
        Report[@"exception"] = @{@"name":exception.name ?: @"", @"reason":exception.reason ?: @"",
            @"stack":exception.callStackSymbols ?: @[]};
        save(nil);
    }
}
static void uncaught(NSException *exception) {
    recordException(exception);
    _exit(2);
}
static void installCapture(void) {
    NSMutableDictionary<NSNumber *, id> *resourceObjects = [NSMutableDictionary dictionary];
    SEL useSelector = NSSelectorFromString(@"recordResource:usage:");
    Method use = class_getInstanceMethod(NSClassFromString(@"AdrenoResourceUsage"), useSelector);
    require(use != NULL, @"Missing resource retention hook");
    IMP originalUse = method_getImplementation(use);
    method_setImplementation(use, imp_implementationWithBlock(^(id usage, id resource, MTLResourceUsage access) {
        ((void (*)(id, SEL, id, MTLResourceUsage))originalUse)(usage, useSelector, resource, access);
        @synchronized (resourceObjects) { resourceObjects[@([resource resourceID])] = resource; }
    }));
    SEL bindingsSelector = NSSelectorFromString(@"adrenoSetFragmentTextures:samplers:");
    Method bindings = class_getInstanceMethod(NSClassFromString(@"AdrenoRenderPass"), bindingsSelector);
    if (bindings) {
        IMP originalBindings = method_getImplementation(bindings);
        NSMutableArray *bindingsReport = [NSMutableArray array];
        Report[@"fragment_bindings"] = bindingsReport;
        method_setImplementation(bindings, imp_implementationWithBlock(^(id pass, id<MTLTexture> const __strong *textures,
                                                                         id<MTLSamplerState> const __strong *samplers) {
            NSMutableArray *ts = [NSMutableArray array], *ss = [NSMutableArray array];
            for (NSUInteger i = 0; i < 31; i++) if (textures[i]) {
                id<MTLTexture> t = textures[i];
                CaptureLinearLayout l = {0};
                BOOL known = [(id)t respondsToSelector:@selector(adrenoGetLinearLayout:)] && [(id)t adrenoGetLinearLayout:&l];
                [ts addObject:@{@"index":@(i), @"resource_id":@([(id)t resourceID]), @"format":@(t.pixelFormat),
                    @"width":@(t.width), @"height":@(t.height), @"usage":@(t.usage), @"layout_known":@(known),
                    @"offset":@(l.offset), @"pitch":@(l.rowBytes), @"allocation":@(l.allocationBytes)}];
            }
            for (NSUInteger i = 0; i < 16; i++) if (samplers[i]) {
                MTLSamplerDescriptor *s = [(id)samplers[i] adrenoSamplerDescriptor];
                require(s != nil, @"Missing immutable sampler descriptor");
                [ss addObject:@{@"index":@(i), @"min":@(s.minFilter), @"mag":@(s.magFilter), @"mip":@(s.mipFilter),
                    @"s":@(s.sAddressMode), @"t":@(s.tAddressMode), @"r":@(s.rAddressMode), @"aniso":@(s.maxAnisotropy),
                    @"normalized":@(s.normalizedCoordinates), @"lod_min":@(s.lodMinClamp), @"lod_max":@(s.lodMaxClamp),
                    @"compare":@(s.compareFunction), @"border":@(s.borderColor), @"lod_average":@(s.lodAverage)}];
            }
            @synchronized (Report) { [bindingsReport addObject:@{@"textures":ts, @"samplers":ss}]; }
            ((void (*)(id, SEL, id<MTLTexture> const __strong *, id<MTLSamplerState> const __strong *))originalBindings)
                (pass, bindingsSelector, textures, samplers);
        }));
    }
    Method copyAvailable = class_getInstanceMethod(NSClassFromString(@"AdrenoMTLDevice"), NSSelectorFromString(@"adrenoBufferCopyAvailable"));
    Report[@"copy_availability_overridden"] = @(copyAvailable != NULL && SimulateCopyABI);
    if (copyAvailable && SimulateCopyABI)
        method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id device) { (void)device; return YES; }));
    Class pipeline = NSClassFromString(@"AdrenoRenderPipelineState");
    SEL programSelector = NSSelectorFromString(@"adrenoDrawProgram");
    Method program = class_getInstanceMethod(pipeline, programSelector);
    require(program != NULL, @"Missing Adreno draw-program hook");
    IMP originalProgram = method_getImplementation(program);
    NSMutableArray *programs = [NSMutableArray array];
    Report[@"programs"] = programs;
    NSHashTable *seen = [NSHashTable hashTableWithOptions:NSPointerFunctionsStrongMemory | NSPointerFunctionsObjectPointerPersonality];
    method_setImplementation(program, imp_implementationWithBlock(^id(id state) {
        @synchronized (Report) {
            if (![seen containsObject:state]) {
                [seen addObject:state];
                NSMutableDictionary *row = [NSMutableDictionary dictionary];
                for (NSString *stage in @[@"vertex", @"fragment"]) {
                    id shader = [state valueForKey:[stage stringByAppendingString:@"Code"]];
                    NSData *data = [shader valueForKey:@"programData"];
                    NSString *path = [NSString stringWithFormat:@"%@.pipeline-%lu-%@.json", Output, (unsigned long)programs.count, stage];
                    require(data && [data writeToFile:path options:NSDataWritingWithoutOverwriting error:NULL], @"Program artifact write failed");
                    row[stage] = @{@"path":path, @"sha256":digest(data)};
                }
                [programs addObject:row]; save(nil);
            }
        }
        return ((id (*)(id, SEL))originalProgram)(state, programSelector);
    }));
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, NSSelectorFromString(@"_reserveKernelCommandBufferSpace:"));
    Method commit = class_getInstanceMethod(native, @selector(commit));
    require(reserve && commit, @"Missing native reserve/commit boundary");
    Reservations = [NSMapTable strongToStrongObjectsMapTable];
    IMP original = method_getImplementation(reserve);
    SEL reserveSelector = method_getName(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id command, NSUInteger length) {
        void *bytes = ((void *(*)(id, SEL, NSUInteger))original)(command, reserveSelector, length);
        @synchronized (Reservations) {
            [Reservations setObject:@{@"pointer":[NSValue valueWithPointer:bytes], @"length":@(length)} forKey:command];
        }
        return bytes;
    }));
    method_setImplementation(commit, imp_implementationWithBlock(^(id command) {
        require([NSStringFromClass([command class]) isEqual:@"AdrenoCommandBuffer"], @"Unexpected command class at submission boundary");
        @synchronized (Report) {
            NSDictionary *reservation;
            @synchronized (Reservations) { reservation = [Reservations objectForKey:command]; }
            NSUInteger length = [reservation[@"length"] unsignedIntegerValue];
            const void *bytes = [reservation[@"pointer"] pointerValue];
            require(bytes && length && length <= (16 << 20), @"Missing or unbounded command reservation");
            NSData *data = [NSData dataWithBytes:bytes length:length];
            NSString *path = [NSString stringWithFormat:@"%@.commit-%u.bin", Output, CommitCount++];
            require([data writeToFile:path options:NSDataWritingWithoutOverwriting error:NULL], @"Commit artifact write failed");
            Ivar usageIvar = class_getInstanceVariable(object_getClass(command), "_adrenoResources");
            id usage = usageIvar ? object_getIvar(command, usageIvar) : nil;
            Ivar recordsIvar = usage ? class_getInstanceVariable(object_getClass(usage), "_records") : NULL;
            NSData *records = recordsIvar ? object_getIvar(usage, recordsIvar) : nil;
            require(records && !(records.length % 32), @"Missing native resource records");
            NSMutableArray *published = [NSMutableArray array];
            for (NSUInteger at = 0; at < records.length; at += 32) {
                const uint8_t *entry = (const uint8_t *)records.bytes + at;
                uint64_t sizeAndField; uint32_t rid, access;
                memcpy(&sizeAndField, entry + 8, 8); memcpy(&rid, entry + 16, 4); memcpy(&access, entry + 24, 4);
                uint64_t size = sizeAndField & 0x00ffffffffffffffull;
                id resource;
                @synchronized (resourceObjects) { resource = resourceObjects[@(rid)]; }
                require(resource && size && size <= (1 << 20), @"Missing or oversized captured resource");
                const void *cpu = [resource virtualAddress];
                if ([resource conformsToProtocol:@protocol(MTLTexture)]) {
                    IOSurfaceRef surface = [(id<MTLTexture>)resource iosurface];
                    if (surface) {
                        require(IOSurfaceGetAllocSize(surface) >= size, @"Texture surface is smaller than the resource");
                        cpu = IOSurfaceGetBaseAddress(surface);
                    }
                }
                require(cpu != NULL, @"Captured resource has no CPU mapping");
                NSData *snapshot = [NSData dataWithBytes:cpu length:(NSUInteger)size];
                NSString *resourcePath = [NSString stringWithFormat:@"%@.resource-%u.bin", Output, rid];
                require([snapshot writeToFile:resourcePath options:NSDataWritingWithoutOverwriting error:NULL], @"Resource snapshot write failed");
                [published addObject:@{@"id":@(rid), @"size":@(size), @"usage":@(access),
                    @"path":resourcePath, @"sha256":digest(snapshot), @"class":NSStringFromClass([resource class])}];
            }
            [Commits addObject:@{@"command_class":NSStringFromClass([command class]),
                @"bytes":@(length), @"sha256":digest(data), @"path":path, @"published_resources":published}];
            Report[@"status"] = @"ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED";
            Report[@"boundary"] = @"Stopped at first native commit; completion and endFrame were not simulated.";
            save(@"native-commit-captured");
            // CA can still wait for a command despite the client-supplied queue.
            // End the capture here instead of fabricating completed GPU work.
            _exit(0);
        }
    }));
    Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDrawAvailable"));
    require(available != NULL, @"Missing Adreno draw-availability hook");
    method_setImplementation(available, imp_implementationWithBlock(^BOOL(id command) { (void)command; return YES; }));
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 4 && argc != 5) return 64;
        BOOL imageScene = argc == 5 && !strcmp(argv[4], "--image");
        // --rich: the layer features a login screen uses (gradient, rounded masked corners, shadows, text, a Gaussian
        // blur filter, group opacity), to list what the plug-in drops for them (the lenient build's diagnostics file).
        BOOL richScene = argc == 5 && !strcmp(argv[4], "--rich");
        if (argc == 5 && !imageScene && !richScene) return 64;
        BOOL host = !strcmp(argv[1], "--host");
        SimulateCopyABI = !strcmp(argv[1], "--adreno");
        if (!host && !SimulateCopyABI && strcmp(argv[1], "--adreno-no-copy")) return 64;
        NSString *bundlePath = @(argv[2]); Output = @(argv[3]);
        if ([[NSFileManager defaultManager] fileExistsAtPath:Output]) return 73;
        Commits = [NSMutableArray array];
        Report = [@{@"status":@"RUNNING", @"mode":host ? @"host-reference" : @"adreno-capture",
            @"commits":Commits, @"a16_access":@NO, @"adreno_submitted_to_gpu":@NO,
            @"draw_availability_overridden":@(!host), @"width":@256, @"height":@160,
            @"scene":imageScene ? @"blue root with checkerboard image child" : @"blue root with orange child rectangle",
            @"host":NSProcessInfo.processInfo.operatingSystemVersionString,
            @"executable_sha256":digest([NSData dataWithContentsOfFile:@(argv[0])])} mutableCopy];
        NSSetUncaughtExceptionHandler(uncaught);
        int result = 2;
        @try {
            save(@"device");
            id<MTLDevice> device;
            if (host) device = MTLCreateSystemDefaultDevice();
            else {
                (void)MTLCopyAllDevices();
                NSError *error = nil;
                NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
                require([bundle loadAndReturnError:&error], error.description ?: @"Bundle load failed");
                Report[@"plugin_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/MacOS/AdrenoMetal"]]);
                Report[@"compiler_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/Frameworks/libAdrenoCompiler.dylib"]]);
                installCapture();
                io_service_t provider = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
                require(provider != 0, @"No host allocation provider");
                device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:provider];
                IOObjectRelease(provider);
                require(device != nil, @"Adreno device initialization failed");
                MTLAddDevice(device);
            }
            require(device != nil, @"Missing device");
            Report[@"device_class"] = NSStringFromClass([(id)device class]);
            id<MTLCommandQueue> queue = [device newCommandQueue];
            require(queue && queue.device == device, @"Queue device mismatch");
            Report[@"queue_class"] = NSStringFromClass([(id)queue class]);
            save(@"texture");
            IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)@{
                (id)kIOSurfaceWidth:@256, (id)kIOSurfaceHeight:@160,
                (id)kIOSurfaceBytesPerRow:@1024, (id)kIOSurfaceBytesPerElement:@4,
                (id)kIOSurfaceAllocSize:@163840, (id)kIOSurfacePixelFormat:@(0x42475241)});
            require(surface != NULL, @"IOSurface creation failed");
            MTLTextureDescriptor *desc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:256 height:160 mipmapped:NO];
            desc.storageMode = MTLStorageModeShared;
            desc.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:desc iosurface:surface plane:0];
            require(texture && texture.device == device, @"Texture device mismatch");
            Report[@"texture_class"] = NSStringFromClass([(id)texture class]);
            if (!host) Report[@"target_resource_id"] = @([(id)texture resourceID]);
            save(@"renderer");
            CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture options:@{kCARendererMetalCommandQueue:queue}];
            require(renderer != nil, @"CARenderer initialization failed");
            CALayer *root = [CALayer layer]; root.frame = CGRectMake(0, 0, 256, 160);
            CGColorRef blue = CGColorCreateGenericRGB(0.05, 0.15, 0.65, 1);
            CGColorRef orange = CGColorCreateGenericRGB(1, 0.25, 0.05, 1);
            root.backgroundColor = blue; root.opaque = YES;
            CALayer *child = [CALayer layer]; child.frame = CGRectMake(48, 32, 160, 96);
            child.backgroundColor = orange; child.opaque = YES; [root addSublayer:child];
            if (imageScene) {
                uint8_t pixels[8*8*4];
                for (unsigned y=0; y<8; ++y) for (unsigned x=0; x<8; ++x) {
                    uint8_t *pixel = pixels + 4*(8*y+x);
                    BOOL alternate = (x+y)&1;
                    pixel[0] = alternate ? 220 : 20;
                    pixel[1] = alternate ? 30 : 210;
                    pixel[2] = 180; pixel[3] = 255;
                }
                NSData *imageData = [NSData dataWithBytes:pixels length:sizeof pixels];
                CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)imageData);
                CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
                CGImageRef image = CGImageCreate(8, 8, 8, 32, 32, colorSpace,
                    kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big, provider, NULL, NO, kCGRenderingIntentDefault);
                require(image != NULL, @"Checkerboard image creation failed");
                child.contents = (__bridge id)image;
                child.magnificationFilter = kCAFilterNearest; child.minificationFilter = kCAFilterNearest;
                CGImageRelease(image); CGColorSpaceRelease(colorSpace); CGDataProviderRelease(provider);
            }
            if (richScene) {
                CAGradientLayer *gradient = [CAGradientLayer layer];
                gradient.frame = root.bounds;
                gradient.colors = @[(__bridge id)blue, (__bridge id)orange];
                [root insertSublayer:gradient atIndex:0];
                CALayer *card = [CALayer layer]; card.frame = CGRectMake(24, 24, 120, 80);
                card.backgroundColor = blue; card.cornerRadius = 14; card.masksToBounds = YES;
                card.borderWidth = 2; card.borderColor = orange;
                [root addSublayer:card];
                CALayer *shadowed = [CALayer layer]; shadowed.frame = CGRectMake(150, 70, 80, 60);
                shadowed.backgroundColor = orange; shadowed.cornerRadius = 10;
                shadowed.shadowOpacity = 0.6; shadowed.shadowRadius = 8; shadowed.shadowOffset = CGSizeMake(0, -4);
                [root addSublayer:shadowed];
                CATextLayer *text = [CATextLayer layer]; text.frame = CGRectMake(30, 110, 200, 30);
                text.string = @"Snapintosh"; text.fontSize = 20; text.contentsScale = 1;
                CGColorRef white = CGColorCreateGenericRGB(1, 1, 1, 1);
                text.foregroundColor = white; CGColorRelease(white);
                [root addSublayer:text];
                Class filterClass = NSClassFromString(@"CAFilter");
                if (filterClass) {
                    id blur = [filterClass performSelector:@selector(filterWithType:) withObject:@"gaussianBlur"];
                    [blur setValue:@6 forKey:@"inputRadius"];
                    CALayer *blurred = [CALayer layer]; blurred.frame = CGRectMake(160, 10, 80, 50);
                    blurred.backgroundColor = orange; blurred.filters = @[blur];
                    [root addSublayer:blurred];
                }
                CALayer *group = [CALayer layer]; group.frame = CGRectMake(100, 20, 60, 40);
                group.opacity = 0.5; group.allowsGroupOpacity = YES;
                CALayer *a = [CALayer layer]; a.frame = CGRectMake(0, 0, 40, 30); a.backgroundColor = blue;
                CALayer *b = [CALayer layer]; b.frame = CGRectMake(20, 10, 40, 30); b.backgroundColor = orange;
                [group addSublayer:a]; [group addSublayer:b];
                [root addSublayer:group];
            }
            CGColorRelease(blue); CGColorRelease(orange);
            renderer.layer = root; renderer.bounds = root.bounds;
            [CATransaction flush];
            save(@"begin-frame");
            [renderer beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
            [renderer addUpdateRect:root.bounds];
            // Catch before ARC unwinds renderer: its dealloc calls endFrame and
            // can replace the first encoding error with a failed-commit error.
            @try {
                save(@"render"); [renderer render];
                save(@"end-frame"); [renderer endFrame];
            } @catch (NSException *exception) {
                recordException(exception);
                _exit(2);
            }
            if (host) {
                id<MTLCommandBuffer> barrier = [queue commandBuffer]; [barrier commit]; [barrier waitUntilCompleted];
                require(barrier.status == MTLCommandBufferStatusCompleted, @"Host render did not complete");
                require(IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL) == 0, @"Readback lock failed");
                NSData *pixels = [NSData dataWithBytes:IOSurfaceGetBaseAddress(surface) length:163840];
                IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
                NSString *path = [Output stringByAppendingString:@".bgra"];
                require([pixels writeToFile:path options:NSDataWritingWithoutOverwriting error:NULL], @"Pixel artifact write failed");
                Report[@"pixels"] = @{@"path":path, @"sha256":digest(pixels)};
                Report[@"status"] = @"HOST_CA_RENDER_COMPLETED";
            } else {
                require(Commits.count > 0, @"CARenderer did not reach native commit");
                Report[@"status"] = @"ADRENO_CA_COMMANDS_CAPTURED_NOT_SUBMITTED";
            }
            CFRelease(surface);
            result = 0;
        } @catch (NSException *exception) { recordException(exception); }
        save(nil);
        printf("%s\n", [Report[@"status"] UTF8String]);
        return result;
    }
}
