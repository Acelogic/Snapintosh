/* SPDX-License-Identifier: MIT */
// Real CoreAnimation requests through the Adreno plug-in on the host, kept alive until the plug-in's
// compiles settle, so the shader records it writes (ADRENO_SHADER_CACHE_DIR) include the pipelines CA
// compiles asynchronously (the generic fallback) and not only those before the first commit.
// The layer trees are the composite capture scenes (tools/capture-ca-desktop-scenes.py). Native submission
// is dropped at IOGPUMetalCommandBuffer -commit: no command reaches the host GPU, and CA may then wait
// forever for completion, so the frame runs on its own thread and the process ends with _exit.
// usage: ca-shader-records BUNDLE REPORT.json SCENE METAL_CACHE_DIR [SETTLE_S] [LIMIT_S]
//   CA_SHADER_RECORDS_AIR_DIR=DIR also keeps every pipeline stage's AIR input as DIR/<sha256>-<entry>.bc.
// Doc: docs/SHADER-COMPILE-PATH-20260928.md.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#include <unistd.h>

extern void MTLAddDevice(id<MTLDevice>);
extern void MTLSetShaderCachePath(NSString *);
@interface NSObject (CAShaderRecords)
- (id)initWithAcceleratorPort:(unsigned int)port;
@end

static NSMutableDictionary *Report;
static NSString *Output;
// Kept alive until _exit: CARenderer's dealloc ends the frame again and would raise over a dropped commit.
static CARenderer *Renderer;

static void require(BOOL value, NSString *reason) {
    if (!value) @throw [NSException exceptionWithName:@"CAShaderRecords" reason:reason userInfo:nil];
}
static NSString *digest(NSData *data) {
    unsigned char value[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, value);
    NSMutableString *result = [NSMutableString string];
    for (unsigned i = 0; i < sizeof value; ++i) [result appendFormat:@"%02x", value[i]];
    return result;
}
static void save(NSString *stage) {
    @synchronized (Report) {
        if (stage) Report[@"stage"] = stage;
        NSData *data = [NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
        if (!data || ![data writeToFile:Output options:NSDataWritingAtomic error:NULL]) _exit(73);
    }
}

static void installNoSubmit(void) {
    __block NSUInteger dropped = 0;
    Method commit = class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandBuffer"), @selector(commit));
    require(commit != NULL, @"Missing native commit boundary");
    method_setImplementation(commit, imp_implementationWithBlock(^(id command) {
        @synchronized (Report) {
            Report[@"commits_dropped"] = @(++dropped);
            Report[@"commit_class"] = NSStringFromClass([command class]);
        }
        save(nil);                                        // never forwarded: nothing is submitted
    }));
    // The same host overrides the capture harness uses, so CA's draws encode as they would on the A16.
    Method copy = class_getInstanceMethod(NSClassFromString(@"AdrenoMTLDevice"), NSSelectorFromString(@"adrenoBufferCopyAvailable"));
    if (copy) method_setImplementation(copy, imp_implementationWithBlock(^BOOL(id device) { (void)device; return YES; }));
    Method draw = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDrawAvailable"));
    require(draw != NULL, @"Missing Adreno draw-availability hook");
    method_setImplementation(draw, imp_implementationWithBlock(^BOOL(id command) { (void)command; return YES; }));
}

// Optional (CA_SHADER_RECORDS_AIR_DIR): keep the exact AIR each pipeline stage hands the compiler, named by
// its SHA-256, the way qc-pipelines.m does, so a stage can be recompiled or profiled outside CoreAnimation.
static IMP OriginalPipeline;
static void keepPipelineAIR(Class deviceClass, NSString *directory) {
    SEL selector = NSSelectorFromString(@"newRenderPipelineWithDescriptor:vertexVariant:fragmentVariant:errorMessage:");
    Method method = class_getInstanceMethod(deviceClass, selector);
    require(method != NULL, @"Missing Adreno pipeline callback");
    [[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:NULL];
    OriginalPipeline = method_getImplementation(method);
    method_setImplementation(method, imp_implementationWithBlock(^id(id device, MTLRenderPipelineDescriptor *desc, id vertex,
                                                                    id fragment, NSString **error) {
        for (id variant in @[vertex ?: [NSNull null], fragment ?: [NSNull null]]) {
            if (variant == [NSNull null]) continue;
            id input = [variant valueForKey:@"input"];
            NSData *air = [input valueForKey:@"airModule"];
            NSString *entry = [input valueForKey:@"entry"] ?: @"";
            if (!air) continue;
            NSString *hash = digest(air);
            NSString *file = [directory stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@.bc", hash, entry]];
            if (![[NSFileManager defaultManager] fileExistsAtPath:file]) [air writeToFile:file atomically:YES];
            @synchronized (Report) {
                NSMutableArray *rows = Report[@"air_inputs"] ?: [NSMutableArray array];
                Report[@"air_inputs"] = rows;
                [rows addObject:@{@"entry":entry, @"air_sha256":hash, @"file":file,
                                  @"stage":@([[input valueForKey:@"stage"] unsignedIntegerValue]),
                                  @"label":desc.label ?: @""}];
            }
        }
        return ((id (*)(id, SEL, MTLRenderPipelineDescriptor *, id, id, NSString **))OriginalPipeline)(device, selector, desc,
                                                                                                     vertex, fragment, error);
    }));
}

static CALayer *sceneLayer(NSString *scene) {
    CALayer *root = [CALayer layer]; root.frame = CGRectMake(0, 0, 256, 160);
    CGColorRef blue = CGColorCreateGenericRGB(0.05, 0.15, 0.65, 1);
    CGColorRef orange = CGColorCreateGenericRGB(1, 0.25, 0.05, 1);
    CGColorRef pale = CGColorCreateGenericRGB(0.85, 0.91, 1, 0.92);
    CGColorRef dark = CGColorCreateGenericRGB(0.04, 0.07, 0.14, 1);
    CGColorRef white = CGColorCreateGenericRGB(1, 1, 1, 1);
    CGColorRef clear = CGColorCreateGenericRGB(0, 0, 0, 0);
    root.backgroundColor = blue; root.opaque = YES;
    CAGradientLayer *wall = [CAGradientLayer layer];
    wall.frame = root.bounds; wall.colors = @[(__bridge id)blue, (__bridge id)orange];
    wall.startPoint = CGPointMake(0, 0); wall.endPoint = CGPointMake(1, 1);
    [root addSublayer:wall];
    CALayer *menu = [CALayer layer]; menu.frame = CGRectMake(0, 142, 256, 18);
    menu.backgroundColor = pale; menu.opacity = 0.75; [root addSublayer:menu];
    CALayer *window = [CALayer layer]; window.frame = CGRectMake(16, 28, 180, 104);
    window.backgroundColor = pale; window.cornerRadius = 8; window.masksToBounds = YES;
    [root addSublayer:window];
    CAGradientLayer *header = [CAGradientLayer layer];
    header.frame = CGRectMake(0, 82, 180, 22);
    header.colors = @[(__bridge id)blue, (__bridge id)dark];
    header.startPoint = CGPointMake(0, 0.5); header.endPoint = CGPointMake(1, 0.5);
    [window addSublayer:header];
    CATextLayer *title = [CATextLayer layer]; title.frame = CGRectMake(8, 84, 164, 18);
    title.string = @"Snapintosh"; title.fontSize = 13; title.contentsScale = 1;
    title.foregroundColor = white; title.alignmentMode = kCAAlignmentCenter;
    [window addSublayer:title];
    CATextLayer *body = [CATextLayer layer]; body.frame = CGRectMake(10, 30, 158, 40);
    body.string = @"Adreno + Metal\nNative CA composition"; body.fontSize = 12;
    body.contentsScale = 1; body.wrapped = YES; body.foregroundColor = dark;
    [window addSublayer:body];
    CALayer *button = [CALayer layer]; button.frame = CGRectMake(104, 9, 62, 18);
    button.cornerRadius = 6; button.backgroundColor = blue; button.opacity = 0.7;
    [window addSublayer:button];
    CALayer *icon = [CALayer layer]; icon.frame = CGRectMake(200, 87, 40, 40);
    icon.backgroundColor = orange; icon.cornerRadius = 9;
    icon.borderColor = white; icon.borderWidth = 2; icon.opacity = 0.8;
    [root addSublayer:icon];
    if ([scene isEqualToString:@"shadow"]) {
        window.masksToBounds = NO; window.shadowColor = dark;
        window.shadowOpacity = 0.75; window.shadowRadius = 7;
        window.shadowOffset = CGSizeMake(5, -5);
    } else if ([scene isEqualToString:@"mask"]) {
        CAGradientLayer *mask = [CAGradientLayer layer]; mask.frame = window.bounds;
        mask.colors = @[(__bridge id)clear, (__bridge id)white, (__bridge id)white];
        mask.locations = @[@0, @0.4, @1];
        mask.startPoint = CGPointMake(0, 0.5); mask.endPoint = CGPointMake(1, 0.5);
        window.mask = mask;
    } else if ([scene isEqualToString:@"transform"]) {
        CATransform3D perspective = CATransform3DIdentity; perspective.m34 = -1.0 / 500.0;
        window.transform = CATransform3DRotate(perspective, 0.22, 0, 1, 0);
    }
    CGColorRelease(blue); CGColorRelease(orange); CGColorRelease(pale);
    CGColorRelease(dark); CGColorRelease(white); CGColorRelease(clear);
    return root;
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc < 5 || argc > 7) return 64;
        NSString *bundlePath = @(argv[1]), *scene = @(argv[3]), *metalCache = @(argv[4]);
        Output = @(argv[2]);
        double settle = argc > 5 ? atof(argv[5]) : 20, limit = argc > 6 ? atof(argv[6]) : 600;
        if (![@[@"desktop", @"shadow", @"mask", @"transform"] containsObject:scene] || settle < 1 || limit < settle) return 64;
        if ([[NSFileManager defaultManager] fileExistsAtPath:Output]) return 73;
        [[NSFileManager defaultManager] createDirectoryAtPath:metalCache withIntermediateDirectories:YES attributes:nil error:NULL];
        MTLSetShaderCachePath(metalCache);                   // before any Metal use
        Report = [@{@"status":@"RUNNING", @"scene":scene, @"a16_access":@NO, @"adreno_submitted_to_gpu":@NO,
            @"metal_cache":metalCache, @"records":@(getenv("ADRENO_SHADER_CACHE_DIR") ?: ""),
            @"executable_sha256":digest([NSData dataWithContentsOfFile:@(argv[0])]),
            @"boundary":@"Host CoreAnimation requests through the Adreno plug-in; native commits dropped, nothing submitted."} mutableCopy];
        int result = 2;
        @try {
            (void)MTLCopyAllDevices();
            NSError *error = nil;
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            require([bundle loadAndReturnError:&error], error.description ?: @"Bundle load failed");
            Report[@"plugin_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/MacOS/AdrenoMetal"]]);
            Report[@"compiler_sha256"] = digest([NSData dataWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Contents/Frameworks/libAdrenoCompiler.dylib"]]);
            installNoSubmit();
            if (getenv("CA_SHADER_RECORDS_AIR_DIR"))
                keepPipelineAIR([bundle classNamed:@"AdrenoMTLDevice"], @(getenv("CA_SHADER_RECORDS_AIR_DIR")));
            io_service_t provider = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
            require(provider != 0, @"No host allocation provider");
            id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:provider];
            IOObjectRelease(provider);
            require(device != nil, @"Adreno device initialization failed");
            MTLAddDevice(device);
            Class shader = [bundle classNamed:@"AdrenoShader"];
            require([shader respondsToSelector:NSSelectorFromString(@"cacheStatistics")], @"Plug-in without cache statistics");
            id<MTLCommandQueue> queue = [device newCommandQueue];
            IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)@{
                (id)kIOSurfaceWidth:@256, (id)kIOSurfaceHeight:@160,
                (id)kIOSurfaceBytesPerRow:@1024, (id)kIOSurfaceBytesPerElement:@4,
                (id)kIOSurfaceAllocSize:@163840, (id)kIOSurfacePixelFormat:@(0x42475241)});
            require(surface != NULL, @"IOSurface creation failed");
            MTLTextureDescriptor *desc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:256 height:160 mipmapped:NO];
            desc.storageMode = MTLStorageModeShared;
            desc.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:desc iosurface:surface plane:0];
            require(texture != nil, @"Target texture creation failed");
            __block NSString *frame = @"started";
            double start = CACurrentMediaTime();
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                @try {
                    CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture options:@{kCARendererMetalCommandQueue:queue}];
                    Renderer = renderer;
                    CALayer *root = sceneLayer(scene);
                    renderer.layer = root; renderer.bounds = root.bounds;
                    [CATransaction flush];
                    [renderer beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
                    [renderer addUpdateRect:root.bounds];
                    [renderer render];
                    @synchronized (Report) { frame = @"rendered"; }
                    [renderer endFrame];
                    @synchronized (Report) { frame = @"ended"; }
                } @catch (NSException *exception) {
                    @synchronized (Report) { frame = [NSString stringWithFormat:@"exception: %@: %@", exception.name, exception.reason]; }
                }
            });
            // Settled: no compile in flight and no counter change for `settle` seconds.
            NSArray *counters = @[@"hits_memory", @"hits_pack", @"hits_disk", @"misses", @"waits", @"rejects"];
            NSArray *last = nil;
            double changed = start;
            NSDictionary *stats = nil;
            while (CACurrentMediaTime() - start < limit) {
                usleep(250000);
                stats = [shader valueForKey:@"cacheStatistics"];
                NSArray *now = [stats objectsForKeys:counters notFoundMarker:@0];
                if (![now isEqual:last] || [stats[@"inflight"] unsignedIntegerValue]) { last = now; changed = CACurrentMediaTime(); }
                else if (CACurrentMediaTime() - changed >= settle) break;
            }
            NSString *frameState;
            @synchronized (Report) { frameState = frame; }
            Report[@"frame"] = frameState;
            Report[@"shader_cache"] = stats ?: @{};
            Report[@"elapsed_s"] = @(CACurrentMediaTime() - start);
            BOOL settled = CACurrentMediaTime() - start < limit;
            Report[@"status"] = settled ? @"CA_SHADERS_SETTLED" : @"CA_SHADERS_TIMEOUT";
            result = settled && ![frameState hasPrefix:@"exception"] ? 0 : 1;
        } @catch (NSException *exception) {
            Report[@"status"] = @"HARNESS_FAILED";
            Report[@"error"] = exception.reason ?: @"";
        }
        save(nil);
        printf("%s %s %s\n", [Report[@"status"] UTF8String], scene.UTF8String, [[Report[@"shader_cache"] description] UTF8String]);
        fflush(stdout);
        _exit(result);                                    // CA may still wait for a completion that never comes
    }
}
