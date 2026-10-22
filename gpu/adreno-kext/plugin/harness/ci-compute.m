/* SPDX-License-Identifier: MIT */
// Real CoreImage work on the Adreno device: the compute kernels iconservicesagent's icon rendering builds
// (docs/USERSPACE-GRAPHICS-20261019.md, v80 CoreImage compute shapes). Native commits are intercepted; nothing is
// submitted to a GPU. Per case: OUT/CASE/commands.bin (the committed kernel commands, for the kext validator replay)
// and, in OUT/report.json, every compute pipeline (entry, bindings, admission) and each command buffer's work report.
//   ci-compute BUNDLE OUT
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CoreImage/CoreImage.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (AdrenoCI)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (BOOL)adrenoDrawAvailable;
@end
static NSMutableDictionary *Report;
static NSString *Out;
static NSData *Captured;
static void *ReservedStart;
static NSUInteger ReservedLength;
static void save(void) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:Report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!d || ![d writeToFile:[Out stringByAppendingPathComponent:@"report.json"] atomically:YES]) exit(73);
}
static id clean(id v) {
    if ([v isKindOfClass:[NSDictionary class]]) { NSMutableDictionary *m = [NSMutableDictionary dictionary];
        for (id k in v) m[[k description]] = clean(v[k]); return m; }
    if ([v isKindOfClass:[NSArray class]]) { NSMutableArray *a = [NSMutableArray array]; for (id x in v) [a addObject:clean(x)]; return a; }
    if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSNumber class]] || [v isKindOfClass:[NSNull class]]) return v;
    return [v description];
}
static CGImageRef Icon(size_t n) {     // an icon-like premultiplied sRGB BGRA image with alpha edges
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef c = CGBitmapContextCreate(NULL, n, n, 8, n * 4, cs, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGContextSetRGBFillColor(c, 0.2, 0.5, 0.9, 1); CGContextFillEllipseInRect(c, CGRectMake(n / 8, n / 8, n * 3 / 4, n * 3 / 4));
    CGContextSetRGBFillColor(c, 1, 0.8, 0.1, 0.6); CGContextFillRect(c, CGRectMake(n / 3, n / 3, n / 3, n / 3));
    CGImageRef img = CGBitmapContextCreateImage(c); CGContextRelease(c); CGColorSpaceRelease(cs); return img;
}
int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 3) return 64;
    Out = @(argv[2]);
    if (!Out.isAbsolutePath || [[NSFileManager defaultManager] fileExistsAtPath:Out]) return 64;
    [[NSFileManager defaultManager] createDirectoryAtPath:Out withIntermediateDirectories:YES attributes:nil error:NULL];
    Report = [@{@"status":@"RUNNING", @"pipelines":[NSMutableArray array], @"cases":[NSMutableArray array],
                @"boundary":@"host CoreImage and the Adreno compiler/encoder; no GPU submission or A16 access"} mutableCopy];
    save();
    @try {
        (void)MTLCopyAllDevices();
        NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])]; NSError *e = nil;
        if (![bundle loadAndReturnError:&e]) @throw [NSException exceptionWithName:@"Bundle" reason:e.description userInfo:nil];
        Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
        Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
        Method reserve = class_getInstanceMethod(native, @selector(_reserveKernelCommandBufferSpace:));
        Method commit = class_getInstanceMethod(native, @selector(commit));
        if (!dc || !reserve || !commit) @throw [NSException exceptionWithName:@"Classes" reason:@"device or native commit" userInfo:nil];
        // This Mac's accelerator does not publish the kext's IB ABI: force the host-only availability gate, as the MPS
        // and target harnesses do (the packages are checked by the kext validator replay instead).
        Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), @selector(adrenoDrawAvailable));
        if (!available) @throw [NSException exceptionWithName:@"Gate" reason:@"no availability gate" userInfo:nil];
        method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
        Report[@"forced_availability_gate"] = @YES;
        IMP reserveIMP = method_getImplementation(reserve);
        method_setImplementation(reserve, imp_implementationWithBlock(^void *(id cb, NSUInteger length) {
            void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(cb, @selector(_reserveKernelCommandBufferSpace:), length);
            ReservedStart = p; ReservedLength = length; return p;
        }));
        method_setImplementation(commit, imp_implementationWithBlock(^(id cb) {
            if (ReservedStart && ReservedLength) {
                NSMutableData *all = Captured ? [Captured mutableCopy] : [NSMutableData data];
                [all appendBytes:ReservedStart length:ReservedLength]; Captured = all;
            }
            ReservedStart = NULL; ReservedLength = 0;
        }));
        SEL ps = NSSelectorFromString(@"newComputePipelineWithDescriptor:variant:errorMessage:");
        Method pm = class_getInstanceMethod(dc, ps); IMP original = method_getImplementation(pm);
        method_setImplementation(pm, imp_implementationWithBlock(^id(id dev, MTLComputePipelineDescriptor *desc, id variant, NSString **err) {
            NSString *entry = [[variant valueForKey:@"input"] valueForKey:@"entry"];
            NSMutableDictionary *row = [@{@"entry":entry ?: @"?", @"case":Report[@"active"] ?: @""} mutableCopy];
            [Report[@"pipelines"] addObject:row];
            id p = ((id(*)(id, SEL, id, id, NSString **))original)(dev, ps, desc, variant, err);
            row[@"compiled"] = @(p != nil);
            if (p) {
                NSDictionary *prog = [[p valueForKey:@"kernelCode"] valueForKey:@"program"];
                row[@"bindings"] = clean(prog[@"sidecar"][@"reflection"][@"bindings"] ?: @[]);
                @try { (void)[p valueForKey:@"adrenoComputeProgram"]; row[@"admission"] = @"admitted"; }
                @catch (NSException *x) { row[@"admission"] = x.reason ?: x.name; }
            } else row[@"error"] = (err && *err) ? *err : @"unknown";
            save(); return p;
        }));
        io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
        id<MTLDevice> device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
        if (!device) @throw [NSException exceptionWithName:@"Device" reason:@"no Adreno device" userInfo:nil];
        MTLAddDevice(device);
        CGImageRef img = Icon(128);
        CIImage *src = [CIImage imageWithCGImage:img];
        CIImage *white = [[CIImage imageWithColor:[CIColor colorWithRed:1 green:1 blue:1]] imageByCroppingToRect:CGRectMake(0, 0, 64, 64)];
        NSDictionary *cases = @{
            @"downscale-quarter": [src imageByApplyingTransform:CGAffineTransformMakeScale(0.25, 0.25) highQualityDownsample:YES],
            @"downscale-0.4": [src imageByApplyingTransform:CGAffineTransformMakeScale(0.4, 0.4) highQualityDownsample:YES],
            @"lanczos": [src imageByApplyingFilter:@"CILanczosScaleTransform" withInputParameters:@{@"inputScale":@0.3}],
            @"blur": [[[src imageByClampingToExtent] imageByApplyingGaussianBlurWithSigma:2] imageByCroppingToRect:src.extent],
            @"composite": [[src imageByApplyingTransform:CGAffineTransformMakeScale(0.5, 0.5)] imageByCompositingOverImage:white],
            @"fill": [[CIImage imageWithColor:[CIColor colorWithRed:0.2 green:0.5 blue:0.9]] imageByCroppingToRect:CGRectMake(0, 0, 70, 5)],
        };
        for (NSString *name in [cases.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            Report[@"active"] = name; Captured = nil;
            // A context and queue per case: a strict build's refusal raises inside CoreImage, which leaves its context busy.
            CIContext *ctx = [CIContext contextWithMTLDevice:device options:@{kCIContextCacheIntermediates:@NO}];
            id<MTLCommandQueue> queue = [device newCommandQueue];
            CIImage *im = cases[name]; CGRect r = CGRectIntegral(im.extent);
            if (CGRectIsInfinite(r) || r.size.width > 256 || r.size.height > 256) r = CGRectMake(0, 0, 64, 64);
            MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                        width:(NSUInteger)r.size.width height:(NSUInteger)r.size.height mipmapped:NO];
            td.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget;
            id<MTLTexture> dst = [device newTextureWithDescriptor:td];
            id<MTLCommandBuffer> cb = [queue commandBuffer];
            NSMutableDictionary *row = [@{@"name":name, @"width":@(r.size.width), @"height":@(r.size.height)} mutableCopy];
            @try {
                CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
                [ctx render:im toMTLTexture:dst commandBuffer:cb bounds:r colorSpace:srgb];
                CGColorSpaceRelease(srgb);
                [cb commit];
                row[@"status"] = @"committed";
                row[@"work"] = clean([(id)cb adrenoWorkReport] ?: @{});
            } @catch (NSException *x) { row[@"status"] = @"exception"; row[@"exception"] = x.reason ?: x.name; }
            NSString *dir = [Out stringByAppendingPathComponent:name];
            [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
            if (Captured) { [Captured writeToFile:[dir stringByAppendingPathComponent:@"commands.bin"] atomically:NO];
                row[@"commands_bytes"] = @(Captured.length); }
            [Report[@"cases"] addObject:row]; save();
        }
        CGImageRelease(img);
        Report[@"status"] = @"CAPTURED_NOT_SUBMITTED"; save(); return 0;
    } @catch (NSException *x) { Report[@"status"] = @"FAILED"; Report[@"exception"] = x.reason ?: x.name; save(); return 1; }
} }
