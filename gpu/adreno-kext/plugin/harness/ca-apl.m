/* SPDX-License-Identifier: MIT */
// CoreAnimation's average-pixel-luminance filter and Metal texture reads on the plug-in device, through Metal's own
// compiler service (docs/WINDOWSERVER-APL-ABORT-20261020.md). WindowServer died in installed-fresh-20261020-v13/v14 in
// the compiler: the service hands the plug-in AIR 2.2, whose texture read has four operands, and the translator read a
// fifth (an LLVM assertion, abort).
//   DYLD_INSERT_LIBRARIES=default-device-interpose.dylib ca-apl --apl BUNDLE [FRAMES]
//       a layer with CoreAnimation's limitAveragePixelLuminance filter, rendered by CARenderer on the plug-in device
//       (commits intercepted and completed at once, as ca-generic.m --adreno). Prints one line per frame with the
//       dim_factor CoreAnimation binds as fragment buffer(9) of apply_apl_dimming, and a totals line with the commits,
//       encoded and omitted operations and the omitted operations' pipelines.
//   ca-apl --kernel BUNDLE SOURCE.metal NAME
//       one compute pipeline for kernel NAME of SOURCE, created on the plug-in device: prints "KERNEL NAME ok" or
//       "KERNEL NAME error: ..." (an NSError, as Metal reports a refused compile).
//   clang -arch arm64e -fobjc-arc -O1 ca-apl.m -o ca-apl -framework Foundation -framework Metal -framework QuartzCore \
//     -framework IOSurface -framework IOKit -framework CoreGraphics
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import <dlfcn.h>

extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (CAAPLHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (void)didScheduleWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (void)didCompleteWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (NSDictionary *)adrenoWorkReport;
+ (instancetype)filterWithType:(NSString *)type;
@end

static long Commits, Encoded, Omitted;
static NSMutableSet *OmittedPipelines;
static id DimBuffer; static NSUInteger DimOffset;

static id createAdrenoDevice(NSString *bundlePath, BOOL intercept) {
    (void)MTLCopyAllDevices();
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath]; NSError *e = nil;
    if (![bundle loadAndReturnError:&e]) { fprintf(stderr, "bundle: %s\n", e.description.UTF8String); exit(65); }
    Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
    if (!dc) exit(66);
    if (intercept) {
        Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), NSSelectorFromString(@"adrenoDrawAvailable"));
        Method copyAvailable = class_getInstanceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"));
        Method commit = class_getInstanceMethod(NSClassFromString(@"IOGPUMetalCommandBuffer"), @selector(commit));
        if (!available || !copyAvailable || !commit) { fprintf(stderr, "missing plug-in or native hooks\n"); exit(66); }
        // This Mac's accelerator publishes neither the kext's IB ABI nor its CopyABI (as in the other harnesses).
        method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
        method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }));
        method_setImplementation(commit, imp_implementationWithBlock(^(id cb) {
            NSDictionary *r = [cb respondsToSelector:@selector(adrenoWorkReport)] ? [cb adrenoWorkReport] : @{};
            @synchronized (OmittedPipelines) {
                Commits++; Encoded += [r[@"encoded"] longValue]; Omitted += [r[@"omitted"] longValue];
                for (NSDictionary *o in r[@"omissions"]) {
                    NSDictionary *d = o[@"details"];
                    [OmittedPipelines addObject:[NSString stringWithFormat:@"%@: %@", d[@"pipeline"][@"entry"] ?: o[@"operation"], d[@"reason"] ?: @"?"]];
                }
            }
            // No GPU runs this: report the buffer scheduled and complete so Core Animation's waits proceed.
            [cb didScheduleWithStartTime:0 endTime:0 error:nil]; [cb didCompleteWithStartTime:0 endTime:0 error:nil]; }));
        // apply_apl_dimming reads its factor from fragment buffer(9) ("dim_factor", a float4).
        SEL sel = @selector(setFragmentBuffer:offset:atIndex:);
        Method m = class_getInstanceMethod(NSClassFromString(@"AdrenoRenderCommandEncoder"), sel);
        if (!m) { fprintf(stderr, "missing render encoder hook\n"); exit(66); }
        void (*o)(id, SEL, id, NSUInteger, NSUInteger) = (void *)method_getImplementation(m);
        method_setImplementation(m, imp_implementationWithBlock(^(id enc, id b, NSUInteger off, NSUInteger i) {
            if (i == 9 && b) { DimBuffer = b; DimOffset = off; }
            o(enc, sel, b, off, i); }));
    }
    io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    id device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
    if (!device) exit(67);
    MTLAddDevice(device);
    return device;
}

static CGColorRef color(double r, double g, double b, double a) { return CGColorCreateSRGB(r, g, b, a); }

static int apl(NSString *bundle, int frames) {
    OmittedPipelines = [NSMutableSet set];
    id adreno = createAdrenoDevice(bundle, YES);
    void (*setDefault)(id) = dlsym(RTLD_DEFAULT, "AdrenoSetDefaultDevice");
    if (!setDefault) { fprintf(stderr, "default-device-interpose.dylib is not inserted\n"); return 68; }
    setDefault(adreno);
    id<MTLDevice> device = adreno;
    id<MTLCommandQueue> queue = [device newCommandQueue];
    const NSUInteger W = 256, H = 256;
    IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@(W), (id)kIOSurfaceHeight:@(H),
        (id)kIOSurfaceBytesPerRow:@(W * 4), (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfacePixelFormat:@(0x42475241)});
    MTLTextureDescriptor *desc = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:W height:H mipmapped:NO];
    desc.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    id<MTLTexture> target = [device newTextureWithDescriptor:desc iosurface:surface plane:0];
    CARenderer *r = [CARenderer rendererWithMTLTexture:target options:@{kCARendererMetalCommandQueue:queue}];
    CALayer *root = [CALayer layer]; root.frame = CGRectMake(0, 0, W, H); root.backgroundColor = color(0.8, 0.8, 0.8, 1); root.opaque = YES;
    // A bright image layer with a sublayer (CoreAnimation applies the filter to the layer's rendered group).
    CGColorSpaceRef cs = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef c = CGBitmapContextCreate(NULL, 128, 128, 8, 0, cs, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    for (int i = 0; i < 8; i++) { CGContextSetRGBFillColor(c, 1, 1 - i / 14.0, 0.9, 1); CGContextFillRect(c, CGRectMake(i * 16, 0, 16, 128)); }
    CGImageRef image = CGBitmapContextCreateImage(c); CGContextRelease(c); CGColorSpaceRelease(cs);
    CALayer *bright = [CALayer layer]; bright.frame = CGRectMake(32, 32, 192, 192); bright.contents = (__bridge id)image;
    CGImageRelease(image);
    CALayer *inner = [CALayer layer]; inner.frame = CGRectMake(24, 24, 96, 64); inner.backgroundColor = color(0.9, 0.3, 0.1, 1);
    inner.cornerRadius = 8; [bright addSublayer:inner];
    // inputAmount and inputScale engage the limiter (with the defaults CoreAnimation skips the filter).
    id limit = [NSClassFromString(@"CAFilter") filterWithType:@"limitAveragePixelLuminance"];
    [limit setValue:@0.7 forKey:@"inputAmount"]; [limit setValue:@1.5 forKey:@"inputScale"];
    bright.filters = @[limit];
    [root addSublayer:bright];
    r.layer = root; r.bounds = root.bounds;
    [CATransaction flush];
    for (int f = 0; f < frames; f++) {
        [r beginFrameAtTime:CACurrentMediaTime() + f * 0.1 timeStamp:NULL];
        [r addUpdateRect:root.bounds];
        [r render];
        [r endFrame];
        id<MTLCommandBuffer> cb = [queue commandBuffer]; [cb commit]; [cb waitUntilCompleted];
        const float *v = DimBuffer ? (const float *)((const char *)[(id<MTLBuffer>)DimBuffer contents] + DimOffset) : NULL;
        if (v) printf("FRAME %d dim_factor %g %g %g %g\n", f, v[0], v[1], v[2], v[3]);
        else printf("FRAME %d dim_factor none\n", f);
        usleep(100000);
    }
    printf("APL commits=%ld encoded=%ld omitted=%ld\n", Commits, Encoded, Omitted);
    for (NSString *p in [[OmittedPipelines allObjects] sortedArrayUsingSelector:@selector(compare:)]) printf("OMITTED %s\n", p.UTF8String);
    CFRelease(surface);
    return 0;
}

static int kernel(NSString *bundle, NSString *path, NSString *name) {
    id<MTLDevice> device = createAdrenoDevice(bundle, NO);
    NSError *e = nil;
    NSString *src = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&e];
    id<MTLLibrary> lib = src ? [device newLibraryWithSource:src options:[MTLCompileOptions new] error:&e] : nil;
    id<MTLFunction> fn = [lib newFunctionWithName:name];
    if (!fn) { printf("KERNEL %s error: no function (%s)\n", name.UTF8String, e.localizedDescription.UTF8String ?: ""); return 0; }
    e = nil;
    id p = [device newComputePipelineStateWithFunction:fn error:&e];
    if (p) printf("KERNEL %s ok\n", name.UTF8String);
    else printf("KERNEL %s error: %s\n", name.UTF8String, [e.localizedDescription stringByReplacingOccurrencesOfString:@"\n" withString:@" "].UTF8String);
    return 0;
}

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc >= 3 && !strcmp(argv[1], "--apl")) return apl(@(argv[2]), argc > 3 ? atoi(argv[3]) : 4);
    if (argc == 5 && !strcmp(argv[1], "--kernel")) return kernel(@(argv[2]), @(argv[3]), @(argv[4]));
    fprintf(stderr, "usage: ca-apl --apl BUNDLE [FRAMES] | ca-apl --kernel BUNDLE SOURCE NAME\n");
    return 64;
} }
