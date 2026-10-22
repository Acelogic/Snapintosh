/* SPDX-License-Identifier: MIT */
// iconservicesagent's icon rendering on the Adreno device (docs/USERSPACE-GRAPHICS-20261019.md, "Why the Dock gets
// placeholders"): IconServices' ISIconStackAssetCatalogResource -> IconRendering -> RenderBox, in this process, with
// default-device-interpose.dylib making the plug-in device the system default. Native commits are intercepted and
// marked complete; nothing is submitted to a GPU, so the image's pixels are not meaningful, only that one is produced.
// Per app: OUT/APP/report.json (resource, image, every commit's work report) and OUT/APP/NNN/commands.bin (each
// commit's kernel commands, for the kext validator replay).
//   DYLD_INSERT_LIBRARIES=default-device-interpose.dylib icon-render BUNDLE OUT APP...
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#import <dlfcn.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (AdrenoIconHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (BOOL)adrenoDrawAvailable;
+ (id)assetCatalogResourceWithURL:(NSURL *)url imageName:(NSString *)name platform:(unsigned long long)platform
                        isAppLike:(BOOL)appLike error:(NSError **)error;
- (id)imageForSize:(CGSize)size scale:(double)scale;
- (CGImageRef)CGImage;
- (void)didScheduleWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
- (void)didCompleteWithStartTime:(unsigned long long)start endTime:(unsigned long long)end error:(id)error;
@end
static NSMutableArray *Commits;
static NSString *CommitDir;
static void *ReservedStart;
static NSUInteger ReservedLength;
static id clean(id v) {
    if ([v isKindOfClass:[NSDictionary class]]) { NSMutableDictionary *m = [NSMutableDictionary dictionary];
        for (id k in v) m[[k description]] = clean(v[k]); return m; }
    if ([v isKindOfClass:[NSArray class]]) { NSMutableArray *a = [NSMutableArray array]; for (id x in v) [a addObject:clean(x)]; return a; }
    if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSNumber class]] || [v isKindOfClass:[NSNull class]]) return v;
    return [v description];
}
static void save(NSDictionary *report, NSString *dir) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    if (!d || ![d writeToFile:[dir stringByAppendingPathComponent:@"report.json"] atomically:YES]) exit(73);
}
int main(int argc, const char **argv) { @autoreleasepool {
    if (argc < 4) return 64;
    NSString *out = @(argv[2]);
    if (!out.isAbsolutePath || [[NSFileManager defaultManager] fileExistsAtPath:out]) return 64;
    (void)MTLCopyAllDevices();
    NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])]; NSError *e = nil;
    if (![bundle loadAndReturnError:&e]) { fprintf(stderr, "bundle: %s\n", e.description.UTF8String); return 65; }
    Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
    Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), @selector(adrenoDrawAvailable));
    Method copyAvailable = class_getInstanceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"));
    Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
    Method reserve = class_getInstanceMethod(native, @selector(_reserveKernelCommandBufferSpace:));
    Method commit = class_getInstanceMethod(native, @selector(commit));
    void (*setDefault)(id) = dlsym(RTLD_DEFAULT, "AdrenoSetDefaultDevice");
    if (!dc || !available || !copyAvailable || !reserve || !commit || !setDefault) {
        fprintf(stderr, "missing device class, gates, native commit or the interpose library\n"); return 66;
    }
    // This Mac's accelerator publishes neither the kext's IB ABI nor its CopyABI (as in the other harnesses).
    method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
    method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }));
    IMP reserveIMP = method_getImplementation(reserve);
    method_setImplementation(reserve, imp_implementationWithBlock(^void *(id cb, NSUInteger length) {
        void *p = ((void *(*)(id, SEL, NSUInteger))reserveIMP)(cb, @selector(_reserveKernelCommandBufferSpace:), length);
        ReservedStart = p; ReservedLength = length; return p;
    }));
    method_setImplementation(commit, imp_implementationWithBlock(^(id cb) {
        NSString *dir = [CommitDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%03lu", (unsigned long)Commits.count]];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
        if (ReservedStart && ReservedLength)
            [[NSData dataWithBytes:ReservedStart length:ReservedLength] writeToFile:[dir stringByAppendingPathComponent:@"commands.bin"] atomically:NO];
        [Commits addObject:clean([cb respondsToSelector:@selector(adrenoWorkReport)] ? [cb adrenoWorkReport] ?: @{} : @{})];
        ReservedStart = NULL; ReservedLength = 0;
        // No GPU runs this: report the buffer scheduled and complete so RenderBox's waits and handlers proceed.
        [cb didScheduleWithStartTime:0 endTime:0 error:nil];
        [cb didCompleteWithStartTime:0 endTime:0 error:nil];
    }));
    io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    id device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
    if (!device) return 67;
    MTLAddDevice(device);
    setDefault(device);
    if (MTLCreateSystemDefaultDevice() != device) { fprintf(stderr, "the default device is not the Adreno device\n"); return 68; }
    if (!dlopen("/System/Library/PrivateFrameworks/IconServices.framework/IconServices", RTLD_NOW)) return 69;
    int status = 0;
    for (int i = 3; i < argc; i++) {
        NSString *app = @(argv[i]);
        NSString *dir = [out stringByAppendingPathComponent:app.lastPathComponent.stringByDeletingPathExtension];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
        Commits = [NSMutableArray array]; CommitDir = dir;
        NSMutableDictionary *report = [@{@"app":app, @"boundary":@"host IconServices/IconRendering/RenderBox on the Adreno "
                                         "encoder; commits intercepted; no GPU submission"} mutableCopy];
        NSString *iconName = [NSBundle bundleWithPath:app].infoDictionary[@"CFBundleIconName"] ?: @"AppIcon";
        NSURL *car = [NSURL fileURLWithPath:[app stringByAppendingPathComponent:@"Contents/Resources/Assets.car"]];
        NSError *error = nil;
        id resource = [NSClassFromString(@"ISAssetCatalogResource") assetCatalogResourceWithURL:car imageName:iconName
                                                                                      platform:1 isAppLike:YES error:&error];
        report[@"icon_name"] = iconName;
        report[@"resource"] = resource ? @(class_getName([resource class])) : (error.description ?: @"nil");
        id image = [resource imageForSize:CGSizeMake(128, 128) scale:2];
        CGImageRef cg = [image respondsToSelector:@selector(CGImage)] ? [image CGImage] : NULL;
        report[@"image"] = cg ? @{@"width":@(CGImageGetWidth(cg)), @"height":@(CGImageGetHeight(cg))} : [NSNull null];
        report[@"commits"] = Commits;
        save(report, dir);
        if (!cg) status = 1;
    }
    return status;
} }
