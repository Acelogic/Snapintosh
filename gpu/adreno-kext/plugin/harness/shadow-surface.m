/* SPDX-License-Identifier: MIT */
// Aligned shadows for IOSurfaces with unaligned rows (docs/USERSPACE-GRAPHICS-20261019.md): the data path, on the Adreno
// device with native commits intercepted. Nothing is submitted to a GPU; the GPU's writes are simulated by writing the
// shadow buffer, then running the command buffer's write-back (what its completion handlers and waitUntilCompleted run).
// OUT/report.json holds each check; OUT/CASE/commands.bin the committed kernel commands for the kext validator replay.
//   shadow-surface BUNDLE OUT
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <CoreImage/CoreImage.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (AdrenoShadowHarness)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (NSDictionary *)adrenoWorkReport;
- (BOOL)adrenoDrawAvailable;
- (id)adrenoShadowObject;
- (void)adrenoRunShadowWriteBack;
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
static void check(BOOL ok, NSString *what) {
    [Report[@"checks"] addObject:@{@"ok":@(ok), @"what":what}];
    if (!ok) fprintf(stderr, "FAIL %s\n", what.UTF8String);
    save();
}
static IOSurfaceRef Surface(size_t w, size_t h, size_t row) {
    NSDictionary *p = @{(id)kIOSurfaceWidth:@(w), (id)kIOSurfaceHeight:@(h), (id)kIOSurfaceBytesPerElement:@4,
                        (id)kIOSurfaceBytesPerRow:@(row), (id)kIOSurfacePixelFormat:@((uint32_t)'BGRA')};
    return IOSurfaceCreate((__bridge CFDictionaryRef)p);
}
// Pixel (x,y) of pattern k: distinct per row, column and pattern; alpha 255 so premultiplication keeps it.
static uint32_t Pixel(size_t x, size_t y, uint32_t k) { return 0xff000000u | ((uint32_t)(x * 3 + k) & 0xff) << 16 | ((uint32_t)(y * 7 + k) & 0xff) << 8 | (k & 0xff); }
static void WriteSurface(IOSurfaceRef s, uint32_t k) {
    IOSurfaceLock(s, 0, NULL);
    char *b = IOSurfaceGetBaseAddress(s); size_t row = IOSurfaceGetBytesPerRow(s);
    for (size_t y = 0; y < IOSurfaceGetHeight(s); y++) for (size_t x = 0; x < IOSurfaceGetWidth(s); x++)
        ((uint32_t *)(b + y * row))[x] = Pixel(x, y, k);
    IOSurfaceUnlock(s, 0, NULL);
}
static void WriteRows(char *b, size_t row, size_t w, size_t h, uint32_t k) {
    for (size_t y = 0; y < h; y++) for (size_t x = 0; x < w; x++) ((uint32_t *)(b + y * row))[x] = Pixel(x, y, k);
}
static BOOL RowsAre(const char *b, size_t row, size_t w, size_t h, uint32_t k) {
    for (size_t y = 0; y < h; y++) for (size_t x = 0; x < w; x++) if (((const uint32_t *)(b + y * row))[x] != Pixel(x, y, k)) return NO;
    return YES;
}
static BOOL SurfaceIs(IOSurfaceRef s, uint32_t k) {
    IOSurfaceLock(s, kIOSurfaceLockReadOnly, NULL);
    BOOL ok = RowsAre(IOSurfaceGetBaseAddress(s), IOSurfaceGetBytesPerRow(s), IOSurfaceGetWidth(s), IOSurfaceGetHeight(s), k);
    IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL);
    return ok;
}
static id<MTLTexture> SurfaceTexture(id<MTLDevice> device, IOSurfaceRef s) {
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                width:IOSurfaceGetWidth(s) height:IOSurfaceGetHeight(s) mipmapped:NO];
    td.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget;
    td.storageMode = MTLStorageModeShared;
    return [device newTextureWithDescriptor:td iosurface:s plane:0];
}
// Commits one CoreImage render of im into dst; records the work report and the committed kernel commands as case NAME.
static id<MTLCommandBuffer> Render(id<MTLDevice> device, NSString *name, CIImage *im, id<MTLTexture> dst) {
    Captured = nil;
    CIContext *ctx = [CIContext contextWithMTLDevice:device options:@{kCIContextCacheIntermediates:@NO}];
    id<MTLCommandBuffer> cb = [[device newCommandQueue] commandBuffer];
    NSMutableDictionary *row = [@{@"name":name} mutableCopy];
    @try {
        CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        [ctx render:im toMTLTexture:dst commandBuffer:cb bounds:CGRectMake(0, 0, dst.width, dst.height) colorSpace:srgb];
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
    return cb;
}
// Commits one blit copy of the texture's rows into a shared buffer (a GPU read of the texture) as case NAME.
static void ReadBack(id<MTLDevice> device, NSString *name, id<MTLTexture> t) {
    Captured = nil;
    id<MTLBuffer> rows = [device newBufferWithLength:t.width * 4 * t.height options:MTLResourceStorageModeShared];
    id<MTLCommandBuffer> cb = [[device newCommandQueue] commandBuffer];
    NSMutableDictionary *row = [@{@"name":name} mutableCopy];
    @try {
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        [blit copyFromTexture:t sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(t.width, t.height, 1)
                     toBuffer:rows destinationOffset:0 destinationBytesPerRow:t.width * 4 destinationBytesPerImage:t.width * 4 * t.height];
        [blit endEncoding];
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
int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 3) return 64;
    Out = @(argv[2]);
    if (!Out.isAbsolutePath || [[NSFileManager defaultManager] fileExistsAtPath:Out]) return 64;
    [[NSFileManager defaultManager] createDirectoryAtPath:Out withIntermediateDirectories:YES attributes:nil error:NULL];
    Report = [@{@"status":@"RUNNING", @"checks":[NSMutableArray array], @"cases":[NSMutableArray array],
                @"boundary":@"host IOSurfaces and the Adreno encoder; GPU writes simulated in the shadow; no GPU submission"} mutableCopy];
    save();
    @try {
        (void)MTLCopyAllDevices();
        NSBundle *bundle = [NSBundle bundleWithPath:@(argv[1])]; NSError *e = nil;
        if (![bundle loadAndReturnError:&e]) @throw [NSException exceptionWithName:@"Bundle" reason:e.description userInfo:nil];
        Class dc = [bundle classNamed:@"AdrenoMTLDevice"];
        Class native = NSClassFromString(@"IOGPUMetalCommandBuffer");
        Method reserve = class_getInstanceMethod(native, @selector(_reserveKernelCommandBufferSpace:));
        Method commit = class_getInstanceMethod(native, @selector(commit));
        Method available = class_getInstanceMethod(NSClassFromString(@"AdrenoCommandBuffer"), @selector(adrenoDrawAvailable));
        if (!dc || !reserve || !commit || !available) @throw [NSException exceptionWithName:@"Classes" reason:@"device, native commit or gate" userInfo:nil];
        method_setImplementation(available, imp_implementationWithBlock(^BOOL(id cb) { (void)cb; return YES; }));
        // Blits have their own gate on the kext's CopyABI, which this Mac's accelerator does not publish either.
        Method copyAvailable = class_getInstanceMethod(dc, NSSelectorFromString(@"adrenoBufferCopyAvailable"));
        if (!copyAvailable) @throw [NSException exceptionWithName:@"Gate" reason:@"no CopyABI gate" userInfo:nil];
        method_setImplementation(copyAvailable, imp_implementationWithBlock(^BOOL(id d) { (void)d; return YES; }));
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
        io_service_t acc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
        id<MTLDevice> device = [[dc alloc] initWithAcceleratorPort:acc]; IOObjectRelease(acc);
        if (!device) @throw [NSException exceptionWithName:@"Device" reason:@"no Adreno device" userInfo:nil];
        MTLAddDevice(device);
        const size_t W = 70, H = 5;
        BOOL shadows = [NSClassFromString(@"AdrenoTexture") instancesRespondToSelector:@selector(adrenoShadowObject)];
        check(shadows, @"the plug-in's textures have aligned shadows");

        // 1. An unaligned surface (row 288 bytes, Adreno needs 64-byte multiples) gets a filled shadow at a 320-byte pitch.
        IOSurfaceRef s = Surface(W, H, 288);
        size_t row = s ? IOSurfaceGetBytesPerRow(s) : 0;
        Report[@"surface_row"] = @(row);
        check(s && (row & 63), [NSString stringWithFormat:@"test surface rows are unaligned (%zu bytes)", row]);
        WriteSurface(s, 1);
        id<MTLTexture> t = SurfaceTexture(device, s);
        check(t != nil, @"texture over the unaligned surface");
        id shadow = shadows ? [(id)t adrenoShadowObject] : nil;
        check(shadow != nil, @"the unaligned surface's texture has a shadow");
        id<MTLBuffer> buffer = [shadow valueForKey:@"buffer"];
        size_t pitch = [[shadow valueForKey:@"rowBytes"] unsignedIntegerValue];
        Report[@"shadow_row"] = @(pitch);
        check(pitch == 320 && buffer.length >= pitch * H, [NSString stringWithFormat:@"shadow pitch %zu (expected 320), %lu bytes",
                                                           pitch, (unsigned long)buffer.length]);
        check(buffer && RowsAre(buffer.contents, pitch, W, H, 1), @"shadow filled from the surface's rows");
        BOOL padding = buffer != nil;
        for (size_t y = 0; buffer && y < H; y++) for (size_t b = W * 4; b < pitch; b++) if (((char *)buffer.contents)[y * pitch + b]) padding = NO;
        check(padding, @"shadow row padding is zero");

        // 2. Every texture over the surface shares its one shadow.
        id<MTLTexture> t2 = SurfaceTexture(device, s);
        check(shadows && [(id)t2 adrenoShadowObject] == shadow, @"a second texture over the surface shares its shadow");

        // 3. Aligned surfaces keep the zero-copy path.
        IOSurfaceRef aligned = Surface(64, 4, 256);
        id<MTLTexture> ta = SurfaceTexture(device, aligned);
        check(ta && shadows && ![(id)ta adrenoShadowObject], @"an aligned surface (256-byte rows) has no shadow");

        // 4. GPU writes into the shadow reach the surface when the command buffer completes, once.
        CIImage *src = [[CIImage imageWithColor:[CIColor colorWithRed:0.2 green:0.5 blue:0.9]] imageByCroppingToRect:CGRectMake(0, 0, W, H)];
        id<MTLCommandBuffer> cb = Render(device, @"write-unaligned", src, t);
        NSDictionary *last = [Report[@"cases"] lastObject], *work = last[@"work"];
        check([last[@"status"] isEqual:@"committed"] && [work[@"encoded"] integerValue] > 0 && [work[@"omitted"] integerValue] == 0,
              [NSString stringWithFormat:@"render into the unaligned surface: %@ encoded %@ omitted %@ %@", last[@"status"],
               work[@"encoded"], work[@"omitted"], work[@"omissions"] ?: last[@"exception"] ?: @""]);
        id once = nil;
        @try { once = [(id)cb valueForKey:@"adrenoShadowWriteBack"]; } @catch (NSException *x) { (void)x; }
        check(once != nil, @"the command buffer that wrote the shadow will write it back");
        if (buffer) WriteRows(buffer.contents, pitch, W, H, 2);       // the GPU's output
        if ([(id)cb respondsToSelector:@selector(adrenoRunShadowWriteBack)]) [(id)cb adrenoRunShadowWriteBack];
        check(SurfaceIs(s, 2), @"write-back copied the shadow's rows into the surface");
        check(shadow && [[shadow valueForKey:@"seed"] unsignedIntValue] == IOSurfaceGetSeed(s),
              @"write-back recorded the surface seed (its own write is not a CPU change)");
        if (buffer) WriteRows(buffer.contents, pitch, W, H, 3);
        if ([(id)cb respondsToSelector:@selector(adrenoRunShadowWriteBack)]) [(id)cb adrenoRunShadowWriteBack];
        check(SurfaceIs(s, 2), @"a second completion does not write back again");

        // 5. A CPU write to the surface (seed change) refills the shadow before the next GPU use.
        WriteSurface(s, 4);
        ReadBack(device, @"read-after-cpu-write", t);
        last = [Report[@"cases"] lastObject]; work = last[@"work"];
        check([work[@"encoded"] integerValue] > 0 && [work[@"omitted"] integerValue] == 0,
              [NSString stringWithFormat:@"blit reading the surface: %@ encoded %@ omitted %@ %@", last[@"status"], work[@"encoded"],
               work[@"omitted"], work[@"omissions"] ?: last[@"exception"] ?: @""]);
        check(buffer && RowsAre(buffer.contents, pitch, W, H, 4), @"a CPU write to the surface refilled the shadow before the GPU read");

        // 6. replaceRegion marks the shadow stale even when it leaves the seed alone.
        NSMutableData *rows = [NSMutableData dataWithLength:W * 4 * H];
        WriteRows(rows.mutableBytes, W * 4, W, H, 5);
        [t replaceRegion:MTLRegionMake2D(0, 0, W, H) mipmapLevel:0 withBytes:rows.bytes bytesPerRow:W * 4];
        ReadBack(device, @"read-after-replace", t);
        check(buffer && RowsAre(buffer.contents, pitch, W, H, 5), @"replaceRegion refilled the shadow before the GPU read");
        CFRelease(s); CFRelease(aligned);
        Report[@"status"] = @"CAPTURED_NOT_SUBMITTED"; save(); return 0;
    } @catch (NSException *x) { Report[@"status"] = @"FAILED"; Report[@"exception"] = x.reason ?: x.name; save(); return 1; }
} }
