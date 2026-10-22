/* SPDX-License-Identifier: MIT */
// resource-roundtrip.m - host (26A428) end-to-end checks of AdrenoMetal.bundle's CPU-visible resource
// contract, driven through the public Metal API on a device registered with MTLAddDevice on this Mac's
// IOAccelerator (the same substitution as regtest.m and native-texture.m). No GPU submission.
//
//   resource-roundtrip <AdrenoMetal.bundle> <report.json>     run every case, each in its own child process
//   resource-roundtrip <AdrenoMetal.bundle> --case <name>     (child) run one case, print one JSON line
//
// Every case runs in a child so an abort (MTLReportFailure, a bad memcpy) is recorded as that case's
// failure instead of ending the run. Exit status 0 only when every case passes.
//
// Cases:
//   fp16-profile        supportsNativeHardwareFP16 is NO (the validated min profile).
//   sysmem-2d           newTextureWithDescriptor: shared BGRA8: replaceRegion/getBytes round trip, bytes land at
//                       the IOGPU sysmem address with the constructor's linear row pitch (the GPU clear layout).
//   mip-chain           every level of a mipmapped RGBA8 texture holds its own data (no overlap, none dropped).
//   array-slices        2D array: every (level, slice) distinct.
//   cube-faces          cube: every (level, face) distinct.
//   volume-3d           3D texture with multi-image uploads (bytesPerImage) per level.
//   format-sizes        RGBA16Float / R8 / RG32Uint / RGBA32Float mip chains (bytes-per-pixel table).
//   subregion           a partial upload changes only its rectangle.
//   texture-view        writes through a level/slice view land in the parent's subresource, and a
//                       pixel-format view shares the parent's bytes.
//   bounds              an upload outside the level is refused: IOSurface rows below the texture and the
//                       row padding stay untouched, and a missing level is ignored.
//   iosurface-2d        IOSurface texture round trip through the surface's own memory.
//   nocopy-2d           newTextureWithBytesNoCopy: round trip through the caller's memory.
//   buffer-texture      newTiledTextureWithDescriptor: (SkyLight) round trip through the buffer's contents.
//   blit-synchronize    synchronizeResource: and synchronizeTexture:slice:level: are accepted as no-ops.
//   shared-event        newSharedEvent is non-nil, signals, and exports a handle.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurface.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <spawn.h>
#import <sys/wait.h>
#import "../AdrenoMetal/AdrenoLinearTexture.h"
extern char **environ;
extern void MTLAddDevice(id<MTLDevice>);
@interface NSObject (ResourceRoundTrip)
- (id)initWithAcceleratorPort:(unsigned int)port;
- (void *)virtualAddress;
- (uint64_t)resourceSize;
- (id<MTLTexture>)newTiledTextureWithDescriptor:(MTLTextureDescriptor *)d offset:(NSUInteger)o bytesPerRow:(NSUInteger)bpr;
- (id<MTLTexture>)newTextureWithBytesNoCopy:(void *)b length:(NSUInteger)len descriptor:(MTLTextureDescriptor *)d
                                deallocator:(id)dealloc;
@end

static NSString *gFailure;
#define REQUIRE(c, ...) do { if (!(c)) { gFailure = [NSString stringWithFormat:__VA_ARGS__]; return NO; } } while (0)

static id<MTLDevice> RegisterDevice(NSString *bundlePath) {
    (void)MTLCopyAllDevices();
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    NSError *error = nil;
    if (![bundle loadAndReturnError:&error]) return nil;
    io_service_t accelerator = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAccelerator"));
    if (!accelerator) return nil;
    id<MTLDevice> device = [[[bundle classNamed:@"AdrenoMTLDevice"] alloc] initWithAcceleratorPort:accelerator];
    IOObjectRelease(accelerator);
    if (device) MTLAddDevice(device);
    return device;
}

// Deterministic, subresource-unique bytes: a stale or shared subresource cannot match.
static uint8_t Pattern(NSUInteger seed, NSUInteger level, NSUInteger slice, NSUInteger z, NSUInteger y, NSUInteger x) {
    uint32_t h = (uint32_t)(seed * 0x9e3779b1u) ^ (uint32_t)(level * 0x85ebca6bu) ^ (uint32_t)(slice * 0xc2b2ae35u) ^
                 (uint32_t)(z * 0x27d4eb2fu) ^ (uint32_t)(y * 0x165667b1u) ^ (uint32_t)(x * 0xd3a2646cu);
    h ^= h >> 15; h *= 0x2c1b3c6du; h ^= h >> 12;
    return (uint8_t)h;
}
static NSUInteger LevelDim(NSUInteger v, NSUInteger level) { return MAX((NSUInteger)1, v >> level); }
static NSUInteger SliceCount(id<MTLTexture> t) {
    NSUInteger n = t.arrayLength;
    if (t.textureType == MTLTextureTypeCube || t.textureType == MTLTextureTypeCubeArray) n *= 6;
    return n;
}

// Upload every (level, slice) with its own pattern, then read every one back.
static BOOL UploadAndVerifyAll(id<MTLTexture> t, NSUInteger bpp, NSUInteger seed) {
    NSUInteger levels = t.mipmapLevelCount, slices = SliceCount(t);
    BOOL volume = t.textureType == MTLTextureType3D;
    for (int pass = 0; pass < 2; pass++)
        for (NSUInteger l = 0; l < levels; l++)
            for (NSUInteger s = 0; s < slices; s++) {
                NSUInteger w = LevelDim(t.width, l), h = LevelDim(t.height, l), d = volume ? LevelDim(t.depth, l) : 1;
                NSUInteger bpr = w * bpp + 8, bpi = bpr * h + 16;   // padded caller strides
                NSMutableData *want = [NSMutableData dataWithLength:bpi * d];
                uint8_t *p = want.mutableBytes;
                for (NSUInteger z = 0; z < d; z++) for (NSUInteger y = 0; y < h; y++) for (NSUInteger x = 0; x < w * bpp; x++)
                    p[z * bpi + y * bpr + x] = Pattern(seed, l, s, z, y, x);
                MTLRegion r = MTLRegionMake3D(0, 0, 0, w, h, d);
                if (!pass) { [t replaceRegion:r mipmapLevel:l slice:s withBytes:p bytesPerRow:bpr bytesPerImage:bpi]; continue; }
                NSMutableData *got = [NSMutableData dataWithLength:bpi * d];
                memset(got.mutableBytes, 0xee, got.length);
                [t getBytes:got.mutableBytes bytesPerRow:bpr bytesPerImage:bpi fromRegion:r mipmapLevel:l slice:s];
                const uint8_t *g = got.bytes;
                for (NSUInteger z = 0; z < d; z++) for (NSUInteger y = 0; y < h; y++)
                    REQUIRE(!memcmp(g + z * bpi + y * bpr, p + z * bpi + y * bpr, w * bpp),
                            @"level %lu slice %lu z %lu row %lu differs after round trip (%lux%lux%lu, %lu levels, %lu slices)",
                            l, s, z, y, w, h, d, levels, slices);
            }
    return YES;
}

static MTLTextureDescriptor *Descriptor(MTLTextureType type, MTLPixelFormat f, NSUInteger w, NSUInteger h, NSUInteger d,
                                        NSUInteger levels, NSUInteger array) {
    MTLTextureDescriptor *td = [MTLTextureDescriptor new];
    td.textureType = type; td.pixelFormat = f; td.width = w; td.height = h; td.depth = d;
    td.mipmapLevelCount = levels; td.arrayLength = array;
    td.storageMode = MTLStorageModeShared; td.usage = MTLTextureUsageShaderRead;
    return td;
}

static BOOL CaseFP16(id<MTLDevice> dev) {
    SEL s = sel_registerName("supportsNativeHardwareFP16");
    REQUIRE([(id)dev respondsToSelector:s], @"device does not answer supportsNativeHardwareFP16");
    BOOL v = ((BOOL (*)(id, SEL))objc_msgSend)(dev, s);
    REQUIRE(!v, @"supportsNativeHardwareFP16 is YES; the validated minimum profile is NO");
    return YES;
}

static BOOL CaseSysmem2D(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 37, 23, 1, 1, 1)];
    REQUIRE(t, @"nil texture");
    AdrenoLinearTextureLayout lin = {0};
    REQUIRE([(id<AdrenoLinearTexture>)t adrenoGetLinearLayout:&lin] && lin.rowBytes == 192 && lin.allocationBytes == 16384,
            @"linear layout changed: rowBytes %llu allocation %llu", lin.rowBytes, lin.allocationBytes);
    if (!UploadAndVerifyAll(t, 4, 1)) return NO;
    const uint8_t *va = [(id)t virtualAddress];
    REQUIRE(va, @"no IOGPU sysmem CPU address");
    for (NSUInteger y = 0; y < 23; y++) for (NSUInteger x = 0; x < 37 * 4; x++)
        REQUIRE(va[y * lin.rowBytes + x] == Pattern(1, 0, 0, 0, y, x),
                @"sysmem byte (%lu,%lu) is not where the GPU linear layout (row pitch %llu) puts it", y, x, lin.rowBytes);
    return YES;
}

static BOOL CaseMipChain(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatRGBA8Unorm, 67, 45, 1, 7, 1)];
    REQUIRE(t && t.mipmapLevelCount == 7, @"texture/levels");
    return UploadAndVerifyAll(t, 4, 2);
}
static BOOL CaseArray(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2DArray, MTLPixelFormatBGRA8Unorm, 40, 24, 1, 3, 5)];
    REQUIRE(t && t.arrayLength == 5, @"texture/array");
    return UploadAndVerifyAll(t, 4, 3);
}
static BOOL CaseCube(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureTypeCube, MTLPixelFormatRGBA8Unorm, 64, 64, 1, 4, 1)];
    REQUIRE(t && t.textureType == MTLTextureTypeCube, @"texture/cube");
    return UploadAndVerifyAll(t, 4, 4);
}
static BOOL CaseVolume(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType3D, MTLPixelFormatRGBA8Unorm, 20, 12, 9, 3, 1)];
    REQUIRE(t && t.depth == 9, @"texture/3d");
    return UploadAndVerifyAll(t, 4, 5);
}
static BOOL CaseFormats(id<MTLDevice> dev) {
    struct { MTLPixelFormat f; NSUInteger bpp; } f[] = {{MTLPixelFormatRGBA16Float, 8}, {MTLPixelFormatR8Unorm, 1},
        {MTLPixelFormatRG32Uint, 8}, {MTLPixelFormatRGBA32Float, 16}, {MTLPixelFormatRGBA16Sint, 8}, {MTLPixelFormatB5G6R5Unorm, 2}};
    for (unsigned i = 0; i < sizeof f / sizeof *f; i++) {
        id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, f[i].f, 33, 17, 1, 3, 1)];
        REQUIRE(t, @"texture format %lu", (unsigned long)f[i].f);
        if (!UploadAndVerifyAll(t, f[i].bpp, 10 + i)) {
            gFailure = [NSString stringWithFormat:@"format %lu: %@", (unsigned long)f[i].f, gFailure]; return NO;
        }
    }
    return YES;
}
static BOOL CaseSubregion(id<MTLDevice> dev) {
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatRGBA8Unorm, 32, 32, 1, 2, 1)];
    REQUIRE(t, @"texture");
    if (!UploadAndVerifyAll(t, 4, 20)) return NO;
    uint8_t patch[5 * 3 * 4]; memset(patch, 0x5a, sizeof patch);
    [t replaceRegion:MTLRegionMake2D(7, 4, 5, 3) mipmapLevel:1 slice:0 withBytes:patch bytesPerRow:20 bytesPerImage:0];
    uint8_t got[16 * 16 * 4];
    [t getBytes:got bytesPerRow:64 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 0, 16, 16) mipmapLevel:1 slice:0];
    for (NSUInteger y = 0; y < 16; y++) for (NSUInteger x = 0; x < 64; x++) {
        BOOL inside = y >= 4 && y < 7 && x >= 28 && x < 48;
        REQUIRE(got[y * 64 + x] == (inside ? 0x5a : Pattern(20, 1, 0, 0, y, x)), @"level 1 byte (%lu,%lu) wrong after partial upload", y, x);
    }
    uint8_t level0[32 * 4];
    [t getBytes:level0 bytesPerRow:128 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 5, 32, 1) mipmapLevel:0 slice:0];
    for (NSUInteger x = 0; x < 128; x++) REQUIRE(level0[x] == Pattern(20, 0, 0, 0, 5, x), @"level 0 disturbed by a level-1 upload");
    return YES;
}
static BOOL CaseView(id<MTLDevice> dev) {
    id<MTLTexture> p = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2DArray, MTLPixelFormatRGBA8Unorm, 32, 32, 1, 3, 4)];
    REQUIRE(p, @"parent");
    if (!UploadAndVerifyAll(p, 4, 30)) return NO;
    id<MTLTexture> v = [p newTextureViewWithPixelFormat:MTLPixelFormatRGBA8Unorm textureType:MTLTextureType2DArray
                                                 levels:NSMakeRange(1, 2) slices:NSMakeRange(1, 2)];
    REQUIRE(v && v.width == 16 && v.mipmapLevelCount == 2 && v.arrayLength == 2, @"level/slice view geometry");
    uint8_t row[16 * 4], got[16 * 4];
    for (NSUInteger i = 0; i < sizeof row; i++) row[i] = (uint8_t)(0x80 + i);
    [v replaceRegion:MTLRegionMake2D(0, 3, 16, 1) mipmapLevel:0 slice:1 withBytes:row bytesPerRow:64 bytesPerImage:0];
    [p getBytes:got bytesPerRow:64 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 3, 16, 1) mipmapLevel:1 slice:2];
    REQUIRE(!memcmp(got, row, 64), @"view (level 0, slice 1) did not write parent (level 1, slice 2)");
    [v getBytes:got bytesPerRow:64 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 4, 16, 1) mipmapLevel:0 slice:1];
    for (NSUInteger x = 0; x < 64; x++) REQUIRE(got[x] == Pattern(30, 1, 2, 0, 4, x), @"view read of parent (1,2) wrong");
    // Pixel-format view of a 2D texture: same bytes.
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatRGBA8Unorm, 32, 8, 1, 1, 1)];
    id<MTLTexture> fv = [t newTextureViewWithPixelFormat:MTLPixelFormatBGRA8Unorm];
    REQUIRE(t && fv, @"format view");
    [fv replaceRegion:MTLRegionMake2D(0, 2, 16, 1) mipmapLevel:0 slice:0 withBytes:row bytesPerRow:64 bytesPerImage:0];
    [t getBytes:got bytesPerRow:64 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 2, 16, 1) mipmapLevel:0 slice:0];
    REQUIRE(!memcmp(got, row, 64), @"pixel-format view did not write the parent's bytes");
    return YES;
}
static BOOL CaseBounds(id<MTLDevice> dev) {
    // A 16x16 BGRA8 texture on a 64-row, 128-byte-pitch surface: rows 16.. and bytes 64..127 of
    // every row belong to nobody and must never be written.
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@16, (id)kIOSurfaceHeight:@16,
        (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfaceBytesPerRow:@128, (id)kIOSurfaceAllocSize:@(128 * 64),
        (id)kIOSurfacePixelFormat:@(0x42475241u)});
    REQUIRE(s && IOSurfaceGetAllocSize(s) >= 128 * 64, @"surface");
    MTLTextureDescriptor *td = Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 16, 16, 1, 1, 1);
    id<MTLTexture> t = [dev newTextureWithDescriptor:td iosurface:s plane:0];
    REQUIRE(t, @"iosurface texture");
    IOSurfaceLock(s, 0, NULL);
    uint8_t *base = IOSurfaceGetBaseAddress(s);
    memset(base, 0x11, 128 * 64);
    uint8_t junk[64 * 64]; memset(junk, 0xcc, sizeof junk);
    [t replaceRegion:MTLRegionMake2D(10, 10, 8, 8) mipmapLevel:0 slice:0 withBytes:junk bytesPerRow:32 bytesPerImage:0];
    [t replaceRegion:MTLRegionMake2D(0, 0, 4, 4) mipmapLevel:3 slice:0 withBytes:junk bytesPerRow:16 bytesPerImage:0];
    [t replaceRegion:MTLRegionMake2D(0, 0, 4, 4) mipmapLevel:0 slice:2 withBytes:junk bytesPerRow:16 bytesPerImage:0];
    uint8_t out[64 * 64]; memset(out, 0x77, sizeof out);
    [t getBytes:out bytesPerRow:64 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 12, 16, 8) mipmapLevel:0 slice:0];
    NSUInteger bad = 0;
    for (NSUInteger i = 0; i < 128 * 64; i++) bad += base[i] != 0x11;
    IOSurfaceUnlock(s, 0, NULL);
    CFRelease(s);
    REQUIRE(!bad, @"%lu surface bytes changed by out-of-range uploads", bad);
    for (NSUInteger i = 0; i < sizeof out; i++) REQUIRE(out[i] == 0x77, @"out-of-range readback wrote the caller buffer");
    return YES;
}
static BOOL CaseIOSurface(id<MTLDevice> dev) {
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)@{(id)kIOSurfaceWidth:@37, (id)kIOSurfaceHeight:@23,
        (id)kIOSurfaceBytesPerElement:@4, (id)kIOSurfaceBytesPerRow:@1024, (id)kIOSurfaceAllocSize:@32768,
        (id)kIOSurfacePixelFormat:@(0x42475241u)});
    REQUIRE(s, @"surface");
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 37, 23, 1, 1, 1)
                                           iosurface:s plane:0];
    BOOL ok = t && UploadAndVerifyAll(t, 4, 40);
    const uint8_t *b = IOSurfaceGetBaseAddress(s);
    for (NSUInteger y = 0; ok && y < 23; y++) for (NSUInteger x = 0; ok && x < 37 * 4; x++)
        if (b[y * 1024 + x] != Pattern(40, 0, 0, 0, y, x)) { gFailure = @"surface memory differs"; ok = NO; }
    CFRelease(s);
    if (!t) gFailure = @"iosurface texture";
    return ok;
}
static BOOL CaseNoCopy(id<MTLDevice> dev) {
    void *mem = NULL;
    REQUIRE(!posix_memalign(&mem, 16384, 65536), @"alloc");
    memset(mem, 0, 65536);
    id<MTLTexture> t = [(id)dev newTextureWithBytesNoCopy:mem length:65536
                                           descriptor:Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 37, 23, 1, 1, 1)
                                          deallocator:nil];
    BOOL ok = t && UploadAndVerifyAll(t, 4, 50);
    for (NSUInteger y = 0; ok && y < 23; y++) for (NSUInteger x = 0; ok && x < 37 * 4; x++)
        if (((uint8_t *)mem)[y * 192 + x] != Pattern(50, 0, 0, 0, y, x)) { gFailure = @"caller memory differs"; ok = NO; }
    if (!t) gFailure = @"nocopy texture";
    t = nil;
    return ok;   // mem intentionally leaked: the texture may outlive this frame under ARC autorelease.
}
static BOOL CaseBufferTexture(id<MTLDevice> dev) {
    id<MTLBuffer> b = [dev newBufferWithLength:65536 options:MTLResourceStorageModeShared];
    REQUIRE(b && [(id)b respondsToSelector:@selector(newTiledTextureWithDescriptor:offset:bytesPerRow:)], @"buffer");
    memset(b.contents, 0, 65536);
    id<MTLTexture> t = [(id)b newTiledTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 37, 23, 1, 1, 1)
                                                     offset:4096 bytesPerRow:256];
    REQUIRE(t, @"buffer texture");
    if (!UploadAndVerifyAll(t, 4, 60)) return NO;
    const uint8_t *c = b.contents;
    for (NSUInteger y = 0; y < 23; y++) for (NSUInteger x = 0; x < 37 * 4; x++)
        REQUIRE(c[4096 + y * 256 + x] == Pattern(60, 0, 0, 0, y, x), @"buffer contents differ at (%lu,%lu)", y, x);
    return YES;
}
static BOOL CaseBlitSynchronize(id<MTLDevice> dev) {
    id<MTLCommandQueue> q = [dev newCommandQueue];
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLBuffer> b = [dev newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    id<MTLTexture> t = [dev newTextureWithDescriptor:Descriptor(MTLTextureType2D, MTLPixelFormatBGRA8Unorm, 16, 16, 1, 1, 1)];
    REQUIRE(q && cb && b && t, @"objects");
    id<MTLBlitCommandEncoder> be = [cb blitCommandEncoder];
    REQUIRE(be, @"blit encoder");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"   // still sent by existing clients; IOGPU reports failure
    @try {
        [be synchronizeResource:b];
        [be synchronizeResource:t];
        [be synchronizeTexture:t slice:0 level:0];
    } @catch (NSException *e) { REQUIRE(0, @"synchronize raised %@", e.reason); }
#pragma clang diagnostic pop
    [be endEncoding];
    return YES;
}
static BOOL CaseSharedEvent(id<MTLDevice> dev) {
    id<MTLSharedEvent> e = [dev newSharedEvent];
    REQUIRE(e, @"newSharedEvent returned nil (CA new_compositor stores it without a nil check)");
    e.signaledValue = 7;
    REQUIRE(e.signaledValue == 7, @"signaledValue %llu after setting 7", e.signaledValue);
    MTLSharedEventHandle *h = [e newSharedEventHandle];
    REQUIRE(h, @"no shared event handle");
    return YES;
}

static const struct { const char *name; BOOL (*fn)(id<MTLDevice>); } kCases[] = {
    {"fp16-profile", CaseFP16}, {"sysmem-2d", CaseSysmem2D}, {"mip-chain", CaseMipChain}, {"array-slices", CaseArray},
    {"cube-faces", CaseCube}, {"volume-3d", CaseVolume}, {"format-sizes", CaseFormats}, {"subregion", CaseSubregion},
    {"texture-view", CaseView}, {"bounds", CaseBounds}, {"iosurface-2d", CaseIOSurface}, {"nocopy-2d", CaseNoCopy},
    {"buffer-texture", CaseBufferTexture}, {"blit-synchronize", CaseBlitSynchronize}, {"shared-event", CaseSharedEvent},
};

static int RunChild(const char *name, NSString *bundle) {
    id<MTLDevice> dev = RegisterDevice(bundle);
    if (!dev) { printf("{\"pass\":false,\"detail\":\"device registration failed\"}\n"); return 3; }
    for (unsigned i = 0; i < sizeof kCases / sizeof *kCases; i++) if (!strcmp(kCases[i].name, name)) {
        BOOL ok = NO;
        @try { ok = kCases[i].fn(dev); } @catch (NSException *e) { gFailure = [NSString stringWithFormat:@"exception %@: %@", e.name, e.reason]; }
        NSData *j = [NSJSONSerialization dataWithJSONObject:@{@"pass":@(ok), @"detail":ok ? @"" : (gFailure ?: @"?")} options:0 error:nil];
        printf("%s\n", (const char *)[[[NSString alloc] initWithData:j encoding:NSUTF8StringEncoding] UTF8String]);
        fflush(stdout);
        return ok ? 0 : 1;
    }
    return 64;
}

static NSDictionary *SpawnCase(const char *self, const char *bundle, const char *name) {
    int out[2]; if (pipe(out)) return @{@"pass":@NO, @"detail":@"pipe"};
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclose(&fa, out[0]);
    char *argv[] = {(char *)self, (char *)bundle, "--case", (char *)name, NULL};
    pid_t pid;
    int err = posix_spawn(&pid, self, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(out[1]);
    if (err) { close(out[0]); return @{@"pass":@NO, @"detail":@"spawn"}; }
    NSMutableData *buf = [NSMutableData data]; char chunk[4096]; ssize_t n;
    while ((n = read(out[0], chunk, sizeof chunk)) > 0) [buf appendBytes:chunk length:(NSUInteger)n];
    close(out[0]);
    int status = 0; waitpid(pid, &status, 0);
    NSString *text = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding] ?: @"";
    NSDictionary *line = nil;
    for (NSString *l in [text componentsSeparatedByString:@"\n"])
        if ([l hasPrefix:@"{"]) line = [NSJSONSerialization JSONObjectWithData:[l dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
    BOOL exited = WIFEXITED(status);
    BOOL pass = exited && WEXITSTATUS(status) == 0 && [line[@"pass"] boolValue];
    NSString *detail = line[@"detail"] ?: (exited ? [NSString stringWithFormat:@"exit %d, no result", WEXITSTATUS(status)]
                                                  : [NSString stringWithFormat:@"killed by signal %d", WTERMSIG(status)]);
    return @{@"pass":@(pass), @"detail":detail, @"exit":@(exited ? WEXITSTATUS(status) : -WTERMSIG(status))};
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc == 4 && !strcmp(argv[2], "--case")) return RunChild(argv[3], @(argv[1]));
        if (argc != 3) { fprintf(stderr, "usage: resource-roundtrip <AdrenoMetal.bundle> <report.json>\n"); return 64; }
        NSMutableDictionary *cases = [NSMutableDictionary dictionary];
        unsigned failed = 0;
        for (unsigned i = 0; i < sizeof kCases / sizeof *kCases; i++) {
            NSDictionary *r = SpawnCase(argv[0], argv[1], kCases[i].name);
            cases[@(kCases[i].name)] = r;
            failed += ![r[@"pass"] boolValue];
            printf("  %s %-18s %s\n", [r[@"pass"] boolValue] ? "PASS" : "FAIL", kCases[i].name, [r[@"detail"] UTF8String]);
        }
        NSDictionary *report = @{@"status":failed ? @"RESOURCE_ROUNDTRIP_FAILED" : @"RESOURCE_ROUNDTRIP_PASS",
            @"failed":@(failed), @"cases":cases, @"bundle":@(argv[1]), @"gpu_submission":@NO,
            @"boundary":@"Host AGX IOAccelerator provider; CPU-visible resource contract only. No Adreno hardware."};
        NSData *j = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
        if (![j writeToFile:@(argv[2]) atomically:YES]) return 73;
        printf("%s (%u failed)\n", [report[@"status"] UTF8String], failed);
        return failed ? 1 : 0;
    }
}
