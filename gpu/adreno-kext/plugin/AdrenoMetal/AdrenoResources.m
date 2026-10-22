/* SPDX-License-Identifier: MIT */
// AdrenoResources.m - buffers, textures, sampler and depth-stencil states.
//
// Resources are native IOGPU allocations carrying the Adreno vendor argument tail
// (AdrenoContract.h). Textures record constructor-provided linear geometry for the
// GPU clear path (AdrenoLinearTexture.h) and a CPU view of their allocation for
// replaceRegion:/getBytes:, placed by AdrenoTextureSubresource (AdrenoMTLObjectsPrivate.h).
#import "AdrenoMTLObjectsPrivate.h"
#import "AdrenoTextureBindings.h"
#import <os/log.h>
#import <objc/runtime.h>
#if ADRENO_PIPELINE
#include <stdatomic.h>
#include <time.h>
#endif

static os_log_t AdrenoResourceLog(void) {
    static os_log_t l; static dispatch_once_t o;
    dispatch_once(&o, ^{ l = os_log_create("org.snapintosh.adreno", "resources"); });
    return l;
}

// Bytes per pixel of uncompressed formats; also the allocation size class for everything else.
static NSUInteger AdrenoBytesPerPixel(MTLPixelFormat f) {
    switch (f) {
        case MTLPixelFormatA8Unorm: case MTLPixelFormatR8Unorm: case MTLPixelFormatR8Unorm_sRGB:
        case MTLPixelFormatR8Snorm: case MTLPixelFormatR8Uint: case MTLPixelFormatR8Sint: case MTLPixelFormatStencil8:
            return 1;
        case MTLPixelFormatR16Unorm: case MTLPixelFormatR16Snorm: case MTLPixelFormatR16Uint: case MTLPixelFormatR16Sint:
        case MTLPixelFormatR16Float: case MTLPixelFormatRG8Unorm: case MTLPixelFormatRG8Unorm_sRGB: case MTLPixelFormatRG8Snorm:
        case MTLPixelFormatRG8Uint: case MTLPixelFormatRG8Sint: case MTLPixelFormatB5G6R5Unorm: case MTLPixelFormatA1BGR5Unorm:
        case MTLPixelFormatABGR4Unorm: case MTLPixelFormatBGR5A1Unorm: case MTLPixelFormatDepth16Unorm:
            return 2;
        case MTLPixelFormatRG32Uint: case MTLPixelFormatRG32Sint: case MTLPixelFormatRG32Float:
        case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRGBA16Snorm: case MTLPixelFormatRGBA16Uint:
        case MTLPixelFormatRGBA16Sint: case MTLPixelFormatRGBA16Float: case MTLPixelFormatBGRA10_XR:
        case MTLPixelFormatBGRA10_XR_sRGB: case MTLPixelFormatDepth32Float_Stencil8: case MTLPixelFormatX32_Stencil8:
            return 8;
        case MTLPixelFormatRGBA32Uint: case MTLPixelFormatRGBA32Sint: case MTLPixelFormatRGBA32Float:
            return 16;
        default: return 4;   // BGRA8, RGBA8, BGR10A2, RGB10A2, BGR10_XR, RG16, R32, depth32 ...
    }
}
// Block-compressed and subsampled formats (BC, PVRTC, EAC/ETC, ASTC, GBGR422/BGRG422) have no
// per-pixel row layout here; CPU copies of them are refused rather than guessed.
static BOOL AdrenoFormatIsBlockEncoded(MTLPixelFormat f) {
    return f >= MTLPixelFormatBC1_RGBA && f < MTLPixelFormatDepth16Unorm;
}
// These formats have matching linear sampling descriptors in AdrenoDrawCommands.
static NSUInteger AdrenoLinearBytesPerPixel(MTLPixelFormat f) {
    switch (f) {
        case MTLPixelFormatR8Unorm: case MTLPixelFormatA8Unorm: return 1;
        case MTLPixelFormatRG8Unorm: case MTLPixelFormatR16Float: case MTLPixelFormatR16Unorm: return 2;
        case MTLPixelFormatRG16Float: case MTLPixelFormatRG16Unorm: case MTLPixelFormatR32Float: return 4;
        case MTLPixelFormatRGBA16Unorm: case MTLPixelFormatRG32Float: return 8;
        case MTLPixelFormatRGBA32Float: return 16;
        case MTLPixelFormatRGBA8Unorm: case MTLPixelFormatRGBA8Unorm_sRGB:
        case MTLPixelFormatBGRA8Unorm: case MTLPixelFormatBGRA8Unorm_sRGB: return 4;
        case MTLPixelFormatRGBA16Float: return 8;
        // v35: ControlCenter's status-item surfaces are 'l10r' (ARGB2101010 little-endian) IOSurfaces with BGR10A2 textures.
        case MTLPixelFormatBGR10A2Unorm: case MTLPixelFormatRGB10A2Unorm: return 4;
        // agents/gfx-correctness F2: integer formats (Core Animation's rim/brim passes render and read RG16Uint).
        case MTLPixelFormatR8Uint: case MTLPixelFormatR8Sint: return 1;
        case MTLPixelFormatRG8Uint: case MTLPixelFormatRG8Sint: case MTLPixelFormatR16Uint: case MTLPixelFormatR16Sint: return 2;
        case MTLPixelFormatRGBA8Uint: case MTLPixelFormatRGBA8Sint: case MTLPixelFormatRG16Uint: case MTLPixelFormatRG16Sint:
        case MTLPixelFormatR32Uint: case MTLPixelFormatR32Sint: return 4;
        case MTLPixelFormatRGBA16Uint: case MTLPixelFormatRGBA16Sint: case MTLPixelFormatRG32Uint: case MTLPixelFormatRG32Sint: return 8;
        case MTLPixelFormatRGBA32Uint: case MTLPixelFormatRGBA32Sint: return 16;
        default: return 0;
    }
}
static const NSUInteger kAdrenoPitchAlign = 64;   // linear pitch alignment used for sysmem-backed textures
static const NSUInteger kAdrenoSliceAlign = 4096; // slice (array layer / cube face) stride alignment

static NSUInteger AdrenoAlign(NSUInteger v, NSUInteger a) { return (v + a - 1) & ~(a - 1); }
static NSUInteger AdrenoLevelDim(NSUInteger v, NSUInteger level) { return level < 64 ? MAX((NSUInteger)1, v >> level) : 1; }
// The lower mip levels' pitch alignment for a level-0 pitch, as log2(bytes) - 6: the T#'s MIN_LINE_OFFSET. 256 bytes
// where level 0's pitch allows it (what AdrenoLinearViewWords has always programmed); 64 for a 64-byte-aligned pitch.
NSUInteger AdrenoMipLineShift(NSUInteger rowBytes0) {
    if (!rowBytes0 || (rowBytes0 & 63)) return 0;
    return MIN((NSUInteger)2, (NSUInteger)__builtin_ctzl(rowBytes0) - 6);
}
// Level `level` of a chain (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: mip levels the GPU can sample"). Level 0 has the
// recorded pitch (or 64-byte-aligned rows). A lower level has the pitch the GPU derives from level 0's (Mesa
// fdl_pitch: align(max(1, pitch0 >> level), 1 << pitchalign), the pitch alignment being AdrenoMipLineShift + 6); the
// levels follow each other back to back (fd6_layout.c, linear), so a T# with MIPLVLS reads exactly these bytes.
static AdrenoSubresourceLayout AdrenoLevelLayout(const AdrenoTextureGeometry *g, NSUInteger level) {
    AdrenoSubresourceLayout l = {0};
    l.width = AdrenoLevelDim(g->width, level);
    l.height = AdrenoLevelDim(g->height, level);
    l.depth = g->type == MTLTextureType3D ? AdrenoLevelDim(g->depth, level) : 1;
    const NSUInteger pitch0 = g->rowBytes0 ? g->rowBytes0 : AdrenoAlign(g->width * g->bytesPerPixel, kAdrenoPitchAlign);
    l.rowBytes = level == 0 ? pitch0 : AdrenoAlign(MAX((NSUInteger)1, level < 64 ? pitch0 >> level : 0),
                                                   kAdrenoPitchAlign << AdrenoMipLineShift(pitch0));
    l.imageBytes = l.rowBytes * l.height;
    return l;
}
static NSUInteger AdrenoChainBytes(const AdrenoTextureGeometry *g) {
    NSUInteger bytes = 0, levels = MAX(g->levels, (NSUInteger)1);
    for (NSUInteger l = 0; l < levels; l++) {
        AdrenoSubresourceLayout s = AdrenoLevelLayout(g, l);
        // A chain's last level gets rows to a multiple of 4 (fd6_layout.c: the 16x4 over-fetch slack). A single-level
        // texture keeps its size.
        bytes += (levels > 1 && l == levels - 1 ? AdrenoAlign(s.height, 4) * s.rowBytes : s.imageBytes) * s.depth;
    }
    return bytes;
}
static NSUInteger AdrenoSliceStride(const AdrenoTextureGeometry *g) {
    NSUInteger chain = AdrenoChainBytes(g);
    return g->slices > 1 ? AdrenoAlign(chain, kAdrenoSliceAlign) : chain;
}
AdrenoSubresourceLayout AdrenoTextureSubresource(const AdrenoTextureGeometry *g, NSUInteger level, NSUInteger slice) {
    NSUInteger offset = slice * AdrenoSliceStride(g);
    for (NSUInteger l = 0; l < level; l++) {
        AdrenoSubresourceLayout s = AdrenoLevelLayout(g, l);
        offset += s.imageBytes * s.depth;
    }
    AdrenoSubresourceLayout s = AdrenoLevelLayout(g, level);
    s.offset = offset;
    return s;
}
NSUInteger AdrenoTextureAllocationBytes(const AdrenoTextureGeometry *g) {
    return AdrenoSliceStride(g) * MAX(g->slices, (NSUInteger)1);
}
static NSUInteger AdrenoSliceCount(MTLTextureType type, NSUInteger arrayLength) {
    NSUInteger n = MAX(arrayLength, (NSUInteger)1);
    return type == MTLTextureTypeCube || type == MTLTextureTypeCubeArray ? n * 6 : n;
}
static AdrenoTextureGeometry AdrenoGeometryFromDescriptor(MTLTextureDescriptor *d, NSUInteger rowBytes0) {
    return (AdrenoTextureGeometry){d.textureType, MAX(d.width, (NSUInteger)1), MAX(d.height, (NSUInteger)1),
        MAX(d.depth, (NSUInteger)1), MAX(d.mipmapLevelCount, (NSUInteger)1), AdrenoSliceCount(d.textureType, d.arrayLength),
        AdrenoBytesPerPixel(d.pixelFormat), rowBytes0};
}

static void AdrenoArgsInit(AdrenoNewResourceArgs *a, uint32_t format) {
    memset(a, 0, sizeof *a);
    a->adrenoFormat = format;   // kernel-abi track owns the meaning; 0 = "linear, no UBWC"
}

// =============================== aligned shadows ===============================
// docs/USERSPACE-GRAPHICS-20261019.md (aligned shadows). One per IOSurface ID in this process, shared by every texture
// and view over the surface. The GPU reads and writes the shadow; CPU writes to the surface (its seed, or replaceRegion)
// refill it before the next GPU use, and command buffers that wrote it copy it back when they complete.
@interface AdrenoSurfaceShadow : NSObject {
@public
    IOSurfaceRef _surface;
    id<MTLBuffer> _buffer;
    NSUInteger _rowBytes, _surfaceRow, _width, _height, _cpp;
    uint32_t _seed;
    BOOL _dirty;
#if ADRENO_PIPELINE
    uint32_t _gpuUsers;                    // committed, not completed command buffers using _buffer (U2)
#endif
}
@end
#if ADRENO_PIPELINE
static NSCondition *AdrenoShadowIdle(void) {        // signalled whenever a shadow loses a GPU user
    static NSCondition *c; static dispatch_once_t once;
    dispatch_once(&once, ^{ c=[NSCondition new]; });
    return c;
}
static _Atomic uint64_t gAdrenoShadowOverruns;
static const uint64_t kAdrenoShadowRefillWaitNs = 250 * NSEC_PER_MSEC;
#endif
@implementation AdrenoSurfaceShadow
- (void)dealloc { if (_surface) CFRelease(_surface); }
- (void)fillLocked {
    uint32_t seed=0;
    if (IOSurfaceLock(_surface,kIOSurfaceLockReadOnly,&seed)!=kIOReturnSuccess) {
        os_log_error(AdrenoResourceLog(), "IOSurface %u shadow fill: lock refused", IOSurfaceGetID(_surface));
        return;
    }
    const char *src=IOSurfaceGetBaseAddress(_surface); char *dst=_buffer.contents;
    const NSUInteger n=_width*_cpp;
    if (src && dst) for (NSUInteger y=0;y<_height;y++) memcpy(dst+y*_rowBytes,src+y*_surfaceRow,n);
    IOSurfaceUnlock(_surface,kIOSurfaceLockReadOnly,&seed);
    _seed=IOSurfaceGetSeed(_surface);_dirty=NO;
}
#if ADRENO_PIPELINE
// U2: never refill while a committed command buffer may still read or write the shadow on the GPU. The wait holds no
// lock the completion path takes (its write-back takes @synchronized(self) first, then drops the user).
- (void)syncIfNeeded {
    const uint64_t deadline=clock_gettime_nsec_np(CLOCK_UPTIME_RAW)+kAdrenoShadowRefillWaitNs;
    for (;;) {
        @synchronized(self) {
            if (!_dirty && IOSurfaceGetSeed(_surface)==_seed) return;
            const BOOL late=clock_gettime_nsec_np(CLOCK_UPTIME_RAW)>=deadline;
            if (!_gpuUsers || late) {
                if (_gpuUsers) {
                    const uint64_t n=atomic_fetch_add(&gAdrenoShadowOverruns,1)+1;
                    if (n<=8 || !(n&255))
                        os_log_error(AdrenoResourceLog(), "IOSurface %u shadow refilled with %u command buffers in flight after 250 ms (%llu times)",
                                     IOSurfaceGetID(_surface), _gpuUsers, (unsigned long long)n);
                }
                [self fillLocked];
                return;
            }
        }
        NSCondition *idle=AdrenoShadowIdle();
        [idle lock];
        [idle waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.001]];   // polled: a broadcast may precede the wait
        [idle unlock];
    }
}
- (void)gpuBegin { @synchronized(self) { _gpuUsers++; } }
- (void)gpuEnd {
    @synchronized(self) { if (_gpuUsers) _gpuUsers--; }
    NSCondition *idle=AdrenoShadowIdle();
    [idle lock]; [idle broadcast]; [idle unlock];
}
#else
- (void)syncIfNeeded { @synchronized(self) { if (_dirty || IOSurfaceGetSeed(_surface)!=_seed) [self fillLocked]; } }
#endif
- (void)writeBack {
    @synchronized(self) {
        if (IOSurfaceLock(_surface,0,NULL)!=kIOReturnSuccess) {
            os_log_error(AdrenoResourceLog(), "IOSurface %u shadow write-back: lock refused", IOSurfaceGetID(_surface));
            return;
        }
        char *dst=IOSurfaceGetBaseAddress(_surface); const char *src=_buffer.contents;
        const NSUInteger n=_width*_cpp;
        if (src && dst) for (NSUInteger y=0;y<_height;y++) memcpy(dst+y*_surfaceRow,src+y*_rowBytes,n);
        IOSurfaceUnlock(_surface,0,NULL);
        _seed=IOSurfaceGetSeed(_surface);_dirty=NO;     // our own write is not a CPU change to refill from
    }
}
- (void)markDirty { @synchronized(self) { _dirty=YES; } }
@end

static NSMapTable *AdrenoShadowsBySurface(void) {   // IOSurface ID -> shadow (weak)
    static NSMapTable *t; static dispatch_once_t once;
    dispatch_once(&once, ^{ t=[NSMapTable strongToWeakObjectsMapTable]; });
    return t;
}
static NSMapTable *AdrenoShadowsByBuffer(void) {    // shadow buffer -> shadow (both weak)
    static NSMapTable *t; static dispatch_once_t once;
    dispatch_once(&once, ^{ t=[NSMapTable weakToWeakObjectsMapTable]; });
    return t;
}
#if ADRENO_PIPELINE
static NSMapTable *AdrenoShadowsByResourceID(void) {   // the shadow buffer's IOGPU resource ID -> shadow (weak)
    static NSMapTable *t; static dispatch_once_t once;
    dispatch_once(&once, ^{ t=[NSMapTable strongToWeakObjectsMapTable]; });
    return t;
}
#endif
// The surface's shadow, created (and filled) on first use; nil if the surface cannot have one.
static AdrenoSurfaceShadow *AdrenoShadowForSurface(id<MTLDevice> device, IOSurfaceRef s, NSUInteger cpp) {
    const NSUInteger width=IOSurfaceGetWidth(s), height=IOSurfaceGetHeight(s), row=IOSurfaceGetBytesPerRow(s);
    if (!device || !width || !height || !cpp || width>16384 || height>16384 || row<width*cpp) return nil;
    const NSUInteger aligned=AdrenoAlign(width*cpp,kAdrenoPitchAlign);
    NSNumber *key=@(IOSurfaceGetID(s));
    @synchronized (AdrenoShadowsBySurface()) {
        AdrenoSurfaceShadow *sh=[AdrenoShadowsBySurface() objectForKey:key];
        if (sh && sh->_surface==s && sh->_rowBytes==aligned && sh->_surfaceRow==row && sh->_width==width &&
            sh->_height==height && sh->_cpp==cpp)
            return sh;
        sh=[AdrenoSurfaceShadow new];
        sh->_buffer=[device newBufferWithLength:aligned*height options:MTLResourceStorageModeShared];
        if (!sh->_buffer || !sh->_buffer.contents || sh->_buffer.length<aligned*height) return nil;
        sh->_buffer.label=@"Adreno IOSurface shadow";
        sh->_surface=(IOSurfaceRef)CFRetain(s);
        sh->_rowBytes=aligned;sh->_surfaceRow=row;sh->_width=width;sh->_height=height;sh->_cpp=cpp;
        @synchronized(sh) { [sh fillLocked]; }
        [AdrenoShadowsBySurface() setObject:sh forKey:key];
        @synchronized (AdrenoShadowsByBuffer()) { [AdrenoShadowsByBuffer() setObject:sh forKey:sh->_buffer]; }
#if ADRENO_PIPELINE
        if ([sh->_buffer isKindOfClass:[IOGPUMetalResource class]])
            @synchronized (AdrenoShadowsByResourceID()) {
                [AdrenoShadowsByResourceID() setObject:sh forKey:@([(IOGPUMetalResource *)sh->_buffer resourceID])];
            }
#endif
        return sh;
    }
}
id AdrenoShadowOfBuffer(id resource) {
    if (!resource) return nil;
    @synchronized (AdrenoShadowsByBuffer()) { return [AdrenoShadowsByBuffer() objectForKey:resource]; }
}
void AdrenoShadowWriteBack(id shadow) { if ([shadow isKindOfClass:[AdrenoSurfaceShadow class]]) [(AdrenoSurfaceShadow *)shadow writeBack]; }
#if ADRENO_PIPELINE
NSArray *AdrenoShadowsForResourceIDs(NSData *resourceIDs) {
    NSMutableArray *found=nil;
    const uint32_t *ids=resourceIDs.bytes;
    const NSUInteger n=resourceIDs.length/sizeof(uint32_t);
    if (!n) return nil;
    @synchronized (AdrenoShadowsByResourceID()) {
        NSMapTable *t=AdrenoShadowsByResourceID();
        if (!t.count) return nil;
        for (NSUInteger i=0;i<n;i++) {
            AdrenoSurfaceShadow *sh=[t objectForKey:@(ids[i])];
            if (!sh || [found containsObject:sh]) continue;
            if (!found) found=[NSMutableArray array];
            [found addObject:sh];
        }
    }
    return found;
}
void AdrenoShadowsGPUBegin(NSArray *shadows) { for (AdrenoSurfaceShadow *sh in shadows) [sh gpuBegin]; }
void AdrenoShadowsGPUEnd(NSArray *shadows) { for (AdrenoSurfaceShadow *sh in shadows) [sh gpuEnd]; }
uint64_t AdrenoShadowRefillOverruns(void) { return atomic_load(&gAdrenoShadowOverruns); }
#endif

// =============================== resources ===============================
@implementation AdrenoBuffer
- (id<MTLTexture>)newTextureWithDescriptor:(MTLTextureDescriptor *)d offset:(NSUInteger)o bytesPerRow:(NSUInteger)bpr {
    NSUInteger cpp = d ? AdrenoLinearBytesPerPixel(d.pixelFormat) : 0;
    if (!cpp || d.textureType != MTLTextureType2D || !d.width || !d.height ||
        d.depth != 1 || d.arrayLength != 1 || d.mipmapLevelCount != 1 || d.sampleCount != 1 ||
        d.width > NSUIntegerMax / cpp || bpr < d.width * cpp || (bpr & 63) || (o & 63) ||
        o > self.length || d.height > (self.length - o) / bpr || d.storageMode != self.storageMode)
        return nil;
    AdrenoTexture *texture = (AdrenoTexture *)[self newTiledTextureWithDescriptor:d offset:o bytesPerRow:bpr];
    if (texture && (texture.buffer != self || [texture resourceID] != [self resourceID] ||
                    [texture resourceSize] != [self resourceSize])) {
        os_log_error(AdrenoResourceLog(), "buffer texture did not retain the native backing allocation");
        return nil;
    }
    return texture;
}
// newTiledTextureWithDescriptor:offset:bytesPerRow: (SkyLight) - a linear texture aliasing this buffer.
- (id<MTLTexture>)newTiledTextureWithDescriptor:(MTLTextureDescriptor *)d offset:(NSUInteger)o bytesPerRow:(NSUInteger)bpr {
    AdrenoTexture *texture=[[AdrenoTexture alloc] initWithBuffer:self descriptor:d offset:o bytesPerRow:bpr];
    [texture adrenoSetUsage:d.usage];
    if (texture && [texture resourceID] == [self resourceID] && [texture resourceSize] == [self resourceSize])
        [texture adrenoSetLinearDescriptor:d rowBytes:bpr offset:o available:self.length];
    else if (texture)
        [texture adrenoSetLinearUnknown:@"buffer texture's native resource differs from its buffer"];
    if (texture && self.contents && o <= self.length && d.mipmapLevelCount <= 1) {
        AdrenoTextureGeometry g=AdrenoGeometryFromDescriptor(d, bpr);
        [texture adrenoSetCPU:(char *)self.contents + o bytes:self.length - o geometry:&g];
    }
    return texture;
}
- (void)didModifyRange:(NSRange)r { /* coherent CPU/GPU on X2E (IO-coherent GBIF): nothing to flush */ }
@end

// GPU address exhaustion (docs/PLUGIN-ARENA-TRIM-20261021.md, A8/A16): every mapping of every process shares one
// 3 GiB window, and IOGPU answers the kext's refused allocation (-82) with nil. Idle UBO staging arenas hold part of the
// window, so a plausible request that failed drains the staging pool and, when that released something, is retried
// once. A no-copy request is not retried (IOGPU may already have called its deallocator).
id<MTLBuffer> AdrenoNewBuffer(id<MTLDevice> dev, void *noCopy, NSUInteger len, MTLResourceOptions o,
                              void (^dealloc)(void *, NSUInteger)) {
    NSUInteger size = (len + 16383) & ~(NSUInteger)16383;        // 16 KiB pages
    for (int attempt = 0;; attempt++) {
        AdrenoNewResourceArgs a; AdrenoArgsInit(&a, 0);
        AdrenoBuffer *b = [[AdrenoBuffer alloc] initWithDevice:dev pointer:noCopy length:len alignment:16384 options:o
                                                    sysMemSize:size gpuAddress:0 args:&a argsSize:sizeof a deallocator:dealloc];
        if (attempt) AdrenoStagingRetried(b != nil);
        if (b || attempt || !len || !AdrenoStagingRelieveAfterFailure() || noCopy) return b;
    }
}
id<MTLBuffer> AdrenoNewBufferWithIOSurface(id<MTLDevice> dev, IOSurfaceRef s) {
    for (int attempt = 0;; attempt++) {
        AdrenoNewResourceArgs a; AdrenoArgsInit(&a, 0);
        AdrenoBuffer *b = [[AdrenoBuffer alloc] initWithDevice:dev iosurface:s args:&a argsSize:sizeof a];
        if (attempt) AdrenoStagingRetried(b != nil);
        if (b || attempt || !s || !AdrenoStagingRelieveAfterFailure()) return b;
    }
}

@implementation AdrenoTexture {
    // CPU view of the root allocation this texture (or view) lives in; cpu == NULL when not CPU-visible.
    char *_cpu;
    NSUInteger _cpuBytes;
    AdrenoTextureGeometry _root;
    NSUInteger _levelBase, _sliceBase;     // this texture's level 0 / slice 0 inside the root (views)
    BOOL _cpuRefusalLogged;
    AdrenoLinearTextureLayout _linear;
    BOOL _linearKnown;
    // Mip levels of a recorded 2D layout (AdrenoLinearLayoutAtLevel): the root's geometry, the root's level-0 offset
    // and this texture's first level inside it (views), and how many levels this texture has.
    AdrenoTextureGeometry _linearGeometry;
    uint64_t _linearRootOffset;
    NSUInteger _linearLevelBase, _linearLevels;
    NSString *_linearWhy;                  // why no layout was recorded (AdrenoDescribeTarget)
    AdrenoSurfaceShadow *_shadow;          // aligned shadow of an IOSurface with unaligned rows (views share the parent's)
    MTLTextureUsage _adrenoUsage;
    BOOL _adrenoUsageKnown;
}
- (void)adrenoSetUsage:(MTLTextureUsage)usage { _adrenoUsage=usage;_adrenoUsageKnown=YES; }
// The native IOGPU initializer leaves its generic usage getter at Unknown.
// Preserve the caller's descriptor so validation sees the actual contract.
- (MTLTextureUsage)usage { return _adrenoUsageKnown ? _adrenoUsage : [super usage]; }
- (void)adrenoSetCPU:(void *)p bytes:(NSUInteger)bytes geometry:(const AdrenoTextureGeometry *)g {
    _cpu = p; _cpuBytes = p ? bytes : 0; _root = *g; _levelBase = _sliceBase = 0;
}
- (void)adrenoInheritCPUFrom:(AdrenoTexture *)parent levels:(NSRange)levels slices:(NSRange)slices {
    if (!parent->_cpu) return;
    _cpu = parent->_cpu; _cpuBytes = parent->_cpuBytes; _root = parent->_root;
    _levelBase = parent->_levelBase + levels.location; _sliceBase = parent->_sliceBase + slices.location;
}
- (void)adrenoSetLinearDescriptor:(MTLTextureDescriptor *)d rowBytes:(NSUInteger)rb available:(NSUInteger)bytes {
    [self adrenoSetLinearDescriptor:d rowBytes:rb offset:0 available:bytes];
}
- (void)adrenoSetLinearDescriptor:(MTLTextureDescriptor *)d rowBytes:(NSUInteger)rb
                          offset:(NSUInteger)offset available:(NSUInteger)bytes {
    _linearKnown=NO;
    NSUInteger cpp=AdrenoLinearBytesPerPixel(d.pixelFormat);
    // A 3D texture one slice deep has exactly the single 2D slice's layout (CoreAnimation binds 1x1x1 ones).
    if(!cpp) { _linearWhy=[NSString stringWithFormat:@"format %lu has no linear entry",(unsigned long)d.pixelFormat]; return; }
    // A 2D texture may have mip levels: level 0's layout is recorded, the others follow it (AdrenoLinearLayoutAtLevel).
    if((d.textureType!=MTLTextureType2D && d.textureType!=MTLTextureType3D) || !d.mipmapLevelCount ||
       (d.mipmapLevelCount!=1 && (d.textureType!=MTLTextureType2D || rb!=AdrenoAlign(d.width*cpp,kAdrenoPitchAlign))) ||
       d.sampleCount!=1 || d.arrayLength!=1 || d.depth!=1 || !d.width || !d.height) {
        _linearWhy=[NSString stringWithFormat:@"descriptor type %lu, %lu levels, %lu samples, array %lu, depth %lu is not one 2D image",
                    (unsigned long)d.textureType,(unsigned long)d.mipmapLevelCount,(unsigned long)d.sampleCount,
                    (unsigned long)d.arrayLength,(unsigned long)d.depth];
        return;
    }
    if(d.width>UINT64_MAX/cpp || rb<d.width*cpp) {
        _linearWhy=[NSString stringWithFormat:@"row bytes %lu are below width %lu x %lu",(unsigned long)rb,(unsigned long)d.width,(unsigned long)cpp];
        return;
    }
    if((rb&63) || (offset&63)) {
        _linearWhy=[NSString stringWithFormat:@"row bytes %lu or offset %lu are not 64-byte aligned",(unsigned long)rb,(unsigned long)offset];
        return;
    }
    uint64_t size=[self resourceSize];
    uint64_t bound=MIN(size,bytes);
    if(!size || offset>bound || d.height>(bound-offset)/rb) {
        _linearWhy=[NSString stringWithFormat:@"%lu rows of %lu bytes at %lu exceed %llu bytes (resource %llu)",(unsigned long)d.height,
                    (unsigned long)rb,(unsigned long)offset,bound,size];
        return;
    }
    _linearGeometry=AdrenoGeometryFromDescriptor(d,rb);
    _linearGeometry.slices=1;
    if(d.mipmapLevelCount>1 && (uint64_t)AdrenoTextureAllocationBytes(&_linearGeometry)>bound-offset) {
        _linearWhy=[NSString stringWithFormat:@"%lu levels of %lux%lu exceed %llu bytes",(unsigned long)d.mipmapLevelCount,
                    (unsigned long)d.width,(unsigned long)d.height,bound-offset];
        return;
    }
    _linearRootOffset=offset;_linearLevelBase=0;_linearLevels=d.mipmapLevelCount;
    _linear=(AdrenoLinearTextureLayout){offset,rb,d.width,d.height,size,d.pixelFormat};
    _linearKnown=YES;_linearWhy=nil;
}
- (BOOL)adrenoLinearLevel:(NSUInteger)level layout:(AdrenoLinearTextureLayout *)out {
    if(!_linearKnown || !out || level>=MAX(_linearLevels,(NSUInteger)1)) return NO;
    if(level==0 && _linearLevelBase==0) { *out=_linear; return YES; }
    if(_linearGeometry.type!=MTLTextureType2D) return NO;
    AdrenoSubresourceLayout s=AdrenoTextureSubresource(&_linearGeometry,_linearLevelBase+level,0);
    *out=(AdrenoLinearTextureLayout){_linearRootOffset+s.offset,s.rowBytes,s.width,s.height,_linear.allocationBytes,_linear.format};
    return YES;
}
// An IOSurface plane whose element is
// one pixel of the format's linear size, at least as large as the descriptor. The layout takes the descriptor's size,
// the selected plane's pitch and offset; adrenoSetLinearDescriptor bounds it inside the surface and the resource.
- (void)adrenoSetLinearSurface:(IOSurfaceRef)s descriptor:(MTLTextureDescriptor *)d plane:(NSUInteger)plane {
    _linearKnown=NO;
    size_t planes=IOSurfaceGetPlaneCount(s), alloc=IOSurfaceGetAllocSize(s);
    NSUInteger compressedRow=AdrenoCompressedSurfaceRow(s,d);
    if(compressedRow) {
        // Apple's lossless-compressed surfaces ('&BGA' since v29, '&RhA' since v69; AdrenoCompressedSurfaceRow).
        // This GPU cannot read or write that encoding; every producer and consumer of such a surface here is this
        // plug-in, so it is one linear image of 64-byte-aligned rows inside the same allocation.
        static dispatch_once_t once;
        dispatch_once(&once, ^{ os_log(AdrenoResourceLog(), "IOSurface lossless format used as a linear image, row %lu",
                                       (unsigned long)compressedRow); });
        [self adrenoSetLinearDescriptor:d rowBytes:compressedRow offset:0 available:alloc];
        return;
    }
    if((planes && plane>=planes) || (!planes && plane)) {
        _linearWhy=[NSString stringWithFormat:@"IOSurface plane %lu of %zu planes",(unsigned long)plane,planes];
        return;
    }
    size_t bpe=planes ? IOSurfaceGetBytesPerElementOfPlane(s,plane) : IOSurfaceGetBytesPerElement(s);
    size_t ew=planes ? IOSurfaceGetElementWidthOfPlane(s,plane) : IOSurfaceGetElementWidth(s);
    size_t eh=planes ? IOSurfaceGetElementHeightOfPlane(s,plane) : IOSurfaceGetElementHeight(s);
    size_t sw=planes ? IOSurfaceGetWidthOfPlane(s,plane) : IOSurfaceGetWidth(s);
    size_t sh=planes ? IOSurfaceGetHeightOfPlane(s,plane) : IOSurfaceGetHeight(s);
    size_t row=planes ? IOSurfaceGetBytesPerRowOfPlane(s,plane) : IOSurfaceGetBytesPerRow(s);
    NSUInteger cpp=AdrenoLinearBytesPerPixel(d.pixelFormat), offset=0;
    if(!cpp) { _linearWhy=[NSString stringWithFormat:@"format %lu has no linear entry",(unsigned long)d.pixelFormat]; return; }
    if(ew!=1 || eh!=1 || bpe!=cpp) {
        _linearWhy=[NSString stringWithFormat:@"IOSurface element %zux%zu of %zu bytes, format %lu needs 1x1 of %lu",
                    ew,eh,bpe,(unsigned long)d.pixelFormat,(unsigned long)cpp];
        return;
    }
    if(sw<d.width || sh<d.height) {
        _linearWhy=[NSString stringWithFormat:@"IOSurface %zux%zu is smaller than the texture %lux%lu",sw,sh,
                    (unsigned long)d.width,(unsigned long)d.height];
        return;
    }
    if(planes) {
        // Selected plane offset: each plane base lies inside the one allocation.
        char *base=IOSurfaceGetBaseAddress(s), *p0=IOSurfaceGetBaseAddressOfPlane(s,plane);
        if(!base || !p0 || p0<base || (size_t)(p0-base)>=alloc) { _linearWhy=@"selected IOSurface plane lies outside its allocation"; return; }
        offset=(NSUInteger)(p0-base);
    }
    // Rows that are not 64-byte multiples (v82: CoreImage's 1,120-byte RGBA16F rows): an aligned shadow, for single-plane
    // single-level 2D surfaces at offset 0 only; aligned surfaces keep the zero-copy layout below.
    if((row&63) && !offset && planes<=1 && d.textureType==MTLTextureType2D && d.mipmapLevelCount==1 &&
       d.sampleCount==1 && d.arrayLength==1 && d.depth==1 && cpp==bpe) {
        AdrenoSurfaceShadow *shadow=AdrenoShadowForSurface(self.device,s,cpp);
        if(shadow) {
            static dispatch_once_t once;
            dispatch_once(&once, ^{ os_log(AdrenoResourceLog(), "IOSurface rows of %zu bytes use an aligned shadow of %lu",
                                           row,(unsigned long)shadow->_rowBytes); });
            _shadow=shadow;
            _linearGeometry=AdrenoGeometryFromDescriptor(d,shadow->_rowBytes);_linearGeometry.slices=1;
            _linearRootOffset=0;_linearLevelBase=0;_linearLevels=1;
            _linear=(AdrenoLinearTextureLayout){0,shadow->_rowBytes,d.width,d.height,
                [(IOGPUMetalResource *)shadow->_buffer resourceSize],d.pixelFormat};
            _linearKnown=YES;_linearWhy=nil;
            return;
        }
    }
    [self adrenoSetLinearDescriptor:d rowBytes:row offset:offset available:alloc];
}
- (id)adrenoShadowObject { return _shadow; }
// docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md B: a whole-texture view (level 0, slice 0 of a single-level,
// single-slice 2D parent) in a format of the same linear size aliases exactly the parent's bytes. It inherits the
// parent's layout only when the native view shares the parent's resource and size.
- (void)adrenoInheritLinearFrom:(AdrenoTexture *)parent format:(MTLPixelFormat)f whole:(BOOL)whole {
    [self adrenoInheritLinearFrom:parent format:f levels:NSMakeRange(0, parent.mipmapLevelCount) whole:whole];
}
// A 2D view of levels [location, location + length) of a 2D parent with a recorded layout (slice 0 of one slice):
// level 0 of the view is the parent's level `location`.
- (void)adrenoInheritLinearFrom:(AdrenoTexture *)parent format:(MTLPixelFormat)f levels:(NSRange)levels whole:(BOOL)whole {
    _linearKnown=NO;
    if(!whole || parent.textureType!=MTLTextureType2D || parent.arrayLength!=1 || !levels.length ||
       levels.location+levels.length>MAX(parent->_linearLevels,(NSUInteger)1)) {
        _linearWhy=@"view is not 2D levels of a single-slice 2D texture";
        return;
    }
    if(!parent->_linearKnown) {
        _linearWhy=[NSString stringWithFormat:@"view of a texture without a layout (%@)",parent->_linearWhy ?: @"none recorded"];
        return;
    }
    NSUInteger a=AdrenoLinearBytesPerPixel(parent->_linear.format), b=AdrenoLinearBytesPerPixel(f);
    if(!b || a!=b) {
        _linearWhy=[NSString stringWithFormat:@"view format %lu (%lu bytes) differs in size from %lu (%lu bytes)",(unsigned long)f,
                    (unsigned long)b,(unsigned long)parent->_linear.format,(unsigned long)a];
        return;
    }
    if([self resourceID]!=[parent resourceID] || [self resourceSize]!=[parent resourceSize] ||
       (!parent->_shadow && [self resourceSize]!=parent->_linear.allocationBytes)) {
        _linearWhy=[NSString stringWithFormat:@"view resource %u/%llu differs from its parent's %u/%llu",[self resourceID],
                    [self resourceSize],[parent resourceID],[parent resourceSize]];
        return;
    }
    AdrenoLinearTextureLayout first;
    if(![parent adrenoLinearLevel:levels.location layout:&first]) {
        _linearWhy=@"view's first level has no layout";
        return;
    }
    _linear=first;_linear.format=f;_shadow=parent->_shadow;
    _linearGeometry=parent->_linearGeometry;_linearRootOffset=parent->_linearRootOffset;
    _linearLevelBase=parent->_linearLevelBase+levels.location;_linearLevels=levels.length;
    _linearKnown=YES;_linearWhy=nil;
}
- (void)adrenoSetLinearUnknown:(NSString *)why { _linearKnown=NO;_linearWhy=why; }
- (BOOL)adrenoGetLinearLayout:(AdrenoLinearTextureLayout *)layout {
    if(!_linearKnown || !layout) return NO;
    *layout=_linear;return YES;
}
- (NSString *)adrenoLayoutDescription {
    if(_linearKnown)
        return [NSString stringWithFormat:@"(offset=%llu row=%llu %llux%llu alloc=%llu fmt=%lu)",_linear.offset,_linear.rowBytes,
                _linear.width,_linear.height,_linear.allocationBytes,(unsigned long)_linear.format];
    return [NSString stringWithFormat:@"none (%@)",_linearWhy ?: @"no constructor recorded one"];
}
- (BOOL)adrenoRefuseCPU:(const char *)why {
    if (!_cpuRefusalLogged) {
        _cpuRefusalLogged = YES;
        os_log_error(AdrenoResourceLog(), "texture %p (format %lu type %lu) CPU copy refused: %{public}s",
                     self, (unsigned long)self.pixelFormat, (unsigned long)self.textureType, why);
    }
    return NO;
}
// Resolve a CPU copy of region r of (level, slice) to its first byte and pitches, or refuse it.
// Every byte the copy touches is inside the texture's level and inside the CPU-visible allocation.
- (BOOL)adrenoCPURegion:(MTLRegion)r level:(NSUInteger)lvl slice:(NSUInteger)slice
            bytesPerRow:(NSUInteger)bpr bytesPerImage:(NSUInteger)bpi
                  start:(char **)start rowBytes:(NSUInteger *)rowBytes imageBytes:(NSUInteger *)imageBytes
                    bpp:(NSUInteger *)bppOut {
    if (!r.size.width || !r.size.height || !r.size.depth) return NO;               // nothing to copy
    if (!_cpu) return [self adrenoRefuseCPU:"no CPU-visible allocation"];
    MTLPixelFormat f = self.pixelFormat;
    NSUInteger bpp = AdrenoBytesPerPixel(f);
    if (AdrenoFormatIsBlockEncoded(f) || bpp != _root.bytesPerPixel) return [self adrenoRefuseCPU:"format has no linear pixel layout"];
    if (self.sampleCount > 1) return [self adrenoRefuseCPU:"multisample texture"];
    MTLTextureType type = self.textureType;
    if (lvl >= self.mipmapLevelCount || slice >= AdrenoSliceCount(type, self.arrayLength) ||
        (type == MTLTextureType3D && slice))
        return [self adrenoRefuseCPU:"level or slice outside the texture"];
    NSUInteger rootLevel = _levelBase + lvl, rootSlice = _sliceBase + slice;
    if (rootLevel >= _root.levels || rootSlice >= _root.slices) return [self adrenoRefuseCPU:"level or slice outside the allocation"];
    AdrenoSubresourceLayout s = AdrenoTextureSubresource(&_root, rootLevel, rootSlice);
    if (r.origin.x > s.width || r.size.width > s.width - r.origin.x ||
        r.origin.y > s.height || r.size.height > s.height - r.origin.y ||
        r.origin.z > s.depth || r.size.depth > s.depth - r.origin.z)
        return [self adrenoRefuseCPU:"region outside the level"];
    NSUInteger rowPayload = r.size.width * bpp;
    if (s.rowBytes < s.width * bpp || bpr < rowPayload ||
        (r.size.depth > 1 && bpi < bpr * (r.size.height - 1) + rowPayload))
        return [self adrenoRefuseCPU:"row or image pitch too small"];
    NSUInteger first = s.offset + r.origin.z * s.imageBytes + r.origin.y * s.rowBytes + r.origin.x * bpp;
    NSUInteger last = first + (r.size.depth - 1) * s.imageBytes + (r.size.height - 1) * s.rowBytes + rowPayload;
    if (last > _cpuBytes) return [self adrenoRefuseCPU:"subresource exceeds the CPU-visible allocation"];
    *start = _cpu + first; *rowBytes = s.rowBytes; *imageBytes = s.imageBytes; *bppOut = bpp;
    return YES;
}
- (void)replaceRegion:(MTLRegion)r mipmapLevel:(NSUInteger)lvl slice:(NSUInteger)slice withBytes:(const void *)b
          bytesPerRow:(NSUInteger)bpr bytesPerImage:(NSUInteger)bpi {
    char *dst; NSUInteger rb, ib, bpp;
    if (!b || ![self adrenoCPURegion:r level:lvl slice:slice bytesPerRow:bpr bytesPerImage:bpi
                               start:&dst rowBytes:&rb imageBytes:&ib bpp:&bpp]) return;
    for (NSUInteger z = 0; z < r.size.depth; z++)
        for (NSUInteger y = 0; y < r.size.height; y++)
            memcpy(dst + z * ib + y * rb, (const char *)b + z * bpi + y * bpr, r.size.width * bpp);
    [_shadow markDirty];   // the surface changed without a seed change: refill the shadow before the next GPU use
}
- (void)getBytes:(void *)b bytesPerRow:(NSUInteger)bpr bytesPerImage:(NSUInteger)bpi fromRegion:(MTLRegion)r
     mipmapLevel:(NSUInteger)lvl slice:(NSUInteger)slice {
    char *src; NSUInteger rb, ib, bpp;
    if (!b || ![self adrenoCPURegion:r level:lvl slice:slice bytesPerRow:bpr bytesPerImage:bpi
                               start:&src rowBytes:&rb imageBytes:&ib bpp:&bpp]) return;
    for (NSUInteger z = 0; z < r.size.depth; z++)
        for (NSUInteger y = 0; y < r.size.height; y++)
            memcpy((char *)b + z * bpi + y * bpr, src + z * ib + y * rb, r.size.width * bpp);
}
- (id<MTLTexture>)newTextureViewWithPixelFormat:(MTLPixelFormat)f {
    AdrenoTexture *texture=[[AdrenoTexture alloc] initWithTexture:self pixelFormat:f];
    [texture adrenoSetUsage:self.usage];
    [texture adrenoInheritCPUFrom:self levels:NSMakeRange(0, 0) slices:NSMakeRange(0, 0)];
    [texture adrenoInheritLinearFrom:self format:f whole:YES];
    return texture;
}
- (id<MTLTexture>)newTextureViewWithPixelFormat:(MTLPixelFormat)f textureType:(MTLTextureType)t levels:(NSRange)l slices:(NSRange)s {
    AdrenoTexture *texture=[[AdrenoTexture alloc] initWithTexture:self pixelFormat:f textureType:t levels:l slices:s];
    [texture adrenoSetUsage:self.usage];
    [texture adrenoInheritCPUFrom:self levels:l slices:s];
    [texture adrenoInheritLinearFrom:self format:f levels:l whole:t == MTLTextureType2D && s.location == 0 && s.length == 1];
    return texture;
}
@end

BOOL AdrenoLinearLayoutAtLevel(id<MTLTexture> texture, NSUInteger level, AdrenoLinearTextureLayout *out) {
    return [texture isKindOfClass:[AdrenoTexture class]] && [(AdrenoTexture *)texture adrenoLinearLevel:level layout:out];
}
// Apple's lossless-compressed IOSurfaces paired with the one texture format each holds: the linear row this plug-in
// uses for the surface, else 0. Only these exact pairs; every other fourcc keeps the ordinary element checks.
//   '&BGA' (kCVPixelFormatType_Lossless_32BGRA, 16x16 tiles of 1024 bytes) with BGRA8: v29, ControlCenter's layers
//   '&RhA' (lossless RGBA16Float, 16x16 tiles of 2048 bytes) with RGBA16Float: v69, NotificationCenter/WindowServer
NSUInteger AdrenoCompressedSurfaceRow(IOSurfaceRef s, MTLTextureDescriptor *d) {
    if (!s || IOSurfaceGetPlaneCount(s) > 1 || d.textureType != MTLTextureType2D || d.mipmapLevelCount != 1 ||
        !d.width || !d.height || d.width > IOSurfaceGetWidth(s) || d.height > IOSurfaceGetHeight(s))
        return 0;
    NSUInteger cpp;
    switch (IOSurfaceGetPixelFormat(s)) {
    case 0x26424741: /* '&BGA' */
        if (d.pixelFormat != MTLPixelFormatBGRA8Unorm && d.pixelFormat != MTLPixelFormatBGRA8Unorm_sRGB) return 0;
        cpp = 4;
        break;
    case 0x26526841: /* '&RhA' */
        if (d.pixelFormat != MTLPixelFormatRGBA16Float) return 0;
        cpp = 8;
        break;
    default:
        return 0;
    }
    NSUInteger row = AdrenoAlign(IOSurfaceGetWidth(s) * cpp, kAdrenoPitchAlign);
    return (uint64_t)row * IOSurfaceGetHeight(s) <= IOSurfaceGetAllocSize(s) ? row : 0;
}
id<MTLTexture> AdrenoNewTexture(id<MTLDevice> dev, MTLTextureDescriptor *d, IOSurfaceRef s, NSUInteger plane) {
    AdrenoNewResourceArgs a; AdrenoArgsInit(&a, (uint32_t)d.pixelFormat);
    AdrenoTexture *t;
    const BOOL plausible = d && d.width && d.height;
    if (s) {
        for (int attempt = 0;; attempt++) {
            t = [[AdrenoTexture alloc] initWithDevice:dev descriptor:d iosurface:s plane:(unsigned)plane field:0
                                                 args:&a argsSize:sizeof a];
            if (attempt) AdrenoStagingRetried(t != nil);
            if (t || attempt || !plausible || !AdrenoStagingRelieveAfterFailure()) break;   // A8: one retry after relief
            AdrenoArgsInit(&a, (uint32_t)d.pixelFormat);
        }
        [t adrenoSetUsage:d.usage];
        // IOSurface CPU view for replaceRegion/getBytes (surfaces are locked by their producers).
        char *base = IOSurfaceGetBaseAddress(s);
        char *planeBase = IOSurfaceGetPlaneCount(s) ? IOSurfaceGetBaseAddressOfPlane(s, plane) : plane ? NULL : base;
        size_t planeRowBytes = IOSurfaceGetPlaneCount(s) ? IOSurfaceGetBytesPerRowOfPlane(s, plane) : IOSurfaceGetBytesPerRow(s);
        if (AdrenoCompressedSurfaceRow(s, d)) planeRowBytes = AdrenoCompressedSurfaceRow(s, d);   // the same linear rows as the GPU
        size_t alloc = IOSurfaceGetAllocSize(s);
        if (t && base && planeBase >= base && (size_t)(planeBase - base) < alloc) {
            AdrenoTextureGeometry g = AdrenoGeometryFromDescriptor(d, planeRowBytes);
            g.levels = 1; g.slices = 1;
            [t adrenoSetCPU:planeBase bytes:alloc - (size_t)(planeBase - base) geometry:&g];
        }
        // The linear layout of plane 0 (adrenoSetLinearSurface: records why when there is none).
        if(t) [t adrenoSetLinearSurface:s descriptor:d plane:plane];
        return t;
    }
    NSUInteger rb = (d.width * AdrenoBytesPerPixel(d.pixelFormat) + kAdrenoPitchAlign - 1) & ~(kAdrenoPitchAlign - 1);
    AdrenoTextureGeometry g = AdrenoGeometryFromDescriptor(d, rb);
    uint64_t sz = (uint64_t)rb * d.height * MAX(d.depth, 1) * MAX(d.arrayLength, 1) * 2;   // single-level sizes unchanged
    sz = MAX(sz, (uint64_t)AdrenoTextureAllocationBytes(&g));   // every level and slice (cube faces included) fits
    // A depth/stencil render target also holds its TILE6_3 buffer (AdrenoZSLayoutOf; 4096-byte slack for the base).
    AdrenoZSLayout zs;
    if ((d.usage & MTLTextureUsageRenderTarget) && AdrenoZSLayoutOf(d.pixelFormat, d.width, d.height, &zs))
        sz = MAX(sz, zs.layerBytes + 4096);
    sz = (sz + 16383) & ~16383ull;
    for (int attempt = 0;; attempt++) {
        t = [[AdrenoTexture alloc] initWithDevice:dev descriptor:d sysMemSize:sz sysMemRowBytes:rb vidMemSize:0 vidMemRowBytes:0
                                             args:&a argsSize:sizeof a];
        if (attempt) AdrenoStagingRetried(t != nil);
        if (t || attempt || !plausible || !AdrenoStagingRelieveAfterFailure()) break;       // A8: one retry after relief
        AdrenoArgsInit(&a, (uint32_t)d.pixelFormat);
    }
    [t adrenoSetUsage:d.usage];
    if(t) [t adrenoSetLinearDescriptor:d rowBytes:rb available:sz];
    // Shared allocations are mapped into this task by IOGPU; private ones have no CPU address.
    uint64_t mapped = t ? [t resourceSize] : 0;
    if (t && [t virtualAddress] && mapped) [t adrenoSetCPU:[t virtualAddress] bytes:(NSUInteger)MIN(mapped, sz) geometry:&g];
    return t;
}
id<MTLTexture> AdrenoNewTextureNoCopy(id<MTLDevice> dev, MTLTextureDescriptor *d, void *bytes, NSUInteger len,
                                      void (^dealloc)(void *, NSUInteger)) {
    AdrenoNewResourceArgs a; AdrenoArgsInit(&a, (uint32_t)d.pixelFormat);
    NSUInteger rb = (d.width * AdrenoBytesPerPixel(d.pixelFormat) + kAdrenoPitchAlign - 1) & ~(kAdrenoPitchAlign - 1);
    AdrenoTexture *t = [[AdrenoTexture alloc] initWithDevice:dev descriptor:d sysMemPointer:bytes sysMemSize:len
                                                sysMemLength:len sysMemRowBytes:rb args:&a argsSize:sizeof a deallocator:dealloc];
    if (!t && d && d.width && d.height) (void)AdrenoStagingRelieveAfterFailure();   // A8: relief only (no-copy: no retry)
    [t adrenoSetUsage:d.usage];
    AdrenoTextureGeometry g = AdrenoGeometryFromDescriptor(d, rb);
    if (t) [t adrenoSetCPU:bytes bytes:len geometry:&g];
    if (t) [t adrenoSetLinearDescriptor:d rowBytes:rb available:len];
    return t;
}

NSString *AdrenoDescribeTarget(id<MTLTexture> t) {
    if (!t) return @"none";
    @try {
        NSMutableString *s = [NSMutableString stringWithFormat:@"%s fmt=%lu %lux%lu type=%lu mips=%lu samples=%lu array=%lu depth=%lu "
            "usage=0x%lx storage=%lu", object_getClassName(t), (unsigned long)t.pixelFormat, (unsigned long)t.width,
            (unsigned long)t.height, (unsigned long)t.textureType, (unsigned long)t.mipmapLevelCount, (unsigned long)t.sampleCount,
            (unsigned long)t.arrayLength, (unsigned long)t.depth, (unsigned long)t.usage, (unsigned long)t.storageMode];
        id<MTLTexture> parent = t.parentTexture;
        if (parent)
            [s appendFormat:@" view-of(fmt=%lu %lux%lu level=%lu slice=%lu)", (unsigned long)parent.pixelFormat,
             (unsigned long)parent.width, (unsigned long)parent.height, (unsigned long)t.parentRelativeLevel,
             (unsigned long)t.parentRelativeSlice];
        IOSurfaceRef surface = t.iosurface;
        if (surface) {
            uint32_t f = IOSurfaceGetPixelFormat(surface);
            char cc[5] = {(char)(f >> 24), (char)(f >> 16), (char)(f >> 8), (char)f, 0};
            for (int i = 0; i < 4; i++) if (cc[i] < 0x20 || cc[i] > 0x7e) cc[i] = '?';
            [s appendFormat:@" iosurface='%s' %zux%zu bpe=%zu row=%zu planes=%zu alloc=%zu plane=%lu", cc,
             IOSurfaceGetWidth(surface), IOSurfaceGetHeight(surface), IOSurfaceGetBytesPerElement(surface),
             IOSurfaceGetBytesPerRow(surface), IOSurfaceGetPlaneCount(surface), IOSurfaceGetAllocSize(surface),
             (unsigned long)t.iosurfacePlane];
        }
        if (t.buffer)
            [s appendFormat:@" buffer(offset=%lu bpr=%lu length=%lu)", (unsigned long)t.bufferOffset,
             (unsigned long)t.bufferBytesPerRow, (unsigned long)t.buffer.length];
        if ([(id)t isKindOfClass:[IOGPUMetalTexture class]])
            [s appendFormat:@" resource=%u/%llu", [(IOGPUMetalTexture *)t resourceID], [(IOGPUMetalTexture *)t resourceSize]];
        [s appendFormat:@" layout=%@", [(id)t respondsToSelector:@selector(adrenoLayoutDescription)] ?
            [(AdrenoTexture *)t adrenoLayoutDescription] : @"none (not an Adreno texture)"];
        return s;
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"%s (description failed: %@)", object_getClassName(t), e.reason];
    }
}

@implementation AdrenoSamplerState {
    MTLSamplerDescriptor *_adrenoSamplerDescriptor;
}
- (instancetype)initWithDevice:(id<MTLDevice>)device samplerDescriptor:(MTLSamplerDescriptor *)descriptor {
    if ((self = [super initWithDevice:device samplerDescriptor:descriptor]))
        _adrenoSamplerDescriptor = [descriptor copy];
    return self;
}
- (MTLSamplerDescriptor *)adrenoSamplerDescriptor { return _adrenoSamplerDescriptor; }
@end
// The descriptor the draw path reads (AdrenoDrawCommands.m ZSA); _MTLDepthStencilState keeps no public copy.
@implementation AdrenoDepthStencilState {
    MTLDepthStencilDescriptor *_adrenoDepthStencilDescriptor;
}
- (instancetype)initWithDevice:(id<MTLDevice>)device depthStencilDescriptor:(MTLDepthStencilDescriptor *)descriptor {
    if ((self = [super initWithDevice:device depthStencilDescriptor:descriptor]))
        _adrenoDepthStencilDescriptor = [descriptor copy] ?: [MTLDepthStencilDescriptor new];
    return self;
}
- (MTLDepthStencilDescriptor *)adrenoDepthStencilDescriptor { return _adrenoDepthStencilDescriptor; }
@end

id AdrenoGPUBacking(id resource) {
    if (![resource isKindOfClass:[AdrenoTexture class]]) return resource;
    AdrenoSurfaceShadow *shadow=[(AdrenoTexture *)resource adrenoShadowObject];
    if (!shadow) return resource;
    [shadow syncIfNeeded];
    return shadow->_buffer;
}
uint64_t AdrenoGPUBackingSize(id resource) {
    AdrenoSurfaceShadow *shadow=[resource isKindOfClass:[AdrenoTexture class]] ? [(AdrenoTexture *)resource adrenoShadowObject] : nil;
    id backing=shadow ? shadow->_buffer : resource;
    return [backing isKindOfClass:[IOGPUMetalResource class]] ? [(IOGPUMetalResource *)backing resourceSize] : 0;
}
