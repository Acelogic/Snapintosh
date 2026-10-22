/* SPDX-License-Identifier: MIT */
// AdrenoDrawCommands.m - a8xx sysmem draw packets for ADRENO_KCMD_IB packages. See AdrenoDrawCommands.h.
//
// Function names follow q1n1 (3f2966d): RD = tools/a16gpu_render.py, M = tools/a16gpu_p6p7.py,
// B = tools/a16gpu_bindings.py. Register sequences are M/RD's (gallium's a8xx sysmem batch), in their order, so
// a package's IB equals RD.build_ib dword for dword once addresses are normalised (tools/test-adreno-draw-package.py).
#import "AdrenoDrawCommands.h"
#import "AdrenoTextureBindings.h"
#import <os/log.h>
#import "AdrenoShader.h"
extern void AdrenoLogZeroTexture(NSString *function, NSString *argument, NSInteger index);   // AdrenoCommandBuffer.m
#import <objc/runtime.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <math.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "AdrenoStagingPolicy.h"
#if ADRENO_UBO_MIRROR
#include "AdrenoCodeScan.h"
#endif

#if ADRENO_PERF_COUNTERS
static _Atomic uint64_t gAdrenoPerfRenderPasses, gAdrenoPerfDraws, gAdrenoPerfDwords, gAdrenoPerfOtherPasses;
void AdrenoPerfCounters(uint64_t out[4]) {
    out[0] = atomic_load(&gAdrenoPerfRenderPasses); out[1] = atomic_load(&gAdrenoPerfDraws);
    out[2] = atomic_load(&gAdrenoPerfOtherPasses); out[3] = atomic_load(&gAdrenoPerfDwords) / 1000;
}
#endif

// ================================================================================================================
// Refusals and field packing (M.pack / M._field_bits)
// ================================================================================================================
// A Metal state or program this builder does not build: explicit, never approximated.
__attribute__((noreturn)) static void AdrenoDrawRefuse(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void AdrenoDrawRefuse(NSString *format, ...) {
    va_list ap;
    va_start(ap, format);
    NSString *reason = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    @throw [NSException exceptionWithName:NSInvalidArgumentException
                                   reason:[@"Adreno draw: " stringByAppendingString:reason] userInfo:nil];
}
// A value the builder itself computed does not fit its field: a builder bug.
__attribute__((noreturn)) static void AdrenoDrawBug(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
static void AdrenoDrawBug(NSString *format, ...) {
    va_list ap;
    va_start(ap, format);
    NSString *reason = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[@"Adreno draw builder: " stringByAppendingString:reason] userInfo:nil];
}

// M._field_bits for integer/boolean/enum fields: shr must divide the value, the result must fit.
static uint64_t AdrenoField(const char *name, unsigned shift, unsigned width, unsigned shr, uint64_t value) {
    if (shr && (value & ((1ull << shr) - 1)))
        AdrenoDrawBug(@"%s: %#llx is not a multiple of %u", name, value, 1u << shr);
    uint64_t bits = value >> shr;
    if (width < 64 && (bits >> width)) AdrenoDrawBug(@"%s: %#llx does not fit in %u bits", name, value, width);
    return bits << shift;
}
// M._field_bits for fixed/ufixed fields: gen_header's truncating cast, masked to the width.
static uint64_t AdrenoFixed(unsigned shift, unsigned width, unsigned radix, double value) {
    int64_t scaled = (int64_t)(value * (double)(1u << radix));
    return ((uint64_t)scaled & ((1ull << width) - 1)) << shift;
}
static uint32_t AdrenoF32(double value) {
    float f = (float)value;
    uint32_t bits;
    memcpy(&bits, &f, sizeof bits);
    return bits;
}
static uint32_t AdrenoRegIndex(const char *name, uint32_t base, uint32_t stride, uint32_t count, uint64_t index) {
    if (index >= count) AdrenoDrawBug(@"%s[%llu] outside its %u entries", name, index, count);
    return base + (uint32_t)index * stride;
}

#define E(NAME) ((uint64_t)A8XX_E_##NAME)
#define AF(REG, FIELD, v) AdrenoField(#REG "." #FIELD, A8XX_REG_##REG##__##FIELD##__SHIFT, \
    A8XX_REG_##REG##__##FIELD##__WIDTH, 0, (uint64_t)(v))
#define AFS(REG, FIELD, v) AdrenoField(#REG "." #FIELD, A8XX_REG_##REG##__##FIELD##__SHIFT, \
    A8XX_REG_##REG##__##FIELD##__WIDTH, A8XX_REG_##REG##__##FIELD##__SHR, (uint64_t)(v))
#define AFIX(REG, FIELD, radix, v) AdrenoFixed(A8XX_REG_##REG##__##FIELD##__SHIFT, A8XX_REG_##REG##__##FIELD##__WIDTH, \
    (radix), (v))
#define PF(PKT, FIELD, v) ((uint32_t)AdrenoField(#PKT "." #FIELD, A8XX_PKT_##PKT##__##FIELD##__SHIFT, \
    A8XX_PKT_##PKT##__##FIELD##__WIDTH, 0, (uint64_t)(v)))
#define DF(DESC, FIELD, v) ((uint32_t)AdrenoField(#DESC "." #FIELD, A8XX_DESC_##DESC##__##FIELD##__SHIFT, \
    A8XX_DESC_##DESC##__##FIELD##__WIDTH, 0, (uint64_t)(v)))
#define DFS(DESC, FIELD, v) ((uint32_t)AdrenoField(#DESC "." #FIELD, A8XX_DESC_##DESC##__##FIELD##__SHIFT, \
    A8XX_DESC_##DESC##__##FIELD##__WIDTH, A8XX_DESC_##DESC##__##FIELD##__SHR, (uint64_t)(v)))
#define DFIX(DESC, FIELD, radix, v) ((uint32_t)AdrenoFixed(A8XX_DESC_##DESC##__##FIELD##__SHIFT, \
    A8XX_DESC_##DESC##__##FIELD##__WIDTH, (radix), (v)))
#define REGI(NAME, i) AdrenoRegIndex(#NAME, A8XX_REG_##NAME, A8XX_REG_##NAME##__ARRAY_STRIDE, \
    A8XX_REG_##NAME##__ARRAY_COUNT, (uint64_t)(i))

#define INVALID_REG 0xFCu                   // M.INVALID_REG: regid(63, 0), ir3's "no register"
#define SLOT_POS 0                           // gl_varying_slot VARYING_SLOT_POS
#define FRAG_RESULT_DEPTH 0                  // shader_enums.h
#define FRAG_RESULT_STENCIL 1
#define FRAG_RESULT_DATA0 4
#define VARYING_SLOT_PSIZ 12                 // shader_enums.h: [[point_size]] (BINDING-ABI 4.4)
#define VARYING_SLOT_LAYER 22                // RD.VARYING_SLOT_LAYER / VIEWPORT
#define VARYING_SLOT_VIEWPORT 23
#define VARYING_SLOT_PNTC 25                 // shader_enums.h: [[point_coord]] (BINDING-ABI 4.3)
#define INTERP_FLAT 1u                       // a6xx_interp_mode
#define INTERP_ZERO 2u
#define INTERP_ONE 3u
#define PS_REPL_S 1u                         // a6xx_varying_ps_repl_mode
#define PS_REPL_T 2u
// Metal's point sizes on the host AGX (M3 Max, measured): size 0 draws nothing, larger sizes clamp to 511 pixels.
#define ADRENO_POINT_SIZE_MIN 0.0
#define ADRENO_POINT_SIZE_MAX 511.0
#define ADRENO_UBO_SLOTS 16                  // B.UBO_SLOTS: the non-bindless UBO descriptors a8xx honours
#define ADRENO_DRIVER_TABLE_BYTES 384u       // B.DRIVER_TABLE_BYTES
#define ADRENO_ZERO_SET_BYTES 0x1000u        // RD: border colour table / empty bindless sets (one r_misc page)
#define ADRENO_UBO_MAX_BYTES (0x7fffull * 16) // A6XX_UBO_1 SIZE: 15 bits of vec4
#define ADRENO_FB_SET 4                      // ir3_shader_descriptor_set(MESA_SHADER_FRAGMENT): framebuffer reads
#define ADRENO_FB_DESCRIPTOR 55              // IR3_BINDLESS_IMAGE_OFFSET + IR3_BINDLESS_IMAGE_COUNT - 1 - 8: colour n is 55 + n

// ================================================================================================================
// Addresses, register lists and the command stream (M.CS; M.Window.addr becomes a relocation)
// ================================================================================================================
enum { ADRENO_SPACE_IB = 0, ADRENO_SPACE_DATA = 1, ADRENO_SPACE_NONE = 2 };

typedef struct {
    uint8_t kind, access, alignLog2, hiBits;
    uint32_t resourceID;
    uint64_t offset, length;            // PACKAGE: offset inside the pass (later package) data area
    __unsafe_unretained id _Nullable resource;
} AdrenoAddr;

typedef struct {
    uint8_t loSpace, hiSpace, kind, access, alignLog2, hiBits;
    uint32_t resourceID;
    uint64_t lo, hi, offset, length;    // lo/hi: IB dword index or data byte offset (by space)
} AdrenoRelocDraft;

static AdrenoAddr AdrenoZeroAddr(void) {
    return (AdrenoAddr){ADRENO_IB_RELOC_ZERO, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_TEXTURE, 0, 0, 0,
                        ADRENO_ZERO_SET_BYTES, nil};
}
static AdrenoAddr AdrenoPackageAddr(uint64_t dataOffset, uint64_t length, uint8_t alignLog2) {
    return (AdrenoAddr){ADRENO_IB_RELOC_PACKAGE, ADRENO_IB_ACCESS_READ, alignLog2, 0, 0, dataOffset, length, nil};
}
static AdrenoAddr AdrenoResourceAddr(id resource, uint64_t offset, uint64_t length, uint8_t access,
                                     uint8_t alignLog2, NSString *what) {
    resource = AdrenoGPUBacking(resource);   // a shadowed IOSurface texture's aligned shadow (filled first if stale)
    if (![resource isKindOfClass:[IOGPUMetalResource class]])
        AdrenoDrawRefuse(@"%@ is not a native IOGPU resource", what);
    IOGPUMetalResource *native = resource;
    uint32_t rid = [native resourceID];
    uint64_t size = [native resourceSize];
    if (!rid) AdrenoDrawRefuse(@"%@ has no IOGPU resource identifier", what);
    if (!length || offset > size || length > size - offset)
        AdrenoDrawRefuse(@"%@: bytes %#llx+%#llx outside its %#llx-byte allocation", what, offset, length, size);
    if (offset & ((1ull << alignLog2) - 1))
        AdrenoDrawRefuse(@"%@: offset %#llx is not %u-byte aligned", what, offset, 1u << alignLog2);
    return (AdrenoAddr){ADRENO_IB_RELOC_RESOURCE, access, alignLog2, 0, rid, offset, length, resource};
}

typedef struct { uint32_t offset, value; int16_t addr; uint8_t half; } AdrenoPair;
#define ADRENO_REGS_MAX 640
#define ADRENO_REGS_ADDRS 48
typedef struct {
    uint32_t n, naddr;
    AdrenoPair p[ADRENO_REGS_MAX];
    AdrenoAddr addr[ADRENO_REGS_ADDRS];
} AdrenoRegs;

static void regs_reset(AdrenoRegs *r) { r->n = r->naddr = 0; }
static void R32(AdrenoRegs *r, uint32_t offset, uint64_t value) {
    if (value > 0xffffffffull) AdrenoDrawBug(@"register %#x value %#llx exceeds 32 bits", offset, value);
    if (r->n >= ADRENO_REGS_MAX) AdrenoDrawBug(@"register list overflow");
    r->p[r->n++] = (AdrenoPair){offset, (uint32_t)value, -1, 0};
}
static void R64(AdrenoRegs *r, uint32_t offset, uint64_t value) {
    R32(r, offset, value & 0xffffffffull);
    R32(r, offset + 1, value >> 32);
}
// A 64-bit address register: the low dword keeps the fields below the alignment (placeholder rule), both halves
// are relocation targets.
static void RADDR(AdrenoRegs *r, uint32_t offset, uint64_t lowBits, AdrenoAddr a) {
    if (r->naddr >= ADRENO_REGS_ADDRS) AdrenoDrawBug(@"address list overflow");
    if (lowBits >> a.alignLog2) AdrenoDrawBug(@"register %#x keeps bits %#llx above its address alignment", offset, lowBits);
    int16_t k = (int16_t)r->naddr;
    a.hiBits = ADRENO_IB_HI_BITS_REG64;
    r->addr[r->naddr++] = a;
    R32(r, offset, lowBits);
    r->p[r->n - 1].addr = k; r->p[r->n - 1].half = 0;
    R32(r, offset + 1, 0);
    r->p[r->n - 1].addr = k; r->p[r->n - 1].half = 1;
}
#define REG32(r, NAME, i, v) do { \
    _Static_assert(A8XX_REG_##NAME##__BIT_SIZE == 32, #NAME " is a 32-bit register"); \
    R32((r), REGI(NAME, (i)), (v)); } while (0)
#define REG64(r, NAME, i, v) do { \
    _Static_assert(A8XX_REG_##NAME##__BIT_SIZE == 64, #NAME " is a 64-bit register"); \
    R64((r), REGI(NAME, (i)), (v)); } while (0)
#define REGADDR(r, NAME, i, low, a) do { \
    _Static_assert(A8XX_REG_##NAME##__BIT_SIZE == 64, #NAME " is a 64-bit register"); \
    RADDR((r), REGI(NAME, (i)), (low), (a)); } while (0)

// One pass (later: one package) of command-stream words, data and relocations.
@interface AdrenoCS : NSObject {
@public
    NSMutableData *_w;          // IB dwords
    NSMutableData *_data;       // data area (T#/S# arrays, setBytes, driver tables), 64-byte aligned chunks
    NSMutableData *_relocs;     // AdrenoRelocDraft
    NSMapTable *_usage;         // IOGPU resource -> NSNumber(MTLResourceUsage), identity keys
    id<MTLBuffer> _staging;     // aligned UBO staging arena: 64-byte slices, retained through _usage until retirement
    uint64_t _stagingUsed;
    NSMutableArray *_arenas;    // the pool-size arenas this stream took (recycled after GPU completion, C3); a continued
                                // arena is its command buffer's and is not listed again
    NSMutableArray *_record;    // a recording stream (AdrenoDrawPlan): each relocation's resource (or NSNull), in order
    // cs_use's cache (C6): a resource and a usage its _usage entry already contains; keys are _usage keys, which the map
    // holds for the stream's life.
    __unsafe_unretained id _useKey[8];
    MTLResourceUsage _useValue[8];
}
@end
@implementation AdrenoCS
- (instancetype)init {
    if ((self = [super init])) {
        _w = [NSMutableData data];
        _data = [NSMutableData data];
        _relocs = [NSMutableData data];
        _usage = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsStrongMemory | NSPointerFunctionsObjectPointerPersonality
                                       valueOptions:NSPointerFunctionsStrongMemory];
    }
    return self;
}
@end

static uint64_t cs_dwords(AdrenoCS *cs) { return cs->_w.length / 4; }
static void cs_raw(AdrenoCS *cs, uint32_t word) { [cs->_w appendBytes:&word length:sizeof word]; }
static void cs_pkt7(AdrenoCS *cs, uint64_t opcode, const uint32_t *payload, uint32_t count) {
    if (opcode > A8XX_PKT7_OPCODE_MASK || count > A8XX_PKT7_COUNT_MASK)
        AdrenoDrawBug(@"pkt7 opcode %#llx count %u", opcode, count);
    cs_raw(cs, a8xx_pkt7_hdr((uint32_t)opcode, count));
    if (count) [cs->_w appendBytes:payload length:4u * count];
}
#define PKT7(cs, op, ...) do { const uint32_t _payload[] = {__VA_ARGS__}; \
    cs_pkt7((cs), (op), _payload, (uint32_t)(sizeof _payload / sizeof *_payload)); } while (0)

// The stream's usage of a relocated resource: the union of every relocation's access.
static void cs_use(AdrenoCS *cs, id resource, uint8_t access) {
    MTLResourceUsage use = ((access & ADRENO_IB_ACCESS_READ) ? MTLResourceUsageRead : 0) |
                           ((access & ADRENO_IB_ACCESS_WRITE) ? MTLResourceUsageWrite : 0);
    const unsigned h = (unsigned)(((uint64_t)(uintptr_t)(__bridge void *)resource * 0x9E3779B97F4A7C15ull) >> 61);
    if (cs->_useKey[h] == resource && (cs->_useValue[h] | use) == cs->_useValue[h]) return;   // already in the map
    NSNumber *old = [cs->_usage objectForKey:resource];
    // The union only grows: store it when the resource is new or gains an access (an equal value is not re-stored).
    const MTLResourceUsage now = old.unsignedIntegerValue | use;
    if (!old || now != old.unsignedIntegerValue) [cs->_usage setObject:@(now) forKey:resource];
    cs->_useKey[h] = resource; cs->_useValue[h] = now;
}
static void cs_reloc(AdrenoCS *cs, uint8_t loSpace, uint64_t lo, uint8_t hiSpace, uint64_t hi, uint8_t hiBits,
                     AdrenoAddr a) {
    if (!a.length || a.alignLog2 > ADRENO_IB_RELOC_MAX_ALIGN_LOG2) AdrenoDrawBug(@"address range or alignment");
    if (a.kind == ADRENO_IB_RELOC_RESOURCE) {
        if (!a.resource || !a.resourceID || !a.access || (a.access & ~(ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE)))
            AdrenoDrawBug(@"resource relocation without resource or access");
        cs_use(cs, a.resource, a.access);
    } else if (a.access != ADRENO_IB_ACCESS_READ || a.resource || a.resourceID) {
        AdrenoDrawBug(@"package/zero relocations are read-only and name no resource");
    }
    AdrenoRelocDraft d = {loSpace, hiSpace, a.kind, a.access, a.alignLog2, hiBits, a.resourceID, lo, hi, a.offset,
                          a.length};
    [cs->_relocs appendBytes:&d length:sizeof d];
    if (cs->_record) [cs->_record addObject:a.resource ?: (id)[NSNull null]];
}
static void cs_regs_relocs(AdrenoCS *cs, const AdrenoRegs *r, uint64_t first, uint64_t stride) {
    // One pass over the pairs (the last pair naming a half wins, as in a per-address scan), then the relocations in
    // address order.
    uint64_t lo[ADRENO_REGS_ADDRS], hi[ADRENO_REGS_ADDRS];
    for (uint32_t k = 0; k < r->naddr; k++) lo[k] = hi[k] = UINT64_MAX;
    for (uint32_t i = 0; i < r->n; i++) {
        int16_t k = r->p[i].addr;
        if (k < 0 || (uint32_t)k >= r->naddr) continue;
        if (r->p[i].half) hi[k] = first + stride * i; else lo[k] = first + stride * i;
    }
    for (uint32_t k = 0; k < r->naddr; k++) {
        if (lo[k] == UINT64_MAX || hi[k] == UINT64_MAX) AdrenoDrawBug(@"address register without both halves");
        cs_reloc(cs, ADRENO_SPACE_IB, lo[k], ADRENO_SPACE_IB, hi[k], r->addr[k].hiBits, r->addr[k]);
    }
}
// Packets are built in a stack buffer and appended with one call (not one message per dword).
// fd_pkt4: one PKT4 over consecutive registers.
static void cs_pkt4(AdrenoCS *cs, const AdrenoRegs *r) {
    if (!r->n || r->n > A8XX_PKT4_COUNT_MASK || r->p[0].offset > A8XX_PKT4_REG_MASK) AdrenoDrawBug(@"pkt4 shape");
    for (uint32_t i = 1; i < r->n; i++)
        if (r->p[i].offset != r->p[i - 1].offset + 1)
            AdrenoDrawBug(@"PKT4 registers not consecutive: %#x, %#x", r->p[i - 1].offset, r->p[i].offset);
    uint64_t start = cs_dwords(cs);
    uint32_t words[1 + ADRENO_REGS_MAX];
    words[0] = a8xx_pkt4_hdr(r->p[0].offset, r->n);
    for (uint32_t i = 0; i < r->n; i++) words[1 + i] = r->p[i].value;
    [cs->_w appendBytes:words length:4u * (1 + r->n)];
    cs_regs_relocs(cs, r, start + 1, 1);
}
// CP_CONTEXT_REG_BUNCH: (offset, value) pairs (fd_crb).
static void cs_crb(AdrenoCS *cs, const AdrenoRegs *r) {
    if (2u * r->n > A8XX_PKT7_COUNT_MASK) AdrenoDrawBug(@"CRB too long");
    uint64_t start = cs_dwords(cs);
    uint32_t words[1 + 2 * ADRENO_REGS_MAX];
    words[0] = a8xx_pkt7_hdr(A8XX_E_CP_CONTEXT_REG_BUNCH, 2u * r->n);
    for (uint32_t i = 0; i < r->n; i++) { words[1 + 2 * i] = r->p[i].offset; words[2 + 2 * i] = r->p[i].value; }
    [cs->_w appendBytes:words length:4u * (1 + 2 * r->n)];
    cs_regs_relocs(cs, r, start + 2, 2);
}
// CP_NON_CONTEXT_REG_BUNCH: 1, 0, then (offset, value) pairs (fd_ncrb, A7XX+).
static void cs_ncrb(AdrenoCS *cs, const AdrenoRegs *r) {
    if (2u + 2u * r->n > A8XX_PKT7_COUNT_MASK) AdrenoDrawBug(@"NCRB too long");
    uint64_t start = cs_dwords(cs);
    uint32_t words[3 + 2 * ADRENO_REGS_MAX];
    words[0] = a8xx_pkt7_hdr(A8XX_E_CP_NON_CONTEXT_REG_BUNCH, 2u + 2u * r->n);
    words[1] = 1;
    words[2] = 0;
    for (uint32_t i = 0; i < r->n; i++) { words[3 + 2 * i] = r->p[i].offset; words[4 + 2 * i] = r->p[i].value; }
    [cs->_w appendBytes:words length:4u * (3 + 2 * r->n)];
    cs_regs_relocs(cs, r, start + 4, 2);
}
// CP_EVENT_WRITE7 without a memory write (fd6 __event_write<A8XX>).
static void cs_event(AdrenoCS *cs, uint64_t event) {
    PKT7(cs, E(CP_EVENT_WRITE7), PF(CP_EVENT_WRITE7_0, EVENT, event) |
         PF(CP_EVENT_WRITE7_0, WRITE_SRC, E(EV_WRITE_USER_32B)) | PF(CP_EVENT_WRITE7_0, WRITE_DST, E(EV_DST_RAM)));
}
static void cs_wfi(AdrenoCS *cs) { cs_pkt7(cs, E(CP_WAIT_FOR_IDLE), NULL, 0); }
// fd6_set_render_mode<A8XX>: CP_SET_MARKER with the A8XX layout.
static void cs_marker(AdrenoCS *cs, uint64_t mode) { PKT7(cs, E(CP_SET_MARKER), PF(A8XX_CP_SET_MARKER_0, MODE, mode)); }
// The BR thread only (gallium fd6_emit_restore<A8XX>, Turnip tu7_set_thread_br_patchpoint). The kext ring selects
// CP_SET_THREAD_BOTH before CP_INDIRECT_BUFFER (compat/adreno-ib.c, as Linux a7xx/a8xx_submit), so a pass that opens
// a package runs on BV and BR until it selects BR itself: a pass that does not start with emit_restore starts with this.
static void cs_thread_br(AdrenoCS *cs) {
    PKT7(cs, E(CP_THREAD_CONTROL), PF(CP_THREAD_CONTROL_0, THREAD, E(CP_SET_THREAD_BR)) |
         PF(CP_THREAD_CONTROL_0, CONCURRENT_BIN_DISABLE, 1));
}
// A 64-byte aligned data chunk of `padded` bytes (zero after `length`); returns its data-area offset.
static uint64_t cs_data(AdrenoCS *cs, const void *bytes, uint64_t length, uint64_t padded) {
    if (padded < length || padded > ADRENO_IB_MAX_DATA) AdrenoDrawRefuse(@"%llu bytes of inline data exceed one package", padded);
    NSUInteger at = (cs->_data.length + ADRENO_IB_ALIGN - 1) & ~(NSUInteger)(ADRENO_IB_ALIGN - 1);
    [cs->_data setLength:at + (NSUInteger)padded];
    if (length) memcpy((char *)cs->_data.mutableBytes + at, bytes, (size_t)length);
    return at;
}
// An address field inside the data area (driver-table u64): data-space relocation, both halves.
static void cs_data_address(AdrenoCS *cs, uint64_t at, AdrenoAddr a) {
    cs_reloc(cs, ADRENO_SPACE_DATA, at, ADRENO_SPACE_DATA, at + 4, ADRENO_IB_HI_BITS_REG64, a);
}

// ================================================================================================================
// Pieces every pass shares (M: emit_gmem_cache_cntl_sysmem, emit_lrz_inv, emit_restore, emit_static_binning_regs,
// emit_lrz_off, emit_flushes, emit_2d_clear)
// ================================================================================================================
// M.emit_gmem_cache_cntl_sysmem: fd6_calc_gmem_cache_offsets(X2-90: 8 CCUs, 21 MiB GMEM) sysmem half.
static void emit_gmem_cache_cntl_sysmem(AdrenoCS *cs) {
    const uint64_t numCCU = 8, gmem = 21ull * 1024 * 1024;
    const uint64_t colorFraction = 0, colorSize = 128 * 1024, depthFraction = 3, depthSize = 192 * 1024;
    const uint64_t attrSize = 131072, posSize = 65536, bvPosSize = 32768;
    uint64_t offset = gmem;
    const uint64_t bvPosOffset = offset = offset - numCCU * bvPosSize;
    const uint64_t attrOffset = offset = offset - numCCU * attrSize;
    const uint64_t posOffset = offset = offset - numCCU * posSize;
    const uint64_t colorOffset = offset = offset - numCCU * colorSize;
    const uint64_t depthOffset = offset - numCCU * depthSize;
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, RB_CCU_CACHE_CNTL, 0, AF(RB_CCU_CACHE_CNTL, DEPTH_CACHE_SIZE, depthFraction) |
          AFS(RB_CCU_CACHE_CNTL, DEPTH_OFFSET, depthOffset) | AF(RB_CCU_CACHE_CNTL, COLOR_CACHE_SIZE, colorFraction) |
          AFS(RB_CCU_CACHE_CNTL, COLOR_OFFSET, colorOffset));
    REG32(&r, VPC_ATTR_BUF_GMEM_SIZE, 0, AF(VPC_ATTR_BUF_GMEM_SIZE, VALUE, attrSize));
    REG32(&r, VPC_ATTR_BUF_GMEM_BASE, 0, AF(VPC_ATTR_BUF_GMEM_BASE, VALUE, attrOffset));
    REG32(&r, PC_ATTR_BUF_GMEM_SIZE, 0, AF(PC_ATTR_BUF_GMEM_SIZE, VALUE, attrSize));
    REG32(&r, VPC_POS_BUF_GMEM_SIZE, 0, AF(VPC_POS_BUF_GMEM_SIZE, VALUE, posSize));
    REG32(&r, VPC_POS_BUF_GMEM_BASE, 0, AF(VPC_POS_BUF_GMEM_BASE, VALUE, posOffset));
    REG32(&r, PC_POS_BUF_GMEM_SIZE, 0, AF(PC_POS_BUF_GMEM_SIZE, VALUE, posSize));
    REG32(&r, VPC_BV_POS_BUF_GMEM_BASE, 0, AF(VPC_BV_POS_BUF_GMEM_BASE, VALUE, bvPosOffset));
    REG32(&r, VPC_BV_POS_BUF_GMEM_SIZE, 0, AF(VPC_BV_POS_BUF_GMEM_SIZE, VALUE, bvPosSize));
    REG32(&r, PC_BV_POS_BUF_GMEM_SIZE, 0, AF(PC_BV_POS_BUF_GMEM_SIZE, VALUE, bvPosSize));
    cs_crb(cs, &r);
}

// M.emit_lrz_inv: fd6_lrz_inv<A8XX>.
static void emit_lrz_inv(AdrenoCS *cs) {
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, GRAS_LRZ_CNTL, 0, AF(GRAS_LRZ_CNTL, ENABLE, 1));
    REG32(&r, GRAS_LRZ_CNTL2, 0, AF(GRAS_LRZ_CNTL2, DISABLE_ON_WRONG_DIR, 1) | AF(GRAS_LRZ_CNTL2, FC_ENABLE, 1));
    REG32(&r, RB_LRZ_CNTL2, 0, 0);
    cs_crb(cs, &r);
    cs_event(cs, E(LRZ_CACHE_FLUSH));
    regs_reset(&r);
    REG32(&r, GRAS_LRZ_CNTL, 0, 0);
    REG32(&r, GRAS_LRZ_CNTL2, 0, 0);
    REG32(&r, RB_LRZ_CNTL2, 0, 0);
    cs_crb(cs, &r);
}

static uint64_t sp_update_all(void) {
    return AF(SP_UPDATE_CNTL, VS_STATE, 1) | AF(SP_UPDATE_CNTL, HS_STATE, 1) | AF(SP_UPDATE_CNTL, DS_STATE, 1) |
           AF(SP_UPDATE_CNTL, GS_STATE, 1) | AF(SP_UPDATE_CNTL, FS_STATE, 1) | AF(SP_UPDATE_CNTL, CS_STATE, 1);
}

// M.emit_restore: fd6_emit_restore<A8XX> + fd6_emit_static_regs<A8XX> + the sysmem gmem cache config.
static void emit_restore(AdrenoCS *cs, AdrenoAddr border) {
    AdrenoRegs r;
    PKT7(cs, E(CP_SET_MODE), 0);
    cs_thread_br(cs);
    emit_lrz_inv(cs);
    cs_event(cs, E(CCU_INVALIDATE_COLOR));
    cs_event(cs, E(CCU_INVALIDATE_DEPTH));
    cs_pkt7(cs, E(CP_CCHE_INVALIDATE), NULL, 0);
    cs_event(cs, E(CACHE_INVALIDATE7));
    cs_wfi(cs);
    regs_reset(&r);
    REG32(&r, SP_UPDATE_CNTL, 0, sp_update_all());
    cs_pkt4(cs, &r);
    cs_wfi(cs);
    // fd6_emit_static_non_context_regs<A8XX>: M.MAGIC_RAW (a8xx_base_raw_magic_regs), then the static set
    regs_reset(&r);
    for (unsigned i = 0; i < 6; i++) REG32(&r, GRAS_BIN_FOVEAT_XY_FDM_OFFSET, i, 0);
    REG32(&r, RB_UNKNOWN_8818, 0, 0);
    REG32(&r, RB_UNKNOWN_8819, 0, 0);
    REG32(&r, RB_UNKNOWN_881A, 0, 0);
    REG32(&r, RB_UNKNOWN_881B, 0, 0);
    REG32(&r, RB_UNKNOWN_881C, 0, 0);
    REG32(&r, RB_UNKNOWN_881D, 0, 0);
    REG32(&r, RB_UNKNOWN_881E, 0, 0);
    REG32(&r, RB_LRZ_CNTL2, 0, 0);
    REG32(&r, RB_RESOLVE_CNTL_5, 0, 1);
    REG32(&r, SP_UNKNOWN_AB01, 0, 0);
    REG32(&r, SP_HLSQ_MODE_CNTL, 0, 0);
    REG32(&r, SP_UNKNOWN_AB23, 0, 0);
    REG32(&r, TPL1_PS_ROTATION_CNTL, 0, 4);
    REG32(&r, TPL1_PS_SWIZZLE_CNTL, 0, 0);
    REG32(&r, PC_UNKNOWN_980B, 0, 0x00800280);
    REG32(&r, PC_MODE_CNTL, 0, 0x00003F00);
    REG32(&r, SP_PERFCTR_SHADER_MASK, 0, AF(SP_PERFCTR_SHADER_MASK, VS, 1) | AF(SP_PERFCTR_SHADER_MASK, HS, 1) |
          AF(SP_PERFCTR_SHADER_MASK, DS, 1) | AF(SP_PERFCTR_SHADER_MASK, GS, 1) | AF(SP_PERFCTR_SHADER_MASK, FS, 1) |
          AF(SP_PERFCTR_SHADER_MASK, CS, 1));
    REG32(&r, GRAS_SC_SCREEN_SCISSOR_CNTL, 0, 0);
    REG32(&r, GRAS_BIN_FOVEAT, 0, 0);
    REG32(&r, RB_BIN_FOVEAT, 0, 0);
    REG32(&r, RB_A2D_DEST_BUFFER_ARRAY_PITCH, 0, 0);
    cs_ncrb(cs, &r);
    // fd6_emit_static_context_regs<A8XX>
    regs_reset(&r);
    REG32(&r, SP_GFX_USIZE, 0, 0);
    REG32(&r, TPL1_PS_ROTATION_CNTL, 0, 0);
    REG32(&r, SP_UNKNOWN_A9A8, 0, 0);
    REG32(&r, VFD_MODE_CNTL, 0, AF(VFD_MODE_CNTL, VERTEX, 1) | AF(VFD_MODE_CNTL, INSTANCE, 1));
    REG32(&r, RB_MODE_CNTL, 0, 0x10);
    REG32(&r, GRAS_LRZ_PS_INPUT_CNTL, 0, 0);
    REG32(&r, GRAS_LRZ_PS_SAMPLEFREQ_CNTL, 0, 0);
    REG32(&r, GRAS_MODE_CNTL, 0, 0x2);
    REG32(&r, RB_UNKNOWN_8818, 0, 0);
    REG32(&r, VPC_REPLACE_MODE_CNTL, 0, 0);
    REG32(&r, VPC_ROTATION_CNTL, 0, 0);
    REG32(&r, VPC_SO_OVERRIDE, 0, AF(VPC_SO_OVERRIDE, DISABLE, 1));
    REG32(&r, VPC_RAST_STREAM_CNTL, 0, 0);
    REG32(&r, PC_STEREO_RENDERING_CNTL, 0, 0);
    REG32(&r, TPL1_PS_SWIZZLE_CNTL, 0, 0);
    REG32(&r, GRAS_SU_CONSERVATIVE_RAS_CNTL, 0, 0);
    REG32(&r, GRAS_SU_VS_SIV_CNTL, 0, 0);
    REG32(&r, GRAS_SC_CNTL, 0, 0);
    REG32(&r, SP_REG_PROG_ID_3, 0, AF(SP_REG_PROG_ID_3, LINELENGTHREGID, 0xFC) |
          AF(SP_REG_PROG_ID_3, FOVEATIONQUALITYREGID, 0xFC));
    REG32(&r, VFD_RENDER_MODE, 0, AF(VFD_RENDER_MODE, RENDER_MODE, E(RENDERING_PASS)));
    REG32(&r, VFD_STEREO_RENDERING_CNTL, 0, 0);
    REG32(&r, VPC_SO_CNTL, 0, 0);
    REG32(&r, GRAS_LRZ_CNTL, 0, 0);
    REG32(&r, GRAS_LRZ_CNTL2, 0, 0);
    REG32(&r, RB_LRZ_CNTL, 0, 0);
    REG32(&r, RB_DEPTH_PLANE_CNTL, 0, 0);
    REG32(&r, GRAS_SU_DEPTH_PLANE_CNTL, 0, 0);
    for (unsigned i = 0; i < 32; i++) REG32(&r, VFD_VERTEX_BUFFER_SIZE, i, AF(VFD_VERTEX_BUFFER_SIZE, VALUE, 0));
    REGADDR(&r, TPL1_GFX_BORDER_COLOR_BASE, 0, 0, border);
    REGADDR(&r, TPL1_CS_BORDER_COLOR_BASE, 0, 0, border);
    REG32(&r, PC_DGEN_SU_CONSERVATIVE_RAS_CNTL, 0, 0);
    REG32(&r, VPC_UNKNOWN_CNTL, 0, 0);
    REG32(&r, PC_HS_BUFFER_SIZE, 0, 0x40000);
    REG32(&r, PC_TF_BUFFER_SIZE, 0, 0x4040);
    REG32(&r, GRAS_LRZ_QUALITY_LOOKUP_TABLE_REG, 0, 0x09510840);
    REG32(&r, GRAS_LRZ_QUALITY_LOOKUP_TABLE_REG, 1, 0x00000A62);
    REG32(&r, SP_PS_CNTL_0, 0, 0);
    cs_crb(cs, &r);
    PKT7(cs, E(CP_SET_DRAW_STATE), PF(CP_SET_DRAW_STATE__0, DISABLE_ALL_GROUPS, 1), 0, 0);
    emit_gmem_cache_cntl_sysmem(cs);
}

static uint64_t rb_buffer_cntl_sysmem(void) {
    return AF(RB_BUFFER_CNTL, Z_SYSMEM, 1) | AF(RB_BUFFER_CNTL, S_SYSMEM, 1) | AF(RB_BUFFER_CNTL, RT0_SYSMEM, 1) |
           AF(RB_BUFFER_CNTL, RT1_SYSMEM, 1) | AF(RB_BUFFER_CNTL, RT2_SYSMEM, 1) | AF(RB_BUFFER_CNTL, RT3_SYSMEM, 1) |
           AF(RB_BUFFER_CNTL, RT4_SYSMEM, 1) | AF(RB_BUFFER_CNTL, RT5_SYSMEM, 1) | AF(RB_BUFFER_CNTL, RT6_SYSMEM, 1) |
           AF(RB_BUFFER_CNTL, RT7_SYSMEM, 1);
}

// M.emit_static_binning_regs: fd7_emit_static_binning_regs<A8XX>(gmem=false).
static void emit_static_binning_regs(AdrenoCS *cs) {
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, RB_BUFFER_CNTL, 0, rb_buffer_cntl_sysmem());
    REG32(&r, GRAS_LRZ_CB_CNTL, 0, 0);
    REG32(&r, GRAS_MODE_CNTL, 0, 0x2);
    REG32(&r, RB_CLEAR_TARGET, 0, AF(RB_CLEAR_TARGET, CLEAR_MODE, E(CLEAR_MODE_SYSMEM)));
    cs_ncrb(cs, &r);
}

// M.emit_lrz_off: emit_lrz with no depth buffer, every LRZ buffer register zero.
static void emit_lrz_off(AdrenoCS *cs) {
    AdrenoRegs r; regs_reset(&r);
    REG64(&r, GRAS_LRZ_BUFFER_BASE, 0, 0);
    REG32(&r, GRAS_LRZ_BUFFER_PITCH, 0, 0);
    REG32(&r, GRAS_LRZ_VIEW_INFO, 0, 0);
    REG64(&r, GRAS_LRZ_FAST_CLEAR_BUFFER_BASE, 0, 0);
    REG32(&r, GRAS_LRZ_DEPTH_BUFFER_INFO, 0, 0);
    REG32(&r, GRAS_LRZ_CNTL2, 0, 0);
    REG32(&r, GRAS_LRZ_BUFFER_SLICE_PITCH, 0, 0);
    cs_crb(cs, &r);
}

// M.emit_flushes: fd6_emit_flushes<A8XX>. invCache is FD6_INVALIDATE_CACHE (FD_CACHE_INVALIDATE: CACHE_INVALIDATE7 on
// a7xx/a8xx), which only the framebuffer-fetch barrier uses.
typedef struct { BOOL ccuColor, invCcuColor, ccuDepth, invCcuDepth, cache, invCche, wfi, invCache; } AdrenoFlushes;
static void emit_flushes(AdrenoCS *cs, AdrenoFlushes f) {
    if (f.ccuColor || f.invCcuColor) cs_event(cs, E(CCU_CLEAN_COLOR));
    if (f.ccuDepth || f.invCcuDepth) cs_event(cs, E(CCU_CLEAN_DEPTH));
    if (f.invCcuColor) cs_event(cs, E(CCU_INVALIDATE_COLOR));
    if (f.invCcuDepth) cs_event(cs, E(CCU_INVALIDATE_DEPTH));
    if (f.cache) cs_event(cs, E(CACHE_CLEAN));
    if (f.invCache) cs_event(cs, E(CACHE_INVALIDATE7));
    cs_event(cs, E(DUMMY_EVENT));
    cs_event(cs, E(SUBPASS_FENCE));
    cs_event(cs, E(DUMMY_EVENT));
    if (f.invCche) { cs_wfi(cs); cs_pkt7(cs, E(CP_CCHE_INVALIDATE), NULL, 0); }
    if (f.wfi) cs_wfi(cs);
}

// docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md C: the render-target formats the IB builder renders, from q1n1's
// RT_HW/TEX_HW (fd6_format_table.c): RB format, swap, bytes per pixel, 2D IFMT, and whether MRT0 is sRGB-encoded
// (RB_SRGB_CNTL/SP_SRGB_CNTL). RGBA swaps WZYX, BGRA swaps WXYZ.
// integer (agents/gfx-correctness FAILURE-MODES.md F2): 1 UINT, 2 SINT targets (SP_PS_MRT_REG COLOR_UINT/COLOR_SINT, the
// 2D clear's integer output type, blending off); 0 for every normalised and float format.
typedef struct { uint64_t rb, swap, cpp, ifmt; BOOL srgb; uint8_t integer; } AdrenoTargetFormat;
static BOOL AdrenoTargetFormatOf(MTLPixelFormat f, AdrenoTargetFormat *out) {
    switch (f) {
        case MTLPixelFormatBGRA8Unorm: *out = (AdrenoTargetFormat){E(FMT6_8_8_8_8_UNORM), E(WXYZ), 4, E(R2D_UNORM8), NO}; return YES;
        case MTLPixelFormatBGRA8Unorm_sRGB: *out = (AdrenoTargetFormat){E(FMT6_8_8_8_8_UNORM), E(WXYZ), 4, E(R2D_UNORM8), YES}; return YES;
        case MTLPixelFormatRGBA8Unorm: *out = (AdrenoTargetFormat){E(FMT6_8_8_8_8_UNORM), E(WZYX), 4, E(R2D_UNORM8), NO}; return YES;
        case MTLPixelFormatRGBA8Unorm_sRGB: *out = (AdrenoTargetFormat){E(FMT6_8_8_8_8_UNORM), E(WZYX), 4, E(R2D_UNORM8), YES}; return YES;
        case MTLPixelFormatRGBA16Float:
            *out = (AdrenoTargetFormat){E(FMT6_16_16_16_16_FLOAT), E(WZYX), 8, E(R2D_FLOAT16), NO}; return YES;
        // One- and two-channel targets (CoreAnimation's masks, WindowServer's second attachments; v18): the RB format
        // carries the channels, the clear words' unused channels are ignored.
        case MTLPixelFormatR8Unorm: *out = (AdrenoTargetFormat){E(FMT6_8_UNORM), E(WZYX), 1, E(R2D_UNORM8), NO}; return YES;
        case MTLPixelFormatRG8Unorm: *out = (AdrenoTargetFormat){E(FMT6_8_8_UNORM), E(WZYX), 2, E(R2D_UNORM8), NO}; return YES;
        case MTLPixelFormatR16Float: *out = (AdrenoTargetFormat){E(FMT6_16_FLOAT), E(WZYX), 2, E(R2D_FLOAT16), NO}; return YES;
        case MTLPixelFormatRG16Float: *out = (AdrenoTargetFormat){E(FMT6_16_16_FLOAT), E(WZYX), 4, E(R2D_FLOAT16), NO}; return YES;
        // Packed 10:10:10:2 (v35: ControlCenter's 'l10r' status items). fd6_format_table.c: B10G10R10A2_UNORM and
        // R10G10B10A2_UNORM render as FMT6_10_10_10_2_UNORM_DEST, swap WXYZ / WZYX; fd6_ifmt gives R2D_FLOAT16. Metal
        // (measured on the M3 Max): BGR10A2Unorm keeps blue in bits 0..9 and red in 20..29, RGB10A2Unorm red in 0..9.
        case MTLPixelFormatBGR10A2Unorm:
            *out = (AdrenoTargetFormat){E(FMT6_10_10_10_2_UNORM_DEST), E(WXYZ), 4, E(R2D_FLOAT16), NO}; return YES;
        case MTLPixelFormatRGB10A2Unorm:
            *out = (AdrenoTargetFormat){E(FMT6_10_10_10_2_UNORM_DEST), E(WZYX), 4, E(R2D_FLOAT16), NO}; return YES;
        // F2: integer targets (Core Animation's rim/brim passes render RG16Uint; fd6_format_table.c, fd6_ifmt).
#define INT_TARGET(MTL, FMT, CPP, IFMT, KIND) case MTLPixelFormat##MTL: \
            *out = (AdrenoTargetFormat){E(FMT), E(WZYX), CPP, E(IFMT), NO, KIND}; return YES;
        INT_TARGET(R8Uint, FMT6_8_UINT, 1, R2D_INT8, 1) INT_TARGET(R8Sint, FMT6_8_SINT, 1, R2D_INT8, 2)
        INT_TARGET(RG8Uint, FMT6_8_8_UINT, 2, R2D_INT8, 1) INT_TARGET(RG8Sint, FMT6_8_8_SINT, 2, R2D_INT8, 2)
        INT_TARGET(RGBA8Uint, FMT6_8_8_8_8_UINT, 4, R2D_INT8, 1) INT_TARGET(RGBA8Sint, FMT6_8_8_8_8_SINT, 4, R2D_INT8, 2)
        INT_TARGET(R16Uint, FMT6_16_UINT, 2, R2D_INT16, 1) INT_TARGET(R16Sint, FMT6_16_SINT, 2, R2D_INT16, 2)
        INT_TARGET(RG16Uint, FMT6_16_16_UINT, 4, R2D_INT16, 1) INT_TARGET(RG16Sint, FMT6_16_16_SINT, 4, R2D_INT16, 2)
        INT_TARGET(RGBA16Uint, FMT6_16_16_16_16_UINT, 8, R2D_INT16, 1) INT_TARGET(RGBA16Sint, FMT6_16_16_16_16_SINT, 8, R2D_INT16, 2)
        INT_TARGET(R32Uint, FMT6_32_UINT, 4, R2D_INT32, 1) INT_TARGET(R32Sint, FMT6_32_SINT, 4, R2D_INT32, 2)
        INT_TARGET(RG32Uint, FMT6_32_32_UINT, 8, R2D_INT32, 1) INT_TARGET(RG32Sint, FMT6_32_32_SINT, 8, R2D_INT32, 2)
        INT_TARGET(RGBA32Uint, FMT6_32_32_32_32_UINT, 16, R2D_INT32, 1) INT_TARGET(RGBA32Sint, FMT6_32_32_32_32_SINT, 16, R2D_INT32, 2)
#undef INT_TARGET
        default: return NO;
    }
}
// M.emit_2d_clear: fd6_clear_surface<A8XX> as emit_sysmem_clears calls it (8888 linear destination).
static void emit_2d_clear(AdrenoCS *cs, AdrenoAddr destination, uint64_t pitch, const AdrenoTargetFormat *f, uint32_t x,
                          uint32_t y, uint32_t w, uint32_t h, const uint32_t rgba[4]) {
    AdrenoRegs r;
    cs_marker(cs, E(RM6_BLIT2DSCALE));
    regs_reset(&r);
    REG32(&r, GRAS_A2D_DEST_TL, 0, AF(GRAS_A2D_DEST_TL, X, x) | AF(GRAS_A2D_DEST_TL, Y, y));
    REG32(&r, GRAS_A2D_DEST_BR, 0, AF(GRAS_A2D_DEST_BR, X, x + w - 1) | AF(GRAS_A2D_DEST_BR, Y, y + h - 1));
    REG32(&r, RB_A2D_CLEAR_COLOR_DW0, 0, rgba[0]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW1, 0, rgba[1]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW2, 0, rgba[2]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW3, 0, rgba[3]);
    // M.blit_setup_regs(solid): emit_blit_setup<A8XX>(format, IFMT); 8888 is FMT6_8_8_8_8_UNORM with R2D_UNORM8
    REG32(&r, RB_A2D_BLT_CNTL, 0, AF(RB_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(RB_A2D_BLT_CNTL, SOLID_COLOR, 1) |
          AF(RB_A2D_BLT_CNTL, COLOR_FORMAT, f->rb) | AF(RB_A2D_BLT_CNTL, MASK, 0xF) | AF(RB_A2D_BLT_CNTL, IFMT, f->ifmt));
    REG32(&r, GRAS_A2D_BLT_CNTL, 0, AF(GRAS_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(GRAS_A2D_BLT_CNTL, SOLID_COLOR, 1) |
          AF(GRAS_A2D_BLT_CNTL, COLOR_FORMAT, f->rb) | AF(GRAS_A2D_BLT_CNTL, MASK, 0xF) | AF(GRAS_A2D_BLT_CNTL, IFMT, f->ifmt));
    REG32(&r, TPL1_A2D_BLT_CNTL, 0, AF(TPL1_A2D_BLT_CNTL, TYPE, E(A6XX_TEX_2D)));
    // emit_blit_setup: SP_A2D_OUTPUT_INFO takes FMT6_16_16_16_16_FLOAT for a 10_10_10_2_UNORM_DEST destination.
    const uint64_t outFormat = f->rb == E(FMT6_10_10_10_2_UNORM_DEST) ? E(FMT6_16_16_16_16_FLOAT) : f->rb;
    // F2: integer targets take the raw words through the 2D engine's integer output (Turnip r2d_setup_common).
    const uint64_t outType = f->integer == 1 ? E(OUTPUT_IFMT_2D_UINT) : f->integer == 2 ? E(OUTPUT_IFMT_2D_SINT) : E(OUTPUT_IFMT_2D_FLOAT);
    REG32(&r, SP_A2D_OUTPUT_INFO, 0, AF(SP_A2D_OUTPUT_INFO, IFMT_TYPE, outType) |
          AF(SP_A2D_OUTPUT_INFO, COLOR_FORMAT, outFormat) | AF(SP_A2D_OUTPUT_INFO, MASK, 0xF));
    REG32(&r, RB_A2D_PIXEL_CNTL, 0, AF(RB_A2D_PIXEL_CNTL, PIXEL_OP, E(PIXEL_OP_DISABLED)));
    cs_ncrb(cs, &r);
    // M.dst_regs: emit_blit_dst<A8XX> for a linear surface (no UBWC)
    regs_reset(&r);
    REG32(&r, RB_A2D_DEST_BUFFER_INFO, 0, AF(RB_A2D_DEST_BUFFER_INFO, COLOR_FORMAT, f->rb) |
          AF(RB_A2D_DEST_BUFFER_INFO, TILE_MODE, E(TILE6_LINEAR)) | AF(RB_A2D_DEST_BUFFER_INFO, COLOR_SWAP, f->swap) |
          AF(RB_A2D_DEST_BUFFER_INFO, SAMPLES, E(MSAA_ONE)));
    REGADDR(&r, RB_A2D_DEST_BUFFER_BASE, 0, 0, destination);
    REG32(&r, RB_A2D_DEST_BUFFER_PITCH, 0, AFS(RB_A2D_DEST_BUFFER_PITCH, VALUE, pitch));
    cs_ncrb(cs, &r);
    cs_event(cs, E(DEBUG_LABEL));
    PKT7(cs, E(CP_BLIT), PF(CP_BLIT_0, OP, E(BLIT_OP_SCALE)));
}

// AdrenoTextureBindings.h. fd6_pipe2depth, fd6_color_format and fd6_ifmt per format; fdl6_tile_alignment and
// fdl6_layout_image for one TILE6_3 level: pitch align(width * cpp, 256), rows align(height, 16).
BOOL AdrenoZSLayoutOf(MTLPixelFormat f, NSUInteger w, NSUInteger h, AdrenoZSLayout *out) {
    AdrenoZSLayout z;
    switch (f) {
        case MTLPixelFormatDepth16Unorm:
            z = (AdrenoZSLayout){E(DEPTH6_16), E(FMT6_16_UNORM), E(FMT6_16_UNORM), E(R2D_FLOAT32), 2, 0, 0, YES, NO, NO}; break;
        case MTLPixelFormatDepth32Float:
            z = (AdrenoZSLayout){E(DEPTH6_32), E(FMT6_32_FLOAT), E(FMT6_32_FLOAT), E(R2D_FLOAT32), 4, 0, 0, YES, NO, NO}; break;
        case MTLPixelFormatStencil8:
            z = (AdrenoZSLayout){E(DEPTH6_24_8), E(FMT6_Z24_UNORM_S8_UINT_AS_R8G8B8A8), E(FMT6_Z24_UNORM_S8_UINT), E(R2D_INT8),
                                 4, 0, 0, NO, YES, YES}; break;
        case MTLPixelFormatDepth32Float_Stencil8:
            z = (AdrenoZSLayout){E(DEPTH6_24_8), E(FMT6_Z24_UNORM_S8_UINT_AS_R8G8B8A8), E(FMT6_Z24_UNORM_S8_UINT), E(R2D_INT8),
                                 4, 0, 0, YES, YES, YES}; break;
        default: return NO;
    }
    if (!w || !h || w > 16384 || h > 16384) return NO;
    z.pitch = ((uint64_t)w * z.cpp + 255) & ~(uint64_t)255;
    z.layerBytes = z.pitch * (((uint64_t)h + 15) & ~(uint64_t)15);
    if (out) *out = z;
    return YES;
}

// emit_sysmem_clears' depth/stencil half: fd6_clear_surface on the zsbuf (emit_clear_color's words, emit_blit_setup,
// emit_blit_dst on the TILE6_3 buffer, which takes WZYX like every tiled destination). keep: 0 writes every byte;
// 1 keeps the packed stencil byte (a depth-only clear), 2 keeps the depth bytes (a stencil-only clear), with
// emit_blit_setup's Z24_UNORM_S8_UINT PIXEL_OP_BLENDING factors.
static void emit_2d_clear_zs(AdrenoCS *cs, AdrenoAddr destination, const AdrenoZSLayout *z, uint32_t w, uint32_t h,
                             const uint32_t words[4], int keep) {
    AdrenoRegs r;
    cs_marker(cs, E(RM6_BLIT2DSCALE));
    regs_reset(&r);
    REG32(&r, GRAS_A2D_DEST_TL, 0, AF(GRAS_A2D_DEST_TL, X, 0) | AF(GRAS_A2D_DEST_TL, Y, 0));
    REG32(&r, GRAS_A2D_DEST_BR, 0, AF(GRAS_A2D_DEST_BR, X, w - 1) | AF(GRAS_A2D_DEST_BR, Y, h - 1));
    REG32(&r, RB_A2D_CLEAR_COLOR_DW0, 0, words[0]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW1, 0, words[1]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW2, 0, words[2]);
    REG32(&r, RB_A2D_CLEAR_COLOR_DW3, 0, words[3]);
    REG32(&r, RB_A2D_BLT_CNTL, 0, AF(RB_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(RB_A2D_BLT_CNTL, SOLID_COLOR, 1) |
          AF(RB_A2D_BLT_CNTL, COLOR_FORMAT, z->blitFormat) | AF(RB_A2D_BLT_CNTL, MASK, 0xF) | AF(RB_A2D_BLT_CNTL, IFMT, z->ifmt));
    REG32(&r, GRAS_A2D_BLT_CNTL, 0, AF(GRAS_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(GRAS_A2D_BLT_CNTL, SOLID_COLOR, 1) |
          AF(GRAS_A2D_BLT_CNTL, COLOR_FORMAT, z->blitFormat) | AF(GRAS_A2D_BLT_CNTL, MASK, 0xF) | AF(GRAS_A2D_BLT_CNTL, IFMT, z->ifmt));
    REG32(&r, TPL1_A2D_BLT_CNTL, 0, AF(TPL1_A2D_BLT_CNTL, TYPE, E(A6XX_TEX_2D)));
    REG32(&r, SP_A2D_OUTPUT_INFO, 0, AF(SP_A2D_OUTPUT_INFO, IFMT_TYPE, E(OUTPUT_IFMT_2D_FLOAT)) |
          AF(SP_A2D_OUTPUT_INFO, COLOR_FORMAT, z->blitFormat) | AF(SP_A2D_OUTPUT_INFO, MASK, 0xF));
    uint64_t pixel = AF(RB_A2D_PIXEL_CNTL, PIXEL_OP, E(PIXEL_OP_DISABLED));
    if (keep == 1)         // FD_BUFFER_DEPTH: preserve the stencil channel
        pixel = AF(RB_A2D_PIXEL_CNTL, PIXEL_OP, E(PIXEL_OP_BLENDING)) | AF(RB_A2D_PIXEL_CNTL, COLOR_SRC_FACTOR, E(FACTOR_ONE)) |
                AF(RB_A2D_PIXEL_CNTL, ALPHA_DST_FACTOR, E(FACTOR_ONE));
    else if (keep == 2)    // FD_BUFFER_STENCIL: preserve the depth channels
        pixel = AF(RB_A2D_PIXEL_CNTL, PIXEL_OP, E(PIXEL_OP_BLENDING)) | AF(RB_A2D_PIXEL_CNTL, COLOR_DST_FACTOR, E(FACTOR_ONE)) |
                AF(RB_A2D_PIXEL_CNTL, ALPHA_SRC_FACTOR, E(FACTOR_ONE));
    REG32(&r, RB_A2D_PIXEL_CNTL, 0, pixel);
    cs_ncrb(cs, &r);
    regs_reset(&r);
    REG32(&r, RB_A2D_DEST_BUFFER_INFO, 0, AF(RB_A2D_DEST_BUFFER_INFO, COLOR_FORMAT, z->destFormat) |
          AF(RB_A2D_DEST_BUFFER_INFO, TILE_MODE, E(TILE6_3)) | AF(RB_A2D_DEST_BUFFER_INFO, COLOR_SWAP, E(WZYX)) |
          AF(RB_A2D_DEST_BUFFER_INFO, SAMPLES, E(MSAA_ONE)));
    REGADDR(&r, RB_A2D_DEST_BUFFER_BASE, 0, 0, destination);
    REG32(&r, RB_A2D_DEST_BUFFER_PITCH, 0, AFS(RB_A2D_DEST_BUFFER_PITCH, VALUE, z->pitch));
    cs_ncrb(cs, &r);
    cs_event(cs, E(DEBUG_LABEL));
    PKT7(cs, E(CP_BLIT), PF(CP_BLIT_0, OP, E(BLIT_OP_SCALE)));
}

// Metal's colour write mask (Red 8, Green 4, Blue 2, Alpha 1) as RB_MRT_CONTROL.COMPONENT_ENABLE / pipe colormask
// (R 1, G 2, B 4, A 8).
static uint64_t AdrenoComponentMask(MTLColorWriteMask m) {
    return ((m & MTLColorWriteMaskRed) ? 1 : 0) | ((m & MTLColorWriteMaskGreen) ? 2 : 0) |
           ((m & MTLColorWriteMaskBlue) ? 4 : 0) | ((m & MTLColorWriteMaskAlpha) ? 8 : 0);
}
static uint64_t AdrenoCompareFunc(MTLCompareFunction f) {       // adreno_compare_func, the same order as Metal's
    switch (f) {
        case MTLCompareFunctionNever: return E(FUNC_NEVER);
        case MTLCompareFunctionLess: return E(FUNC_LESS);
        case MTLCompareFunctionEqual: return E(FUNC_EQUAL);
        case MTLCompareFunctionLessEqual: return E(FUNC_LEQUAL);
        case MTLCompareFunctionGreater: return E(FUNC_GREATER);
        case MTLCompareFunctionNotEqual: return E(FUNC_NOTEQUAL);
        case MTLCompareFunctionGreaterEqual: return E(FUNC_GEQUAL);
        case MTLCompareFunctionAlways: return E(FUNC_ALWAYS);
    }
    AdrenoDrawRefuse(@"compare function %lu", (unsigned long)f);
}
static uint64_t AdrenoStencilOp(MTLStencilOperation o) {         // adreno_stencil_op (fd_stencil_op's targets)
    switch (o) {
        case MTLStencilOperationKeep: return E(STENCIL_KEEP);
        case MTLStencilOperationZero: return E(STENCIL_ZERO);
        case MTLStencilOperationReplace: return E(STENCIL_REPLACE);
        case MTLStencilOperationIncrementClamp: return E(STENCIL_INCR_CLAMP);
        case MTLStencilOperationDecrementClamp: return E(STENCIL_DECR_CLAMP);
        case MTLStencilOperationInvert: return E(STENCIL_INVERT);
        case MTLStencilOperationIncrementWrap: return E(STENCIL_INCR_WRAP);
        case MTLStencilOperationDecrementWrap: return E(STENCIL_DECR_WRAP);
    }
    AdrenoDrawRefuse(@"stencil operation %lu", (unsigned long)o);
}

// M.guardband: fd_calc_guardband (freedreno_guardband.h), a4xx+ limits.
static uint32_t AdrenoGuardband(double offset, double scale) {
    const double gbMin = -32768.0, gbMax = 32767.0;
    double lo = (gbMin - offset) / fabs(scale), hi = (gbMax - offset) / fabs(scale);
    double adj = fmin(-lo, hi);
    if (adj < 1.0 || isinf(adj)) return 0x1FF;
    int exp = 0;
    double mant = frexp(adj, &exp);
    if (exp <= 0 || exp > 8) return 0x1FF;
    return (uint32_t)(((exp - 1) << 6) | ((int)trunc(mant * (1 << 7)) - (1 << 6)));
}

// The measured Metal clear conversion (AdrenoFillCommands.m clearChannel, qualified against AGX in
// qualify-adreno-texture-clear.py): float before UNorm packing. q1n1's unorm8 rounds the same way in double
// precision; the two differ only where x * 255 rounds differently in float and double.
static uint32_t AdrenoClearByte(double value) {
    if (!isfinite(value)) AdrenoDrawRefuse(@"clear colour components must be finite");
    float clipped = (float)fmin(1.0, fmax(0.0, value));
    return (uint32_t)floorf(clipped * 255.0f + 0.5f);
}

// IEC 61966-2-1 encoding of a linear clear component, the value a sRGB target stores.
static double AdrenoLinearToSRGB(double value) {
    if (!isfinite(value)) AdrenoDrawRefuse(@"clear colour components must be finite");
    double x = fmin(1.0, fmax(0.0, value));
    return x <= 0.0031308 ? 12.92 * x : 1.055 * pow(x, 1.0 / 2.4) - 0.055;
}
// RB_A2D_CLEAR_COLOR_DWn for the target: RGBA order (the swap applies on output). UNORM8 targets take Metal's byte
// rounding, sRGB ones the encoded value written through the plain UNORM path (the 2D destination's SRGB bit stays
// clear, so nothing encodes twice), RGBA16Float one IEEE half per word (Mesa r2d_clear_value, R2D_FLOAT16).
static void AdrenoClearWords(const AdrenoTargetFormat *f, MTLClearColor c, uint32_t words[4]) {
    const double rgba[4] = {c.red, c.green, c.blue, c.alpha};
    for (int i = 0; i < 4; i++) {
        if (f->integer) {
            // F2: the integer value (Metal converts the double clear colour to the integer format: truncation toward zero,
            // clamped to the channel's range), as raw words (Turnip r2d_clear_value: color.uint32).
            if (!isfinite(rgba[i])) AdrenoDrawRefuse(@"clear colour components must be finite");
            const unsigned bits = f->ifmt == E(R2D_INT8) ? 8 : f->ifmt == E(R2D_INT16) ? 16 : 32;
            const double lo = f->integer == 2 ? -ldexp(1.0, (int)bits - 1) : 0.0;
            const double hi = f->integer == 2 ? ldexp(1.0, (int)bits - 1) - 1 : ldexp(1.0, (int)bits) - 1;
            const double v = fmin(hi, fmax(lo, trunc(rgba[i])));
            words[i] = f->integer == 2 ? (uint32_t)(int32_t)v : (uint32_t)v;
        } else if (f->ifmt == E(R2D_FLOAT16)) {
            if (!isfinite(rgba[i])) AdrenoDrawRefuse(@"clear colour components must be finite");
            // A UNORM 10:10:10:2 target clears through the half path: the value Metal stores is the clamped one.
            const double v = f->rb == E(FMT6_10_10_10_2_UNORM_DEST) ? fmin(1.0, fmax(0.0, rgba[i])) : rgba[i];
            _Float16 h = (_Float16)v;
            uint16_t bits; memcpy(&bits, &h, sizeof bits);
            words[i] = bits;
        } else {
            words[i] = AdrenoClearByte(f->srgb && i < 3 ? AdrenoLinearToSRGB(rgba[i]) : rgba[i]);
        }
    }
}

// ================================================================================================================
// The owned program exports (AdrenoShader.program: ir3_program_export.h, the p7 exporter's field contract)
// ================================================================================================================
static NSInteger PInt(NSDictionary *d, NSString *key) {
    id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
    if (![v isKindOfClass:[NSNumber class]] || [v doubleValue] != floor([v doubleValue]))
        AdrenoDrawRefuse(@"program export field %@ is missing or not an integer", key);
    return [v integerValue];
}
static NSDictionary *PDict(NSDictionary *d, NSString *key) {
    id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
    if (![v isKindOfClass:[NSDictionary class]]) AdrenoDrawRefuse(@"program export field %@ is missing", key);
    return v;
}
static NSArray *PArray(NSDictionary *d, NSString *key) {
    id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
    if (![v isKindOfClass:[NSArray class]]) AdrenoDrawRefuse(@"program export field %@ is missing", key);
    return v;
}
// Unsigned field value: refuses a negative export (a builder input, not a bug).
static uint64_t PU(NSDictionary *d, NSString *key) {
    NSInteger v = PInt(d, key);
    if (v < 0) AdrenoDrawRefuse(@"program export field %@ is negative (%ld)", key, (long)v);
    return (uint64_t)v;
}
// M.sysval_regid
static uint32_t PSysval(NSDictionary *v, NSString *name) {
    NSDictionary *ids = PDict(v, @"sysval_regids");
    id r = ids[name];
    if (!r) return INVALID_REG;
    if (![r isKindOfClass:[NSNumber class]] || [r integerValue] < 0 || [r integerValue] > 0xFF)
        AdrenoDrawRefuse(@"system value %@ has no valid register", name);
    return (uint32_t)[r unsignedIntValue];
}
// M.output_regid
static uint32_t POutputRegid(NSDictionary *v, NSInteger slot) {
    for (NSDictionary *o in PArray(v, @"outputs"))
        if (PInt(o, @"slot") == slot) return (uint32_t)(PU(o, @"regid") | (PInt(o, @"half") ? 0x100u : 0u));
    return INVALID_REG;
}
static BOOL Valid(uint32_t regid) { return regid != INVALID_REG; }
static NSArray<NSDictionary *> *Bindings(NSDictionary *v, NSString *kind) {
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *b in PArray(PDict(PDict(v, @"sidecar"), @"reflection"), @"bindings"))
        if (!kind || [b[@"kind"] isEqual:kind]) [out addObject:b];
    return out;
}
static BOOL BoundOrUsed(NSDictionary *b) { return [b[@"present"] boolValue] || [b[@"used"] boolValue]; }
// Whether the code may read the binding: the AIR argument has uses (a binding without the field counts as used).
static BOOL Used(NSDictionary *b) { id u = b[@"used"]; return ![u isKindOfClass:[NSNumber class]] || [u boolValue]; }

// B.driver_table_ubo: the UBO the driver table is bound at, -1 without device buffers.
static NSInteger AdrenoDriverTableUBO(NSDictionary *v) {
    NSMutableSet *at = [NSMutableSet set];
    for (NSDictionary *b in Bindings(v, nil))
        if ([b[@"kind"] isEqual:@"device_buffer"] || [b[@"kind"] isEqual:@"threadgroup_buffer"]) [at addObject:@(PInt(b, @"driver_table_ubo"))];
    if (!at.count) return -1;
    if (at.count != 1) AdrenoDrawRefuse(@"device buffers name different driver tables");
    NSInteger dt = [at.anyObject integerValue];
    NSInteger st = [PDict(PDict(PDict(v, @"sidecar"), @"ir3"), @"stats")[@"driver_table_ubo"] integerValue];
    if (st != -1 && st != dt) AdrenoDrawRefuse(@"bindings name driver table UBO %ld, ir3.stats %ld", (long)dt, (long)st);
    return dt;
}
// B.ubo_min_bytes: the bytes the code may read from UBO slot (the preamble's pushed ranges).
static uint64_t AdrenoUBOMinBytes(NSDictionary *v, NSInteger slot) {
    uint64_t end = 0;
    for (NSDictionary *range in PArray(PDict(v, @"const_state"), @"ubo_ranges"))
        if (PInt(range, @"block") == slot) end = MAX(end, PU(range, @"end"));
    return end;
}
// B.vertex_attributes: {VFD instruction i: Metal attribute index} of the non-sysval VS inputs, in order.
static NSArray<NSNumber *> *AdrenoVertexAttributes(NSDictionary *vs) {
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *input in PArray(vs, @"inputs")) {
        if (PInt(input, @"sysval")) continue;
        NSInteger slot = PInt(input, @"slot");
        if (slot < 15) AdrenoDrawRefuse(@"vertex input slot %ld is not a generic attribute", (long)slot);
        [out addObject:@(slot - 15)];
    }
    return out;
}

static uint32_t AdrenoHexWord(id value) {
    if (![value isKindOfClass:[NSString class]] || ![value hasPrefix:@"0x"] ||
        [value length] < 3 || [value length] > 10)
        AdrenoDrawRefuse(@"constant sampler field must be a hexadecimal 32-bit word");
    uint32_t word = 0;
    for (NSUInteger i = 2; i < [value length]; i++) {
        unichar c = [value characterAtIndex:i];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else { AdrenoDrawRefuse(@"invalid hexadecimal constant sampler word"); digit = 0; }
        word = (word << 4) | digit;
    }
    return word;
}

// ABI6 carries finished hardware sampler descriptors, separate from API indices.
static NSArray *AdrenoConstantSamplers(NSDictionary *v) {
    NSDictionary *sidecar = PDict(v, @"sidecar");
    NSDictionary *constant = PDict(sidecar, @"constant_samplers");
    NSDictionary *reflection = PDict(sidecar, @"reflection");
    NSArray *samplers = PArray(constant, @"samplers");
    NSMutableDictionary *bySlot = [NSMutableDictionary dictionary];
    uint32_t mask = 0, reflectedMask = 0;
    uint64_t count = PU(v, @"num_samp");
    for (NSDictionary *sampler in samplers) {
        uint64_t slot = PU(sampler, @"slot");
        if (slot >= ADRENO_DRAW_SAMPLER_SLOTS || slot >= count || (mask & (1u << slot)))
            AdrenoDrawRefuse(@"constant sampler has an invalid or duplicate slot");
        NSArray *words = PArray(sampler, @"a8xx_tex_samp");
        if (words.count != 4) AdrenoDrawRefuse(@"constant sampler descriptor must contain four words");
        for (id word in words) (void)AdrenoHexWord(word);
        bySlot[@(slot)] = sampler;
        mask |= 1u << slot;
    }
    for (NSDictionary *binding in Bindings(v, @"constexpr_sampler")) {
        uint64_t slot = PU(binding, @"slot");
        if (slot >= ADRENO_DRAW_SAMPLER_SLOTS || (reflectedMask & (1u << slot)))
            AdrenoDrawRefuse(@"constant sampler reflection has an invalid or duplicate slot");
        NSDictionary *sampler = bySlot[@(slot)];
        if (!sampler || ![PArray(binding, @"a8xx_tex_samp") isEqual:PArray(sampler, @"a8xx_tex_samp")] ||
            ![binding[@"unique_id"] isEqual:sampler[@"unique_id"]] ||
            ![binding[@"air_word"] isEqual:sampler[@"air_word"]])
            AdrenoDrawRefuse(@"constant sampler reflection differs from its descriptor");
        reflectedMask |= 1u << slot;
    }
    if (mask != reflectedMask || mask != AdrenoHexWord(constant[@"bitmask"]) ||
        mask != AdrenoHexWord(reflection[@"constexpr_sampler_mask"]))
        AdrenoDrawRefuse(@"constant sampler masks disagree");
    for (NSDictionary *binding in Bindings(v, @"sampler")) {
        NSInteger slot = PInt(binding, @"slot");
        if (slot >= 0 && slot < ADRENO_DRAW_SAMPLER_SLOTS && (mask & (1u << slot)))
            AdrenoDrawRefuse(@"API sampler collides with a constant sampler slot");
    }
    return samplers;
}

// B.check_variant (the subset this wave builds) and B.check_pipeline: a variant outside it is refused.
static void AdrenoCheckVariant(NSDictionary *v, BOOL vertex) {
    NSString *stage = vertex ? @"vertex" : @"fragment";
    NSDictionary *sc = PDict(v, @"sidecar"), *ir3 = PDict(sc, @"ir3"), *stats = PDict(ir3, @"stats");
    NSDictionary *cs = PDict(v, @"const_state"), *refl = PDict(sc, @"reflection");
    if (![v[@"type"] isEqual:vertex ? @"VS" : @"FS"]) AdrenoDrawRefuse(@"%@ program has type %@", stage, v[@"type"]);
    if (PInt(sc, @"abi_version") != 6) AdrenoDrawRefuse(@"%@: sidecar ABI %ld, this builder implements 6", stage, (long)PInt(sc, @"abi_version"));
    if (PInt(stats, @"ubo_slots") != ADRENO_UBO_SLOTS) AdrenoDrawRefuse(@"%@: compiled for %ld UBO slots", stage, (long)PInt(stats, @"ubo_slots"));
    if (![sc[@"chip_id"] isEqual:@"0x44070041"]) AdrenoDrawRefuse(@"%@: compiled for chip %@, not the X2-90", stage, sc[@"chip_id"]);
    if (PInt(cs, @"num_app_ubos") < 0 || PInt(cs, @"num_app_ubos") > ADRENO_UBO_SLOTS)
        AdrenoDrawRefuse(@"%@: %ld UBO descriptors, above the %d a8xx honours", stage, (long)PInt(cs, @"num_app_ubos"), ADRENO_UBO_SLOTS);
    NSInteger dt = AdrenoDriverTableUBO(v);
    if (dt != -1 && (dt < 0 || dt >= ADRENO_UBO_SLOTS)) AdrenoDrawRefuse(@"%@: driver table at UBO %ld", stage, (long)dt);
    for (NSNumber *c in PArray(PDict(sc, @"key_inputs"), @"rt_classes"))
        if (c.integerValue) AdrenoDrawRefuse(@"%@: lowered (XR) attachments are not supported yet", stage);
    NSArray *tclasses = PDict(sc, @"key_inputs")[@"texture_classes"];
    for (NSNumber *c in [tclasses isKindOfClass:[NSArray class]] ? tclasses : @[])
        if (c.integerValue) AdrenoDrawRefuse(@"%@: XR texture classes are not supported yet", stage);
    if (PArray(refl, @"rt_lowering").count) AdrenoDrawRefuse(@"%@: attachment lowering is not supported yet", stage);
    for (NSDictionary *b in PArray(refl, @"bindings")) {
        NSString *kind = b[@"kind"];
        if ([kind isEqual:@"storage_texture"] || [kind isEqual:@"threadgroup_buffer"])
            AdrenoDrawRefuse(@"%@: %@ bindings are not built", stage, kind);
        if (vertex && ([kind isEqual:@"fb_fetch"] || [kind isEqual:@"texture"] || [kind isEqual:@"sampler"] ||
                       [kind isEqual:@"constexpr_sampler"]) && BoundOrUsed(b))
            AdrenoDrawRefuse(@"%@: %@ bindings are not supported yet", stage, kind);
        // Framebuffer fetch (BINDING-ABI 3.6): [[color(n)]] is bindless set 4, descriptor 55 + n, n < 8. The reads are
        // rewritten to non-bindless T# (AdrenoRewriteFramebufferReads); a binding in any other place is refused.
        if (!vertex && [kind isEqual:@"fb_fetch"] && BoundOrUsed(b) &&
            (PInt(b, @"metal_index") < 0 || PInt(b, @"metal_index") >= 8 || PInt(b, @"bindless_set") != ADRENO_FB_SET ||
             PInt(b, @"slot") != ADRENO_FB_DESCRIPTOR + PInt(b, @"metal_index")))
            AdrenoDrawRefuse(@"framebuffer fetch of colour %ld at bindless set %ld, descriptor %ld: not BINDING-ABI 3.6's "
                             @"set %d, descriptor %d + n", (long)PInt(b, @"metal_index"), (long)PInt(b, @"bindless_set"),
                             (long)PInt(b, @"slot"), ADRENO_FB_SET, ADRENO_FB_DESCRIPTOR);
        // Sampled 2D and 3D textures (CoreAnimation's generic fragment function declares three texture3d colour
        // cubes); AdrenoTextureWords builds 3D descriptors for one-slice textures only and refuses deeper ones.
        if (!vertex && [kind isEqual:@"texture"] && BoundOrUsed(b) &&
            ((![(NSString *)b[@"type"] hasPrefix:@"texture2d<"] && ![(NSString *)b[@"type"] hasPrefix:@"texture3d<"]) ||
             ![b[@"access"] isEqual:@"sample"]))
            AdrenoDrawRefuse(@"fragment texture %@ is not a sampled 2D or 3D texture", b[@"arg"]);
        if ([kind isEqual:@"ubo"] && (PInt(b, @"slot") < 0 || PInt(b, @"slot") >= ADRENO_UBO_SLOTS))
            AdrenoDrawRefuse(@"%@: constant buffer slot %ld outside 0..15", stage, (long)PInt(b, @"slot"));
    }
    if (AdrenoConstantSamplers(v).count && vertex)
        AdrenoDrawRefuse(@"vertex constexpr samplers are not supported yet");
    if (PInt(PDict(ir3, @"pvtmem"), @"pvtmem_size") || PInt(v, @"pvtmem_size"))
        AdrenoDrawRefuse(@"%@: private memory (BINDING-ABI 3.10) is not supported", stage);
    for (NSDictionary *d in PArray(ir3, @"driver_ubos"))
        if (![d[@"kind"] isEqual:@"constant_data"]) AdrenoDrawRefuse(@"%@: driver UBO %@ is not built", stage, d[@"kind"]);
    if (PInt(cs, @"driver_params_ubo") != -1 || PInt(cs, @"primitive_map_ubo") != -1 || PInt(cs, @"primitive_param_ubo") != -1)
        AdrenoDrawRefuse(@"%@: ir3 driver-param or primitive UBOs are not built", stage);
    if (PInt(v, @"shared_size") || PInt(v, @"num_uavs") || PInt(v, @"has_ssbo"))
        AdrenoDrawRefuse(@"%@: shared memory, UAVs or SSBOs are not supported", stage);
    if (PInt(v, @"num_samp") < 0 || PInt(v, @"num_samp") > ADRENO_DRAW_TEXTURE_SLOTS || (vertex && PInt(v, @"num_samp")))
        AdrenoDrawRefuse(@"%@: unsupported texture/sampler count", stage);
    // Bindless state: only the framebuffer read's texture (bindless[0] of a fragment variant with fb_read), which the
    // rewrite turns into a non-bindless T#.
    NSArray *bindless = PArray(v, @"bindless");
    for (NSUInteger i = 0; i < bindless.count; i++)
        if ([bindless[i] integerValue] && !(i == 0 && !vertex && PInt(v, @"fb_read")))
            AdrenoDrawRefuse(@"%@: bindless state is not supported yet", stage);
    if (vertex) {
        for (NSDictionary *output in PArray(v, @"outputs"))
            if (PInt(output, @"half"))
                AdrenoDrawRefuse(@"vertex output slot %ld requires a full-register VPC export", (long)PInt(output, @"slot"));
        // Clip and cull distances (VPC/GRAS_CL clip-cull state) and stream output are not built: refused, never dropped.
        // No WindowServer or CoreAnimation function writes them; air2ir3 itself rejects air.clip_distance outputs.
        if (PInt(v, @"clip_mask") || PInt(v, @"cull_mask"))
            AdrenoDrawRefuse(@"vertex function writes clip distances (mask %#lx) or cull distances (mask %#lx): not built",
                             (long)PInt(v, @"clip_mask"), (long)PInt(v, @"cull_mask"));
        if (PInt(v, @"stream_outputs")) AdrenoDrawRefuse(@"vertex function uses stream output: not built");
        // [[point_size]] (CoreAnimation's generic vertex function writes it): exported after position, emit_program_linkage.
        if (PInt(v, @"writes_psize") != Valid(POutputRegid(v, VARYING_SLOT_PSIZ)))
            AdrenoDrawRefuse(@"vertex function's point size flag and its point size output disagree");
    } else {
        NSArray *noAttachment = refl[@"requires_no_attachment"];
        if ([noAttachment isKindOfClass:[NSArray class]] && noAttachment.count)
            AdrenoDrawRefuse(@"fragment function requires attachments %@ to be absent", noAttachment);
        // frag_face (RenderBox's path_interior counts winding with [[front_facing]]) is built: FACEREGID,
        // GRAS_CL_INTERP_CNTL and RB_PS_INPUT_CNTL FACENESS below, GRAS_SU_CNTL FRONT_CW from the encoder's winding.
        NSMutableArray *unbuilt = [NSMutableArray array];
        for (NSString *flag in @[@"num_sampler_prefetch", @"sample_shading", @"reads_primid", @"dual_src_blend",
                                 @"yuv_color", @"color0_mrt", @"post_depth_coverage"])
            if (PInt(v, flag)) [unbuilt addObject:flag];
        if (unbuilt.count)
            AdrenoDrawRefuse(@"fragment function uses prefetch, sample shading, face, primitive id, dual source, yuv, "
                             @"color0_mrt or post-depth coverage (%@)", [unbuilt componentsJoinedByString:@", "]);
        if (PInt(v, @"fb_read") && !Bindings(v, @"fb_fetch").count)
            AdrenoDrawRefuse(@"fragment function reads the framebuffer without an fb_fetch binding");
    }
    NSInteger constlen = PInt(v, @"constlen");
    for (NSDictionary *range in PArray(cs, @"ubo_ranges"))
        if (PInt(range, @"bindless") || PInt(range, @"offset") + (PInt(range, @"end") - PInt(range, @"start")) > 16 * constlen)
            AdrenoDrawRefuse(@"%@: UBO range beyond constlen %ld", stage, (long)constlen);
    if (constlen < 0 || constlen > 512 || constlen % 4) AdrenoDrawRefuse(@"%@: constlen %ld", stage, (long)constlen);
    if (PInt(v, @"instrlen") <= 0 || PU(PDict(v, @"info"), @"size") == 0) AdrenoDrawRefuse(@"%@: empty program", stage);
}
static void AdrenoCheckPipeline(NSDictionary *vs, NSDictionary *fs) {
    if (PInt(vs, @"constlen") + PInt(fs, @"constlen") > 512) AdrenoDrawRefuse(@"VS + FS constlen above 512");
    // The linkage pairs VS outputs and FS inputs by slot (ir3_link_shaders); B.check_pipeline requires every FS
    // varying to be the VS output of the same name, so the slots must agree name by name.
    NSMutableDictionary *vsSlots = [NSMutableDictionary dictionary];
    for (NSDictionary *var in PArray(PDict(PDict(vs, @"sidecar"), @"reflection"), @"varyings")) vsSlots[var[@"name"]] = var[@"slot"];
    for (NSDictionary *var in PArray(PDict(PDict(fs, @"sidecar"), @"reflection"), @"varyings")) {
        if (![vsSlots[var[@"name"]] isEqual:var[@"slot"]])
            AdrenoDrawRefuse(@"varying %@ has no vertex output of that name at slot %@", var[@"name"], var[@"slot"]);
        // Smooth inputs use IR3's perspective or linear pixel barycentric sysval;
        // emit_program assigns/enables both. VPC's per-input flat flag is separate.
        if ((![var[@"interp"] isEqual:@"perspective"] && ![var[@"interp"] isEqual:@"no_perspective"] &&
             ![var[@"interp"] isEqual:@"flat"]) || ![var[@"sampling"] isEqual:@"center"])
            AdrenoDrawRefuse(@"varying %@: %@/%@ interpolation is not built", var[@"name"], var[@"interp"], var[@"sampling"]);
    }
}

// ================================================================================================================
// Framebuffer fetch (docs/ADRENO-DEPTH-STENCIL-20261017.md, "Plug-in: framebuffer fetch")
// ================================================================================================================
// The compiler (BINDING-ABI 3.6; ir3 emit_tex for nir_texop_txf_ms_fb with bindless_fb_read_descriptor 4) reads colour n
// through bindless set 4, descriptor 55 + n, at (frag coord x, y, layer) and the sample id:
//     alias.tex.b32.0 rS.x, (55 + n)       the descriptor index, then rS.y = (0x0), the sampler
//     isamm.a.s2en.uniform.base4 (type)(mask)rD, rC, rS.x
// The kext admits bindless sets only as its empty zero page (compat/adreno-ib-command.c register_field), so the uploaded
// copy of the code takes the non-bindless immediate form ir3 itself emits without bindless_fb_read_descriptor (ir3_cp
// folds its s2en immediates): isamm.a (type)(mask)rD, rC, s#0, t#K, and the draw writes T# K, the attachment's view
// (patch_fb_read_sysmem: fdl6_view_init of the surface's level, identity swizzle). K follows the application's T#/S#
// (max(ntex, nsamp)), one per colour read in ascending order; ir3 counts one num_samp per read, so K < num_samp and
// NTEX = NSAMP = num_samp load it (S#0 below num_samp: isamm does not filter). The alias.tex entries of rS stay in the
// table unread. Any other bindless instruction, or a read in another shape, is refused.
typedef struct { uint32_t count; struct { uint32_t attachment, slot; } read[8]; } AdrenoFBReads;
#define ADRENO_BITS(w, lo, hi) ((uint32_t)(((w) >> (lo)) & ((1ull << ((hi) - (lo) + 1)) - 1)))
static AdrenoFBReads AdrenoRewriteFramebufferReads(NSDictionary *fs, NSMutableData *code) {
    AdrenoFBReads fb;
    memset(&fb, 0, sizeof fb);
    if (!PInt(fs, @"fb_read")) return fb;
    NSDictionary *info = PDict(fs, @"info"), *stats = PDict(PDict(PDict(fs, @"sidecar"), @"ir3"), @"stats");
    const uint64_t size = PU(info, @"size"), data = PU(info, @"constant_data_offset"), end = data ? data : size;
    if (size != code.length || end > size || end % 8)
        AdrenoDrawRefuse(@"framebuffer fetch: code of %llu bytes, constants at %llu", size, data);
    uint32_t bound = 0;
    for (NSDictionary *b in Bindings(fs, @"fb_fetch")) if (BoundOrUsed(b)) bound |= 1u << PInt(b, @"metal_index");
    uint8_t *bytes = code.mutableBytes;
    const NSUInteger count = (NSUInteger)(end / 8);
    NSUInteger at[64];
    uint32_t colourOf[64], colours = 0, reads = 0;
    for (NSUInteger i = 0; i < count; i++) {
        uint64_t w;
        memcpy(&w, bytes + 8 * i, 8);
        if (w >> 61 != 5 || !ADRENO_BITS(w, 51, 51)) continue;                       // cat5, s2en or bindless
        const uint32_t mode = ADRENO_BITS(w, 29, 31), opc = ADRENO_BITS(w, 54, 58);
        const uint32_t set = ADRENO_BITS(w, 19, 20) * 2 | ADRENO_BITS(w, 47, 47), src3 = ADRENO_BITS(w, 21, 28);
        if (mode == 0 || mode == 4) continue;                                         // CAT5_UNIFORM/NONUNIFORM: not bindless
        if (opc != 0x2 || mode != 5 || set != ADRENO_FB_SET)                          // isamm, CAT5_BINDLESS_UNIFORM, base 4
            AdrenoDrawRefuse(@"framebuffer fetch: bindless texture instruction %lu (opcode %#x, descriptor mode %u, set %u) "
                             @"is not the compiler's framebuffer read", (unsigned long)i, opc, mode, set);
        // The alias.tex group directly before it (cat7 alias, scope tex): rS = immediate 55 + n, rS + 1 = immediate 0.
        BOOL seenTex = NO, seenSamp = NO, texImm = NO, sampImm = NO;
        uint32_t texValue = 0, sampValue = 1;
        for (NSUInteger j = i; j-- > 0;) {
            uint64_t a;
            memcpy(&a, bytes + 8 * j, 8);
            if (a >> 61 != 7 || ADRENO_BITS(a, 55, 58) != 0x8 || (ADRENO_BITS(a, 49, 49) << 1 | ADRENO_BITS(a, 47, 47)) != 0) break;
            const uint32_t dst = ADRENO_BITS(a, 32, 39);
            const BOOL imm32 = ADRENO_BITS(a, 51, 52) == 2 && ADRENO_BITS(a, 50, 50) == 1;
            if (dst == src3 && !seenTex) { seenTex = YES; texImm = imm32; texValue = ADRENO_BITS(a, 0, 31); }
            if (dst == src3 + 1 && !seenSamp) { seenSamp = YES; sampImm = imm32; sampValue = ADRENO_BITS(a, 0, 31); }
        }
        if (!texImm || !sampImm || sampValue || texValue < ADRENO_FB_DESCRIPTOR || texValue >= ADRENO_FB_DESCRIPTOR + 8)
            AdrenoDrawRefuse(@"framebuffer fetch: the read at instruction %lu takes its descriptor from r%u.%c, which no alias.tex "
                             @"immediate %d..%d (sampler 0) sets", (unsigned long)i, src3 >> 2, "xyzw"[src3 & 3],
                             ADRENO_FB_DESCRIPTOR, ADRENO_FB_DESCRIPTOR + 7);
        const uint32_t colour = texValue - ADRENO_FB_DESCRIPTOR;
        if (!(bound & (1u << colour)))
            AdrenoDrawRefuse(@"framebuffer fetch: the read at instruction %lu names colour %u, which has no fb_fetch binding",
                             (unsigned long)i, colour);
        if (reads >= 64) AdrenoDrawRefuse(@"framebuffer fetch: more than 64 reads");
        at[reads] = i; colourOf[reads++] = colour;
        colours |= 1u << colour;
    }
    if (!reads) AdrenoDrawRefuse(@"framebuffer fetch: the compiler reports a framebuffer read, the code has none");
    const NSInteger first = MAX(PInt(stats, @"ntex"), PInt(stats, @"nsamp"));
    const uint64_t numSamp = PU(fs, @"num_samp");
    uint32_t slotOf[8] = {0};
    for (uint32_t c = 0; c < 8; c++) {
        if (!(colours & (1u << c))) continue;
        const NSInteger slot = first + (NSInteger)fb.count;
        if (first < 0 || (uint64_t)slot >= numSamp || slot >= (NSInteger)ADRENO_DRAW_TEXTURE_SLOTS)
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u needs T# %ld, outside the %llu ir3 counts", c, (long)slot, numSamp);
        fb.read[fb.count].attachment = c;
        fb.read[fb.count++].slot = slotOf[c] = (uint32_t)slot;
    }
    for (uint32_t k = 0; k < reads; k++) {
        uint64_t w;
        memcpy(&w, bytes + 8 * at[k], 8);
        // S2EN_BINDLESS (51), BASE_LO (47) and BASE_HI (19..20) cleared; SRC3/DESC_MODE (21..31) become SAMP 0, TEX K.
        w = (w & ~((1ull << 51) | (1ull << 47) | (3ull << 19) | (0x7ffull << 21))) | ((uint64_t)slotOf[colourOf[k]] << 25);
        memcpy(bytes + 8 * at[k], &w, 8);
    }
    return fb;
}

// ================================================================================================================
// The pipeline: descriptor capture, code buffers (category on AdrenoPipeline.m's AdrenoRenderPipelineState)
// ================================================================================================================
@interface _MTLRenderPipelineState : NSObject
- (instancetype)initWithDevice:(id)device pipelineStateDescriptor:(id)descriptor;
- (id<MTLDevice>)device;
@end
@interface AdrenoRenderPipelineState : _MTLRenderPipelineState
@property (nonatomic, readonly) AdrenoShader *vertexCode, *fragmentCode;
@property (nonatomic, readonly) NSDictionary *programLinkage;
@end
@interface _MTLComputePipelineState : NSObject
- (id<MTLDevice>)device;
@end
@interface AdrenoComputePipelineState : _MTLComputePipelineState
@property (nonatomic, readonly) AdrenoShader *kernelCode;
@end

// What a draw needs from the MTLRenderPipelineDescriptor (_MTLRenderPipelineState keeps none of it).
typedef struct {
    BOOL captured;
    MTLPixelFormat color[8];
    BOOL blend[8];
    MTLBlendOperation rgbOp[8], alphaOp[8];
    MTLBlendFactor srcRGB[8], dstRGB[8], srcAlpha[8], dstAlpha[8];
    MTLColorWriteMask writeMask[8];
    NSUInteger rasterSampleCount;
    BOOL alphaToCoverage, alphaToOne, rasterization;
    MTLPixelFormat depth, stencil;
    BOOL vertexDescriptor;
    struct { MTLVertexFormat format; NSUInteger offset, bufferIndex; } attribute[31];
    struct { NSUInteger stride; MTLVertexStepFunction step; NSUInteger rate; } layout[31];
} AdrenoFixedState;

static NSData *AdrenoCaptureFixedState(id descriptor) {
    AdrenoFixedState s;
    memset(&s, 0, sizeof s);
    if ([descriptor isKindOfClass:[MTLRenderPipelineDescriptor class]]) {
        MTLRenderPipelineDescriptor *d = descriptor;
        for (NSUInteger i = 0; i < 8; i++) {
            MTLRenderPipelineColorAttachmentDescriptor *a = d.colorAttachments[i];
            s.color[i] = a.pixelFormat; s.blend[i] = a.blendingEnabled;
            s.rgbOp[i] = a.rgbBlendOperation; s.alphaOp[i] = a.alphaBlendOperation;
            s.srcRGB[i] = a.sourceRGBBlendFactor; s.dstRGB[i] = a.destinationRGBBlendFactor;
            s.srcAlpha[i] = a.sourceAlphaBlendFactor; s.dstAlpha[i] = a.destinationAlphaBlendFactor;
            s.writeMask[i] = a.writeMask;
            // Without a fragment function Metal writes no colour (the built-in empty stage runs instead).
            if (!d.fragmentFunction) { s.writeMask[i] = MTLColorWriteMaskNone; s.blend[i] = NO; }
        }
        s.rasterSampleCount = d.rasterSampleCount;
        s.alphaToCoverage = d.alphaToCoverageEnabled; s.alphaToOne = d.alphaToOneEnabled;
        s.rasterization = d.rasterizationEnabled;
        s.depth = d.depthAttachmentPixelFormat; s.stencil = d.stencilAttachmentPixelFormat;
        MTLVertexDescriptor *vd = d.vertexDescriptor;
        s.vertexDescriptor = vd != nil;
        for (NSUInteger i = 0; vd && i < 31; i++) {
            s.attribute[i].format = vd.attributes[i].format;
            s.attribute[i].offset = vd.attributes[i].offset;
            s.attribute[i].bufferIndex = vd.attributes[i].bufferIndex;
            s.layout[i].stride = vd.layouts[i].stride;
            s.layout[i].step = vd.layouts[i].stepFunction;
            s.layout[i].rate = vd.layouts[i].stepRate;
        }
        s.captured = YES;
    }
    return [NSData dataWithBytes:&s length:sizeof s];
}

static const void *const kAdrenoFixedStateKey = &kAdrenoFixedStateKey;
static const void *const kAdrenoDrawProgramKey = &kAdrenoDrawProgramKey;

@interface AdrenoDrawProgram () {
@public
    AdrenoFixedState _fixed;
    AdrenoFBReads _fb;              // the fragment function's framebuffer reads, rewritten to these T# slots
    os_unfair_lock _planLock;       // guards _plan/_planTried (AdrenoDrawPlanOf)
    id _plan;                       // AdrenoDrawPlan, built at the first draw; nil: draws take the export path
    BOOL _planTried;
#if ADRENO_UBO_MIRROR
    BOOL _mayStore;                 // gpu-perf U4: the vertex or fragment code may write memory (AdrenoCodeScan.h)
#endif
}
- (instancetype)initWithPipeline:(AdrenoRenderPipelineState *)pipeline;
@end

@implementation AdrenoRenderPipelineState (AdrenoDraw)
// AdrenoPipeline.m creates every render pipeline with this initializer; the category keeps the descriptor's
// fixed-function state the draw needs (blend, write mask, formats, vertex descriptor).
- (instancetype)initWithDevice:(id)device pipelineStateDescriptor:(id)descriptor {
    NSData *fixed = AdrenoCaptureFixedState(descriptor);
    if ((self = [super initWithDevice:device pipelineStateDescriptor:descriptor]))
        objc_setAssociatedObject(self, kAdrenoFixedStateKey, fixed, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    return self;
}
- (AdrenoDrawProgram *)adrenoDrawProgram {
    @synchronized (self) {
        AdrenoDrawProgram *program = objc_getAssociatedObject(self, kAdrenoDrawProgramKey);
        if (!program) {
            program = [[AdrenoDrawProgram alloc] initWithPipeline:self];
            objc_setAssociatedObject(self, kAdrenoDrawProgramKey, program, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        return program;
    }
}
@end

static uint64_t AdrenoBlendFactor(MTLBlendFactor f) {
    switch (f) {                       // RD.MTL_BLEND_FACTOR -> RD.BLEND_FACTOR
        case MTLBlendFactorZero: return E(FACTOR_ZERO);
        case MTLBlendFactorOne: return E(FACTOR_ONE);
        case MTLBlendFactorSourceAlpha: return E(FACTOR_SRC_ALPHA);
        case MTLBlendFactorOneMinusSourceAlpha: return E(FACTOR_ONE_MINUS_SRC_ALPHA);
        case MTLBlendFactorDestinationAlpha: return E(FACTOR_DST_ALPHA);
        case MTLBlendFactorOneMinusDestinationAlpha: return E(FACTOR_ONE_MINUS_DST_ALPHA);
        // The rest of Metal's single-source factors (fd6_blend: util_blend_factor_to_rb). The constant factors read
        // RB_BLEND_CONSTANT_*_FP32, which every draw writes from setBlendColor. v27: the Dock's icon draws use
        // OneMinusSourceColor. Dual-source (Source1*) needs DUAL_COLOR_IN_ENABLE and stays refused.
        case MTLBlendFactorSourceColor: return E(FACTOR_SRC_COLOR);
        case MTLBlendFactorOneMinusSourceColor: return E(FACTOR_ONE_MINUS_SRC_COLOR);
        case MTLBlendFactorDestinationColor: return E(FACTOR_DST_COLOR);
        case MTLBlendFactorOneMinusDestinationColor: return E(FACTOR_ONE_MINUS_DST_COLOR);
        case MTLBlendFactorSourceAlphaSaturated: return E(FACTOR_SRC_ALPHA_SATURATE);
        case MTLBlendFactorBlendColor: return E(FACTOR_CONSTANT_COLOR);
        case MTLBlendFactorOneMinusBlendColor: return E(FACTOR_ONE_MINUS_CONSTANT_COLOR);
        case MTLBlendFactorBlendAlpha: return E(FACTOR_CONSTANT_ALPHA);
        case MTLBlendFactorOneMinusBlendAlpha: return E(FACTOR_ONE_MINUS_CONSTANT_ALPHA);
        default: AdrenoDrawRefuse(@"blend factor %lu is not supported yet", (unsigned long)f);
    }
}
static uint64_t AdrenoBlendOp(MTLBlendOperation op) {
    switch (op) {                      // RD.MTL_BLEND_OP -> RD.BLEND_OP
        case MTLBlendOperationAdd: return E(BLEND_DST_PLUS_SRC);
        case MTLBlendOperationSubtract: return E(BLEND_SRC_MINUS_DST);
        case MTLBlendOperationReverseSubtract: return E(BLEND_DST_MINUS_SRC);
        case MTLBlendOperationMin: return E(BLEND_MIN_DST_SRC);
        case MTLBlendOperationMax: return E(BLEND_MAX_DST_SRC);
        default: AdrenoDrawRefuse(@"blend operation %lu is not supported yet", (unsigned long)op);
    }
}
static uint64_t AdrenoVertexFormat(MTLVertexFormat f) {
    switch (f) {                       // RD.VTX_HW (the formats q1n1 proved)
        case MTLVertexFormatFloat: return E(FMT6_32_FLOAT);
        case MTLVertexFormatFloat2: return E(FMT6_32_32_FLOAT);
        case MTLVertexFormatFloat3: return E(FMT6_32_32_32_FLOAT);
        case MTLVertexFormatFloat4: return E(FMT6_32_32_32_32_FLOAT);
        default: AdrenoDrawRefuse(@"vertex format %lu is not supported yet", (unsigned long)f);
    }
}

@implementation AdrenoDrawProgram
- (instancetype)initWithPipeline:(AdrenoRenderPipelineState *)pipeline {
    if (!(self = [super init])) return nil;
    AdrenoShader *vs = pipeline.vertexCode, *fs = pipeline.fragmentCode;
    NSDictionary *linkage = pipeline.programLinkage;
    if (!vs.program || !vs.machineCode.length) AdrenoDrawRefuse(@"the pipeline owns no vertex program");
    if (!fs.program || !fs.machineCode.length) AdrenoDrawRefuse(@"render pipelines without a fragment function are not supported yet");
    if (![linkage isKindOfClass:[NSDictionary class]]) AdrenoDrawRefuse(@"the pipeline has no program linkage");
    NSData *fixed = objc_getAssociatedObject(pipeline, kAdrenoFixedStateKey);
    if (fixed.length != sizeof _fixed) AdrenoDrawRefuse(@"the pipeline's descriptor state was not captured");
    memcpy(&_fixed, fixed.bytes, sizeof _fixed);
    if (!_fixed.captured) AdrenoDrawRefuse(@"the pipeline was not created from an MTLRenderPipelineDescriptor");
    _vertexProgram = vs.program; _fragmentProgram = fs.program; _linkage = linkage;
    AdrenoCheckVariant(_vertexProgram, YES);
    AdrenoCheckVariant(_fragmentProgram, NO);
    AdrenoCheckPipeline(_vertexProgram, _fragmentProgram);
    // Framebuffer fetch: the reads are rewritten in the uploaded copy of the fragment code (the shader cache keeps the
    // compiler's bytes).
    NSMutableData *fragmentCode = [fs.machineCode mutableCopy];
    _fb = AdrenoRewriteFramebufferReads(_fragmentProgram, fragmentCode);
    // Fixed-function state this wave builds: one attachment in a target format (AdrenoTargetFormatOf), one sample,
    // no depth/stencil.
    AdrenoTargetFormat targetFormat;
    if (!AdrenoTargetFormatOf(_fixed.color[0], &targetFormat))
        AdrenoDrawRefuse(@"colour attachment format %lu is not supported yet", (unsigned long)_fixed.color[0]);
    BOOL gap = NO;
    for (NSUInteger i = 1; i < 8; i++) {
        if (_fixed.color[i] == MTLPixelFormatInvalid) { gap = YES; continue; }
        if (gap) AdrenoDrawRefuse(@"colour attachments with gaps are not supported yet");
        if (!AdrenoTargetFormatOf(_fixed.color[i], &targetFormat))
            AdrenoDrawRefuse(@"colour attachment %lu format %lu is not supported yet", (unsigned long)i, (unsigned long)_fixed.color[i]);
        if (_fixed.blend[i]) {
            (void)AdrenoBlendFactor(_fixed.srcRGB[i]); (void)AdrenoBlendFactor(_fixed.dstRGB[i]);
            (void)AdrenoBlendFactor(_fixed.srcAlpha[i]); (void)AdrenoBlendFactor(_fixed.dstAlpha[i]);
            (void)AdrenoBlendOp(_fixed.rgbOp[i]); (void)AdrenoBlendOp(_fixed.alphaOp[i]);
        }
    }
    if (_fixed.rasterSampleCount > 1 || _fixed.alphaToCoverage || _fixed.alphaToOne || !_fixed.rasterization)
        AdrenoDrawRefuse(@"MSAA, alpha-to-coverage and disabled rasterization are not supported yet");
    if ((_fixed.depth != MTLPixelFormatInvalid && !AdrenoZSLayoutOf(_fixed.depth, 1, 1, NULL)) ||
        (_fixed.stencil != MTLPixelFormatInvalid && !AdrenoZSLayoutOf(_fixed.stencil, 1, 1, NULL)))
        AdrenoDrawRefuse(@"depth/stencil attachment formats %lu/%lu are not supported yet", (unsigned long)_fixed.depth,
                         (unsigned long)_fixed.stencil);
    if (_fixed.blend[0]) {
        (void)AdrenoBlendFactor(_fixed.srcRGB[0]); (void)AdrenoBlendFactor(_fixed.dstRGB[0]);
        (void)AdrenoBlendFactor(_fixed.srcAlpha[0]); (void)AdrenoBlendFactor(_fixed.dstAlpha[0]);
        (void)AdrenoBlendOp(_fixed.rgbOp[0]); (void)AdrenoBlendOp(_fixed.alphaOp[0]);
    }
    // Code buffers: machine code zero-padded to max(size, instrlen * 128) (the SP fetches instrlen * 128 bytes;
    // RD.plan) rounded to 256 (SP_xS_BASE alignment). Recorded READ by every command buffer that draws with them.
    id<MTLDevice> device = [pipeline device];
    id<MTLBuffer> buffers[2];
    NSDictionary *programs[2] = {_vertexProgram, _fragmentProgram};
    NSData *codes[2] = {vs.machineCode, fragmentCode};
    for (int s = 0; s < 2; s++) {
        uint64_t size = PU(PDict(programs[s], @"info"), @"size"), fetch = 128 * PU(programs[s], @"instrlen");
        if (size != codes[s].length) AdrenoDrawRefuse(@"program export size %llu differs from the machine code", size);
        uint64_t length = (MAX(size, fetch) + 255) & ~255ull;
        if (length > (16u << 20)) AdrenoDrawRefuse(@"shader code of %llu bytes", length);
        buffers[s] = [device newBufferWithLength:(NSUInteger)length options:MTLResourceStorageModeShared];
        if (!buffers[s].contents || buffers[s].length < length) AdrenoDrawRefuse(@"shader code buffer allocation failed");
        memset(buffers[s].contents, 0, (size_t)length);
        memcpy(buffers[s].contents, codes[s].bytes, codes[s].length);
        buffers[s].label = s ? @"Adreno fragment code" : @"Adreno vertex code";
    }
    _vertexCodeBuffer = buffers[0]; _fragmentCodeBuffer = buffers[1];
#if ADRENO_UBO_MIRROR
    // gpu-perf U4: scan the instructions (the code up to its constant data) of both programs as uploaded; an export
    // without a usable constant-data offset counts as storing.
    for (int s = 0; s < 2; s++) {
        id cdo = [PDict(programs[s], @"info") objectForKey:@"constant_data_offset"];
        uint64_t scan = [cdo isKindOfClass:[NSNumber class]] ? [cdo unsignedLongLongValue] : UINT64_MAX;
        if (!scan) scan = codes[s].length;
        if (scan > codes[s].length || (scan & 7) || adreno_ir3_code_may_store(codes[s].bytes, (size_t)scan)) _mayStore = YES;
    }
#endif
    return self;
}
@end

// ================================================================================================================
// Program state (M.program_config / RD.program_config, M.shader_regs, RD.program_linkage over M.program_linkage,
// RD.fs_outputs, M.link_vpc, RD.interp_regs)
// ================================================================================================================
static uint64_t AdrenoBindlessBits(NSDictionary *v, BOOL vertex) {
    NSArray *b = PArray(v, @"bindless");
    if (b.count != 4) AdrenoDrawRefuse(@"bindless export");
    if (vertex)
        return AF(SP_VS_CONFIG, BINDLESS_TEX, [b[0] boolValue]) | AF(SP_VS_CONFIG, BINDLESS_SAMP, [b[1] boolValue]) |
               AF(SP_VS_CONFIG, BINDLESS_UAV, [b[2] boolValue]) | AF(SP_VS_CONFIG, BINDLESS_UBO, [b[3] boolValue]);
    return AF(SP_PS_CONFIG, BINDLESS_TEX, [b[0] boolValue]) | AF(SP_PS_CONFIG, BINDLESS_SAMP, [b[1] boolValue]) |
           AF(SP_PS_CONFIG, BINDLESS_UAV, [b[2] boolValue]) | AF(SP_PS_CONFIG, BINDLESS_UBO, [b[3] boolValue]);
}

// setup_config_stateobj<A8XX> (group PROG_CONFIG) with the variants' BINDLESS_* bits.
static void emit_program_config(AdrenoCS *cs, NSDictionary *vs, NSDictionary *fs, uint64_t ntex, uint64_t nsamp,
                                BOOL fbRewritten) {
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, SP_UPDATE_CNTL, 0, sp_update_all());
    REG32(&r, SP_VS_CONST_CONFIG, 0, AFS(SP_VS_CONST_CONFIG, CONSTLEN, PU(vs, @"constlen")) | AF(SP_VS_CONST_CONFIG, ENABLED, 1));
    REG32(&r, SP_HS_CONST_CONFIG, 0, 0);
    REG32(&r, SP_DS_CONST_CONFIG, 0, 0);
    REG32(&r, SP_GS_CONST_CONFIG, 0, 0);
    REG32(&r, SP_PS_CONST_CONFIG, 0, AFS(SP_PS_CONST_CONFIG, CONSTLEN, PU(fs, @"constlen")) | AF(SP_PS_CONST_CONFIG, ENABLED, 1));
    REG32(&r, SP_VS_CONFIG, 0, AF(SP_VS_CONFIG, ENABLED, 1) | AF(SP_VS_CONFIG, NTEX, PU(vs, @"num_samp")) |
          AF(SP_VS_CONFIG, NSAMP, PU(vs, @"num_samp")) | AF(SP_VS_CONFIG, NUAV, PU(vs, @"num_uavs")) | AdrenoBindlessBits(vs, YES));
    REG32(&r, SP_HS_CONFIG, 0, 0);
    REG32(&r, SP_DS_CONFIG, 0, 0);
    REG32(&r, SP_GS_CONFIG, 0, 0);
    REG32(&r, SP_PS_CONFIG, 0, AF(SP_PS_CONFIG, ENABLED, 1) | AF(SP_PS_CONFIG, NTEX, ntex) | AF(SP_PS_CONFIG, NSAMP, nsamp) |
          AF(SP_PS_CONFIG, NUAV, PU(fs, @"num_uavs")) |
          (AdrenoBindlessBits(fs, NO) & ~(fbRewritten ? AF(SP_PS_CONFIG, BINDLESS_TEX, 1) : 0)));
    REG32(&r, SP_GFX_USIZE, 0, AF(SP_GFX_USIZE, VALUE, PU(fs, @"num_uavs")));
    cs_crb(cs, &r);
}

// M.shader_regs: emit_shader_regs<A8XX> for the VS or the FS, no private memory.
static void emit_shader_regs(AdrenoCS *cs, NSDictionary *v, BOOL vertex, AdrenoAddr code, BOOL pixlod) {
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, SP_MODE_CNTL, 0, AF(SP_MODE_CNTL, CONSTANT_DEMOTION_ENABLE, 1) | AF(SP_MODE_CNTL, ISAMMODE, E(ISAMMODE_GL)));
    REG32(&r, TPL1_MODE_CNTL, 0, AF(TPL1_MODE_CNTL, ISAMMODE, E(ISAMMODE_GL)) |
          AF(TPL1_MODE_CNTL, TEXCOORDROUNDMODE, E(COORD_TRUNCATE)) | AF(TPL1_MODE_CNTL, ARRAYCOORDROUNDMODE, E(COORD_TRUNCATE)) |
          AF(TPL1_MODE_CNTL, NEARESTMIPSNAP, E(CLAMP_ROUND_TRUNCATE)) | AF(TPL1_MODE_CNTL, DESTDATATYPEOVERRIDE, 1) |
          AF(TPL1_MODE_CNTL, CLAMP_DISABLE, 1));
    NSDictionary *info = PDict(v, @"info");
    NSInteger half = PInt(info, @"max_half_reg") + 1, full = PInt(info, @"max_reg") + 1;
    if (half < 0 || full < 0) AdrenoDrawRefuse(@"register footprint");
    uint64_t branch = PU(v, @"branchstack_hw"), merged = PInt(v, @"mergedregs") ? 1 : 0, early = PInt(v, @"early_preamble") ? 1 : 0;
    if (vertex) {
        REG32(&r, SP_VS_CNTL_0, 0, AF(SP_VS_CNTL_0, MERGEDREGS, merged) | AF(SP_VS_CNTL_0, EARLYPREAMBLE, early) |
              AF(SP_VS_CNTL_0, HALFREGFOOTPRINT, half) | AF(SP_VS_CNTL_0, FULLREGFOOTPRINT, full) |
              AF(SP_VS_CNTL_0, BRANCHSTACK, branch));
        REG32(&r, SP_VS_INSTR_SIZE, 0, AF(SP_VS_INSTR_SIZE, VALUE, PU(v, @"instrlen")));
        REG32(&r, SP_VS_PROGRAM_COUNTER_OFFSET, 0, 0);
        REGADDR(&r, SP_VS_BASE, 0, 0, code);
        REG32(&r, SP_VS_PVT_MEM_PARAM, 0, AFS(SP_VS_PVT_MEM_PARAM, MEMSIZEPERITEM, 0));
        REG64(&r, SP_VS_PVT_MEM_BASE, 0, 0);
        REG32(&r, SP_VS_PVT_MEM_SIZE, 0, AFS(SP_VS_PVT_MEM_SIZE, TOTALPVTMEMSIZE, 0) | AF(SP_VS_PVT_MEM_SIZE, PERWAVEMEMLAYOUT, 0));
        REG32(&r, SP_VS_PVT_MEM_STACK_OFFSET, 0, AFS(SP_VS_PVT_MEM_STACK_OFFSET, OFFSET, 0));
        REG32(&r, SP_VS_VGS_CNTL, 0, 0);
    } else {
        uint64_t fullQuad = PInt(v, @"need_full_quad") ? 1 : 0;
        REG32(&r, SP_PS_CNTL_0, 0, AF(SP_PS_CNTL_0, THREADSIZE, PInt(info, @"double_threadsize") ? E(THREAD128) : E(THREAD64)) |
              AF(SP_PS_CNTL_0, VARYING, PInt(v, @"total_in") != 0) | AF(SP_PS_CNTL_0, LODPIXMASK, fullQuad) |
              AF(SP_PS_CNTL_0, INOUTREGOVERLAP, 1) | AF(SP_PS_CNTL_0, PIXLODENABLE, pixlod) |
              AF(SP_PS_CNTL_0, EARLYPREAMBLE, early) | AF(SP_PS_CNTL_0, MERGEDREGS, merged) |
              AF(SP_PS_CNTL_0, HALFREGFOOTPRINT, half) | AF(SP_PS_CNTL_0, FULLREGFOOTPRINT, full) |
              AF(SP_PS_CNTL_0, BRANCHSTACK, branch));
        REG32(&r, RB_PS_CNTL, 0, AF(RB_PS_CNTL, PIXLODENABLE, pixlod) | AF(RB_PS_CNTL, LODPIXMASK, fullQuad));
        REG32(&r, SP_PS_INSTR_SIZE, 0, AF(SP_PS_INSTR_SIZE, VALUE, PU(v, @"instrlen")));
        REG32(&r, SP_PS_PROGRAM_COUNTER_OFFSET, 0, 0);
        REGADDR(&r, SP_PS_BASE, 0, 0, code);
        REG32(&r, SP_PS_PVT_MEM_PARAM, 0, AFS(SP_PS_PVT_MEM_PARAM, MEMSIZEPERITEM, 0));
        REG64(&r, SP_PS_PVT_MEM_BASE, 0, 0);
        REG32(&r, SP_PS_PVT_MEM_SIZE, 0, AFS(SP_PS_PVT_MEM_SIZE, TOTALPVTMEMSIZE, 0) | AF(SP_PS_PVT_MEM_SIZE, PERWAVEMEMLAYOUT, 0));
        REG32(&r, SP_PS_PVT_MEM_STACK_OFFSET, 0, AFS(SP_PS_PVT_MEM_STACK_OFFSET, OFFSET, 0));
        REG32(&r, SP_PS_VGS_CNTL, 0, 0);
    }
    cs_crb(cs, &r);
}

// M.link_vpc: ir3_link_shaders' export plus position appended at max_loc (ir3_link_add), then the point size
// after it as fd6_program.cc emit_vpc links VARYING_SLOT_PSIZ (compmask 0x1 at the new max_loc); fs_varmask is the
// varmask before position (emit_vpc writes VPC_VARYING_LM_TRANSFER_CNTL_DISABLE from it).
typedef struct {
    uint32_t maxLoc, cnt, positionLoc, psizeLoc, primidLoc, viewidLoc, clip0Loc, clip1Loc;
    uint32_t varmask[4], fsVarmask[4];
    struct { uint32_t regid, compmask, loc; } var[34];
} AdrenoLink;
static AdrenoLink AdrenoLinkVPC(NSDictionary *vs, NSDictionary *linkage) {
    AdrenoLink l;
    memset(&l, 0, sizeof l);
    l.maxLoc = (uint32_t)PU(linkage, @"max_loc");
    l.primidLoc = (uint32_t)PU(linkage, @"primid_loc"); l.viewidLoc = (uint32_t)PU(linkage, @"viewid_loc");
    l.clip0Loc = (uint32_t)PU(linkage, @"clip0_loc"); l.clip1Loc = (uint32_t)PU(linkage, @"clip1_loc");
    NSArray *mask = PArray(linkage, @"varmask"), *vars = PArray(linkage, @"var");
    if (mask.count != 4 || vars.count > 32 || PU(linkage, @"cnt") != vars.count) AdrenoDrawRefuse(@"program linkage shape");
    for (NSUInteger i = 0; i < 4; i++) {
        if (![mask[i] isKindOfClass:[NSNumber class]]) AdrenoDrawRefuse(@"program linkage varmask");
        l.varmask[i] = l.fsVarmask[i] = [mask[i] unsignedIntValue];
    }
    for (NSDictionary *v in vars) {
        l.var[l.cnt].regid = (uint32_t)PU(v, @"regid");
        l.var[l.cnt].compmask = (uint32_t)PU(v, @"compmask");
        l.var[l.cnt].loc = (uint32_t)PU(v, @"loc");
        l.cnt++;
    }
    uint32_t pos = POutputRegid(vs, SLOT_POS);
    l.positionLoc = 0xFF;
    if (pos != INVALID_REG) {
        l.positionLoc = l.maxLoc;
        for (uint32_t j = 0; j < 4; j++) {
            uint32_t loc = l.positionLoc + j;
            if (loc >= 128) AdrenoDrawRefuse(@"position location %u", loc);
            l.varmask[loc / 32] |= 1u << (loc % 32);
        }
        l.maxLoc = MAX(l.maxLoc, l.positionLoc + 4);
        l.var[l.cnt].regid = pos; l.var[l.cnt].compmask = 0xF; l.var[l.cnt].loc = l.positionLoc;
        l.cnt++;
    }
    uint32_t psize = POutputRegid(vs, VARYING_SLOT_PSIZ);
    l.psizeLoc = 0xFF;
    if (psize != INVALID_REG) {
        l.psizeLoc = l.maxLoc;
        if (l.psizeLoc >= 128) AdrenoDrawRefuse(@"point size location %u", l.psizeLoc);
        l.varmask[l.psizeLoc / 32] |= 1u << (l.psizeLoc % 32);
        l.maxLoc = MAX(l.maxLoc, l.psizeLoc + 1);
        l.var[l.cnt].regid = psize; l.var[l.cnt].compmask = 0x1; l.var[l.cnt].loc = l.psizeLoc;
        l.cnt++;
    }
    // SP_VS_OUTPUT_REG / SP_VS_VPC_DEST_REG hold 32 exports (emit_vpc asserts linkage.cnt <= 32).
    if (l.cnt > 32) AdrenoDrawRefuse(@"%u vertex exports, above the VPC's 32", l.cnt);
    return l;
}

// RD.fs_outputs: emit_fs_outputs<A8XX> with the alias.rt constants.
typedef struct { uint32_t regs[8], count, alias, mrt; } AdrenoFSOutputs;
static AdrenoFSOutputs AdrenoFSOutputsOf(NSDictionary *fs) {
    AdrenoFSOutputs o;
    memset(&o, 0, sizeof o);
    for (uint32_t i = 0; i < 8; i++) {
        NSDictionary *out = nil;
        for (NSDictionary *candidate in PArray(fs, @"outputs"))
            if (PInt(candidate, @"slot") == FRAG_RESULT_DATA0 + (NSInteger)i) { out = candidate; break; }
        uint32_t r = out ? (uint32_t)(PU(out, @"regid") | (PInt(out, @"half") ? 0x100u : 0u)) : INVALID_REG;
        uint32_t a = out ? (uint32_t)PU(out, @"aliased_components") : 0;
        o.regs[i] = r;
        if ((r & 0xFF) != INVALID_REG || a) {
            o.count = i + 1;
            o.alias |= a << (4 * i);
            o.mrt |= 0xFu << (4 * i);
        }
    }
    return o;
}

// RD.program_linkage: M.program_linkage (setup_stateobj<A8XX>: emit_vfd_dest, emit_vpc, emit_vs_system_values,
// emit_fs_inputs, emit_fs_outputs) with the vertex-id/instance-id sideband and RD.fs_outputs' alias.rt constants.
static uint32_t emit_program_linkage(AdrenoCS *cs, NSDictionary *vs, NSDictionary *fs, NSDictionary *linkage) {
    AdrenoRegs r; regs_reset(&r);
    REG32(&r, PC_STEREO_RENDERING_CNTL, 0, 0);
    NSMutableArray<NSDictionary *> *attrs = [NSMutableArray array];
    for (NSDictionary *input in PArray(vs, @"inputs")) if (!PInt(input, @"sysval")) [attrs addObject:input];
    uint32_t vtx = PSysval(vs, @"SYSTEM_VALUE_VERTEX_ID"), inst = PSysval(vs, @"SYSTEM_VALUE_INSTANCE_ID");
    REG32(&r, VFD_CNTL_0, 0, AF(VFD_CNTL_0, FETCH_CNT, attrs.count) | AF(VFD_CNTL_0, DECODE_CNT, attrs.count));
    REG32(&r, PC_VS_INPUT_CNTL, 0, AF(PC_VS_INPUT_CNTL, INSTR_CNT, attrs.count) |
          AF(PC_VS_INPUT_CNTL, SIDEBAND_CNT, (uint64_t)Valid(vtx) + (uint64_t)Valid(inst)));
    for (NSUInteger n = 0; n < attrs.count; n++)
        REG32(&r, VFD_DEST_CNTL_INSTR, n, AF(VFD_DEST_CNTL_INSTR, WRITEMASK, PU(attrs[n], @"compmask")) |
              AF(VFD_DEST_CNTL_INSTR, REGID, PU(attrs[n], @"regid")));
    AdrenoLink link = AdrenoLinkVPC(vs, linkage);
    REG32(&r, VFD_CNTL_1, 0, AF(VFD_CNTL_1, REGID4VTX, vtx) | AF(VFD_CNTL_1, REGID4INST, inst) |
          AF(VFD_CNTL_1, REGID4PRIMID, INVALID_REG) | AF(VFD_CNTL_1, REGID4VIEWID, INVALID_REG));
    REG32(&r, VFD_CNTL_2, 0, AF(VFD_CNTL_2, REGID_HSRELPATCHID, INVALID_REG) | AF(VFD_CNTL_2, REGID_INVOCATIONID, INVALID_REG));
    REG32(&r, VFD_CNTL_3, 0, AF(VFD_CNTL_3, REGID_DSPRIMID, INVALID_REG) | AF(VFD_CNTL_3, REGID_DSRELPATCHID, INVALID_REG) |
          AF(VFD_CNTL_3, REGID_TESSX, INVALID_REG) | AF(VFD_CNTL_3, REGID_TESSY, INVALID_REG));
    REG32(&r, VFD_CNTL_4, 0, AF(VFD_CNTL_4, REGID_DSVIEWID, INVALID_REG));
    REG32(&r, VFD_CNTL_5, 0, AF(VFD_CNTL_5, REGID_GSHEADER, INVALID_REG) | AF(VFD_CNTL_5, REGID_GSVIEWID, INVALID_REG));
    REG32(&r, VFD_CNTL_6, 0, AF(VFD_CNTL_6, PRIMID4PSEN, PInt(fs, @"reads_primid") ? 1 : 0));
    for (unsigned i = 0; i < 4; i++) REG32(&r, VPC_VARYING_LM_TRANSFER_CNTL_DISABLE, i, ~link.fsVarmask[i]);
    uint32_t spOut[34] = {0}, spVpc[36] = {0};
    for (uint32_t i = 0; i < link.cnt; i++) {
        spOut[i] = (link.var[i].regid & 0xFF) | (link.var[i].compmask & 0xF) << 8;
        spVpc[i] = link.var[i].loc & 0xFF;
    }
    for (uint32_t i = 0; i < (link.cnt + 1) / 2; i++) REG32(&r, SP_VS_OUTPUT_REG, i, spOut[2 * i] | spOut[2 * i + 1] << 16);
    for (uint32_t i = 0; i < (link.cnt + 3) / 4; i++)
        REG32(&r, SP_VS_VPC_DEST_REG, i, spVpc[4 * i] | spVpc[4 * i + 1] << 8 | spVpc[4 * i + 2] << 16 | spVpc[4 * i + 3] << 24);
    // emit_vpc: .psizeloc = pointsize_loc (0xff without a point size export)
    REG32(&r, VPC_VS_CNTL, 0, AF(VPC_VS_CNTL, STRIDE_IN_VPC, link.maxLoc) | AF(VPC_VS_CNTL, POSITIONLOC, link.positionLoc) |
          AF(VPC_VS_CNTL, PSIZELOC, link.psizeLoc));
    REG32(&r, VPC_VS_CLIP_CULL_CNTL, 0, AF(VPC_VS_CLIP_CULL_CNTL, CLIP_MASK, 0) |
          AF(VPC_VS_CLIP_CULL_CNTL, CLIP_DIST_03_LOC, link.clip0Loc) | AF(VPC_VS_CLIP_CULL_CNTL, CLIP_DIST_47_LOC, link.clip1Loc));
    REG32(&r, GRAS_CL_VS_CLIP_CULL_DISTANCE, 0, AF(GRAS_CL_VS_CLIP_CULL_DISTANCE, CLIP_MASK, 0) |
          AF(GRAS_CL_VS_CLIP_CULL_DISTANCE, CULL_MASK, 0));
    // emit_vpc: PC_VS_CNTL .psize = VALIDREG(pointsize_regid)
    REG32(&r, PC_VS_CNTL, 0, AF(PC_VS_CNTL, STRIDE_IN_VPC, link.maxLoc) | AF(PC_VS_CNTL, PSIZE, link.psizeLoc != 0xFF) |
          AF(PC_VS_CNTL, LAYER, 0) |
          AF(PC_VS_CNTL, VIEW, 0) | AF(PC_VS_CNTL, PRIMITIVE_ID, 0) | AF(PC_VS_CNTL, CLIP_MASK, 0));
    REG32(&r, SP_VS_OUTPUT_CNTL, 0, AF(SP_VS_OUTPUT_CNTL, OUT, link.cnt));
    REG32(&r, VPC_VS_SIV_CNTL, 0, AF(VPC_VS_SIV_CNTL, LAYERLOC, 0xFF) | AF(VPC_VS_SIV_CNTL, VIEWLOC, 0xFF) |
          AF(VPC_VS_SIV_CNTL, SHADINGRATELOC, 0xFF));
    REG32(&r, GRAS_SU_VS_SIV_CNTL, 0, AF(GRAS_SU_VS_SIV_CNTL, WRITES_LAYER, 0) | AF(GRAS_SU_VS_SIV_CNTL, WRITES_VIEW, 0));
    REG32(&r, PC_PS_CNTL, 0, AF(PC_PS_CNTL, PRIMITIVEIDEN, PInt(fs, @"reads_primid") ? 1 : 0));
    REG32(&r, GRAS_MODE_CNTL, 0, 0x2);
    REG32(&r, SP_RENDER_CNTL, 0, AF(SP_RENDER_CNTL, FS_DISABLE, 0));
    uint64_t totalIn = PU(fs, @"total_in");
    REG32(&r, VPC_PS_CNTL, 0, AF(VPC_PS_CNTL, NUMNONPOSVAR, totalIn) | AF(VPC_PS_CNTL, PRIMIDLOC, link.primidLoc) |
          AF(VPC_PS_CNTL, VARYING, totalIn != 0) | AF(VPC_PS_CNTL, VIEWIDLOC, link.viewidLoc));
    // emit_fs_inputs<A8XX>
    uint32_t perspPixel = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_PERSP_PIXEL");
    uint32_t perspSample = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_PERSP_SAMPLE");
    uint32_t perspCentroid = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTROID");
    uint32_t perspCenterRHW = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_PERSP_CENTER_RHW");
    uint32_t linearPixel = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_LINEAR_PIXEL");
    uint32_t linearCentroid = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_LINEAR_CENTROID");
    uint32_t linearSample = PSysval(fs, @"SYSTEM_VALUE_BARYCENTRIC_LINEAR_SAMPLE");
    uint32_t face = PSysval(fs, @"SYSTEM_VALUE_FRONT_FACE"), sampid = PSysval(fs, @"SYSTEM_VALUE_SAMPLE_ID");
    uint32_t smask = PSysval(fs, @"SYSTEM_VALUE_SAMPLE_MASK_IN"), coord = PSysval(fs, @"SYSTEM_VALUE_FRAG_COORD");
    uint32_t zwcoord = Valid(coord) ? coord + 2 : INVALID_REG;
    REG32(&r, SP_PS_INITIAL_TEX_LOAD_CNTL, 0, AF(SP_PS_INITIAL_TEX_LOAD_CNTL, COUNT, 0) |
          AF(SP_PS_INITIAL_TEX_LOAD_CNTL, IJ_WRITE_DISABLE, !Valid(perspPixel)) | AF(SP_PS_INITIAL_TEX_LOAD_CNTL, ENDOFQUAD, 0) |
          AF(SP_PS_INITIAL_TEX_LOAD_CNTL, CONSTSLOTID, 0x1FF) | AF(SP_PS_INITIAL_TEX_LOAD_CNTL, CONSTSLOTID4COORD, 0x1FF));
    REG32(&r, SP_LB_PARAM_LIMIT, 0, AF(SP_LB_PARAM_LIMIT, PRIMALLOCTHRESHOLD, 7));
    REG32(&r, RB_LB_PARAM_LIMIT, 0, AF(RB_LB_PARAM_LIMIT, PRIMALLOCTHRESHOLD, 7));
    REG32(&r, SP_REG_PROG_ID_0, 0, AF(SP_REG_PROG_ID_0, FACEREGID, face) | AF(SP_REG_PROG_ID_0, SAMPLEID, sampid) |
          AF(SP_REG_PROG_ID_0, SAMPLEMASK, smask) | AF(SP_REG_PROG_ID_0, CENTERRHW, perspCenterRHW));
    REG32(&r, SP_REG_PROG_ID_1, 0, AF(SP_REG_PROG_ID_1, IJ_PERSP_PIXEL, perspPixel) | AF(SP_REG_PROG_ID_1, IJ_LINEAR_PIXEL, linearPixel) |
          AF(SP_REG_PROG_ID_1, IJ_PERSP_CENTROID, perspCentroid) | AF(SP_REG_PROG_ID_1, IJ_LINEAR_CENTROID, linearCentroid));
    REG32(&r, SP_REG_PROG_ID_2, 0, AF(SP_REG_PROG_ID_2, IJ_PERSP_SAMPLE, perspSample) |
          AF(SP_REG_PROG_ID_2, IJ_LINEAR_SAMPLE, linearSample) | AF(SP_REG_PROG_ID_2, XYCOORDREGID, coord) |
          AF(SP_REG_PROG_ID_2, ZWCOORDREGID, zwcoord));
    REG32(&r, SP_REG_PROG_ID_3, 0, AF(SP_REG_PROG_ID_3, LINELENGTHREGID, INVALID_REG) |
          AF(SP_REG_PROG_ID_3, FOVEATIONQUALITYREGID, INVALID_REG));
    uint64_t sysvalRegs = 0;
    const uint32_t ij[7] = {perspPixel, perspSample, perspCentroid, perspCenterRHW, linearPixel, linearCentroid, linearSample};
    for (unsigned i = 0; i < 7; i++) if (Valid(ij[i])) sysvalRegs += i == 3 ? 1 : 2;
    sysvalRegs += (uint64_t)Valid(face) + (uint64_t)Valid(sampid) + (uint64_t)Valid(smask);
    sysvalRegs += 2 * ((uint64_t)Valid(coord) + (uint64_t)Valid(zwcoord));
    REG32(&r, SP_PS_CNTL_1, 0, AF(SP_PS_CNTL_1, SYSVAL_REGS_COUNT, sysvalRegs) | AF(SP_PS_CNTL_1, DEFER_WAVE_ALLOC_DIS, 1) |
          AF(SP_PS_CNTL_1, EVICT_BUF_MODE, 1));
    REG32(&r, SP_PS_WAVE_CNTL, 0, AF(SP_PS_WAVE_CNTL, VARYINGS, totalIn > 0));
    BOOL needSize = Valid(perspCenterRHW);
    uint64_t coordMask = PU(fs, @"fragcoord_compmask");
#define INTERP_FIELDS(REG) (AF(REG, IJ_PERSP_PIXEL, Valid(perspPixel)) | AF(REG, IJ_PERSP_CENTROID, Valid(perspCentroid)) | \
    AF(REG, IJ_PERSP_SAMPLE, Valid(perspSample)) | AF(REG, IJ_LINEAR_PIXEL, Valid(linearPixel) || needSize) | \
    AF(REG, IJ_LINEAR_CENTROID, Valid(linearCentroid)) | AF(REG, IJ_LINEAR_SAMPLE, Valid(linearSample)) | \
    AF(REG, COORD_MASK, coordMask))
    REG32(&r, GRAS_CL_INTERP_CNTL, 0, AF(GRAS_CL_INTERP_CNTL, FACENESS, PInt(fs, @"frag_face") ? 1 : 0) |
          AF(GRAS_CL_INTERP_CNTL, CENTERRHW, Valid(perspCenterRHW)) | INTERP_FIELDS(GRAS_CL_INTERP_CNTL));
    REG32(&r, RB_INTERP_CNTL, 0, AF(RB_INTERP_CNTL, INTERP_EN, totalIn > 0) | INTERP_FIELDS(RB_INTERP_CNTL));
#undef INTERP_FIELDS
    REG32(&r, RB_PS_INPUT_CNTL, 0, AF(RB_PS_INPUT_CNTL, SAMPLEMASK, Valid(smask)) |
          AF(RB_PS_INPUT_CNTL, POSTDEPTHCOVERAGE, PInt(fs, @"post_depth_coverage") ? 1 : 0) |
          AF(RB_PS_INPUT_CNTL, FACENESS, PInt(fs, @"frag_face") ? 1 : 0) | AF(RB_PS_INPUT_CNTL, SAMPLEID, Valid(sampid)) |
          AF(RB_PS_INPUT_CNTL, FRAGCOORDSAMPLEMODE, E(FRAGCOORD_CENTER)) | AF(RB_PS_INPUT_CNTL, CENTERRHW, Valid(perspCenterRHW)));
    REG32(&r, RB_PS_SAMPLEFREQ_CNTL, 0, AF(RB_PS_SAMPLEFREQ_CNTL, PER_SAMP_MODE, 0));
    REG32(&r, GRAS_LRZ_PS_INPUT_CNTL, 0, AF(GRAS_LRZ_PS_INPUT_CNTL, SAMPLEID, Valid(sampid)) |
          AF(GRAS_LRZ_PS_INPUT_CNTL, FRAGCOORDSAMPLEMODE, E(FRAGCOORD_CENTER)));
    REG32(&r, GRAS_LRZ_PS_SAMPLEFREQ_CNTL, 0, AF(GRAS_LRZ_PS_SAMPLEFREQ_CNTL, PER_SAMP_MODE, 0));
    // emit_fs_outputs<A8XX> (no MSAA), with RD.fs_outputs' output registers and alias.rt constants
    REG32(&r, SP_PS_OUTPUT_CNTL, 0, AF(SP_PS_OUTPUT_CNTL, DUAL_COLOR_IN_ENABLE, 0) |
          AF(SP_PS_OUTPUT_CNTL, DEPTH_REGID, POutputRegid(fs, FRAG_RESULT_DEPTH) & 0xFF) |
          AF(SP_PS_OUTPUT_CNTL, SAMPMASK_REGID, INVALID_REG) |
          AF(SP_PS_OUTPUT_CNTL, STENCILREF_REGID, POutputRegid(fs, FRAG_RESULT_STENCIL) & 0xFF));
    AdrenoFSOutputs outputs = AdrenoFSOutputsOf(fs);
    for (uint32_t i = 0; i < outputs.count; i++)
        REG32(&r, SP_PS_OUTPUT_REG, i, AF(SP_PS_OUTPUT_REG, REGID, outputs.regs[i] & 0xFF) |
              AF(SP_PS_OUTPUT_REG, HALF_PRECISION, (outputs.regs[i] & 0x100) != 0));
    REG32(&r, SP_PS_OUTPUT_CONST_CNTL, 0, AF(SP_PS_OUTPUT_CONST_CNTL, ENABLED, outputs.alias != 0));
    REG32(&r, SP_PS_OUTPUT_CONST_MASK, 0, outputs.alias);
    cs_crb(cs, &r);
    return outputs.mrt;
}

// RD.interp_regs: emit_interp_state<A8XX> without rasterflat. [[point_coord]] (VARYING_SLOT_PNTC, never a vertex
// output: the linkage only reserves its locations) is the point sprite input: per packed component location the VPC
// replaces .x with S and .y with T and interpolates .z as 0 and .w as 1 (fd6_program.cc emit_interp_state). Metal's
// point_coord has its origin at the point's top-left and grows downward like Vulkan's PointCoord (measured on the
// host AGX), so .y is T, not 1 - T: turnip's tu6_vpc_varying_mode (PS_REPL_S, PS_REPL_T) with
// VPC_REPLACE_MODE_CNTL.INVERT 0 (tu_cmd_buffer.cc; emit_static_context_regs here).
static void emit_interp_regs(AdrenoCS *cs, NSDictionary *vs, NSDictionary *fs) {
    NSMutableSet *vsSlots = [NSMutableSet set];
    for (NSDictionary *o in PArray(vs, @"outputs")) [vsSlots addObject:@(PInt(o, @"slot"))];
    uint32_t vinterp[8] = {0}, vpsrepl[8] = {0};
    for (NSDictionary *input in PArray(fs, @"inputs")) {
        uint32_t compmask = (uint32_t)PU(input, @"compmask");
        if (!compmask || !PInt(input, @"bary")) continue;
        uint32_t loc = (uint32_t)PU(input, @"inloc");
        NSInteger slot = PInt(input, @"slot");
        if (slot == VARYING_SLOT_PNTC) {
            if ([vsSlots containsObject:@(slot)]) AdrenoDrawRefuse(@"the vertex function exports a point coordinate");
            static const uint32_t replace[4] = {PS_REPL_S, PS_REPL_T, 0, 0}, interp[4] = {0, 0, INTERP_ZERO, INTERP_ONE};
            for (uint32_t i = 0; i < 4; i++)
                if (compmask & (1u << i)) {
                    if (loc / 16 >= 8) AdrenoDrawRefuse(@"varying location %u", loc);
                    vpsrepl[loc / 16] |= replace[i] << ((loc % 16) * 2);
                    vinterp[loc / 16] |= interp[i] << ((loc % 16) * 2);
                    loc++;
                }
        } else if (slot == VARYING_SLOT_LAYER || slot == VARYING_SLOT_VIEWPORT) {
            uint32_t mode = (![vsSlots containsObject:@(slot)] && (compmask & 1)) ? INTERP_ZERO : INTERP_FLAT;
            if (loc / 16 >= 8) AdrenoDrawRefuse(@"varying location %u", loc);
            vinterp[loc / 16] |= mode << ((loc % 16) * 2);
        } else if (PInt(input, @"flat")) {
            for (uint32_t i = 0; i < 4; i++)
                if (compmask & (1u << i)) {
                    if (loc / 16 >= 8) AdrenoDrawRefuse(@"varying location %u", loc);
                    vinterp[loc / 16] |= INTERP_FLAT << ((loc % 16) * 2);
                    loc++;
                }
        }
    }
    AdrenoRegs r; regs_reset(&r);
    for (unsigned i = 0; i < 8; i++) REG32(&r, VPC_VARYING_INTERP_MODE_MODE, i, vinterp[i]);
    for (unsigned i = 0; i < 8; i++) REG32(&r, VPC_VARYING_REPLACE_MODE_MODE, i, vpsrepl[i]);
    cs_crb(cs, &r);
}

// ================================================================================================================
// The per-program draw plan (docs/PLUGIN-DRAG-SPEED-20261020.md, C2). What every draw used to re-read from the
// program's NSDictionary export, decoded once per AdrenoDrawProgram: the binding tables (in export order, only the
// entries a draw can consider: present or used), the values the draw section reads, and a recording of the groups that
// depend on the program alone (PROG_CONFIG, PROG, PROG_LINKAGE, PROG_INTERP; the driver constant-data UBO loads). A
// draw with a plan runs the same checks, in the same order, with the same helpers, so its command stream is identical;
// a program whose export does not decode gets no plan and its draws take the export path below unchanged.
// ================================================================================================================
#define ADRENO_PLAN_BINDINGS 64
typedef struct { NSInteger slot, index; BOOL used; uint64_t extent, minBytes; } AdrenoPlanBuffer;
typedef struct {
    NSInteger uboCount, driverTable;      // const_state.num_app_ubos; the driver-table UBO after the ir3.stats rule
    uint32_t nUBO, nDevice;
    AdrenoPlanBuffer ubo[ADRENO_PLAN_BINDINGS];       // reflection "ubo" bindings with present || used
    AdrenoPlanBuffer device[ADRENO_PLAN_BINDINGS];    // "device_buffer" bindings with present || used (driver table only)
} AdrenoStagePlan;
typedef struct { NSInteger slot, index; BOOL used, texture3d; __unsafe_unretained id arg; } AdrenoPlanTexture;
typedef struct { NSInteger slot, index; BOOL used; } AdrenoPlanSampler;
typedef struct { NSUInteger slot; uint32_t words[4]; } AdrenoPlanConstantSampler;
typedef struct {
    uint32_t count;                       // num_samp: the T#/S# arrays loaded
    NSInteger namedT, namedS;             // ir3.stats ntex / nsamp
    __unsafe_unretained id function;      // reflection.function (the zero-texture diagnostic)
    uint32_t nTexture, nSampler, nConstant;
    AdrenoPlanTexture texture[ADRENO_PLAN_BINDINGS];
    AdrenoPlanSampler sampler[ADRENO_PLAN_BINDINGS];
    AdrenoPlanConstantSampler constant[ADRENO_DRAW_SAMPLER_SLOTS];
} AdrenoTexturePlan;

@interface AdrenoDrawPlan : NSObject {
@public
    NSData *_progWords, *_progRelocs, *_tailWords, *_tailRelocs;   // recordings: dwords; drafts relative to dword 0
    NSArray *_progResources, *_tailResources;                      // per recorded relocation: its resource or NSNull
    NSArray *_keep;                                                // export objects the C tables point at
    uint32_t _mrt;                                                 // emit_program_linkage's colour component mask
    BOOL _writesZ, _writesStencil, _pointSize;
    NSUInteger _attributeCount, _attributes[32];                   // VFD instruction i: Metal attribute index
    AdrenoStagePlan _vs, _fs;
    AdrenoTexturePlan _textures;
}
@end
@implementation AdrenoDrawPlan
@end

// Names of a binding slot in refusal messages: the strings the format produced, made once.
enum { AdrenoSlotVertexBuffer, AdrenoSlotVertexUBO, AdrenoSlotFragmentUBO, AdrenoSlotVertexDevice, AdrenoSlotFragmentDevice,
       AdrenoSlotKinds };
static NSString *AdrenoSlotName(unsigned kind, NSInteger index) {
    static NSString *names[AdrenoSlotKinds][ADRENO_DRAW_BUFFER_SLOTS];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        for (NSUInteger i = 0; i < ADRENO_DRAW_BUFFER_SLOTS; i++) {
            names[AdrenoSlotVertexBuffer][i] = [NSString stringWithFormat:@"vertex buffer(%lu)", (unsigned long)i];
            names[AdrenoSlotVertexUBO][i] = [NSString stringWithFormat:@"%@ constant buffer(%ld)", @"vertex", (long)i];
            names[AdrenoSlotFragmentUBO][i] = [NSString stringWithFormat:@"%@ constant buffer(%ld)", @"fragment", (long)i];
            names[AdrenoSlotVertexDevice][i] = [NSString stringWithFormat:@"%@ device buffer(%ld)", @"vertex", (long)i];
            names[AdrenoSlotFragmentDevice][i] = [NSString stringWithFormat:@"%@ device buffer(%ld)", @"fragment", (long)i];
        }
    });
    if (kind >= AdrenoSlotKinds || index < 0 || index >= (NSInteger)ADRENO_DRAW_BUFFER_SLOTS) AdrenoDrawBug(@"slot name %u %ld", kind, (long)index);
    return names[kind][index];
}

// A recording appended to a stream: its dwords, then its relocations shifted to where they landed, each resource's
// usage recorded as cs_reloc records it (same order).
static void cs_replay(AdrenoCS *cs, NSData *words, NSData *relocs, NSArray *resources) {
    const uint64_t base = cs_dwords(cs);
    [cs->_w appendData:words];
    const AdrenoRelocDraft *drafts = relocs.bytes;
    const NSUInteger count = relocs.length / sizeof *drafts, at = cs->_relocs.length;
    for (NSUInteger i = 0; i < count; i++)
        if (drafts[i].kind == ADRENO_IB_RELOC_RESOURCE) cs_use(cs, resources[i], drafts[i].access);
    [cs->_relocs setLength:at + count * sizeof *drafts];
    AdrenoRelocDraft *out = (AdrenoRelocDraft *)((uint8_t *)cs->_relocs.mutableBytes + at);
    for (NSUInteger i = 0; i < count; i++) {
        AdrenoRelocDraft d = drafts[i];
        d.lo += base;                                   // recordings hold IB-space positions only (AdrenoRecordOf)
        if (d.hiSpace == ADRENO_SPACE_IB) d.hi += base;
        out[i] = d;
    }
}

// M.load_state6 with SS6_DIRECT UBO descriptors (M.ubo_desc) as the payload; each descriptor is relocated.
typedef struct { BOOL present; AdrenoAddr addr; uint64_t bytes; } AdrenoUBO;
static void emit_ubo_load(AdrenoCS *cs, BOOL vertex, uint32_t dstOff, const AdrenoUBO *ubos, uint32_t count) {
    uint64_t start = cs_dwords(cs);
    uint32_t payload[3 + 2 * ADRENO_UBO_SLOTS];
    if (count > ADRENO_UBO_SLOTS) AdrenoDrawBug(@"UBO count");
    payload[0] = PF(CP_LOAD_STATE6_0, DST_OFF, dstOff) | PF(CP_LOAD_STATE6_0, STATE_TYPE, E(ST6_UBO)) |
                 PF(CP_LOAD_STATE6_0, STATE_SRC, E(SS6_DIRECT)) |
                 PF(CP_LOAD_STATE6_0, STATE_BLOCK, vertex ? E(SB6_VS_SHADER) : E(SB6_FS_SHADER)) |
                 PF(CP_LOAD_STATE6_0, NUM_UNIT, count);
    payload[1] = payload[2] = 0;
    for (uint32_t i = 0; i < count; i++) {
        payload[3 + 2 * i] = 0;
        payload[4 + 2 * i] = ubos[i].present ? DF(A6XX_UBO_1, SIZE, (ubos[i].bytes + 15) / 16) : 0;
    }
    cs_pkt7(cs, vertex ? E(CP_LOAD_STATE6_GEOM) : E(CP_LOAD_STATE6_FRAG), payload, 3 + 2 * count);
    for (uint32_t i = 0; i < count; i++)
        if (ubos[i].present)
            cs_reloc(cs, ADRENO_SPACE_IB, start + 4 + 2 * i, ADRENO_SPACE_IB, start + 5 + 2 * i, ADRENO_IB_HI_BITS_DESC, ubos[i].addr);
}

// A setBuffer/setBytes slot as a GPU address: bytes are copied into the package (padded to `minimum`).
static AdrenoAddr AdrenoBindingAddr(AdrenoCS *cs, const AdrenoBufferBinding *b, uint64_t minimum, uint8_t access,
                                    uint8_t alignLog2, uint64_t maximum, uint64_t *bytes, NSString *what) {
    if (b->bytes) {
        uint64_t length = b->bytes.length;
        uint64_t padded = MAX(length, minimum);
        padded = MAX((padded + 15) & ~15ull, 16);
        if (padded > maximum) AdrenoDrawRefuse(@"%@: %llu bytes exceed the %llu the descriptor holds", what, padded, maximum);
        *bytes = padded;
        return AdrenoPackageAddr(cs_data(cs, b->bytes.bytes, length, padded), padded, alignLog2);
    }
    if (!b->buffer) AdrenoDrawRefuse(@"%@ is not bound", what);
    NSUInteger length = b->buffer.length;
    if (b->offset >= length) AdrenoDrawRefuse(@"%@: offset %lu beyond its %lu bytes", what, (unsigned long)b->offset, (unsigned long)length);
    uint64_t available = MIN((uint64_t)(length - b->offset), maximum);
    if (available < minimum) AdrenoDrawRefuse(@"%@ holds %llu bytes, the program reads %llu", what, available, minimum);
    *bytes = available;
    return AdrenoResourceAddr(b->buffer, b->offset, available, access, alignLog2, what);
}

// UBO staging arenas recycled across command buffers (C3), sized and trimmed so that idle ones give back their GPU
// address space (docs/PLUGIN-ARENA-TRIM-20261021.md, A1-A19; the policy is AdrenoStagingPolicy.h). Every GPU mapping of
// every process shares one 3 GiB window, and idle arenas held it (128 per process before). An arena enters the pool only
// from a command buffer's completed handler with status Completed and no error (AdrenoStagingArenasRecycle), so the
// GPU no longer reads or writes it; one taker gets it under the lock. The pool owns one +1 reference per entry; the
// arenas it lets go (aged, capped, drained, refused) are released after the unlock, never under it. A timer on a
// private queue trims while the pool holds anything; memory pressure and a failed allocation drain it.
#define ADRENO_STAGING_TICK_NS 100000000ull
static os_unfair_lock gAdrenoStagingLock = OS_UNFAIR_LOCK_INIT;
static AdrenoStagingPool gAdrenoStagingPolicy;      // under gAdrenoStagingLock, as are the two flags
static BOOL gAdrenoStagingReady, gAdrenoStagingArmed;
static dispatch_source_t gAdrenoStagingTimer, gAdrenoStagingMemory;
static _Atomic uint64_t gAdrenoStagingNew, gAdrenoStagingReused, gAdrenoStagingPooled, gAdrenoStagingDropped;
static _Atomic uint64_t gAdrenoStagingLive, gAdrenoStagingLiveBytes, gAdrenoStagingPeak, gAdrenoStagingPeakBytes,
    gAdrenoStagingPeakPooled, gAdrenoStagingFailures, gAdrenoStagingRetries, gAdrenoStagingRetryOK, gAdrenoStagingFires,
    gAdrenoStagingContinued;
static uint64_t AdrenoStagingNow(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }
static void AdrenoStagingRaise(_Atomic uint64_t *peak, uint64_t value) {
    uint64_t seen = atomic_load(peak);
    while (value > seen && !atomic_compare_exchange_weak(peak, &seen, value)) {}
}
// The live gauge: one sentinel per arena, released with it (atomics only: it may run on any thread, under any lock).
@interface AdrenoStagingSentinel : NSObject { @public uint64_t _bytes; } @end
@implementation AdrenoStagingSentinel
- (void)dealloc { atomic_fetch_sub(&gAdrenoStagingLive, 1); atomic_fetch_sub(&gAdrenoStagingLiveBytes, _bytes); }
@end
static char kAdrenoStagingSentinel;
// Caller holds the lock: arm the timer when the pool holds anything, disarm it when it is empty (A6, A7).
static void AdrenoStagingTimerLocked(void) {
    BOOL want = adreno_staging_wants_timer(&gAdrenoStagingPolicy);
    if (!gAdrenoStagingTimer || want == gAdrenoStagingArmed) return;
    gAdrenoStagingArmed = want;
    dispatch_source_set_timer(gAdrenoStagingTimer, want ? dispatch_time(DISPATCH_TIME_NOW, (int64_t)ADRENO_STAGING_TICK_NS) :
                              DISPATCH_TIME_FOREVER, ADRENO_STAGING_TICK_NS, ADRENO_STAGING_TICK_NS / 4);
}
// Caller holds the lock.
static void AdrenoStagingReadyLocked(void) {
    if (gAdrenoStagingReady) return;
    adreno_staging_init(&gAdrenoStagingPolicy, adreno_staging_default_limits());
    gAdrenoStagingReady = YES;
}
// After the unlock: release what the pool let go.
static void AdrenoStagingReleaseVictims(AdrenoStagingVictims *v) {
    for (unsigned i = 0; i < v->count; i++) (void)CFBridgingRelease(v->item[i]);
    if (v->count) atomic_fetch_add(&gAdrenoStagingDropped, v->count);
    v->count = 0;
}
static void AdrenoStagingTick(void) {
    AdrenoStagingVictims v; v.count = 0;
    os_unfair_lock_lock(&gAdrenoStagingLock);
    if (gAdrenoStagingReady) adreno_staging_trim(&gAdrenoStagingPolicy, AdrenoStagingNow(), &v);
    AdrenoStagingTimerLocked();
    os_unfair_lock_unlock(&gAdrenoStagingLock);
    atomic_fetch_add(&gAdrenoStagingFires, 1);
    AdrenoStagingReleaseVictims(&v);
}
uint64_t AdrenoStagingRelieve(void) {
    AdrenoStagingVictims v; v.count = 0;
    os_unfair_lock_lock(&gAdrenoStagingLock);
    AdrenoStagingReadyLocked();
    uint64_t bytes = adreno_staging_drain(&gAdrenoStagingPolicy, AdrenoStagingNow(), &v);
    AdrenoStagingTimerLocked();
    os_unfair_lock_unlock(&gAdrenoStagingLock);
    AdrenoStagingReleaseVictims(&v);
    return bytes;
}
// The queue, the timer and the memory-pressure source exist only in a process that pools an arena (A7, A15).
static void AdrenoStagingSetUp(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_queue_t queue = dispatch_queue_create("org.snapintosh.adreno.staging",
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0));
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_event_handler(timer, ^{ AdrenoStagingTick(); });
        dispatch_source_set_timer(timer, DISPATCH_TIME_FOREVER, ADRENO_STAGING_TICK_NS, ADRENO_STAGING_TICK_NS / 4);
        dispatch_activate(timer);
        dispatch_source_t memory = dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
                                                          DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL, queue);
        if (memory) {
            dispatch_source_set_event_handler(memory, ^{ (void)AdrenoStagingRelieve(); });
            dispatch_activate(memory);
        }
        os_unfair_lock_lock(&gAdrenoStagingLock);
        gAdrenoStagingTimer = timer; gAdrenoStagingMemory = memory;
        os_unfair_lock_unlock(&gAdrenoStagingLock);
    });
}
BOOL AdrenoStagingRelieveAfterFailure(void) {
    atomic_fetch_add(&gAdrenoStagingFailures, 1);
    return AdrenoStagingRelieve() != 0;
}
void AdrenoStagingRetried(BOOL succeeded) {
    atomic_fetch_add(&gAdrenoStagingRetries, 1);
    if (succeeded) atomic_fetch_add(&gAdrenoStagingRetryOK, 1);
}
// The most recent pooled arena of exactly this device and length (A12), or nil.
static id<MTLBuffer> AdrenoStagingArenaTake(id<MTLDevice> device, uint64_t length) {
    os_unfair_lock_lock(&gAdrenoStagingLock);
    void *item = gAdrenoStagingReady ? adreno_staging_take(&gAdrenoStagingPolicy, (__bridge const void *)device, length,
                                                           AdrenoStagingNow()) : NULL;
    os_unfair_lock_unlock(&gAdrenoStagingLock);
    if (!item) return nil;
    atomic_fetch_add(&gAdrenoStagingReused, 1);
    return (__bridge_transfer id<MTLBuffer>)item;
}
// A new arena (the device's own allocation, which drains the pool and retries once if IOGPU refuses it), with its gauge
// sentinel. Not inlined: harness/ca-generic.m's independent gauge finds staging allocations by this caller's name.
__attribute__((noinline)) static id<MTLBuffer> AdrenoStagingArenaNew(id<MTLDevice> device, uint64_t length) {
    id<MTLBuffer> arena = [device newBufferWithLength:(NSUInteger)length options:MTLResourceStorageModeShared];
    if (!arena) return nil;
    atomic_fetch_add(&gAdrenoStagingNew, 1);
    AdrenoStagingSentinel *sentinel = [AdrenoStagingSentinel new];
    sentinel->_bytes = arena.length;
    objc_setAssociatedObject(arena, &kAdrenoStagingSentinel, sentinel, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    AdrenoStagingRaise(&gAdrenoStagingPeak, atomic_fetch_add(&gAdrenoStagingLive, 1) + 1);
    AdrenoStagingRaise(&gAdrenoStagingPeakBytes, atomic_fetch_add(&gAdrenoStagingLiveBytes, sentinel->_bytes) + sentinel->_bytes);
    return arena;
}
#if ADRENO_UBO_MIRROR && ADRENO_UBO_MIRROR_SLABS
// ---- mirror slabs (FAILURE-MODES.md R1-R7) ----------------------------------------------------------------------------
// Allocated on first need, at most ADRENO_UBO_MIRROR_SLABS_MAX per process, never released by the plug-in: no staging-pool
// age, cap or pressure rule applies to them (R3), so a frame after an idle gap reuses the same GPU memory instead of
// allocating new arenas (b12v16: SPTM UPDATE_DISJOINT_MULTIPAGE x13). A slab returns to its device's list only from a
// command buffer's clean completion (AdrenoStagingArenasRecycle below, R1); after an error it is released with the
// command buffer, like any arena, and its sentinel gives its count back so a later take may allocate a replacement.
#define ADRENO_UBO_MIRROR_SLAB_BYTES (1ull << 20)
#ifndef ADRENO_UBO_MIRROR_SLABS_MAX
#define ADRENO_UBO_MIRROR_SLABS_MAX 24u
#endif
static os_unfair_lock gAdrenoSlabLock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray *gAdrenoSlabFree;              // free slabs, most recently returned last (under gAdrenoSlabLock)
static _Atomic uint64_t gAdrenoSlabLive, gAdrenoSlabAllocated, gAdrenoSlabTakes, gAdrenoSlabReturns, gAdrenoSlabExhausted;
static char kAdrenoSlabKey;
@interface AdrenoSlabSentinel : NSObject @end
@implementation AdrenoSlabSentinel
- (void)dealloc { atomic_fetch_sub(&gAdrenoSlabLive, 1); }
@end
static BOOL AdrenoIsMirrorSlab(id arena) { return arena && objc_getAssociatedObject(arena, &kAdrenoSlabKey) != nil; }
// A free slab of this device (LIFO), else a new one while fewer than the cap are alive, else nil (R2).
static id<MTLBuffer> AdrenoMirrorSlabTake(id<MTLDevice> device) {
    id<MTLBuffer> slab = nil;
    os_unfair_lock_lock(&gAdrenoSlabLock);
    for (NSUInteger i = gAdrenoSlabFree.count; i-- > 0;)
        if ([(id<MTLBuffer>)gAdrenoSlabFree[i] device] == device) { slab = gAdrenoSlabFree[i]; [gAdrenoSlabFree removeObjectAtIndex:i]; break; }
    os_unfair_lock_unlock(&gAdrenoSlabLock);
    if (slab) { atomic_fetch_add(&gAdrenoSlabTakes, 1); return slab; }
    if (atomic_fetch_add(&gAdrenoSlabLive, 1) >= ADRENO_UBO_MIRROR_SLABS_MAX) {
        atomic_fetch_sub(&gAdrenoSlabLive, 1);
        atomic_fetch_add(&gAdrenoSlabExhausted, 1);
        return nil;
    }
    // R5: shared storage, the default (write-back) CPU cache mode, as every staging arena has always had.
    slab = [device newBufferWithLength:(NSUInteger)ADRENO_UBO_MIRROR_SLAB_BYTES
                               options:MTLResourceStorageModeShared | MTLResourceCPUCacheModeDefaultCache];
    if (!slab || !slab.contents || slab.length < ADRENO_UBO_MIRROR_SLAB_BYTES) {
        atomic_fetch_sub(&gAdrenoSlabLive, 1);
        return nil;
    }
    slab.label = @"Adreno UBO mirror slab";
    objc_setAssociatedObject(slab, &kAdrenoSlabKey, [AdrenoSlabSentinel new], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    atomic_fetch_add(&gAdrenoSlabAllocated, 1);
    atomic_fetch_add(&gAdrenoSlabTakes, 1);
    return slab;
}
static void AdrenoMirrorSlabReturn(id<MTLBuffer> slab) {
    os_unfair_lock_lock(&gAdrenoSlabLock);
    if (!gAdrenoSlabFree) gAdrenoSlabFree = [NSMutableArray array];
    if ([gAdrenoSlabFree indexOfObjectIdenticalTo:slab] == NSNotFound) [gAdrenoSlabFree addObject:slab];
    os_unfair_lock_unlock(&gAdrenoSlabLock);
    atomic_fetch_add(&gAdrenoSlabReturns, 1);
}
void AdrenoMirrorSlabCounters(uint64_t out[5]) {
    out[0] = atomic_load(&gAdrenoSlabLive); out[1] = atomic_load(&gAdrenoSlabAllocated); out[2] = atomic_load(&gAdrenoSlabTakes);
    out[3] = atomic_load(&gAdrenoSlabReturns); out[4] = atomic_load(&gAdrenoSlabExhausted);
}
#endif
void AdrenoStagingArenasRecycle(NSArray *arenas) {
    if (!arenas.count) return;
#if ADRENO_UBO_MIRROR && ADRENO_UBO_MIRROR_SLABS
    // R1, R3: mirror slabs go back to their own list, never into the staging pool.
    NSMutableArray *staging = nil;
    for (id arena in arenas) {
        if (AdrenoIsMirrorSlab(arena)) AdrenoMirrorSlabReturn(arena);
        else { if (!staging) staging = [NSMutableArray array]; [staging addObject:arena]; }
    }
    if (!staging.count) return;
    arenas = staging;
#endif
    AdrenoStagingSetUp();
    // Each arena's +1 for the pool, its device and its length, read before the lock (A4).
    enum { BATCH = 32 };
    struct { void *item; const void *owner; uint64_t bytes; } batch[BATCH];
    AdrenoStagingVictims v; v.count = 0;
    uint64_t pooled = 0;
    NSUInteger at = 0, total = arenas.count;
    while (at < total) {
        unsigned n = 0;
        for (; at < total && n < BATCH; at++) {
            id<MTLBuffer> arena = arenas[at];
            batch[n].owner = (__bridge const void *)arena.device; batch[n].bytes = arena.length;
            batch[n].item = (__bridge_retained void *)arena;
            n++;
        }
        os_unfair_lock_lock(&gAdrenoStagingLock);
        AdrenoStagingReadyLocked();
        const uint64_t now = AdrenoStagingNow();
        for (unsigned i = 0; i < n; i++)
            pooled += (uint64_t)adreno_staging_put(&gAdrenoStagingPolicy, batch[i].item, batch[i].owner, batch[i].bytes,
                                                   now, &v);
        const uint64_t bytes = gAdrenoStagingPolicy.bytes;
        AdrenoStagingTimerLocked();
        os_unfair_lock_unlock(&gAdrenoStagingLock);
        AdrenoStagingRaise(&gAdrenoStagingPeakPooled, bytes);
        AdrenoStagingReleaseVictims(&v);
    }
    atomic_fetch_add(&gAdrenoStagingPooled, pooled);
}
NSArray *AdrenoFinishedPassArenas(id<AdrenoFinishedPass> pass) {
    AdrenoCS *cs = [pass adrenoCS];
    return cs->_arenas ?: @[];
}
id<MTLBuffer> AdrenoFinishedPassStagingCursor(id<AdrenoFinishedPass> pass, uint64_t *used) {
    AdrenoCS *cs = [pass adrenoCS];
    BOOL valid = cs && cs->_staging && cs->_stagingUsed <= cs->_staging.length && !(cs->_stagingUsed & 63);
    *used = valid ? cs->_stagingUsed : 0;
    return valid ? cs->_staging : nil;
}
// A new render pass of the same command buffer stages from where the previous pass stopped (A10): its slices start at
// `used` (64-byte aligned), above every slice of the earlier passes. The arena is already on the command buffer's
// recycle list (it came from an earlier pass's _arenas), so it is not listed again; the stream's usage map records it
// when it slices it, as for any arena.
void AdrenoPassContinueStaging(AdrenoRenderPass *pass, id<MTLBuffer> arena, uint64_t used) {
    AdrenoCS *cs = [pass adrenoCS];
    if (!cs || cs->_staging || !arena || used > arena.length || (used & 63)) return;
    cs->_staging = arena;
    cs->_stagingUsed = used;
    atomic_fetch_add(&gAdrenoStagingContinued, 1);
}
void AdrenoStagingCounters(uint64_t counters[4]) {
    counters[0] = atomic_load(&gAdrenoStagingNew); counters[1] = atomic_load(&gAdrenoStagingReused);
    counters[2] = atomic_load(&gAdrenoStagingPooled); counters[3] = atomic_load(&gAdrenoStagingDropped);
}
unsigned AdrenoStagingStatistics(uint64_t *out, unsigned capacity) {
    uint64_t v[21];
    v[0] = atomic_load(&gAdrenoStagingNew); v[1] = atomic_load(&gAdrenoStagingReused);
    v[2] = atomic_load(&gAdrenoStagingPooled); v[3] = atomic_load(&gAdrenoStagingDropped);
    v[4] = atomic_load(&gAdrenoStagingLive); v[5] = atomic_load(&gAdrenoStagingLiveBytes);
    v[6] = atomic_load(&gAdrenoStagingPeak); v[7] = atomic_load(&gAdrenoStagingPeakBytes);
    os_unfair_lock_lock(&gAdrenoStagingLock);
    const AdrenoStagingPool *p = &gAdrenoStagingPolicy;
    v[8] = p->count; v[9] = p->bytes; v[11] = p->aged; v[12] = p->capped; v[13] = p->drained; v[14] = p->drains;
    v[19] = p->refused;
    os_unfair_lock_unlock(&gAdrenoStagingLock);
    v[10] = atomic_load(&gAdrenoStagingPeakPooled);
    v[15] = atomic_load(&gAdrenoStagingFailures); v[16] = atomic_load(&gAdrenoStagingRetries);
    v[17] = atomic_load(&gAdrenoStagingRetryOK); v[18] = atomic_load(&gAdrenoStagingFires);
    v[20] = atomic_load(&gAdrenoStagingContinued);
    unsigned n = capacity < 21 ? capacity : 21;
    memcpy(out, v, n * sizeof *v);
    return n;
}

// The application UBO descriptors of one stage (RD.build_ib's CONST group over B.ubo_table without the driver
// UBOs, which plan-adreno-native-triangle.py loads separately at their own index, as Mesa does).
@interface IOGPUMetalDevice (AdrenoCopyCapability)
- (BOOL)adrenoBufferCopyAvailable;
@end

#if ADRENO_UBO_MIRROR
// ================================================================================================================
// The per-command-buffer UBO mirror (agents/gpu-perf FAILURE-MODES.md U1-U13).
// A constant buffer bound at an offset that is not 64-byte aligned (Core Animation binds its 256 KiB uniform buffer at
// 16-byte offsets for every draw) used to be copied inside the pass, draw by draw, each copy bracketed by CCU and UCHE
// cleans, invalidates and two WFIs. Instead, the command buffer keeps one mirror per (source, offset mod 64): a
// 64-byte-aligned arena region holding source[phase, end), copied once by a prelude stream placed before the first
// pass that reads it. A binding at offset o reads region + (o - phase), which is 64-byte aligned. A mirror lives until
// something in the command buffer may write its source (U1); then the next reader copies again.
// ================================================================================================================
#ifndef ADRENO_UBO_MIRROR_MAX_SOURCE
#define ADRENO_UBO_MIRROR_MAX_SOURCE ((1ull << 20) - 128)   // U6: a region (+ its zero tail) stays one poolable 1 MiB arena
#endif
#ifndef ADRENO_UBO_MIRROR_MAX_BYTES
#define ADRENO_UBO_MIRROR_MAX_BYTES (8ull << 20)            // U6: source bytes mirrored per command buffer
#endif
#ifndef ADRENO_UBO_MIRROR_MAX_COPIES
#define ADRENO_UBO_MIRROR_MAX_COPIES 256u                   // U9: one prelude stays far inside one package
#endif
static _Atomic uint64_t gAdrenoMirrorCopies, gAdrenoMirrorCopyBytes, gAdrenoMirrorReads, gAdrenoMirrorFallbacks,
    gAdrenoInPassStages, gAdrenoInPassStageBytes, gAdrenoMirrorDrops;
void AdrenoUBOMirrorCounters(uint64_t out[7]) {
    out[0] = atomic_load(&gAdrenoMirrorCopies); out[1] = atomic_load(&gAdrenoMirrorCopyBytes) >> 10;
    out[2] = atomic_load(&gAdrenoMirrorReads); out[3] = atomic_load(&gAdrenoMirrorFallbacks);
    out[4] = atomic_load(&gAdrenoInPassStages); out[5] = atomic_load(&gAdrenoInPassStageBytes) >> 10;
    out[6] = atomic_load(&gAdrenoMirrorDrops);
}
// T4: ADRENO_GPU_PERF_OFF=mirror in this process's own environment (the A16 timing tool's A/B) reads every unaligned
// constant buffer the old way. WindowServer has no such variable.
static BOOL AdrenoMirrorOn(void) {
    static BOOL on; static dispatch_once_t once;
    dispatch_once(&once, ^{ const char *off = getenv("ADRENO_GPU_PERF_OFF"); on = !(off && strstr(off, "mirror")); });
    return on;
}

// One region: source[_start, _start + _length) at _arena + _offset (64-byte aligned), then at least 16 zero bytes
// (U5). A binding at offset o reads _arena + _offset + (o - _start): 64-byte aligned when o = _start (mod 64).
@interface AdrenoUBOMirror : NSObject {
@public
    __weak id<MTLBuffer> _arena;     // U7: the streams that relocate it hold it; the table never keeps an arena alive
    uint64_t _offset, _start, _length;
    BOOL _full;                      // to the end of the source (a pointer argument's copy); else one binding's bytes
    __unsafe_unretained id _owner;   // U2: the pass whose prelude copies it, until that pass ends; then nil (everyone's)
}
@end
@implementation AdrenoUBOMirror
@end

// A command buffer's mirrors (U11: one table per command buffer, used on its encoding thread).
@interface AdrenoUBOMirrors : NSObject {
@public
    NSMapTable *_entries;            // source GPU backing (identity) -> NSMutableArray of AdrenoUBOMirror, newest last
    __weak id<MTLBuffer> _arena;     // the arena new regions are cut from
    uint64_t _arenaUsed, _bytes;     // bytes cut from it; source bytes mirrored in this command buffer
}
@end
@implementation AdrenoUBOMirrors
- (instancetype)init {
    if ((self = [super init]))
        _entries = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsStrongMemory | NSPointerFunctionsObjectPointerPersonality
                                         valueOptions:NSPointerFunctionsStrongMemory];
    return self;
}
@end
static char kAdrenoUBOMirrorsKey;
static AdrenoUBOMirrors *AdrenoMirrorsOf(id commandBuffer, BOOL create) {
    AdrenoUBOMirrors *t = commandBuffer ? objc_getAssociatedObject(commandBuffer, &kAdrenoUBOMirrorsKey) : nil;
    if (!t && create && commandBuffer) {
        t = [AdrenoUBOMirrors new];
        objc_setAssociatedObject(commandBuffer, &kAdrenoUBOMirrorsKey, t, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    return t;
}
static void AdrenoMirrorsDropSource(AdrenoUBOMirrors *t, id source) {
    if (!t || !source || ![t->_entries objectForKey:source]) return;
    [t->_entries removeObjectForKey:source];
    atomic_fetch_add(&gAdrenoMirrorDrops, 1);
}
// U1(b)(c): a written texture whose storage is a buffer (or a view of one) writes that buffer too.
static void AdrenoMirrorsDropWritten(AdrenoUBOMirrors *t, id resource) {
    if (!t || !resource) return;
    AdrenoMirrorsDropSource(t, resource);
    AdrenoMirrorsDropSource(t, AdrenoGPUBacking(resource));
    if ([resource conformsToProtocol:@protocol(MTLTexture)]) {
        id<MTLTexture> x = resource;
        if (x.buffer) AdrenoMirrorsDropWritten(t, x.buffer);
        if (x.parentTexture) AdrenoMirrorsDropWritten(t, x.parentTexture);
    }
}
void AdrenoMirrorsWritten(id commandBuffer, id resource) {
    AdrenoMirrorsDropWritten(AdrenoMirrorsOf(commandBuffer, NO), resource);
}
void AdrenoMirrorsDropAll(id commandBuffer) {
    AdrenoUBOMirrors *t = AdrenoMirrorsOf(commandBuffer, NO);
    if (!t || !t->_entries.count) return;
    atomic_fetch_add(&gAdrenoMirrorDrops, t->_entries.count);
    [t->_entries removeAllObjects];
}

// What a render pass hands emit_app_ubos for one draw.
typedef struct {
    __unsafe_unretained AdrenoUBOMirrors *table;   // nil: no mirror (compute, or the switch is off)
    __unsafe_unretained id pass;
    __unsafe_unretained NSMutableArray *copies;    // @[source buffer, AdrenoUBOMirror, arena] this pass's prelude copies
    __unsafe_unretained NSMutableArray *arenas;    // arenas this pass took for regions (U7: listed once)
    BOOL off;                                      // U1(a)(b): this pass may write a buffer: the in-pass copy from here on
} AdrenoMirrorContext;
#define MIRROR_PARAM , const AdrenoMirrorContext *mc
#define MIRROR_ARG(x) , (x)

// U3: the binding's address inside a region of its source, creating the region (and its prelude copy) on first use.
// NO: the caller copies inside the pass, as before. `copy` and `padded` are the bytes the in-pass path would copy and
// the descriptor size it would give. U6, bytes never exceed the in-pass path's: a pointer argument (no AIR extent) is
// copied to the end of the buffer either way, and that region then serves every later binding of the source at or
// above its start in the same 16-byte phase mod 64 (Core Animation: one copy per command buffer); a binding with a
// known extent reuses any region that holds its bytes, else gets exactly its own bytes, copied in the prelude.
#ifndef ADRENO_UBO_MIRROR_SMALL_PER_SOURCE
#define ADRENO_UBO_MIRROR_SMALL_PER_SOURCE 32u              // regions of one binding kept for reuse, per source
#endif
static BOOL AdrenoMirrorAddr(id<MTLDevice> device, const AdrenoBufferBinding *binding, uint64_t copy, uint64_t padded,
                             BOOL pointer, NSString *what, const AdrenoMirrorContext *mc, AdrenoAddr *out) {
    if (!mc || !mc->table || mc->off || !AdrenoMirrorOn()) return NO;
    id<MTLBuffer> buffer = binding->buffer;
    id source = AdrenoGPUBacking(buffer);
    if (![source isKindOfClass:[IOGPUMetalResource class]] || ![(IOGPUMetalResource *)source resourceID]) return NO;
    const uint64_t length = buffer.length, o = binding->offset;
    if (length > [(IOGPUMetalResource *)source resourceSize] || o >= length || copy > length - o || (copy & 3) || !copy ||
        padded < copy || padded - copy > 15 || (pointer && length - o > ADRENO_UBO_MIRROR_MAX_SOURCE)) {
        atomic_fetch_add(&gAdrenoMirrorFallbacks, 1);
        return NO;
    }
    AdrenoUBOMirrors *t = mc->table;
    NSMutableArray *list = [t->_entries objectForKey:source];
    AdrenoUBOMirror *m = nil;
    id<MTLBuffer> arena = nil;
    for (AdrenoUBOMirror *e in list.reverseObjectEnumerator)
        if (o >= e->_start && !((o - e->_start) & 63) && o + copy <= e->_start + e->_length &&
            (!e->_owner || e->_owner == mc->pass)) {
            arena = e->_arena;
            if (arena) { m = e; break; }
        }
    if (!m) {
        const uint64_t bytes = pointer ? length - o : copy, region = (bytes + 16 + 63) & ~63ull;
        if (t->_bytes + bytes > ADRENO_UBO_MIRROR_MAX_BYTES || mc->copies.count >= ADRENO_UBO_MIRROR_MAX_COPIES) {
            atomic_fetch_add(&gAdrenoMirrorFallbacks, 1);
            return NO;
        }
        arena = t->_arena;
        if (!arena || t->_arenaUsed > arena.length || region > arena.length - t->_arenaUsed) {
#if ADRENO_UBO_MIRROR_SLABS
            // R2, R4: a slab of this device (allocated once, never released); none free and the cap reached, or a
            // region larger than a slab: the in-pass copy.
            arena = region <= ADRENO_UBO_MIRROR_SLAB_BYTES ? AdrenoMirrorSlabTake(device) : nil;
            if (!arena) {
                atomic_fetch_add(&gAdrenoMirrorFallbacks, 1);
                return NO;
            }
            [mc->arenas addObject:arena];       // R1: returned to the slab list when the command buffer completes cleanly
#else
            const uint64_t size = adreno_staging_class(region, 0);
            arena = adreno_staging_poolable(size) ? AdrenoStagingArenaTake(device, size) : nil;
            if (!arena) arena = AdrenoStagingArenaNew(device, size);
            if (!arena || !arena.contents || arena.length < region) {
                atomic_fetch_add(&gAdrenoMirrorFallbacks, 1);
                return NO;                       // U6: the in-pass copy still works without an arena
            }
            // Pooled after the command buffer completes (a larger one, which a region never needs, would be released
            // with the streams that relocate it).
            if (adreno_staging_poolable(arena.length)) [mc->arenas addObject:arena];
#endif
            t->_arena = arena; t->_arenaUsed = 0;
        }
        m = [AdrenoUBOMirror new];
        m->_arena = arena; m->_offset = t->_arenaUsed; m->_start = o; m->_length = bytes; m->_full = pointer;
        m->_owner = mc->pass;
        t->_arenaUsed += region; t->_bytes += bytes;
        memset((uint8_t *)arena.contents + m->_offset + bytes, 0, (size_t)(region - bytes));   // U5: the zero tail
        if (!list) { list = [NSMutableArray array]; [t->_entries setObject:list forKey:source]; }
        [list addObject:m];
        if (!pointer) {                          // keep the newest few one-binding regions of this source for reuse
            NSUInteger small = 0;
            for (AdrenoUBOMirror *e in list) small += !e->_full;
            for (NSUInteger i = 0; small > ADRENO_UBO_MIRROR_SMALL_PER_SOURCE && i < list.count;)
                if (!((AdrenoUBOMirror *)list[i])->_full) { [list removeObjectAtIndex:i]; small--; } else i++;
        }
        [mc->copies addObject:@[buffer, m, arena]];      // strong until the prelude is built (U7)
    }
    // o + padded <= _start + _length + 15 < the region's end: the descriptor stays inside the region and its zero tail.
    *out = AdrenoResourceAddr(arena, m->_offset + (o - m->_start), padded, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_UBO,
                              what);
    atomic_fetch_add(&gAdrenoMirrorReads, 1);
    return YES;
}
#else
#define MIRROR_PARAM
#define MIRROR_ARG(x)
#endif

// minimum: the bytes ir3's analysed ranges read (16-byte multiple). extent: the argument's Metal-visible size from AIR
// (air.buffer_size: a `constant T&` reads only sizeof(T)), 0 when unknown (a `constant T*`).
static AdrenoAddr AdrenoUBOBindingAddr(AdrenoCS *cs, id<MTLDevice> device, const AdrenoBufferBinding *binding,
                                      uint64_t minimum, uint64_t extent, uint64_t *bytes, NSString *what MIRROR_PARAM) {
    // Inline setBytes is already padded and aligned by cs_data.
    if (binding->bytes || !binding->buffer || binding->offset >= binding->buffer.length)
        return AdrenoBindingAddr(cs, binding, minimum, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_UBO,
                                 ADRENO_UBO_MAX_BYTES, bytes, what);
    uint64_t available = MIN((uint64_t)(binding->buffer.length - binding->offset), ADRENO_UBO_MAX_BYTES);
    if (!(binding->offset & 63) && !(available & 15))
        return AdrenoBindingAddr(cs, binding, minimum, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_UBO,
                                 ADRENO_UBO_MAX_BYTES, bytes, what);
    if (available < minimum || (binding->offset & 3) || (available & 3))
        AdrenoDrawRefuse(@"%@: staging requires an in-bounds dword-aligned source", what);
    if (![(id)device respondsToSelector:@selector(adrenoBufferCopyAvailable)] ||
        ![(IOGPUMetalDevice *)device adrenoBufferCopyAvailable])
        AdrenoDrawRefuse(@"%@: unaligned UBO staging requires AdrenoIBCopyABI=1", what);
    // Copy what the shader can read (docs/USERSPACE-GRAPHICS-20261019.md, "Speed: CoreAnimation uniforms staged by the
    // kilobyte"): the AIR extent when known, and never less than ir3's ranges; otherwise everything up to the end of the
    // buffer, as before. CoreAnimation binds a 256 KB uniform buffer at 16-byte offsets for every draw.
    uint64_t copy = extent ? MIN(available, MAX(minimum, (extent + 15) & ~15ull)) : available;
    uint64_t padded = (copy + 15) & ~15ull;
#if ADRENO_UBO_MIRROR
    AdrenoAddr mirrored;
    if (AdrenoMirrorAddr(device, binding, copy, padded, !extent, what, mc, &mirrored)) { *bytes = padded; return mirrored; }
    atomic_fetch_add(&gAdrenoInPassStages, 1);
    atomic_fetch_add(&gAdrenoInPassStageBytes, copy);
#endif
    // One shared arena per command stream instead of a new buffer per binding: 64-byte slices, a new arena only when the
    // current one is full (a pointer argument still copies up to the end of its buffer, about 200 KB for
    // CoreAnimation's). A render pass continues the arena its command buffer's previous pass ended with
    // (AdrenoPassContinueStaging). A new arena is the smallest of 64 KiB, 256 KiB and 1 MiB that holds the copy and is at
    // least 4 times the full one (docs/PLUGIN-ARENA-TRIM-20261021.md); it comes from the process's pool of arenas whose
    // command buffers completed (C3), else it is allocated; larger ones (one copy above 1 MiB) are never pooled.
    if (!cs->_staging || cs->_stagingUsed > cs->_staging.length || padded > cs->_staging.length - cs->_stagingUsed) {
        const uint64_t length = adreno_staging_class(padded, cs->_staging ? cs->_staging.length : 0);
        id<MTLBuffer> arena = adreno_staging_poolable(length) ? AdrenoStagingArenaTake(device, length) : nil;
        if (!arena) arena = AdrenoStagingArenaNew(device, length);
        cs->_staging = arena;
        cs->_stagingUsed = 0;
        if (!cs->_staging || !cs->_staging.contents) AdrenoDrawRefuse(@"%@: aligned staging allocation failed", what);
        if (adreno_staging_poolable(arena.length)) {
            if (!cs->_arenas) cs->_arenas = [NSMutableArray array];
            [cs->_arenas addObject:arena];
        }
    }
    const uint64_t slice = cs->_stagingUsed;
    cs->_stagingUsed = (slice + padded + 63) & ~63ull;
    // Zero from the copied bytes to the next slice: the descriptor's padding and the gap a fresh arena held as zeros (a
    // recycled arena holds earlier copies there).
    if (cs->_stagingUsed > slice + copy)
        memset((uint8_t *)cs->_staging.contents + slice + copy, 0, (size_t)(cs->_stagingUsed - slice - copy));
    AdrenoAddr source = AdrenoResourceAddr(binding->buffer, binding->offset, copy, ADRENO_IB_ACCESS_READ, 2, what);
    AdrenoAddr destination = AdrenoResourceAddr(cs->_staging, slice, padded, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                               ADRENO_IB_ALIGN_LOG2_UBO, @"aligned UBO staging");
    // Read the buffer when the GPU executes this draw, including preceding GPU
    // writes. Copying its CPU contents while encoding would change Metal semantics.
    emit_flushes(cs, (AdrenoFlushes){.ccuColor=YES, .ccuDepth=YES, .cache=YES, .wfi=YES});
    cs_pkt7(cs, E(CP_WAIT_MEM_WRITES), NULL, 0);
    uint64_t at = cs_dwords(cs);
    PKT7(cs, E(CP_MEMCPY), (uint32_t)(copy / 4), 0, 0, 0, 0);
    cs_reloc(cs, ADRENO_SPACE_IB, at + 2, ADRENO_SPACE_IB, at + 3, ADRENO_IB_HI_BITS_REG64, source);
    cs_reloc(cs, ADRENO_SPACE_IB, at + 4, ADRENO_SPACE_IB, at + 5, ADRENO_IB_HI_BITS_REG64, destination);
    cs_pkt7(cs, E(CP_WAIT_MEM_WRITES), NULL, 0);
    cs_event(cs, E(CACHE_INVALIDATE7));
    cs_wfi(cs);
    cs_pkt7(cs, E(CP_CCHE_INVALIDATE), NULL, 0);
    *bytes = padded;
    return destination;
}

static void emit_app_ubos(AdrenoCS *cs, NSDictionary *v, BOOL vertex, const AdrenoBufferBinding *bindings,
                           id<MTLDevice> device MIRROR_PARAM) {
    NSInteger count = PInt(PDict(v, @"const_state"), @"num_app_ubos");
    AdrenoUBO ubos[ADRENO_UBO_SLOTS];
    memset(ubos, 0, sizeof ubos);
    NSString *stage = vertex ? @"vertex" : @"fragment";
    BOOL used[ADRENO_UBO_SLOTS] = {NO};
    for (NSDictionary *b in Bindings(v, @"ubo")) {
        if (!BoundOrUsed(b)) continue;
        NSInteger slot = PInt(b, @"slot"), index = PInt(b, @"metal_index");
        if (slot < 0 || slot >= count) AdrenoDrawRefuse(@"%@: UBO %ld is beyond the %ld descriptors ir3 loads", stage, (long)slot, (long)count);
        if (index < 0 || index >= (NSInteger)ADRENO_DRAW_BUFFER_SLOTS) AdrenoDrawRefuse(@"%@: buffer(%ld)", stage, (long)index);
        // A declared constant buffer the code never reads (reflection `used`: the AIR argument has no uses) that the draw
        // does not bind keeps no descriptor.
        if (!Used(b) && !bindings[index].buffer && !bindings[index].bytes) continue;
        NSString *what = [NSString stringWithFormat:@"%@ constant buffer(%ld)", stage, (long)index];
        NSNumber *extent = [b[@"minimum_bytes"] isKindOfClass:[NSNumber class]] ? b[@"minimum_bytes"] : nil;
        ubos[slot].addr = AdrenoUBOBindingAddr(cs, device, &bindings[index], (AdrenoUBOMinBytes(v, slot) + 15) & ~15ull,
                                               extent.longLongValue > 0 ? (uint64_t)extent.longLongValue : 0,
                                               &ubos[slot].bytes, what MIRROR_ARG(mc));
        ubos[slot].present = used[slot] = YES;
    }
    NSInteger dt = AdrenoDriverTableUBO(v);
    // v38 (com.apple.dock.extra): device buffers that are declared but never read. ir3.stats.driver_table_ubo is -1 when
    // the code reads no table (BINDING-ABI 3.2), and ir3 then loads no descriptor for it: nothing to write.
    if (dt != -1 && PInt(PDict(PDict(PDict(v, @"sidecar"), @"ir3"), @"stats"), @"driver_table_ubo") == -1) dt = -1;
    if (dt != -1) {
        if (dt >= count || used[dt]) AdrenoDrawRefuse(@"%@: driver table UBO %ld collides or is not loaded", stage, (long)dt);
        // B.driver_table: u64 VA of device buffer n at the binding's slot (a byte offset), zero elsewhere.
        uint8_t table[ADRENO_DRIVER_TABLE_BYTES] = {0};
        uint64_t at = cs_data(cs, table, sizeof table, sizeof table);
        for (NSDictionary *b in Bindings(v, @"device_buffer")) {
            if (!BoundOrUsed(b)) continue;
            NSInteger slot = PInt(b, @"slot"), index = PInt(b, @"metal_index");
            if (slot < 0 || slot % 8 || slot + 8 > (NSInteger)ADRENO_DRIVER_TABLE_BYTES || index < 0 ||
                index >= (NSInteger)ADRENO_DRAW_BUFFER_SLOTS)
                AdrenoDrawRefuse(@"%@: device buffer(%ld) at driver-table byte %ld", stage, (long)index, (long)slot);
            if (!Used(b) && !bindings[index].buffer && !bindings[index].bytes) continue;   // never read: 0
            uint64_t bytes = 0;
            NSString *what = [NSString stringWithFormat:@"%@ device buffer(%ld)", stage, (long)index];
            AdrenoAddr a = AdrenoBindingAddr(cs, &bindings[index], 1, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                             ADRENO_IB_ALIGN_LOG2_VERTEX, UINT32_MAX, &bytes, what);
            if (a.kind == ADRENO_IB_RELOC_PACKAGE) a.access = ADRENO_IB_ACCESS_READ;   // setBytes copies are read-only
            cs_data_address(cs, at + (uint64_t)slot, a);
        }
        ubos[dt].present = YES;
        ubos[dt].bytes = ADRENO_DRIVER_TABLE_BYTES;
        ubos[dt].addr = AdrenoPackageAddr(at, ADRENO_DRIVER_TABLE_BYTES, ADRENO_IB_ALIGN_LOG2_UBO);
    }
    emit_ubo_load(cs, vertex, 0, ubos, (uint32_t)count);
}
// emit_app_ubos from the stage's plan: the same loop, checks and helpers over the decoded tables.
static void emit_app_ubos_planned(AdrenoCS *cs, const AdrenoStagePlan *p, BOOL vertex, const AdrenoBufferBinding *bindings,
                                  id<MTLDevice> device MIRROR_PARAM) {
    NSInteger count = p->uboCount;
    AdrenoUBO ubos[ADRENO_UBO_SLOTS];
    memset(ubos, 0, sizeof ubos);
    NSString *stage = vertex ? @"vertex" : @"fragment";
    BOOL used[ADRENO_UBO_SLOTS] = {NO};
    for (uint32_t k = 0; k < p->nUBO; k++) {
        const AdrenoPlanBuffer *b = &p->ubo[k];
        NSInteger slot = b->slot, index = b->index;
        if (slot < 0 || slot >= count) AdrenoDrawRefuse(@"%@: UBO %ld is beyond the %ld descriptors ir3 loads", stage, (long)slot, (long)count);
        if (index < 0 || index >= (NSInteger)ADRENO_DRAW_BUFFER_SLOTS) AdrenoDrawRefuse(@"%@: buffer(%ld)", stage, (long)index);
        if (!b->used && !bindings[index].buffer && !bindings[index].bytes) continue;
        NSString *what = AdrenoSlotName(vertex ? AdrenoSlotVertexUBO : AdrenoSlotFragmentUBO, index);
        ubos[slot].addr = AdrenoUBOBindingAddr(cs, device, &bindings[index], b->minBytes, b->extent, &ubos[slot].bytes, what
                                               MIRROR_ARG(mc));
        ubos[slot].present = used[slot] = YES;
    }
    NSInteger dt = p->driverTable;
    if (dt != -1) {
        if (dt >= count || used[dt]) AdrenoDrawRefuse(@"%@: driver table UBO %ld collides or is not loaded", stage, (long)dt);
        uint8_t table[ADRENO_DRIVER_TABLE_BYTES] = {0};
        uint64_t at = cs_data(cs, table, sizeof table, sizeof table);
        for (uint32_t k = 0; k < p->nDevice; k++) {
            const AdrenoPlanBuffer *b = &p->device[k];
            NSInteger slot = b->slot, index = b->index;
            if (slot < 0 || slot % 8 || slot + 8 > (NSInteger)ADRENO_DRIVER_TABLE_BYTES || index < 0 ||
                index >= (NSInteger)ADRENO_DRAW_BUFFER_SLOTS)
                AdrenoDrawRefuse(@"%@: device buffer(%ld) at driver-table byte %ld", stage, (long)index, (long)slot);
            if (!b->used && !bindings[index].buffer && !bindings[index].bytes) continue;   // never read: 0
            uint64_t bytes = 0;
            NSString *what = AdrenoSlotName(vertex ? AdrenoSlotVertexDevice : AdrenoSlotFragmentDevice, index);
            AdrenoAddr a = AdrenoBindingAddr(cs, &bindings[index], 1, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                             ADRENO_IB_ALIGN_LOG2_VERTEX, UINT32_MAX, &bytes, what);
            if (a.kind == ADRENO_IB_RELOC_PACKAGE) a.access = ADRENO_IB_ACCESS_READ;   // setBytes copies are read-only
            cs_data_address(cs, at + (uint64_t)slot, a);
        }
        ubos[dt].present = YES;
        ubos[dt].bytes = ADRENO_DRIVER_TABLE_BYTES;
        ubos[dt].addr = AdrenoPackageAddr(at, ADRENO_DRIVER_TABLE_BYTES, ADRENO_IB_ALIGN_LOG2_UBO);
    }
    emit_ubo_load(cs, vertex, 0, ubos, (uint32_t)count);
}
// The stage's UBO tables as emit_app_ubos reads them; throws where reading the export throws.
static BOOL AdrenoDecodeStage(NSDictionary *v, AdrenoStagePlan *s) {
    s->uboCount = PInt(PDict(v, @"const_state"), @"num_app_ubos");
    s->nUBO = s->nDevice = 0;
    for (NSDictionary *b in Bindings(v, @"ubo")) {
        if (!BoundOrUsed(b)) continue;
        if (s->nUBO >= ADRENO_PLAN_BINDINGS) return NO;
        AdrenoPlanBuffer *e = &s->ubo[s->nUBO++];
        e->slot = PInt(b, @"slot"); e->index = PInt(b, @"metal_index"); e->used = Used(b);
        NSNumber *extent = [b[@"minimum_bytes"] isKindOfClass:[NSNumber class]] ? b[@"minimum_bytes"] : nil;
        e->extent = extent.longLongValue > 0 ? (uint64_t)extent.longLongValue : 0;
        e->minBytes = (AdrenoUBOMinBytes(v, e->slot) + 15) & ~15ull;
    }
    NSInteger dt = AdrenoDriverTableUBO(v);
    if (dt != -1 && PInt(PDict(PDict(PDict(v, @"sidecar"), @"ir3"), @"stats"), @"driver_table_ubo") == -1) dt = -1;
    s->driverTable = dt;
    if (dt != -1)
        for (NSDictionary *b in Bindings(v, @"device_buffer")) {
            if (!BoundOrUsed(b)) continue;
            if (s->nDevice >= ADRENO_PLAN_BINDINGS) return NO;
            AdrenoPlanBuffer *e = &s->device[s->nDevice++];
            e->slot = PInt(b, @"slot"); e->index = PInt(b, @"metal_index"); e->used = Used(b);
            e->extent = e->minBytes = 0;
        }
    return YES;
}

// The driver constant-data UBOs (Mesa fd6_const.cc fd6_emit_driver_ubo; plan-adreno-native-triangle.py): one
// separate CP_LOAD_STATE6 ST6_UBO per driver UBO at its own index, pointing into the stage's code buffer.
static void emit_driver_ubos(AdrenoCS *cs, NSDictionary *v, BOOL vertex, id<MTLBuffer> code) {
    NSDictionary *cs_ = PDict(v, @"const_state"), *info = PDict(v, @"info");
    for (NSDictionary *driver in PArray(PDict(PDict(v, @"sidecar"), @"ir3"), @"driver_ubos")) {
        if (![driver[@"kind"] isEqual:@"constant_data"]) AdrenoDrawRefuse(@"driver UBO %@", driver[@"kind"]);
        NSInteger slot = PInt(driver, @"ubo");
        uint64_t size = 16 * PU(driver, @"size_vec4"), offset = PU(info, @"constant_data_offset");
        if (slot != PInt(cs_, @"consts_ubo") || slot < PInt(cs_, @"num_app_ubos") || slot >= ADRENO_UBO_SLOTS ||
            !offset || offset % 16 || !size || offset + size > PU(info, @"size"))
            AdrenoDrawRefuse(@"driver constant data UBO %ld (%llu bytes at %llu) is inconsistent", (long)slot, size, offset);
        AdrenoUBO ubo = {YES, AdrenoResourceAddr(code, offset, size, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_UBO,
                                                 vertex ? @"vertex constant data" : @"fragment constant data"), size};
        emit_ubo_load(cs, vertex, (uint32_t)slot, &ubo, 1);
    }
}

// Fragment texture state follows fdl6_view_init<A8XX> and fd6_sampler_state_create<A8XX>.
// Resource addresses stay symbolic until the kernel has retained and mapped the command's resources.
static uint32_t AdrenoSamplerWrap(MTLSamplerAddressMode mode) {
    switch (mode) {
        case MTLSamplerAddressModeClampToEdge: return E(A6XX_TEX_CLAMP_TO_EDGE);
        case MTLSamplerAddressModeRepeat: return E(A6XX_TEX_REPEAT);
        case MTLSamplerAddressModeMirrorRepeat: return E(A6XX_TEX_MIRROR_REPEAT);
        case MTLSamplerAddressModeMirrorClampToEdge: return E(A6XX_TEX_MIRROR_CLAMP);
        case MTLSamplerAddressModeClampToZero:
        case MTLSamplerAddressModeClampToBorderColor: return E(A6XX_TEX_CLAMP_TO_BORDER);
        default: AdrenoDrawRefuse(@"sampler address mode %lu", (unsigned long)mode);
    }
}
static uint32_t AdrenoSamplerCompare(MTLCompareFunction compare) {
    switch (compare) {
        case MTLCompareFunctionNever: return E(FUNC_NEVER);
        case MTLCompareFunctionLess: return E(FUNC_LESS);
        case MTLCompareFunctionEqual: return E(FUNC_EQUAL);
        case MTLCompareFunctionLessEqual: return E(FUNC_LEQUAL);
        case MTLCompareFunctionGreater: return E(FUNC_GREATER);
        case MTLCompareFunctionNotEqual: return E(FUNC_NOTEQUAL);
        case MTLCompareFunctionGreaterEqual: return E(FUNC_GEQUAL);
        case MTLCompareFunctionAlways: return E(FUNC_ALWAYS);
        default: AdrenoDrawRefuse(@"sampler compare function %lu", (unsigned long)compare);
    }
}
static void AdrenoSamplerWords(MTLSamplerDescriptor *s, uint32_t d[4]) {
    // The LOD fields hold [0, 4095/256]: an infinite or NaN clamp is the same as the field's end (v29: the Dock's icon
    // renderer). lodAverage (quad-averaged LOD) has no A8XX bit and is approximated by per-pixel LOD.
    if (!s || s.minFilter > MTLSamplerMinMagFilterLinear || s.magFilter > MTLSamplerMinMagFilterLinear ||
        s.mipFilter > MTLSamplerMipFilterLinear)
        AdrenoDrawRefuse(@"unsupported sampler filter %lu/%lu/%lu", (unsigned long)s.minFilter, (unsigned long)s.magFilter,
                         (unsigned long)s.mipFilter);
    const double lodMin = isnan(s.lodMinClamp) ? 0 : s.lodMinClamp;
    const double lodMax = isnan(s.lodMaxClamp) ? 4095.0 / 256.0 : s.lodMaxClamp;
    if (lodMin > lodMax) AdrenoDrawRefuse(@"sampler LOD clamp %g > %g", lodMin, lodMax);
    // Anisotropy rounds down to the power of two A8XX encodes (1..16).
    NSUInteger aniso = MIN(MAX(s.maxAnisotropy, (NSUInteger)1), (NSUInteger)16);
    while (aniso & (aniso - 1)) aniso &= aniso - 1;
    unsigned anisoBits = (unsigned)__builtin_ctz((unsigned)aniso);
    uint32_t linear = aniso > 1 ? E(A6XX_TEX_ANISO) : E(A6XX_TEX_LINEAR);
    d[0] = DF(A8XX_TEX_SAMP_0, MIPFILTER_LINEAR_NEAR, s.mipFilter == MTLSamplerMipFilterLinear) |
           DF(A8XX_TEX_SAMP_0, MIPMAPING_DIS, s.mipFilter == MTLSamplerMipFilterNotMipmapped) |
           DF(A8XX_TEX_SAMP_0, XY_MAG, s.magFilter == MTLSamplerMinMagFilterLinear ? linear : E(A6XX_TEX_NEAREST)) |
           DF(A8XX_TEX_SAMP_0, XY_MIN, s.minFilter == MTLSamplerMinMagFilterLinear ? linear : E(A6XX_TEX_NEAREST)) |
           DF(A8XX_TEX_SAMP_0, WRAP_S, AdrenoSamplerWrap(s.sAddressMode)) |
           DF(A8XX_TEX_SAMP_0, WRAP_T, AdrenoSamplerWrap(s.tAddressMode)) |
           DF(A8XX_TEX_SAMP_0, WRAP_R, AdrenoSamplerWrap(s.rAddressMode)) |
           DF(A8XX_TEX_SAMP_0, ANISO, anisoBits);
    double limit = s.mipFilter == MTLSamplerMipFilterNotMipmapped ? 0.25 : 4095.0 / 256.0;
    double lo = s.normalizedCoordinates ? fmin(fmax(lodMin, 0), limit) : 0;
    double hi = s.normalizedCoordinates ? fmin(fmax(lodMax, 0), limit) : 0;
    d[1] = DFIX(A8XX_TEX_SAMP_1, MAX_LOD, 8, hi) | DFIX(A8XX_TEX_SAMP_1, MIN_LOD, 8, lo) |
           DF(A8XX_TEX_SAMP_1, REDUCTION_MODE, E(A6XX_REDUCTION_MODE_AVERAGE)) |
           DF(A8XX_TEX_SAMP_1, COMPARE_FUNC, AdrenoSamplerCompare(s.compareFunction)) |
           DF(A8XX_TEX_SAMP_1, CHROMA_LINEAR, s.magFilter == MTLSamplerMinMagFilterLinear && s.minFilter == MTLSamplerMinMagFilterLinear) |
           DF(A8XX_TEX_SAMP_1, UNNORM_COORDS, !s.normalizedCoordinates);
    d[2] = d[3] = 0;
    BOOL zero = s.sAddressMode == MTLSamplerAddressModeClampToZero || s.tAddressMode == MTLSamplerAddressModeClampToZero ||
                s.rAddressMode == MTLSamplerAddressModeClampToZero;
    BOOL border = s.sAddressMode == MTLSamplerAddressModeClampToBorderColor || s.tAddressMode == MTLSamplerAddressModeClampToBorderColor ||
                  s.rAddressMode == MTLSamplerAddressModeClampToBorderColor;
    if (zero && border && s.borderColor != MTLSamplerBorderColorTransparentBlack)
        AdrenoDrawRefuse(@"different border colors on sampler axes are not supported");
    if (zero || border) {
        uint32_t color = E(A6XX_BORDER_COLOR_0_0_0_0);
        if (border) switch (s.borderColor) {
            case MTLSamplerBorderColorTransparentBlack: break;
            case MTLSamplerBorderColorOpaqueBlack: color = E(A6XX_BORDER_COLOR_0_0_0_1); break;
            case MTLSamplerBorderColorOpaqueWhite: color = E(A6XX_BORDER_COLOR_1_1_1_1); break;
            default: AdrenoDrawRefuse(@"sampler border color %lu", (unsigned long)s.borderColor);
        }
        d[2] = DF(A8XX_TEX_SAMP_2, FASTBORDERCOLOR, color) | DF(A8XX_TEX_SAMP_2, FASTBORDERCOLOREN, 1);
    }
}
// The linear TEX formats (fd6_format_table.c) of what the plug-in samples or fetches: TEX format, bytes per pixel, swap,
// the format's own channel mapping (missing colour channels 0, alpha 1; A8 in W) and sRGB decode.
typedef struct { uint32_t fmt, cpp, swap, swiz[4]; BOOL srgb; } AdrenoTexFormat;
static BOOL AdrenoTexFormatOf(MTLPixelFormat format, AdrenoTexFormat *out) {
    const uint32_t X = E(A8XX_SWIZ_X), Y = E(A8XX_SWIZ_Y), Z = E(A8XX_SWIZ_Z), W = E(A8XX_SWIZ_W);
    const uint32_t O = E(A8XX_SWIZ_ZERO), I = E(A8XX_SWIZ_ONE), WZYX = E(WZYX), WXYZ = E(WXYZ);
    switch (format) {
        case MTLPixelFormatRGBA8Unorm_sRGB: *out = (AdrenoTexFormat){E(FMT6_8_8_8_8_UNORM), 4, WZYX, {X, Y, Z, W}, YES}; return YES;
        case MTLPixelFormatRGBA8Unorm: *out = (AdrenoTexFormat){E(FMT6_8_8_8_8_UNORM), 4, WZYX, {X, Y, Z, W}, NO}; return YES;
        case MTLPixelFormatBGRA8Unorm_sRGB: *out = (AdrenoTexFormat){E(FMT6_8_8_8_8_UNORM), 4, WXYZ, {X, Y, Z, W}, YES}; return YES;
        case MTLPixelFormatBGRA8Unorm: *out = (AdrenoTexFormat){E(FMT6_8_8_8_8_UNORM), 4, WXYZ, {X, Y, Z, W}, NO}; return YES;
        case MTLPixelFormatR8Unorm: *out = (AdrenoTexFormat){E(FMT6_8_UNORM), 1, WZYX, {X, O, O, I}, NO}; return YES;
        case MTLPixelFormatRG8Unorm: *out = (AdrenoTexFormat){E(FMT6_8_8_UNORM), 2, WZYX, {X, Y, O, I}, NO}; return YES;
        case MTLPixelFormatRGBA16Float: *out = (AdrenoTexFormat){E(FMT6_16_16_16_16_FLOAT), 8, WZYX, {X, Y, Z, W}, NO}; return YES;
        case MTLPixelFormatR16Float: *out = (AdrenoTexFormat){E(FMT6_16_FLOAT), 2, WZYX, {X, O, O, I}, NO}; return YES;
        case MTLPixelFormatRG16Float: *out = (AdrenoTexFormat){E(FMT6_16_16_FLOAT), 4, WZYX, {X, Y, O, I}, NO}; return YES;
        // v31: WindowServer samples A8 masks (text, shapes) and 384x384 RGBA16Unorm images (Dock icons).
        case MTLPixelFormatA8Unorm: *out = (AdrenoTexFormat){E(FMT6_8_UNORM), 1, WZYX, {O, O, O, X}, NO}; return YES;
        case MTLPixelFormatR16Unorm: *out = (AdrenoTexFormat){E(FMT6_16_UNORM), 2, WZYX, {X, O, O, I}, NO}; return YES;
        case MTLPixelFormatRG16Unorm: *out = (AdrenoTexFormat){E(FMT6_16_16_UNORM), 4, WZYX, {X, Y, O, I}, NO}; return YES;
        case MTLPixelFormatRGBA16Unorm: *out = (AdrenoTexFormat){E(FMT6_16_16_16_16_UNORM), 8, WZYX, {X, Y, Z, W}, NO}; return YES;
        case MTLPixelFormatR32Float: *out = (AdrenoTexFormat){E(FMT6_32_FLOAT), 4, WZYX, {X, O, O, I}, NO}; return YES;
        case MTLPixelFormatRG32Float: *out = (AdrenoTexFormat){E(FMT6_32_32_FLOAT), 8, WZYX, {X, Y, O, I}, NO}; return YES;
        case MTLPixelFormatRGBA32Float: *out = (AdrenoTexFormat){E(FMT6_32_32_32_32_FLOAT), 16, WZYX, {X, Y, Z, W}, NO}; return YES;
        // v35: 'l10r' surfaces (fd6_format_table.c B10G10R10A2_UNORM / R10G10B10A2_UNORM: FMT6_10_10_10_2_UNORM).
        case MTLPixelFormatBGR10A2Unorm: *out = (AdrenoTexFormat){E(FMT6_10_10_10_2_UNORM), 4, WXYZ, {X, Y, Z, W}, NO}; return YES;
        case MTLPixelFormatRGB10A2Unorm: *out = (AdrenoTexFormat){E(FMT6_10_10_10_2_UNORM), 4, WZYX, {X, Y, Z, W}, NO}; return YES;
        // F2: integer textures (read with read()/txf; Core Animation's brim passes read RG16Uint): the format's channels,
        // 0 and 1 for the rest.
#define INT_TEX(MTL, FMT, CPP, SX, SY, SZ, SW) case MTLPixelFormat##MTL: \
            *out = (AdrenoTexFormat){E(FMT), CPP, WZYX, {SX, SY, SZ, SW}, NO}; return YES;
        INT_TEX(R8Uint, FMT6_8_UINT, 1, X, O, O, I) INT_TEX(R8Sint, FMT6_8_SINT, 1, X, O, O, I)
        INT_TEX(RG8Uint, FMT6_8_8_UINT, 2, X, Y, O, I) INT_TEX(RG8Sint, FMT6_8_8_SINT, 2, X, Y, O, I)
        INT_TEX(RGBA8Uint, FMT6_8_8_8_8_UINT, 4, X, Y, Z, W) INT_TEX(RGBA8Sint, FMT6_8_8_8_8_SINT, 4, X, Y, Z, W)
        INT_TEX(R16Uint, FMT6_16_UINT, 2, X, O, O, I) INT_TEX(R16Sint, FMT6_16_SINT, 2, X, O, O, I)
        INT_TEX(RG16Uint, FMT6_16_16_UINT, 4, X, Y, O, I) INT_TEX(RG16Sint, FMT6_16_16_SINT, 4, X, Y, O, I)
        INT_TEX(RGBA16Uint, FMT6_16_16_16_16_UINT, 8, X, Y, Z, W) INT_TEX(RGBA16Sint, FMT6_16_16_16_16_SINT, 8, X, Y, Z, W)
        INT_TEX(R32Uint, FMT6_32_UINT, 4, X, O, O, I) INT_TEX(R32Sint, FMT6_32_SINT, 4, X, O, O, I)
        INT_TEX(RG32Uint, FMT6_32_32_UINT, 8, X, Y, O, I) INT_TEX(RG32Sint, FMT6_32_32_SINT, 8, X, Y, O, I)
        INT_TEX(RGBA32Uint, FMT6_32_32_32_32_UINT, 16, X, Y, Z, W) INT_TEX(RGBA32Sint, FMT6_32_32_32_32_SINT, 16, X, Y, Z, W)
#undef INT_TEX
        default: return NO;
    }
}
// fdl6_view_init<A8XX> for one linear level (a 2D image, or a one-slice 3D one): the T# words except the base address
// (dwords 0 and 1's BASE_HI stay zero for the relocation). Returns the bytes the view covers (rows * pitch).
static uint64_t AdrenoLinearViewWords(uint32_t d[16], const AdrenoTexFormat *f, const uint32_t swiz[4], uint64_t rowBytes,
                                      uint64_t width, uint64_t height, BOOL volume) {
    uint64_t size = rowBytes * height;
    // Level 0 has an explicit pitch; MIN_LINE_OFFSET is the lower levels' pitch alignment, the one AdrenoLevelLayout
    // lays them out with (AdrenoMipLineShift: 256 bytes where the pitch allows it).
    uint32_t minLine = (uint32_t)AdrenoMipLineShift((NSUInteger)rowBytes);
    memset(d, 0, 64);
    d[1] = DF(A8XX_TEX_MEMOBJ_1, TYPE, volume ? E(A6XX_TEX_3D) : E(A6XX_TEX_2D)) | DF(A8XX_TEX_MEMOBJ_1, DEPTH, 1);
    d[2] = DF(A8XX_TEX_MEMOBJ_2, WIDTH, width) | DF(A8XX_TEX_MEMOBJ_2, HEIGHT, height) |
           DF(A8XX_TEX_MEMOBJ_2, SAMPLES, E(MSAA_ONE));
    d[3] = DF(A8XX_TEX_MEMOBJ_3, FMT, f->fmt) | DF(A8XX_TEX_MEMOBJ_3, SWAP, f->swap) |
           DF(A8XX_TEX_MEMOBJ_3, SWIZ_X, swiz[0]) | DF(A8XX_TEX_MEMOBJ_3, SWIZ_Y, swiz[1]) |
           DF(A8XX_TEX_MEMOBJ_3, SWIZ_Z, swiz[2]) | DF(A8XX_TEX_MEMOBJ_3, SWIZ_W, swiz[3]);
    d[4] = DF(A8XX_TEX_MEMOBJ_4, TILE_MODE, E(TILE6_LINEAR)) | DF(A8XX_TEX_MEMOBJ_4, SRGB, f->srgb);
    d[6] = DF(A8XX_TEX_MEMOBJ_6, TEX_LINE_OFFSET, rowBytes * 8) | DF(A8XX_TEX_MEMOBJ_6, MIN_LINE_OFFSET, minLine);
    // Array stride is unused for this single layer, but its field still requires 4 KiB alignment.
    uint64_t slice = (size + 4095) & ~4095ull;
    d[7] = DFS(A8XX_TEX_MEMOBJ_7, ARRAY_SLICE_OFFSET, slice);
    if (volume) {
        // fd6_view.cc (A8XX): a 3D view also carries MIN_ARRAY_SLIZE_OFFSET, the last level's slice size (fd6_layout.c:
        // level 0 of a 3D layout is align(rows * pitch, 4096)); this one level is that slice. 4 bits of 4 KiB units.
        if (slice > (15ull << 12)) AdrenoDrawRefuse(@"one-slice 3D texture of %llu bytes exceeds the 60 KiB minimum slice field", slice);
        d[7] |= DFS(A8XX_TEX_MEMOBJ_7, MIN_ARRAY_SLIZE_OFFSET, slice);
    }
    return size;
}
static AdrenoAddr AdrenoTextureWords(id<MTLTexture> texture, id<MTLDevice> device, uint32_t d[16]) {
    // A 3D texture one slice deep (CoreAnimation binds 1x1x1 ones to its generic shader's colour cubes) is that
    // slice's 2D layout sampled through a TEX_3D descriptor; deeper volumes need the 4 KiB slice layout
    // (fd6_layout.c) that our texture allocations do not have yet, so they are refused.
    const BOOL volume = texture.textureType == MTLTextureType3D;
    if (volume && texture.depth != 1)
        AdrenoDrawRefuse(@"sampled 3D texture is %lu slices deep: only one-slice 3D textures are built", (unsigned long)texture.depth);
    // A mipmapped 2D texture (or a view of a parent's levels) names all of its levels in the T# (MIPLVLS) when each
    // recorded level is where the GPU derives it; otherwise it samples its first level only, as before
    // (docs/USERSPACE-GRAPHICS-20261019.md, "Fix: mip levels the GPU can sample").
    if (![texture isKindOfClass:[IOGPUMetalTexture class]] || texture.device != device ||
        ![texture respondsToSelector:@selector(adrenoGetLinearLayout:)] || (texture.textureType != MTLTextureType2D && !volume) ||
        texture.sampleCount != 1 || (volume && texture.mipmapLevelCount != 1) || texture.arrayLength != 1 || texture.depth != 1 ||
        (texture.usage != MTLTextureUsageUnknown && !(texture.usage & MTLTextureUsageShaderRead)))
        AdrenoDrawRefuse(@"sampled texture must be a native single-level linear 2D (or one-slice 3D) texture on this device; "
                         @"texture %@", AdrenoDescribeTarget(texture));
    AdrenoLinearTextureLayout l = {0};
    if (![(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&l] || l.width != texture.width ||
        l.height != texture.height || l.format != texture.pixelFormat || !l.width || !l.height ||
        l.width > 16384 || l.height > 16384 || l.allocationBytes != AdrenoGPUBackingSize(texture))
        AdrenoDrawRefuse(@"sampled texture has an unknown or inconsistent linear layout; texture %@", AdrenoDescribeTarget(texture));
    AdrenoTexFormat tf;
    if (!AdrenoTexFormatOf(l.format, &tf)) AdrenoDrawRefuse(@"sampled texture format %lu is not supported yet", (unsigned long)l.format);
    // The texture's swizzle (MTLTextureDescriptor.swizzle) applied after the format's own channel mapping
    // (fd6_view.cc: the view swizzle composed with the format swizzle into SWIZ_X..W).
    uint32_t swiz[4];
    {
        const MTLTextureSwizzleChannels sw = texture.swizzle;
        const MTLTextureSwizzle pick[4] = {sw.red, sw.green, sw.blue, sw.alpha};
        for (int c = 0; c < 4; c++) switch (pick[c]) {
            case MTLTextureSwizzleZero: swiz[c] = E(A8XX_SWIZ_ZERO); break;
            case MTLTextureSwizzleOne: swiz[c] = E(A8XX_SWIZ_ONE); break;
            case MTLTextureSwizzleRed: case MTLTextureSwizzleGreen: case MTLTextureSwizzleBlue: case MTLTextureSwizzleAlpha:
                swiz[c] = tf.swiz[pick[c] - MTLTextureSwizzleRed]; break;
            default: AdrenoDrawRefuse(@"sampled texture swizzle %u is not a Metal swizzle", (unsigned)pick[c]);
        }
    }
    if (!l.rowBytes || l.rowBytes % 64 || l.offset % 64 || l.rowBytes < l.width * tf.cpp ||
        l.rowBytes > 0xffffff / 8 || l.offset > l.allocationBytes ||
        l.height > (l.allocationBytes - l.offset) / l.rowBytes)
        AdrenoDrawRefuse(@"sampled texture rows need 64-byte alignment and must fit the allocation");
    uint64_t size = AdrenoLinearViewWords(d, &tf, swiz, l.rowBytes, l.width, l.height, volume);
    // Mip levels: level k's pitch is align(max(1, pitch0 >> k), 64 << MIN_LINE_OFFSET) and the levels follow level 0
    // back to back (Mesa fdl_pitch / fd6_layout.c). The T# names them only when every recorded level is exactly there;
    // the relocation then spans all of them. At most 16 levels (MIPLVLS has 4 bits).
    const NSUInteger levels = texture.mipmapLevelCount;
    if (!volume && levels > 1 && levels <= 16) {
        const uint64_t align = 64ull << AdrenoMipLineShift((NSUInteger)l.rowBytes);
        uint64_t at = l.offset + l.rowBytes * l.height;
        BOOL same = YES;
        for (NSUInteger k = 1; k < levels && same; k++) {
            AdrenoLinearTextureLayout m = {0};
            const uint64_t pitch = (MAX(1ull, (uint64_t)l.rowBytes >> k) + align - 1) & ~(align - 1);
            same = AdrenoLinearLayoutAtLevel(texture, k, &m) && m.offset == at && m.rowBytes == pitch &&
                   m.width == MAX((NSUInteger)1, l.width >> k) && m.height == MAX((NSUInteger)1, l.height >> k) &&
                   m.format == l.format && m.allocationBytes == l.allocationBytes && m.offset <= m.allocationBytes &&
                   m.height <= (m.allocationBytes - m.offset) / m.rowBytes;
            if (same) at = m.offset + m.rowBytes * m.height;
        }
        if (same) {
            d[6] |= DF(A8XX_TEX_MEMOBJ_6, MIPLVLS, levels - 1);
            size = at - l.offset;
        } else {
            static dispatch_once_t once;
            dispatch_once(&once, ^{ os_log_error(OS_LOG_DEFAULT, "AdrenoMetal: mipmapped texture levels are not where the GPU "
                                                 "derives them: sampling level 0 only (%{public}@)", AdrenoDescribeTarget(texture)); });
        }
    }
    return AdrenoResourceAddr(texture, l.offset, size, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_TEXTURE, @"sampled texture");
}
// One colour attachment as the pass renders it: its level's linear layout inside the texture's allocation.
typedef struct {
    __unsafe_unretained id<MTLTexture> texture;
    MTLPixelFormat format;
    uint64_t offset, pitch, width, height;
} AdrenoAttachmentView;
// The framebuffer-fetch T# of colour attachment n (patch_fb_read_sysmem: fdl6_view_init of the surface, level and
// layer as rendered, the format's own channel mapping with an identity view swizzle, 2D, one level).
static AdrenoAddr AdrenoAttachmentViewWords(const AdrenoAttachmentView *v, uint32_t n, uint32_t d[16]) {
    AdrenoTexFormat tf;
    if (!AdrenoTexFormatOf(v->format, &tf))
        AdrenoDrawRefuse(@"framebuffer fetch of colour %u: format %lu has no texture view", n, (unsigned long)v->format);
    if (v->pitch % 64 || v->pitch > 0xffffff / 8 || v->pitch < v->width * tf.cpp)
        AdrenoDrawRefuse(@"framebuffer fetch of colour %u: rows of %llu bytes", n, v->pitch);
    uint64_t size = AdrenoLinearViewWords(d, &tf, tf.swiz, v->pitch, v->width, v->height, NO);
    return AdrenoResourceAddr(v->texture, v->offset, size, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_TEXTURE,
                              [NSString stringWithFormat:@"framebuffer fetch view of colour %u", n]);
}

// The T# of a used texture binding the draw leaves unbound: a 1x1 RGBA8 image on the kext's zero page (4 KiB of zeros,
// GPU read-only), 2D or, for a texture3d binding, one-slice 3D, so a read returns transparent black and never touches
// unmapped memory.
static AdrenoAddr AdrenoZeroTextureWordsOf(BOOL texture3d, uint32_t d[16]) {
    AdrenoTexFormat tf;
    if (!AdrenoTexFormatOf(MTLPixelFormatRGBA8Unorm, &tf)) AdrenoDrawBug(@"RGBA8 texture format");
    (void)AdrenoLinearViewWords(d, &tf, tf.swiz, 64, 1, 1, texture3d);
    return AdrenoZeroAddr();
}
static AdrenoAddr AdrenoZeroTextureWords(NSDictionary *binding, uint32_t d[16]) {
    return AdrenoZeroTextureWordsOf([binding[@"type"] hasPrefix:@"texture3d<"], d);
}
static void emit_texture_load(AdrenoCS *cs, uint32_t type, uint32_t count, AdrenoAddr address) {
    uint64_t start = cs_dwords(cs);
    PKT7(cs, E(CP_LOAD_STATE6_FRAG), PF(CP_LOAD_STATE6_0, DST_OFF, 0) | PF(CP_LOAD_STATE6_0, STATE_TYPE, type) |
         PF(CP_LOAD_STATE6_0, STATE_SRC, E(SS6_INDIRECT)) | PF(CP_LOAD_STATE6_0, STATE_BLOCK, E(SB6_FS_TEX)) |
         PF(CP_LOAD_STATE6_0, NUM_UNIT, count), 0, 0);
    cs_reloc(cs, ADRENO_SPACE_IB, start + 2, ADRENO_SPACE_IB, start + 3, ADRENO_IB_HI_BITS_REG64, address);
}
static void emit_fragment_textures(AdrenoCS *cs, NSDictionary *fs, id<MTLDevice> device,
                                    id<MTLTexture> const __strong *textures, id<MTLSamplerState> const __strong *samplers,
                                    const AdrenoFBReads *fb, const AdrenoAttachmentView *views, NSUInteger attachments) {
    uint32_t count = (uint32_t)PU(fs, @"num_samp");
    AdrenoRegs r;
    regs_reset(&r);
    if (!count) {
        REG64(&r, SP_PS_SAMPLER_BASE, 0, 0);
        REG64(&r, SP_PS_TEXMEMOBJ_BASE, 0, 0);
        REG32(&r, SP_PS_TSIZE, 0, AF(SP_PS_TSIZE, VALUE, 0));
        cs_crb(cs, &r);
        return;
    }
    if (count > ADRENO_DRAW_TEXTURE_SLOTS) AdrenoDrawBug(@"fragment texture count %u", count);
    uint32_t td[ADRENO_DRAW_TEXTURE_SLOTS][16] = {0}, sd[ADRENO_DRAW_TEXTURE_SLOTS][4] = {0};
    AdrenoAddr addresses[ADRENO_DRAW_TEXTURE_SLOTS] = {0};
    BOOL usedT[ADRENO_DRAW_TEXTURE_SLOTS] = {NO}, usedS[ADRENO_DRAW_TEXTURE_SLOTS] = {NO};
    // v38 (com.apple.dock.extra, loginwindow): textures and samplers a function declares but the draw does not supply.
    // ir3's ntex / nsamp are 1 + the highest T# / S# a texture instruction names (BINDING-ABI 3.4), so a binding at or
    // above them is never read; an argument without uses (reflection `used` false) is never read either and stays a
    // hole. A used one left unbound (Metal leaves what it reads undefined) gets a 1x1 transparent-black texture on the
    // kext's zero page, or Metal's default sampler state.
    NSDictionary *stats = PDict(PDict(PDict(fs, @"sidecar"), @"ir3"), @"stats");
    const NSInteger namedT = PInt(stats, @"ntex"), namedS = PInt(stats, @"nsamp");
    for (NSDictionary *b in Bindings(fs, @"texture")) {
        if (!BoundOrUsed(b)) continue;
        NSInteger slot = PInt(b, @"slot"), index = PInt(b, @"metal_index");
        if (slot >= 0 && slot >= namedT) continue;
        if (slot < 0 || slot >= count || index < 0 || index >= ADRENO_DRAW_TEXTURE_SLOTS || usedT[slot])
            AdrenoDrawRefuse(@"fragment texture(%ld) maps to invalid or duplicate slot %ld", (long)index, (long)slot);
        if (!textures[index]) {
            if (!Used(b)) continue;
            AdrenoLogZeroTexture(PDict(PDict(fs, @"sidecar"), @"reflection")[@"function"], b[@"arg"], index);
            addresses[slot] = AdrenoZeroTextureWords(b, td[slot]);
        } else {
            addresses[slot] = AdrenoTextureWords(textures[index], device, td[slot]);
        }
        usedT[slot] = YES;
    }
    for (uint32_t k = 0; k < fb->count; k++) {         // framebuffer fetch: the attachment's view at the rewritten T#
        const uint32_t slot = fb->read[k].slot, n = fb->read[k].attachment;
        if (slot >= count || usedT[slot])
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u: T# %u is outside the %u loaded or holds a texture binding", n, slot, count);
        if (n >= attachments)
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u, which the render pass does not attach (%lu attachments)", n,
                             (unsigned long)attachments);
        addresses[slot] = AdrenoAttachmentViewWords(&views[n], n, td[slot]);
        usedT[slot] = YES;
    }
    for (NSDictionary *b in Bindings(fs, @"sampler")) {
        if (!BoundOrUsed(b)) continue;
        NSInteger slot = PInt(b, @"slot"), index = PInt(b, @"metal_index");
        if (slot >= 0 && slot >= namedS) continue;
        if (slot < 0 || slot >= count || index < 0 || index >= ADRENO_DRAW_SAMPLER_SLOTS || usedS[slot])
            AdrenoDrawRefuse(@"fragment sampler(%ld) maps to invalid or duplicate slot %ld", (long)index, (long)slot);
        id<MTLSamplerState> sampler = samplers[index];
        if (!sampler) {
            if (!Used(b)) continue;
            static MTLSamplerDescriptor *standard;
            static dispatch_once_t once;
            dispatch_once(&once, ^{ standard = [MTLSamplerDescriptor new]; });   // nearest, clamp to edge, no mips
            AdrenoSamplerWords(standard, sd[slot]);
            usedS[slot] = YES;
            continue;
        }
        if (sampler.device != device || ![(id)sampler respondsToSelector:@selector(adrenoSamplerDescriptor)])
            AdrenoDrawRefuse(@"fragment sampler(%ld) is missing or belongs to another device", (long)index);
        AdrenoSamplerWords([(id)sampler adrenoSamplerDescriptor], sd[slot]);
        usedS[slot] = YES;
    }
    for (NSDictionary *constant in AdrenoConstantSamplers(fs)) {
        NSUInteger slot = (NSUInteger)PU(constant, @"slot");
        if (usedS[slot]) AdrenoDrawRefuse(@"constant sampler would overwrite an API sampler");
        NSArray *words = PArray(constant, @"a8xx_tex_samp");
        for (unsigned i = 0; i < 4; i++) sd[slot][i] = AdrenoHexWord(words[i]);
        usedS[slot] = YES;
    }
    uint64_t ta = cs_data(cs, td, count * 64, count * 64);
    uint64_t sa = cs_data(cs, sd, count * 16, (count * 16 + 63) & ~63u);
    for (uint32_t i = 0; i < count; i++) if (usedT[i])
        cs_reloc(cs, ADRENO_SPACE_DATA, ta + i * 64, ADRENO_SPACE_DATA, ta + i * 64 + 4, ADRENO_IB_HI_BITS_DESC, addresses[i]);
    AdrenoAddr tex = AdrenoPackageAddr(ta, count * 64, ADRENO_IB_ALIGN_LOG2_TEXTURE);
    AdrenoAddr samp = AdrenoPackageAddr(sa, count * 16, ADRENO_IB_ALIGN_LOG2_TEXTURE);
    emit_texture_load(cs, E(ST6_SHADER), count, samp);
    emit_texture_load(cs, E(ST6_CONSTANTS), count, tex);
    REGADDR(&r, SP_PS_SAMPLER_BASE, 0, 0, samp);
    REGADDR(&r, SP_PS_TEXMEMOBJ_BASE, 0, 0, tex);
    REG32(&r, SP_PS_TSIZE, 0, AF(SP_PS_TSIZE, VALUE, count));
    cs_crb(cs, &r);
}
// emit_fragment_textures from the plan: the same loops, checks and helpers over the decoded tables.
static void emit_fragment_textures_planned(AdrenoCS *cs, const AdrenoTexturePlan *t, id<MTLDevice> device,
                                           id<MTLTexture> const __strong *textures, id<MTLSamplerState> const __strong *samplers,
                                           const AdrenoFBReads *fb, const AdrenoAttachmentView *views, NSUInteger attachments) {
    uint32_t count = t->count;
    AdrenoRegs r;
    regs_reset(&r);
    if (!count) {
        REG64(&r, SP_PS_SAMPLER_BASE, 0, 0);
        REG64(&r, SP_PS_TEXMEMOBJ_BASE, 0, 0);
        REG32(&r, SP_PS_TSIZE, 0, AF(SP_PS_TSIZE, VALUE, 0));
        cs_crb(cs, &r);
        return;
    }
    if (count > ADRENO_DRAW_TEXTURE_SLOTS) AdrenoDrawBug(@"fragment texture count %u", count);
    uint32_t td[ADRENO_DRAW_TEXTURE_SLOTS][16] = {0}, sd[ADRENO_DRAW_TEXTURE_SLOTS][4] = {0};
    AdrenoAddr addresses[ADRENO_DRAW_TEXTURE_SLOTS] = {0};
    BOOL usedT[ADRENO_DRAW_TEXTURE_SLOTS] = {NO}, usedS[ADRENO_DRAW_TEXTURE_SLOTS] = {NO};
    const NSInteger namedT = t->namedT, namedS = t->namedS;
    for (uint32_t k = 0; k < t->nTexture; k++) {
        const AdrenoPlanTexture *b = &t->texture[k];
        NSInteger slot = b->slot, index = b->index;
        if (slot >= 0 && slot >= namedT) continue;
        if (slot < 0 || slot >= count || index < 0 || index >= ADRENO_DRAW_TEXTURE_SLOTS || usedT[slot])
            AdrenoDrawRefuse(@"fragment texture(%ld) maps to invalid or duplicate slot %ld", (long)index, (long)slot);
        if (!textures[index]) {
            if (!b->used) continue;
            AdrenoLogZeroTexture(t->function, b->arg, index);
            addresses[slot] = AdrenoZeroTextureWordsOf(b->texture3d, td[slot]);
        } else {
            addresses[slot] = AdrenoTextureWords(textures[index], device, td[slot]);
        }
        usedT[slot] = YES;
    }
    for (uint32_t k = 0; k < fb->count; k++) {         // framebuffer fetch: the attachment's view at the rewritten T#
        const uint32_t slot = fb->read[k].slot, n = fb->read[k].attachment;
        if (slot >= count || usedT[slot])
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u: T# %u is outside the %u loaded or holds a texture binding", n, slot, count);
        if (n >= attachments)
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u, which the render pass does not attach (%lu attachments)", n,
                             (unsigned long)attachments);
        addresses[slot] = AdrenoAttachmentViewWords(&views[n], n, td[slot]);
        usedT[slot] = YES;
    }
    for (uint32_t k = 0; k < t->nSampler; k++) {
        const AdrenoPlanSampler *b = &t->sampler[k];
        NSInteger slot = b->slot, index = b->index;
        if (slot >= 0 && slot >= namedS) continue;
        if (slot < 0 || slot >= count || index < 0 || index >= ADRENO_DRAW_SAMPLER_SLOTS || usedS[slot])
            AdrenoDrawRefuse(@"fragment sampler(%ld) maps to invalid or duplicate slot %ld", (long)index, (long)slot);
        id<MTLSamplerState> sampler = samplers[index];
        if (!sampler) {
            if (!b->used) continue;
            static MTLSamplerDescriptor *standard;
            static dispatch_once_t once;
            dispatch_once(&once, ^{ standard = [MTLSamplerDescriptor new]; });   // nearest, clamp to edge, no mips
            AdrenoSamplerWords(standard, sd[slot]);
            usedS[slot] = YES;
            continue;
        }
        if (sampler.device != device || ![(id)sampler respondsToSelector:@selector(adrenoSamplerDescriptor)])
            AdrenoDrawRefuse(@"fragment sampler(%ld) is missing or belongs to another device", (long)index);
        AdrenoSamplerWords([(id)sampler adrenoSamplerDescriptor], sd[slot]);
        usedS[slot] = YES;
    }
    for (uint32_t k = 0; k < t->nConstant; k++) {
        NSUInteger slot = t->constant[k].slot;
        if (usedS[slot]) AdrenoDrawRefuse(@"constant sampler would overwrite an API sampler");
        for (unsigned i = 0; i < 4; i++) sd[slot][i] = t->constant[k].words[i];
        usedS[slot] = YES;
    }
    uint64_t ta = cs_data(cs, td, count * 64, count * 64);
    uint64_t sa = cs_data(cs, sd, count * 16, (count * 16 + 63) & ~63u);
    for (uint32_t i = 0; i < count; i++) if (usedT[i])
        cs_reloc(cs, ADRENO_SPACE_DATA, ta + i * 64, ADRENO_SPACE_DATA, ta + i * 64 + 4, ADRENO_IB_HI_BITS_DESC, addresses[i]);
    AdrenoAddr tex = AdrenoPackageAddr(ta, count * 64, ADRENO_IB_ALIGN_LOG2_TEXTURE);
    AdrenoAddr samp = AdrenoPackageAddr(sa, count * 16, ADRENO_IB_ALIGN_LOG2_TEXTURE);
    emit_texture_load(cs, E(ST6_SHADER), count, samp);
    emit_texture_load(cs, E(ST6_CONSTANTS), count, tex);
    REGADDR(&r, SP_PS_SAMPLER_BASE, 0, 0, samp);
    REGADDR(&r, SP_PS_TEXMEMOBJ_BASE, 0, 0, tex);
    REG32(&r, SP_PS_TSIZE, 0, AF(SP_PS_TSIZE, VALUE, count));
    cs_crb(cs, &r);
}
// The fragment texture tables as emit_fragment_textures reads them; throws where reading the export throws.
static BOOL AdrenoDecodeTextures(NSDictionary *fs, AdrenoTexturePlan *t, NSMutableArray *keep) {
    uint64_t count = PU(fs, @"num_samp");
    t->count = (uint32_t)count;
    t->nTexture = t->nSampler = t->nConstant = 0;
    t->namedT = t->namedS = 0;
    t->function = nil;
    if (!count) return YES;
    if (count > ADRENO_DRAW_TEXTURE_SLOTS) return NO;     // the export path reports it (a builder bug at every draw)
    NSDictionary *stats = PDict(PDict(PDict(fs, @"sidecar"), @"ir3"), @"stats");
    t->namedT = PInt(stats, @"ntex"); t->namedS = PInt(stats, @"nsamp");
    for (NSDictionary *b in Bindings(fs, @"texture")) {
        if (!BoundOrUsed(b)) continue;
        if (t->nTexture >= ADRENO_PLAN_BINDINGS) return NO;
        AdrenoPlanTexture *e = &t->texture[t->nTexture++];
        e->slot = PInt(b, @"slot"); e->index = PInt(b, @"metal_index"); e->used = Used(b);
        id type = b[@"type"];
        if (type && ![type isKindOfClass:[NSString class]]) return NO;
        e->texture3d = [type hasPrefix:@"texture3d<"];
        e->arg = b[@"arg"];
        if (e->arg) [keep addObject:e->arg];
    }
    id function = PDict(PDict(fs, @"sidecar"), @"reflection")[@"function"];
    t->function = function;
    if (function) [keep addObject:function];
    for (NSDictionary *b in Bindings(fs, @"sampler")) {
        if (!BoundOrUsed(b)) continue;
        if (t->nSampler >= ADRENO_PLAN_BINDINGS) return NO;
        AdrenoPlanSampler *e = &t->sampler[t->nSampler++];
        e->slot = PInt(b, @"slot"); e->index = PInt(b, @"metal_index"); e->used = Used(b);
    }
    for (NSDictionary *constant in AdrenoConstantSamplers(fs)) {
        if (t->nConstant >= ADRENO_DRAW_SAMPLER_SLOTS) return NO;
        AdrenoPlanConstantSampler *e = &t->constant[t->nConstant++];
        e->slot = (NSUInteger)PU(constant, @"slot");
        NSArray *words = PArray(constant, @"a8xx_tex_samp");
        if (words.count < 4 || e->slot >= ADRENO_DRAW_SAMPLER_SLOTS) return NO;
        for (unsigned i = 0; i < 4; i++) e->words[i] = AdrenoHexWord(words[i]);
    }
    return YES;
}

// A recording stream's dwords and relocations, when they can be replayed anywhere: IB-space positions only, no data
// area (whose offsets would move), every relocation's resource logged.
static BOOL AdrenoRecordOf(AdrenoCS *rec, NSData **words, NSData **relocs, NSArray **resources) {
    const AdrenoRelocDraft *d = rec->_relocs.bytes;
    const NSUInteger n = rec->_relocs.length / sizeof *d;
    if (rec->_data.length || rec->_record.count != n) return NO;
    for (NSUInteger i = 0; i < n; i++)
        if (d[i].loSpace != ADRENO_SPACE_IB || (d[i].hiSpace != ADRENO_SPACE_IB && d[i].hiSpace != ADRENO_SPACE_NONE) ||
            d[i].kind == ADRENO_IB_RELOC_PACKAGE)
            return NO;
    *words = [rec->_w copy]; *relocs = [rec->_relocs copy]; *resources = [rec->_record copy];
    return YES;
}
static AdrenoCS *AdrenoRecordingCS(void) {
    AdrenoCS *rec = [AdrenoCS new];
    rec->_record = [NSMutableArray array];
    return rec;
}
// The plan: decoded and recorded with the draw path's own functions and arguments; nil when anything does not decode.
static AdrenoDrawPlan *AdrenoBuildDrawPlan(AdrenoDrawProgram *program) {
    NSDictionary *vs = program.vertexProgram, *fs = program.fragmentProgram;
    AdrenoDrawPlan *p = [AdrenoDrawPlan new];
    NSMutableArray *keep = [NSMutableArray array];
    // emitDraw's program groups, exactly as it calls them.
    AdrenoCS *rec = AdrenoRecordingCS();
    AdrenoAddr vsCode = AdrenoResourceAddr(program.vertexCodeBuffer, 0, program.vertexCodeBuffer.length,
                                           ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_SHADER, @"vertex code");
    AdrenoAddr fsCode = AdrenoResourceAddr(program.fragmentCodeBuffer, 0, program.fragmentCodeBuffer.length,
                                           ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_SHADER, @"fragment code");
    uint64_t ntex = PU(fs, @"num_samp"), nsamp = ntex;
    BOOL pixlod = PInt(fs, @"need_pixlod") != 0;
    emit_program_config(rec, vs, fs, ntex, nsamp, program->_fb.count != 0);
    emit_shader_regs(rec, vs, YES, vsCode, pixlod);
    emit_shader_regs(rec, fs, NO, fsCode, pixlod);
    p->_mrt = emit_program_linkage(rec, vs, fs, program.linkage);
    emit_interp_regs(rec, vs, fs);
    NSData *words, *relocs; NSArray *resources;
    if (!AdrenoRecordOf(rec, &words, &relocs, &resources)) return nil;
    p->_progWords = words; p->_progRelocs = relocs; p->_progResources = resources;
    p->_writesZ = Valid(POutputRegid(fs, FRAG_RESULT_DEPTH));
    p->_writesStencil = Valid(POutputRegid(fs, FRAG_RESULT_STENCIL));
    NSArray<NSNumber *> *attributes = AdrenoVertexAttributes(vs);
    if (attributes.count > 32) return nil;
    p->_attributeCount = attributes.count;
    for (NSUInteger i = 0; i < attributes.count; i++) p->_attributes[i] = attributes[i].unsignedIntegerValue;
    if (!AdrenoDecodeStage(vs, &p->_vs) || !AdrenoDecodeStage(fs, &p->_fs)) return nil;
    if (!AdrenoDecodeTextures(fs, &p->_textures, keep)) return nil;
    p->_pointSize = Valid(POutputRegid(vs, VARYING_SLOT_PSIZ));
    // emitDraw's driver constant-data UBO loads.
    AdrenoCS *tail = AdrenoRecordingCS();
    emit_driver_ubos(tail, vs, YES, program.vertexCodeBuffer);
    emit_driver_ubos(tail, fs, NO, program.fragmentCodeBuffer);
    if (!AdrenoRecordOf(tail, &words, &relocs, &resources)) return nil;
    p->_tailWords = words; p->_tailRelocs = relocs; p->_tailResources = resources;
    p->_keep = keep;
    return p;
}
// ADRENO_DRAW_PLAN=0 (read once): every draw takes the export path (an A/B switch for the tests).
static BOOL AdrenoDrawPlansEnabled(void) {
    static BOOL enabled; static dispatch_once_t once;
    dispatch_once(&once, ^{ const char *e = getenv("ADRENO_DRAW_PLAN"); enabled = !e || strcmp(e, "0"); });
    return enabled;
}
// The program's plan, built at its first draw (under the program's lock, once; immutable afterwards).
static AdrenoDrawPlan *AdrenoDrawPlanOf(AdrenoDrawProgram *program) {
    if (!AdrenoDrawPlansEnabled()) return nil;
    os_unfair_lock_lock(&program->_planLock);
    if (!program->_planTried) {
        program->_planTried = YES;
        @try { program->_plan = AdrenoBuildDrawPlan(program); }
        @catch (id error) { program->_plan = nil; }      // the export path refuses (or reports) the same way at each draw
    }
    AdrenoDrawPlan *plan = program->_plan;
    os_unfair_lock_unlock(&program->_planLock);
    return plan;
}

// ================================================================================================================
// The render pass (RD.build_ib: prologue, per-draw section, epilogue)
// ================================================================================================================
void AdrenoDrawBindingsInit(AdrenoDrawBindings *b) {
    memset(b, 0, sizeof *b);
    b->cullMode = MTLCullModeNone;
    b->winding = MTLWindingClockwise;
    b->fillMode = MTLTriangleFillModeFill;
    b->depthClipMode = MTLDepthClipModeClip;
    b->visibilityMode = MTLVisibilityResultModeDisabled;
}

BOOL AdrenoDrawSubmissionAvailable(id<MTLDevice> device) {
    static const void *const key = &key;
    if (!device) return NO;
    @synchronized ((id)device) {
        NSNumber *cached = objc_getAssociatedObject(device, key);
        if (cached) return cached.boolValue;
        long long abi = 0;
        if ([(id)device respondsToSelector:@selector(acceleratorPort)]) {
            io_service_t port = [(IOGPUMetalDevice *)device acceleratorPort];
            CFTypeRef value = port ? IORegistryEntryCreateCFProperty(port, CFSTR(ADRENO_IB_REGISTRY_PROPERTY), kCFAllocatorDefault, 0) : NULL;
            if (value && CFGetTypeID(value) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)value, kCFNumberLongLongType, &abi);
            if (value) CFRelease(value);
        }
        BOOL available = abi == ADRENO_GUEST_IB_ABI;
        objc_setAssociatedObject(device, key, @(available), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        return available;
    }
}

// fd6_emit_sysmem_fini<A8XX> + emit_common_fini, without the batch fence (design 5.3): the end of a pass, and of each
// continuation segment of one (turnip-audit P2).
static void emit_pass_epilogue(AdrenoCS *cs) {
    emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .ccuDepth = YES, .invCcuDepth = YES,
                                     .cache = YES, .invCche = YES, .wfi = YES});
    cs_event(cs, E(CACHE_CLEAN));
    PKT7(cs, E(CP_SKIP_IB2_ENABLE_GLOBAL), 0);
    cs_event(cs, E(LRZ_CACHE_FLUSH));
}

// A finished, earlier segment of a render pass larger than one IB package (turnip-audit P2): its own stream, packaged
// before the pass's later segments, with its own resource uses and staging arenas.
@interface AdrenoPassSegment : NSObject <AdrenoFinishedPass> {
@public
    AdrenoCS *_cs;
}
@end
@implementation AdrenoPassSegment
- (BOOL)finished { return YES; }
- (BOOL)empty { return NO; }
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block {
    for (id resource in _cs->_usage) block(resource, [[_cs->_usage objectForKey:resource] unsignedIntegerValue]);
}
- (AdrenoCS *)adrenoCS { return _cs; }
@end

#if ADRENO_UBO_MIRROR
// The prelude of a pass that created mirrors (FAILURE-MODES.md U2, U10): BR first (P1's rule for a stream without
// emit_restore), the in-pass copy's bracket once (earlier GPU writes reach memory, the CP waits for its own), one
// CP_MEMCPY per region, then the copies are made visible to UBO reads (UCHE and CCHE invalidated). It is packaged
// immediately before the pass's first segment.
static AdrenoPassSegment *AdrenoMirrorPrelude(NSArray *copies, NSArray *arenas) {
    AdrenoCS *cs = [AdrenoCS new];
    cs_thread_br(cs);
    emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .ccuDepth = YES, .cache = YES, .wfi = YES});
    cs_pkt7(cs, E(CP_WAIT_MEM_WRITES), NULL, 0);
    for (NSArray *c in copies) {
        id<MTLBuffer> buffer = c[0], arena = c[2];
        AdrenoUBOMirror *m = c[1];
        AdrenoAddr source = AdrenoResourceAddr(buffer, m->_start, m->_length, ADRENO_IB_ACCESS_READ, 2, @"UBO mirror source");
        AdrenoAddr destination = AdrenoResourceAddr(arena, m->_offset, m->_length, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                                    ADRENO_IB_ALIGN_LOG2_UBO, @"UBO mirror");
        uint64_t at = cs_dwords(cs);
        PKT7(cs, E(CP_MEMCPY), (uint32_t)(m->_length / 4), 0, 0, 0, 0);
        cs_reloc(cs, ADRENO_SPACE_IB, at + 2, ADRENO_SPACE_IB, at + 3, ADRENO_IB_HI_BITS_REG64, source);
        cs_reloc(cs, ADRENO_SPACE_IB, at + 4, ADRENO_SPACE_IB, at + 5, ADRENO_IB_HI_BITS_REG64, destination);
        atomic_fetch_add(&gAdrenoMirrorCopies, 1);
        atomic_fetch_add(&gAdrenoMirrorCopyBytes, m->_length);
    }
    cs_pkt7(cs, E(CP_WAIT_MEM_WRITES), NULL, 0);
    cs_event(cs, E(CACHE_INVALIDATE7));
    cs_wfi(cs);
    cs_pkt7(cs, E(CP_CCHE_INVALIDATE), NULL, 0);
    if (cs_dwords(cs) > ADRENO_IB_MAX_DWORDS || cs->_relocs.length / sizeof(AdrenoRelocDraft) > ADRENO_IB_MAX_RELOCS)
        AdrenoDrawBug(@"UBO mirror prelude exceeds one package");
    if (arenas.count) cs->_arenas = [arenas mutableCopy];
    AdrenoPassSegment *prelude = [AdrenoPassSegment new];
    prelude->_cs = cs;
    return prelude;
}
#endif

@interface AdrenoRenderPass ()
- (void)adrenoEnsureHeadroom;
- (void)adrenoEmitPrologue:(AdrenoCS *)cs clears:(BOOL)clears;
@end

@implementation AdrenoRenderPass {
    id<MTLDevice> _device;
    AdrenoCS *_cs;
    id<MTLTexture> _target;
    id<MTLTexture> _fragmentTextures[ADRENO_DRAW_TEXTURE_SLOTS];
    id<MTLSamplerState> _fragmentSamplers[ADRENO_DRAW_SAMPLER_SLOTS];
    uint32_t _width, _height;
    uint64_t _pitch, _targetOffset;
    AdrenoTargetFormat _format;
    BOOL _clear;
    NSUInteger _draws;
    // Colour attachments 1..7 (attachment 0 is _target/_format/_pitch/_targetOffset/_clear above); _mrtCount counts
    // attachment 0 too. Attachments are contiguous from 0.
    NSUInteger _mrtCount;
    struct { __unsafe_unretained id<MTLTexture> texture; AdrenoTargetFormat format; uint64_t pitch, offset, bytes;
             BOOL clear; uint32_t words[4]; } _mrt[8];
    id<MTLTexture> _mrtTextures[8];         // owns _mrt[i].texture
    id<MTLTexture> _zsTexture;              // the depth and/or stencil attachment's texture (one packed buffer)
    AdrenoZSLayout _zs;
    BOOL _depthAttached, _stencilAttached, _zsClear;
    uint32_t _zsWords[4];                   // the 2D clear words of the buffer (emit_clear_color)
    int _zsKeep;                            // emit_2d_clear_zs: 0 all bytes, 1 keep stencil, 2 keep depth
    BOOL _anyMrtClear;                      // an attachment 1..7 clears
    id<MTLDepthStencilState> _depthStencil; // the encoder's current state (nil: Metal's default)
    uint32_t _stencilFront, _stencilBack;
    AdrenoAttachmentView _views[8];         // colour attachments 0.._mrtCount-1 as rendered (framebuffer fetch reads them)
    id _lastPipeline;                       // programForPipeline's last answer for this pass (held: the key stays valid)
    AdrenoDrawProgram *_lastProgram;
    // Continuation segments (turnip-audit P2): the attachments' addresses and clear words the prologue needs, computed
    // once; the earlier, finished segments of a pass larger than one IB package; the draws in the current segment.
    AdrenoAddr _rtRW, _zsRW, _mrtRW[8];
    uint32_t _clearRGBA[4];
    NSMutableArray<id<AdrenoFinishedPass>> *_segments;
    NSUInteger _segmentDraws;
#if ADRENO_UBO_MIRROR
    // gpu-perf U: the command buffer's mirror table; the regions this pass's prelude copies and the arenas it took; set
    // when the pass may write some buffer (an attachment stored in a buffer, a program that may store): from then on
    // its constants are copied in the pass, and the table is emptied when it ends.
    AdrenoUBOMirrors *_mirrors;
    NSMutableArray *_mirrorCopies, *_mirrorArenas;
    BOOL _mirrorOff;
    AdrenoPassSegment *_mirrorPrelude;
#endif
}

- (NSString *)adrenoDropRefusedDraw:(void (^)(void))draw {
    // A continuation segment opens before the rollback point: a refused draw rolls back the segment it was emitted in.
    [self adrenoEnsureHeadroom];
    AdrenoCS *cs = _cs;
    const NSUInteger w = cs->_w.length, d = cs->_data.length, r = cs->_relocs.length, n = _draws, s = _segmentDraws;
    @try { draw(); return nil; }
    @catch (NSException *e) {
        if (![e.name isEqualToString:NSInvalidArgumentException]) @throw;
        [cs->_w setLength:w]; [cs->_data setLength:d]; [cs->_relocs setLength:r]; _draws = n; _segmentDraws = s;
        return e.reason ?: @"draw refused";
    }
}

// The headroom a draw needs in the current stream before it starts (turnip-audit P2). A draw section is about 550
// dwords, 20-40 relocations and a few hundred data bytes; inline setBytes copies and staging add to the data. With less
// than this left, a segment that already holds a draw ends and the pass continues in a new one (its own package)
// instead of refusing the draws that no longer fit ("a render pass larger than one IB package").
// (A test build may lower the room a segment keeps for itself, e.g. -DADRENO_SPLIT_DWORDS=250000u, to split every pass.)
#ifndef ADRENO_SPLIT_DWORDS
#define ADRENO_SPLIT_DWORDS 8192u
#endif
#ifndef ADRENO_SPLIT_DATA
#define ADRENO_SPLIT_DATA (64u * 1024u)
#endif
#ifndef ADRENO_SPLIT_RELOCS
#define ADRENO_SPLIT_RELOCS 512u
#endif
- (void)adrenoEnsureHeadroom {
    AdrenoCS *cs = _cs;
    if (_finished || !cs || !_segmentDraws) return;
    const uint64_t relocs = cs->_relocs.length / sizeof(AdrenoRelocDraft);
    if (cs_dwords(cs) + ADRENO_SPLIT_DWORDS <= ADRENO_IB_MAX_DWORDS && cs->_data.length + ADRENO_SPLIT_DATA <= ADRENO_IB_MAX_DATA &&
        relocs + ADRENO_SPLIT_RELOCS <= ADRENO_IB_MAX_RELOCS)
        return;
    // End this segment as -finish ends a pass (its writes clean, caches invalidated), keep it, and continue the pass
    // in a new stream: the same prologue without the clears (sysmem: the attachments already hold what this pass drew),
    // staging from where this segment stopped (AdrenoPassContinueStaging's A10 rule: the arena stays on the list of
    // the stream that took it).
    emit_pass_epilogue(cs);
    AdrenoPassSegment *segment = [AdrenoPassSegment new];
    segment->_cs = cs;
    if (!_segments) _segments = [NSMutableArray array];
    [_segments addObject:segment];
    AdrenoCS *next = [AdrenoCS new];
    if (cs->_staging && cs->_stagingUsed <= cs->_staging.length && !(cs->_stagingUsed & 63)) {
        next->_staging = cs->_staging;
        next->_stagingUsed = cs->_stagingUsed;
    }
    _cs = next;
    _segmentDraws = 0;
    [self adrenoEmitPrologue:next clears:NO];
}
- (NSArray<id<AdrenoFinishedPass>> *)adrenoSegments {
#if ADRENO_UBO_MIRROR
    // U2: the prelude goes before every segment of the pass.
    if (_mirrorPrelude) return [@[_mirrorPrelude] arrayByAddingObjectsFromArray:_segments ?: @[]];
#endif
    return _segments ?: @[];
}
#if ADRENO_UBO_MIRROR
- (void)adrenoUseMirrors:(AdrenoUBOMirrors *)mirrors {
    if (_mirrors || !mirrors || _draws) return;
    _mirrors = mirrors;
    _mirrorCopies = [NSMutableArray array];
    _mirrorArenas = [NSMutableArray array];
}
// U2: the regions this pass created become everyone's; U1(a)(b): a pass that may have written a buffer empties the
// table. Runs once, in -finish, after the epilogue.
- (void)adrenoFinishMirrors {
    if (!_mirrors) return;
    if (_mirrorCopies.count) _mirrorPrelude = AdrenoMirrorPrelude(_mirrorCopies, _mirrorArenas);
    for (NSArray *c in _mirrorCopies) ((AdrenoUBOMirror *)c[1])->_owner = nil;
    if (_mirrorOff && _mirrors->_entries.count) {
        atomic_fetch_add(&gAdrenoMirrorDrops, _mirrors->_entries.count);
        [_mirrors->_entries removeAllObjects];
    }
    _mirrorCopies = nil; _mirrorArenas = nil;
}
#endif

- (void)adrenoSetDepthStencil:(id<MTLDepthStencilState>)state front:(uint32_t)front back:(uint32_t)back {
    _depthStencil = state; _stencilFront = front; _stencilBack = back;
}

- (void)adrenoSetFragmentTextures:(id<MTLTexture> const __strong *)textures
                         samplers:(id<MTLSamplerState> const __strong *)samplers {
    for (NSUInteger i = 0; i < ADRENO_DRAW_TEXTURE_SLOTS; i++) _fragmentTextures[i] = textures[i];
    for (NSUInteger i = 0; i < ADRENO_DRAW_SAMPLER_SLOTS; i++) _fragmentSamplers[i] = samplers[i];
}

// The depth and stencil attachments (docs/ADRENO-DEPTH-STENCIL-20261017.md): one texture (a combined format, or
// one aspect), single-level 2D, in its own allocation, which AdrenoNewTexture sizes for the TILE6_3 buffer of
// AdrenoZSLayoutOf. Clear load actions become one 2D clear of the buffer; bytes of an aspect this pass does not
// attach (or loads) keep their contents, except Stencil8's depth bits, which nothing reads.
- (void)adrenoAttachDepthStencil:(MTLRenderPassDescriptor *)pass {
    MTLRenderPassDepthAttachmentDescriptor *da = pass.depthAttachment;
    MTLRenderPassStencilAttachmentDescriptor *sa = pass.stencilAttachment;
    id<MTLTexture> depth = da.texture, stencil = sa.texture;
    if (!depth && !stencil) return;
    if (depth && stencil && depth != stencil)
        AdrenoDrawRefuse(@"separate depth and stencil textures are not supported yet (one packed buffer); depth %@; stencil %@",
                         AdrenoDescribeTarget(depth), AdrenoDescribeTarget(stencil));
    id<MTLTexture> zs = depth ?: stencil;
    if (!AdrenoZSLayoutOf(zs.pixelFormat, zs.width, zs.height, &_zs))
        AdrenoDrawRefuse(@"depth/stencil format %lu is not supported yet; target %@", (unsigned long)zs.pixelFormat,
                         AdrenoDescribeTarget(zs));
    if ((depth && !_zs.hasDepth) || (stencil && !_zs.hasStencil))
        AdrenoDrawRefuse(@"depth/stencil format %lu lacks an attached aspect; target %@", (unsigned long)zs.pixelFormat,
                         AdrenoDescribeTarget(zs));
    for (MTLRenderPassAttachmentDescriptor *a in @[da, sa]) {
        if (!a.texture) continue;
        if (a.level || a.slice || a.depthPlane || a.resolveTexture ||
            (a.storeAction != MTLStoreActionStore && a.storeAction != MTLStoreActionDontCare))
            AdrenoDrawRefuse(@"depth/stencil attachments must be level/slice 0, unresolved, stored or discarded; target %@",
                             AdrenoDescribeTarget(zs));
    }
    if (![zs isKindOfClass:[IOGPUMetalTexture class]] || zs.textureType != MTLTextureType2D || zs.sampleCount != 1 ||
        zs.mipmapLevelCount != 1 || zs.arrayLength != 1 || zs.depth != 1 || !(zs.usage & MTLTextureUsageRenderTarget) ||
        zs.parentTexture || zs.iosurface || zs.buffer || [(IOGPUMetalTexture *)zs resourceSize] < _zs.layerBytes ||
        zs.width < _width || zs.height < _height)
        AdrenoDrawRefuse(@"the depth/stencil attachment must be a single-level 2D render target of its own allocation "
                         @"(%llu bytes for its tiled buffer) covering the render area %ux%u; target %@", _zs.layerBytes,
                         _width, _height, AdrenoDescribeTarget(zs));
    _zsTexture = zs;
    _depthAttached = depth != nil;
    _stencilAttached = stencil != nil;
    const BOOL clearDepth = depth && da.loadAction == MTLLoadActionClear;
    const BOOL clearStencil = stencil && sa.loadAction == MTLLoadActionClear;
    if (!clearDepth && !clearStencil) return;
    const BOOL keepDepth = _zs.hasDepth && !(depth && da.loadAction != MTLLoadActionLoad);
    const BOOL keepStencil = _zs.hasStencil && !(stencil && sa.loadAction != MTLLoadActionLoad);
    _zsKeep = _zs.packed && keepStencil ? 1 : _zs.packed && keepDepth ? 2 : 0;
    // emit_clear_color: Z24_UNORM_S8_UINT packs depth * (2^24 - 1) little endian and the stencil byte; Z32_FLOAT and
    // Z16_UNORM (R2D_FLOAT32) take the depth's float bits, with the clear stencil in the second word.
    const float d = (float)fmin(fmax(da.clearDepth, 0.0), 1.0);
    if (_zs.packed) {
        const uint32_t z24 = (uint32_t)(d * (float)((1u << 24) - 1));
        _zsWords[0] = z24 & 0xff; _zsWords[1] = (z24 >> 8) & 0xff; _zsWords[2] = (z24 >> 16) & 0xff;
        _zsWords[3] = sa.clearStencil & 0xff;
    } else {
        _zsWords[0] = AdrenoF32(d); _zsWords[1] = sa.clearStencil; _zsWords[2] = _zsWords[3] = 0;
    }
    _zsClear = YES;
}

- (instancetype)initWithDescriptor:(MTLRenderPassDescriptor *)pass device:(id<MTLDevice>)device {
    if (!(self = [super init])) return nil;
    _device = device;
    if (!pass || pass.renderTargetArrayLength > 1 || pass.defaultRasterSampleCount > 1 || pass.visibilityResultBuffer)
        AdrenoDrawRefuse(@"layered rendering, MSAA and visibility results are not supported yet");
    _mrtCount = 1;
    for (NSUInteger n = 1; n < 8; n++)
        if (pass.colorAttachments[n].texture) {
            if (n != _mrtCount) AdrenoDrawRefuse(@"colour attachments with gaps (attachment %lu after %lu) are not supported yet",
                                                 (unsigned long)n, (unsigned long)_mrtCount);
            _mrtCount = n + 1;
        }
    MTLRenderPassColorAttachmentDescriptor *attachment = pass.colorAttachments[0];
    id<MTLTexture> texture = attachment.texture;
    if (!texture) AdrenoDrawRefuse(@"render passes without colour attachment 0 are not supported yet");
    // Any mip level of a 2D target: its own layout inside the allocation (AdrenoLinearLayoutAtLevel).
    const NSUInteger level = attachment.level;
    if (![texture isKindOfClass:[IOGPUMetalTexture class]] || ![texture respondsToSelector:@selector(adrenoGetLinearLayout:)] ||
        level >= texture.mipmapLevelCount || attachment.slice || attachment.depthPlane || attachment.resolveTexture ||
        (attachment.storeAction != MTLStoreActionStore && attachment.storeAction != MTLStoreActionDontCare) ||
        texture.textureType != MTLTextureType2D || texture.sampleCount != 1 ||
        texture.arrayLength != 1 || texture.depth != 1 || !(texture.usage & MTLTextureUsageRenderTarget))
        AdrenoDrawRefuse(@"the colour attachment must be a linear 2D render target, slice 0, "
                         @"stored or discarded; target %@ level %lu", AdrenoDescribeTarget(texture), (unsigned long)level);
    AdrenoLinearTextureLayout layout = {0};
    if (!AdrenoLinearLayoutAtLevel(texture, level, &layout) || layout.width != MAX((NSUInteger)1, texture.width >> level) ||
        layout.height != MAX((NSUInteger)1, texture.height >> level) || layout.format != texture.pixelFormat ||
        !layout.width || !layout.height ||
        layout.allocationBytes != AdrenoGPUBackingSize(texture) ||
        pass.renderTargetWidth > layout.width || pass.renderTargetHeight > layout.height)
        AdrenoDrawRefuse(@"the colour attachment's linear layout is unknown or inconsistent; target %@", AdrenoDescribeTarget(texture));
    if (!AdrenoTargetFormatOf(layout.format, &_format))
        AdrenoDrawRefuse(@"render target format %lu is not supported yet; target %@", (unsigned long)layout.format,
                         AdrenoDescribeTarget(texture));
    // RB_MRT_PITCH / RB_A2D_DEST_BUFFER_PITCH count 64-byte units; the scissor and 2D fields hold 14 bits.
    if (layout.rowBytes % 64 || layout.offset % 64 || layout.width > 16384 || layout.height > 16384 ||
        layout.rowBytes < layout.width * _format.cpp || layout.offset > layout.allocationBytes ||
        layout.rowBytes * layout.height > layout.allocationBytes - layout.offset)
        AdrenoDrawRefuse(@"render target rows (%llu bytes at %llu) need 64-byte alignment inside the allocation; target %@",
                         layout.rowBytes, layout.offset, AdrenoDescribeTarget(texture));
    _target = texture;
    // CA pools rounded-up textures and constrains each pass to its used area.
    // Zero means the attachment dimension; pitch still describes the allocation.
    _width = (uint32_t)(pass.renderTargetWidth ?: layout.width);
    _height = (uint32_t)(pass.renderTargetHeight ?: layout.height);
    _pitch = layout.rowBytes; _targetOffset = layout.offset;
    _views[0] = (AdrenoAttachmentView){_target, layout.format, layout.offset, layout.rowBytes, layout.width, layout.height};
    [self adrenoAttachDepthStencil:pass];
    // emit_mrt for attachments 1..n-1: each the same kind of target as attachment 0, covering the render area.
    for (NSUInteger n = 1; n < _mrtCount; n++) {
        MTLRenderPassColorAttachmentDescriptor *a = pass.colorAttachments[n];
        id<MTLTexture> t = a.texture;
        AdrenoLinearTextureLayout l = {0};
        if (![t isKindOfClass:[IOGPUMetalTexture class]] || ![t respondsToSelector:@selector(adrenoGetLinearLayout:)] ||
            a.level >= t.mipmapLevelCount || a.slice || a.depthPlane || a.resolveTexture ||
            (a.storeAction != MTLStoreActionStore && a.storeAction != MTLStoreActionDontCare) ||
            t.textureType != MTLTextureType2D || t.sampleCount != 1 || t.arrayLength != 1 ||
            t.depth != 1 || !(t.usage & MTLTextureUsageRenderTarget) ||
            !AdrenoLinearLayoutAtLevel(t, a.level, &l) || l.width != MAX((NSUInteger)1, t.width >> a.level) ||
            l.height != MAX((NSUInteger)1, t.height >> a.level) ||
            l.format != t.pixelFormat || l.allocationBytes != AdrenoGPUBackingSize(t) ||
            l.width < _width || l.height < _height)
            AdrenoDrawRefuse(@"colour attachment %lu must be a single-level linear 2D render target covering the render area; "
                             @"target %@", (unsigned long)n, AdrenoDescribeTarget(t));
        if (!AdrenoTargetFormatOf(l.format, &_mrt[n].format))
            AdrenoDrawRefuse(@"render target format %lu (attachment %lu) is not supported yet; target %@", (unsigned long)l.format,
                             (unsigned long)n, AdrenoDescribeTarget(t));
        if (l.rowBytes % 64 || l.offset % 64 || l.rowBytes < l.width * _mrt[n].format.cpp || l.offset > l.allocationBytes ||
            l.rowBytes * l.height > l.allocationBytes - l.offset)
            AdrenoDrawRefuse(@"render target rows of attachment %lu need 64-byte alignment inside the allocation; target %@",
                             (unsigned long)n, AdrenoDescribeTarget(t));
        _mrtTextures[n] = t; _mrt[n].texture = t;
        _mrt[n].pitch = l.rowBytes; _mrt[n].offset = l.offset; _mrt[n].bytes = l.rowBytes * l.height;
        _views[n] = (AdrenoAttachmentView){t, l.format, l.offset, l.rowBytes, l.width, l.height};
        _mrt[n].clear = a.loadAction == MTLLoadActionClear;
        if (_mrt[n].clear) AdrenoClearWords(&_mrt[n].format, a.clearColor, _mrt[n].words);
    }
    _clear = attachment.loadAction == MTLLoadActionClear;
    if (_clear) AdrenoClearWords(&_format, attachment.clearColor, _clearRGBA);
    const uint64_t rtBytes = _pitch * layout.height;
    // The attachments' addresses, once: the first segment's prologue and every continuation's use the same ones.
    _rtRW = AdrenoResourceAddr(_target, _targetOffset, rtBytes, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                               ADRENO_IB_ALIGN_LOG2_TEXTURE, @"render target 0");
    _zsRW = AdrenoZeroAddr();
    if (_zsTexture)
        _zsRW = AdrenoResourceAddr(_zsTexture, 0, _zs.layerBytes, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                   ADRENO_IB_ALIGN_LOG2_TEXTURE, @"depth/stencil buffer");
    for (NSUInteger n = 1; n < _mrtCount; n++)
        _mrtRW[n] = AdrenoResourceAddr(_mrt[n].texture, _mrt[n].offset, _mrt[n].bytes, ADRENO_IB_ACCESS_READ | ADRENO_IB_ACCESS_WRITE,
                                       ADRENO_IB_ALIGN_LOG2_TEXTURE, [NSString stringWithFormat:@"render target %lu", (unsigned long)n]);
    BOOL mrtClear = NO;
    for (NSUInteger n = 1; n < _mrtCount; n++) mrtClear |= _mrt[n].clear;
    _anyMrtClear = mrtClear;
#if ADRENO_UBO_MIRROR
    // U1(b): an attachment stored in a buffer (or a view of one) writes that buffer: no mirror in this pass.
    for (NSUInteger n = 0; n <= _mrtCount; n++) {
        id<MTLTexture> t = n == _mrtCount ? _zsTexture : n ? _mrtTextures[n] : _target;
        if (t && (t.buffer || t.parentTexture.buffer || t.parentTexture.parentTexture)) _mirrorOff = YES;
    }
#endif
    _cs = [AdrenoCS new];
    [self adrenoEmitPrologue:_cs clears:YES];
    return self;
}

// The pass prologue (RD.build_ib's prologue): emit_restore, fd6_emit_sysmem_prep<A8XX>, the attachments, and
// fd6_emit_sysmem<A8XX> with the load-action clears. A continuation segment (turnip-audit P2) runs it without the clears.
- (void)adrenoEmitPrologue:(AdrenoCS *)cs clears:(BOOL)clears {
    const uint32_t W = _width, H = _height;
    AdrenoAddr rtRW = _rtRW;
    AdrenoAddr rtR = rtRW, rtW = rtRW;
    rtR.access = ADRENO_IB_ACCESS_READ;
    rtW.access = ADRENO_IB_ACCESS_WRITE;
    AdrenoRegs r;
    emit_restore(cs, AdrenoZeroAddr());
    // fd6_emit_sysmem_prep<A8XX>
    cs_event(cs, E(LRZ_CACHE_FLUSH));
    cs_marker(cs, E(RM6_DIRECT_RENDER));
    regs_reset(&r);
    REG32(&r, GRAS_SC_WINDOW_SCISSOR_TL, 0, AF(GRAS_SC_WINDOW_SCISSOR_TL, X, 0) | AF(GRAS_SC_WINDOW_SCISSOR_TL, Y, 0));
    REG32(&r, GRAS_SC_WINDOW_SCISSOR_BR, 0, AF(GRAS_SC_WINDOW_SCISSOR_BR, X, W - 1) | AF(GRAS_SC_WINDOW_SCISSOR_BR, Y, H - 1));
    cs_pkt4(cs, &r);
    regs_reset(&r);
    REG32(&r, GRAS_A2D_SCISSOR_TL, 0, AF(GRAS_A2D_SCISSOR_TL, X, 0) | AF(GRAS_A2D_SCISSOR_TL, Y, 0));
    REG32(&r, GRAS_A2D_SCISSOR_BR, 0, AF(GRAS_A2D_SCISSOR_BR, X, W - 1) | AF(GRAS_A2D_SCISSOR_BR, Y, H - 1));
    cs_pkt4(cs, &r);
    regs_reset(&r);
    REG32(&r, RB_RESOLVE_CNTL_1, 0, AF(RB_RESOLVE_CNTL_1, X, 0) | AF(RB_RESOLVE_CNTL_1, Y, 0));
    REG32(&r, RB_RESOLVE_CNTL_2, 0, AF(RB_RESOLVE_CNTL_2, X, W - 1) | AF(RB_RESOLVE_CNTL_2, Y, H - 1));
    cs_pkt4(cs, &r);
    regs_reset(&r);
    REG32(&r, GRAS_MODE_CNTL, 0, 0x2);
    cs_pkt4(cs, &r);
    regs_reset(&r);
    REG32(&r, RB_WINDOW_OFFSET, 0, AF(RB_WINDOW_OFFSET, X, 0) | AF(RB_WINDOW_OFFSET, Y, 0));
    REG32(&r, RB_RESOLVE_WINDOW_OFFSET, 0, AF(RB_RESOLVE_WINDOW_OFFSET, X, 0) | AF(RB_RESOLVE_WINDOW_OFFSET, Y, 0));
    REG32(&r, SP_WINDOW_OFFSET, 0, AF(SP_WINDOW_OFFSET, X, 0) | AF(SP_WINDOW_OFFSET, Y, 0));
    REG32(&r, TPL1_WINDOW_OFFSET, 0, AF(TPL1_WINDOW_OFFSET, X, 0) | AF(TPL1_WINDOW_OFFSET, Y, 0));
    REG32(&r, TPL1_A2D_WINDOW_OFFSET, 0, AF(TPL1_A2D_WINDOW_OFFSET, X, 0) | AF(TPL1_A2D_WINDOW_OFFSET, Y, 0));
    REG32(&r, GRAS_SC_BIN_CNTL, 0, AFS(GRAS_SC_BIN_CNTL, BINW, 0) | AFS(GRAS_SC_BIN_CNTL, BINH, 0) |
          AF(GRAS_SC_BIN_CNTL, FORCE_BI_DIR_LRZ_DISABLE, 1) | AF(GRAS_SC_BIN_CNTL, RENDER_MODE, E(RENDERING_PASS)) |
          AF(GRAS_SC_BIN_CNTL, LRZ_FEEDBACK_ZMODE_MASK, E(LRZ_FEEDBACK_EARLY_Z_LATE_Z)));
    REG32(&r, RB_CNTL, 0, AFS(RB_CNTL, BINW, 0) | AFS(RB_CNTL, BINH, 0) | AF(RB_CNTL, RENDER_MODE, E(RENDERING_PASS)) |
          AF(RB_CNTL, LRZ_FEEDBACK_ZMODE_MASK, E(LRZ_FEEDBACK_EARLY_Z_LATE_Z)));
    REG32(&r, VFD_RENDER_MODE, 0, AF(VFD_RENDER_MODE, RENDER_MODE, E(RENDERING_PASS)));
    REG32(&r, TPL1_BIN_SIZE, 0, AFS(TPL1_BIN_SIZE, BINW, 0) | AFS(TPL1_BIN_SIZE, BINH, 0));
    REG32(&r, TPL1_A2D_BIN_SIZE, 0, AFS(TPL1_A2D_BIN_SIZE, BINW, 0) | AFS(TPL1_A2D_BIN_SIZE, BINH, 0));
    REG32(&r, SP_BIN_SIZE, 0, AFS(SP_BIN_SIZE, BINW, 0) | AFS(SP_BIN_SIZE, BINH, 0));
    for (unsigned i = 0; i < 8; i++)
        REG32(&r, RB_MRT_GMEM_DIMENSION_REG, i, AF(RB_MRT_GMEM_DIMENSION_REG, WIDTH, 0) | AF(RB_MRT_GMEM_DIMENSION_REG, HEIGHT, 0));
    REG32(&r, RB_DEPTH_GMEM_DIMENSION, 0, AF(RB_DEPTH_GMEM_DIMENSION, WIDTH, 0) | AF(RB_DEPTH_GMEM_DIMENSION, HEIGHT, 0));
    REG32(&r, RB_STENCIL_GMEM_DIMENSION, 0, AF(RB_STENCIL_GMEM_DIMENSION, WIDTH, 0) | AF(RB_STENCIL_GMEM_DIMENSION, HEIGHT, 0));
    REG32(&r, RB_RESOLVE_CNTL_3, 0, AFS(RB_RESOLVE_CNTL_3, BINW, 0) | AFS(RB_RESOLVE_CNTL_3, BINH, 0));
    REG32(&r, RB_BUFFER_CNTL, 0, rb_buffer_cntl_sysmem());
    REG32(&r, GRAS_LRZ_CB_CNTL, 0, 0);
    REG32(&r, VPC_SO_OVERRIDE, 0, AF(VPC_SO_OVERRIDE, DISABLE, 0));
    cs_crb(cs, &r);
    cs_marker(cs, E(RM6_DIRECT_RENDER));
    PKT7(cs, E(CP_SKIP_IB2_ENABLE_GLOBAL), 0);
    PKT7(cs, E(CP_SKIP_IB2_ENABLE_LOCAL), 1);
    PKT7(cs, E(CP_SET_VISIBILITY_OVERRIDE), 1);
    // emit_zs, emit_mrt (attachment 0: RD.RT_HW bgra8), emit_msaa
    regs_reset(&r);
    const AdrenoAddr zsRW = _zsRW;
    if (_zsTexture) {
        // emit_zs with a depth (or packed depth/stencil) buffer: TILE6_3, no UBWC, no separate stencil.
        REG32(&r, RB_DEPTH_BUFFER_INFO, 0, AF(RB_DEPTH_BUFFER_INFO, DEPTH_FORMAT, _zs.depthFormat) |
              AF(RB_DEPTH_BUFFER_INFO, TILEMODE, E(TILE6_3)));
        REG32(&r, RB_DEPTH_BUFFER_PITCH, 0, AFS(RB_DEPTH_BUFFER_PITCH, VALUE, _zs.pitch));
        REG32(&r, RB_DEPTH_BUFFER_ARRAY_PITCH, 0, AFS(RB_DEPTH_BUFFER_ARRAY_PITCH, VALUE, _zs.layerBytes));
        REGADDR(&r, RB_DEPTH_BUFFER_BASE, 0, 0, zsRW);
        REG32(&r, RB_DEPTH_GMEM_BASE, 0, 0);
        REG32(&r, GRAS_SU_DEPTH_BUFFER_INFO, 0, AF(GRAS_SU_DEPTH_BUFFER_INFO, DEPTH_FORMAT, _zs.depthFormat));
        REG32(&r, RB_STENCIL_BUFFER_INFO, 0, 0);
    } else {
        REG32(&r, RB_DEPTH_BUFFER_INFO, 0, AF(RB_DEPTH_BUFFER_INFO, DEPTH_FORMAT, E(DEPTH6_NONE)) |
              AF(RB_DEPTH_BUFFER_INFO, TILEMODE, E(TILE6_LINEAR)));
        REG32(&r, RB_DEPTH_BUFFER_PITCH, 0, AFS(RB_DEPTH_BUFFER_PITCH, VALUE, 0));
        REG32(&r, RB_DEPTH_BUFFER_ARRAY_PITCH, 0, AFS(RB_DEPTH_BUFFER_ARRAY_PITCH, VALUE, 0));
        REG64(&r, RB_DEPTH_BUFFER_BASE, 0, 0);
        REG32(&r, RB_DEPTH_GMEM_BASE, 0, 0);
        REG32(&r, GRAS_SU_DEPTH_BUFFER_INFO, 0, AF(GRAS_SU_DEPTH_BUFFER_INFO, DEPTH_FORMAT, E(DEPTH6_NONE)));
        REG32(&r, RB_STENCIL_BUFFER_INFO, 0, AF(RB_STENCIL_BUFFER_INFO, TILEMODE, E(TILE6_LINEAR)));
    }
    REG32(&r, RB_MRT_BUF_INFO, 0, AF(RB_MRT_BUF_INFO, COLOR_FORMAT, _format.rb) |
          AF(RB_MRT_BUF_INFO, COLOR_TILE_MODE, E(TILE6_LINEAR)) | AF(RB_MRT_BUF_INFO, COLOR_SWAP, _format.swap));
    REG32(&r, RB_MRT_PITCH, 0, AFS(RB_MRT_PITCH, VALUE, _pitch));
    REG32(&r, RB_MRT_ARRAY_PITCH, 0, AFS(RB_MRT_ARRAY_PITCH, VALUE, _rtRW.length));
    REGADDR(&r, RB_MRT_BASE, 0, 0, rtRW);
    REG32(&r, RB_MRT_BASE_GMEM, 0, 0);
    REG32(&r, SP_PS_MRT_REG, 0, AF(SP_PS_MRT_REG, COLOR_FORMAT, _format.rb) | AF(SP_PS_MRT_REG, COLOR_UINT, _format.integer == 1) |
          AF(SP_PS_MRT_REG, COLOR_SINT, _format.integer == 2));                  // F2: fd6 emit_mrt
    REGADDR(&r, RB_COLOR_FLAG_BUFFER_ADDR, 0, 0, rtR);
    REG32(&r, RB_COLOR_FLAG_BUFFER_PITCH, 0, AFS(RB_COLOR_FLAG_BUFFER_PITCH, PITCH, 0) | AFS(RB_COLOR_FLAG_BUFFER_PITCH, ARRAY_PITCH, 0));
    REG32(&r, GRAS_LRZ_MRT_BUFFER_INFO_0, 0, AF(GRAS_LRZ_MRT_BUFFER_INFO_0, COLOR_FORMAT, _format.rb));
    uint64_t srgb = AF(RB_SRGB_CNTL, SRGB_MRT0, _format.srgb);
    const AdrenoAddr *mrtRW = _mrtRW;
    for (NSUInteger n = 1; n < _mrtCount; n++) {
        AdrenoAddr rd = mrtRW[n]; rd.access = ADRENO_IB_ACCESS_READ;
        REG32(&r, RB_MRT_BUF_INFO, n, AF(RB_MRT_BUF_INFO, COLOR_FORMAT, _mrt[n].format.rb) |
              AF(RB_MRT_BUF_INFO, COLOR_TILE_MODE, E(TILE6_LINEAR)) | AF(RB_MRT_BUF_INFO, COLOR_SWAP, _mrt[n].format.swap));
        REG32(&r, RB_MRT_PITCH, n, AFS(RB_MRT_PITCH, VALUE, _mrt[n].pitch));
        REG32(&r, RB_MRT_ARRAY_PITCH, n, AFS(RB_MRT_ARRAY_PITCH, VALUE, _mrt[n].bytes));
        REGADDR(&r, RB_MRT_BASE, n, 0, mrtRW[n]);
        REG32(&r, RB_MRT_BASE_GMEM, n, 0);
        REG32(&r, SP_PS_MRT_REG, n, AF(SP_PS_MRT_REG, COLOR_FORMAT, _mrt[n].format.rb) |
              AF(SP_PS_MRT_REG, COLOR_UINT, _mrt[n].format.integer == 1) | AF(SP_PS_MRT_REG, COLOR_SINT, _mrt[n].format.integer == 2));
        REGADDR(&r, RB_COLOR_FLAG_BUFFER_ADDR, n, 0, rd);
        REG32(&r, RB_COLOR_FLAG_BUFFER_PITCH, n, AFS(RB_COLOR_FLAG_BUFFER_PITCH, PITCH, 0) | AFS(RB_COLOR_FLAG_BUFFER_PITCH, ARRAY_PITCH, 0));
        srgb |= (uint64_t)(_mrt[n].format.srgb ? 1 : 0) << n;      // SRGB_MRTn is bit n of both sRGB controls
    }
    REG32(&r, RB_SRGB_CNTL, 0, srgb);                                         // fd6 emit_mrt: srgb_cntl |= 1 << i
    REG32(&r, SP_SRGB_CNTL, 0, srgb);
    REG32(&r, GRAS_CL_ARRAY_SIZE, 0, AF(GRAS_CL_ARRAY_SIZE, VALUE, 0));
    REG32(&r, TPL1_RAS_MSAA_CNTL, 0, AF(TPL1_RAS_MSAA_CNTL, SAMPLES, E(MSAA_ONE)));
    REG32(&r, TPL1_DEST_MSAA_CNTL, 0, AF(TPL1_DEST_MSAA_CNTL, SAMPLES, E(MSAA_ONE)) | AF(TPL1_DEST_MSAA_CNTL, MSAA_DISABLE, 1));
    REG32(&r, GRAS_SC_RAS_MSAA_CNTL, 0, AF(GRAS_SC_RAS_MSAA_CNTL, SAMPLES, E(MSAA_ONE)));
    REG32(&r, GRAS_SC_DEST_MSAA_CNTL, 0, AF(GRAS_SC_DEST_MSAA_CNTL, SAMPLES, E(MSAA_ONE)) | AF(GRAS_SC_DEST_MSAA_CNTL, MSAA_DISABLE, 1));
    REG32(&r, RB_RAS_MSAA_CNTL, 0, AF(RB_RAS_MSAA_CNTL, SAMPLES, E(MSAA_ONE)));
    REG32(&r, RB_DEST_MSAA_CNTL, 0, AF(RB_DEST_MSAA_CNTL, SAMPLES, E(MSAA_ONE)) | AF(RB_DEST_MSAA_CNTL, MSAA_DISABLE, 1));
    REG32(&r, RB_RESOLVE_GMEM_BUFFER_INFO, 0, AF(RB_RESOLVE_GMEM_BUFFER_INFO, SAMPLES, E(MSAA_ONE)));
    cs_crb(cs, &r);
    // fd6_emit_sysmem<A8XX>; MTLLoadActionClear = build_p7_ib's emit_sysmem_clears block (2D engine)
    emit_gmem_cache_cntl_sysmem(cs);
    emit_static_binning_regs(cs);
    if (clears && (_clear || _zsClear || _anyMrtClear)) {
        // A depth/stencil buffer is written through the 2D engine's colour path and then read through CCU depth:
        // the bracket cleans and invalidates both (fd6_emit_flushes' FD6_FLUSH_CCU_DEPTH | FD6_INVALIDATE_CCU_DEPTH).
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .ccuDepth = _zsClear, .invCcuDepth = _zsClear,
                                         .invCche = YES, .wfi = YES});
        if (_clear) emit_2d_clear(cs, rtW, _pitch, &_format, 0, 0, W, H, _clearRGBA);
        for (NSUInteger n = 1; n < _mrtCount; n++)
            if (_mrt[n].clear) {
                AdrenoAddr w = mrtRW[n]; w.access = ADRENO_IB_ACCESS_WRITE;
                emit_2d_clear(cs, w, _mrt[n].pitch, &_mrt[n].format, 0, 0, W, H, _mrt[n].words);
            }
        if (_zsClear) {
            AdrenoAddr zsW = zsRW;
            zsW.access = ADRENO_IB_ACCESS_WRITE;
            emit_2d_clear_zs(cs, zsW, &_zs, (uint32_t)_zsTexture.width, (uint32_t)_zsTexture.height, _zsWords, _zsKeep);
        }
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES});
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .ccuDepth = _zsClear, .invCcuDepth = _zsClear,
                                         .invCche = YES, .wfi = YES});
        cs_marker(cs, E(RM6_DIRECT_RENDER));
    }
    regs_reset(&r);
    REG32(&r, RB_RENDER_CNTL, 0, AF(RB_RENDER_CNTL, RASTER_MODE, E(TYPE_TILED)) | AF(RB_RENDER_CNTL, RASTER_DIRECTION, E(LR_TB)));
    REG32(&r, GRAS_SU_RENDER_CNTL, 0, 0);
    cs_crb(cs, &r);
    emit_lrz_off(cs);
}

- (AdrenoDrawProgram *)programForPipeline:(id<MTLRenderPipelineState>)pipeline {
    // The checks below depend only on the pipeline and this pass: a pipeline already accepted here is accepted again.
    if (pipeline && pipeline == _lastPipeline) return _lastProgram;
    AdrenoDrawProgram *program = [self adrenoCheckedProgramForPipeline:pipeline];
    _lastPipeline = pipeline; _lastProgram = program;
    return program;
}
- (AdrenoDrawProgram *)adrenoCheckedProgramForPipeline:(id<MTLRenderPipelineState>)pipeline {
    if (![(id)pipeline respondsToSelector:@selector(adrenoDrawProgram)] || [(id)pipeline device] != _device)
        AdrenoDrawRefuse(@"the render pipeline state does not belong to this Adreno device");
    AdrenoDrawProgram *program = [(AdrenoRenderPipelineState *)pipeline adrenoDrawProgram];
    if (program->_fixed.color[0] != _target.pixelFormat)
        AdrenoDrawRefuse(@"the pipeline's colour format %lu differs from the attachment's %lu",
                         (unsigned long)program->_fixed.color[0], (unsigned long)_target.pixelFormat);
    for (NSUInteger n = 1; n < 8; n++) {
        MTLPixelFormat want = n < _mrtCount ? _mrt[n].texture.pixelFormat : MTLPixelFormatInvalid;
        if (program->_fixed.color[n] != want)
            AdrenoDrawRefuse(@"the pipeline's colour format %lu for attachment %lu differs from the pass's %lu",
                             (unsigned long)program->_fixed.color[n], (unsigned long)n, (unsigned long)want);
    }
    return program;
}

// One draw: RD.build_ib's draw section (fd6_draw_vbo: vertex params, non-group state, the draw-state groups
// inline in group order, the driver constant loads, CP_DRAW_INDX_OFFSET).
- (void)emitDraw:(MTLPrimitiveType)type count:(NSUInteger)count instances:(NSUInteger)instances
     vertexStart:(NSUInteger)vertexStart indexBuffer:(id<MTLBuffer>)indexBuffer indexOffset:(NSUInteger)indexOffset
         index32:(BOOL)index32 bindings:(const AdrenoDrawBindings *)b {
    if (_finished) AdrenoDrawBug(@"draw after the pass ended");
    [self adrenoEnsureHeadroom];      // a no-op when adrenoDropRefusedDraw: already made room
    if (!b->pipeline) AdrenoDrawRefuse(@"no render pipeline state is set");
    AdrenoDrawProgram *program = [self programForPipeline:b->pipeline];
    NSDictionary *vs = program.vertexProgram, *fs = program.fragmentProgram;
    const AdrenoFixedState *fixed = &program->_fixed;
    uint64_t primType;
    BOOL strip = NO;
    switch (type) {
        case MTLPrimitiveTypePoint: primType = E(DI_PT_POINTLIST); break;           // fd6_screen.cc primtypes[]
        case MTLPrimitiveTypeTriangle: primType = E(DI_PT_TRILIST); break;
        case MTLPrimitiveTypeTriangleStrip: primType = E(DI_PT_TRISTRIP); strip = YES; break;
        // v80 (WindowServer). One-pixel lines: GRAS_SU_CNTL's LINEHALFWIDTH 0.5 and Bresenham LINE_MODE below; the kext
        // validator admits both. Indexed line strips restart like triangle strips (Metal always restarts strips).
        case MTLPrimitiveTypeLine: primType = E(DI_PT_LINELIST); break;
        case MTLPrimitiveTypeLineStrip: primType = E(DI_PT_LINESTRIP); strip = YES; break;
        default: AdrenoDrawRefuse(@"primitive type %lu is not supported yet", (unsigned long)type);
    }
    if (b->cullMode != MTLCullModeNone) AdrenoDrawRefuse(@"culling is not supported yet");
    if (b->fillMode != MTLTriangleFillModeFill) AdrenoDrawRefuse(@"line fill mode is not supported yet");
    if (b->depthClipMode != MTLDepthClipModeClip) AdrenoDrawRefuse(@"depth clamping is not supported yet");
    if (b->depthBias != 0 || b->depthSlopeScale != 0 || b->depthBiasClamp != 0) AdrenoDrawRefuse(@"depth bias is not supported yet");
    if (b->visibilityMode != MTLVisibilityResultModeDisabled) AdrenoDrawRefuse(@"visibility results are not supported yet");
    if (count > UINT32_MAX || instances > UINT32_MAX || vertexStart > UINT32_MAX) AdrenoDrawRefuse(@"draw counts exceed 32 bits");
    // Viewport (BINDING-ABI 4.3: Metal NDC y up, z in [0, 1]) and its scissor, clamped to the target.
    const double W = _width, H = _height;
    MTLViewport vp = b->viewportSet ? b->viewport : (MTLViewport){0, 0, W, H, 0, 1};
    if (!(vp.width > 0) || !(vp.height > 0) || !isfinite(vp.originX) || !isfinite(vp.originY) ||
        !isfinite(vp.width) || !isfinite(vp.height) || !isfinite(vp.znear) || !isfinite(vp.zfar))
        AdrenoDrawRefuse(@"viewport must have a positive finite size");
    double xs = vp.width / 2, xo = vp.originX + vp.width / 2, ys = -vp.height / 2, yo = vp.originY + vp.height / 2;
    double zs = vp.zfar - vp.znear, zo = vp.znear;
    int64_t vx0 = (int64_t)fmax(0, floor(vp.originX)), vy0 = (int64_t)fmax(0, floor(vp.originY));
    int64_t vx1 = (int64_t)fmin(W, ceil(vp.originX + vp.width)), vy1 = (int64_t)fmin(H, ceil(vp.originY + vp.height));
    MTLScissorRect sc = b->scissorSet ? b->scissor : (MTLScissorRect){0, 0, _width, _height};
    NSUInteger sx1 = MIN((NSUInteger)_width, sc.x + sc.width), sy1 = MIN((NSUInteger)_height, sc.y + sc.height);
    if (vx1 <= vx0 || vy1 <= vy0 || sc.x >= sx1 || sc.y >= sy1) return;      // nothing inside the target
    AdrenoCS *cs = _cs;
    AdrenoRegs r;
    const AdrenoFBReads *fb = &program->_fb;
    for (uint32_t k = 0; k < fb->count; k++)
        if (fb->read[k].attachment >= _mrtCount)
            AdrenoDrawRefuse(@"framebuffer fetch of colour %u, which the render pass does not attach (%lu attachments)",
                             fb->read[k].attachment, (unsigned long)_mrtCount);
    // The framebuffer-fetch barrier: this draw's fragments read what the clear or an earlier draw of the pass wrote
    // through CCU. Gallium's PIPE_TEXTURE_BARRIER_FRAMEBUFFER (fd6_texture_barrier: CCU colour clean, cache clean and
    // invalidate, wait for idle; CP_WAIT_FOR_ME is not an IB packet the kext admits) and turnip's sysmem colour-write ->
    // fragment-read barrier (CCU_CLEAN_COLOR, CACHE_INVALIDATE, WFI). Overlapping primitives of the draw itself are
    // ordered by SINGLE_PRIM_MODE below. A pass's first draw reads what the previous pass stored, which that pass's
    // finish and this pass's restore already flushed and invalidated.
    if (fb->count && (_clear || _anyMrtClear || _draws))
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .cache = YES, .invCache = YES, .invCche = YES, .wfi = YES});
    const BOOL indexed = indexBuffer != nil;
    const BOOL restart = indexed && strip;       // Metal: primitive restart is always on for indexed strips
    // fd6_draw_vbo vertex params
    regs_reset(&r);
    REG32(&r, VFD_INDEX_OFFSET, 0, indexed ? 0 : vertexStart);
    REG32(&r, VFD_INSTANCE_START_OFFSET, 0, 0);
    REG32(&r, PC_RESTART_INDEX, 0, AF(PC_RESTART_INDEX, VALUE, restart && !index32 ? 0xFFFFu : 0xFFFFFFFFu));
    cs_crb(cs, &r);
    // fd6_emit_non_group
    regs_reset(&r);
    REG32(&r, RB_STENCIL_REF_CNTL, 0, AF(RB_STENCIL_REF_CNTL, REF, _stencilFront & 0xFF) |
          AF(RB_STENCIL_REF_CNTL, BFREF, _stencilBack & 0xFF));
    REG32(&r, GRAS_CL_VIEWPORT_XOFFSET, 0, AdrenoF32(xo));
    REG32(&r, GRAS_CL_VIEWPORT_XSCALE, 0, AdrenoF32(xs));
    REG32(&r, GRAS_CL_VIEWPORT_YOFFSET, 0, AdrenoF32(yo));
    REG32(&r, GRAS_CL_VIEWPORT_YSCALE, 0, AdrenoF32(ys));
    REG32(&r, GRAS_CL_VIEWPORT_ZOFFSET, 0, AdrenoF32(zo));
    REG32(&r, GRAS_CL_VIEWPORT_ZSCALE, 0, AdrenoF32(zs));
    REG32(&r, GRAS_SC_VIEWPORT_SCISSOR_TL, 0, AF(GRAS_SC_VIEWPORT_SCISSOR_TL, X, vx0) | AF(GRAS_SC_VIEWPORT_SCISSOR_TL, Y, vy0));
    REG32(&r, GRAS_SC_VIEWPORT_SCISSOR_BR, 0, AF(GRAS_SC_VIEWPORT_SCISSOR_BR, X, vx1 - 1) | AF(GRAS_SC_VIEWPORT_SCISSOR_BR, Y, vy1 - 1));
    REG32(&r, GRAS_CL_GUARDBAND_CLIP_ADJ, 0, AF(GRAS_CL_GUARDBAND_CLIP_ADJ, HORZ, AdrenoGuardband(xo, xs)) |
          AF(GRAS_CL_GUARDBAND_CLIP_ADJ, VERT, AdrenoGuardband(yo, ys)));
    cs_crb(cs, &r);
    AdrenoDrawPlan *plan = AdrenoDrawPlanOf(program);   // nil: this program's draws read its export (the path below)
    uint32_t mrt;
    if (plan) {
        cs_replay(cs, plan->_progWords, plan->_progRelocs, plan->_progResources);  // PROG_CONFIG .. PROG_INTERP
        mrt = plan->_mrt;
    } else {
        AdrenoAddr vsCode = AdrenoResourceAddr(program.vertexCodeBuffer, 0, program.vertexCodeBuffer.length,
                                               ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_SHADER, @"vertex code");
        AdrenoAddr fsCode = AdrenoResourceAddr(program.fragmentCodeBuffer, 0, program.fragmentCodeBuffer.length,
                                               ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_SHADER, @"fragment code");
        // B.texture_counts: NTEX = NSAMP = num_samp (0: the variant checks refuse texture state in this wave)
        uint64_t ntex = PU(fs, @"num_samp"), nsamp = ntex;
        BOOL pixlod = PInt(fs, @"need_pixlod") != 0;
        emit_program_config(cs, vs, fs, ntex, nsamp, fb->count != 0);                 // PROG_CONFIG
        emit_shader_regs(cs, vs, YES, vsCode, pixlod);                                // PROG
        emit_shader_regs(cs, fs, NO, fsCode, pixlod);
        mrt = emit_program_linkage(cs, vs, fs, program.linkage);
        emit_interp_regs(cs, vs, fs);                                                 // PROG_INTERP
    }
    const uint32_t nr = (uint32_t)_mrtCount;                                          // PROG_FB_RAST
    const uint32_t comps = (uint32_t)(mrt & ((nr >= 8 ? 0 : (UINT64_C(1) << (4 * nr))) - 1));
    regs_reset(&r);
    const BOOL writesZ = plan ? plan->_writesZ : Valid(POutputRegid(fs, FRAG_RESULT_DEPTH));
    const BOOL writesStencil = plan ? plan->_writesStencil : Valid(POutputRegid(fs, FRAG_RESULT_STENCIL));
    REG32(&r, RB_PS_OUTPUT_CNTL, 0, AF(RB_PS_OUTPUT_CNTL, FRAG_WRITES_Z, writesZ) |
          AF(RB_PS_OUTPUT_CNTL, FRAG_WRITES_STENCILREF, writesStencil));
    REG32(&r, RB_PS_MRT_CNTL, 0, AF(RB_PS_MRT_CNTL, MRT, nr));
    REG32(&r, SP_PS_MRT_CNTL, 0, AF(SP_PS_MRT_CNTL, MRT, nr));
    REG32(&r, SP_PS_OUTPUT_MASK, 0, comps);
    REG32(&r, RB_PS_OUTPUT_MASK, 0, comps);
    cs_crb(cs, &r);
    regs_reset(&r);                                                                   // LRZ
    REG32(&r, GRAS_LRZ_CNTL, 0, 0);
    REG32(&r, RB_LRZ_CNTL, 0, 0);
    REG32(&r, RB_DEPTH_PLANE_CNTL, 0, AF(RB_DEPTH_PLANE_CNTL, Z_MODE, E(A6XX_LATE_Z)));
    REG32(&r, GRAS_SU_DEPTH_PLANE_CNTL, 0, AF(GRAS_SU_DEPTH_PLANE_CNTL, Z_MODE, E(A6XX_LATE_Z)));
    cs_crb(cs, &r);
    // VTXSTATE, VBO: one VFD fetch per VS generic input from one vertex buffer (RD programs VFD buffer 0)
    NSArray<NSNumber *> *attributes = plan ? nil : AdrenoVertexAttributes(vs);
    const NSUInteger attributeCount = plan ? plan->_attributeCount : attributes.count;
    if (attributeCount) {
        if (!fixed->vertexDescriptor) AdrenoDrawRefuse(@"the vertex function reads attributes but the pipeline has no vertex descriptor");
        NSUInteger bufferIndex = NSUIntegerMax;
        regs_reset(&r);
        for (NSUInteger i = 0; i < attributeCount; i++) {
            NSUInteger a = plan ? plan->_attributes[i] : attributes[i].unsignedIntegerValue;
            if (a >= 31 || fixed->attribute[a].format == MTLVertexFormatInvalid)
                AdrenoDrawRefuse(@"the vertex function reads attribute %lu, the vertex descriptor has none", (unsigned long)a);
            if (bufferIndex != NSUIntegerMax && fixed->attribute[a].bufferIndex != bufferIndex)
                AdrenoDrawRefuse(@"attributes from more than one vertex buffer are not supported yet");
            bufferIndex = fixed->attribute[a].bufferIndex;
            REG32(&r, VFD_FETCH_INSTR_INSTR, i, AF(VFD_FETCH_INSTR_INSTR, IDX, 0) |
                  AF(VFD_FETCH_INSTR_INSTR, OFFSET, fixed->attribute[a].offset) |
                  AF(VFD_FETCH_INSTR_INSTR, FORMAT, AdrenoVertexFormat(fixed->attribute[a].format)) |
                  AF(VFD_FETCH_INSTR_INSTR, SWAP, E(WZYX)) | AF(VFD_FETCH_INSTR_INSTR, UNK30, 1) | AF(VFD_FETCH_INSTR_INSTR, FLOAT, 1));
            REG32(&r, VFD_FETCH_INSTR_STEP_RATE, i, AF(VFD_FETCH_INSTR_STEP_RATE, VALUE, 1));
        }
        if (bufferIndex >= ADRENO_DRAW_BUFFER_SLOTS) AdrenoDrawRefuse(@"vertex buffer index %lu", (unsigned long)bufferIndex);
        if (fixed->layout[bufferIndex].step != MTLVertexStepFunctionPerVertex || fixed->layout[bufferIndex].rate != 1 ||
            !fixed->layout[bufferIndex].stride)
            AdrenoDrawRefuse(@"only per-vertex vertex buffers with a stride are supported yet");
        REG32(&r, VFD_VERTEX_BUFFER_STRIDE, 0, AF(VFD_VERTEX_BUFFER_STRIDE, VALUE, fixed->layout[bufferIndex].stride));
        cs_crb(cs, &r);
        uint64_t bytes = 0;
        AdrenoAddr vbo = AdrenoBindingAddr(cs, &b->vertex[bufferIndex], 1, ADRENO_IB_ACCESS_READ, ADRENO_IB_ALIGN_LOG2_VERTEX,
                                           UINT32_MAX, &bytes, AdrenoSlotName(AdrenoSlotVertexBuffer, (NSInteger)bufferIndex));
        regs_reset(&r);
        REGADDR(&r, VFD_VERTEX_BUFFER_BASE, 0, 0, vbo);
        REG32(&r, VFD_VERTEX_BUFFER_SIZE, 0, AF(VFD_VERTEX_BUFFER_SIZE, VALUE, bytes));
        cs_crb(cs, &r);
    }
#if ADRENO_UBO_MIRROR
    // U1(a): a program that may store can write any buffer it binds: this draw and the rest of the pass copy their
    // unaligned constants in the pass, and the table is emptied when the pass ends.
    if (program->_mayStore) _mirrorOff = YES;
    const AdrenoMirrorContext mirrorContext = {_mirrors, self, _mirrorCopies, _mirrorArenas, _mirrorOff};
    const AdrenoMirrorContext *mc = &mirrorContext;
#endif
    if (plan) {                                                                        // CONST
        emit_app_ubos_planned(cs, &plan->_vs, YES, b->vertex, _device MIRROR_ARG(mc));
        emit_app_ubos_planned(cs, &plan->_fs, NO, b->fragment, _device MIRROR_ARG(mc));
        emit_fragment_textures_planned(cs, &plan->_textures, _device, _fragmentTextures, _fragmentSamplers, fb, _views,
                                       _mrtCount);                                     // FS_TEX
    } else {
        emit_app_ubos(cs, vs, YES, b->vertex, _device MIRROR_ARG(mc));
        emit_app_ubos(cs, fs, NO, b->fragment, _device MIRROR_ARG(mc));
        emit_fragment_textures(cs, fs, _device, _fragmentTextures, _fragmentSamplers, fb, _views, _mrtCount);
    }
    regs_reset(&r);                                                                   // RASTERIZER
    REG32(&r, GRAS_CL_CNTL, 0, AF(GRAS_CL_CNTL, Z_CLAMP_ENABLE, 1) | AF(GRAS_CL_CNTL, ZERO_GB_SCALE_Z, 1) |
          AF(GRAS_CL_CNTL, VP_CLIP_CODE_IGNORE, 1));
    REG32(&r, GRAS_SU_CNTL, 0, AF(GRAS_SU_CNTL, FRONT_CW, b->winding == MTLWindingClockwise) |
          AFIX(GRAS_SU_CNTL, LINEHALFWIDTH, 2, 0.5) | AF(GRAS_SU_CNTL, LINE_MODE, E(BRESENHAM)));
    // fd6_rasterizer.cc: a per-vertex point size is clamped to [MIN, MAX] (gallium: 0 for sprites .. 4092), here
    // Metal's measured range; without one, MIN = MAX = GRAS_SU_POINT_SIZE = 1 pixel.
    const BOOL pointSize = plan ? plan->_pointSize : Valid(POutputRegid(vs, VARYING_SLOT_PSIZ));
    REG32(&r, GRAS_SU_POINT_MINMAX, 0, AFIX(GRAS_SU_POINT_MINMAX, MIN, 4, pointSize ? ADRENO_POINT_SIZE_MIN : 1.0) |
          AFIX(GRAS_SU_POINT_MINMAX, MAX, 4, pointSize ? ADRENO_POINT_SIZE_MAX : 1.0));
    REG32(&r, GRAS_SU_POINT_SIZE, 0, AFIX(GRAS_SU_POINT_SIZE, VALUE, 4, 1.0));
    REG32(&r, GRAS_SU_POLY_OFFSET_SCALE, 0, AdrenoF32(0.0));
    REG32(&r, GRAS_SU_POLY_OFFSET_OFFSET, 0, AdrenoF32(0.0));
    REG32(&r, GRAS_SU_POLY_OFFSET_OFFSET_CLAMP, 0, AdrenoF32(0.0));
    REG32(&r, PC_CNTL, 0, AF(PC_CNTL, PRIMITIVE_RESTART, restart) | AF(PC_CNTL, PROVOKING_VTX_LAST, 0));
    REG32(&r, VPC_PC_CNTL, 0, AF(VPC_PC_CNTL, PRIMITIVE_RESTART, restart) | AF(VPC_PC_CNTL, PROVOKING_VTX_LAST, 0));
    REG32(&r, VPC_RAST_CNTL, 0, AF(VPC_RAST_CNTL, MODE, E(POLYMODE6_TRIANGLES)));
    REG32(&r, PC_DGEN_RAST_CNTL, 0, AF(PC_DGEN_RAST_CNTL, MODE, E(POLYMODE6_TRIANGLES)));
    REG32(&r, GRAS_RAST_CNTL, 0, AF(GRAS_RAST_CNTL, MODE, E(POLYMODE6_TRIANGLES)));
    REG32(&r, VPC_PS_RAST_CNTL, 0, AF(VPC_PS_RAST_CNTL, MODE, E(POLYMODE6_TRIANGLES)));
    for (unsigned i = 0; i < 16; i++) {
        REG32(&r, GRAS_CL_VIEWPORT_ZCLAMP_MIN, i, AdrenoF32(0.0));
        REG32(&r, GRAS_CL_VIEWPORT_ZCLAMP_MAX, i, AdrenoF32(1.0));
        REG32(&r, RB_VIEWPORT_ZCLAMP_MIN_REG, i, AdrenoF32(0.0));
        REG32(&r, RB_VIEWPORT_ZCLAMP_MAX_REG, i, AdrenoF32(1.0));
    }
    cs_crb(cs, &r);
    // ZSA: fd6_zsa_state_create<A8XX> for the bound MTLDepthStencilState. Metal tests only attached aspects: without a
    // depth attachment depth is off, without a stencil attachment stencil is off; compare Always with no write (depth)
    // or Always with Keep everywhere (stencil, both faces) has no effect and stays off, as in the default state.
    MTLDepthStencilDescriptor *ds = _depthStencil ? [(id)_depthStencil adrenoDepthStencilDescriptor] : nil;
    BOOL zTest = NO, zWrite = NO, sOn = NO;
    uint64_t zfunc = E(FUNC_NEVER), stencilCntl = 0, stencilMask = 0, stencilWrite = 0;
    if (_depthAttached && ds && (ds.depthCompareFunction != MTLCompareFunctionAlways || ds.depthWriteEnabled)) {
        zTest = YES; zWrite = ds.depthWriteEnabled; zfunc = AdrenoCompareFunc(ds.depthCompareFunction);
    }
    if (_stencilAttached && ds) {
        MTLStencilDescriptor *f = ds.frontFaceStencil ?: [MTLStencilDescriptor new];
        MTLStencilDescriptor *k = ds.backFaceStencil ?: [MTLStencilDescriptor new];
        for (MTLStencilDescriptor *x in @[f, k])
            if (x.stencilCompareFunction != MTLCompareFunctionAlways || x.stencilFailureOperation != MTLStencilOperationKeep ||
                x.depthFailureOperation != MTLStencilOperationKeep || x.depthStencilPassOperation != MTLStencilOperationKeep)
                sOn = YES;
        if (sOn) {
            stencilCntl = AF(RB_STENCIL_CNTL, STENCIL_ENABLE, 1) | AF(RB_STENCIL_CNTL, STENCIL_ENABLE_BF, 1) |
                          AF(RB_STENCIL_CNTL, STENCIL_READ, 1) |
                          AF(RB_STENCIL_CNTL, FUNC, AdrenoCompareFunc(f.stencilCompareFunction)) |
                          AF(RB_STENCIL_CNTL, FAIL, AdrenoStencilOp(f.stencilFailureOperation)) |
                          AF(RB_STENCIL_CNTL, ZPASS, AdrenoStencilOp(f.depthStencilPassOperation)) |
                          AF(RB_STENCIL_CNTL, ZFAIL, AdrenoStencilOp(f.depthFailureOperation)) |
                          AF(RB_STENCIL_CNTL, FUNC_BF, AdrenoCompareFunc(k.stencilCompareFunction)) |
                          AF(RB_STENCIL_CNTL, FAIL_BF, AdrenoStencilOp(k.stencilFailureOperation)) |
                          AF(RB_STENCIL_CNTL, ZPASS_BF, AdrenoStencilOp(k.depthStencilPassOperation)) |
                          AF(RB_STENCIL_CNTL, ZFAIL_BF, AdrenoStencilOp(k.depthFailureOperation));
            stencilMask = AF(RB_STENCIL_MASK, MASK, f.readMask & 0xFF) | AF(RB_STENCIL_MASK, BFMASK, k.readMask & 0xFF);
            stencilWrite = AF(RB_STENCIL_WRITE_MASK, WRMASK, f.writeMask & 0xFF) |
                           AF(RB_STENCIL_WRITE_MASK, BFWRMASK, k.writeMask & 0xFF);
        }
    }
    regs_reset(&r);                                                                   // ZSA
    REG32(&r, RB_ALPHA_TEST_CNTL, 0, AF(RB_ALPHA_TEST_CNTL, ALPHA_TEST_FUNC, E(FUNC_NEVER)));
    REG32(&r, SP_ALPHA_TEST_CNTL, 0, 0);
    REG32(&r, RB_STENCIL_CNTL, 0, stencilCntl);
    REG32(&r, GRAS_SU_STENCIL_CNTL, 0, AF(GRAS_SU_STENCIL_CNTL, STENCIL_ENABLE, sOn));
    REG32(&r, RB_STENCIL_MASK, 0, stencilMask);
    REG32(&r, RB_STENCIL_WRITE_MASK, 0, stencilWrite);
    REG32(&r, RB_DEPTH_CNTL, 0, AF(RB_DEPTH_CNTL, Z_TEST_ENABLE, zTest) | AF(RB_DEPTH_CNTL, Z_WRITE_ENABLE, zWrite) |
          AF(RB_DEPTH_CNTL, ZFUNC, zfunc) | AF(RB_DEPTH_CNTL, Z_CLAMP_ENABLE, 1) | AF(RB_DEPTH_CNTL, Z_READ_ENABLE, zTest) |
          AF(RB_DEPTH_CNTL, O_DEPTH_01_CLAMP_EN, 1));
    REG32(&r, GRAS_SU_DEPTH_CNTL, 0, AF(GRAS_SU_DEPTH_CNTL, Z_TEST_ENABLE, zTest));
    REG32(&r, RB_DEPTH_BOUND_MIN, 0, AdrenoF32(0.0));
    REG32(&r, RB_DEPTH_BOUND_MAX, 0, AdrenoF32(1.0));
    cs_crb(cs, &r);
    // BLEND: Metal's per-attachment state (RD.effective_blend, native attachments; fd6_blend_state_create for MRTs)
    regs_reset(&r);
    uint64_t blendMask = 0;
    for (NSUInteger n = 0; n < _mrtCount; n++) {
        // F2: Metal does not blend integer attachments (Gallium and Turnip force it off): never read the destination.
        const BOOL on = fixed->blend[n] && !(n ? _mrt[n].format.integer : _format.integer);
        const uint64_t mask = AdrenoComponentMask(fixed->writeMask[n]);
        uint64_t factors = on
            ? AF(RB_MRT_BLEND_CONTROL, RGB_SRC_FACTOR, AdrenoBlendFactor(fixed->srcRGB[n])) |
              AF(RB_MRT_BLEND_CONTROL, RGB_BLEND_OPCODE, AdrenoBlendOp(fixed->rgbOp[n])) |
              AF(RB_MRT_BLEND_CONTROL, RGB_DEST_FACTOR, AdrenoBlendFactor(fixed->dstRGB[n])) |
              AF(RB_MRT_BLEND_CONTROL, ALPHA_SRC_FACTOR, AdrenoBlendFactor(fixed->srcAlpha[n])) |
              AF(RB_MRT_BLEND_CONTROL, ALPHA_BLEND_OPCODE, AdrenoBlendOp(fixed->alphaOp[n])) |
              AF(RB_MRT_BLEND_CONTROL, ALPHA_DEST_FACTOR, AdrenoBlendFactor(fixed->dstAlpha[n]))
            : AF(RB_MRT_BLEND_CONTROL, RGB_SRC_FACTOR, E(FACTOR_ZERO)) | AF(RB_MRT_BLEND_CONTROL, RGB_BLEND_OPCODE, E(BLEND_DST_PLUS_SRC)) |
              AF(RB_MRT_BLEND_CONTROL, RGB_DEST_FACTOR, E(FACTOR_ZERO)) | AF(RB_MRT_BLEND_CONTROL, ALPHA_SRC_FACTOR, E(FACTOR_ZERO)) |
              AF(RB_MRT_BLEND_CONTROL, ALPHA_BLEND_OPCODE, E(BLEND_DST_PLUS_SRC)) | AF(RB_MRT_BLEND_CONTROL, ALPHA_DEST_FACTOR, E(FACTOR_ZERO));
        REG32(&r, RB_MRT_BLEND_CONTROL, n, factors);
        REG32(&r, RB_MRT_CONTROL, n, AF(RB_MRT_CONTROL, COLOR_BLEND_EN, on) | AF(RB_MRT_CONTROL, ALPHA_BLEND_EN, on) |
              AF(RB_MRT_CONTROL, ROP_CODE, E(ROP_COPY)) | AF(RB_MRT_CONTROL, COMPONENT_ENABLE, mask));
        REG32(&r, SP_MRT_BLEND_CNTL_REG, n, AF(SP_MRT_BLEND_CNTL_REG, COLOR_BLEND_EN, on) |
              AF(SP_MRT_BLEND_CNTL_REG, ALPHA_BLEND_EN, on) | AF(SP_MRT_BLEND_CNTL_REG, COMPONENT_WRITE_MASK, mask));
        if (on) blendMask |= UINT64_C(1) << n;
    }
    const uint64_t independent = _mrtCount > 1 ? 1 : 0;
    REG32(&r, RB_DITHER_CNTL, 0, 0);
    REG32(&r, SP_BLEND_CNTL, 0, AF(SP_BLEND_CNTL, ENABLE_BLEND, blendMask) | AF(SP_BLEND_CNTL, INDEPENDENT_BLEND_EN, independent));
    REG32(&r, RB_BLEND_CNTL, 0, AF(RB_BLEND_CNTL, BLEND_READS_DEST, blendMask) | AF(RB_BLEND_CNTL, INDEPENDENT_BLEND, independent) |
          AF(RB_BLEND_CNTL, SAMPLE_MASK, 0xFFFF));
    cs_crb(cs, &r);
    regs_reset(&r);                                                                   // SCISSOR
    REG32(&r, GRAS_SC_SCREEN_SCISSOR_TL, 0, AF(GRAS_SC_SCREEN_SCISSOR_TL, X, sc.x) | AF(GRAS_SC_SCREEN_SCISSOR_TL, Y, sc.y));
    REG32(&r, GRAS_SC_SCREEN_SCISSOR_BR, 0, AF(GRAS_SC_SCREEN_SCISSOR_BR, X, sx1 - 1) | AF(GRAS_SC_SCREEN_SCISSOR_BR, Y, sy1 - 1));
    cs_crb(cs, &r);
    regs_reset(&r);                                                                   // BLEND_COLOR
    REG32(&r, RB_BLEND_CONSTANT_RED_FP32, 0, AdrenoF32(b->blendColor[0]));
    REG32(&r, RB_BLEND_CONSTANT_GREEN_FP32, 0, AdrenoF32(b->blendColor[1]));
    REG32(&r, RB_BLEND_CONSTANT_BLUE_FP32, 0, AdrenoF32(b->blendColor[2]));
    REG32(&r, RB_BLEND_CONSTANT_ALPHA_FP32, 0, AdrenoF32(b->blendColor[3]));
    cs_crb(cs, &r);
    regs_reset(&r);                                                                   // SAMPLE_LOCATIONS
    REG32(&r, GRAS_SC_MSAA_SAMPLE_POS_CNTL, 0, 0);
    REG32(&r, RB_MSAA_SAMPLE_POS_CNTL, 0, 0);
    cs_crb(cs, &r);
    for (unsigned i = 0; i < 5; i++) {                                                // BINDLESS 0..4: the zero page
        regs_reset(&r);
        REG32(&r, SP_UPDATE_CNTL, 0, 0);
        REGADDR(&r, SP_GFX_BINDLESS_BASE_DESCRIPTOR, i,
                AF(SP_GFX_BINDLESS_BASE_DESCRIPTOR, DESC_SIZE, E(BINDLESS_DESCRIPTOR_64B)), AdrenoZeroAddr());
        cs_crb(cs, &r);
    }
    // PRIM_MODE_SYSMEM: build_prim_mode (fd6_emit.cc) / tu6_emit_prim_mode_sysmem: a fragment function that reads its
    // attachments in sysmem flushes per overlapping primitive (Metal's raster-order framebuffer fetch).
    regs_reset(&r);
    REG32(&r, GRAS_SC_CNTL, 0, AF(GRAS_SC_CNTL, SINGLE_PRIM_MODE, fb->count ? E(FLUSH_PER_OVERLAP_AND_OVERWRITE) : E(NO_FLUSH)));
    cs_crb(cs, &r);
    if (plan) cs_replay(cs, plan->_tailWords, plan->_tailRelocs, plan->_tailResources);   // driver constant data
    else {
        emit_driver_ubos(cs, vs, YES, program.vertexCodeBuffer);
        emit_driver_ubos(cs, fs, NO, program.fragmentCodeBuffer);
    }
    uint32_t draw0 = PF(CP_DRAW_INDX_OFFSET_0, PRIM_TYPE, primType) |
                     PF(CP_DRAW_INDX_OFFSET_0, SOURCE_SELECT, indexed ? E(DI_SRC_SEL_DMA) : E(DI_SRC_SEL_AUTO_INDEX)) |
                     PF(CP_DRAW_INDX_OFFSET_0, VIS_CULL, E(USE_VISIBILITY)) |
                     PF(CP_DRAW_INDX_OFFSET_0, INDEX_SIZE, !indexed ? E(INDEX4_SIZE_8_BIT) :
                                                           index32 ? E(INDEX4_SIZE_32_BIT) : E(INDEX4_SIZE_16_BIT)) |
                     PF(CP_DRAW_INDX_OFFSET_0, PATCH_TYPE, E(TESS_QUADS));
    if (!indexed) {
        PKT7(cs, E(CP_DRAW_INDX_OFFSET), draw0, PF(CP_DRAW_INDX_OFFSET_1, NUM_INSTANCES, instances),
             PF(CP_DRAW_INDX_OFFSET_2, NUM_INDICES, count));
    } else {
        // fd6_draw.cc draw_emit<DRAW_DIRECT_OP_INDEXED>: FIRST_INDX, INDX_BASE (reg64), MAX_INDICES
        uint64_t available = indexBuffer.length > indexOffset ? indexBuffer.length - indexOffset : 0;
        const uint64_t indexBytes = index32 ? 4 : 2;
        uint64_t maxIndices = available / indexBytes;
        if (count > maxIndices) AdrenoDrawRefuse(@"%lu indices at offset %lu exceed the index buffer", (unsigned long)count, (unsigned long)indexOffset);
        AdrenoAddr indices = AdrenoResourceAddr(indexBuffer, indexOffset, indexBytes * maxIndices, ADRENO_IB_ACCESS_READ,
                                                index32 ? 2 : ADRENO_IB_ALIGN_LOG2_INDEX16, @"index buffer");
        uint64_t start = cs_dwords(cs);
        PKT7(cs, E(CP_DRAW_INDX_OFFSET), draw0, PF(CP_DRAW_INDX_OFFSET_1, NUM_INSTANCES, instances),
             PF(CP_DRAW_INDX_OFFSET_2, NUM_INDICES, count), PF(CP_DRAW_INDX_OFFSET_3, FIRST_INDX, 0), 0, 0,
             PF(A5XX_CP_DRAW_INDX_OFFSET_6, MAX_INDICES, maxIndices));
        cs_reloc(cs, ADRENO_SPACE_IB, start + 1 + A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE, ADRENO_SPACE_IB,
                 start + 2 + A8XX_PKT_A5XX_CP_DRAW_INDX_OFFSET_INDX_BASE, ADRENO_IB_HI_BITS_REG64, indices);
    }
    _draws++;
    _segmentDraws++;
    // A segment is one package; adrenoEnsureHeadroom opened a new one before this draw when this one was nearly full,
    // so this refuses only a single draw larger than an empty segment's room.
    if (cs_dwords(cs) + 64 > ADRENO_IB_MAX_DWORDS || cs->_data.length > ADRENO_IB_MAX_DATA ||
        cs->_relocs.length / sizeof(AdrenoRelocDraft) + 8 > ADRENO_IB_MAX_RELOCS)
        AdrenoDrawRefuse(@"a render pass larger than one IB package is not supported yet");
}

- (void)drawPrimitives:(MTLPrimitiveType)type vertexStart:(NSUInteger)start vertexCount:(NSUInteger)count
         instanceCount:(NSUInteger)instances bindings:(const AdrenoDrawBindings *)bindings {
    if (!count || !instances) return;
    [self emitDraw:type count:count instances:instances vertexStart:start indexBuffer:nil indexOffset:0 index32:NO
          bindings:bindings];
}
- (void)drawIndexedPrimitives:(MTLPrimitiveType)type indexCount:(NSUInteger)count indexType:(MTLIndexType)indexType
                  indexBuffer:(id<MTLBuffer>)indexBuffer indexBufferOffset:(NSUInteger)offset
                instanceCount:(NSUInteger)instances bindings:(const AdrenoDrawBindings *)bindings {
    if (!count || !instances) return;
    // fd6_draw.cc: INDEX4_SIZE_16_BIT or INDEX4_SIZE_32_BIT; Metal's restart index is the type's all-ones value.
    const BOOL index32 = indexType == MTLIndexTypeUInt32;
    if (indexType != MTLIndexTypeUInt16 && !index32) AdrenoDrawRefuse(@"index type %lu", (unsigned long)indexType);
    if (!indexBuffer || offset % (index32 ? 4 : 2))
        AdrenoDrawRefuse(@"indexed draws need an index buffer and an offset aligned to the index size");
    [self emitDraw:type count:count instances:instances vertexStart:0 indexBuffer:indexBuffer indexOffset:offset
           index32:index32 bindings:bindings];
}

// fd6_emit_sysmem_fini<A8XX> + emit_common_fini, without the batch fence (design 5.3).
- (void)finish {
    if (_finished) return;
    emit_pass_epilogue(_cs);
#if ADRENO_UBO_MIRROR
    [self adrenoFinishMirrors];
#endif
#if ADRENO_PERF_COUNTERS
    atomic_fetch_add(&gAdrenoPerfRenderPasses, 1);
    atomic_fetch_add(&gAdrenoPerfDraws, _draws);
#endif
    _finished = YES;
}
- (BOOL)empty { return !_clear && !_zsClear && !_anyMrtClear && !_draws; }
- (void)enumerateResources:(void (^)(id resource, MTLResourceUsage usage))block {
    for (id resource in _cs->_usage) block(resource, [[_cs->_usage objectForKey:resource] unsignedIntegerValue]);
}
- (AdrenoCS *)adrenoCS { return _cs; }
@end

#if ADRENO_UBO_MIRROR
void AdrenoPassUseMirrors(AdrenoRenderPass *pass, id commandBuffer) {
    if (!pass || !commandBuffer || !AdrenoMirrorOn()) return;
    [pass adrenoUseMirrors:AdrenoMirrorsOf(commandBuffer, YES)];
}
// U1(c): render passes and their segments and preludes settle their own writes in -finish; any other finished pass
// (blit copies, mipmaps, compute) drops the mirrors of everything it relocates for writing.
void AdrenoMirrorsAfterPass(id commandBuffer, id<AdrenoFinishedPass> pass) {
    AdrenoUBOMirrors *t = AdrenoMirrorsOf(commandBuffer, NO);
    if (!t || !t->_entries.count || !pass || [(id)pass isKindOfClass:[AdrenoRenderPass class]] ||
        [(id)pass isKindOfClass:[AdrenoPassSegment class]])
        return;
    NSMutableArray *written = [NSMutableArray array];
    [pass enumerateResources:^(id resource, MTLResourceUsage usage) { if (usage & MTLResourceUsageWrite) [written addObject:resource]; }];
    for (id resource in written) AdrenoMirrorsDropWritten(t, resource);
}
#endif

// ================================================================================================================
// Compute programs and dispatches. Scope/failure inventory:
// docs/ADRENO-COMPUTE-EXECUTION-20261019.md. No entry-name whitelist or CPU shader fallback.
// ================================================================================================================
#define ADRENO_COMPUTE_SLOTS 8   // highest T#/UAV slot + 1 a compute binding may use (CoreImage: T#1, UAV0; MPS: T#0, UAV1)
static uint64_t AdrenoComputeUBOMinimum(NSDictionary *v) {
    uint64_t minimum=AdrenoUBOMinBytes(v,0);
    BOOL used=NO;
    for (NSDictionary *binding in Bindings(v,@"ubo")) {
        if (binding[@"minimum_bytes"]) minimum=MAX(minimum,PU(binding,@"minimum_bytes"));
        if (PInt(binding,@"slot")==0 && Used(binding)) used=YES;
    }
    // A used UBO0 read only by ldc (CoreImage's ci_fill: no pushed block-0 range, no reflected extent) needs one vec4;
    // its descriptor spans the whole bound range (AdrenoBindingAddr) and the hardware bounds-checks reads past it.
    if (!minimum && used) minimum=16;
    if (!minimum || minimum>ADRENO_UBO_MAX_BYTES)
        AdrenoDrawRefuse(@"compute application UBO extent is absent or exceeds its descriptor");
    return minimum;
}

// The compute binding contract (docs/USERSPACE-GRAPHICS-20261019.md, v80 CoreImage compute shapes): one sampled float
// texture2d and one writable float texture2d, each at the slot equal to its Metal texture index, sampler0 and UBO0.
// MPS's image integral is T#0 / UAV1; CoreImage's generated kernels (iconservicesagent) are UAV0 / T#1. A generator
// (CoreImage's ci_fill) has the writable texture and UBO0 only: no sampled texture and no sampler (textureSlot -1).
static void AdrenoComputeSlots(NSDictionary *v, NSInteger *textureSlot, NSInteger *imageSlot) {
    *textureSlot=*imageSlot=-1;
    BOOL sampler=NO,ubo=NO;
    for (NSDictionary *b in Bindings(v,nil)) {
        NSString *kind=b[@"kind"];
        NSInteger slot=PInt(b,@"slot"),index=PInt(b,@"metal_index");
        if (!BoundOrUsed(b) || !Used(b) || slot!=index || slot<0)
            AdrenoDrawRefuse(@"compute binding %@ is unused or its slot %ld differs from Metal index %ld",kind,(long)slot,(long)index);
        if ([kind isEqual:@"texture"]) {
            if (*textureSlot>=0 || slot>=ADRENO_COMPUTE_SLOTS || ![b[@"access"] isEqual:@"sample"] ||
                ![b[@"type"] isEqual:@"texture2d<float, sample>"])
                AdrenoDrawRefuse(@"compute requires one sampled float texture2d below texture(%d)",ADRENO_COMPUTE_SLOTS);
            *textureSlot=slot;
        } else if ([kind isEqual:@"storage_texture"]) {
            if (*imageSlot>=0 || slot>=ADRENO_COMPUTE_SLOTS || ![b[@"access"] isEqual:@"write"] ||
                ![b[@"type"] isEqual:@"texture2d<float, write>"])
                AdrenoDrawRefuse(@"compute requires one writable float texture2d below texture(%d)",ADRENO_COMPUTE_SLOTS);
            *imageSlot=slot;
        } else if ([kind isEqual:@"sampler"] && !sampler && slot==0) sampler=YES;
        else if ([kind isEqual:@"ubo"] && !ubo && slot==0) ubo=YES;
        else AdrenoDrawRefuse(@"compute has unsupported or duplicate binding %@",kind);
    }
    if (*imageSlot<0 || *textureSlot==*imageSlot || (*textureSlot>=0)!=sampler || !ubo)
        AdrenoDrawRefuse(@"compute binding contract is incomplete");
}

static void AdrenoCheckComputeVariant(NSDictionary *v) {
    NSDictionary *sc=PDict(v,@"sidecar"), *ir3=PDict(sc,@"ir3"), *stats=PDict(ir3,@"stats");
    NSDictionary *constants=PDict(v,@"const_state"), *reflection=PDict(sc,@"reflection"), *info=PDict(v,@"info");
    NSDictionary *compute=PDict(v,@"cs");
    for (NSString *flag in @[@"force_linear_dispatch",@"round_robin_mode",@"local_size_variable"])
        if (PU(compute,flag)>1) AdrenoDrawRefuse(@"compute compiler flag %@ is not boolean",flag);
    NSArray *local=PArray(compute,@"local_size");
    if (local.count!=3) AdrenoDrawRefuse(@"compute local-size export shape");
    for (id value in local)
        if (![value isKindOfClass:[NSNumber class]] || [value doubleValue]!=floor([value doubleValue]) ||
            [value integerValue]<0 || [value unsignedLongLongValue]>1024 ||
            (!PU(compute,@"local_size_variable") && ![value unsignedLongLongValue]))
            AdrenoDrawRefuse(@"compute local-size export is invalid");
    if (![v[@"type"] isEqual:@"CS"] || ![reflection[@"stage"] isEqual:@"kernel"] ||
        ![sc[@"chip_id"] isEqual:@"0x44070041"] || PInt(sc,@"abi_version")!=6 ||
        PInt(reflection,@"abi_version")!=6 || PInt(stats,@"ubo_slots")!=ADRENO_UBO_SLOTS)
        AdrenoDrawRefuse(@"compute requires X2-90 CS reflection ABI 6");
    if (PInt(v,@"pvtmem_size") || PInt(PDict(ir3,@"pvtmem"),@"pvtmem_size") ||
        PInt(v,@"shared_size") || PInt(reflection,@"threadgroup_bytes") ||
        PInt(info,@"constant_data_offset") || PInt(reflection,@"constant_data_bytes"))
        AdrenoDrawRefuse(@"compute private/shared memory or constant-data allocation is not built");
    for (NSString *field in @[@"fb_read",@"has_kill",@"need_full_quad",@"need_pixlod",@"num_sampler_prefetch",
                              @"clip_mask",@"cull_mask",@"stream_outputs"])
        if (PInt(v,field)) AdrenoDrawRefuse(@"compute requires unsupported %@",field);
    NSArray *bindless=PArray(v,@"bindless");
    if (bindless.count!=4) AdrenoDrawRefuse(@"compute bindless export shape");
    for (NSNumber *b in bindless) if (b.integerValue) AdrenoDrawRefuse(@"compute bindless resources are not built");
    if (PArray(reflection,@"rt_lowering").count || PArray(reflection,@"render_targets").count ||
        PArray(reflection,@"varyings").count || PArray(v,@"outputs").count || AdrenoConstantSamplers(v).count)
        AdrenoDrawRefuse(@"compute attachment, varying or constant-sampler state is not built");
    for (NSString *key in @[@"rt_classes",@"texture_classes"])
        for (NSNumber *c in PArray(PDict(sc,@"key_inputs"),key))
            if (c.integerValue) AdrenoDrawRefuse(@"compute lowered texture/target classes are not built");
    NSInteger textureSlot=-1,imageSlot=-1;
    AdrenoComputeSlots(v,&textureSlot,&imageSlot);
    // num_samp is the T# count (as SP_PS_TSIZE for fragments): ntex, 1 + the sampled texture's slot (0 for a generator).
    if (PU(v,@"num_samp")!=(uint64_t)(textureSlot+1) || PU(stats,@"nsamp")!=(textureSlot>=0 ? 1u : 0u) || PU(v,@"has_ssbo")!=1 ||
        PU(stats,@"ntex")!=(uint64_t)(textureSlot+1) || PU(v,@"num_uavs")!=(uint64_t)imageSlot+1)
        AdrenoDrawRefuse(@"compute requires one sampled texture at T#%ld, one storage image at UAV %ld and sampler0 "
                         "(num_samp %llu nsamp %llu has_ssbo %llu ntex %llu num_uavs %llu)",(long)textureSlot,(long)imageSlot,
                         PU(v,@"num_samp"),PU(stats,@"nsamp"),PU(v,@"has_ssbo"),PU(stats,@"ntex"),PU(v,@"num_uavs"));
    (void)AdrenoComputeUBOMinimum(v);
    if (PInt(constants,@"num_app_ubos")!=1 || PInt(constants,@"driver_params_ubo")!=1 ||
        PInt(constants,@"consts_ubo")!=-1 || PInt(constants,@"primitive_map_ubo")!=-1 ||
        PInt(constants,@"primitive_param_ubo")!=-1 || PInt(stats,@"driver_table_ubo")!=-1)
        AdrenoDrawRefuse(@"compute requires application UBO0 and driver-parameter UBO1 only");
    NSArray *drivers=PArray(ir3,@"driver_ubos");
    uint64_t doubleSize=PU(info,@"double_threadsize");
    // THREAD128 (MPS, most CoreImage kernels) or THREAD64 (CoreImage's Lanczos passes); emit_compute_program
    // programs SP_CS_CNTL_0 / WIE / WGE THREADSIZE from it and the driver ABI's subgroup size must agree.
    if (doubleSize>1 || drivers.count!=1) AdrenoDrawRefuse(@"compute requires the X2-90 THREAD64 or THREAD128 compiler variant");
    NSDictionary *driver=drivers[0];
    if (![driver[@"kind"] isEqual:@"driver_params"] || ![driver[@"struct"] isEqual:@"ir3_driver_params_cs"] ||
        PInt(driver,@"ubo")!=1 || PInt(driver,@"size_dwords")<11 || PInt(driver,@"size_dwords")>16 ||
        PInt(driver,@"subgroup_size")!=(64u<<doubleSize) || !PInt(v,@"need_driver_params"))
        AdrenoDrawRefuse(@"compute driver-parameter ABI is unsupported");
    NSInteger constlen=PInt(v,@"constlen");
    if (constlen<=0 || constlen>512 || constlen%4 || PInt(v,@"instrlen")<=0 || !PU(info,@"size") ||
        PInt(info,@"max_half_reg") < -1 || PInt(info,@"max_reg") < -1)
        AdrenoDrawRefuse(@"compute instruction, register or constant footprint is invalid");
    for (NSDictionary *range in PArray(constants,@"ubo_ranges")) {
        uint64_t start=PU(range,@"start"),end=PU(range,@"end"),offset=PU(range,@"offset");
        NSInteger block=PInt(range,@"block");
        if (PInt(range,@"bindless") || block<0 || block>1 || end<start || offset>16u*constlen ||
            end-start>16u*constlen-offset || (block==1 && end>64))
            AdrenoDrawRefuse(@"compute pushed UBO range is outside the supported allocation");
    }
    // shader_enums.h: LOCAL_INVOCATION_ID=42, WORKGROUP_ID=47. The current
    // export's sysval_regids dictionary lists graphics keys only; use inputs.
    NSMutableSet *inputs=[NSMutableSet set];
    for (NSDictionary *input in PArray(v,@"inputs")) {
        NSInteger slot=PInt(input,@"slot");
        if ((slot!=42 && slot!=47) || [inputs containsObject:@(slot)] || !PInt(input,@"sysval") ||
            PInt(input,@"half") || PInt(input,@"compmask")!=7 || PU(input,@"regid")>=INVALID_REG)
            AdrenoDrawRefuse(@"compute input slot %ld is not a supported full-width system value",(long)slot);
        [inputs addObject:@(slot)];
    }
    if (inputs.count!=2) AdrenoDrawRefuse(@"compute requires local and workgroup ID inputs");
}

@interface AdrenoComputeProgram ()
- (instancetype)initWithPipeline:(AdrenoComputePipelineState *)pipeline;
@end
@implementation AdrenoComputeProgram
- (instancetype)initWithPipeline:(AdrenoComputePipelineState *)pipeline {
    if (!(self=[super init])) return nil;
    AdrenoShader *shader=pipeline.kernelCode;
    if (!shader.program || !shader.machineCode.length) AdrenoDrawRefuse(@"compute pipeline has no compiled program");
    AdrenoCheckComputeVariant(shader.program);
    _kernelProgram=shader.program;
    AdrenoComputeSlots(_kernelProgram,&_textureSlot,&_imageSlot);
    uint64_t size=PU(PDict(_kernelProgram,@"info"),@"size"),instructions=PU(_kernelProgram,@"instrlen");
    if (size!=shader.machineCode.length || size>(16u<<20) || instructions>((16u<<20)/128))
        AdrenoDrawRefuse(@"compute program extent differs from compiled bytes or exceeds 16 MiB");
    uint64_t fetch=128*instructions;
    uint64_t bytes=(MAX(size,fetch)+255)&~255ull;
    _codeBuffer=[[pipeline device] newBufferWithLength:(NSUInteger)bytes options:MTLResourceStorageModeShared];
    if (!_codeBuffer.contents || _codeBuffer.length<bytes) AdrenoDrawRefuse(@"compute shader code allocation failed");
    memset(_codeBuffer.contents,0,(size_t)bytes);
    memcpy(_codeBuffer.contents,shader.machineCode.bytes,shader.machineCode.length);
    _codeBuffer.label=@"Adreno compute code";
    return self;
}
@end

@implementation AdrenoComputePipelineState (AdrenoCompute)
- (AdrenoComputeProgram *)adrenoComputeProgram {
    static const void *const key=&key;
    @synchronized(self) {
        AdrenoComputeProgram *program=objc_getAssociatedObject(self,key);
        if (!program) {
            program=[[AdrenoComputeProgram alloc] initWithPipeline:self];
            objc_setAssociatedObject(self,key,program,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        return program;
    }
}
@end

static uint32_t AdrenoComputeSysval(NSDictionary *v, NSInteger slot) {
    for (NSDictionary *input in PArray(v,@"inputs"))
        if (PInt(input,@"slot")==slot) return (uint32_t)PU(input,@"regid");
    AdrenoDrawRefuse(@"compute system value %ld is absent",(long)slot);
}

static void emit_compute_ubo(AdrenoCS *cs, uint32_t slot, AdrenoAddr address, uint64_t bytes) {
    if (slot>=ADRENO_UBO_SLOTS || !bytes || bytes>ADRENO_UBO_MAX_BYTES)
        AdrenoDrawRefuse(@"compute UBO extent or slot");
    uint64_t at=cs_dwords(cs);
    PKT7(cs,E(CP_LOAD_STATE6_FRAG),
        PF(CP_LOAD_STATE6_0,DST_OFF,slot)|PF(CP_LOAD_STATE6_0,STATE_TYPE,E(ST6_UBO))|
        PF(CP_LOAD_STATE6_0,STATE_SRC,E(SS6_DIRECT))|PF(CP_LOAD_STATE6_0,STATE_BLOCK,E(SB6_CS_SHADER))|
        PF(CP_LOAD_STATE6_0,NUM_UNIT,1),0,0,0,DF(A6XX_UBO_1,SIZE,(bytes+15)/16));
    cs_reloc(cs,ADRENO_SPACE_IB,at+4,ADRENO_SPACE_IB,at+5,ADRENO_IB_HI_BITS_DESC,address);
}

static void emit_compute_ubos(AdrenoCS *cs, NSDictionary *v, id<MTLDevice> device,
                              const AdrenoBufferBinding *binding, MTLSize groups, MTLSize threads) {
    if ((binding->buffer && binding->bytes) || (binding->bytes && (!binding->bytes.length || binding->offset)) ||
        (binding->buffer && binding->buffer.device!=device))
        AdrenoDrawRefuse(@"compute UBO0 has conflicting, empty or foreign binding state");
    // Alignment padding cannot turn an undersized API binding into valid data.
    // The bound comes from this program's reflection/pushed ranges.
    uint64_t bytes=0,minimum=AdrenoComputeUBOMinimum(v);
    if (binding->bytes && binding->bytes.length<minimum)
        AdrenoDrawRefuse(@"compute UBO0 provides %lu application bytes, program requires %llu",
                         (unsigned long)binding->bytes.length,minimum);
    AdrenoAddr app=AdrenoUBOBindingAddr(cs,device,binding,minimum,0,&bytes,@"compute UBO0" MIRROR_ARG(NULL));
    emit_compute_ubo(cs,0,app,bytes);
    // ir3_driver_params_cs (Mesa ir3_const.h): num_work_groups, work_dim,
    // base_group, subgroup_size, local_group_size, subgroup_id_shift, reserved.
    uint32_t subgroup=64u<<(unsigned)PU(PDict(v,@"info"),@"double_threadsize");
    uint32_t dimension=(groups.depth>1 || threads.depth>1)?3:(groups.height>1 || threads.height>1)?2:1;
    uint32_t driver[16]={(uint32_t)groups.width,(uint32_t)groups.height,(uint32_t)groups.depth,dimension,
                        0,0,0,subgroup,(uint32_t)threads.width,(uint32_t)threads.height,(uint32_t)threads.depth,
                        (uint32_t)__builtin_ctz(subgroup),0,0,0,0};
    uint64_t offset=cs_data(cs,driver,sizeof driver,sizeof driver);
    emit_compute_ubo(cs,1,AdrenoPackageAddr(offset,sizeof driver,ADRENO_IB_ALIGN_LOG2_UBO),sizeof driver);
}

// Compute texture formats (docs/USERSPACE-GRAPHICS-20261019.md): MPS's RGBA32Float, CoreImage's RGBA16Float
// intermediates and BGRA8 source/destination, and RGBA8.
static BOOL AdrenoComputeFormat(MTLPixelFormat f) {
    return f==MTLPixelFormatRGBA32Float || f==MTLPixelFormatRGBA16Float || f==MTLPixelFormatBGRA8Unorm ||
           f==MTLPixelFormatRGBA8Unorm;
}
static AdrenoAddr AdrenoComputeTextureWords(id<MTLTexture> texture, id<MTLDevice> device,
                                            BOOL writable, uint32_t words[16]) {
    if (![texture isKindOfClass:[IOGPUMetalTexture class]] || texture.device!=device ||
        ![texture respondsToSelector:@selector(adrenoGetLinearLayout:)] || texture.textureType!=MTLTextureType2D ||
        !AdrenoComputeFormat(texture.pixelFormat) || texture.sampleCount!=1 || texture.mipmapLevelCount!=1 ||
        texture.arrayLength!=1 || texture.depth!=1 ||
        (texture.usage!=MTLTextureUsageUnknown && !(texture.usage&(writable?MTLTextureUsageShaderWrite:MTLTextureUsageShaderRead))))
        AdrenoDrawRefuse(@"compute requires native single-level linear 2D RGBA32Float, RGBA16Float, BGRA8 or RGBA8 %@ texture (format %lu)",
                         writable?@"writable":@"sampled",(unsigned long)texture.pixelFormat);
    MTLTextureSwizzleChannels sw=texture.swizzle;
    if (sw.red!=MTLTextureSwizzleRed || sw.green!=MTLTextureSwizzleGreen ||
        sw.blue!=MTLTextureSwizzleBlue || sw.alpha!=MTLTextureSwizzleAlpha)
        AdrenoDrawRefuse(@"compute texture swizzles are not supported yet");
    AdrenoTexFormat format;
    if (!AdrenoTexFormatOf(texture.pixelFormat,&format)) AdrenoDrawBug(@"compute format %lu",(unsigned long)texture.pixelFormat);
    AdrenoLinearTextureLayout l={0};
    if (![(id<AdrenoLinearTexture>)texture adrenoGetLinearLayout:&l] || l.width!=texture.width ||
        l.height!=texture.height || l.format!=texture.pixelFormat || !l.width || !l.height ||
        l.width>16384 || l.height>16384 || l.allocationBytes!=AdrenoGPUBackingSize(texture) ||
        !l.rowBytes || l.rowBytes%64 || l.offset%64 || l.rowBytes<l.width*format.cpp || l.rowBytes>0xffffff/8 ||
        l.offset>l.allocationBytes || l.height>(l.allocationBytes-l.offset)/l.rowBytes)
        AdrenoDrawRefuse(@"compute texture layout is inconsistent, unaligned or outside its allocation "
                         "(%llux%llu row %llu offset %llu alloc %llu resource %llu, texture %lux%lu; %@)",
                         (unsigned long long)l.width,(unsigned long long)l.height,(unsigned long long)l.rowBytes,
                         (unsigned long long)l.offset,(unsigned long long)l.allocationBytes,
                         (unsigned long long)AdrenoGPUBackingSize(texture),
                         (unsigned long)texture.width,(unsigned long)texture.height,
                         [(id)texture respondsToSelector:@selector(adrenoLayoutDescription)] ?
                             [(id)texture performSelector:@selector(adrenoLayoutDescription)] : @"no layout description");
    uint64_t size=AdrenoLinearViewWords(words,&format,format.swiz,l.rowBytes,l.width,l.height,NO);
    // fdl6_view_init's a8xx storage descriptor: the texture descriptor with storage TYPE/DEPTH and the texture's own
    // FMT/SWAP/swizzle (turnip gives every colour-renderable non-depth format storage, BGRA8 included). For these
    // admitted nonarray views TYPE/DEPTH are 2D/1.
    if (writable) {
        words[1]=DF(A8XX_TEX_MEMOBJ_1,TYPE,E(A6XX_TEX_2D))|DF(A8XX_TEX_MEMOBJ_1,DEPTH,1);
        words[3]=DF(A8XX_TEX_MEMOBJ_3,FMT,format.fmt)|DF(A8XX_TEX_MEMOBJ_3,SWAP,format.swap)|
            DF(A8XX_TEX_MEMOBJ_3,SWIZ_X,format.swiz[0])|DF(A8XX_TEX_MEMOBJ_3,SWIZ_Y,format.swiz[1])|
            DF(A8XX_TEX_MEMOBJ_3,SWIZ_Z,format.swiz[2])|DF(A8XX_TEX_MEMOBJ_3,SWIZ_W,format.swiz[3]);
    }
    return AdrenoResourceAddr(texture,l.offset,size,writable?ADRENO_IB_ACCESS_WRITE:ADRENO_IB_ACCESS_READ,
                              ADRENO_IB_ALIGN_LOG2_TEXTURE,writable?@"compute storage texture":@"compute sampled texture");
}

static void emit_compute_state_load(AdrenoCS *cs, uint32_t type, uint32_t block,
                                    uint32_t count, AdrenoAddr address) {
    uint64_t at=cs_dwords(cs);
    PKT7(cs,E(CP_LOAD_STATE6_FRAG),PF(CP_LOAD_STATE6_0,DST_OFF,0)|PF(CP_LOAD_STATE6_0,STATE_TYPE,type)|
         PF(CP_LOAD_STATE6_0,STATE_SRC,E(SS6_INDIRECT))|PF(CP_LOAD_STATE6_0,STATE_BLOCK,block)|
         PF(CP_LOAD_STATE6_0,NUM_UNIT,count),0,0);
    cs_reloc(cs,ADRENO_SPACE_IB,at+2,ADRENO_SPACE_IB,at+3,ADRENO_IB_HI_BITS_REG64,address);
}

// Tables of ntex T# and num_uavs UAV descriptors, null except the bound slots (AdrenoComputeSlots); MPS's T#0/UAV1
// tables are its one T# and two UAVs, unchanged. A generator (no sampled texture) loads one null T# and the default
// sampler, the packet shape every other kernel has; its shader samples neither.
static uint64_t AdrenoTableAlign(NSUInteger bytes) { uint64_t a=64; while (a<bytes) a<<=1; return a; }
static void emit_compute_textures(AdrenoCS *cs, id<MTLDevice> device, const AdrenoComputeBindings *b,
                                  AdrenoComputeProgram *program) {
    const NSInteger t=program.textureSlot,u=program.imageSlot;
    if (t<-1 || u<0 || t>=ADRENO_COMPUTE_SLOTS || u>=ADRENO_COMPUTE_SLOTS || t>=ADRENO_DRAW_TEXTURE_SLOTS || u>=ADRENO_DRAW_TEXTURE_SLOTS)
        AdrenoDrawBug(@"compute slots T#%ld UAV %ld",(long)t,(long)u);
    uint32_t textures[ADRENO_COMPUTE_SLOTS][16]={{0}},sampler[4]={0},images[ADRENO_COMPUTE_SLOTS][16]={{0}};
    const NSUInteger tableTextures=(NSUInteger)(t<0 ? 1 : t+1);
    const NSUInteger textureBytes=tableTextures*sizeof textures[0],imageBytes=(NSUInteger)(u+1)*sizeof images[0];
    AdrenoAddr destination=AdrenoComputeTextureWords(b->textures[u],device,YES,images[u]);
    AdrenoAddr source={0};
    MTLSamplerDescriptor *descriptor;
    if (t>=0) {
        source=AdrenoComputeTextureWords(b->textures[t],device,NO,textures[t]);
        id<MTLTexture> src=b->textures[t],dst=b->textures[u];
        if (source.resourceID==destination.resourceID || (src.iosurface && src.iosurface==dst.iosurface) ||
            (src.buffer && src.buffer==dst.buffer))
            AdrenoDrawRefuse(@"compute sampled and writable textures must not share storage");
        id<MTLSamplerState> state=b->samplers[0];
        if (!state || state.device!=device || ![(id)state respondsToSelector:@selector(adrenoSamplerDescriptor)])
            AdrenoDrawRefuse(@"compute sampler0 is absent or belongs to another device");
        descriptor=[(id)state adrenoSamplerDescriptor];
    } else {
        static MTLSamplerDescriptor *standard;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ standard=[MTLSamplerDescriptor new]; });   // nearest, clamp to edge, no mips
        descriptor=standard;
    }
    // Nearest or linear, clamp-to-edge or clamp-to-zero, either coordinate space (CoreImage: unnormalised linear,
    // clamp-to-edge; MPS: nearest clamp-to-zero). Compute textures are single-level: no mips, LOD averaging,
    // comparison or anisotropy.
    BOOL (^filter)(MTLSamplerMinMagFilter)=^BOOL(MTLSamplerMinMagFilter f){
        return f==MTLSamplerMinMagFilterNearest || f==MTLSamplerMinMagFilterLinear; };
    BOOL (^clamp)(MTLSamplerAddressMode)=^BOOL(MTLSamplerAddressMode m){
        return m==MTLSamplerAddressModeClampToEdge || m==MTLSamplerAddressModeClampToZero; };
    if (!filter(descriptor.minFilter) || !filter(descriptor.magFilter) || descriptor.mipFilter!=MTLSamplerMipFilterNotMipmapped ||
        !clamp(descriptor.sAddressMode) || !clamp(descriptor.tAddressMode) || !clamp(descriptor.rAddressMode) ||
        descriptor.compareFunction!=MTLCompareFunctionNever || descriptor.maxAnisotropy!=1 || descriptor.lodAverage)
        AdrenoDrawRefuse(@"compute sampler requires nearest or linear clamping without mips, comparison or anisotropy");
    AdrenoSamplerWords(descriptor,sampler);
    uint64_t ta=cs_data(cs,textures,textureBytes,AdrenoTableAlign(textureBytes));
    uint64_t sa=cs_data(cs,sampler,sizeof sampler,64);
    uint64_t ua=cs_data(cs,images,imageBytes,AdrenoTableAlign(imageBytes));
    if (t>=0)
        cs_reloc(cs,ADRENO_SPACE_DATA,ta+64*(uint64_t)t,ADRENO_SPACE_DATA,ta+64*(uint64_t)t+4,ADRENO_IB_HI_BITS_DESC,source);
    cs_reloc(cs,ADRENO_SPACE_DATA,ua+64*(uint64_t)u,ADRENO_SPACE_DATA,ua+64*(uint64_t)u+4,ADRENO_IB_HI_BITS_DESC,destination);
    AdrenoAddr tex=AdrenoPackageAddr(ta,textureBytes,ADRENO_IB_ALIGN_LOG2_TEXTURE);
    AdrenoAddr samp=AdrenoPackageAddr(sa,sizeof sampler,ADRENO_IB_ALIGN_LOG2_TEXTURE);
    AdrenoAddr uav=AdrenoPackageAddr(ua,imageBytes,ADRENO_IB_ALIGN_LOG2_TEXTURE);
    AdrenoRegs r;regs_reset(&r);
    REGADDR(&r,SP_CS_SAMPLER_BASE,0,0,samp);
    REGADDR(&r,SP_CS_TEXMEMOBJ_BASE,0,0,tex);
    REG32(&r,SP_CS_TSIZE,0,AF(SP_CS_TSIZE,VALUE,(uint32_t)tableTextures));
    REGADDR(&r,SP_CS_UAV_BASE,0,0,uav);
    REG32(&r,SP_CS_USIZE,0,AF(SP_CS_USIZE,VALUE,(uint32_t)u+1));
    cs_crb(cs,&r);
    // fd6_texture.cc programs table bases/counts before LOAD_STATE packets.
    emit_compute_state_load(cs,E(ST6_SHADER),E(SB6_CS_TEX),1,samp);
    emit_compute_state_load(cs,E(ST6_CONSTANTS),E(SB6_CS_TEX),(uint32_t)tableTextures,tex);
    // Non-bindless images: the complete UAV table, null below the bound slot.
    // This path is source-derived; packet encoding is not hardware proof.
    emit_compute_state_load(cs,E(ST6_UAV),E(SB6_CS_SHADER),(uint32_t)u+1,uav);
}

static void emit_compute_program(AdrenoCS *cs, AdrenoComputeProgram *program, MTLSize groups, MTLSize threads) {
    NSDictionary *v=program.kernelProgram,*info=PDict(v,@"info"),*compute=PDict(v,@"cs");
    AdrenoAddr code=AdrenoResourceAddr(program.codeBuffer,0,program.codeBuffer.length,ADRENO_IB_ACCESS_READ,
                                      ADRENO_IB_ALIGN_LOG2_SHADER,@"compute code");
    uint64_t subgroup=PInt(info,@"double_threadsize")?E(THREAD128):E(THREAD64);
    uint64_t constlen=PU(v,@"constlen");
    uint64_t constantMode=constlen<=128?E(CONSTLEN_128):constlen<=192?E(CONSTLEN_192):
                           constlen<=256?E(CONSTLEN_256):E(CONSTLEN_512);
    AdrenoRegs r;regs_reset(&r);
    REG32(&r,SP_UPDATE_CNTL,0,sp_update_all());
    REG32(&r,SP_CS_CONST_CONFIG,0,AFS(SP_CS_CONST_CONFIG,CONSTLEN,constlen)|AF(SP_CS_CONST_CONFIG,ENABLED,1));
    REG32(&r,SP_CS_CONFIG,0,AF(SP_CS_CONFIG,ENABLED,1)|AF(SP_CS_CONFIG,NTEX,1)|
          AF(SP_CS_CONFIG,NSAMP,1)|AF(SP_CS_CONFIG,NUAV,2));
    REG32(&r,SP_MODE_CNTL,0,AF(SP_MODE_CNTL,CONSTANT_DEMOTION_ENABLE,1)|AF(SP_MODE_CNTL,ISAMMODE,E(ISAMMODE_GL)));
    REG32(&r,TPL1_MODE_CNTL,0,AF(TPL1_MODE_CNTL,ISAMMODE,E(ISAMMODE_GL))|
          AF(TPL1_MODE_CNTL,TEXCOORDROUNDMODE,E(COORD_TRUNCATE))|AF(TPL1_MODE_CNTL,ARRAYCOORDROUNDMODE,E(COORD_TRUNCATE))|
          AF(TPL1_MODE_CNTL,NEARESTMIPSNAP,E(CLAMP_ROUND_TRUNCATE))|AF(TPL1_MODE_CNTL,DESTDATATYPEOVERRIDE,1)|
          AF(TPL1_MODE_CNTL,CLAMP_DISABLE,1));
    REG32(&r,SP_CS_CNTL_0,0,AF(SP_CS_CNTL_0,HALFREGFOOTPRINT,PInt(info,@"max_half_reg")+1)|
          AF(SP_CS_CNTL_0,FULLREGFOOTPRINT,PInt(info,@"max_reg")+1)|AF(SP_CS_CNTL_0,BRANCHSTACK,PU(v,@"branchstack_hw"))|
          AF(SP_CS_CNTL_0,THREADSIZE,subgroup)|AF(SP_CS_CNTL_0,COMPUTERRMODEEN,PU(compute,@"round_robin_mode"))|
          AF(SP_CS_CNTL_0,EARLYPREAMBLE,PU(v,@"early_preamble"))|AF(SP_CS_CNTL_0,MERGEDREGS,PU(v,@"mergedregs")));
    REG32(&r,SP_CS_INSTR_SIZE,0,AF(SP_CS_INSTR_SIZE,VALUE,PU(v,@"instrlen")));
    REG32(&r,SP_CS_PROGRAM_COUNTER_OFFSET,0,0);
    REGADDR(&r,SP_CS_BASE,0,0,code);
    REG32(&r,SP_CS_PVT_MEM_PARAM,0,0);REG64(&r,SP_CS_PVT_MEM_BASE,0,0);
    REG32(&r,SP_CS_PVT_MEM_SIZE,0,0);REG32(&r,SP_CS_PVT_MEM_STACK_OFFSET,0,0);REG32(&r,SP_CS_VGS_CNTL,0,0);
    REG32(&r,SP_CS_CNTL_1,0,AF(SP_CS_CNTL_1,SHARED_SIZE,1)|AF(SP_CS_CNTL_1,CONSTANTRAMMODE,constantMode));
    REG32(&r,SP_CS_HYSTERESIS,0,0);
    // A8xx's PS wave register has only VARYINGS; Mesa's generic THREAD64
    // initializer packs to zero for this XML generation.
    REG32(&r,SP_PS_WAVE_CNTL,0,0);
    REG32(&r,SP_CS_WIE_CNTL_0,0,AF(SP_CS_WIE_CNTL_0,WGIDCONSTID,AdrenoComputeSysval(v,47))|
          AF(SP_CS_WIE_CNTL_0,WGSIZECONSTID,INVALID_REG)|AF(SP_CS_WIE_CNTL_0,WGOFFSETCONSTID,INVALID_REG)|
          AF(SP_CS_WIE_CNTL_0,LOCALIDREGID,AdrenoComputeSysval(v,42)));
    REG32(&r,SP_CS_WIE_CNTL_1,0,AF(SP_CS_WIE_CNTL_1,LINEARLOCALIDREGID,INVALID_REG)|
          AF(SP_CS_WIE_CNTL_1,THREADSIZE,subgroup)|AF(SP_CS_WIE_CNTL_1,WORKITEMRASTORDER,
              PU(compute,@"force_linear_dispatch")?E(WORKITEMRASTORDER_LINEAR):E(WORKITEMRASTORDER_TILED)));
    uint64_t tileHeight=threads.height%8==0?3:threads.height%4==0?5:threads.height%2==0?9:17;
    REG32(&r,SP_CS_WGE_CNTL,0,AF(SP_CS_WGE_CNTL,LINEARLOCALIDREGID,INVALID_REG)|
          AF(SP_CS_WGE_CNTL,THREADSIZE,subgroup)|AF(SP_CS_WGE_CNTL,WORKGROUPRASTORDERZFIRSTEN,1)|
          AF(SP_CS_WGE_CNTL,WGTILEWIDTH,4)|AF(SP_CS_WGE_CNTL,WGTILEHEIGHT,tileHeight));
    uint32_t dimension=(groups.depth>1 || threads.depth>1)?3:(groups.height>1 || threads.height>1)?2:1;
    REG32(&r,SP_CS_NDRANGE_0,0,AF(SP_CS_NDRANGE_0,KERNELDIM,dimension)|
          AF(SP_CS_NDRANGE_0,LOCALSIZEX,threads.width-1)|AF(SP_CS_NDRANGE_0,LOCALSIZEY,threads.height-1)|
          AF(SP_CS_NDRANGE_0,LOCALSIZEZ,threads.depth-1));
    REG32(&r,SP_CS_NDRANGE_1,0,AF(SP_CS_NDRANGE_1,GLOBALSIZE_X,threads.width*groups.width));
    REG32(&r,SP_CS_NDRANGE_2,0,0);
    REG32(&r,SP_CS_NDRANGE_3,0,AF(SP_CS_NDRANGE_3,GLOBALSIZE_Y,threads.height*groups.height));
    REG32(&r,SP_CS_NDRANGE_4,0,0);
    REG32(&r,SP_CS_NDRANGE_5,0,AF(SP_CS_NDRANGE_5,GLOBALSIZE_Z,threads.depth*groups.depth));
    REG32(&r,SP_CS_NDRANGE_6,0,0);
    REG32(&r,SP_CS_KERNEL_GROUP_X,0,groups.width);REG32(&r,SP_CS_KERNEL_GROUP_Y,0,groups.height);
    REG32(&r,SP_CS_KERNEL_GROUP_Z,0,groups.depth);
    REG32(&r,SP_CS_NDRANGE_7,0,AF(SP_CS_NDRANGE_7,LOCALSIZEX,threads.width-1)|
          AF(SP_CS_NDRANGE_7,LOCALSIZEY,threads.height-1)|AF(SP_CS_NDRANGE_7,LOCALSIZEZ,threads.depth-1));
    cs_crb(cs,&r);
    // fd6_compute: activate direct configuration before loading constants.
    PKT7(cs,E(CP_SET_MODE),1);
}

void AdrenoComputeBindingsInit(AdrenoComputeBindings *bindings) { memset(bindings,0,sizeof *bindings); }

@implementation AdrenoComputePass {
    id<MTLDevice> _device;
    AdrenoCS *_cs;
    AdrenoComputeProgram *_program;
    BOOL _dispatched;
}
- (instancetype)initWithDevice:(id<MTLDevice>)device {
    if ((self=[super init])) {
        if (!device) AdrenoDrawRefuse(@"compute pass has no device");
        _device=device;_cs=[AdrenoCS new];
    }
    return self;
}
- (AdrenoComputeProgram *)programForPipeline:(id<MTLComputePipelineState>)pipeline {
    if (![pipeline isKindOfClass:[AdrenoComputePipelineState class]] || pipeline.device!=_device)
        AdrenoDrawRefuse(@"compute pipeline is absent or belongs to another device");
    return [(AdrenoComputePipelineState *)pipeline adrenoComputeProgram];
}
- (void)dispatchThreadgroups:(MTLSize)groups threadsPerThreadgroup:(MTLSize)threads
                    bindings:(const AdrenoComputeBindings *)bindings {
    if (_finished || _dispatched || !bindings) AdrenoDrawRefuse(@"compute pass accepts exactly one dispatch snapshot");
    if (!threads.width || !threads.height || !threads.depth || threads.width>1024 || threads.height>1024 ||
        threads.depth>1024 || threads.width*threads.height*threads.depth>1024 ||
        !groups.width || !groups.height || !groups.depth || groups.width>UINT32_MAX/threads.width ||
        groups.height>UINT32_MAX/threads.height || groups.depth>UINT32_MAX/threads.depth)
        AdrenoDrawRefuse(@"compute grid is empty or exceeds local/global hardware dimensions");
    AdrenoComputeProgram *program=[self programForPipeline:bindings->pipeline];
    NSDictionary *compute=PDict(program.kernelProgram,@"cs");
    NSArray *local=PArray(compute,@"local_size");
    if (!PU(compute,@"local_size_variable") &&
        ([local[0] unsignedLongLongValue]!=threads.width || [local[1] unsignedLongLongValue]!=threads.height ||
         [local[2] unsignedLongLongValue]!=threads.depth))
        AdrenoDrawRefuse(@"compute dispatch local size differs from the compiled fixed workgroup");
    AdrenoCS *cs=[AdrenoCS new];
    // BR first (cs_thread_br): these flushes precede emit_restore, which selects BR only after them.
    cs_thread_br(cs);
    // Clean previous render writes before restore invalidates CCU state. The
    // conservative full boundary also covers earlier compute/image stores.
    emit_flushes(cs,(AdrenoFlushes){.ccuColor=YES,.ccuDepth=YES,.cache=YES,.wfi=YES});
    emit_restore(cs,AdrenoZeroAddr());
    cs_marker(cs,E(RM6_COMPUTE));
    emit_compute_program(cs,program,groups,threads);
    emit_compute_ubos(cs,program.kernelProgram,_device,&bindings->buffers[0],groups,threads);
    emit_compute_textures(cs,_device,bindings,program);
    PKT7(cs,E(CP_EXEC_CS),0,(uint32_t)groups.width,(uint32_t)groups.height,(uint32_t)groups.depth);
    emit_flushes(cs,(AdrenoFlushes){.cache=YES,.invCache=YES,.invCche=YES,.wfi=YES});
    cs_pkt7(cs,E(CP_WAIT_MEM_WRITES),NULL,0);
    if (cs_dwords(cs)>ADRENO_IB_MAX_DWORDS || cs->_data.length>ADRENO_IB_MAX_DATA ||
        cs->_relocs.length/sizeof(AdrenoRelocDraft)>ADRENO_IB_MAX_RELOCS)
        AdrenoDrawRefuse(@"compute dispatch exceeds one IB package");
    _cs=cs;_program=program;_dispatched=YES;
}
- (void)finish { _finished=YES; }
- (BOOL)empty { return !_dispatched; }
- (void)enumerateResources:(void (^)(id resource,MTLResourceUsage usage))block {
    for (id resource in _cs->_usage) block(resource,[[_cs->_usage objectForKey:resource] unsignedIntegerValue]);
}
- (AdrenoCS *)adrenoCS { return _cs; }
@end

// ================================================================================================================
// Queued copies. Failure inventory: docs/ADRENO-BLIT-ENCODING-E2E-20261019.md.
// ================================================================================================================
enum { ADRENO_BLIT_BOUNDARY_DWORDS = 64 };
_Static_assert(ADRENO_BLIT_MAX_SPANS * 2u <= ADRENO_IB_MAX_RELOCS, "blit relocation capacity");
_Static_assert(ADRENO_BLIT_BOUNDARY_DWORDS + ADRENO_BLIT_MAX_SPANS * 6u <= ADRENO_IB_MAX_DWORDS,
               "blit packet capacity");

// Record mapped-address metadata only; never inspect the bytes. This detects
// overlapping no-copy buffers whose native resource IDs differ.
static void AdrenoBlitMappedRange(NSMutableArray *ranges, const void *pointer, uint64_t bytes, BOOL destination) {
    if (!pointer || !bytes) return;
    uint64_t start=(uintptr_t)pointer;
    if (bytes>UINTPTR_MAX-start) AdrenoDrawRefuse(@"blit mapped backing range overflows");
    [ranges addObject:@[@(start),@(start+bytes),@(destination)]];
}

static void AdrenoBlitBacking(id resource, id<MTLDevice> device, NSMutableSet *tokens,
                              NSHashTable *seen, NSMutableArray *ranges, BOOL destination, unsigned depth) {
    if (!resource || [seen containsObject:resource]) return;
    if (depth>=16 || ![resource isKindOfClass:[IOGPUMetalResource class]] ||
        [(IOGPUMetalResource *)resource device]!=device)
        AdrenoDrawRefuse(@"blit backing chain is too deep, foreign or not native");
    [seen addObject:resource];
    [tokens addObject:[NSString stringWithFormat:@"object:%p",(__bridge void *)resource]];
    uint32_t rid=[(IOGPUMetalResource *)resource resourceID];
    if (!rid) AdrenoDrawRefuse(@"blit backing has no resource identifier");
    [tokens addObject:[NSString stringWithFormat:@"resource:%u",rid]];
    if ([resource isKindOfClass:[IOGPUMetalBuffer class]]) {
        id<MTLBuffer> buffer=resource;
        AdrenoBlitMappedRange(ranges,buffer.contents,buffer.length,destination);
    } else if ([resource isKindOfClass:[IOGPUMetalTexture class]]) {
        id<MTLTexture> texture=resource;
        IOSurfaceRef surface=texture.iosurface;
        if (surface) {
            [tokens addObject:[NSString stringWithFormat:@"surface:%u",IOSurfaceGetID(surface)]];
            AdrenoBlitMappedRange(ranges,IOSurfaceGetBaseAddress(surface),IOSurfaceGetAllocSize(surface),destination);
        }
        AdrenoBlitBacking(texture.buffer,device,tokens,seen,ranges,destination,depth+1);
        AdrenoBlitBacking(texture.parentTexture,device,tokens,seen,ranges,destination,depth+1);
    } else {
        AdrenoDrawRefuse(@"blit supports native buffer and texture backing only");
    }
}

// generateMipmapsForTexture: (agents/gfx-correctness FAILURE-MODES.md F1). The 2D engine's formats for a filtered copy
// between two levels of one texture: Turnip blit_format_color / format_to_ifmt (tu_clear_blit.cc), fd6_format_table.c.
// src: TPL1_A2D_SRC_TEXTURE_INFO format; dst: RB_A2D_BLT_CNTL / RB_A2D_DEST_BUFFER_INFO format; out:
// SP_A2D_OUTPUT_INFO format (16_16_16_16_FLOAT for a 10_10_10_2 destination, emit_blit_setup).
typedef struct { uint64_t src, dst, out, swap, ifmt; BOOL srgb, half; } AdrenoBlit2DFormat;
static BOOL AdrenoBlit2DFormatOf(MTLPixelFormat f, AdrenoBlit2DFormat *o) {
    const uint64_t WZYX = E(WZYX), WXYZ = E(WXYZ);
#define B2D(FMT, SWAP, IFMT, SRGB, HALF) do { *o = (AdrenoBlit2DFormat){E(FMT), E(FMT), E(FMT), (SWAP), E(IFMT), (SRGB), (HALF)}; return YES; } while (0)
    switch (f) {
        case MTLPixelFormatBGRA8Unorm: B2D(FMT6_8_8_8_8_UNORM, WXYZ, R2D_UNORM8, NO, NO);
        case MTLPixelFormatBGRA8Unorm_sRGB: B2D(FMT6_8_8_8_8_UNORM, WXYZ, R2D_UNORM8_SRGB, YES, NO);
        case MTLPixelFormatRGBA8Unorm: B2D(FMT6_8_8_8_8_UNORM, WZYX, R2D_UNORM8, NO, NO);
        case MTLPixelFormatRGBA8Unorm_sRGB: B2D(FMT6_8_8_8_8_UNORM, WZYX, R2D_UNORM8_SRGB, YES, NO);
        case MTLPixelFormatR8Unorm: case MTLPixelFormatA8Unorm: B2D(FMT6_8_UNORM, WZYX, R2D_UNORM8, NO, NO);
        case MTLPixelFormatRG8Unorm: B2D(FMT6_8_8_UNORM, WZYX, R2D_UNORM8, NO, NO);
        case MTLPixelFormatR16Float: B2D(FMT6_16_FLOAT, WZYX, R2D_FLOAT16, NO, YES);
        case MTLPixelFormatRG16Float: B2D(FMT6_16_16_FLOAT, WZYX, R2D_FLOAT16, NO, YES);
        case MTLPixelFormatRGBA16Float: B2D(FMT6_16_16_16_16_FLOAT, WZYX, R2D_FLOAT16, NO, YES);
        case MTLPixelFormatR16Unorm: B2D(FMT6_16_UNORM, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatRG16Unorm: B2D(FMT6_16_16_UNORM, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatRGBA16Unorm: B2D(FMT6_16_16_16_16_UNORM, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatR32Float: B2D(FMT6_32_FLOAT, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatRG32Float: B2D(FMT6_32_32_FLOAT, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatRGBA32Float: B2D(FMT6_32_32_32_32_FLOAT, WZYX, R2D_FLOAT32, NO, NO);
        case MTLPixelFormatBGR10A2Unorm: case MTLPixelFormatRGB10A2Unorm:
            *o = (AdrenoBlit2DFormat){E(FMT6_10_10_10_2_UNORM), E(FMT6_10_10_10_2_UNORM_DEST), E(FMT6_16_16_16_16_FLOAT),
                                      f == MTLPixelFormatBGR10A2Unorm ? WXYZ : WZYX, E(R2D_FLOAT16), NO, NO};
            return YES;
        default: return NO;
    }
#undef B2D
}

@implementation AdrenoBlitPass {
    AdrenoCS *_cs;
}
// F1: level k from level k-1, k = 1..levels-1, each a scaled 2D-engine copy with the bilinear filter (q1n1's
// hardware-proven emit_2d_copy inside emit_nondraw_batch; Turnip tu6_blit_image's r2d path for a scaled linear blit).
// Every level's layout is the one AdrenoTextureWords derives the T#'s level chain from (AdrenoLinearLayoutAtLevel).
+ (instancetype)adrenoMipmapPassWithDevice:(id<MTLDevice>)device texture:(id<MTLTexture>)texture {
    const NSUInteger levels = texture.mipmapLevelCount;
    if (!device || ![texture isKindOfClass:[IOGPUMetalTexture class]] || texture.device != device ||
        texture.textureType != MTLTextureType2D || texture.sampleCount != 1 || texture.arrayLength != 1 ||
        texture.depth != 1 || texture.parentTexture || texture.buffer || levels < 2 || levels > 16 ||
        ![texture respondsToSelector:@selector(adrenoGetLinearLayout:)])
        AdrenoDrawRefuse(@"GPU mipmap generation needs a native single-slice 2D texture of 2..16 levels; texture %@",
                         AdrenoDescribeTarget(texture));
    AdrenoBlit2DFormat bf;
    if (!AdrenoBlit2DFormatOf(texture.pixelFormat, &bf))
        AdrenoDrawRefuse(@"GPU mipmap generation of format %lu is not supported yet", (unsigned long)texture.pixelFormat);
    AdrenoLinearTextureLayout L[16];
    const uint64_t backing = AdrenoGPUBackingSize(texture);
    for (NSUInteger k = 0; k < levels; k++) {
        AdrenoLinearTextureLayout *l = &L[k];
        if (!AdrenoLinearLayoutAtLevel(texture, k, l) || l->format != texture.pixelFormat ||
            l->width != MAX((NSUInteger)1, texture.width >> k) || l->height != MAX((NSUInteger)1, texture.height >> k) ||
            !l->width || !l->height || l->width > 16384 || l->height > 16384 || !l->rowBytes || l->rowBytes % 64 ||
            l->offset % 64 || l->rowBytes > (1u << 21) - 1 || l->allocationBytes != backing || l->offset > backing ||
            l->height > (backing - l->offset) / l->rowBytes)
            AdrenoDrawRefuse(@"GPU mipmap generation: level %lu has no aligned linear layout inside the allocation; texture %@",
                             (unsigned long)k, AdrenoDescribeTarget(texture));
    }
    AdrenoBlitPass *pass = [[self alloc] init];
    AdrenoCS *cs = [AdrenoCS new];
    AdrenoRegs r;
    // emit_nondraw_batch's prologue (restore, LRZ flush, CCU config, static binning regs, render control, LRZ off)
    emit_restore(cs, AdrenoZeroAddr());
    cs_event(cs, E(LRZ_CACHE_FLUSH));
    emit_gmem_cache_cntl_sysmem(cs);
    emit_static_binning_regs(cs);
    regs_reset(&r);
    REG32(&r, RB_RENDER_CNTL, 0, AF(RB_RENDER_CNTL, RASTER_MODE, E(TYPE_TILED)) | AF(RB_RENDER_CNTL, RASTER_DIRECTION, E(LR_TB)));
    REG32(&r, GRAS_SU_RENDER_CNTL, 0, 0);
    cs_crb(cs, &r);
    emit_lrz_off(cs);
    for (NSUInteger k = 1; k < levels; k++) {
        const AdrenoLinearTextureLayout *s = &L[k - 1], *d = &L[k];
        AdrenoAddr src = AdrenoResourceAddr(texture, s->offset, s->rowBytes * s->height, ADRENO_IB_ACCESS_READ,
                                            ADRENO_IB_ALIGN_LOG2_TEXTURE, @"mipmap source level");
        AdrenoAddr dst = AdrenoResourceAddr(texture, d->offset, d->rowBytes * d->height, ADRENO_IB_ACCESS_WRITE,
                                            ADRENO_IB_ALIGN_LOG2_TEXTURE, @"mipmap destination level");
        // emit_2d_copy: emit_setup's flushes, BLIT2DSCALE, sysmem CCU; coordinates (the source rectangle is level k-1,
        // the destination level k: the 2D engine scales) and setup; source (FILTER: bilinear) and destination.
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .ccuDepth = YES, .invCcuDepth = YES});
        cs_marker(cs, E(RM6_BLIT2DSCALE));
        emit_gmem_cache_cntl_sysmem(cs);
        regs_reset(&r);
        REG32(&r, GRAS_A2D_SRC_XMIN, 0, AF(GRAS_A2D_SRC_XMIN, VALUE, 0));
        REG32(&r, GRAS_A2D_SRC_XMAX, 0, AF(GRAS_A2D_SRC_XMAX, VALUE, s->width - 1));
        REG32(&r, GRAS_A2D_SRC_YMIN, 0, AF(GRAS_A2D_SRC_YMIN, VALUE, 0));
        REG32(&r, GRAS_A2D_SRC_YMAX, 0, AF(GRAS_A2D_SRC_YMAX, VALUE, s->height - 1));
        REG32(&r, GRAS_A2D_DEST_TL, 0, AF(GRAS_A2D_DEST_TL, X, 0) | AF(GRAS_A2D_DEST_TL, Y, 0));
        REG32(&r, GRAS_A2D_DEST_BR, 0, AF(GRAS_A2D_DEST_BR, X, d->width - 1) | AF(GRAS_A2D_DEST_BR, Y, d->height - 1));
        REG32(&r, RB_A2D_BLT_CNTL, 0, AF(RB_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(RB_A2D_BLT_CNTL, COLOR_FORMAT, bf.dst) |
              AF(RB_A2D_BLT_CNTL, MASK, 0xF) | AF(RB_A2D_BLT_CNTL, IFMT, bf.ifmt));
        REG32(&r, GRAS_A2D_BLT_CNTL, 0, AF(GRAS_A2D_BLT_CNTL, ROTATE, E(ROTATE_0)) | AF(GRAS_A2D_BLT_CNTL, COLOR_FORMAT, bf.dst) |
              AF(GRAS_A2D_BLT_CNTL, MASK, 0xF) | AF(GRAS_A2D_BLT_CNTL, IFMT, bf.ifmt));
        REG32(&r, TPL1_A2D_BLT_CNTL, 0, AF(TPL1_A2D_BLT_CNTL, TYPE, E(A6XX_TEX_2D)));
        REG32(&r, SP_A2D_OUTPUT_INFO, 0, AF(SP_A2D_OUTPUT_INFO, HALF_PRECISION, bf.half) |
              AF(SP_A2D_OUTPUT_INFO, IFMT_TYPE, E(OUTPUT_IFMT_2D_FLOAT)) | AF(SP_A2D_OUTPUT_INFO, COLOR_FORMAT, bf.out) |
              AF(SP_A2D_OUTPUT_INFO, SRGB, bf.srgb) | AF(SP_A2D_OUTPUT_INFO, MASK, 0xF));
        REG32(&r, RB_A2D_PIXEL_CNTL, 0, AF(RB_A2D_PIXEL_CNTL, PIXEL_OP, E(PIXEL_OP_DISABLED)));
        cs_ncrb(cs, &r);
        regs_reset(&r);
        REG32(&r, TPL1_A2D_SRC_TEXTURE_INFO, 0, AF(TPL1_A2D_SRC_TEXTURE_INFO, COLOR_FORMAT, bf.src) |
              AF(TPL1_A2D_SRC_TEXTURE_INFO, TILE_MODE, E(TILE6_LINEAR)) | AF(TPL1_A2D_SRC_TEXTURE_INFO, COLOR_SWAP, bf.swap) |
              AF(TPL1_A2D_SRC_TEXTURE_INFO, SRGB, bf.srgb) | AF(TPL1_A2D_SRC_TEXTURE_INFO, SAMPLES, E(MSAA_ONE)) |
              AF(TPL1_A2D_SRC_TEXTURE_INFO, FILTER, 1) | AF(TPL1_A2D_SRC_TEXTURE_INFO, UNK20, 1) |
              AF(TPL1_A2D_SRC_TEXTURE_INFO, UNK22, 1));
        REG32(&r, TPL1_A2D_SRC_TEXTURE_SIZE, 0, AF(TPL1_A2D_SRC_TEXTURE_SIZE, WIDTH, s->width) |
              AF(TPL1_A2D_SRC_TEXTURE_SIZE, HEIGHT, s->height));
        REGADDR(&r, TPL1_A2D_SRC_TEXTURE_BASE, 0, 0, src);
        REG32(&r, TPL1_A2D_SRC_TEXTURE_PITCH, 0, AF(TPL1_A2D_SRC_TEXTURE_PITCH, PITCH, s->rowBytes));
        REG64(&r, TPL1_A2D_SRC_TEXTURE_FLAG_BASE, 0, 0);
        REG32(&r, TPL1_A2D_SRC_TEXTURE_FLAG_PITCH, 0, 0);
        REG32(&r, RB_A2D_DEST_BUFFER_INFO, 0, AF(RB_A2D_DEST_BUFFER_INFO, COLOR_FORMAT, bf.dst) |
              AF(RB_A2D_DEST_BUFFER_INFO, TILE_MODE, E(TILE6_LINEAR)) | AF(RB_A2D_DEST_BUFFER_INFO, COLOR_SWAP, bf.swap) |
              AF(RB_A2D_DEST_BUFFER_INFO, SRGB, bf.srgb) | AF(RB_A2D_DEST_BUFFER_INFO, SAMPLES, E(MSAA_ONE)));
        REGADDR(&r, RB_A2D_DEST_BUFFER_BASE, 0, 0, dst);
        REG32(&r, RB_A2D_DEST_BUFFER_PITCH, 0, AFS(RB_A2D_DEST_BUFFER_PITCH, VALUE, d->rowBytes));
        cs_ncrb(cs, &r);
        cs_event(cs, E(DEBUG_LABEL));
        PKT7(cs, E(CP_BLIT), PF(CP_BLIT_0, OP, E(BLIT_OP_SCALE)));
        // Level k is the next copy's source: clean CCU into memory, invalidate the texture caches, wait.
        emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .cache = YES, .invCache = YES, .invCche = YES,
                                         .wfi = YES});
    }
    // The render pass epilogue (fd6_emit_sysmem_fini): later passes and the CPU see every level.
    emit_flushes(cs, (AdrenoFlushes){.ccuColor = YES, .invCcuColor = YES, .ccuDepth = YES, .invCcuDepth = YES,
                                     .cache = YES, .invCche = YES, .wfi = YES});
    cs_event(cs, E(CACHE_CLEAN));
    PKT7(cs, E(CP_SKIP_IB2_ENABLE_GLOBAL), 0);
    if (cs_dwords(cs) > ADRENO_IB_MAX_DWORDS || cs->_data.length || cs->_relocs.length / sizeof(AdrenoRelocDraft) > ADRENO_IB_MAX_RELOCS)
        AdrenoDrawBug(@"mipmap pass exceeds one package");
    pass->_cs = cs;
    return pass;
}
- (instancetype)initWithDevice:(id<MTLDevice>)device copies:(const AdrenoBlitCopySpan *)copies count:(NSUInteger)count {
    if (!(self=[super init])) return nil;
    if (!device || !copies || !count || count>ADRENO_BLIT_MAX_SPANS)
        AdrenoDrawRefuse(@"blit copy requires 1..%u spans",ADRENO_BLIT_MAX_SPANS);
    typedef struct { AdrenoAddr source,destination; } CopyAddresses;
    NSMutableData *storage=[NSMutableData dataWithLength:count*sizeof(CopyAddresses)];
    CopyAddresses *addresses=storage.mutableBytes;
    NSMutableSet *sources=[NSMutableSet set],*destinations=[NSMutableSet set];
    NSPointerFunctionsOptions identity=NSPointerFunctionsStrongMemory|NSPointerFunctionsObjectPointerPersonality;
    NSHashTable *sourceOwners=[NSHashTable hashTableWithOptions:identity];
    NSHashTable *destinationOwners=[NSHashTable hashTableWithOptions:identity];
    NSMutableArray *mappedRanges=[NSMutableArray array];
    // Complete validation precedes any packet emission. Strong owner tables
    // also hold the borrowed argument resources until CS relocations retain them.
    for (NSUInteger i=0;i<count;i++) {
        AdrenoBlitCopySpan span=copies[i];
        if (!span.bytes || (span.bytes&3) || span.bytes/4>UINT32_MAX ||
            (span.sourceOffset&3) || (span.destinationOffset&3) ||
            span.source.device!=device || span.destination.device!=device)
            AdrenoDrawRefuse(@"blit span %lu is empty, unaligned, foreign or exceeds CP_MEMCPY",(unsigned long)i);
        id<MTLResource> owners[2]={span.source,span.destination};
        uint64_t offsets[2]={span.sourceOffset,span.destinationOffset};
        for (unsigned n=0;n<2;n++) {
            if ([owners[n] isKindOfClass:[IOGPUMetalBuffer class]]) {
                uint64_t length=[(id<MTLBuffer>)owners[n] length];
                if (offsets[n]>length || span.bytes>length-offsets[n])
                    AdrenoDrawRefuse(@"blit span %lu exceeds the logical buffer length",(unsigned long)i);
            }
        }
        addresses[i].source=AdrenoResourceAddr(span.source,span.sourceOffset,span.bytes,ADRENO_IB_ACCESS_READ,2,@"blit source");
        addresses[i].destination=AdrenoResourceAddr(span.destination,span.destinationOffset,span.bytes,ADRENO_IB_ACCESS_WRITE,2,@"blit destination");
        AdrenoBlitBacking(span.source,device,sources,sourceOwners,mappedRanges,NO,0);
        AdrenoBlitBacking(span.destination,device,destinations,destinationOwners,mappedRanges,YES,0);
    }
    if ([sources intersectsSet:destinations])
        AdrenoDrawRefuse(@"blit source and destination share a backing allocation; aliased copies are not supported");
    [mappedRanges sortUsingComparator:^NSComparisonResult(NSArray *a,NSArray *b) { return [a[0] compare:b[0]]; }];
    uint64_t ends[2]={0,0};
    for (NSArray *range in mappedRanges) {
        unsigned side=[range[2] boolValue];
        uint64_t start=[range[0] unsignedLongLongValue],end=[range[1] unsignedLongLongValue];
        if (start<ends[!side]) AdrenoDrawRefuse(@"blit source and destination have overlapping mapped backing");
        ends[side]=MAX(ends[side],end);
    }
    AdrenoCS *cs=[AdrenoCS new];
    // BR first (cs_thread_br): a copy pass has no emit_restore, and opening a package it would otherwise copy on BV
    // and BR at once, BV unsynchronised with BR's later passes until the post-IB fence.
    cs_thread_br(cs);
    emit_flushes(cs,(AdrenoFlushes){.ccuColor=YES,.ccuDepth=YES,.cache=YES,.wfi=YES});
    cs_pkt7(cs,E(CP_WAIT_MEM_WRITES),NULL,0);
    for (NSUInteger i=0;i<count;i++) {
        uint64_t at=cs_dwords(cs);
        PKT7(cs,E(CP_MEMCPY),(uint32_t)(addresses[i].source.length/4),0,0,0,0);
        cs_reloc(cs,ADRENO_SPACE_IB,at+2,ADRENO_SPACE_IB,at+3,ADRENO_IB_HI_BITS_REG64,addresses[i].source);
        cs_reloc(cs,ADRENO_SPACE_IB,at+4,ADRENO_SPACE_IB,at+5,ADRENO_IB_HI_BITS_REG64,addresses[i].destination);
    }
    cs_pkt7(cs,E(CP_WAIT_MEM_WRITES),NULL,0);
    // Include the A8xx DUMMY/SUBPASS_FENCE/DUMMY sequence when invalidating
    // previous render/image consumers, exactly as the shared barrier helper does.
    emit_flushes(cs,(AdrenoFlushes){.invCcuColor=YES,.invCcuDepth=YES,.invCache=YES,.invCche=YES,.wfi=YES});
    if (cs_dwords(cs)>ADRENO_BLIT_BOUNDARY_DWORDS+6*count ||
        cs->_relocs.length!=2*count*sizeof(AdrenoRelocDraft) || cs->_data.length)
        AdrenoDrawBug(@"blit boundary changed beyond its preflight capacity contract");
    _cs=cs;
    return self;
}
- (void)finish { _finished=YES; }
- (BOOL)empty { return NO; }
- (void)enumerateResources:(void (^)(id resource,MTLResourceUsage usage))block {
    for (id resource in _cs->_usage) block(resource,[[_cs->_usage objectForKey:resource] unsignedIntegerValue]);
}
- (AdrenoCS *)adrenoCS { return _cs; }
@end

// ================================================================================================================
// The ADRENO_KCMD_IB package (compat/adreno-submit.h)
// ================================================================================================================
@interface AdrenoRenderPass (Package)
- (AdrenoCS *)adrenoCS;
@end

static uint64_t AdrenoAlign64(uint64_t v) { return ADRENO_IB_ALIGN_UP(v); }

// The package keeps its passes' finished streams and copies each once, into the kernel reservation (C7): pass k's
// dwords follow the earlier passes' dwords, its data starts at the earlier data length rounded up to 64.
@implementation AdrenoIBPackage {
    NSMutableArray<AdrenoCS *> *_streams;
    NSMutableData *_bases;          // per stream: uint64_t word base, data base
    uint64_t _dwords, _dataLength;  // the dwords and data bytes the streams fill (the data of the last ends at _dataLength)
    NSMutableData *_relocs;
}
- (instancetype)initWithFillsBefore:(NSUInteger)fills {
    if ((self = [super init])) {
        _fillsBefore = fills;
        _streams = [NSMutableArray array]; _bases = [NSMutableData data]; _relocs = [NSMutableData data];
    }
    return self;
}
- (BOOL)canAppendPass:(id<AdrenoFinishedPass>)pass {
    AdrenoCS *cs = [pass adrenoCS];
    uint64_t dwords = _dwords + cs->_w.length / 4;
    uint64_t data = AdrenoAlign64(_dataLength) + AdrenoAlign64(cs->_data.length);
    uint64_t relocs = _relocs.length / sizeof(AdrenoRelocDraft) + cs->_relocs.length / sizeof(AdrenoRelocDraft);
    return pass.finished && dwords && dwords <= ADRENO_IB_MAX_DWORDS && data <= ADRENO_IB_MAX_DATA &&
           relocs <= ADRENO_IB_MAX_RELOCS;
}
- (void)appendPass:(id<AdrenoFinishedPass>)pass {
    if (![self canAppendPass:pass]) AdrenoDrawBug(@"pass does not fit its package");
    AdrenoCS *cs = [pass adrenoCS];
    uint64_t wordBase = _dwords;
    uint64_t dataBase = AdrenoAlign64(_dataLength);
    [_streams addObject:cs];
    const uint64_t bases[2] = {wordBase, dataBase};
    [_bases appendBytes:bases length:sizeof bases];
    _dwords = wordBase + cs->_w.length / 4;
    _dataLength = dataBase + cs->_data.length;
#if ADRENO_PERF_COUNTERS
    atomic_fetch_add(&gAdrenoPerfDwords, cs->_w.length / 4);
    if (![(id)pass isKindOfClass:[AdrenoRenderPass class]] && ![(id)pass isKindOfClass:[AdrenoPassSegment class]])
        atomic_fetch_add(&gAdrenoPerfOtherPasses, 1);
#endif
    const AdrenoRelocDraft *drafts = cs->_relocs.bytes;
    const NSUInteger count = cs->_relocs.length / sizeof *drafts, at = _relocs.length;
    [_relocs setLength:at + count * sizeof *drafts];          // one resize, then the shifted drafts in place
    AdrenoRelocDraft *out = (AdrenoRelocDraft *)((uint8_t *)_relocs.mutableBytes + at);
    for (NSUInteger i = 0; i < count; i++) {
        AdrenoRelocDraft d = drafts[i];
        d.lo += d.loSpace == ADRENO_SPACE_IB ? wordBase : dataBase;
        if (d.hiSpace != ADRENO_SPACE_NONE) d.hi += d.hiSpace == ADRENO_SPACE_IB ? wordBase : dataBase;
        if (d.kind == ADRENO_IB_RELOC_PACKAGE) d.offset += dataBase;
        out[i] = d;
    }
    _passCount++;
}
- (NSUInteger)commandBytes {
    return (NSUInteger)adreno_ib_command_bytes((uint32_t)_dwords, (uint32_t)AdrenoAlign64(_dataLength),
                                               (uint32_t)(_relocs.length / sizeof(AdrenoRelocDraft)));
}
- (void)encodeInto:(void *)destination capacity:(NSUInteger)capacity {
    const uint32_t ibDwords = (uint32_t)_dwords, dataBytes = (uint32_t)AdrenoAlign64(_dataLength);
    const uint32_t relocCount = (uint32_t)(_relocs.length / sizeof(AdrenoRelocDraft));
    const uint64_t dataOffset = adreno_ib_data_offset(ibDwords), packageBytes = adreno_ib_package_bytes(ibDwords, dataBytes);
    if (!destination || capacity != self.commandBytes || !ibDwords || ibDwords > ADRENO_IB_MAX_DWORDS ||
        dataBytes > ADRENO_IB_MAX_DATA || relocCount > ADRENO_IB_MAX_RELOCS)
        AdrenoDrawBug(@"package reservation or limits");
    // Written straight into the reservation (which IOGPU does not zero): header, IB dwords, zeros up to the data area,
    // data, zeros up to its 64-byte-aligned size, relocations. A builder bug below throws before the command buffer
    // commits, so a partly written reservation is never submitted.
    uint8_t *dst = destination;
    struct adreno_ib_command header = {{ADRENO_KCMD_IB, (uint32_t)capacity}, ADRENO_IB_COMMAND_VERSION, 0, ibDwords,
                                       dataBytes, relocCount, 0, {0, 0}};
    memcpy(dst, &header, sizeof header);
    uint8_t *p = dst + sizeof header;
    const uint64_t *bases = _bases.bytes;
    uint64_t dataEnd = 0;
    for (NSUInteger k = 0; k < _streams.count; k++) {
        AdrenoCS *cs = _streams[k];
        const uint64_t wordBase = bases[2 * k], dataBase = bases[2 * k + 1];
        memcpy(p + 4 * wordBase, cs->_w.bytes, cs->_w.length);
        memset(p + dataOffset + dataEnd, 0, (size_t)(dataBase - dataEnd));        // the rounding gap before this pass's data
        memcpy(p + dataOffset + dataBase, cs->_data.bytes, cs->_data.length);
        dataEnd = dataBase + cs->_data.length;
    }
    memset(p + 4 * (uint64_t)ibDwords, 0, (size_t)(dataOffset - 4 * (uint64_t)ibDwords));
    memset(p + dataOffset + dataEnd, 0, (size_t)(dataBytes - dataEnd));
    struct adreno_ib_reloc *out = (struct adreno_ib_reloc *)(p + packageBytes);
    // Every patched dword at most once: one bit per package dword (the bounds check comes first).
    uint64_t *targets = calloc((size_t)(packageBytes / 4 + 63) / 64, sizeof *targets);
    if (!targets) AdrenoDrawBug(@"reloc target map allocation");
#define ADRENO_TARGET_TAKEN(byte) ((targets[(byte) / 256] >> (((byte) / 4) % 64)) & 1)
#define ADRENO_TARGET_TAKE(byte) (targets[(byte) / 256] |= 1ull << (((byte) / 4) % 64))
    const AdrenoRelocDraft *drafts = _relocs.bytes;
    @try {
        for (uint32_t i = 0; i < relocCount; i++) {
            const AdrenoRelocDraft *d = &drafts[i];
            uint64_t lo = d->loSpace == ADRENO_SPACE_IB ? 4 * d->lo : dataOffset + d->lo;
            uint64_t hi = d->hiSpace == ADRENO_SPACE_NONE ? ADRENO_IB_RELOC_NO_HI
                        : d->hiSpace == ADRENO_SPACE_IB ? 4 * d->hi : dataOffset + d->hi;
            uint64_t offset = d->kind == ADRENO_IB_RELOC_PACKAGE ? dataOffset + d->offset : d->offset;
            // The kext's rules (adreno-submit.h), checked here so a builder bug never leaves the plug-in.
            uint32_t loWord, hiWord = 0;
            if (lo % 4 || lo + 4 > packageBytes || ADRENO_TARGET_TAKEN(lo)) AdrenoDrawBug(@"reloc %u lo target", i);
            ADRENO_TARGET_TAKE(lo);
            memcpy(&loWord, p + lo, 4);
            if (loWord & ~((1u << d->alignLog2) - 1)) AdrenoDrawBug(@"reloc %u lo placeholder %#x", i, loWord);
            if (hi != ADRENO_IB_RELOC_NO_HI) {
                if (hi % 4 || hi + 4 > packageBytes || ADRENO_TARGET_TAKEN(hi) || !d->hiBits || d->hiBits > 32)
                    AdrenoDrawBug(@"reloc %u hi target", i);
                ADRENO_TARGET_TAKE(hi);
                memcpy(&hiWord, p + hi, 4);
                if (hiWord & (uint32_t)((1ull << d->hiBits) - 1)) AdrenoDrawBug(@"reloc %u hi placeholder %#x", i, hiWord);
            }
            if (d->kind == ADRENO_IB_RELOC_PACKAGE && (offset > packageBytes || d->length > packageBytes - offset))
                AdrenoDrawBug(@"reloc %u package range", i);
            if (d->kind == ADRENO_IB_RELOC_ZERO && (offset > ADRENO_IB_ZERO_BYTES || d->length > ADRENO_IB_ZERO_BYTES - offset))
                AdrenoDrawBug(@"reloc %u zero-page range", i);
            struct adreno_ib_reloc row = {(uint32_t)lo, (uint32_t)hi, d->kind, d->access, d->alignLog2,
                                          d->hiSpace == ADRENO_SPACE_NONE ? 0 : d->hiBits, d->resourceID, offset, d->length};
            memcpy(&out[i], &row, sizeof row);          // the reservation is 4-aligned only
        }
    }
    @finally { free(targets); }
#undef ADRENO_TARGET_TAKEN
#undef ADRENO_TARGET_TAKE
}
@end
