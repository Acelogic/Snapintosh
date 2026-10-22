/* SPDX-License-Identifier: MIT */
// Native IOGPU resource allocation with a device-mapper reservation retained
// across unwire/rewire. Contract: docs/ADRENO-KEXT-RESOURCE-LIFETIME-20260926.md;
// translations resident across unwire: docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md.
#include "AdrenoX2.h"
#include <IOKit/IOLib.h>
#if ADRENO_PERF_GPU
#include <kern/clock.h>
#include "AdrenoDisplayPacing.h"    // ADRENO_GPU_* (the perf gpu line's fields)
#endif

#define MLOG(fmt, ...) IOLog("AdrenoX2 resource: " fmt "\n", ##__VA_ARGS__)

// One budget for every map's resident translations (atomic in compat/adreno-resource.c).
#if ADRENO_RESIDENT_BUDGET_MIB
// Residency on (pacing work 2026-10-21, R13): zero here, so the object keeps no initialized data ahead of
// kmod_info (as gPool below); AdrenoGPUMapStart() stores the budget before IOGPU::start can make any map.
static struct adreno_residency gResidency;
extern "C" void AdrenoGPUMapStart(void)
{
    __atomic_store_n(&gResidency.budget, kAdrenoResidentBudget, __ATOMIC_RELEASE);
}
#else
static struct adreno_residency gResidency = {kAdrenoResidentBudget, 0, 0, 0, 0, 0};
#endif
static uint32_t gResidencyFullLogged;
#if ADRENO_PERF_GPU
// The perf gpu line (AdrenoDisplayPacing.h, P1-P7): totals that only grow; AdrenoDisplay takes window deltas.
// Writers are IOGPU's submission and scheduler threads on any CPU, so every update is a relaxed atomic add.
enum { kWorkPrepares, kWorkPrepareTicks, kWorkUnwires, kWorkUnwireTicks, kWorkCacheCalls, kWorkCacheBytes,
       kWorkCacheTicks, kWorkCounters };
static uint64_t gWork[kWorkCounters];
static void workAdd(unsigned which, uint64_t n) { __atomic_fetch_add(&gWork[which], n, __ATOMIC_RELAXED); }
extern "C" void AdrenoGPUWorkCounters(uint64_t *v)
{
    v[ADRENO_GPU_PREPARES] = __atomic_load_n(&gWork[kWorkPrepares], __ATOMIC_RELAXED);
    v[ADRENO_GPU_PREPARE_TICKS] = __atomic_load_n(&gWork[kWorkPrepareTicks], __ATOMIC_RELAXED);
    v[ADRENO_GPU_UNWIRES] = __atomic_load_n(&gWork[kWorkUnwires], __ATOMIC_RELAXED);
    v[ADRENO_GPU_UNWIRE_TICKS] = __atomic_load_n(&gWork[kWorkUnwireTicks], __ATOMIC_RELAXED);
    v[ADRENO_GPU_CACHE_CALLS] = __atomic_load_n(&gWork[kWorkCacheCalls], __ATOMIC_RELAXED);
    v[ADRENO_GPU_CACHE_BYTES] = __atomic_load_n(&gWork[kWorkCacheBytes], __ATOMIC_RELAXED);
    v[ADRENO_GPU_CACHE_TICKS] = __atomic_load_n(&gWork[kWorkCacheTicks], __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_RETAINED] = __atomic_load_n(&gResidency.retained, __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_REUSED] = __atomic_load_n(&gResidency.reused, __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_EVICTED] = __atomic_load_n(&gResidency.evicted, __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_REFUSED] = __atomic_load_n(&gResidency.refused, __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_BYTES] = __atomic_load_n(&gResidency.bytes, __ATOMIC_RELAXED);
    v[ADRENO_GPU_RES_BUDGET] = __atomic_load_n(&gResidency.budget, __ATOMIC_RELAXED);
}
#endif

#if ADRENO_RESOURCE_POOL
// Kext batch 8 (FAILURES-AND-DESIGN.md 2026-10-20): native bind and final release through
// adreno_resource_bind/retire, and one pool of empty DART reservations for every map. The pool is
// changed only under gPoolLock, a leaf lock (no callout while held); its counters are atomic.
#include "AdrenoDisplayPacing.h"    // ADRENO_MAP_* (the perf map line's fields)
static constexpr uint64_t kPoolBytes = 128ull << 20;    // of the 3 GiB window (D5)
static constexpr uint64_t kPoolMaxSpan = 4ull << 20;    // the plug-in's 1 MiB UBO arenas and smaller
#if ADRENO_POOL_ARENA
// Kext batch 9 (FAILURES-AND-DESIGN.md K5): the plug-in's per-command-stream UBO staging arena
// (AdrenoDrawCommands.m: MAX(1048576, ...)) is its own class of ADRENO_VA_POOL_ARENA_ENTRIES entries, outside the
// 128 MiB that every other span shares (v9: those filled it for good and 13,257 arenas were strict-freed).
static constexpr uint64_t kPoolArenaSpan = 1ull << 20;
#endif
static IOLock *gPoolLock;
static void poolLock(void *) { IOLockLock(gPoolLock); }
static void poolUnlock(void *) { IOLockUnlock(gPoolLock); }
static struct adreno_va_pool gPool;          // zero until pool() fills it: no initialized data ahead of kmod_info
static uint32_t gPoolState;                  // 0 none, 1 being made, 2 ready, 3 no lock (never pool)
#if ADRENO_VA_RECLAIM
// agents/gpu-va (FAILURE-MODES.md G1-G17): the filler (compat/adreno-resource.h) and the IOVA gauge. All in bss (G13).
// The device mapper every map shares (withMapper publishes it, retained for the kext's life); the filler is made with
// the pool (G14) and is never completed or released (G4): its pages stay pinned while any leaf can name them.
static IOMapper *gFillerMapper;
static IOBufferMemoryDescriptor *gFillerBuffer;
static struct adreno_va_filler gFiller;
static constexpr uint64_t kFillerBytes = 1ull << 20;     // one insert per MiB; one 16 KiB page as the fallback (G12)
// G10: DART bytes held by this file's reservations (maps and pool: + on reserve, - on a native free) and their peak
// since the last perf va line; bytes and count of reservations frozen by a failed release (retained until reboot).
static uint64_t gVAHeld, gVAPeak, gVAFrozen, gVAFrozenCount;
static uint32_t gVALogged;
static void vaHeld(int64_t delta)
{
    uint64_t now = __atomic_add_fetch(&gVAHeld, (uint64_t)delta, __ATOMIC_RELAXED);
    uint64_t peak = __atomic_load_n(&gVAPeak, __ATOMIC_RELAXED);
    while (delta > 0 && now > peak &&
           !__atomic_compare_exchange_n(&gVAPeak, &peak, now, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}
static const struct adreno_va_filler *fillerMake();
#endif
// The pool once made; nullptr while another thread makes it or if its lock cannot be allocated, and then the
// caller takes the strict path, as before the pool.
static struct adreno_va_pool *pool()
{
    uint32_t state = __atomic_load_n(&gPoolState, __ATOMIC_ACQUIRE), none = 0;
    if (state == 2) return &gPool;
    if (state || !__atomic_compare_exchange_n(&gPoolState, &none, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return nullptr;
    gPoolLock = IOLockAlloc();
    if (!gPoolLock) {
        __atomic_store_n(&gPoolState, 3, __ATOMIC_RELEASE);
        return nullptr;
    }
    gPool.limit_bytes = kPoolBytes;
    gPool.max_span = kPoolMaxSpan;
#if ADRENO_POOL_ARENA
    gPool.arena_span = kPoolArenaSpan;
    gPool.arena_limit = ADRENO_VA_POOL_ARENA_ENTRIES;
#endif
    gPool.lock = poolLock;
    gPool.unlock = poolUnlock;
#if ADRENO_VA_RECLAIM
    gPool.filler = fillerMake();             // before the pool is published: every reader sees its final value
#endif
    __atomic_store_n(&gPoolState, 2, __ATOMIC_RELEASE);
    return &gPool;
}
// Glue counters (D11): insert calls and pages, pages committed inside the native bind, clear calls, DART
// strict frees. Wire pages are the rest of the inserted pages (minus bind and final-free recommits).
enum { kMapInserts, kMapPages, kMapBindPages, kMapClears, kMapStrict, kMapCounters };
static uint64_t gMapStats[kMapCounters];
static void mapCount(unsigned which, uint64_t n) { __atomic_fetch_add(&gMapStats[which], n, __ATOMIC_RELAXED); }
static uint32_t gBindLogged;
#if ADRENO_VA_RECLAIM
static int fillerInsert(void *, uint64_t address, uint64_t offset, uint64_t pa, uint64_t size)
{
    // G4: read access only; the filler's pages are never device-writable.
    IOReturn result = gFillerMapper->iovmInsert(kIODMAMapReadAccess, address, offset, pa, size);
    mapCount(kMapInserts, 1);
    mapCount(kMapPages, size / kAdrenoGPUVAAlign);
    return result;
}
static int fillerFree(void *, uint64_t address, uint64_t length)
{
    IOReturn result = gFillerMapper->iovmUnmapMemory(nullptr, nullptr, address, length);
    mapCount(kMapStrict, 1);
    if (result == kIOReturnSuccess) vaHeld(-(int64_t)length);
    return result;
}
// G12: 1 MiB physically contiguous, else one page; nullptr (no filled free, no reclaim) when neither can be pinned.
static const struct adreno_va_filler *fillerMake()
{
    IOMapper *mapper = __atomic_load_n(&gFillerMapper, __ATOMIC_ACQUIRE);
    if (!mapper) return nullptr;
    for (uint64_t bytes = kFillerBytes; bytes; bytes = bytes == kFillerBytes ? kAdrenoGPUVAAlign : 0) {
        IOBufferMemoryDescriptor *buffer = IOBufferMemoryDescriptor::withOptions(
            kIODirectionOut | kIOMemoryPhysicallyContiguous, bytes, kAdrenoGPUVAAlign);
        if (!buffer) continue;
        if (buffer->prepare(kIODirectionOut) != kIOReturnSuccess) { buffer->release(); continue; }
        IOByteCount segment = 0;
        uint64_t pa = buffer->getPhysicalSegment(0, &segment, kIOMemoryMapperNone);
        if (!pa || (pa % kAdrenoGPUVAAlign) || segment < bytes) {
            buffer->complete(kIODirectionOut);
            buffer->release();
            continue;
        }
        gFillerBuffer = buffer;
        gFiller = {nullptr, fillerInsert, fillerFree, pa, bytes};
        MLOG("VA reclaim: filler 0x%llx bytes at 0x%llx", bytes, pa);
        return &gFiller;
    }
    MLOG("VA reclaim: no filler; reclaim off");
    return nullptr;
}
#endif
#endif

extern "C" IOReturn AdrenoNativePrepareMemory(IOGPUMemory *)
    __asm__("__ZN11IOGPUMemory13prepareMemoryEv");
extern "C" void AdrenoNativeCompleteMemory(IOGPUMemory *)
    __asm__("__ZN11IOGPUMemory14completeMemoryEv");

bool AdrenoMemoryMap::prepareForSubmission()
{
    IOGPUMemory *memory=nativeMemory();
    if (!memory || !fLock) return false;
    // Native prepare acquires its memory lock and may reenter this map to
    // commit PTEs. Never hold fLock while entering that lock hierarchy.
#if ADRENO_PERF_GPU
    // P2: one clock pair per preparation; the wire, our rewire and every DART insert happen inside.
    const uint64_t prepareStart=mach_absolute_time();
    IOReturn result=AdrenoNativePrepareMemory(memory);
    workAdd(kWorkPrepares,1);
    workAdd(kWorkPrepareTicks,mach_absolute_time()-prepareStart);
#else
    IOReturn result=AdrenoNativePrepareMemory(memory);
#endif
    if (result!=kIOReturnSuccess) {
        MLOG("submission prepare failed 0x%x",result);
        return false; // native slow failure already removed its speculative ref
    }
    IORecursiveLockLock(fLock);
    bool ok=fResource.flags==(ADRENO_RESOURCE_RESERVED|ADRENO_RESOURCE_PINNED) &&
        fResource.length && fResource.mapped_length==fResource.length && fBacking &&
        memory->get_iomd_ptr()==fBacking && nativeAllocated() &&
        fResource.address==IOGPUMemoryMap::getGPUVirtualAddress();
    IORecursiveLockUnlock(fLock);
    if (!ok) {
        MLOG("native preparation did not produce a complete admitted mapping");
        AdrenoNativeCompleteMemory(memory);
    }
    return ok;
}
void AdrenoMemoryMap::completeSubmission()
{
    // The retained map keeps this memory alive. Completion drops one native
    // preparation ref; deferred scheduler unwiring owns actual PTE release.
    AdrenoNativeCompleteMemory(nativeMemory());
}

int AdrenoMemoryMap::maintainCache(void *context, uint64_t address, uint64_t bytes, unsigned direction)
{
    auto *map=static_cast<AdrenoMemoryMap *>(context);
#if ADRENO_PERF_GPU
    const uint64_t cacheStart=mach_absolute_time();
#endif
    register uint64_t x0 __asm__("x0")=ADRENO_GUEST_CACHE;
    register uint64_t x1 __asm__("x1")=address;
    register uint64_t x2 __asm__("x2")=bytes;
    register uint64_t x3 __asm__("x3")=direction;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
#if ADRENO_PERF_GPU
    workAdd(kWorkCacheCalls,1);
    workAdd(kWorkCacheBytes,bytes);
    workAdd(kWorkCacheTicks,mach_absolute_time()-cacheStart);
#endif
    map->fLastNativeStatus=x0;
    if (x0 || x1!=bytes || x2) {
        MLOG("cache direction %u failed status=0x%llx completed=0x%llx reserved=0x%llx",
             direction,x0,x1,x2);
        return -1;
    }
    return 0;
}
int AdrenoMemoryMap::cacheSubmission(unsigned direction)
{
    if (!fLock) return ADRENO_RESOURCE_E_STATE;
    IORecursiveLockLock(fLock);
    IOGPUMemory *memory=nativeMemory();
    bool backing=memory && fBacking && nativeAllocated() && memory->get_iomd_ptr()==fBacking &&
        fResource.address==IOGPUMemoryMap::getGPUVirtualAddress();
    // The GPU cannot write read-only backing (its DART and SMMU leaves are no-write), so there is
    // nothing to invalidate after it, and the monitor refuses FROM_DEVICE on such a leaf.
    if (backing && direction==ADRENO_CACHE_FROM_DEVICE && fBackingDirection==kIODirectionOut) direction=0;
    int result=backing ? adreno_resource_cache(&fResource,direction,maintainCache,this) : ADRENO_RESOURCE_E_STATE;
    IORecursiveLockUnlock(fLock);
    return result;
}
#if ADRENO_CACHE_SPARSE
int AdrenoMemoryMap::cacheRange(unsigned direction, uint64_t offset, uint64_t bytes)
{
    // cacheSubmission's ownership checks and read-only rule, over [offset, offset + bytes) of the logical extent
    // (a FILL32 target, FAILURE-MODES.md C13/C14).
    if (!fLock) return ADRENO_RESOURCE_E_STATE;
    IORecursiveLockLock(fLock);
    IOGPUMemory *memory=nativeMemory();
    bool backing=memory && fBacking && nativeAllocated() && memory->get_iomd_ptr()==fBacking &&
        fResource.address==IOGPUMemoryMap::getGPUVirtualAddress();
    if (backing && direction==ADRENO_CACHE_FROM_DEVICE && fBackingDirection==kIODirectionOut) direction=0;
    int result=backing ? adreno_resource_cache_range(&fResource,direction,offset,bytes,maintainCache,this) :
                         ADRENO_RESOURCE_E_STATE;
    IORecursiveLockUnlock(fLock);
    return result;
}
#endif

int AdrenoMemoryMap::resolveFill(uint64_t offset, uint64_t bytes, uint64_t *address)
{
    if (!fLock || !address) return ADRENO_RESOURCE_E_STATE;
    *address=0;
    IORecursiveLockLock(fLock);
    IOGPUMemory *memory=nativeMemory();
    bool backing=memory && fBacking && nativeAllocated() && memory->get_iomd_ptr()==fBacking &&
        fResource.address==IOGPUMemoryMap::getGPUVirtualAddress() &&
        fResource.logical_length==IOGPUMemoryMap::getLength();
    int result=backing ? adreno_fill32_resource_range(&fResource,offset,bytes,address) : ADRENO_RESOURCE_E_STATE;
    IORecursiveLockUnlock(fLock);
    return result;
}

int AdrenoMemoryMap::resolveRange(uint64_t offset, uint64_t bytes, uint64_t *address)
{
    // resolveFill's ownership checks without FILL32's 16 KiB / dword limits (compat adreno_ib_resource_range).
    if (!fLock || !address) return ADRENO_RESOURCE_E_STATE;
    *address=0;
    IORecursiveLockLock(fLock);
    IOGPUMemory *memory=nativeMemory();
    bool backing=memory && fBacking && nativeAllocated() && memory->get_iomd_ptr()==fBacking &&
        fResource.address==IOGPUMemoryMap::getGPUVirtualAddress() &&
        fResource.logical_length==IOGPUMemoryMap::getLength();
    int result=backing ? adreno_ib_resource_range(&fResource,offset,bytes,address) : ADRENO_RESOURCE_E_STATE;
    IORecursiveLockUnlock(fLock);
    return result;
}

AdrenoMemoryMap *AdrenoMemoryMap::withMapper(IOMapper *mapper)
{
    if (!mapper) return nullptr;
    auto *map = OSTypeAlloc(AdrenoMemoryMap);
    if (!map) return nullptr;
    map->fLock = IORecursiveLockAlloc();
    if (!map->fLock) { map->release(); return nullptr; }
    map->fMapper = mapper;
    mapper->retain();
#if ADRENO_VA_RECLAIM
    // The filler's mapper: the accelerator's one device mapper, published once and kept for the kext's life.
    IOMapper *none = nullptr;
    if (!__atomic_load_n(&gFillerMapper, __ATOMIC_ACQUIRE)) {
        mapper->retain();
        if (!__atomic_compare_exchange_n(&gFillerMapper, &none, mapper, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            mapper->release();
    }
#endif
    return map; // IOGPU::createMemoryMap performs native init afterwards.
}

IOGPUMemory *AdrenoMemoryMap::nativeMemory() const
{
    // UUID-bound IOGPUMemoryMap::init/free retain/release this field.
    return *reinterpret_cast<IOGPUMemory *const *>(reinterpret_cast<const uint8_t *>(this) + 0x18);
}
bool AdrenoMemoryMap::nativeAllocated() const
{
    return *reinterpret_cast<const uint16_t *>(reinterpret_cast<const uint8_t *>(this) + 0x10) & 1;
}
struct adreno_resource_ops AdrenoMemoryMap::operations()
{
    return {this, reservePages, freePages, pinBacking, unpinBacking, physicalPage, insertPage, clearPages};
}

int AdrenoMemoryMap::reservePages(void *ctx, uint64_t length, uint64_t *address, uint64_t *span)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    IODMAMapSpecification specification = {};
    specification.alignment = kAdrenoGPUVAAlign;
    specification.numAddressBits = 64 - ADRENO_CB0_T0SZ;   // 32, or 34 with ADRENO_VA_WIDE (IODARTMapper ignores it)
    IOReturn result = map->fMapper->iovmMapMemory(nullptr, 0, length,
        kIODMAMapReadAccess | kIODMAMapWriteAccess, &specification, nullptr, nullptr, address, span);
    map->fLastNativeStatus = static_cast<uint32_t>(result);
#if ADRENO_VA_RECLAIM
    if (result == kIOReturnSuccess) vaHeld((int64_t)*span);            // G10
#endif
    return result;
}
int AdrenoMemoryMap::freePages(void *ctx, uint64_t address, uint64_t length)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    IOReturn result = map->fMapper->iovmUnmapMemory(nullptr, nullptr, address, length);
    map->fLastNativeStatus = static_cast<uint32_t>(result);
#if ADRENO_RESOURCE_POOL
    mapCount(kMapStrict, 1);
#endif
#if ADRENO_VA_RECLAIM
    if (result == kIOReturnSuccess) vaHeld(-(int64_t)length);         // G10
#endif
    return result;
}
int AdrenoMemoryMap::pinBacking(void *ctx)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    IOGPUMemory *memory = map->nativeMemory();
    IOMemoryDescriptor *backing = memory ? memory->get_iomd_ptr() : nullptr;
    if (map->fBacking || !backing || backing->getLength() < map->fResource.logical_length) {
        map->fLastNativeStatus = static_cast<uint32_t>(kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    backing->retain();
    // Read-only memory (descriptor direction Out) is wired for device reads only. Once
    // anything has wired it that way, a read/write prepare fails with kIOReturnNotWritable
    // ("IOMemoryDescriptor ... prepared read only"), so prepare and map it read-only.
    IODirection direction = (backing->getDirection() & kIODirectionOutIn) == kIODirectionOut ?
        kIODirectionOut : kIODirectionInOut;
    IOReturn result = backing->prepare(direction);
    if (result == kIOReturnNotWritable && direction != kIODirectionOut) {
        direction = kIODirectionOut;
        result = backing->prepare(direction);
    }
    map->fLastNativeStatus = static_cast<uint32_t>(result);
    if (result != kIOReturnSuccess) { backing->release(); return result; }
    map->fBacking = backing;
    map->fBackingDirection = direction;
#if ADRENO_CACHE_SPARSE
    map->clearCacheMark();   // new pages: nothing about them is known to be clean (FAILURE-MODES.md C1d, C6)
#endif
    return 0;
}
int AdrenoMemoryMap::unpinBacking(void *ctx)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    IOReturn result = map->fBacking->complete(map->fBackingDirection);
    map->fLastNativeStatus = static_cast<uint32_t>(result);
    if (result != kIOReturnSuccess) return result; // retain on uncertain completion
    OSSafeReleaseNULL(map->fBacking);
#if ADRENO_CACHE_SPARSE
    map->clearCacheMark();
#endif
    return 0;
}
uint64_t AdrenoMemoryMap::physicalPage(void *ctx, uint64_t offset, uint64_t *length)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    IOByteCount span = 0;
    uint64_t pa = map->fBacking->getPhysicalSegment(offset, &span, kIOMemoryMapperNone);
    *length = span;
    return pa;
}
int AdrenoMemoryMap::insertPage(void *ctx, uint64_t address, uint64_t offset, uint64_t pa, uint64_t size)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    // Read access lets the device read memory; write access is granted only to read/write backing.
    IOReturn result = map->fMapper->iovmInsert(map->fBackingDirection == kIODirectionOut ? kIODMAMapReadAccess :
                                             kIODMAMapReadAccess | kIODMAMapWriteAccess,
                                             address, offset, pa, size);
    map->fLastNativeStatus = static_cast<uint32_t>(result);
#if ADRENO_RESOURCE_POOL
    mapCount(kMapInserts, 1);
    mapCount(kMapPages, size / kAdrenoGPUVAAlign);
#endif
    return result;
}
int AdrenoMemoryMap::clearPages(void *ctx, uint64_t address, uint64_t size)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    register uint64_t x0 __asm__("x0") = ADRENO_GUEST_UNMAP;
    register uint64_t x1 __asm__("x1") = address;
    register uint64_t x2 __asm__("x2") = size;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    map->fLastNativeStatus = x0 ? x0 : x2;
#if ADRENO_RESOURCE_POOL
    mapCount(kMapClears, 1);
#endif
    if (x0 || x1 != size || x2) return -1;
    return 0;
}

#if ADRENO_RESOURCE_POOL
int AdrenoMemoryMap::bindNative(void *ctx, uint64_t address, uint64_t length)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    // Native task allocation normally passes this byte alignment to its range allocator. An exact-address
    // reservation bypasses that step, so check it; a misaligned address is refused before any native state.
    uint32_t alignment = *reinterpret_cast<const uint32_t *>(reinterpret_cast<const uint8_t *>(map) + 0x14);
    bool aligned = !alignment || !(address % alignment);
    // This may immediately invoke commitIntoGPUPageTable(). The recursive lock and the DART reservation
    // already in fResource are required here.
    if (aligned && map->IOGPUMemoryMap::reserveGPUVirtualAddress(address, length)) return 0;
    bool allocated = map->nativeAllocated();
    uint32_t n = __atomic_add_fetch(&gBindLogged, 1, __ATOMIC_RELAXED);
    if (n <= 16 || !(n & 1023))
        MLOG("native VA bind failed address=0x%llx alignment=0x%x: %s (%u)", address, alignment,
             !aligned ? "misaligned, another address" : allocated ? "commit failed" : "in use, another address", n);
    return allocated ? 2 : 1;
}
void AdrenoMemoryMap::unbindNative(void *ctx)
{
    auto *map = static_cast<AdrenoMemoryMap *>(ctx);
    if (map->nativeAllocated()) map->IOGPUMemoryMap::freeGPUVirtualAddress();
}
// The perf map line's cumulative counters (AdrenoDisplay.cpp takes window deltas; POOL_LIVE is a level).
extern "C" void AdrenoGPUMapCounters(uint64_t *v)
{
    uint64_t pages = __atomic_load_n(&gMapStats[kMapPages], __ATOMIC_RELAXED);
    uint64_t bind = __atomic_load_n(&gMapStats[kMapBindPages], __ATOMIC_RELAXED);
    uint64_t free = __atomic_load_n(&gPool.recommit_pages, __ATOMIC_RELAXED);
    v[ADRENO_MAP_INSERTS] = __atomic_load_n(&gMapStats[kMapInserts], __ATOMIC_RELAXED);
    v[ADRENO_MAP_PAGES_BIND] = bind;
    v[ADRENO_MAP_PAGES_FREE] = free;
    v[ADRENO_MAP_PAGES_WIRE] = pages > bind + free ? pages - bind - free : 0;
    v[ADRENO_MAP_CLEARS] = __atomic_load_n(&gMapStats[kMapClears], __ATOMIC_RELAXED);
    v[ADRENO_MAP_STRICT] = __atomic_load_n(&gMapStats[kMapStrict], __ATOMIC_RELAXED);
    v[ADRENO_MAP_POOL_PUT] = __atomic_load_n(&gPool.puts, __ATOMIC_RELAXED);
    v[ADRENO_MAP_POOL_TAKE] = __atomic_load_n(&gPool.takes, __ATOMIC_RELAXED);
    v[ADRENO_MAP_POOL_REFUSED] = __atomic_load_n(&gPool.refused, __ATOMIC_RELAXED);
    v[ADRENO_MAP_POOL_LIVE] = __atomic_load_n(&gPool.count, __ATOMIC_RELAXED);
    v[ADRENO_MAP_VA_BUSY] = __atomic_load_n(&gPool.collisions, __ATOMIC_RELAXED);
    v[ADRENO_MAP_VA_COMMIT] = __atomic_load_n(&gPool.unbound, __ATOMIC_RELAXED);
    v[ADRENO_MAP_VA_RETRIED] = __atomic_load_n(&gPool.retried, __ATOMIC_RELAXED);
    v[ADRENO_MAP_VA_FAILED] = __atomic_load_n(&gPool.gave_up, __ATOMIC_RELAXED);
    v[ADRENO_MAP_IBS] = 0;      // AdrenoDisplay.cpp fills it from AdrenoX2.cpp's IB counter
}
#if ADRENO_VA_RECLAIM
// The perf va line (AdrenoDisplayPacing.h, G16): levels in bytes (held, the peak since the last call, pooled, frozen)
// and counts; AdrenoDisplay.cpp takes window deltas of the counters and MiB of the levels.
extern "C" void AdrenoGPUVACounters(uint64_t *v)
{
    v[ADRENO_VA_HELD] = __atomic_load_n(&gVAHeld, __ATOMIC_RELAXED);
    v[ADRENO_VA_PEAK] = __atomic_exchange_n(&gVAPeak, __atomic_load_n(&gVAHeld, __ATOMIC_RELAXED), __ATOMIC_RELAXED);
    v[ADRENO_VA_POOLED] = __atomic_load_n(&gPool.bytes, __ATOMIC_RELAXED);
    v[ADRENO_VA_FROZEN] = __atomic_load_n(&gVAFrozen, __ATOMIC_RELAXED);
    v[ADRENO_VA_FROZEN_N] = __atomic_load_n(&gVAFrozenCount, __ATOMIC_RELAXED);
    v[ADRENO_VA_EXHAUSTED] = __atomic_load_n(&gPool.exhausted, __ATOMIC_RELAXED);
    v[ADRENO_VA_RECLAIMED] = __atomic_load_n(&gPool.reclaimed, __ATOMIC_RELAXED);
    v[ADRENO_VA_RECLAIM_FAILED] = __atomic_load_n(&gPool.reclaim_failed, __ATOMIC_RELAXED);
    v[ADRENO_VA_DRAINED] = __atomic_load_n(&gPool.drained, __ATOMIC_RELAXED);
    v[ADRENO_VA_DRAINED_BYTES] = __atomic_load_n(&gPool.drained_bytes, __ATOMIC_RELAXED);
    v[ADRENO_VA_FILLED] = __atomic_load_n(&gPool.filled, __ATOMIC_RELAXED);
    v[ADRENO_VA_PRESSURE] = __atomic_load_n(&gPool.pressure_refused, __ATOMIC_RELAXED);
    v[ADRENO_VA_LOST] = __atomic_load_n(&gPool.lost, __ATOMIC_RELAXED);
}
#endif
#endif

bool AdrenoMemoryMap::allocGPUVirtualAddress()
{
    if (!fLock || !fMapper || !nativeMemory()) return false;
    IORecursiveLockLock(fLock);
    if (nativeAllocated()) {
        bool ok = !(fResource.flags & ADRENO_RESOURCE_FAILED) && fResource.address &&
                  fResource.address == IOGPUMemoryMap::getGPUVirtualAddress();
        IORecursiveLockUnlock(fLock); return ok;
    }
    auto ops = operations();
#if ADRENO_RESOURCE_POOL
    // V1-V7: a pooled or fresh DART reservation, bound natively at exactly that address; a CB0 collision
    // retries elsewhere; a failed commit releases CB0 first. Pages committed inside the bind count as bind.
    int bound = adreno_resource_bind(&fResource, &ops, IOGPUMemoryMap::getLength(), pool(), bindNative, unbindNative,
                                     this, &gResidency, ADRENO_COMMIT_RUNS);
    if (!bound && (fResource.flags & ADRENO_RESOURCE_PINNED))
        mapCount(kMapBindPages, fResource.mapped_length / kAdrenoGPUVAAlign);
    if (bound) {
        uint32_t n = __atomic_add_fetch(&gBindLogged, 1, __ATOMIC_RELAXED);
        if (n <= 16 || !(n & 1023)) MLOG("GPU address allocation failed %d native=0x%llx (%u)", bound, fLastNativeStatus, n);
#if ADRENO_VA_RECLAIM
        // G10: what held the window when it refused (the first time and every 1024th): this file's DART bytes, the
        // pool's share, frozen reservations, and what reclaim gave back so far.
        uint32_t v = __atomic_add_fetch(&gVALogged, 1, __ATOMIC_RELAXED);
        if (bound == ADRENO_RESOURCE_E_RESERVE && (v == 1 || !(v & 1023)))
            MLOG("VA exhausted: need 0x%llx held %llu MiB pool %llu MiB/%u frozen %llu MiB/%llu reclaimed %llu/%llu "
                 "drained %llu MiB filled %llu lost %llu (%u)", IOGPUMemoryMap::getLength(),
                 __atomic_load_n(&gVAHeld, __ATOMIC_RELAXED) >> 20, __atomic_load_n(&gPool.bytes, __ATOMIC_RELAXED) >> 20,
                 __atomic_load_n(&gPool.count, __ATOMIC_RELAXED), __atomic_load_n(&gVAFrozen, __ATOMIC_RELAXED) >> 20,
                 __atomic_load_n(&gVAFrozenCount, __ATOMIC_RELAXED), __atomic_load_n(&gPool.reclaimed, __ATOMIC_RELAXED),
                 __atomic_load_n(&gPool.reclaim_failed, __ATOMIC_RELAXED),
                 __atomic_load_n(&gPool.drained_bytes, __ATOMIC_RELAXED) >> 20,
                 __atomic_load_n(&gPool.filled, __ATOMIC_RELAXED), __atomic_load_n(&gPool.lost, __ATOMIC_RELAXED), v);
#endif
    }
    IORecursiveLockUnlock(fLock);
    return !bound;
#else
    int error = adreno_resource_reserve(&fResource, &ops, IOGPUMemoryMap::getLength());
    if (error) {
        MLOG("DART reserve failed %d native=0x%llx", error, fLastNativeStatus);
        IORecursiveLockUnlock(fLock); return false;
    }
    // Native task allocation normally passes this byte alignment to its range
    // allocator. An exact-address reservation bypasses that step, so check it.
    uint32_t alignment = *reinterpret_cast<const uint32_t *>(reinterpret_cast<const uint8_t *>(this) + 0x14);
    bool ok = !alignment || !(fResource.address % alignment);
    if (ok) {
        // This may immediately invoke commitIntoGPUPageTable(). The recursive
        // lock and the already-created DART reservation are required here.
        ok = IOGPUMemoryMap::reserveGPUVirtualAddress(fResource.address, fResource.logical_length);
    }
    if (!ok) {
        MLOG("native VA bind failed address=0x%llx alignment=0x%x", fResource.address, alignment);
        releaseAddress();
    }
    IORecursiveLockUnlock(fLock);
    return ok;
#endif
}
bool AdrenoMemoryMap::reserveGPUVirtualAddress(unsigned long long address, unsigned long long length)
{
    // Arbitrary/shared fixed VAs need a native VMSpace ownership path; do not
    // publish another address or pretend an allocator-only reservation is DMA.
    MLOG("requested fixed GPU address unsupported address=0x%llx length=0x%llx", address, length);
    return false;
}
bool AdrenoMemoryMap::backingKeepable() const
{
    // Retain only translations to the descriptor native IOGPU still uses, prepared in its own
    // direction. A device-writable descriptor prepared Out (someone else had wired it read-only)
    // is released as before: holding that read-only wire would keep the GPU mapping no-write and
    // make later read/write prepares fail with kIOReturnNotWritable.
    IOGPUMemory *memory = nativeMemory();
    return fBacking && memory && memory->get_iomd_ptr() == fBacking &&
        !(fBackingDirection == kIODirectionOut &&
          (fBacking->getDirection() & kIODirectionOutIn) != kIODirectionOut);
}
bool AdrenoMemoryMap::commitIntoGPUPageTable()
{
    if (!fLock) return false;
    IORecursiveLockLock(fLock);
    auto ops = operations();
    bool same = !fBacking || (nativeMemory() && nativeMemory()->get_iomd_ptr() == fBacking);
    // Resident with the same descriptor: nothing to map. Resident with another descriptor: the
    // stale translations are cleared and unpinned before the new descriptor is pinned.
    int error = adreno_resource_rewire(&fResource, &ops, &gResidency, same, ADRENO_COMMIT_RUNS);
    if (error) MLOG("map failed %d native=0x%llx address=0x%llx", error, fLastNativeStatus, fResource.address);
    IORecursiveLockUnlock(fLock);
    return error == 0;
}
void AdrenoMemoryMap::releaseFromGPUPageTable()
{
    // Native unwire after the GPU retired every preparation. Within the budget the translations
    // and our descriptor wire stay (no clear, no TLB invalidation); every reachable page stays
    // pinned, so it cannot be paged out, purged or reused while the GPU can reach it.
    if (!fLock) return;
#if ADRENO_PERF_GPU
    const uint64_t unwireStart = mach_absolute_time();
#endif
    IORecursiveLockLock(fLock);
    auto ops = operations();
    int error = adreno_resource_unwire(&fResource, &ops, &gResidency, backingKeepable());
#if ADRENO_PERF_GPU
    workAdd(kWorkUnwires, 1);
    workAdd(kWorkUnwireTicks, mach_absolute_time() - unwireStart);
#endif
    if (error) MLOG("clear/unpin failed %d native=0x%llx; retaining resource", error, fLastNativeStatus);
    if (__atomic_load_n(&gResidency.refused, __ATOMIC_RELAXED) &&
        !__atomic_exchange_n(&gResidencyFullLogged, 1, __ATOMIC_RELAXED))
        MLOG("resident budget %llu MiB full: %llu bytes, retained %llu, reused %llu, evicted %llu",
             (unsigned long long)(gResidency.budget >> 20), (unsigned long long)gResidency.bytes,
             (unsigned long long)gResidency.retained, (unsigned long long)gResidency.reused,
             (unsigned long long)gResidency.evicted);
    IORecursiveLockUnlock(fLock);
}
bool AdrenoMemoryMap::releaseAddress()
{
    auto ops = operations();
#if ADRENO_RESOURCE_POOL
    // V1: the native CB0 range is released first; then the reservation is emptied into the pool, or
    // freed strictly as before when the pool refuses it (D2). A failure freezes it with CB0 already free.
    int retired = adreno_resource_retire(&fResource, &ops, &gResidency, ADRENO_COMMIT_RUNS, pool(), unbindNative, this);
    if (retired) {
        MLOG("address release failed %d native=0x%llx; retaining resource", retired, fLastNativeStatus);
#if ADRENO_VA_RECLAIM
        // G10: newly frozen (a retire of an already frozen resource answers E_STATE and is not counted again).
        if (retired != ADRENO_RESOURCE_E_STATE && (fResource.flags & ADRENO_RESOURCE_RESERVED)) {
            __atomic_fetch_add(&gVAFrozen, fResource.length, __ATOMIC_RELAXED);
            __atomic_fetch_add(&gVAFrozenCount, 1, __ATOMIC_RELAXED);
        }
#endif
        return false;
    }
    return true;
#else
    int error = adreno_resource_free_with(&fResource, &ops, &gResidency, ADRENO_COMMIT_RUNS);
    if (error) {
        MLOG("address release failed %d native=0x%llx; retaining resource", error, fLastNativeStatus);
        return false;
    }
    if (nativeAllocated()) IOGPUMemoryMap::freeGPUVirtualAddress();
    return true;
#endif
}
void AdrenoMemoryMap::freeGPUVirtualAddress()
{
    if (!fLock) return;
    IORecursiveLockLock(fLock);
    releaseAddress();
    IORecursiveLockUnlock(fLock);
}
void AdrenoMemoryMap::free()
{
    if (fLock) {
        IORecursiveLockLock(fLock);
        bool released = releaseAddress();
        IORecursiveLockUnlock(fLock);
        if (!released) return; // keep native task/memory refs and backing until reboot
        IORecursiveLockFree(fLock); fLock = nullptr;
    }
    OSSafeReleaseNULL(fMapper);
    IOGPUMemoryMap::free();
}
bool AdrenoMemoryMap::updateGPUPageTable()
{
    if (!fLock) return false;
    IORecursiveLockLock(fLock);
    // A resident map is natively unwired: answer as the old unpinned state did. Its next
    // commit replaces stale translations.
    bool ok = !(fResource.flags & ADRENO_RESOURCE_FAILED) &&
        (!fBacking || (fResource.flags & ADRENO_RESOURCE_RESIDENT) ||
         (nativeMemory() && nativeMemory()->get_iomd_ptr() == fBacking));
    IORecursiveLockUnlock(fLock);
    return ok;
}
bool AdrenoMemoryMap::updateGPUPageTable(unsigned int options, IOMemoryDescriptor *, IOMemoryDescriptor *)
{
    // Native update_mappings rolls earlier maps back when a map returns false.
    // An atomic in-place descriptor exchange needs that rollback contract;
    // ordinary unwire/rewire already commits the new descriptor at the same VA.
    MLOG("in-place backing update unsupported options=0x%x; preserving mapping", options);
    return false;
}
