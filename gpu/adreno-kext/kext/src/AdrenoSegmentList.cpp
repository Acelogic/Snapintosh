/* SPDX-License-Identifier: MIT */
// Native list shape and ownership: ADRENO-SUBMISSION-RESOURCES-20260926.md.
#include "AdrenoX2.h"
#include <IOKit/IOLib.h>

// Concrete exported implementations from the UUID-matched IOGPU image. The
// base getter exposes failure before the derived getter adds the subrange
// offset. A null base has not acquired a lease and must not be released.
extern "C" void *AdrenoShmemGetData(IOGPUDeviceShmem *)
    __asm__("__ZN23IOGPUKernelMappedMemory13getKernelDataEv");
extern "C" uint64_t AdrenoShmemGetLength(const IOGPUDeviceShmem *)
    __asm__("__ZNK16IOGPUDeviceShmem9getLengthEv");
extern "C" void AdrenoShmemReleaseData(IOGPUDeviceShmem *)
    __asm__("__ZN23IOGPUKernelMappedMemory17releaseKernelDataEv");
extern "C" IOGPUResource *AdrenoDeviceRetainResource(IOGPUDevice *, uint32_t)
    __asm__("__ZN11IOGPUDevice14retainResourceEj");

void *AdrenoSegmentList::retainResource(void *context, uint32_t id)
{
    return AdrenoDeviceRetainResource(static_cast<IOGPUDevice *>(context), id);
}
void AdrenoSegmentList::releaseResource(void *, void *resource)
{
    // IOGPUObject overrides release; a qualified OSObject call would bypass
    // its distinct reference count and native finalization.
    static_cast<IOGPUResource *>(resource)->release();
}
int AdrenoSegmentList::prepareResource(void *, void *resource, void **token)
{
    *token=nullptr;
    // Native Resource::map/free owns this persistent map. The retained
    // resource prevents free/unmap; the token takes an additional map ref.
    auto *native=*reinterpret_cast<IOGPUMemoryMap **>(
        reinterpret_cast<uint8_t *>(resource)+0x20);
    auto *map=OSDynamicCast(AdrenoMemoryMap,native);
    if (!map) return -1;
    map->retain();
    if (!map->prepareForSubmission()) { map->release(); return -1; }
    *token=map;
    return 0;
}
void AdrenoSegmentList::completeResource(void *, void *token)
{
    auto *map=static_cast<AdrenoMemoryMap *>(token);
    map->completeSubmission();
    map->release();
}
void AdrenoSegmentList::retainAfterTimeout()
{
    adreno_resource_list_freeze(&fResources);
}
int AdrenoSegmentList::syncResource(void *, void *token, unsigned direction)
{
    return static_cast<AdrenoMemoryMap *>(token)->cacheSubmission(direction);
}
#if ADRENO_CACHE_SPARSE
struct adreno_cache_mark *AdrenoSegmentList::markResource(void *, void *token)
{
    return static_cast<AdrenoMemoryMap *>(token)->cacheMark();
}
int AdrenoSegmentList::syncRange(void *, void *token, unsigned direction, uint64_t offset, uint64_t bytes)
{
    return static_cast<AdrenoMemoryMap *>(token)->cacheRange(direction, offset, bytes);
}
// Sparse cache ownership (agents/cache-maint FAILURE-MODES.md): the list carries each map's marks and range sync.
const struct adreno_cache_ops AdrenoSegmentList::kCacheOps={markResource,syncRange};
#if ADRENO_PERF_GPU
// One summary per 1,024 list submissions (FAILURE-MODES.md C15): submissions by scope, whole-map cleans done/skipped,
// invalidates done/skipped. Called under fSubmitLock; the counters are compat's relaxed totals.
static void noteSparse()
{
    static uint64_t submissions;
    if (++submissions & 1023) return;
    uint64_t v[ADRENO_CACHE_COUNTERS];
    adreno_cache_sparse_counters(v);
    IOLog("AdrenoX2 cache: sparse all=%llu fence=%llu fill=%llu to=%llu/%llu from=%llu/%llu\n",
          v[ADRENO_CACHE_N_ALL], v[ADRENO_CACHE_N_NONE], v[ADRENO_CACHE_N_RANGE], v[ADRENO_CACHE_N_TO],
          v[ADRENO_CACHE_N_TO_SKIPPED], v[ADRENO_CACHE_N_FROM], v[ADRENO_CACHE_N_FROM_SKIPPED]);
}
#else
static void noteSparse() {}
#endif
#endif
// Its only caller is the FENCE (AdrenoAcceleratorX2::fenceGated). Sparse: the fence lets the GPU reach no list entry
// (its one write is the kext's stamp page), so the list is validated and nothing is maintained (C9, C13).
int AdrenoSegmentList::submit(int (*work)(void *), void *context)
{
    const struct adreno_resource_list_ops ops={fDevice,retainResource,releaseResource,
        prepareResource,completeResource,syncResource};
#if ADRENO_CACHE_SPARSE
    const struct adreno_cache_scope none={ADRENO_CACHE_SCOPE_NONE,nullptr,0,0};
    int result=adreno_resource_list_submit_scope(&fResources,&ops,work,context,&none);
    noteSparse();
    return result;
#else
    return adreno_resource_list_submit(&fResources,&ops,work,context);
#endif
}

int AdrenoSegmentList::resolveFill(void *, void *resource, void *token,
                                  uint64_t offset, uint64_t bytes, uint64_t *address)
{
    auto *native=*reinterpret_cast<IOGPUMemoryMap **>(
        reinterpret_cast<uint8_t *>(resource)+0x20);
    auto *map=OSDynamicCast(AdrenoMemoryMap,native);
    if (!map || map!=token) return ADRENO_LIST_E_RESOURCE;
    return map->resolveFill(offset,bytes,address);
}
int AdrenoSegmentList::fill(const struct adreno_fill32_request *request,
                           int (*transfer)(void *, uint64_t, uint64_t, uint32_t), void *context)
{
    const struct adreno_resource_list_ops ops={fDevice,retainResource,releaseResource,
        prepareResource,completeResource,syncResource};
#if ADRENO_CACHE_SPARSE
    int result=adreno_fill32_submit(&fResources,&ops,request,resolveFill,transfer,context);
    noteSparse();
    return result;
#else
    return adreno_fill32_submit(&fResources,&ops,request,resolveFill,transfer,context);
#endif
}

// IB relocations (design 3.2): adreno_ib_submit has already admitted the ID from this list (usage vs access,
// repeated IDs sharing one preparation); this checks the prepared map and bounds the range under its lock.
int AdrenoSegmentList::resolveRange(void *, void *resource, void *token,
                                   uint64_t offset, uint64_t bytes, uint64_t *address)
{
    auto *native=*reinterpret_cast<IOGPUMemoryMap **>(
        reinterpret_cast<uint8_t *>(resource)+0x20);
    auto *map=OSDynamicCast(AdrenoMemoryMap,native);
    if (!map || map!=token) return ADRENO_LIST_E_RESOURCE;
    return map->resolveRange(offset,bytes,address);
}
int AdrenoSegmentList::ib(struct adreno_ib_work *work, const void *command, uint64_t bytes,
                         int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context)
{
    const struct adreno_resource_list_ops ops={fDevice,retainResource,releaseResource,
        prepareResource,completeResource,syncResource};
#if ADRENO_CACHE_SPARSE
    int result=adreno_ib_submit(work,&fResources,&ops,command,bytes,resolveRange,ring,context);
    noteSparse();
    return result;
#else
    return adreno_ib_submit(work,&fResources,&ops,command,bytes,resolveRange,ring,context);
#endif
}

bool AdrenoSegmentList::initWithSharedResourceList(IOGPUDevice *device,
    const IOGPUSegmentResourceListHeader *header, IOGPUDeviceShmem *shmem)
{
    if (fDevice || fEntries || fResources.ready || !device || !header || !shmem || !OSObject::init())
        return false;
    const uint64_t length=AdrenoShmemGetLength(shmem);
    const uintptr_t mapping=reinterpret_cast<uintptr_t>(AdrenoShmemGetData(shmem));
    if (!mapping) return false;
    // Native IOGPUDeviceShmem::getKernelData loads this exact field before
    // adding it to the base getter's result (original KC 0xfffffe000a864a64).
    const uint64_t offset=*reinterpret_cast<const uint64_t *>(
        reinterpret_cast<const uint8_t *>(shmem)+0x50);
    const uintptr_t base=offset<=UINTPTR_MAX-mapping ? mapping+offset : 0;
    const uintptr_t at=reinterpret_cast<uintptr_t>(header);
    void *snapshot=nullptr;
    uint64_t snapshotBytes=0, entryCapacity=0;
    int result=ADRENO_LIST_E_FORMAT;
    if (base && length<=UINTPTR_MAX-base && at>=base && at-base<=length) {
        const uint64_t available=length-(at-base);
        result=adreno_resource_list_measure(header,available,&snapshotBytes,&entryCapacity);
        if (!result) {
            snapshot=IOMalloc(snapshotBytes);
            fEntryBytes=entryCapacity*sizeof(*fEntries);
            if (fEntryBytes) fEntries=static_cast<adreno_resource_entry *>(IOMalloc(fEntryBytes));
            if (!snapshot || (fEntryBytes && !fEntries)) result=ADRENO_LIST_E_CAPACITY;
            else {
                fDevice=device; device->retain();
#if ADRENO_CACHE_SPARSE
                fResources.cache=&kCacheOps;
#endif
                const struct adreno_resource_list_ops ops={fDevice,retainResource,releaseResource,
                    prepareResource,completeResource,syncResource};
                result=adreno_resource_list_acquire(&fResources,header,available,snapshot,
                    snapshotBytes,fEntries,entryCapacity,&ops);
                if (!result) result=adreno_resource_list_prepare(&fResources,&ops);
            }
        }
    }
    // A base acquisition succeeded; balance even on every later failure.
    AdrenoShmemReleaseData(shmem);
    if (snapshot) IOFree(snapshot,snapshotBytes);
    if (result) IOLog("AdrenoX2 resource list: preparation failed %d\n",result);
    return result==0; // caller releases a failed object and its partial state
}

void AdrenoSegmentList::free()
{
    const struct adreno_resource_list_ops ops={fDevice,retainResource,releaseResource,
        prepareResource,completeResource,syncResource};
    if (adreno_resource_list_release(&fResources,&ops)) {
        IOLog("AdrenoX2 resource list: retaining uncertain GPU ownership until reset\n");
        return;
    }
    if (fEntries) { IOFree(fEntries,fEntryBytes); fEntries=nullptr; }
    fEntryBytes=0;
    OSSafeReleaseNULL(fDevice);
    IOGPUSegmentResourceList::free();
}
