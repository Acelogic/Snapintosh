/* SPDX-License-Identifier: MIT */
// AdrenoX2.cpp - Adreno X2-90 IOGPU driver. See AdrenoX2.h.
#include "AdrenoX2.h"
#include "AdrenoEarlyStop.h"
#include "../../../../compat/adreno-guest.h"
#include "../../../../compat/early-stop.h"
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <kern/task.h>

extern "C" task_t kernel_task;   // com.apple.kpi.mach

#define ALOG(fmt, ...) IOLog("AdrenoX2: " fmt "\n", ##__VA_ARGS__)

#if ADRENO_PERF_FRAMES
#include <kern/clock.h>
// Frame pacing (AdrenoDisplayPacing.h, FAILURES-AND-DESIGN.md 2026-10-20 F8): draw submissions complete inside
// submitIB, so its completion time is what the display can compare a copy with. The time is stored before the
// count is published (release); the display reads the count first (acquire). One clock read per IB.
extern "C" uint64_t gAdrenoIBCompleted, gAdrenoIBCompletedAt;
uint64_t gAdrenoIBCompleted, gAdrenoIBCompletedAt;
#endif
#if ADRENO_PERF_GPU
#if !ADRENO_PERF_FRAMES
#error "ADRENO_PERF_GPU needs ADRENO_PERF_FRAMES (the clock and the IB counters)"
#endif
// The perf gpu line (AdrenoX2.h): the monitor's CP poll ticks of every completed IB (its GPU execution, host counter
// units) and their maximum since the display last took it (exchange), and the mach time spent inside submitIB with
// fSubmitLock held and waiting for it. Relaxed totals: the display takes window deltas.
uint64_t gAdrenoIBGpuTicks, gAdrenoIBGpuTicksMax, gAdrenoIBSubmitTicks, gAdrenoIBLockTicks;
#endif
#ifndef ADRENO_LATCH
#define ADRENO_LATCH 0
#endif
#if ADRENO_LATCH
// --present-latch's copy gate (agents/input-latency FAILURE-MODES.md G1-G3): GPU submissions (IB, FILL32) that entered
// the kext and have not returned, waiting for fSubmitLock or running. AdrenoDisplay defers a fresh layer-0 copy while it
// is not 0. b12v11: WindowServer's swap can arrive before its frame's IB completes (ibaft 17-87 a window).
extern "C" uint64_t gAdrenoGPUBusy;
uint64_t gAdrenoGPUBusy;
struct AdrenoGPUBusy {
    AdrenoGPUBusy() { __atomic_fetch_add(&gAdrenoGPUBusy, 1, __ATOMIC_ACQ_REL); }
    ~AdrenoGPUBusy() { __atomic_fetch_sub(&gAdrenoGPUBusy, 1, __ATOMIC_ACQ_REL); }
};
#endif
#if ADRENO_PRESENT_SYNC
#include "AdrenoDisplaySync.h"
#include <kern/clock.h>
// --present-sync (agents/present-sync FAILURE-MODES.md K1, K5, K7): the IOSurfaces a GPU submission (IB, FILL32) writes,
// marked from before the fSubmitLock wait to the return, when the IB has retired and its FROM_DEVICE maintenance is
// done. AdrenoDisplay asks AdrenoPresentSyncQuery before it copies a layer-0 surface. The table's spin lock is held for
// a slot scan only and never together with fSubmitLock. Zero-initialized (__bss); the lock is made by configureDevice
// before any queue exists.
extern "C" void *AdrenoResourceIOSurface(const void *) __asm__("__ZNK13IOGPUResource12getIOSurfaceEv");
extern "C" uint32_t AdrenoIOSurfaceID(const void *) __asm__("__ZNK9IOSurface12getSurfaceIDEv");
static struct adreno_sync_table gAdrenoSyncTable;
static IOSimpleLock *gAdrenoSyncLock;
extern "C" uint32_t AdrenoPresentSyncQuery(uint32_t surfaceID, uint64_t *oldest)
{
    IOSimpleLock *lock = __atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE);
    if (oldest) *oldest = 0;
    if (!lock) return 0;
    IOSimpleLockLock(lock);
    const uint32_t writers = adreno_sync_query(&gAdrenoSyncTable, surfaceID, oldest);
    IOSimpleLockUnlock(lock);
    return writers;
}
extern "C" void AdrenoPresentSyncCounters(uint64_t *marks, uint64_t *overflows, uint64_t *unmatched)
{
    IOSimpleLock *lock = __atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE);
    *marks = *overflows = *unmatched = 0;
    if (!lock) return;
    IOSimpleLockLock(lock);
    *marks = gAdrenoSyncTable.marks; *overflows = gAdrenoSyncTable.overflows; *unmatched = gAdrenoSyncTable.unmatched;
    IOSimpleLockUnlock(lock);
}
// RAII: the constructor marks the distinct IOSurfaces of the list's Write entries; the destructor unmarks exactly them on
// every return path (K2). One clock read, and only when something is marked.
struct AdrenoSurfaceWrites {
    uint32_t ids[ADRENO_SYNC_IDS_PER_SUBMIT];
    unsigned n;
    bool wild;
    explicit AdrenoSurfaceWrites(AdrenoSegmentList *list) : n(0), wild(false)
    {
        IOSimpleLock *lock = __atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE);
        if (!lock || !list) return;
        const struct adreno_resource_list *r = list->presentSyncResources();
        for (uint64_t i = 0; r->entries && i < r->count; i++) {
            const struct adreno_resource_entry *e = &r->entries[i];
            if (!(e->usage & 2u) || !e->resource) continue;               // Write usage (adreno-resource-list.c)
            const void *surface = AdrenoResourceIOSurface(e->resource);
            const uint32_t id = surface ? AdrenoIOSurfaceID(surface) : 0;
            if (!id) continue;
            unsigned k = 0;
            while (k < n && ids[k] != id) k++;
            if (k < n) continue;
            if (n < ADRENO_SYNC_IDS_PER_SUBMIT) ids[n++] = id; else wild = true;
        }
        if (!n && !wild) return;
        const uint64_t now = mach_absolute_time();
        IOSimpleLockLock(lock);
        for (unsigned k = 0; k < n; k++) adreno_sync_mark(&gAdrenoSyncTable, ids[k], now);
        if (wild) adreno_sync_mark(&gAdrenoSyncTable, ADRENO_SYNC_WILDCARD, now);
        IOSimpleLockUnlock(lock);
    }
    ~AdrenoSurfaceWrites()
    {
        if (!n && !wild) return;
        IOSimpleLock *lock = __atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE);
        IOSimpleLockLock(lock);
        for (unsigned k = 0; k < n; k++) adreno_sync_unmark(&gAdrenoSyncTable, ids[k]);
        if (wild) adreno_sync_unmark(&gAdrenoSyncTable, ADRENO_SYNC_WILDCARD);
        IOSimpleLockUnlock(lock);
    }
#if ADRENO_PIPELINE
    // agents/gpu-pipeline D1: the IB stays in flight after the submission returns; its marks go to the flight's record
    // and are released at its retirement (AdrenoSyncUnmarkIDs), not here.
    void handTo(uint32_t *out, unsigned *count, bool *outWild)
    {
        for (unsigned k = 0; k < n; k++) out[k] = ids[k];
        *count = n; *outWild = wild;
        n = 0; wild = false;
    }
#endif
};
#if ADRENO_PIPELINE
static void AdrenoSyncUnmarkIDs(const uint32_t *ids, unsigned n, bool wild)
{
    if (!n && !wild) return;
    IOSimpleLock *lock = __atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE);
    if (!lock) return;
    IOSimpleLockLock(lock);
    for (unsigned k = 0; k < n; k++) adreno_sync_unmark(&gAdrenoSyncTable, ids[k]);
    if (wild) adreno_sync_unmark(&gAdrenoSyncTable, ADRENO_SYNC_WILDCARD);
    IOSimpleLockUnlock(lock);
}
#endif
#endif

#ifndef ADRENO_IB_ASYNC
#define ADRENO_IB_ASYNC 0
#endif
#if ADRENO_IB_ASYNC
#include "../../../../compat/adreno-ib-async.h"
// Asynchronous IB completion (compat/adreno-ib-async.h, agents/async-ib/FAILURE-MODES.md): a monitor built with
// SNAP_ADRENO_IB_ASYNC answers IB_POLL(0) with IDLE; then ibRing is IB_START and IB_POLLs with IODelay backoff, and the
// GPU's execution no longer holds the monitor's service token. Any other monitor keeps the synchronous ADRENO_GUEST_IB.
// Set once by configureGuestIB before the first IB; the counters change under fSubmitLock. Zero-initialized (__bss):
// no initialized data ahead of kmod_info.
static uint32_t gAdrenoIBAsync;
static struct adreno_ib_async_stats gAdrenoIBAsyncStats;
static void ibAsyncHVC(void *, uint64_t regs[4])
{
    register uint64_t x0 __asm__("x0") = regs[0];
    register uint64_t x1 __asm__("x1") = regs[1];
    register uint64_t x2 __asm__("x2") = regs[2];
    register uint64_t x3 __asm__("x3") = regs[3];
    // As ibRing: the arena stores are complete before the monitor cleans the package to PoC and rings it.
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    regs[0] = x0; regs[1] = x1; regs[2] = x2; regs[3] = x3;
}
static void ibAsyncDelay(void *, uint32_t us) { IODelay(us); }
#endif

#if ADRENO_GPU_RECOVER
#if !ADRENO_IB_ASYNC
#error "ADRENO_GPU_RECOVER needs ADRENO_IB_ASYNC (the monitor's RESET ends an asynchronous flight)"
#endif
#include <kern/clock.h>
#include "../../../../compat/adreno-recover-guest.h"
// agents/gpu-recovery: QUERY's answer (configureGuestIB, before the probe IB) and the un-latch state; changed under
// fSubmitLock afterwards. Zero-initialized (__bss): no initialized data ahead of kmod_info.
static struct adreno_recover_guest gAdrenoRecover;
static const struct adreno_recover_ops kAdrenoRecoverOps = {nullptr, ibAsyncHVC};
#endif

#if ADRENO_PIPELINE
#if !ADRENO_IB_ASYNC || !ADRENO_PRESENT_SYNC
#error "ADRENO_PIPELINE needs ADRENO_IB_ASYNC (IB_START/IB_POLL) and ADRENO_PRESENT_SYNC (the marks the display waits on)"
#endif
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include "AdrenoDisplayPipe.h"
// --pipeline (agents/gpu-pipeline FAILURE-MODES.md, findings 1-6): IOGPUFamily 26A428's exported event machine and
// completion kick, and two private offsets checked against the KDK's arm64e.kernel slice: the queue's current fence
// (queue+0x518, set at submit_command_buffer 0x4c710) and the fence's completion status (fence+0xc8, written at
// 0x4c834, read by IOGPUBlockFence::notifyClient at 0x2367c).
#include "AdrenoIOGPUStamps.h"   // the event machine's calls, checked by tools/test-adreno-iogpu-stamps.c on the KDK's code
extern "C" void AdrenoGPUSignalStampsUpdated(IOGPU *) __asm__("__ZN5IOGPU19signalStampsUpdatedEv");
extern "C" IOGPUTask *AdrenoDeviceGPUTask(const IOGPUDevice *) __asm__("__ZNK11IOGPUDevice10getGPUTaskEv");
static constexpr size_t kIOGPUQueueCurrentFenceOffset = 0x518;
static constexpr size_t kIOGPUFenceStatusOffset = 0xc8;
#if !ADRENO_GPU_RECOVER
static constexpr uint32_t kIOGPUSubmissionErrorKext = 0xa;   // what processSegmentKernelCommand sets today
#endif
#define ADRENO_PIPE_RECORDS 8u
// One pipelined IB's kernel side: its list (retained while in flight), the command buffer's fence (retained, for
// an asynchronous failure's status), the present-sync marks handed over at the submission's return, its stamp.
struct AdrenoAcceleratorX2::AdrenoFlightRecord {
    AdrenoSegmentList *list;
    IOGPUCommandQueue *queue;     // during the submission only: its event takes the stamp
    OSObject *fence;
    uint32_t ids[ADRENO_SYNC_IDS_PER_SUBMIT];
    unsigned nids;
    bool wild;
    uint32_t stamp, busy;
    int result;
};
// The display's perf pipe line reads the engine's counters (AdrenoDisplayPipe.h order; relaxed, window deltas there).
static const struct adreno_pipe_stats *gAdrenoPipeStats;
static uint32_t gAdrenoPipeState;               // bit 0 on, bits 8-15 adreno_pipeline
extern "C" uint32_t AdrenoPipelineCounters(uint64_t *v)
{
    const struct adreno_pipe_stats *s = __atomic_load_n(&gAdrenoPipeStats, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < ADRENO_PIPE_COUNTERS; i++) v[i] = 0;
    if (s) {
        v[ADRENO_PIPE_C_FLIGHTS] = __atomic_load_n(&s->flights, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_OVERLAPPED] = __atomic_load_n(&s->overlapped, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_IMMEDIATE] = __atomic_load_n(&s->immediate, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_SYNC] = __atomic_load_n(&s->sync_ibs, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_FOLDED] = __atomic_load_n(&s->folded, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_DRAINS] = __atomic_load_n(&s->drains, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_TIMER] = __atomic_load_n(&s->timer_finishes, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_POLLS] = __atomic_load_n(&s->polls, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_SPIN_US] = __atomic_load_n(&s->spin_us, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_GAP_US] = __atomic_load_n(&s->gap_us, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_GAP_N] = __atomic_load_n(&s->gap_n, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_MAX_US] = __atomic_load_n(&s->flight_max_us, __ATOMIC_RELAXED);
        v[ADRENO_PIPE_C_FAILURES] = __atomic_load_n(&s->failures, __ATOMIC_RELAXED);
    }
    return __atomic_load_n(&gAdrenoPipeState, __ATOMIC_RELAXED);
}
#if ADRENO_PRESENT_RELATCH
// agents/present-pacing (FAILURE-MODES.md UR1 UR2, EP1-EP3, OP1). AdrenoDisplay sets gAdrenoPresentUrgent while a
// relatch waits for a mark: the completion timer then polls every adreno_pipeline_urgent_us. gAdrenoPipeEarly holds the
// early-release switches (adreno_pipe_early, adreno_pipe_assist_us) and totals, changed under fSubmitLock and read
// relaxed by the perf relatch line. Zero-initialized (__bss): no initialized data ahead of kmod_info.
extern "C" uint32_t gAdrenoPresentUrgent;
uint32_t gAdrenoPresentUrgent;
static struct adreno_pipe_early gAdrenoPipeEarly;
static uint64_t gAdrenoPipeUrgentTicks;
extern "C" uint32_t AdrenoPipelineEarlyCounters(uint64_t *v)
{
    v[0] = __atomic_load_n(&gAdrenoPipeEarly.pre, __ATOMIC_RELAXED);
    v[1] = __atomic_load_n(&gAdrenoPipeEarly.assisted, __ATOMIC_RELAXED);
    v[2] = __atomic_load_n(&gAdrenoPipeEarly.assist_polls, __ATOMIC_RELAXED);
    v[3] = __atomic_load_n(&gAdrenoPipeEarly.unmarks, __ATOMIC_RELAXED);
    return (__atomic_load_n(&gAdrenoPipeEarly.on, __ATOMIC_RELAXED) ? 1u : 0u) |
           (__atomic_load_n(&gAdrenoPipeUrgentTicks, __ATOMIC_RELAXED) ? 2u : 0u);
}
#endif
#endif

OSDefineMetaClassAndStructors(AdrenoEventMachine, IOGPUEventMachine)
OSDefineMetaClassAndStructors(AdrenoSysMemory, IOGPUSysMemory)
OSDefineMetaClassAndStructors(AdrenoResource, IOGPUResource)
OSDefineMetaClassAndStructors(AdrenoMemoryMap, IOGPUMemoryMap)
OSDefineMetaClassAndStructors(AdrenoTask, IOGPUTask)
OSDefineMetaClassAndStructors(AdrenoSegmentList, IOGPUSegmentResourceList)
OSDefineMetaClassAndStructors(AdrenoCommandQueue, IOGPUCommandQueue)
OSDefineMetaClassAndStructors(AdrenoAcceleratorX2, IOGPU)

// ---------------------------------------------------------------------------------------------------
// Event machine: stamps exist (so user space can map them) but nothing writes them in stage 2.
void AdrenoEventMachine::writeStamp(int, vendevtCommandRec *, unsigned int) {}
void AdrenoEventMachine::prepareBarrier(vendevtBarrierRec *) const {}
void AdrenoEventMachine::completeBarrier(vendevtBarrierRec *) const {}
void AdrenoEventMachine::writeBarrierElement(vendevtBarrierRec *, int, unsigned int) const {}

// ---------------------------------------------------------------------------------------------------
void AdrenoResource::calculateIOSurfaceDeviceCacheVRAMBytes(unsigned long long *bytes)
{
    if (bytes) *bytes = 0;
}

IOMemoryDescriptor *AdrenoResource::getApertureMemoryDescriptor(unsigned long long *)
{
    return nullptr;   // same as AGXResource::getApertureMemoryDescriptor
}

// ---------------------------------------------------------------------------------------------------
// Resource mapping and descriptor lifetime are implemented in AdrenoMemoryMap.cpp.

// ---------------------------------------------------------------------------------------------------
// WindowServer, by two entitlements only it holds among 26A428's GPU and IOMFB clients (SkyLight's
// WindowServer; IOMFB_bics_daemon, IOMFBDiagnose and IOMFB_FDR_Loader share its iomfb.set-block, not these).
static bool entitled(task_t owner, const char *name)
{
    OSObject *value = IOUserClient::copyClientEntitlement(owner, name);
    bool yes = value == kOSBooleanTrue;
    OSSafeReleaseNULL(value);
    return yes;
}
static bool isWindowServer(task_t owner)
{
    return owner != kernel_task && entitled(owner, "com.apple.QuartzCore.secure-mode") &&
           entitled(owner, "com.apple.private.gpuwrangler");
}
static uint32_t gWindowServerTasks;

AdrenoTask *AdrenoTask::withTask(IOGPU *gpu, task_t owner, IORangeAllocator *allocator)
{
    if (!gpu || !owner || !allocator) return nullptr;
    AdrenoTask *t = OSTypeAlloc(AdrenoTask);
    // Native IOGPUTask retains this shared allocator and releases it in free().
    // Never seed a second free list: CB0 is shared by user and kernel tasks.
    if (t && !t->init(gpu, owner, 1, &allocator)) {
        t->release();
        t = nullptr;
    }
    if (t && AdrenoEarlyStopEnabled() && isWindowServer(owner)) {
        t->fWindowServer = true;
        t->fSequence = __atomic_add_fetch(&gWindowServerTasks, 1, __ATOMIC_RELAXED);
    }
#if ADRENO_PIPELINE
    if (t) t->fPipelineClient = isWindowServer(owner);   // agents/gpu-pipeline R4: adreno_pipeline=1 pipelines these
#endif
    return t;
}

uint64_t AdrenoTask::allocate(IOGPUMemoryMap *map)
{
    uint64_t va = IOGPUTask::allocate(map);
    if (va && __atomic_load_n(&fAllocations, __ATOMIC_RELAXED) != UINT32_MAX)
        __atomic_add_fetch(&fAllocations, 1, __ATOMIC_RELAXED);
    return va;
}

void AdrenoTask::free()
{
    // WindowServer keeps its GPU device while it runs; its task going away after it allocated is the process
    // ending. A device it opened only to probe never allocates and never counts.
    uint32_t allocations = __atomic_load_n(&fAllocations, __ATOMIC_RELAXED);
    if (fWindowServer && allocations)
        AdrenoEarlyStopClientDied((uint64_t)fSequence << 32 | allocations);
    IOGPUTask::free();
}

// ---------------------------------------------------------------------------------------------------
AdrenoCommandQueue *AdrenoCommandQueue::withAccelerator(AdrenoAcceleratorX2 *accelerator)
{
    if (!accelerator) return nullptr;
    auto *queue = OSTypeAlloc(AdrenoCommandQueue);
    if (queue) { queue->fAccelerator = accelerator; accelerator->retain(); }
    return queue; // native IOGPU initializes the queue afterwards
}
void AdrenoCommandQueue::free()
{
    OSSafeReleaseNULL(fAccelerator);
    IOGPUCommandQueue::free();
}
struct AdrenoFenceContext {
    AdrenoAcceleratorX2 *accelerator;
    IOGPUSegmentResourceList *list;
#if ADRENO_PIPELINE
    IOGPUCommandQueue *queue;
#endif
};
int AdrenoCommandQueue::fence(void *context)
{
    auto *submission=static_cast<AdrenoFenceContext *>(context);
    return submission->accelerator ? submission->accelerator->submitFence(
        OSDynamicCast(AdrenoSegmentList,submission->list)) : ADRENO_SUBMIT_E_INACTIVE;
}
int AdrenoCommandQueue::fill(void *context, const struct adreno_fill32_request *request)
{
    auto *submission=static_cast<AdrenoFenceContext *>(context);
    return submission->accelerator ? submission->accelerator->submitFill(
        OSDynamicCast(AdrenoSegmentList,submission->list),request) : ADRENO_SUBMIT_E_INACTIVE;
}
int AdrenoCommandQueue::ib(void *context, const void *command, uint64_t bytes)
{
    auto *submission=static_cast<AdrenoFenceContext *>(context);
#if ADRENO_PIPELINE
    return submission->accelerator ? submission->accelerator->submitIB(
        OSDynamicCast(AdrenoSegmentList,submission->list),command,bytes,submission->queue) : ADRENO_SUBMIT_E_INACTIVE;
#else
    return submission->accelerator ? submission->accelerator->submitIB(
        OSDynamicCast(AdrenoSegmentList,submission->list),command,bytes) : ADRENO_SUBMIT_E_INACTIVE;
#endif
}
IOGPUSegmentResourceList *AdrenoCommandQueue::parseSegmentList(IOGPUDevice *device,
                                                               IOGPUSegmentResourceListHeader const *header,
                                                               IOGPUDeviceShmem *shmem)
{
    AdrenoSegmentList *list = OSTypeAlloc(AdrenoSegmentList);
    if (list && !list->initWithSharedResourceList(device, header, shmem)) {
        list->release();
        list = nullptr;
    }
    return list;   // +1; IOGPUCommandQueue::processCommandBuffer releases it
}

void AdrenoCommandQueue::processSegmentKernelCommand(IOGPUSegmentResourceList *list, IOGPUKernelCommand const *command,
                                                     IOGPUKernelCommand const *end, unsigned char const *segmentStart,
                                                     unsigned char const *segmentEnd,
                                                     IOGPUCommandQueueCommandBufferArgs const *args)
{
    uintptr_t start = reinterpret_cast<uintptr_t>(command), limit = reinterpret_cast<uintptr_t>(end);
#if ADRENO_PIPELINE
    AdrenoFenceContext submission={fAccelerator,list,this};
#else
    AdrenoFenceContext submission={fAccelerator,list};
#endif
    // FENCE, FILL32 and ADRENO_KCMD_IB, decoded by the same pure-C dispatcher the host tests drive.
    const struct adreno_kernel_ops ops={&submission,fence,fill,ib};
    int result = adreno_kernel_command(command, limit >= start ? limit-start : 0, &ops);
    if (result == ADRENO_SUBMIT_GENERIC) {
        IOGPUCommandQueue::processSegmentKernelCommand(list, command, end, segmentStart, segmentEnd, args);
        return;
    }
    if (result) {
        // Native IOGPU uses 0xa for malformed/unsupported kernel commands; the command buffer then completes
        // with an error status instead of Completed (4).
        if (result==ADRENO_SUBMIT_E_UNCERTAIN || result==ADRENO_LIST_E_VISIBILITY) {
            // Retirement or CPU visibility could not be established. Preserve
            // preparation ownership before native queue cleanup drops list.
            if (auto *resources=OSDynamicCast(AdrenoSegmentList,list))
                resources->retainAfterTimeout();
        }
#if ADRENO_GPU_RECOVER
        // R26: the guilty command buffer of a reset gets IOGPU's hang status (3, 0xb after a fault; IOGPU counts the
        // strike), one refused while latched is a victim (5); everything else keeps 0xa.
        setSubmissionError(fAccelerator ? fAccelerator->recoverStatus(result) : 0xa);
#else
        setSubmissionError(0xa);
#endif
        if (fAccelerator) fAccelerator->noteCommandFailure(result);
        else ALOG("command submission failed %d", result);
    }
}

// ---------------------------------------------------------------------------------------------------
bool AdrenoAcceleratorX2::configureDevice(IOService *provider)
{
    // Called by IOGPU::start before the config and the event machine exist.
    if (fGPUVA || fStamps || fMapper || fSubmitLock) return false;
    if (!provider || !provider->metaCast("AppleARMIODevice")) {
        ALOG("Adreno device provider missing");
        return false;
    }
    OSData *chip = OSDynamicCast(OSData, provider->getProperty("chip-id"));
    OSData *parent = OSDynamicCast(OSData, provider->getProperty("iommu-parent"));
    OSData *fence = OSDynamicCast(OSData, provider->getProperty(ADRENO_GUEST_PROPERTY));
    OSData *unmap = OSDynamicCast(OSData, provider->getProperty(ADRENO_GUEST_UNMAP_PROPERTY));
    OSData *cache = OSDynamicCast(OSData, provider->getProperty(ADRENO_GUEST_CACHE_PROPERTY));
    OSData *fill = OSDynamicCast(OSData, provider->getProperty(ADRENO_GUEST_FILL32_PROPERTY));
    uint32_t chipID = 0, mapperID = 0, fenceABI = 0, unmapABI = 0, cacheABI = 0;
    uint32_t fillABI = 0;
    if (chip && chip->getLength() == sizeof(chipID))
        bcopy(chip->getBytesNoCopy(), &chipID, sizeof(chipID));
    if (parent && parent->getLength() == sizeof(mapperID))
        bcopy(parent->getBytesNoCopy(), &mapperID, sizeof(mapperID));
    if (fence && fence->getLength() == sizeof(fenceABI))
        bcopy(fence->getBytesNoCopy(), &fenceABI, sizeof(fenceABI));
    if (unmap && unmap->getLength() == sizeof(unmapABI))
        bcopy(unmap->getBytesNoCopy(), &unmapABI, sizeof(unmapABI));
    if (cache && cache->getLength() == sizeof(cacheABI))
        bcopy(cache->getBytesNoCopy(), &cacheABI, sizeof(cacheABI));
    if (fill && fill->getLength() == sizeof(fillABI))
        bcopy(fill->getBytesNoCopy(), &fillABI, sizeof(fillABI));
    if (chipID != 0x44070041 || !mapperID || fenceABI != ADRENO_GUEST_ABI ||
        unmapABI != ADRENO_GUEST_ABI || cacheABI != ADRENO_GUEST_ABI || fillABI != ADRENO_GUEST_ABI) {
        ALOG("unqualified Adreno chip, mapper identity or guest fence/clear/cache/fill ABI");
        return false;
    }
#if ADRENO_VA_WIDE
    // agents/gpu-va-wide V12: the 16 GiB window needs the wide monitor and tree; only that tree names the width.
    OSData *bits = OSDynamicCast(OSData, provider->getProperty(ADRENO_GPU_VA_BITS_PROPERTY));
    uint32_t vaBits = 0;
    if (bits && bits->getLength() == sizeof(vaBits))
        bcopy(bits->getBytesNoCopy(), &vaBits, sizeof(vaBits));
    if (vaBits != 64 - ADRENO_CB0_T0SZ) {
        ALOG("GPU VA width %u in the tree, %u in this kext: a wide kext needs the wide monitor", vaBits,
             64 - ADRENO_CB0_T0SZ);
        return false;
    }
#endif
    AdrenoEarlyStopConfigure(provider);   // opt-in per launch; otherwise inert
    // Resolve only this node's iommu-parent. No system-mapper fallback.
    fMapper = IOMapper::copyMapperForDevice(provider);
    if (!fMapper || fMapper->getPageSize() != kAdrenoGPUVAAlign) {
        ALOG("Adreno mapper missing or unsupported page size");
        OSSafeReleaseNULL(fMapper);
        return false;
    }
    // Native tasks have independent locks. The common CB0 free list needs its
    // own lock, and is populated once for the lifetime of this accelerator.
    fGPUVA = IORangeAllocator::withRange(0, kAdrenoGPUVAAlign, 0, IORangeAllocator::kLocking);
    if (!fGPUVA) {
        ALOG("GPU address allocator creation failed");
        OSSafeReleaseNULL(fMapper);
        return false;
    }
    fGPUVA->deallocate(kAdrenoGPUVABase, kAdrenoGPUVASize);
    const size_t len = round_page(ADRENO_NUM_STAMPS * ADRENO_STAMP_BYTES);
    fStamps = IOBufferMemoryDescriptor::withOptions(kIODirectionInOut | kIOMemoryKernelUserShared, len, page_size);
    if (!fStamps) {
        ALOG("stamp page allocation failed");
        OSSafeReleaseNULL(fGPUVA);
        OSSafeReleaseNULL(fMapper);
        return false;
    }
    bzero(fStamps->getBytesNoCopy(), fStamps->getLength());
#if ADRENO_PRESENT_SYNC
    if (!__atomic_load_n(&gAdrenoSyncLock, __ATOMIC_ACQUIRE)) {
        IOSimpleLock *lock = IOSimpleLockAlloc();     // kept for the boot: the display may ask at any time
        __atomic_store_n(&gAdrenoSyncLock, lock, __ATOMIC_RELEASE);
        ALOG("present sync: %s", lock ? "IB and FILL32 mark the IOSurfaces they write" : "no lock, nothing marked");
    }
#endif
    fSubmitLock = IOLockAlloc();
    bool ready = fSubmitLock && prepareStampDMA() && !probeGuestFence();
    if (ready) {
        configureGuestIB(provider);   // optional; only an UNCERTAIN IB probe (latched) stops the device
        ready = !fStampCleanupFailed;
    }
    if (!ready) {
        if (releaseIBArena() && releaseStampDMA()) {
            freeIBWork();
            OSSafeReleaseNULL(fStamps);
            OSSafeReleaseNULL(fGPUVA);
            OSSafeReleaseNULL(fMapper);
        }
        if (fSubmitLock) { IOLockFree(fSubmitLock); fSubmitLock = nullptr; }
        return false;
    }
    ALOG("device mapper 0x%x bound, page size 0x%llx", mapperID, kAdrenoGPUVAAlign);
    return true;
}

// ---------------------------------------------------------------------------------------------------
// Draw submission (design 3.4-3.6). Everything here is optional: without the monitor's IB ABI, or when the
// arena or the probe fails before a doorbell, the device starts with FENCE/FILL32 only and without the
// "AdrenoIBABI" property, so the plug-in keeps refusing render pipelines (explicitly).
static int guestCacheRange(uint64_t address, uint64_t bytes, unsigned direction)
{
    register uint64_t x0 __asm__("x0") = ADRENO_GUEST_CACHE;
    register uint64_t x1 __asm__("x1") = address;
    register uint64_t x2 __asm__("x2") = bytes;
    register uint64_t x3 __asm__("x3") = direction;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    return (x0 || x1 != bytes || x2) ? -1 : 0;
}

bool AdrenoAcceleratorX2::allocateIBWork()
{
    if (fIB) return false;
    fIB = static_cast<struct adreno_ib_work *>(IOMalloc(sizeof(*fIB)));
    fIBTables = static_cast<struct adreno_ib_tables *>(IOMalloc(sizeof(*fIBTables)));
    fIBRelocs = static_cast<struct adreno_ib_reloc *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBRelocs)));
    fIBOrder = static_cast<uint16_t *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBOrder)));
    fIBUsed = static_cast<uint8_t *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBUsed)));
    fIBTargets = static_cast<uint64_t *>(IOMalloc(ADRENO_IB_TARGET_WORDS * sizeof(*fIBTargets)));
    if (!fIB || !fIBTables || !fIBRelocs || !fIBOrder || !fIBUsed || !fIBTargets) return false;
    bzero(fIB, sizeof(*fIB));   // state 0: every submission is refused until adreno_ib_work_init
    int error = adreno_ib_tables_init(fIBTables);
    if (error) ALOG("IB allowlist tables inconsistent (%d): regenerate AdrenoA8xxRegs.h / adreno-ib-tables.h", error);
    return !error;
}

void AdrenoAcceleratorX2::freeIBWork()
{
    if (fIB) IOFree(fIB, sizeof(*fIB));
    if (fIBTables) IOFree(fIBTables, sizeof(*fIBTables));
    if (fIBRelocs) IOFree(fIBRelocs, ADRENO_IB_MAX_RELOCS * sizeof(*fIBRelocs));
    if (fIBOrder) IOFree(fIBOrder, ADRENO_IB_MAX_RELOCS * sizeof(*fIBOrder));
    if (fIBUsed) IOFree(fIBUsed, ADRENO_IB_MAX_RELOCS * sizeof(*fIBUsed));
    if (fIBTargets) IOFree(fIBTargets, ADRENO_IB_TARGET_WORDS * sizeof(*fIBTargets));
    fIB = nullptr; fIBTables = nullptr; fIBRelocs = nullptr; fIBOrder = nullptr; fIBUsed = nullptr; fIBTargets = nullptr;
#if ADRENO_PIPELINE
    pipelineFreeSlot1();
#endif
}

// Kernel-only and GPU-read-only: kIODirectionOut makes the device mapper map the arena without write access
// (INFERRED for the 26A428 IODARTMapper; the monitor requires a no-write leaf for every package page, so a wrong
// guess is refused by the start-time probe with ADRENO_E_TARGET before any doorbell).
bool AdrenoAcceleratorX2::prepareIBArena()
{
    if (!fGPUVA || !fMapper || !fIB || fIBArena || fIBDMA || fStampCleanupFailed) return false;
#if ADRENO_PIPELINE
    const uint64_t length = ADRENO_PIPE_ARENA_BYTES;   // agents/gpu-pipeline Q2: two [zero page][package] slots
#else
    const uint64_t length = ADRENO_IB_ARENA_BYTES;
#endif
    fIBArena = IOBufferMemoryDescriptor::withOptions(kIODirectionOut, length, kAdrenoGPUVAAlign);
    if (!fIBArena) {
        ALOG("IB arena allocation failed");
        return false;
    }
    bzero(fIBArena->getBytesNoCopy(), length);
    IOReturn result = fIBArena->prepare(kIODirectionOut);
    if (result != kIOReturnSuccess) {
        ALOG("IB arena wiring failed: 0x%x", result);
        return false;
    }
    fIBWired = true;
    fIBDMA = IODMACommand::withSpecification(kIODMACommandOutputHost64, 32, length,
        IODMACommand::kMapped, length, kAdrenoGPUVAAlign, fMapper);
    if (!fIBDMA) {
        ALOG("IB arena DMA command allocation failed");
        return false;
    }
    result = fIBDMA->setMemoryDescriptor(fIBArena, false);
    if (result != kIOReturnSuccess) {
        ALOG("IB arena DMA descriptor failed: 0x%x", result);
        return false;
    }
    result = fIBDMA->prepare(0, length);
    fIBDMAActive = fIBDMA->getPreparedOffsetAndLength(nullptr, nullptr) == kIOReturnSuccess;
    if (result != kIOReturnSuccess || !fIBDMAActive) {
        ALOG("IB arena DMA preparation failed: 0x%x", result);
        return false;
    }
    IODMACommand::Segment64 segment = {};
    UInt64 offset = 0;
    UInt32 count = 1;
    result = fIBDMA->gen64IOVMSegments(&offset, &segment, &count);
    if (result != kIOReturnSuccess || count != 1 || offset != length || segment.fLength != length ||
        segment.fIOVMAddr < kAdrenoGPUVABase || segment.fIOVMAddr >= ADRENO_WINDOW_END ||
        segment.fIOVMAddr % kAdrenoGPUVAAlign || length > ADRENO_WINDOW_END - segment.fIOVMAddr) {
        ALOG("IB arena segment rejected: result 0x%x, count %u, offset 0x%llx, address 0x%llx, length 0x%llx",
             result, count, offset, segment.fIOVMAddr, segment.fLength);
        return false;
    }
    if (!fGPUVA->allocateRange(segment.fIOVMAddr, length)) {
        ALOG("IB arena address collides with shared task allocator");
        return false;
    }
    fIBGPUAddress = segment.fIOVMAddr;
    fIBGPULength = length;
#if ADRENO_PIPELINE
    int error = adreno_ib_work_init(fIB, fIBTables, static_cast<uint8_t *>(fIBArena->getBytesNoCopy()), fIBGPUAddress,
                                    ADRENO_PIPE_SLOT_BYTES, fIBRelocs, fIBOrder, fIBUsed, ADRENO_IB_MAX_RELOCS, fIBTargets);
#else
    int error = adreno_ib_work_init(fIB, fIBTables, static_cast<uint8_t *>(fIBArena->getBytesNoCopy()), fIBGPUAddress,
                                    length, fIBRelocs, fIBOrder, fIBUsed, ADRENO_IB_MAX_RELOCS, fIBTargets);
#endif
    if (error) {
        ALOG("IB work binding refused %d", error);
        return false;
    }
    ALOG("IB arena mapped: address 0x%llx, length 0x%llx", fIBGPUAddress, fIBGPULength);
    return true;
}

bool AdrenoAcceleratorX2::releaseIBArena()
{
    // A package the CP may still fetch keeps its arena, mapping and address until reboot (fail-fast leak).
    if (fStampCleanupFailed || (fIB && (fIB->state & ADRENO_IB_STATE_UNCERTAIN))) return false;
#if ADRENO_PIPELINE
    if (fIB2 && (fIB2->state & ADRENO_IB_STATE_UNCERTAIN)) return false;
    if (fIB2) fIB2->state = 0;
#endif
    IOReturn result = kIOReturnSuccess;
    if (fIB) fIB->state = 0;
    if (fIBDMAActive) {
        result = fIBDMA->complete();
        fIBDMAActive = false;
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("IB arena DMA completion failed: 0x%x; retaining resources", result);
            return false;
        }
    }
    if (fIBDMA) {
        result = fIBDMA->clearMemoryDescriptor(false);
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("IB arena DMA descriptor cleanup failed: 0x%x; retaining resources", result);
            return false;
        }
        OSSafeReleaseNULL(fIBDMA);
    }
    if (fIBGPUAddress) {
        fGPUVA->deallocate(fIBGPUAddress, fIBGPULength);
        fIBGPUAddress = 0;
        fIBGPULength = 0;
    }
    if (fIBWired) {
        result = fIBArena->complete(kIODirectionOut);
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("IB arena unwiring failed: 0x%x; retaining backing", result);
            return false;
        }
        fIBWired = false;
    }
    OSSafeReleaseNULL(fIBArena);
    return true;
}

void AdrenoAcceleratorX2::configureGuestIB(IOService *provider)
{
    OSData *abi = OSDynamicCast(OSData, provider->getProperty(ADRENO_GUEST_IB_PROPERTY));
    uint32_t ibABI = 0;
    if (abi && abi->getLength() == sizeof(ibABI)) bcopy(abi->getBytesNoCopy(), &ibABI, sizeof(ibABI));
    if (ibABI != ADRENO_GUEST_IB_ABI) {
        ALOG("monitor has no guest IB ABI (%u): draw submission off", ibABI);
        return;
    }
    if (!allocateIBWork() || !prepareIBArena()) {
        ALOG("IB arena unavailable: draw submission off");
        if (releaseIBArena()) freeIBWork();
        return;
    }
    // R1: the zero page (border colours, empty bindless sets) reaches PoC once; the GPU never snoops it.
    uint64_t va = 0, dwords = 0, bytes = 0;
    int error = guestCacheRange(fIBGPUAddress, ADRENO_IB_ZERO_BYTES, ADRENO_CACHE_TO_DEVICE);
    if (!error) error = adreno_ib_probe(fIB, &va, &dwords, &bytes);
    if (error) {
        ALOG("IB zero page or probe package refused %d: draw submission off", error);
        if (releaseIBArena()) freeIBWork();   // nothing reached the ring
        return;
    }
#if ADRENO_IB_ASYNC
    {
        const struct adreno_ib_async_ops ops = {nullptr, ibAsyncHVC, ibAsyncDelay};
        gAdrenoIBAsync = adreno_ib_async_probe(&ops) ? 1 : 0;
        ALOG("IB completion: %s", gAdrenoIBAsync ? "asynchronous (monitor IB_START/IB_POLL, waits off its token)"
                                                 : "synchronous (the monitor answers no IB_POLL)");
    }
#endif
#if ADRENO_GPU_RECOVER
    if (gAdrenoIBAsync && adreno_recover_guest_probe(&kAdrenoRecoverOps, &gAdrenoRecover))
        ALOG("GPU recovery: monitor level %u, hard IB limit %u s (async bound %llu us), epoch %llu%s", gAdrenoRecover.level,
             gAdrenoRecover.hard_s, adreno_recover_guest_limit_us(&gAdrenoRecover), gAdrenoRecover.epoch,
             gAdrenoRecover.dead ? ", gave up" : "");
    else
        ALOG("GPU recovery: the monitor has none (QUERY refused): a GPU latch lasts the boot");
#endif
    struct adreno_ib_reply reply = {};
    ibRing(this, va, dwords, bytes, &reply);
    fIB->reply = reply;
    int result = adreno_ib_classify(&reply);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN) {
        fIB->state |= ADRENO_IB_STATE_UNCERTAIN;
        fStampCleanupFailed = true;   // as the fence probe: keep every DMA mapping until reboot
        ALOG("IB probe uncertain status=%lld marker=0x%llx ticks=%llu wptr=%llu; retaining DMA",
             reply.status, reply.marker, reply.ticks, reply.wptr);
        return;
    }
    if (result) {
        ALOG("IB probe refused status=%lld (%s): draw submission off", reply.status,
             result == ADRENO_IB_E_GPU_ERROR ? "GPU error after completion, GPU idle" : "before any ring write");
        if (releaseIBArena()) freeIBWork();   // refused, or retired and idle: the arena is not referenced
        return;
    }
    setProperty(ADRENO_IB_REGISTRY_PROPERTY, (unsigned long long)ADRENO_GUEST_IB_ABI, 32);
    setProperty("AdrenoIBCopyABI", (unsigned long long)1, 32);
    ALOG("IB probe completed: package 0x%llx, marker 0x%llx, ticks %llu, wptr %llu", va, reply.marker,
         reply.ticks, reply.wptr);
#if ADRENO_IB_ASYNC
    if (gAdrenoIBAsync)
        ALOG("IB probe through IB_START/IB_POLL: %llu pending, %llu polls, %llu us waited", gAdrenoIBAsyncStats.pending,
             gAdrenoIBAsyncStats.polls, gAdrenoIBAsyncStats.waited_us);
#endif
#if ADRENO_PIPELINE
    if (gAdrenoIBAsync && !pipelineBindSlot1())
        ALOG("pipeline: second package slot unavailable; IB submissions stay synchronous");
#endif
}

int AdrenoAcceleratorX2::probeGuestFence()
{
    // Probe padding after the public stamp slots, before publishing the device.
    const uint64_t offset = ADRENO_NUM_STAMPS * ADRENO_STAMP_BYTES;
    const uint32_t value = 0x534e5001;
    if (!fStampDMAActive || !fStampGPUAddress || fStampGPULength < offset + sizeof(value))
        return ADRENO_SUBMIT_E_INACTIVE;
    volatile uint32_t *probe = reinterpret_cast<volatile uint32_t *>(
        static_cast<uint8_t *>(fStamps->getBytesNoCopy()) + offset);
    *probe = ~value;
    register uint64_t x0 __asm__("x0") = ADRENO_GUEST_FENCE;
    register uint64_t x1 __asm__("x1") = fStampGPUAddress + offset;
    register uint64_t x2 __asm__("x2") = value;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    uint32_t observed = *probe;
    // Ring-wrap aware (design S1): x3 is the new WPTR and moves backwards across a wrap, so it is only
    // logged. Only refusals that precede every ring write are clean; the monitor reports a doorbell dropped
    // after a wrap's padding (or after the fence words) as ADRENO_E_RING or ADRENO_E_FENCE, so those, like
    // any unknown status or inconsistent reply, are UNCERTAIN.
    int result = adreno_fence_classify((int64_t)x0, x1, value, observed);
    if (result == ADRENO_SUBMIT_E_UNCERTAIN) {
        // A failed poll does not prove the CP is stopped. Keep this IOVA and
        // its backing until reboot, including when IOGPU calls free().
        fStampCleanupFailed = true;
        ALOG("guest fence failed status=0x%llx reply=0x%llx observed=0x%x ticks=%llu wptr=%llu; retaining DMA",
             x0, x1, observed, x2, x3);
        return result;
    }
    if (result) {
        ALOG("guest fence refused before any ring write status=%lld wptr=%llu", (int64_t)x0, x3);
        return result;
    }
    if (!fSubmittedFences)
        ALOG("GPU fence verified iova=0x%llx value=0x%x ticks=%llu wptr=%llu",
             fStampGPUAddress + offset, observed, x2, x3);
    return 0;
}

int AdrenoAcceleratorX2::fenceWork(void *context)
{
    // 0, ADRENO_SUBMIT_E_INACTIVE (the list completes without FROM_DEVICE and is not frozen) or UNCERTAIN.
    return static_cast<AdrenoAcceleratorX2 *>(context)->probeGuestFence();
}
struct AdrenoGatedSubmission {
    AdrenoAcceleratorX2 *accelerator;
    AdrenoSegmentList *list;
    const struct adreno_fill32_request *fill;
    const void *command;
    uint64_t bytes;
};
int AdrenoAcceleratorX2::fenceGated(void *context)
{
    auto *s = static_cast<AdrenoGatedSubmission *>(context);
    return s->list->submit(fenceWork, s->accelerator);
}
int AdrenoAcceleratorX2::fillGated(void *context)
{
    auto *s = static_cast<AdrenoGatedSubmission *>(context);
    return s->list->fill(s->fill, fillWork, s->accelerator);
}
int AdrenoAcceleratorX2::ibGated(void *context)
{
    auto *s = static_cast<AdrenoGatedSubmission *>(context);
    return s->list->ib(s->accelerator->fIB, s->command, s->bytes, ibRing, s->accelerator);
}
int AdrenoAcceleratorX2::submitFence(AdrenoSegmentList *resources)
{
    if (!resources) return ADRENO_LIST_E_ARGUMENT;
    if (!fSubmitLock) return ADRENO_SUBMIT_E_INACTIVE;
    IOLockLock(fSubmitLock);
#if ADRENO_GPU_RECOVER
    recoverLatched();
#endif
#if ADRENO_PIPELINE
    // agents/gpu-pipeline Q3: with an IB in flight the FENCE folds into it: its list is validated, nothing is rung; the
    // command buffer completes through the queue event, which holds the flight's stamp.
    if (fPipeOn && !fStampCleanupFailed && adreno_pipe_fold(&fPipe)) {
        const int folded = resources->pipelineValidate();
        IOLockUnlock(fSubmitLock);
        return folded;
    }
#endif
    AdrenoGatedSubmission submission = {this, resources, nullptr, nullptr, 0};
    // Fail-fast: after an UNCERTAIN/VISIBILITY result no FENCE, FILL32 or IB reaches the monitor again.
    int result = adreno_submit_gated(&fStampCleanupFailed, fenceGated, &submission);
    if (!result) fSubmittedFences++;
    IOLockUnlock(fSubmitLock);
    return result;
}

int AdrenoAcceleratorX2::fillWork(void *, uint64_t address, uint64_t bytes, uint32_t pattern)
{
    register uint64_t x0 __asm__("x0")=ADRENO_GUEST_FILL32;
    register uint64_t x1 __asm__("x1")=address;
    register uint64_t x2 __asm__("x2")=bytes;
    register uint64_t x3 __asm__("x3")=pattern;
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    int64_t status=(int64_t)x0;
    if (!status) return x1==bytes ? 0 : ADRENO_FILL32_E_UNCERTAIN;
    // Only these documented helper refusals precede a possible doorbell.
    // Unknown status or an inconsistent error reply retains ownership.
    if (x1) return ADRENO_FILL32_E_UNCERTAIN;
    switch (status) {
    case ADRENO_E_PARAMS: case ADRENO_E_WINDOW: case ADRENO_E_TARGET:
    case ADRENO_E_CX: case ADRENO_E_GX: case ADRENO_E_HALT:
    case ADRENO_E_CB0: case ADRENO_E_FAULT: case ADRENO_E_SQE: case ADRENO_E_RING:
        return (int)status;
    default: return ADRENO_FILL32_E_UNCERTAIN;
    }
}
int AdrenoAcceleratorX2::submitFill(AdrenoSegmentList *resources,
                                   const struct adreno_fill32_request *request)
{
    if (!resources || !request) return ADRENO_LIST_E_ARGUMENT;
    if (!fSubmitLock) return ADRENO_SUBMIT_E_INACTIVE;
#if ADRENO_LATCH
    const AdrenoGPUBusy busy;                // G1: counted from before the lock wait to the return
#endif
#if ADRENO_PRESENT_SYNC
    const AdrenoSurfaceWrites writes(resources);   // K1: its written IOSurfaces, until the return (after the unlock)
#endif
    IOLockLock(fSubmitLock);
#if ADRENO_GPU_RECOVER
    recoverLatched();
#endif
#if ADRENO_PIPELINE
    AdrenoFlightRecord *post[4];
    unsigned posts = 0;
    if (fPipeOn) pipelineFinishLocked(post, &posts);   // agents/gpu-pipeline Q4: the flight first (one ring user)
#endif
    AdrenoGatedSubmission submission = {this, resources, request, nullptr, 0};
    int result = adreno_submit_gated(&fStampCleanupFailed, fillGated, &submission);
    if (!result) {
        fSubmittedFills++;
        if (fSubmittedFills==1)
            ALOG("GPU resource fill completed id=%u offset=0x%llx bytes=0x%llx pattern=0x%x",
                 request->resource_id,request->offset,request->bytes,request->pattern);
    }
    IOLockUnlock(fSubmitLock);
#if ADRENO_PIPELINE
    pipelinePost(post, posts);
#endif
    return result;
}

// ADRENO_GUEST_IB (compat/adreno-guest.h): the package is already copied, relocated and validated in the arena.
int AdrenoAcceleratorX2::ibRing(void *, uint64_t package, uint64_t dwords, uint64_t bytes,
                                struct adreno_ib_reply *reply)
{
#if ADRENO_IB_ASYNC
    if (gAdrenoIBAsync) {
        // IB_START, then IB_POLLs with IODelay from 10 to 200 us until a final reply (FAILURE-MODES A9, A10, A17):
        // returns only once the IB retired or is UNCERTAIN, with ADRENO_GUEST_IB's reply shape, so the caller's
        // classification and the resource list's FROM_DEVICE order are unchanged. fSubmitLock stays held.
#if ADRENO_GPU_RECOVER
        const struct adreno_ib_async_ops ops = {nullptr, ibAsyncHVC, ibAsyncDelay,
                                                adreno_recover_guest_limit_us(&gAdrenoRecover)};
#else
        const struct adreno_ib_async_ops ops = {nullptr, ibAsyncHVC, ibAsyncDelay};
#endif
        uint64_t out[4];
        adreno_ib_async_run(&ops, package, dwords, bytes, out, &gAdrenoIBAsyncStats);
        reply->status = (int64_t)out[0];
        reply->marker = out[1];
        reply->ticks = out[2];
        reply->wptr = out[3];
        return 0;
    }
#endif
    register uint64_t x0 __asm__("x0") = ADRENO_GUEST_IB;
    register uint64_t x1 __asm__("x1") = package;
    register uint64_t x2 __asm__("x2") = dwords;
    register uint64_t x3 __asm__("x3") = bytes;
    // The arena stores must be complete before the monitor cleans the package to PoC and rings it.
    __asm__ volatile("dsb ish\n\thvc %4" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : "i"(ADRENO_GUEST_HVC) : "memory", "cc");
    reply->status = (int64_t)x0;
    reply->marker = x1;
    reply->ticks = x2;
    reply->wptr = x3;
    return 0;
}
#if ADRENO_PIPELINE
#if ADRENO_PERF_FRAMES
// The pacing and perf gpu counters of one retired IB (submitIB's block below, moved): at the submission's return for a
// synchronous IB, at the retirement for a flight (agents/gpu-pipeline D5).
static void AdrenoNoteIBRetired(uint64_t gpuTicks)
{
    const uint64_t completedAt = mach_absolute_time();
    __atomic_store_n(&gAdrenoIBCompletedAt, completedAt, __ATOMIC_RELAXED);
#if ADRENO_PERF_GPU
    __atomic_fetch_add(&gAdrenoIBGpuTicks, gpuTicks, __ATOMIC_RELAXED);
    uint64_t seen = __atomic_load_n(&gAdrenoIBGpuTicksMax, __ATOMIC_RELAXED);
    while (gpuTicks > seen && !__atomic_compare_exchange_n(&gAdrenoIBGpuTicksMax, &seen, gpuTicks, false,
                                                           __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
#else
    (void)gpuTicks;
#endif
    __atomic_fetch_add(&gAdrenoIBCompleted, 1, __ATOMIC_RELEASE);
}
#endif
// The command buffer's IOGPUEventFence during its submission (queue+0x518), or null.
static OSObject *AdrenoCurrentFence(IOGPUCommandQueue *queue)
{
    if (!queue) return nullptr;
    OSObject *fence = *reinterpret_cast<OSObject **>(reinterpret_cast<uint8_t *>(queue) + kIOGPUQueueCurrentFenceOffset);
    return OSDynamicCast(IOGPUEventFence, fence);
}
// agents/gpu-pipeline: a pipelined client's IB returns once it is in flight (compat/adreno-ib-pipeline.h); any other
// IB, and every IB while the engine is off, runs as before. The present-sync marks of an IB that stays in flight move to
// its record (D1); the finished flights' post work (unmark, IOGPU signal, list release) runs after the unlock (C6).
int AdrenoAcceleratorX2::submitIB(AdrenoSegmentList *resources, const void *command, uint64_t bytes,
                                  IOGPUCommandQueue *queue)
{
    if (!resources || !command) return ADRENO_LIST_E_ARGUMENT;
    if (!fSubmitLock) return ADRENO_SUBMIT_E_INACTIVE;
#if ADRENO_LATCH
    const AdrenoGPUBusy busy;                // G1: counted from before the lock wait to the return
#endif
    AdrenoSurfaceWrites writes(resources);   // K1: its written IOSurfaces, until the return or, in flight, retirement
#if ADRENO_PERF_GPU
    const uint64_t lockStart = mach_absolute_time();
    IOLockLock(fSubmitLock);
    const uint64_t submitStart = mach_absolute_time();
#else
    IOLockLock(fSubmitLock);
#endif
#if ADRENO_GPU_RECOVER
    recoverLatched();
#endif
    int result;
    bool inFlight = false;
    struct adreno_ib_work *w = fIB;
    if (__atomic_load_n(&fPipeOn, __ATOMIC_ACQUIRE) && fIB) {
#if ADRENO_PRESENT_RELATCH
        // EP2: a flight that is already final is finished before this submission's TO_DEVICE (one POLL)
        if (gAdrenoPipeEarly.on && fPipe.flight.active && !fStampCleanupFailed && adreno_pipe_try_finish(&fPipe, &fPipeOps))
            gAdrenoPipeEarly.pre++;
#endif
        if (fStampCleanupFailed) {
            result = ADRENO_SUBMIT_E_INACTIVE;            // the fail-fast gate, as adreno_submit_gated
        } else {
            AdrenoFlightRecord *rec = pipelineEligible(resources) ? recordAlloc() : nullptr;
            if (rec) { rec->list = resources; rec->queue = queue; rec->fence = AdrenoCurrentFence(queue); }
            const struct adreno_resource_list_ops ops = resources->pipelineOps();
            int flying = 0;
#if ADRENO_PRESENT_RELATCH
            result = adreno_pipe_submit(&fPipe, &fPipeOps, resources->pipelineResources(), &ops, command, bytes,
                                        AdrenoSegmentList::pipelineResolve, this, rec, rec != nullptr, &flying,
                                        &gAdrenoPipeEarly);   // EP3: its TO_DEVICE assists a flight it finds
#else
            result = adreno_pipe_submit(&fPipe, &fPipeOps, resources->pipelineResources(), &ops, command, bytes,
                                        AdrenoSegmentList::pipelineResolve, this, rec, rec != nullptr, &flying);
#endif
            w = fPipe.slot[fPipe.last_slot];
            if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY)
                fStampCleanupFailed = true;               // as adreno_submit_gated latches
            if (flying) {
                resources->retain();                      // R2: until its retirement's post work
                if (rec->fence) rec->fence->retain();
                writes.handTo(rec->ids, &rec->nids, &rec->wild);
                rec->queue = nullptr;
                inFlight = true;
            } else if (rec) {
                rec->list = nullptr; rec->queue = nullptr; rec->fence = nullptr;
                __atomic_store_n(&rec->busy, 0u, __ATOMIC_RELEASE);
            }
        }
    } else {
        AdrenoGatedSubmission submission = {this, resources, nullptr, command, bytes};
        result = fIB ? adreno_submit_gated(&fStampCleanupFailed, ibGated, &submission) : ADRENO_SUBMIT_E_INACTIVE;
    }
#if ADRENO_PERF_FRAMES
    if (!result && !inFlight) AdrenoNoteIBRetired(w->reply.ticks);
#if ADRENO_PERF_GPU
    if (!result) {
        __atomic_fetch_add(&gAdrenoIBSubmitTicks, mach_absolute_time() - submitStart, __ATOMIC_RELAXED);
        __atomic_fetch_add(&gAdrenoIBLockTicks, submitStart - lockStart, __ATOMIC_RELAXED);
    }
#endif
#endif
    if (!result && ++fSubmittedIBs == 1)
        ALOG("GPU IB %s: %u dwords, %u relocations, marker 0x%llx, ticks %llu, wptr %llu", inFlight ? "in flight" : "completed",
             w->command.ib_dwords, w->command.reloc_count, w->reply.marker, w->reply.ticks, w->reply.wptr);
    if (result && w && result != ADRENO_SUBMIT_E_INACTIVE)
        ALOG("GPU IB refused %d at 0x%x (monitor status %lld, ib state 0x%x)", result, w->error_at,
             w->reply.status, w->state);
    AdrenoFlightRecord *post[4];
    unsigned posts = 0;
    pipelineTakePost(post, &posts);
    IOLockUnlock(fSubmitLock);
    pipelinePost(post, posts);
    if (inFlight) pipelineArm();
    return result;
}
#else
int AdrenoAcceleratorX2::submitIB(AdrenoSegmentList *resources, const void *command, uint64_t bytes)
{
    if (!resources || !command) return ADRENO_LIST_E_ARGUMENT;
    if (!fSubmitLock) return ADRENO_SUBMIT_E_INACTIVE;
#if ADRENO_LATCH
    const AdrenoGPUBusy busy;                // G1: counted from before the lock wait to the return
#endif
#if ADRENO_PRESENT_SYNC
    const AdrenoSurfaceWrites writes(resources);   // K1: its written IOSurfaces, until the return (after the unlock)
#endif
#if ADRENO_PERF_GPU
    const uint64_t lockStart = mach_absolute_time();
    IOLockLock(fSubmitLock);
    const uint64_t submitStart = mach_absolute_time();
#else
    IOLockLock(fSubmitLock);
#endif
#if ADRENO_GPU_RECOVER
    recoverLatched();
#endif
    AdrenoGatedSubmission submission = {this, resources, nullptr, command, bytes};
    int result = fIB ? adreno_submit_gated(&fStampCleanupFailed, ibGated, &submission) : ADRENO_SUBMIT_E_INACTIVE;
#if ADRENO_PERF_FRAMES
    if (!result) {
#if ADRENO_PERF_GPU
        const uint64_t completedAt = mach_absolute_time();
        __atomic_store_n(&gAdrenoIBCompletedAt, completedAt, __ATOMIC_RELAXED);
        // P5: the monitor's poll ticks (x2 of the IB HVC): GPU execution from the doorbell to retirement.
        const uint64_t gpuTicks = fIB->reply.ticks;
        __atomic_fetch_add(&gAdrenoIBGpuTicks, gpuTicks, __ATOMIC_RELAXED);
        uint64_t seen = __atomic_load_n(&gAdrenoIBGpuTicksMax, __ATOMIC_RELAXED);
        while (gpuTicks > seen && !__atomic_compare_exchange_n(&gAdrenoIBGpuTicksMax, &seen, gpuTicks, false,
                                                               __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
        __atomic_fetch_add(&gAdrenoIBSubmitTicks, completedAt - submitStart, __ATOMIC_RELAXED);
        __atomic_fetch_add(&gAdrenoIBLockTicks, submitStart - lockStart, __ATOMIC_RELAXED);
#else
        __atomic_store_n(&gAdrenoIBCompletedAt, mach_absolute_time(), __ATOMIC_RELAXED);
#endif
        __atomic_fetch_add(&gAdrenoIBCompleted, 1, __ATOMIC_RELEASE);
    }
#endif
    if (!result && ++fSubmittedIBs == 1)
        ALOG("GPU IB completed: %u dwords, %u relocations, marker 0x%llx, ticks %llu, wptr %llu",
             fIB->command.ib_dwords, fIB->command.reloc_count, fIB->reply.marker, fIB->reply.ticks, fIB->reply.wptr);
    if (result && fIB && result != ADRENO_SUBMIT_E_INACTIVE)
        ALOG("GPU IB refused %d at 0x%x (monitor status %lld, ib state 0x%x)", result, fIB->error_at,
             fIB->reply.status, fIB->state);
    IOLockUnlock(fSubmitLock);
    return result;
}

#endif

#if ADRENO_PIPELINE
// ---------------------------------------------------------------------------------------------------
// The IB pipeline's kext side (agents/gpu-pipeline FAILURE-MODES.md; the engine is compat/adreno-ib-pipeline.h).

// Q2: the second package slot, right after the first in the doubled arena, with its own zero page cleaned to PoC.
bool AdrenoAcceleratorX2::pipelineBindSlot1()
{
    if (fIB2 || !fIB || !fIBArena || !fIBTables || fIBGPULength < 2 * ADRENO_PIPE_SLOT_BYTES) return false;
    fIB2 = static_cast<struct adreno_ib_work *>(IOMalloc(sizeof(*fIB2)));
    fIBRelocs2 = static_cast<struct adreno_ib_reloc *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBRelocs2)));
    fIBOrder2 = static_cast<uint16_t *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBOrder2)));
    fIBUsed2 = static_cast<uint8_t *>(IOMalloc(ADRENO_IB_MAX_RELOCS * sizeof(*fIBUsed2)));
    fIBTargets2 = static_cast<uint64_t *>(IOMalloc(ADRENO_IB_TARGET_WORDS * sizeof(*fIBTargets2)));
    if (!fIB2 || !fIBRelocs2 || !fIBOrder2 || !fIBUsed2 || !fIBTargets2) { pipelineFreeSlot1(); return false; }
    uint8_t *arena = static_cast<uint8_t *>(fIBArena->getBytesNoCopy()) + ADRENO_PIPE_SLOT_BYTES;
    if (adreno_ib_work_init(fIB2, fIBTables, arena, fIBGPUAddress + ADRENO_PIPE_SLOT_BYTES, ADRENO_PIPE_SLOT_BYTES,
                            fIBRelocs2, fIBOrder2, fIBUsed2, ADRENO_IB_MAX_RELOCS, fIBTargets2) ||
        guestCacheRange(fIBGPUAddress + ADRENO_PIPE_SLOT_BYTES, ADRENO_IB_ZERO_BYTES, ADRENO_CACHE_TO_DEVICE)) {
        pipelineFreeSlot1();
        return false;
    }
    return true;
}
void AdrenoAcceleratorX2::pipelineFreeSlot1()
{
    if (fIB2) IOFree(fIB2, sizeof(*fIB2));
    if (fIBRelocs2) IOFree(fIBRelocs2, ADRENO_IB_MAX_RELOCS * sizeof(*fIBRelocs2));
    if (fIBOrder2) IOFree(fIBOrder2, ADRENO_IB_MAX_RELOCS * sizeof(*fIBOrder2));
    if (fIBUsed2) IOFree(fIBUsed2, ADRENO_IB_MAX_RELOCS * sizeof(*fIBUsed2));
    if (fIBTargets2) IOFree(fIBTargets2, ADRENO_IB_TARGET_WORDS * sizeof(*fIBTargets2));
    fIB2 = nullptr; fIBRelocs2 = nullptr; fIBOrder2 = nullptr; fIBUsed2 = nullptr; fIBTargets2 = nullptr;
}

uint64_t AdrenoAcceleratorX2::pipeNow(void *)
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000u;
}
// C1: a flight started: the next stamp value, set into this queue's event before the submission returns, so the
// command buffer's fence (and any later signalSharedEvent) completes only when the retirement writes it.
uint32_t AdrenoAcceleratorX2::pipeStamp(void *c, void *owner)
{
    auto *self = static_cast<AdrenoAcceleratorX2 *>(c);
    auto *rec = static_cast<AdrenoFlightRecord *>(owner);
    const int index = (int)self->fPipeStampIndex;
    AdrenoEMIncrementStamp(self->fPipeEvents, index);
    const uint32_t stamp = AdrenoEMCurrentStamp(self->fPipeEvents, index);
    if (rec->queue) AdrenoEMSetEventStamp(self->fPipeEvents, index, rec->queue->getPreMappingBarrierEvent());
    rec->stamp = stamp;
    return stamp;
}
// C1 C3 C4: a flight finished, FROM_DEVICE done (under fSubmitLock, in retirement order). Its failure status reaches the
// command buffer's fence, the fail-fast latch takes UNCERTAIN, and the stamp word is written last; signalling IOGPU,
// unmarking and releasing happen after the unlock (pipelinePost).
void AdrenoAcceleratorX2::pipeRetired(void *c, void *owner, int result, const struct adreno_ib_reply *final,
                                      uint32_t stamp)
{
    auto *self = static_cast<AdrenoAcceleratorX2 *>(c);
    auto *rec = static_cast<AdrenoFlightRecord *>(owner);
    rec->result = result;
    if (result == ADRENO_SUBMIT_E_UNCERTAIN || result == ADRENO_LIST_E_VISIBILITY) self->fStampCleanupFailed = true;
#if ADRENO_GPU_RECOVER
    const uint32_t status = self->recoverStatus(result);   // R26: 3 / 0xb for a reset, 2 uncertain, 5 victim
#else
    const uint32_t status = kIOGPUSubmissionErrorKext;
#endif
    if (result && rec->fence)
        __atomic_store_n(reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(rec->fence) + kIOGPUFenceStatusOffset),
                         status, __ATOMIC_RELAXED);
#if ADRENO_PERF_FRAMES
    if (!result) AdrenoNoteIBRetired(final->ticks);
#else
    (void)final;
#endif
#if ADRENO_PRESENT_RELATCH
    // EP1: its FROM_DEVICE ran (adreno_ib_submit_finish, before this callback): the display may copy what it wrote now,
    // not after the unlock (and not after a synchronous client's whole IB). fSubmitLock -> gAdrenoSyncLock only.
    if (gAdrenoPipeEarly.on && (rec->nids || rec->wild)) {
        AdrenoSyncUnmarkIDs(rec->ids, rec->nids, rec->wild);
        rec->nids = 0;
        rec->wild = false;
        gAdrenoPipeEarly.unmarks++;
    }
#endif
    uint32_t *word = static_cast<uint32_t *>(self->fStamps->getBytesNoCopy()) + self->fPipeStampIndex;
    __atomic_store_n(word, stamp, __ATOMIC_RELEASE);
    if (result) {
        const uint64_t n = __atomic_add_fetch(&self->fFailedCommands, 1, __ATOMIC_RELAXED);
        if (n <= 16 || !(n & 4095))
            ALOG("pipeline: IB failed after its submission returned: %d (monitor status %lld); command buffer marked 0x%x",
                 result, final->status, status);
    }
    if (self->fPostCount < sizeof self->fPost / sizeof self->fPost[0]) self->fPost[self->fPostCount++] = rec;
}
AdrenoAcceleratorX2::AdrenoFlightRecord *AdrenoAcceleratorX2::recordAlloc()
{
    for (unsigned i = 0; fRecords && i < ADRENO_PIPE_RECORDS; i++) {
        uint32_t idle = 0;
        if (__atomic_compare_exchange_n(&fRecords[i].busy, &idle, 1u, false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            AdrenoFlightRecord *r = &fRecords[i];
            r->list = nullptr; r->queue = nullptr; r->fence = nullptr; r->nids = 0; r->wild = false;
            r->stamp = 0; r->result = 0;
            return r;
        }
    }
    return nullptr;   // every record taken: this IB runs synchronously
}
void AdrenoAcceleratorX2::pipelineTakePost(AdrenoFlightRecord **out, unsigned *n)
{
    *n = fPostCount;
    for (unsigned i = 0; i < fPostCount; i++) out[i] = fPost[i];
    fPostCount = 0;
}
// After the unlock: unmark (D1), wake IOGPU's waiters and its completion machinery (C1), release the list and the
// fence (R2), free the record.
void AdrenoAcceleratorX2::pipelinePost(AdrenoFlightRecord *const *records, unsigned n)
{
    if (!n) return;
    for (unsigned i = 0; i < n; i++) {
        AdrenoFlightRecord *r = records[i];
        AdrenoSyncUnmarkIDs(r->ids, r->nids, r->wild);
        AdrenoEMSignalStamp(fPipeEvents, (int)fPipeStampIndex, r->stamp);
    }
    AdrenoGPUSignalStampsUpdated(this);
    for (unsigned i = 0; i < n; i++) {
        AdrenoFlightRecord *r = records[i];
        OSSafeReleaseNULL(r->fence);
        if (r->list) { r->list->release(); r->list = nullptr; }
        __atomic_store_n(&r->busy, 0u, __ATOMIC_RELEASE);
    }
}
void AdrenoAcceleratorX2::pipelineFinishLocked(AdrenoFlightRecord **post, unsigned *n)
{
    *n = 0;
    if (adreno_pipe_complete(&fPipe, &fPipeOps)) fPipe.stats.drains++;
    pipelineTakePost(post, n);
}
// C5: the completion timer, on the pipeline's own workloop.
void AdrenoAcceleratorX2::pipelineArm()
{
    if (!fPipeTimer || __atomic_exchange_n(&fPipeTimerArmed, 1u, __ATOMIC_ACQ_REL)) return;
#if ADRENO_PRESENT_RELATCH
    // UR1: while the display relatches, the urgent period (the flag is only read here; a stuck flag costs polls)
    const uint64_t urgent = __atomic_load_n(&gAdrenoPresentUrgent, __ATOMIC_RELAXED) ? gAdrenoPipeUrgentTicks : 0;
    fPipeTimer->setTimeout(kIOTimeOptionsWithLeeway, urgent ? urgent : fPipePollTicks, fPipeLeewayTicks);
#else
    fPipeTimer->setTimeout(kIOTimeOptionsWithLeeway, fPipePollTicks, fPipeLeewayTicks);
#endif
}
void AdrenoAcceleratorX2::pipelineTimerFired()
{
    __atomic_store_n(&fPipeTimerArmed, 0u, __ATOMIC_RELEASE);
    AdrenoFlightRecord *post[4];
    unsigned posts = 0;
    IOLockLock(fSubmitLock);
    const int active = fPipeOn ? adreno_pipe_poll(&fPipe, &fPipeOps) : 0;
    pipelineTakePost(post, &posts);
    IOLockUnlock(fSubmitLock);
    pipelinePost(post, posts);
    if (active) pipelineArm();
}
bool AdrenoAcceleratorX2::pipelineEligible(AdrenoSegmentList *list)
{
    if (fPipeMode >= 2) return true;
    IOGPUDevice *device = list ? list->pipelineDevice() : nullptr;
    AdrenoTask *task = OSDynamicCast(AdrenoTask, device ? AdrenoDeviceGPUTask(device) : nullptr);
    return task && task->pipelineClient();
}
// After IOGPU::start: the policy, the monitor, both slots, the IOGPU self-test (C2), records, the timer. Any failure
// leaves the engine off: every IB stays synchronous.
bool AdrenoAcceleratorX2::pipelineStart(IOGPUEventMachine *events)
{
    uint32_t mode = 1, pollUs = 500;
    PE_parse_boot_argn("adreno_pipeline", &mode, sizeof(mode));
    PE_parse_boot_argn("adreno_pipeline_poll_us", &pollUs, sizeof(pollUs));
    fPipeMode = mode > 2 ? 2 : mode;
    if (pollUs < 50) pollUs = 50;
    if (pollUs > 5000) pollUs = 5000;
    if (!fPipeMode) { ALOG("pipeline off (adreno_pipeline=0)"); return false; }
    if (!gAdrenoIBAsync || !fIB || !(fIB->state & ADRENO_IB_STATE_READY) || !fIB2 ||
        !(fIB2->state & ADRENO_IB_STATE_READY) || !events || !fStamps || fStampCleanupFailed) {
        ALOG("pipeline off: needs the monitor's IB_START/IB_POLL (%u) and both package slots (%d %d)", gAdrenoIBAsync,
             fIB ? (int)fIB->state : -1, fIB2 ? (int)fIB2->state : -1);
        return false;
    }
    // C2: the IOGPU event machine as the disassembly says (AdrenoIOGPUStamps.h; host-tested on the KDK's code): the
    // index exists (getNumStamps, read only), a local event at the synced stamp completes, then not after the increment,
    // then again once the stamp word holds the new value.
    fPipeStampIndex = ADRENO_NUM_STAMPS - 1;
    volatile uint32_t *word = static_cast<volatile uint32_t *>(fStamps->getBytesNoCopy()) + fPipeStampIndex;
    struct adreno_iogpu_selftest st;
    if (adreno_iogpu_selftest(events, word, (int)fPipeStampIndex, &st)) {
        ALOG("pipeline off: IOGPU stamp self-test failed (stamps %d, index %u, complete %d, pending %d, complete %d, "
             "stamp 0x%x -> 0x%x)", st.num_stamps, fPipeStampIndex, st.synced, st.pending, st.after, st.start, st.stamp);
        return false;
    }
    fRecords = static_cast<AdrenoFlightRecord *>(IOMalloc(ADRENO_PIPE_RECORDS * sizeof(*fRecords)));
    fPipeLoop = IOWorkLoop::workLoop();
    fPipeTimer = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityKernelHigh, this,
                                                      ^(IOTimerEventSource *) { pipelineTimerFired(); });
    if (!fRecords || !fPipeLoop || !fPipeTimer || fPipeLoop->addEventSource(fPipeTimer) != kIOReturnSuccess) {
        ALOG("pipeline off: no records, workloop or timer");
        if (fRecords) IOFree(fRecords, ADRENO_PIPE_RECORDS * sizeof(*fRecords));
        fRecords = nullptr;
        OSSafeReleaseNULL(fPipeTimer);
        OSSafeReleaseNULL(fPipeLoop);
        return false;
    }
    bzero(fRecords, ADRENO_PIPE_RECORDS * sizeof(*fRecords));
    nanoseconds_to_absolutetime((uint64_t)pollUs * 1000u, &fPipePollTicks);
    nanoseconds_to_absolutetime(50000u, &fPipeLeewayTicks);
#if ADRENO_PRESENT_RELATCH
    {   // UR1 EP1-EP3 OP3: adreno_pipeline_urgent_us (0 = off, else 50..poll), adreno_pipe_early, adreno_pipe_assist_us
        uint32_t urgentUs = 100, early = 1, assistUs = 250;
        PE_parse_boot_argn("adreno_pipeline_urgent_us", &urgentUs, sizeof(urgentUs));
        PE_parse_boot_argn("adreno_pipe_early", &early, sizeof(early));
        PE_parse_boot_argn("adreno_pipe_assist_us", &assistUs, sizeof(assistUs));
        if (urgentUs && urgentUs < 50) urgentUs = 50;
        if (urgentUs > pollUs) urgentUs = pollUs;
        if (assistUs > 5000) assistUs = 5000;
        uint64_t urgent = 0;
        if (urgentUs) nanoseconds_to_absolutetime((uint64_t)urgentUs * 1000u, &urgent);
        __atomic_store_n(&gAdrenoPipeUrgentTicks, urgent, __ATOMIC_RELAXED);
        gAdrenoPipeEarly.on = early != 0;
        gAdrenoPipeEarly.assist_us = assistUs;
        ALOG("pipeline: urgent completion poll %u us, early release %s, TO_DEVICE assist %u us",
             urgentUs, early ? "on" : "off", early ? assistUs : 0);
    }
#endif
    adreno_pipe_init(&fPipe, fIB, fIB2);
#if ADRENO_GPU_RECOVER
    const struct adreno_pipe_ops ops = {this, ibAsyncHVC, ibAsyncDelay, pipeNow, pipeStamp, pipeRetired,
                                        adreno_recover_guest_limit_us(&gAdrenoRecover)};
#else
    const struct adreno_pipe_ops ops = {this, ibAsyncHVC, ibAsyncDelay, pipeNow, pipeStamp, pipeRetired};
#endif
    fPipeOps = ops;
    fPipeEvents = events;
    __atomic_store_n(&gAdrenoPipeStats, &fPipe.stats, __ATOMIC_RELEASE);
    __atomic_store_n(&gAdrenoPipeState, 1u | fPipeMode << 8, __ATOMIC_RELAXED);
    __atomic_store_n(&fPipeOn, 1u, __ATOMIC_RELEASE);
    ALOG("pipeline on: %s IB submissions return once in flight; stamp %u (0x%x, %d stamps), completion poll %u us",
         fPipeMode >= 2 ? "every client's" : "WindowServer's", fPipeStampIndex, st.stamp, st.num_stamps, pollUs);
    return true;
}
// O2: finish the flight before the arena goes; the timer is cancelled and removed before its workloop is released.
void AdrenoAcceleratorX2::pipelineStop()
{
    if (fSubmitLock && fPipeOn) {
        AdrenoFlightRecord *post[4];
        unsigned posts = 0;
        IOLockLock(fSubmitLock);
        pipelineFinishLocked(post, &posts);
        __atomic_store_n(&fPipeOn, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&gAdrenoPipeState, 0u, __ATOMIC_RELAXED);
        IOLockUnlock(fSubmitLock);
        pipelinePost(post, posts);
    }
    if (fPipeTimer) {
        fPipeTimer->cancelTimeout();
        if (fPipeLoop) fPipeLoop->removeEventSource(fPipeTimer);
    }
    OSSafeReleaseNULL(fPipeTimer);
    OSSafeReleaseNULL(fPipeLoop);
    if (fRecords && !fPipe.flight.active) {
        IOFree(fRecords, ADRENO_PIPE_RECORDS * sizeof(*fRecords));
        fRecords = nullptr;
    }
}
#endif

void AdrenoAcceleratorX2::noteCommandFailure(int result)
{
    // After the fail-fast latch every command buffer fails the same way: log the first ones, then rarely.
    uint64_t n = __atomic_add_fetch(&fFailedCommands, 1, __ATOMIC_RELAXED);
    if (n <= 16 || !(n & 4095))
        ALOG("command submission failed %d (%llu failures; latched %u)", result, n, fStampCleanupFailed);
}

#if ADRENO_GPU_RECOVER
uint32_t AdrenoAcceleratorX2::recoverStatus(int result) const
{
    return adreno_recover_guest_status(result, fStampCleanupFailed || gAdrenoRecover.dead);
}
// R27, R28: only a latch a GPU result set (the stamp DMA, and the IB arena's when there is one, still prepared: a failed
// DMA completion at teardown clears them first), only after the monitor's SETTLE answered 0, at most every 100 ms.
void AdrenoAcceleratorX2::recoverLatched()
{
    if (!fStampCleanupFailed || !gAdrenoRecover.abi || gAdrenoRecover.dead) return;
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
#if ADRENO_PIPELINE
    struct adreno_ib_work *const works[2] = {fIB, fIB2};
#else
    struct adreno_ib_work *const works[2] = {fIB, nullptr};
#endif
    const int dmaOK = fStampDMAActive && (!fIB || fIBDMAActive);
    if (adreno_recover_guest_unlatch(&kAdrenoRecoverOps, &gAdrenoRecover, ns / 1000u, &fStampCleanupFailed, works, 2, dmaOK))
        ALOG("GPU recovered: the monitor proved it idle (epoch %llu, %s); latch cleared after %llu failed commands",
             gAdrenoRecover.epoch, gAdrenoRecover.settle_resets ? "after a reset" : "no reset needed", fFailedCommands);
    else if (gAdrenoRecover.dead)
        ALOG("GPU recovery: the monitor gave up for this boot; the latch stays");
}
#endif

bool AdrenoAcceleratorX2::prepareStampDMA()
{
    if (!fStamps || !fGPUVA || !fMapper || fStampDMA || fStampWired || fStampCleanupFailed)
        return false;
    const uint64_t length = fStamps->getLength();
    if (!length || length % kAdrenoGPUVAAlign) return false;
    IOReturn result = fStamps->prepare(kIODirectionInOut);
    if (result != kIOReturnSuccess) {
        ALOG("stamp wiring failed: 0x%x", result);
        return false;
    }
    fStampWired = true;
    fStampDMA = IODMACommand::withSpecification(kIODMACommandOutputHost64, 32, length,
        IODMACommand::kMapped, length, kAdrenoGPUVAAlign, fMapper);
    if (!fStampDMA) {
        ALOG("stamp DMA command allocation failed");
        return false;
    }
    // Explicit preparation lets teardown account for each successful step.
    result = fStampDMA->setMemoryDescriptor(fStamps, false);
    if (result != kIOReturnSuccess) {
        ALOG("stamp DMA descriptor failed: 0x%x", result);
        return false;
    }
    result = fStampDMA->prepare(0, length);
    // Native prepare increments its active count before attempting the map,
    // and can return a mapping error while still active. Balance that state too.
    fStampDMAActive = fStampDMA->getPreparedOffsetAndLength(nullptr, nullptr) == kIOReturnSuccess;
    if (result != kIOReturnSuccess || !fStampDMAActive) {
        ALOG("stamp DMA preparation failed: 0x%x", result);
        return false;
    }
    IODMACommand::Segment64 segment = {};
    UInt64 offset = 0;
    UInt32 count = 1;
    result = fStampDMA->gen64IOVMSegments(&offset, &segment, &count);
    if (result != kIOReturnSuccess || count != 1 || offset != length ||
        segment.fLength != length || segment.fIOVMAddr < kAdrenoGPUVABase ||
        segment.fIOVMAddr >= ADRENO_WINDOW_END ||
        segment.fIOVMAddr % kAdrenoGPUVAAlign ||
        length > ADRENO_WINDOW_END - segment.fIOVMAddr) {
        ALOG("stamp DMA segment rejected: result 0x%x, count %u, offset 0x%llx, address 0x%llx, length 0x%llx",
             result, count, offset, segment.fIOVMAddr, segment.fLength);
        return false;
    }
    if (!fGPUVA->allocateRange(segment.fIOVMAddr, length)) {
        ALOG("stamp DMA address collides with shared task allocator");
        return false;
    }
    fStampGPUAddress = segment.fIOVMAddr;
    fStampGPULength = length;
    ALOG("stamp DMA mapped: address 0x%llx, length 0x%llx", fStampGPUAddress, fStampGPULength);
    return true;
}

bool AdrenoAcceleratorX2::releaseStampDMA()
{
    // A failed completion cannot establish that the mapper released the pages.
    // Preserve all owned resources in that case, even if free() is called later.
    if (fStampCleanupFailed) return false;
    IOReturn result = kIOReturnSuccess;
    if (fStampDMAActive) {
        result = fStampDMA->complete();
        fStampDMAActive = false;
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("stamp DMA completion failed: 0x%x; retaining resources", result);
            return false;
        }
    }
    if (fStampDMA) {
        result = fStampDMA->clearMemoryDescriptor(false);
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("stamp DMA descriptor cleanup failed: 0x%x; retaining resources", result);
            return false;
        }
        OSSafeReleaseNULL(fStampDMA);
    }
    if (fStampGPUAddress) {
        fGPUVA->deallocate(fStampGPUAddress, fStampGPULength);
        fStampGPUAddress = 0;
        fStampGPULength = 0;
    }
    if (fStampWired) {
        result = fStamps->complete(kIODirectionInOut);
        if (result != kIOReturnSuccess) {
            fStampCleanupFailed = true;
            ALOG("stamp unwiring failed: 0x%x; retaining backing", result);
            return false;
        }
        fStampWired = false;
    }
    return true;
}

void AdrenoAcceleratorX2::teardownDevice(IOService *) {}

void AdrenoAcceleratorX2::populateAccelConfig(IOGPUConfig *config)
{
    // config == this + 0x228 (IOGPU::start 0xfffffe000a8850ac). IOGPU::initializeConfigStructure has
    // already written the defaults; only the fields below differ from them.
    uint8_t *c = reinterpret_cast<uint8_t *>(config);
    *reinterpret_cast<const char **>(c + 0x00) = ADRENO_ACCEL_NAME;                // accelName (s_get_name)
    *reinterpret_cast<uint32_t *>(c + 0x08) |= ADRENO_RESOURCE_AUTO_MAP;           // native resource mapping
    *reinterpret_cast<uint32_t *>(c + 0x18) = ADRENO_NUM_STAMPS;                   // numEventChannels
    *reinterpret_cast<uint32_t *>(c + 0x4c) = ADRENO_RESOURCE_ARGS_KERNEL_TAIL;    // resource-args tail
    *reinterpret_cast<uint32_t *>(c + 0x54) = ADRENO_WAIT_FOR_GPU_TIMEOUT_S;       // waitForGPUTimeoutSeconds
    *reinterpret_cast<uint32_t *>(c + 0x90) = ADRENO_QUEUE_ARGS_SIZE;              // queue-args size (sel 7)
}

bool AdrenoAcceleratorX2::start(IOService *provider)
{
#if ADRENO_RESIDENT_BUDGET_MIB
    AdrenoGPUMapStart();   // the residency budget, before IOGPU::start makes the first map (R13)
#endif
    if (!IOGPU::start(provider)) {
        ALOG("IOGPU::start failed");
        return false;
    }
    IOGPUEventMachine *em = *reinterpret_cast<IOGPUEventMachine **>(reinterpret_cast<uint8_t *>(this) +
                                                                    kIOGPUEventMachineOffset);
    if (!em || !fStamps) {
        ALOG("no event machine (%p) or stamp page (%p)", em, fStamps);
        IOGPU::stop(provider);
        return false;
    }
    // Only AGX calls this (AGXAccelerator::start 0xfffffe0008a312e4); IOGPUFamily never does, and
    // testEvent dereferences the table it builds as soon as an event carries a stamp.
    em->setStampBaseAddress(reinterpret_cast<volatile unsigned int *>(fStamps->getBytesNoCopy()));
#if ADRENO_PIPELINE
    pipelineStart(em);   // agents/gpu-pipeline: optional; off leaves every IB synchronous
#endif

    setProperty("model", "Adreno X2-90");
    if (AdrenoEarlyStopEnabled())   // before the publish notification the plug-in's device creation follows
        setProperty(ADRENO_EARLY_STOP_REGISTRY_PROPERTY, 1ULL, 32);
    enableAccelerator();   // accelerator+0x220 bit 0
    registerService();     // Metal waits for the IOAccelerator publish notification; IOGPU::start never registers
    { extern bool AdrenoDisplayAttach(IOService *); AdrenoDisplayAttach(this); }   // Stage 8 panel child (AdrenoDisplay.cpp); never fatal
    ALOG("started: %u stamps, queue args 0x%x, synchronous GPU fence transport, IB %s", ADRENO_NUM_STAMPS,
         ADRENO_QUEUE_ARGS_SIZE, fIB && (fIB->state & ADRENO_IB_STATE_READY) ? "ready" : "off");
    ALOG("GPU mappings resident across unwire: budget %llu MiB, contiguous-run inserts",
         (unsigned long long)(kAdrenoResidentBudget >> 20));
    return true;
}

void AdrenoAcceleratorX2::free()
{
#if ADRENO_PIPELINE
    pipelineStop();      // O2: no flight left on the arena below
#endif
    // The IB arena shares fGPUVA and fMapper: after an uncertain submission both it and they stay (leak).
    if (releaseIBArena() && releaseStampDMA()) {
        freeIBWork();
        OSSafeReleaseNULL(fStamps);
        OSSafeReleaseNULL(fGPUVA);
        OSSafeReleaseNULL(fMapper);
    }
    if (fSubmitLock) { IOLockFree(fSubmitLock); fSubmitLock = nullptr; }
    IOGPU::free();
}

// The plug-in's unrecoverable-failure report (AdrenoContract.h ADRENO_EARLY_STOP_FAILURE_KEY): exactly that key,
// a 64-bit number, only while this launch enabled early stop. Every other property change keeps IOGPU's answer.
IOReturn AdrenoAcceleratorX2::setProperties(OSObject *properties)
{
    OSDictionary *dictionary = OSDynamicCast(OSDictionary, properties);
    OSObject *report = dictionary ? dictionary->getObject(ADRENO_EARLY_STOP_FAILURE_KEY) : nullptr;
    if (!report) return IOGPU::setProperties(properties);
    OSNumber *value = OSDynamicCast(OSNumber, report);
    if (dictionary->getCount() != 1 || !value || value->numberOfBits() != 64) return kIOReturnBadArgument;
    if (!AdrenoEarlyStopEnabled()) return kIOReturnUnsupported;
    int status = AdrenoEarlyStopRequest(EARLY_STOP_REASON_PLUGIN_FAILURE, value->unsigned64BitValue());
    return status < 0 ? kIOReturnNotPermitted : kIOReturnSuccess;
}

IOMemoryDescriptor *AdrenoAcceleratorX2::getStampMemory(unsigned int *offset)
{
    // IOGPUDeviceUserClient::deviceUserClientStart retains the result and maps it read-only into the
    // client (options 0x04001001); NULL there fails every Metal device open.
    if (offset) *offset = 0;
    return fStamps;
}

// Factories: IOGPU's create* wrappers run init() on what these return (IOGPU::createEventMachine,
// createSysMemory, createResource, createMemoryMap, s_new_command_queue), so these only allocate.
IOGPUEventMachine *AdrenoAcceleratorX2::newEventMachine() { return OSTypeAlloc(AdrenoEventMachine); }
IOGPUSysMemory *AdrenoAcceleratorX2::newSysMemory() { return OSTypeAlloc(AdrenoSysMemory); }
IOGPUResource *AdrenoAcceleratorX2::newResource() { return OSTypeAlloc(AdrenoResource); }
IOGPUMemoryMap *AdrenoAcceleratorX2::newMemoryMap() { return AdrenoMemoryMap::withMapper(fMapper); }
IOGPUCommandQueue *AdrenoAcceleratorX2::newCommandQueue() { return AdrenoCommandQueue::withAccelerator(this); }

// Task factories return an initialised +1 task, as AGXAccelerator::create{User,Kernel}GPUTask do.
IOGPUTask *AdrenoAcceleratorX2::createUserGPUTask(task *owner) { return AdrenoTask::withTask(this, owner, fGPUVA); }
IOGPUTask *AdrenoAcceleratorX2::createKernelGPUTask() { return AdrenoTask::withTask(this, kernel_task, fGPUVA); }
