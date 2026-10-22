/* SPDX-License-Identifier: MIT */
// AdrenoX2.h - Adreno X2-90 IOGPU driver, synchronous fence transport.
//
// The vendor fence completes synchronously through the monitor-owned GPU ring.
// IOGPU then retires its stamp-free event, or reports the submission error.
// General packet execution and render/compute encoding are still unfinished.
//
// Overrides are the minimum IOGPU needs, each checked against the 26A428 kernelcache
// (tools/vtcheck.py checks every vtable slot of every class here against the kernel's base vtable).
#pragma once
#include "IOGPUFamily26A428.h"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/IOLocks.h>
#include "AdrenoContract.h"
#include "../../../../compat/adreno.h"
#include "../../../../compat/adreno-resource.h"
#include "../../../../compat/adreno-resource-list.h"
#include "../../../../compat/adreno-fill-command.h"
#include "../../../../compat/adreno-ib-command.h"

// IOGPU keeps the event machine it made in start() at this offset (IOGPU::start 0xfffffe000a8854d4,
// str x0, [x19, #0x140]); AGXAccelerator::start reads it from the same place to call setStampBaseAddress.
static constexpr size_t kIOGPUEventMachineOffset = 0x140;

// All tasks share CB0 and therefore one accelerator-owned VA allocator. Use
// the monitor's mirrored window; address zero is native allocation failure.
static constexpr uint64_t kAdrenoGPUVABase = ADRENO_WINDOW_BASE;
static constexpr uint64_t kAdrenoGPUVASize = ADRENO_WINDOW_END - ADRENO_WINDOW_BASE;
static constexpr uint64_t kAdrenoGPUVAAlign = 0x4000;                 // 16 KiB pages
// Bytes of GPU mappings kept mapped and pinned after IOGPU unwires them, for all maps together
// (docs/ADRENO-GPU-MAP-RESIDENCY-20261017.md). They stay wired outside IOGPU's own accounting;
// beyond the budget an unwire clears and unpins as before. 0 restores the old behaviour.
#ifndef ADRENO_RESIDENT_BUDGET_MIB
#define ADRENO_RESIDENT_BUDGET_MIB 512
#endif
static constexpr uint64_t kAdrenoResidentBudget = (uint64_t)ADRENO_RESIDENT_BUDGET_MIB << 20;
#if ADRENO_RESIDENT_BUDGET_MIB
// AdrenoMemoryMap.cpp: stores the budget (kept out of initialized data, R13); AdrenoAcceleratorX2::start calls it
// before IOGPU::start, so it precedes every map.
extern "C" void AdrenoGPUMapStart(void);
#endif
// The perf gpu line (pacing work 2026-10-21, AdrenoDisplayPacing.h): GPU execution, submission, resource
// preparation/unwire, cache maintenance and residency per perf window. Off by default; needs ADRENO_PERF_FRAMES in
// AdrenoDisplay.o, which prints it.
#ifndef ADRENO_PERF_GPU
#define ADRENO_PERF_GPU 0
#endif
#if ADRENO_PERF_GPU
extern "C" void AdrenoGPUWorkCounters(uint64_t *);        // AdrenoMemoryMap.cpp
extern "C" uint64_t gAdrenoIBGpuTicks, gAdrenoIBGpuTicksMax, gAdrenoIBSubmitTicks, gAdrenoIBLockTicks;   // AdrenoX2.cpp
#endif
// --present-sync (agents/present-sync FAILURE-MODES.md K1-K11): -DADRENO_PRESENT_SYNC=1 here and in AdrenoDisplay.o. IB
// and FILL32 submissions mark the IOSurfaces their resource list writes, from before the submit-lock wait to their return
// (AdrenoDisplaySync.h); AdrenoDisplay does not copy a layer-0 surface while it is marked. Off by default; without it
// this source compiles as before.
#ifndef ADRENO_PRESENT_SYNC
#define ADRENO_PRESENT_SYNC 0
#endif
#if ADRENO_PRESENT_SYNC
extern "C" uint32_t AdrenoPresentSyncQuery(uint32_t surfaceID, uint64_t *oldest);   // AdrenoX2.cpp: writers, oldest mark
extern "C" void AdrenoPresentSyncCounters(uint64_t *marks, uint64_t *overflows, uint64_t *unmatched);
#endif
// --pipeline (agents/gpu-pipeline FAILURE-MODES.md): -DADRENO_PIPELINE=1 in every unit (AdrenoX2.o needs
// ADRENO_IB_ASYNC and ADRENO_PRESENT_SYNC too). A pipelined client's IB submission returns once the IB is in flight
// (IB_START); IOGPU's completion follows the GPU through a stamp in the queue event (finding 3), the IOSurfaces it
// writes stay marked until it retired, and every other ring user first finishes the flight
// (compat/adreno-ib-pipeline.h). Boot-arg adreno_pipeline: 0 off, 1 WindowServer's tasks (default), 2 every client.
// Off by default; without it this source compiles as before.
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
// --gpu-recover's kext half (agents/gpu-recovery FAILURE-MODES.md; needs ADRENO_IB_ASYNC): the monitor's RESET answers
// fail only the guilty command buffer (IOGPU status 3, 0xb after a fault), the async bound follows the monitor's hard
// limit, and a latch set by an uncertain GPU result is cleared once the monitor's SETTLE proved the GPU idle
// (compat/adreno-recover-guest.h). Off by default; without it this source compiles as before.
#ifndef ADRENO_GPU_RECOVER
#define ADRENO_GPU_RECOVER 0
#endif
#if ADRENO_PIPELINE
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include "../../../../compat/adreno-ib-pipeline.h"
#endif
static_assert(kAdrenoGPUVABase >= ADRENO_WINDOW_BASE &&
              kAdrenoGPUVABase < ADRENO_WINDOW_END &&
              kAdrenoGPUVASize <= ADRENO_WINDOW_END - kAdrenoGPUVABase,
              "task GPU VA range must fit the monitor's shared CB0 window");
static_assert(kAdrenoGPUVABase != 0 && kAdrenoGPUVASize != 0 &&
              !(kAdrenoGPUVABase % kAdrenoGPUVAAlign) &&
              !(kAdrenoGPUVASize % kAdrenoGPUVAAlign),
              "task GPU VA range must exclude zero and align to guest pages");

class AdrenoEventMachine : public IOGPUEventMachine
{
    OSDeclareDefaultStructors(AdrenoEventMachine)
public:
    // The four IOGPUEventMachine pures. IOGPUFamily only reaches them through the channel helpers
    // (writeStampCommand / writeEventBarrierCommand), and the null executor has no channels.
    virtual void writeStamp(int stamp, vendevtCommandRec *rec, unsigned int value) APPLE_KEXT_OVERRIDE;
    virtual void prepareBarrier(vendevtBarrierRec *rec) const APPLE_KEXT_OVERRIDE;
    virtual void completeBarrier(vendevtBarrierRec *rec) const APPLE_KEXT_OVERRIDE;
    virtual void writeBarrierElement(vendevtBarrierRec *rec, int i, unsigned int value) const APPLE_KEXT_OVERRIDE;
};

class AdrenoSysMemory : public IOGPUSysMemory
{
    OSDeclareDefaultStructors(AdrenoSysMemory)
    // IOGPUSysMemory implements the three IOGPUMemory pures; nothing to add for stage 2.
};

class AdrenoResource : public IOGPUResource
{
    OSDeclareDefaultStructors(AdrenoResource)
public:
    // Only AGX's own code calls these (no call site in IOGPUFamily); AGX returns NULL from the second.
    virtual void calculateIOSurfaceDeviceCacheVRAMBytes(unsigned long long *bytes) APPLE_KEXT_OVERRIDE;
    virtual IOMemoryDescriptor *getApertureMemoryDescriptor(unsigned long long *offset) APPLE_KEXT_OVERRIDE;
};

class AdrenoMemoryMap : public IOGPUMemoryMap
{
    OSDeclareDefaultStructors(AdrenoMemoryMap)
public:
    // bool, not IOReturn: IOGPUMemoryMap::commit_pte sets the committed flag and IOGPUMemory::add_mapping
    // succeeds only when this returns non-zero (0xfffffe000a893414, 0xfffffe000a850bb4).
    virtual bool commitIntoGPUPageTable() APPLE_KEXT_OVERRIDE;
    virtual void releaseFromGPUPageTable() APPLE_KEXT_OVERRIDE;
    static AdrenoMemoryMap *withMapper(IOMapper *mapper);
    bool prepareForSubmission();
    void completeSubmission();
    int cacheSubmission(unsigned direction);
#if ADRENO_CACHE_SPARSE
    // Sparse cache ownership (agents/cache-maint FAILURE-MODES.md): cacheSubmission over part of the logical extent,
    // and this map's marks (compat/adreno-resource-list.h), zeroed whenever the backing is pinned or unpinned.
    int cacheRange(unsigned direction, uint64_t offset, uint64_t bytes);
    struct adreno_cache_mark *cacheMark() { return &fCacheMark; }
    void clearCacheMark()
    {
        __atomic_store_n(&fCacheMark.cleaned, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&fCacheMark.invalidated, 0, __ATOMIC_RELAXED);
    }
#endif
    int resolveFill(uint64_t offset, uint64_t bytes, uint64_t *address);
    int resolveRange(uint64_t offset, uint64_t bytes, uint64_t *address);   // IB relocations (design 3.2)
    virtual void free() APPLE_KEXT_OVERRIDE;
    virtual bool allocGPUVirtualAddress() APPLE_KEXT_OVERRIDE;
    virtual bool reserveGPUVirtualAddress(unsigned long long address, unsigned long long length) APPLE_KEXT_OVERRIDE;
    virtual void freeGPUVirtualAddress() APPLE_KEXT_OVERRIDE;
    virtual bool updateGPUPageTable() APPLE_KEXT_OVERRIDE;
    virtual bool updateGPUPageTable(unsigned int options, IOMemoryDescriptor *oldBacking,
                                   IOMemoryDescriptor *newBacking) APPLE_KEXT_OVERRIDE;
private:
    struct adreno_resource_ops operations();
    IOGPUMemory *nativeMemory() const;
    bool nativeAllocated() const;
    bool releaseAddress(); // caller holds the recursive lock
    bool backingKeepable() const; // caller holds the recursive lock
    static int reservePages(void *, uint64_t, uint64_t *, uint64_t *);
    static int freePages(void *, uint64_t, uint64_t);
    static int pinBacking(void *);
    static int unpinBacking(void *);
    static uint64_t physicalPage(void *, uint64_t, uint64_t *);
    static int insertPage(void *, uint64_t, uint64_t, uint64_t, uint64_t);
    static int clearPages(void *, uint64_t, uint64_t);
    static int maintainCache(void *, uint64_t, uint64_t, unsigned);
#if ADRENO_RESOURCE_POOL
    // adreno_resource_bind/retire callbacks (FAILURES-AND-DESIGN.md 2026-10-20, V1-V7): the native fixed
    // bind at exactly one address, and the native CB0 release when this map holds it.
    static int bindNative(void *, uint64_t, uint64_t);
    static void unbindNative(void *);
#endif
    IORecursiveLock *fLock;
    IOMapper *fMapper;
    IOMemoryDescriptor *fBacking;
    IODirection fBackingDirection; // the direction fBacking was prepared with; Out = GPU reads only
    struct adreno_resource fResource;
    uint64_t fLastNativeStatus;
#if ADRENO_CACHE_SPARSE
    struct adreno_cache_mark fCacheMark;
#endif
};

class AdrenoTask : public IOGPUTask
{
    OSDeclareDefaultStructors(AdrenoTask)
public:
    // IOGPUTask::init(gpu, task, count, allocators) retains up to 16 IORangeAllocators; allocate(map)
    // picks one by map+0x12, which IOGPUMemoryMap::init leaves at 0. One allocator is enough.
    static AdrenoTask *withTask(IOGPU *gpu, task_t owner, IORangeAllocator *allocator);
    // Early stop (AdrenoEarlyStop.h): count this task's GPU allocations, and when WindowServer's task that
    // allocated goes away, report it. Both call through to IOGPUTask.
    virtual uint64_t allocate(IOGPUMemoryMap *map) APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;
#if ADRENO_PIPELINE
    bool pipelineClient() const { return fPipelineClient; }   // WindowServer's task (adreno_pipeline=1)
#endif
private:
    bool fWindowServer;           // owner holds WindowServer's own entitlements (withTask)
    uint32_t fSequence;           // nth WindowServer task of this boot, from 1
    uint32_t fAllocations;        // successful allocate() calls, saturating
#if ADRENO_PIPELINE
    bool fPipelineClient;         // WindowServer's entitlements, whether or not early stop is on
#endif
};

class AdrenoSegmentList : public IOGPUSegmentResourceList
{
    OSDeclareDefaultStructors(AdrenoSegmentList)
public:
    virtual bool initWithSharedResourceList(IOGPUDevice *device, IOGPUSegmentResourceListHeader const *header,
                                            IOGPUDeviceShmem *shmem) APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;
private:
    static void *retainResource(void *, uint32_t);
    static void releaseResource(void *, void *);
    static int prepareResource(void *, void *, void **);
    static void completeResource(void *, void *);
    static int syncResource(void *, void *, unsigned);
#if ADRENO_CACHE_SPARSE
    static struct adreno_cache_mark *markResource(void *, void *);
    static int syncRange(void *, void *, unsigned, uint64_t, uint64_t);
    static const struct adreno_cache_ops kCacheOps;
#endif
    static int resolveFill(void *, void *, void *, uint64_t, uint64_t, uint64_t *);
    static int resolveRange(void *, void *, void *, uint64_t, uint64_t, uint64_t *);
public:
    void retainAfterTimeout();
    int submit(int (*work)(void *), void *context);
    int fill(const struct adreno_fill32_request *,
             int (*transfer)(void *, uint64_t, uint64_t, uint32_t), void *context);
    // One ADRENO_KCMD_IB package against this list (compat/adreno-ib-command.c adreno_ib_submit).
    int ib(struct adreno_ib_work *, const void *command, uint64_t bytes,
           int (*ring)(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *), void *context);
#if ADRENO_PRESENT_SYNC
    // agents/present-sync K1: the entries an IB or FILL32 runs against, read (never changed) to mark the IOSurfaces it
    // writes; valid while the list is prepared, which the submission holds.
    const struct adreno_resource_list *presentSyncResources() const { return &fResources; }
#endif
#if ADRENO_PIPELINE
    // agents/gpu-pipeline: the list and its callbacks for compat/adreno-ib-pipeline.h, which keeps the list (retained
    // by the flight's record) across the submission's return; the device names the submitting task (policy).
    struct adreno_resource_list *pipelineResources() { return &fResources; }
    struct adreno_resource_list_ops pipelineOps() const
    {
        const struct adreno_resource_list_ops ops = {fDevice, retainResource, releaseResource, prepareResource,
                                                     completeResource, syncResource};
        return ops;
    }
    static int pipelineResolve(void *c, void *resource, void *token, uint64_t offset, uint64_t bytes, uint64_t *address)
    {
        return resolveRange(c, resource, token, offset, bytes, address);
    }
    IOGPUDevice *pipelineDevice() const { return fDevice; }
    // A FENCE folded into a flight: the list's checks, no maintenance, nothing rung (FAILURE-MODES.md Q3).
    int pipelineValidate()
    {
        const struct adreno_resource_list_ops ops = pipelineOps();
        return adreno_resource_list_validate(&fResources, &ops);
    }
#endif
private:
    IOGPUDevice *fDevice;
    struct adreno_resource_entry *fEntries;
    uint64_t fEntryBytes;
    struct adreno_resource_list fResources;
};

class AdrenoAcceleratorX2;
class AdrenoCommandQueue : public IOGPUCommandQueue
{
    OSDeclareDefaultStructors(AdrenoCommandQueue)
public:
    static AdrenoCommandQueue *withAccelerator(AdrenoAcceleratorX2 *accelerator);
    virtual void free() APPLE_KEXT_OVERRIDE;
    // The base returns NULL, and IOGPUCommandQueue::processCommandBuffer then fails every submission.
    // processCommandBuffer releases the list after reclaimSegmentList, so this returns a +1 object.
    virtual IOGPUSegmentResourceList *parseSegmentList(IOGPUDevice *device, IOGPUSegmentResourceListHeader const *header,
                                                       IOGPUDeviceShmem *shmem) APPLE_KEXT_OVERRIDE;
    // The base handles kernel-command types 0 and 1 and flags anything else as submission error 0xa.
    virtual void processSegmentKernelCommand(IOGPUSegmentResourceList *list, IOGPUKernelCommand const *command,
                                             IOGPUKernelCommand const *end, unsigned char const *segmentStart,
                                             unsigned char const *segmentEnd,
                                             IOGPUCommandQueueCommandBufferArgs const *args) APPLE_KEXT_OVERRIDE;
private:
    // compat/adreno-ib-command.h adreno_kernel_command callbacks (FENCE, FILL32, IB).
    static int fence(void *context);
    static int fill(void *context, const struct adreno_fill32_request *);
    static int ib(void *context, const void *command, uint64_t bytes);
    AdrenoAcceleratorX2 *fAccelerator;
};

class AdrenoAcceleratorX2 : public IOGPU
{
    OSDeclareDefaultStructors(AdrenoAcceleratorX2)
public:
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;
    // IOGPU does not override it (IOGPUFamily26A428.h); only ADRENO_EARLY_STOP_FAILURE_KEY is handled here.
    virtual IOReturn setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;
    int submitFence(AdrenoSegmentList *); // serializes cache ownership and GPU work across queues
    int submitFill(AdrenoSegmentList *, const struct adreno_fill32_request *);
#if ADRENO_PIPELINE
    // The queue: its event takes a pipelined IB's stamp, its current fence the asynchronous failure status.
    int submitIB(AdrenoSegmentList *, const void *command, uint64_t bytes, IOGPUCommandQueue *queue);
    void pipelineTimerFired();
#else
    int submitIB(AdrenoSegmentList *, const void *command, uint64_t bytes);   // ADRENO_KCMD_IB
#endif
    void noteCommandFailure(int result);   // rate-limited log of kernel commands completed with error 0xa
#if ADRENO_GPU_RECOVER
    // agents/gpu-recovery R26: the IOGPU status word a kernel command that failed with `result` completes with
    // (compat/adreno-recover-guest.h adreno_recover_guest_status).
    uint32_t recoverStatus(int result) const;
#endif

    // The ten IOGPU pures.
    virtual IOMemoryDescriptor *getStampMemory(unsigned int *offset) APPLE_KEXT_OVERRIDE;
    virtual IOGPUEventMachine *newEventMachine() APPLE_KEXT_OVERRIDE;
    virtual IOGPUTask *createUserGPUTask(task *owner) APPLE_KEXT_OVERRIDE;
    virtual void populateAccelConfig(IOGPUConfig *config) APPLE_KEXT_OVERRIDE;
    virtual bool configureDevice(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void teardownDevice(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual IOGPUTask *createKernelGPUTask() APPLE_KEXT_OVERRIDE;
    virtual IOGPUSysMemory *newSysMemory() APPLE_KEXT_OVERRIDE;
    virtual IOGPUResource *newResource() APPLE_KEXT_OVERRIDE;
    virtual IOGPUMemoryMap *newMemoryMap() APPLE_KEXT_OVERRIDE;

    // Not pure, but the base returns a plain IOGPUCommandQueue (no parseSegmentList).
    virtual IOGPUCommandQueue *newCommandQueue() APPLE_KEXT_OVERRIDE;

private:
    bool prepareStampDMA();
    int probeGuestFence();   // 0, ADRENO_SUBMIT_E_INACTIVE (refused before the ring) or ADRENO_SUBMIT_E_UNCERTAIN
#if ADRENO_GPU_RECOVER
    // agents/gpu-recovery R27/R28: under fSubmitLock with the latch set, ask the monitor to SETTLE (rate-limited); clears
    // the latch once it proved the GPU idle (compat/adreno-recover-guest.h adreno_recover_guest_unlatch).
    void recoverLatched();
#endif
    static int fenceWork(void *);
    static int fillWork(void *, uint64_t, uint64_t, uint32_t);
    static int fenceGated(void *);
    static int fillGated(void *);
    static int ibGated(void *);
    static int ibRing(void *, uint64_t, uint64_t, uint64_t, struct adreno_ib_reply *);
    bool releaseStampDMA();
    // Draw submission (design 3.4-3.6): IB work storage, the GPU-read-only arena, the start-time probe.
    void configureGuestIB(IOService *provider);
    bool allocateIBWork();
    void freeIBWork();
    bool prepareIBArena();
    bool releaseIBArena();
    IOBufferMemoryDescriptor *fStamps;
    IORangeAllocator *fGPUVA;
    IOMapper *fMapper;
    IODMACommand *fStampDMA;
    uint64_t fStampGPUAddress;
    uint64_t fStampGPULength;
    bool fStampWired;
    bool fStampDMAActive;
    // The fail-fast latch (plan M7), shared by FENCE, FILL32 and IB through adreno_submit_gated: set on any
    // UNCERTAIN/VISIBILITY result or failed DMA cleanup; then no GPU HVC runs and every backing stays retained.
    uint8_t fStampCleanupFailed;
    IOLock *fSubmitLock;
    uint64_t fSubmittedFences;
    uint64_t fSubmittedFills;
    uint64_t fSubmittedIBs;
    uint64_t fFailedCommands;
    IOBufferMemoryDescriptor *fIBArena;
    IODMACommand *fIBDMA;
    uint64_t fIBGPUAddress;
    uint64_t fIBGPULength;
    bool fIBWired;
    bool fIBDMAActive;
    struct adreno_ib_work *fIB;
    struct adreno_ib_tables *fIBTables;
    struct adreno_ib_reloc *fIBRelocs;
    uint16_t *fIBOrder;
    uint8_t *fIBUsed;
    uint64_t *fIBTargets;
#if ADRENO_PIPELINE
    // agents/gpu-pipeline: the engine (compat/adreno-ib-pipeline.h), its second package slot (fIB is the first), the
    // flight records, the completion timer on its own workloop, and IOGPU's stamp. All under fSubmitLock except the
    // timer's arming flag and the post list's hand-off (taken under the lock, worked after it).
    struct AdrenoFlightRecord;
    bool pipelineStart(IOGPUEventMachine *events);
    void pipelineStop();
    bool pipelineBindSlot1();
    void pipelineFreeSlot1();
    bool pipelineEligible(AdrenoSegmentList *list);
    AdrenoFlightRecord *recordAlloc();
    void pipelineTakePost(AdrenoFlightRecord **out, unsigned *n);
    void pipelinePost(AdrenoFlightRecord *const *records, unsigned n);
    void pipelineArm();
    void pipelineFinishLocked(AdrenoFlightRecord **post, unsigned *n);   // FILL32, teardown: the flight first
    static uint64_t pipeNow(void *);
    static uint32_t pipeStamp(void *, void *owner);
    static void pipeRetired(void *, void *owner, int result, const struct adreno_ib_reply *final, uint32_t stamp);
    struct adreno_pipe fPipe;
    struct adreno_pipe_ops fPipeOps;
    struct adreno_ib_work *fIB2;
    struct adreno_ib_reloc *fIBRelocs2;
    uint16_t *fIBOrder2;
    uint8_t *fIBUsed2;
    uint64_t *fIBTargets2;
    AdrenoFlightRecord *fRecords;          // ADRENO_PIPE_RECORDS of them: one in flight, one being finished, spares
    AdrenoFlightRecord *fPost[4];          // retired under the lock, posted after it
    unsigned fPostCount;
    IOWorkLoop *fPipeLoop;
    IOTimerEventSource *fPipeTimer;
    IOGPUEventMachine *fPipeEvents;
    uint64_t fPipePollTicks, fPipeLeewayTicks;
    uint32_t fPipeTimerArmed;              // atomic
    uint32_t fPipeMode;                    // adreno_pipeline: 0 off, 1 WindowServer, 2 every client
    uint32_t fPipeOn;                      // the engine is in use (mode, monitor, slots, IOGPU self-test)
    uint32_t fPipeStampIndex;
#endif
};
