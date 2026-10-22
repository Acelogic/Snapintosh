/* SPDX-License-Identifier: MIT */
// AdrenoDisplay.cpp - see AdrenoDisplay.h. Each behaviour cites the AppleParavirtDisplay
// (KDK 26A428 AppleParavirtGPUIOGPUFamily, arm64e) routine it mirrors.
#include "AdrenoDisplay.h"
#include "AdrenoDisplayCopy.h"
#include "AdrenoEarlyStop.h"
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSSet.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <uuid/uuid.h>

extern "C" task_t kernel_task;
#if ADRENO_PERF_FRAMES
extern "C" uint64_t gAdrenoIBCompleted, gAdrenoIBCompletedAt;   // AdrenoX2.cpp submitIB
#if ADRENO_RESOURCE_POOL
extern "C" void AdrenoGPUMapCounters(uint64_t *);              // AdrenoMemoryMap.cpp
#endif
#if ADRENO_VA_RECLAIM
extern "C" void AdrenoGPUVACounters(uint64_t *);               // AdrenoMemoryMap.cpp (agents/gpu-va)
#endif
#if ADRENO_LATCH
extern "C" uint64_t gAdrenoGPUBusy;                            // AdrenoX2.cpp: submissions in the kext (G1)
#endif
#if ADRENO_PERF_GPU
extern "C" void AdrenoGPUWorkCounters(uint64_t *);             // AdrenoMemoryMap.cpp
extern "C" uint64_t gAdrenoIBGpuTicks, gAdrenoIBGpuTicksMax, gAdrenoIBSubmitTicks, gAdrenoIBLockTicks;   // AdrenoX2.cpp
#endif
static uint64_t perfNs(uint64_t ticks)
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(ticks, &ns);
    return ns;
}
#endif
#if ADRENO_PRESENT_SYNC
extern "C" uint32_t AdrenoPresentSyncQuery(uint32_t surfaceID, uint64_t *oldest);   // AdrenoX2.cpp: writers, oldest mark
extern "C" void AdrenoPresentSyncCounters(uint64_t *marks, uint64_t *overflows, uint64_t *unmatched);
#endif
#if ADRENO_PIPELINE
extern "C" uint32_t AdrenoPipelineCounters(uint64_t *v);   // AdrenoX2.cpp: the engine's totals (AdrenoDisplayPipe.h)
#endif
#if ADRENO_PRESENT_RELATCH
extern "C" uint32_t AdrenoPipelineEarlyCounters(uint64_t *v);   // AdrenoX2.cpp: EP1-EP3 totals and switches (OP1)
#endif

// ---------------------------------------------------------------- IOAVFamily
// Only the exported factories AppleParavirtDisplay imports; the class layouts stay opaque.
// Manglings (checked by tools/check-iomfb-vtable.py against the kernelcache exports):
//   __ZN22IOAVVideoTimingElement8withDataEPK19IOAVVideoTimingData16IOAVStandardType23IOAVVideoTimingStandard
//   __ZN22IOAVVideoTimingElement16setColorElementsEP7OSArray
//   __ZN21IOAVVideoColorElement16withCapabilitiesE16IOAVStandardTypej22IOAVVideoPixelEncoding
//     26IOAVVideoColorDynamicRange18IOAVVideoColorEOTF20IOAVVideoColorimetrybPK12OSDictionaryS7_S7_PK5OSSet
enum IOAVStandardType : uint32_t {};
enum IOAVVideoTimingStandard : uint32_t {};
enum IOAVVideoPixelEncoding : uint32_t {};
enum IOAVVideoColorDynamicRange : uint32_t {};
enum IOAVVideoColorEOTF : uint32_t {};
enum IOAVVideoColorimetry : uint32_t {};
// createTimingElementWithDimensionsAndRate (PV 0xe49c) zeroes 0x50 bytes and fills four words.
struct IOAVVideoTimingData {
    uint32_t h0, h1;
    uint32_t hActive, h3;         // +0x08
    uint32_t h4, h5;
    uint32_t hSyncRate, h7;       // +0x18 = refresh * vActive (line rate, same fixed point)
    uint32_t v0, v1;
    uint32_t vActive, v3;         // +0x28
    uint32_t v4, v5;
    uint32_t vSyncRate, v7;       // +0x38 = refresh
    uint32_t tail[4];
};
static_assert(sizeof(IOAVVideoTimingData) == 0x50, "IOAVVideoTimingData size (PV zeroes 0x50)");
class IOAVVideoTimingElement : public OSObject {
public:
    static IOAVVideoTimingElement *withData(const IOAVVideoTimingData *, IOAVStandardType, IOAVVideoTimingStandard);
    void setColorElements(OSArray *);
};
class IOAVVideoColorElement : public OSObject {
public:
    static IOAVVideoColorElement *withCapabilities(IOAVStandardType, unsigned int, IOAVVideoPixelEncoding,
                                                   IOAVVideoColorDynamicRange, IOAVVideoColorEOTF,
                                                   IOAVVideoColorimetry, bool, const OSDictionary *,
                                                   const OSDictionary *, const OSDictionary *, const OSSet *);
};
// IOAVElement keeps an ID at +0x10 (u64) and a score at +0x18 (u32); PV writes both directly
// (createTimingElementWithDimensionsAndRate 0xe4f4..0xe504, createColorElementWithDepthAndEDR 0x9554).
static void setAVElementIdentity(OSObject *element, uint32_t id, uint32_t score)
{
    *(uint64_t *)((uint8_t *)element + 0x10) = id;
    *(uint32_t *)((uint8_t *)element + 0x18) = score;
}

// IOUserClient::sendAsyncResult64WithOptions is protected; PV reaches it through its user-client
// subclass (AppleParavirtDisplayUserClient::sendAsyncResult64WithOptions, 0x8000). Never instantiated.
struct AdrenoDisplayAsync : public IOUserClient {
    static IOReturn send(OSAsyncReference64 ref, io_user_reference_t *args, uint32_t n)
    {
        return sendAsyncResult64WithOptions(ref, kIOReturnSuccess, args, n, kIOUserNotifyOptionCanDrop);
    }
};

#define super IOMobileFramebufferLegacy
OSDefineMetaClassAndStructors(AdrenoDisplay, IOMobileFramebufferLegacy)

static constexpr IOMFBSwapCompletionState kSwapStateStarted = (IOMFBSwapCompletionState)2;
static bool putNum(OSDictionary *d, const char *key, uint64_t v, unsigned bits = 32);

// ---------------------------------------------------------------- accelerator hook

bool AdrenoDisplayAttach(IOService *accelerator)
{
    // AppleParavirtGPU::start 0x15a28..0x15ad4: OSTypeAlloc, init(nullptr), attach(gpu),
    // start(gpu), detach on failure. The registry's attach reference keeps the display
    // alive; terminating the accelerator terminates this only child with it.
    //
    // Opt-in by board: the display is created only on a device tree whose external
    // display graph is withdrawn (the -adreno-metal-display profile). On any board that
    // still has /arm-io/dispext0 (the deployed -adreno-metal profile) the framework
    // expects two IOMFB services, so this one would become the main display next to a
    // 30 s wait per client, and the GOP remap would run on a board never meant to
    // present. boot-arg adreno_display=0 forces it off, adreno_display=1 forces it on.
    uint32_t enabled = 0;
    if (!accelerator)
        return false;
    if (PE_parse_boot_argn("adreno_display", &enabled, sizeof(enabled))) {
        if (!enabled) {
            IOLog("AdrenoDisplay: disabled by boot-arg adreno_display=0\n");
            return false;
        }
    } else {
        IORegistryEntry *external = IORegistryEntry::fromPath("/arm-io/dispext0", gIODTPlane);
        if (external) {
            external->release();
            IOLog("AdrenoDisplay: not created: /arm-io/dispext0 present (not the display board; "
                  "boot-arg adreno_display=1 forces it)\n");
            return false;
        }
    }
    AdrenoDisplay *display = OSTypeAlloc(AdrenoDisplay);
    if (!display)
        return false;
    bool ok = display->init(nullptr);
    if (ok) {
        ok = display->attach(accelerator);
        if (ok && !display->start(accelerator)) {
            display->detach(accelerator);
            ok = false;
        }
    }
    display->release();
    IOLog("AdrenoDisplay: %s\n", ok ? "started under the accelerator" : "not started; accelerator unaffected");
    return ok;
}

// ---------------------------------------------------------------- IOService

bool AdrenoDisplay::start(IOService *provider)
{
    // PV start (0x9664): one property, then the family start. The family start creates
    // the gate, event sources and user-client plumbing and calls start_hardware()
    // (IOMobileFramebufferLegacy::start 0x1f6c4) and registerService (0x1f790).
    // PV sets "CursorPlane" = 1 (0x969c..0x96b0: setProperty("CursorPlane", 1, 32)) and
    // programs a hardware cursor from layer 1. QuartzCore 26A428 reads it in
    // CA::WindowServer::AppleDisplay::AppleDisplay (0x18b0a23d4, a CFNumber SInt8 into the
    // display's cursor plane, this+0x69b3) only when CADeviceIsVirtualized (MobileGestalt
    // IsVirtualDevice); otherwise the plane is IOMFBSupportsGPLite ? 3 : 1 (0x18b0a189c).
    // The hardware cursor is used unless the CAUseSWCursor default is set
    // (IOMFBDisplay::hw_supports_cursor 0x18b39fffc), so it never was a software cursor in
    // layer 0: the old 0 here named layer 0 itself on a virtualized device and was ignored
    // otherwise, and the cursor layer was dropped. Layer 1 is now composited
    // (updateCursorGated); 2 and 3 are accepted too.
    setProperty("CursorPlane", 1ULL, 32);
    fSwapInfoHead = fSwapInfoTail = 0;
    return super::start(provider);
}

void AdrenoDisplay::stop(IOService *provider)
{
    super::stop(provider);
}

void AdrenoDisplay::free()
{
    OSSafeReleaseNULL(fColorElements);
    OSSafeReleaseNULL(fTimingElements);
    releaseSurfaceMaps();
    releaseCursor();
    releasePresentBuffers();
    unmapScanout();
#if ADRENO_BEAM
    beamUnmap();
#endif
    super::free();
}

// ---------------------------------------------------------------- pure virtuals

IOReturn AdrenoDisplay::set_notify_tag_mask_gated(IOMFB_NotificationType type, IOMFBNotifyRequest *req,
                                                  unsigned int mask)
{
    // PV 0xefb8: only the swap-info notification (type 3) has a tag mask, kept at req+0x78.
    if ((uint32_t)type != 3)
        return kIOReturnBadArgument;
    *(uint32_t *)((uint8_t *)req + 0x78) = mask;
    return kIOReturnSuccess;
}

IOReturn AdrenoDisplay::supported_frame_info(unsigned int, unsigned int *, char (*)[64], unsigned int *)
{
    return kIOReturnUnsupported;                                // PV 0xefdc
}

IOReturn AdrenoDisplay::factory_portal(void *, task *)
{
    return kIOReturnUnsupported;                                // PV 0xefec
}

IOReturn AdrenoDisplay::executeFactoryConfigurations_gated()
{
    return kIOReturnUnsupported;                                // PV 0xeffc
}

void AdrenoDisplay::set_frame_info_notification_state_gated(IOMFBNotifyRequest *, bool)
{
    // PV 0xf00c: nothing.
}

void AdrenoDisplay::do_swap_info_notify_gated(IOMFBNotifyRequest *req,
                                              const IOMobileFramebufferLegacy::SwapInfoBlob *blob)
{
    // PV 0xf014: args[0] = tag mask (req+0x78), args[1] = swap id (blob+0); then for each
    // set mask bit i < 5 the blob quadword at +8+8i (bit 1: delta against req+0x80),
    // split in two 32-bit halves when mask bit 31 is set; at most 12 arguments.
    const uint8_t *b = blob->bytes;
    uint32_t mask = *(const uint32_t *)((const uint8_t *)req + 0x78);
    uint64_t *last = (uint64_t *)((uint8_t *)req + 0x80);
    io_user_reference_t args[12] = {};
    uint32_t n = 0;
    args[n++] = mask;
    args[n++] = *(const uint32_t *)b;
    const uint64_t *q = (const uint64_t *)(b + 8);
    for (uint32_t i = 0; i < 5; i++) {
        if (!((mask >> i) & 1))
            continue;
        uint64_t v = (i == 1) ? q[0] - *last : q[i];
        if (n == 12) {
            IOLog("AdrenoDisplay: swap-info notification argument overflow\n");
            continue;
        }
        if (mask & 0x80000000u) {
            args[n++] = (uint32_t)v;
            if (n < 12)
                args[n++] = v >> 32;
        } else {
            args[n++] = v;
        }
    }
    *last = q[0];
    AdrenoDisplayAsync::send(*(OSAsyncReference64 *)((uint8_t *)req + 0x18), args, n);
}

IOReturn AdrenoDisplay::notify_swap_done_gated(unsigned int swapID, ::SwapInfoBlob *, unsigned int *, unsigned int)
{
    // PV 0xf148: refuse when the current swap was aborted (state != 0); otherwise fill the
    // ring entry {id, this+0x108, 0, swap+0x390, swap+0x3d0, 0} and, unless dispatch is
    // held (u16 at this+0x1dd2), drain the ring through swap_info_notify_dispatch_gated.
    IOMFBSwapIORequest *swap = fCurrentSwap;
    if (!swap || IOMFBSwapFields::state(swap) != 0)
        return kIOReturnUnsupported;
    uint8_t *e = fSwapInfo[fSwapInfoTail].bytes;
    bzero(e, sizeof(fSwapInfo[0]));
    *(uint32_t *)e = swapID;
    *(uint64_t *)(e + 0x08) = *(const uint64_t *)((const uint8_t *)this + 0x108);
    *(uint64_t *)(e + 0x18) = *(const uint64_t *)((const uint8_t *)swap + 0x390);
    *(uint64_t *)(e + 0x20) = *(const uint32_t *)((const uint8_t *)swap + 0x3d0);
    uint16_t held = *(const uint16_t *)((const uint8_t *)this + 0x1dd2);
    uint32_t tail = fSwapInfoTail;
    fSwapInfoTail = (fSwapInfoTail + 1) % kSwapInfoRing;
    if (held)
        return kIOReturnSuccess;
    while (fSwapInfoHead != tail) {
        swap_info_notify_dispatch_gated(&fSwapInfo[fSwapInfoHead]);
        fSwapInfoHead = (fSwapInfoHead + 1) % kSwapInfoRing;
    }
    swap_info_notify_dispatch_gated(&fSwapInfo[tail]);
    fSwapInfoHead = fSwapInfoTail;
    return kIOReturnSuccess;
}

void AdrenoDisplay::notify_crc_ready_gated(unsigned int)
{
    // PV 0xf278: nothing.
}

bool AdrenoDisplay::are_timings_enabled() const
{
    return false;                                               // PV 0x126d8
}

// ---------------------------------------------------------------- swap engine

bool AdrenoDisplay::verify_swap(IOMFBSwapIORequest *)
{
    return true;                                                // PV 0x125e0 (the base returns false)
}

IOReturn AdrenoDisplay::swap_layer_map(IOMFBSwapIORequest *, unsigned int)
{
    return kIOReturnSuccess;                                    // PV 0x126e4
}

IOReturn AdrenoDisplay::surface_layer_map(IOMFB::AP::DisplayedData *, unsigned int, IOSurface *)
{
    return kIOReturnSuccess;                                    // PV 0x126f0
}

void AdrenoDisplay::surface_layer_unmap(IOMFB::AP::DisplayedData *, unsigned int)
{
    // PV 0x126fc: nothing.
}

bool AdrenoDisplay::cleanQueueGated()
{
    // PV clean_queue_gated 0x119a8: nothing while a swap is on screen; otherwise let the
    // family discard obsolete, no-op, aborted and dummy swaps, and report what is left.
    if (fCurrentSwap)
        return false;
    if (!fPendingSwapFirst)
        return false;
    if (dropObsoleteSwaps_gated())
        return false;
    dropNoOpSwaps_gated();
    dropAbortedSwaps_gated(false);
    dropDummySwaps_gated();
    return fPendingSwapFirst != nullptr;
}

void AdrenoDisplay::swap_begin_gated()
{
    // PV swap_begin_gated 0x11aac, with one change: PV cancels and re-arms its timer on every
    // call because the host completes swaps; here the timer *is* the completion, so it is
    // armed once per frame and never pushed back by a stream of submissions.
#if ADRENO_PERF_FRAMES
    // F1: one clock read when a swap is first seen pending on the submission path.
    if (!fInTick && fPendingSwapFirst && !fPendingSince) fPendingSince = mach_absolute_time();
#endif
#if ADRENO_LATCH
    // H1 H11: R, from the last release to the first arrival after it (F1's clock read; nothing if none is pending).
    if (!fInTick && fPendingSince && fHold.released_at) adreno_hold_arrival(&fHold, fPendingSince);
#endif
#if ADRENO_BEAM
    // C6: with the beam locked, a layer-0 swap that finds nothing on screen outside a tick waits for the next vblank
    // (the timer is armed for it) instead of being copied at a random phase; cursor-only swaps still go at once (C7).
    if (!fInTick && !fCurrentSwap && fBeamRegs && fBeam.state == ADRENO_BEAM_LOCKED && cleanQueueGated() &&
        (IOMFBSwapFields::layerMask(fPendingSwapFirst) & 1)) {
        armFrameTimerGated();
        return;
    }
#endif
    while (cleanQueueGated()) {
#if ADRENO_PRESENT_SYNC
        // K1 K3 K4: a layer-0 head whose surface the GPU is still writing stays queued; the timer below is armed for it
        // (beam GO or grid), the swap on screen stays as it is. Nothing is written to the scanout.
        if (syncWaitGated(fPendingSwapFirst))
            break;
#endif
        IOMFBSwapIORequest *swap = fPendingSwapFirst;
        fCurrentSwap = swap;
        update_swap_info_state_gated(swap, kSwapStateStarted);
        // TAILQ_REMOVE(pending, swap), with the same consistency checks PV traps on.
        IOMFBSwapIORequest *next = IOMFBSwapFields::queueNext(swap);
        IOMFBSwapIORequest **prev = IOMFBSwapFields::queuePrev(swap);
        if (next) {
            if (IOMFBSwapFields::queuePrev(next) != &IOMFBSwapFields::queueNext(swap) || *prev != swap)
                panic("AdrenoDisplay: corrupt swap queue at %p", swap);
            IOMFBSwapFields::queuePrev(next) = prev;
        } else {
            if (*prev != swap)
                panic("AdrenoDisplay: corrupt swap queue tail at %p", swap);
            fPendingSwapLast = prev;
        }
        *prev = next;
        if ((IOMFBSwapFields::state(swap) & ~8u) == 0) {
            uint8_t layers = IOMFBSwapFields::layerMask(swap);
            // The frame tick is armed before the copy (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): the
            // period is then max(copy, kFramePeriodMS), not copy + kFramePeriodMS. The tick runs on this work loop,
            // so it can never complete a swap before its copy has returned.
            armFrameTimerGated();
#if ADRENO_PERF_FRAMES
            fPresentQueuedAt = fPendingSince;
            fPendingSince = 0;
#endif
#if ADRENO_LATCH
            if (swap == fPrecopied) fPrecopied = nullptr;   // H4: dequeued by today's path: its marker goes
#endif
            presentGated(swap);
            // PV program_hardware_gated 0x11934..0x119a4: a swap that programs no layer-0
            // surface is completed at once (tail call through vtable +0xd00,
            // swap_complete_gated), and PV's swap_begin_gated loop (0x11bc8 clean_queue_gated,
            // 0x11bd0 back to the dequeue) takes the next swap in the same call. Done here for
            // cursor-only swaps, so they never hold a frame tick ahead of a layer-0 swap; every
            // other swap still completes on the tick as before. swap_complete_gated (iomgf
            // 0x210a0) does not re-enter swap_begin_gated.
            if (!(layers & 1) && (layers & kOverlayLayers)) {
                fSwapPresented = false;
                fCursorImmediate++;
                swap_complete_gated();
                continue;
            }
            break;                       // on screen until the next frame tick completes it
        }
        dropSwap_gated(swap, false);     // PV: aborted/rejected swaps are dropped, not shown
        fDropCount++;
    }
    armFrameTimerGated();
}

void AdrenoDisplay::armFrameTimerGated()
{
    if (!fFrameTimer || fFrameTimerArmed)
        return;
    if (!fCurrentSwap && !fPendingSwapFirst)
        return;
#if ADRENO_BEAM
    if (beamArmGated())
        return;                              // armed on the panel's real vblank; otherwise the grid below
#endif
#if ADRENO_VSYNC60
    // S1 S2 S6: the next grid point (never in the past, missed points skipped, re-sync after a long idle), armed
    // early by the slop the thread-call timer will add. No kIOTimeOptionsWithLeeway: 26A428 would use
    // max(leeway, coalescing slop), which can only be later. One clock read per arm, as before.
    const uint64_t now = mach_absolute_time();
    const uint64_t at = adreno_vsync_arm_time(&fVsync, now, adreno_vsync_target(&fVsync, now, fInTick));
    if (fFrameTimer->wakeAtTime(0, at, 0) != kIOReturnSuccess) {
        adreno_vsync_arm_failed(&fVsync);  // S4: not armed; the next swap arms again
        return;
    }
    fFrameTimerArmed = true;
    fArmedAt = now;
#else
    fFrameTimerArmed = true;
#if ADRENO_PERF_FRAMES
    fArmedAt = mach_absolute_time();       // F9: one clock read per arm
#endif
    fFrameTimer->setTimeoutMS(kFramePeriodMS);
#endif
}

void AdrenoDisplay::vsyncGated(IOTimerEventSource *)
{
    // Frame tick (emulated vsync): the swap copied during the last frame is now "displayed".
#if ADRENO_PERF_FRAMES
    const uint64_t now = mach_absolute_time(), armed = fArmedAt, copies = fCopyTimed;   // F1: one read per tick
    const bool completed = fCurrentSwap && fSwapPresented;
#if ADRENO_VSYNC60
    const uint64_t grid = adreno_vsync_fired(&fVsync, now);   // S7 S8: before swap_begin_gated re-arms from it
    (void)armed;
#endif
#endif
    fFrameTimerArmed = false;
#if ADRENO_BEAM
    if (beamFireGated())
        return;                          // C1 C2: re-armed for its vblank; nothing completed or copied
#endif
#if ADRENO_PRESENT_RELATCH
    relatchEndGated(true);               // RL3 RL4: a tick that proceeds ends a pending relatch (its frame has gone)
    fRelatchCandidate = nullptr;
#endif
#if ADRENO_LATCH
    // H1-H8: a GO with the hold on keeps the swap on screen current and copies the pending one; otherwise today's tick,
    // after which a layer-0 swap it put on screen gets its release (and a release armed for the swap it completed goes).
    fInTick = true;
    const bool held = holdLatchGated();
    fInTick = false;
    if (!held) {
        if (fReleaseArmed && fCurrentSwap && fSwapPresented) {
            fReleaseTimer->cancelTimeout();
            fReleaseArmed = false;
        }
#endif
    if (fCurrentSwap && fSwapPresented) {
        fSwapPresented = false;
        swap_complete_gated();           // family: notify_swap_done_gated, release, clear +0x1a40
    }
#if ADRENO_PERF_FRAMES
    fInTick = true;
#endif
#if ADRENO_LATCH
    if (copyGatedGated()) {              // G1-G3: a fresh layer-0 swap waits one latch while the GPU has work
        fHold.gated++;
        armFrameTimerGated();
    } else
#endif
    swap_begin_gated();
#if ADRENO_PRESENT_RELATCH
    relatchArmGated();                   // RL4: this tick's sync gate deferred its head and nothing took the GO's frame
#endif
#if ADRENO_BEAM
    fBeam.go_row0 = 0;                   // a GO whose tick copied nothing: its frame is not kept for a later present
#endif
#if ADRENO_LATCH
        fInTick = false;
        if (fHold.enabled && fCurrentSwap && fSwapPresented && fBeamRegs && fBeam.state == ADRENO_BEAM_LOCKED) {
            fHold.fallbacks++;
            holdArmReleaseGated();
        }
    }
#endif
#if ADRENO_PERF_FRAMES
    fInTick = false;
    // F6: ready when a layer-0 copy started in this tick.
#if ADRENO_VSYNC60
    // S8: late against the grid point, on the 16.667 ms grid.
    adreno_pacing_tick(&fPacing, perfNs(now), grid ? perfNs(grid - fVsync.period) : 0, perfNs(fVsync.period),
                       completed, fCopyTimed != copies);
#else
    adreno_pacing_tick(&fPacing, perfNs(now), armed ? perfNs(armed) : 0, (uint64_t)kFramePeriodMS * 1000000u,
                       completed, fCopyTimed != copies);
#endif
#endif
}

// FROM_DEVICE maintenance of source bytes before the CPU reads them.
// Adreno writes are not coherent with the CPU caches. The kext already invalidates every
// GPU-written resource (render targets included) over its whole length after completion
// (adreno_resource_list_submit); this still covers a list whose FROM_DEVICE did not run,
// writers outside the resource list, and mismatched cacheable aliases of a write-combined
// surface. DC CIVAC, not DC IVAC: a CPU-drawn surface (the guest display probe) may still
// hold its only copy in dirty lines, which IVAC would discard. At EL1 with HCR_EL2.VM set
// the architecture performs IVAC as CIVAC anyway. The exported flush_dcache64 is
// `dsb sy; ret` on this coherent-I/O kernel (KDK 0xfffffe0007530080), so the kext issues
// the instructions on its own mapping.
//
// The layer-0 present maintains every row it will read in one pass, without a barrier per
// row, then issues presentBarrier once (AdrenoDisplayPresent.h): DC CIVAC is not ordered
// against later loads of Normal Non-cacheable memory without a DMB/DSB, and QuartzCore
// allocates IOMFB framebuffers write-combined. No clock here: mach_absolute_time reads
// S3_4_C15_C10_6, which traps to the monitor (docs/CLOCK-TIMER-20260919.md).
static void maintainSourceRange(void *, const void *address, uint64_t bytes)
{
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t line = 4ull << ((ctr >> 16) & 15);            // DminLine, bytes
    uintptr_t p = (uintptr_t)address & ~(uintptr_t)(line - 1);
    uintptr_t end = (uintptr_t)address + bytes;
    for (; p < end; p += line)
        __asm__ volatile("dc civac, %0" :: "r"(p) : "memory");
}

static void presentBarrier(void *)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

static uint64_t presentClock(void *)
{
    return mach_absolute_time();
}

// The cursor capture (at most 512 rows): each row maintained and completed before it is read.
static void maintainSourceRow(void *context, const void *address, uint64_t bytes)
{
    maintainSourceRange(context, address, bytes);
    __asm__ volatile("dsb sy" ::: "memory");
}

// The stage-1 attributes the CPU really uses for a kernel mapping: AT S1E1R, then PAR_EL1
// bits 63:56 (the MAIR attribute byte: 0x44 Normal Non-cacheable, 0xff Normal Write-Back,
// 0x00 Device-nGnRnE), or 0x100 | FST when the walk faults. Interrupts are off so that no
// handler's own AT replaces PAR_EL1 in between (as xnu's mmu_kvtop); the monitor preserves
// PAR_EL1 across its exits (probes/xnuboot.c guest_pa). The physical address is not kept.
static uint64_t mappingAttribute(const void *va)
{
    uint64_t par;
    boolean_t enabled = ml_set_interrupts_enabled(FALSE);
    __asm__ volatile("at s1e1r, %1\n\tisb\n\tmrs %0, par_el1" : "=r"(par) : "r"(va) : "memory");
    ml_set_interrupts_enabled(enabled);
    return (par & 1) ? (0x100 | ((par >> 1) & 0x3f)) : (par >> 56);
}

IOMemoryMap *AdrenoDisplay::mapSurfaceGated(IOMemoryDescriptor *md, SurfaceMap *slots, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (slots[i].md == md && slots[i].map) {
            slots[i].lastUse = fPresentCount;
            return slots[i].map;
        }
    }
    // An empty slot, else the least recently presented one.
    uint32_t victim = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (!slots[i].md) {
            victim = i;
            break;
        }
        if (slots[i].lastUse < slots[victim].lastUse)
            victim = i;
    }
    SurfaceMap &slot = slots[victim];
    OSSafeReleaseNULL(slot.map);
    OSSafeReleaseNULL(slot.md);
    IOMemoryMap *map = md->createMappingInTask(kernel_task, 0, kIOMapAnywhere | kIOMapReadOnly, 0, 0);
    if (!map)
        return nullptr;
    md->retain();
    slot.md = md;
    slot.map = map;
    slot.lastUse = fPresentCount;
    return map;
}

#if ADRENO_PRESENT_CACHED_READ
// PAR_EL1.ATTR (mappingAttribute) is Normal memory, inner and outer write-back (0b01RW or
// 0b11RW with RW != 0, Arm ARM MAIR encoding); 0x44 (non-cacheable), device and faults are not.
static bool attrWriteBack(uint64_t attr)
{
    if (attr > 0xff)
        return false;
    unsigned in = attr & 15, out = (attr >> 4) & 15;
    return (in & 4) && (in & 3) && (out & 4) && (out & 3);
}

// --present-cached-read (FAILURES-AND-DESIGN.md section 10). The layer-0 map, with one
// conversion attempt per new slot:
//   1. the default-mode map, as today; already write-back (M10): done;
//   2. a kIOMapCopybackCache map of the same descriptor. 26A428's memoryReferenceMap turns the
//      mode into MAP_MEM_ONLY on the surface's own named entry, and vm_object_change_wimg_mode
//      converts the whole object and every mapping of it through SPTM (10.1);
//   3. probe 1: the copyback map walks to write-back (else M3); probe 2: the default map made in
//      step 1 now walks to write-back too, so xnu changed the object and no mismatched alias
//      exists (else M1). Only then is the slot cached. The copyback map is released either way;
//      after a failed attempt the whole range is cleaned and invalidated through the default map,
//      so no line the short-lived copyback alias filled survives.
// Reads keep pass 1's CIVAC and the barrier (AdrenoDisplayPresent.h) whatever the outcome.
IOMemoryMap *AdrenoDisplay::mapSourceGated(IOSurface *surface, IOMemoryDescriptor *md, bool *cached)
{
    *cached = false;
    for (uint32_t i = 0; i < kSurfaceMapSlots; i++) {
        if (fSurfaceMaps[i].md == md && fSurfaceMaps[i].map) {
            fSurfaceMaps[i].lastUse = fPresentCount;
            *cached = fSurfaceMaps[i].cached;
            return fSurfaceMaps[i].map;
        }
    }
    uint32_t victim = 0;
    for (uint32_t i = 0; i < kSurfaceMapSlots; i++) {
        if (!fSurfaceMaps[i].md) {
            victim = i;
            break;
        }
        if (fSurfaceMaps[i].lastUse < fSurfaceMaps[victim].lastUse)
            victim = i;
    }
    SurfaceMap &slot = fSurfaceMaps[victim];
    OSSafeReleaseNULL(slot.map);                 // M6: our view only; the object keeps its attribute
    OSSafeReleaseNULL(slot.md);
    slot.cached = false;
    IOMemoryMap *map = md->createMappingInTask(kernel_task, 0, kIOMapAnywhere | kIOMapReadOnly, 0, 0);
    if (!map)
        return nullptr;
    const void *va = (const void *)(uintptr_t)map->getVirtualAddress();
    bool writeBack = attrWriteBack(mappingAttribute(va));
    bool reverted = false;
    for (uint32_t i = 0; i < kRevertedSlots; i++)
        reverted |= fCachedReadReverted_[i] == md;
    uint32_t mode = surface->getCacheMode();
    if (writeBack) {
        fCachedReadAlready++;                    // M10
    } else if (!reverted && mode != kIOMapDefaultCache && mode != kIOMapCopybackCache &&
               mode != kIOMapCopybackInnerCache) {
        const uint64_t start = mach_absolute_time();
        IOMemoryMap *copyback = md->createMappingInTask(kernel_task, 0,
                                                        kIOMapAnywhere | kIOMapReadOnly | kIOMapCopybackCache, 0, 0);
        fCachedReadAttr = copyback ? mappingAttribute((const void *)(uintptr_t)copyback->getVirtualAddress()) : 0x200;
        fCachedReadProbeAttr = mappingAttribute(va);
        OSSafeReleaseNULL(copyback);
        if (!attrWriteBack(fCachedReadAttr)) {
            fCachedReadFallbacks++;              // M3: refused, null or not write-back
        } else if (!attrWriteBack(fCachedReadProbeAttr)) {
            fCachedReadMismatch++;               // M1: only the copyback map was write-back
        } else {
            fCachedReadConversions++;
            writeBack = true;
        }
        if (!writeBack) {
            maintainSourceRange(nullptr, va, map->getLength());
            presentBarrier(nullptr);
        }
        const uint64_t ticks = mach_absolute_time() - start;
        if (ticks > fCachedReadConvertMaxTicks) fCachedReadConvertMaxTicks = ticks;
        if (fCachedReadConversions + fCachedReadFallbacks + fCachedReadMismatch == 1)
            fPerfConversionPending = true;   // one perf line for the first outcome, after its copy
        if (fCachedReadConversions + fCachedReadFallbacks + fCachedReadMismatch <= 4)
            IOLog("AdrenoDisplay: cached read: mode %#x copyback attr %#llx default attr %#llx: %s\n", mode,
                  fCachedReadAttr, fCachedReadProbeAttr, writeBack ? "converted" : "kept the uncached path");
    }
    md->retain();
    slot.md = md;
    slot.map = map;
    slot.lastUse = fPresentCount;
    slot.cached = writeBack;
    *cached = writeBack;
    return map;
}
#endif

void AdrenoDisplay::releaseSurfaceMaps()
{
    for (uint32_t i = 0; i < kSurfaceMapSlots; i++) {
        OSSafeReleaseNULL(fSurfaceMaps[i].map);
        OSSafeReleaseNULL(fSurfaceMaps[i].md);
        fSurfaceMaps[i].lastUse = 0;
    }
    for (uint32_t i = 0; i < kCursorMapSlots; i++) {
        OSSafeReleaseNULL(fCursorMaps[i].map);
        OSSafeReleaseNULL(fCursorMaps[i].md);
        fCursorMaps[i].lastUse = 0;
    }
}

bool AdrenoDisplay::cursorBuffersGated()
{
    if (!fCursor.image)
        fCursor.image = (uint8_t *)IOMalloc(ADRENO_DISPLAY_CURSOR_BYTES);
    if (!fCursor.save)
        fCursor.save = (uint8_t *)IOMalloc(ADRENO_DISPLAY_CURSOR_BYTES);
    if (!fPresentWorkspace.next_save)
        fPresentWorkspace.next_save = (uint8_t *)IOMalloc(ADRENO_DISPLAY_CURSOR_BYTES);
    if (!fPresentWorkspace.row && fScanoutWidth) {
        fPresentWorkspace.row_bytes = (uint64_t)fScanoutWidth * 4;
        fPresentWorkspace.row = (uint8_t *)IOMalloc(fPresentWorkspace.row_bytes);
    }
    return fCursor.image && fCursor.save && fPresentWorkspace.next_save && fPresentWorkspace.row;
}

void AdrenoDisplay::releaseCursor()
{
    if (fCursor.image)
        IOFree(fCursor.image, ADRENO_DISPLAY_CURSOR_BYTES);
    if (fCursor.save)
        IOFree(fCursor.save, ADRENO_DISPLAY_CURSOR_BYTES);
    if (fPresentWorkspace.next_save)
        IOFree(fPresentWorkspace.next_save, ADRENO_DISPLAY_CURSOR_BYTES);
    if (fPresentWorkspace.row)
        IOFree(fPresentWorkspace.row, fPresentWorkspace.row_bytes);
    // The stage and the signature table outlive a cursor reset; releasePresentBuffers frees them.
    uint8_t *stage = fPresentWorkspace.stage;
    uint64_t stageRowBytes = fPresentWorkspace.stage_row_bytes;
    bzero(&fPresentWorkspace, sizeof(fPresentWorkspace));
    fPresentWorkspace.stage = stage;
    fPresentWorkspace.stage_row_bytes = stageRowBytes;
    fPresentWorkspace.damage = fDamage.sig ? &fDamage : nullptr;
    bzero(&fCursor, sizeof(fCursor));
}

bool AdrenoDisplay::presentBuffersGated()
{
    // A layer-0 copy reads each source row once into a cacheable stage (AdrenoDisplayPresent.h), so
    // the stage is required. The signature table is not: without it every source row is written.
    if (!fPresentWorkspace.stage && fScanoutWidth) {
        uint64_t rowBytes = (uint64_t)fScanoutWidth * 4;
        uint64_t bytes = rowBytes * ADRENO_DISPLAY_STAGE_ROWS;
        fPresentWorkspace.stage = (uint8_t *)IOMalloc(bytes);
        if (fPresentWorkspace.stage) {
            fStageBytes = bytes;
            fPresentWorkspace.stage_row_bytes = rowBytes;
        }
    }
    if (!fDamage.sig && fScanoutHeight) {
        uint64_t *sig = (uint64_t *)IOMalloc((uint64_t)fScanoutHeight * 2 * sizeof(uint64_t));
        uint8_t *known = (uint8_t *)IOMalloc(fScanoutHeight);
        if (sig && known) {
            bzero(known, fScanoutHeight);
            fDamage.sig = sig;
            fDamage.known = known;
            fDamage.rows = fScanoutHeight;
            fDamage.width = 0;
            fDamage.refresh_next = 0;
            fDamage.refresh_period = ADRENO_DISPLAY_REFRESH_PERIOD;
        } else {
            if (sig) IOFree(sig, (uint64_t)fScanoutHeight * 2 * sizeof(uint64_t));
            if (known) IOFree(known, fScanoutHeight);
        }
    }
    fPresentWorkspace.damage = fDamage.sig ? &fDamage : nullptr;
    return fPresentWorkspace.stage != nullptr;
}

void AdrenoDisplay::releasePresentBuffers()
{
    if (fPresentWorkspace.stage)
        IOFree(fPresentWorkspace.stage, fStageBytes);
    fPresentWorkspace.stage = nullptr;
    fPresentWorkspace.stage_row_bytes = 0;
    fPresentWorkspace.damage = nullptr;
    fStageBytes = 0;
    if (fDamage.sig)
        IOFree(fDamage.sig, fDamage.rows * 2 * sizeof(uint64_t));
    if (fDamage.known)
        IOFree(fDamage.known, fDamage.rows);
    bzero(&fDamage, sizeof(fDamage));
}

void AdrenoDisplay::forgetDamageGated()
{
    // The scanout may no longer hold what the signatures describe (start, stop, mode set, remap):
    // the next layer-0 present writes every source row.
    if (fDamage.width)
        fCopyDamageResets++;
    adreno_display_damage_forget(&fDamage);
}

bool AdrenoDisplay::disableConsoleGated()
{
    // J700 26A428: release relinquishes text/progress drawing before we own the
    // framebuffer. Disable also switches the serial selector, whose sealed store
    // faulted in PE_initialize_console in the first physical triangle run.
    if (fConsoleDisabled)
        return true;
    IOPlatformExpert *pe = getPlatform();
    if (!pe)
        return false;
    IOReturn status = pe->setConsoleInfo(nullptr, kPEReleaseScreen);
    if (status != kIOReturnSuccess) {
        IOLog("AdrenoDisplay: kernel screen release failed (%08x)\n", status);
        return false;
    }
    fConsoleDisabled = true;
    forgetDamageGated();             // the console drew into the GOP until now
    IOLog("AdrenoDisplay: kernel console released the panel (kPEReleaseScreen)\n");
    return true;
}

void AdrenoDisplay::publishStatsGated()
{
    OSDictionary *stats = OSDictionary::withCapacity(80);
    if (!stats)
        return;
    bool ok = putNum(stats, "Presents", fPresentCount, 64) && putNum(stats, "Drops", fDropCount, 64) &&
              putNum(stats, "Blank", fBlankCount, 64) && putNum(stats, "CopyErrors", fCopyErrors, 64) &&
              putNum(stats, "LastCopyError", (uint32_t)fLastCopyError) &&
              putNum(stats, "LastFormat", fLastFormat) &&
              putNum(stats, "LastWidth", fLastSurfaceWidth, 64) &&
              putNum(stats, "LastHeight", fLastSurfaceHeight, 64) &&
              putNum(stats, "LastRowBytes", fLastSurfaceRowBytes, 64) &&
              stats->setObject("ConsoleDisabled", fConsoleDisabled ? kOSBooleanTrue : kOSBooleanFalse);
    // Cursor layer (docs/ADRENO-DISPLAY-CURSOR-20261018.md). Positions are int32 shown as
    // their 32-bit two's complement (0xfffffffb is -5).
    uint64_t copyNs = 0, copyMaxNs = 0, maintNs = 0;
    absolutetime_to_nanoseconds(fCopyTicks, &copyNs);
    absolutetime_to_nanoseconds(fCopyMaxTicks, &copyMaxNs);
    absolutetime_to_nanoseconds(fCopyMaintTicks, &maintNs);
    ok = ok && putNum(stats, "CopyTimed", fCopyTimed, 64) && putNum(stats, "CopyMicros", copyNs / 1000, 64) &&
         putNum(stats, "CopyMaxMicros", copyMaxNs / 1000, 64) && putNum(stats, "CopyMaintMicros", maintNs / 1000, 64);
    // The rest of the split (AdrenoDisplayPresent.h): CopyMicros ~ Maint + Barrier + Read + Hash + Write.
    uint64_t barrierNs = 0, readNs = 0, hashNs = 0, writeNs = 0;
    absolutetime_to_nanoseconds(fCopyBarrierTicks, &barrierNs);
    absolutetime_to_nanoseconds(fCopyReadTicks, &readNs);
    absolutetime_to_nanoseconds(fCopyHashTicks, &hashNs);
    absolutetime_to_nanoseconds(fCopyWriteTicks, &writeNs);
    ok = ok && putNum(stats, "CopyBarrierMicros", barrierNs / 1000, 64) &&
         putNum(stats, "CopyReadMicros", readNs / 1000, 64) && putNum(stats, "CopyHashMicros", hashNs / 1000, 64) &&
         putNum(stats, "CopyWriteMicros", writeNs / 1000, 64) &&
         putNum(stats, "CopyRowsCompared", fCopyRowsCompared, 64) &&
         putNum(stats, "CopyRowsWritten", fCopyRowsWritten, 64) &&
         putNum(stats, "CopyRowsSkipped", fCopyRowsSkipped, 64) &&
         putNum(stats, "CopyRowsRefreshed", fCopyRowsRefreshed, 64) &&
         putNum(stats, "CopyDamageResets", fCopyDamageResets, 64) &&
         putNum(stats, "CopyFullFrames", fCopyFullFrames, 64) &&
         putNum(stats, "CopyLastRowsWritten", fCopyLastRowsWritten, 64) &&
         putNum(stats, "CopyTracking", fPresentWorkspace.damage ? 1 : 0) &&
         putNum(stats, "LastCacheMode", fLastCacheMode) && putNum(stats, "SourceAttr", fSourceAttr, 64) &&
         putNum(stats, "ScanoutAttr", fScanoutAttr, 64) &&
         putNum(stats, "LastSrcX", (uint32_t)fLastSrc.x) && putNum(stats, "LastSrcY", (uint32_t)fLastSrc.y) &&
         putNum(stats, "LastSrcWidth", (uint32_t)fLastSrc.w) && putNum(stats, "LastSrcHeight", (uint32_t)fLastSrc.h) &&
         putNum(stats, "LastDstX", (uint32_t)fLastDst.x) && putNum(stats, "LastDstY", (uint32_t)fLastDst.y) &&
         putNum(stats, "LastDstWidth", (uint32_t)fLastDst.w) && putNum(stats, "LastDstHeight", (uint32_t)fLastDst.h) &&
         putNum(stats, "SwapDirtyFlagged", fSwapDirtyFlagged, 64) &&
         putNum(stats, "SwapDirtyX", (uint32_t)fSwapDirty.x) && putNum(stats, "SwapDirtyY", (uint32_t)fSwapDirty.y) &&
         putNum(stats, "SwapDirtyWidth", (uint32_t)fSwapDirty.w) &&
         putNum(stats, "SwapDirtyHeight", (uint32_t)fSwapDirty.h);
#if ADRENO_PRESENT_CACHED_READ
    uint64_t convertNs = 0;
    absolutetime_to_nanoseconds(fCachedReadConvertMaxTicks, &convertNs);
    ok = ok && putNum(stats, "CachedRead", 1) && putNum(stats, "CachedReadConversions", fCachedReadConversions, 64) &&
         putNum(stats, "CachedReadFallbacks", fCachedReadFallbacks, 64) &&
         putNum(stats, "CachedReadMismatch", fCachedReadMismatch, 64) &&
         putNum(stats, "CachedReadReverted", fCachedReadReverted, 64) &&
         putNum(stats, "CachedReadAlready", fCachedReadAlready, 64) &&
         putNum(stats, "CachedReadAttr", fCachedReadAttr, 64) &&
         putNum(stats, "CachedReadProbeAttr", fCachedReadProbeAttr, 64) &&
         putNum(stats, "CachedReadConvertMaxMicros", convertNs / 1000, 64) &&
         putNum(stats, "SourceCached", fSourceCached ? 1 : 0);
#endif
    ok = ok && putNum(stats, "PublishedBytes", fPublishedBytes, 64) &&
         putNum(stats, "PublishedRegions", fPublishedRegions, 64) && putNum(stats, "SourceBytes", fSourceBytes, 64);
    ok = ok && putNum(stats, "LayerMask", fLastLayerMask) && putNum(stats, "LayerMaskSeen", fLayerMaskSeen) &&
         putNum(stats, "CursorSwaps", fCursorSwaps, 64) && putNum(stats, "CursorOnlySwaps", fCursorOnlySwaps, 64) &&
         putNum(stats, "CursorImmediate", fCursorImmediate, 64) &&
         putNum(stats, "CursorUpdates", fCursorUpdates, 64) && putNum(stats, "CursorDraws", fCursorDraws, 64) &&
         putNum(stats, "CursorHides", fCursorHides, 64) &&
         putNum(stats, "CursorFormatSkips", fCursorFormatSkips, 64) &&
         putNum(stats, "CursorErrors", fCursorErrors, 64) && putNum(stats, "CursorScaled", fCursorScaled, 64) &&
         putNum(stats, "LastCursorError", (uint32_t)fLastCursorError) &&
         putNum(stats, "CursorLayer", fCursorLayer) && putNum(stats, "CursorFormat", fCursorFormat) &&
         putNum(stats, "CursorSurfaceWidth", fCursorSurfaceWidth, 64) &&
         putNum(stats, "CursorSurfaceHeight", fCursorSurfaceHeight, 64) &&
         putNum(stats, "CursorSurfaceRowBytes", fCursorSurfaceRowBytes, 64) &&
         putNum(stats, "CursorX", (uint32_t)fCursorDst.x) && putNum(stats, "CursorY", (uint32_t)fCursorDst.y) &&
         putNum(stats, "CursorDstWidth", (uint32_t)fCursorDst.w) &&
         putNum(stats, "CursorDstHeight", (uint32_t)fCursorDst.h) &&
         putNum(stats, "CursorSrcX", (uint32_t)fCursorSrc.x) && putNum(stats, "CursorSrcY", (uint32_t)fCursorSrc.y) &&
         putNum(stats, "CursorSrcWidth", (uint32_t)fCursorSrc.w) &&
         putNum(stats, "CursorSrcHeight", (uint32_t)fCursorSrc.h) &&
         putNum(stats, "CursorImageWidth", fCursor.width) && putNum(stats, "CursorImageHeight", fCursor.height) &&
         stats->setObject("CursorVisible", fCursor.visible ? kOSBooleanTrue : kOSBooleanFalse) &&
         stats->setObject("CursorDrawn", fCursor.drawn ? kOSBooleanTrue : kOSBooleanFalse);
    if (ok)
        setProperty("AdrenoDisplayStats", stats);
    stats->release();
}

static uint64_t perfMicros(uint64_t ticks)
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(ticks, &ns);
    return ns / 1000;
}

// One bounded console line with the numbers this experiment is decided by (the run keeps the
// whole kernel console; the stats dictionary is not captured). Called every kPerfEvery layer-0
// copies and once for the first cached-read conversion outcome, never from the row loops.
//   AdrenoDisplay: perf why=<periodic|convert|reject> presents=P copies=C win=N
//     mean_us=M max_us=X all_mean_us=AM all_max_us=AX
//     maint_us=a barrier_us=b read_us=r hash_us=h write_us=w            (per copy, this window)
//     rows=W/K skipped=S refreshed=F                                   (this window)
//     mode=0x<getCacheMode> attr=0x<SourceAttr> cached=<build>/<this source>
//     conv=<conversions>/<fallbacks>/<mismatch>/<reverted>/<already> errors=E last_error=L
void AdrenoDisplay::perfLineGated(const char *why)
{
    PerfMark now = {fCopyTimed, fCopyTicks, fCopyMaintTicks, fCopyBarrierTicks, fCopyReadTicks, fCopyHashTicks,
                    fCopyWriteTicks, fCopyRowsCompared, fCopyRowsWritten, fCopyRowsSkipped, fCopyRowsRefreshed};
    uint64_t n = now.copies - fPerfMark.copies, d = n ? n : 1, all = now.copies ? now.copies : 1;
#if ADRENO_PRESENT_CACHED_READ
    const unsigned build = 1, sourceCached = fSourceCached ? 1 : 0;
    const uint64_t conv[5] = {fCachedReadConversions, fCachedReadFallbacks, fCachedReadMismatch, fCachedReadReverted,
                              fCachedReadAlready};
#else
    const unsigned build = 0, sourceCached = 0;
    const uint64_t conv[5] = {0, 0, 0, 0, 0};
#endif
#if ADRENO_PERF_FRAMES
    // F2 F3 F11: the same numbers as the single line below, split so none passes the console's 255 bytes, then
    // the window's pacing and GPU-map counters; one s=<seq> joins them.
    char line[ADRENO_PERF_LINE_MAX + 16];
    const uint64_t seq = ++fPerfSeq;
    const uint64_t head[ADRENO_PERF_HEAD_FIELDS] = {fPresentCount, now.copies, n, perfMicros(now.ticks - fPerfMark.ticks) / d,
                                                    perfMicros(fPerfMaxTicks), perfMicros(now.ticks) / all,
                                                    perfMicros(fCopyMaxTicks)};
    adreno_perf_line_head(line, sizeof line, why, seq, head);
    IOLog("%s\n", line);
    const uint64_t split[ADRENO_PERF_SPLIT_FIELDS] = {perfMicros(now.maint - fPerfMark.maint) / d,
        perfMicros(now.barrier - fPerfMark.barrier) / d, perfMicros(now.read - fPerfMark.read) / d,
        perfMicros(now.hash - fPerfMark.hash) / d, perfMicros(now.write - fPerfMark.write) / d,
        now.written - fPerfMark.written, now.compared - fPerfMark.compared, now.skipped - fPerfMark.skipped,
        now.refreshed - fPerfMark.refreshed};
    adreno_perf_line_split(line, sizeof line, seq, split);
    IOLog("%s\n", line);
    adreno_perf_line_src(line, sizeof line, seq, fLastCacheMode, fSourceAttr, build, sourceCached, conv, fCopyErrors,
                         fLastCopyError);
    IOLog("%s\n", line);
    struct adreno_pacing_summary pace;
    adreno_pacing_summarize(&fPacing, &pace);
    adreno_pacing_next_window(&fPacing);
    adreno_perf_line_pace(line, sizeof line, seq, &pace);
    IOLog("%s\n", line);
#if ADRENO_VSYNC60
    struct adreno_vsync_summary vsync;
    adreno_vsync_summarize(&fVsync, perfNs, &vsync);
    adreno_vsync_next_window(&fVsync);
    adreno_perf_line_vsync(line, sizeof line, seq, &vsync);
    IOLog("%s\n", line);
#endif
#if ADRENO_LATCH
    {   // H9: the latch and the hold this window (before the beam line resets the slack's window values)
        struct adreno_latch_summary ls;
        memset(&ls, 0, sizeof ls);
        ls.slack_us = perfNs(fBeam.slack) / 1000u;
        ls.slack_peak_us = perfNs(fBeam.slack_peak) / 1000u;
        ls.off = fBeam.latch_off;
        ls.hold_us = fHold.hold_n ? perfNs(fHold.hold_sum / fHold.hold_n) / 1000u : 0;
        ls.rb_us = perfNs(fHold.rb_last) / 1000u;
        ls.r_n = fHold.r_n;
        ls.r_us = fHold.r_n ? perfNs(fHold.r_sum / fHold.r_n) / 1000u : 0;
        ls.r_max_us = perfNs(fHold.r_max) / 1000u;
        ls.precopies = fHold.precopies;
        ls.rel_successor = fHold.rel_successor; ls.rel_lone = fHold.rel_lone;
        ls.rel_deferred = fHold.rel_deferred; ls.rel_overdue = fHold.rel_overdue;
        ls.misses = fHold.misses; ls.ib_after = fHold.ib_after; ls.fallbacks = fHold.fallbacks; ls.gated = fHold.gated;
        ls.raise_ovt = fBeam.slack_ovt; ls.raise_late = fBeam.slack_late;
        adreno_hold_next_window(&fHold);
        adreno_perf_line_latch(line, sizeof line, seq, &ls);
        IOLog("%s\n", line);
    }
#endif
#if ADRENO_PRESENT_SYNC
    {   // K9: the gate's decisions this window and the kext's marks (window deltas)
        uint64_t total[3];
        AdrenoPresentSyncCounters(&total[0], &total[1], &total[2]);
        const struct adreno_sync_summary ss = {fSync.defer, fSync.swaps, fSync.forced, perfNs(fSync.max_waited) / 1000u,
                                               total[0] - fSyncMark[0], fSync.busy, total[1] - fSyncMark[1],
                                               fSync.stale_seen, total[2] - fSyncMark[2]};
        memcpy(fSyncMark, total, sizeof fSyncMark);
        adreno_sync_next_window(&fSync);
        adreno_perf_line_sync(line, sizeof line, seq, &ss);
        IOLog("%s\n", line);
    }
#endif
#if ADRENO_PIPELINE
    {   // agents/gpu-pipeline O4: the IB pipeline this window (window deltas of AdrenoX2's totals)
        uint64_t total[ADRENO_PIPE_COUNTERS];
        const uint32_t state = AdrenoPipelineCounters(total);
        struct adreno_pipe_summary ps;
        adreno_pipe_window(&ps, state, total, fPipeMark);
        memcpy(fPipeMark, total, sizeof fPipeMark);
        adreno_perf_line_pipe(line, sizeof line, seq, &ps);
        IOLog("%s\n", line);
    }
#endif
#if ADRENO_PRESENT_RELATCH
    {   // OP1: the relatch this window, and AdrenoX2's early-release totals (window deltas)
        uint64_t total[ADRENO_RELATCH_EARLY_FIELDS], early[ADRENO_RELATCH_EARLY_FIELDS];
        const uint32_t state = AdrenoPipelineEarlyCounters(total);   // bit 0 early release, bit 1 urgent polling
        for (unsigned i = 0; i < ADRENO_RELATCH_EARLY_FIELDS; i++) early[i] = total[i] - fRelatchEarlyMark[i];
        memcpy(fRelatchEarlyMark, total, sizeof fRelatchEarlyMark);
        struct adreno_relatch_summary rs;
        adreno_relatch_summarize(&fRelatch, perfNs, (fRelatch.enabled && fRelatchTimer ? 1u : 0u) | (uint64_t)(state & 3u) << 1,
                                 early, &rs);
        adreno_relatch_next_window(&fRelatch);
        adreno_perf_line_relatch(line, sizeof line, seq, &rs);
        IOLog("%s\n", line);
    }
#endif
#if ADRENO_BEAM
    {   // E4: the beam's state, timing and this window's decisions
        struct adreno_beam_summary beam;
        adreno_beam_summarize(&fBeam, perfNs, &beam);
        adreno_beam_next_window(&fBeam);
        adreno_perf_line_beam(line, sizeof line, seq, &beam);
        IOLog("%s\n", line);
    }
#endif
#if ADRENO_RESOURCE_POOL
    uint64_t map[ADRENO_PERF_MAP_FIELDS], win[ADRENO_PERF_MAP_FIELDS];
    AdrenoGPUMapCounters(map);
    map[ADRENO_MAP_IBS] = __atomic_load_n(&gAdrenoIBCompleted, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < ADRENO_PERF_MAP_FIELDS; i++)
        win[i] = i == ADRENO_MAP_POOL_LIVE ? map[i] : map[i] - fMapMark[i];
    memcpy(fMapMark, map, sizeof fMapMark);
    adreno_perf_line_map(line, sizeof line, seq, win);
    IOLog("%s\n", line);
#if ADRENO_VA_RECLAIM
    {   // G16: levels as they are (bytes to MiB), counters as window deltas
        uint64_t total[ADRENO_PERF_VA_FIELDS], va[ADRENO_PERF_VA_FIELDS];
        AdrenoGPUVACounters(total);
        for (unsigned i = 0; i < ADRENO_PERF_VA_FIELDS; i++)
            va[i] = adreno_perf_va_level(i) ? total[i] : total[i] - fVaMark[i];
        memcpy(fVaMark, total, sizeof fVaMark);
        va[ADRENO_VA_HELD] >>= 20; va[ADRENO_VA_PEAK] >>= 20; va[ADRENO_VA_POOLED] >>= 20;
        va[ADRENO_VA_FROZEN] >>= 20; va[ADRENO_VA_DRAINED_BYTES] >>= 20;
        adreno_perf_line_va(line, sizeof line, seq, va);
        IOLog("%s\n", line);
    }
#endif
#endif
#if ADRENO_PERF_GPU
    {   // P3: totals read without a lock (window deltas); the IB maximum since the last line is taken by exchange.
        uint64_t total[ADRENO_PERF_GPU_FIELDS], gpu[ADRENO_PERF_GPU_FIELDS];
        AdrenoGPUWorkCounters(total);
        total[ADRENO_GPU_IB_TICKS] = __atomic_load_n(&gAdrenoIBGpuTicks, __ATOMIC_RELAXED);
        total[ADRENO_GPU_IB_TICKS_MAX] = __atomic_exchange_n(&gAdrenoIBGpuTicksMax, 0, __ATOMIC_RELAXED);
        total[ADRENO_GPU_SUBMIT_TICKS] = __atomic_load_n(&gAdrenoIBSubmitTicks, __ATOMIC_RELAXED);
        total[ADRENO_GPU_LOCK_TICKS] = __atomic_load_n(&gAdrenoIBLockTicks, __ATOMIC_RELAXED);
        for (unsigned i = 0; i < ADRENO_PERF_GPU_FIELDS; i++)
            gpu[i] = i == ADRENO_GPU_IB_TICKS_MAX || i == ADRENO_GPU_RES_BYTES || i == ADRENO_GPU_RES_BUDGET ?
                total[i] : total[i] - fGpuMark[i];
        memcpy(fGpuMark, total, sizeof fGpuMark);
        // P5: mach ticks to us; bytes to MiB. The IB ticks stay in the monitor's counter units.
        static const unsigned us[] = {ADRENO_GPU_PREPARE_TICKS, ADRENO_GPU_UNWIRE_TICKS, ADRENO_GPU_CACHE_TICKS,
                                      ADRENO_GPU_SUBMIT_TICKS, ADRENO_GPU_LOCK_TICKS};
        for (unsigned i = 0; i < sizeof us / sizeof us[0]; i++) gpu[us[i]] = perfMicros(gpu[us[i]]);
        gpu[ADRENO_GPU_CACHE_BYTES] >>= 20;
        gpu[ADRENO_GPU_RES_BYTES] >>= 20;
        gpu[ADRENO_GPU_RES_BUDGET] >>= 20;
        adreno_perf_line_gpu(line, sizeof line, seq, gpu);
        IOLog("%s\n", line);
    }
#endif
#else
    IOLog("AdrenoDisplay: perf why=%s presents=%llu copies=%llu win=%llu mean_us=%llu max_us=%llu all_mean_us=%llu "
          "all_max_us=%llu maint_us=%llu barrier_us=%llu read_us=%llu hash_us=%llu write_us=%llu rows=%llu/%llu "
          "skipped=%llu refreshed=%llu mode=0x%x attr=0x%llx cached=%u/%u conv=%llu/%llu/%llu/%llu/%llu errors=%llu "
          "last_error=%d\n",
          why, fPresentCount, now.copies, n, perfMicros(now.ticks - fPerfMark.ticks) / d, perfMicros(fPerfMaxTicks),
          perfMicros(now.ticks) / all, perfMicros(fCopyMaxTicks), perfMicros(now.maint - fPerfMark.maint) / d,
          perfMicros(now.barrier - fPerfMark.barrier) / d, perfMicros(now.read - fPerfMark.read) / d,
          perfMicros(now.hash - fPerfMark.hash) / d, perfMicros(now.write - fPerfMark.write) / d,
          now.written - fPerfMark.written, now.compared - fPerfMark.compared, now.skipped - fPerfMark.skipped,
          now.refreshed - fPerfMark.refreshed, fLastCacheMode, fSourceAttr, build, sourceCached, conv[0], conv[1],
          conv[2], conv[3], conv[4], fCopyErrors, fLastCopyError);
#endif
    fPerfMark = now;
    fPerfMaxTicks = 0;
}

bool AdrenoDisplay::updateCursorGated(IOMFBSwapIORequest *swap, uint8_t layers)
{
    // PV program_hardware_gated 0x118d8..0x1190c: with mask bit 1, the layer-1 surface
    // (swap+0xb88) and destRect[1].x/.y (swap+0x61/+0x65, int) go to
    // program_hardware_cursor_gated, which refuses a surface that is not 'BGRA' with 4 bytes
    // per element (0x11004/0x11014) and programs the host cursor glyph 1:1 (no scaling).
    // Here: the layer's srcRect is captured 1:1 and drawn with its pixel (0,0) at the
    // destRect origin. A layer whose bit is clear keeps its state (the family's own rule,
    // swapWillChangeDisplayedData); a set bit with no surface (ID 0) switches it off.
    bool report = ++fCursorSwaps == 1;
    if (!(layers & 1))
        fCursorOnlySwaps++;
    for (uint32_t l = 1; l < IOMFBSwapFields::kLayerCount; l++) {
        if (!(layers & (1u << l)))
            continue;
        IOSurface *surface = IOMFBSwapFields::layerSurface(swap, l);
        IOMFBSwapFields::Rect src = IOMFBSwapFields::srcRect(swap, l), dst = IOMFBSwapFields::dstRect(swap, l);
        struct adreno_display_rect rect = {src.x, src.y, src.w, src.h};
        if (!surface) {
            fCursorHides++;
            adreno_display_cursor_layer(&fCursor, l, nullptr, rect, dst.x, dst.y, nullptr, nullptr);
            continue;
        }
        fCursorLayer = l;
        fCursorSrc = src;
        fCursorDst = dst;
        fCursorFormat = surface->getPixelFormat();
        fCursorSurfaceWidth = surface->getWidth();
        fCursorSurfaceHeight = surface->getHeight();
        fCursorSurfaceRowBytes = surface->getBytesPerRow();
        // Mapped only when it can be shown: 'BGRA' and the two cursor buffers present.
        struct adreno_display_surface s = {
            nullptr, 0, surface->getBaseOffset(), fCursorSurfaceRowBytes, fCursorSurfaceWidth,
            fCursorSurfaceHeight, fCursorFormat};
        int error = 0;
        if (fCursorFormat == ADRENO_DISPLAY_FORMAT_BGRA) {
            if (!cursorBuffersGated()) {
                error = (int)kIOReturnNoMemory;
            } else {
                IOMemoryDescriptor *md = surface->getMemoryDescriptor();
                IOMemoryMap *map = md ? mapSurfaceGated(md, fCursorMaps, kCursorMapSlots) : nullptr;
                if (map) {
                    s.base = (const uint8_t *)map->getVirtualAddress();
                    s.length = map->getLength();
                }
            }
        }
        if (error)
            adreno_display_cursor_hide(&fCursor);
        else
            error = adreno_display_cursor_layer(&fCursor, l, &s, rect, dst.x, dst.y, maintainSourceRow, nullptr);
        if (error) {
            if (error == ADRENO_DISPLAY_E_FORMAT)
                fCursorFormatSkips++;               // hidden, nothing mapped or read
            else
                fCursorErrors++;
            if (error != fLastCursorError || fCursorErrors + fCursorFormatSkips <= 4) {
                IOLog("AdrenoDisplay: cursor layer %u %08x %llux%llu src (%d,%d %dx%d) not shown (%d)\n", l,
                      fCursorFormat, fCursorSurfaceWidth, fCursorSurfaceHeight, fCursorSrc.x, fCursorSrc.y,
                      fCursorSrc.w, fCursorSrc.h, error);
                report = true;
            }
            fLastCursorError = error;
            continue;
        }
        if ((uint32_t)fCursorDst.w != fCursor.width || (uint32_t)fCursorDst.h != fCursor.height)
            fCursorScaled++;
        if (++fCursorUpdates <= 2) {
            IOLog("AdrenoDisplay: cursor layer %u %08x %llux%llu src (%d,%d %dx%d) dst (%d,%d %dx%d)\n", l,
                  fCursorFormat, fCursorSurfaceWidth, fCursorSurfaceHeight, fCursorSrc.x, fCursorSrc.y,
                  fCursorSrc.w, fCursorSrc.h, fCursorDst.x, fCursorDst.y, fCursorDst.w, fCursorDst.h);
            report = true;
        }
    }
    return report;
}

void AdrenoDisplay::presentGated(IOMFBSwapIORequest *swap)
{
#if ADRENO_LATCH
    // H4: a precopy puts a pending swap's pixels on the scanout; it becomes current (presented) only at its release.
    if (!fPrecopying) {
        fSwapPresented = true;
        fPresentCount++;
    }
#else
    fSwapPresented = true;
    fPresentCount++;
#endif
    // PV program_hardware_gated 0x118d8: layer-enable mask at swap+0x3d8, bit0 = layer 0
    // (surface at swap+0xb80), bit1 = cursor (swap+0xb88, destRect[1] origin at
    // swap+0x61/+0x65). Layer 0 is still 1:1 from the top-left (its rectangles and scaling
    // are not applied); layers 1..3 are the cursor (updateCursorGated).
    uint8_t layers = IOMFBSwapFields::layerMask(swap);
    fLastLayerMask = IOMFBSwapFields::layerMaskWord(swap);
    fLayerMaskSeen |= fLastLayerMask;
    bool report = fPresentCount <= 4 || !(fPresentCount & 63);
    struct adreno_display_scanout d = {
        (uint8_t *)(uintptr_t)fScanout, fScanoutLength, fScanoutRowBytes, fScanoutWidth, fScanoutHeight};
    IOSurface *surface = (layers & 1) ? IOMFBSwapFields::layerSurface(swap, 0) : nullptr;
    if (layers & 1) {
        // Recorded, not applied: layer 0 is copied 1:1 from the top-left, and the IOMFB dirty
        // region has no 26A428 producer (IOMobileGraphicsFamily26A428.h, kDirtyValid).
        fLastSrc = IOMFBSwapFields::srcRect(swap, 0);
        fLastDst = IOMFBSwapFields::dstRect(swap, 0);
        if (IOMFBSwapFields::dirtyValid(swap)) {
            fSwapDirtyFlagged++;
            fSwapDirty = IOMFBSwapFields::dirtyRect(swap);
            if (fSwapDirtyFlagged == 1) {
                IOLog("AdrenoDisplay: swap carries an IOMFB dirty region (%d,%d %dx%d); not used\n", fSwapDirty.x,
                      fSwapDirty.y, fSwapDirty.w, fSwapDirty.h);
                report = true;
            }
        }
    }
    struct adreno_display_surface source = {};
    const struct adreno_display_surface *copy = nullptr;
    int error = 0;
    if (!surface || !fScanout) {
        fBlankCount++;
    } else {
        fLastFormat = surface->getPixelFormat();
        fLastSurfaceWidth = surface->getWidth();
        fLastSurfaceHeight = surface->getHeight();
        fLastSurfaceRowBytes = surface->getBytesPerRow();
        fLastCacheMode = surface->getCacheMode();
        error = ADRENO_DISPLAY_E_FORMAT;
        if (adreno_display_bytes_per_pixel(fLastFormat)) {
            IOMemoryDescriptor *md = surface->getMemoryDescriptor();
#if ADRENO_PRESENT_CACHED_READ
            bool cached = false;
            IOMemoryMap *map = md ? mapSourceGated(surface, md, &cached) : nullptr;
#else
            IOMemoryMap *map = md ? mapSurfaceGated(md, fSurfaceMaps, kSurfaceMapSlots) : nullptr;
#endif
            error = ADRENO_DISPLAY_E_ARGS;
            if (map) {
                source = {(const uint8_t *)map->getVirtualAddress(), map->getLength(), surface->getBaseOffset(),
                    fLastSurfaceRowBytes, fLastSurfaceWidth, fLastSurfaceHeight, fLastFormat};
                struct adreno_display_plan plan;
                error = adreno_display_plan(&source, &d, &plan);
                if (!error) copy = &source;
                if (!error) fSourceAttr = mappingAttribute(source.base + source.offset);
#if ADRENO_PRESENT_CACHED_READ
                // M4: a cached slot whose object went back to an uncached attribute. Reads stay correct
                // (CIVAC, barrier, read); the descriptor is never converted again.
                fSourceCached = !error && cached && attrWriteBack(fSourceAttr);
                if (!error && cached && !fSourceCached) {
                    fCachedReadReverted++;
                    fCachedReadReverted_[fCachedReadRevertedNext++ % kRevertedSlots] = md;
                    for (uint32_t i = 0; i < kSurfaceMapSlots; i++)
                        if (fSurfaceMaps[i].md == md) fSurfaceMaps[i].cached = false;
                }
#endif
            }
        }
    }
    // Refused layer-0 input must not erase the currently visible cursor. Prepare
    // all scratch storage before accepting a new cursor or publishing any pixels.
    if (!error && fScanout && ((layers & kOverlayLayers) || fCursor.drawn || fCursor.visible) &&
        !cursorBuffersGated()) error = (int)kIOReturnNoMemory;
    if (!error && copy && !presentBuffersGated()) error = (int)kIOReturnNoMemory;
    if (!error && copy && !disableConsoleGated()) error = (int)kIOReturnNotReady;
    if (!error && fScanout && fConsoleDisabled) {
        if (layers & kOverlayLayers) report |= updateCursorGated(swap, layers);
        struct adreno_display_present_result result;
#if ADRENO_BEAM
        // C3 C7: before each chunk's first scanout write the beam is waited for and checked (adreno_beam_gate). A
        // layer-0 present takes the frame its tick's GO chose; a cursor-only one chooses for the rows it may touch.
        const bool beam = fBeamRegs && fBeam.state == ADRENO_BEAM_LOCKED;
        if (beam) {
            uint64_t lo = 0, hi = fScanoutHeight;
            if (!copy) {
                lo = fScanoutHeight; hi = 0;
                if (fCursor.drawn) { lo = fCursor.sy; hi = fCursor.sy + fCursor.sh; }
                if (fCursor.visible && fCursor.height) {
                    int64_t top = fCursor.y, bottom = (int64_t)fCursor.y + fCursor.height;
                    if (top < 0) top = 0;
                    if (bottom > (int64_t)fScanoutHeight) bottom = fScanoutHeight;
                    if (bottom > top) {
                        if ((uint64_t)top < lo) lo = (uint64_t)top;
                        if ((uint64_t)bottom > hi) hi = (uint64_t)bottom;
                    }
                }
                if (lo >= hi) { lo = 0; hi = fScanoutHeight; }
            }
            adreno_beam_begin(&fBeam, !copy, lo, hi);
        }
#endif
#if ADRENO_BEAM || ADRENO_PRESENT_SKIP_MAINT
#if ADRENO_PRESENT_SKIP_MAINT && ADRENO_BEAM
        const bool maint = fPresentMaint || !beam;   // skipped only while the beam is locked; otherwise as before
#elif ADRENO_PRESENT_SKIP_MAINT
        const bool maint = fPresentMaint;    // no CIVAC pass and no barrier: the resource list invalidated the source
#else
        const bool maint = true;
#endif
        const struct adreno_display_present_ops ops = {maint ? maintainSourceRange : nullptr,
                                                       maint ? presentBarrier : nullptr, presentClock, nullptr, nullptr,
                                                       nullptr
#if ADRENO_BEAM
                                                       , beam ? beamGate : nullptr, this
#endif
                                                      };
#else
        static const struct adreno_display_present_ops ops = {
            maintainSourceRange, presentBarrier, presentClock, nullptr, nullptr, nullptr};
#endif
        const uint64_t start = mach_absolute_time();
        error = adreno_display_present(&fCursor, &d, copy, &fPresentWorkspace, &ops, &result);
#if ADRENO_BEAM
        if (beam) {
            // C5: the fire leads the vblank by the observed lateness plus this estimate of the maintenance pass
            if (!error && copy) {
                fBeam.maint = fBeam.maint - fBeam.maint / 8 + (result.maint_ticks + result.barrier_ticks) / 8;
                adreno_beam_copied(&fBeam, mach_absolute_time() - start);
            }
            adreno_beam_end(&fBeam);
        }
#endif
        if (!error && copy) {
            const uint64_t ticks = mach_absolute_time() - start;
            fCopyTimed++;
            fCopyTicks += ticks;
            if (ticks > fCopyMaxTicks) fCopyMaxTicks = ticks;
            fCopyMaintTicks += result.maint_ticks;
            fCopyBarrierTicks += result.barrier_ticks;
            fCopyReadTicks += result.read_ticks;
            fCopyHashTicks += result.hash_ticks;
            fCopyWriteTicks += result.write_ticks;
            fCopyRowsCompared += result.rows_compared;
            fCopyRowsWritten += result.rows_written;
            fCopyRowsSkipped += result.rows_skipped;
            fCopyRowsRefreshed += result.rows_refreshed;
            fCopyLastRowsWritten = result.rows_written;
            if (result.forgot) fCopyDamageResets++;
            if (!result.rows_skipped) fCopyFullFrames++;
            if (ticks > fPerfMaxTicks) fPerfMaxTicks = ticks;
#if ADRENO_PERF_FRAMES
            {   // F4 F7 F8: the copy start is the clock read the copy already made.
                const uint64_t ibs = __atomic_load_n(&gAdrenoIBCompleted, __ATOMIC_ACQUIRE);
                const uint64_t ibAt = __atomic_load_n(&gAdrenoIBCompletedAt, __ATOMIC_RELAXED);
                adreno_pacing_copy(&fPacing, perfNs(start), fInTick, fPresentQueuedAt ? perfNs(fPresentQueuedAt) : 0, ibs,
                                   ibAt ? perfNs(ibAt) : 0);
            }
#endif
            // At most one line per kPerfEvery copies; the first conversion outcome takes its place.
            if (fPerfConversionPending) {
                fPerfConversionPending = false;
#if ADRENO_PRESENT_CACHED_READ
                perfLineGated(fCachedReadConversions ? "convert" : "reject");
#endif
            } else if (!(fCopyTimed % kPerfEvery)) {
                perfLineGated("periodic");
            }
        }
        if (!error) {
            fPublishedBytes += result.bytes_written;
            fPublishedRegions += result.regions;
            fSourceBytes += result.bytes_read;
            if (result.cursor_pixels) fCursorDraws++;
            if (copy) AdrenoEarlyStopPresented(fPresentCount);
        }
    }
    if (error) {
        fCopyErrors++;
        if (error != fLastCopyError || fCopyErrors <= 4) {
            IOLog("AdrenoDisplay: composed present %08x %llux%llu row %llu not shown (%d)\n", fLastFormat,
                  fLastSurfaceWidth, fLastSurfaceHeight, fLastSurfaceRowBytes, error);
            report = true;
        }
        fLastCopyError = error;
    }
    if (report)
        publishStatsGated();         // readable with ioreg -rc AdrenoDisplay
}

// ---------------------------------------------------------------- hardware

bool AdrenoDisplay::start_hardware()
{
    // PV start_hardware 0xe9e8: under the family's command gate, set up the device, set the
    // four "display on" words at +0x1c0c..+0x1c18 to 1, create a 1-shot timer whose action
    // calls swap_begin_gated, add it to the work loop, enable it.
    if (!fLegacyCommandGate)
        return false;
    IOReturn ret = fLegacyCommandGate->runActionBlock(^IOReturn {
        if (!mapScanout())
            return kIOReturnNoDevice;
        forgetDamageGated();
        uint32_t *on = (uint32_t *)((uint8_t *)this + 0x1c0c);
        on[0] = on[1] = on[2] = on[3] = 1;
        fDisplayWidth = kWidth;
        fDisplayHeight = kHeight;
#if ADRENO_VSYNC60
        // S5: the grid in abstime, once and in 64 bits, before the timer exists.
        uint64_t period = 0, lead = 0;
        nanoseconds_to_absolutetime(kVsyncPeriodNs, &period);
        nanoseconds_to_absolutetime(kVsyncLeadMaxNs, &lead);
        adreno_vsync_init(&fVsync, period, lead, 4 * period);
#endif
#if ADRENO_BEAM
        beamMapGated();                  // never fails the start: a refusal keeps the timer path (B1 D3)
#endif
#if ADRENO_LATCH
        {   // L5: adreno_latch_us=0 is today's aim, adreno_hold=0 today's completion at the tick; both 0 = the beam kext
            uint32_t slackUs = 3000, hold = 0, marginUs = 1500, gateUs = 4000;   // b12v11: the hold is opt-in
            PE_parse_boot_argn("adreno_latch_us", &slackUs, sizeof(slackUs));
            PE_parse_boot_argn("adreno_gate_us", &gateUs, sizeof(gateUs));
            if (gateUs > 16000) gateUs = 16000;
            fGateTicks = 0;
            nanoseconds_to_absolutetime((uint64_t)gateUs * 1000u, &fGateTicks);
            PE_parse_boot_argn("adreno_hold", &hold, sizeof(hold));
            PE_parse_boot_argn("adreno_hold_margin_us", &marginUs, sizeof(marginUs));
            if (slackUs > 9000) slackUs = 9000;
            if (marginUs > 16000) marginUs = 16000;
            fLatchSlackUs = slackUs;
            fHoldMarginUs = marginUs;
            uint64_t slack = 0, margin = 0, floor = 0;
            nanoseconds_to_absolutetime((uint64_t)slackUs * 1000u, &slack);
            nanoseconds_to_absolutetime((uint64_t)marginUs * 1000u, &margin);
            nanoseconds_to_absolutetime((uint64_t)ADRENO_HOLD_FLOOR_US * 1000u, &floor);
            adreno_beam_latch(&fBeam, slack);
            adreno_hold_init(&fHold, hold != 0, margin, floor);
            fReleaseArmed = fPrecopying = false;
            fPrecopied = nullptr;
            IOLog("AdrenoDisplay: latch slack %u us%s, release hold %s (margin %u us), copy gate %u us\n", slackUs,
                  slackUs ? "" : " (today's aim)", hold ? "on" : "off", marginUs, gateUs);
        }
#endif
#if ADRENO_PRESENT_SYNC
        {   // K2: the bound per swap (0 = off); marks older than 2 s are lost ones
#if ADRENO_PIPELINE
            // agents/gpu-pipeline D2: a swap now waits for its whole IB; only a lost unmark may reach the bound
            uint32_t maxUs = 1100000;
            PE_parse_boot_argn("adreno_sync_max_us", &maxUs, sizeof(maxUs));
            if (maxUs > 1999000) maxUs = 1999000;
            AdrenoPipelineCounters(fPipeMark);
#else
            uint32_t maxUs = 50000;
            PE_parse_boot_argn("adreno_sync_max_us", &maxUs, sizeof(maxUs));
            if (maxUs > 500000) maxUs = 500000;
#endif
            uint64_t maxWait = 0, stale = 0;
            nanoseconds_to_absolutetime((uint64_t)maxUs * 1000u, &maxWait);
            nanoseconds_to_absolutetime(2000000000ull, &stale);
            adreno_sync_gate_init(&fSync, maxWait, stale);
            fSyncForcedLogged = 0;
            AdrenoPresentSyncCounters(&fSyncMark[0], &fSyncMark[1], &fSyncMark[2]);
            IOLog("AdrenoDisplay: present sync %s: a layer-0 copy waits for GPU writes to its surface, at most %u us\n",
                  maxUs ? "on" : "off", maxUs);
        }
#endif
#if ADRENO_PRESENT_SKIP_MAINT
        {
            uint32_t keep = 0;
            fPresentMaint = PE_parse_boot_argn("adreno_present_maint", &keep, sizeof(keep)) && keep;
            IOLog("AdrenoDisplay: layer-0 maintenance pass %s\n", fPresentMaint ? "kept (adreno_present_maint=1)" :
                  ADRENO_BEAM ? "skipped while the beam is locked: the resource list invalidates GPU-written surfaces" :
                  "skipped: the resource list invalidates GPU-written surfaces");
        }
#endif
        fFrameTimer = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityKernel, this, ^(IOTimerEventSource *sender) {
            vsyncGated(sender);
        });
        if (!fFrameTimer || getWorkLoop()->addEventSource(fFrameTimer) != kIOReturnSuccess) {
            OSSafeReleaseNULL(fFrameTimer);
            return kIOReturnNoResources;
        }
        fFrameTimer->enable();
#if ADRENO_LATCH
        // H2 H7: the release, on the same work loop as the tick. Without it the hold stays off (today's completion).
        fReleaseTimer = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityKernel, this,
                                                             ^(IOTimerEventSource *) { holdReleaseGated(false); });
        if (fReleaseTimer && getWorkLoop()->addEventSource(fReleaseTimer) != kIOReturnSuccess)
            OSSafeReleaseNULL(fReleaseTimer);
        if (fReleaseTimer)
            fReleaseTimer->enable();
        else
            fHold.enabled = 0;
#endif
#if ADRENO_PRESENT_RELATCH
        {   // RL1 RL6 OP3: adreno_relatch=0 measures only; the poll and the guard in mach ticks
            uint32_t relatch = 1, pollUs = 200, guardUs = 1000;
            PE_parse_boot_argn("adreno_relatch", &relatch, sizeof(relatch));
            PE_parse_boot_argn("adreno_relatch_poll_us", &pollUs, sizeof(pollUs));
            PE_parse_boot_argn("adreno_relatch_guard_us", &guardUs, sizeof(guardUs));
            if (pollUs < 50) pollUs = 50;
            if (pollUs > 2000) pollUs = 2000;
            if (guardUs > 8000) guardUs = 8000;
            uint64_t poll = 0, guard = 0, ms = 0;
            nanoseconds_to_absolutetime((uint64_t)pollUs * 1000u, &poll);
            nanoseconds_to_absolutetime((uint64_t)guardUs * 1000u, &guard);
            nanoseconds_to_absolutetime(1000000, &ms);
            adreno_relatch_init(&fRelatch, relatch != 0, poll, guard, ms);
            fRelatchArmed = false;
            fRelatchCandidate = nullptr;
            fRelatchTimer = IOTimerEventSource::timerEventSource(kIOTimerEventSourceOptionsPriorityKernel, this,
                                                                 ^(IOTimerEventSource *) { relatchFireGated(); });
            if (fRelatchTimer && getWorkLoop()->addEventSource(fRelatchTimer) != kIOReturnSuccess)
                OSSafeReleaseNULL(fRelatchTimer);
            if (fRelatchTimer)
                fRelatchTimer->enable();
            AdrenoPipelineEarlyCounters(fRelatchEarlyMark);
            IOLog("AdrenoDisplay: relatch %s (poll %u us, guard %u us)\n",
                  !fRelatchTimer ? "off (no timer)" : relatch ? "on" : "measuring only", pollUs, guardUs);
        }
#endif
        if (!publishDisplayAttributes())
            return kIOReturnNoMemory;
        return kIOReturnSuccess;
    });
    if (ret != kIOReturnSuccess)
        IOLog("AdrenoDisplay: start_hardware failed %08x\n", ret);
    return ret == kIOReturnSuccess;
}

void AdrenoDisplay::stop_hardware_gated()
{
    // PV stop_hardware_gated 0xee30: disable, cancel, remove and release the timer.
    if (fFrameTimer) {
        fFrameTimer->disable();
        fFrameTimer->cancelTimeout();
        getWorkLoop()->removeEventSource(fFrameTimer);
        OSSafeReleaseNULL(fFrameTimer);
    }
    fFrameTimerArmed = false;
#if ADRENO_PRESENT_SYNC
    adreno_sync_forget(&fSync);              // K11: no waiting head across a stop
#endif
#if ADRENO_LATCH
    holdForgetGated();                       // H7: no release after the stop
    if (fReleaseTimer) {
        fReleaseTimer->disable();
        getWorkLoop()->removeEventSource(fReleaseTimer);
        OSSafeReleaseNULL(fReleaseTimer);
    }
#endif
#if ADRENO_PRESENT_RELATCH
    relatchEndGated(false);                  // RL3 UR1: no relatch after the stop, the urgent flag cleared
    fRelatchCandidate = nullptr;
    if (fRelatchTimer) {
        fRelatchTimer->disable();
        fRelatchTimer->cancelTimeout();
        getWorkLoop()->removeEventSource(fRelatchTimer);
        OSSafeReleaseNULL(fRelatchTimer);
    }
#endif
#if ADRENO_VSYNC60
    adreno_vsync_reset(&fVsync);             // S4: a restarted display starts a new grid
#endif
#if ADRENO_BEAM
    adreno_beam_reset(&fBeam);               // D1: nothing armed; the next start maps and calibrates again
    beamUnmap();                             // after the timer is gone, so no fire can read the page
#endif
    releaseSurfaceMaps();
    fCursor.visible = fCursor.drawn = 0;     // a restarted display starts without a cursor
    forgetDamageGated();                     // and with every row written by its first frame
    withdrawDisplayAttributes();
}

IOReturn AdrenoDisplay::set_digital_out_mode(unsigned int colorID, unsigned int timingID)
{
    // The native API and selector23 pass color first, timing second. Four
    // generation55 WindowServer corpses retain the request (100, 1000).
    if (!fLegacyCommandGate)
        return kIOReturnNotReady;
    return fLegacyCommandGate->runActionBlock(^IOReturn {
        if (!fAttributesPublished || !fTimingElements || !fColorElements)
            return kIOReturnNotReady;
        // Only the published pair exists: the 8-bit SDR color element on the one timing.
        if (timingID != kTimingID || colorID != kColorIDSDR8)
            return kIOReturnNotFound;
        // PV's successful gated path (0xa264..0xa340) publishes its selected
        // geometry/timing and returns success. Its Legacy fallback is only for
        // failure: Legacy::set_digital_out_mode always returns Unsupported.
        // This panel has one fixed scanout mode; all published colors use it.
        if (!setProperty("DisplayWidth", kWidth, 32) ||
            !setProperty("DisplayHeight", kHeight, 32) ||
            !setProperty("DPTimingModeId", timingID, 64))
            return kIOReturnNoMemory;
        fDisplayWidth = kWidth;
        fDisplayHeight = kHeight;
        forgetDamageGated();         // the first frame after a mode set is written in full
#if ADRENO_VSYNC60
        adreno_vsync_reset(&fVsync); // S4: and the tick grid restarts
#endif
#if ADRENO_BEAM
        adreno_beam_reset(&fBeam);   // D2: and the beam recalibrates at the next arm
#endif
#if ADRENO_LATCH
        fPrecopied = nullptr;        // H4: a precopied swap is copied again at its latch
#endif
#if ADRENO_PRESENT_RELATCH
        relatchEndGated(false);      // RL3: the beam's positions are renumbered at the recalibration
#endif
        return kIOReturnSuccess;
    });
}

IOReturn AdrenoDisplay::get_dot_pitch(unsigned int *pitch)
{
    // IOMobileFramebufferLegacy::start (iomgf 0x1f120..0x1f128) keeps
    // OSDynamicCast(AppleARMIODevice, provider) at +0x1b80 and only logs when it is NULL.
    // Legacy::get_dot_pitch (0x29b00..0x29b04) then does ldr x0,[x0,#0x1b80]; ldr x16,[x0]
    // with no check, and get_dot_pitch_float (0x29c0c) and get_display_area (0x29c80) call
    // it through the vtable, all reachable from user-client selectors. Started with the
    // accelerator as provider, that pointer is NULL, so the base must never run. PV overrides
    // it too (0xf494: pixels / mm * 25.4 rounded), falling back to the base only with a
    // real AppleARMIODevice provider.
    if (!pitch)
        return kIOReturnBadArgument;
    *pitch = (kWidth * 254 + kPanelWidthMM * 5) / (kPanelWidthMM * 10);   // pixels per inch
    return kIOReturnSuccess;
}

bool AdrenoDisplay::mapScanout()
{
    if (fScanout)
        return true;
    // PE_current_console/PE_state are not exported to kexts on 26A428 (the checker's export
    // scan); IOBootFramebuffer's route is the platform expert's virtual getConsoleInfo.
    PE_Video video = {};
    IOPlatformExpert *pe = getPlatform();
    if (!pe || pe->getConsoleInfo(&video) != kIOReturnSuccess || !video.v_baseAddr || !video.v_rowBytes) {
        IOLog("AdrenoDisplay: no boot framebuffer in PE_Video\n");
        return false;
    }
    fScanoutRowBytes = (uint32_t)video.v_rowBytes;
    fScanoutWidth = (uint32_t)video.v_width;
    fScanoutHeight = (uint32_t)video.v_height;
    fScanoutDepth = (uint32_t)video.v_depth;
    if (fScanoutWidth < kWidth || fScanoutHeight < kHeight || fScanoutDepth != 32)
        IOLog("AdrenoDisplay: firmware framebuffer %ux%u@%u differs from the %ux%u mode\n",
              fScanoutWidth, fScanoutHeight, fScanoutDepth, kWidth, kHeight);
    uint64_t length = (uint64_t)fScanoutRowBytes * fScanoutHeight;
    uint64_t addr = video.v_baseAddr + video.v_offset;
    fScanoutLength = length;
    if ((addr >> 48) == 0xffff) {
        // Already a kernel virtual address (the console's own mapping).
        fScanout = (volatile uint8_t *)addr;
        fScanoutPhys = 0;
        return true;
    }
    // arm64 PE_state.video.v_baseAddr is boot_args->Video.v_baseAddr, a physical address
    // (A16 GOP: 0xf9a20000-ish, 11520 bytes per row). Map it write-combined.
    fScanoutPhys = addr;
    fScanoutMD = IOMemoryDescriptor::withPhysicalAddress(addr, length, kIODirectionInOut);
    if (fScanoutMD)
        fScanoutMap = fScanoutMD->createMappingInTask(kernel_task, 0,
                                                      kIOMapAnywhere | kIOMapWriteCombineCache, 0, length);
    if (!fScanoutMap) {
        IOLog("AdrenoDisplay: cannot map framebuffer %llx+%llx\n", addr, length);
        OSSafeReleaseNULL(fScanoutMD);
        return false;
    }
    fScanout = (volatile uint8_t *)fScanoutMap->getVirtualAddress();
    fScanoutAttr = mappingAttribute((const void *)(uintptr_t)fScanout);
    setProperty("AdrenoScanoutPhysical", fScanoutPhys, 64);
    setProperty("AdrenoScanoutRowBytes", fScanoutRowBytes, 32);
    return true;
}

void AdrenoDisplay::unmapScanout()
{
    forgetDamageGated();
    fScanout = nullptr;
    fScanoutLength = 0;
    OSSafeReleaseNULL(fScanoutMap);
    OSSafeReleaseNULL(fScanoutMD);
}

#if ADRENO_BEAM
// ---------------------------------------------------------------- beam (--present-beam, AdrenoDisplayBeam.h)

uint32_t AdrenoDisplay::beamRead(void *ctx, uint32_t offset)
{
    // A1 A3: one 32-bit load inside the one mapped page; every caller passes a DPU_INTF_* constant.
    const AdrenoDisplay *self = (const AdrenoDisplay *)ctx;
    return offset < DPU_INTF_PAGE && !(offset & 3) ? self->fBeamRegs[offset / 4] : 0;
}

uint64_t AdrenoDisplay::beamNow(void *)
{
    return mach_absolute_time();
}

void AdrenoDisplay::beamGate(void *ctx, uint64_t, uint64_t y0, uint64_t y1)
{
    AdrenoDisplay *self = (AdrenoDisplay *)ctx;
    const struct adreno_beam_io io = {beamRead, beamNow, self};
    adreno_beam_gate(&self->fBeam, &io, y0, y1);
}

void AdrenoDisplay::beamUnmap()
{
    fBeamRegs = nullptr;
    OSSafeReleaseNULL(fBeamMap);
    OSSafeReleaseNULL(fBeamMD);
}

// A1-A4 B1 D3: the page named by the GPU node (no properties: an ordinary launch, nothing is mapped or read), mapped
// read-only and uncached, its stage-1 attribute checked, the timing decoded and calibrated. A refusal unmaps the page
// and keeps the VSYNC60 timer path; the registers and the outcome go to the console once.
void AdrenoDisplay::beamMapGated()
{
    uint64_t ms = 0;
    nanoseconds_to_absolutetime(1000000, &ms);
    beamUnmap();
    adreno_beam_init(&fBeam, ms, kHeight);
    IOService *accelerator = getProvider(), *node = accelerator ? accelerator->getProvider() : nullptr;
    OSData *abi = node ? OSDynamicCast(OSData, node->getProperty(DPU_INTF_ABI_PROPERTY)) : nullptr;
    OSData *pa = node ? OSDynamicCast(OSData, node->getProperty(DPU_INTF_PA_PROPERTY)) : nullptr;
    if (!abi && !pa)
        return;                                      // state OFF: the monitor maps no INTF page
    int reason = adreno_beam_check_property(abi ? abi->getBytesNoCopy() : nullptr, abi ? abi->getLength() : 0,
                                            pa ? pa->getBytesNoCopy() : nullptr, pa ? pa->getLength() : 0);
    if (!reason) {
        fBeamMD = IOMemoryDescriptor::withPhysicalAddress(DPU_INTF_PA, DPU_INTF_PAGE, kIODirectionIn);
        if (fBeamMD)
            fBeamMap = fBeamMD->createMappingInTask(kernel_task, 0, kIOMapAnywhere | kIOMapInhibitCache | kIOMapReadOnly,
                                                    0, DPU_INTF_PAGE);
        if (!fBeamMap)
            reason = ADRENO_BEAM_R_MAP;
    }
    if (!reason) {
        fBeamAttr = mappingAttribute((const void *)(uintptr_t)fBeamMap->getVirtualAddress());
        if (!adreno_beam_attr_ok(fBeamAttr))
            reason = ADRENO_BEAM_R_ATTR;
    }
    if (reason) {
        IOLog("AdrenoDisplay: beam refused (%d) before any read: attr 0x%llx\n", reason, fBeamAttr);
        adreno_beam_refuse(&fBeam, (uint32_t)reason);
        beamUnmap();
        return;
    }
    fBeamRegs = (const volatile uint32_t *)(uintptr_t)fBeamMap->getVirtualAddress();
    const struct adreno_beam_io io = {beamRead, beamNow, this};
    struct adreno_beam_regs r;
    adreno_beam_read_regs(&io, &r);
    reason = adreno_beam_decode(&r, kWidth, kHeight, &fBeam.t);
    IOLog("AdrenoDisplay: beam INTF_5 en=%x status=%x cfg=%x/%x hsync=%x vperiod=%x v=%x-%x act=%x-%x hctl=%x/%x "
          "count_en=%x avr=%x attr=0x%llx: vtotal %u active %u-%u width %u%s (%d)\n", r.engine, r.status, r.config,
          r.config2, r.hsync_ctl, r.vsync_period, r.disp_v_start, r.disp_v_end, r.act_v_start, r.act_v_end, r.disp_hctl,
          r.act_hctl, r.count_en, r.avr, fBeamAttr, fBeam.t.vtotal, fBeam.t.a0, fBeam.t.a1, fBeam.t.width,
          fBeam.t.width_ok ? "" : " (width differs)", reason);
    if (reason) {
        adreno_beam_refuse(&fBeam, (uint32_t)reason);
        beamUnmap();
        return;
    }
    fBeam.state = ADRENO_BEAM_UNCAL;
    beamCalibrateGated();
}

// B2 B3 D4: up to 250 ms of LINE_COUNT reads. The first failure refuses the beam for this start; after a lock, a
// failed recalibration stalls it for ADRENO_BEAM_STALL_TICKS timer ticks, and the fourth in a row refuses it.
bool AdrenoDisplay::beamCalibrateGated()
{
    if (!fBeamRegs)
        return false;
    const struct adreno_beam_io io = {beamRead, beamNow, this};
    const bool locked_before = fBeam.frame != 0;
    const int reason = adreno_beam_calibrate(&fBeam, &io);
    if (!reason) {
        fBeam.recal_failures = 0;
    } else if (!locked_before || ++fBeam.recal_failures >= ADRENO_BEAM_RETRIES) {
        adreno_beam_refuse(&fBeam, locked_before ? (uint32_t)ADRENO_BEAM_R_RETRIES : (uint32_t)reason);
    } else {
        fBeam.state = ADRENO_BEAM_STALLED;
        fBeam.reason = (uint32_t)reason;
        fBeam.stalled_ticks = 0;
        fBeam.stalls++;
    }
    IOLog("AdrenoDisplay: beam calibration %s (%d): frame %llu ns, line base %u, frame counter %s at line %u, "
          "%u vblank(s) per tick\n", reason ? "failed" : "locked", reason, perfNs(fBeam.frame), fBeam.line_base,
          fBeam.fc_ok ? "tracks" : "unused", fBeam.fc_line, fBeam.n);
    return !reason;
}

// C1 C6 D4: arm the frame timer `lead` before the targeted vblank, or return false for the VSYNC60 grid (no page,
// refused, stalled, a glitched sample, drift found by the sample, or a timer refusal).
bool AdrenoDisplay::beamArmGated()
{
    if (!fBeamRegs)
        return false;
    if (fBeam.state == ADRENO_BEAM_STALLED && ++fBeam.stalled_ticks >= ADRENO_BEAM_STALL_TICKS)
        fBeam.state = ADRENO_BEAM_UNCAL;
    if (fBeam.state == ADRENO_BEAM_UNCAL && !beamCalibrateGated())
        return false;
    if (fBeam.state != ADRENO_BEAM_LOCKED)
        return false;
    const struct adreno_beam_io io = {beamRead, beamNow, this};
    uint64_t now = 0;
    const uint64_t pos = adreno_beam_sample(&fBeam, &io, &now);
    if (!pos || fBeam.state != ADRENO_BEAM_LOCKED) {
        fBeam.target = 0;
        return false;
    }
    if (!fBeam.target)
        adreno_beam_target(&fBeam, pos, fInTick);    // EARLY and LATE keep the vblank they chose
    const uint64_t fire = adreno_beam_fire_time(&fBeam, now, pos);
    const uint64_t at = adreno_vsync_arm_time(&fVsync, now, fire);    // S6: absorb the timer's coalescing slop
    if (fFrameTimer->wakeAtTime(0, at, 0) != kIOReturnSuccess) {
        fBeam.target = fBeam.armed_fire = 0;
        return false;
    }
    fVsync.deadline = fire;                           // the vsync line reports fire lateness against it
    fVsync.arms++;
    fFrameTimerArmed = true;
    fArmedAt = now;
    return true;
}

// C1 C2: the fire on the beam. EARLY and LATE re-arm for their vblank and return true (the tick does nothing else);
// GO, FORCED, UNARMED and FAILED return false and the tick completes and copies as before.
bool AdrenoDisplay::beamFireGated()
{
    if (!fBeamRegs || fBeam.state != ADRENO_BEAM_LOCKED || (!fBeam.target && !fBeam.armed_fire))
        return false;                                 // armed by the grid: an ordinary tick
    const struct adreno_beam_io io = {beamRead, beamNow, this};
    uint64_t now = 0;
    const uint64_t pos = adreno_beam_sample(&fBeam, &io, &now);
    const int outcome = adreno_beam_fire(&fBeam, now, pos);
    if (outcome != ADRENO_BEAM_EARLY && outcome != ADRENO_BEAM_LATE)
        return false;
    armFrameTimerGated();
    return true;
}
#endif

#if ADRENO_LATCH
// ---------------------------------------------------------------- the release hold (--present-latch, AdrenoDisplayLatch.h)

// IOMFBSwapIORequest +0x3d4: the swap ID swap_start_gated assigns (iomgf 0x23794 str w8,[x2,#0x3d4]), monotonic per
// display. H4: with the pointer it names a precopied swap without dereferencing a request the family may have freed.
static inline uint32_t swapID(const IOMFBSwapIORequest *swap)
{
    return *(const uint32_t *)((const uint8_t *)swap + 0x3d4);
}

// H1-H8: at a GO with the hold on, the swap on screen stays current and the pending layer-0 head is copied into the
// GO's frame; the release then completes the former Rb before the next latch and makes the head current without a
// second copy. Returns false where today's tick runs instead: no hold, the beam not locked, not a GO, nothing on screen,
// or a head that is cursor-only or not programmable (H5).
bool AdrenoDisplay::holdLatchGated()
{
    if (!fHold.enabled || !fReleaseTimer || !fBeamRegs || fBeam.state != ADRENO_BEAM_LOCKED || !fBeam.go_row0)
        return false;
    if (fReleaseArmed) {                                   // H7: the release is overdue: it runs first
        fReleaseTimer->cancelTimeout();
        fReleaseArmed = false;
        fHold.rel_overdue++;
        holdReleaseGated(true);
    }
    if (!fCurrentSwap || !fSwapPresented)
        return false;                                      // nothing on screen: today's tick dequeues and copies
    IOMFBSwapIORequest *head = fPendingSwapFirst;
    if (head && (!(IOMFBSwapFields::layerMask(head) & 1) || (IOMFBSwapFields::state(head) & ~8u) != 0 ||
                 (head == fPrecopied && swapID(head) == fPrecopiedID))) {
        fHold.fallbacks++;
        return false;                                      // H5
    }
#if ADRENO_PRESENT_SYNC
    if (!head || copyGatedGated() || syncWaitGated(head)) {   // K8: the precopy asks the same question
#else
    if (!head || copyGatedGated()) {
#endif
        if (head)
            fHold.gated++;                                 // G2: the head waits a latch, the current stays
        else
            adreno_hold_missed(&fHold, mach_absolute_time());  // H1: nothing new for this frame; the current stays
        fBeam.go_row0 = 0;
        armFrameTimerGated();
        holdArmReleaseGated();
        return true;
    }
    fPresentQueuedAt = fPendingSince;                      // H9: q from the head's first sight, as today's dequeue
    fPendingSince = 0;
    if (fPresentQueuedAt && __atomic_load_n(&gAdrenoIBCompletedAt, __ATOMIC_RELAXED) > fPresentQueuedAt)
        fHold.ib_after++;                                  // H6: hardware evidence
    armFrameTimerGated();                                  // the next latch first, as today's tick (in tick: last GO + n)
    fPrecopying = true;
    presentGated(head);                                    // into the GO's frame (adreno_beam_begin takes go_row0)
    fPrecopying = false;
    fPrecopied = head;
    fPrecopiedID = swapID(head);
    fHold.precopies++;
    fBeam.go_row0 = 0;
    holdArmReleaseGated();
    return true;
}

// H1 H2: arm the release Rb before the next latch's fire time; without an armed beam latch there is no hold for this
// frame (the next tick completes the swap, as today); a release time already reached releases at once.
void AdrenoDisplay::holdArmReleaseGated()
{
    if (!fHold.enabled || !fReleaseTimer || !fCurrentSwap || !fSwapPresented)
        return;
    if (fReleaseArmed) {
        fReleaseTimer->cancelTimeout();
        fReleaseArmed = false;
    }
    if (!fFrameTimerArmed || fBeam.state != ADRENO_BEAM_LOCKED || !fBeam.armed_fire || !fBeam.frame)
        return;
    const uint64_t now = mach_absolute_time();
    const uint64_t at = adreno_hold_release_time(&fHold, now, fBeam.armed_fire, fBeam.frame);
    if (at <= now) {
        holdReleaseGated(false);
        return;
    }
    // S6: armed early by the slop 26A428's thread-call timer adds (adreno_vsync_arm_time's rule), never in the past.
    uint64_t lead = (at - now) / 9;
    if (lead > fVsync.lead_max) lead = fVsync.lead_max;
    if (fReleaseTimer->wakeAtTime(0, at - lead, 0) != kIOReturnSuccess) {
        holdReleaseGated(false);
        return;
    }
    fReleaseArmed = true;
}

// H2 H3 H8: complete the swap on screen unless a successor is pending that was not copied yet (the next latch copies it);
// then make the precopied head current, already on the scanout. In submission order: the current first.
void AdrenoDisplay::holdReleaseGated(bool overdue)
{
    (void)overdue;
    fReleaseArmed = false;
    if (!fCurrentSwap || !fSwapPresented)
        return;
    IOMFBSwapIORequest *head = fPendingSwapFirst;
    const bool precopied = head && head == fPrecopied && swapID(head) == fPrecopiedID;
    if (head && !precopied) {
        fHold.rel_deferred++;                              // H3
        return;
    }
    fSwapPresented = false;
    swap_complete_gated();                                 // family: notify_swap_done_gated, release, clear +0x1a40
    if (precopied) {
        fHold.rel_successor++;
        // H4: the family may have dropped it (obsolete, no-op, aborted) meanwhile: only the live head is taken.
        if (cleanQueueGated() && fPendingSwapFirst == fPrecopied && swapID(fPendingSwapFirst) == fPrecopiedID) {
            // swap_begin_gated's dequeue, step for step (current, started, TAILQ_REMOVE with PV's checks).
            IOMFBSwapIORequest *swap = fPendingSwapFirst;
            fCurrentSwap = swap;
            update_swap_info_state_gated(swap, kSwapStateStarted);
            IOMFBSwapIORequest *next = IOMFBSwapFields::queueNext(swap);
            IOMFBSwapIORequest **prev = IOMFBSwapFields::queuePrev(swap);
            if (next) {
                if (IOMFBSwapFields::queuePrev(next) != &IOMFBSwapFields::queueNext(swap) || *prev != swap)
                    panic("AdrenoDisplay: corrupt swap queue at %p", swap);
                IOMFBSwapFields::queuePrev(next) = prev;
            } else {
                if (*prev != swap)
                    panic("AdrenoDisplay: corrupt swap queue tail at %p", swap);
                fPendingSwapLast = prev;
            }
            *prev = next;
            if ((IOMFBSwapFields::state(swap) & ~8u) == 0) {
                fSwapPresented = true;                     // its pixels went out at the latch
                fPresentCount++;
            } else {
                dropSwap_gated(swap, false);               // aborted after its copy: dropped, as swap_begin_gated does
                fDropCount++;
            }
        }
        fPrecopied = nullptr;
    } else {
        fHold.rel_lone++;
    }
    if (!fPendingSwapFirst)
        adreno_hold_released(&fHold, mach_absolute_time());   // H11: R only when nothing else is waiting
    if (!fCurrentSwap && fPendingSwapFirst)
        armFrameTimerGated();                              // H2: a swap still waits for a latch
}

// G1-G3 (b12v11: WindowServer's swap can arrive before its frame's IB completes): a layer-0 head first seen less than
// adreno_gate_us ago is not copied while a GPU submission (IB, FILL32) is in the kext, waiting for the submit lock or
// running. It waits one latch: by the next one it is no longer fresh, so a swap is deferred at most once. Submissions
// IOGPU has queued but not yet handed to the kext are not visible here.
bool AdrenoDisplay::copyGatedGated()
{
    if (!fGateTicks || !fBeamRegs || fBeam.state != ADRENO_BEAM_LOCKED)
        return false;
    IOMFBSwapIORequest *head = fPendingSwapFirst;
    if (!head || !(IOMFBSwapFields::layerMask(head) & 1) || !fPendingSince)
        return false;
    if (!__atomic_load_n(&gAdrenoGPUBusy, __ATOMIC_ACQUIRE))
        return false;
    return mach_absolute_time() - fPendingSince < fGateTicks;
}

// H7: stop and restart: no release, no marker.
void AdrenoDisplay::holdForgetGated()
{
    if (fReleaseTimer && fReleaseArmed)
        fReleaseTimer->cancelTimeout();
    fReleaseArmed = false;
    fPrecopied = nullptr;
    fHold.released_at = 0;
}
#endif

#if ADRENO_PRESENT_SYNC
// ---------------------------------------------------------------- present sync (agents/present-sync, AdrenoDisplaySync.h)

// K1-K4 K11: true when this layer-0 head must stay queued because an IB or FILL32 in the kext still writes its surface.
// The head is named by its pointer and swap ID (+0x3d4), compared and never dereferenced beyond the swap's own fields. No
// clock read unless the surface is marked or a head is waiting. At the bound the head is copied anyway (FORCED, logged).
static inline uint32_t syncSwapID(const IOMFBSwapIORequest *swap)
{
    return *(const uint32_t *)((const uint8_t *)swap + 0x3d4);
}
#if ADRENO_PIPELINE
// agents/gpu-pipeline D1 D3: as below, for every layer the swap carries (layer 0 and the cursor layers 1-3, which are
// captured at the swap): the head stays queued while any of their surfaces has a writer in flight.
bool AdrenoDisplay::syncWaitGated(IOMFBSwapIORequest *head)
{
    const uint8_t mask = head ? IOMFBSwapFields::layerMask(head) : 0;
    if (!fSync.max_wait || !head || !mask || (IOMFBSwapFields::state(head) & ~8u) != 0)
        return false;
    uint32_t writers = 0, written = 0;
    uint64_t oldest = 0;
    for (uint32_t l = 0; l < IOMFBSwapFields::kLayerCount; l++) {
        IOSurface *surface = (mask & (1u << l)) ? IOMFBSwapFields::layerSurface(head, l) : nullptr;
        if (!surface)
            continue;
        uint64_t since = 0;
        const uint32_t w = AdrenoPresentSyncQuery(surface->getSurfaceID(), &since);
        if (!w)
            continue;
        writers += w;
        if (!written) written = surface->getSurfaceID();
        if (since && (!oldest || since < oldest)) oldest = since;
    }
    if (!writers && !fSync.head)
        return false;                                       // the common case: nothing written, nobody waiting
    const uint64_t now = mach_absolute_time();
    const int r = adreno_sync_decide(&fSync, head, syncSwapID(head), writers, oldest, now);
    if (r == ADRENO_SYNC_FORCED && (++fSyncForcedLogged <= 8 || !(fSyncForcedLogged & 255)))
        IOLog("AdrenoDisplay: present sync: copied IOSurface %u with %u GPU writes in flight after the %llu us bound (%llu times)\n",
              written, writers, (unsigned long long)(perfNs(fSync.max_wait) / 1000u),
              (unsigned long long)fSyncForcedLogged);
#if ADRENO_PRESENT_RELATCH
    if (r == ADRENO_SYNC_WAIT && fInTick) {                 // RL4: the head a tick deferred (vsyncGated may relatch it)
        fRelatchCandidate = head;
        fRelatchCandidateID = syncSwapID(head);
    }
#endif
    return r == ADRENO_SYNC_WAIT;
}
#if ADRENO_PRESENT_RELATCH
// ---------------------------------------------------------------- relatch (agents/present-pacing, AdrenoDisplayRelatch.h)

// The writers syncWaitGated asks for (layer 0 and the cursor layers of the swap's mask), without a decision (RL2).
uint32_t AdrenoDisplay::relatchWritersGated(IOMFBSwapIORequest *head)
{
    const uint8_t mask = head ? IOMFBSwapFields::layerMask(head) : 0;
    uint32_t writers = 0;
    for (uint32_t l = 0; l < IOMFBSwapFields::kLayerCount; l++) {
        IOSurface *surface = (mask & (1u << l)) ? IOMFBSwapFields::layerSurface(head, l) : nullptr;
        if (surface)
            writers += AdrenoPresentSyncQuery(surface->getSurfaceID(), nullptr);
    }
    return writers;
}

extern "C" uint32_t gAdrenoPresentUrgent;                  // AdrenoX2.cpp: the completion timer's urgent period (UR1)
void AdrenoDisplay::relatchUrgent(bool on)
{
    __atomic_store_n(&gAdrenoPresentUrgent, on ? 1u : 0u, __ATOMIC_RELAXED);
}

// RL1 RL4: after a tick's swap_begin_gated: the tick's GO chose a frame (go_row0 still set: no layer-0 copy took it),
// nothing is on screen as current, and the sync gate deferred the live head in this tick. Not with the hold (RL5).
void AdrenoDisplay::relatchArmGated()
{
    IOMFBSwapIORequest *head = fPendingSwapFirst;
    if (!fRelatchTimer || !fRelatchCandidate || head != fRelatchCandidate || syncSwapID(head) != fRelatchCandidateID ||
        fCurrentSwap || fHold.enabled || !fBeamRegs || fBeam.state != ADRENO_BEAM_LOCKED || !fBeam.go_row0)
        return;
    const uint64_t now = mach_absolute_time();
    adreno_relatch_arm(&fRelatch, &fBeam, head, fRelatchCandidateID, fBeam.go_row0, now);
    if (fRelatch.enabled)
        relatchUrgent(true);
    relatchScheduleGated(now);
}

// The next poll: every poll ticks while the frame can still take the copy, every millisecond after (histogram only).
// Armed early by the slop 26A428's thread-call timer adds (adreno_vsync_arm_time's rule), never in the past.
void AdrenoDisplay::relatchScheduleGated(uint64_t now)
{
    if (!fRelatchTimer || !fRelatch.pending)
        return;
    uint64_t ms = 0;
    nanoseconds_to_absolutetime(1000000, &ms);
    const uint64_t at = now + (fRelatch.open ? fRelatch.poll : (fRelatch.poll > ms ? fRelatch.poll : ms));
    uint64_t lead = (at - now) / 9;
    if (lead > fVsync.lead_max) lead = fVsync.lead_max;
    if (fRelatchTimer->wakeAtTime(0, at - lead, 0) != kIOReturnSuccess) {
        relatchEndGated(false);
        return;
    }
    fRelatchArmed = true;
}

// RL1-RL3: one poll on the work loop. A released head before the deadline is copied as the GO's copy would have been:
// go_row0 = the GO's frame, swap_begin_gated in tick context (syncWaitGated asks again, every chunk is beam-gated).
void AdrenoDisplay::relatchFireGated()
{
    fRelatchArmed = false;
    if (!fRelatch.pending)
        return;
    IOMFBSwapIORequest *head = fPendingSwapFirst;
    if (fCurrentSwap || !head || !fBeamRegs || fBeam.state != ADRENO_BEAM_LOCKED) {
        fRelatch.gone++;
        relatchEndGated(false);
        return;
    }
    const struct adreno_beam_io io = {beamRead, beamNow, this};
    uint64_t now = 0;
    const uint64_t pos = adreno_beam_sample(&fBeam, &io, &now);
    if (!pos || fBeam.state != ADRENO_BEAM_LOCKED) {
        fRelatch.gone++;
        relatchEndGated(false);
        return;
    }
    int d = adreno_relatch_check(&fRelatch, head, syncSwapID(head), pos, relatchWritersGated(head), now);
    if (d == ADRENO_RELATCH_GO && copyGatedGated()) {      // G1: asked as the tick asks it
        adreno_relatch_gated(&fRelatch);
        d = ADRENO_RELATCH_WAIT;
    }
    if (d == ADRENO_RELATCH_WAIT) {
        if (!fRelatch.open)
            relatchUrgent(false);                           // the frame has gone: only the histogram waits
        relatchScheduleGated(now);
        return;
    }
    relatchUrgent(false);
    if (d != ADRENO_RELATCH_GO)
        return;
    const uint64_t row0 = fRelatch.row0, ovt = fBeam.ovt, since = fRelatch.since;
    const bool tick = fInTick;
    fBeam.go_row0 = row0;
    fInTick = true;
    swap_begin_gated();
    fInTick = tick;
    const bool copied = !fBeam.go_row0 && fCurrentSwap && fSwapPresented;   // the present took the GO's frame
    fBeam.go_row0 = 0;
    adreno_relatch_copied(&fRelatch, copied, row0 > pos ? adreno_beam_ticks(&fBeam, row0 - pos) : 0,
                          now > since ? now - since : 0, fBeam.ovt - ovt);
}

// End a pending relatch: at a tick that proceeds (tick: its histogram bin), or a stop, a mode set, a failed arm.
void AdrenoDisplay::relatchEndGated(bool tick)
{
    if (fRelatch.pending) {
        if (tick)
            adreno_relatch_tick(&fRelatch);
        else
            adreno_relatch_cancel(&fRelatch);
    }
    if (fRelatchArmed && fRelatchTimer)
        fRelatchTimer->cancelTimeout();
    fRelatchArmed = false;
    relatchUrgent(false);
}
#endif
#else
bool AdrenoDisplay::syncWaitGated(IOMFBSwapIORequest *head)
{
    if (!fSync.max_wait || !head || !(IOMFBSwapFields::layerMask(head) & 1) || (IOMFBSwapFields::state(head) & ~8u) != 0)
        return false;
    IOSurface *surface = IOMFBSwapFields::layerSurface(head, 0);
    if (!surface)
        return false;
    uint64_t oldest = 0;
    const uint32_t writers = AdrenoPresentSyncQuery(surface->getSurfaceID(), &oldest);
    if (!writers && !fSync.head)
        return false;                                       // the common case: nothing written, nobody waiting
    const uint64_t now = mach_absolute_time();
    const int r = adreno_sync_decide(&fSync, head, syncSwapID(head), writers, oldest, now);
    if (r == ADRENO_SYNC_FORCED && (++fSyncForcedLogged <= 8 || !(fSyncForcedLogged & 255)))
        IOLog("AdrenoDisplay: present sync: copied IOSurface %u with %u GPU writes in flight after the %llu us bound (%llu times)\n",
              surface->getSurfaceID(), writers, (unsigned long long)(perfNs(fSync.max_wait) / 1000u),
              (unsigned long long)fSyncForcedLogged);
    return r == ADRENO_SYNC_WAIT;
}
#endif
#endif

// ---------------------------------------------------------------- DisplayAttributes

static bool putNum(OSDictionary *d, const char *key, uint64_t v, unsigned bits)
{
    OSNumber *n = OSNumber::withNumber(v, bits);
    bool ok = n && d->setObject(key, n);
    OSSafeReleaseNULL(n);
    return ok;
}

static bool putStr(OSDictionary *d, const char *key, const char *v)
{
    OSString *s = OSString::withCString(v);
    bool ok = s && d->setObject(key, s);
    OSSafeReleaseNULL(s);
    return ok;
}

static bool putDict(OSDictionary *d, const char *key, OSDictionary *v)
{
    bool ok = v && d->setObject(key, v);
    OSSafeReleaseNULL(v);
    return ok;
}

// PV createColorPointDict (0xe28c): {X, Y} in 16.16 (float + 2^-17, truncated), Gamma 1.0.
static OSDictionary *colorPoint(double x, double y)
{
    OSDictionary *d = OSDictionary::withCapacity(3);
    if (!d)
        return nullptr;
    bool ok = putNum(d, "X", (uint32_t)((x + 0x1p-17) * 65536.0)) &&
              putNum(d, "Y", (uint32_t)((y + 0x1p-17) * 65536.0)) &&
              putNum(d, "Gamma", 0x10000);
    if (!ok)
        OSSafeReleaseNULL(d);
    return d;
}

bool AdrenoDisplay::publishDisplayAttributes()
{
    // PV createDisplayAttributes (0xa370..0xb170): ProductAttributes, Chromaticity, the
    // panel geometry, Transport, IOMFBMaxSrcPixels, IOMFBScalingLimits, and the IOAV
    // ColorElements / TimingElements arrays. Values are for the fixed A16 panel mode.
    if (fAttributesPublished)
        return true;
    uuid_t uuid;
    uuid_string_t text;
    uuid_generate(uuid);
    uuid_unparse(uuid, text);
    setProperty("IOMFBUUID", text);
    setProperty("external", false);

    OSDictionary *product = OSDictionary::withCapacity(6);
    OSDictionary *chroma = OSDictionary::withCapacity(3);
    OSDictionary *attrs = OSDictionary::withCapacity(12);
    OSDictionary *transport = OSDictionary::withCapacity(2);
    OSDictionary *maxSrc = OSDictionary::withCapacity(5);
    OSDictionary *scaling = OSDictionary::withCapacity(2);
    bool ok = product && chroma && attrs && transport && maxSrc && scaling;
    ok = ok && putStr(product, "ManufacturerID", "APP") && putNum(product, "ProductID", 0) &&
         putNum(product, "SerialNumber", 0) && putStr(product, "ProductName", "Adreno X2 Panel") &&
         putNum(product, "WeekOfManufacture", 24) && putNum(product, "YearOfManufacture", 2021);
    // sRGB / Rec.709 primaries, D65 white (INFERRED for the A16 panel; PV takes them from the host).
    ok = ok && putDict(chroma, "Red", colorPoint(0.640, 0.330)) &&
         putDict(chroma, "Green", colorPoint(0.300, 0.600)) &&
         putDict(chroma, "Blue", colorPoint(0.150, 0.060));
    ok = ok && attrs->setObject("SupportsPQEOTF", kOSBooleanFalse) &&
         attrs->setObject("ProductAttributes", product) && attrs->setObject("Chromaticity", chroma) &&
         attrs->setObject("DefaultColorSpaceIsSRGB", kOSBooleanFalse) &&
         putDict(attrs, "DefaultWhitePoint", colorPoint(0.3127, 0.3290)) &&
         attrs->setObject("SupportsStandby", kOSBooleanTrue) &&
         putNum(attrs, "ContinuousFrequencySupport", 3) &&
         putNum(attrs, "MaxHorizontalImageSize", (kPanelWidthMM + 9) / 10) &&
         putNum(attrs, "MaxVerticalImageSize", (kPanelHeightMM + 9) / 10) &&
         putNum(attrs, "NativeFormatHorizontalPixels", kWidth) &&
         putNum(attrs, "NativeFormatVerticalPixels", kHeight) &&
         putNum(attrs, "PreciseAspectRatio", (uint32_t)((float)kWidth * 65536.0f / (float)kHeight));
    ok = ok && putStr(transport, "Upstream", "Other") && putStr(transport, "Downstream", "Other");
    ok = ok && putNum(maxSrc, "MaxSrcBufferWidth", 16384) && putNum(maxSrc, "MaxSrcBufferHeight", 16384) &&
         putNum(maxSrc, "MaxSrcRectWidth", 16384) && putNum(maxSrc, "MaxSrcRectTotal", 0) &&
         putNum(maxSrc, "IOMFBMaxCompressedSizeInBytes", 0);
    ok = ok && putNum(scaling, "RGBLayer_MinScaleFraction", 4) && putNum(scaling, "RGBLayer_MaxScale", 4);

    // IOAV elements, as PV's init (0x9018..0x9100) and createDisplayAttributes (0xa854..0xaa58),
    // except that only PV's first color element is published: depth 8, SDR (EOTF 0), RGB, id 100
    // -- the only one the 32 bpp firmware scanout (fScanoutDepth == 32) can show. PV also offers
    // depth-10 SDR (102) and EDR (103); from those, CoreAnimation 26A428 builds 10-bit modes
    // (IOMFBDisplay::update_digital_modes assigns color codes 16..28 only when Depth >= 10) and
    // then renders into 10-bit framebuffers (framebuffer_pixel_format), which neither this copy
    // path nor the plug-in's RGBA8/BGRA8 clear accepts (generation71). One timing element per
    // mode (id 1000 + index, score 1000 - index) owns the color list.
    // Colorimetry 10 is sRGB (IOAVVideoColorimetryString). PV's 16, "Default RGB", is the panel's
    // native gamut: QuartzCore's update_digital_modes gives an RGB Default-RGB element its native
    // colour code, update_framebuffer_locked then sets supportsExtendedColors, and the framebuffer
    // becomes the two-plane 10-bit 'b3a8' (Metal 550) instead of 'BGRA'
    // (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md). This panel is sRGB: the primaries above, and
    // /product artwork-display-gamut "sRGB".
    if (ok && !fColorElements) {
        fColorElements = OSArray::withCapacity(1);
        IOAVVideoColorElement *c = fColorElements ? IOAVVideoColorElement::withCapabilities(
            (IOAVStandardType)2, 8, (IOAVVideoPixelEncoding)0, (IOAVVideoColorDynamicRange)0,
            (IOAVVideoColorEOTF)0, (IOAVVideoColorimetry)10, false, nullptr, nullptr, nullptr, nullptr) : nullptr;
        if (c) {
            setAVElementIdentity(c, kColorIDSDR8, kColorIDSDR8);
            ok = fColorElements->setObject(c);
            c->release();
        } else {
            ok = false;
        }
    }
    if (ok && !fTimingElements) {
        fTimingElements = OSArray::withCapacity(1);
        IOAVVideoTimingData t = {};
        uint32_t rate = kRefreshHz << 16;                        // INFERRED 16.16 Hz, as PV's mode table
        t.hActive = kWidth;
        t.hSyncRate = rate * kHeight;
        t.vActive = kHeight;
        t.vSyncRate = rate;
        IOAVVideoTimingElement *e = fTimingElements
            ? IOAVVideoTimingElement::withData(&t, (IOAVStandardType)2, (IOAVVideoTimingStandard)4) : nullptr;
        if (e) {
            setAVElementIdentity(e, kTimingID, 1000);
            OSArray *colors = OSArray::withCapacity(1);
            if (colors) {
                colors->merge(fColorElements);
                e->setColorElements(colors);
                colors->release();
            }
            ok = fTimingElements->setObject(e);
            e->release();
        } else {
            ok = false;
        }
    }
    if (ok) {
        setProperty("DisplayAttributes", attrs);
        setProperty("Transport", transport);
        setProperty("ColorElements", fColorElements);
        setProperty("TimingElements", fTimingElements);
        setProperty("IOMFBMaxSrcPixels", maxSrc);
        setProperty("IOMFBScalingLimits", scaling);
        fAttributesPublished = true;
    } else {
        IOLog("AdrenoDisplay: DisplayAttributes construction failed\n");
    }
    OSSafeReleaseNULL(product);
    OSSafeReleaseNULL(chroma);
    OSSafeReleaseNULL(attrs);
    OSSafeReleaseNULL(transport);
    OSSafeReleaseNULL(maxSrc);
    OSSafeReleaseNULL(scaling);
    if (ok) {
        // PV handleHostInterrupt 0x93bc: after (re)creating the attributes, tell clients the
        // display configuration changed (message 0xe0000130).
        messageClients(0xe0000130);
    }
    return ok;
}

void AdrenoDisplay::withdrawDisplayAttributes()
{
    // PV destroyDisplayAttributes 0x977c: the properties go and the size reads zero.
    if (!fAttributesPublished)
        return;
    removeProperty("DisplayAttributes");
    removeProperty("Transport");
    removeProperty("ColorElements");
    removeProperty("TimingElements");
    removeProperty("IOMFBMaxSrcPixels");
    removeProperty("IOMFBScalingLimits");
    fDisplayWidth = fDisplayHeight = 0;
    fAttributesPublished = false;
}
