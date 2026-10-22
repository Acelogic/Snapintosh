/* SPDX-License-Identifier: MIT */
// AdrenoDisplay.h - IOMobileFramebuffer for the A16 panel (Stage 8, milestone M0).
//
// WindowServer can only present to an IOMobileFramebuffer service. This is a
// software IOMobileFramebufferLegacy subclass modelled on Apple's
// AppleParavirtDisplay (AppleParavirtGPUIOGPUFamily, 26A428): the family owns the
// user client, swap queue and notifications; the subclass supplies the nine pure
// virtuals, accepts every swap (verify_swap) and retires swaps from a 16 ms
// timer, the way the paravirtual driver's swap_begin_gated re-arms its timer.
//
// Presentation is a CPU copy of layer 0's IOSurface into the firmware (GOP)
// framebuffer the boot console uses (PE_Video from boot_args). No display
// engine is programmed. Fixed mode: 2880x1800, 60 Hz, 32-bit BGRA.
// The copy itself (bounds, formats, per-row cache maintenance) is the
// header-only AdrenoDisplayCopy.h, shared with the host E2E test; the present
// (AdrenoDisplayPresent.h) maintains the source rows in one pass with one barrier,
// reads each row once into a stage and publishes only rows whose 128-bit signature
// changed (plus a rolling refresh and every cursor row). The first
// presented surface turns the kernel's text console off the panel
// (IOPlatformExpert::setConsoleInfo(nullptr, kPEReleaseScreen)).
// The hardware cursor QuartzCore puts on its own layer (layers 1-3; layer 1 with
// CursorPlane=1) is alpha-composited over that copy with a save-under, by the
// header-only AdrenoDisplayCursor.h (docs/ADRENO-DISPLAY-CURSOR-20261018.md).
//
// Topology (PROVEN from AppleParavirtGPU::start 0x15a28..0x15ad4): the GPU
// service allocates the display, init()s it, attach()es it as its own child and
// start()s it with itself as provider. AdrenoAcceleratorX2::start does the same
// through AdrenoDisplayAttach() below, so SkyLight finds the accelerator above it.
//
// Main-display selection (PROVEN, host 26A428 IOMobileFramebuffer.framework):
// IOMobileFramebufferGetMainDisplay takes the first enumerated IOMobileFramebuffer
// whose "dfr", "AppleTV" and "external" properties are all false (absent
// "external" counts as internal) and whose secondary-internal number is zero.
// The framework only enumerates when /arm-io holds at least one child with
// device_type display-subsystem or ext-display-subsystem, and it waits up to
// 30 s for as many services as there are such nodes. The display guest
// profile therefore keeps disp0 (its AppleCLCD2 never registers: DCP start
// blocks) and withdraws dispext0, so the count is exactly this one service.
#pragma once
// --present-cached-read (FAILURES-AND-DESIGN.md section 10): build AdrenoDisplay.o with
// -DADRENO_PRESENT_CACHED_READ=1. Off by default; without it this source compiles to the
// --present-damage object.
#ifndef ADRENO_PRESENT_CACHED_READ
#define ADRENO_PRESENT_CACHED_READ 0
#endif
// Kext batch 8 (FAILURES-AND-DESIGN.md 2026-10-20): -DADRENO_PERF_FRAMES=1 adds frame pacing to the perf output
// and splits it into five lines of at most 250 bytes. Off by default; without it this source compiles as before.
#ifndef ADRENO_PERF_FRAMES
#define ADRENO_PERF_FRAMES 0
#endif
// --present-vsync60 (FAILURES-AND-DESIGN-VSYNC.md 2026-10-20): -DADRENO_VSYNC60=1 locks the frame tick to an absolute
// 16,666,667 ns grid (IOTimerEventSource::wakeAtTime at the next grid point, armed early by the timer's coalescing
// slop) instead of re-arming 16 ms relative to each tick. Needs ADRENO_PERF_FRAMES. Off by default.
#ifndef ADRENO_VSYNC60
#define ADRENO_VSYNC60 0
#endif
#if ADRENO_VSYNC60 && !ADRENO_PERF_FRAMES
#error "ADRENO_VSYNC60 needs ADRENO_PERF_FRAMES (the tick state and the perf lines)"
#endif
// The perf gpu line (pacing work 2026-10-21, AdrenoDisplayPacing.h P1-P7): -DADRENO_PERF_GPU=1 here and in AdrenoX2.o
// and AdrenoMemoryMap.o, whose counters it reads. Off by default; without it this source compiles as before.
#ifndef ADRENO_PERF_GPU
#define ADRENO_PERF_GPU 0
#endif
#if ADRENO_PERF_GPU && !ADRENO_PERF_FRAMES
#error "ADRENO_PERF_GPU needs ADRENO_PERF_FRAMES (the perf windows)"
#endif
// --present-beam (agents/tear-free FAILURE-MODES.md): -DADRENO_BEAM=1 reads the eDP interface's real scanout position
// (DPU INTF_5, one read-only page the -DSNAP_DISPLAY_TIMING=1 monitor maps and advertises on the GPU node), arms the frame
// tick on the panel's real vblank, and gates every 16-row chunk of the scanout copy against the beam
// (AdrenoDisplayBeam.h). Needs ADRENO_VSYNC60 (its timer path is the fallback). Off by default.
#ifndef ADRENO_BEAM
#define ADRENO_BEAM 0
#endif
#if ADRENO_BEAM && !ADRENO_VSYNC60
#error "ADRENO_BEAM needs ADRENO_VSYNC60 (the fallback tick and the in-tick state)"
#endif
// agents/tear-free (the dvfs finding): -DADRENO_PRESENT_SKIP_MAINT=1 drops the layer-0 present's DC CIVAC pass and its
// barrier. Every GPU write to a layer-0 surface is invalidated by physical address over the whole resource after the IB
// retires and before the commit returns (adreno_resource_list_submit FROM_DEVICE, ADRENO_CACHE_SPARSE scope ALL, the
// asynchronous IB included), a failed invalidation stops all further GPU work (AdrenoX2.h fail-fast), and CPU-drawn
// surfaces are coherent; so the pass only re-cleaned clean lines (0.22 ms a frame in b11v1). boot-arg
// adreno_present_maint=1 restores it at run time. The cursor capture keeps its own maintenance. Off by default.
#ifndef ADRENO_PRESENT_SKIP_MAINT
#define ADRENO_PRESENT_SKIP_MAINT 0
#endif
// --present-latch (agents/input-latency FAILURE-MODES.md L1-L9, H1-H11): -DADRENO_LATCH=1 latches a swap late in the
// panel's blank (slack before row 0 leaves, boot-arg adreno_latch_us, default 3000; 0 = today's aim) and holds the
// completion of the swap on screen until just before the next latch, copying the pending swap at the latch meanwhile
// (boot-arg adreno_hold, default 0 since b12v11; adreno_hold_margin_us, default 1500), so WindowServer renders just in time
// instead of a frame ahead (AdrenoDisplayLatch.h). A layer-0 swap first seen less than adreno_gate_us (default 4000) ago is
// not copied while a GPU submission is in the kext (G1-G3). Needs ADRENO_BEAM, and ADRENO_LATCH in AdrenoX2.o too (the
// submission counter). Off by default; without it this source compiles as before.
#ifndef ADRENO_LATCH
#define ADRENO_LATCH 0
#endif
#if ADRENO_LATCH && !ADRENO_BEAM
#error "ADRENO_LATCH needs ADRENO_BEAM (the latch is a beam position)"
#endif
// --present-sync (agents/present-sync FAILURE-MODES.md K1-K11): -DADRENO_PRESENT_SYNC=1 here and in AdrenoX2.o, whose IB
// and FILL32 submissions mark the IOSurfaces they write until they return. A layer-0 swap whose surface is marked is not
// copied; it waits for a later tick, at most adreno_sync_max_us (default 50000; 0 = off) per swap, then is copied and
// counted (AdrenoDisplaySync.h). Off by default; without it this source compiles as before.
#ifndef ADRENO_PRESENT_SYNC
#define ADRENO_PRESENT_SYNC 0
#endif
#if ADRENO_PRESENT_SYNC && !ADRENO_PERF_FRAMES
#error "ADRENO_PRESENT_SYNC needs ADRENO_PERF_FRAMES (the perf sync line and its clock conversion)"
#endif
// --pipeline (agents/gpu-pipeline FAILURE-MODES.md D1-D5, O4): -DADRENO_PIPELINE=1 in every unit. An IB's write marks now
// last until it retired, which a swap that arrives right after the IB started waits for: adreno_sync_max_us defaults to
// 1,100,000 (above the monitor's 1 s IB budget), and the gate also asks for the cursor layers' surfaces. A perf pipe line
// per perf window. Off by default; without it this source compiles as before.
#ifndef ADRENO_PIPELINE
#define ADRENO_PIPELINE 0
#endif
#if ADRENO_PIPELINE && !ADRENO_PRESENT_SYNC
#error "ADRENO_PIPELINE needs ADRENO_PRESENT_SYNC (the display's write gate)"
#endif
// --present-relatch (agents/present-pacing FAILURE-MODES.md RL1-RL7, UR1, OP1): -DADRENO_PRESENT_RELATCH=1 in every unit.
// A layer-0 head the sync gate defers at a latch's GO is copied into that GO's frame as soon as its surfaces are released,
// if the copy can still start before the relatch deadline (boot-args adreno_relatch, default 1 (0 = measure only),
// adreno_relatch_poll_us 200, adreno_relatch_guard_us 1000); the pipeline's completion timer polls faster meanwhile
// (AdrenoX2.cpp). A perf relatch line per perf window. Off by default; without it this source compiles as before.
#ifndef ADRENO_PRESENT_RELATCH
#define ADRENO_PRESENT_RELATCH 0
#endif
#if ADRENO_PRESENT_RELATCH && (!ADRENO_LATCH || !ADRENO_PIPELINE)
#error "ADRENO_PRESENT_RELATCH needs ADRENO_LATCH (the GO's frame) and ADRENO_PIPELINE (the marks it waits for)"
#endif
#include "IOMobileGraphicsFamily26A428.h"
#include "AdrenoDisplayPresent.h"
#if ADRENO_PERF_FRAMES
#include "AdrenoDisplayPacing.h"
#endif
#if ADRENO_BEAM
#include "AdrenoDisplayBeam.h"
#endif
#if ADRENO_LATCH
#include "AdrenoDisplayLatch.h"
#endif
#if ADRENO_PRESENT_SYNC
#include "AdrenoDisplaySync.h"
#endif
#if ADRENO_PIPELINE
#include "AdrenoDisplayPipe.h"
#endif
#if ADRENO_PRESENT_RELATCH
#include "AdrenoDisplayRelatch.h"
#endif
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOCommandGate.h>

// Creates the display as a child of the accelerator. By default only when
// IODeviceTree:/arm-io/dispext0 is absent (the display profile); boot-arg
// adreno_display=0/1 forces it off/on. Returns false (and leaves the accelerator
// untouched) when not created or when the display fails to start. Never fatal.
bool AdrenoDisplayAttach(IOService *accelerator);

class AdrenoDisplay : public IOMobileFramebufferLegacy
{
    OSDeclareDefaultStructors(AdrenoDisplay)
public:
    static constexpr uint32_t kWidth = 2880;
    static constexpr uint32_t kHeight = 1800;
    static constexpr uint32_t kRefreshHz = 60;
    static constexpr uint32_t kFramePeriodMS = 16;
    static constexpr uint32_t kTimingID = 1000;       // AppleParavirtDisplay: element +0x10 = 1000 + index
    static constexpr uint32_t kColorIDSDR8 = 100;     // createColorElementWithDepthAndEDR(0, 8, false); the only one published
    static constexpr uint32_t kPanelWidthMM = 302;    // INFERRED 13.6" 16:10 panel; only EDID-style metadata
    static constexpr uint32_t kPanelHeightMM = 189;

    // IOService
    virtual bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void stop(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;

    // IOMobileFramebufferLegacy pure virtuals (slots 318 320 361 362 428 429 462 463 470).
    virtual IOReturn set_notify_tag_mask_gated(IOMFB_NotificationType type, IOMFBNotifyRequest *req,
                                               unsigned int mask) APPLE_KEXT_OVERRIDE;
    virtual IOReturn supported_frame_info(unsigned int index, unsigned int *count, char (*names)[64],
                                          unsigned int *sizes) APPLE_KEXT_OVERRIDE;
    virtual IOReturn factory_portal(void *arg, task *owner) APPLE_KEXT_OVERRIDE;
    virtual IOReturn executeFactoryConfigurations_gated() APPLE_KEXT_OVERRIDE;
    virtual void set_frame_info_notification_state_gated(IOMFBNotifyRequest *req, bool on) APPLE_KEXT_OVERRIDE;
    virtual void do_swap_info_notify_gated(IOMFBNotifyRequest *req,
                                           const IOMobileFramebufferLegacy::SwapInfoBlob *blob) APPLE_KEXT_OVERRIDE;
    // ::SwapInfoBlob (global) is the mangled type; the nested one would change the diversity.
    virtual IOReturn notify_swap_done_gated(unsigned int swapID, ::SwapInfoBlob *blob, unsigned int *a2,
                                            unsigned int a3) APPLE_KEXT_OVERRIDE;
    virtual void notify_crc_ready_gated(unsigned int a0) APPLE_KEXT_OVERRIDE;
    virtual bool are_timings_enabled() const APPLE_KEXT_OVERRIDE;

    // Swap engine.
    virtual bool verify_swap(IOMFBSwapIORequest *swap) APPLE_KEXT_OVERRIDE;
    virtual void swap_begin_gated() APPLE_KEXT_OVERRIDE;
    virtual bool start_hardware() APPLE_KEXT_OVERRIDE;
    virtual void stop_hardware_gated() APPLE_KEXT_OVERRIDE;
    virtual IOReturn set_digital_out_mode(unsigned int timingID, unsigned int colorID) APPLE_KEXT_OVERRIDE;
    // Legacy::get_dot_pitch dereferences the AppleARMIODevice provider cached at +0x1b80
    // without a NULL check; get_dot_pitch_float and get_display_area reach it too.
    virtual IOReturn get_dot_pitch(unsigned int *pitch) APPLE_KEXT_OVERRIDE;
    // No DART: layer surfaces are read by the CPU, never mapped for a display engine.
    virtual IOReturn swap_layer_map(IOMFBSwapIORequest *swap, unsigned int layer) APPLE_KEXT_OVERRIDE;
    virtual IOReturn surface_layer_map(IOMFB::AP::DisplayedData *data, unsigned int layer,
                                       IOSurface *surface) APPLE_KEXT_OVERRIDE;
    virtual void surface_layer_unmap(IOMFB::AP::DisplayedData *data, unsigned int layer) APPLE_KEXT_OVERRIDE;

private:
    bool cleanQueueGated();
    void presentGated(IOMFBSwapIORequest *swap);
    void vsyncGated(IOTimerEventSource *sender);
    void armFrameTimerGated();
    bool mapScanout();
    void unmapScanout();
    bool publishDisplayAttributes();
    void withdrawDisplayAttributes();
    struct SurfaceMap;
    IOMemoryMap *mapSurfaceGated(IOMemoryDescriptor *md, SurfaceMap *slots, uint32_t count);
#if ADRENO_PRESENT_CACHED_READ
    IOMemoryMap *mapSourceGated(IOSurface *surface, IOMemoryDescriptor *md, bool *cached);
#endif
    void releaseSurfaceMaps();
    bool disableConsoleGated();
    void publishStatsGated();
    void perfLineGated(const char *why);
    bool updateCursorGated(IOMFBSwapIORequest *swap, uint8_t layers);
    bool cursorBuffersGated();
    void releaseCursor();
    bool presentBuffersGated();
    void releasePresentBuffers();
    void forgetDamageGated();
#if ADRENO_BEAM
    void beamMapGated();
    void beamUnmap();
    bool beamCalibrateGated();
    bool beamArmGated();
    bool beamFireGated();
    static uint32_t beamRead(void *ctx, uint32_t offset);
    static uint64_t beamNow(void *ctx);
    static void beamGate(void *ctx, uint64_t x, uint64_t y0, uint64_t y1);
#endif
#if ADRENO_LATCH
    bool holdLatchGated();
    void holdArmReleaseGated();
    void holdReleaseGated(bool overdue);
    void holdForgetGated();
    bool copyGatedGated();
#endif
#if ADRENO_PRESENT_SYNC
    bool syncWaitGated(IOMFBSwapIORequest *head);   // K1: this layer-0 head stays queued (its surface is being written)
#endif
#if ADRENO_PRESENT_RELATCH
    uint32_t relatchWritersGated(IOMFBSwapIORequest *head);   // the writers syncWaitGated asks for, without a decision
    void relatchArmGated();
    void relatchScheduleGated(uint64_t now);
    void relatchFireGated();
    void relatchEndGated(bool tick);
    void relatchUrgent(bool on);
#endif

    // Kernel read-only mappings of recently presented surface allocations. Each
    // slot retains its descriptor, so the pages stay valid while mapped; the
    // least recently used slot is replaced. WindowServer rotates a few buffers.
    // The cursor layer has slots of its own, so it never evicts a layer-0 buffer.
    static constexpr uint32_t kSurfaceMapSlots = 3;
    static constexpr uint32_t kCursorMapSlots = 2;
    struct SurfaceMap {
        IOMemoryDescriptor *md;
        IOMemoryMap *map;
        uint64_t lastUse;
#if ADRENO_PRESENT_CACHED_READ
        bool cached;                       // the map walked to Normal write-back when made (M1)
#endif
    };
    SurfaceMap fSurfaceMaps[kSurfaceMapSlots];
    SurfaceMap fCursorMaps[kCursorMapSlots];

    // Cursor (overlay) layers 1..3. fCursor's image/save buffers are allocated on the
    // first swap that carries a cursor surface. Diagnostics go to AdrenoDisplayStats.
    static constexpr uint8_t kOverlayLayers = 0x0e;
    struct adreno_display_cursor fCursor;
    struct adreno_display_present_workspace fPresentWorkspace;
    uint64_t fPublishedBytes, fPublishedRegions, fSourceBytes;
    uint32_t fLastLayerMask;               // swap+0x3d8 of the last swap (u32)
    uint32_t fLayerMaskSeen;               // OR of every swap's mask
    uint64_t fCursorSwaps;                 // swaps with a layer 1..3 bit
    uint64_t fCursorOnlySwaps;             // ... and without layer 0
    uint64_t fCursorImmediate;             // cursor-only swaps completed at once (PV), not on the tick
    uint64_t fCursorUpdates;               // cursor surfaces captured and placed
    uint64_t fCursorDraws;                 // presents that composited the cursor
    uint64_t fCursorHides;                 // cursor layer switched off (surface ID 0)
    uint64_t fCursorFormatSkips;           // cursor surface not 'BGRA': hidden, not drawn
    uint64_t fCursorErrors;                // refused geometry, size, mapping or memory
    uint64_t fCursorScaled;                // destination size != source size (drawn 1:1)
    int32_t fLastCursorError;
    uint32_t fCursorLayer;
    uint32_t fCursorFormat;
    uint64_t fCursorSurfaceWidth, fCursorSurfaceHeight, fCursorSurfaceRowBytes;
    IOMFBSwapFields::Rect fCursorSrc, fCursorDst;
    uint64_t fScanoutLength;
    bool fConsoleDisabled;
    uint64_t fBlankCount;                  // swaps without a layer-0 surface
    uint64_t fCopyErrors;                  // refused geometry, format or mapping
    int32_t fLastCopyError;
    uint32_t fLastFormat;
    uint64_t fLastSurfaceWidth, fLastSurfaceHeight, fLastSurfaceRowBytes;

    IOTimerEventSource *fFrameTimer;       // 16 ms: completes the presented swap, starts the next
    bool fFrameTimerArmed;
    bool fSwapPresented;                   // fCurrentSwap was copied; complete at the next tick
    bool fAttributesPublished;
    IOMemoryDescriptor *fScanoutMD;        // physical GOP aperture from PE_Video
    IOMemoryMap *fScanoutMap;
    volatile uint8_t *fScanout;
    uint64_t fScanoutPhys;
    uint32_t fScanoutRowBytes;
    uint32_t fScanoutWidth;
    uint32_t fScanoutHeight;
    uint32_t fScanoutDepth;
    uint64_t fPresentCount;
    uint64_t fDropCount;
    // Layer-0 copy cost (docs/USERSPACE-GRAPHICS-20261019.md, "Speed batch"): copies timed, their total and
    // longest, in mach_absolute_time ticks; published in microseconds.
    uint64_t fCopyTimed;
    uint64_t fCopyTicks;
    uint64_t fCopyMaxTicks;
    uint64_t fCopyMaintTicks;              // the part of fCopyTicks spent in source-row cache maintenance
    // Present cost split (2026-10-20, AdrenoDisplayPresent.h): the one barrier after the maintenance pass, reading
    // the source rows into the stage, their signatures, and composing and writing the scanout; ticks.
    uint64_t fCopyBarrierTicks, fCopyReadTicks, fCopyHashTicks, fCopyWriteTicks;
    // Damage: source rows hashed, written to the scanout, skipped as unchanged, written only by the rolling refresh;
    // signature resets (start, stop, mode set, remap, width change) and copies that wrote every source row.
    uint64_t fCopyRowsCompared, fCopyRowsWritten, fCopyRowsSkipped, fCopyRowsRefreshed;
    uint64_t fCopyDamageResets, fCopyFullFrames, fCopyLastRowsWritten;
    uint32_t fLastCacheMode;               // layer-0 IOSurface::getCacheMode() (QuartzCore asks 0x400, write-combine)
    uint64_t fSourceAttr;                  // AT S1E1R on the source mapping: PAR_EL1.ATTR, or 0x100|FST on a fault
    uint64_t fScanoutAttr;                 // the same for the GOP mapping
    IOMFBSwapFields::Rect fLastSrc, fLastDst;   // layer 0's srcRect/destRect (not applied: 1:1 from the top-left)
    uint64_t fSwapDirtyFlagged;            // swaps with the IOMFB dirty-region flag (+0x228 bit 0): recorded, never used
    IOMFBSwapFields::Rect fSwapDirty;      // the last such rectangle (+0x1a1)
    struct adreno_display_damage fDamage;  // per scanout row: what layer 0 last put there
    uint64_t fStageBytes;                  // fPresentWorkspace.stage allocation
    // "AdrenoDisplay: perf " console line (perfLineGated): every kPerfEvery layer-0 copies, plus once for the first
    // cached-read conversion outcome. fPerfMark holds the cumulative counters at the previous line.
    static constexpr uint64_t kPerfEvery = 600;
    struct PerfMark {
        uint64_t copies, ticks, maint, barrier, read, hash, write, compared, written, skipped, refreshed;
    } fPerfMark;
    uint64_t fPerfMaxTicks;                // longest copy since the previous line
    bool fPerfConversionPending;           // the first conversion outcome is waiting for its line
#if ADRENO_PERF_FRAMES
    // Frame pacing (AdrenoDisplayPacing.h): this window's counters; the perf lines' sequence number; the last
    // arm, the time the head swap was first seen pending and that time for the swap being copied (mach ticks);
    // whether swap_begin_gated runs from a frame tick; the GPU-map counters at the previous line.
    struct adreno_pacing fPacing;
    uint64_t fPerfSeq;
    uint64_t fArmedAt, fPendingSince, fPresentQueuedAt;
    bool fInTick;
    uint64_t fMapMark[ADRENO_PERF_MAP_FIELDS];
#endif
#if ADRENO_PERF_GPU
    uint64_t fGpuMark[ADRENO_PERF_GPU_FIELDS];   // the perf gpu line's totals at the previous line
#endif
#if ADRENO_PERF_FRAMES && ADRENO_VA_RECLAIM
    uint64_t fVaMark[ADRENO_PERF_VA_FIELDS];     // the perf va line's totals at the previous line (agents/gpu-va G16)
#endif
#if ADRENO_VSYNC60
    // The frame-tick grid in mach abstime (AdrenoDisplayPacing.h adreno_vsync): computed by start_hardware, forgotten
    // by stop_hardware_gated and a mode set; the period and the slop the early arm absorbs, in ns.
    static constexpr uint64_t kVsyncPeriodNs = 16666667;
    static constexpr uint64_t kVsyncLeadMaxNs = 1000000;     // 26A428 kt coalescing cap (tcoal_prio_params_init)
    struct adreno_vsync fVsync;
#endif
#if ADRENO_PRESENT_SKIP_MAINT
    bool fPresentMaint;                    // boot-arg adreno_present_maint=1: keep the layer-0 maintenance pass
#endif
#if ADRENO_BEAM
    // The INTF_5 page (read-only Device mapping), its stage-1 attribute (A4), and the beam state.
    IOMemoryDescriptor *fBeamMD;
    IOMemoryMap *fBeamMap;
    const volatile uint32_t *fBeamRegs;
    uint64_t fBeamAttr;
    struct adreno_beam fBeam;
#endif
#if ADRENO_LATCH
    // The hold (AdrenoDisplayLatch.h): its release timer, the pending swap copied at the latch (H4: identity only, pointer
    // and swap ID, compared with the live queue head and never dereferenced otherwise), whether presentGated runs as that
    // copy, the R estimate and counters, and the boot-args read at start.
    IOTimerEventSource *fReleaseTimer;
    bool fReleaseArmed;
    bool fPrecopying;
    IOMFBSwapIORequest *fPrecopied;
    uint32_t fPrecopiedID;
    struct adreno_hold fHold;
    uint32_t fLatchSlackUs, fHoldMarginUs;
    uint64_t fGateTicks;                   // G1-G3: adreno_gate_us in mach ticks (0 = no gate)
#endif
#if ADRENO_PRESENT_SYNC
    // The present-sync gate (AdrenoDisplaySync.h): the waiting head's identity, the bound, this window's counters; the
    // kext's mark totals at the previous perf line; the forced-copy log count.
    struct adreno_sync_gate fSync;
    uint64_t fSyncMark[3];
    uint64_t fSyncForcedLogged;
#endif
#if ADRENO_PIPELINE
    uint64_t fPipeMark[ADRENO_PIPE_COUNTERS];   // AdrenoX2's pipeline totals at the previous perf line (O4)
#endif
#if ADRENO_PRESENT_RELATCH
    // The relatch (AdrenoDisplayRelatch.h): its timer on this work loop, the head the sync gate deferred in this tick
    // (identity only: pointer and swap ID, RL3), the state and counters, AdrenoX2's early-release totals at the previous
    // perf line, and the boot-arg switches read at start (for the line's on=).
    IOTimerEventSource *fRelatchTimer;
    bool fRelatchArmed;
    IOMFBSwapIORequest *fRelatchCandidate;
    uint32_t fRelatchCandidateID;
    struct adreno_relatch fRelatch;
    uint64_t fRelatchEarlyMark[ADRENO_RELATCH_EARLY_FIELDS];
#endif
#if ADRENO_PRESENT_CACHED_READ
    // Layer-0 sources converted to write-back by a kIOMapCopybackCache mapping (xnu converts the whole VM object,
    // FAILURES-AND-DESIGN.md 10.1) and proven global before use; counters for M1, M3, M4 and M7.
    uint64_t fCachedReadConversions;       // conversions proven global (both probes write-back)
    uint64_t fCachedReadFallbacks;         // copyback map refused, null, or not write-back (M3)
    uint64_t fCachedReadMismatch;          // copyback map write-back but the default map not: alias dropped (M1)
    uint64_t fCachedReadReverted;          // a cached slot later walked to non-write-back (M4)
    uint64_t fCachedReadAlready;           // already cacheable, nothing converted (M10)
    uint64_t fCachedReadAttr, fCachedReadProbeAttr;   // last probe 1 (copyback map) and probe 2 (default map)
    uint64_t fCachedReadConvertMaxTicks;   // longest conversion (M7)
    static constexpr uint32_t kRevertedSlots = 8;
    IOMemoryDescriptor *fCachedReadReverted_[kRevertedSlots];   // never converted again (M4); identity only
    uint32_t fCachedReadRevertedNext;
    bool fSourceCached;                    // the current present reads through a cached slot
#endif
    // Swap-info ring, same shape as AppleParavirtDisplay (+0x1dd8 head, +0x1ddc tail, 6 x 48 bytes).
    static constexpr uint32_t kSwapInfoRing = 6;
    uint32_t fSwapInfoHead;
    uint32_t fSwapInfoTail;
    IOMobileFramebufferLegacy::SwapInfoBlob fSwapInfo[kSwapInfoRing];
    OSArray *fColorElements;
    OSArray *fTimingElements;
};
