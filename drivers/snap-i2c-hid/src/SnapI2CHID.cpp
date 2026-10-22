/* SPDX-License-Identifier: MIT */
/*
 * IOKit glue for the A16 built-in keyboard and touchpad: one SnapI2CHIDBus per
 * guest device-tree node (compatible "snapintosh,geni-i2c-hid") drives the
 * node's GENI I2C serial engine through the stage-2 passthrough page in reg[0]
 * and publishes one SnapI2CHIDDevice (an IOHIDDevice) for the I2C-HID device
 * the node names. IOHIDFamily then builds IOHIDInterface and IOHIDEventDriver
 * on it as for any HID device. All bus traffic runs on the bus's own work
 * loop; the transport and state machine are the hardware-independent files
 * next to this one (geni-i2c.c, i2c-hid.c, hid-rdesc.c), which
 * tools/test-snap-i2c-hid.c exercises on the host.
 *
 * Node properties (all little-endian 32-bit cells unless noted):
 *   reg[0]                              GENI serial-engine page (>= 4 KiB)
 *   reg[1]                              optional read-only TLMM GPIO page
 *   snapintosh,hid-address              7-bit I2C address
 *   snapintosh,hid-descriptor-reg  HID descriptor register (ACPI/DT)
 *   snapintosh,hid-vendor-product       optional expected VID, PID
 *   snapintosh,bus-hz                   optional, default 400000
 *   snapintosh,poll-us                  optional, default 8000
 *   snapintosh,irq-policy               optional, 0 events / 1 masked (default 1)
 *   snapintosh,attention                optional: offset in reg[1], active-low flag
 *   snapintosh,hid-product              optional string
 */
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
/* The in-kernel IOHIDDevice is marked "Use DriverKit"; it is still what the
 * J700 kernel collection's IOHIDFamily 2.0.0 exports, and a dext would need
 * the DriverKit runtime this guest does not run yet. */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <IOKit/hid/IOHIDDevice.h>
#include <IOKit/hid/IOHIDDeviceKeys.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hidevent/IOHIDEventService.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <libkern/c++/OSData.h>

extern "C" {
#include "geni-i2c.h"
#include "i2c-hid.h"
#include "hid-keyboard.h"
#include "hid-pointer.h"
#include "hid-ptp.h"
#include "hid-mt2.h"
}

#define LOG_PREFIX "SnapI2CHID: "

/* agents/input-latency FAILURE-MODES.md T1-T9: -DSNAP_I2C_HID_LATENCY=1 schedules each RUNNING poll one period after
 * the previous one began, not after it ended. b12v6 measured 12.0-12.2 ms between 8 ms polls: the step's own transfer
 * and the timer's slop added about 4 ms. It also polls every SNAP_I2C_HID_ACTIVE_POLL_US while the device sent a report
 * in the last SNAP_I2C_HID_ACTIVE_HOLD_US (boot-arg snap_i2c_active_us; 0 = the configured period throughout), and
 * waits a transfer's wire time to the microsecond instead of rounding it up to whole milliseconds of IOSleep. Off by
 * default; without it this file compiles as before. */
#ifndef SNAP_I2C_HID_LATENCY
#define SNAP_I2C_HID_LATENCY 0
#endif
#if SNAP_I2C_HID_LATENCY
#include <pexpert/pexpert.h>
#ifndef SNAP_I2C_HID_ACTIVE_POLL_US
#define SNAP_I2C_HID_ACTIVE_POLL_US 4000u
#endif
#define SNAP_I2C_HID_ACTIVE_HOLD_US 500000u     /* T1: active for this long after a report */
#define SNAP_I2C_HID_MIN_POLL_US 2000u          /* T1: the floor of the active period */
#endif

/* The engine's scroll options are IOHIDEventService's dispatch options (26A428 header values). */
static_assert(HID_PTP_SCROLL_PHASE_BEGAN == kHIDDispatchOptionPhaseBegan &&
              HID_PTP_SCROLL_PHASE_CHANGED == kHIDDispatchOptionPhaseChanged &&
              HID_PTP_SCROLL_PHASE_ENDED == kHIDDispatchOptionPhaseEnded &&
              HID_PTP_SCROLL_MOMENTUM_START == kHIDDispatchOptionScrollMomentumStart &&
              HID_PTP_SCROLL_MOMENTUM_CONTINUE == kHIDDispatchOptionScrollMomentumContinue &&
              HID_PTP_SCROLL_MOMENTUM_END == kHIDDispatchOptionScrollMomentumEnd,
              "hid-ptp.h scroll options differ from kHIDDispatchOption*");

/* Feature reports for the Precision Touchpad switch. tools/test-snap-i2c-hid-start.cpp defines
 * these two to its model of the touchpad's features. */
#ifndef SNAP_I2C_HID_FEATURE_GET
#define SNAP_I2C_HID_FEATURE_GET(dev, id, buf, cap, got) \
    i2c_hid_get_report((dev), I2C_HID_TYPE_FEATURE, (id), (buf), (cap), (got))
#define SNAP_I2C_HID_FEATURE_SET(dev, report, len) i2c_hid_set_report((dev), I2C_HID_TYPE_FEATURE, (report), (len))
#endif

/* The latest non-modifier key-down, in microseconds of uptime, from any SnapI2CHIDKeyboard: the
 * touchpad takes no tap within HID_PTP_TYPING_US of it (failure mode F17). 0 = none yet. */
static uint64_t gSnapLastKeyDownUs;

static uint64_t uptimeUs(uint64_t abs)
{
    uint64_t ns;
    absolutetime_to_nanoseconds(abs, &ns);
    return ns / 1000u;
}

class SnapI2CHIDDevice;
class SnapI2CHIDKeyboard;
class SnapI2CHIDPointer;
class SnapI2CHIDMultitouch;

class SnapI2CHIDBus : public IOService {
    OSDeclareDefaultStructors(SnapI2CHIDBus)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;

    /* Called by SnapI2CHIDDevice, any thread. */
    IOReturn request(uint32_t kind, uint8_t type, uint8_t id, uint8_t *buf, uint32_t len,
                     uint32_t *got);
    const struct i2c_hid_dev *device() const { return fDev; }
    uint32_t location() const { return fLocation; }
    /* Any thread: an event driver (a kernel service, not a user client) opened or closed our
     * IOHIDDevice. The bus applies it on its next step (yieldToEventDriver). */
    void noteEventDriver(const void *client, const char *cls, bool open);
    OSString *copyProduct() const;

    enum { kRequestOutput = 1, kRequestSetReport = 2, kRequestGetReport = 3 };

private:
    static uint32_t ioRead32(void *ctx, uint32_t offset);
    static void ioWrite32(void *ctx, uint32_t offset, uint32_t value);
    static uint64_t ioNowUs(void *ctx);
    static void ioDelayUs(void *ctx, uint32_t us);
    static void deliver(void *ctx, const uint8_t *report, uint32_t len);
    friend class SnapI2CHIDKeyboard;
    friend class SnapI2CHIDPointer;
    friend class SnapI2CHIDMultitouch;
    static int attention(void *ctx);
    static void timerAction(OSObject *owner, IOTimerEventSource *sender);
    static IOReturn gatedStart(OSObject *owner, void *, void *, void *, void *);
    static IOReturn gatedStop(OSObject *owner, void *, void *, void *, void *);
    static IOReturn gatedRun(OSObject *owner, void *hid, void *mt, void *, void *);
    static IOReturn gatedRequest(OSObject *owner, void *req, void *, void *, void *);
    static IOReturn gatedPtp(OSObject *owner, void *setup, void *, void *, void *);
    static int ptpGet(void *ctx, uint8_t id, uint8_t *buf, uint32_t cap, uint32_t *got);
    static int ptpSet(void *ctx, const uint8_t *report, uint32_t len);
    static void publishCall(thread_call_param_t owner, thread_call_param_t);
    void publish();
    bool enablePrecisionTouchpad();
    void notePtpReinit();

    void step();
#if SNAP_I2C_HID_LATENCY
    void noteWake(uint64_t startUs);
    void armNextStep(uint32_t wake, uint64_t startUs, uint32_t reports);
#endif
    void noteState();
    void noteProgress();
    void noteServices();
    void yieldToEventDriver();
    uint32_t driverOpens() const;
    void noteMultitouch();
    bool multitouchWanted() const;
    SnapI2CHIDMultitouch *publishMultitouch();
    bool readU32(const char *key, uint32_t *out, uint32_t count = 1) const;
    void releaseAll();

    IOService *fProvider = nullptr;
    IOMemoryMap *fRegs = nullptr;
    IOMemoryMap *fGpio = nullptr;
    volatile uint32_t *fBase = nullptr;
    volatile uint32_t *fAttention = nullptr;
    uint32_t fAttentionActiveLow = 1;
    uint32_t fLocation = 0;
    uint32_t fBusHz = 400000;
    uint32_t fPolicy = GENI_I2C_IRQ_MASKED;
    IOWorkLoop *fWorkLoop = nullptr;
    IOTimerEventSource *fTimer = nullptr;
    IOCommandGate *fGate = nullptr;
    thread_call_t fPublish = nullptr;
    /* 1 from thread_call_enter until publishCall returns (or a cancel dequeued
     * it). thread_call_cancel_wait is private KPI, so stop() waits on this. */
    uint32_t fPublishing = 0;
    struct geni_i2c fBus;
    struct i2c_hid_config fCfg;
    struct i2c_hid_dev *fDev = nullptr;
    SnapI2CHIDDevice *fHID = nullptr;
    /* Our own keyboard event service (26A428's generic drivers are IOMatchDefer and none
     * attached in v40/v41): set on the work loop by gatedRun, used by deliver(). */
    SnapI2CHIDKeyboard *fKeyboard = nullptr;
    SnapI2CHIDKeyboard *fKeyboardStarted = nullptr;
    /* The touchpad's pointer, the same way: mouse mode (hid-pointer.c) and, once the device took
     * the switch at publish, Precision Touchpad mode (hid-ptp.c). */
    SnapI2CHIDPointer *fPointer = nullptr;
    SnapI2CHIDPointer *fPointerStarted = nullptr;
    struct hid_ptp_layout fPtp;
    bool fPtpArmed = false;
    bool fPtpReapply = false;            /* set by the pointer on report 1 while armed (F24) */
    uint32_t fPtpReinits = 0;            /* stats.reinits when the switch was last applied */
    uint8_t fPtpScratch[264];            /* the largest feature report it reads: the 257-byte blob */
    uint32_t fLastState = ~0u;
    uint64_t fStartUs = 0;
    uint32_t fNextStatsPoll = 125;      /* about 1 s of 8 ms polls, then 10 s, 60 s, every 10 min */
    uint32_t fLoggedReports = 0;
    uint64_t fRunningAtUs = 0;
    uint32_t fRegistryLogs = 0;         /* the HID stack above the device: at about 2 s and 30 s */
    /* Event drivers holding our IOHIDDevice open (handleOpen/handleClose, any thread; a client
     * opening twice is one entry), and whether step() last saw any: while one holds it, our own
     * services yield to it (Y1-Y5). */
    enum { kDriverSlots = 4 };
    uintptr_t fDriverClients[kDriverSlots] = {0, 0, 0, 0};
    uint32_t fDriverOpensApplied = 0;
    char fDriverName[48] = {0};
    bool fRawPublished = false;         /* the device's own IOHIDDevice (never for an armed touchpad) */
    /* The armed touchpad's Apple multitouch device (hid-mt2.c), set on the work loop by gatedRun,
     * and what the registry above it showed last (SnapI2CHIDMultitouch::kStack*). */
    SnapI2CHIDMultitouch *fMT = nullptr;
    uint32_t fMTStack = ~0u, fMTNextCheck = 0, fMTKicks = 0, fMTLastKick = 0;
    bool fStopping = false;
#if SNAP_I2C_HID_LATENCY
    /* T1-T3: the active period (0 = the configured one throughout), the current poll's deadline, the time the timer was
     * asked for and a decaying estimate of how late it fires, the last report, and the polls of each kind. */
    uint32_t fActiveUs = SNAP_I2C_HID_ACTIVE_POLL_US;
    uint64_t fDeadlineUs = 0, fArmedForUs = 0, fSlopUs = 0, fLastReportUs = 0;
    uint32_t fActivePolls = 0, fIdlePolls = 0;
#endif
};

class SnapI2CHIDDevice : public IOHIDDevice {
    OSDeclareDefaultStructors(SnapI2CHIDDevice)

public:
    bool initWithBus(SnapI2CHIDBus *bus);
    void free() override;
    bool handleStart(IOService *provider) override;
    IOReturn newReportDescriptor(IOMemoryDescriptor **descriptor) const override;
    OSString *newTransportString() const override;
    OSString *newProductString() const override;
    OSNumber *newVendorIDNumber() const override;
    OSNumber *newProductIDNumber() const override;
    OSNumber *newVersionNumber() const override;
    OSNumber *newLocationIDNumber() const override;
    OSNumber *newReportIntervalNumber() const override;
    using IOHIDDevice::getReport;
    using IOHIDDevice::setReport;
    IOReturn getReport(IOMemoryDescriptor *report, IOHIDReportType type,
                       IOOptionBits options) override;
    IOReturn setReport(IOMemoryDescriptor *report, IOHIDReportType type,
                       IOOptionBits options = 0) override;
    bool handleOpen(IOService *client, IOOptionBits options, void *argument) override;
    void handleClose(IOService *client, IOOptionBits options) override;
    void deliverReport(const uint8_t *report, uint32_t len);
    void logRegistry(const char *when);

private:
    void logRequest(const char *what, IOHIDReportType type, IOOptionBits options, IOByteCount len,
                    IOReturn result);

    SnapI2CHIDBus *fBus = nullptr;
    uint32_t fReportCalls = 0, fReportFailures = 0, fRequests = 0;
    OSData *fDescriptor = nullptr;
    OSString *fProduct = nullptr;
    IOBufferMemoryDescriptor *fReport = nullptr;
    uint16_t fVendor = 0, fProductID = 0, fVersion = 0;
    uint32_t fInterval = 0;
};

/* The armed touchpad as an Apple multitouch device (hid-mt2.h has the formats and their 26A428
 * sources): VendorID 0x05ac, ProductID 641, so Apple's own AppleMultitouchTrackpadHIDEventDriver
 * (J700 BootKC personality "Mac SPI MT - TopCase - 641", not deferred) matches its interface and
 * builds an AppleMultitouchDevice; its user-space clients (HSTouchHIDService, MultitouchSupport) then
 * make the pointer, scroll, clicks and every system gesture from the contact frames this device
 * sends. Input report 2 carries one frame per Precision Touchpad frame (from the pointer service's
 * engine hook) plus trailing frames on the bus tick; feature reports answer the driver's handshake
 * from memory and never touch the I2C device (M14). Our pointer service stays the fallback: it
 * hands the touchpad over only while a frames consumer is attached (M1, M6, M7). */
class SnapI2CHIDMultitouch : public IOHIDDevice {
    OSDeclareDefaultStructors(SnapI2CHIDMultitouch)

public:
    enum { kStackInterface = 1, kStackAppleDriver = 2, kStackOtherDriver = 4, kStackDevice = 8, kStackConsumer = 16 };

    bool initWithBus(SnapI2CHIDBus *bus, const struct hid_mt2 *geometry);
    void free() override;
    bool handleStart(IOService *provider) override;
    IOReturn newReportDescriptor(IOMemoryDescriptor **descriptor) const override;
    OSString *newTransportString() const override;
    OSString *newManufacturerString() const override;
    OSString *newProductString() const override;
    OSNumber *newVendorIDNumber() const override;
    OSNumber *newProductIDNumber() const override;
    OSNumber *newVersionNumber() const override;
    OSNumber *newLocationIDNumber() const override;
    OSNumber *newReportIntervalNumber() const override;
    using IOHIDDevice::getReport;
    using IOHIDDevice::setReport;
    IOReturn getReport(IOMemoryDescriptor *report, IOHIDReportType type, IOOptionBits options) override;
    IOReturn setReport(IOMemoryDescriptor *report, IOHIDReportType type, IOOptionBits options = 0) override;
    /* Bus work loop. */
    void frame(const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons, uint32_t scan, int has_scan);
    void tick();
    void reset();
    void kick();
    uint32_t stack() const;             /* kStack* bits: the registry above this device */

private:
    void send(uint32_t len);
    void noteFrames();
    void logRequest(const char *what, IOHIDReportType type, uint8_t id, uint32_t len, IOReturn result);

    SnapI2CHIDBus *fBus = nullptr;
    struct hid_mt2 fMT;
    IOBufferMemoryDescriptor *fReport = nullptr;
    uint8_t fBuf[HID_MT2_MAX_REPORT];
    uint8_t fQuery = 0;                 /* report 1's pending query (set, then get) */
    uint32_t fSent = 0, fFailures = 0, fRequests = 0, fNextLog = 1;
};

/* The keyboard as an IOHIDEventService the HID event system consumes directly: report 54
 * becomes keyboard-page transitions and report 55 consumer-page ones (src/hid-keyboard.c),
 * dispatched with dispatchKeyboardEvent; the Caps Lock LED comes back as output report 54.
 * It is attached to the bus and started by it, not matched, so no deferred personality or
 * DriverKit server is involved. Key usages are never logged; only counts. */
class SnapI2CHIDKeyboard : public IOHIDEventService {
    OSDeclareDefaultStructors(SnapI2CHIDKeyboard)

public:
    bool initWithBus(SnapI2CHIDBus *bus);
    void free() override;
    IOWorkLoop *getWorkLoop() const override;
    void handleReport(const uint8_t *report, uint32_t len);   /* bus work loop */
    void releaseKeys();                                        /* bus work loop */
    void suppress(const char *why);                            /* bus work loop */
    void resume();                                             /* bus work loop */
    const char *state() const { return fSuppressed ? "yielded" : "dispatching"; }

protected:
    bool handleStart(IOService *provider) override;
    OSString *getTransport() override;
    UInt32 getLocationID() override;
    UInt32 getVendorID() override;
    UInt32 getProductID() override;
    UInt32 getVersion() override;
    UInt32 getCountryCode() override;
    OSString *getManufacturer() override;
    OSString *getProduct() override;
    UInt32 getReportInterval() override;
    UInt32 getPrimaryUsagePage() override;
    UInt32 getPrimaryUsage() override;
    IOReturn setElementValue(UInt32 usagePage, UInt32 usage, UInt32 value) override;

private:
    static void emit(void *ctx, uint32_t page, uint32_t usage, uint32_t down);

    SnapI2CHIDBus *fBus = nullptr;
    OSString *fProductName = nullptr;
    struct hid_kbd_state fState;
    uint64_t fNow = 0;
    uint32_t fReports = 0, fTransitions = 0, fNextLog = 1, fLeds = 0, fLedRequests = 0;
    uint32_t fYieldedReports = 0, fNextYieldLog = 1;
    bool fSuppressed = false;
};

/* The touchpad as an IOHIDEventService. In its default mouse mode the mouse collection's input
 * report (layout from the device's report descriptor, hid-pointer.c) becomes
 * dispatchRelativePointerEvent and dispatchScrollWheelEvent. When the bus switched the device to
 * Precision Touchpad mode, the multi-contact report goes through hid-ptp.c's engine instead:
 * dispatchRelativePointerEventWithFixed for one finger, clicks and taps, and phased
 * dispatchScrollWheelEventWithFixed (with momentum on the bus tick) for two; the service then
 * also carries the trackpad scroll identity (HIDScrollAccelerationType and the rest, section 4.4
 * of docs/A16-INPUT-PTP-20261020.md). Report 1 keeps today's path in both modes. Started by the
 * bus like the keyboard service; counts only in the log. */
class SnapI2CHIDPointer : public IOHIDEventService {
    OSDeclareDefaultStructors(SnapI2CHIDPointer)

public:
    bool initWithBus(SnapI2CHIDBus *bus, const struct hid_pointer_layout *layout,
                     const struct hid_ptp_layout *ptp = nullptr);
    void free() override;
    IOWorkLoop *getWorkLoop() const override;
    void handleReport(const uint8_t *report, uint32_t len);   /* bus work loop */
    void tick();                                               /* bus work loop, every poll */
    void resetTouch();                                         /* bus work loop */
    void releaseButtons();                                     /* bus work loop */
    void suppress(const char *why);                            /* bus work loop */
    void resume();                                             /* bus work loop */
    void handover(bool on);                                    /* bus work loop */
    const char *state() const
    {
        return fSuppressed ? "yielded" : fHandover ? "handed over to the multitouch stack" : "dispatching";
    }

protected:
    bool handleStart(IOService *provider) override;
    OSString *getTransport() override;
    UInt32 getLocationID() override;
    UInt32 getVendorID() override;
    UInt32 getProductID() override;
    UInt32 getVersion() override;
    UInt32 getCountryCode() override;
    OSString *getManufacturer() override;
    OSString *getProduct() override;
    UInt32 getReportInterval() override;
    UInt32 getPrimaryUsagePage() override;
    UInt32 getPrimaryUsage() override;

private:
    static void move(void *ctx, int32_t dx, int32_t dy, uint32_t buttons);
    static void scroll(void *ctx, int32_t vertical, int32_t horizontal);
    static void ptpPointer(void *ctx, int32_t dx, int32_t dy, uint32_t buttons);
    static void ptpScroll(void *ctx, int32_t vertical, int32_t horizontal, uint32_t options);
    static void ptpFrame(void *ctx, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons,
                         uint32_t scan, int has_scan);
    void noteEvent();
    void notePtp(int result);

    SnapI2CHIDBus *fBus = nullptr;
    OSString *fProductName = nullptr;
    struct hid_pointer_layout fLayout;
    struct hid_pointer_state fState;
    bool fHaveMouse = false, fPtpArmed = false;
    struct hid_ptp_engine fEngine;
    struct hid_ptp_sink fSink;
    uint64_t fNow = 0;
    uint32_t fReports = 0, fMoves = 0, fScrolls = 0, fNextLog = 1;
    uint32_t fMouseWhileArmed = 0, fNextPtpLog = 1;
    uint32_t fLoggedFrames = 0;                  /* the first frames' contacts, logged (D2) */
    uint32_t fYieldedReports = 0, fYieldedPtp = 0, fNextYieldLog = 1;
    uint32_t fHandedOver = 0;                    /* engine events not dispatched while handed over */
    bool fSuppressed = false, fHandover = false;
};

OSDefineMetaClassAndStructors(SnapI2CHIDBus, IOService)
OSDefineMetaClassAndStructors(SnapI2CHIDDevice, IOHIDDevice)
OSDefineMetaClassAndStructors(SnapI2CHIDMultitouch, IOHIDDevice)
OSDefineMetaClassAndStructors(SnapI2CHIDKeyboard, IOHIDEventService)
OSDefineMetaClassAndStructors(SnapI2CHIDPointer, IOHIDEventService)

/* --------------------------------------------------------------- bus ---- */

struct SnapRequest {
    uint32_t kind;
    uint8_t type, id;
    uint8_t *buf;
    uint32_t len, *got;
    int result;
};

/* The only MMIO in this file. tools/test-snap-i2c-hid-start.cpp defines these
 * two to its controller model; the kext uses the plain volatile accesses. */
#ifndef SNAP_I2C_HID_MMIO_READ
#define SNAP_I2C_HID_MMIO_READ(base, offset) ((base)[(offset) / 4])
#define SNAP_I2C_HID_MMIO_WRITE(base, offset, value) ((base)[(offset) / 4] = (value))
#endif

uint32_t SnapI2CHIDBus::ioRead32(void *ctx, uint32_t offset)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    return SNAP_I2C_HID_MMIO_READ(self->fBase, offset);
}

void SnapI2CHIDBus::ioWrite32(void *ctx, uint32_t offset, uint32_t value)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    SNAP_I2C_HID_MMIO_WRITE(self->fBase, offset, value);
}

uint64_t SnapI2CHIDBus::ioNowUs(void *)
{
    uint64_t abs, ns;
    clock_get_uptime(&abs);
    absolutetime_to_nanoseconds(abs, &ns);
    return ns / 1000u;
}

void SnapI2CHIDBus::ioDelayUs(void *, uint32_t us)
{
#if SNAP_I2C_HID_LATENCY
    /* T4: whole milliseconds asleep and the remainder the way the status polls already wait (IODelay below 1 ms):
     * a 52-byte input read waits 1 ms + 193 us, not 2 ms. */
    if (us >= 1000u)
        IOSleep(us / 1000u);
    if (us % 1000u)
        IODelay(us % 1000u);
#else
    /* Transfers wait their nominal wire time (about 1.5 ms for a 64-byte
     * input read): sleep for whole milliseconds, spin only below that. */
    if (us >= 1000u)
        IOSleep((us + 999u) / 1000u);
    else
        IODelay(us);
#endif
}

int SnapI2CHIDBus::attention(void *ctx)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    uint32_t level = *self->fAttention & 1u;     /* TLMM GPIO_IN_OUT bit 0: input */
    return self->fAttentionActiveLow ? level == 0u : level == 1u;
}

void SnapI2CHIDBus::deliver(void *ctx, const uint8_t *report, uint32_t len)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    if (self->fKeyboard)
        self->fKeyboard->handleReport(report, len);
    if (self->fPointer)
        self->fPointer->handleReport(report, len);
    if (self->fHID)
        self->fHID->deliverReport(report, len);
}

bool SnapI2CHIDBus::readU32(const char *key, uint32_t *out, uint32_t count) const
{
    OSData *data = OSDynamicCast(OSData, fProvider->getProperty(key));
    if (!data || data->getLength() != count * sizeof(uint32_t))
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(data->getBytesNoCopy());
    for (uint32_t i = 0; i < count; i++)
        out[i] = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8 |
                 (uint32_t)p[4 * i + 2] << 16 | (uint32_t)p[4 * i + 3] << 24;
    return true;
}

OSString *SnapI2CHIDBus::copyProduct() const
{
    OSData *data = OSDynamicCast(OSData, fProvider->getProperty("snapintosh,hid-product"));
    if (data && data->getLength() > 1 && data->getLength() < 64) {
        char name[64];
        bcopy(data->getBytesNoCopy(), name, data->getLength());
        name[data->getLength() - 1] = 0;
        return OSString::withCString(name);
    }
    return OSString::withCString("I2C HID Device");
}

bool SnapI2CHIDBus::start(IOService *provider)
{
    uint32_t address = 0, descReg = 0, vidpid[2] = {0, 0}, att[2], poll = 8000;

    if (!IOService::start(provider))
        return false;
    fProvider = provider;
    if (!readU32("snapintosh,hid-address", &address) || address > 0x7f ||
        !readU32("snapintosh,hid-descriptor-reg", &descReg) || descReg > 0xffff) {
        IOLog(LOG_PREFIX "node lacks hid-address/hid-descriptor-register\n");
        goto fail;
    }
    (void)readU32("snapintosh,hid-vendor-product", vidpid, 2);
    (void)readU32("snapintosh,bus-hz", &fBusHz);
    (void)readU32("snapintosh,poll-us", &poll);
    (void)readU32("snapintosh,irq-policy", &fPolicy);

    /* reg[0] is the one 4 KiB page the monitor maps (compat/i2c-input.h); a
     * missing, short or unaligned window means the loader and monitor did not
     * provide it, and nothing here touches the bus. */
    fRegs = provider->mapDeviceMemoryWithIndex(0);
    if (!fRegs || fRegs->getLength() < GENI_WINDOW_BYTES ||
        (fRegs->getPhysicalAddress() & (GENI_WINDOW_BYTES - 1))) {
        IOLog(LOG_PREFIX "cannot map the serial-engine page\n");
        goto fail;
    }
    fBase = reinterpret_cast<volatile uint32_t *>(fRegs->getVirtualAddress());
    fLocation = (uint32_t)(fRegs->getPhysicalAddress() & 0xffffff00u) | address;
    if (readU32("snapintosh,attention", att, 2)) {
        fGpio = provider->mapDeviceMemoryWithIndex(1);
        if (fGpio && !(att[0] & 3u) && att[0] + 4u <= fGpio->getLength()) {
            fAttention = reinterpret_cast<volatile uint32_t *>(fGpio->getVirtualAddress() + att[0]);
            fAttentionActiveLow = att[1] != 0;
        } else {
            IOLog(LOG_PREFIX "attention property without a usable reg[1]; polling the bus\n");
        }
    }

    fDev = static_cast<struct i2c_hid_dev *>(IOMallocZero(sizeof(*fDev)));
    fWorkLoop = IOWorkLoop::workLoop();
    fGate = IOCommandGate::commandGate(this);
    fTimer = IOTimerEventSource::timerEventSource(this, timerAction);
    fPublish = thread_call_allocate(publishCall, this);
    if (!fDev || !fWorkLoop || !fGate || !fTimer || !fPublish ||
        fWorkLoop->addEventSource(fGate) != kIOReturnSuccess ||
        fWorkLoop->addEventSource(fTimer) != kIOReturnSuccess)
        goto fail;

    i2c_hid_default_config(&fCfg, (uint8_t)address, (uint16_t)descReg);
    fCfg.expect_vendor = (uint16_t)vidpid[0];
    fCfg.expect_product = (uint16_t)vidpid[1];
    if (poll >= 1000u && poll <= 100000u)
        fCfg.poll_us = poll;
#if SNAP_I2C_HID_LATENCY
    {   /* T1: snap_i2c_active_us=0 keeps the configured period throughout; anything else at least 2 ms */
        uint32_t active = SNAP_I2C_HID_ACTIVE_POLL_US;
        (void)PE_parse_boot_argn("snap_i2c_active_us", &active, sizeof(active));
        if (active && active < SNAP_I2C_HID_MIN_POLL_US)
            active = SNAP_I2C_HID_MIN_POLL_US;
        fActiveUs = active;
    }
#endif
    fStartUs = ioNowUs(this);
    if (fGate->runAction(gatedStart) != kIOReturnSuccess)
        goto fail;
    registerService();
    fTimer->setTimeoutUS(1);
    return true;
fail:
    releaseAll();
    IOService::stop(provider);
    return false;
}

IOReturn SnapI2CHIDBus::gatedStart(OSObject *owner, void *, void *, void *, void *)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    const struct geni_i2c_io io = {self, ioRead32, ioWrite32, ioNowUs, ioDelayUs};
    int r = geni_i2c_start(&self->fBus, &io, self->fBusHz, self->fPolicy);
    const struct geni_i2c *b = &self->fBus;
    if (r != GENI_I2C_OK) {
        /* The registers as found, before any write (geni-i2c.h); no further MMIO. */
        IOLog(LOG_PREFIX "controller refused (%s): status 0x%x irq 0x%x irq-en 0x%x tx 0x%x rx 0x%x, "
              "recovered %u words\n", geni_i2c_result_name(r), b->found_status, b->found_irq,
              b->found_irq_en, b->found_tx_fifo, b->found_rx_fifo, b->stats.recovered_words);
        return kIOReturnNotReady;
    }
    if (b->recovered)
        IOLog(LOG_PREFIX "recovered a previous run's controller state: status 0x%x irq 0x%x irq-en 0x%x "
              "tx 0x%x rx 0x%x; discarded %u words, %u cancels, %u aborts\n", b->found_status,
              b->found_irq, b->found_irq_en, b->found_tx_fifo, b->found_rx_fifo,
              b->stats.recovered_words, b->stats.cancels, b->stats.aborts);
    if (i2c_hid_begin(self->fDev, &self->fBus, &self->fCfg, deliver, self) != I2C_HID_R_OK) {
        (void)geni_i2c_stop(&self->fBus);
        return kIOReturnBadArgument;
    }
    if (self->fAttention)
        i2c_hid_set_attention(self->fDev, attention, self);
    IOLog(LOG_PREFIX "addr 0x%02x clock 0x%x scl 0x%x fifo %u/%u policy %u%s\n",
          self->fCfg.address, self->fBus.clock_cfg, self->fBus.scl_counters,
          self->fBus.tx_fifo_words, self->fBus.rx_fifo_words, self->fPolicy,
          self->fAttention ? " attention" : "");
    return kIOReturnSuccess;
}

void SnapI2CHIDBus::timerAction(OSObject *owner, IOTimerEventSource *)
{
    static_cast<SnapI2CHIDBus *>(owner)->step();
}

void SnapI2CHIDBus::step()
{
    uint32_t wake;
    if (fStopping || !fDev)
        return;
#if SNAP_I2C_HID_LATENCY
    const uint64_t startUs = ioNowUs(this);
    const uint32_t reports = fDev->stats.reports;
    noteWake(startUs);
#endif
    wake = i2c_hid_step(fDev);
    noteState();
    noteProgress();
    notePtpReinit();
    yieldToEventDriver();
    if (fPointer)
        fPointer->tick();                   /* tap release, the lift window, momentum */
    if (fMT)
        fMT->tick();                        /* lifted contacts' last stages, the empty frame (M8) */
    if (fDev->state == I2C_HID_S_READY && !fHID) {
        /* IOHIDDevice::start may call back into this driver; run it outside
         * the work loop, then resume polling through gatedRun. The callout
         * holds a reference until it returns. */
        if (!__atomic_load_n(&fPublishing, __ATOMIC_ACQUIRE)) {
            __atomic_store_n(&fPublishing, 1u, __ATOMIC_RELEASE);
            retain();
            if (thread_call_enter(fPublish))
                release();                  /* already queued: keep one reference */
        }
        return;
    }
    if (wake != I2C_HID_NO_WAKE)
#if SNAP_I2C_HID_LATENCY
        armNextStep(wake, startUs, reports);
#else
        fTimer->setTimeoutUS(wake ? wake : 1);
#endif
}

#if SNAP_I2C_HID_LATENCY
/* T3: how late the timer fired against the time asked for, as a decaying estimate (each sample capped at 2 ms). */
void SnapI2CHIDBus::noteWake(uint64_t startUs)
{
    if (!fArmedForUs)
        return;
    const uint64_t late = startUs > fArmedForUs ? startUs - fArmedForUs : 0;
    fSlopUs = (fSlopUs * 7u + (late < 2000u ? late : 2000u)) / 8u;
    fArmedForUs = 0;
}

/* T1-T3: in RUNNING, the next poll is due one period after this one's deadline (or its start, after a late one). The
 * period is the active one while a report came in the last SNAP_I2C_HID_ACTIVE_HOLD_US, the configured one otherwise.
 * The poll comes at least a quarter period (1 ms minimum) after this step's end. The timer is asked early by the
 * measured lateness, at most min(1 ms, period / 8). Any other state or wake keeps today's relative delay. */
void SnapI2CHIDBus::armNextStep(uint32_t wake, uint64_t startUs, uint32_t reports)
{
    if (fDev->state != I2C_HID_S_RUNNING || wake != fCfg.poll_us || !fActiveUs) {
        fDeadlineUs = 0;
        fTimer->setTimeoutUS(wake ? wake : 1);
        return;
    }
    const uint64_t now = ioNowUs(this);
    if (fDev->stats.reports != reports)
        fLastReportUs = now ? now : 1;
    uint32_t period = fCfg.poll_us;
    if (fLastReportUs && now - fLastReportUs < SNAP_I2C_HID_ACTIVE_HOLD_US && fActiveUs < period) {
        period = fActiveUs;
        fActivePolls++;
    } else {
        fIdlePolls++;
    }
    uint64_t base = fDeadlineUs ? fDeadlineUs : startUs;
    if (base + period <= startUs)
        base = startUs;                                    /* far behind: re-anchor, no burst of catch-up polls */
    uint64_t next = base + period;
    const uint64_t gap = period / 4u > 1000u ? period / 4u : 1000u;
    if (next < now + gap)
        next = now + gap;                                  /* T2 */
    fDeadlineUs = next;
    uint64_t lead = fSlopUs;
    const uint64_t cap = period / 8u < 1000u ? period / 8u : 1000u;
    if (lead > cap)
        lead = cap;                                        /* T3 */
    uint64_t delay = next - now;
    delay = delay > lead ? delay - lead : 1;
    fArmedForUs = now + delay;
    fTimer->setTimeoutUS((uint32_t)delay);
}
#endif

/* One line per state change (about eight in a healthy start), so a stopped
 * guest's console shows how far initialisation got without anyone at the
 * keyboard: the reset acknowledgment's length prefix (00 00 expected), then
 * READY and RUNNING. */
void SnapI2CHIDBus::noteState()
{
    uint32_t previous = fLastState;
    if (fDev->state == fLastState)
        return;
    fLastState = fDev->state;
    IOLog(LOG_PREFIX "addr 0x%02x %s -> %s at %llu ms\n", fCfg.address,
          previous == ~0u ? "start" : i2c_hid_state_name(previous), i2c_hid_state_name(fDev->state),
          (ioNowUs(this) - fStartUs) / 1000u);
    if (previous == I2C_HID_S_RESET_WAIT && fDev->state != I2C_HID_S_FAILED)
        IOLog(LOG_PREFIX "addr 0x%02x reset acknowledged: length prefix %02x %02x after %llu ms, "
              "%u NACK retries, %u early reports, %u bad lengths\n", fCfg.address,
              fDev->inbuf[0], fDev->inbuf[1], (ioNowUs(this) - fDev->reset_at_us) / 1000u,
              fDev->stats.reset_retries, fDev->stats.early_reports, fDev->stats.bad_length);
    if (fDev->state == I2C_HID_S_FAILED)
        IOLog(LOG_PREFIX "addr 0x%02x FAILED in %s: %s (bus %s, status 0x%x tx 0x%x rx 0x%x)\n",
              fCfg.address, i2c_hid_state_name(fDev->failed_in),
              i2c_hid_failure_name(fDev->failure), geni_i2c_result_name(fDev->last_result),
              fBus.last_status, fBus.last_tx_fifo, fBus.last_rx_fifo);
    else if (fDev->state == I2C_HID_S_READY || fDev->state == I2C_HID_S_RUNNING)
        IOLog(LOG_PREFIX "addr 0x%02x %s: %04x:%04x report descriptor %u bytes, input %u "
              "(%u declared input reports longer)\n",
              fCfg.address, i2c_hid_state_name(fDev->state), fDev->desc.vendor_id,
              fDev->desc.product_id, fDev->rdesc_len, fDev->desc.max_input, fDev->stats.oversize_inputs);
}

/* Progress without a person: polling counters at about 1 s, 10 s and 60 s of
 * RUNNING and then every 10 minutes, and the first few input reports by ID and
 * size only, never their contents. */
void SnapI2CHIDBus::noteProgress()
{
    const struct i2c_hid_stats *s = &fDev->stats;
    if (fDev->state != I2C_HID_S_RUNNING)
        return;
    if (!fRunningAtUs)
        fRunningAtUs = ioNowUs(this);
    noteMultitouch();
    if (fHID && fRegistryLogs < 2) {
        uint64_t at = fRegistryLogs ? 30000000u : 2000000u;
        if (ioNowUs(this) - fRunningAtUs >= at) {
            fHID->logRegistry(fRegistryLogs ? "30 s" : "2 s");
            fRegistryLogs++;
        }
    }
    if (s->reports > fLoggedReports && fLoggedReports < 4) {
        fLoggedReports = s->reports;
        IOLog(LOG_PREFIX "addr 0x%02x input report %u: id %u, %u bytes\n", fCfg.address, s->reports,
              fDev->last_report_len ? fDev->last_report[0] : 0u, fDev->last_report_len);
    }
    if (s->polls < fNextStatsPoll)
        return;
    IOLog(LOG_PREFIX "addr 0x%02x polls %u: empty %u reports %u bogus %u identical %u rejected %u "
          "errors %u nacks %u reinits %u; bus ok %u timeouts %u cancels %u aborts %u\n",
          fCfg.address, s->polls, s->empty, s->reports, s->bogus, s->identical,
          s->bad_length + s->unknown_id + s->wrong_size, s->transfer_errors, s->nacks, s->reinits,
          fBus.stats.ok, fBus.stats.timeouts, fBus.stats.cancels, fBus.stats.aborts);
#if SNAP_I2C_HID_LATENCY
    IOLog(LOG_PREFIX "addr 0x%02x latency: active %u us, %u active and %u idle polls, timer slop %llu us\n",
          fCfg.address, fActiveUs, fActivePolls, fIdlePolls, fSlopUs);
#endif
    noteServices();
    fNextStatsPoll = fNextStatsPoll < 1250u ? 1250u : fNextStatsPoll < 7500u ? 7500u
                   : fNextStatsPoll + 75000u;
}

/* D1: with every polls line (so a console tail has it), who turns this device's reports into
 * events: our services (dispatching or yielded), whether the device's own IOHIDDevice exists, and
 * which event driver holds it open. */
void SnapI2CHIDBus::noteServices()
{
    IOLog(LOG_PREFIX "addr 0x%02x services: keyboard %s, pointer %s%s; raw HID device %s; event drivers open %u%s%s; "
          "multitouch device %s, stack 0x%x\n",
          fCfg.address, fKeyboard ? fKeyboard->state() : "none", fPointer ? fPointer->state() : "none",
          fPointer ? (fPtpArmed ? " (precision touchpad)" : " (mouse mode)") : "",
          fRawPublished ? "published" : "not published", driverOpens(),
          fDriverName[0] ? " last " : "", fDriverName, fMT ? "published" : "none", fMT ? fMTStack : 0u);
}

/* Y1-Y5: an event driver that opened our IOHIDDevice (DriverKit's AppleUserHIDEventService once
 * its server runs, or any kernel HID event driver) dispatches the device's reports itself: our own
 * services yield while it holds the device open and resume when it closes it (its dext exited),
 * so keys are never doubled and never lost. An armed touchpad has no IOHIDDevice (Y2): nothing
 * can take it from our pointer, which no generic driver can replace. Called from handleOpen and
 * handleClose (any thread); yieldToEventDriver applies it on the work loop (step). */
void SnapI2CHIDBus::noteEventDriver(const void *client, const char *cls, bool open)
{
    uintptr_t key = reinterpret_cast<uintptr_t>(client);
    for (uint32_t i = 0; i < kDriverSlots; i++) {
        uintptr_t expected = key;
        if (__atomic_load_n(&fDriverClients[i], __ATOMIC_ACQUIRE) != key)
            continue;
        if (!open)
            __atomic_compare_exchange_n(&fDriverClients[i], &expected, (uintptr_t)0, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE);
        return;                                          /* already held (open twice) or now released */
    }
    if (!open)
        return;
    for (uint32_t i = 0; i < kDriverSlots; i++) {
        uintptr_t expected = 0;
        if (__atomic_compare_exchange_n(&fDriverClients[i], &expected, key, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
            break;
    }
    unsigned n = 0;
    for (; cls && cls[n] && n + 1 < sizeof(fDriverName); n++)
        fDriverName[n] = cls[n];
    fDriverName[n] = 0;
}

uint32_t SnapI2CHIDBus::driverOpens() const
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < kDriverSlots; i++)
        n += __atomic_load_n(&fDriverClients[i], __ATOMIC_ACQUIRE) != 0;
    return n;
}

void SnapI2CHIDBus::yieldToEventDriver()
{
    uint32_t opens = driverOpens();
    if ((opens != 0) == (fDriverOpensApplied != 0)) {
        fDriverOpensApplied = opens;
        return;
    }
    fDriverOpensApplied = opens;
    if (opens) {
        if (fKeyboard)
            fKeyboard->suppress(fDriverName);
        if (fPointer)
            fPointer->suppress(fDriverName);
    } else {
        IOLog(LOG_PREFIX "addr 0x%02x: %s closed the HID device; our services dispatch again\n", fCfg.address,
              fDriverName[0] ? fDriverName : "the event driver");
        if (fKeyboard)
            fKeyboard->resume();
        if (fPointer)
            fPointer->resume();
    }
    noteServices();
}

int SnapI2CHIDBus::ptpGet(void *ctx, uint8_t id, uint8_t *buf, uint32_t cap, uint32_t *got)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    return SNAP_I2C_HID_FEATURE_GET(self->fDev, id, buf, cap, got) != I2C_HID_R_OK;
}

int SnapI2CHIDBus::ptpSet(void *ctx, const uint8_t *report, uint32_t len)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(ctx);
    return SNAP_I2C_HID_FEATURE_SET(self->fDev, report, len) != I2C_HID_R_OK;
}

/* The mode switch of hid-ptp.c (blob, capabilities, Input Mode 3, Surface/Button Switch,
 * readback) as one gated sequence: no poll runs between its transfers. */
IOReturn SnapI2CHIDBus::gatedPtp(OSObject *owner, void *setup, void *, void *, void *)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    const struct hid_ptp_io io = {self, ptpGet, ptpSet};
    hid_ptp_enable(&self->fPtp, &io, self->fPtpScratch, sizeof(self->fPtpScratch),
                   static_cast<struct hid_ptp_setup *>(setup));
    self->noteState();
    return kIOReturnSuccess;
}

/* At publish (READY, before polling): whether the device is a Precision Touchpad that took the
 * switch. Every outcome is logged; anything but a written mode leaves today's mouse mode (F1, F2,
 * F14, F16). The keyboard's descriptor has no Touch Pad collection: nothing is sent (F15). */
bool SnapI2CHIDBus::enablePrecisionTouchpad()
{
    struct hid_ptp_setup setup;
    char contacts[8], pad[8], blob[24], before[8];
    int lr = hid_ptp_layout(fDev->rdesc, fDev->rdesc_len, &fPtp);
    if (lr == HID_PTP_NO_TOUCHPAD)
        return false;
    if (lr != HID_PTP_OK) {
        IOLog(LOG_PREFIX "addr 0x%02x: precision touchpad not enabled (%s): mouse mode\n", fCfg.address,
              hid_ptp_layout_name(lr));
        return false;
    }
    fGate->runAction(gatedPtp, &setup);
    fPtpReinits = fDev->stats.reinits;
    fPtpArmed = setup.result == HID_PTP_ENABLED || setup.result == HID_PTP_ENABLED_UNVERIFIED;
    if (!fPtpArmed) {
        if (setup.result == HID_PTP_REFUSED_READBACK)
            IOLog(LOG_PREFIX "addr 0x%02x: precision touchpad not enabled (refused: readback %u): mouse mode\n",
                  fCfg.address, setup.mode_after);
        else
            IOLog(LOG_PREFIX "addr 0x%02x: precision touchpad not enabled (%s): mouse mode\n", fCfg.address,
                  hid_ptp_enable_name(setup.result));
        return false;
    }
    snprintf(contacts, sizeof(contacts), setup.caps_read ? "%u" : "?", setup.max_contacts);
    snprintf(pad, sizeof(pad), setup.caps_read ? "%u" : "?", setup.pad_type);
    snprintf(blob, sizeof(blob), setup.blob_read ? "%u bytes" : "not read", setup.blob_bytes);
    snprintf(before, sizeof(before), setup.mode_before_read ? "%u" : "?", setup.mode_before);
    IOLog(LOG_PREFIX "precision touchpad %s: report %u (%u bytes), fingers %u, confidence %s, contact count %s, "
          "scan time %s, buttons %u, %u.%u x %u.%u mm; contacts max %s, pad type %s; blob %s; input mode %s -> 3; "
          "surface and button switch %s\n", hid_ptp_enable_name(setup.result), fPtp.report_id, fPtp.report_bytes,
          fPtp.fingers, fPtp.has_confidence ? "yes" : "no", fPtp.contact_count.size ? "yes" : "no",
          fPtp.scan_time.size ? "yes" : "no", fPtp.buttons, fPtp.width_um / 1000u, fPtp.width_um % 1000u / 100u,
          fPtp.height_um / 1000u, fPtp.height_um % 1000u / 100u, contacts, pad, blob, before,
          setup.selective_written ? "on" : "not written");
    return true;
}

/* F10: a re-initialisation RESETs the device, which returns it to mouse mode; F24: so does a reset
 * the device did by itself, seen as report 1 while armed (the pointer asks, bounded). Once
 * RUNNING, apply the switch again and end whatever touch was in progress. Work loop (step). */
void SnapI2CHIDBus::notePtpReinit()
{
    struct hid_ptp_setup setup;
    bool reinit;
    if (!fPtpArmed || fDev->state != I2C_HID_S_RUNNING)
        return;
    reinit = fDev->stats.reinits != fPtpReinits;
    if (!reinit && !fPtpReapply)
        return;
    fPtpReinits = fDev->stats.reinits;
    fPtpReapply = false;
    gatedPtp(this, &setup, nullptr, nullptr, nullptr);       /* already on the work loop */
    if (reinit)
        IOLog(LOG_PREFIX "addr 0x%02x: precision touchpad re-applied after re-initialisation %u: %s\n",
              fCfg.address, fPtpReinits, hid_ptp_enable_name(setup.result));
    else
        IOLog(LOG_PREFIX "addr 0x%02x: precision touchpad re-applied after mouse-mode reports: %s\n", fCfg.address,
              hid_ptp_enable_name(setup.result));
    if (fPointer)
        fPointer->resetTouch();
    if (fMT)
        fMT->reset();                       /* M15: open touches end on the next ticks */
}

/* Multitouch emulation for an armed touchpad: on unless the node says snapintosh,multitouch = 0. */
bool SnapI2CHIDBus::multitouchWanted() const
{
    uint32_t on = 1;
    (void)readU32("snapintosh,multitouch", &on);
    return on != 0;
}

/* At publish, after the switch held (publish's thread): the Apple multitouch device, or nothing
 * (M12: a pad hid-mt2.c cannot describe; the node turned it off; IOHIDDevice start failed). Every
 * outcome is logged; without it the pointer service is the touchpad's only event service. */
SnapI2CHIDMultitouch *SnapI2CHIDBus::publishMultitouch()
{
    struct hid_mt2 geometry;
    SnapI2CHIDMultitouch *mt;
    int r;
    if (!multitouchWanted()) {
        IOLog(LOG_PREFIX "addr 0x%02x: multitouch device off (snapintosh,multitouch = 0)\n", fCfg.address);
        return nullptr;
    }
    r = hid_mt2_init(&geometry, &fPtp);
    if (r != HID_MT2_OK) {
        IOLog(LOG_PREFIX "addr 0x%02x: multitouch device not published (%s)\n", fCfg.address, hid_mt2_init_name(r));
        return nullptr;
    }
    mt = OSTypeAlloc(SnapI2CHIDMultitouch);
    if (!mt || !mt->initWithBus(this, &geometry) || !mt->attach(this)) {
        IOLog(LOG_PREFIX "addr 0x%02x: cannot create the multitouch device\n", fCfg.address);
        OSSafeReleaseNULL(mt);
        return nullptr;
    }
    if (!mt->start(this)) {
        IOLog(LOG_PREFIX "addr 0x%02x: multitouch device start failed\n", fCfg.address);
        mt->detach(this);
        OSSafeReleaseNULL(mt);
        return nullptr;
    }
    if (!(mt->getState() & kIOServiceRegisteredState))
        mt->registerService();
    IOLog(LOG_PREFIX "addr 0x%02x: multitouch device published: %04x:%04x, family 0x%02x, surface %u.%02u x %u.%02u mm, "
          "frames as report %u (0x%02x)\n", fCfg.address, HID_MT2_VENDOR, HID_MT2_PRODUCT, HID_MT2_FAMILY,
          (unsigned)(4 * geometry.wq) / 100u, (unsigned)(4 * geometry.wq) % 100u, (unsigned)(4 * geometry.hq) / 100u,
          (unsigned)(4 * geometry.hq) % 100u, HID_MT2_REPORT_ID, HID_MT2_FRAME_ID);
    return mt;
}

/* M1-M7, work loop (noteProgress, RUNNING): what sits above the multitouch device, every 32 polls
 * (about 0.25 s) until a frames consumer is there and for the first minute, then every 125. The
 * pointer hands the touchpad over exactly while a consumer is attached; an empty frame (at most 10,
 * one a second) makes Apple's driver build its multitouch device before the first touch. */
void SnapI2CHIDBus::noteMultitouch()
{
    const struct i2c_hid_stats *s = &fDev->stats;
    uint32_t bits;
    if (!fMT || s->polls < fMTNextCheck)
        return;
    bits = fMT->stack();
    fMTNextCheck = s->polls + ((bits & SnapI2CHIDMultitouch::kStackConsumer) && s->polls > 7500u ? 125u : 32u);
    if (bits != fMTStack) {
        IOLog(LOG_PREFIX "addr 0x%02x: multitouch stack: interface %s, %s, multitouch device %s, frames consumer %s "
              "(poll %u)\n", fCfg.address, bits & SnapI2CHIDMultitouch::kStackInterface ? "yes" : "no",
              bits & SnapI2CHIDMultitouch::kStackAppleDriver ? "Apple multitouch driver"
              : bits & SnapI2CHIDMultitouch::kStackOtherDriver ? "another driver (no handover)" : "no driver",
              bits & SnapI2CHIDMultitouch::kStackDevice ? "yes" : "no",
              bits & SnapI2CHIDMultitouch::kStackConsumer ? "yes" : "no", s->polls);
        fMTStack = bits;
    }
    if (fPointer)
        fPointer->handover((bits & SnapI2CHIDMultitouch::kStackConsumer) != 0);
    if ((bits & SnapI2CHIDMultitouch::kStackAppleDriver) && !(bits & SnapI2CHIDMultitouch::kStackDevice) &&
        fMTKicks < 10u && (!fMTKicks || s->polls - fMTLastKick >= 125u)) {
        fMT->kick();
        fMTKicks++;
        fMTLastKick = s->polls;
        IOLog(LOG_PREFIX "addr 0x%02x: multitouch: empty frame %u, for the driver to build its device\n", fCfg.address,
              fMTKicks);
    }
}

void SnapI2CHIDBus::publishCall(thread_call_param_t owner, thread_call_param_t)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    self->publish();
    __atomic_store_n(&self->fPublishing, 0u, __ATOMIC_RELEASE);
    self->release();                        /* step()'s reference */
}

void SnapI2CHIDBus::publish()
{
    SnapI2CHIDKeyboard *kbd;
    SnapI2CHIDDevice *hid;
    SnapI2CHIDMultitouch *mt = nullptr;
    bool ptp;

    if (fStopping)
        return;
    /* The event services first: they do not depend on the IOHIDDevice. The keyboard service
     * only for the A16 keyboard's layout (input report 54 of 9 bytes); the pointer service
     * whenever the report descriptor has a relative mouse collection or the device took the
     * Precision Touchpad switch (which runs here, before polling starts). */
    ptp = enablePrecisionTouchpad();
    {
        struct hid_pointer_layout layout;
        int lr = hid_pointer_layout(fDev->rdesc, fDev->rdesc_len, &layout);
        SnapI2CHIDPointer *ptr = lr == HID_POINTER_OK || ptp ? OSTypeAlloc(SnapI2CHIDPointer) : nullptr;
        if (lr != HID_POINTER_OK && !ptp) {
            IOLog(LOG_PREFIX "addr 0x%02x: no pointer service (%s)\n", fCfg.address,
                  lr == HID_POINTER_NO_MOUSE ? "no relative mouse collection" : "malformed descriptor");
        } else if (ptr && ptr->initWithBus(this, lr == HID_POINTER_OK ? &layout : nullptr, ptp ? &fPtp : nullptr) &&
                   ptr->attach(this) && ptr->start(this)) {
            if (!(ptr->getState() & kIOServiceRegisteredState))
                ptr->registerService();
            if (lr == HID_POINTER_OK)
                IOLog(LOG_PREFIX "pointer event service started: %s, primary 1/2, report %u (%u bytes), %u buttons, "
                      "x %u y %u wheel %u pan %u bits, %s mode, state 0x%x\n", ptr->getMetaClass()->getClassName(),
                      layout.report_id, layout.report_bytes, layout.buttons, layout.x.size, layout.y.size,
                      layout.wheel.size, layout.pan.size, ptp ? "touchpad" : "mouse", (unsigned)ptr->getState());
            else
                IOLog(LOG_PREFIX "pointer event service started: %s, primary 1/2, touchpad mode only, state 0x%x\n",
                      ptr->getMetaClass()->getClassName(), (unsigned)ptr->getState());
            fPointerStarted = ptr;
        } else {
            IOLog(LOG_PREFIX "pointer event service start failed\n");
            if (ptr) {
                ptr->detach(this);
                OSSafeReleaseNULL(ptr);
            }
        }
    }
    if (hid_rdesc_report_bytes(&fDev->rinfo, HID_REPORT_INPUT, HID_KBD_REPORT_KEYS) != HID_KBD_KEYS_BYTES)
        kbd = nullptr;
    else
        kbd = OSTypeAlloc(SnapI2CHIDKeyboard);
    if (!kbd) {
        /* not this device's layout */
    } else if (kbd->initWithBus(this) && kbd->attach(this)) {
        if (kbd->start(this)) {
            if (!(kbd->getState() & kIOServiceRegisteredState))
                kbd->registerService();
            IOLog(LOG_PREFIX "keyboard event service started: %s, primary %u/%u, transport I2C, state 0x%x\n",
                  kbd->getMetaClass()->getClassName(), 1u, 6u, (unsigned)kbd->getState());
            fKeyboardStarted = kbd;              /* keeps the allocation's reference */
        } else {
            IOLog(LOG_PREFIX "keyboard event service start failed\n");
            kbd->detach(this);
            OSSafeReleaseNULL(kbd);
        }
    } else {
        IOLog(LOG_PREFIX "cannot create the keyboard event service\n");
        OSSafeReleaseNULL(kbd);
    }
    /* Y2: a touchpad in Precision Touchpad mode gets no IOHIDDevice. Its reports are Touch Pad
     * digitizer frames: a generic HID event driver (DriverKit's AppleUserHIDEventService, which
     * matches any 13/x interface once its server runs) makes no pointer motion from them, and our
     * pointer would yield to it (installed-fresh-desktop-20261021-v2: dead touchpad). Without the
     * device nothing can match; the pointer service stays the touchpad's only event service. */
    if (ptp) {
        hid = nullptr;
        IOLog(LOG_PREFIX "addr 0x%02x: raw HID device not published: the precision touchpad is served by the "
              "pointer event service only\n", fCfg.address);
        mt = publishMultitouch();
    } else {
        hid = OSTypeAlloc(SnapI2CHIDDevice);
    }
    if (hid && (!hid->initWithBus(this) || !hid->attach(this))) {
        IOLog(LOG_PREFIX "cannot create the HID device\n");
        OSSafeReleaseNULL(hid);
    } else if (hid && !hid->start(this)) {
        IOLog(LOG_PREFIX "IOHIDDevice start failed\n");
        hid->detach(this);
        OSSafeReleaseNULL(hid);
    } else if (hid && !(hid->getState() & kIOServiceRegisteredState)) {
        /* IOHIDDevice::start publishes the device; make sure matching runs. */
        hid->registerService();
    }
    fGate->runAction(gatedRun, hid, mt);
}

IOReturn SnapI2CHIDBus::gatedRun(OSObject *owner, void *hid, void *mt, void *, void *)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    self->fHID = static_cast<SnapI2CHIDDevice *>(hid);   /* keeps publishCall's reference */
    self->fMT = static_cast<SnapI2CHIDMultitouch *>(mt); /* likewise */
    self->fRawPublished = hid != nullptr;
    self->fKeyboard = self->fKeyboardStarted;
    self->fPointer = self->fPointerStarted;
    if (i2c_hid_run(self->fDev) == I2C_HID_R_OK && !self->fStopping) {
        self->noteState();
        self->fTimer->setTimeoutUS(self->fCfg.poll_us);
    }
    return kIOReturnSuccess;
}

IOReturn SnapI2CHIDBus::gatedRequest(OSObject *owner, void *arg, void *, void *, void *)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    SnapRequest *req = static_cast<SnapRequest *>(arg);
    switch (req->kind) {
    case kRequestOutput:
        req->result = i2c_hid_send_output(self->fDev, req->buf, req->len);
        break;
    case kRequestSetReport:
        req->result = i2c_hid_set_report(self->fDev, req->type, req->buf, req->len);
        break;
    case kRequestGetReport:
        req->result = i2c_hid_get_report(self->fDev, req->type, req->id, req->buf, req->len,
                                         req->got);
        break;
    default:
        req->result = I2C_HID_R_INVALID;
        break;
    }
    self->noteState();
    return kIOReturnSuccess;
}

IOReturn SnapI2CHIDBus::request(uint32_t kind, uint8_t type, uint8_t id, uint8_t *buf,
                                uint32_t len, uint32_t *got)
{
    SnapRequest req = {kind, type, id, buf, len, got, I2C_HID_R_INVALID};
    if (fStopping || !fGate)
        return kIOReturnOffline;
    /* Re-entrant from deliver() on the work loop thread: the gate is recursive
     * and the bus is idle between transfers. */
    fGate->runAction(gatedRequest, &req);
    switch (req.result) {
    case I2C_HID_R_OK: return kIOReturnSuccess;
    case I2C_HID_R_EMPTY: return kIOReturnNotReady;
    case I2C_HID_R_NOT_READY: return kIOReturnNotReady;
    case I2C_HID_R_INVALID: return kIOReturnBadArgument;
    case I2C_HID_R_BAD_RESPONSE: return kIOReturnIOError;
    default: return kIOReturnIOError;
    }
}

IOReturn SnapI2CHIDBus::gatedStop(OSObject *owner, void *, void *, void *, void *)
{
    SnapI2CHIDBus *self = static_cast<SnapI2CHIDBus *>(owner);
    if (self->fKeyboard)
        self->fKeyboard->releaseKeys();
    if (self->fPointer)
        self->fPointer->releaseButtons();
    self->fKeyboard = nullptr;
    self->fPointer = nullptr;
    self->fMTNextCheck = ~0u;               /* M20: no registry walks or kicks while stopping */
    i2c_hid_stop(self->fDev);
    if (self->fBus.started && !self->fBus.wedged)
        (void)geni_i2c_stop(&self->fBus);        /* restore lengths and IRQ enables */
    return kIOReturnSuccess;
}

void SnapI2CHIDBus::stop(IOService *provider)
{
    fStopping = true;
    if (fTimer)
        fTimer->cancelTimeout();
    if (fPublish && thread_call_cancel(fPublish)) {
        /* Dequeued before it ran: drop the reference step() gave it. */
        __atomic_store_n(&fPublishing, 0u, __ATOMIC_RELEASE);
        release();
    }
    for (uint32_t ms = 0; __atomic_load_n(&fPublishing, __ATOMIC_ACQUIRE); ms++) {
        if (ms == 1000)
            IOLog(LOG_PREFIX "stop is waiting for the HID device's start to return\n");
        IOSleep(1);
    }
    if (fGate && fDev)
        fGate->runAction(gatedStop);
    releaseAll();
    IOService::stop(provider);
}

void SnapI2CHIDBus::releaseAll()
{
    if (fWorkLoop && fTimer)
        fWorkLoop->removeEventSource(fTimer);
    if (fWorkLoop && fGate)
        fWorkLoop->removeEventSource(fGate);
    OSSafeReleaseNULL(fTimer);
    OSSafeReleaseNULL(fGate);
    OSSafeReleaseNULL(fWorkLoop);
    if (fPublish) {
        thread_call_free(fPublish);
        fPublish = nullptr;
    }
    OSSafeReleaseNULL(fHID);
    OSSafeReleaseNULL(fMT);
    fKeyboard = nullptr;
    OSSafeReleaseNULL(fKeyboardStarted);
    fPointer = nullptr;
    OSSafeReleaseNULL(fPointerStarted);
    OSSafeReleaseNULL(fRegs);
    OSSafeReleaseNULL(fGpio);
    fBase = nullptr;
    fAttention = nullptr;
    if (fDev) {
        IOFree(fDev, sizeof(*fDev));
        fDev = nullptr;
    }
}

void SnapI2CHIDBus::free()
{
    releaseAll();
    IOService::free();
}

/* ------------------------------------------------------------ device ---- */

bool SnapI2CHIDDevice::initWithBus(SnapI2CHIDBus *bus)
{
    const struct i2c_hid_dev *dev = bus->device();
    OSDictionary *props = OSDictionary::withCapacity(2);
    bool ok;

    if (!props)
        return false;
    props->setObject(kIOHIDBuiltInKey, kOSBooleanTrue);
    ok = IOHIDDevice::init(props);
    props->release();
    if (!ok)
        return false;
    fBus = bus;
    fDescriptor = OSData::withBytes(dev->rdesc, dev->rdesc_len);
    fProduct = bus->copyProduct();
    fReport = IOBufferMemoryDescriptor::withCapacity(dev->desc.max_input, kIODirectionOutIn);
    fVendor = dev->desc.vendor_id;
    fProductID = dev->desc.product_id;
    fVersion = dev->desc.device_version;
    fInterval = dev->cfg.poll_us;
    return fDescriptor && fProduct && fReport;
}

void SnapI2CHIDDevice::free()
{
    OSSafeReleaseNULL(fDescriptor);
    OSSafeReleaseNULL(fProduct);
    OSSafeReleaseNULL(fReport);
    IOHIDDevice::free();
}

bool SnapI2CHIDDevice::handleStart(IOService *provider)
{
    return provider == fBus && IOHIDDevice::handleStart(provider);
}

IOReturn SnapI2CHIDDevice::newReportDescriptor(IOMemoryDescriptor **descriptor) const
{
    IOBufferMemoryDescriptor *md = IOBufferMemoryDescriptor::withBytes(
        fDescriptor->getBytesNoCopy(), fDescriptor->getLength(), kIODirectionOutIn);
    if (!md)
        return kIOReturnNoMemory;
    *descriptor = md;
    return kIOReturnSuccess;
}

OSString *SnapI2CHIDDevice::newTransportString() const
{
    return OSString::withCString("I2C");
}

OSString *SnapI2CHIDDevice::newProductString() const
{
    fProduct->retain();
    return fProduct;
}

OSNumber *SnapI2CHIDDevice::newVendorIDNumber() const
{
    return OSNumber::withNumber(fVendor, 32);
}

OSNumber *SnapI2CHIDDevice::newProductIDNumber() const
{
    return OSNumber::withNumber(fProductID, 32);
}

OSNumber *SnapI2CHIDDevice::newVersionNumber() const
{
    return OSNumber::withNumber(fVersion, 32);
}

OSNumber *SnapI2CHIDDevice::newLocationIDNumber() const
{
    return OSNumber::withNumber(fBus->location(), 32);
}

OSNumber *SnapI2CHIDDevice::newReportIntervalNumber() const
{
    return OSNumber::withNumber(fInterval, 32);
}

void SnapI2CHIDDevice::deliverReport(const uint8_t *report, uint32_t len)
{
    uint64_t now;
    if (len > fReport->getCapacity())
        return;
    IOReturn r;
    bcopy(report, fReport->getBytesNoCopy(), len);
    fReport->setLength(len);
    clock_get_uptime(&now);
    r = handleReportWithTime(now, fReport, kIOHIDReportTypeInput, 0);
    /* The first 16 by ID and size (never contents), then failures only, rate-limited. */
    if (++fReportCalls <= 16)
        IOLog(LOG_PREFIX "handleReportWithTime %u: id %u, %u bytes -> 0x%x\n", fReportCalls,
              len ? report[0] : 0u, len, r);
    else if (r != kIOReturnSuccess && (++fReportFailures <= 8 || !(fReportFailures & 255)))
        IOLog(LOG_PREFIX "handleReportWithTime %u: id %u, %u bytes -> 0x%x (failure %u)\n",
              fReportCalls, len ? report[0] : 0u, len, r, fReportFailures);
}

/* Every set/get request from the HID stack (a Caps Lock LED output report shows that
 * the event system turned a key into an event); after 64, every 64th. */
void SnapI2CHIDDevice::logRequest(const char *what, IOHIDReportType type, IOOptionBits options,
                                  IOByteCount len, IOReturn result)
{
    if (++fRequests <= 64 || !(fRequests & 63))
        IOLog(LOG_PREFIX "%s %u: type %u id %u length %u -> 0x%x\n", what, fRequests, (unsigned)type,
              (unsigned)(options & 0xff), (unsigned)len, result);
}

static uint32_t numberProperty(IORegistryEntry *entry, const char *key)
{
    OSNumber *n = OSDynamicCast(OSNumber, entry->getProperty(key));
    return n ? n->unsigned32BitValue() : 0xffffffffu;
}

static void logEntry(IORegistryEntry *entry, unsigned depth)
{
    IOService *service = OSDynamicCast(IOService, entry);
    IOLog(LOG_PREFIX "  %*s%s: state 0x%x%s\n", (int)(2 * depth), "", entry->getMetaClass()->getClassName(),
          service ? (unsigned)service->getState() : 0u, service && service->isOpen() ? " open" : "");
    if (depth >= 3)
        return;
    OSIterator *it = entry->getChildIterator(gIOServicePlane);
    if (!it)
        return;
    unsigned n = 0;
    for (OSObject *o = it->getNextObject(); o && n < 16; o = it->getNextObject(), n++) {
        IORegistryEntry *child = OSDynamicCast(IORegistryEntry, o);
        if (child)
            logEntry(child, depth + 1);
    }
    it->release();
}

/* The device's published matching properties, and the service-plane clients above it
 * (IOHIDInterface, then IOHIDEventDriver or AppleUserHIDEventService, then their clients),
 * with IOService state bits (2 registered, 4 matched) and whether each is open. Diagnostics
 * only: who dispatches is decided by handleOpen/handleClose (Y1). */
void SnapI2CHIDDevice::logRegistry(const char *when)
{
    OSString *transport = OSDynamicCast(OSString, getProperty(kIOHIDTransportKey));
    OSArray *pairs = OSDynamicCast(OSArray, getProperty(kIOHIDDeviceUsagePairsKey));
    char list[96];
    unsigned at = 0;
    list[0] = 0;
    for (unsigned i = 0; pairs && i < pairs->getCount() && at + 16 < sizeof(list); i++) {
        OSDictionary *pair = OSDynamicCast(OSDictionary, pairs->getObject(i));
        OSNumber *page = pair ? OSDynamicCast(OSNumber, pair->getObject(kIOHIDDeviceUsagePageKey)) : nullptr;
        OSNumber *usage = pair ? OSDynamicCast(OSNumber, pair->getObject(kIOHIDDeviceUsageKey)) : nullptr;
        at += (unsigned)snprintf(list + at, sizeof(list) - at, "%s%u/%u", i ? " " : "",
                                 page ? page->unsigned32BitValue() : 0u, usage ? usage->unsigned32BitValue() : 0u);
    }
    IOLog(LOG_PREFIX "HID stack at %s: primary %u/%u pairs [%s] transport %s built-in %s vendor 0x%x product 0x%x "
          "location 0x%x country %d interval %u max-in %u max-out %u\n", when,
          numberProperty(this, kIOHIDPrimaryUsagePageKey), numberProperty(this, kIOHIDPrimaryUsageKey), list,
          transport ? transport->getCStringNoCopy() : "-",
          getProperty(kIOHIDBuiltInKey) == kOSBooleanTrue ? "yes" : "no",
          numberProperty(this, kIOHIDVendorIDKey), numberProperty(this, kIOHIDProductIDKey),
          numberProperty(this, kIOHIDLocationIDKey), (int)numberProperty(this, kIOHIDCountryCodeKey),
          numberProperty(this, kIOHIDReportIntervalKey), numberProperty(this, kIOHIDMaxInputReportSizeKey),
          numberProperty(this, kIOHIDMaxOutputReportSizeKey));
    logEntry(this, 0);
}

/* Y1: a kernel client that opens the device is an event driver (IOHIDInterface opens us on its
 * driver's behalf: "open by AppleUserHIDEventDriver" in desktop-20261021-v2); a user client (an
 * IOHIDManager reader) is not, and takes nothing from our services. */
bool SnapI2CHIDDevice::handleOpen(IOService *client, IOOptionBits options, void *argument)
{
    bool ok = IOHIDDevice::handleOpen(client, options, argument);
    if (ok && client && !OSDynamicCast(IOUserClient, client))
        fBus->noteEventDriver(client, client->getMetaClass()->getClassName(), true);
    return ok;
}

void SnapI2CHIDDevice::handleClose(IOService *client, IOOptionBits options)
{
    IOHIDDevice::handleClose(client, options);
    if (client && !OSDynamicCast(IOUserClient, client))
        fBus->noteEventDriver(client, client->getMetaClass()->getClassName(), false);
}

IOReturn SnapI2CHIDDevice::setReport(IOMemoryDescriptor *report, IOHIDReportType type,
                                     IOOptionBits options)
{
    uint8_t buf[I2C_HID_MAX_OUTPUT + 1];
    uint8_t id = (uint8_t)(options & 0xff);
    IOByteCount len = report ? report->getLength() : 0;
    uint32_t kind;
    IOReturn r;

    if (type == kIOHIDReportTypeOutput)
        kind = SnapI2CHIDBus::kRequestOutput;
    else if (type == kIOHIDReportTypeFeature)
        kind = SnapI2CHIDBus::kRequestSetReport;
    else {
        logRequest("setReport", type, options, len, kIOReturnUnsupported);
        return kIOReturnUnsupported;
    }
    if (!len || len > I2C_HID_MAX_OUTPUT) {
        logRequest("setReport", type, options, len, kIOReturnBadArgument);
        return kIOReturnBadArgument;
    }
    report->readBytes(0, buf, len);
    r = fBus->request(kind, type == kIOHIDReportTypeOutput ? I2C_HID_TYPE_OUTPUT
                                                           : I2C_HID_TYPE_FEATURE,
                      id, buf, (uint32_t)len, nullptr);
    if (r == kIOReturnBadArgument && id && buf[0] != id) {
        /* The buffer may omit the numbered report's ID byte. */
        bcopy(buf, buf + 1, len);
        buf[0] = id;
        r = fBus->request(kind, type == kIOHIDReportTypeOutput ? I2C_HID_TYPE_OUTPUT
                                                               : I2C_HID_TYPE_FEATURE,
                          id, buf, (uint32_t)len + 1u, nullptr);
    }
    logRequest("setReport", type, options, len, r);
    return r;
}

IOReturn SnapI2CHIDDevice::getReport(IOMemoryDescriptor *report, IOHIDReportType type,
                                     IOOptionBits options)
{
    uint8_t buf[I2C_HID_MAX_INPUT];
    uint32_t got = 0;
    uint8_t i2c_type = type == kIOHIDReportTypeInput ? I2C_HID_TYPE_INPUT
                     : type == kIOHIDReportTypeFeature ? I2C_HID_TYPE_FEATURE : 0;
    IOReturn r;

    if (!report || !i2c_type) {
        logRequest("getReport", type, options, report ? report->getLength() : 0, kIOReturnUnsupported);
        return kIOReturnUnsupported;
    }
    r = fBus->request(SnapI2CHIDBus::kRequestGetReport, i2c_type, (uint8_t)(options & 0xff),
                      buf, sizeof(buf), &got);
    if (r == kIOReturnSuccess && got > report->getLength())
        r = kIOReturnOverrun;
    if (r == kIOReturnSuccess)
        report->writeBytes(0, buf, got);
    logRequest("getReport", type, options, got, r);
    return r;
}

/* -------------------------------------------------------- multitouch ---- */

bool SnapI2CHIDMultitouch::initWithBus(SnapI2CHIDBus *bus, const struct hid_mt2 *geometry)
{
    OSDictionary *props = OSDictionary::withCapacity(2);
    bool ok;
    if (!props || !geometry || !geometry->wq)
        return false;
    props->setObject(kIOHIDBuiltInKey, kOSBooleanTrue);
    ok = IOHIDDevice::init(props);
    props->release();
    if (!ok)
        return false;
    fBus = bus;
    fMT = *geometry;
    fReport = IOBufferMemoryDescriptor::withCapacity(HID_MT2_MAX_REPORT, kIODirectionOutIn);
    return fReport != nullptr;
}

void SnapI2CHIDMultitouch::free()
{
    OSSafeReleaseNULL(fReport);
    IOHIDDevice::free();
}

bool SnapI2CHIDMultitouch::handleStart(IOService *provider)
{
    return provider == fBus && IOHIDDevice::handleStart(provider);
}

IOReturn SnapI2CHIDMultitouch::newReportDescriptor(IOMemoryDescriptor **descriptor) const
{
    uint32_t len;
    const uint8_t *bytes = hid_mt2_report_descriptor(&len);
    IOBufferMemoryDescriptor *md = IOBufferMemoryDescriptor::withBytes(bytes, len, kIODirectionOutIn);
    if (!md)
        return kIOReturnNoMemory;
    *descriptor = md;
    return kIOReturnSuccess;
}

OSString *SnapI2CHIDMultitouch::newTransportString() const { return OSString::withCString("I2C"); }
OSString *SnapI2CHIDMultitouch::newManufacturerString() const { return OSString::withCString("ASUSTeK"); }
OSString *SnapI2CHIDMultitouch::newProductString() const
{
    return OSString::withCString("Precision Touchpad (multitouch frames)");
}
OSNumber *SnapI2CHIDMultitouch::newVendorIDNumber() const { return OSNumber::withNumber(HID_MT2_VENDOR, 32); }
OSNumber *SnapI2CHIDMultitouch::newProductIDNumber() const { return OSNumber::withNumber(HID_MT2_PRODUCT, 32); }
OSNumber *SnapI2CHIDMultitouch::newVersionNumber() const { return OSNumber::withNumber(HID_MT2_VERSION, 32); }
OSNumber *SnapI2CHIDMultitouch::newLocationIDNumber() const { return OSNumber::withNumber(fBus->location(), 32); }
OSNumber *SnapI2CHIDMultitouch::newReportIntervalNumber() const
{
    return OSNumber::withNumber(fBus->device()->cfg.poll_us, 32);
}

/* M14: every request by type, report ID, length and result: 32, then every 64th. */
void SnapI2CHIDMultitouch::logRequest(const char *what, IOHIDReportType type, uint8_t id, uint32_t len, IOReturn result)
{
    if (++fRequests <= 32 || !(fRequests & 63))
        IOLog(LOG_PREFIX "multitouch %s %u: type %u id 0x%02x length %u -> 0x%x\n", what, fRequests, (unsigned)type,
              id, len, result);
}

/* M4: the handshake replies, from memory (hid_mt2_feature), with the buffer's length set to the
 * reply: the driver reads the length back to know how much it got. */
IOReturn SnapI2CHIDMultitouch::getReport(IOMemoryDescriptor *report, IOHIDReportType type, IOOptionBits options)
{
    uint8_t buf[HID_MT2_MAX_FEATURE];
    uint8_t id = (uint8_t)(options & 0xff);
    IOBufferMemoryDescriptor *b = OSDynamicCast(IOBufferMemoryDescriptor, report);
    uint32_t n = 0;
    IOReturn r;
    if (!report || type != kIOHIDReportTypeFeature) {
        r = kIOReturnUnsupported;
    } else if (!(n = hid_mt2_feature(&fMT, id, __atomic_load_n(&fQuery, __ATOMIC_RELAXED), buf, sizeof(buf)))) {
        r = kIOReturnUnsupported;
    } else if (b ? n > b->getCapacity() : n > report->getLength()) {
        r = kIOReturnNoSpace;
    } else {
        if (b)
            b->setLength(n);
        report->writeBytes(0, buf, n);
        r = kIOReturnSuccess;
    }
    logRequest("getReport", type, id, n, r);
    return r;
}

/* M14: accepted and ignored (the touchpad is not an Apple sensor), except report 1's query. */
IOReturn SnapI2CHIDMultitouch::setReport(IOMemoryDescriptor *report, IOHIDReportType type, IOOptionBits options)
{
    uint8_t id = (uint8_t)(options & 0xff), q[2] = {0, 0};
    uint32_t len = report ? (uint32_t)report->getLength() : 0;
    if (type == kIOHIDReportTypeFeature && id == 0x01 && len >= 2) {
        report->readBytes(0, q, 2);
        __atomic_store_n(&fQuery, q[0] == 0x01 ? q[1] : q[0], __ATOMIC_RELAXED);
    }
    logRequest("setReport", type, id, len, kIOReturnSuccess);
    return kIOReturnSuccess;
}

void SnapI2CHIDMultitouch::send(uint32_t len)
{
    AbsoluteTime now;
    IOReturn r;
    if (!len || len > fReport->getCapacity())
        return;
    bcopy(fBuf, fReport->getBytesNoCopy(), len);
    fReport->setLength(len);
    clock_get_uptime(&now);
    r = handleReportWithTime(now, fReport, kIOHIDReportTypeInput, 0);
    fSent++;
    if (r != kIOReturnSuccess && (++fFailures <= 8 || !(fFailures & 255)))
        IOLog(LOG_PREFIX "multitouch report %u, %u bytes -> 0x%x (failure %u)\n", fSent, len, r, fFailures);
    noteFrames();
}

/* Counts only (never positions), at 1, 16, 256 reports and then every 4096. */
void SnapI2CHIDMultitouch::noteFrames()
{
    const struct hid_mt2_stats *s = &fMT.stats;
    if (fSent < fNextLog)
        return;
    IOLog(LOG_PREFIX "multitouch: %u reports (%u from frames, %u from ticks, %u empty), %u touches, %u palms, %u lifts "
          "(%u vanished), %u jumps, %u dropped, %u duplicate ids, max %u contacts, %u time fallbacks, %u failures\n",
          fSent, s->frames, s->tick_frames, s->empty_frames, s->touches, s->palms, s->lifts, s->vanished, s->jumps,
          s->dropped, s->duplicate_ids, s->max_contacts, s->time_fallbacks, fFailures);
    fNextLog = fNextLog < 256u ? fNextLog * 16u : fNextLog + 4096u;
}

void SnapI2CHIDMultitouch::frame(const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons, uint32_t scan,
                                 int has_scan)
{
    AbsoluteTime now;
    clock_get_uptime(&now);
    send(hid_mt2_frame(&fMT, c, n, buttons, scan, has_scan, uptimeUs(now), fBuf, sizeof(fBuf)));
}

void SnapI2CHIDMultitouch::tick()
{
    AbsoluteTime now;
    if (!hid_mt2_busy(&fMT))
        return;
    clock_get_uptime(&now);
    send(hid_mt2_tick(&fMT, uptimeUs(now), fBuf, sizeof(fBuf)));
}

void SnapI2CHIDMultitouch::reset()
{
    hid_mt2_reset(&fMT);
}

void SnapI2CHIDMultitouch::kick()
{
    AbsoluteTime now;
    clock_get_uptime(&now);
    send(hid_mt2_empty(&fMT, uptimeUs(now), fBuf, sizeof(fBuf)));
}

/* The service plane above this device: IOHIDInterface, its driver (Apple's multitouch event
 * drivers are AppleMultitouch*), that driver's AppleMultitouchDevice and the user clients reading
 * its frames (AppleMultitouchDeviceUserClient: WindowServer on a 26A428 host). By class name: the
 * classes are Apple's, not linked. */
uint32_t SnapI2CHIDMultitouch::stack() const
{
    uint32_t bits = 0;
    OSIterator *interfaces = getChildIterator(gIOServicePlane);
    for (OSObject *o = interfaces ? interfaces->getNextObject() : nullptr; o; o = interfaces->getNextObject()) {
        IORegistryEntry *interface = OSDynamicCast(IORegistryEntry, o);
        OSIterator *drivers = interface ? interface->getChildIterator(gIOServicePlane) : nullptr;
        if (!interface)
            continue;
        bits |= kStackInterface;
        for (OSObject *d = drivers ? drivers->getNextObject() : nullptr; d; d = drivers->getNextObject()) {
            IORegistryEntry *driver = OSDynamicCast(IORegistryEntry, d);
            OSIterator *devices;
            if (!driver)
                continue;
            if (strncmp(driver->getMetaClass()->getClassName(), "AppleMultitouch", 15) != 0) {
                bits |= kStackOtherDriver;
                continue;
            }
            bits |= kStackAppleDriver;
            devices = driver->getChildIterator(gIOServicePlane);
            for (OSObject *m = devices ? devices->getNextObject() : nullptr; m; m = devices->getNextObject()) {
                IORegistryEntry *amd = OSDynamicCast(IORegistryEntry, m);
                OSIterator *clients;
                if (!amd || strcmp(amd->getMetaClass()->getClassName(), "AppleMultitouchDevice") != 0)
                    continue;
                bits |= kStackDevice;
                clients = amd->getChildIterator(gIOServicePlane);
                for (OSObject *u = clients ? clients->getNextObject() : nullptr; u; u = clients->getNextObject()) {
                    IORegistryEntry *client = OSDynamicCast(IORegistryEntry, u);
                    if (client && !strcmp(client->getMetaClass()->getClassName(), "AppleMultitouchDeviceUserClient"))
                        bits |= kStackConsumer;
                }
                OSSafeReleaseNULL(clients);
            }
            OSSafeReleaseNULL(devices);
        }
        OSSafeReleaseNULL(drivers);
    }
    OSSafeReleaseNULL(interfaces);
    return bits;
}

/* ---------------------------------------------------------- keyboard ---- */

bool SnapI2CHIDKeyboard::initWithBus(SnapI2CHIDBus *bus)
{
    OSDictionary *props = OSDictionary::withCapacity(2);
    bool ok;

    if (!props)
        return false;
    props->setObject(kIOHIDBuiltInKey, kOSBooleanTrue);
    /* As Apple's keyboard personalities carry it for the HID event system. */
    OSString *empty = OSString::withCString("");
    if (empty) {
        props->setObject("HIDDefaultBehavior", empty);
        empty->release();
    }
    ok = IOHIDEventService::init(props);
    props->release();
    if (!ok)
        return false;
    fBus = bus;
    bzero(&fState, sizeof(fState));
    fProductName = bus->copyProduct();
    return fProductName != nullptr;
}

void SnapI2CHIDKeyboard::free()
{
    OSSafeReleaseNULL(fProductName);
    IOHIDEventService::free();
}

IOWorkLoop *SnapI2CHIDKeyboard::getWorkLoop() const
{
    return fBus && fBus->fWorkLoop ? fBus->fWorkLoop : IOHIDEventService::getWorkLoop();
}

bool SnapI2CHIDKeyboard::handleStart(IOService *provider)
{
    return provider == fBus && IOHIDEventService::handleStart(provider);
}

OSString *SnapI2CHIDKeyboard::getTransport() { return OSString::withCString("I2C"); }
UInt32 SnapI2CHIDKeyboard::getLocationID() { return fBus->location(); }
UInt32 SnapI2CHIDKeyboard::getVendorID() { return fBus->device()->desc.vendor_id; }
UInt32 SnapI2CHIDKeyboard::getProductID() { return fBus->device()->desc.product_id; }
UInt32 SnapI2CHIDKeyboard::getVersion() { return fBus->device()->desc.device_version; }
/* HID country code 33, US: the A16's ANSI layout (the keyboardtype preference is keyed by it). */
UInt32 SnapI2CHIDKeyboard::getCountryCode() { return 33; }
OSString *SnapI2CHIDKeyboard::getManufacturer() { return OSString::withCString("ASUSTeK"); }
OSString *SnapI2CHIDKeyboard::getProduct()
{
    fProductName->retain();
    return fProductName;
}
UInt32 SnapI2CHIDKeyboard::getReportInterval() { return fBus->device()->cfg.poll_us; }
UInt32 SnapI2CHIDKeyboard::getPrimaryUsagePage() { return 0x01; }  /* Generic Desktop */
UInt32 SnapI2CHIDKeyboard::getPrimaryUsage() { return 0x06; }      /* Keyboard */

void SnapI2CHIDKeyboard::emit(void *ctx, uint32_t page, uint32_t usage, uint32_t down)
{
    SnapI2CHIDKeyboard *self = static_cast<SnapI2CHIDKeyboard *>(ctx);
    self->fTransitions++;
    if (down && page == HID_KBD_PAGE_KEYBOARD && (usage < 0xe0u || usage > 0xe7u))   /* not a modifier */
        __atomic_store_n(&gSnapLastKeyDownUs, uptimeUs(self->fNow), __ATOMIC_RELAXED);
    self->dispatchKeyboardEvent(self->fNow, page, usage, down);
}

void SnapI2CHIDKeyboard::handleReport(const uint8_t *report, uint32_t len)
{
    uint32_t before = fTransitions;
    int r;
    if (fSuppressed) {
        /* D1: counts only, while the event driver that opened the device dispatches them. */
        if (++fYieldedReports >= fNextYieldLog) {
            IOLog(LOG_PREFIX "keyboard yielded: %u reports left to the event driver\n", fYieldedReports);
            fNextYieldLog = fNextYieldLog < 256u ? fNextYieldLog * 16u : fNextYieldLog + 4096u;
        }
        return;
    }
    clock_get_uptime(&fNow);
    fReports++;
    r = hid_kbd_translate(&fState, report, len, emit, this);
    /* Counts only: the user may be typing a password. */
    if (fTransitions != before && fTransitions >= fNextLog) {
        IOLog(LOG_PREFIX "keyboard dispatched %u key transitions from %u reports\n", fTransitions, fReports);
        fNextLog = fNextLog < 64u ? fNextLog * 4u : fNextLog + 1024u;
    } else if (r == HID_KBD_BAD_LENGTH || r == HID_KBD_ROLLOVER_REPORT) {
        if (fReports <= 64u)
            IOLog(LOG_PREFIX "keyboard report %u not taken (%s), id %u, %u bytes\n", fReports,
                  r == HID_KBD_BAD_LENGTH ? "length" : "rollover", len ? report[0] : 0u, len);
    }
}

void SnapI2CHIDKeyboard::releaseKeys()
{
    clock_get_uptime(&fNow);
    hid_kbd_release_all(&fState, emit, this);
}

void SnapI2CHIDKeyboard::suppress(const char *why)
{
    if (fSuppressed)
        return;
    IOLog(LOG_PREFIX "keyboard event service stops dispatching: %s opened the HID device\n", why);
    clock_get_uptime(&fNow);
    hid_kbd_release_all(&fState, emit, this);
    fSuppressed = true;
}

/* Y3: the event driver closed the device (its dext exited): keys come from us again, from a clean
 * state (everything was released when we yielded). */
void SnapI2CHIDKeyboard::resume()
{
    if (!fSuppressed)
        return;
    IOLog(LOG_PREFIX "keyboard event service dispatches again after %u yielded reports\n", fYieldedReports);
    bzero(&fState, sizeof(fState));
    fSuppressed = false;
}

/* LEDs (page 8): Num 1, Caps 2, Scroll 3, Compose 4, Kana 5 -> output report 54, one bit each. */
IOReturn SnapI2CHIDKeyboard::setElementValue(UInt32 usagePage, UInt32 usage, UInt32 value)
{
    uint8_t buf[2];
    IOReturn r;
    if (usagePage != 0x08 || usage < 1 || usage > 5)
        return IOHIDEventService::setElementValue(usagePage, usage, value);
    fLeds = value ? fLeds | (1u << (usage - 1)) : fLeds & ~(1u << (usage - 1));
    buf[0] = HID_KBD_REPORT_KEYS;
    buf[1] = (uint8_t)fLeds;
    r = fBus->request(SnapI2CHIDBus::kRequestOutput, I2C_HID_TYPE_OUTPUT, HID_KBD_REPORT_KEYS, buf, 2, nullptr);
    if (++fLedRequests <= 64 || !(fLedRequests & 63))
        IOLog(LOG_PREFIX "keyboard LED %u: usage %u -> %u, output 0x%02x -> 0x%x\n", fLedRequests,
              (unsigned)usage, (unsigned)value, fLeds, r);
    return r;
}

/* ----------------------------------------------------------- pointer ---- */

static void setNumber(OSDictionary *d, const char *key, uint64_t value)
{
    OSNumber *n = OSNumber::withNumber(value, 32);
    if (n) {
        d->setObject(key, n);
        n->release();
    }
}

/* The scroll acceleration Apple's built-in trackpad service publishes on 26A428
 * (AppleMultitouchTrackpadHIDEventDriver, HIDScrollAccelCurves; docs/A16-INPUT-PTP-20261020.md
 * section 2.3), for deltas in 1/400 inch at HIDScrollResolution 400 dpi. GainParabolic 0 = absent. */
static const struct {
    uint32_t index, gain_linear, gain_parabolic, tangent_linear, tangent_parabolic_root;
} kTrackpadScrollCurves[10] = {
    {0, 65536, 0, 393216, 786432},           {8192, 62259, 39322, 406323, 786432},
    {32768, 58982, 58982, 419430, 786432},   {45056, 55706, 78643, 432538, 786432},
    {57344, 52429, 91750, 445645, 786432},   {65536, 49152, 104858, 458752, 786432},
    {98304, 45875, 117965, 471859, 786432},  {131072, 42598, 131072, 484966, 786432},
    {163840, 39322, 144179, 498074, 786432}, {196608, 36045, 157286, 511181, 786432},
};

/* Section 4.4: the trackpad scroll identity, only in touchpad mode. Pointer acceleration keys
 * stay unset, so one finger takes the same mouse acceleration path (and user setting) as today. */
static void addTrackpadScrollIdentity(OSDictionary *props)
{
    OSString *type = OSString::withCString("HIDTrackpadScrollAcceleration");
    OSArray *curves = OSArray::withCapacity(10);
    if (type) {
        props->setObject("HIDScrollAccelerationType", type);
        type->release();
    }
    setNumber(props, "HIDScrollResolution", (uint64_t)HID_PTP_UNITS_PER_INCH << 16);
    setNumber(props, "HIDTrackpadScrollAcceleration", 20480);   /* 26A428's default; the event system pushes the user's */
    for (uint32_t i = 0; curves && i < 10; i++) {
        OSDictionary *point = OSDictionary::withCapacity(5);
        if (!point)
            continue;
        setNumber(point, "HIDAccelIndex", kTrackpadScrollCurves[i].index);
        setNumber(point, "HIDAccelGainLinear", kTrackpadScrollCurves[i].gain_linear);
        if (kTrackpadScrollCurves[i].gain_parabolic)
            setNumber(point, "HIDAccelGainParabolic", kTrackpadScrollCurves[i].gain_parabolic);
        setNumber(point, "HIDAccelTangentSpeedLinear", kTrackpadScrollCurves[i].tangent_linear);
        setNumber(point, "HIDAccelTangentSpeedParabolicRoot", kTrackpadScrollCurves[i].tangent_parabolic_root);
        curves->setObject(point);
        point->release();
    }
    if (curves) {
        props->setObject("HIDScrollAccelCurves", curves);
        curves->release();
    }
}

bool SnapI2CHIDPointer::initWithBus(SnapI2CHIDBus *bus, const struct hid_pointer_layout *layout,
                                    const struct hid_ptp_layout *ptp)
{
    OSDictionary *props;
    bool ok;

    if (!layout && !ptp)
        return false;
    props = OSDictionary::withCapacity(ptp ? 6 : 2);
    if (!props)
        return false;
    props->setObject(kIOHIDBuiltInKey, kOSBooleanTrue);
    OSString *empty = OSString::withCString("");
    if (empty) {
        props->setObject("HIDDefaultBehavior", empty);
        empty->release();
    }
    if (ptp)
        addTrackpadScrollIdentity(props);
    ok = IOHIDEventService::init(props);
    props->release();
    if (!ok)
        return false;
    fBus = bus;
    bzero(&fLayout, sizeof(fLayout));
    fHaveMouse = layout != nullptr;
    if (layout)
        fLayout = *layout;
    bzero(&fState, sizeof(fState));
    fPtpArmed = ptp != nullptr;
    if (ptp)
        hid_ptp_engine_init(&fEngine, ptp);
    fSink.ctx = this;
    fSink.pointer = ptpPointer;
    fSink.scroll = ptpScroll;
    fSink.frame = ptpFrame;
    fProductName = bus->copyProduct();
    return fProductName != nullptr;
}

void SnapI2CHIDPointer::free()
{
    OSSafeReleaseNULL(fProductName);
    IOHIDEventService::free();
}

IOWorkLoop *SnapI2CHIDPointer::getWorkLoop() const
{
    return fBus && fBus->fWorkLoop ? fBus->fWorkLoop : IOHIDEventService::getWorkLoop();
}

bool SnapI2CHIDPointer::handleStart(IOService *provider)
{
    return provider == fBus && IOHIDEventService::handleStart(provider);
}

OSString *SnapI2CHIDPointer::getTransport() { return OSString::withCString("I2C"); }
UInt32 SnapI2CHIDPointer::getLocationID() { return fBus->location(); }
UInt32 SnapI2CHIDPointer::getVendorID() { return fBus->device()->desc.vendor_id; }
UInt32 SnapI2CHIDPointer::getProductID() { return fBus->device()->desc.product_id; }
UInt32 SnapI2CHIDPointer::getVersion() { return fBus->device()->desc.device_version; }
UInt32 SnapI2CHIDPointer::getCountryCode() { return 0; }
OSString *SnapI2CHIDPointer::getManufacturer() { return OSString::withCString("ASUSTeK"); }
OSString *SnapI2CHIDPointer::getProduct()
{
    fProductName->retain();
    return fProductName;
}
UInt32 SnapI2CHIDPointer::getReportInterval() { return fBus->device()->cfg.poll_us; }
UInt32 SnapI2CHIDPointer::getPrimaryUsagePage() { return 0x01; }  /* Generic Desktop */
UInt32 SnapI2CHIDPointer::getPrimaryUsage() { return 0x02; }      /* Mouse */

void SnapI2CHIDPointer::noteEvent()
{
    uint32_t events = fMoves + fScrolls;
    if (events >= fNextLog) {
        IOLog(LOG_PREFIX "pointer dispatched %u moves and %u scrolls from %u reports\n", fMoves, fScrolls, fReports);
        fNextLog = fNextLog < 64u ? fNextLog * 4u : fNextLog + 1024u;
    }
}

void SnapI2CHIDPointer::move(void *ctx, int32_t dx, int32_t dy, uint32_t buttons)
{
    SnapI2CHIDPointer *self = static_cast<SnapI2CHIDPointer *>(ctx);
    self->fMoves++;
    self->dispatchRelativePointerEvent(self->fNow, dx, dy, buttons);
    self->noteEvent();
}

void SnapI2CHIDPointer::scroll(void *ctx, int32_t vertical, int32_t horizontal)
{
    SnapI2CHIDPointer *self = static_cast<SnapI2CHIDPointer *>(ctx);
    self->fScrolls++;
    self->dispatchScrollWheelEvent(self->fNow, vertical, horizontal, 0);
    self->noteEvent();
}

void SnapI2CHIDPointer::ptpPointer(void *ctx, int32_t dx, int32_t dy, uint32_t buttons)
{
    SnapI2CHIDPointer *self = static_cast<SnapI2CHIDPointer *>(ctx);
    if (self->fHandover) {                       /* Apple's multitouch stack has the touchpad */
        self->fHandedOver++;
        return;
    }
    self->fMoves++;
    self->dispatchRelativePointerEventWithFixed(self->fNow, dx, dy, buttons);
}

void SnapI2CHIDPointer::ptpScroll(void *ctx, int32_t vertical, int32_t horizontal, uint32_t options)
{
    SnapI2CHIDPointer *self = static_cast<SnapI2CHIDPointer *>(ctx);
    if (self->fHandover) {
        self->fHandedOver++;
        return;
    }
    self->fScrolls++;
    self->dispatchScrollWheelEventWithFixed(self->fNow, vertical, horizontal, 0, options);
}

/* D2: the first 8 complete frames: how many contacts, touching, confident (palm-free), the
 * buttons, and what the engine dispatched so far; never positions. */
void SnapI2CHIDPointer::ptpFrame(void *ctx, const struct hid_ptp_contact *c, uint32_t n, uint32_t buttons,
                                 uint32_t scan, int has_scan)
{
    SnapI2CHIDPointer *self = static_cast<SnapI2CHIDPointer *>(ctx);
    uint32_t tips = 0, confident = 0;
    if (self->fBus->fMT)                         /* every frame, to Apple's multitouch stack */
        self->fBus->fMT->frame(c, n, buttons, scan, has_scan);
    if (self->fLoggedFrames >= 8u)
        return;
    self->fLoggedFrames++;
    for (uint32_t i = 0; i < n; i++) {
        tips += c[i].tip != 0;
        confident += c[i].tip && c[i].confident;
    }
    IOLog(LOG_PREFIX "touchpad frame %u: %u contacts, %u touching, %u confident, buttons 0x%x; dispatched so far "
          "%u pointer, %u scroll\n", self->fLoggedFrames, n, tips, confident, buttons, self->fMoves, self->fScrolls);
}

/* Counts only, at 1, 16, 256 frames and then every 4096. */
void SnapI2CHIDPointer::notePtp(int result)
{
    const struct hid_ptp_stats *s = &fEngine.stats;
    if (result == HID_PTP_BAD_LENGTH && s->bad_length <= 8u)
        IOLog(LOG_PREFIX "touchpad report %u not taken (length)\n", s->reports);
    if (s->frames < fNextPtpLog)
        return;
    IOLog(LOG_PREFIX "touchpad: %u frames, %u pointer, %u scrolls (%u momentum), %u taps (%u secondary, %u while "
          "typing), %u palms, %u bad lengths, %u scan fallbacks, max %u fingers\n", s->frames, s->pointer_events,
          s->scrolls, s->momentum, s->taps, s->secondary_taps, s->typing_blocked_taps, s->palms, s->bad_length,
          s->scan_fallbacks, s->max_fingers);
    fNextPtpLog = fNextPtpLog < 256u ? fNextPtpLog * 16u : fNextPtpLog + 4096u;
}

void SnapI2CHIDPointer::handleReport(const uint8_t *report, uint32_t len)
{
    int r;
    if (!len)
        return;
    if (fSuppressed) {
        /* D1: counts only, while the event driver that opened the device dispatches them. */
        fYieldedReports++;
        if (fPtpArmed && report[0] == fEngine.l.report_id)
            fYieldedPtp++;
        if (fYieldedReports >= fNextYieldLog) {
            IOLog(LOG_PREFIX "pointer yielded: %u reports left to the event driver (%u touchpad frames)\n",
                  fYieldedReports, fYieldedPtp);
            fNextYieldLog = fNextYieldLog < 256u ? fNextYieldLog * 16u : fNextYieldLog + 4096u;
        }
        return;
    }
    clock_get_uptime(&fNow);
    fReports++;
    if (fPtpArmed && report[0] == fEngine.l.report_id) {
        r = hid_ptp_engine_report(&fEngine, report, len, uptimeUs(fNow),
                                  __atomic_load_n(&gSnapLastKeyDownUs, __ATOMIC_RELAXED), &fSink);
        notePtp(r);
        return;
    }
    if (!fHaveMouse)
        return;
    if (fPtpArmed && report[0] == fLayout.report_id) {
        ++fMouseWhileArmed;
        if (fMouseWhileArmed <= 4u)
            IOLog(LOG_PREFIX "pointer: mouse-mode report %u while in touchpad mode (%u)\n", report[0], fMouseWhileArmed);
        if (fMouseWhileArmed == 1u || fMouseWhileArmed == 64u || fMouseWhileArmed == 4096u)
            fBus->fPtpReapply = true;        /* F24: the next bus step applies the switch again */
    }
    r = hid_pointer_translate(&fLayout, &fState, report, len, move, scroll, this);
    if (r == HID_POINTER_BAD_LENGTH && fReports <= 64u)
        IOLog(LOG_PREFIX "pointer report %u not taken (length), id %u, %u bytes\n", fReports,
              len ? report[0] : 0u, len);
}

void SnapI2CHIDPointer::tick()
{
    if (!fPtpArmed || fSuppressed || !hid_ptp_engine_busy(&fEngine))
        return;
    clock_get_uptime(&fNow);
    hid_ptp_engine_tick(&fEngine, uptimeUs(fNow), &fSink);
}

/* Scroll and momentum ended, buttons released, contacts forgotten (F10, F22). */
void SnapI2CHIDPointer::resetTouch()
{
    if (!fPtpArmed)
        return;
    clock_get_uptime(&fNow);
    hid_ptp_engine_reset(&fEngine, uptimeUs(fNow), &fSink);
}

void SnapI2CHIDPointer::releaseButtons()
{
    resetTouch();
    if (!fState.buttons)
        return;
    clock_get_uptime(&fNow);
    dispatchRelativePointerEvent(fNow, 0, 0, 0);
    fState.buttons = 0;
}

void SnapI2CHIDPointer::suppress(const char *why)
{
    if (fSuppressed)
        return;
    IOLog(LOG_PREFIX "pointer event service stops dispatching: %s opened the HID device\n", why);
    releaseButtons();
    fSuppressed = true;
}

/* M1, M6, M7: hand the touchpad to Apple's multitouch stack while it has a frames consumer, take it
 * back when the consumer goes (WindowServer exited). Either way the engine's touch state is reset with
 * its events going where they went before (ending a scroll or a button we dispatched; dropping the
 * ones Apple's stack had), so nothing is left open on either side. */
void SnapI2CHIDPointer::handover(bool on)
{
    if (on == fHandover || !fPtpArmed)
        return;
    resetTouch();
    fHandover = on;
    IOLog(LOG_PREFIX "pointer %s the touchpad %s the multitouch stack (%u engine events not dispatched so far)\n",
          on ? "hands" : "takes back", on ? "to" : "from", fHandedOver);
}

/* Y3: the event driver closed the device: the pointer dispatches again from clean state. */
void SnapI2CHIDPointer::resume()
{
    if (!fSuppressed)
        return;
    IOLog(LOG_PREFIX "pointer event service dispatches again after %u yielded reports\n", fYieldedReports);
    bzero(&fState, sizeof(fState));
    fSuppressed = false;
    resetTouch();
}
