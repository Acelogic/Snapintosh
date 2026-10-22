/* SPDX-License-Identifier: MIT */
/*
 * User-space stand-ins for exactly the kernel interfaces drivers/snap-i2c-hid/src/SnapI2CHID.cpp
 * uses, so the real IOKit glue compiles on the host (tools/test-snap-i2c-hid-start.cpp, driven by
 * tools/test-snap-i2c-hid-kext.py). Every IOKit/libkern/kern header the driver includes resolves
 * to this file. Time is a fake clock that IOSleep and IODelay advance; the timer, the command gate
 * and the thread call record what the driver asks and the harness runs it. Not a model of IOKit's
 * matching, power or registry: only what the start, step, publish and stop paths touch.
 */
#pragma once
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>

typedef int IOReturn;
typedef uint32_t IOOptionBits;
typedef size_t IOByteCount;
typedef uint64_t AbsoluteTime;
typedef uint32_t UInt32;
typedef int32_t IOFixed;
typedef uint64_t IOPhysicalAddress;
typedef uintptr_t IOVirtualAddress;
enum { kIOReturnSuccess = 0, kIOReturnNoMemory = 0x2bd, kIOReturnBadArgument = 0x2c2,
       kIOReturnUnsupported = 0x2c7, kIOReturnIOError = 0x2ca, kIOReturnNotReady = 0x2d8,
       kIOReturnOverrun = 0x2e4, kIOReturnOffline = 0x2e5, kIOReturnNoSpace = 0x2c4 };
enum { kIODirectionOutIn = 3 };
enum { kIOServiceRegisteredState = 2 };

/* The harness's world. */
struct Standin {
    uint64_t now_ns = 0;
    std::string log;
    unsigned timeouts_armed = 0, timeouts_cancelled = 0, registered = 0, maps = 0;
    unsigned thread_calls_entered = 0, hid_starts = 0, reports = 0;
    IOReturn report_result = 0;
    unsigned event_service_starts = 0, primary = 0;
    std::string transport;
    struct KeyEvent { uint32_t page, usage, value; };
    std::vector<KeyEvent> key_events;
    struct Triple { int32_t a, b, c; };
    std::vector<Triple> pointer_events, scroll_events;
    /* dispatchRelativePointerEventWithFixed (dx, dy, buttons) and dispatchScrollWheelEventWithFixed
     * (axis 1, axis 2, options). */
    std::vector<Triple> pointer_fixed, scroll_fixed;
    int64_t live_objects = 0;
    /* agents/input-latency T4: what the driver slept and delayed; boot-args PE_parse_boot_argn answers */
    unsigned sleeps = 0, delays = 0;
    uint64_t sleep_ms = 0, delay_us = 0;
    std::map<std::string, uint32_t> boot_args;
};
extern Standin standin;

inline void IOLog(const char *format, ...) __attribute__((format(printf, 1, 2)));
inline void IOLog(const char *format, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, format);
    vsnprintf(line, sizeof(line), format, ap);
    va_end(ap);
    standin.log += line;
}
inline void IOSleep(unsigned ms) { standin.sleeps++; standin.sleep_ms += ms; standin.now_ns += (uint64_t)ms * 1000000u; }
inline void IODelay(unsigned us) { standin.delays++; standin.delay_us += us; standin.now_ns += (uint64_t)us * 1000u; }
inline bool PE_parse_boot_argn(const char *name, void *out, int size)
{
    auto it = standin.boot_args.find(name);
    if (it == standin.boot_args.end())
        return false;
    uint32_t v = it->second;
    memcpy(out, &v, size < 4 ? (size_t)size : 4u);
    return true;
}
inline void clock_get_uptime(uint64_t *t) { *t = standin.now_ns; }
inline void absolutetime_to_nanoseconds(uint64_t t, uint64_t *ns) { *ns = t; }
inline void *IOMallocZero(size_t n) { return calloc(1, n); }
inline void *IOMalloc(size_t n) { return malloc(n); }
inline void IOFree(void *p, size_t) { free(p); }

struct OSMetaClassStandin {
    const char *name;
    const char *getClassName() const { return name; }
};
class OSObject {
public:
    OSObject() { standin.live_objects++; }
    const OSMetaClassStandin *getMetaClass() const { return &meta; }
    OSMetaClassStandin meta = {"OSObject"};
    virtual ~OSObject() { standin.live_objects--; }
    virtual void retain() const { refs++; }
    virtual void release() const
    {
        if (--refs == 0) {
            const_cast<OSObject *>(this)->free();
            delete this;
        }
    }
    virtual void free() {}
    mutable int refs = 1;
};
#define OSDeclareDefaultStructors(c)
#define OSDefineMetaClassAndStructors(c, s)
#define OSTypeAlloc(c) (new c)
#define OSDynamicCast(type, instance) dynamic_cast<type *>(instance)
#define OSSafeReleaseNULL(p) do { if (p) { (p)->release(); (p) = nullptr; } } while (0)

class OSData : public OSObject {
public:
    std::vector<uint8_t> bytes;
    static OSData *withBytes(const void *p, unsigned n)
    {
        OSData *d = new OSData;
        d->bytes.assign((const uint8_t *)p, (const uint8_t *)p + n);
        return d;
    }
    unsigned getLength() const { return (unsigned)bytes.size(); }
    const void *getBytesNoCopy() const { return bytes.data(); }
};
class OSString : public OSObject {
public:
    std::string s;
    static OSString *withCString(const char *c) { OSString *o = new OSString; o->s = c; return o; }
    const char *getCStringNoCopy() const { return s.c_str(); }
};
class OSNumber : public OSObject {
public:
    uint64_t v = 0;
    static OSNumber *withNumber(uint64_t value, unsigned) { OSNumber *o = new OSNumber; o->v = value; return o; }
    uint32_t unsigned32BitValue() const { return (uint32_t)v; }
};
class OSArray : public OSObject {
public:
    std::vector<OSObject *> items;
    static OSArray *withCapacity(unsigned) { return new OSArray; }
    bool setObject(OSObject *o) { o->retain(); items.push_back(o); return true; }   /* retains, as libkern's */
    unsigned getCount() const { return (unsigned)items.size(); }
    OSObject *getObject(unsigned i) const { return i < items.size() ? items[i] : nullptr; }
};
class OSIterator : public OSObject {
public:
    std::vector<OSObject *> items;
    size_t at = 0;
    OSObject *getNextObject() { return at < items.size() ? items[at++] : nullptr; }
};
class OSBoolean : public OSObject {
public:
    void release() const override {}
};
extern OSBoolean *const kOSBooleanTrue;
class OSDictionary : public OSObject {
public:
    std::map<std::string, OSObject *> map;
    static OSDictionary *withCapacity(unsigned) { return new OSDictionary; }
    /* Retains, as libkern's does: the driver releases what it sets. */
    bool setObject(const char *k, OSObject *o)
    {
        o->retain();
        auto it = map.find(k);
        if (it != map.end()) it->second->release();
        map[k] = o;
        return true;
    }
    OSObject *getObject(const char *k) const { auto it = map.find(k); return it == map.end() ? nullptr : it->second; }
    void free() override { for (auto &kv : map) kv.second->release(); map.clear(); }
};
#define kIOHIDBuiltInKey "Built-In"
#define kIOHIDTransportKey "Transport"
#define kIOHIDVendorIDKey "VendorID"
#define kIOHIDProductIDKey "ProductID"
#define kIOHIDLocationIDKey "LocationID"
#define kIOHIDCountryCodeKey "CountryCode"
#define kIOHIDReportIntervalKey "ReportInterval"
#define kIOHIDMaxInputReportSizeKey "MaxInputReportSize"
#define kIOHIDMaxOutputReportSizeKey "MaxOutputReportSize"
#define kIOHIDPrimaryUsagePageKey "PrimaryUsagePage"
#define kIOHIDPrimaryUsageKey "PrimaryUsage"
#define kIOHIDDeviceUsagePairsKey "DeviceUsagePairs"
#define kIOHIDDeviceUsagePageKey "DeviceUsagePage"
#define kIOHIDDeviceUsageKey "DeviceUsage"

class IOMemoryDescriptor : public OSObject {
public:
    std::vector<uint8_t> data;
    size_t length = 0;
    IOByteCount getLength() const { return length; }
    IOByteCount readBytes(IOByteCount off, void *out, IOByteCount n)
    {
        memcpy(out, data.data() + off, n);
        return n;
    }
    IOByteCount writeBytes(IOByteCount off, const void *in, IOByteCount n)
    {
        if (data.size() < off + n) data.resize(off + n);
        memcpy(data.data() + off, in, n);
        return n;
    }
};
class IOBufferMemoryDescriptor : public IOMemoryDescriptor {
public:
    static IOBufferMemoryDescriptor *withCapacity(size_t n, unsigned)
    {
        IOBufferMemoryDescriptor *m = new IOBufferMemoryDescriptor;
        m->data.resize(n);
        m->length = n;
        return m;
    }
    static IOBufferMemoryDescriptor *withBytes(const void *p, size_t n, unsigned)
    {
        IOBufferMemoryDescriptor *m = withCapacity(n, 0);
        memcpy(m->data.data(), p, n);
        return m;
    }
    void *getBytesNoCopy() { return data.data(); }
    size_t getCapacity() const { return data.size(); }
    void setLength(size_t n) { length = n; }
};
class IOMemoryMap : public OSObject {
public:
    IOVirtualAddress va = 0;
    IOPhysicalAddress pa = 0;
    IOByteCount len = 0;
    IOByteCount getLength() const { return len; }
    IOVirtualAddress getVirtualAddress() const { return va; }
    IOPhysicalAddress getPhysicalAddress() const { return pa; }
};

class IOService;
class IOEventSource : public OSObject {};
class IOWorkLoop : public OSObject {
public:
    static IOWorkLoop *workLoop() { return new IOWorkLoop; }
    IOReturn addEventSource(IOEventSource *) { return kIOReturnSuccess; }
    IOReturn removeEventSource(IOEventSource *) { return kIOReturnSuccess; }
};
class IOCommandGate : public IOEventSource {
public:
    typedef IOReturn (*Action)(OSObject *, void *, void *, void *, void *);
    OSObject *owner = nullptr;
    static IOCommandGate *commandGate(OSObject *o) { IOCommandGate *g = new IOCommandGate; g->owner = o; return g; }
    IOReturn runAction(Action a, void *a0 = 0, void *a1 = 0, void *a2 = 0, void *a3 = 0)
    {
        return a(owner, a0, a1, a2, a3);
    }
};
class IOTimerEventSource : public IOEventSource {
public:
    typedef void (*Action)(OSObject *, IOTimerEventSource *);
    OSObject *owner = nullptr;
    Action action = nullptr;
    bool armed = false;
    uint64_t due_ns = 0;
    static IOTimerEventSource *timerEventSource(OSObject *o, Action a)
    {
        IOTimerEventSource *t = new IOTimerEventSource;
        t->owner = o;
        t->action = a;
        return t;
    }
    IOReturn setTimeoutUS(uint32_t us)
    {
        armed = true;
        due_ns = standin.now_ns + (uint64_t)us * 1000u;
        standin.timeouts_armed++;
        return kIOReturnSuccess;
    }
    void cancelTimeout() { armed = false; standin.timeouts_cancelled++; }
};

typedef void *thread_call_param_t;
typedef void (*thread_call_func_t)(thread_call_param_t, thread_call_param_t);
struct thread_call { thread_call_func_t func; thread_call_param_t param; bool pending; };
typedef struct thread_call *thread_call_t;
inline thread_call_t thread_call_allocate(thread_call_func_t f, thread_call_param_t p)
{
    return new thread_call{f, p, false};
}
inline bool thread_call_enter(thread_call_t c)
{
    bool was = c->pending;
    c->pending = true;
    standin.thread_calls_entered++;
    return was;
}
inline bool thread_call_cancel(thread_call_t c) { bool was = c->pending; c->pending = false; return was; }
inline bool thread_call_free(thread_call_t c) { delete c; return true; }

struct IORegistryPlane {};
extern const IORegistryPlane *gIOServicePlane;
class IORegistryEntry : public OSObject {
public:
    std::map<std::string, OSObject *> properties;
    std::vector<IORegistryEntry *> children;
    OSObject *getProperty(const char *key) const
    {
        auto it = properties.find(key);
        return it == properties.end() ? nullptr : it->second;
    }
    OSIterator *getChildIterator(const IORegistryPlane *) const
    {
        OSIterator *it = new OSIterator;
        it->items.assign(children.begin(), children.end());
        return it;
    }
};
class IOService : public IORegistryEntry {
public:
    bool open_ = false;
    bool isOpen(const IOService * = nullptr) const { return open_; }
    std::vector<IOMemoryMap *> windows;      /* what mapDeviceMemoryWithIndex returns, by index */
    unsigned state = 0;
    virtual bool start(IOService *) { return true; }
    virtual void stop(IOService *) {}
    virtual bool attach(IOService *) { return true; }
    virtual void detach(IOService *) {}
    void registerService() { state |= kIOServiceRegisteredState; standin.registered++; }
    unsigned getState() const { return state; }
    IOMemoryMap *mapDeviceMemoryWithIndex(unsigned index)
    {
        standin.maps++;
        if (index >= windows.size() || !windows[index]) return nullptr;
        windows[index]->retain();
        return windows[index];
    }
};

class IOHIDEventService : public IOService {
public:
    /* IOService::init(dictionary) makes the dictionary the property table: kept here, retained. */
    virtual bool init(OSDictionary *d)
    {
        if (d)
            for (auto &kv : d->map) {
                kv.second->retain();
                properties[kv.first] = kv.second;
            }
        return true;
    }
    bool start(IOService *provider) override
    {
        standin.event_service_starts++;
        if (!handleStart(provider)) return false;
        standin.primary = (getPrimaryUsagePage() << 16) | getPrimaryUsage();
        OSString *t = getTransport();
        if (t) { standin.transport = t->s; t->release(); }
        return true;
    }
    virtual IOWorkLoop *getWorkLoop() const { return nullptr; }
protected:
    virtual bool handleStart(IOService *) { return true; }
    virtual OSString *getTransport() { return nullptr; }
    virtual UInt32 getLocationID() { return 0; }
    virtual UInt32 getVendorID() { return 0; }
    virtual UInt32 getProductID() { return 0; }
    virtual UInt32 getVersion() { return 0; }
    virtual UInt32 getCountryCode() { return 0; }
    virtual OSString *getManufacturer() { return nullptr; }
    virtual OSString *getProduct() { return nullptr; }
    virtual UInt32 getReportInterval() { return 0; }
    virtual UInt32 getPrimaryUsagePage() { return 0; }
    virtual UInt32 getPrimaryUsage() { return 0; }
    virtual IOReturn setElementValue(UInt32, UInt32, UInt32) { return kIOReturnUnsupported; }
    virtual void dispatchKeyboardEvent(AbsoluteTime, UInt32 page, UInt32 usage, UInt32 value, IOOptionBits = 0)
    {
        standin.key_events.push_back({page, usage, value});
    }
    virtual void dispatchRelativePointerEvent(AbsoluteTime, int32_t dx, int32_t dy, UInt32 buttons, IOOptionBits = 0)
    {
        standin.pointer_events.push_back({dx, dy, (int32_t)buttons});
    }
    virtual void dispatchScrollWheelEvent(AbsoluteTime, int32_t a1, int32_t a2, int32_t a3, IOOptionBits = 0)
    {
        standin.scroll_events.push_back({a1, a2, a3});
    }
    /* Not virtual in IOHIDEventService.h (an exported function); the scroll one is reserved slot 22. */
    void dispatchRelativePointerEventWithFixed(AbsoluteTime, int32_t dx, int32_t dy, UInt32 buttons, IOOptionBits = 0)
    {
        standin.pointer_fixed.push_back({dx, dy, (int32_t)buttons});
    }
    virtual void dispatchScrollWheelEventWithFixed(AbsoluteTime, int32_t a1, int32_t a2, int32_t, IOOptionBits options = 0)
    {
        standin.scroll_fixed.push_back({a1, a2, (int32_t)options});
    }
};
enum {
    kHIDDispatchOptionScrollMomentumContinue = (1 << 1), kHIDDispatchOptionScrollMomentumStart = (1 << 2),
    kHIDDispatchOptionScrollMomentumEnd = (1 << 3), kHIDDispatchOptionPhaseBegan = (1 << 4),
    kHIDDispatchOptionPhaseChanged = (1 << 5), kHIDDispatchOptionPhaseEnded = (1 << 6),
};

typedef uint32_t IOHIDReportType;
enum { kIOHIDReportTypeInput = 0, kIOHIDReportTypeOutput = 1, kIOHIDReportTypeFeature = 2 };
class IOUserClient : public IOService {};
class IOHIDDevice : public IOService {
public:
    virtual bool init(OSDictionary *) { return true; }
    bool start(IOService *provider) override { standin.hid_starts++; return handleStart(provider); }
    /* IOService::open/close call these with the arbitration lock held; the harness calls them. */
    virtual bool handleOpen(IOService *, IOOptionBits, void *) { open_ = true; return true; }
    virtual void handleClose(IOService *, IOOptionBits) {}
    virtual bool handleStart(IOService *) { return true; }
    virtual IOReturn newReportDescriptor(IOMemoryDescriptor **) const = 0;
    virtual OSString *newTransportString() const { return nullptr; }
    virtual OSString *newProductString() const { return nullptr; }
    virtual OSString *newManufacturerString() const { return nullptr; }
    virtual OSNumber *newVendorIDNumber() const { return nullptr; }
    virtual OSNumber *newProductIDNumber() const { return nullptr; }
    virtual OSNumber *newVersionNumber() const { return nullptr; }
    virtual OSNumber *newLocationIDNumber() const { return nullptr; }
    virtual OSNumber *newReportIntervalNumber() const { return nullptr; }
    virtual IOReturn getReport(IOMemoryDescriptor *, IOHIDReportType, IOOptionBits) { return kIOReturnUnsupported; }
    virtual IOReturn setReport(IOMemoryDescriptor *, IOHIDReportType, IOOptionBits = 0) { return kIOReturnUnsupported; }
    IOReturn handleReportWithTime(AbsoluteTime, IOMemoryDescriptor *, IOHIDReportType, IOOptionBits)
    {
        standin.reports++;
        return standin.report_result;
    }
};
