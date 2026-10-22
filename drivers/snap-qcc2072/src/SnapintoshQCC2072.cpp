/* SPDX-License-Identifier: MIT */
#include "SnapintoshQCC2072.h"
#include <SnapintoshQCC2072Interface.h>
#include "IO80211WorkQueue26A428.h"
#include "qcc2072-provider.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/crypto/rand.h>
#include "native-wpa2-crypto.h"
#include <kern/clock.h>
// The SDK's event-source init overloads trip -Woverloaded-virtual under -Werror.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#include <IOKit/IOTimerEventSource.h>
#pragma clang diagnostic pop

#define super IO80211Controller
OSDefineMetaClassAndStructors(SnapintoshQCC2072, IO80211Controller)

static const unsigned kPollMS = 5;

bool SnapintoshQCC2072::createWorkQueue()
{
    if (queue_) return true;
    IO80211WorkQueue *queue = snapIO80211WorkQueueCreate();
    if (!queue) return false;
    // The factory constructs the IOWorkLoop base at the object's own address.
    OSObject *object = reinterpret_cast<OSObject *>(queue);
    // The first queue is the family's unretained default: leave that original
    // reference to the global for the kernel's lifetime and take our own.
    if (queue == snapIO80211DefaultWorkQueue()) object->retain();
    IOWorkLoop *loop = OSDynamicCast(IOWorkLoop, object);
    if (!loop) { object->release(); return false; }
    queue_ = queue;
    loop_ = loop;
    return true;
}

IO80211WorkQueue *SnapintoshQCC2072::getWorkQueue() const
{
    return queue_;
}

bool SnapintoshQCC2072::start(IOService *provider)
{
    setProperty("SnapintoshQCC2072Milestone", "native-controller-lifecycle");
    setProperty("NativeWiFiRuntimeQualified", false);
    setProperty("FirmwareReady", false);
    setProperty("NativeStationReady", false);
    setProperty("NativeInterfacePublished", false);
    setProperty("TransportQuarantined", false);
    if (!provider || !super::start(provider)) return false;
    // The base start, the poll timer and every provider call share one queue.
    if (!loop_ || getWorkLoop() != loop_) { super::stop(provider); return false; }
    timer_ = IOTimerEventSource::timerEventSource(this, &SnapintoshQCC2072::pollTimer);
    if (!timer_) { super::stop(provider); return false; }
    if (loop_->addEventSource(timer_) != kIOReturnSuccess) {
        removeTimer();
        super::stop(provider);
        return false;
    }
    timerAdded_ = true;
    static const snap_station_ops ops = {
        &SnapintoshQCC2072::stationSubmit, &SnapintoshQCC2072::stationCancel,
        &SnapintoshQCC2072::stationStop, &SnapintoshQCC2072::stationEvent,
        &SnapintoshQCC2072::stationControl
    };
    snap_station_init(&station_, &ops, this);
    // WPA2 connect engine (re/connect/FAILURES.md 24, 26, 43): copies inside
    // callbacks, acts in pollTimer after the provider poll returned.
    const qcc2072_connect_ops connectOps = {
        this, &SnapintoshQCC2072::connectTransmit, &SnapintoshQCC2072::connectRandom,
        &SnapintoshQCC2072::connectAdmit, &SnapintoshQCC2072::connectSecurity,
        &SnapintoshQCC2072::connectDisconnect, &SnapintoshQCC2072::connectNote
    };
    qcc2072_connect_init(&connect_, &station_, &connectOps);
    if (loop_->runAction(&SnapintoshQCC2072::gatedPrepare, this, provider) != kIOReturnSuccess ||
        !provider_) {
        removeTimer();
        super::stop(provider);
        return false;
    }
    generation_ = qcc2072_provider_generation(provider_);
    // From here DMA may be running: keep this object, the provider and its
    // mappings until stop observes actual quiescence.
    retain();
    retainedSelf_ = true;
    if (loop_->runAction(&SnapintoshQCC2072::gatedBegin, this) != kIOReturnSuccess) {
        if (loop_->runAction(&SnapintoshQCC2072::gatedStop, this) != kIOReturnSuccess) {
            IOLog("SnapintoshQCC2072: firmware boot failed; transport quarantined\n");
            return true;
        }
        removeTimer();
        super::stop(provider);
        retainedSelf_ = false;
        release();
        return false;
    }
    polling_ = true;
    timer_->setTimeoutMS(kPollMS);
    return true;
}

void SnapintoshQCC2072::stop(IOService *provider)
{
    if (stopped_ || !loop_) return;
    // A failed stop keeps every object, the base and the self reference.
    // A later stop retries the same generation.
    if (provider_ && loop_->runAction(&SnapintoshQCC2072::gatedStop, this) != kIOReturnSuccess)
        return;
    removeTimer();
    stopped_ = true;
    quarantined_ = false;
    setProperty("FirmwareReady", false);
    setProperty("NativeStationReady", false);
    setProperty("TransportQuarantined", false);
    super::stop(provider);
    if (retainedSelf_) {
        retainedSelf_ = false;
        release();
    }
}

void SnapintoshQCC2072::free()
{
    // Reached only before DMA began or after actual quiescence: a running
    // provider holds the self reference taken in start.
    removeTimer();
    if (queue_) {
        reinterpret_cast<OSObject *>(queue_)->release();
        queue_ = nullptr;
        loop_ = nullptr;
    }
    super::free();
}

void SnapintoshQCC2072::removeTimer()
{
    if (!timer_) return;
    timer_->cancelTimeout();
    if (timerAdded_) loop_->removeEventSource(timer_);
    timerAdded_ = false;
    timer_->release();
    timer_ = nullptr;
}

void SnapintoshQCC2072::quarantine()
{
    quarantined_ = true;
    polling_ = false;
    // Tell IO80211/WCL the driver is gone before any request can reach it.
    if (interface_) interface_->announceDriverUnavailable();
    if (timer_) timer_->cancelTimeout();
    setProperty("TransportQuarantined", true);
}

IOReturn SnapintoshQCC2072::gatedPrepare(OSObject *target, void *provider, void *, void *, void *)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, target);
    if (!self || !provider || self->provider_) return kIOReturnBadArgument;
    const qcc2072_provider_callbacks callbacks = {
        self, &SnapintoshQCC2072::providerState,
        &SnapintoshQCC2072::providerStationReady, &SnapintoshQCC2072::providerStationEvent,
        &SnapintoshQCC2072::providerLog
    };
    IOReturn rc = qcc2072_provider_prepare(static_cast<IOService *>(provider), &callbacks, &self->provider_);
    if (rc != kIOReturnSuccess || !self->provider_) return rc;
    // dp-io frames: EAPOL for the connect engine (copied, handled after poll). Other data has
    // no host network stack yet and is counted, never forwarded.
    const qcc2072_dpio_callbacks data = {self, &SnapintoshQCC2072::dataReceived, &SnapintoshQCC2072::dataSent};
    return qcc2072_provider_data_attach(self->provider_, &data) ? kIOReturnNotReady : kIOReturnSuccess;
}

IOReturn SnapintoshQCC2072::gatedBegin(OSObject *target, void *, void *, void *, void *)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, target);
    if (!self || !self->provider_) return kIOReturnNotReady;
    return qcc2072_provider_begin(self->provider_);
}

IOReturn SnapintoshQCC2072::gatedStop(OSObject *target, void *, void *, void *, void *)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, target);
    if (!self || !self->provider_) return kIOReturnNotReady;
    self->polling_ = false;
    if (self->timer_) self->timer_->cancelTimeout();
    qcc2072_connect_abort(&self->connect_);   // wipes the PMK and handshake state
    // An admitted (or previously failed) station stops through its bridge,
    // which ends pending requests only after the provider reports quiescence.
    int status = self->station_.admitted || self->station_.quarantined
        ? snap_station_stop(&self->station_)
        : qcc2072_provider_stop(self->provider_, self->generation_);
    if (status != SNAP_STATION_OK) {
        self->quarantine();
        return kIOReturnBusy;
    }
    if (self->interface_) {
        if (self->interface_->shutdown(self) != kIOReturnSuccess) {
            self->quarantine();
            return kIOReturnBusy;
        }
        if (self->interfacePublished_) self->detachInterface(self->interface_, false);
        if (self->interfaceAttached_) self->interface_->detach(self);
        self->interface_->release();
        self->interface_ = nullptr;
        self->interfaceAttached_ = self->interfacePublished_ = false;
        self->setProperty("NativeInterfacePublished", false);
    }
    IOReturn released = qcc2072_provider_release(self->provider_);
    if (released != kIOReturnSuccess) {
        self->quarantine();
        return released;
    }
    self->provider_ = nullptr;
    return kIOReturnSuccess;
}

void SnapintoshQCC2072::pollTimer(OSObject *owner, IOTimerEventSource *sender)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, owner);
    if (!self || !self->polling_ || !self->provider_) return;
    if (qcc2072_provider_poll(self->provider_) != kIOReturnSuccess) {
        qcc2072_connect_abort(&self->connect_);
        self->quarantine();
        return;
    }
    // Outside the provider poll and every callback: snap_wpa2 may submit key controls now.
    (void)qcc2072_connect_service(&self->connect_, nowMS());
    if (self->polling_) sender->setTimeoutMS(kPollMS);
}

void SnapintoshQCC2072::providerState(void *context, unsigned state, int reason)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    (void)reason;
    if (state == QCC2072_PROVIDER_QUARANTINE) {
        self->quarantine();
        return;
    }
    if (state == QCC2072_PROVIDER_FW_READY || state == QCC2072_PROVIDER_WLAN_CONFIG ||
        state == QCC2072_PROVIDER_HTC || state == QCC2072_PROVIDER_HTC_SETUP)
        self->setProperty("FirmwareReady", true);
}

void SnapintoshQCC2072::providerStationReady(void *context, const snap_station_ready *ready)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    if (!ready || ready->generation != self->generation_ || self->interface_ ||
        self->quarantined_) return;
    if (snap_station_admit(&self->station_, ready) != SNAP_STATION_OK) return;
    self->setProperty("FirmwareReady", true);
    self->setProperty("NativeStationReady", true);
    auto *interface = new SnapintoshQCC2072Interface;
    if (!interface) return;
    if (!interface->init()) { interface->release(); return; }
    self->interface_ = interface;
    uint32_t build = 0;
    if (qcc2072_provider_firmware_build(self->provider_, &build) == SNAP_STATION_OK)
        interface->noteFirmwareBuild(build);
    bool bound = interface->bindStation(&self->station_, qcc2072_provider_channel, self->provider_);
    bool attached = bound && interface->attach(self);
    self->interfaceAttached_ = attached;
    bool started = attached && interface->start(self);
    if (started && self->attachInterface(interface, self)) {
        self->interfacePublished_ = true;
        self->setProperty("NativeInterfacePublished", true);
        interface->registerService();
        // RESET_INTERFACE(1), DRIVER_AVAILABLE(1), POWER_CHANGED (re/wifi-ui).
        if (interface->announceDriverReady() != kIOReturnSuccess)
            IOLog("SnapintoshQCC2072: native Wi-Fi announcement refused\n");
        return;
    }
    if (interface->shutdown(self) != kIOReturnSuccess) {
        self->quarantine();
        return;
    }
    if (attached) interface->detach(self);
    interface->release();
    self->interface_ = nullptr;
    self->interfaceAttached_ = false;
}

void SnapintoshQCC2072::providerStationEvent(void *context, const struct snap_station_event *event)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    if (snap_station_event(&self->station_, event) != SNAP_STATION_OK) ++self->droppedEvents_;
}

int SnapintoshQCC2072::stationSubmit(void *context, const snap_station_request *request)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return qcc2072_provider_submit(self->provider_, request);
}

int SnapintoshQCC2072::stationCancel(void *context, uint64_t generation, uint64_t transaction)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return qcc2072_provider_cancel(self->provider_, generation, transaction);
}

int SnapintoshQCC2072::stationStop(void *context, uint64_t generation)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return qcc2072_provider_stop(self->provider_, generation);
}

int SnapintoshQCC2072::stationControl(void *context, const snap_station_control *control)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return qcc2072_provider_control(self->provider_, control);
}

void SnapintoshQCC2072::stationEvent(void *context, const struct snap_station_event *event)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    qcc2072_connect_station_event(&self->connect_, event);   // copy only
    if (!self->interface_ || !self->interfacePublished_ ||
        self->interface_->publishStationEvent(event) != kIOReturnSuccess)
        ++self->droppedEvents_;
}

uint64_t SnapintoshQCC2072::nowMS()
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000000;
}

void SnapintoshQCC2072::providerLog(void *, const char *line)
{
    IOLog("SnapintoshQCC2072: %s\n", line);
}

void SnapintoshQCC2072::dataReceived(void *context, const uint8_t *frame, size_t length,
                                    const struct qcc2072_dpio_rx_info *)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    if (!qcc2072_connect_rx(&self->connect_, frame, length)) ++self->droppedFrames_;
}

void SnapintoshQCC2072::dataSent(void *context, const struct qcc2072_dpio_tx_result *result)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    if (result) (void)qcc2072_connect_tx_done(&self->connect_, result->tag, result->status);
}

int SnapintoshQCC2072::connectTransmit(void *context, const uint8_t *frame, size_t length, uint64_t tag)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    // EAPOL, M4 included, always without QCC2072_DPIO_TX_PROTECTED: dp-io sends it unencrypted
    // (RAW+OPEN with Ethernet encap, no protected bit with native wifi, the A16 case).
    return self->provider_ ? qcc2072_provider_data_tx(self->provider_, frame, length, tag, 0, 0) : SNAP_STATION_NOT_READY;
}

int SnapintoshQCC2072::connectRandom(void *, uint8_t *out, size_t length)
{
    return random_buf(out, length) ? SNAP_STATION_NOT_READY : SNAP_STATION_OK;
}

int SnapintoshQCC2072::connectAdmit(void *context, const uint8_t *frame, size_t length, int transmit)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return self->provider_ ? qcc2072_provider_eapol_admit(self->provider_, frame, length, transmit) : SNAP_STATION_NOT_READY;
}

int SnapintoshQCC2072::connectSecurity(void *context, struct snap_wpa2_ap *ap)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return self->provider_ ? qcc2072_provider_link_security(self->provider_, ap) : SNAP_STATION_NOT_READY;
}

int SnapintoshQCC2072::connectDisconnect(void *context, uint64_t link, uint16_t reason)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    return self->provider_ ? qcc2072_provider_disconnect(self->provider_, self->generation_, link, reason)
                           : SNAP_STATION_NOT_READY;
}

void SnapintoshQCC2072::connectNote(void *context, unsigned code, int64_t a, int64_t b)
{
    auto *self = static_cast<SnapintoshQCC2072 *>(context);
    (void)self;
    IOLog("SnapintoshQCC2072: connect %s %lld %lld state %s wpa2 phase %u reason %s\n",
          qcc2072_connect_note_name(code), (long long)a, (long long)b,
          qcc2072_connect_state_name(self->connect_.state), self->connect_.wpa.phase,
          snap_wpa2_reason(self->connect_.wpa.reason));
}

struct JoinArgs {
    const uint8_t *ssid, *bssid;
    uint8_t *pmk;
    uint8_t ssidLength;
    uint16_t frequency;
};

IOReturn SnapintoshQCC2072::gatedJoin(OSObject *target, void *argument, void *, void *, void *)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, target);
    auto *join = static_cast<JoinArgs *>(argument);
    if (!self || !join || !self->provider_ || !self->station_.admitted || self->quarantined_) return kIOReturnNotReady;
    snap_station_request &request = self->joinRequest_;
    memset(&request, 0, sizeof(request));
    request.transaction = self->station_.last_transaction + 1;
    request.type = SNAP_STATION_CONNECT;
    request.ssid_length = join->ssidLength;
    memcpy(request.ssid, join->ssid, join->ssidLength);
    memcpy(request.bssid, join->bssid, 6);
    if (join->frequency) { request.channel_count = 1; request.channels_mhz[0] = join->frequency; }
    // Our own RSN element (WPA2-PSK, CCMP, no PMF); the AP's comes from the scan cache.
    request.ie_length = SNAP_RSN_OWN_LENGTH;
    memcpy(request.ies, snap_rsn_own, SNAP_RSN_OWN_LENGTH);
    int rc = snap_station_submit(&self->station_, &request);
    if (rc == SNAP_STATION_OK)
        rc = qcc2072_connect_arm(&self->connect_, request.transaction, join->bssid, self->station_.ready.mac, join->pmk);
    IOLog("SnapintoshQCC2072: join transaction %llu -> %d\n", (unsigned long long)request.transaction, rc);
    return rc == SNAP_STATION_OK ? kIOReturnSuccess : kIOReturnError;
}

IOReturn SnapintoshQCC2072::stationJoin(const uint8_t *ssid, uint8_t ssidLength, const uint8_t bssid[6],
                                        uint16_t frequencyMHz, uint8_t pmk[32])
{
    IOReturn rc = kIOReturnBadArgument;
    if (ssid && ssidLength && ssidLength <= 32 && bssid && pmk && loop_) {
        JoinArgs join = {ssid, bssid, pmk, ssidLength, frequencyMHz};
        rc = loop_->runAction(&SnapintoshQCC2072::gatedJoin, this, &join);
    }
    if (pmk) snap_wpa2_clear(pmk, 32);
    return rc;
}

IOReturn SnapintoshQCC2072::gatedLeave(OSObject *target, void *reason, void *, void *, void *)
{
    auto *self = OSDynamicCast(SnapintoshQCC2072, target);
    if (!self || !self->station_.associated) return kIOReturnNotReady;
    snap_station_control control;
    memset(&control, 0, sizeof(control));
    control.generation = self->station_.generation;
    control.transaction = self->station_.last_transaction + 1;
    control.link_transaction = self->station_.link_transaction;
    control.type = SNAP_STATION_LINK_DISCONNECT;
    uint16_t code = static_cast<uint16_t>(reinterpret_cast<uintptr_t>(reason));
    control.reason = code ? code : 3;
    return snap_station_control_submit(&self->station_, &control) == SNAP_STATION_OK ? kIOReturnSuccess : kIOReturnBusy;
}

IOReturn SnapintoshQCC2072::stationLeave(uint16_t reason)
{
    if (!loop_) return kIOReturnNotReady;
    return loop_->runAction(&SnapintoshQCC2072::gatedLeave, this, reinterpret_cast<void *>(static_cast<uintptr_t>(reason)));
}

bool SnapintoshQCC2072::isCommandProhibited(int command)
{
    // Every exact 26A428 apple80211 handler returns this value as its error
    // (0 allows). Allow only while our interface exists and its station is
    // admitted and unquarantined; each method still refuses what it cannot
    // answer truthfully (re/wifi-ui/FAILURES.md 1).
    return !interface_ || quarantined_ || !interface_->snapCommandAllowed(command);
}

SInt32 SnapintoshQCC2072::handleCardSpecific(IO80211SkywalkInterface *, unsigned long,
                                          void *, bool)
{
    return kIOReturnNotReady;
}

// Payloads are answered only by the native interface, whose exact 26A428
// layouts and truth rules are in re/wifi-ui (ABI-26A428.md, FAILURES.md).
// Never fabricate capability, power, country, scan or connection success.
IOReturn SnapintoshQCC2072::getDRIVER_VERSION(IO80211SkywalkInterface *i, apple80211_version_data *d)
{ return interface_ ? interface_->snapGetDriverVersion(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::getHARDWARE_VERSION(IO80211SkywalkInterface *i, apple80211_version_data *d)
{ return interface_ ? interface_->snapGetHardwareVersion(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::getCARD_CAPABILITIES(IO80211SkywalkInterface *i, apple80211_capability_data *d)
{ return interface_ ? interface_->snapGetCardCapabilities(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::getPOWER(IO80211SkywalkInterface *i, apple80211_power_data *d)
{ return interface_ ? interface_->snapGetPower(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::setPOWER(IO80211SkywalkInterface *i, apple80211_power_data *d)
{ return interface_ ? interface_->snapSetPower(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::getCOUNTRY_CODE(IO80211SkywalkInterface *i, apple80211_country_code_data *d)
{ return interface_ ? interface_->snapGetCountryCode(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::setCOUNTRY_CODE(IO80211SkywalkInterface *i, apple80211_country_code_data *d)
{ return interface_ ? interface_->snapSetCountryCode(i, d) : kIOReturnNotReady; }
IOReturn SnapintoshQCC2072::setGET_DEBUG_INFO(IO80211SkywalkInterface *, apple80211_debug_command *)
{ return kIOReturnNotReady; }
CCLogStream *SnapintoshQCC2072::getLogger() const
{ return nullptr; }
CommonFaultReporter *SnapintoshQCC2072::getFaultReporterFromDriver()
{ return nullptr; }
