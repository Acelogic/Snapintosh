/* SPDX-License-Identifier: MIT */
#ifndef SNAPINTOSH_QCC2072_H
#define SNAPINTOSH_QCC2072_H

#include "IO80211Controller26A428.h"
#include "native-station.h"
#include "qcc2072-connect.h"

class IOTimerEventSource;
class SnapintoshQCC2072Interface;
struct qcc2072_provider;

// Native Wi-Fi controller. It starts the admitted chipset transport on the
// IO80211 work queue and admits a native station only from provider-observed
// WMI facts. Native registration uses the exact Skywalk queue/pool contracts.
// Datapath readiness remains separate from interface publication. Lifecycle rules:
// re/native-controller/FAILURES-AND-REPLAY.md.
class SnapintoshQCC2072 : public IO80211Controller {
    OSDeclareDefaultStructors(SnapintoshQCC2072)
public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    bool createWorkQueue() override;
    IO80211WorkQueue *getWorkQueue() const override;
    bool isCommandProhibited(int command) override;
    SInt32 handleCardSpecific(IO80211SkywalkInterface *, unsigned long, void *, bool) override;
    IOReturn getDRIVER_VERSION(IO80211SkywalkInterface *, apple80211_version_data *) override;
    IOReturn getHARDWARE_VERSION(IO80211SkywalkInterface *, apple80211_version_data *) override;
    IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *, apple80211_capability_data *) override;
    IOReturn getPOWER(IO80211SkywalkInterface *, apple80211_power_data *) override;
    IOReturn setPOWER(IO80211SkywalkInterface *, apple80211_power_data *) override;
    IOReturn getCOUNTRY_CODE(IO80211SkywalkInterface *, apple80211_country_code_data *) override;
    IOReturn setCOUNTRY_CODE(IO80211SkywalkInterface *, apple80211_country_code_data *) override;
    IOReturn setGET_DEBUG_INFO(IO80211SkywalkInterface *, apple80211_debug_command *) override;
    CCLogStream *getLogger() const override;
    CommonFaultReporter *getFaultReporterFromDriver() override;
    // WPA2-PSK join on the controller's work queue: the same snap_station -> provider ->
    // qcc2072-connect -> snap_wpa2 path the host-proxy harness runs. The PMK comes from the
    // join request and is wiped here; EAPOL is never sent protected. Waiting for the
    // 26A428 apple80211AssocCandidates layout before setWCL_ASSOCIATE can call it.
    IOReturn stationJoin(const uint8_t *ssid, uint8_t ssidLength, const uint8_t bssid[6],
                         uint16_t frequencyMHz, uint8_t pmk[32]);
    IOReturn stationLeave(uint16_t reason);

protected:
    void free() override;

private:
    static IOReturn gatedPrepare(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedBegin(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedStop(OSObject *, void *, void *, void *, void *);
    static void pollTimer(OSObject *, IOTimerEventSource *);
    static void providerState(void *, unsigned state, int reason);
    static void providerStationReady(void *, const snap_station_ready *);
    static void providerStationEvent(void *, const struct snap_station_event *);
    static int stationSubmit(void *, const snap_station_request *);
    static int stationCancel(void *, uint64_t generation, uint64_t transaction);
    static int stationStop(void *, uint64_t generation);
    static int stationControl(void *, const snap_station_control *);
    static void stationEvent(void *, const struct snap_station_event *);
    static void providerLog(void *, const char *);
    static void dataReceived(void *, const uint8_t *, size_t, const struct qcc2072_dpio_rx_info *);
    static void dataSent(void *, const struct qcc2072_dpio_tx_result *);
    static int connectTransmit(void *, const uint8_t *, size_t, uint64_t);
    static int connectRandom(void *, uint8_t *, size_t);
    static int connectAdmit(void *, const uint8_t *, size_t, int);
    static int connectSecurity(void *, struct snap_wpa2_ap *);
    static int connectDisconnect(void *, uint64_t, uint16_t);
    static void connectNote(void *, unsigned, int64_t, int64_t);
    static IOReturn gatedJoin(OSObject *, void *, void *, void *, void *);
    static IOReturn gatedLeave(OSObject *, void *, void *, void *, void *);
    static uint64_t nowMS();
    void quarantine();
    void removeTimer();

    IO80211WorkQueue *queue_ = nullptr;
    IOWorkLoop *loop_ = nullptr;
    IOTimerEventSource *timer_ = nullptr;
    qcc2072_provider *provider_ = nullptr;
    SnapintoshQCC2072Interface *interface_ = nullptr;
    bool interfaceAttached_ = false, interfacePublished_ = false;
    snap_station station_;
    qcc2072_connect connect_;
    snap_station_request joinRequest_;   // borrowed by snap_station until the connect ends
    uint64_t generation_ = 0;
    uint32_t droppedEvents_ = 0, droppedFrames_ = 0;
    bool timerAdded_ = false, polling_ = false, retainedSelf_ = false;
    bool quarantined_ = false, stopped_ = false;
};

#endif
