/* SPDX-License-Identifier: MIT */
#include "SnapintoshQCC2072Interface.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#include <IOKit/IOEventSource.h>
#pragma clang diagnostic pop
#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(SnapintoshQCC2072Interface, IO80211InfraProtocol)
bool SnapintoshQCC2072Interface::init() {
    station_ = nullptr; resolve_ = nullptr; resolveContext_ = nullptr; transaction_ = 0;
    scanTransaction_ = scanGeneration_ = 0; nativeStarted_ = false;
    return super::init();
}
bool SnapintoshQCC2072Interface::bindStation(struct snap_station *s,
        snap_wcl_channel_resolver resolver, void *context) {
    if (station_ || !s || !resolver) return false;
    station_ = s; resolve_ = resolver; resolveContext_ = context;
    transaction_ = s->last_transaction;
    return true;
}
unsigned SnapintoshQCC2072Interface::txUnavailable(OSObject *, IOSkywalkTxSubmissionQueue *,
        IOSkywalkPacket *const *, unsigned, void *) {
    // Zero packets accepted: no DMA/firmware data path owns these buffers yet.
    return 0;
}
unsigned SnapintoshQCC2072Interface::rxUnavailable(OSObject *, IOSkywalkRxSubmissionQueue *,
        IOSkywalkPacket *const *, unsigned, void *) {
    return 0;
}
bool SnapintoshQCC2072Interface::start(IOService *provider) {
    if (!provider || nativeLoop_ || !station_ || !station_->admitted ||
        station_->quarantined || !resolve_) return false;
    nativeLoop_ = provider->getWorkLoop();
    if (!nativeLoop_) return false;
    nativeLoop_->retain();
    alignas(2) uint8_t mac[6];
    memcpy(mac, station_->ready.mac, sizeof(mac));
    // The second init resets only Skywalk ivars, before any agent owns them.
    if (!IO80211SkywalkInterface::init(provider, reinterpret_cast<ether_addr *>(mac))) return false;
    snapSkywalkSetRole(this, 1);
    snapSkywalkSetId(this, 0);
    setHardwareAddress(reinterpret_cast<ether_addr *>(mac));
    baseStartAttempted_ = true;
    if (!super::start(provider)) return false;

    const snap_skywalk_pool_options options = {256, 256, 2048, 1, 16384, 0, {0, 0}};
    txPool_ = snapSkywalkPoolCreate("QCC2072-TX", this, 1, &options);
    rxPool_ = snapSkywalkPoolCreate("QCC2072-RX", this, 1, &options);
    if (!txPool_ || !rxPool_) return false;
    packetQueues_[0] = reinterpret_cast<IOSkywalkPacketQueue *>(
        snapSkywalkTxCreate(txPool_, 256, 0, this, &txUnavailable, this, 0));
    packetQueues_[1] = reinterpret_cast<IOSkywalkPacketQueue *>(
        snapSkywalkTxCompletionCreate(txPool_, 256, 1, this, nullptr, this, 0));
    packetQueues_[2] = reinterpret_cast<IOSkywalkPacketQueue *>(
        snapSkywalkRxSubmissionCreate(rxPool_, 2048, 256, 2, this, &rxUnavailable, this, 0));
    packetQueues_[3] = reinterpret_cast<IOSkywalkPacketQueue *>(
        snapSkywalkRxCreate(rxPool_, 256, 3, this, nullptr, this, 0));
    for (unsigned i = 0; i != 4; ++i) {
        if (!packetQueues_[i]) return false;
        // Exact factories construct their IOEventSource base at offset zero.
        auto *source = OSDynamicCast(IOEventSource,
            reinterpret_cast<OSObject *>(packetQueues_[i]));
        if (!source || nativeLoop_->addEventSource(source) != kIOReturnSuccess) return false;
        queueAdded_ |= 1U << i;
    }
    snap_skywalk_registration info = {};
    if (!snapSkywalkInitRegistration(this, &info, 1, sizeof(info))) return false;
    const uint32_t wifi = 3, interfaceType = 2, role = 1, media = 0x80;
    const uint16_t headroom = 0x40;
    memcpy(info.bytes + 0x0c, &wifi, sizeof(wifi));
    memcpy(info.bytes + 0x10, &role, sizeof(role));
    memcpy(info.bytes + 0x14, &interfaceType, sizeof(interfaceType));
    memcpy(info.bytes + 0x24, &media, sizeof(media));
    memcpy(info.bytes + 0x28, &media, sizeof(media));
    memcpy(info.bytes + 0x3c, &headroom, sizeof(headroom));
    memcpy(info.bytes + 0x108, mac, sizeof(mac));
    registrationAttempted_ = true;
    if (snapSkywalkRegister(this, &info, packetQueues_, 4, txPool_, rxPool_) != kIOReturnSuccess)
        return false;
    nativeStarted_ = true;
    setProperty("NativeWiFiRuntimeQualified", false);
    setProperty("NativeDataPathReady", false);
    setProperty("NativeWiFiAnnounced", false);
    setProperty("NativeRadioPowerDownImplemented", false);
    setProperty("NativeRSSIModel", "uncalibrated: firmware SNR + -95 dBm (ath12k default noise floor)");
    publishScanCounters();
    return true;
}
void SnapintoshQCC2072Interface::releasePacketResources() {
    for (unsigned i = 4; i-- != 0;) {
        if (!packetQueues_[i]) continue;
        if (queueAdded_ & (1U << i))
            nativeLoop_->removeEventSource(reinterpret_cast<IOEventSource *>(packetQueues_[i]));
        queueAdded_ &= ~(1U << i);
        reinterpret_cast<OSObject *>(packetQueues_[i])->release();
        packetQueues_[i] = nullptr;
    }
    if (rxPool_) { reinterpret_cast<OSObject *>(rxPool_)->release(); rxPool_ = nullptr; }
    if (txPool_) { reinterpret_cast<OSObject *>(txPool_)->release(); txPool_ = nullptr; }
    if (nativeLoop_) { nativeLoop_->release(); nativeLoop_ = nullptr; }
}
IOReturn SnapintoshQCC2072Interface::shutdown(IOService *provider) {
    nativeStarted_ = false;
    announced_ = false;
    announcedGeneration_ = 0;
    if (registrationAttempted_) {
        IOReturn status = snapSkywalkDeregister(this, 0);
        if (status != kIOReturnSuccess) return status;
        registrationAttempted_ = false;
    }
    releasePacketResources();
    if (baseStartAttempted_) { super::stop(provider); baseStartAttempted_ = false; }
    scanTransaction_ = scanGeneration_ = 0;
    station_ = nullptr; resolve_ = nullptr; resolveContext_ = nullptr;
    return kIOReturnSuccess;
}
void SnapintoshQCC2072Interface::stop(IOService *provider) {
    // The controller keeps its ownership if deregistration cannot finish.
    (void)shutdown(provider);
}
void SnapintoshQCC2072Interface::free() {
    releasePacketResources();
    station_ = nullptr; resolve_ = nullptr; resolveContext_ = nullptr;
    super::free();
}
static IOReturn nativeStatus(int status) {
    switch (status) {
    case SNAP_STATION_OK: return kIOReturnSuccess;
    case SNAP_STATION_INVALID: return kIOReturnBadArgument;
    case SNAP_STATION_BUSY: return kIOReturnBusy;
    case SNAP_STATION_UNSUPPORTED: return kIOReturnUnsupported;
    default: return kIOReturnNotReady;
    }
}

// ---- Wi-Fi menu bring-up (re/wifi-ui/FAILURES.md, re/wifi-ui/ABI-26A428.md) ----
bool SnapintoshQCC2072Interface::radioAvailable() const {
    return station_ && station_->admitted && !station_->quarantined && !unavailable_;
}
bool SnapintoshQCC2072Interface::ownsRequest(IO80211SkywalkInterface *interface) const {
    // Controller-level requests name their interface; we answer only for us.
    return interface && interface == static_cast<const IO80211SkywalkInterface *>(this);
}
void SnapintoshQCC2072Interface::noteQuery(unsigned bit, const char *what, IOReturn status) {
    // One line per request kind and boot: enough to see what WCL asked for.
    if (queriesLogged_ & bit) return;
    queriesLogged_ |= bit;
    IOLog("SnapintoshQCC2072Interface: %s -> 0x%x\n", what, (unsigned)status);
}
IOReturn SnapintoshQCC2072Interface::channelList(struct snap_if_channel *channels,
                                                 unsigned *count) {
    if (!radioAvailable() || !resolve_) return kIOReturnNotReady;
    int status = snap_if_channels(resolve_, resolveContext_, channels,
                                  SNAP_IF_CHANNEL_CAPACITY, count);
    // An inconsistent resolver answer is our bug, not the caller's argument.
    return status == SNAP_STATION_INVALID ? kIOReturnError : nativeStatus(status);
}
bool SnapintoshQCC2072Interface::snapCommandAllowed(int type) const {
    // Apple's handlers return this gate's value as their error. Allowing a
    // type only lets the family reach our method, which still refuses what it
    // cannot answer truthfully.
    (void)type;
    return radioAvailable();
}
IOReturn SnapintoshQCC2072Interface::snapGetPower(IO80211SkywalkInterface *interface,
                                                  apple80211_power_data *data) {
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data) {
        // On means firmware READY with MAC/regulatory admitted, not quarantined.
        status = radioAvailable()
            ? nativeStatus(snap_if_power_encode(data, SNAP_IF_POWER_BYTES, SNAP_IF_POWER_ON))
            : kIOReturnNotReady;
    }
    noteQuery(1U << 16, "POWER get", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::snapSetPower(IO80211SkywalkInterface *interface,
                                                  apple80211_power_data *data) {
    uint32_t state = SNAP_IF_POWER_OFF;
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data &&
        snap_if_power_decode(data, SNAP_IF_POWER_BYTES, &state) == SNAP_STATION_OK) {
        if (!radioAvailable()) status = kIOReturnNotReady;
        else if (state == SNAP_IF_POWER_ON) status = kIOReturnSuccess;  // already on
        else status = kIOReturnUnsupported;  // no firmware power-down path yet
    }
    if (state == SNAP_IF_POWER_OFF && status == kIOReturnUnsupported)
        IOLog("SnapintoshQCC2072Interface: POWER off refused: no firmware power-down path\n");
    noteQuery(1U << 17, "POWER set", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::snapGetCardCapabilities(IO80211SkywalkInterface *interface,
                                                             apple80211_capability_data *data) {
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data)
        status = radioAvailable()
            ? nativeStatus(snap_if_capability_encode(data, SNAP_IF_CAPABILITY_BYTES))
            : kIOReturnNotReady;
    noteQuery(1U << 5, "CARD_CAPABILITIES", status);
    return status;
}
static size_t appendText(char *out, size_t at, size_t capacity, const char *text) {
    while (*text && at + 1 < capacity) out[at++] = *text++;
    out[at] = 0;
    return at;
}
IOReturn SnapintoshQCC2072Interface::snapGetDriverVersion(IO80211SkywalkInterface *interface,
                                                          apple80211_version_data *data) {
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data) {
        char text[96];
        size_t at = appendText(text, 0, sizeof(text), "SnapintoshQCC2072 0.1.0");
        if (firmwareBuildKnown_) {
            // WMI SERVICE_READY fw_build, reported verbatim in hexadecimal.
            static const char digits[] = "0123456789abcdef";
            char build[11] = {'0', 'x'};
            for (unsigned i = 0; i < 8; ++i)
                build[2 + i] = digits[(firmwareBuild_ >> (28 - 4 * i)) & 15];
            build[10] = 0;
            at = appendText(text, at, sizeof(text), "; firmware build ");
            at = appendText(text, at, sizeof(text), build);
        }
        status = radioAvailable()
            ? nativeStatus(snap_if_version_encode(data, SNAP_IF_VERSION_BYTES, text))
            : kIOReturnNotReady;
    }
    noteQuery(1U << 6, "DRIVER_VERSION", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::snapGetHardwareVersion(IO80211SkywalkInterface *interface,
                                                            apple80211_version_data *data) {
    // Identity is established by provider admission of the QCC2072 images.
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data)
        status = radioAvailable()
            ? nativeStatus(snap_if_version_encode(data, SNAP_IF_VERSION_BYTES, "Qualcomm QCC2072"))
            : kIOReturnNotReady;
    noteQuery(1U << 7, "HARDWARE_VERSION", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::snapGetCountryCode(IO80211SkywalkInterface *interface,
                                                        apple80211_country_code_data *data) {
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data) {
        status = kIOReturnNotReady;
        if (radioAvailable() && (station_->ready.observed & SNAP_STATION_READY_REGULATORY))
            status = nativeStatus(snap_if_country_encode(data, SNAP_IF_COUNTRY_BYTES,
                                                         station_->ready.country));
    }
    noteQuery(1U << 8, "COUNTRY_CODE get", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::snapSetCountryCode(IO80211SkywalkInterface *interface,
                                                        apple80211_country_code_data *data) {
    // The firmware regulatory domain cannot be changed here: accept only the
    // country the firmware already reported (FAILURES.md 7).
    IOReturn status = kIOReturnBadArgument;
    if (ownsRequest(interface) && data) {
        status = kIOReturnNotReady;
        if (radioAvailable() && (station_->ready.observed & SNAP_STATION_READY_REGULATORY))
            status = nativeStatus(snap_if_country_matches(data, SNAP_IF_COUNTRY_BYTES,
                                                          station_->ready.country));
    }
    noteQuery(1U << 9, "COUNTRY_CODE set", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::postBringUp(uint32_t message, const void *payload,
                                                 size_t bytes) {
    // IO80211InfraInterface::postMessage copies synchronously; true selects
    // the WCL route as AppleBCMWLANCore does for these messages. It is void:
    // posting proves submission only (WCL may log "glue is not active").
    postMessage(message, const_cast<void *>(payload), bytes, true);
    return kIOReturnSuccess;
}
IOReturn SnapintoshQCC2072Interface::announceDriverReady() {
    if (!nativeStarted_ || !radioAvailable()) return kIOReturnNotReady;
    if (announced_ && announcedGeneration_ == station_->generation) return kIOReturnSuccess;
    uint8_t reset[SNAP_IF_RESET_INTERFACE_BYTES];
    snap_if_put32(reset, SNAP_IF_RESET_FW_LOADED);
    uint8_t available[SNAP_IF_DRIVER_AVAILABLE_BYTES];
    int status = snap_if_driver_available_encode(available, sizeof(available), 1,
                                                 SNAP_IF_DRIVER_AVAILABLE_POWER_ON_REASON);
    if (status != SNAP_STATION_OK) return nativeStatus(status);
    // Apple order: firmware loaded (WCL FW_LOADED: capabilities, MAC, channels),
    // driver available, then power changed so user space re-reads POWER.
    postBringUp(SNAP_IF_M_RESET_INTERFACE, reset, sizeof(reset));
    postBringUp(SNAP_IF_M_DRIVER_AVAILABLE, available, sizeof(available));
    postBringUp(SNAP_IF_M_POWER_CHANGED, nullptr, 0);
    announced_ = true;
    announcedGeneration_ = station_->generation;
    setProperty("NativeWiFiAnnounced", true);
    IOLog("SnapintoshQCC2072Interface: announced RESET_INTERFACE(1) DRIVER_AVAILABLE(1) "
          "POWER_CHANGED generation %llu\n", (unsigned long long)announcedGeneration_);
    return kIOReturnSuccess;
}
void SnapintoshQCC2072Interface::announceDriverUnavailable() {
    if (unavailable_) return;
    unavailable_ = true;
    if (nativeStarted_ && announced_) {
        uint8_t available[SNAP_IF_DRIVER_AVAILABLE_BYTES];
        if (snap_if_driver_available_encode(available, sizeof(available), 0, 0) == SNAP_STATION_OK)
            postBringUp(SNAP_IF_M_DRIVER_AVAILABLE, available, sizeof(available));
    }
    announced_ = false;
    setProperty("NativeWiFiAnnounced", false);
    IOLog("SnapintoshQCC2072Interface: driver unavailable (transport quarantined)\n");
}
void SnapintoshQCC2072Interface::noteFirmwareBuild(uint32_t build) {
    firmwareBuild_ = build;
    firmwareBuildKnown_ = true;
}
void SnapintoshQCC2072Interface::publishScanCounters() {
    setProperty("NativeScanResultsPublished", (uint64_t)scanResults_, 32);
    setProperty("NativeScanResultsUncalibratedRSSI", (uint64_t)scanResultsEstimated_, 32);
    setProperty("NativeScanResultsRefused", (uint64_t)scanResultsRefused_, 32);
    setProperty("NativeScanDonePublished", (uint64_t)scanDone_, 32);
}
IOReturn SnapintoshQCC2072Interface::setMacAddress(mloAddrArray&) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCHANNEL(apple80211_channel_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getPOWERSAVE(apple80211_powersave_data *data) {
    // No firmware power-save state is programmed or read back (FAILURES.md 16).
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 10, "POWERSAVE get", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getTXPOWER(apple80211_txpower_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getRATE(apple80211_rate_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getOP_MODE(apple80211_opmode_data *data) {
    // Exact AppleBCMWLANCore::getOP_MODE: 0 while unassociated; WCL refuses a
    // scan only for HOSTAP/MONITOR bits (FAILURES.md 10).
    IOReturn status = kIOReturnBadArgument;
    if (data) {
        status = kIOReturnNotReady;
        if (radioAvailable())
            status = nativeStatus(snap_if_opmode_encode(data, SNAP_IF_OPMODE_BYTES,
                station_->connected ? SNAP_IF_OPMODE_STA : SNAP_IF_OPMODE_NONE));
    }
    noteQuery(1U << 0, "OP_MODE", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getRSSI(apple80211_rssi_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getSUPPORTED_CHANNELS(apple80211_sup_channel_data *data) {
    struct snap_if_channel channels[SNAP_IF_CHANNEL_CAPACITY];
    unsigned count = 0;
    IOReturn status = data ? channelList(channels, &count) : kIOReturnBadArgument;
    if (status == kIOReturnSuccess)
        status = nativeStatus(snap_if_sup_channels_encode(data, SNAP_IF_SUP_CHANNEL_BYTES,
                                                          channels, count));
    noteQuery(1U << 1, "SUPPORTED_CHANNELS", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getGUARD_INTERVAL(apple80211_guard_interval_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMCS(apple80211_mcs_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getPOWER_DEBUG_INFO(apple80211_power_debug_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getHT_CAPABILITY(apple80211_ht_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMCS_VHT(apple80211_mcs_vht_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCHANNELS_INFO(apple80211_channels_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getVHT_CAPABILITY(apple80211_vht_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getROAM_PROFILE(apple80211_roam_profile_all_bands*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCHIP_COUNTER_STATS(apple80211_chip_stats*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCOUNTRY_CHANNELS(apple80211_country_channel_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getPRIVATE_MAC(apple80211_private_mac_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getRANGING_ENABLE(apple80211_ranging_enable_request_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getRANGING_START(apple80211_ranging_start_request_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getAWDL_RSDB_CAPS(apple80211_rsdb_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTKO_PARAMS(apple80211_tko_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTKO_DUMP(apple80211_tko_dump*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data *data) {
    // Only the firmware's configured set is known; nothing wider is claimed.
    struct snap_if_channel channels[SNAP_IF_CHANNEL_CAPACITY];
    unsigned count = 0;
    IOReturn status = data ? channelList(channels, &count) : kIOReturnBadArgument;
    if (status == kIOReturnSuccess)
        status = nativeStatus(snap_if_sup_channels_encode(data, SNAP_IF_SUP_CHANNEL_BYTES,
                                                          channels, count));
    noteQuery(1U << 2, "HW_SUPPORTED_CHANNELS", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getBTCOEX_PROFILE(apple80211_btcoex_profile*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTRAP_INFO(apple80211_trap_info_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTHERMAL_INDEX(apple80211_thermal_index_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMAX_NSS_FOR_AP(apple80211_btcoex_max_nss_for_ap_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getPOWER_BUDGET(apple80211_power_budget_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getRANGING_CAPS(apple80211_ranging_capabilities_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getLQM_CONFIG(apple80211_lqm_config_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTRAP_CRASHTRACER_MINI_DUMP(apple80211_trap_mini_dump_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getBEACON_INFO(apple80211_beacon_info_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCHIP_POWER_RANGE(apple80211_chip_power_limit*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getNSS(apple80211_nss_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getHW_ADDR(apple80211_hw_mac_address *data) {
    IOReturn status = kIOReturnBadArgument;
    if (data) {
        status = kIOReturnNotReady;
        if (radioAvailable())
            status = nativeStatus(snap_if_hw_addr_encode(data, SNAP_IF_HW_ADDR_BYTES,
                                                         station_->ready.mac));
    }
    noteQuery(1U << 3, "HW_ADDR", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getCHIP_DIAGS(appl80211_chip_diags_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getHP2P_CTRL(apple80211_hp2p_ctrl*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getBSS_BLACKLIST(bss_blacklist*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTXRX_CHAIN_INFO(apple80211_txrx_chain_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMIMO_STATUS(apple80211_mimo_status*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCUR_PMK(apple80211_pmk*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getDYNSAR_DETAIL(apple80211_dynsar_detail*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getCOUNTRY_CHANNELS_INFO(apple80211_channels_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getLQM_SUMMARY(apple80211_lqm_summary*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getSLOW_WIFI_FEATURE_ENABLED(apple80211_slow_wifi_feature_enabled*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTIMESYNC_INFO(apple80211_timesync_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_BSS_INFO(apple80211_beacon_msg*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_GET_TX_BLANKING_STATUS(unsigned int *data) {
    // WCL keeps scan status 0 when this query fails (sendScanCompleteEvent).
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 11, "TX_BLANKING_STATUS", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getHE_COUNTERS(apple80211_he_counters_ctl*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *data) {
    struct snap_if_channel channels[SNAP_IF_CHANNEL_CAPACITY];
    unsigned count = 0;
    IOReturn status = data ? channelList(channels, &count) : kIOReturnBadArgument;
    if (status == kIOReturnSuccess)
        status = nativeStatus(snap_if_wcl_channel_info_encode(
            data, SNAP_IF_WCL_CHANNEL_INFO_BYTES, channels, count));
    noteQuery(1U << 4, "WCL_CHANNELS_INFO", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::getRSN_XE(apple80211_rsn_xe_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getSIB_COEX_STATUS(apple80211_sib_coex_status*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_LOW_LATENCY_INFO_STATS(apple80211_wcl_low_latency_stats*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getWIFI_NOISE_PER_ANT(apple80211_noise_per_ant_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getFW_CLOCK_INFO(apple80211_fw_clock_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getTIMESYNC_STATS(apple80211_timesync_stats*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getSYSTEM_SLEEP_CONFIG(apple80211_system_sleep_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getSMARTCCA_OPMODE(apple80211_smartcca_opmode*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getLQM_STATISTICS(apple80211_lqm_statistics*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getHE_CAPABILITY(apple80211_he_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getDEVICE_ORIENTATION(apple80211_device_orientation*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getACCESSORY_STATE(apple80211_device_accessory_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getP2P_DEVICE_CAPABILITY(apple80211_p2p_device_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getPOWERTABLE_VERSION(apple80211_powertable_version_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMCS_HE(apple80211_mcs_he_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getMCS_BE(apple80211_mcs_be_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::getROAM_SLEEP_HISTORY(apple80211_roam_sleep_history*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setCIPHER_KEY(apple80211_key*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setCHANNEL(apple80211_channel_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setPOWERSAVE(apple80211_powersave_data *data) {
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 12, "POWERSAVE set", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::setTXPOWER(apple80211_txpower_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRATE(apple80211_rate_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setIBSS_MODE(apple80211_network_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setAP_MODE(apple80211_apmode_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setIE(apple80211_ie_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWOW_TEST(apple80211_wow_test_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setCLEAR_PMKSA_CACHE(void*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setHT_CAPABILITY(apple80211_ht_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setOFFLOAD_ARP(apple80211_offload_arp_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setOFFLOAD_NDP(apple80211_offload_ndp_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setGAS_REQ(apple80211_gas_query_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setVHT_CAPABILITY(apple80211_vht_capability*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setROAM_PROFILE(apple80211_roam_profile_all_bands*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setPRIVATE_MAC(apple80211_private_mac_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRESET_CHIP(apple80211_reset_command*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setCRASH(apple80211_crash_command*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRANGING_ENABLE(apple80211_ranging_enable_request_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRANGING_START(apple80211_ranging_start_request_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRANGING_AUTHENTICATE(apple80211_ranging_authenticate_request_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTKO_PARAMS(apple80211_tko_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBTCOEX_PROFILE(apple80211_btcoex_profile*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTHERMAL_INDEX(apple80211_thermal_index_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setPOWER_BUDGET(apple80211_power_budget_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setLQM_CONFIG(apple80211_lqm_config_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDYNAMIC_RSSI_WINDOW_CONFIG(apple80211_dynamic_rssi_window_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setUSB_HOST_NOTIFICATION(apple80211_usb_host_notification_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setHP2P_CTRL(apple80211_hp2p_ctrl*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBSS_BLACKLIST(bss_blacklist*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setSET_PROPERTY(apple80211_set_property_unserialized_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setROAM_CACHE_UPDATE(apple80211_roam_cache_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setPM_MODE(apple80211_pm_mode *data) {
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 13, "PM_MODE set", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::setREALTIME_QOS_MSCS(apple80211_state_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_LEAVE_NETWORK(apple80211_leave_network*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_REASSOC(apple80211_reassoc*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_LEGACY_ROAM_PROFILE_CONFIG(apple80211_legacy_roam_profile_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ROAM_PROFILE_CONFIG(apple80211_roam_profile_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ROAM_USER_CACHE(apple80211_user_roam_cache*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_SCAN_ABORT(void *request) {
    if (request) return kIOReturnUnsupported; // opaque optional abort payload
    if (!station_ || !station_->pending.type) return kIOReturnNotReady;
    return nativeStatus(snap_station_cancel(station_, station_->pending.transaction));
}
IOReturn SnapintoshQCC2072Interface::setWCL_REAL_TIME_MODE(apple80211_wcl_real_time_mode*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ARP_MODE(apple80211_wcl_arp_mode*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_TRIGGER_CC(triggerCC *data) {
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 14, "TRIGGER_CC", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::setWCL_SCAN_REQ(apple80211ScanRequest *request) {
    if (!radioAvailable()) return kIOReturnNotReady;
    if (transaction_ == UINT64_MAX) return kIOReturnNoResources;
    int status = snap_wcl_scan_submit(station_, request,
        SNAP_WCL_SCAN_26A428_BYTES, ++transaction_, resolve_, resolveContext_);
    if (status == SNAP_STATION_OK) {
        scanTransaction_ = transaction_; scanGeneration_ = station_->generation;
    }
    // Every request and its outcome: WCL logs only "unable to set scan request".
    IOLog("SnapintoshQCC2072Interface: WCL_SCAN_REQ tx %llu channels %u -> %d\n",
          (unsigned long long)transaction_,
          status == SNAP_STATION_OK ? (unsigned)station_->pending.channel_count : 0U, status);
    return nativeStatus(status);
}
IOReturn SnapintoshQCC2072Interface::setWCL_ASSOCIATE(apple80211AssocCandidates*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_QOS_PARAMS(apple80211_wcl_qos_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_LINK_UP_DONE(void*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *data) {
    IOReturn status = data ? kIOReturnUnsupported : kIOReturnBadArgument;
    noteQuery(1U << 15, "SCAN_HOME_AWAY_TIME", status);
    return status;
}
IOReturn SnapintoshQCC2072Interface::setVOICE_IND_STATE(apple80211_voice_ind_state*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRSN_XE(apple80211_rsn_xe_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_ACCESSORY_POWER_LIMIT_WIFI_ENH(apple80211_mws_accessory_power_limit*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ULOFDMA_STATE(apple80211_wcl_ulofdma_state*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ACTION_FRAME(apple80211_wcl_action_frame*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setGAS_ABORT(void*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setOS_FEATURE_FLAGS(apple80211_feature_flags*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDHCP_RENEWAL_DATA(apple80211_dhcp_renewal_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBATTERY_POWERSAVE_CONFIG(apple80211_battery_ps_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMIMO_CONFIG(apple80211_mimo_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_CONFIG_BG_MOTIONPROFILE(apple80211_bg_motion_profile*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_CONFIG_BG_NETWORK(apple80211_bg_network*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_CONFIG_BGSCAN(apple80211_bg_scan*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_CONFIG_BG_PARAMS(apple80211_bg_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setPOWER_PROFILE(apple80211_power_profile*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setHEARTBEAT(void*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setINTERFACE_SETTING(apple80211_interface_setting*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBYPASS_TX_POWER_CAP(apple80211_bypass_tx_power_cap*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setFACETIME_WIFICALLING_PARAMS(apple80211_facetime_wificalling_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setIPV4_PARAMS(apple80211_ipv4_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_WNM_OPS(apple80211_wcl_wnm_config_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_LIMITED_AGGREGATION(apple80211_limited_aggregation_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_BCN_MUTE_CONFIG(apple80211_bcn_mute_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setEAP_FILTER_CONFIG(apple80211_eap_filter_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWOW_LOW_POWER_MODE(apple80211_wow_low_power_mode*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDUAL_POWER_MODE(apple80211_dual_power_mode_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_UPDATE_FAST_LANE(apple80211_fastlane*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setVIRTUAL_IF_STATE(apple80211_virtual_if_state*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_ASSOCIATED_SLEEP(apple80211_associated_sleep_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setCONGESTION_CTRL_IND(apple80211_congestion_control_indication*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setSTAND_ALONE_MODE_STATE(apple80211_standalone_state*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setIPV6_PARAMS(apple80211_ipv6_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setINFRA_ENUMERATED(apple80211_infra_enumerated*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setLMTPC_CONFIG(apple80211_lmtpc_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTRAFFIC_ENG_PARAMS(apple80211_traffic_eng_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setLE_SCAN_PARAM(apple80211_le_scan_params*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTIMESYNC_GPIO(apple80211_timesync_gpio*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setHOST_CLOCK_INFO(apple80211_host_clock_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setFW_CLOCK_SOURCE(apple80211_fw_clock_source*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTIMESYNC_TX_POLICY(apple80211_timesync_tx_policy*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTIMESYNC_RX_POLICY(apple80211_timesync_rx_policy*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTIMESTAMPING_EN(apple80211_timestamping_en*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setWCL_SOI_CONFIG(appl80211_sleep_on_inactivity_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_TIME_SHARING_WIFI_ENH(apple80211_mws_time_sharing*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_WIFI_TYPE_7_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_COEX_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_DISABLE_OCL_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_RFEM_CONFIG_WIFI_ENH(apple80211_mws_rfem_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_ASSOC_PROTECTION_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_SCAN_FREQ_WIFI_ENH(apple80211_mws_scan_freq*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_SCAN_FREQ_MODE_WIFI_ENH(apple80211_mws_scan_freq_mode*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_CONDITION_ID_BITMAP_WIFI_ENH(apple80211_mws_condition_id_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setMWS_ANTENNA_SELECTION_WIFI_ENH(apple80211_mws_antenna_selection*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setNDD_REQ(apple80211_ndd_data*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDBRG_ENTROPY(apple80211_drbg_entropy*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setSDB_ENABLE(apple80211_sdb_enable*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBTCOEX_EXT_PROFILE(apple80211_btcoex_ext_profile*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setDEVICE_ORIENTATION(apple80211_device_orientation*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setACCESSORY_STATE(apple80211_device_accessory_info*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setOS_ELIGIBILITY(apple80211_os_eligibility*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setTX_MODE_CONFIG(apple80211_tx_mode_config*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setELNA_POWER_GAIN(apple80211_elna_power_gain*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setBW_CHANGE(apple80211_bw_change*) { return kIOReturnNotReady; }
IOReturn SnapintoshQCC2072Interface::setRC2_BT_COEX_PARAM(apple80211_rc2_bt_coex_param*) { return kIOReturnNotReady; }

IOReturn SnapintoshQCC2072Interface::publishStationEvent(const struct snap_station_event *event) {
    // Owner forwards only accepted station events, on the same serialized queue.
    if (!nativeStarted_ || !station_ || !event || unavailable_) return kIOReturnNotReady;
    if (!scanTransaction_ || event->transaction != scanTransaction_ ||
        event->generation != scanGeneration_ ||
        event->generation != station_->generation) return kIOReturnNotFound;
    uint8_t payload[SNAP_WCL_EVENT_MAX_BYTES];
    uint32_t message = 0;
    size_t bytes = 0;
    int provenance = SNAP_IF_RSSI_NONE;
    // Exact 0xc9/0xed encoder; an estimated RSSI is labelled, never promoted
    // to calibrated (FAILURES.md 9).
    int status = snap_if_wcl_event_encode(event, &scratchEvent_, payload, sizeof(payload),
                                          &message, &bytes, &provenance);
    if (status != SNAP_STATION_OK) {
        if (event->type == SNAP_STATION_BSS) ++scanResultsRefused_;
        return nativeStatus(status);
    }
    if (message == SNAP_IF_M_WCL_SCAN_RESULT) {
        ++scanResults_;
        if (provenance == SNAP_IF_RSSI_ESTIMATED) {
            ++scanResultsEstimated_;
            if (!rssiNoted_) {
                rssiNoted_ = true;
                IOLog("SnapintoshQCC2072Interface: scan RSSI is uncalibrated "
                      "(firmware SNR + -95 dBm noise floor)\n");
            }
        }
    } else if (message == SNAP_IF_M_WCL_SCAN_DONE) {
        scanTransaction_ = scanGeneration_ = 0;
        ++scanDone_;
    }
    // Exact 26A428 glue copies synchronously; true selects the WCL route.
    // postMessage is void: success here records submission, not UI consumption.
    postMessage(message, payload, bytes, true);
    if (message == SNAP_IF_M_WCL_SCAN_DONE) {
        uint32_t done = 0;
        for (unsigned i = 0; i < 4; ++i) done |= (uint32_t)payload[i] << (8 * i);
        IOLog("SnapintoshQCC2072Interface: WCL_SCAN_DONE 0x%x results %u estimated-rssi %u "
              "refused %u\n", done, scanResults_, scanResultsEstimated_, scanResultsRefused_);
        (void)done;  // host replays compile IOLog away
        publishScanCounters();
    }
    return kIOReturnSuccess;
}
