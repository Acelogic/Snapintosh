/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_NATIVE_INTERFACE_H
#define SNAP_QCC2072_NATIVE_INTERFACE_H
#include "IO80211Interface26A428.h"
#include "native-wcl-scan.h"
#include "native-wcl-event.h"
#include "IOSkywalkLifecycle26A428.h"
#include "native-interface-state.h"
class IOWorkLoop;
// Controller-level request payloads (IO80211Controller26A428.h names them too).
struct apple80211_power_data;
struct apple80211_capability_data;
struct apple80211_version_data;
struct apple80211_country_code_data;
class SnapintoshQCC2072Interface : public IO80211InfraProtocol {
    OSDeclareDefaultStructors(SnapintoshQCC2072Interface)
public:
    bool init() override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    void free() override;
    IOReturn shutdown(IOService *);
    bool bindStation(struct snap_station *, snap_wcl_channel_resolver, void *);
    IOReturn publishStationEvent(const struct snap_station_event *);
    // Wi-Fi menu bring-up (re/wifi-ui). Nonvirtual: no vtable/PAC change.
    // The controller forwards its exact 26A428 request slots here and gates
    // isCommandProhibited on snapCommandAllowed (re/wifi-ui/controller.patch).
    bool snapCommandAllowed(int type) const;
    IOReturn snapGetPower(IO80211SkywalkInterface *, apple80211_power_data *);
    IOReturn snapSetPower(IO80211SkywalkInterface *, apple80211_power_data *);
    IOReturn snapGetCardCapabilities(IO80211SkywalkInterface *, apple80211_capability_data *);
    IOReturn snapGetDriverVersion(IO80211SkywalkInterface *, apple80211_version_data *);
    IOReturn snapGetHardwareVersion(IO80211SkywalkInterface *, apple80211_version_data *);
    IOReturn snapGetCountryCode(IO80211SkywalkInterface *, apple80211_country_code_data *);
    IOReturn snapSetCountryCode(IO80211SkywalkInterface *, apple80211_country_code_data *);
    // After attachInterface: RESET_INTERFACE(1), DRIVER_AVAILABLE(1), POWER_CHANGED.
    IOReturn announceDriverReady();
    // On transport quarantine: DRIVER_AVAILABLE(0); every request then refuses.
    void announceDriverUnavailable();
    // Firmware build from WMI SERVICE_READY, when the provider exposes it.
    void noteFirmwareBuild(uint32_t build);
    // Exact native slot 482; status only until a payload is qualified.
    IOReturn setMacAddress(mloAddrArray&) override;
    // Exact native slot 483; status only until a payload is qualified.
    IOReturn getCHANNEL(apple80211_channel_data*) override;
    // Exact native slot 484; Unsupported: no firmware power-save programming.
    IOReturn getPOWERSAVE(apple80211_powersave_data*) override;
    // Exact native slot 485; status only until a payload is qualified.
    IOReturn getTXPOWER(apple80211_txpower_data*) override;
    // Exact native slot 486; status only until a payload is qualified.
    IOReturn getRATE(apple80211_rate_data*) override;
    // Exact native slot 487; answered: exact 8-byte op mode (0 unassociated, STA when connected).
    IOReturn getOP_MODE(apple80211_opmode_data*) override;
    // Exact native slot 488; status only until a payload is qualified.
    IOReturn getRSSI(apple80211_rssi_data*) override;
    // Exact native slot 489; answered: resolver-admitted 20 MHz channels.
    IOReturn getSUPPORTED_CHANNELS(apple80211_sup_channel_data*) override;
    // Exact native slot 490; status only until a payload is qualified.
    IOReturn getGUARD_INTERVAL(apple80211_guard_interval_data*) override;
    // Exact native slot 491; status only until a payload is qualified.
    IOReturn getMCS(apple80211_mcs_data*) override;
    // Exact native slot 492; status only until a payload is qualified.
    IOReturn getPOWER_DEBUG_INFO(apple80211_power_debug_info*) override;
    // Exact native slot 493; status only until a payload is qualified.
    IOReturn getHT_CAPABILITY(apple80211_ht_capability*) override;
    // Exact native slot 494; status only until a payload is qualified.
    IOReturn getMCS_VHT(apple80211_mcs_vht_data*) override;
    // Exact native slot 495; status only until a payload is qualified.
    IOReturn getCHANNELS_INFO(apple80211_channels_info*) override;
    // Exact native slot 496; status only until a payload is qualified.
    IOReturn getVHT_CAPABILITY(apple80211_vht_capability*) override;
    // Exact native slot 497; status only until a payload is qualified.
    IOReturn getROAM_PROFILE(apple80211_roam_profile_all_bands*) override;
    // Exact native slot 498; status only until a payload is qualified.
    IOReturn getCHIP_COUNTER_STATS(apple80211_chip_stats*) override;
    // Exact native slot 499; status only until a payload is qualified.
    IOReturn getDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) override;
    // Exact native slot 500; status only until a payload is qualified.
    IOReturn getLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) override;
    // Exact native slot 501; status only until a payload is qualified.
    IOReturn getCOUNTRY_CHANNELS(apple80211_country_channel_data*) override;
    // Exact native slot 502; status only until a payload is qualified.
    IOReturn getPRIVATE_MAC(apple80211_private_mac_data*) override;
    // Exact native slot 503; status only until a payload is qualified.
    IOReturn getRANGING_ENABLE(apple80211_ranging_enable_request_t*) override;
    // Exact native slot 504; status only until a payload is qualified.
    IOReturn getRANGING_START(apple80211_ranging_start_request_t*) override;
    // Exact native slot 505; status only until a payload is qualified.
    IOReturn getAWDL_RSDB_CAPS(apple80211_rsdb_capability*) override;
    // Exact native slot 506; status only until a payload is qualified.
    IOReturn getTKO_PARAMS(apple80211_tko_params*) override;
    // Exact native slot 507; status only until a payload is qualified.
    IOReturn getTKO_DUMP(apple80211_tko_dump*) override;
    // Exact native slot 508; answered: same resolver-admitted set.
    IOReturn getHW_SUPPORTED_CHANNELS(apple80211_sup_channel_data*) override;
    // Exact native slot 509; status only until a payload is qualified.
    IOReturn getBTCOEX_PROFILE(apple80211_btcoex_profile*) override;
    // Exact native slot 510; status only until a payload is qualified.
    IOReturn getBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) override;
    // Exact native slot 511; status only until a payload is qualified.
    IOReturn getTRAP_INFO(apple80211_trap_info_data*) override;
    // Exact native slot 512; status only until a payload is qualified.
    IOReturn getTHERMAL_INDEX(apple80211_thermal_index_t*) override;
    // Exact native slot 513; status only until a payload is qualified.
    IOReturn getMAX_NSS_FOR_AP(apple80211_btcoex_max_nss_for_ap_data*) override;
    // Exact native slot 514; status only until a payload is qualified.
    IOReturn getBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) override;
    // Exact native slot 515; status only until a payload is qualified.
    IOReturn getPOWER_BUDGET(apple80211_power_budget_t*) override;
    // Exact native slot 516; status only until a payload is qualified.
    IOReturn getOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) override;
    // Exact native slot 517; status only until a payload is qualified.
    IOReturn getRANGING_CAPS(apple80211_ranging_capabilities_t*) override;
    // Exact native slot 518; status only until a payload is qualified.
    IOReturn getLQM_CONFIG(apple80211_lqm_config_t*) override;
    // Exact native slot 519; status only until a payload is qualified.
    IOReturn getTRAP_CRASHTRACER_MINI_DUMP(apple80211_trap_mini_dump_data*) override;
    // Exact native slot 520; status only until a payload is qualified.
    IOReturn getBEACON_INFO(apple80211_beacon_info_t*) override;
    // Exact native slot 521; status only until a payload is qualified.
    IOReturn getCHIP_POWER_RANGE(apple80211_chip_power_limit*) override;
    // Exact native slot 522; status only until a payload is qualified.
    IOReturn getNSS(apple80211_nss_data*) override;
    // Exact native slot 523; answered: WMI READY MAC.
    IOReturn getHW_ADDR(apple80211_hw_mac_address*) override;
    // Exact native slot 524; status only until a payload is qualified.
    IOReturn getCHIP_DIAGS(appl80211_chip_diags_data*) override;
    // Exact native slot 525; status only until a payload is qualified.
    IOReturn getHP2P_CTRL(apple80211_hp2p_ctrl*) override;
    // Exact native slot 526; status only until a payload is qualified.
    IOReturn getBSS_BLACKLIST(bss_blacklist*) override;
    // Exact native slot 527; status only until a payload is qualified.
    IOReturn getTXRX_CHAIN_INFO(apple80211_txrx_chain_info*) override;
    // Exact native slot 528; status only until a payload is qualified.
    IOReturn getMIMO_STATUS(apple80211_mimo_status*) override;
    // Exact native slot 529; status only until a payload is qualified.
    IOReturn getCUR_PMK(apple80211_pmk*) override;
    // Exact native slot 530; status only until a payload is qualified.
    IOReturn getDYNSAR_DETAIL(apple80211_dynsar_detail*) override;
    // Exact native slot 531; status only until a payload is qualified.
    IOReturn getCOUNTRY_CHANNELS_INFO(apple80211_channels_info*) override;
    // Exact native slot 532; status only until a payload is qualified.
    IOReturn getLQM_SUMMARY(apple80211_lqm_summary*) override;
    // Exact native slot 533; status only until a payload is qualified.
    IOReturn getSLOW_WIFI_FEATURE_ENABLED(apple80211_slow_wifi_feature_enabled*) override;
    // Exact native slot 534; status only until a payload is qualified.
    IOReturn getTIMESYNC_INFO(apple80211_timesync_info*) override;
    // Exact native slot 535; status only until a payload is qualified.
    IOReturn getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels*) override;
    // Exact native slot 536; status only until a payload is qualified.
    IOReturn getWCL_BSS_INFO(apple80211_beacon_msg*) override;
    // Exact native slot 537; status only until a payload is qualified.
    IOReturn getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters*) override;
    // Exact native slot 538; Unsupported: no TX blanking source.
    IOReturn getWCL_GET_TX_BLANKING_STATUS(unsigned int*) override;
    // Exact native slot 539; status only until a payload is qualified.
    IOReturn getHE_COUNTERS(apple80211_he_counters_ctl*) override;
    // Exact native slot 540; answered: exact 0xc86 WCL channel info.
    IOReturn getWCL_CHANNELS_INFO(apple80211ChannelInfo*) override;
    // Exact native slot 541; status only until a payload is qualified.
    IOReturn getRSN_XE(apple80211_rsn_xe_data*) override;
    // Exact native slot 542; status only until a payload is qualified.
    IOReturn getSIB_COEX_STATUS(apple80211_sib_coex_status*) override;
    // Exact native slot 543; status only until a payload is qualified.
    IOReturn getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info*) override;
    // Exact native slot 544; status only until a payload is qualified.
    IOReturn getWCL_LOW_LATENCY_INFO_STATS(apple80211_wcl_low_latency_stats*) override;
    // Exact native slot 545; status only until a payload is qualified.
    IOReturn getWCL_BGSCAN_CACHE_RESULT(apple80211_bgscan_cached_network_data_list*) override;
    // Exact native slot 546; status only until a payload is qualified.
    IOReturn getWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) override;
    // Exact native slot 547; status only until a payload is qualified.
    IOReturn getWIFI_NOISE_PER_ANT(apple80211_noise_per_ant_t*) override;
    // Exact native slot 548; status only until a payload is qualified.
    IOReturn getFW_CLOCK_INFO(apple80211_fw_clock_info*) override;
    // Exact native slot 549; status only until a payload is qualified.
    IOReturn getTIMESYNC_STATS(apple80211_timesync_stats*) override;
    // Exact native slot 550; status only until a payload is qualified.
    IOReturn getSYSTEM_SLEEP_CONFIG(apple80211_system_sleep_config*) override;
    // Exact native slot 551; status only until a payload is qualified.
    IOReturn getSMARTCCA_OPMODE(apple80211_smartcca_opmode*) override;
    // Exact native slot 552; status only until a payload is qualified.
    IOReturn getLQM_STATISTICS(apple80211_lqm_statistics*) override;
    // Exact native slot 553; status only until a payload is qualified.
    IOReturn getHE_CAPABILITY(apple80211_he_capability*) override;
    // Exact native slot 554; status only until a payload is qualified.
    IOReturn getDEVICE_ORIENTATION(apple80211_device_orientation*) override;
    // Exact native slot 555; status only until a payload is qualified.
    IOReturn getACCESSORY_STATE(apple80211_device_accessory_info*) override;
    // Exact native slot 556; status only until a payload is qualified.
    IOReturn getP2P_DEVICE_CAPABILITY(apple80211_p2p_device_capability*) override;
    // Exact native slot 557; status only until a payload is qualified.
    IOReturn getPOWERTABLE_VERSION(apple80211_powertable_version_data*) override;
    // Exact native slot 558; status only until a payload is qualified.
    IOReturn getMCS_HE(apple80211_mcs_he_data*) override;
    // Exact native slot 559; status only until a payload is qualified.
    IOReturn getMCS_BE(apple80211_mcs_be_data*) override;
    // Exact native slot 560; status only until a payload is qualified.
    IOReturn getROAM_SLEEP_HISTORY(apple80211_roam_sleep_history*) override;
    // Exact native slot 561; status only until a payload is qualified.
    IOReturn setCIPHER_KEY(apple80211_key*) override;
    // Exact native slot 562; status only until a payload is qualified.
    IOReturn setCHANNEL(apple80211_channel_data*) override;
    // Exact native slot 563; Unsupported: no firmware power-save programming.
    IOReturn setPOWERSAVE(apple80211_powersave_data*) override;
    // Exact native slot 564; status only until a payload is qualified.
    IOReturn setTXPOWER(apple80211_txpower_data*) override;
    // Exact native slot 565; status only until a payload is qualified.
    IOReturn setRATE(apple80211_rate_data*) override;
    // Exact native slot 566; status only until a payload is qualified.
    IOReturn setIBSS_MODE(apple80211_network_data*) override;
    // Exact native slot 567; status only until a payload is qualified.
    IOReturn setAP_MODE(apple80211_apmode_data*) override;
    // Exact native slot 568; status only until a payload is qualified.
    IOReturn setIE(apple80211_ie_data*) override;
    // Exact native slot 569; status only until a payload is qualified.
    IOReturn setWOW_TEST(apple80211_wow_test_data*) override;
    // Exact native slot 570; status only until a payload is qualified.
    IOReturn setCLEAR_PMKSA_CACHE(void*) override;
    // Exact native slot 571; status only until a payload is qualified.
    IOReturn setVIRTUAL_IF_CREATE(apple80211_virt_if_create_data*) override;
    // Exact native slot 572; status only until a payload is qualified.
    IOReturn setHT_CAPABILITY(apple80211_ht_capability*) override;
    // Exact native slot 573; status only until a payload is qualified.
    IOReturn setOFFLOAD_ARP(apple80211_offload_arp_data*) override;
    // Exact native slot 574; status only until a payload is qualified.
    IOReturn setOFFLOAD_NDP(apple80211_offload_ndp_data*) override;
    // Exact native slot 575; status only until a payload is qualified.
    IOReturn setGAS_REQ(apple80211_gas_query_t*) override;
    // Exact native slot 576; status only until a payload is qualified.
    IOReturn setVHT_CAPABILITY(apple80211_vht_capability*) override;
    // Exact native slot 577; status only until a payload is qualified.
    IOReturn setROAM_PROFILE(apple80211_roam_profile_all_bands*) override;
    // Exact native slot 578; status only until a payload is qualified.
    IOReturn setDBG_GUARD_TIME_PARAMS(apple80211_dbg_guard_time_params*) override;
    // Exact native slot 579; status only until a payload is qualified.
    IOReturn setLEAKY_AP_STATS_MODE(apple80211_leaky_ap_setting*) override;
    // Exact native slot 580; status only until a payload is qualified.
    IOReturn setPRIVATE_MAC(apple80211_private_mac_data*) override;
    // Exact native slot 581; status only until a payload is qualified.
    IOReturn setRESET_CHIP(apple80211_reset_command*) override;
    // Exact native slot 582; status only until a payload is qualified.
    IOReturn setCRASH(apple80211_crash_command*) override;
    // Exact native slot 583; status only until a payload is qualified.
    IOReturn setRANGING_ENABLE(apple80211_ranging_enable_request_t*) override;
    // Exact native slot 584; status only until a payload is qualified.
    IOReturn setRANGING_START(apple80211_ranging_start_request_t*) override;
    // Exact native slot 585; status only until a payload is qualified.
    IOReturn setRANGING_AUTHENTICATE(apple80211_ranging_authenticate_request_t*) override;
    // Exact native slot 586; status only until a payload is qualified.
    IOReturn setTKO_PARAMS(apple80211_tko_params*) override;
    // Exact native slot 587; status only until a payload is qualified.
    IOReturn setBTCOEX_PROFILE(apple80211_btcoex_profile*) override;
    // Exact native slot 588; status only until a payload is qualified.
    IOReturn setBTCOEX_PROFILE_ACTIVE(apple80211_btcoex_profile_active_data*) override;
    // Exact native slot 589; status only until a payload is qualified.
    IOReturn setTHERMAL_INDEX(apple80211_thermal_index_t*) override;
    // Exact native slot 590; status only until a payload is qualified.
    IOReturn setBTCOEX_2G_CHAIN_DISABLE(apple80211_btcoex_2g_chain_disable*) override;
    // Exact native slot 591; status only until a payload is qualified.
    IOReturn setPOWER_BUDGET(apple80211_power_budget_t*) override;
    // Exact native slot 592; status only until a payload is qualified.
    IOReturn setOFFLOAD_TCPKA_ENABLE(apple80211_offload_tcpka_enable_t*) override;
    // Exact native slot 593; status only until a payload is qualified.
    IOReturn setLQM_CONFIG(apple80211_lqm_config_t*) override;
    // Exact native slot 594; status only until a payload is qualified.
    IOReturn setDYNAMIC_RSSI_WINDOW_CONFIG(apple80211_dynamic_rssi_window_config*) override;
    // Exact native slot 595; status only until a payload is qualified.
    IOReturn setUSB_HOST_NOTIFICATION(apple80211_usb_host_notification_data*) override;
    // Exact native slot 596; status only until a payload is qualified.
    IOReturn setHP2P_CTRL(apple80211_hp2p_ctrl*) override;
    // Exact native slot 597; status only until a payload is qualified.
    IOReturn setBSS_BLACKLIST(bss_blacklist*) override;
    // Exact native slot 598; status only until a payload is qualified.
    IOReturn setSET_PROPERTY(apple80211_set_property_unserialized_data*) override;
    // Exact native slot 599; status only until a payload is qualified.
    IOReturn setROAM_CACHE_UPDATE(apple80211_roam_cache_data*) override;
    // Exact native slot 600; Unsupported: no firmware power-save programming.
    IOReturn setPM_MODE(apple80211_pm_mode*) override;
    // Exact native slot 601; status only until a payload is qualified.
    IOReturn setREALTIME_QOS_MSCS(apple80211_state_data*) override;
    // Exact native slot 602; status only until a payload is qualified.
    IOReturn setWCL_LEAVE_NETWORK(apple80211_leave_network*) override;
    // Exact native slot 603; status only until a payload is qualified.
    IOReturn setWCL_REASSOC(apple80211_reassoc*) override;
    // Exact native slot 604; status only until a payload is qualified.
    IOReturn setWCL_SET_ROAM_LOCK(apple80211_set_roam_lock*) override;
    // Exact native slot 605; status only until a payload is qualified.
    IOReturn setWCL_LEGACY_ROAM_PROFILE_CONFIG(apple80211_legacy_roam_profile_config*) override;
    // Exact native slot 606; status only until a payload is qualified.
    IOReturn setWCL_ROAM_PROFILE_CONFIG(apple80211_roam_profile_config*) override;
    // Exact native slot 607; status only until a payload is qualified.
    IOReturn setWCL_ROAM_USER_CACHE(apple80211_user_roam_cache*) override;
    // Exact native slot 608; status only until a payload is qualified.
    IOReturn setWCL_SCAN_ABORT(void*) override;
    // Exact native slot 609; status only until a payload is qualified.
    IOReturn setWCL_REAL_TIME_MODE(apple80211_wcl_real_time_mode*) override;
    // Exact native slot 610; status only until a payload is qualified.
    IOReturn setWCL_ARP_MODE(apple80211_wcl_arp_mode*) override;
    // Exact native slot 611; status only until a payload is qualified.
    IOReturn setWCL_JOIN_ABORT(apple80211_wcl_abort_join*) override;
    // Exact native slot 612; Unsupported: firmware country cannot be changed here.
    IOReturn setWCL_TRIGGER_CC(triggerCC*) override;
    // Exact native slot 613; status only until a payload is qualified.
    IOReturn setWCL_SCAN_REQ(apple80211ScanRequest*) override;
    // Exact native slot 614; status only until a payload is qualified.
    IOReturn setWCL_ASSOCIATE(apple80211AssocCandidates*) override;
    // Exact native slot 615; status only until a payload is qualified.
    IOReturn setWCL_QOS_PARAMS(apple80211_wcl_qos_params*) override;
    // Exact native slot 616; status only until a payload is qualified.
    IOReturn setWCL_LINK_UP_DONE(void*) override;
    // Exact native slot 617; Unsupported: scan dwell policy not programmable.
    IOReturn setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime*) override;
    // Exact native slot 618; status only until a payload is qualified.
    IOReturn setVOICE_IND_STATE(apple80211_voice_ind_state*) override;
    // Exact native slot 619; status only until a payload is qualified.
    IOReturn setRSN_XE(apple80211_rsn_xe_data*) override;
    // Exact native slot 620; status only until a payload is qualified.
    IOReturn setMWS_ACCESSORY_POWER_LIMIT_WIFI_ENH(apple80211_mws_accessory_power_limit*) override;
    // Exact native slot 621; status only until a payload is qualified.
    IOReturn setWCL_ULOFDMA_STATE(apple80211_wcl_ulofdma_state*) override;
    // Exact native slot 622; status only until a payload is qualified.
    IOReturn setWCL_ACTION_FRAME(apple80211_wcl_action_frame*) override;
    // Exact native slot 623; status only until a payload is qualified.
    IOReturn setGAS_ABORT(void*) override;
    // Exact native slot 624; status only until a payload is qualified.
    IOReturn setOS_FEATURE_FLAGS(apple80211_feature_flags*) override;
    // Exact native slot 625; status only until a payload is qualified.
    IOReturn setDHCP_RENEWAL_DATA(apple80211_dhcp_renewal_data*) override;
    // Exact native slot 626; status only until a payload is qualified.
    IOReturn setBATTERY_POWERSAVE_CONFIG(apple80211_battery_ps_config*) override;
    // Exact native slot 627; status only until a payload is qualified.
    IOReturn setMIMO_CONFIG(apple80211_mimo_config*) override;
    // Exact native slot 628; status only until a payload is qualified.
    IOReturn setWCL_CONFIG_BG_MOTIONPROFILE(apple80211_bg_motion_profile*) override;
    // Exact native slot 629; status only until a payload is qualified.
    IOReturn setWCL_CONFIG_BG_NETWORK(apple80211_bg_network*) override;
    // Exact native slot 630; status only until a payload is qualified.
    IOReturn setWCL_CONFIG_BGSCAN(apple80211_bg_scan*) override;
    // Exact native slot 631; status only until a payload is qualified.
    IOReturn setWCL_CONFIG_BG_PARAMS(apple80211_bg_params*) override;
    // Exact native slot 632; status only until a payload is qualified.
    IOReturn setPOWER_PROFILE(apple80211_power_profile*) override;
    // Exact native slot 633; status only until a payload is qualified.
    IOReturn setHEARTBEAT(void*) override;
    // Exact native slot 634; status only until a payload is qualified.
    IOReturn setINTERFACE_SETTING(apple80211_interface_setting*) override;
    // Exact native slot 635; status only until a payload is qualified.
    IOReturn setBYPASS_TX_POWER_CAP(apple80211_bypass_tx_power_cap*) override;
    // Exact native slot 636; status only until a payload is qualified.
    IOReturn setFACETIME_WIFICALLING_PARAMS(apple80211_facetime_wificalling_params*) override;
    // Exact native slot 637; status only until a payload is qualified.
    IOReturn setIPV4_PARAMS(apple80211_ipv4_params*) override;
    // Exact native slot 638; status only until a payload is qualified.
    IOReturn setWCL_WNM_OPS(apple80211_wcl_wnm_config_t*) override;
    // Exact native slot 639; status only until a payload is qualified.
    IOReturn setWCL_WNM_OFFLOAD(apple80211_wcl_wnm_offload_t*) override;
    // Exact native slot 640; status only until a payload is qualified.
    IOReturn setWCL_LIMITED_AGGREGATION(apple80211_limited_aggregation_config*) override;
    // Exact native slot 641; status only until a payload is qualified.
    IOReturn setWCL_BCN_MUTE_CONFIG(apple80211_bcn_mute_config*) override;
    // Exact native slot 642; status only until a payload is qualified.
    IOReturn setEAP_FILTER_CONFIG(apple80211_eap_filter_config*) override;
    // Exact native slot 643; status only until a payload is qualified.
    IOReturn setWOW_LOW_POWER_MODE(apple80211_wow_low_power_mode*) override;
    // Exact native slot 644; status only until a payload is qualified.
    IOReturn setDUAL_POWER_MODE(apple80211_dual_power_mode_params*) override;
    // Exact native slot 645; status only until a payload is qualified.
    IOReturn setWCL_UPDATE_FAST_LANE(apple80211_fastlane*) override;
    // Exact native slot 646; status only until a payload is qualified.
    IOReturn setVIRTUAL_IF_STATE(apple80211_virtual_if_state*) override;
    // Exact native slot 647; status only until a payload is qualified.
    IOReturn setWCL_ASSOCIATED_SLEEP(apple80211_associated_sleep_config*) override;
    // Exact native slot 648; status only until a payload is qualified.
    IOReturn setCONGESTION_CTRL_IND(apple80211_congestion_control_indication*) override;
    // Exact native slot 649; status only until a payload is qualified.
    IOReturn setSTAND_ALONE_MODE_STATE(apple80211_standalone_state*) override;
    // Exact native slot 650; status only until a payload is qualified.
    IOReturn setIPV6_PARAMS(apple80211_ipv6_params*) override;
    // Exact native slot 651; status only until a payload is qualified.
    IOReturn setINFRA_ENUMERATED(apple80211_infra_enumerated*) override;
    // Exact native slot 652; status only until a payload is qualified.
    IOReturn setLMTPC_CONFIG(apple80211_lmtpc_config*) override;
    // Exact native slot 653; status only until a payload is qualified.
    IOReturn setTRAFFIC_ENG_PARAMS(apple80211_traffic_eng_params*) override;
    // Exact native slot 654; status only until a payload is qualified.
    IOReturn setLE_SCAN_PARAM(apple80211_le_scan_params*) override;
    // Exact native slot 655; status only until a payload is qualified.
    IOReturn setTIMESYNC_GPIO(apple80211_timesync_gpio*) override;
    // Exact native slot 656; status only until a payload is qualified.
    IOReturn setHOST_CLOCK_INFO(apple80211_host_clock_info*) override;
    // Exact native slot 657; status only until a payload is qualified.
    IOReturn setFW_CLOCK_SOURCE(apple80211_fw_clock_source*) override;
    // Exact native slot 658; status only until a payload is qualified.
    IOReturn setTIMESYNC_TX_POLICY(apple80211_timesync_tx_policy*) override;
    // Exact native slot 659; status only until a payload is qualified.
    IOReturn setTIMESYNC_RX_POLICY(apple80211_timesync_rx_policy*) override;
    // Exact native slot 660; status only until a payload is qualified.
    IOReturn setTIMESTAMPING_EN(apple80211_timestamping_en*) override;
    // Exact native slot 661; status only until a payload is qualified.
    IOReturn setWCL_SOI_CONFIG(appl80211_sleep_on_inactivity_config*) override;
    // Exact native slot 662; status only until a payload is qualified.
    IOReturn setMWS_TIME_SHARING_WIFI_ENH(apple80211_mws_time_sharing*) override;
    // Exact native slot 663; status only until a payload is qualified.
    IOReturn setMWS_WIFI_TYPE_7_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override;
    // Exact native slot 664; status only until a payload is qualified.
    IOReturn setMWS_COEX_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override;
    // Exact native slot 665; status only until a payload is qualified.
    IOReturn setMWS_DISABLE_OCL_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override;
    // Exact native slot 666; status only until a payload is qualified.
    IOReturn setMWS_RFEM_CONFIG_WIFI_ENH(apple80211_mws_rfem_config*) override;
    // Exact native slot 667; status only until a payload is qualified.
    IOReturn setMWS_ASSOC_PROTECTION_BITMAP_WIFI_ENH(apple80211_mws_wifi_channel_bitmap*) override;
    // Exact native slot 668; status only until a payload is qualified.
    IOReturn setMWS_SCAN_FREQ_WIFI_ENH(apple80211_mws_scan_freq*) override;
    // Exact native slot 669; status only until a payload is qualified.
    IOReturn setMWS_SCAN_FREQ_MODE_WIFI_ENH(apple80211_mws_scan_freq_mode*) override;
    // Exact native slot 670; status only until a payload is qualified.
    IOReturn setMWS_CONDITION_ID_BITMAP_WIFI_ENH(apple80211_mws_condition_id_config*) override;
    // Exact native slot 671; status only until a payload is qualified.
    IOReturn setMWS_ANTENNA_SELECTION_WIFI_ENH(apple80211_mws_antenna_selection*) override;
    // Exact native slot 672; status only until a payload is qualified.
    IOReturn setNDD_REQ(apple80211_ndd_data*) override;
    // Exact native slot 673; status only until a payload is qualified.
    IOReturn setDBRG_ENTROPY(apple80211_drbg_entropy*) override;
    // Exact native slot 674; status only until a payload is qualified.
    IOReturn setSDB_ENABLE(apple80211_sdb_enable*) override;
    // Exact native slot 675; status only until a payload is qualified.
    IOReturn setBTCOEX_EXT_PROFILE(apple80211_btcoex_ext_profile*) override;
    // Exact native slot 676; status only until a payload is qualified.
    IOReturn setDEVICE_ORIENTATION(apple80211_device_orientation*) override;
    // Exact native slot 677; status only until a payload is qualified.
    IOReturn setACCESSORY_STATE(apple80211_device_accessory_info*) override;
    // Exact native slot 678; status only until a payload is qualified.
    IOReturn setOS_ELIGIBILITY(apple80211_os_eligibility*) override;
    // Exact native slot 679; status only until a payload is qualified.
    IOReturn setTX_MODE_CONFIG(apple80211_tx_mode_config*) override;
    // Exact native slot 680; status only until a payload is qualified.
    IOReturn setELNA_POWER_GAIN(apple80211_elna_power_gain*) override;
    // Exact native slot 681; status only until a payload is qualified.
    IOReturn setBW_CHANGE(apple80211_bw_change*) override;
    // Exact native slot 682; status only until a payload is qualified.
    IOReturn setRC2_BT_COEX_PARAM(apple80211_rc2_bt_coex_param*) override;
private:
    struct snap_station *station_;
    snap_wcl_channel_resolver resolve_;
    void *resolveContext_;
    uint64_t transaction_, scanTransaction_, scanGeneration_;
    bool nativeStarted_;
    // Wi-Fi menu state (re/wifi-ui/FAILURES.md). Counters cover one boot.
    bool announced_ = false, unavailable_ = false, firmwareBuildKnown_ = false;
    bool rssiNoted_ = false;
    uint32_t firmwareBuild_ = 0, queriesLogged_ = 0;
    uint64_t announcedGeneration_ = 0;
    uint32_t scanResults_ = 0, scanResultsEstimated_ = 0, scanResultsRefused_ = 0;
    uint32_t scanDone_ = 0;
    struct snap_station_event scratchEvent_;
    bool ownsRequest(IO80211SkywalkInterface *) const;
    bool radioAvailable() const;
    void noteQuery(unsigned bit, const char *what, IOReturn status);
    IOReturn channelList(struct snap_if_channel *, unsigned *);
    IOReturn postBringUp(uint32_t message, const void *payload, size_t bytes);
    void publishScanCounters();
    bool baseStartAttempted_ = false, registrationAttempted_ = false;
    unsigned queueAdded_ = 0;
    IOWorkLoop *nativeLoop_ = nullptr;
    IOSkywalkPacketBufferPool *txPool_ = nullptr, *rxPool_ = nullptr;
    IOSkywalkPacketQueue *packetQueues_[4] = {};
    void releasePacketResources();
    static unsigned txUnavailable(OSObject *, IOSkywalkTxSubmissionQueue *,
                                  IOSkywalkPacket *const *, unsigned, void *);
    static unsigned rxUnavailable(OSObject *, IOSkywalkRxSubmissionQueue *,
                                  IOSkywalkPacket *const *, unsigned, void *);
};
#endif
