/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_PROVIDER_H
#define SNAP_QCC2072_PROVIDER_H
#include <IOKit/IOService.h>
#include "native-station.h"
#include "qcc2072-dp-io.h"
struct qcc2072_provider;
/* state_changed values; equal to qcc2072_service_state (checked in provider). */
enum {
    QCC2072_PROVIDER_FW_READY = 4, QCC2072_PROVIDER_QUARANTINE = 5,
    QCC2072_PROVIDER_WLAN_CONFIG = 6, QCC2072_PROVIDER_HTC = 7,
    QCC2072_PROVIDER_HTC_SETUP = 8
};
struct qcc2072_provider_callbacks {
    void *context;
    void (*state_changed)(void *,unsigned state,int reason);
    void (*station_ready)(void *,const struct snap_station_ready *);
    void (*station_event)(void *,const struct snap_station_event *);
    /* Optional: one line per connect-state transition (with its cause), assoc.caps, connect
     * notices and refusals (re/connect/FAILURES.md 40). Never key material. */
    void (*log)(void *,const char *line);
};
struct snap_wpa2_ap;
/* All calls and callbacks share the controller's serialized work queue.
 * prepare maps admitted resources and initializes CPU memory only. begin starts
 * firmware boot; poll advances bounded work, enables CE/HTC only after observed
 * WLFW FW_READY, and routes actual WMI events. Pre-INIT datapath setup requires
 * observed QMI CMEM; READY and HTT confirmation are separate observed stages.
 * Neither admits a native station
 * until real WMI service/ready metadata has been observed. Callback data is
 * borrowed only for the call; callbacks must not reenter this provider.
 */
IOReturn qcc2072_provider_prepare(IOService *,const qcc2072_provider_callbacks *,
                                  qcc2072_provider **);
IOReturn qcc2072_provider_begin(qcc2072_provider *);
uint64_t qcc2072_provider_generation(const qcc2072_provider *);
IOReturn qcc2072_provider_poll(qcc2072_provider *);
int qcc2072_provider_submit(void *,const snap_station_request *);
int qcc2072_provider_control(void *,const snap_station_control *);
int qcc2072_provider_cancel(void *,uint64_t generation,uint64_t transaction);
int qcc2072_provider_channel(void *,uint32_t version,uint32_t channel,
                             uint32_t flags,uint16_t *frequency_mhz);
/* WMI SERVICE_READY fw_build, reported only after SERVICE_READY was observed. */
int qcc2072_provider_firmware_build(const qcc2072_provider *,uint32_t *build);
/* OK means actual quiescence; errors retain every object and mapping. */
int qcc2072_provider_stop(void *,uint64_t generation);
/* Data frames (re/dp-io/REPORT.md). Ethernet II both ways; raw qcc2072 result codes.
 * attach: rx/tx_done run inside provider poll and may call data_tx.
 * configure: after VDEV_CREATE and the vdev TX_ENCAP/RX_DECAP params; bssid NULL clears.
 * peer_setup: once after PEER_CREATE for the AP (ath12k_dp_peer_setup), before EAPOL.
 * data_tx: needs configure and the AP's HTT PEER_MAP2/3; RUNTIME_FULL means retry. */
int qcc2072_provider_data_attach(qcc2072_provider *,const qcc2072_dpio_callbacks *);
int qcc2072_provider_data_configure(qcc2072_provider *,const qcc2072_dpio_vdev *,const uint8_t bssid[6]);
int qcc2072_provider_data_peer_setup(qcc2072_provider *,uint32_t vdev_id,const uint8_t mac[6]);
int qcc2072_provider_data_tx(qcc2072_provider *,const uint8_t *,size_t,uint64_t tag,unsigned tid,unsigned flags);
/* WPA2 connect engine hooks (src/qcc2072-connect.h); owner queue, outside provider poll:
 * link_security: the AP's RSN element/RSNXE of the link being connected or associated.
 * eapol_admit: qcc2072_assoc_eapol_admit on the link (read-only; also safe in callbacks).
 * disconnect: tear down a link snap_station already dropped (snap_wpa2 failure); its
 * completion is internal (no CONTROL_DONE reaches snap_station), DISCONNECTED still is. */
int qcc2072_provider_link_security(void *,struct snap_wpa2_ap *);
int qcc2072_provider_eapol_admit(void *,const uint8_t *,size_t,int transmit);
int qcc2072_provider_disconnect(void *,uint64_t generation,uint64_t link_transaction,uint16_t reason);
/* Only pre-DMA objects or a successfully stopped generation may be released. */
IOReturn qcc2072_provider_release(qcc2072_provider *);
#endif
