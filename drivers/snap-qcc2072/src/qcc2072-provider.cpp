/* SPDX-License-Identifier: MIT */
#include "qcc2072-provider.h"
#include "qcc2072-provider-record.h"
#include "qcc2072-service.h"
#include "qcc2072-wmi.h"
#include "qcc2072-reo.h"
#include "qcc2072-datapath.h"
#include "qcc2072-scan.h"
#include "qcc2072-assoc.h"
#include "qcc2072-dp-io.h"
#include "native-wpa2.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSData.h>
#include <mach/mach_time.h>
#include <kern/clock.h>
extern "C" {
#include "sha256.h"
}
#ifdef QCC2072_HOST_PROXY
#include <cstdarg>
#include <cstdio>
/* Host bring-up only (re/host-proxy): the four hardware leaves go to the A16. */
extern "C" int qcc_host_bar_read32(uint32_t offset,uint32_t *value);
extern "C" int qcc_host_bar_write32(uint32_t offset,uint32_t value);
extern "C" int qcc_host_command_write16(uint16_t value,volatile uint16_t *mirror);
extern "C" int qcc_host_dma_sync(uint64_t physical,uint8_t *cpu,size_t length,uint32_t direction);
#endif

struct qcc2072_provider {
    IOService *owner;
    IOMemoryMap *mapping[5];
    qcc2072_provider_record record;
    qcc2072_provider_callbacks callbacks;
    volatile uint8_t *bar,*pci;
    volatile const uint64_t *control;
    uint8_t *dma;
    qcc2072_dma_map map;
    qcc2072_dma_admission admission;
    qcc2072_dma_buffer segments[QCC2072_MHI_MAX_SEGMENTS],protected_buffers[80],ce;
    uint32_t protected_count;
    uint64_t allocation;
    qcc2072_service service;
    qcc2072_wmi wmi;
    qcc2072_reo reo;
    qcc2072_datapath datapath;
    /* Data frames (re/dp-io/REPORT.md): attached once the eight HTT ring setups went out. */
    qcc2072_dpio dpio;
    qcc2072_dpio_callbacks data_callbacks;
    uint8_t data_command[64],peer_setup_mac[6];
    size_t data_command_bytes;
    uint32_t peer_setup_vdev;
    unsigned peer_setup_stage;
    bool dpio_ready;
    uint64_t htt_deadline;
    unsigned htt_setup_submitted,htt_unhandled;
    bool hw_mode_sent,htt_requested,htt_ready;
    qcc2072_wmi_event last_wmi_event;
    uint8_t wmi_command[2040];
    size_t wmi_command_bytes;
    /* Station scan (re/scan/FAILURES.md): one request at a time, one command per poll. */
    snap_station_request scan_request;
    struct snap_station_event scan_event;
    uint8_t scan_command[2040];
    size_t scan_command_bytes;
    uint64_t scan_deadline;
    unsigned scan_stage,scan_results;
    uint32_t chan_list_revision;
    bool chan_list_sent,vdev_created;
    /* Station connect (re/assoc): one WMI command per poll from the connect state machine;
     * the AP's elements come from this scan cache, management frames from assoc_mgmt. */
    qcc2072_assoc assoc;
    qcc2072_assoc_connect_args connect_args;
    qcc2072_dma_buffer assoc_mgmt;
    /* Refreshed in place per BSSID; when full the weakest is replaced (re/connect/FAILURES.md 32). */
    struct snap_station_bss bss_cache[32];
    struct snap_station_event assoc_event;
    /* Connect trace (re/connect/FAILURES.md 40): the last state logged, internal controls. */
    struct { uint8_t state,prog,pc,op,wait,response,acked,tries; } trace;
    bool caps_logged;
    int assoc_dp_rc;
    uint64_t internal_control;
    char log_line[320];
    bool began,dma_started,quarantined,wmi_active,wmi_init_blocked,in_call;
    /* Native station admission is reported once per generation (re/wifi-ui). */
    bool station_reported;

};
static_assert(sizeof(qcc2072_provider_record)==QCC2072_PROVIDER_RECORD_BYTES,"monitor provider ABI");
static_assert(QCC2072_PROVIDER_FW_READY==QCC2072_SERVICE_FW_READY &&
              QCC2072_PROVIDER_QUARANTINE==QCC2072_SERVICE_QUARANTINE &&
              QCC2072_PROVIDER_WLAN_CONFIG==QCC2072_SERVICE_WLAN_CONFIG &&
              QCC2072_PROVIDER_HTC==QCC2072_SERVICE_HTC &&
              QCC2072_PROVIDER_HTC_SETUP==QCC2072_SERVICE_HTC_SETUP,"provider states");

static void barrier() { __asm__ volatile("dsb sy" ::: "memory"); }
static int owned(void *opaque,uint64_t generation,uint64_t cookie)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || p->quarantined || generation!=p->record.generation || cookie!=p->record.cookie)
        return QCC2072_SESSION_STALE;
    barrier();const auto *expected=reinterpret_cast<const uint64_t *>(&p->record);
    for(unsigned i=0;i<sizeof(p->record)/8;i++)
        if(p->control[i]!=expected[i])return QCC2072_SESSION_STALE;
    if(*reinterpret_cast<volatile uint32_t *>(p->pci)!=0x111217cbU ||
       *reinterpret_cast<volatile uint32_t *>(p->pci+0x2c)!=0xe14f105bU)
        return QCC2072_WRONG_DEVICE;
    return 0;
}
static int enable_dma(void *opaque,uint64_t generation,uint64_t cookie)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    int rc=owned(p,generation,cookie);if(rc)return rc;
    auto *command=reinterpret_cast<volatile uint16_t *>(p->pci+4);
    uint16_t old=*command;
    if(p->dma_started || old!=2)return QCC2072_DEVICE_NOT_QUIESCENT;
    /* Mark ownership before the MMIO write: failed readback never frees DMA. */
    p->dma_started=true;barrier();
#ifdef QCC2072_HOST_PROXY
    if(qcc_host_command_write16(6,command))return QCC2072_RUNTIME_IO;
#else
    *command=6;
#endif
    barrier();
    return *command==6 ? 0 : QCC2072_RUNTIME_IO;
}
static int read32(void *opaque,uint32_t offset,uint32_t *value)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    int rc=owned(p,p->record.generation,p->record.cookie);if(rc)return rc;
    if(!value || (offset&3) || offset>p->record.bar_bytes-4)return QCC2072_BAD_REGISTER;
#ifdef QCC2072_HOST_PROXY
    return qcc_host_bar_read32(offset,value);
#else
    *value=*reinterpret_cast<volatile uint32_t *>(p->bar+offset);barrier();return 0;
#endif
}
static int write32(void *opaque,uint32_t offset,uint32_t value)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    int rc=owned(p,p->record.generation,p->record.cookie);if(rc)return rc;
    if((offset&3) || offset>p->record.bar_bytes-4)return QCC2072_BAD_REGISTER;
#ifdef QCC2072_HOST_PROXY
    return qcc_host_bar_write32(offset,value);
#else
    barrier();*reinterpret_cast<volatile uint32_t *>(p->bar+offset)=value;barrier();return 0;
#endif
}
static int sync_buffer(void *opaque,const qcc2072_dma_buffer *b,size_t offset,
                        size_t length,uint32_t direction)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    int rc=owned(p,p->record.generation,p->record.cookie);if(rc)return rc;
    if(!b || !length || offset>b->capacity || length>b->capacity-offset ||
       (direction!=QCC2072_SYNC_DEVICE && direction!=QCC2072_SYNC_CPU) ||
       qcc2072_dma_buffer_validate(&p->admission,b,b->capacity,16) ||
       b->cpu!=p->dma+(b->physical-p->record.dma_pa))return QCC2072_DMA_INVALID;
    uintptr_t first=reinterpret_cast<uintptr_t>(b->cpu)+offset,last=first+length;
    if(last<first)return QCC2072_DMA_INVALID;
    /* The admitted mapping is normal, non-cacheable memory. DSB orders actual
     * CPU accesses against the doorbell and DMA completion in both directions.
     * No cacheable alias may exist; the monitor verifies that before admission. */
#ifdef QCC2072_HOST_PROXY
    return qcc_host_dma_sync(b->physical+offset,reinterpret_cast<uint8_t *>(first),length,direction);
#else
    barrier();return 0;
#endif
}
static uint64_t now_ms(void *)
{
    uint64_t nanoseconds=0;absolutetime_to_nanoseconds(mach_absolute_time(),&nanoseconds);
    return nanoseconds/1000000;
}
static void plog(qcc2072_provider *p,const char *fmt,...) __attribute__((format(printf,2,3)));
static void plog(qcc2072_provider *p,const char *fmt,...)
{
    if(!p->callbacks.log)return;
    va_list ap;va_start(ap,fmt);vsnprintf(p->log_line,sizeof(p->log_line),fmt,ap);va_end(ap);
    p->callbacks.log(p->callbacks.context,p->log_line);
}
/* One line whenever the connect machine's state, step or wait changed, with what caused it. */
static void assoc_trace(qcc2072_provider *p,const char *cause,uint32_t value)
{
    if(!p->callbacks.log)return;
    const auto &a=p->assoc;
    unsigned op=a.pc<a.prog_len?a.prog[a.pc].op:0;
    decltype(p->trace) v={a.state,a.prog_kind,a.pc,static_cast<uint8_t>(op),a.wait,a.response,a.acked,a.tries};
    if(!memcmp(&v,&p->trace,sizeof(v)))return;
    plog(p,"assoc t=%llu %s %#x: %s->%s %s step %u/%u %s wait %s response %u ack %u tries %u",
         (unsigned long long)now_ms(p),cause,value,qcc2072_assoc_state_name(p->trace.state),
         qcc2072_assoc_state_name(a.state),qcc2072_assoc_prog_name(a.prog_kind),a.pc,a.prog_len,
         qcc2072_assoc_op_name(op),qcc2072_assoc_wait_name(a.wait),a.response,a.acked,a.tries);
    p->trace=v;
}
static void caps_log(qcc2072_provider *p)
{
    const auto &c=p->assoc.caps;
    if(p->caps_logged || !c.service_ready || !c.ext_ready)return;
    p->caps_logged=true;
    plog(p,"assoc.caps service_ready=%u ext_ready=%u preferred_hw_mode=%u rf_chains=%u ht_cap_info=[%#x,%#x] "
         "vht_cap=%#x chainmask tx=%#x rx=%#x hw_tx_power=[%u,%u] bands=%#x ampdu_density=%u",
         c.service_ready,c.ext_ready,c.preferred_hw_mode,c.num_rf_chains,c.ht_cap_info[0],c.ht_cap_info[1],
         c.vht_cap,c.tx_chainmask,c.rx_chainmask,c.hw_min_tx_power,c.hw_max_tx_power,c.supported_bands,c.ampdu_density);
}
static int allocate_bytes(qcc2072_provider *p,size_t size,qcc2072_dma_buffer *out)
{
    uint64_t at=(p->allocation+4095)&~UINT64_C(4095);
    if(!size || at>p->record.dma_bytes || size>p->record.dma_bytes-at)
        return QCC2072_DMA_INVALID;
    *out={p->dma+at,size,p->record.dma_iova+at,p->record.dma_pa+at};
    p->allocation=at+size;return 0;
}
static int allocate(void *opaque,const qcc2072_wlfw_memory_request *request,qcc2072_dma_buffer *out)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    int rc=owned(p,p->record.generation,p->record.cookie);if(rc)return rc;
    if(!request || !out)return QCC2072_INVALID_ARGUMENT;
    /* Linux's dma_alloc_coherent hands the firmware >=1 MiB-aligned blocks for
     * chunks this large; match it rather than offering 4 KiB-aligned memory. */
    if(request->bytes>=0x100000)p->allocation=(p->allocation+0xfffff)&~UINT64_C(0xfffff);
    return allocate_bytes(p,request->bytes,out);
}
static void state_changed(void *opaque,qcc2072_service_state state,int reason)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(state==QCC2072_SERVICE_QUARANTINE)p->quarantined=true;
    if(p->callbacks.state_changed)p->callbacks.state_changed(p->callbacks.context,static_cast<unsigned>(state),reason);
}
/* Exact pre-INIT SoC setup: cookie translation, WBM idle links, TCL/WBM and
 * REO rings. RXDMA/pdev setup is after actual READY and HTT version negotiation.
 * These flags attest successful MMIO/readback, not independent device execution. */
static int admit_wmi_datapath(void *opaque,uint64_t generation,uint64_t cookie)
{
    int rc=owned(opaque,generation,cookie);
    auto *p=static_cast<qcc2072_provider *>(opaque);
    return rc ? rc : (p->datapath.active && p->reo.activated &&
        !p->datapath.quarantined && !p->reo.quarantined ? 0 : QCC2072_RUNTIME_UNSUPPORTED);
}
enum { SCAN_IDLE, SCAN_CHAN_LIST, SCAN_VDEV, SCAN_START, SCAN_RUNNING };
/* SERVICE_READY_EXT on the A16 reports one MAC/PHY (hw modes 0 and 9) as pdev 1; ath12k
 * uses that pdev id for the channel list and the station vdev. */
#define QCC2072_SCAN_PDEV_ID 1U
/* The channel set the firmware is given: its own regulatory rules, never a host guess. */
static unsigned scan_channels(const qcc2072_provider *p,qcc2072_scan_channel *out)
{
    if(!p->wmi.reg_seen)return 0;
    return qcc2072_scan_channels_from_rules(p->wmi.reg_rules,p->wmi.reg_rule_count,out,QCC2072_SCAN_MAX_CHANNELS);
}
static void scan_emit(qcc2072_provider *p,uint32_t type,int32_t status)
{
    auto &e=p->scan_event;
    e.generation=p->record.generation;e.transaction=p->scan_request.transaction;
    e.type=type;e.status=status;e.link_transaction=0;
    if(p->callbacks.station_event)p->callbacks.station_event(p->callbacks.context,&e);
}
static void scan_finish(qcc2072_provider *p,int32_t status)
{
    p->scan_stage=SCAN_IDLE;memset(&p->scan_event.bss,0,sizeof(p->scan_event.bss));
    /* The station bridge accepts SCAN_DONE only with status 0. A failed, preempted
     * or expired scan must end as ERROR, or the bridge stays busy and WCL never
     * receives APPLE80211_M_WCL_SCAN_DONE (re/wifi-ui/FAILURES.md 15). */
    scan_emit(p,status?SNAP_STATION_ERROR:SNAP_STATION_SCAN_DONE,status);
}
/* Called for every accepted WMI event; reports only our running scan. */
static void scan_observe(qcc2072_provider *p)
{
    const auto &w=p->last_wmi_event;
    if(p->scan_stage!=SCAN_RUNNING)return;
    if(w.kind==QCC2072_WMI_EVENT_BSS) {
        p->scan_event.bss=w.bss;
        /* ath12k without firmware dB-to-dBm conversion: snr + ATH12K_DEFAULT_NOISE_FLOOR.
         * Not calibrated here, so SNAP_STATION_BSS_RSSI stays clear in bss.observed. */
        p->scan_event.bss.rssi_dbm=(int16_t)((int32_t)w.snr-95);
        /* Keep the AP's elements for a later connect, one entry per BSSID, refreshed in place.
         * When full, a BSS of the SSID a directed scan asked for always gets a slot (the
         * weakest other SSID gives way); otherwise only a stronger sighting replaces the weakest. */
        const unsigned slots=sizeof(p->bss_cache)/sizeof(p->bss_cache[0]);
        const auto &want=p->scan_request;
        auto wanted=[&](const snap_station_bss &x){return want.ssid_length && x.ssid_length==want.ssid_length &&
                                                         !memcmp(x.ssid,want.ssid,want.ssid_length);};
        unsigned slot=slots,weakest=slots;
        for(unsigned i=0;i<slots && slot==slots;i++)
            if(p->bss_cache[i].frequency_mhz && !memcmp(p->bss_cache[i].bssid,w.bss.bssid,6))slot=i;
        for(unsigned i=0;i<slots && slot==slots;i++)if(!p->bss_cache[i].frequency_mhz)slot=i;
        if(slot==slots) {
            bool directed=wanted(w.bss);
            for(unsigned i=0;i<slots;i++)
                if((!directed || !wanted(p->bss_cache[i])) &&
                   (weakest==slots || p->bss_cache[i].rssi_dbm<p->bss_cache[weakest].rssi_dbm))weakest=i;
            if(weakest<slots && (directed || p->bss_cache[weakest].rssi_dbm<p->scan_event.bss.rssi_dbm))slot=weakest;
        }
        if(slot<slots){p->bss_cache[slot]=w.bss;p->bss_cache[slot].rssi_dbm=p->scan_event.bss.rssi_dbm;}
        p->scan_results++;scan_emit(p,SNAP_STATION_BSS,SNAP_STATION_OK);
    } else if(w.kind==QCC2072_WMI_EVENT_SCAN && w.scan_id==QCC2072_SCAN_ID && w.vdev_id==0) {
        if(w.scan_type&QCC2072_SCAN_COMPLETED)scan_finish(p,SNAP_STATION_OK);
        else if(w.scan_type&(QCC2072_SCAN_START_FAILED|QCC2072_SCAN_DEQUEUED|QCC2072_SCAN_PREEMPTED))
            scan_finish(p,SNAP_STATION_CANCELLED);
    }
}
/* Builds the stage's frame once and keeps it across CE/HTC backpressure. */
static int scan_step(qcc2072_provider *p,uint64_t now)
{
    if(p->scan_stage==SCAN_RUNNING) {
        if(now>=p->scan_deadline)scan_finish(p,SNAP_STATION_CANCELLED);
        return 0;
    }
    if(!p->scan_command_bytes) {
        qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
        unsigned count=scan_channels(p,all);
        if(!count){scan_finish(p,SNAP_STATION_NOT_READY);return 0;}
        if(p->scan_stage==SCAN_CHAN_LIST) {
            p->scan_command_bytes=qcc2072_scan_chan_list(p->scan_command,sizeof(p->scan_command),
                                                         QCC2072_SCAN_PDEV_ID,all,count);
        } else if(p->scan_stage==SCAN_VDEV) {
            p->scan_command_bytes=qcc2072_scan_vdev_create(p->scan_command,sizeof(p->scan_command),0,
                                                           QCC2072_SCAN_PDEV_ID,p->wmi.mac,p->wmi.rf_chains);
        } else {
            const auto &r=p->scan_request;uint16_t channels[QCC2072_SCAN_MAX_CHANNELS];unsigned n=r.channel_count;
            if(n)for(unsigned i=0;i<n;i++)channels[i]=r.channels_mhz[i];
            else for(n=0;n<count;n++)channels[n]=all[n].mhz;
            /* A wildcard probe (one empty SSID) unless the request names one, as mac80211 asks. */
            qcc2072_scan_start_args a={0,channels,n,1,r.ssid_length,r.ssid};
            p->scan_command_bytes=qcc2072_scan_start(p->scan_command,sizeof(p->scan_command),&a);
        }
        if(!p->scan_command_bytes){scan_finish(p,SNAP_STATION_INVALID);return 0;}
    }
    int rc=qcc2072_service_send_wmi(&p->service,p->scan_command,p->scan_command_bytes);
    if(rc==QCC2072_RUNTIME_FULL)return 0;
    if(rc)return rc;
    p->scan_command_bytes=0;
    if(p->scan_stage==SCAN_CHAN_LIST){p->chan_list_sent=true;p->chan_list_revision=p->wmi.reg_revision;
        p->scan_stage=p->vdev_created?SCAN_START:SCAN_VDEV;}
    else if(p->scan_stage==SCAN_VDEV){p->vdev_created=true;p->scan_stage=SCAN_START;}
    else {p->scan_stage=SCAN_RUNNING;p->scan_deadline=now+QCC2072_SCAN_MAX_TIME_MS+5000;}
    return 0;
}
/* dp-io callbacks run inside provider poll; data_tx may be called from them. */
static void data_rx(void *opaque,const uint8_t *frame,size_t length,const qcc2072_dpio_rx_info *info)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(p->data_callbacks.rx)p->data_callbacks.rx(p->data_callbacks.context,frame,length,info);
}
static void data_tx_done(void *opaque,const qcc2072_dpio_tx_result *result)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(p->data_callbacks.tx_done)p->data_callbacks.tx_done(p->data_callbacks.context,result);
}
/* ath12k_dp_peer_setup: default routing, then a REO queue for TIDs 0..16, one WMI
 * command per poll; the frame is kept across CE/HTC backpressure. */
static int peer_setup_step(qcc2072_provider *p)
{
    if(!p->data_command_bytes) {
        unsigned s=p->peer_setup_stage-1;
        if(!s)p->data_command_bytes=qcc2072_dpio_wmi_default_routing(p->data_command,sizeof(p->data_command),
                                                                      p->peer_setup_vdev,p->peer_setup_mac);
        else {
            uint32_t queue=0;int rc=qcc2072_dpio_reo_qdesc(&p->dpio,s-1,&queue);
            if(rc)return rc;
            p->data_command_bytes=qcc2072_dpio_wmi_reorder_setup(p->data_command,sizeof(p->data_command),
                                                                 p->peer_setup_vdev,p->peer_setup_mac,s-1,queue);
        }
        if(!p->data_command_bytes)return QCC2072_BAD_STATE;
    }
    int rc=qcc2072_service_send_wmi(&p->service,p->data_command,p->data_command_bytes);
    if(rc==QCC2072_RUNTIME_FULL)return 0;
    if(rc)return rc;
    p->data_command_bytes=0;
    p->peer_setup_stage=p->peer_setup_stage>=1+QCC2072_DPIO_TIDS?0:p->peer_setup_stage+1;
    return 0;
}
static bool service_bit(const qcc2072_provider *p,unsigned n)
{
    return n<512 && ((p->wmi.services[n/32]>>(n%32))&1U);
}
/* ath12k_dp_rx_peer_tid_setup for the BSS peer: dp-io owns the REO queue descriptors. */
static int assoc_reo_queue(void *opaque,const uint8_t *,uint32_t,unsigned tid,uint64_t *queue)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p->dpio_ready)return QCC2072_BAD_STATE;
    uint32_t iova=0;int rc=qcc2072_dpio_reo_qdesc(&p->dpio,tid,&iova);
    if(!rc)*queue=iova;
    return rc;
}
/* Data path for the associated BSS (ath12k_dp_vdev_tx_attach + the AP's AST from PEER_MAP),
 * before ASSOCIATED reaches snap_station, so M2 can go out as soon as M1 arrives. */
static int assoc_data_path(qcc2072_provider *p,bool up)
{
    if(!p->dpio_ready)return 0;
    if(!up)return qcc2072_dpio_clear_bss(&p->dpio);
    qcc2072_assoc_link l;
    int rc=qcc2072_assoc_link_info(&p->assoc,&l);
    if(rc)return rc;
    qcc2072_dpio_vdev v={};
    v.vdev_id=static_cast<uint8_t>(l.vdev_id);v.pdev_id=static_cast<uint8_t>(l.pdev_id);v.lmac_id=0;v.bank_id=0;
    v.encap=static_cast<uint8_t>(l.tx_encap);v.qos=l.qos;memcpy(v.mac,l.own_mac,6);
    rc=qcc2072_dpio_set_vdev(&p->dpio,&v);
    return rc?rc:qcc2072_dpio_set_bss(&p->dpio,l.bssid);
}
/* Notices become snap_station events from the poll loop. A data-path configuration error is
 * dp-io's own (it quarantines itself; dpio_poll then fails the provider); the handshake would
 * time out, so the event is still delivered. */
static void assoc_emit(qcc2072_provider *p,const qcc2072_assoc_notice *n)
{
    static const char *const names[]={"?","ASSOCIATED","CONNECTED","CONTROL_DONE","FAILED","CANCELLED","DISCONNECTED"};
    plog(p,"assoc notice %s status %d transaction %llu reason %u aid %u detail %#x (%s at %s)",
         n->type<7?names[n->type]:"?",n->status,(unsigned long long)n->transaction,n->reason,n->aid,n->detail,
         qcc2072_assoc_kind_name(n->detail),qcc2072_assoc_op_name(n->detail&0xffU));
    /* A teardown the connect engine asked for (qcc2072_provider_disconnect) completes internally. */
    if(n->type==QCC2072_ASSOC_N_CONTROL_DONE && (n->transaction>>62)==1)return;
    auto &e=p->assoc_event;memset(&e,0,sizeof(e));
    e.generation=p->record.generation;e.transaction=n->transaction;e.status=n->status;
    switch(n->type) {
    case QCC2072_ASSOC_N_ASSOCIATED:
        e.type=SNAP_STATION_ASSOCIATED;p->assoc_dp_rc=assoc_data_path(p,true);
        plog(p,"assoc data path %s: rc %d",p->dpio_ready?"vdev+bss configured":"not attached (association only)",p->assoc_dp_rc);
        break;
    case QCC2072_ASSOC_N_CONNECTED:e.type=SNAP_STATION_CONNECTED;break;
    case QCC2072_ASSOC_N_CONTROL_DONE:e.type=SNAP_STATION_CONTROL_DONE;e.link_transaction=n->link_transaction;break;
    case QCC2072_ASSOC_N_CANCELLED:e.type=SNAP_STATION_CANCEL_ACK;e.status=SNAP_STATION_OK;(void)assoc_data_path(p,false);break;
    case QCC2072_ASSOC_N_DISCONNECTED:e.type=SNAP_STATION_DISCONNECTED;(void)assoc_data_path(p,false);break;
    default:e.type=SNAP_STATION_ERROR;if(!e.status)e.status=SNAP_STATION_NOT_READY;(void)assoc_data_path(p,false);break;
    }
    if(p->callbacks.station_event)p->callbacks.station_event(p->callbacks.context,&e);
}
/* One connect command per poll; CE FULL keeps the identical bytes inside the machine. */
static int assoc_step(qcc2072_provider *p,uint64_t now)
{
    const uint8_t *frame=nullptr;size_t length=0;
    int rc=qcc2072_assoc_poll(&p->assoc,now,&frame,&length);
    assoc_trace(p,"poll",0);
    if(!rc && length) {
        uint32_t id=static_cast<uint32_t>(frame[0])|static_cast<uint32_t>(frame[1])<<8|static_cast<uint32_t>(frame[2])<<16;
        rc=qcc2072_service_send_wmi(&p->service,frame,length);
        if(rc==QCC2072_RUNTIME_FULL)rc=0;
        else if(!rc){rc=qcc2072_assoc_sent(&p->assoc,now);assoc_trace(p,"sent",id);}
    }
    if(p->assoc.vdev_created)p->vdev_created=true;
    qcc2072_assoc_notice n;
    while(qcc2072_assoc_take_notice(&p->assoc,&n))assoc_emit(p,&n);
    return rc;
}
static int firmware_event(void *opaque,uint16_t service,const uint8_t *bytes,size_t length)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p->in_call || !p->wmi_active)return QCC2072_BAD_STATE;
    if(service==0x300) {
        if(!bytes || length<4)return QCC2072_BAD_WIRE;
        /* The connect machine waits for the BSS peer's map/unmap; dp-io keeps its AST. */
        if(bytes[0]==QCC2072_ASSOC_HTT_PEER_MAP || bytes[0]==QCC2072_ASSOC_HTT_PEER_UNMAP ||
           bytes[0]==QCC2072_ASSOC_HTT_PEER_MAP2 || bytes[0]==QCC2072_ASSOC_HTT_PEER_UNMAP2 ||
           bytes[0]==QCC2072_ASSOC_HTT_PEER_MAP3)
            {(void)qcc2072_assoc_htt_event(&p->assoc,now_ms(p),bytes,length);assoc_trace(p,"htt",bytes[0]);}
        if(bytes[0] && p->dpio_ready) {
            /* PEER_MAP2/3 carry the BSS peer's AST index/hash TCL needs for TX. */
            int x=qcc2072_dpio_htt_t2h(&p->dpio,bytes,length);
            if(x!=QCC2072_RUNTIME_UNSUPPORTED)return x;
        }
        if(bytes[0]) {
            /* T2H types the provider does not consume yet (the A16 sends 0x30 right after
             * VERSION_CONF) take ath12k's default case: counted, not acted on. */
            p->htt_unhandled++;return 0;
        }
        /* VERSION_CONF: ath12k reads only word 0 (major 3); the A16's firmware appends the
         * TCL metadata-version TLV the request carried. */
        if(!p->htt_requested || p->htt_ready || p->wmi.state!=QCC2072_WMI_READY ||
           bytes[2]!=3 || bytes[3])return QCC2072_BAD_WIRE;
        p->htt_ready=true;return 0;
    }
    int x=qcc2072_wmi_receive(&p->wmi,p->record.generation,p->record.cookie,
                              now_ms(p),service,bytes,length,&p->last_wmi_event);
    if(!x)scan_observe(p);
    /* Every accepted event, boot capabilities included; the connect machine ignores the rest. */
    if(!x)x=qcc2072_assoc_wmi_event(&p->assoc,now_ms(p),bytes,length);
    if(!x){assoc_trace(p,"wmi",p->last_wmi_event.id);caps_log(p);}
    return x;
}
static bool digest(const uint8_t *bytes,size_t length,const char *hex)
{
    uint8_t actual[32];q1n1_sha256(bytes,length,actual);
    static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++)
        if(digits[actual[i]>>4]!=hex[i*2] || digits[actual[i]&15]!=hex[i*2+1])return false;
    return true;
}
static bool asset(qcc2072_provider *p,uint64_t offset,uint64_t length,const char *hash,qcc2072_slice *out)
{
    if(!length || offset>p->record.allocate_offset || length>p->record.allocate_offset-offset)
        return false;
    out->bytes=p->dma+offset;out->length=static_cast<size_t>(length);
    return digest(out->bytes,out->length,hash);
}
static bool protected_allocation(qcc2072_provider *p,size_t bytes,qcc2072_dma_buffer *out)
{
    if(p->protected_count>=80 || allocate_bytes(p,bytes,out))return false;
    p->protected_buffers[p->protected_count++]=*out;return true;
}
static void dispose(qcc2072_provider *p)
{
    for(unsigned i=0;i<5;i++)if(p->mapping[i])p->mapping[i]->release();
    if(p->owner)p->owner->release();IOFree(p,sizeof(*p));
}
static bool prepare_image(qcc2072_provider *p)
{
    qcc2072_slice container,board,regdb;
    if(!asset(p,p->record.firmware_offset,p->record.firmware_bytes,
       "4c6a1be1f5bfad76319755ff76904abb21c4c7ece5293cc5f33a20b1f4c35254",&container) ||
       !asset(p,p->record.board_offset,p->record.board_bytes,
       "eeb1311ec3e4955323f1b62247d4caeaad1f292938e2077dfdc466d6a4d3be86",&board) ||
       !asset(p,p->record.regdb_offset,p->record.regdb_bytes,
       "9752107372bdefcd2dd11a394459f8eaec0166a3ca1e680f10ad9a243ac2d360",&regdb))return false;
    qcc2072_firmware parsed={};if(qcc2072_parse_firmware(container.bytes,container.length,&parsed))return false;
    qcc2072_service_config config={};
    config.io={p,owned,enable_dma,read32,write32,sync_buffer,now_ms,nullptr,nullptr};
    config.memory={p,owned,allocate,sync_buffer};
    config.event_context=p;config.state_changed=state_changed;config.firmware_event=firmware_event;
    config.local_node=1;config.local_port=0x100;config.discovery_timeout_ms=10000;
    auto &boot=config.boot;
    if(!protected_allocation(p,QCC2072_RUNTIME_ARENA_BYTES,&boot.arena) ||
       !protected_allocation(p,QCC2072_MHI_CHUNK,&boot.sbl) ||
       !protected_allocation(p,4096,&boot.vectors))return false;
    size_t skip=0;
    if(parsed.amss.length>=QCC2072_MHI_CHUNK+4 &&
       !memcmp(parsed.amss.bytes+QCC2072_MHI_CHUNK,"\177ELF",4))skip=QCC2072_MHI_CHUNK;
    uint32_t count=static_cast<uint32_t>((parsed.amss.length-skip+QCC2072_MHI_CHUNK-1)/QCC2072_MHI_CHUNK);
    if(!count || count>QCC2072_MHI_MAX_SEGMENTS)return false;
    size_t remaining=parsed.amss.length-skip;
    for(unsigned i=0;i<count;i++) {
        size_t bytes=remaining>QCC2072_MHI_CHUNK ? QCC2072_MHI_CHUNK : remaining;
        if(!protected_allocation(p,bytes,&p->segments[i]))return false;remaining-=bytes;
    }
    boot.segments=p->segments;boot.segment_count=count;boot.bar_bytes=static_cast<uint32_t>(p->record.bar_bytes);
    boot.sequence=1;boot.timeout_ms=10000;boot.event_msi[0]=1;boot.event_msi[1]=2;
    if(qcc2072_mhi_prepare(&p->admission,p->record.generation,p->record.cookie,&parsed.amss,
                           &boot.sbl,p->segments,count,&boot.vectors,&boot.image))return false;
    auto &fw=config.firmware;fw.admission=&p->admission;
    fw.board=board;fw.regdb=regdb;fw.m3_image=parsed.m3;fw.aux_image=parsed.aux;
    /* WLFW protects M3/AUX separately; its generic guard list must exclude them. */
    if(allocate_bytes(p,parsed.m3.length,&fw.m3) ||
       allocate_bytes(p,parsed.aux.length,&fw.aux) ||
       !protected_allocation(p,QCC2072_CE_ARENA_BYTES,&p->ce))return false;
    memcpy(fw.m3.cpu,parsed.m3.bytes,parsed.m3.length);
    memcpy(fw.aux.cpu,parsed.aux.bytes,parsed.aux.length);
    qcc2072_dma_buffer reo_arena;
    if(allocate_bytes(p,QCC2072_REO_ARENA_BYTES,&reo_arena))return false;
    qcc2072_dma_buffer guards[82];
    for(unsigned i=0;i<p->protected_count;i++)guards[i]=p->protected_buffers[i];
    guards[p->protected_count]=fw.m3;guards[p->protected_count+1]=fw.aux;
    qcc2072_reo_ops reo_ops={p,owned,read32,write32,sync_buffer};
    if(qcc2072_reo_init(&p->reo,&reo_ops,&p->admission,&reo_arena,guards,
                        p->protected_count+2,static_cast<uint32_t>(p->record.bar_bytes)))return false;
    if(p->protected_count>=80)return false;
    p->protected_buffers[p->protected_count++]=reo_arena;
    qcc2072_dma_buffer datapath_arena;
    if(allocate_bytes(p,QCC2072_DATAPATH_ARENA_BYTES,&datapath_arena))return false;
    for(unsigned i=0;i<p->protected_count;i++)guards[i]=p->protected_buffers[i];
    guards[p->protected_count]=fw.m3;guards[p->protected_count+1]=fw.aux;
    if(qcc2072_datapath_init(&p->datapath,&reo_ops,&p->admission,&datapath_arena,
                             guards,p->protected_count+2))return false;
    if(p->protected_count>=80)return false;
    p->protected_buffers[p->protected_count++]=datapath_arena;
    /* MGMT_TX_SEND frames (8 x 512-byte slots), reserved before WLFW memory requests. */
    if(!protected_allocation(p,QCC2072_ASSOC_MGMT_DMA_BYTES,&p->assoc_mgmt))return false;
    qcc2072_assoc_hooks hooks={p,p->assoc_mgmt,sync_buffer,assoc_reo_queue,nullptr};
    if(qcc2072_assoc_init(&p->assoc,&hooks))return false;
    fw.protected_buffers=p->protected_buffers;fw.protected_count=p->protected_count;
    fw.memory_budget_bytes=static_cast<uint32_t>(p->record.dma_bytes-p->allocation);
    fw.timeout_ms=10000;fw.exact_inputs_verified=1;fw.supports_global_reset=0;
    return !qcc2072_service_init(&p->service,&config);
}
IOReturn qcc2072_provider_prepare(IOService *owner,const qcc2072_provider_callbacks *callbacks,qcc2072_provider **result)
{
    if(!owner || !callbacks || !result)return kIOReturnBadArgument;
    *result=nullptr;
    auto *data=OSDynamicCast(OSData,owner->getProperty("snapintosh,qcc2072-admission"));
    if(!data || data->getLength()!=sizeof(qcc2072_provider_record))return kIOReturnNotReady;
    auto *p=static_cast<qcc2072_provider *>(IOMallocZero(sizeof(qcc2072_provider)));
    if(!p)return kIOReturnNoMemory;
    memcpy(&p->record,data->getBytesNoCopy(),sizeof(p->record));const auto &r=p->record;
    p->callbacks=*callbacks;
    if(r.magic!=QCC2072_PROVIDER_MAGIC || r.version!=1 || r.bytes!=sizeof(r) || r.state!=1 ||
       !r.generation || !r.cookie || r.pci_id!=0x111217cb || r.pci_subsystem!=0xe14f105b ||
       r.sid!=QCC2072_DMA_SID || r.proofs!=QCC2072_DMA_REQUIRED_PROOFS ||
       r.bar_pa!=0x78000000 || r.bar_bytes!=0x100000 || r.bar2_pa!=0x78200000 ||
       r.bar2_bytes!=0x1000 || r.ecam_pa!=0x780100000 || r.dma_bytes!=QCC2072_PROVIDER_DMA_BYTES ||
       r.allocate_offset>r.dma_bytes || (r.allocate_offset&4095) ||
       r.cache_line!=64 || r.reserved[0] || r.reserved[1] || r.reserved[2]) {
        dispose(p);return kIOReturnBadArgument;
    }
    const uint64_t addresses[5]={r.bar_pa,r.dma_pa,r.bar2_pa,r.ecam_pa,r.control_pa};
    const uint64_t lengths[5]={r.bar_bytes,r.dma_bytes,r.bar2_bytes,4096,4096};
    for(unsigned i=0;i<5;i++) {
        IOOptionBits options=kIOMapAnywhere|(i==1 ? kIOMapWriteCombineCache : kIOMapInhibitCache);
        if(i==4)options|=kIOMapReadOnly;
        p->mapping[i]=owner->mapDeviceMemoryWithIndex(i,options);
        if(!p->mapping[i] || p->mapping[i]->getPhysicalAddress()!=addresses[i] ||
           p->mapping[i]->getLength()!=lengths[i]) {dispose(p);return kIOReturnNotReady;}
    }
    p->bar=reinterpret_cast<volatile uint8_t *>(p->mapping[0]->getVirtualAddress());
    p->dma=reinterpret_cast<uint8_t *>(p->mapping[1]->getVirtualAddress());
    p->pci=reinterpret_cast<volatile uint8_t *>(p->mapping[3]->getVirtualAddress());
    p->control=reinterpret_cast<volatile const uint64_t *>(p->mapping[4]->getVirtualAddress());
    p->map={r.dma_iova,r.dma_pa,r.dma_bytes,QCC2072_DMA_READ|QCC2072_DMA_WRITE};
    p->admission={static_cast<uint32_t>(r.pci_id),static_cast<uint32_t>(r.pci_subsystem),
        static_cast<uint32_t>(r.sid),static_cast<uint32_t>(r.proofs),r.generation,r.cookie,
        r.dma_pa,r.dma_bytes,r.guest_pa,r.guest_bytes,&p->map,1};
    if(qcc2072_dma_validate(&p->admission,r.generation,r.cookie) || owned(p,r.generation,r.cookie) ||
       *reinterpret_cast<volatile uint16_t *>(p->pci+4)!=2) {dispose(p);return kIOReturnNotReady;}
    p->allocation=r.allocate_offset;
    if(!prepare_image(p)) {dispose(p);return kIOReturnBadArgument;}
    owner->retain();p->owner=owner;*result=p;return kIOReturnSuccess;
}
uint64_t qcc2072_provider_generation(const qcc2072_provider *p) {return p ? p->record.generation : 0;}
IOReturn qcc2072_provider_begin(qcc2072_provider *p)
{
    if(!p || p->began || p->quarantined)return kIOReturnNotReady;
    if(p->in_call)return kIOReturnBusy;
    p->began=true;p->in_call=true;
    int rc=qcc2072_service_begin(&p->service);
    if(rc)p->quarantined=true;
    p->in_call=false;return rc ? kIOReturnIOError : kIOReturnSuccess;
}
IOReturn qcc2072_provider_poll(qcc2072_provider *p)
{
    if(!p || !p->began || p->quarantined)return kIOReturnNotReady;
    if(p->in_call)return kIOReturnBusy;
    p->in_call=true;
    int rc=qcc2072_service_poll(&p->service,32);
    if(!rc && p->service.state==QCC2072_SERVICE_FW_READY && !p->wmi_active) {
        qcc2072_wmi_config config={p,owned,admit_wmi_datapath};
        rc=qcc2072_wmi_init(&p->wmi,&config,p->record.generation,p->record.cookie,
                             now_ms(p),10000);
        if(!rc) {
            p->wmi_active=true;
            rc=qcc2072_service_enable_wlan(&p->service,&p->ce);
        }
    }
    if(!rc && p->wmi_active) {
        uint64_t now=now_ms(p);rc=qcc2072_wmi_poll(&p->wmi,now);
        if(!rc && p->wmi.state==QCC2072_WMI_INIT_ELIGIBLE && !p->reo.staged)
            rc=qcc2072_reo_stage(&p->reo);
        if(!rc && p->wmi.state==QCC2072_WMI_INIT_ELIGIBLE && !p->datapath.active)
            rc=qcc2072_datapath_begin(&p->datapath,&p->service.wlfw.qmi);
        if(!rc && p->wmi.state==QCC2072_WMI_INIT_ELIGIBLE && !p->reo.activated)
            rc=qcc2072_reo_activate(&p->reo);
        if(!rc && p->wmi.state==QCC2072_WMI_INIT_ELIGIBLE && !p->wmi_command_bytes) {
            rc=qcc2072_wmi_init_command(&p->wmi,now,p->wmi_command,
                                        sizeof(p->wmi_command),&p->wmi_command_bytes);
            if(rc==QCC2072_BAD_STATE) {p->wmi_init_blocked=true;rc=0;}
            else if(!rc)p->wmi_init_blocked=false;
        }
        if(!rc && p->wmi_command_bytes) {
            rc=qcc2072_service_send_wmi(&p->service,p->wmi_command,p->wmi_command_bytes);
            if(rc==QCC2072_RUNTIME_FULL)rc=0;
            else if(!rc)p->wmi_command_bytes=0;
        }
        if(!rc && p->wmi.state==QCC2072_WMI_READY && !p->hw_mode_sent) {
            /* PDEV_SET_HW_MODE(0x401e), tag515: SOC pdev0, DBS1, no band map. */
            const uint8_t cmd[20]={0x1e,0x40,0,0,12,0,3,2,0,0,0,0,1,0,0,0,0,0,0,0};
            rc=qcc2072_service_send_wmi(&p->service,cmd,sizeof(cmd));
            if(rc==QCC2072_RUNTIME_FULL)rc=0;
            else if(!rc)p->hw_mode_sent=true;
        }
        if(!rc && p->hw_mode_sent && !p->htt_requested) {
            /* VERSION_REQ + TCL_METADATA_VERSION TLV(tag5,len4,value2). */
            const uint8_t request[8]={0,0,0,0,5,4,2,0};
            rc=qcc2072_service_send_htt(&p->service,request,sizeof(request));
            if(rc==QCC2072_RUNTIME_FULL)rc=0;
            else if(!rc) {p->htt_requested=true;p->htt_deadline=now+3000;}
        }
        if(!rc && p->htt_requested && !p->htt_ready && now>=p->htt_deadline)
            rc=QCC2072_DEADLINE;
        if(!rc && p->htt_ready && !p->datapath.rx_prepared)
            rc=qcc2072_datapath_rx_prepare(&p->datapath);
        if(!rc && p->htt_ready && p->htt_setup_submitted<8) {
            uint8_t command[68];size_t bytes=0;
            rc=qcc2072_datapath_htt_command(&p->datapath,p->htt_setup_submitted,
                                           command,sizeof(command),&bytes);
            if(!rc)rc=qcc2072_service_send_htt(&p->service,command,bytes);
            if(rc==QCC2072_RUNTIME_FULL)rc=0;
            else if(!rc)p->htt_setup_submitted++;
        }
        if(!rc && p->htt_setup_submitted>=8 && !p->dpio_ready) {
            /* Peer metadata only selects the RX peer-id mask; V1A/V1B share it. */
            const qcc2072_dpio_callbacks cb={p,data_rx,data_tx_done};
            rc=qcc2072_dpio_init(&p->dpio,&p->datapath,&p->reo,&cb,3);
            if(!rc)p->dpio_ready=true;
        }
        if(!rc && p->datapath.active)rc=qcc2072_datapath_poll(&p->datapath);
        if(!rc && p->dpio_ready)rc=qcc2072_dpio_poll(&p->dpio,64);
        if(!rc && p->dpio_ready && p->peer_setup_stage)rc=peer_setup_step(p);
        if(!rc && p->scan_stage)rc=scan_step(p,now);
        if(!rc && p->assoc.state!=QCC2072_ASSOC_IDLE && p->assoc.state!=QCC2072_ASSOC_WEDGED)
            rc=assoc_step(p,now);
        /* Admit the native station only from observed facts: WMI READY (MAC),
         * SERVICE_READY, the firmware regulatory event and the HTT setup the scan
         * path requires. Connect once SERVICE_READY_EXT gave the HT capabilities (re/assoc). */
        if(!rc && !p->station_reported && p->wmi.state==QCC2072_WMI_READY && p->htt_ready &&
           p->htt_setup_submitted>=8 && p->wmi.reg_seen && p->callbacks.station_ready) {
            snap_station_ready ready;
            if(!qcc2072_wmi_snapshot(&p->wmi,&ready) &&
               (ready.observed&SNAP_STATION_READY_ALL)==SNAP_STATION_READY_ALL) {
                ready.capabilities=SNAP_STATION_CAP_SCAN|
                    (p->assoc.caps.ext_ready && p->assoc.caps.service_ready ? SNAP_STATION_CAP_CONNECT : 0U);
                p->station_reported=true;
                p->callbacks.station_ready(p->callbacks.context,&ready);
            }
        }
    }
    if(rc) {
        p->quarantined=true;
        (void)qcc2072_assoc_abort(&p->assoc);
        (void)qcc2072_reo_abort(&p->reo,rc);
        (void)qcc2072_datapath_abort(&p->datapath,rc);
        if(p->dpio_ready)(void)qcc2072_dpio_abort(&p->dpio,rc);
        if(p->wmi_active)(void)qcc2072_wmi_abort(&p->wmi,rc);
        (void)qcc2072_service_abort(&p->service,rc);
    }
    p->in_call=false;
    return rc ? kIOReturnIOError : kIOReturnSuccess;
}
/* CONNECT: the BSS must be in the scan cache (its elements drive rates, HT, WMM, RSN);
 * of the request's elements only the RSN one is used (snap_wpa2's, FAILURES.md 12). */
static int connect_submit(qcc2072_provider *p,const snap_station_request *r)
{
    if(p->scan_stage)return SNAP_STATION_BUSY;
    const snap_station_bss *b=nullptr;
    for(unsigned i=0;i<sizeof(p->bss_cache)/sizeof(p->bss_cache[0]);i++)
        if(p->bss_cache[i].frequency_mhz && !memcmp(p->bss_cache[i].bssid,r->bssid,6))b=&p->bss_cache[i];
    if(!b){plog(p,"connect refused: BSS not in the scan cache");return SNAP_STATION_NOT_READY;}
    if(r->channel_count>1 || (r->channel_count==1 && r->channels_mhz[0]!=b->frequency_mhz))return SNAP_STATION_INVALID;
    qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
    unsigned n=scan_channels(p,all),i=0;
    while(i<n && all[i].mhz!=b->frequency_mhz)i++;
    if(i==n)return SNAP_STATION_UNSUPPORTED;
    auto &c=p->connect_args;memset(&c,0,sizeof(c));
    c.transaction=r->transaction;c.vdev_id=0;c.pdev_id=QCC2072_SCAN_PDEV_ID;
    c.flags=(p->vdev_created?QCC2072_ASSOC_F_VDEV_CREATED:0U)|
            (service_bit(p,QCC2072_ASSOC_SERVICE_ETH_OFFLOAD)?QCC2072_ASSOC_F_ETH_OFFLOAD:0U)|
            (service_bit(p,QCC2072_ASSOC_SERVICE_11BE)?QCC2072_ASSOC_F_EHT:0U)|
            (p->dpio_ready?0U:QCC2072_ASSOC_F_ASSOC_ONLY);
    memcpy(c.own_mac,p->wmi.mac,6);memcpy(c.bssid,r->bssid,6);
    c.ssid_length=r->ssid_length;memcpy(c.ssid,r->ssid,r->ssid_length);
    c.freq_mhz=b->frequency_mhz;c.beacon_interval_tu=b->beacon_interval_tu;c.capability=b->capability;
    c.max_power_dbm=static_cast<int8_t>(all[i].max_power_half_db/2);c.max_reg_power_dbm=c.max_power_dbm;
    c.passive=(all[i].passive||all[i].dfs)?1:0;
    for(unsigned at=0;at+2U<=r->ie_length && at+2U+r->ies[at+1]<=r->ie_length;at+=2U+r->ies[at+1])
        if(r->ies[at]==48 && r->ies[at+1]+2U<=sizeof(c.rsn)) {
            c.rsn_length=static_cast<uint8_t>(r->ies[at+1]+2U);memcpy(c.rsn,r->ies+at,c.rsn_length);break;
        }
    c.ie_length=b->ie_length;memcpy(c.ies,b->ies,b->ie_length);
    int reason=0;uint8_t ap[SNAP_RSN_MAX_ELEMENT],x[SNAP_RSN_MAX_RSNXE];size_t xn=0;
    if(c.rsn_length && !qcc2072_assoc_ap_rsn(c.ies,c.ie_length,ap,x,&xn,&reason))
        plog(p,"connect refused: AP RSN: %s",snap_rsn_reason(reason));
    int rc=qcc2072_assoc_connect(&p->assoc,now_ms(p),&c);
    plog(p,"connect submit transaction %llu %u MHz passive %u rsn %u caps %s: rc %d",(unsigned long long)c.transaction,
         c.freq_mhz,c.passive,c.rsn_length,p->assoc.caps.ext_ready?"ext":"none",rc);
    assoc_trace(p,"connect",static_cast<uint32_t>(c.transaction));
    return rc;
}
int qcc2072_provider_submit(void *opaque,const snap_station_request *r)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || !r)return SNAP_STATION_INVALID;
    if(r->generation!=p->record.generation)return SNAP_STATION_STALE;
    if(p->in_call)return SNAP_STATION_BUSY;
    if(p->quarantined || !p->wmi_active || p->wmi.state!=QCC2072_WMI_READY || !p->htt_ready ||
       p->htt_setup_submitted<8 || !p->wmi.reg_seen)return SNAP_STATION_NOT_READY;
    if(r->type==SNAP_STATION_CONNECT)return connect_submit(p,r);
    if(r->type!=SNAP_STATION_SCAN)return SNAP_STATION_UNSUPPORTED;
    if(p->scan_stage)return SNAP_STATION_BUSY;
    /* No off-channel scan while a connection is being set up, handshaken or torn down. */
    if(p->assoc.state!=QCC2072_ASSOC_IDLE && p->assoc.state!=QCC2072_ASSOC_AUTHORIZED)return SNAP_STATION_BUSY;
    if(r->ssid_length>32 || r->channel_count>QCC2072_SCAN_MAX_CHANNELS)return SNAP_STATION_INVALID;
    for(unsigned i=0;i<r->channel_count;i++) {
        unsigned f=r->channels_mhz[i];
        if(!(f>=2412 && f<=2484) && !(f>=5150 && f<=5885))return SNAP_STATION_INVALID;
    }
    p->scan_request=*r;p->scan_results=0;
    /* A new regulatory revision (e.g. a country change) needs a fresh channel list. */
    if(p->chan_list_revision!=p->wmi.reg_revision)p->chan_list_sent=false;
    p->scan_stage=!p->chan_list_sent?SCAN_CHAN_LIST:!p->vdev_created?SCAN_VDEV:SCAN_START;
    return SNAP_STATION_OK;
}
/* KEY_INSTALL/KEY_REMOVE/PORT_AUTHORIZE/LINK_DISCONNECT from snap_station (snap_wpa2);
 * CONTROL_DONE comes later from the poll loop, never inline. */
int qcc2072_provider_control(void *opaque,const snap_station_control *c)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || !c)return SNAP_STATION_INVALID;
    if(c->generation!=p->record.generation)return SNAP_STATION_STALE;
    if(p->in_call)return SNAP_STATION_BUSY;
    if(p->quarantined || !p->wmi_active || p->wmi.state!=QCC2072_WMI_READY)return SNAP_STATION_NOT_READY;
    int rc=qcc2072_assoc_control(&p->assoc,now_ms(p),c);
    plog(p,"control type %u transaction %llu: rc %d",c->type,(unsigned long long)c->transaction,rc);
    assoc_trace(p,"control",c->type);
    return rc;
}
int qcc2072_provider_link_security(void *opaque,struct snap_wpa2_ap *ap)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || !ap)return SNAP_STATION_INVALID;
    if(p->in_call)return SNAP_STATION_BUSY;
    uint8_t rsn[SNAP_RSN_MAX_ELEMENT],x[SNAP_RSN_MAX_RSNXE];size_t rn=0,xn=0;
    if(qcc2072_assoc_link_security(&p->assoc,rsn,&rn,x,&xn))return SNAP_STATION_NOT_READY;
    memset(ap,0,sizeof(*ap));
    memcpy(ap->rsn,rsn,rn);ap->rsn_length=static_cast<uint8_t>(rn);
    memcpy(ap->rsnxe,x,xn);ap->rsnxe_length=static_cast<uint8_t>(xn);
    return SNAP_STATION_OK;
}
int qcc2072_provider_eapol_admit(void *opaque,const uint8_t *frame,size_t length,int transmit)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || !frame)return QCC2072_INVALID_ARGUMENT;
    return qcc2072_assoc_eapol_admit(&p->assoc,frame,length,transmit);
}
int qcc2072_provider_disconnect(void *opaque,uint64_t generation,uint64_t link_transaction,uint16_t reason)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p)return SNAP_STATION_INVALID;
    if(generation!=p->record.generation)return SNAP_STATION_STALE;
    if(p->in_call)return SNAP_STATION_BUSY;
    if(p->quarantined || !p->wmi_active || p->wmi.state!=QCC2072_WMI_READY)return SNAP_STATION_NOT_READY;
    snap_station_control c;memset(&c,0,sizeof(c));
    c.generation=generation;c.transaction=(UINT64_C(1)<<62)|++p->internal_control;
    c.link_transaction=link_transaction;c.type=SNAP_STATION_LINK_DISCONNECT;c.reason=reason?reason:3;
    int rc=qcc2072_assoc_control(&p->assoc,now_ms(p),&c);
    plog(p,"engine disconnect link %llu reason %u: rc %d",(unsigned long long)link_transaction,c.reason,rc);
    assoc_trace(p,"disconnect",c.reason);
    return rc;
}
int qcc2072_provider_firmware_build(const qcc2072_provider *p,uint32_t *build)
{
    if(!p || !build)return SNAP_STATION_INVALID;
    if(!p->wmi_active || !p->wmi.service_seen)return SNAP_STATION_NOT_READY;
    *build=p->wmi.fw_build;return SNAP_STATION_OK;
}
int qcc2072_provider_cancel(void *opaque,uint64_t generation,uint64_t transaction)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || generation!=p->record.generation)return SNAP_STATION_STALE;
    if(p->in_call)return SNAP_STATION_BUSY;
    if(p->assoc.state==QCC2072_ASSOC_CONNECTING) {
        int rc=qcc2072_assoc_cancel(&p->assoc,now_ms(p),transaction);
        assoc_trace(p,"cancel",static_cast<uint32_t>(transaction));
        return rc;
    }
    return SNAP_STATION_NOT_READY;
}
/* apple80211_channel {version 1, channel, flags}: band from APPLE80211_C_FLAG_2GHZ (0x8),
 * _5GHZ (0x10), _6GHZ (0x2000). Only channels in the set the firmware is given
 * (qcc2072_scan_default_channels) resolve; anything else refuses the request. */
int qcc2072_provider_channel(void *opaque,uint32_t version,uint32_t channel,uint32_t flags,uint16_t *mhz)
{
    if(!opaque || !mhz || version!=1)return SNAP_STATION_INVALID;
    if(flags&0x2000U)return SNAP_STATION_UNSUPPORTED;
    bool g2=(flags&0x8U)!=0,g5=(flags&0x10U)!=0;
    if(g2 && g5)return SNAP_STATION_INVALID;
    if(!g2 && !g5){g2=channel>=1 && channel<=14;g5=!g2;}
    unsigned f=g2 ? (channel==14 ? 2484U : 2407U+5U*channel) : 5000U+5U*channel;
    qcc2072_scan_channel all[QCC2072_SCAN_MAX_CHANNELS];
    unsigned n=scan_channels(static_cast<const qcc2072_provider *>(opaque),all);
    if(!n)return SNAP_STATION_NOT_READY;
    for(unsigned i=0;i<n;i++)if(all[i].mhz==f){*mhz=static_cast<uint16_t>(f);return SNAP_STATION_OK;}
    return SNAP_STATION_UNSUPPORTED;
}
int qcc2072_provider_stop(void *opaque,uint64_t generation)
{
    auto *p=static_cast<qcc2072_provider *>(opaque);
    if(!p || generation!=p->record.generation)return SNAP_STATION_STALE;
    if(p->in_call)return SNAP_STATION_BUSY;
    if(!p->dma_started)return SNAP_STATION_OK;
    p->quarantined=true;(void)qcc2072_assoc_abort(&p->assoc);(void)qcc2072_reo_abort(&p->reo,QCC2072_QUARANTINED);
    (void)qcc2072_datapath_abort(&p->datapath,QCC2072_QUARANTINED);
    if(p->dpio_ready)(void)qcc2072_dpio_abort(&p->dpio,QCC2072_QUARANTINED);
    (void)qcc2072_service_abort(&p->service,QCC2072_QUARANTINED);
    return SNAP_STATION_NOT_READY;
}
IOReturn qcc2072_provider_release(qcc2072_provider *p)
{
    if(!p)return kIOReturnBadArgument;
    if(p->dma_started || p->in_call)return kIOReturnBusy;
    dispose(p);return kIOReturnSuccess;
}
int qcc2072_provider_data_attach(qcc2072_provider *p,const qcc2072_dpio_callbacks *callbacks)
{
    if(!p || !callbacks)return QCC2072_INVALID_ARGUMENT;
    if(p->in_call)return QCC2072_BAD_STATE;
    p->data_callbacks=*callbacks;return 0;
}
int qcc2072_provider_data_configure(qcc2072_provider *p,const qcc2072_dpio_vdev *vdev,const uint8_t bssid[6])
{
    if(!p || !vdev)return QCC2072_INVALID_ARGUMENT;
    if(p->in_call || p->quarantined || !p->dpio_ready)return QCC2072_BAD_STATE;
    p->in_call=true;
    int rc=qcc2072_dpio_set_vdev(&p->dpio,vdev);
    if(!rc)rc=bssid?qcc2072_dpio_set_bss(&p->dpio,bssid):qcc2072_dpio_clear_bss(&p->dpio);
    p->in_call=false;return rc;
}
int qcc2072_provider_data_peer_setup(qcc2072_provider *p,uint32_t vdev_id,const uint8_t mac[6])
{
    if(!p || !mac)return QCC2072_INVALID_ARGUMENT;
    if(p->in_call || p->quarantined || !p->dpio_ready || p->peer_setup_stage)return QCC2072_BAD_STATE;
    memcpy(p->peer_setup_mac,mac,6);p->peer_setup_vdev=vdev_id;p->peer_setup_stage=1;
    return 0;
}
int qcc2072_provider_data_tx(qcc2072_provider *p,const uint8_t *frame,size_t length,uint64_t tag,
                             unsigned tid,unsigned flags)
{
    if(!p || !frame)return QCC2072_INVALID_ARGUMENT;
    if(p->quarantined || !p->dpio_ready)return QCC2072_BAD_STATE;
    /* Outside poll, or from a data callback (the WPA2 engine answers M1 with M2 there). */
    if(p->in_call && !p->dpio.in_callback)return QCC2072_BAD_STATE;
    return qcc2072_dpio_tx(&p->dpio,frame,length,tag,tid,flags);
}
