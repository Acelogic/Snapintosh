/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_HTC_H
#define SNAP_QCC2072_HTC_H
#include "qcc2072-runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
enum qcc2072_htc_state {QCC2072_HTC_WAIT_READY,QCC2072_HTC_READY,QCC2072_HTC_WAIT_WMI,
 QCC2072_HTC_WMI_CONNECTED,QCC2072_HTC_WAIT_HTT,QCC2072_HTC_HTT_CONNECTED,
 QCC2072_HTC_SETUP_SENT,QCC2072_HTC_QUARANTINE};
struct qcc2072_htc {uint64_t generation,owner_cookie,last_ms,deadline_ms;uint32_t timeout_ms;
 uint16_t credits,credit_size,allocation,wmi_max,htt_max;uint8_t max_endpoints,wmi_endpoint,htt_endpoint,ready_seen,sequence[9];
 enum qcc2072_htc_state state;int quarantine_reason;};
struct qcc2072_htc_message {struct qcc2072_slice payload;uint16_t service;uint8_t endpoint;};
int qcc2072_htc_init(struct qcc2072_htc *,uint64_t generation,uint64_t owner_cookie,uint64_t now,uint32_t timeout_ms);
int qcc2072_htc_receive(struct qcc2072_htc *,uint64_t generation,uint64_t owner_cookie,uint64_t now,uint32_t pipe,const void *,size_t,struct qcc2072_htc_message *);
/* Output is committed send intent, retain across CE-full; abort on uncertain IO.
 * SETUP_SENT means emitted message only. WMI service/ready events remain required. */
int qcc2072_htc_next(struct qcc2072_htc *,uint64_t now,void *,size_t,size_t *,uint32_t *pipe);
int qcc2072_htc_wmi(struct qcc2072_htc *,uint64_t now,const void *,size_t,void *,size_t,size_t *);
/* Negotiated HTT endpoint has credit flow disabled; CE pipe4 is 256 bytes. */
int qcc2072_htc_htt(struct qcc2072_htc *,uint64_t now,const void *,size_t,void *,size_t,size_t *);
int qcc2072_htc_abort(struct qcc2072_htc *,int reason);
#ifdef __cplusplus
}
#endif
#endif
