/* SPDX-License-Identifier: MIT */
#ifndef SNAP_QCC2072_QRTR_H
#define SNAP_QCC2072_QRTR_H
#include "qcc2072-runtime.h"
#ifdef __cplusplus
extern "C" {
#endif
#define QCC2072_QRTR_CTRL 0xfffffffeU
#define QCC2072_QRTR_BROADCAST 0xffffffffU
#define QCC2072_QRTR_WLFW 0x45U
#define QCC2072_QRTR_WLFW_INSTANCE 0x101U /* version1, instance1; exact QCC2072 hw.c */
struct qcc2072_qrtr {
    uint64_t generation, owner_cookie;
    uint32_t local_node, local_port, remote_node, remote_port, pending_tx;
    uint8_t hello_sent, remote_known, service_present, quarantined;
};
struct qcc2072_qrtr_message {
    struct qcc2072_slice data;
    uint32_t node, port;
    uint8_t service_arrived, service_departed;
    /* Caller queues this control reply after runtime RX callback returns. */
    uint8_t reply[52];
    size_t reply_length;
};
int qcc2072_qrtr_init(struct qcc2072_qrtr *,uint32_t local_node,uint32_t local_port,
                      uint64_t generation,uint64_t owner_cookie);
/* Generated output is a committed send intent: if the transport cannot accept it,
 * quarantine this QRTR session rather than silently retrying mutated state. */
int qcc2072_qrtr_hello(struct qcc2072_qrtr *,void *,size_t,size_t *);
int qcc2072_qrtr_send(struct qcc2072_qrtr *,const void *,size_t,void *,size_t,size_t *);
int qcc2072_qrtr_receive(struct qcc2072_qrtr *,uint64_t generation,uint64_t owner_cookie,
                         const void *,size_t,struct qcc2072_qrtr_message *);
#ifdef __cplusplus
}
#endif
#endif
