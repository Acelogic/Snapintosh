/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_IPI_H
#define SNAP_COMPAT_IPI_H
#include <stdint.h>
#define IPI_SYSREG(o0,o1,n,m,o2) \
    (((o0)<<20)|((o2)<<17)|((o1)<<14)|((n)<<10)|((m)<<1))
#define IPI_RR_LOCAL IPI_SYSREG(3,5,15,0,0)
#define IPI_RR_GLOBAL IPI_SYSREG(3,5,15,0,1)
#define IPI_SR IPI_SYSREG(3,5,15,1,1)
/* Zero-initialized state for one guest CPU. Requests received coalesce; only a
 * guest W1C acknowledgement consumes pending state. No guest RAM is changed.
 * acks counts acknowledgements which actually clear a pending interrupt. */
struct guest_ipi {
    uint64_t pending, requests, reads, acks, coalesced, last_request;
};
enum ipi_result {
    IPI_UNHANDLED, IPI_OK, IPI_BAD_CONFIG, IPI_BAD_DIRECTION,
    IPI_BAD_TARGET, IPI_BAD_VALUE
};
enum ipi_result guest_ipi_access(struct guest_ipi *ipi,uint64_t mpidr,
    uint64_t reg,int read,uint64_t *value);
/* Route requests to an admitted, prepared executor. The caller owns the
 * shared service lock for target discovery, publication and acknowledgement.
 * RR_LOCAL inherits the sender's cluster; RR_GLOBAL carries cluster bits16..23.
 * SR always addresses the caller. No guest completion flags are changed. */
enum ipi_result guest_ipi_route(struct guest_ipi *const states[],
    const uint64_t affinities[],unsigned count,uint64_t runnable,unsigned source,
    uint64_t reg,int read,uint64_t *value);
/* Cap an existing host deadline to a 1 ms delivery opportunity. A caller
 * using this transport must arm its owned physical timer on every executor,
 * even with the guest timer disabled. Never extend the independent watchdog. */
uint64_t guest_ipi_poll_delay(uint64_t host_hz,uint64_t budget);
/* Timer and IPI share the FIQ line but keep independent pending state. */
int guest_ipi_fiq(const struct guest_ipi *ipi,int timer_pending);
#endif
