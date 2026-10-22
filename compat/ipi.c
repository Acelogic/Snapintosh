/* SPDX-License-Identifier: MIT */
#include "ipi.h"
#ifndef SNAP_FAST_IPI
#define SNAP_FAST_IPI 0
#endif
#if SNAP_FAST_IPI
/* Other CPUs post and acknowledge without the service token (compat/fast-ipi.h,
 * docs/FAST-IPI-20261019.md): the shared words change atomically here too. */
#include "fast-ipi.h"
#define IPI_PENDING(x) __atomic_load_n(&x->pending,__ATOMIC_RELAXED)
#else
#define IPI_PENDING(x) x->pending
#endif
static enum ipi_result request_target(uint64_t mpidr,uint64_t reg,int read,
                                      uint64_t value,uint64_t *target)
{
    if (read) return IPI_BAD_DIRECTION;
    uint64_t allowed=reg==IPI_RR_LOCAL ? 0xff : 0xff00ff;
    if(value & ~allowed) return IPI_BAD_VALUE;
    *target=(value&0xff) | (reg==IPI_RR_LOCAL ?
        (mpidr&0xff00) : ((value>>8)&0xff00));
    return IPI_OK;
}
static void request(struct guest_ipi *ipi,uint64_t value)
#if SNAP_FAST_IPI
{fast_ipi_post(ipi,value);}
#else
{
    ipi->coalesced+=ipi->pending;
    ipi->pending=1;ipi->requests++;ipi->last_request=value;
}
#endif
enum ipi_result guest_ipi_access(struct guest_ipi *ipi,uint64_t mpidr,
    uint64_t reg,int read,uint64_t *value)
{
    if(reg!=IPI_RR_LOCAL && reg!=IPI_RR_GLOBAL && reg!=IPI_SR) return IPI_UNHANDLED;
    /* The selected guest topology has only cluster/core affinity levels.
     * Ignore architectural MPIDR non-affinity bits, including bit 31. */
    if(!ipi || !value || (read!=0 && read!=1) || IPI_PENDING(ipi)>1 ||
       (mpidr & UINT64_C(0xff00ff0000))) return IPI_BAD_CONFIG;
    if(reg==IPI_SR) {
#if SNAP_FAST_IPI
        if(read) { *value=__atomic_load_n(&ipi->pending,__ATOMIC_ACQUIRE);ipi->reads++; }
        else {
            if(*value & ~UINT64_C(1)) return IPI_BAD_VALUE;
            if(*value) fast_ipi_acknowledge(ipi);
        }
#else
        if(read) { *value=ipi->pending;ipi->reads++; }
        else {
            if(*value & ~UINT64_C(1)) return IPI_BAD_VALUE;
            if(*value && ipi->pending) { ipi->pending=0;ipi->acks++; }
        }
#endif
        return IPI_OK;
    }
    uint64_t target;
    enum ipi_result result=request_target(mpidr,reg,read,*value,&target);
    if(result!=IPI_OK) return result;
    if(target!=(mpidr&0xffff)) return IPI_BAD_TARGET;
    request(ipi,*value);
    return IPI_OK;
}
enum ipi_result guest_ipi_route(struct guest_ipi *const states[],
    const uint64_t affinities[],unsigned count,uint64_t runnable,unsigned source,
    uint64_t reg,int read,uint64_t *value)
{
    if(reg!=IPI_RR_LOCAL && reg!=IPI_RR_GLOBAL && reg!=IPI_SR) return IPI_UNHANDLED;
    if(!states || !affinities || !value || !count || count>64 || source>=count ||
       (count<64 && runnable>>count) || !(runnable&(UINT64_C(1)<<source)) ||
       (read!=0 && read!=1)) return IPI_BAD_CONFIG;
    for(unsigned i=0;i<count;i++) {
        if(!states[i] || IPI_PENDING(states[i])>1 || (affinities[i]&UINT64_C(0xff00ff0000)))
            return IPI_BAD_CONFIG;
        for(unsigned j=0;j<i;j++) if(states[i]==states[j] ||
            (affinities[i]&0xffff)==(affinities[j]&0xffff)) return IPI_BAD_CONFIG;
    }
    if(reg==IPI_SR) return guest_ipi_access(states[source],affinities[source],reg,read,value);
    uint64_t target;
    enum ipi_result result=request_target(affinities[source],reg,read,*value,&target);
    if(result!=IPI_OK) return result;
    for(unsigned i=0;i<count;i++) if((affinities[i]&0xffff)==target) {
        if(!(runnable&(UINT64_C(1)<<i))) return IPI_BAD_TARGET;
        request(states[i],*value);
        return IPI_OK;
    }
    return IPI_BAD_TARGET;
}
uint64_t guest_ipi_poll_delay(uint64_t host_hz,uint64_t budget)
{
    uint64_t ticks=host_hz/1000+(host_hz%1000!=0);
    return ticks<budget ? ticks : budget;
}
int guest_ipi_fiq(const struct guest_ipi *ipi,int timer_pending)
{
    return timer_pending || (ipi && IPI_PENDING(ipi));
}
