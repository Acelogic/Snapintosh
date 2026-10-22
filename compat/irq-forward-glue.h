/* SPDX-License-Identifier: MIT */
#ifndef IRQ_FORWARD_GLUE_H
#define IRQ_FORWARD_GLUE_H

#include <stdint.h>
#include "irq-forward.h"

/* GIC/AIC interrupt forwarding and GPU IRQ handling glue */
static int aic_model(const struct context *c)
{
    for (unsigned i=0;i<c->params->model_count;i++)
        if (c->params->models[i].kind==DEVICE_AIC3_FLAT_V1) return (int)i;
    return -1;
}
static void fwd_disable(void *ctx,uint32_t intid)
{
    uint64_t g=((struct context *)ctx)->params->gpu.gicd;
    gpu_wr(g+GICD_ICENABLER+4*(intid/32),1u<<(intid%32));
    for (unsigned n=0;n<100000 && (gpu_rd(g+GICD_CTLR)&(1u<<31));n++) {}
}
static void fwd_enable(void *ctx,uint32_t intid)
{
    gpu_wr(((struct context *)ctx)->params->gpu.gicd+GICD_ISENABLER+4*(intid/32),1u<<(intid%32));
}
static int fwd_pending(void *ctx,uint32_t intid)
{
    return !!(gpu_rd(((struct context *)ctx)->params->gpu.gicd+GICD_ISPENDR+4*(intid/32))&
              (1u<<(intid%32)));
}
static void fwd_complete(void *ctx,uint32_t intid) {(void)ctx;timer_eoi(intid);}
static int fwd_level(void *ctx,uint32_t irq,int level)
{
    struct context *c=ctx;
    int a=aic_model(c);
    return a<0 || device_irq_set_level(&c->params->models[a],&c->model_state[a],irq,level)!=DEVICE_OK;
}
static struct irqfwd_ops fwd_ops(struct context *c)
{
    return (struct irqfwd_ops){c,fwd_disable,fwd_enable,fwd_pending,fwd_complete,fwd_level};
}
static void gpu_serror_check(struct context *c)
{
    uint64_t isr;
    __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    if (isr&(1u<<8)) c->gpu.serrors++;
}
static void gpu_fault_record(struct context *c,uint64_t pc)
{
    const struct adreno_state *s=&c->gpu;
    record(c,EV_GPU_SMMU,pc,s->fault_fsynr0<<32|s->fault_fsr,s->fault_far,
           s->fault_gfsr<<32|s->fault_cbfrsynra);
}
/* EL2 IRQ for INTID 0x14C: mask, complete, raise AIC 975 (compat/irq-forward.c). */
static void gpu_irq(struct context *c)
{
    uint64_t intid;
    __asm__ volatile("mrs %0, icc_iar1_el1; dsb sy" : "=r"(intid) :: "memory");
    struct irqfwd_ops f=fwd_ops(c);
    if (irqfwd_physical(&c->gpu.irq,&f,(uint32_t)intid)==IRQFWD_NOT_OURS && intid<1020)
        timer_eoi(intid);   /* a level source that is not ours re-asserts on its own */
    vcpu_of(c)->model_irq_pending=0;
    for (unsigned i=0;i<c->params->model_count;i++)
        vcpu_of(c)->model_irq_pending|=device_irq_pending(&c->params->models[i],&c->model_state[i]);
    guest_interrupt_sync(c);
}

#endif /* IRQ_FORWARD_GLUE_H */
