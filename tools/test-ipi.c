/* SPDX-License-Identifier: MIT */
#include "ipi.h"
#include "exception.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static void refused(struct guest_ipi *s,uint64_t mpidr,uint64_t reg,int read,
                    uint64_t value,enum ipi_result result)
{
    struct guest_ipi before=*s; uint64_t original=value;
    CHECK(guest_ipi_access(s,mpidr,reg,read,&value)==result);
    CHECK(!memcmp(s,&before,sizeof(*s)) && value==original);
}
int main(void)
{
    for(unsigned cluster=0;cluster<256;cluster++) for(unsigned core=0;core<256;core+=17) {
        const uint64_t mpidr=0x80000000UL | (cluster<<8) | core;
        struct guest_ipi s={0}; uint64_t value=core;
        CHECK(guest_ipi_access(&s,mpidr,IPI_RR_LOCAL,0,&value)==IPI_OK);
        CHECK(s.pending==1 && s.requests==1 && s.coalesced==0);
        /* Reading pending, masking FIQ and disabling the timer cannot eat an IPI. */
        struct exception_step step={0}; uint64_t spsr=0x3c5,mdscr=0;
        exception_step_set(&step,1,&spsr,&mdscr);
        CHECK(!exception_step_fiq(&step,guest_ipi_fiq(&s,0)) && s.pending);
        exception_step_set(&step,0,&spsr,&mdscr);
        CHECK(exception_step_fiq(&step,guest_ipi_fiq(&s,0)));
        for(unsigned n=0;n<3;n++) {
            value=99;
            CHECK(guest_ipi_access(&s,mpidr,IPI_SR,1,&value)==IPI_OK && value==1);
            CHECK(s.pending && s.reads==n+1 && !s.acks);
        }
        value=((uint64_t)cluster<<16)|core;
        CHECK(guest_ipi_access(&s,mpidr,IPI_RR_GLOBAL,0,&value)==IPI_OK);
        CHECK(s.pending==1 && s.requests==2 && s.coalesced==1 && s.last_request==value);
        refused(&s,mpidr,IPI_RR_LOCAL,0,core^1,IPI_BAD_TARGET);
        refused(&s,mpidr,IPI_RR_GLOBAL,0,value^0x10000,IPI_BAD_TARGET);
        refused(&s,mpidr,IPI_RR_LOCAL,1,0,IPI_BAD_DIRECTION);
        refused(&s,mpidr,IPI_RR_GLOBAL,1,0,IPI_BAD_DIRECTION);
        for(unsigned bit=0;bit<64;bit++) {
            uint64_t mask=UINT64_C(1)<<bit;
            if(bit>7) refused(&s,mpidr,IPI_RR_LOCAL,0,core|mask,IPI_BAD_VALUE);
            if(bit>23 || (bit>=8 && bit<16))
                refused(&s,mpidr,IPI_RR_GLOBAL,0,value|mask,IPI_BAD_VALUE);
            if(bit) refused(&s,mpidr,IPI_SR,0,mask,IPI_BAD_VALUE);
        }
        value=0;
        CHECK(guest_ipi_access(&s,mpidr,IPI_SR,0,&value)==IPI_OK && s.pending && !s.acks);
        value=1;
        CHECK(guest_ipi_access(&s,mpidr,IPI_SR,0,&value)==IPI_OK);
        CHECK(!s.pending && s.acks==1);
        CHECK(guest_ipi_fiq(&s,1) && !guest_ipi_fiq(&s,0)); /* timer survives IPI ack */
        CHECK(guest_ipi_access(&s,mpidr,IPI_SR,0,&value)==IPI_OK && s.acks==1);
        CHECK(guest_ipi_access(&s,mpidr,IPI_SR,1,&value)==IPI_OK && value==0);
        value=core;
        CHECK(guest_ipi_access(&s,mpidr,IPI_RR_LOCAL,0,&value)==IPI_OK);
        CHECK(s.pending && s.requests==3 && s.coalesced==1); /* rearm after ack */
    }
    struct guest_ipi s={0}; uint64_t value=1;
    refused(&s,0,IPI_SR,2,value,IPI_BAD_CONFIG);
    refused(&s,0x10000,IPI_SR,0,value,IPI_BAD_CONFIG);
    refused(&s,UINT64_C(1)<<32,IPI_SR,0,value,IPI_BAD_CONFIG);
    refused(&s,0,0,0,value,IPI_UNHANDLED);
    CHECK(guest_ipi_access(NULL,0,IPI_SR,0,&value)==IPI_BAD_CONFIG);
    CHECK(guest_ipi_access(&s,0,IPI_SR,0,NULL)==IPI_BAD_CONFIG);
    s.pending=2;
    refused(&s,0,IPI_SR,1,value,IPI_BAD_CONFIG);
    CHECK(!guest_ipi_fiq(NULL,0) && guest_ipi_fiq(NULL,1));
    printf("PASS: %u fast IPI lifecycle, refusal and shared FIQ checks\n",checks);
}
