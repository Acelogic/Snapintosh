/* SPDX-License-Identifier: MIT */
#include "ipi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { checks++; if(!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static struct guest_ipi state[6],saved[6];
static struct guest_ipi *states[6]={state,state+1,state+2,state+3,state+4,state+5};
static uint64_t affinities[6]={0x80000000,0x80000001,0x80000002,0x80000003,0x80000100,0x80000101};
static void refused(unsigned count,uint64_t mask,unsigned source,uint64_t reg,
                    int read,uint64_t value,enum ipi_result expected)
{
    memcpy(saved,state,sizeof(state));uint64_t v=value;
    CHECK(guest_ipi_route(states,affinities,count,mask,source,reg,read,&v)==expected);
    CHECK(v==value && !memcmp(saved,state,sizeof(state)));
}
int main(void)
{
    for(unsigned from=0;from<6;from++) for(unsigned to=0;to<6;to++) {
        uint64_t target=affinities[to]&0xffff;
        for(unsigned global=0;global<2;global++) {
            if(!global && ((affinities[from]^target)&0xff00))continue;
            uint64_t reg=global ? IPI_RR_GLOBAL : IPI_RR_LOCAL;
            uint64_t value=(target&0xff)|(global ? (target&0xff00)<<8 : 0);
            for(unsigned mask=0;mask<64;mask++) if(mask&(1U<<from)) {
                memset(state,0,sizeof(state));
                if(!(mask&(1U<<to))) {
                    refused(6,mask,from,reg,0,value,IPI_BAD_TARGET);continue;
                }
                for(unsigned n=0;n<3;n++) {
                    CHECK(guest_ipi_route(states,affinities,6,mask,from,reg,0,&value)==IPI_OK);
                    CHECK(state[to].pending==1 && state[to].requests==n+1 && state[to].coalesced==n);
                    for(unsigned i=0;i<6;i++) if(i!=to) {
                        struct guest_ipi zero={0};CHECK(!memcmp(&state[i],&zero,sizeof(zero)));
                    }
                }
                uint64_t v=99;
                CHECK(guest_ipi_route(states,affinities,6,mask,to,IPI_SR,1,&v)==IPI_OK && v==1);
                CHECK(state[to].pending && state[to].reads==1 && state[to].acks==0);
                if(from!=to) {
                    v=1;
                    CHECK(guest_ipi_route(states,affinities,6,mask,from,IPI_SR,0,&v)==IPI_OK);
                    CHECK(state[to].pending && !state[to].acks); /* sender cannot consume receiver */
                }
                v=1;
                CHECK(guest_ipi_route(states,affinities,6,mask,to,IPI_SR,0,&v)==IPI_OK);
                CHECK(!state[to].pending && state[to].acks==1 && guest_ipi_fiq(&state[to],1));
                CHECK(state[to].requests==state[to].acks+state[to].coalesced);
                CHECK(guest_ipi_route(states,affinities,6,mask,from,reg,0,&value)==IPI_OK);
                CHECK(state[to].pending && state[to].requests==4 && state[to].coalesced==2);
            }
        }
    }
    memset(state,0,sizeof(state));
    for(unsigned source=0;source<6;source++) {
        refused(6,63,source,IPI_RR_LOCAL,1,0,IPI_BAD_DIRECTION);
        refused(6,63,source,IPI_RR_GLOBAL,1,0,IPI_BAD_DIRECTION);
        refused(6,63,source,IPI_RR_LOCAL,0,255,IPI_BAD_TARGET);
        refused(6,63,source,IPI_RR_GLOBAL,0,0xff00ff,IPI_BAD_TARGET);
        for(unsigned bit=0;bit<64;bit++) {
            uint64_t b=UINT64_C(1)<<bit;
            if(bit>7)refused(6,63,source,IPI_RR_LOCAL,0,b,IPI_BAD_VALUE);
            if(bit>23 || (bit>=8 && bit<16))refused(6,63,source,IPI_RR_GLOBAL,0,b,IPI_BAD_VALUE);
            if(bit)refused(6,63,source,IPI_SR,0,b,IPI_BAD_VALUE);
        }
    }
    refused(0,0,0,IPI_SR,1,0,IPI_BAD_CONFIG);
    refused(65,63,0,IPI_SR,1,0,IPI_BAD_CONFIG);
    refused(6,63,6,IPI_SR,1,0,IPI_BAD_CONFIG);
    refused(6,64,0,IPI_SR,1,0,IPI_BAD_CONFIG);
    refused(6,62,0,IPI_SR,1,0,IPI_BAD_CONFIG);
    refused(6,63,0,IPI_SR,2,0,IPI_BAD_CONFIG);
    refused(6,63,0,0,0,0,IPI_UNHANDLED);
    affinities[5]=affinities[0];refused(6,63,0,IPI_SR,1,0,IPI_BAD_CONFIG);affinities[5]=0x80000101;
    states[5]=states[0];refused(6,63,0,IPI_SR,1,0,IPI_BAD_CONFIG);states[5]=state+5;
    state[5].pending=2;refused(6,63,0,IPI_SR,1,0,IPI_BAD_CONFIG);state[5].pending=0;
    for(uint64_t hz=1;hz<25000000;hz+=9973) {
        uint64_t slice=guest_ipi_poll_delay(hz,UINT64_MAX);
        CHECK(slice>0 && slice*1000>=hz && (slice-1)*1000<hz);
        CHECK(guest_ipi_poll_delay(hz,0)==0);
        CHECK(guest_ipi_poll_delay(hz,1)==1);
        CHECK(guest_ipi_poll_delay(hz,slice+1)==slice);
    }
    CHECK(guest_ipi_poll_delay(19200000,UINT64_MAX)==19200);
    CHECK(guest_ipi_poll_delay(24000000,UINT64_MAX)==24000);
    CHECK(guest_ipi_poll_delay(UINT64_MAX,UINT64_MAX)==UINT64_MAX/1000+1);
    printf("PASS: %u routed IPI, receiver acknowledgement, topology and delivery-deadline checks\n",checks);
}
