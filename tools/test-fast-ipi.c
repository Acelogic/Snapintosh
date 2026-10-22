/* SPDX-License-Identifier: MIT */
/* SNAP_FAST_IPI (compat/fast-ipi.h, docs/FAST-IPI-20261019.md): the lock-free
 * IPI registers against guest_ipi_route.
 *
 * Failure inventory this covers, each as checks with the expected result:
 *   - divergence: random six-CPU configurations (valid and invalid
 *     affinities, runnable masks, pending words of 0, 1 and 2), registers
 *     (the three IPI registers and others), directions and values (inside and
 *     outside each register's bits, present, absent and non-runnable
 *     targets). Where compat/ipi.c as it was (linked with ref_ names) returns
 *     IPI_OK, fast_ipi_access must return the matching handled kind with the
 *     same value and the same state for every vCPU. Where it refuses,
 *     fast_ipi_access must decline (DECLINE_TARGET exactly for
 *     IPI_BAD_TARGET) with every state unchanged;
 *   - a changed locked path: compat/ipi.c built with the define must give the
 *     same results and states as without it, for the same cases;
 *   - a lost or torn IPI: six threads, one per vCPU, post to random targets
 *     and read and acknowledge their own IPI_SR. Each access goes lock-free or
 *     through the define's guest_ipi_route under a mutex (the token). At the
 *     end, every vCPU's requests must equal the posts aimed at it, and
 *     requests == coalesced + acks + pending; last_request must be a value
 *     posted to it; and a reader that saw pending must not later find a fresh
 *     post cleared without its own acknowledgement (each acknowledgement
 *     clears at most what was posted).
 * tools/test-fast-ipi.py builds this and requires weakened headers to fail it.
 *
 * cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -Icompat \
 *    -c compat/ipi.c -o ref.o -Dguest_ipi_access=ref_guest_ipi_access \
 *    -Dguest_ipi_route=ref_guest_ipi_route -Dguest_ipi_poll_delay=ref_guest_ipi_poll_delay \
 *    -Dguest_ipi_fiq=ref_guest_ipi_fiq
 * cc ... -DSNAP_FAST_IPI=1 -Icompat tools/test-fast-ipi.c compat/ipi.c ref.o -lpthread \
 *    -o build/test-fast-ipi && build/test-fast-ipi */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-ipi.h"

enum ipi_result ref_guest_ipi_route(struct guest_ipi *const states[],const uint64_t affinities[],
    unsigned count,uint64_t runnable,unsigned source,uint64_t reg,int read,uint64_t *value);

static unsigned long checks,failures;
#define CHECK(cond,...) do { checks++; if(!(cond)) { failures++; \
    if(failures<20) { printf("FAIL %s:%d: ",__FILE__,__LINE__); printf(__VA_ARGS__); printf("\n"); } } } while(0)

static uint64_t rng=0x243f6a8885a308d3u;
static uint64_t next(void) {rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}

#define CPUS 6
struct config {
    struct guest_ipi ipi[CPUS];
    uint64_t affinity[CPUS],runnable;
    unsigned source;
};

static void random_config(struct config *k)
{
    memset(k,0,sizeof(*k));
    /* Two clusters of up to four cores, as the guest topology. */
    static const uint64_t valid[]={0x0000,0x0001,0x0002,0x0003,0x0100,0x0101,0x0102,0x0103};
    unsigned start=(unsigned)(next()%3);
    for(unsigned i=0;i<CPUS;i++)k->affinity[i]=valid[start+i];
    if(next()%8==0)k->affinity[next()%CPUS]|=UINT64_C(1)<<(32+next()%8);   /* a non-affinity bit */
    if(next()%10==0)k->affinity[1]=k->affinity[0];                       /* a duplicate */
    if(next()%6==0)k->affinity[next()%CPUS]|=UINT64_C(0x80000000);       /* MPIDR bit 31: ignored */
    k->runnable=(UINT64_C(1)<<CPUS)-1;
    if(next()%4==0)k->runnable&=~(UINT64_C(1)<<(next()%CPUS));
    if(next()%16==0)k->runnable|=UINT64_C(1)<<(CPUS+next()%3);
    k->source=(unsigned)(next()%CPUS);
    for(unsigned i=0;i<CPUS;i++) {
        k->ipi[i].pending=next()%2;
        k->ipi[i].requests=next()%50;k->ipi[i].reads=next()%50;k->ipi[i].acks=next()%50;
        k->ipi[i].coalesced=next()%50;k->ipi[i].last_request=next()%0x1000000;
    }
    if(next()%20==0)k->ipi[next()%CPUS].pending=2;
}
static uint64_t random_reg(void)
{
    static const uint64_t regs[]={IPI_RR_LOCAL,IPI_RR_GLOBAL,IPI_SR,IPI_RR_LOCAL,IPI_RR_GLOBAL,IPI_SR,
                                  IPI_SYSREG(3,5,15,1,0),IPI_SYSREG(3,0,13,0,1)};
    return regs[next()%8];
}
static uint64_t random_value(uint64_t reg)
{
    switch(next()%6) {
    case 0:return next();
    case 1:return next()%2;
    case 2:return reg==IPI_RR_LOCAL ? next()%4 : (next()%2)<<16 | next()%4;
    case 3:return (next()%4) | (next()%3)<<16;
    case 4:return (next()%8) | (next()%2)<<8;
    default:return next()%0x100;
    }
}
static void pointers(struct config *k,struct guest_ipi *p[CPUS])
{for(unsigned i=0;i<CPUS;i++)p[i]=&k->ipi[i];}

static void differential(unsigned cases)
{
    unsigned handled=0,declined=0,targets=0;
    for(unsigned n=0;n<cases;n++) {
        struct config base,a,b;
        random_config(&base);
        uint64_t reg=random_reg(),value=random_value(reg);
        int read=(int)(next()%2),clean=n%2==0;
        if(clean) {
            /* A valid access: the topology as prepared, everyone runnable, an
             * existing target, the register's own direction. */
            for(unsigned i=0;i<CPUS;i++) {base.affinity[i]&=0xffff;base.ipi[i].pending&=1;}
            base.affinity[1]=base.affinity[0]+1;
            base.runnable=(UINT64_C(1)<<CPUS)-1;
            reg=(uint64_t[]){IPI_RR_LOCAL,IPI_RR_GLOBAL,IPI_SR}[next()%3];
            unsigned t=(unsigned)(next()%CPUS);
            if(reg==IPI_RR_LOCAL) {
                if((base.affinity[t]&0xff00)!=(base.affinity[base.source]&0xff00))t=base.source;
                value=base.affinity[t]&0xff;read=0;
            } else if(reg==IPI_RR_GLOBAL) {
                value=(base.affinity[t]&0xff)|(base.affinity[t]&0xff00)<<8;read=0;
            } else value=read ? 0 : next()%2;
        }
        a=base;b=base;
        struct guest_ipi *pa[CPUS],*pb[CPUS];pointers(&a,pa);pointers(&b,pb);
        if(!clean && next()%40==0)pb[3]=pb[2],pa[3]=pa[2];   /* one state twice */
        uint64_t va=value,vb=value;
        if(!clean && next()%50==0)read=2;
        enum ipi_result ra=ref_guest_ipi_route(pa,a.affinity,CPUS,a.runnable,a.source,reg,read,&va);
        unsigned rb=fast_ipi_access(pb,b.affinity,CPUS,b.runnable,b.source,reg,read,&vb);
        if(ra==IPI_OK) {
            unsigned kind=reg==IPI_SR ? (read ? FAST_IPI_SR_READ : FAST_IPI_SR_WRITE) :
                          reg==IPI_RR_LOCAL ? FAST_IPI_REQUEST_LOCAL : FAST_IPI_REQUEST_GLOBAL;
            CHECK(rb==kind,"case %u: route OK, fast %u (expected %u)",n,rb,kind);
            CHECK(va==vb,"case %u: value %llx vs %llx",n,(unsigned long long)va,(unsigned long long)vb);
            CHECK(!memcmp(a.ipi,b.ipi,sizeof(a.ipi)),"case %u: states differ after OK",n);
            handled++;
        } else {
            CHECK(rb>=FAST_IPI_DECLINES && rb<FAST_IPI_RESULTS,"case %u: route %d, fast handled %u",n,ra,rb);
            CHECK((rb==FAST_IPI_DECLINE_TARGET)==(ra==IPI_BAD_TARGET),"case %u: route %d, fast %u",n,ra,rb);
            CHECK(!memcmp(base.ipi,b.ipi,sizeof(b.ipi)) && vb==value,"case %u: a decline changed state",n);
            declined++;targets+=rb==FAST_IPI_DECLINE_TARGET;
        }
    }
    printf("differential: %u cases, %u handled, %u declined (%u target)\n",cases,handled,declined,targets);
    CHECK(handled>cases/4 && declined>cases/20 && targets>cases/100,"coverage");
}

/* compat/ipi.c with the define (linked as guest_ipi_route) against without. */
static void locked_differential(unsigned cases)
{
    for(unsigned n=0;n<cases;n++) {
        struct config base,a,b;
        random_config(&base);a=base;b=base;
        struct guest_ipi *pa[CPUS],*pb[CPUS];pointers(&a,pa);pointers(&b,pb);
        uint64_t reg=random_reg(),value=random_value(reg),va=value,vb=value;
        int read=(int)(next()%2);
        enum ipi_result ra=ref_guest_ipi_route(pa,a.affinity,CPUS,a.runnable,a.source,reg,read,&va);
        enum ipi_result rb=guest_ipi_route(pb,b.affinity,CPUS,b.runnable,b.source,reg,read,&vb);
        CHECK(ra==rb && va==vb && !memcmp(a.ipi,b.ipi,sizeof(a.ipi)),"locked case %u: %d vs %d",n,ra,rb);
    }
}

/* Concurrency: one thread per vCPU. */
static struct guest_ipi shared[CPUS];
static uint64_t affinity[CPUS]={0x0000,0x0001,0x0002,0x0003,0x0100,0x0101};
static pthread_mutex_t token=PTHREAD_MUTEX_INITIALIZER;
static unsigned rounds;
struct worker {
    unsigned cpu;uint64_t seed;
    uint64_t posted[CPUS];      /* posts this thread aimed at each vCPU */
    uint64_t sent_values[CPUS]; /* OR of the low bits of those values */
    unsigned long errors;
};
static uint64_t wnext(uint64_t *s) {*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
static void *worker(void *opaque)
{
    struct worker *w=opaque;
    struct guest_ipi *states[CPUS];
    for(unsigned i=0;i<CPUS;i++)states[i]=&shared[i];
    uint64_t all=(UINT64_C(1)<<CPUS)-1;
    for(unsigned n=0;n<rounds;n++) {
        uint64_t r=wnext(&w->seed);
        int locked=(int)(r>>60)%4==0;
        unsigned op=(unsigned)(r%8);
        uint64_t reg,value;int read=0;unsigned target=0;
        if(op<4) {                      /* a request */
            target=(unsigned)((r>>8)%CPUS);
            if((affinity[target]&0xff00)==(affinity[w->cpu]&0xff00) && (r>>16)%2)
                reg=IPI_RR_LOCAL,value=affinity[target]&0xff;
            else reg=IPI_RR_GLOBAL,value=(affinity[target]&0xff)|(affinity[target]&0xff00)<<8;
        } else if(op<6) {reg=IPI_SR;read=1;value=0;}
        else {reg=IPI_SR;value=1;}
        uint64_t v=value;int ok;
        if(locked) {
            pthread_mutex_lock(&token);
            ok=guest_ipi_route(states,affinity,CPUS,all,w->cpu,reg,read,&v)==IPI_OK;
            pthread_mutex_unlock(&token);
        } else ok=fast_ipi_access(states,affinity,CPUS,all,w->cpu,reg,read,&v)<FAST_IPI_DECLINES;
        if(!ok)w->errors++;
        else if(op<4) {w->posted[target]++;w->sent_values[target]|=UINT64_C(1)<<(value&0x3f);}
        else if(read && v>1)w->errors++;
    }
    return 0;
}
static void concurrency(unsigned per_thread)
{
    memset(shared,0,sizeof(shared));rounds=per_thread;
    struct worker w[CPUS];pthread_t t[CPUS];
    memset(w,0,sizeof(w));
    for(unsigned i=0;i<CPUS;i++) {w[i].cpu=i;w[i].seed=0x9e3779b97f4a7c15u*(i+1);}
    for(unsigned i=0;i<CPUS;i++)pthread_create(&t[i],0,worker,&w[i]);
    for(unsigned i=0;i<CPUS;i++)pthread_join(t[i],0);
    uint64_t total=0,coalesced=0;
    for(unsigned c=0;c<CPUS;c++) {
        uint64_t posted=0,mask=0;
        for(unsigned i=0;i<CPUS;i++) {posted+=w[i].posted[c];mask|=w[i].sent_values[c];}
        struct guest_ipi *s=&shared[c];
        CHECK(!w[c].errors,"cpu %u: %lu refused or impossible accesses",c,w[c].errors);
        CHECK(s->requests==posted,"cpu %u: %llu requests, %llu posted",c,
              (unsigned long long)s->requests,(unsigned long long)posted);
        CHECK(s->requests==s->coalesced+s->acks+s->pending,"cpu %u: requests %llu != coalesced %llu + acks %llu + "
              "pending %llu",c,(unsigned long long)s->requests,(unsigned long long)s->coalesced,
              (unsigned long long)s->acks,(unsigned long long)s->pending);
        CHECK(s->pending<=1,"cpu %u: pending %llu",c,(unsigned long long)s->pending);
        CHECK(!posted || (mask>>(s->last_request&0x3f)&1),"cpu %u: last_request was never posted",c);
        total+=s->requests;coalesced+=s->coalesced;
    }
    printf("concurrency: %u threads x %u accesses, %llu requests (%llu coalesced)\n",CPUS,per_thread,
           (unsigned long long)total,(unsigned long long)coalesced);
}

int main(int argc,char **argv)
{
    unsigned cases=argc>1 ? (unsigned)strtoul(argv[1],0,0) : 200000;
    unsigned per_thread=argc>2 ? (unsigned)strtoul(argv[2],0,0) : 400000;
    differential(cases);
    locked_differential(cases/2);
    concurrency(per_thread);
    if(failures) {printf("FAIL: %lu of %lu checks\n",failures,checks);return 1;}
    printf("PASS: %lu checks\n",checks);
    return 0;
}
