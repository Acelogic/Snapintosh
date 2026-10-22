/* SPDX-License-Identifier: MIT */
/* Actual SPTM lifecycle and byte-for-byte comparison with the saved production
 * preimage. Failure inventory: docs/GRAPHICS-CORRECTNESS-20261018.md. */
#define main existing_lifecycle_replay
#include "test-sptm-user.c"
#undef main
#include <time.h>
#include <stdlib.h>
#include <assert.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(int argc,char **argv) {
    if(argc!=2)return 64;
    if(existing_lifecycle_replay())return 1;
    struct sptm_memory m=reset_geometry(11,2,VA,1);
    /* A normal user L3, initially empty. Setup shares the existing root/table
     * constructors; the replay changes leaves only through production calls. */
    put(meta(L3)+2,20,1);const uint64_t va=VA,pte=DATA|UINT64_C(0x0060000000000e43);
    uint64_t response=0;unsigned loops=200000;double samples[7];
    for(unsigned trial=0;trial<7;trial++) {
        double start=now();
        for(unsigned i=0;i<loops;i++) {
            assert(sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,BASE,&response)==SPTM_OK && response==0);
            assert(sptm_mac_map_user_page(&m,&backend,ROOT,va,pte,0,BASE,&response)==SPTM_OK && response==1);
            assert(sptm_mac_unmap_user_region(&m,&backend,ROOT,va,1,0,BASE)==SPTM_OK);
        }
        samples[trial]=now()-start;
        assert(get(meta(DATA)+8,4)==0 && get(meta(DATA)+12,4)==0 && get(meta(L3)+8,2)==0);
    }
    char path[4096];snprintf(path,sizeof path,"%s/memory.bin",argv[1]);FILE *f=fopen(path,"wb");assert(f);assert(fwrite(ram,1,SIZE,f)==SIZE);fclose(f);
    snprintf(path,sizeof path,"%s/monitor-cost.json",argv[1]);f=fopen(path,"w");assert(f);
    fprintf(f,"{\"status\":\"%s\",\"operations_per_trial\":%u,\"publications\":%u,\"checks\":%u,\"seconds\":[",failures?"FAIL":"PASS",loops*3,publications,checks);
    for(unsigned i=0;i<7;i++)fprintf(f,"%s%.9f",i?",":"",samples[i]);
    fprintf(f,"],\"target_run\":false}\n");fclose(f);return failures?1:0;
}
