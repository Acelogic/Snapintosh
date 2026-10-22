/* SPDX-License-Identifier: MIT */
/* Differential check of the monitor's SPTM descriptor selection against
 * Apple's own answers. Every row of tools/sptm-oracle-26A428.rows was
 * produced by the shipped SPTM (sptm.t8140.release, 26A428) running this
 * kernelcache under qemu-sptm with an SPTM-call tracer: the leaf before the
 * call, the request, the options, the leaf after gexit and x0.
 *
 * The same selection helpers the monitor uses must reproduce each row:
 *   D/R kernel  update_entry's select rule + sptm_nx_update_pte(..,0)
 *   D/R user    sptm_mac_user_update_pte;   R shared  sptm_mac_shared_ng_pte
 *   M user/shared sptm_mac_shared_map_pte (6 = conflict, no store)
 *   M/N kernel  sptm_mac_kernel_map_leaf (verbatim store; 6 = conflict)
 *   N user      stored as requested, bit59 dropped only for writable DEFAULT
 *   status      UPDATE_*: 5 iff option 0x100 and a hardware bit changed;
 *               MAP_PAGE: sptm_mac_map_page_status. */
#include <stdio.h>
#include <string.h>
#include "sptm-nx-update.h"
#include "sptm-user.h"
#include "mmu.h"

static unsigned checks, failures, rows;
#define CHECK(c,line) do{checks++;if(!(c)){failures++;printf("FAIL row: %s  (%s)\n",line,#c);}}while(0)
#define PERMISSIONS 0x08680000000000c0UL

/* Any aperture covering the canonical pages; the pointer is not in a row. */
static const struct sptm_aperture kernel_aperture={0x900000000UL,0xfffffe0000000000UL,0x100000000UL};

static uint64_t update_status(uint64_t old,uint64_t next,uint64_t opts)
{return (opts&0x100) && ((old^next)&~(3UL<<58)) ? 5 : 0;}

int main(int argc,char **argv)
{
    const char *path=argc>1 ? argv[1] : "tools/sptm-oracle-26A428.rows";
    FILE *f=fopen(path,"r");
    if(!f){printf("cannot open %s\n",path);return 1;}
    char line[512];
    while(fgets(line,sizeof line,f)) {
        if(line[0]=='#' || line[0]=='\n')continue;
        line[strcspn(line,"\n")]=0;
        char op;unsigned rt;unsigned long long old,req,opts,apple,status;
        if(sscanf(line,"%c %u %llx %llx %llx %llx %llx",&op,&rt,&old,&req,&opts,&apple,&status)!=7) {
            CHECK(0,line);continue;
        }
        rows++;
        uint64_t next=0,result=99;enum sptm_result r=SPTM_OK;
        switch(op) {
        case 'D': case 'R':
            if(op=='R' && (old&3)!=3) {next=old;}          /* skipped entry */
            else if(rt==0) {
                uint64_t select=opts;next=old;
                if(!((old^req)&PERMISSIONS))select&=~2UL;
                if(select&0xb)r=sptm_nx_update_pte(old,req,select,&next,0);
            } else if(op=='R' && rt==SPTM_MAC_SHARED_ROOT_TABLE)
                r=sptm_mac_shared_ng_pte(old,req,opts,&next);
            else r=sptm_mac_user_update_pte(old,req,opts,&next);
            CHECK(r==SPTM_OK,line);
            CHECK(next==apple,line);
            CHECK(update_status(old,next,opts)==status,line);
            break;
        case 'M':
            if(rt==0) {                   /* kernel: verbatim unless CONFLICT */
                struct sptm_kernel_leaf k;
                CHECK(sptm_mac_kernel_map_leaf(&kernel_aperture,0,0x947a14008UL,old,req,&k)==SPTM_OK,line);
                if(!k.install) {CHECK(status==6 && apple==old,line);break;}
                CHECK(apple==req,line);
                CHECK(k.status==status,line);
                break;
            }
            r=sptm_mac_shared_map_pte(old,req,&next,&result);
            CHECK(r==SPTM_OK,line);
            if(result==SPTM_USER_MAP_CONFLICT) {CHECK(status==6 && apple==old,line);break;}
            CHECK(next==apple,line);
            CHECK(sptm_mac_map_page_status(old,req)==status,line);
            break;
        case 'N':
            CHECK(sptm_mac_map_page_status(0,req)==status,line);
            if(rt==0) {
                struct sptm_kernel_leaf k;
                CHECK(sptm_mac_kernel_map_leaf(&kernel_aperture,0,0x947a14008UL,0,req,&k)==SPTM_OK &&
                      k.install && k.status==status,line);
            }
            if(rt==0) CHECK(apple==req,line);
            else CHECK(apple==req || (apple==(req&~(1UL<<59)) && !(req&0x80)),line);
            break;
        default:
            CHECK(0,line);
        }
    }
    fclose(f);
    CHECK(rows>=30,"fixture rows");
    printf("SPTM oracle rows: %u rows, %u checks, %u failures\n",rows,checks,failures);
    return failures!=0;
}
