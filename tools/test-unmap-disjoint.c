/* SPDX-License-Identifier: MIT */
#define SPTM_UNMAP_FIXTURE
#include "test-sptm-user-unmap.c"
#define LIST (BASE+0x20000)
#define OTHER (BASE+0x24000)
#define ROOT2 (BASE+0x28000)
#define L2B (BASE+0x2c000)
#define L3B (BASE+0x30000)
#define L1B (BASE+0x34000)
static struct sptm_shared_update_state witness;
static unsigned reject_prepare,mutate_input;
static int prepare_disjoint(void *ctx,uint64_t root,uint64_t va,unsigned shift,uint64_t count)
{
    if(mutate_input)put(LIST+24,UINT64_MAX,8);
    if(reject_prepare && unmap_prepared+1==reject_prepare)return 0;
    return prepare_remove(ctx,root,va,shift,count);
}
static int resolve_disjoint(void *ctx,uint64_t root,struct sptm_user_backend *out)
{(void)ctx;if(root==ROOT2){*out=(struct sptm_user_backend){0};return 1;}
 if(root!=ROOT)return 0;*out=backend;return 1;}
static void record_disjoint(unsigned i,uint64_t va,uint64_t requested)
{put(LIST+i*24,ROOT,8);put(LIST+i*24+8,va,8);put(LIST+i*24+16,requested,8);}
static enum sptm_result invoke_disjoint(uint64_t target,uint64_t list,uint64_t count,uint64_t scratch)
{
    memcpy(metadata_before,ram+(FM-BASE),sizeof(metadata_before));
    return sptm_mac_unmap_user_disjoint(&memory,resolve_disjoint,0,target,list,count,scratch,&witness);
}
static void init_disjoint(unsigned fmt)
{
    setup_remove(fmt);reject_prepare=mutate_input=0;memset(&witness,0,sizeof(witness));
    backend.prepare_unmap=prepare_disjoint;
}
int main(void)
{
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned count=1;count<=64;count++) {
        init_disjoint(fmt);unsigned shift=fmt?12:14;uint64_t size=1UL<<shift;
        uint64_t old[64];
        for(unsigned i=0;i<count;i++) {
            old[i]=insert(fmt,0x4000+2*i*size,i&1,i&3);
            record_disjoint(i,0x4000+2*i*size,0);
        }
        insert(fmt,0x200000,1,0);
        check(invoke_disjoint(DATA,LIST,count,BASE)==SPTM_OK,"disjoint maximum and smaller batches");
        check(unmap_prepared==count && unmap_committed==count && flushes==count,
              "every removed alias reaches broadcast boundary");
        for(unsigned i=0;i<count;i++) {
            check(get(BASE+8*i,8)==old[i],"old descriptors preserve input order");
            check(!get(source_slot(fmt,0x4000+2*i*size),8),"source descriptor cleared");
            check(get(BASE+512+24*i,8)==ROOT,"private copy published to scratch");
        }
        check(state.cache[0].leaves==1 && get(meta(DATA)+8,4)==1 &&
              !get(meta(DATA)+12,4) && get(meta(L3)+8,2)==1,
              "only untouched alias retains table and data references");
        check(witness.latest.calls==1 && witness.latest.changed==count &&
              witness.changed.changed==count,"changed witness covers the completed batch");
        for(cpu_now=0;cpu_now<6;cpu_now++)
            check(!sptm_mac_switch_root(&memory,&state,&rb,cpu_now,BASE,0,0),"deactivate root");
        backend.active_refs=0;backend.ttbr0=BASE;record_disjoint(0,0x200000,0);
        check(!invoke_disjoint(DATA,LIST,1,BASE),"inactive cached alias removed");
        check(!state.cache[0].leaves && !get(meta(DATA)+8,4),"inactive references released");
        cpu_now=0;
        check(!sptm_mac_switch_root(&memory,&state,&rb,0,ROOT,0,0) && state.builds==1,
              "reactivation reuses the now empty cache");
    }
    for(unsigned fmt=0;fmt<2;fmt++)for(unsigned software=0;software<8;software++) {
        init_disjoint(fmt);uint64_t old=insert(fmt,0x4000,0,0),next=(uint64_t)software<<61;
        record_disjoint(0,0x4000,next|0x12345678);
        record_disjoint(1,0x4000,0);
        check(!invoke_disjoint(DATA,LIST,2,BASE),"duplicate and software template");
        check(get(BASE,8)==old && get(BASE+8,8)==(next|0x80),"duplicate sees transient old descriptor");
        check(get(source_slot(fmt,0x4000),8)==next,"only top three template bits survive");
        /* Apple's +8 occupancy (...ecbe8) tests bits63:61, so bit61 alone
         * also holds the table (tools/test-compressed-pte.c). */
        check(get(meta(L3)+8,2)==!!software && !get(meta(DATA)+12,4),
              "compressed software state retains only its table reference");
        check(unmap_committed==1 && !state.cache[0].leaves,"duplicate releases one mapping");
        check(!invoke_disjoint(DATA,LIST,1,BASE) && get(BASE,8)==next,"stale invalid descriptor returned unchanged");
        check(witness.latest.last_changed==0 && witness.changed.changed==1,"stale call preserves changed witness");
    }
    for(unsigned fmt=0;fmt<2;fmt++) {
        init_disjoint(fmt);unsigned other_fmt=!fmt;uint64_t result;
        insert(fmt,0x4000,0,0);
        check(!sptm_mac_retype(&memory,ROOT2,11,18,(3UL<<32)|(2UL<<16)|other_fmt),"second root constructor");
        check(!sptm_mac_retype(&memory,L2B,11,20,2) && !sptm_mac_retype(&memory,L3B,11,20,3),"second root tables");
        struct sptm_user_backend inactive={0};
        if(other_fmt) {
            check(!sptm_mac_retype(&memory,L1B,11,20,1),"second root L1 allocation");
            check(!sptm_mac_map_user_table_live(&memory,&inactive,ROOT2,0,0,L1B|3),"second root L1 link");
        }
        check(!sptm_mac_map_user_table_live(&memory,&inactive,ROOT2,0,1,L2B|3) &&
              !sptm_mac_map_user_table_live(&memory,&inactive,ROOT2,0,2,L3B|3),"second root hierarchy");
        check(!sptm_mac_map_user_page(&memory,&inactive,ROOT2,0x4000,DATA|0x0060000000000ec3UL,1,0,&result),"second root leaf");
        record_disjoint(0,0x4000,0);record_disjoint(1,0x4000,0);put(LIST+24,ROOT2,8);
        check(!invoke_disjoint(DATA,LIST,2,BASE),"mixed roots and page geometries in one batch");
        check(!get(meta(DATA)+8,4) && !get(meta(DATA)+12,4) && !get(meta(L3B)+8,2),"mixed root references released");
        check(!state.cache[0].leaves,"active mixed batch shadow removed");
    }
    for(unsigned fmt=0;fmt<2;fmt++) {
        init_disjoint(fmt);uint64_t result,pte=OTHER|0x0060000000000ec3UL;
        check(!sptm_mac_map_user_page(&memory,&backend,ROOT,0x4000,pte,1,0,&result),"different target inserted");
        record_disjoint(0,0x4000,0);record_disjoint(1,1UL<<42,0);
        check(!invoke_disjoint(DATA,LIST,2,BASE),"stale and absent mappings succeed");
        check(get(BASE,8)==pte && !get(BASE+8,8) && !unmap_prepared && !unmap_committed,
              "stale and absent outputs without shadow mutation");
        init_disjoint(fmt);unsigned shift=fmt?12:14;
        insert(fmt,0x4000,0,0);insert(fmt,0x4000+(1UL<<shift),1,0);
        record_disjoint(0,0x4000,0);record_disjoint(1,0x4000+(1UL<<shift),0);
        mutate_input=1;
        check(!invoke_disjoint(DATA,LIST,2,BASE) && !state.cache[0].leaves,
              "all input records copied before backend callbacks");
        for(unsigned role=14;role<=17;role+=3) {
            init_disjoint(fmt);uint64_t old=insert(fmt,0x4000,role==14,0);
            if(role==14) {
                old&=~(1UL<<54);put(source_slot(fmt,0x4000),old,8);
                /* Class13 executable aliases use the +12 counter, unlike
                 * the class15 read-only alias used to construct this fixture. */
                put(meta(DATA)+8,0,4);put(meta(DATA)+12,1,4);
                for(uint64_t off=0;off<(1UL<<(fmt?12:14));off+=4096) {
                    uint64_t slot=hw_slot(0x4000+off),v;hread(0,slot,&v);hwrite(0,slot,v&~(1UL<<54));
                }
            }
            put(meta(DATA)+2,role,1);record_disjoint(0,0x4000,0);
            enum sptm_result special=invoke_disjoint(DATA,LIST,1,BASE);
            if(special)printf("special role%u format%u status%u old%llx\n",role,fmt,special,(unsigned long long)old);
            check(!special,"executable or TPRO-role alias removal");
            check(!get(meta(DATA)+8,4) && !get(meta(DATA)+12,4),"special-role references released");
        }
        for(unsigned bad=0;bad<21;bad++) {
            init_disjoint(fmt);insert(fmt,0x4000,0,0);insert(fmt,0x4000+(1UL<<shift),1,0);
            record_disjoint(0,0x4000,0);record_disjoint(1,0x4000+(1UL<<shift),0);
            uint64_t target=DATA,list=LIST,count=2,scratch=BASE;
            switch(bad) {
            case 0:count=0;break;case 1:count=65;break;
            case 2:target++;break;case 3:scratch++;break;
            case 4:scratch=ROOT;break;case 5:scratch=FM;break;
            case 6:list=BASE+SIZE-24;break;case 7:list=LIST+16360;break;
            case 8:put(meta(LIST)+2,20,1);break;
            case 9:put(meta(LIST),1,2);break;case 10:put(meta(LIST),0xfff2,2);break;
            case 11:put(LIST+24,0,8);break;case 12:put(LIST+32,1UL<<47,8);break;
            case 13:put(meta(DATA)+12,0,4);break;
            case 14:fail_pa=LIST;break;case 15:fail_pa=BASE;break;
            case 16:reject_prepare=2;break;
            case 17:backend.prepare_unmap=0;break;
            case 18:put(meta(DATA)+2,20,1);break;
            case 19:put(meta(L3),1,2);break;
            case 20:put(meta(L3)+6,0,2);break;
            }
            memcpy(before,ram,SIZE);memcpy(host_before,host,sizeof(host));
            check(invoke_disjoint(target,list,count,scratch)!=SPTM_OK,"malformed late record refuses transaction");
            check(!memcmp(before,ram,SIZE) && !memcmp(host_before,host,sizeof(host)) &&
                  !unmap_committed,"refusal preserves source, references, scratch and private tables");
        }
    }
    printf("UNMAP_DISJOINT: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
