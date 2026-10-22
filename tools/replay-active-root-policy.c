/* SPDX-License-Identifier: MIT */
/* Full typed-root lifecycle replay. Failure inventory precedes implementation
 * in docs/INSTALLED-ADRENO-METAL-20260926.md. Hardware installation is modeled;
 * source tables, root switching/configuration and shadow construction are real. */
#define SPTM_ROOT_SUITE original_root_suite
#include "test-sptm-root.c"
#include "sptm-root-policy.h"
static struct sptm_root_state state;
static struct sptm_loaded_root loaded[SPTM_ROOT_CPUS];
static struct sptm_root_configuration config;
static uint8_t shadow_before[sizeof host];
static int configure_live(void *ctx,uint64_t root,uint16_t old,uint16_t next)
{
    (void)ctx;
    unsigned active=0;
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)active+=state.active[cpu]==root;
    if(active)return sptm_root_configure_active(&state,loaded,root,old,next);
    return sptm_root_invalidate(&state,root,0);
}
static struct sptm_memory fixture(unsigned format,unsigned mask)
{
    reset_host();memset(&state,0,sizeof state);memset(loaded,0,sizeof loaded);
    memset(&config,0,sizeof config);
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++) {
        sprr_root_reset(&state.sprr[cpu],0);
        check(sptm_root_note_loaded(&state,loaded,cpu),"record initial kernel policy");
    }
    struct sptm_memory m=reset_geometry(31,10,VA,format);uint64_t result;
    m.configure_user_root=configure_live;m.root_configuration=&config;
    check(sptm_mac_map_user_page(&m,&backend,ROOT,VA,DATA|RX,1,0,&result)==SPTM_OK,
          "create real typed executable mapping");
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)if(mask&(1u<<cpu)) {
        check(activate(&m,&state,cpu,ROOT)==SPTM_OK,"activate shared process root");
        check(sptm_root_note_loaded(&state,loaded,cpu),"record successful CPU activation");
    }
    return m;
}
static void lifecycle(unsigned format,unsigned mask)
{
    struct sptm_memory m=fixture(format,mask);
    struct sprr_state saved_sprr[SPTM_ROOT_CPUS];memcpy(saved_sprr,state.sprr,sizeof saved_sprr);
    struct sptm_loaded_root saved_loaded[SPTM_ROOT_CPUS];memcpy(saved_loaded,loaded,sizeof loaded);
    memcpy(shadow_before,host,sizeof host);
    uint64_t refs_before=get(meta(ROOT)+6,2),alloc_before=next_host;
    check(sptm_mac_configure_root(&m,ROOT,1,1)==SPTM_OK,"configure active root saved UMPRR11");
    check(get(meta(ROOT)+10,2)==11 && state.cache[0].flags==11 && state.cache[0].valid,
          "saved metadata and retained cache identity agree");
    check(!memcmp(saved_sprr,state.sprr,sizeof saved_sprr) && !memcmp(saved_loaded,loaded,sizeof loaded),
          "configure preserves all installed CPU policies and records");
    check(!memcmp(shadow_before,host,sizeof host) && next_host==alloc_before,
          "configure neither changes nor reallocates active shadow tables");
    check(get(meta(ROOT)+6,2)==refs_before && !state.invalidations,
          "configure preserves ownership and translations");
    check(!sptm_root_invalidate(&state,ROOT,0) && !sptm_root_invalidate(&state,ROOT,1),
          "active root still cannot invalidate or retire");
    struct sptm_root_state unchanged_state=state;
    check(sptm_mac_configure_root(&m,ROOT,1,1)==SPTM_OK && !memcmp(&state,&unchanged_state,sizeof state),
          "repeated saved flag is a true no-change operation");
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)if(mask&(1u<<cpu)) {
        check(activate(&m,&state,cpu,ROOT)==SPTM_OK,"same-root switch loads saved policy");
        check(sptm_root_note_loaded(&state,loaded,cpu),"record reloaded policy");
        check(state.sprr[cpu].umprr==0x40800 && loaded[cpu].flags==11,
              "only switching CPU acquires new UMPRR policy");
        for(unsigned peer=cpu+1;peer<SPTM_ROOT_CPUS;peer++)if(mask&(1u<<peer))
            check(state.sprr[peer].umprr==0x40000 && loaded[peer].flags==10,
                  "peer retains its old installed policy until its own switch");
        check(get(meta(ROOT)+6,2)==refs_before,"same-root switch balances references");
        mapping(installed[cpu][0],VA+123,DATA+123,1);
    }
    check(sptm_mac_configure_root(&m,ROOT,0,1)==SPTM_OK,"clear saved policy while CPUs retain it");
    for(unsigned cpu=0;cpu<SPTM_ROOT_CPUS;cpu++)if(mask&(1u<<cpu)) {
        check(state.sprr[cpu].umprr==0x40800,"clear does not reset a running CPU");
        check(activate(&m,&state,cpu,BASE)==SPTM_OK,"leave user address space");
        check(sptm_root_note_loaded(&state,loaded,cpu) && !loaded[cpu].root && !loaded[cpu].flags,
              "kernel switch records reset policy");
    }
    check(sptm_root_invalidate(&state,ROOT,0),"last CPU departure permits invalidation");
    check(activate(&m,&state,0,ROOT)==SPTM_OK && sptm_root_note_loaded(&state,loaded,0),
          "invalidated root rebuilds with current saved policy");
    check(state.sprr[0].umprr==0x40000 && loaded[0].flags==10,"rebuilt policy is current");
    mapping(installed[0][0],VA+123,DATA+123,1);
}
static void rejection(unsigned kind)
{
    struct sptm_memory m=fixture(0,1);uint64_t value=1,mask=1;
    switch(kind) {
    case 0:state.cache[0].flags=2;break;
    case 1:state.cache[0].valid=0;break;
    case 2:state.cache[1]=state.cache[0];break;
    case 3:state.cache[0].shadow++;break;
    case 4:state.cache[0].asid=0;break;
    case 5:loaded[0].root=ROOT+0x4000;break;
    case 6:loaded[0].resets++;break;
    case 7:loaded[0].flags^=2;break;
    case 8:state.sprr[0].umprr^=0x800;break;
    case 9:value=0;mask=8;break;
    case 10:value=0;mask=2;break;
    case 11:meta(ROOT);put(meta(ROOT),1,1);break;
    case 12:state.cache[0].format=2;break;
    case 13:state.cache[0].root=ROOT+0x4000;break;
    }
    struct sptm_root_state old=state;
    struct sptm_loaded_root old_loaded[6];memcpy(old_loaded,loaded,sizeof loaded);
    struct sptm_root_configuration old_config=config;
    memcpy(before,ram,sizeof ram);memcpy(shadow_before,host,sizeof host);
    check(sptm_mac_configure_root(&m,ROOT,value,mask)!=SPTM_OK,"malformed or unsupported active change refused");
    check(!memcmp(&old,&state,sizeof state) && !memcmp(old_loaded,loaded,sizeof loaded) &&
          !memcmp(&old_config,&config,sizeof config) && !memcmp(before,ram,sizeof ram) &&
          !memcmp(shadow_before,host,sizeof host),"refusal leaves all ownership and memory unchanged");
}
int main(void)
{
    for(unsigned format=0;format<2;format++)for(unsigned mask=1;mask<64;mask++)lifecycle(format,mask);
    for(unsigned kind=0;kind<14;kind++)rejection(kind);
    printf("{\"status\":\"%s\",\"lifecycle_cases\":126,\"refusal_cases\":14,\"checks\":%u,\"failures\":%u}\n",
           failures ? "FAIL" : "PASS",checks,failures);
    return failures ? 1 : 0;
}
