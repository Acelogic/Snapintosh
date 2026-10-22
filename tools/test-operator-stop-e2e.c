/* SPDX-License-Identifier: MIT
 * Production transport -> monitor -> service-stop replay. Failure inventory:
 * docs/OPERATOR-STOP-CONTROLS-20261018.md. No hardware or timer delivery proof. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "early-stop.h"
#include "service-lock.h"
#include "call-service.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
#define HZ UINT64_C(19200000)
#define SESSION UINT64_C(0x5eed5eed12345678)
static void packet(const char *root,const char *name,uint8_t *b) {
    char p[4096]; CHECK(snprintf(p,sizeof p,"%s/%s",root,name)>0);
    FILE *f=fopen(p,"rb"); CHECK(f); CHECK(fread(b,1,104,f)==104); CHECK(fgetc(f)==EOF); fclose(f);
}
static int32_t status(const uint8_t *b) { uint32_t n; memcpy(&n,b+24,4); return (int32_t)n; }
static void send(struct q1n1_call_state *q,uint8_t *b,uint64_t now,int want) {
    uint8_t reply[64]; CHECK(q1n1_stop_datagram(q,b,104,now,reply)==64); CHECK(status(reply)==want);
    CHECK(q1n1_crc32(reply,56)==((uint32_t)reply[56]|(uint32_t)reply[57]<<8|(uint32_t)reply[58]<<16|(uint32_t)reply[59]<<24));
}
static struct early_stop_params params(void) {
    return (struct early_stop_params){.flags=EARLY_STOP_F_ALL,.max_delay_s=3600,.session=SESSION};
}
static int deliver(struct q1n1_call_state *q,struct early_stop_state *s,uint64_t now) {
    struct early_stop_host_request r={0}; uint64_t accepted=99; struct early_stop_params p=params();
    CHECK(q1n1_call_take(q,&r,sizeof r)==1); CHECK(!early_stop_host_admit(&p,&r,&accepted));
    int e=early_stop_request(s,EARLY_STOP_SOURCE_HOST,r.reason,r.nonce,r.delay_s,accepted,now,HZ,0,0,r.text);
    CHECK(q1n1_call_take(q,&r,sizeof r)==0); return e;
}
static void scenario(const uint8_t *urgent0,const uint8_t *delayed0,int host_first,uint64_t start) {
    uint8_t urgent[104],delayed[104];memcpy(urgent,urgent0,104);memcpy(delayed,delayed0,104);
    struct q1n1_call_state q; q1n1_call_init(&q);CHECK(!q1n1_call_arm(&q,SESSION));
    struct early_stop_state s={0}; struct guest_service_lock lock={0}; CHECK(!guest_service_boot(&lock));
    uint64_t budget=start+1800*HZ, now=start+10*HZ;
    CHECK(!early_stop_request(&s,EARLY_STOP_SOURCE_GUEST,1,1,1700,1700,start,HZ,1,0,NULL));
    if(host_first) {send(&q,delayed,now,0);CHECK(deliver(&q,&s,now)==EARLY_STOP_ACCEPTED);CHECK(s.deadline==now+120*HZ);}
    now+=HZ;send(&q,urgent,now,0);CHECK(deliver(&q,&s,now)==EARLY_STOP_ACCEPTED);
    CHECK(s.source==EARLY_STOP_SOURCE_HOST && s.accepted_delay==0 && s.deadline==now);
    /* Replayed/older packets do not move the winning latch or monitor deadline. */
    send(&q,urgent,now+1,Q1N1_STOP_ALREADY);send(&q,delayed,now+2,Q1N1_STOP_ALREADY);
    CHECK(early_stop_request(&s,EARLY_STOP_SOURCE_GUEST,2,9,0,0,now,HZ,2,0,NULL)==EARLY_STOP_DUPLICATE);
    CHECK(early_stop_request(&s,EARLY_STOP_SOURCE_HOST,1,9,300,300,now,HZ,0,0,NULL)==EARLY_STOP_DUPLICATE);
    CHECK(early_stop_deadline(&s,budget)==now);
    CHECK(!early_stop_fire(&s,now-1,budget,2));CHECK(early_stop_fire(&s,now,budget,2));
    guest_service_stop(&lock,2,SERVICE_STOP_NORMAL);early_stop_finish(&s,guest_service_stopped(&lock));
    CHECK(s.outcome==EARLY_STOP_OUTCOME_STOPPED && s.fire_cpu==3);
    CHECK(early_stop_request(&s,EARLY_STOP_SOURCE_HOST,1,77,0,0,now-1,HZ,0,0,NULL)==EARLY_STOP_DUPLICATE);
    CHECK(s.fire_cpu==3 && s.deadline==now);
    printf("{\"scenario\":\"%s%s\",\"source\":%llu,\"deadline\":%llu,\"fire_ticks\":%llu,\"outcome\":%llu,\"hardware_verified\":false}\n",
           host_first?"delivered-host-then-urgent":"guest-then-urgent",start?"-wrap":"",
           (unsigned long long)s.source,(unsigned long long)s.deadline,(unsigned long long)s.fire_ticks,(unsigned long long)s.outcome);
}
int main(int argc,char **argv) {
    CHECK(argc==2); uint8_t urgent[104],delayed[104],stale[104];
    packet(argv[1],"urgent.bin",urgent);packet(argv[1],"delayed.bin",delayed);packet(argv[1],"stale.bin",stale);
    struct q1n1_call_state q;q1n1_call_init(&q);CHECK(!q1n1_call_arm(&q,SESSION));
    send(&q,stale,1,Q1N1_STOP_E_SESSION);CHECK(!q.latched);
    stale[0]=urgent[0];memcpy(stale,urgent,104);stale[40]^=1;
    send(&q,stale,2,Q1N1_STOP_E_MALFORMED);CHECK(!q.latched);
    scenario(urgent,delayed,0,0);scenario(urgent,delayed,1,0);
    scenario(urgent,delayed,0,UINT64_MAX-5*HZ);scenario(urgent,delayed,1,UINT64_MAX-5*HZ);
    struct early_stop_state huge={0};
    CHECK(!early_stop_request(&huge,EARLY_STOP_SOURCE_GUEST,1,0,3600,3600,1,UINT64_MAX,0,0,NULL));
    CHECK((int64_t)(huge.deadline-1)>0); /* overflow never creates an expired request */
    puts("PASS: production operator-stop integration replay");return 0;
}
