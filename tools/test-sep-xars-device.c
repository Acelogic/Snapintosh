/* SPDX-License-Identifier: MIT */
#define SEP_PNON_TEST_MAIN pnon_checks
#include "test-sep-pnon.c"

static unsigned xars_binds,xars_checks,xars_fail,xars_slots;
static int xars_bind(void *ctx,const struct sep_xars *s,unsigned d,uint64_t va,
                     uint64_t size,uint64_t out[SEP_XARS_PAGES])
{
    CHECK(ctx==&xars_binds && sep_xars_valid(s) && d<2 && va && size==0x8000);
    xars_binds++;
    for(unsigned i=0;i<2;i++)out[i]=0x900000+d*0x8000+i*0x4000;
    return !xars_fail;
}
static int xars_validate(void *ctx,const struct sep_xars *s)
{
    CHECK(ctx==&xars_binds && sep_xars_valid(s));xars_checks++;return !xars_fail;
}
static int xars_slot(void *ctx,const struct sep_xars *s,unsigned bytes)
{
    CHECK(ctx==&xars_binds && sep_xars_valid(s) && s->stage[0]==2 && s->stage[1]==2);
    CHECK(bytes==SEP_XARS_SLOT_BYTES || bytes==SEP_XARS_EPOCH_BYTES);
    xars_slots++;return !xars_fail;
}
static const struct sep_xars_io xars_io={&xars_binds,xars_bind,xars_validate,xars_slot};
static uint64_t xcontrol(unsigned op,unsigned tag)
{
    uint64_t data=op>=4 ? 0x8000 : (0x10003000000UL+(op&1)*0x200000)>>12;
    return data<<32|2UL<<24|(uint64_t)op<<16|(uint64_t)tag<<8;
}
static void xars_reset_mode(unsigned mode)
{
    unsigned pnon=mode!=0,xars=mode!=3;
    service_reset();model.config[4]=mode==0 ? 11 : mode==1 ? 15 : mode==2 ? 27 : 19;
    resources.pnon=pnon ? &pnon_io : 0;resources.xars=xars ? &xars_io : 0;
    xars_binds=xars_checks=xars_fail=xars_slots=0;
    binds=queries=bind_failure=query_failure=0;
    memset(request_body,0,sizeof request_body);
    const uint8_t prefix[]={0x68,0x63,0x50,0x42,0x3e,0,0,0};memcpy(request_body,prefix,sizeof prefix);
    bootstrap();call(image(),1);CHECK(call(service_word(),1)==0xd0000);
    const uint64_t expected[]={SEP_PNON_AD_NAME,SEP_PNON_AD_OOL,SEP_XARS_AD_NAME,SEP_XARS_AD_OOL};
    for(unsigned i=pnon ? 0 : 2;i<(xars ? 4U : 2U);i++) {
        uint64_t pair[2];CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);
        CHECK(pair[0]==expected[i] && !pair[1]);
    }
    unsigned replies=5+2*pnon+2*xars;
    CHECK(state.sep_asc.consumed==5 && state.sep_asc.published==replies && state.sep_asc.delivered==replies);
}
static void xars_reset(void){xars_reset_mode(1);}
static void xars_buffers(unsigned tag)
{
    const unsigned ops[]={4,2,5,3};
    for(unsigned i=0;i<4;i++)CHECK(call(xcontrol(ops[i],tag),1)==(xcontrol(ops[i],tag)&~0xff000000UL));
}
int main(int argc,char **argv)
{
    CHECK(argc==2);CHECK(!pnon_checks(argc,argv));
    /* Installed BootPolicy's reached command0x0e needs pnon independently of
     * the recovery OS-type response, both alone and alongside xars. Exercise
     * the real model's admission, discovery, negotiation, routing and refusal
     * through the same producer and preserve state when the callback fails. */
    for(unsigned mode=2;mode<=3;mode++) {
        xars_reset_mode(mode);configure_buffers(255,1);
        if(mode==2)xars_buffers(7);
        request_body[4]=0x0e;
        const unsigned lengths[]={32,33,0x4028,0x1c000};
        for(unsigned n=0;n<4;n++) {
            CHECK(call((uint64_t)lengths[n]<<32|0x201,1)==SEP_PNON_REFUSED);
            CHECK(reply_body[4]==255 && last_query_length==lengths[n]);
        }
        request_body[4]=0x3e;
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REFUSED && reply_body[4]==255);
        request_body[0]^=1;submit(SEP_PNON_QUERY);before=state;
        uint8_t prior_reply[36];memcpy(prior_reply,reply_body,sizeof prior_reply);
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
        CHECK(!memcmp(&state,&before,sizeof state) && !memcmp(prior_reply,reply_body,sizeof prior_reply));
        request_body[0]^=1;
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);
        uint64_t recovered[2];
        CHECK(device_model_read_pair(&model,&state,0x8830,recovered)==DEVICE_OK);
        CHECK(recovered[0]==SEP_PNON_REFUSED && !recovered[1]);
        if(mode==2)CHECK(call(0x0a0702,1)==0x10702);
        CHECK(call(0x14ff00,1)==0x14ff00);
        query_failure=1;submit(SEP_PNON_QUERY);before=state;
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned flags=0;flags<64;flags++) {
        if(flags==0 || flags==1 || flags==3 || flags==7 || flags==11 ||
           flags==15 || flags==19 || flags==27 || flags==59)continue;
        service_reset();model.config[4]=flags;before=state;
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_CONFIG);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned n=0;n<5;n++) {
        uint8_t header[32]={0x68,0x63,0x50,0x42,0x3e},reply[36];memset(reply,0xa5,sizeof reply);
        uint64_t length=n==0 ? 31 : n==1 ? 0x1c001 : 32;
        if(n==2)header[0]=0;
        if(n==3)header[8]=1;
        if(n==4)header[5]=1;
        CHECK(!sep_pnon_refuse_sized(header,length,reply));
        for(unsigned i=0;i<sizeof reply;i++)CHECK(reply[i]==0xa5);
    }
    /* Installed CPSN lookup needs xars without claiming recoveryOS through
     * pnon. Exercise the real frontend, advertisement queue and buffer
     * negotiation for every tag; the old admission/routing each fail here. */
    for(unsigned tag=1;tag<256;tag++) {
        xars_reset_mode(0);
        /* The native installed startup sends effective-status before buffer
         * negotiation (generation24 queued0x140800). It is not a pnon query. */
        uint64_t status=0x140000UL|(uint64_t)tag<<8;
        CHECK(call(status,1)==status);
        xars_buffers(tag);
        const unsigned ops[]={0x0a,0x0b,0x20};
        for(unsigned i=0;i<3;i++)
            CHECK(call((uint64_t)ops[i]<<16|(uint64_t)tag<<8|2,1)==(0x10002UL|(uint64_t)tag<<8));
        CHECK(state.sep_asc.xars.queries==3 && xars_binds==2 && xars_checks==3 && !xars_slots);
        CHECK(!memcmp(&state.sep_asc.pnon,&(struct sep_pnon){0},sizeof(struct sep_pnon)));
        CHECK(!binds && !queries && !resources.pnon);
        CHECK(call(status,1)==status && state.sep_asc.status_queries==2);
        CHECK(state.sep_asc.consumed==14 && state.sep_asc.published==16 && state.sep_asc.delivered==16);
        submit(SEP_PNON_QUERY);before=state;
        CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_UNKNOWN_REGISTER);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned tag=1;tag<256;tag++) {
        xars_reset();xars_buffers(tag);configure_buffers(tag,tag&1);
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY);
        for(unsigned op=10;op<=11;op++)CHECK(call((uint64_t)op<<16|(uint64_t)tag<<8|2,1)==(0x10002UL|(uint64_t)tag<<8));
        CHECK(call(0x200002UL|(uint64_t)tag<<8,1)==(0x10002UL|(uint64_t)tag<<8));
        CHECK(call(0x140000UL|(uint64_t)tag<<8,1)==(0x140000UL|(uint64_t)tag<<8));
        for(unsigned slot=0;slot<2;slot++)
            CHECK(call((uint64_t)slot<<48|0x180002UL|(uint64_t)tag<<8,1)==(0x38000002UL|(uint64_t)tag<<8));
        CHECK(state.sep_asc.xars.queries==5 && state.sep_asc.pnon.queries==1 && xars_checks==3 && xars_slots==2);
        CHECK(state.sep_asc.consumed==20 && state.sep_asc.published==24 && state.sep_asc.delivered==24);
    }
    for(unsigned test=0;test<4;test++) {
        /* Slot queries: callback failure, slot 2, stray bits and a missing
         * callback all leave the queue, counters and history untouched. */
        xars_reset();xars_buffers(7);
        submit(test==1 ? 0x2000000180702UL : test==2 ? 0x180702UL|1UL<<40 : 0x180702UL);
        if(test==0)xars_fail=1;
        if(test==3)resources.xars=&(const struct sep_xars_io){&xars_binds,xars_bind,xars_validate,0};
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned recovery=0;recovery<2;recovery++)for(unsigned test=0;test<8;test++) {
        xars_reset_mode(recovery);xars_buffers(7);submit(0xa0702);
        if(test==0)xars_fail=1;
        if(test==1)state.sep_asc.xars.queries=UINT64_MAX;
        if(test==2)state.sep_asc.xars.advertisements=0;
        if(test==3)state.sep_asc.request[0][1]=1;
        if(test==4)state.sep_asc.request[0][0]|=1UL<<32;
        if(test==5)state.sep_asc.xars.physical[1][0]=state.sep_asc.xars.physical[0][0];
        if(test==6)resources.xars=0;
        if(test==7)state.sep_asc.published++;
        before=state;CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&state,&before,sizeof state));
    }
    for(unsigned recovery=0;recovery<2;recovery++) {
    xars_reset_mode(recovery);xars_buffers(7);
    for(unsigned i=0;i<8;i++){submit(0xa0702);CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);}
    submit(0xa0702);before=state;
    CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&state,&before,sizeof state));
    }
    CHECK(sizeof(struct device_state)==13000);
    printf("PASS: %u integrated SEP xars/pnon, queue and rollback checks\n",checks);return 0;
}
