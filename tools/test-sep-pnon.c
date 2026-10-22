/* SPDX-License-Identifier: MIT */
#define SEP_SERVICE_TEST_MAIN service_checks
#include "test-sep-service.c"
static unsigned binds,queries,bind_failure,query_failure;
static uint64_t last_query_length;
static uint8_t request_body[32],reply_body[36];
static int bind_buffer(void *ctx,const struct sep_pnon *s,unsigned d,
                       uint64_t va,uint64_t size,uint64_t out[SEP_PNON_PAGES])
{
    CHECK(ctx==&binds && sep_pnon_valid(s) && d<2 && va);
    CHECK(size==(d ? 0x14000 : 0x1c000));binds++;
    for(unsigned i=0;i<SEP_PNON_PAGES;i++)out[i]=i<size/0x4000 ? 0x800000+d*0x40000+i*0x4000 : 0;
    if(bind_failure==2)out[1]=out[0];
    if(bind_failure==3)out[0]+=0x80000;
    return bind_failure!=1;
}
static int query_buffer(void *ctx,const struct sep_pnon *s,uint64_t length)
{
    CHECK(ctx==&binds && sep_pnon_valid(s) && s->stage[0]==2 && s->stage[1]==2);queries++;
    CHECK(length>=SEP_PNON_REQUEST_MIN && length<=SEP_PNON_REQUEST_MAX);last_query_length=length;
    return query_failure ? 0 : (model.config[4]&16) ?
        sep_pnon_refuse_sized(request_body,length,reply_body) :
        sep_pnon_reply_sized(request_body,length,reply_body);
}
static const struct sep_pnon_io pnon_io={&binds,bind_buffer,query_buffer};
static void pnon_reset(void)
{
    service_reset();model.config[4]=7;resources.pnon=&pnon_io;
    binds=queries=bind_failure=query_failure=0;
    memset(request_body,0,sizeof request_body);memset(reply_body,0xa5,sizeof reply_body);
    const uint8_t prefix[]={0x68,0x63,0x50,0x42,0x3e,0,0,0};memcpy(request_body,prefix,sizeof prefix);
    bootstrap();call(image(),1);CHECK(call(service_word(),1)==0xd0000);
    uint64_t pair[2];
    CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);
    CHECK(pair[0]==SEP_PNON_AD_NAME && !pair[1]);
    CHECK(device_model_read_pair(&model,&state,0x8830,pair)==DEVICE_OK);
    CHECK(pair[0]==SEP_PNON_AD_OOL && !pair[1]);
    CHECK(sep_pnon_valid(&state.sep_asc.pnon));
}
static uint64_t control_word(unsigned op,unsigned tag)
{
    unsigned d=op&1;uint64_t data=op>=4 ? (d ? 0x14000 : 0x1c000) : (0x10002000000UL+d*0x200000)>>12;
    return data<<32|0x1000000|(uint64_t)op<<16|(uint64_t)tag<<8;
}
static void configure_buffers(unsigned tag,unsigned reverse)
{
    for(unsigned i=0;i<2;i++) {
        unsigned d=i^reverse;
        CHECK(call(control_word(4+d,tag),1)==(control_word(4+d,tag)&~0xff000000UL));
        CHECK(call(control_word(2+d,tag),1)==(control_word(2+d,tag)&~0xff000000UL));
    }
}
#ifndef SEP_PNON_TEST_MAIN
#define SEP_PNON_TEST_MAIN main
#endif
int SEP_PNON_TEST_MAIN(int argc,char **argv)
{
    CHECK(argc==2 || (argc==3 && (!strcmp(argv[1],"--wire") || !strcmp(argv[1],"--ool") ||
                                  !strcmp(argv[1],"--wire-unsupported") ||
                                  !strcmp(argv[1],"--wire-long"))));
    FILE *f=fopen(argv[argc-1],"rb");CHECK(f);
    CHECK(fread(saved_payload,1,sizeof saved_payload,f)==sizeof saved_payload);
    CHECK(fgetc(f)==EOF);CHECK(!fclose(f));
    if(argc==3 && !strcmp(argv[1],"--ool")) {
        const unsigned ops[]={4,2,5,3};
        for(unsigned tag=1;tag<256;tag++) {
            pnon_reset();
            for(unsigned n=0;n<4;n++) {
                uint64_t request=control_word(ops[n],tag),reply=call(request,1);
                CHECK(reply==(request&~0xff000000UL));
                printf("%llx %llx\n",(unsigned long long)request,(unsigned long long)reply);
            }
        }
        return 0;
    }
    if(argc==3 && !strcmp(argv[1],"--wire-unsupported")) {
        /* mobileassetd's blessed recoveryOS policy nonce digest request. */
        pnon_reset();configure_buffers(8,0);request_body[4]=0x10;
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REFUSED);
        printf("%llx\n",(unsigned long long)SEP_PNON_REFUSED);
        for(unsigned i=0;i<32;i++)printf("%02x",request_body[i]);puts("");
        for(unsigned i=0;i<32;i++)printf("%02x",reply_body[i]);puts("");return 0;
    }
    if(argc==3 && !strcmp(argv[1],"--wire-long")) {
        /* get_security_mode_ex: command 0x11, 0x4028-byte request (header +
         * body); only the header is read. Prints word, header, reply. */
        pnon_reset();configure_buffers(8,0);request_body[4]=0x11;
        uint64_t req=0x4028UL<<32|SEP_PNON_COMMAND_KIND;
        CHECK(call(req,1)==SEP_PNON_REFUSED && last_query_length==0x4028);
        printf("%llx\n",(unsigned long long)req);
        for(unsigned i=0;i<32;i++)printf("%02x",request_body[i]);puts("");
        for(unsigned i=0;i<32;i++)printf("%02x",reply_body[i]);puts("");return 0;
    }
    if(argc==3) {
        pnon_reset();configure_buffers(8,0);CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY);
        printf("%llx\n%llx\n%llx\n",(unsigned long long)SEP_PNON_AD_NAME,
            (unsigned long long)SEP_PNON_AD_OOL,(unsigned long long)SEP_PNON_REPLY);
        for(unsigned i=0;i<36;i++)printf("%02x",reply_body[i]);puts("");return 0;
    }
    for(unsigned tag=1;tag<256;tag++) {
        pnon_reset();configure_buffers(tag,tag&1);
        CHECK(state.sep_asc.pnon.negotiations==4 && binds==2);
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY);
        CHECK(state.sep_asc.pnon.queries==1 && queries==1);
        CHECK(reply_body[0]==0x68 && reply_body[1]==0x72 && reply_body[2]==0x50 && reply_body[3]==0x42);
        for(unsigned i=4;i<36;i++)CHECK(reply_body[i]==(i==32 ? 2 : 0));
        CHECK(state.sep_asc.consumed==10 && state.sep_asc.published==12 && state.sep_asc.delivered==12);
        CHECK(!state.sep_asc.count && !state.sep_asc.reply_count);
        configure_buffers(tag,0);CHECK(state.sep_asc.pnon.negotiations==8 && binds==4);
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY && queries==2);
    }
    for(unsigned test=0;test<16;test++) {
        pnon_reset();uint64_t req=control_word(4,8);
        if(test==0)req&=~0xff00UL;
        if(test==1)req|=1;
        if(test==2)req+=1UL<<24;
        if(test==3)req+=1UL<<32;
        if(test==4)req=control_word(2,8);
        if(test==5)req=SEP_PNON_QUERY;
        if(test>=6) {call(control_word(4,8),1);req=control_word(2,8);}
        if(test==6)resources.pnon=0;
        if(test==7)bind_failure=1;
        if(test==8)bind_failure=2;
        if(test==9)req+=1UL<<32;
        if(test>=10) {
            configure_buffers(8,0);req=SEP_PNON_QUERY;
            if(test==10)query_failure=1;
            if(test==11)request_body[8]=1;
            /* 31 bytes: shorter than the header __sep_command always writes. */
            if(test==12)req-=1UL<<32;
            if(test==13)req^=1;
            if(test==14){req=control_word(2,8);bind_failure=3;}
            if(test==15)req=control_word(3,8)-(0x200000UL>>12<<32);
        }
        submit(req);before=state;uint8_t old_reply[36];memcpy(old_reply,reply_body,sizeof old_reply);
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state));CHECK(!memcmp(old_reply,reply_body,sizeof reply_body));
    }
    for(unsigned byte=0;byte<32;byte++)for(unsigned bit=0;bit<8;bit++) {
        pnon_reset();request_body[byte]^=1U<<bit;uint8_t old[36];memcpy(old,reply_body,sizeof old);
        CHECK(!sep_pnon_os_type(request_body,reply_body));CHECK(!memcmp(old,reply_body,sizeof old));
    }
    pnon_reset();configure_buffers(8,0);call(SEP_PNON_QUERY,1);
    for(unsigned field=0;field<26;field++) {
        struct device_state bad=state;uint64_t *words=(uint64_t *)&bad.sep_asc.pnon;
        words[field]^=1;before=bad;
        /* Counter increments are invalid against outer transport accounting. */
        CHECK(device_sep_rom_step(&model,&bad,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&bad,sizeof bad));
    }
    /* Every other well-formed command (mobileassetd's 0x10, the blessed
     * recoveryOS policy nonce digest, stopped a live run) is answered with a
     * 32-byte not-supported header, and OS type still works afterwards. */
    for(unsigned command=1;command<256;command++) {
        if(command==0x3e)continue;
        pnon_reset();configure_buffers(8,0);request_body[4]=(uint8_t)command;
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REFUSED && queries==1);
        CHECK(state.sep_asc.pnon.queries==1 && state.sep_asc.pnon.last_reply==SEP_PNON_REFUSED);
        CHECK(sep_pnon_valid(&state.sep_asc.pnon));
        CHECK(reply_body[0]==0x68 && reply_body[1]==0x72 && reply_body[2]==0x50 && reply_body[3]==0x42);
        CHECK(reply_body[4]==SEP_PNON_NOT_SUPPORTED);
        for(unsigned i=5;i<32;i++)CHECK(!reply_body[i]);
        request_body[4]=0x3e;
        CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY && state.sep_asc.pnon.queries==2);
        for(unsigned i=4;i<36;i++)CHECK(reply_body[i]==(i==32 ? 2 : 0));
    }
    /* Not the header shape: no reply, no state change, no guest bytes. */
    for(unsigned test=0;test<4;test++) {
        pnon_reset();configure_buffers(8,0);
        if(test==0)request_body[4]=0;
        if(test==1){request_body[4]=0x10;request_body[5]=1;}
        if(test==2){request_body[4]=0x10;request_body[31]=1;}
        if(test==3){request_body[4]=0x10;request_body[1]=0x72;}
        submit(SEP_PNON_QUERY);before=state;uint8_t old[36];memcpy(old,reply_body,sizeof old);
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state) && !memcmp(old,reply_body,sizeof old));
    }
    /* Commands with a body: every 26A428 libbootpolicy request length from the
     * fixed-output wrappers (0x124..0x8168) and the policy builders, plus the
     * range edges, gets the 32-byte not-supported header; the body is never
     * read, so only the header is placed in request_body here. */
    const uint64_t lengths[]={33,0x28,0x124,0x130,0x1124,0x4028,0x4030,0x4058,0x4130,
        0x8030,0x8138,0x8140,0x8168,0x1bfff,SEP_PNON_REQUEST_MAX};
    for(unsigned n=0;n<sizeof lengths/sizeof lengths[0];n++)
        for(unsigned command=1;command<256;command++) {
            pnon_reset();configure_buffers(8,0);request_body[4]=(uint8_t)command;
            uint64_t req=lengths[n]<<32|SEP_PNON_COMMAND_KIND;
            CHECK(sep_pnon_command(req));
            CHECK(call(req,1)==SEP_PNON_REFUSED && queries==1 && last_query_length==lengths[n]);
            CHECK(state.sep_asc.pnon.queries==1 && state.sep_asc.pnon.last_request==req);
            CHECK(state.sep_asc.pnon.last_reply==SEP_PNON_REFUSED && sep_pnon_valid(&state.sep_asc.pnon));
            CHECK(reply_body[0]==0x68 && reply_body[1]==0x72 && reply_body[2]==0x50 && reply_body[3]==0x42);
            CHECK(reply_body[4]==SEP_PNON_NOT_SUPPORTED);
            for(unsigned i=5;i<32;i++)CHECK(!reply_body[i]);
            /* The 36-byte OS-type reply stays reserved for the exact query. */
            request_body[4]=0x3e;
            CHECK(call(SEP_PNON_QUERY,1)==SEP_PNON_REPLY && state.sep_asc.pnon.queries==2);
            for(unsigned i=4;i<36;i++)CHECK(reply_body[i]==(i==32 ? 2 : 0));
        }
    /* A long request can never produce, or be recorded as, the OS-type reply. */
    {
        uint8_t header[32]={0x68,0x63,0x50,0x42,0x3e},out[36];memset(out,0xa5,sizeof out);
        CHECK(sep_pnon_reply_sized(header,0x4028,out)==32 && out[4]==SEP_PNON_NOT_SUPPORTED && !out[32]);
        CHECK(sep_pnon_reply_sized(header,32,out)==36 && out[32]==SEP_PNON_OS_TYPE);
        struct sep_pnon forged={0};pnon_reset();configure_buffers(8,0);
        forged=state.sep_asc.pnon;forged.queries=1;
        forged.last_request=0x4028UL<<32|SEP_PNON_COMMAND_KIND;forged.last_reply=SEP_PNON_REPLY;
        CHECK(!sep_pnon_valid(&forged));
        forged.last_reply=SEP_PNON_REFUSED;CHECK(sep_pnon_valid(&forged));
    }
    /* Out-of-range lengths, other kinds and malformed headers with a body:
     * no reply, no state change, no guest bytes, no callback. */
    for(unsigned test=0;test<12;test++) {
        pnon_reset();configure_buffers(8,0);request_body[4]=0x11;
        uint64_t req=0x4028UL<<32|SEP_PNON_COMMAND_KIND;
        if(test==0)req=0;
        if(test==1)req=31UL<<32|SEP_PNON_COMMAND_KIND;
        if(test==2)req=(SEP_PNON_REQUEST_MAX+1)<<32|SEP_PNON_COMMAND_KIND;
        if(test==3)req=0xffffffffUL<<32|SEP_PNON_COMMAND_KIND;
        if(test==4)req|=0x10000;      /* nonzero status byte in a request */
        if(test==5)req|=0x1000000;
        if(test==6)req^=0x300;        /* request byte other than 2 */
        if(test==7)request_body[4]=0;
        if(test==8)request_body[5]=1;
        if(test==9)request_body[31]=1;
        if(test==10)request_body[0]=0;
        if(test==11)query_failure=1;
        CHECK(sep_pnon_command(req)==(test>=7));
        submit(req);before=state;uint8_t old[36];memcpy(old,reply_body,sizeof old);
        unsigned previous=queries;
        CHECK(device_sep_rom_step(&model,&state,&resources)!=DEVICE_OK);
        CHECK(!memcmp(&before,&state,sizeof state) && !memcmp(old,reply_body,sizeof old));
        CHECK(queries==previous+(test>=7));
    }
    pnon_reset();configure_buffers(8,0);
    for(unsigned i=0;i<8;i++){submit(SEP_PNON_QUERY);CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_OK);}
    submit(SEP_PNON_QUERY);before=state;unsigned previous=queries;
    CHECK(device_sep_rom_step(&model,&state,&resources)==DEVICE_BAD_VALUE);
    CHECK(!memcmp(&before,&state,sizeof state) && queries==previous);
    printf("PASS: %u pnon discovery, negotiation, read-only query and not-supported checks\n",checks);return 0;
}
