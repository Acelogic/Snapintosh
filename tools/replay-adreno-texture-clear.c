/* SPDX-License-Identifier: MIT */
/* E2E: production Metal bytes/native descriptors -> actual parser/cache/fill
 * -> modeled CP/SMMU writes -> complete byte comparison with Apple GPU output.
 * The included retain/prepare callbacks and memory are explicit fixtures. */
#define ADRENO_FILL_COMMAND_TEST_ENTRY retained_fill_command_main
#include "test-adreno-fill-command.c"

int main(int argc,char **argv)
{
    if(argc!=4) return 2;
    checks=failures=0;
    dram=calloc(1,RAM_SIZE);cache=calloc(1,RAM_SIZE);
    if(!dram || !cache) return 2;
    setup_command();
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    resources=(struct adreno_resource_list){0};
    memset(entries,0,sizeof entries);
    retains=prepares=completes=releases=0;
    unsigned char stream[23*32+8],golden[37*23*4];
    read_exact(argv[1],wire_list,sizeof wire_list);
    read_exact(argv[2],stream,sizeof stream);
    read_exact(argv[3],golden,sizeof golden);
    CHECK(adreno_resource_list_acquire(&resources,wire_list,sizeof wire_list,
        wire_copy,sizeof wire_copy,entries,6,&list_ops)==0);
    CHECK(adreno_resource_list_prepare(&resources,&list_ops)==0);
    for(unsigned row=0;row<23;row++) {
        memcpy(wire_command,stream+row*32,sizeof wire_command);
        struct adreno_fill32_request request;
        CHECK(adreno_fill32_decode(wire_command,sizeof wire_command,&request)==0);
        CHECK(request.resource_id==7 && request.offset==0x3f00+row*256 && request.bytes==37*4);
        CHECK(submit()==0);
    }
    CHECK(transfers==23 && cp_target_writes==37*23 && cpu_destination_stores==0);
    CHECK(syncs[0]==23 && syncs[1]==23 && syncs[2]==23);
    unsigned wrong=0;
    for(uint64_t offset=0;offset<GUEST_SIZE;offset+=4) {
        uint64_t logical=offset<0x4000 ? offset : offset>=0xc000 ? offset-0x8000 : UINT64_MAX;
        uint32_t expected=0xa55aa55a;
        if(logical>=0x3f00 && logical<0x3f00+23*256) {
            uint64_t rel=logical-0x3f00,row=rel/256,column=rel%256;
            if(column<37*4) memcpy(&expected,golden+row*37*4+column,4);
        }
        wrong+=m_rd(0,GUEST_PAGE+offset)!=expected;
    }
    CHECK(!wrong);
    CHECK(adreno_submit_command(stream+23*32,8,parsed_native_fence,0)==0);
    CHECK(native_fence_calls==1);
    save_model_artifact("clear-gpu-destination.bin",GUEST_PAGE,GUEST_SIZE);
    CHECK(adreno_resource_list_release(&resources,&list_ops)==0);
    CHECK(retains==1 && prepares==1 && completes==1 && releases==1);
    printf("%s: %u checks; 23 GPU fills, 851 pixel writes, zero CPU destination stores, full64KiB/padding/canaries match Apple GPU reference\n",
        failures ? "FAIL" : "PASS",checks);
    free(dram);free(cache);
    return failures ? 1 : 0;
}
