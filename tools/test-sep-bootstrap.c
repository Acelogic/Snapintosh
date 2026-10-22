/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sep-bootstrap.h"
static unsigned checks,reads,fail;
static uint8_t data[0x14000],original[sizeof data];
#define CHECK(c) do {checks++;if(!(c)){fprintf(stderr,"line %d: %s\n",__LINE__,#c);exit(1);}} while(0)
static int read_buffer(void *ctx,uint32_t offset,size_t size,void *out)
{
    CHECK(ctx==data);reads++;
    CHECK(offset<=sizeof data && size<=sizeof data-offset);
    if(reads==fail)return 0;
    memcpy(out,data+offset,size);return 1;
}
static struct sep_bootstrap_reader reader={data,read_buffer};
static void check_reject(uint64_t size)
{
    struct sep_bootstrap before,out;memset(&out,0xa5,sizeof out);before=out;
    CHECK(sep_bootstrap_parse(&reader,size,&out)!=SEP_BOOTSTRAP_OK);
    CHECK(!memcmp(&out,&before,sizeof out));
}
int main(int argc,char **argv)
{
    CHECK(argc==2);FILE *f=fopen(argv[1],"rb");CHECK(f);
    CHECK(fread(data,1,sizeof data,f)==sizeof data);CHECK(fgetc(f)==EOF);CHECK(!fclose(f));
    memcpy(original,data,sizeof data);
    struct sep_bootstrap out;
    CHECK(sep_bootstrap_parse(&reader,sizeof data,&out)==SEP_BOOTSTRAP_OK);
    CHECK(out.panic_offset==0x4000 && out.panic_size==0x8000);
    CHECK(out.flags_offset==0xc000 && out.scot_offset==0x10000);
    CHECK(!memcmp(data,original,sizeof data));
    /* Corrupt every directory byte except none: all 64 bytes are defined. */
    for(unsigned i=0;i<64;i++) {
        memcpy(data,original,sizeof data);data[i]^=0x80;reads=0;check_reject(sizeof data);
        CHECK(data[i]==(uint8_t)(original[i]^0x80));
    }
    const unsigned starts[]={0x4000,0xc000,0x10000},sizes[]={4,36,36};
    for(unsigned item=0;item<3;item++)for(unsigned i=0;i<sizes[item];i++) {
        memcpy(data,original,sizeof data);data[starts[item]+i]^=1;reads=0;check_reject(sizeof data);
    }
    memcpy(data,original,sizeof data);
    for(unsigned n=1;n<=4;n++){reads=0;fail=n;check_reject(sizeof data);}fail=0;
    const uint64_t invalid[]={0,0x10000,0x14001,0x18000,0x100000,UINT64_MAX};
    for(unsigned i=0;i<sizeof invalid/sizeof *invalid;i++)check_reject(invalid[i]);
    /* A directory is a map, not an ordering requirement. */
    memcpy(data,original,sizeof data);memcpy(data,original+32,16);memcpy(data+32,original,16);
    CHECK(sep_bootstrap_parse(&reader,sizeof data,&out)==SEP_BOOTSTRAP_OK);
    CHECK(out.panic_offset==0x4000 && out.scot_offset==0x10000);
    printf("PASS: %u shared bootstrap capture, corruption and failure checks\n",checks);
    return 0;
}
