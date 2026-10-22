/* SPDX-License-Identifier: MIT */
#define main sep_dart_checks
#include "test-sptm-dart-sep.c"
#undef main
#define VA 0x10000004000UL
#define SH_VA (VA+0x200000)
static struct sptm_memory ready(void)
{
    struct sptm_memory m=reset(0);
    m.sep_firmware_pa=FIRMWARE;m.sep_firmware_size=FIRMWARE_SIZE;
    for(unsigned i=0;i<65;i++){meta(FIRMWARE+i*0x4000)[2]=11;put(LIST+8*i,FIRMWARE+i*0x4000);}
    attach(&m,0,VA);CHECK(sptm_dart_map(&m,&state,20,0,VA,LIST,FIRMWARE_SIZE,0)==SPTM_OK);
    for(unsigned i=0;i<3;i++){meta(DATA+i*0x4000)[2]=11;put(LIST+8*i,DATA+i*0x4000);}
    CHECK(sptm_dart_map(&m,&state,20,0,SH_VA,LIST,0xc000,0)==SPTM_OK);
    CHECK(sptm_dart_enable(&m,&state,20,0)==SPTM_OK);return m;
}
int main(void)
{
    struct sptm_memory m=ready();snapshot();
    CHECK(sptm_sep_rom_buffer(&m,&state,0,VA,FIRMWARE_SIZE)==SPTM_OK);
    CHECK(state.translations==65 && !memcmp(ram,saved,SIZE) && !pubs);
    CHECK(sptm_sep_rom_buffer(&m,&state,1,SH_VA,0xc000)==SPTM_OK);
    CHECK(state.translations==71 && !memcmp(ram,saved,SIZE) && !pubs);
    for(unsigned test=0;test<12;test++) {
        m=ready();unsigned kind=test<6 ? 0 : 1;uint64_t va=kind ? SH_VA : VA,size=kind ? 0xc000 : FIRMWARE_SIZE;
        uint64_t slot=LEAF+8*(((va+size-0x4000)>>14)&2047);
        if(test==0)size-=0x4000;
        if(test==1)va+=0x1000;
        if(test==2)put(slot,0);
        if(test==3)meta(FIRMWARE+FIRMWARE_SIZE-0x4000)[12]=0;
        if(test==4)put(slot,(get(slot)&~0xfffffffc00UL)|(DATA>>4));
        if(test==5)state.translations=UINT64_MAX-64;
        if(test==6)put(slot,0);
        if(test==7)put(slot,get(slot)|4);
        if(test==8)put(slot,(get(slot)&~0xfffffffc00UL)|(DATA>>4));
        if(test==9){va=VA;size=0x4000;}
        if(test==10)size=0x104000;
        if(test==11)kind=2;
        snapshot();CHECK(sptm_sep_rom_buffer(&m,&state,kind,va,size)!=SPTM_OK);unchanged();
    }
    printf("PASS: %u whole SEP boot-buffer admission checks\n",checks);return 0;
}
