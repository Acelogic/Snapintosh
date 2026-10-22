/* SPDX-License-Identifier: MIT */
#include "sep-bootstrap.h"

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
enum sep_bootstrap_result sep_bootstrap_parse(const struct sep_bootstrap_reader *r,
    uint64_t size,struct sep_bootstrap *out)
{
    if(!r || !r->read || !out || size!=0x14000)return SEP_BOOTSTRAP_BAD_SIZE;
    uint8_t directory[64],data[36];
    if(!r->read(r->ctx,0,sizeof directory,directory))return SEP_BOOTSTRAP_READ_FAILED;
    const uint32_t names[3]={0x504e4943,0x464c4147,0x53434f54};
    const uint32_t lengths[3]={0x8000,0x4000,0x4000};
    uint32_t offsets[3]={0,0,0};
    if(u32(directory+48)!=0x6e756c6c || u32(directory+52) ||
       u32(directory+56) || u32(directory+60))return SEP_BOOTSTRAP_BAD_DIRECTORY;
    for(unsigned i=0;i<3;i++) {
        const uint8_t *entry=directory+16*i;
        uint32_t name=u32(entry),length=u32(entry+4),offset=u32(entry+8);
        unsigned kind=0;while(kind<3 && names[kind]!=name)kind++;
        if(kind==3 || offsets[kind] || u32(entry+12) || length!=lengths[kind] ||
           offset<0x4000 || (offset&0x3fff) || offset>size-length)
            return SEP_BOOTSTRAP_BAD_DIRECTORY;
        for(unsigned j=0;j<3;j++)if(offsets[j] &&
            offset<offsets[j]+lengths[j] && offsets[j]<offset+length)
            return SEP_BOOTSTRAP_BAD_DIRECTORY;
        offsets[kind]=offset;
    }
    if(!r->read(r->ctx,offsets[0],4,data))return SEP_BOOTSTRAP_READ_FAILED;
    if(u32(data)!=1)return SEP_BOOTSTRAP_BAD_CONTENT;
    if(!r->read(r->ctx,offsets[1],sizeof data,data))return SEP_BOOTSTRAP_READ_FAILED;
    if(u32(data)!=32)return SEP_BOOTSTRAP_BAD_CONTENT;
    const uint32_t flags[4]={0x78415254,0x5345504f,0x66697073,0x53455044};
    for(unsigned i=0;i<4;i++)if(u32(data+4+i*8)!=flags[i] || u32(data+8+i*8))
        return SEP_BOOTSTRAP_BAD_CONTENT;
    if(!r->read(r->ctx,offsets[2],sizeof data,data))return SEP_BOOTSTRAP_READ_FAILED;
    if(u32(data)!=32)return SEP_BOOTSTRAP_BAD_CONTENT;
    const char scot[32]="This is my wonderful test data!";
    for(unsigned i=0;i<32;i++)if(data[i+4]!=(uint8_t)scot[i])return SEP_BOOTSTRAP_BAD_CONTENT;
    /* All reads and policy checks precede publication of the parsed result. */
    out->panic_offset=offsets[0];out->panic_size=lengths[0];
    out->flags_offset=offsets[1];out->scot_offset=offsets[2];
    for(unsigned i=0;i<4;i++)out->flags[i]=0;
    return SEP_BOOTSTRAP_OK;
}
