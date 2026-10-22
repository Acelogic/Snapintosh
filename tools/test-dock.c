/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include "device.h"

int main(void)
{
    unsigned checks=0;
    struct device_model d={DEVICE_DOCK_ABSENT_V1,0x3082d8000,0x1000,{8,1U<<22,0,0,0}};
    for (unsigned off=0; off<0x1000; off+=4) {
        uint64_t value=0xdeadbeef;
        enum device_result result=device_model_access_state(&d,0,off,4,0,&value);
        assert(result == (off==8 ? DEVICE_OK : DEVICE_UNKNOWN_REGISTER)); checks++;
        assert(value == (off==8 ? 0 : 0xdeadbeef)); checks++;
        value=1U<<22;
        result=device_model_access_state(&d,0,off,4,1,&value);
        assert(result == (off==8 ? DEVICE_READ_ONLY : DEVICE_UNKNOWN_REGISTER)); checks++;
        assert(value == 1U<<22); checks++;
    }
    for (unsigned width=1; width<=8; width*=2) if (width!=4) {
        uint64_t v=123;
        assert(device_model_access_state(&d,0,8,width,0,&v)==DEVICE_BAD_WIDTH);
        assert(v==123); checks+=2;
    }
    for (unsigned i=0; i<7; i++) {
        struct device_model bad=d;
        if (i==0) bad.config[0]=0x1000;
        if (i==1) bad.config[0]=1;
        if (i==2) bad.config[1]=0;
        if (i==3) bad.config[1]=3;
        if (i==4) bad.config[1]=1UL<<32;
        if (i==5) bad.config[2]=1;
        if (i==6) bad.span=0x2000;
        uint64_t v=123;
        assert(device_model_access_state(&bad,0,8,4,0,&v)==DEVICE_BAD_CONFIG);
        assert(v==123); checks+=2;
    }
    d.base=0x100000; d.config[0]=0xffc; d.config[1]=1U<<31;
    uint64_t value=1;
    assert(device_model_access_state(&d,0,0xffc,4,0,&value)==DEVICE_OK && value==0);
    assert(device_model_access_state(&d,0,0x1000,4,0,&value)==DEVICE_NOT_FOUND);
    checks+=2;
    printf("PASS: %u dock status/refusal checks\n",checks);
    return 0;
}
