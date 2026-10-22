/* SPDX-License-Identifier: MIT */
#include "pauth-user.h"

void pauth_user_init(struct pauth_user_state *s)
{
    if(!s)return;
    for(unsigned i=0;i<sizeof(*s)/sizeof(uint64_t);i++)((uint64_t *)s)[i]=0;
    const uint64_t base=0xfeedfacefeedfacfUL;
    s->key[PAUTH_IB]=(struct pauth_key_pair){base,base+1};
    s->key[PAUTH_DB]=(struct pauth_key_pair){base+2,base+3};
    s->extra=(struct pauth_key_pair){base+4,base+5};
    s->key[PAUTH_IA]=(struct pauth_key_pair){base+6,base+7};
    s->key[PAUTH_DA]=(struct pauth_key_pair){base+8,base+9};
    s->key[PAUTH_GA]=(struct pauth_key_pair){base+10,base+11};
    /* Apple mode and user EXTRAKEY selection; kernel override and the
     * force-enable-user bit are clear in the pinned bootstrap sequence. */
    s->apctl=0x11;
}

int pauth_user_reg(struct pauth_user_state *s,uint64_t reg,int read,uint64_t *value)
{
    if(!s || !value || (read!=0 && read!=1))return 0;
    uint64_t *slot=0;unsigned index=0;
    for(unsigned key=0;key<PAUTH_KEYS && !slot;key++) {
        unsigned crm=key<2 ? 1 : key<4 ? 2 : 3;
        unsigned op2=key<4 ? (key&1)*2 : 0;
        for(unsigned half=0;half<2;half++) {
            if(reg==PAUTH_SYSREG(3,0,2,crm,op2+half)) {
                slot=half ? &s->key[key].hi : &s->key[key].lo;
                index=key*2+half;break;
            }
        }
    }
    if(reg==PAUTH_SYSREG(3,4,15,1,0)) {slot=&s->extra.lo;index=10;}
    if(reg==PAUTH_SYSREG(3,4,15,1,1)) {slot=&s->extra.hi;index=11;}
    if(reg==PAUTH_SYSREG(3,4,15,0,4)) {slot=&s->apctl;index=12;}
    if(!slot)return 0;
    if(read) {*value=*slot;s->reads++;}
    else {
        *slot=*value;s->writes++;s->written_mask|=1UL<<index;
        if(index==10 || index==11)s->extra_writes++;
    }
    s->last_reg=reg;s->last_read=(unsigned)read;
    return 1;
}
