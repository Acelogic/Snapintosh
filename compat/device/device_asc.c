/* SPDX-License-Identifier: MIT */
/* I2C status bits, the SEP ASC mailbox, SEP ROM bootstrap steps and paired writes.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */

#define I2C_NACK (1U<<21)
#define I2C_ENDED (1U<<27)
#define I2C_FLAGS (I2C_NACK|I2C_ENDED)
#define I2C_CONTROL 0x07ff0fffU

static int sep_asc_valid(const struct device_sep_asc *s, unsigned transport)
{
    if (!s || s->ready!=1 || s->enable[0]>1 || s->enable[1]>1 ||
        s->count>DEVICE_SEP_ASC_MESSAGES || s->staged_valid>1 ||
        s->submitted<s->consumed || s->submitted-s->consumed!=s->count ||
        s->reply_count>DEVICE_SEP_ASC_MESSAGES || s->published<s->delivered ||
        s->published-s->delivered!=s->reply_count ||
        (!transport && (s->consumed || s->published || s->delivered || s->reply_count)) ||
        (!s->staged_valid && s->staged) ||
        (s->staged_valid && s->count==DEVICE_SEP_ASC_MESSAGES)) return 0;
    for (unsigned i=s->count;i<DEVICE_SEP_ASC_MESSAGES;i++)
        if (s->request[i][0] || s->request[i][1]) return 0;
    for (unsigned i=s->reply_count;i<DEVICE_SEP_ASC_MESSAGES;i++)
        if (s->reply[i][0] || s->reply[i][1]) return 0;
    return 1;
}

static uint32_t sep_asc_control(const struct device_sep_asc *s, unsigned side)
{
    unsigned count=side ? s->reply_count : s->count;
    uint64_t producer=side ? s->published : s->submitted;
    uint64_t consumer=side ? s->delivered : s->consumed;
    return s->enable[side] | (count ? 0 : 1U<<17) |
        (count==DEVICE_SEP_ASC_MESSAGES ? 1U<<16 : 0) |
        (count<<20) | ((producer%DEVICE_SEP_ASC_MESSAGES)<<8) |
        ((consumer%DEVICE_SEP_ASC_MESSAGES)<<12);
}

static enum device_result sep_asc_submit(struct device_sep_asc *s,
                                        const uint64_t values[2])
{
    if (!s->enable[0] || s->count==DEVICE_SEP_ASC_MESSAGES || s->submitted==UINT64_MAX)
        return DEVICE_BAD_VALUE;
    uint64_t first=values[0],second=values[1];
    s->request[s->count][0]=first;
    s->request[s->count][1]=second;
    s->count++;s->submitted++;
    s->staged=0;s->staged_valid=0;
    return DEVICE_OK;
}

static void sep_asc_pop(uint64_t queue[DEVICE_SEP_ASC_MESSAGES][2], uint32_t *count,
                        uint64_t values[2])
{
    uint64_t first=queue[0][0],second=queue[0][1];
    for (unsigned i=1;i<*count;i++) {
        queue[i-1][0]=queue[i][0];queue[i-1][1]=queue[i][1];
    }
    --*count;
    queue[*count][0]=0;queue[*count][1]=0;
    values[0]=first;values[1]=second;
}

static enum device_result sep_asc_receive(struct device_sep_asc *s, uint64_t values[2])
{
    if (!s->enable[1] || !s->reply_count) return DEVICE_BAD_VALUE;
    sep_asc_pop(s->reply,&s->reply_count,values);
    s->delivered++;
    return DEVICE_OK;
}

enum device_result device_sep_asc_take_request(const struct device_model *model,
    struct device_state *state, uint64_t values[2])
{
    if (!valid(model) || !state || !values || model->kind!=DEVICE_SEP_ASC_MAILBOX_V1 ||
        !model->config[1] || model->config[4] || !sep_asc_valid(&state->sep_asc,1)) return DEVICE_BAD_CONFIG;
    if (!state->sep_asc.count) return DEVICE_BAD_VALUE;
    sep_asc_pop(state->sep_asc.request,&state->sep_asc.count,values);
    state->sep_asc.consumed++;
    return DEVICE_OK;
}

enum device_result device_sep_asc_reply(const struct device_model *model,
    struct device_state *state, const uint64_t values[2])
{
    if (!valid(model) || !state || !values || model->kind!=DEVICE_SEP_ASC_MAILBOX_V1 ||
        !model->config[1] || model->config[4] || !sep_asc_valid(&state->sep_asc,1)) return DEVICE_BAD_CONFIG;
    struct device_sep_asc *s=&state->sep_asc;
    if (s->reply_count==DEVICE_SEP_ASC_MESSAGES || s->published==UINT64_MAX)
        return DEVICE_BAD_VALUE;
    uint64_t first=values[0],second=values[1];
    s->reply[s->reply_count][0]=first;s->reply[s->reply_count][1]=second;
    s->reply_count++;s->published++;
    return DEVICE_OK;
}

static int sep_bootstrap_layout(const struct sep_bootstrap *b)
{
    return b->panic_offset==0x4000 && b->panic_size==0x8000 &&
        b->flags_offset==0xc000 && b->scot_offset==0x10000 &&
        !(b->flags[0]|b->flags[1]|b->flags[2]|b->flags[3]);
}
enum device_result device_sep_rom_step(const struct device_model *model,
    struct device_state *state,const struct device_sep_rom_resources *resources)
{
    if(!valid(model) || !state || model->kind!=DEVICE_SEP_ASC_MAILBOX_V1 ||
       !(model->config[4]&1) || !sep_asc_valid(&state->sep_asc,1))return DEVICE_BAD_CONFIG;
    struct device_sep_asc *s=&state->sep_asc;
    uint64_t stage=s->rom_stage,extra=(stage>0)+(stage>1)+(stage>2);
    unsigned initialized=!!(model->config[4]&2) && stage==3;
    unsigned pnon_ready=initialized && !!(model->config[4]&(4|16));
    unsigned xars_ready=initialized && !!(model->config[4]&8);
    unsigned sks_ready=initialized && !!(model->config[4]&32);
    unsigned effective_status_ready=pnon_ready || xars_ready || sks_ready;
    if(!sep_pnon_valid(&s->pnon) || s->pnon.ready!=pnon_ready)return DEVICE_BAD_CONFIG;
    if((model->config[4]&16) && s->pnon.last_reply==SEP_PNON_REPLY)return DEVICE_BAD_CONFIG;
    if(!sep_xars_valid(&s->xars) || s->xars.ready!=xars_ready)return DEVICE_BAD_CONFIG;
    if(!sep_sks_endpoint_valid(&s->sks) || s->sks.ready!=sks_ready)return DEVICE_BAD_CONFIG;
    uint64_t service=s->pnon.negotiations;
    if(service>UINT64_MAX-s->pnon.queries)return DEVICE_BAD_CONFIG;
    service+=s->pnon.queries;
    if(service>UINT64_MAX-s->xars.negotiations)return DEVICE_BAD_CONFIG;
    service+=s->xars.negotiations;
    if(service>UINT64_MAX-s->xars.queries)return DEVICE_BAD_CONFIG;
    service+=s->xars.queries;
    if(service>UINT64_MAX-s->sks.negotiations)return DEVICE_BAD_CONFIG;
    service+=s->sks.negotiations;
    if(service>UINT64_MAX-s->sks.queries)return DEVICE_BAD_CONFIG;
    service+=s->sks.queries;
    uint64_t status_queries=s->status_queries;
    if((!effective_status_ready && (status_queries || s->status_last_request)) ||
       (!status_queries && s->status_last_request) ||
       (status_queries && ((s->status_last_request&~0xff00UL)!=0x140000 ||
                           !(s->status_last_request&0xff00))) ||
       service>UINT64_MAX-status_queries)return DEVICE_BAD_CONFIG;
    service+=status_queries;
    uint64_t advertisements=s->pnon.advertisements+s->xars.advertisements+s->sks.advertisements;
    uint64_t entropy=s->entropy_words;
    if((!initialized && (entropy || s->entropy_last_request)) ||
       (!entropy && s->entropy_last_request) ||
       (entropy && ((s->entropy_last_request&~0xff00UL)!=0x360000 ||
                    !(s->entropy_last_request&0xff00))))return DEVICE_BAD_CONFIG;
    if(s->service_ready!=initialized || s->service_notifications!=initialized)
        return DEVICE_BAD_CONFIG;
    if(initialized) {
        if(s->rom_shared_size!=0x14000 || !sep_bootstrap_layout(&s->bootstrap))return DEVICE_BAD_CONFIG;
    } else {
        const struct sep_bootstrap *b=&s->bootstrap;
        if(b->panic_offset|b->panic_size|b->flags_offset|b->scot_offset|
           b->flags[0]|b->flags[1]|b->flags[2]|b->flags[3])return DEVICE_BAD_CONFIG;
    }
    if(stage>3 || s->rom_status_replies>UINT64_MAX-extra ||
       entropy>UINT64_MAX-s->rom_status_replies-extra ||
       service>UINT64_MAX-s->rom_status_replies-extra-entropy ||
       advertisements>UINT64_MAX-s->rom_status_replies-extra-entropy-service ||
       s->consumed!=s->rom_status_replies+extra+entropy+service ||
       s->published!=s->rom_status_replies+(stage>0)+(stage>1)+initialized+entropy+service+advertisements ||
       (stage && !s->rom_status_replies) || (stage>=2 && s->rom_status_replies<2) ||
       (!s->consumed && (s->rom_last_request || s->rom_last_reply)) ||
       (stage<2 && (s->rom_firmware_iova || s->rom_firmware_size)) ||
       (stage>=2 && (!s->rom_firmware_iova || !s->rom_firmware_size ||
        ((s->rom_firmware_iova|s->rom_firmware_size)&0x3fff) ||
        s->rom_firmware_size>0x1000000 || s->rom_firmware_iova>UINT64_MAX-s->rom_firmware_size)) ||
       (stage<3 && (s->rom_shared_iova || s->rom_shared_size)) ||
       (stage==3 && (!s->rom_shared_iova || !s->rom_shared_size ||
        ((s->rom_shared_iova|s->rom_shared_size)&0x3fff) || s->rom_shared_size>0x100000 ||
        s->rom_shared_iova>UINT64_MAX-s->rom_shared_size ||
        (s->rom_shared_iova<s->rom_firmware_iova+s->rom_firmware_size &&
         s->rom_shared_iova+s->rom_shared_size>s->rom_firmware_iova))))
        return DEVICE_BAD_CONFIG;
    if(s->consumed) {
        uint64_t prior=s->rom_last_request,tag=prior&0xff00,expected;
        if((prior&~0xff00UL)==0x200ff && stage<=1)
            expected=((stage ? 2UL : 1UL)<<32)|0x6600ff|tag;
        else if((prior&~0xff00UL)==0x500ff && stage==1)expected=0x6900ff|tag;
        else if((prior&0xffff00ffUL)==0x200600ff && stage==2 &&
                (prior>>32)<<12==s->rom_firmware_iova)expected=0x6a00ff|tag;
        else if((prior&255)==254 && stage==3 && (prior>>32)<<12==s->rom_shared_iova &&
                ((prior>>16)&65535)<<12==s->rom_shared_size)expected=0;
        else return DEVICE_BAD_CONFIG;
        if(s->rom_last_reply!=expected)return DEVICE_BAD_CONFIG;
    }
    if(!s->count)return DEVICE_OK;
    uint64_t request=s->request[0][0];
    if(s->request[0][1])return DEVICE_UNKNOWN_REGISTER;
    if((request&~0xff00UL)==0x360000) {
        if(!initialized || !(request&0xff00))return DEVICE_BAD_VALUE;
        if(!resources || !resources->entropy32)return DEVICE_BAD_CONFIG;
        if(s->reply_count==DEVICE_SEP_ASC_MESSAGES || s->published==UINT64_MAX ||
           s->consumed==UINT64_MAX || entropy==UINT64_MAX)return DEVICE_BAD_VALUE;
        uint32_t word=0;
        if(!resources->entropy32(resources->ctx,&word)) {
            aes_clear(&word,sizeof(word));return DEVICE_BAD_VALUE;
        }
        /* Only this queued reply contains DATA; popping it clears its slot.
         * Preserve ROM handoff history separately, without a random trace. */
        s->reply[s->reply_count][0]=((uint64_t)word<<32)|request;
        s->reply[s->reply_count][1]=0;s->reply_count++;s->published++;
        aes_clear(&word,sizeof(word));
        uint64_t removed[2];sep_asc_pop(s->request,&s->count,removed);s->consumed++;
        s->entropy_words++;s->entropy_last_request=request;
        return DEVICE_OK;
    }
    if(effective_status_ready && (request&~0xff00UL)==0x140000) {
        if(!(request&0xff00) || s->reply_count==DEVICE_SEP_ASC_MESSAGES ||
           s->published==UINT64_MAX || s->consumed==UINT64_MAX ||
           status_queries==UINT64_MAX)return DEVICE_BAD_VALUE;
        /* Native cmsg status getter consumes DATA's low byte: bit0 is
         * production, bit1 secure execution. This selected virtual platform
         * implements neither. This is a policy result, not an opcode ACK or
         * an assertion about the admitted (unexecuted) RELEASE firmware. */
        uint64_t removed[2];sep_asc_pop(s->request,&s->count,removed);s->consumed++;
        s->reply[s->reply_count][0]=(DEVICE_SEP_EFFECTIVE_STATUS<<32)|request;
        s->reply[s->reply_count][1]=0;s->reply_count++;s->published++;
        s->status_queries++;s->status_last_request=request;return DEVICE_OK;
    }
    if(pnon_ready || xars_ready || sks_ready) {
        if(s->reply_count==DEVICE_SEP_ASC_MESSAGES || s->published==UINT64_MAX ||
           s->consumed==UINT64_MAX)return DEVICE_BAD_VALUE;
        uint64_t reply;
        if(sks_ready && ((request&255)==SEP_SKS_ENDPOINT ||
           (request&0xff0000ffUL)==((uint64_t)SEP_SKS_ENDPOINT<<24))) {
            enum sep_sks_endpoint_result result=sep_sks_endpoint_step(&s->sks,
                resources ? resources->sks : 0,request,&reply);
            if(result!=SEP_SKS_ENDPOINT_OK)return result==SEP_SKS_ENDPOINT_UNKNOWN ? DEVICE_UNKNOWN_REGISTER : DEVICE_BAD_VALUE;
        } else if(xars_ready && ((request&255)==SEP_XARS_ENDPOINT ||
           (request&0xff0000ffUL)==((uint64_t)SEP_XARS_ENDPOINT<<24))) {
            enum sep_xars_result result=sep_xars_step(&s->xars,resources ? resources->xars : 0,request,&reply);
            if(result!=SEP_XARS_OK)return result==SEP_XARS_UNKNOWN ? DEVICE_UNKNOWN_REGISTER : DEVICE_BAD_VALUE;
        } else if(pnon_ready) {
            enum sep_pnon_result result=sep_pnon_step(&s->pnon,resources ? resources->pnon : 0,request,&reply);
            if(result!=SEP_PNON_OK)return result==SEP_PNON_UNKNOWN ? DEVICE_UNKNOWN_REGISTER : DEVICE_BAD_VALUE;
        } else return DEVICE_UNKNOWN_REGISTER;
        uint64_t removed[2];sep_asc_pop(s->request,&s->count,removed);s->consumed++;
        s->reply[s->reply_count][0]=reply;s->reply[s->reply_count][1]=0;
        s->reply_count++;s->published++;return DEVICE_OK;
    }
    uint64_t tag=request&0xff00,response=0,next=stage,iova=0,size=0;
    unsigned status=0,buffer=0,notify=0;
    struct sep_bootstrap bootstrap={0};
    if((request&~0xff00UL)==0x200ff) {
        if(stage>1)return DEVICE_BAD_VALUE;
        response=((stage ? 2UL : 1UL)<<32)|0x6600ff|tag;status=1;
    } else if((request&~0xff00UL)==0x500ff) {
        if(stage || !s->rom_status_replies || s->reply_count)return DEVICE_BAD_VALUE;
        /* Initialize this virtual bootstrap instance exactly once. The next
         * status now reports phase2; no native TZ0 code has been executed. */
        next=1;response=0x6900ff|tag;
    } else if((request&0xffff00ffUL)==0x200600ff) {
        /* Pinned J700 native wire: payload type 0, selected slot 2. The
         * original client packs slot<<4 in PARAM; other slots stay refused. */
        if(stage!=1 || s->rom_status_replies<2 || s->reply_count ||
           (s->rom_last_request&~0xff00UL)!=0x200ff)return DEVICE_BAD_VALUE;
        if(!resources || !resources->admit || !resources->firmware_size ||
           resources->firmware_size>0x1000000 || (resources->firmware_size&0x3fff))
            return DEVICE_BAD_CONFIG;
        iova=(request>>32)<<12;size=resources->firmware_size;
        buffer=1;next=2;response=0x6a00ff|tag;
    } else if((request&255)==254) {
        if(stage!=2 || s->reply_count>1)return DEVICE_BAD_VALUE;
        if(s->reply_count && (s->reply[0][0]!=s->rom_last_reply || s->reply[0][1]))
            return DEVICE_BAD_CONFIG;
        notify=!!(model->config[4]&2);
        if(!resources || (notify ? !resources->bootstrap : !resources->admit))return DEVICE_BAD_CONFIG;
        iova=(request>>32)<<12;size=((request>>16)&65535)<<12;
        if(!size || size>0x100000 || (size&0x3fff))return DEVICE_BAD_VALUE;
        buffer=2;next=3; /* The measured shared-buffer handoff has no reply. */
    } else return DEVICE_UNKNOWN_REGISTER;
    unsigned publications=response ? 1 : notify ? 1+2*!!(model->config[4]&(4|16))+
        2*!!(model->config[4]&8)+2*!!(model->config[4]&32) : 0;
    if(s->reply_count>DEVICE_SEP_ASC_MESSAGES-publications || s->published>UINT64_MAX-publications ||
       s->consumed==UINT64_MAX || (status && s->rom_status_replies==UINT64_MAX))
        return DEVICE_BAD_VALUE;
    if(buffer && (!iova || (iova&0x3fff) || iova>UINT64_MAX-size))return DEVICE_BAD_VALUE;
    if(buffer==2 && iova<s->rom_firmware_iova+s->rom_firmware_size &&
       iova+size>s->rom_firmware_iova)return DEVICE_BAD_VALUE;
    if(notify) {
        if(size!=0x14000 || !resources->bootstrap(resources->ctx,iova,size,&bootstrap) ||
           !sep_bootstrap_layout(&bootstrap))return DEVICE_BAD_VALUE;
    } else if(buffer && !resources->admit(resources->ctx,buffer-1,iova,size))return DEVICE_BAD_VALUE;
    /* No fallible operations after the complete buffer/response preflight. */
    uint64_t removed[2];
    sep_asc_pop(s->request,&s->count,removed);s->consumed++;
    if(response) {
        s->reply[s->reply_count][0]=response;s->reply[s->reply_count][1]=0;
        s->reply_count++;s->published++;
    }
    if(status)s->rom_status_replies++;
    if(buffer==1){s->rom_firmware_iova=iova;s->rom_firmware_size=size;}
    if(buffer==2){s->rom_shared_iova=iova;s->rom_shared_size=size;}
    if(notify) {
        s->bootstrap=bootstrap;s->service_ready=1;s->service_notifications=1;
        s->reply[s->reply_count][0]=0xd0000;s->reply[s->reply_count][1]=0;
        s->reply_count++;s->published++;
        if(model->config[4]&(4|16)) {
            s->pnon.ready=1;s->pnon.advertisements=2;
            s->reply[s->reply_count][0]=SEP_PNON_AD_NAME;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
            s->reply[s->reply_count][0]=SEP_PNON_AD_OOL;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
        }
        if(model->config[4]&8) {
            s->xars.ready=1;s->xars.advertisements=2;
            s->reply[s->reply_count][0]=SEP_XARS_AD_NAME;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
            s->reply[s->reply_count][0]=SEP_XARS_AD_OOL;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
        }
        if(model->config[4]&32) {
            s->sks.ready=1;s->sks.advertisements=2;
            s->reply[s->reply_count][0]=SEP_SKS_AD_NAME;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
            s->reply[s->reply_count][0]=SEP_SKS_AD_OOL;s->reply[s->reply_count][1]=0;
            s->reply_count++;s->published++;
        }
    }
    s->rom_stage=next;
    s->rom_last_request=request;s->rom_last_reply=response;
    return DEVICE_OK;
}

enum device_result device_model_write_pair(const struct device_model *model,
    struct device_state *state, uint64_t offset, const uint64_t values[2])
{
    if (!valid(model) || !state || !values) return DEVICE_BAD_CONFIG;
    if (model->kind!=DEVICE_SEP_ASC_MAILBOX_V1) return DEVICE_BAD_WIDTH;
    if (!sep_asc_valid(&state->sep_asc,(unsigned)model->config[1])) return DEVICE_BAD_CONFIG;
    if (offset>=model->span || model->span-offset<16) return DEVICE_NOT_FOUND;
    if (offset&7) return DEVICE_BAD_WIDTH;
    if (offset!=0x8800) return DEVICE_UNKNOWN_REGISTER;
    /* A previously staged scalar write belongs to a different transaction. */
    if (state->sep_asc.staged_valid) return DEVICE_BAD_VALUE;
    return sep_asc_submit(&state->sep_asc,values);
}

static enum device_result sep_asc_access(struct device_sep_asc *s,
    uint64_t offset, unsigned width, int write, uint64_t *value, unsigned transport)
{
    if (!sep_asc_valid(s,transport)) return DEVICE_BAD_CONFIG;
    if (offset==0x8110 || offset==0x8114) {
        if (width!=4) return DEVICE_BAD_WIDTH;
        unsigned side=(unsigned)(offset-0x8110)/4;
        if (write) {
            /* Counter/pointer/empty/full fields are read-only. Permit their
             * read-modify-write image without changing queue ownership. */
            if (*value&~0x00f3ff01UL) return DEVICE_BAD_VALUE;
            s->enable[side]=(uint32_t)*value&1;
            if (s->writes[side]!=UINT64_MAX) s->writes[side]++;
        } else {
            *value=sep_asc_control(s,side);
            if (s->reads[side]!=UINT64_MAX) s->reads[side]++;
        }
        return DEVICE_OK;
    }
    if (offset==0x8800 || offset==0x8808) {
        if (width!=8) return DEVICE_BAD_WIDTH;
        if (!write || !s->enable[0] || s->count==DEVICE_SEP_ASC_MESSAGES ||
            s->submitted==UINT64_MAX)
            return DEVICE_BAD_VALUE;
        if (offset==0x8800) {
            if (s->staged_valid) return DEVICE_BAD_VALUE;
            s->staged=*value;s->staged_valid=1;
            return DEVICE_OK;
        }
        if (!s->staged_valid) return DEVICE_BAD_VALUE;
        uint64_t values[2]={s->staged,*value};
        return sep_asc_submit(s,values);
    }
    if (offset==0x8830 || offset==0x8838) {
        if (width!=8) return DEVICE_BAD_WIDTH;
        /* The measured native consumer is one LDP X/X at 8830. Scalar
         * consumption has not been qualified; never split a reply here. */
        return write ? DEVICE_READ_ONLY : DEVICE_BAD_VALUE;
    }
    return DEVICE_UNKNOWN_REGISTER;
}

