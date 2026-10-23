/* SPDX-License-Identifier: MIT */
/* Power-gated model access and the SoC/ACC performance-counter restore models.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
enum device_result device_models_access_power_at(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value,
    const struct device_power_resources *resources)
{
    if (!models || !states || !value || !count || count>DEVICE_MODEL_MAX || index>=count)
        return DEVICE_BAD_CONFIG;
    const struct device_model *m=&models[index];
    if (m->kind==DEVICE_I2C_EMPTY_V1) {
        unsigned found=0;
        for (unsigned i=0;i<count;i++)
            if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !models[i].config[0]) {
                if (found++ || !valid(&models[i]) || models[i].base!=0x300700000)
                    return DEVICE_BAD_CONFIG;
                if ((states[i].pmgr_i2c[2]&15)!=15) return DEVICE_BAD_VALUE;
            }
        if (!found) return DEVICE_BAD_CONFIG;
    }
    if (m->kind==DEVICE_DWI_STARTUP_V1) {
        /* DT gate 13 is DWI, PMGR group0 +118, a fixed-active root in
         * this profile. Require its registered owner before serving MMIO. */
        unsigned found=0;
        for (unsigned i=0;i<count;i++)
            if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !models[i].config[0]) {
                uint64_t level=0;
                if (found++ || models[i].base!=0x300700000 ||
                    device_model_access_state(&models[i],&states[i],0x118,4,0,&level)!=DEVICE_OK)
                    return DEVICE_BAD_CONFIG;
                if ((level&0xff)!=0xff) return DEVICE_BAD_VALUE;
            }
        if (!found) return DEVICE_BAD_CONFIG;
    }
    if (m->kind==DEVICE_QSPI_BOOT_V1) {
        /* The QSPI leaf is clock-gated by the registered PMGR bank. This
         * idle-only backend has no in-flight transaction to retain on gate
         * changes, but no controller MMIO is accepted while clocks are off. */
        unsigned found=0;
        for (unsigned i=0;i<count;i++)
            if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !models[i].config[0]) {
                if (found++ || !valid(&models[i]) || models[i].base!=0x300700000)
                    return DEVICE_BAD_CONFIG;
                if ((states[i].pmgr_spi[4]&15)!=15) return DEVICE_BAD_VALUE;
            }
        if (!found) return DEVICE_BAD_CONFIG;
    }
    if (m->kind==DEVICE_PMGR_ACC_BOOT_POLICY_V1)
        return acc_boot_access(models,states,count,index,offset,width,write,value);
    enum device_result ave=ave_access(models,states,count,index,offset,width,write,value);
    if (ave!=DEVICE_NOT_FOUND) return ave;
    /* CPU-aware PMGR boot reads and PMP ACK derivation require the declared
     * independent cluster owner. Legacy conservative fixtures use policy 0. */
    if ((m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && m->config[1]) ||
        m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
        for (unsigned i=0;i<count;i++)
            if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && models[i].config[1] &&
                !cpu_boot_registry(models,count)) return DEVICE_BAD_CONFIG;
    }
    int cluster=m->kind==DEVICE_PMC_DVMR_CONFIG_V1 && (offset==0x5c18 || offset==0x5c1c);
    if (cluster) {
        unsigned pmgr=0,pmp=0,pmc=0,banks[2][2]={{0}};
        if (!venc_binding(models,count,&pmgr,&pmp,&pmc,banks)) return DEVICE_BAD_CONFIG;
        if (width!=4) return DEVICE_BAD_WIDTH;
        if (write && offset==0x5c1c) return DEVICE_UNKNOWN_REGISTER;
        uint32_t current=states[pmc].pmc_dvmr.venc_cluster;
        if (current!=0 && current!=8) return DEVICE_BAD_VALUE;
        for (unsigned u=0;u<2;u++)
            if (!current && (states[pmgr].pmgr_venc_sys[u]&15)) return DEVICE_BAD_VALUE;
        if (!write) { *value=current;return DEVICE_OK; }
        if (*value&~8UL) return DEVICE_BAD_VALUE;
        uint64_t actual=0;
        enum device_result r=pmp_actual_states(&models[pmgr],&states[pmgr],&actual);
        if (r!=DEVICE_OK) return r;
        if (actual!=states[pmp].pmp_active.ack) return DEVICE_BAD_VALUE;
        if (!*value) {
            if (states[pmp].pmp_active.request&(DEVICE_PMP_VENC0_BIT|DEVICE_PMP_VENC1_BIT))
                return DEVICE_BAD_VALUE;
            for (unsigned u=0;u<2;u++) {
                if (states[pmgr].pmgr_venc_sys[u]&15) return DEVICE_BAD_VALUE;
                for (unsigned c=u*5;c<u*5+5;c++)
                    if (states[pmgr].pmgr_venc[c]&15) return DEVICE_BAD_VALUE;
                for (unsigned bank=0;bank<2;bank++)
                    if (!dart_runtime_idle(&states[banks[u][bank]].dart,0)) return DEVICE_BAD_VALUE;
            }
        }
        /* VENC-CLSTR-V is a separate synchronous virtual PMC rail, not a
         * physical PMP row. Both children are admitted before gating it. */
        states[pmc].pmc_dvmr.venc_cluster=(uint32_t)*value;
        return DEVICE_OK;
    }
    int aes=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x308;
    if (aes && write) {
        unsigned pmgr=0,engine=0;
        if (!aes_binding(models,count,&pmgr,&engine) || index!=pmgr) return DEVICE_BAD_CONFIG;
        const struct aes_engine *a=&states[engine].aes;
        if (a->ready!=1) return DEVICE_BAD_CONFIG;
        uint32_t level=states[pmgr].pmgr_aes&~0x300U;
        if (level!=0 && level!=4 && level!=15) return DEVICE_BAD_VALUE;
        if ((*value&15)!=15 && (a->running || a->header || a->need || a->used || a->irq_status || a->irq_enable))
            return DEVICE_BAD_VALUE;
        /* Completed transfers and software keys may remain in state. No
         * asynchronous producer exists; preserve all shared SIO resources. */
        return pmgr_boot_access(m,&states[index],offset,width,write,value,PMGR_OWNED);
    }
    int atc=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] &&
        offset>=0x3e0 && offset<=0x3f0;
    int usb=m->kind==DEVICE_DART_T8110_V1 &&
        ((m->config[4]&(1UL<<22)) || m->base==0x40af00000 || m->base==0x40af80000);
    if (atc || usb) {
        unsigned pmgr=0,banks[2]={0,0};
        if (!atc_binding(models,count,&pmgr,banks)) return DEVICE_BAD_CONFIG;
        if (usb && (states[pmgr].pmgr_atc[2]&15)!=15) return DEVICE_BAD_VALUE;
        if (atc && write) {
            if (!valid(m) || width!=4 || (offset&7))
                return device_model_access_at(m,&states[index],now,offset,width,write,value);
            if ((*value&15)!=15 &&
                (!dart_runtime_idle(&states[banks[0]].dart,1U<<22) ||
                 !dart_runtime_idle(&states[banks[1]].dart,1U<<22))) return DEVICE_BAD_VALUE;
            return pmgr_boot_access(m,&states[index],offset,width,write,value,1);
        }
    }
    int sep_aon=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x60;
    int sep_dart=sep_dart_model(m);
    if (sep_aon || sep_dart) {
        unsigned pmgr=0,pmp=0,dart=0;
        if (!sep_binding(models,count,&pmgr,&pmp,&dart)) return DEVICE_BAD_CONFIG;
        /* AppleT8110DART::_powerUp validates immutable PARAMS before the
         * monitor POWERUP call. This virtual capability ROM is readable
         * with SEP_AON off. The audited SEP boot policy has no DART clock
         * gate and owns its power lifecycle separately: runtime registers
         * become accessible only after successful monitor restoration.
         * Reading it neither changes power nor grants DMA ownership. */
        int sep_runtime=m->config[1]==DEVICE_DART_SEP_BOOT_V1 ?
            states[dart].dart.powered_ids==(1U<<20) :
            (states[pmgr].pmgr_sep_aon&15)==15;
        if (sep_dart && !sep_runtime &&
            (write || width!=4 || (offset&3) || offset>=0x10)) return DEVICE_BAD_VALUE;
        if (sep_aon && write) {
            if (width!=4) return DEVICE_BAD_WIDTH;
            /* PMP ID 28 / row 27 is a virtual SEP-PEARL-V vote, not a
             * physical-domain ACK. Never consume or synthesize that claim. */
            if ((states[pmp].pmp_active.request|states[pmp].pmp_active.ack)&(1UL<<27))
                return DEVICE_BAD_VALUE;
            /* Validate every transition, including wake; corrupted runtime
             * state cannot be made usable by raising an otherwise idle rail.
             * Capability-only INIT is retained and owns no DMA resources. */
            if (!dart_runtime_idle(&states[dart].dart,1U<<20)) return DEVICE_BAD_VALUE;
            for (unsigned i=0;i<count;i++) if (models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1) {
                const struct device_sep_asc *asc=&states[i].sep_asc;
                if (!sep_asc_valid(asc,(unsigned)models[i].config[1])) return DEVICE_BAD_CONFIG;
                /* A queued or partly staged request must survive until its
                 * service owns it; a power transition cannot discard it. */
                if (asc->count || asc->staged_valid || asc->reply_count) return DEVICE_BAD_VALUE;
            }
            return pmgr_boot_access(m,&states[index],offset,width,write,value,PMGR_OWNED);
        }
    }
    int ane=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x290;
    int ane_dart=m->kind==DEVICE_DART_T8110_V1 && m->base>=0x401800000 && m->base<0x401860000;
    if (ane || ane_dart) {
        unsigned pmgr=0,pmp=0,banks[3]={0,0,0};
        if (!ane_binding(models,count,&pmgr,&pmp,banks)) return DEVICE_BAD_CONFIG;
        if (ane_dart && (states[pmgr].pmgr_ane&15)!=15) return DEVICE_BAD_VALUE;
        if (ane && write) {
            if (width!=4) return DEVICE_BAD_WIDTH;
            /* PMP ID 6 lives in soc-device row 10, a separate virtual-device
             * protocol. It is deliberately outside the physical ACK mask.
             * Refuse any such outstanding claim even if state was corrupted;
             * do not withdraw it or fabricate virtual completion. */
            if ((states[pmp].pmp_active.request|states[pmp].pmp_active.ack)&(1UL<<10))
                return DEVICE_BAD_VALUE;
            if ((*value&15)!=15)
                for (unsigned i=0;i<3;i++)
                    if (!dart_runtime_idle(&states[banks[i]].dart,
                            (uint32_t)models[banks[i]].config[4])) return DEVICE_BAD_VALUE;
            return pmgr_boot_access(m,&states[index],offset,width,write,value,1);
        }
    }
    int avd=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x270;
    int avd_dart=m->kind==DEVICE_DART_T8110_V1 &&
        (m->base==0x381020000 || (m->config[4]&(1U<<4)));
    int isp_sys=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x268;
    int isp_dart=isp_dart_model(m);
    int prores=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x250;
    int prores_dart=m->kind==DEVICE_DART_T8110_V1 &&
        (m->base==0x295020000 || (m->config[4]&(1U<<3)));
    int venc_sys=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] &&
        (offset==0x240 || offset==0x248);
    int venc_child=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] &&
        offset>=0x8000 && offset<=0x8048;
    int venc_dart=venc_dart_unit(m);
    int msr=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x238;
    int jpg=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x230;
    int gfx=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] && offset==0x1f0;
    int image_dart=image_dart_kind(m);
    enum { SYSTEMS=8 };
    const uint64_t bits[SYSTEMS]={DEVICE_PMP_AVD_BIT,DEVICE_PMP_ISP_BIT,DEVICE_PMP_PRORES_BIT,
                                 DEVICE_PMP_VENC0_BIT,DEVICE_PMP_VENC1_BIT,DEVICE_PMP_MSR_BIT,DEVICE_PMP_JPG_BIT,DEVICE_PMP_GFX_BIT};
    const unsigned offsets[SYSTEMS]={0x270,0x268,0x250,0x240,0x248,0x238,0x230,0x1f0};
    uint64_t supported=0;
    for (unsigned d=0;d<SYSTEMS;d++) supported|=bits[d];
    uint64_t changed=m->kind==DEVICE_PTD_PMP_ACTIVE_V1 && write && offset==0x10c40 ?
        (*value^states[index].pmp_active.request)&supported : 0;
    unsigned domains=((avd || avd_dart || (changed&bits[0])) ? 1u : 0u)|
        ((isp_sys || isp_dart || (changed&bits[1])) ? 2u : 0u)|
        ((prores || prores_dart || (changed&bits[2])) ? 4u : 0u)|
        ((msr || image_dart==1 || (changed&bits[5])) ? 32u : 0u)|
        ((jpg || image_dart==2 || (changed&bits[6])) ? 64u : 0u)|
        ((gfx || (changed&bits[7])) ? 128u : 0u);
    for (unsigned u=0;u<2;u++)
        if ((venc_sys && offset==offsets[u+3]) || venc_dart==(int)u || (changed&bits[u+3]))
            domains|=1u<<(u+3);
    unsigned pmgr_venc=0,pmp_venc=0,pmc=0,venc_banks[2][2]={{0}};
    if ((domains&24) || venc_child) {
        if (!venc_binding(models,count,&pmgr_venc,&pmp_venc,&pmc,venc_banks))
            return DEVICE_BAD_CONFIG;
        uint32_t cluster_state=states[pmc].pmc_dvmr.venc_cluster;
        if (cluster_state!=0 && cluster_state!=8) return DEVICE_BAD_VALUE;
        for (unsigned u=0;u<2;u++)
            if (!cluster_state && (states[pmgr_venc].pmgr_venc_sys[u]&15)) return DEVICE_BAD_VALUE;
        if (venc_dart>=0 && ((states[pmgr_venc].pmgr_venc_sys[venc_dart]&15)!=15 || !cluster_state))
            return DEVICE_BAD_VALUE;
    }
    if (domains) {
        unsigned pmgr=pmgr_venc,pmp=pmp_venc,banks[SYSTEMS][3]={{0}},counts[SYSTEMS]={1,3,1,2,2,1,2,0};
        const uint32_t initialized[SYSTEMS][3]={{1U<<4},{0},{1U<<3},{0},{0},{1U<<19},{3U<<13,1U<<15}};
        for (unsigned u=0;u<2;u++) for (unsigned b=0;b<2;b++) banks[u+3][b]=venc_banks[u][b];
        if ((domains&1) && !single_media_binding(models,count,&pmgr,&pmp,&banks[0][0],0))
            return DEVICE_BAD_CONFIG;
        if ((domains&2) && !isp_system_binding(models,count,&pmgr,&pmp,banks[1]))
            return DEVICE_BAD_CONFIG;
        if ((domains&4) && !single_media_binding(models,count,&pmgr,&pmp,&banks[2][0],1))
            return DEVICE_BAD_CONFIG;
        if ((domains&32) && !image_system_binding(models,count,&pmgr,&pmp,banks[5],0))
            return DEVICE_BAD_CONFIG;
        if ((domains&64) && !image_system_binding(models,count,&pmgr,&pmp,banks[6],1))
            return DEVICE_BAD_CONFIG;
        if (domains&128) {
            unsigned bridge=0;
            if (!gfx_binding(models,count,&pmgr,&pmp,&bridge)) return DEVICE_BAD_CONFIG;
            if ((states[bridge].pmgr_axi2af[0]|states[bridge].pmgr_axi2af[1])&~1U)
                return DEVICE_BAD_VALUE;
        }
        if ((avd_dart && (states[pmgr].pmgr_avd&15)!=15) ||
            (isp_dart && (states[pmgr].pmgr_isp_sys&15)!=15) ||
            (prores_dart && (states[pmgr].pmgr_prores&15)!=15) ||
            (image_dart==1 && (states[pmgr].pmgr_msr&15)!=15) ||
            (image_dart==2 && (states[pmgr].pmgr_jpg&15)!=15)) return DEVICE_BAD_VALUE;
        if (((avd || isp_sys || prores || venc_sys || msr || jpg || gfx) && write) || changed) {
            if (width!=(changed ? 8u : 4u)) return DEVICE_BAD_WIDTH;
            struct device_state *power=&states[pmgr],*transport=&states[pmp];
            uint64_t actual=0;
            enum device_result r=pmp_actual_states(&models[pmgr],power,&actual);
            if (r!=DEVICE_OK) return r;
            if (actual!=transport->pmp_active.ack) return DEVICE_BAD_VALUE;
            uint64_t request=transport->pmp_active.request,ps[SYSTEMS]={0};
            if (changed) {
                if ((*value&~models[pmp].config[4]) ||
                    ((request&~*value)&~changed) || ((*value&~actual)&~changed))
                    return DEVICE_BAD_VALUE;
                request=*value;
            }
            for (unsigned d=0;d<SYSTEMS;d++) if (domains&(1u<<d)) {
                ps[d]=*value;
                if (changed) {
                    r=pmgr_boot_access(&models[pmgr],power,offsets[d],4,0,&ps[d],PMGR_LOCAL);
                    if (r!=DEVICE_OK) return r;
                    /* Retain explicit policy; an off vote cannot silently
                     * disable automatic-idle policy to make itself succeed. */
                    ps[d]=(ps[d]&0x100f0000)|((request&bits[d]) ? 15 : 0);
                }
                unsigned target=(unsigned)ps[d]&15;
                if (target!=0 && target!=15) return DEVICE_BAD_VALUE;
                if (d==7) {
                    if (!resources || !resources->gfx_idle) return DEVICE_BAD_CONFIG;
                    if (!resources->gfx_idle(resources->ctx)) return DEVICE_BAD_VALUE;
                }
                if ((d==3 || d==4) && target && states[pmc].pmc_dvmr.venc_cluster!=8) return DEVICE_BAD_VALUE;
                if (!target) {
                    if (request&bits[d]) return DEVICE_BAD_VALUE;
                    for (unsigned bank=0;bank<counts[d];bank++)
                        if (!dart_runtime_idle(&states[banks[d][bank]].dart,initialized[d][bank]))
                            return DEVICE_BAD_VALUE;
                }
                r=pmgr_boot_access(&models[pmgr],power,offsets[d],4,1,&ps[d],PMGR_PREFLIGHT);
                if (r!=DEVICE_OK) return r;
            }
            /* Media systems have fixed-active AFISOCNI parents; VENC also requires
             * its explicitly controlled shared cluster to be active for wake.
             * GFX retains AFIMCCNI0/PIOGW and its external resource admission.
             * With all admissions complete and no asynchronous producer,
             * no commit can invalidate another domain's preflight. */
            for (unsigned d=0;d<SYSTEMS;d++) if (domains&(1u<<d))
                pmgr_boot_access(&models[pmgr],power,offsets[d],4,1,&ps[d],PMGR_OWNED);
            uint64_t next=(actual&~supported)|
                ((power->pmgr_avd&15)==15 ? bits[0] : 0)|
                ((power->pmgr_isp_sys&15)==15 ? bits[1] : 0)|
                ((power->pmgr_prores&15)==15 ? bits[2] : 0)|
                ((power->pmgr_venc_sys[0]&15)==15 ? bits[3] : 0)|
                ((power->pmgr_venc_sys[1]&15)==15 ? bits[4] : 0)|
                ((power->pmgr_msr&15)==15 ? bits[5] : 0)|
                ((power->pmgr_jpg&15)==15 ? bits[6] : 0)|
                ((power->pmgr_gfx&15)==15 ? bits[7] : 0);
            if (next!=actual || changed) transport->pmp_active.ack_updated=1;
            transport->pmp_active.ack=next;
            if (changed) {
                transport->pmp_active.request=request;
                transport->pmp_active.request_updated=1;
            }
            return DEVICE_OK;
        }
    }
    return device_model_access_at(m,&states[index],now,offset,width,write,value);
}

enum device_result device_models_access_at(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    return device_models_access_power_at(models,states,count,index,now,
        offset,width,write,value,0);
}

/* Primary and paired secondary records in the pinned perf-counters table.
 * Group 1 has an intentional hole, not a sparse zero-returning MMIO bank. */
static int soc_perf_slot(unsigned group, uint64_t offset)
{
    if (offset<0x100 || (offset&0x1f)) return -1;
    if (group==0 && offset<=0x1200) return (int)((offset-0x100)/0x20);
    if (group==1) {
        if (offset<=0x24a0) return (int)((offset-0x100)/0x20);
        if (offset>=0x2de0 && offset<=0x2ee0) return 286+(int)((offset-0x2de0)/0x20);
    }
    if (group>=2 && group<=4 && offset<=0x420) return (int)((offset-0x100)/0x20);
    if (group==5 && offset<=0x1e0) return (int)((offset-0x100)/0x20);
    return -1;
}

static enum device_result soc_perf_access(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,uint64_t *value)
{
    if (!state) return DEVICE_BAD_CONFIG;
    if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
    unsigned group=(unsigned)model->config[0];
    unsigned bias=group==0 ? 0x800 : 0;
    if (offset<bias) return DEVICE_UNKNOWN_REGISTER;
    offset-=bias;
    if (state->pmgr_perf.control[0]&~1U) return DEVICE_BAD_VALUE;
    if (!offset) {
        if (write) {
            if (*value&~1UL) return DEVICE_BAD_VALUE;
            /* Validate every affected latch before invalidating snapshots. */
            unsigned count=group==0 ? 137 : group==1 ? 295 : group==5 ? 8 : 26;
            for (unsigned i=0;i<count;i++)
                if ((state->pmgr_perf.control[i+1]&~5U) ||
                    (state->pmgr_perf.written[i]&~3U)) return DEVICE_BAD_VALUE;
            /* Enabling requests sampling. Invalidate restored snapshots
             * before they could be mistaken for newly measured activity. */
            if (*value) for (unsigned i=0;i<count;i++)
                if (state->pmgr_perf.control[i+1]&4) state->pmgr_perf.written[i]=0;
            state->pmgr_perf.control[0]=(uint32_t)*value;
        } else *value=state->pmgr_perf.control[0];
        return DEVICE_OK;
    }
    unsigned word=(unsigned)(offset&0x1f);
    int index=soc_perf_slot(group,offset&~0x1fUL);
    if (index<0 || (word!=0 && word!=0x10 && word!=0x14)) return DEVICE_UNKNOWN_REGISTER;
    uint32_t *control=&state->pmgr_perf.control[index+1];
    if (*control&~5U) return DEVICE_BAD_VALUE;
    if (!word) {
        if (write) {
            if (*value&~5UL) return DEVICE_BAD_VALUE;
            if ((*value&4) && state->pmgr_perf.control[0]) state->pmgr_perf.written[index]=0;
            *control=(uint32_t)*value;
        } else *value=*control;
        return DEVICE_OK;
    }
    uint64_t *restored=index<256 ? &state->counter[index/64][index%64] :
                                  &state->pmgr_perf.extra[index-256];
    unsigned shift=word==0x14 ? 32 : 0;
    unsigned half=word==0x14 ? 2 : 1;
    if (state->pmgr_perf.written[index]&~3U) return DEVICE_BAD_VALUE;
    int sampling=state->pmgr_perf.control[0] && (*control&4);
    if (write) {
        if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
        *restored=(*restored&~((uint64_t)UINT32_MAX<<shift))|(*value<<shift);
        state->pmgr_perf.written[index]=sampling ? 0 : state->pmgr_perf.written[index]|half;
    } else {
        /* An enabled counter that nothing drives holds its programmed value:
         * there is no clock/residency/event producer, so an IOReport sample
         * reads no activity and every delta is zero (docs/PMGR-IOREPORT-
         * 20261017.md). Frozen, only a fully restored value is meaningful;
         * the restore protocol still refuses a partial one. */
        if (!sampling && state->pmgr_perf.written[index]!=3) return DEVICE_BAD_VALUE;
        *value=(*restored>>shift)&UINT32_MAX;
    }
    return DEVICE_OK;
}

/* The pinned T8140 setter bounds the E/P residency indices to 8/18.
 * Type-3 DT records select five E and three P telemetry pairs. */
static int acc_perf_slot(unsigned cluster,uint64_t offset)
{
    if ((offset&~0xffUL)==0x400 || (offset&~0xffUL)==0x500) {
        unsigned slot=(unsigned)(offset&0xff)/8;
        if (slot<(cluster ? 18U : 8U)) return (offset<0x500 ? 0 : 18)+slot;
    }
    const unsigned telemetry[]={0,44,48,52,56};
    for (unsigned i=0;i<(cluster ? 3U : 5U);i++)
        for (unsigned event=0;event<2;event++)
            if (offset==0x680+8*telemetry[i]+8*event) return 36+2*i+event;
    /* Setter domains 0x20/0x21: E has two banks, P aliases its two
     * submitted values at the same bank, exactly as the stock setter does. */
    if (!cluster && offset>=0x10e8 && offset<0x1128)
        return 46+(int)((offset-0x10e8)/8);
    if (offset>=0x11e8 && offset<0x11e8+8*(cluster ? 18UL : 8UL))
        return 54+(int)((offset-0x11e8)/8);
    return -1;
}

