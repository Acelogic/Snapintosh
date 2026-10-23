/* SPDX-License-Identifier: MIT */
/* The dock FIFO channel model and the DART monitor init, power-up and frame admission.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
/* t8002 channel zero: A config/data at 28000/2c000, B at 30000/34000.
 * AppleDockChannel::start reads global+4[7:4] as the highest channel index.
 * TX8..32, TX_FREE, RX8..32 and RX_COUNT agree with the primary m1n1/Linux
 * DockChannel drivers. Threshold zero really is active (m1n1 IRQ experiment).
 * This virtual transport exposes masked level status; W1C cannot suppress a
 * still-true FIFO condition. Unknown reset/control registers remain refused. */
static uint32_t dockfifo_level(const struct device_state *s)
{
    uint32_t bits=0;
    for (unsigned side=0; side<2; side++) {
        if (DEVICE_DOCK_FIFO_MAX-s->dockfifo.count[side] >= s->dockfifo.threshold[side][0])
            bits |= 1U << (side*2);
        if (s->dockfifo.count[side^1] >= s->dockfifo.threshold[side][1])
            bits |= 2U << (side*2);
    }
    return bits & s->dockfifo.mask;
}

static enum device_result dockfifo_access(struct device_state *s,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    if (!s) return DEVICE_BAD_CONFIG;
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (offset == 4) {
        if (write) return DEVICE_READ_ONLY;
        *value=0; /* Highest valid channel is zero: one implemented channel. */
        return DEVICE_OK;
    }
    if (offset == 0x14000 || offset == 0x14004) {
        if (write) {
            if (*value > UINT32_MAX || (offset == 0x14000 && (*value & ~15UL)))
                return DEVICE_BAD_VALUE;
            if (offset == 0x14000) s->dockfifo.mask=(uint32_t)*value;
            else s->dockfifo.flags &= ~(uint32_t)*value;
        } else if (offset == 0x14000) *value=s->dockfifo.mask;
        else *value=(s->dockfifo.flags | dockfifo_level(s)) & s->dockfifo.mask;
        s->dockfifo.flags |= dockfifo_level(s);
        return DEVICE_OK;
    }
    if (offset < 0x28000 || offset >= 0x35000) return DEVICE_UNKNOWN_REGISTER;
    unsigned side=(unsigned)((offset-0x28000)/0x8000);
    unsigned reg=(unsigned)((offset-0x28000)%0x8000);
    if (reg == 0 || reg == 4) {
        if (write) {
            if (*value > DEVICE_DOCK_FIFO_MAX) return DEVICE_BAD_VALUE;
            s->dockfifo.threshold[side][reg/4]=(uint32_t)*value;
        } else *value=s->dockfifo.threshold[side][reg/4];
    } else if (reg == 0x4014 || reg == 0x402c) {
        if (write) return DEVICE_READ_ONLY;
        *value=reg == 0x4014 ? DEVICE_DOCK_FIFO_MAX-s->dockfifo.count[side] :
                             s->dockfifo.count[side^1];
    } else if (reg >= 0x4004 && reg <= 0x4010) {
        if (!write) return DEVICE_UNKNOWN_REGISTER;
        unsigned n=(reg-0x4000)/4;
        if (*value > UINT32_MAX || n > DEVICE_DOCK_FIFO_MAX-s->dockfifo.count[side])
            return DEVICE_BAD_VALUE;
        for (unsigned i=0; i<n; i++) {
            unsigned tail=(s->dockfifo.head[side]+s->dockfifo.count[side])%DEVICE_DOCK_FIFO_MAX;
            s->dockfifo.tx[side][tail]=(uint8_t)(*value >> (i*8));
            s->dockfifo.count[side]++;
        }
    } else if (reg >= 0x401c && reg <= 0x4028) {
        if (write) return DEVICE_READ_ONLY;
        unsigned n=(reg-0x4018)/4, peer=side^1;
        if (n == 4 && s->dockfifo.count[peer] < 4) return DEVICE_BAD_VALUE;
        if (n > s->dockfifo.count[peer]) n=s->dockfifo.count[peer];
        uint32_t data=0;
        for (unsigned i=0; i<n; i++) {
            data |= (uint32_t)s->dockfifo.tx[peer][s->dockfifo.head[peer]] << (i*8);
            s->dockfifo.head[peer]=(s->dockfifo.head[peer]+1)%DEVICE_DOCK_FIFO_MAX;
            s->dockfifo.count[peer]--;
        }
        *value=reg == 0x4028 ? data : ((uint64_t)data << 8) | n;
    } else return DEVICE_UNKNOWN_REGISTER;
    s->dockfifo.flags |= dockfifo_level(s);
    return DEVICE_OK;
}

enum device_result device_dart_monitor_init(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t device_id)
{
    if (!states || !device_models_valid(models,count,0,0) || device_id>=32)
        return DEVICE_BAD_CONFIG;
    uint32_t bit=1U<<(unsigned)device_id;
    unsigned matches=0,streams=0;
    int ane=0;
    if (!device_id) {
        for (unsigned i=0;i<count;i++)
            if (models[i].kind==DEVICE_DART_T8110_V1 &&
                (models[i].config[1]==DEVICE_DART_ANE_INIT_V1 ||
                 (models[i].base>=0x401800000UL && models[i].base<0x401860000UL)))
                ane=1;
        if (ane) {
            unsigned pmgr=0,pmp=0,banks[3]={0,0,0};
            if (!ane_binding(models,count,&pmgr,&pmp,banks)) return DEVICE_BAD_CONFIG;
            /* Legacy capability models deliberately have no logical INIT. */
            if (models[banks[0]].config[1]==44) return DEVICE_NOT_FOUND;
            for (unsigned b=0;b<3;b++)
                if (states[banks[b]].dart.initialized_ids) return DEVICE_BAD_VALUE;
        }
    }
    /* The loader has captured the fixed capabilities in each validated model.
     * All matching instances are checked before publishing initialization. */
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_DART_T8110_V1 && (models[i].config[4]&bit)) {
            if (states[i].dart.initialized_ids&bit) return DEVICE_BAD_VALUE;
            if (matches && streams!=models[i].config[0]) return DEVICE_BAD_CONFIG;
            streams=(unsigned)models[i].config[0];
            matches++;
        }
    if (!matches) return DEVICE_NOT_FOUND;
    if (ane && matches!=3) return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_DART_T8110_V1 && (models[i].config[4]&bit))
            states[i].dart.initialized_ids|=bit;
    return DEVICE_OK;
}

enum device_result device_dart_monitor_powerup(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t device_id)
{
    if (!states || !device_models_valid(models,count,0,0) || device_id>=32)
        return DEVICE_BAD_CONFIG;
    uint32_t bit=1U<<(unsigned)device_id;
    int found=-1;
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_DART_T8110_V1 && (models[i].config[4]&bit)) {
            if (found>=0 || (models[i].config[1]!=DEVICE_DART_SIO_BOOT_V1 &&
                            models[i].config[1]!=DEVICE_DART_SEP_BOOT_V1 &&
                            models[i].config[1]!=DEVICE_DART_ADRENO_BOOT_V1))
                return DEVICE_BAD_CONFIG;
            found=(int)i;
        }
    if (found<0) return DEVICE_NOT_FOUND;
    int sep=models[found].config[1]==DEVICE_DART_SEP_BOOT_V1;
    if (sep) {
        unsigned pmgr=0,pmp=0,dart=0;
        if (!sep_binding(models,count,&pmgr,&pmp,&dart) || dart!=(unsigned)found)
            return DEVICE_BAD_CONFIG;
        if ((states[pmp].pmp_active.request|states[pmp].pmp_active.ack)&(1UL<<27))
            return DEVICE_BAD_VALUE;
    }
    struct dart_state *s=&states[found].dart;
    if (s->initialized_ids!=bit) return DEVICE_BAD_VALUE;
    /* Reference state 3 returns without touching registers when no retention or
     * no-sleep policy is present. Preserve subsequent MMIO state and faults. */
    if (s->powered_ids==bit && !sep) return DEVICE_OK;
    if ((s->powered_ids && (!sep || s->powered_ids!=bit)) ||
        s->error || s->error_mask || s->error_address ||
        s->protect || s->protect_lock || s->tlb_op || s->tlb_start || s->tlb_end ||
        s->translations || s->faults || s->flushes) return DEVICE_BAD_VALUE;
    for (unsigned i=0;i<8;i++)
        if (s->enabled[i] || s->error_streams[i]) return DEVICE_BAD_VALUE;
    for (unsigned i=0;i<DART_STREAMS;i++) {
        /* SEP's retention flag enters restoration even in powered state3
         * (270d229c). Only an unchanged empty saved image is admitted here. */
        uint32_t expected=sep && s->powered_ids==bit && i<3 ? (i<2 ? 1 : 9) : 0;
        if (s->tcr[i]!=expected || s->ttbr[i]) return DEVICE_BAD_VALUE;
    }
    /* 26A428 POWERUP 270d2b98..2bd8 restores the declared stream records.
     * Stream setup at 270dd668..688 selects bit3 by the end-page threshold
     * 0x4400000, not merely by the presence of high IOVA bits. SEP SID0/1
     * therefore use TCR=1 (root level1); its exclave SID2 and SIO use TCR=9.
     * No table was installed, so
     * TTBR and the per-instance enable bitmap remain zero. The v2 initial
     * flush queue drains without issuing an MMIO command (270ce634..ce880);
     * this backend also has no translation cache or in-flight DMA.
     * TLIMIT, diagnostic snapshots and the unmasked fault register remain
     * zero. A non-pristine first transition is refused above, not erased. */
    s->tcr[0]=s->tcr[1]=sep || models[found].config[1]==DEVICE_DART_ADRENO_BOOT_V1 ? 1 : 9;
    if (sep) s->tcr[2]=9;
    s->powered_ids=bit;
    return DEVICE_OK;
}

enum device_result device_dart_admit_frame(const struct device_model *models,
    const struct device_state *states, unsigned count, unsigned iommu_class,
    unsigned device_id, unsigned sid, unsigned level, unsigned *model_index)
{
    if (!states || !device_models_valid(models,count,0,0) || device_id>=32)
        return DEVICE_BAD_CONFIG;
    if (iommu_class!=5 || sid>1 || level>3) return DEVICE_BAD_VALUE;
    uint32_t bit=1U<<device_id;
    int found=-1;
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_DART_T8110_V1 && (models[i].config[4]&bit)) {
            if (found>=0 || (models[i].config[1]!=DEVICE_DART_SIO_BOOT_V1 &&
                            models[i].config[1]!=DEVICE_DART_SEP_BOOT_V1 &&
                            models[i].config[1]!=DEVICE_DART_ADRENO_BOOT_V1))
                return DEVICE_BAD_CONFIG;
            found=(int)i;
        }
    if (found<0) return DEVICE_NOT_FOUND;
    const struct dart_state *s=&states[found].dart;
    /* SIO has three table levels; normal SEP streams have two. The constructor records
     * device/SID/level and preserves the payload in either case. SEP's exclave
     * SID2 remains outside the currently admitted MAP/UNMAP contract. */
    int sep=models[found].config[1]==DEVICE_DART_SEP_BOOT_V1;
    if (sep) {
        unsigned pmgr=0,pmp=0,dart=0;
        if (!sep_binding(models,count,&pmgr,&pmp,&dart) || dart!=(unsigned)found)
            return DEVICE_BAD_CONFIG;
        if ((states[pmp].pmp_active.request|states[pmp].pmp_active.ack)&(1UL<<27))
            return DEVICE_BAD_VALUE;
    }
    if (s->initialized_ids!=bit || s->powered_ids!=bit ||
        s->tcr[sid]!=(sep || models[found].config[1]==DEVICE_DART_ADRENO_BOOT_V1 ? 1U : 9U))
        return DEVICE_BAD_VALUE;
    if (model_index) *model_index=(unsigned)found;
    return DEVICE_OK;
}
