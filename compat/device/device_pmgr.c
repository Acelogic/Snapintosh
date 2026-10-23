/* SPDX-License-Identifier: MIT */
/* PMGR boot access, power-domain bindings (AES, ATC, SEP, ANE, ISP, VENC, AVE, GFX) and
 * ACC boot access.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */

enum pmgr_admission { PMGR_LOCAL, PMGR_OWNED, PMGR_PREFLIGHT };

static enum device_result pmgr_boot_access(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value, enum pmgr_admission admission)
{
    if (!state) return DEVICE_BAD_CONFIG;
    if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
    /* 26A428 /arm-io/pmgr devices, non-virtual entries, ps-groups 0/1.
     * Only the first 32-bit word of each eight-byte record is a PS register.
     * Hash-bound loader metadata and exhaustive topology tests cover holes. */
    static const uint32_t ranges[2][11][2]={
        {{0,0x18},{0x30,0x38},{0x50,0x60},{0x100,0x1a8},
         {0x1b8,0x3a0},{0x3c0,0x3c0},{0x3d0,0x3f0},{0xc00,0xc00},
         {0x4000,0x4060},{0x8000,0x8048},{0x10000,0x10000}},
        {{0,0},{0x58,0x88},{0xa0,0xb0},{0x8028,0x8038}}
    };
    unsigned group=(unsigned)model->config[0], index=0, found=0;
    for (unsigned i=0;i<(group ? 4u : 11u);i++) {
        uint32_t first=ranges[group][i][0],last=ranges[group][i][1];
        if (offset>=first && offset<=last && !(offset&7)) {
            index+=(unsigned)(offset-first)/8;found=1;break;
        }
        index+=(last-first)/8+1;
    }
    if (!found || index>=128) return DEVICE_UNKNOWN_REGISTER;
    const uint32_t policy=(1U<<28)|(15U<<16);
    const uint32_t readback=(15U<<24)|0xf0;
    if (model->config[1]==DEVICE_PMGR_CPU0_BOOT_V1) {
        static const unsigned cpu_offsets[8]={0,8,0x10,0x18,0x30,0x38,0x50,0x58};
        for (unsigned cpu=0;cpu<8;cpu++) if (offset==cpu_offsets[cpu]) {
            /* No software force-on vote was installed by virtual firmware.
             * cpu0 is executing; five CPUs have not been released. The
             * independent cluster-control model holds ECPM/PCPM active.
             * Do not confuse these actual states with the request nibble.
             * CPU execution/release and dynamic cluster power are separate,
             * unsupported operations, not implicit effects of a PS write. */
            uint32_t actual=(cpu==0 || cpu>=6) ? 0xf0 : 0;
            if (state->pmgr_cpu_boot[cpu]!=actual) return DEVICE_BAD_VALUE;
            if (write) {
                if (*value & ~(uint64_t)((15U<<16)|readback|0x300)) return DEVICE_BAD_VALUE;
                if (admission==PMGR_PREFLIGHT) return DEVICE_OK;
                state->pmgr_policy[index]=(uint32_t)*value&(15U<<16);
                state->pmgr_cpu_writes|=1U<<cpu;
            } else {
                *value=state->pmgr_policy[index]|state->pmgr_cpu_boot[cpu];
                if (admission!=PMGR_PREFLIGHT) state->pmgr_cpu_reads|=1U<<cpu;
            }
            return DEVICE_OK;
        }
    }
    int venc=!group && offset>=0x8000 && offset<=0x8048;
    int isp=!group && offset>=0x4000 && offset<=0x4060;
    int atc=!group && offset>=0x3e0 && offset<=0x3f0;
    int dpa=!group && offset>=0x390 && offset<=0x398;
    int spi=!group && offset>=0x330 && offset<=0x350;
    int i2c=!group && offset>=0x2c8 && offset<=0x2e8;
    int pwm=!group && offset>=0x2b8 && offset<=0x2c0;
    int ase=!group && offset==0x298;
    int sensor=!group && offset>=0x188 && offset<=0x190;
    int aux=pwm || ase || sensor;
    int ane=!group && offset==0x290;
    int avd=!group && offset==0x270;
    int isp_sys=!group && offset==0x268;
    int prores=!group && offset==0x250;
    int venc_sys=!group && (offset==0x240 || offset==0x248);
    int msr=!group && offset==0x238;
    int jpg=!group && offset==0x230;
    int gfx=!group && offset==0x1f0;
    int misc=!group && (offset==0x170 || offset==0x180 || offset==0x1a0);
    int sep_aon=!group && offset==0x60;
    int aes=!group && offset==0x308;
    unsigned unit=misc ? (offset==0x1a0 ? 2 : offset==0x180 ? 1 : 0) : venc_sys ? (unsigned)(offset-0x240)/8 : venc ? (unsigned)(offset-0x8000)/8 : isp ? (unsigned)(offset-0x4000)/8 :
        atc ? (unsigned)(offset-0x3e0)/8 : dpa ? (unsigned)(offset-0x390)/8 :
        spi ? (unsigned)(offset-0x330)/8 : i2c ? (unsigned)(offset-0x2c8)/8 :
        pwm ? (unsigned)(offset-0x2b8)/8 : ase ? 2 : sensor ? 3+(unsigned)(offset-0x188)/8 : 0;
    uint32_t *levels=aes ? &state->pmgr_aes : sep_aon ? &state->pmgr_sep_aon : misc ? state->pmgr_misc : gfx ? &state->pmgr_gfx : msr ? &state->pmgr_msr : jpg ? &state->pmgr_jpg : venc_sys ? state->pmgr_venc_sys : prores ? &state->pmgr_prores : isp_sys ? &state->pmgr_isp_sys : avd ? &state->pmgr_avd : ane ? &state->pmgr_ane : aux ? state->pmgr_aux : i2c ? state->pmgr_i2c : spi ? state->pmgr_spi :
        dpa ? state->pmgr_dpa : atc ? state->pmgr_atc :
        isp ? state->pmgr_isp : state->pmgr_venc;
    if (write) {
        /* Actual/automatic state are read-only; history bits are W1C.
         * Automatic policy has no idle producer. Reset, force-no-access
         * and no-wakeup remain unsupported; only the audited idle
         * subgraphs below own explicit power transitions. */
        if (*value & ~(uint64_t)(policy|readback|0x30f))
            return DEVICE_BAD_VALUE;
        unsigned target=(unsigned)*value&15;
        if (venc || isp || atc || dpa || spi || i2c || aux || ane || avd || isp_sys || prores || venc_sys || msr || jpg || gfx || misc || sep_aon || aes) {
            /* VENC0/1: DMA -> {PIPE4, PIPE5, ME0 -> ME1}. External
             * ISP: CPU -> CORE0/1; FE -> DPRX/SECURE/STS0/STS1/PEARL/BE;
             * BE -> CLR/CVD -> CVM. VENC/ISP system parents are
             * registry-owned and checked in both directions.
             * No encoder/ISP command or firmware-execution
             * backend exists, hence no accepted work needs draining.
             * A future execution backend must join transition admission. */
            static const int8_t venc_parent[10]={-1,0,0,0,3,-1,5,5,5,8};
            static const int8_t isp_parent[13]={-1,0,0,-1,3,3,3,3,3,3,9,9,11};
            /* ATC COMMON has two parents: local AON and fixed-active
             * AFISOCNI2 (0x228). USB depends on COMMON. Registry admission
             * owns both USB DART banks; there is no USB transfer backend. */
            static const int8_t atc_parent[3]={-1,0,1};
            /* DPA0/1 are independent leaves of fixed-active DPA_P (0x300),
             * under SIO (0x260). There is no accepted DP audio command or
             * SIO audio-channel producer. Do not alter the shared SIO DART
             * or its AES mapping. A future audio producer must join admission. */
            static const int8_t dpa_parent[2]={-1,-1};
            /* SPI0..3/QSPI share fixed-active SPI_P (0x2f0); I2C0..4
             * share fixed-active SIO (0x260). No controller/transfer or
             * SIO channel backend has accepted work for these leaves.
             * State changes do not execute flash/NVRAM, display, USB,
             * sensor or audio operations. Future producers must check
             * domain state and join transition admission. */
            static const int8_t serial_parent[5]={-1,-1,-1,-1,-1};
            /* FPWM1/2 are unused leaves of fixed-active SIO; ASE_CORE is
             * a leaf of registry-owned MSR (0x238). ISPSENS0/1 are independent
             * roots. No PWM, scaler, or ISP sensor execution is accepted.
             * Leaf writes do not alter system votes or DART ownership. */
            /* ANE_SYS's physical parent AFISOCNI2 stays active. Virtual
             * ANE CPU and PMP readiness are not execution backends. The
             * registry admits its three DART banks and absent virtual vote. */
            /* SOC_RC, PMGR_SOC_OCLA and AP_TMM are three exact independent
             * non-PMP leaves, with no declared consumers or execution/sample
             * producer. Their state changes do not affect AON counters,
             * CPU/SEP power or PMP readiness. Future producers must join
             * their power lifecycle; do not infer idle from names alone. */
            /* SEP_AON has no declared PMGR parents/children. Main SEP at c00
             * is a separate fixed-active domain. The registry requires an
             * idle SEP DART and no virtual SEP vote or execution producer. */
            const int8_t *parent=(spi || i2c || aux || ane || avd || isp_sys || prores || venc_sys || msr || jpg || gfx || misc || sep_aon || aes) ? serial_parent : dpa ? dpa_parent :
                atc ? atc_parent : isp ? isp_parent : venc_parent;
            unsigned count=misc ? 3 : venc_sys ? 2 : (ane || avd || isp_sys || prores || msr || jpg || gfx || sep_aon || aes) ? 1 : (spi || i2c || aux) ? 5 : dpa ? 2 : atc ? 3 : isp ? 13 : 10;
            if (target!=0 && target!=4 && target!=15) return DEVICE_BAD_VALUE;
            /* Physical PMP exposes off/on; no clock-gated system ACK
             * contract is admitted. AFISOCNI1 remains active for AVD/ISP,
             * AFISOCNI0 for PRORES, which has no PMGR children. */
            if ((avd || isp_sys || prores || venc_sys || msr || jpg || gfx) && target!=0 && target!=15) return DEVICE_BAD_VALUE;
            if ((atc || ane || avd || isp_sys || prores || venc_sys || msr || jpg || gfx || sep_aon || aes) && target!=(levels[unit]&15) && admission==PMGR_LOCAL)
                return DEVICE_BAD_VALUE;
            /* Automatic-idle events are not modeled. Keep the established
             * active automatic policy; explicit gating must disable it. */
            if ((*value&(1UL<<28)) && target!=15) return DEVICE_BAD_VALUE;
            if (isp && (state->pmgr_isp_sys&15)<target) return DEVICE_BAD_VALUE;
            if (venc && (state->pmgr_venc_sys[unit/5]&15)<target) return DEVICE_BAD_VALUE;
            if (ase && (state->pmgr_msr&15)<target) return DEVICE_BAD_VALUE;
            if (msr && (state->pmgr_aux[2]&15)>target) return DEVICE_BAD_VALUE;
            if (gfx) {
                /* GFX has no physical children. Read both separately retained
                 * parents so future mutable parents cannot bypass ordering. */
                for (unsigned off=0x198;off<=0x1a8;off+=0x10) {
                    uint64_t level=0;
                    if (pmgr_boot_access(model,state,off,4,0,&level,PMGR_LOCAL)!=DEVICE_OK ||
                        (level&15)<target) return DEVICE_BAD_VALUE;
                }
            }
            if (isp_sys)
                for (unsigned child=0;child<13;child++)
                    if ((state->pmgr_isp[child]&15)>target) return DEVICE_BAD_VALUE;
            if (venc_sys)
                for (unsigned child=unit*5;child<unit*5+5;child++)
                    if ((state->pmgr_venc[child]&15)>target) return DEVICE_BAD_VALUE;
            if (parent[unit]>=0 && (levels[parent[unit]]&15)<target)
                return DEVICE_BAD_VALUE;
            for (unsigned child=0;child<count;child++)
                if (parent[child]==(int)unit && (levels[child]&15)>target)
                    return DEVICE_BAD_VALUE;
            /* Coupled PMP requests validate every independent domain before
             * committing any of them. Validation has no observable effects. */
            if (admission==PMGR_PREFLIGHT) return DEVICE_OK;
            uint32_t old=levels[unit];
            uint32_t history=(old&0x300)&~(uint32_t)*value;
            if ((old&15)!=target)
                history|=target==0 ? 0x100 : target==4 ? 0x200 : 0;
            levels[unit]=target|history;
        } else if (target!=15) return DEVICE_BAD_VALUE;
        state->pmgr_policy[index]=(uint32_t)*value&policy;
    } else {
        uint32_t p=state->pmgr_policy[index];
        uint32_t committed=(venc || isp || atc || dpa || spi || i2c || aux || ane || avd || isp_sys || prores || venc_sys || msr || jpg || gfx || misc || sep_aon || aes) ? levels[unit] : 15;
        unsigned level=committed&15;
        *value=p|level|(level<<4)|(committed&0x300)|
            ((p&(1U<<28)) ? 15U<<24 : 0);
    }
    return DEVICE_OK;
}

/* DT gate75 is AES at PMGR+308, an independent leaf of fixed-active SIO.
 * The shared mapper and retained IV buffer belong to SIO, not this gate. */
static int aes_binding(const struct device_model *models,unsigned count,
                       unsigned *pmgr,unsigned *engine)
{
    if (!models || count>DEVICE_MODEL_MAX) return 0;
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0]) {
            if ((found&1) || !valid(m) || m->base!=0x300700000UL) return 0;
            found|=1;*pmgr=i;
        }
        if (m->kind==DEVICE_AES_SOFTWARE_V1 ||
            (m->base>=0x38500c000UL && m->base<0x385010000UL) ||
            (m->base<0x38500c000UL && m->span>0x38500c000UL-m->base)) {
            if ((found&2) || m->kind!=DEVICE_AES_SOFTWARE_V1 || !valid(m) || m->base!=0x38500c000UL) return 0;
            found|=2;*engine=i;
        }
        if (m->kind==DEVICE_DART_T8110_V1 && (m->base==0x385060000UL || (m->config[4]&(1U<<21)))) {
            if ((found&4) || !valid(m) || m->base!=0x385060000UL || m->span!=0x20000 ||
                m->config[0]!=16 || m->config[1]!=DEVICE_DART_SIO_BOOT_V1 ||
                m->config[2]!=1120 || m->config[3]!=36 || m->config[4]!=(1U<<21)) return 0;
            found|=4;
        }
    }
    return found==7;
}
enum device_result device_aes_powered(const struct device_model *models,
    const struct device_state *states,unsigned count,unsigned index)
{
    unsigned pmgr=0,engine=0;
    if (!states || index>=count || !aes_binding(models,count,&pmgr,&engine) || index!=engine)
        return DEVICE_BAD_CONFIG;
    return (states[pmgr].pmgr_aes&~0x300U)==15 ? DEVICE_OK : DEVICE_BAD_VALUE;
}

/* These two T8110 instances are the pinned guest ATC0 USB mapper (ID 22).
 * An unbound/partial registry must not authorize power transitions. */
static int atc_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned banks[2])
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0]) {
            if ((found&1) || !valid(m)) return 0;
            found|=1;*pmgr=i;
        }
        if (m->kind==DEVICE_DART_T8110_V1 &&
            ((m->config[4]&(1UL<<22)) || m->base==0x40af00000 || m->base==0x40af80000)) {
            unsigned bank=m->base==0x40af80000;
            if ((m->base!=0x40af00000 && m->base!=0x40af80000) ||
                (found&(2U<<bank)) || !valid(m) || m->span!=0xc000 ||
                m->config[0]!=16 || m->config[1]!=44 || m->config[2]!=1248 ||
                m->config[3]!=36 || m->config[4]!=(1UL<<22)) return 0;
            found|=2U<<bank;banks[bank]=i;
        }
    }
    return found==7;
}

static int dart_runtime_idle(const struct dart_state *s, uint32_t initialized_mask)
{
    /* Capability initialization alone does not acquire power or DMA.
     * Retain it. Reject every runtime resource rather than clearing it.
     * No USB/ANE power-up producer exists; future support must extend this
     * admission contract and preserve table/frame ownership on shutdown. */
    if ((s->initialized_ids&~initialized_mask) || s->powered_ids || s->error || s->error_mask ||
        s->error_address || s->protect || s->protect_lock || s->tlb_op ||
        s->tlb_start || s->tlb_end || s->translations || s->faults || s->flushes)
        return 0;
    for (unsigned i=0;i<8;i++) if (s->enabled[i] || s->error_streams[i]) return 0;
    for (unsigned i=0;i<DART_STREAMS;i++) if (s->tcr[i] || s->ttbr[i]) return 0;
    return 1;
}

static int sep_dart_model(const struct device_model *m)
{
    return m->kind==DEVICE_DART_T8110_V1 &&
        (m->base==0x280b80000 || (m->config[4]&(1U<<20)));
}

static int sep_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned *dart)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        /* Only the exact request-retaining ASC frontend may overlap SEP.
         * Firmware, ROM execution and other overlapping models still require
         * their own resource contract. The frontend is optional for old VMs. */
        static const uint64_t windows[2][2]={{0x282600000,0x88000},{0x282050000,0x60000}};
        for (unsigned w=0;w<2;w++)
            if ((m->base>=windows[w][0] && m->base-windows[w][0]<windows[w][1]) ||
                (m->base<windows[w][0] && m->span>windows[w][0]-m->base)) {
                if (w || (found&16) || m->kind!=DEVICE_SEP_ASC_MAILBOX_V1 || !valid(m))
                    return 0;
                found|=16;
            }
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 8 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if (sep_dart_model(m) ||
            (m->base>=0x280b80000 && m->base<0x280ba0000) ||
            (m->base<0x280b80000 && m->span>0x280b80000-m->base)) {
            if ((found&4) || m->kind!=DEVICE_DART_T8110_V1 || !valid(m) ||
                m->base!=0x280b80000 || m->span!=0x20000 || m->config[0]!=3 ||
                (m->config[1]!=44 && m->config[1]!=DEVICE_DART_SEP_BOOT_V1) ||
                m->config[2]!=353 || m->config[3]!=36 ||
                m->config[4]!=(1U<<20)) return 0;
            found|=4;*dart=i;
        }
    }
    return found==15 || found==31;
}

static int ane_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned banks[3])
{
    unsigned found=0;
    uint64_t policy=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 32 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if ((m->base>=0x401800000 && m->base<0x401860000) ||
            (m->kind==DEVICE_DART_T8110_V1 && m->config[1]==DEVICE_DART_ANE_INIT_V1)) {
            if (m->kind!=DEVICE_DART_T8110_V1 ||
                m->base<0x401800000 || m->base>=0x401860000) return 0;
            unsigned bank=(unsigned)(m->base-0x401800000)/0x20000;
            if ((m->base-0x401800000)%0x20000 || (found&(4U<<bank)) || !valid(m) ||
                m->span!=(bank ? 0x20000UL : 0xc000UL) || m->config[0]!=16 ||
                (m->config[1]!=44 && m->config[1]!=DEVICE_DART_ANE_INIT_V1) ||
                (policy && policy!=m->config[1]) ||
                m->config[2]!=656 || m->config[3]!=36 ||
                m->config[4]!=(m->config[1]==DEVICE_DART_ANE_INIT_V1 ? 1u : 0u))
                return 0;
            policy=m->config[1];
            found|=4U<<bank;banks[bank]=i;
        }
    }
    return found==63;
}

static int single_media_binding(const struct device_model *models, unsigned count,
                                unsigned *pmgr, unsigned *pmp, unsigned *dart, int prores)
{
    const uint64_t base=prores ? 0x295020000UL : 0x381020000UL;
    const uint64_t binding=1UL<<(prores ? 3 : 4);
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 8 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if (m->kind==DEVICE_DART_T8110_V1 &&
            (m->base==base || (m->config[4]&binding))) {
            if ((found&4) || !valid(m) || m->base!=base || m->span!=0x20000 ||
                m->config[0]!=(prores ? 1u : 16u) || m->config[1]!=44 ||
                m->config[2]!=(prores ? 1257u : 943u) ||
                m->config[3]!=36 || m->config[4]!=binding) return 0;
            found|=4;*dart=i;
        }
    }
    return found==15;
}

static int isp_dart_model(const struct device_model *m)
{
    return m->kind==DEVICE_DART_T8110_V1 && (m->config[2]==341 ||
        (m->base>=0x3228c0000 && m->base<0x322920000));
}

static int isp_system_binding(const struct device_model *models, unsigned count,
                             unsigned *pmgr, unsigned *pmp, unsigned banks[3])
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 32 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if (isp_dart_model(m)) {
            if (m->base<0x3228c0000 || m->base>=0x322920000 ||
                (m->base-0x3228c0000)%0x20000) return 0;
            unsigned bank=(unsigned)(m->base-0x3228c0000)/0x20000;
            if ((found&(4U<<bank)) || !valid(m) || m->span!=0xc000 ||
                m->config[0]!=16 || m->config[1]!=44 || m->config[2]!=341 ||
                m->config[3]!=36 || m->config[4]) return 0;
            found|=4U<<bank;banks[bank]=i;
        }
    }
    return found==63;
}

static int venc_dart_unit(const struct device_model *m)
{
    if (m->kind!=DEVICE_DART_T8110_V1) return -1;
    if (m->config[2]==955 || (m->base>=0x285080000 && m->base<0x2850c0000)) return 0;
    if (m->config[2]==967 || (m->base>=0x289080000 && m->base<0x2890c0000)) return 1;
    return -1;
}

static int venc_binding(const struct device_model *models, unsigned count,
    unsigned *pmgr, unsigned *pmp, unsigned *pmc, unsigned banks[2][2])
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 128 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if (m->kind==DEVICE_PMC_DVMR_CONFIG_V1) {
            if ((found&64) || !valid(m) || m->base!=0x3028a4000) return 0;
            found|=64;*pmc=i;
        }
        int unit=venc_dart_unit(m);
        if (unit>=0) {
            uint64_t base=unit ? 0x289080000UL : 0x285080000UL;
            if (m->base!=base && m->base!=base+0x20000) return 0;
            unsigned bank=m->base!=base,bit=4U<<(2*(unsigned)unit+bank);
            if ((found&bit) || !valid(m) || m->span!=0xc000 ||
                m->config[0]!=16 || m->config[1]!=44 ||
                m->config[2]!=(unit ? 967u : 955u) || m->config[3]!=36 || m->config[4]) return 0;
            found|=bit;banks[unit][bank]=i;
        }
    }
    return found==255;
}

struct ave_owners { unsigned control, tvm, pmgr, pmp, pmc, banks[2][2]; };

static int ave_binding(const struct device_model *models, unsigned count,
                       struct ave_owners *a)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        /* No encoder execution or APF backend is admitted. A future
         * producer in these source-DT windows must extend AVE ownership. */
        static const uint64_t absent[5][2]={
            {0x285100000,0x45c000},{0x285800000,0x800000},{0x285050000,0x4000},
            {0x285094000,0x4000},{0x2850b0000,0x4000}};
        for (unsigned u=0;u<2;u++) for (unsigned w=0;w<5;w++)
            if (overlaps(m->base,m->span,absent[w][0]+u*0x4000000UL,absent[w][1])) return 0;
        if (m->kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
            if ((found&1) || !valid(m) || m->base!=0x300780000 ||
                m->config[0]!=DEVICE_PMGR_AVE_CLUSTER_V1) return 0;
            found|=1;a->control=i;
        }
        if (m->kind==DEVICE_PMGR_AVE_TVM_IDLE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x300760000) return 0;
            found|=2;a->tvm=i;
        }
    }
    return found==3 && venc_binding(models,count,&a->pmgr,&a->pmp,&a->pmc,a->banks);
}

static int ave_registry_valid(const struct device_model *models, unsigned count)
{
    struct ave_owners a={0};
    return ave_binding(models,count,&a);
}

static int image_dart_kind(const struct device_model *m)
{
    if (m->kind!=DEVICE_DART_T8110_V1) return 0;
    if (m->base==0x291260000 || (m->config[4]&(1U<<19))) return 1;
    if (m->base==0x28d020000 || m->base==0x28d080000 || (m->config[4]&(7U<<13))) return 2;
    return 0;
}

static int image_system_binding(const struct device_model *models, unsigned count,
    unsigned *pmgr, unsigned *pmp, unsigned banks[2], int jpeg)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 16 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
        if (image_dart_kind(m)==(jpeg ? 2 : 1)) {
            unsigned bank=jpeg && m->base==0x28d080000;
            uint64_t base=jpeg ? (bank ? 0x28d080000UL : 0x28d020000UL) : 0x291260000UL;
            uint64_t mask=jpeg ? (bank ? 1U<<15 : 3U<<13) : 1U<<19;
            if ((found&(4U<<bank)) || !valid(m) || m->base!=base ||
                m->span!=(jpeg ? 0xc000u : 0x20000u) ||
                m->config[0]!=(jpeg ? (bank ? 1u : 2u) : 16u) || m->config[1]!=44 ||
                m->config[2]!=(jpeg ? (bank ? 1044u : 1041u) : 1087u) ||
                m->config[3]!=36 || m->config[4]!=mask) return 0;
            found|=4U<<bank;banks[bank]=i;
        }
    }
    return found==(jpeg ? 31u : 23u);
}

static int gfx_binding(const struct device_model *models, unsigned count,
    unsigned *pmgr, unsigned *pmp, unsigned *bridge)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        /* SGX's aperture includes both ASCs and one already-modeled AXI2AF
         * policy page. Retain that exact configuration-only model. Every
         * additional producer must extend power-resource admission. */
        if ((m->base>=0x480000000 && m->base<0x484000000) ||
            (m->base<0x480000000 && m->span>0x480000000-m->base)) {
            if ((found&8) || m->kind!=DEVICE_PMGR_AXI2AF_POLICY_V1 ||
                m->base!=0x481000000 || !valid(m)) return 0;
            found|=8;*bridge=i;
        }
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 4 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL)) return 0;
            found|=bit;if (!m->config[0]) *pmgr=i;
        }
        if (m->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            if ((found&2) || !valid(m) || m->base!=0x3003c0000) return 0;
            found|=2;*pmp=i;
        }
    }
    return found==15;
}

static enum device_result pmp_actual_states(const struct device_model *model,
    struct device_state *state, uint64_t *mask)
{
    /* Exact physical soc-device rows. Unrequested is not synonymous with
     * off; each ACK bit is derived from its registered PS word. */
    static const uint16_t offsets[12]={0x50,0x58,0x1f0,0x268,0x280,0x288,
                                     0x250,0x240,0x248,0x270,0x238,0x230};
    static const uint8_t bits[12]={7,8,9,11,12,13,14,15,16,17,18,19};
    uint64_t result=0;
    for (unsigned i=0;i<12;i++) {
        uint64_t value=0;
        enum device_result r=pmgr_boot_access(model,state,offsets[i],4,0,&value,PMGR_PREFLIGHT);
        if (r!=DEVICE_OK) return r;
        unsigned level=((unsigned)value>>4)&15;
        if (level!=0 && level!=15) return DEVICE_BAD_VALUE;
        if (level==15) result|=1UL<<bits[i];
    }
    *mask=result;return DEVICE_OK;
}

static enum device_result ave_idle(const struct device_model *models,
    struct device_state *states, const struct ave_owners *a)
{
    uint64_t actual=0,enc=DEVICE_PMP_VENC0_BIT|DEVICE_PMP_VENC1_BIT;
    enum device_result r=pmp_actual_states(&models[a->pmgr],&states[a->pmgr],&actual);
    if (r!=DEVICE_OK) return r;
    if (actual!=states[a->pmp].pmp_active.ack ||
        (states[a->pmp].pmp_active.request&enc) || (actual&enc)) return DEVICE_BAD_VALUE;
    for (unsigned c=0;c<10;c++) {
        uint64_t ps=0;
        r=pmgr_boot_access(&models[a->pmgr],&states[a->pmgr],0x8000+8*c,4,0,&ps,PMGR_PREFLIGHT);
        if (r!=DEVICE_OK) return r;
        if (ps&15) return DEVICE_BAD_VALUE;
    }
    for (unsigned u=0;u<2;u++) for (unsigned b=0;b<2;b++)
        if (!dart_runtime_idle(&states[a->banks[u][b]].dart,0)) return DEVICE_BAD_VALUE;
    return DEVICE_OK;
}

/* The TVM backend has never admitted sampling or a job. Its disabled/idle
 * response is backed by both encoder systems, all children and DART banks.
 * Enable is deliberately refused until the demanded TVM work is implemented. */
static enum device_result ave_access(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    const struct device_model *m=&models[index];
    int tvm=m->kind==DEVICE_PMGR_AVE_TVM_IDLE_V1;
    int ctl=m->kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && offset==8;
    int rail=m->kind==DEVICE_PMC_DVMR_CONFIG_V1 && (offset==0x5c18 || offset==0x5c1c);
    int ps=m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && !m->config[0] &&
        (offset==0x240 || offset==0x248 || (offset>=0x8000 && offset<=0x8048));
    int dart=venc_dart_unit(m)>=0;
    int pmp=m->kind==DEVICE_PTD_PMP_ACTIVE_V1;
    if (!tvm && !ctl && !rail && !ps && !dart && !pmp) return DEVICE_NOT_FOUND;
    unsigned enabled=0;
    for (unsigned i=0;i<count;i++)
        enabled|=models[i].kind==DEVICE_PMGR_AVE_TVM_IDLE_V1 ||
            (models[i].kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && models[i].config[0]);
    if (!enabled) return DEVICE_NOT_FOUND;
    struct ave_owners a={0};
    if (!ave_binding(models,count,&a)) return DEVICE_BAD_CONFIG;
    uint32_t current=states[a.control].pmgr_ave_cluster;
    uint32_t supply=states[a.pmc].pmc_dvmr.venc_cluster;
    if ((current!=0 && current!=15) || (supply!=0 && supply!=8) ||
        (current && !supply)) return DEVICE_BAD_VALUE;
    if (!current || tvm || (ctl && write && !*value)) {
        enum device_result r=ave_idle(models,states,&a);
        if (r!=DEVICE_OK) return r;
    }
    if (tvm || ctl) {
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (tvm) {
            if (offset!=0x400 && offset!=0x7e0) return DEVICE_UNKNOWN_REGISTER;
            if (write && offset!=0x400) return DEVICE_UNKNOWN_REGISTER;
            if (write && *value) return DEVICE_BAD_VALUE;
            if (!write) *value=0;
        } else {
            if (write) {
                if (*value!=0 && *value!=15) return DEVICE_BAD_VALUE;
                if (*value && supply!=8) return DEVICE_BAD_VALUE;
                states[a.control].pmgr_ave_cluster=(uint32_t)*value;
            } else *value=current;
        }
        return DEVICE_OK;
    }
    if (rail && write && offset==0x5c18 && !*value && current) return DEVICE_BAD_VALUE;
    if (!current && ((ps && write && (*value&15)) || dart ||
        (pmp && write && offset==0x10c40 &&
         (*value&(DEVICE_PMP_VENC0_BIT|DEVICE_PMP_VENC1_BIT))))) return DEVICE_BAD_VALUE;
    return DEVICE_NOT_FOUND;
}

/* T8140 restoreACC ends with a fixed write at f8. ClusterPerfSampler then
 * programs ten event selectors, or writes zero to disable them. Retain these
 * configuration writes; event-counter values and effects are not fabricated.
 * Validate restoration prerequisites and all local state before any change. */
static enum device_result acc_boot_access(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    const struct device_model *m=&models[index];
    if (!valid(m)) return DEVICE_BAD_CONFIG;
    if (offset>=m->span) return DEVICE_NOT_FOUND;
    if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
    static const uint64_t selectors[10]={
        0x8a0f,0x800f,0x8c0f,0x9c0f,0x9e0f,
        0x810f,0xb90f,0xbe0f,0xbf0f,0xd40f,
    };
    unsigned slot=10;
    if (offset>=0x18 && offset<=0xa8 && !((offset-0x18)&15))
        slot=(unsigned)(offset-0x18)/16;
    if (offset!=0xf8 && slot==10) return DEVICE_UNKNOWN_REGISTER;
    struct device_state *s=&states[index];
    if (!write || s->acc_boot_policy>1 || (s->acc_selector_written&~0x3ffUL) ||
        (!s->acc_boot_policy && s->acc_selector_written) ||
        (slot==10 ? *value!=1 :
         (!s->acc_boot_policy || (*value && *value!=selectors[slot]))))
        return DEVICE_BAD_VALUE;
    for (unsigned i=0;i<10;i++)
        if ((s->acc_selectors[i] && s->acc_selectors[i]!=selectors[i]) ||
            (!(s->acc_selector_written&(1UL<<i)) && s->acc_selectors[i]))
            return DEVICE_BAD_VALUE;
    unsigned cluster=(unsigned)m->config[0], cores=cluster ? 2 : 4;
    uint64_t base=0x210000000UL+cluster*0x1000000UL;
    if (m->base!=base+0xe44000) return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++)
        if (i!=index && models[i].base==m->base) return DEVICE_BAD_CONFIG;
    for (unsigned bank=0;bank<cores+2;bank++) {
        unsigned kind=bank==cores+1 ? DEVICE_PMGR_DVMR_WEIGHTS_V1 : DEVICE_PMGR_ENERGY_RESTORE_V1;
        uint64_t expected=base+(bank<cores ? 0x59000UL+bank*0x100000UL :
                               bank==cores ? 0xe48000UL : 0xe70000UL);
        unsigned found=count;
        for (unsigned i=0;i<count;i++)if(models[i].base==expected) {
            if (found!=count || !valid(&models[i]) || models[i].kind!=kind ||
                models[i].config[0]!=(bank==cores+1 ? cluster : 0))
                return DEVICE_BAD_CONFIG;
            found=i;
        }
        if (found==count) return DEVICE_BAD_CONFIG;
        if (bank==cores+1) {
            if (states[found].pmgr_energy_control!=0xa800000000000000UL)
                return DEVICE_BAD_VALUE;
        } else if (states[found].energy_restore.written!=3) return DEVICE_BAD_VALUE;
    }
    if (slot==10) s->acc_boot_policy=1;
    else {
        s->acc_selectors[slot]=*value;
        s->acc_selector_written|=1UL<<slot;
    }
    return DEVICE_OK;
}

