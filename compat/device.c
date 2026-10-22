/* SPDX-License-Identifier: MIT */
#include "device.h"
#include "ans.h"

_Static_assert(sizeof(struct device_model) == DEVICE_MODEL_WORDS * 8,
               "device descriptor loader ABI");

static int sep_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned *dart);
static int ane_binding(const struct device_model *models, unsigned count,
                       unsigned *pmgr, unsigned *pmp, unsigned banks[3]);
static int sep_asc_valid(const struct device_sep_asc *s, unsigned transport);
static enum device_result sep_asc_receive(struct device_sep_asc *s, uint64_t values[2]);
static enum device_result spmi_access(const struct device_model *d,
    struct device_state *s, uint64_t now, uint64_t offset, unsigned width,
    int write, uint64_t *value);

static uint64_t gpio_route(const struct device_model *d, unsigned index)
{
    if (d->kind == DEVICE_GPIO_UART_RX_IDLE_V1)
        return index < 2 ? d->config[3+index] : 0;
    if (d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 && index < 6)
        return (d->config[3+index/3] >> (18*(index%3))) & 0x3ffff;
    if (d->kind == DEVICE_GPIO_IDLE_PADS_V2 && index < 8) {
        uint64_t raw=(d->config[3+index/4] >> (11*(index%4))) & 0x7ff;
        return (raw&0x1ff) | ((raw>>9)<<16);
    }
    return 0;
}

static int gpio_idle_input(const struct device_model *d, unsigned pin, unsigned mux)
{
    uint64_t route=(pin+1) | ((uint64_t)mux << 16);
    for (unsigned i=0; i<8; i++) if (gpio_route(d,i) == route) return 1;
    return 0;
}

static int valid(const struct device_model *d)
{
    if (!d || !d->span || ((d->base | d->span) & 0xfff) ||
        d->base >= (1UL << 36) || d->span > (1UL << 36) - d->base)
        return 0;
    if (d->kind == DEVICE_MCC_COHERENT_V1) {
        if (!d->config[0] || d->config[0] > 4 ||
            d->span < (d->config[0]-1)*0x40000 + 0x2e008 ||
            d->span < 0x102804) return 0;
    } else if (d->kind == DEVICE_MCC_DCS_COHERENT_V1) {
        if (d->config[0] || d->span < 0x4070) return 0;
    } else if (d->kind == DEVICE_MCC_SOCNI_V1) {
        if (!d->config[0] || d->config[0] > 64 ||
            d->span < 0x4000 + 8*d->config[0]) return 0;
    } else if (d->kind == DEVICE_WATCHDOG_WD1_V1) {
        if (!d->config[0] || d->config[0] > UINT32_MAX) return 0;
    } else if (d->kind == DEVICE_WATCHDOG_SMC_DISARM_V1) {
        if (d->span!=0x1000 || d->config[0]!=8) return 0;
    } else if (d->kind == DEVICE_AOP_TIMEBASE_V1) {
        if (d->span != 0x1000 || d->config[0] != 24000000) return 0;
    } else if (d->kind == DEVICE_PMGR_ACTIVE_BOOT_V1) {
        if (d->config[0]>1 || d->span!=(d->config[0] ? 0x9000UL : 0x11000UL)) return 0;
        return d->config[1]<=(d->config[0] ? 0 : DEVICE_PMGR_CPU0_BOOT_V1) &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_PMGR_AON_FUSES_V1) {
        if (d->config[0] || d->span!=0x4000) return 0;
    } else if (d->kind == DEVICE_PMGR_CPU_PERF_BOOT_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1) {
        if ((d->config[0]!=6 && d->config[0]!=7) || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1) {
        if (d->config[0]>5 || d->span!=(d->config[0]==0 ? 0x2000UL :
                d->config[0]==1 ? 0x3000UL : 0x1000UL)) return 0;
    } else if (d->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        if (d->config[0]>1 || d->span!=0x2000) return 0;
    } else if (d->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) {
        if (d->config[0]>1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_LLT_DISABLED_V1) {
        if (d->base!=0x300740000 || d->span!=0x1000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_CORESIGHT_LOCK_V1) {
        uint64_t cpu=d->config[0];
        if (cpu>5 || d->span!=0x1000 || d->base !=
            (cpu<4 ? 0x210010000UL+cpu*0x100000 :
                     0x211010000UL+(cpu-4)*0x100000)) return 0;
    } else if (d->kind == DEVICE_QSPI_BOOT_V1) {
        if (d->span!=0x5000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_DWI_STARTUP_V1) {
        if (d->base!=0x300200000 || d->span!=0x4000 || d->config[0]) return 0;
    } else if (d->kind == DEVICE_I2C_EMPTY_V1) {
        return d->base==0x385018000UL && d->span==0x4000 &&
            d->config[0]==2 && d->config[1]==6 && d->config[2]==1110 &&
            !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_SEP_ASC_MAILBOX_V1) {
        return d->base==0x282600000UL && d->span==0x9000 &&
            d->config[0]==DEVICE_SEP_ASC_MESSAGES &&
            d->config[1]<=1 && d->config[2]==(d->config[1] ? 346 : 0) &&
            d->config[3]==(d->config[1] ? 343 : 0) &&
            (!d->config[4] || (d->config[1] &&
                (d->config[4]==1 || d->config[4]==3 || d->config[4]==7 ||
                 d->config[4]==11 || d->config[4]==15 ||
                 d->config[4]==19 || d->config[4]==27 || d->config[4]==59)));
    } else if (d->kind == DEVICE_PMGR_AP_WAKE_MASK_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
        if (d->config[0]>DEVICE_PMGR_AVE_CLUSTER_V1 || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_ENERGY_RESTORE_V1 ||
               d->kind == DEVICE_PMGR_AVE_TVM_IDLE_V1 ||
               d->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1 ||
               d->kind == DEVICE_PMGR_AXI2AF_POLICY_V1 ||
               d->kind == DEVICE_PMC_ENABLE_POLICY_V1 ||
               d->kind == DEVICE_PMC_RMBS_REQUEST_V1) {
        if (d->config[0] || d->span!=0x1000) return 0;
    } else if (d->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1) {
        if (d->config[0] || d->span!=0x3000) return 0;
    } else if (d->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        if (d->config[0] || d->span!=0x6000) return 0;
    } else if (d->kind == DEVICE_DART_T8110_V1) {
        return (d->span==0xc000 || d->span==0x20000) &&
            d->config[0] && d->config[0]<=DART_STREAMS &&
            (d->config[1]==44 || (d->config[1]==DEVICE_DART_SIO_BOOT_V1 &&
                d->config[0]==16 && d->span==0x20000 && d->config[4] &&
                !(d->config[4]&(d->config[4]-1))) ||
             (d->config[1]==DEVICE_DART_SEP_BOOT_V1 && d->base==0x280b80000UL &&
                d->span==0x20000 && d->config[0]==3 && d->config[2]==353 &&
                d->config[4]==(1U<<20)) ||
             (d->config[1]==DEVICE_DART_ADRENO_BOOT_V1 && d->span==0x20000 &&
                d->config[0]==16 && d->config[4]==(1UL<<31)) ||
             (d->config[1]==DEVICE_DART_ANE_INIT_V1 &&
                ((d->base==0x401800000UL && d->span==0xc000) ||
                 ((d->base==0x401820000UL || d->base==0x401840000UL) && d->span==0x20000)) &&
                d->config[0]==16 && d->config[2]==656 && d->config[4]==1)) &&
            d->config[2]<AIC_MAX_IRQS && d->config[3]==36 && !(d->config[4]>>32);
    } else if (d->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || d->kind == DEVICE_SPMI_PMU_RTC_V1) {
        return d->config[0] >= 0x8000 && !(d->config[0] & 0x3fff) &&
            d->config[0] <= d->span && d->span-d->config[0] == 0x4000 &&
            d->config[1] >= 0x4000 && !(d->config[1] & 0x3fff) &&
            d->config[1] <= d->config[0]-0x4000 && d->config[2] < AIC_MAX_IRQS &&
            (d->kind == DEVICE_SPMI_GEN3_EMPTY_V1 ?
             d->config[3] == DEVICE_SPMI_FIFO_MAX && d->config[4] == DEVICE_SPMI_FIFO_MAX :
             d->base == UINT64_C(0x308700000) && d->config[0] == 0x14000 &&
             d->config[1] == 0x4000 && d->config[2] == 487 && d->config[3] <= PMU_RTC_LIMIT_US &&
             d->config[4] == PMU_RTC_CONTRACT);
    } else if (d->kind == DEVICE_GPIO_QUIET_V1 || d->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
               d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || d->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        int route=!d->config[3] && !d->config[4];
        if (d->kind != DEVICE_GPIO_QUIET_V1) {
            route=gpio_route(d,0) != 0;
            if (d->kind == DEVICE_GPIO_IDLE_INPUTS_V1 &&
                ((d->config[3] | d->config[4]) >> 54)) route=0;
            if (d->kind == DEVICE_GPIO_IDLE_PADS_V2 &&
                ((d->config[3] | d->config[4]) >> 44)) route=0;
            for (unsigned i=0; i<8; i++) if (gpio_route(d,i)) {
                uint64_t word=gpio_route(d,i), pin=word & 0xffff, mux=word >> 16;
                route &= pin && pin <= d->config[0] && mux >= 1 && mux <= 3;
                for (unsigned j=0; j<i; j++)
                    if ((gpio_route(d,j) & 0xffff) == pin) route=0;
            }
        }
        return d->config[0] && d->config[0] <= DEVICE_GPIO_PINS_MAX &&
            d->config[1] && d->config[1] <= 7 && d->config[2] &&
            !(d->config[2] >> d->config[1]) && route &&
            d->span >= 0x800 + d->config[1]*0x40;
    } else if (d->kind == DEVICE_DOCK_ABSENT_V1) {
        uint64_t mask=d->config[1];
        return d->span == 0x1000 && !(d->config[0] & 3) &&
            d->config[0] <= d->span-4 && mask && mask <= UINT32_MAX &&
            !(mask & (mask-1)) && !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_DOCK_FIFO_V1) {
        /* Single channel, six audited t8002 windows. Holes stay trapped. */
        return d->span == 0x35000 && d->config[0] == 0x14000 &&
            d->config[1] == 0x28000 && d->config[2] < AIC_MAX_IRQS &&
            d->config[3] == DEVICE_DOCK_FIFO_MAX && !d->config[4];
    } else if (d->kind == DEVICE_SOCNI_ERRORS_V1) {
        return d->span == 0x4000 && d->config[0] < 6 && !d->config[1] &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_PLATFORM_ERROR_POLICY_V1) {
        return ((d->span == 0x1000 && d->config[0] == 0x104 && d->config[1] == 1) ||
                (d->span == 0x20000 && d->config[0] == 0x4084 && !d->config[1])) &&
               !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_AES_IDLE_V1) {
        return d->span==0x4000 && d->config[0]==5 && !d->config[1] &&
            !d->config[2] && !d->config[3] && !d->config[4];
    } else if (d->kind == DEVICE_AES_SOFTWARE_V1) {
        return d->span==0x4000 && d->config[0]==5 && d->config[1]==42 &&
            d->config[2]==1107 && d->config[3]==21 && d->config[4]==1;
    } else if (d->kind == DEVICE_AES_NO_KEYS_V1) {
        /* config[4]: zero, or PMGR's BPR word, aligned, inside, never a key word. */
        if (d->config[4] && ((d->config[4] & 3) || d->config[4] > d->span-4)) return 0;
        for (unsigned i=0; i<4; i++) {
            if ((d->config[i] & 3) || d->config[i] > d->span-4 ||
                (d->config[4] && d->config[i] == d->config[4])) return 0;
            for (unsigned j=0; j<i; j++)
                if (d->config[i] == d->config[j]) return 0;
        }
        return 1;
    } else if (d->kind == DEVICE_PTD_PMP_ACTIVE_V1) {
        /* Pinned single-instance AP voter 0 plus the MCC transport. */
        return d->span==0x14000 && d->config[0]==0x10000 &&
            d->config[1]==0x1a8 && d->config[2]==0x1b8 && d->config[3]==8 &&
            d->config[4]==DEVICE_PMP_ACTIVE_MASK;
    } else if (d->kind == DEVICE_MCC_PTD_COHERENT_V1) {
        uint64_t update=d->config[0], request=d->config[1];
        uint64_t reply=d->config[2], quotas=d->config[3];
        /* One state owns both apertures. The intervening gap is not a
         * register bank and access to it remains an explicit refusal. */
        return update >= 0x4000 && !(update & 0xfff) &&
            update <= d->span && d->span-update == 0x4000 &&
            quotas && quotas <= 8 && request <= 1024-quotas-2 &&
            reply <= 1024-quotas-1 &&
            (request+quotas+2 <= reply || reply+quotas+1 <= request) &&
            !d->config[4];
    } else if (d->kind == DEVICE_ANS_ASC_V1 || d->kind == DEVICE_ANS_NVME_V1) {
        int nvme=d->kind == DEVICE_ANS_NVME_V1;
        return d->base==(nvme ? 0x38dcc0000UL : 0x389600000UL) &&
            d->span==(nvme ? 0x60000UL : 0x9000UL) && d->config[0] &&
            !(d->config[0]&0x3fff) && d->config[0] < (1UL<<36)-ANS_DISK_OFFSET-ANS_DISK_MAX &&
            (nvme ? d->config[2]==1039 &&
                    (d->config[3]==ANS_WINDOW_MODE ?     /* full-install M6: the SSD window */
                     !(d->config[0]&0xfffff) && d->config[1]>=(1UL<<30) && !(d->config[1]&0xfffff) :
                     !d->config[3] && d->config[1] && !(d->config[1]&0xfff) && d->config[1]<=ANS_DISK_MAX) :
                    d->config[1]==1010 && d->config[2]==1007 && !d->config[3]) &&
            !d->config[4];
    } else if (d->kind == DEVICE_AIC3_FLAT_V1) {
        /* Single virtual die; fixed capacity preserves the audited 0x4a00
         * bank stride. EVENT placement is published to the guest DT. */
        return d->config[0] && d->config[0] <= 4096 &&
            !(d->config[0] & 31) && d->config[1] == 4096 &&
            d->config[2] >= 0x14a00 && !(d->config[2] & 3) &&
            d->config[2] <= d->span - 4 && d->config[3] == 0xa && !d->config[4];
    } else return 0;
    for (unsigned i=1; i<5; i++) if (d->config[i]) return 0;
    return 1;
}

static int overlaps(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    if (!m) return 0;
    /* Difference form avoids wrapping either end. */
    return a >= b ? a-b < m : b-a < n;
}

enum device_result device_latch_resets(const struct device_model *models,
    const struct device_state *states, unsigned count,
    uint64_t bitmap[DEVICE_RESET_WORDS])
{
    if (!bitmap || count>DEVICE_MODEL_MAX || (count && (!models || !states)))
        return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++) if (!valid(&models[i])) return DEVICE_BAD_CONFIG;
    for (unsigned i=0;i<count;i++) if (device_reset_pending(&models[i],&states[i]))
        bitmap[i/64] |= 1UL<<(i%64);
    return DEVICE_OK;
}

static int cpu_boot_registry(const struct device_model *models, unsigned count)
{
    unsigned found=0;
    for (unsigned i=0;i<count;i++) {
        const struct device_model *m=&models[i];
        if (m->kind==DEVICE_PMGR_ACTIVE_BOOT_V1) {
            unsigned bit=m->config[0] ? 2 : 1;
            if ((found&bit) || !valid(m) ||
                m->base!=(m->config[0] ? 0x308280000UL : 0x300700000UL) ||
                (!m->config[0] && m->config[1]!=DEVICE_PMGR_CPU0_BOOT_V1)) return 0;
            found|=bit;
        }
        if (m->kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
            if ((found&4) || !valid(m) || m->base!=0x300780000) return 0;
            found|=4;
        }
    }
    return found==7;
}

int device_models_boot_cpu_valid(const struct device_model *models, unsigned count,
                                uint64_t boot_mpidr)
{
    if (!models || !count || count>DEVICE_MODEL_MAX) return 0;
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && models[i].config[1])
            return boot_mpidr==0x80000000 && cpu_boot_registry(models,count);
    return 1;
}

static int ave_registry_valid(const struct device_model *models, unsigned count);

int device_models_valid(const struct device_model *models, uint64_t count,
                        const struct device_range *exclude, uint64_t excluded)
{
    if (count > DEVICE_MODEL_MAX || (count && !models) || (excluded && !exclude))
        return 0;
    for (uint64_t j=0; j<excluded; j++)
        if (exclude[j].span > UINT64_MAX-exclude[j].base) return 0;
    for (uint64_t i=0; i<count; i++) {
        if (!valid(&models[i])) return 0;
        if ((models[i].kind==DEVICE_PMGR_AVE_TVM_IDLE_V1 ||
             (models[i].kind==DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && models[i].config[0])) &&
            !ave_registry_valid(models,(unsigned)count)) return 0;
        if (models[i].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && models[i].config[1] &&
            !cpu_boot_registry(models,(unsigned)count)) return 0;
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            /* PMP actual states come from both registered PMGR banks.
             * AVD has registry-owned power/vote transitions; other covered
             * systems remain active. Encoder/ISP child subdomains are not
             * PMP rows and cannot independently change a system ACK. */
            unsigned groups=0;
            for (uint64_t j=0;j<count;j++)
                if (models[j].kind==DEVICE_PMGR_ACTIVE_BOOT_V1 && valid(&models[j]) &&
                    models[j].base==(models[j].config[0] ? 0x308280000UL : 0x300700000UL))
                    groups|=1U<<(unsigned)models[j].config[0];
            if (groups!=3) return 0;
        }
        if (models[i].kind==DEVICE_ANS_ASC_V1 || models[i].kind==DEVICE_ANS_NVME_V1) {
            /* Exactly one pair, sharing one reservation that misses every
             * guest, framebuffer, work and device range. */
            unsigned pair=0;uint64_t span=0;
            for (uint64_t j=0;j<count;j++)
                if (models[j].kind==DEVICE_ANS_ASC_V1 || models[j].kind==DEVICE_ANS_NVME_V1) {
                    if (models[j].config[0]!=models[i].config[0]) return 0;
                    pair+=models[j].kind==DEVICE_ANS_ASC_V1 ? 1 : 16;
                    if (models[j].kind==DEVICE_ANS_NVME_V1)
                        span=models[j].config[3]==ANS_WINDOW_MODE ? ANS_WINDOW_BYTES :
                             ANS_DISK_OFFSET+models[j].config[1];
                }
            if (pair!=17) return 0;
            for (uint64_t j=0; j<excluded; j++)
                if (overlaps(models[i].config[0], span,
                             exclude[j].base, exclude[j].span)) return 0;
        }
        for (uint64_t j=0; j<i; j++)
            if (overlaps(models[i].base, models[i].span, models[j].base, models[j].span))
                return 0;
        for (uint64_t j=0; j<excluded; j++)
            if (overlaps(models[i].base, models[i].span, exclude[j].base, exclude[j].span))
                return 0;
    }
    return 1;
}

int device_model_find(const struct device_model *models, uint64_t count,
                      uint64_t ipa, uint64_t *offset)
{
    if (!models || count > DEVICE_MODEL_MAX || !offset) return -1;
    for (uint64_t i=0; i<count; i++)
        if (ipa >= models[i].base && ipa-models[i].base < models[i].span) {
            *offset=ipa-models[i].base;
            return (int)i;
        }
    return -1;
}

enum device_result device_model_access(const struct device_model *model,
    uint64_t offset, unsigned width, int write, uint64_t *value)
{
    return device_model_access_state(model, 0, offset, width, write, value);
}

enum device_result device_model_start(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t frequency)
{
    if (!valid(model) || !state) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_AES_NO_KEYS_V1) {
        for (unsigned i=0;i<4;i++) state->aes_key_disable_writes[i]=0;
        state->aes_pmgr_bpr=state->aes_pmgr_bpr_reads=state->aes_pmgr_bpr_writes=0;
    }
    if (model->kind == DEVICE_AES_SOFTWARE_V1) {
        volatile uint8_t *p=(volatile uint8_t *)&state->aes;
        for (unsigned i=0;i<sizeof(state->aes);i++) p[i]=0;
        state->aes.ready=1;
    }
    if (model->kind == DEVICE_AES_IDLE_V1) {
        state->aes_idle.ready=1;
        state->aes_idle.running=state->aes_idle.irq_enable=state->aes_idle.fifo_threshold=0;
        state->aes_idle.starts=state->aes_idle.stops=0;
        state->aes_idle.reads=state->aes_idle.writes=0;
    }
    if (model->kind == DEVICE_DART_T8110_V1) dart_init(&state->dart);
    if (model->kind == DEVICE_PMGR_ACTIVE_BOOT_V1) {
        for (unsigned i=0;i<128;i++) state->pmgr_policy[i]=0;
        for (unsigned i=0;i<10;i++) state->pmgr_venc[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<13;i++) state->pmgr_isp[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<3;i++) state->pmgr_atc[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<2;i++) state->pmgr_dpa[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<5;i++) state->pmgr_spi[i]=state->pmgr_i2c[i]=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<5;i++) state->pmgr_aux[i]=model->config[0] ? 0 : 15;
        state->pmgr_ane=model->config[0] ? 0 : 15;
        state->pmgr_avd=model->config[0] ? 0 : 15;
        state->pmgr_isp_sys=model->config[0] ? 0 : 15;
        state->pmgr_prores=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<2;i++) state->pmgr_venc_sys[i]=model->config[0] ? 0 : 15;
        state->pmgr_msr=state->pmgr_jpg=model->config[0] ? 0 : 15;
        state->pmgr_gfx=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<3;i++) state->pmgr_misc[i]=model->config[0] ? 0 : 15;
        state->pmgr_sep_aon=model->config[0] ? 0 : 15;
        for (unsigned i=0;i<8;i++)
            state->pmgr_cpu_boot[i]=model->config[1] && (i==0 || i>=6) ? 0xf0 : 0;
        state->pmgr_cpu_reads=state->pmgr_cpu_writes=0;
        state->pmgr_aes=model->config[0] ? 0 : 15;
    }
    if (model->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1)
        for (unsigned i=0;i<70;i++) state->pmgr_counter_config[i]=0;
    if (model->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1) {
        for (unsigned i=0;i<296;i++) state->pmgr_perf.control[i]=0;
        for (unsigned i=0;i<39;i++) state->pmgr_perf.extra[i]=0;
        for (unsigned i=0;i<295;i++) state->pmgr_perf.written[i]=0;
        for (unsigned i=0;i<256;i++) state->counter[i/64][i%64]=0;
    }
    if (model->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        for (unsigned i=0;i<72;i++) state->acc_perf.values[i]=0;
        state->acc_perf.written[0]=state->acc_perf.written[1]=0;
    }
    if (model->kind == DEVICE_PMGR_ENERGY_RESTORE_V1) {
        state->energy_restore.values[0]=state->energy_restore.values[1]=0;
        state->energy_restore.written=0;
    }
    if (model->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1)
        state->pmgr_energy_control=0;
    if (model->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) {
        state->acc_boot_policy=0;
        state->acc_selector_written=0;
        for (unsigned i=0;i<10;i++) state->acc_selectors[i]=0;
    }
    if (model->kind == DEVICE_PMGR_LLT_DISABLED_V1)
        state->pmgr_llt_limit=0;
    if (model->kind == DEVICE_CORESIGHT_LOCK_V1)
        state->coresight_unlocked=0;
    if (model->kind == DEVICE_QSPI_BOOT_V1) {
        for (unsigned i=0;i<DEVICE_QSPI_FIFO_WORDS;i++)
            state->qspi.tx[i]=state->qspi.rx[i]=0;
        state->qspi.tx_count=state->qspi.rx_count=state->qspi.resets=0;
        state->qspi.ready=1;
    }
    if (model->kind == DEVICE_DWI_STARTUP_V1) {
        for (unsigned i=0;i<5;i++) state->dwi.values[i]=0;
        state->dwi.written=0;
        state->dwi.ready=1;
    }
    if (model->kind == DEVICE_I2C_EMPTY_V1) {
        state->i2c=(struct device_i2c_empty){0};
        state->i2c.ready=1;
    }
    if (model->kind == DEVICE_SEP_ASC_MAILBOX_V1) {
        /* Keep reset freestanding as this structure grows: an aggregate
         * assignment otherwise lowers to an unavailable libc memset. */
        volatile unsigned char *bytes=(volatile unsigned char *)&state->sep_asc;
        for (unsigned i=0;i<sizeof(state->sep_asc);i++) bytes[i]=0;
        state->sep_asc.ready=1;
        state->sep_asc.enable[0]=1; /* Requests can enter the retained queue. */
    }
    if (model->kind == DEVICE_PMGR_AP_WAKE_MASK_V1)
        for (unsigned i=0;i<8;i++)
            state->pmgr_wake_mask[i]=i==7 ? 0x1fffff : UINT32_MAX;
    if (model->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1)
        for (unsigned i=0;i<4;i++) state->pmgr_soc_gate[i]=0;
    if (model->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 && model->config[0])
        state->pmgr_ave_cluster=15;
    if (model->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1)
        for (unsigned i=0;i<30;i++) state->pmgr_soc_dpe[i]=0;
    if (model->kind == DEVICE_PMGR_AXI2AF_POLICY_V1)
        for (unsigned i=0;i<2;i++) state->pmgr_axi2af[i]=0;
    if (model->kind == DEVICE_PMC_ENABLE_POLICY_V1)
        for (unsigned i=0;i<7;i++) state->pmc_enable[i]=0;
    if (model->kind == DEVICE_PMC_RMBS_REQUEST_V1)
        state->pmc_rmbs.value=state->pmc_rmbs.valid=0;
    if (model->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        state->pmc_dvmr.enabled=0;
        state->pmc_dvmr.count=state->pmc_dvmr.count_valid=0;
        /* The virtual reset starts both encoder systems active. Their
         * shared cluster is therefore active until admitted shutdown. */
        state->pmc_dvmr.venc_cluster=8;
    }
    if (model->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        for (unsigned i=0;i<256;i++) state->ptd_irq.route[i]=0;
        for (unsigned i=0;i<32;i++) state->ptd_irq.enabled[i]=0;
    }
    if (model->kind == DEVICE_PTD_PMP_ACTIVE_V1) {
        state->pmp_active.request=0;
        state->pmp_active.ack=model->config[4];
        state->pmp_active.request_updated=state->pmp_active.ack_updated=0;
        state->pmp_active.ready=state->pmp_active.ready_updated=0;
        state->pmp_active.status_reads=0;
        for (unsigned i=0;i<10;i++) state->ptd_request[i]=0;
        state->ptd_ack=0;
        state->ptd_payload_ready=0;
        state->ptd_request_updated=state->ptd_reply_updated=0;
    }
    if (model->kind == DEVICE_AOP_TIMEBASE_V1 && frequency != model->config[0])
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_WATCHDOG_SMC_DISARM_V1)
        state->watchdog_smc_disarms=0;
    if (model->kind == DEVICE_WATCHDOG_WD1_V1) {
        if (frequency != model->config[0]) return DEVICE_BAD_CONFIG;
        watchdog_init(&state->watchdog, now);
    } else if (model->kind == DEVICE_GPIO_QUIET_V1 || model->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
               model->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || model->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        unsigned group=0;
        while (!(model->config[2] & (1UL << group))) group++;
        /* Mode 7 is input with interrupts disabled. Choose a group this
         * controller supports, including sparse group sets such as MTP. */
        for (unsigned i=0; i<model->config[0]; i++)
            state->gpio_pin[i]=(group << 16) | 14;
    } else if (model->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || model->kind == DEVICE_SPMI_PMU_RTC_V1) {
        if (model->kind == DEVICE_SPMI_PMU_RTC_V1 &&
            !pmu_rtc_start(&state->pmu_rtc,model->config[3],now,frequency))
            return DEVICE_BAD_CONFIG;
#if SNAP_SPMI_SCRATCH
        if (model->kind == DEVICE_SPMI_PMU_RTC_V1) pmu_scratch_start(&state->pmu_scratch);
#endif
        state->spmi_recovery.config_reads=state->spmi_recovery.config_writes=0;
        state->spmi_recovery.fifo_clears=0;
        state->spmi.rx_head=state->spmi.rx_count=0;
        state->spmi.tx_words=state->spmi.tx_need=0;
        state->spmi.command=0;
        for (unsigned i=0; i<9; i++) state->spmi.enable[i]=state->spmi.flags[i]=0;
    } else if (model->kind == DEVICE_DOCK_FIFO_V1) {
        for (unsigned i=0; i<2; i++) {
            state->dockfifo.head[i]=state->dockfifo.count[i]=0;
            state->dockfifo.threshold[i][0]=state->dockfifo.threshold[i][1]=0;
        }
        state->dockfifo.mask=state->dockfifo.flags=0;
    }
    return DEVICE_OK;
}

enum device_result device_models_start(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t now, uint64_t frequency)
{
    if (!states || !device_models_valid(models,count,0,0)) return DEVICE_BAD_CONFIG;
    /* Disarm publication before restarting any backend. In particular, a
     * failed timed backend must not leave an old ready state observable. */
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            states[i].pmp_active.ready=states[i].pmp_active.ready_updated=0;
            states[i].pmp_active.status_reads=0;
        }
        else if (models[i].kind==DEVICE_SPMI_PMU_RTC_V1) states[i].pmu_rtc.ready=0;
    for (unsigned i=0;i<count;i++) {
        enum device_result result=device_model_start(models+i,states+i,now,frequency);
        if (result!=DEVICE_OK) return result;
    }
    /* The virtual power service is now able to serve its admitted commands.
     * This is not an Apple firmware, GPU, SEP, or DVFS completion report.
     * Commands outside the modeled service continue to fail explicitly. */
    for (unsigned i=0;i<count;i++)
        if (models[i].kind==DEVICE_PTD_PMP_ACTIVE_V1) {
            states[i].pmp_active.ready=1;
            states[i].pmp_active.ready_updated=1;
        }
    return DEVICE_OK;
}

uint64_t device_model_wait(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t budget)
{
    if (model && state && model->kind == DEVICE_WATCHDOG_WD1_V1)
        return watchdog_wait(&state->watchdog, now, budget);
    return budget;
}

int device_reset_pending(const struct device_model *model,
    const struct device_state *state)
{
    return model && state && model->kind == DEVICE_WATCHDOG_WD1_V1 &&
           state->watchdog.reset;
}

enum device_result device_model_access_at(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t offset, unsigned width,
    int write, uint64_t *value)
{
    if (!valid(model) || !state || !value) return DEVICE_BAD_CONFIG;
    if (offset >= model->span) return DEVICE_NOT_FOUND;
    if (model->kind == DEVICE_SPMI_PMU_RTC_V1) {
        if (!state->pmu_rtc.ready) return DEVICE_BAD_CONFIG;
        return spmi_access(model,state,now,offset,width,write,value);
    }
    if (model->kind == DEVICE_AOP_TIMEBASE_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != 0 && offset != 4) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* AppleSPUTimesyncV2 reads high/low/high and retries at rollover.
         * Sample the same 24 MHz domain as CNTVCT; never advance on access
         * or latch the halves, which would defeat that consistency check. */
        *value=(uint32_t)(now >> (offset ? 32 : 0));
        return DEVICE_OK;
    }
    if (model->kind != DEVICE_WATCHDOG_WD1_V1)
        return device_model_access_state(model, state, offset, width, write, value);
    switch (watchdog_access(&state->watchdog, now, offset, width, write, value)) {
    case WATCHDOG_OK: return DEVICE_OK;
    case WATCHDOG_BAD_STATE: return DEVICE_BAD_CONFIG;
    case WATCHDOG_UNKNOWN_REGISTER: return DEVICE_UNKNOWN_REGISTER;
    case WATCHDOG_BAD_WIDTH: return DEVICE_BAD_WIDTH;
    case WATCHDOG_BAD_VALUE: return DEVICE_BAD_VALUE;
    }
    return DEVICE_BAD_CONFIG;
}

enum device_result device_mcc_event(const struct device_model *model,
    struct device_state *state, unsigned bank, unsigned counter, uint64_t count)
{
    if (!valid(model) || !state)
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_MCC_COHERENT_V1) {
        if (bank >= model->config[0] || counter >= 32) return DEVICE_BAD_VALUE;
    } else if (model->kind == DEVICE_MCC_SOCNI_V1) {
        if (bank || counter >= model->config[0]) return DEVICE_BAD_VALUE;
        if (!state->counter_enable[1]) return DEVICE_OK;
    } else if (model->kind == DEVICE_MCC_DCS_COHERENT_V1) {
        if (bank || counter >= 14) return DEVICE_BAD_VALUE;
        if (counter >= 10) {
            if (state->counter_enable[1] & (1UL << (4*(counter-10))))
                state->counter[0][counter] += count;
            return DEVICE_OK;
        }
    } else return DEVICE_BAD_CONFIG;
    if (state->counter_enable[bank] & (1UL << counter))
        state->counter[bank][counter] += count;
    return DEVICE_OK;
}

static enum device_result dcs_access(struct device_state *state, uint64_t offset,
    unsigned width, int write, uint64_t *value)
{
    if (!state) return DEVICE_BAD_CONFIG;
    /* Fifteen _dcsEnableErrors policy words from the stock 26A428 table at
     * fffffe000c903098. Extended apertures are admitted by the loader only
     * when covered by the platform error-handler's declared MMIO window. */
    static const uint32_t error_offsets[15]={0x7a0,0x38014,0x13c10,0x13c14,
        0x13c18,0x13c1c,0x13c20,0x13c28,0x13c2c,0x13c00,0x18400,0x20400,
        0x38050,0x13c24,0x48};
    for (unsigned i=0; i<15; i++) if (offset == error_offsets[i]) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->dcs_error_mask[i]=(uint32_t)*value;
        } else *value=state->dcs_error_mask[i];
        return DEVICE_OK;
    }
    if (offset >= 0x4000 && offset < 0x4070) {
        if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
        if (write) return DEVICE_READ_ONLY;
        *value = state->counter[0][(offset-0x4000)/8];
        return DEVICE_OK;
    }
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (offset >= 0x590 && offset < 0x680) {
        uint32_t *selector = &state->dcs_select[(offset-0x590)/24][((offset-0x590)%24)/4];
        if (write) *selector = (uint32_t)*value;
        else *value = *selector;
        return DEVICE_OK;
    }
    switch (offset) {
    case 0x580:
        /* W1 command plus ten counter-select bits. Completion is synchronous:
         * reset exactly the selected counters, then self-clear the command. */
        if (write) {
            if ((*value & ~0x3ff1UL) ||
                (*value && (!(*value & 1) || !(*value & 0x3ff0))))
                return DEVICE_BAD_VALUE;
            for (unsigned i=0;i<10;i++)
                if (*value & (1UL << (i+4))) state->counter[0][i] = 0;
        } else *value = 0;
        return DEVICE_OK;
    case 0x584:
        if (write) {
            if (*value & ~0x3ffUL) return DEVICE_BAD_VALUE;
            state->counter_enable[0] = *value;
        } else *value = state->counter_enable[0];
        return DEVICE_OK;
    case 0x588:
        /* Four enable bits at nibble boundaries; corresponding W1 reset
         * requests are 16 bits above them. Clear busy/request only after
         * performing the reset, so the guest's completion poll is truthful. */
        if (write) {
            if (*value & ~0x11111111UL) return DEVICE_BAD_VALUE;
            for (unsigned i=0;i<4;i++)
                if (*value & (1UL << (16+4*i))) state->counter[0][10+i] = 0;
            state->counter_enable[1] = *value & 0x1111;
        } else *value = state->counter_enable[1];
        return DEVICE_OK;
    case 0x58c:
        if (write) {
            if (*value & ~0x3f3f3f3fUL) return DEVICE_BAD_VALUE;
            state->dcs_power_select = (uint32_t)*value;
        } else *value = state->dcs_power_select;
        return DEVICE_OK;
    case 0x1d48:
        /* Opaque guest DRAM policy; never changes physical host DRAM. */
        if (write) state->dram_policy = (uint32_t)*value;
        else *value = (uint32_t)state->dram_policy;
        return DEVICE_OK;
    default:
        return DEVICE_UNKNOWN_REGISTER;
    }
}

enum device_result device_mcc_cache_event(const struct device_model *model,
    struct device_state *state, unsigned bank, int hit, uint64_t count)
{
    if (!valid(model) || model->kind != DEVICE_MCC_COHERENT_V1 || !state)
        return DEVICE_BAD_CONFIG;
    if (bank >= model->config[0] || (hit != 0 && hit != 1) || (hit && count))
        return DEVICE_BAD_VALUE;
    if (!hit) state->counter[bank][33] += count;
    return DEVICE_OK;
}

static enum device_result mcc_ptd_access(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value)
{
    if (!state) return DEVICE_BAD_CONFIG;
    if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
    if (model->kind==DEVICE_PTD_PMP_ACTIVE_V1) {
        /* J700 PMP-STATUS: range 2, slot 1. Native PMGR consumes a nonzero
         * data word and latches its per-die readiness byte. Metadata follows
         * the same update-consumption rule as the existing PTD producers. */
        if (offset==0x10 || offset==0x18) {
            if (write) return DEVICE_READ_ONLY;
            if (state->pmp_active.ready>1 || state->pmp_active.ready_updated>1)
                return DEVICE_BAD_VALUE;
            if (offset==0x10) *value=state->pmp_active.ready;
            else {
                *value=state->pmp_active.ready_updated ? 2 : 0;
                state->pmp_active.ready_updated=0;
                if (state->pmp_active.status_reads!=UINT32_MAX)
                    state->pmp_active.status_reads++;
            }
            return DEVICE_OK;
        }
        /* AP voter 0 owns only the first entry of each four-entry range.
         * A pair load consumes metadata once and retains its data word. */
        if (offset==0x1880 || offset==0x1888 || offset==0x18c0 || offset==0x18c8) {
            if (write) return DEVICE_READ_ONLY;
            int ack=offset>=0x18c0;
            uint32_t *updated=ack ? &state->pmp_active.ack_updated :
                                   &state->pmp_active.request_updated;
            if (offset&8) { *value=*updated ? 2 : 0; *updated=0; }
            else *value=ack ? state->pmp_active.ack : state->pmp_active.request;
            return DEVICE_OK;
        }
        if (offset>=0x1b20 && offset<0x1b50) {
            /* PMP V2 energy nodes VDEC, SOC_AON, SOC_REST (entries 0x1b2..4,
             * from the PMP nub's energy-counter): _runEnergyModel reads each
             * as an LDP pair through the PTD dashboard. No energy producer:
             * data 0 and metadata 0 (no update), so the kernel keeps its
             * cached zero (PMGR-IOREPORT-20261017). */
            if (write) return DEVICE_READ_ONLY;
            *value=0;return DEVICE_OK;
        }
        if (offset==0x10c40) {
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            /* This local transport can retain votes for already-active
             * domains, but cannot cause a power transition. Registry-aware
             * admission owns AVD wake/release and publishes actual states.
             * Never restore the reset-time ACK mask after a domain gates. */
            if ((*value&~model->config[4]) ||
                (*value&~state->pmp_active.ack) ||
                (state->pmp_active.request&~*value)) return DEVICE_BAD_VALUE;
            state->pmp_active.request=*value;
            state->pmp_active.request_updated=state->pmp_active.ack_updated=1;
            return DEVICE_OK;
        }
    }
    unsigned request=(unsigned)model->config[1], reply=(unsigned)model->config[2];
    unsigned quotas=(unsigned)model->config[3];
    if (offset < 0x4000) {
        unsigned index=(unsigned)(offset/16), status=(unsigned)(offset & 8);
        uint32_t *updated;
        unsigned slot;
        uint64_t data;
        if (index >= request && index-request < quotas+2) {
            slot=index-request;
            updated=&state->ptd_request_updated;
            data=state->ptd_request[slot];
        } else if (index >= reply && index-reply < quotas+1) {
            slot=index-reply;
            updated=&state->ptd_reply_updated;
            data=slot == quotas ? state->ptd_ack : 0;
        } else return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* Data precedes metadata in readPTDMsg's LDP. Consume the update
         * indication only when metadata is read, retaining the last data. */
        if (status) {
            *value=(*updated & (1U << slot)) ? 2 : 0;
            *updated &= ~(1U << slot);
        } else *value=data;
        return DEVICE_OK;
    }
    if (offset < model->config[0] || offset-model->config[0] >= 0x4000)
        return DEVICE_UNKNOWN_REGISTER;
    unsigned index=(unsigned)((offset-model->config[0])/8);
    if (index < request || index-request >= quotas+2)
        return DEVICE_UNKNOWN_REGISTER;
    if (!write) return DEVICE_UNKNOWN_REGISTER; /* update-only aperture */
    unsigned slot=index-request;
    if (slot < quotas) {
        /* Four size[11:0]/policy[13:12] requests. Keep the request for the
         * driver's read/modify/write; zero capacity yields zero grants. */
        if (*value & 0xc000c000c000c000UL) return DEVICE_BAD_VALUE;
        state->ptd_reply_updated |= 1U << slot;
    } else if (slot == quotas+1) {
        state->ptd_payload_ready=1;
    } else {
        /* Audited SET_AVAILABLE_CACHE_SIZE opcode 1, sequence[11:0]. Only
         * zero is truthful for this backend. No generic PMP acknowledgement. */
        if ((*value >> 12) != 1 || !(*value & 0xfff) ||
            !state->ptd_payload_ready || state->ptd_request[quotas+1])
            return DEVICE_BAD_VALUE;
        state->ptd_ack=(uint16_t)(*value & 0xfff);
        state->ptd_reply_updated |= (1U << (quotas+1))-1;
        state->ptd_payload_ready=0;
    }
    state->ptd_request[slot]=*value;
    state->ptd_request_updated |= 1U << slot;
    return DEVICE_OK;
}

enum device_result device_model_read_pair(const struct device_model *model,
    struct device_state *state, uint64_t offset, uint64_t values[2])
{
    if (!valid(model) || !state || !values) return DEVICE_BAD_CONFIG;
    if (model->kind==DEVICE_SEP_ASC_MAILBOX_V1) {
        if (!sep_asc_valid(&state->sep_asc,(unsigned)model->config[1])) return DEVICE_BAD_CONFIG;
        if (offset>=model->span || model->span-offset<16) return DEVICE_NOT_FOUND;
        if (offset&7) return DEVICE_BAD_WIDTH;
        if (offset!=0x8830) return DEVICE_UNKNOWN_REGISTER;
        return model->config[1] ? sep_asc_receive(&state->sep_asc,values) : DEVICE_BAD_VALUE;
    }
    if (model->kind != DEVICE_MCC_PTD_COHERENT_V1 &&
        model->kind != DEVICE_PTD_PMP_ACTIVE_V1) return DEVICE_BAD_WIDTH;
    if (offset >= model->span || model->span-offset < 16) return DEVICE_NOT_FOUND;
    if (offset & 15) return DEVICE_BAD_WIDTH;
    uint64_t pair[2];
    /* The first lane is side-effect-free data. For an admitted PTD entry,
     * its second lane is metadata; only that read consumes the update bit. */
    enum device_result result=mcc_ptd_access(model,state,offset,8,0,&pair[0]);
    if (result != DEVICE_OK) return result;
    result=mcc_ptd_access(model,state,offset+8,8,0,&pair[1]);
    if (result != DEVICE_OK) return result;
    values[0]=pair[0]; values[1]=pair[1];
    return DEVICE_OK;
}

/* Extended packet forms carry a register address in EXTRA. The stock
 * payloadless register-zero form uses opcode80 and its seven-bit byte at
 * bits31:24, with no following FIFO payload. Stock short reads use opcode60
 * and the five-bit register at bits20:16. Stock short writes use opcode40:
 * 26A428 AppleSPMIController::registerReadWriteCommand (...9a14858) takes
 * opcode table ...769fc08 index 5, requires register <= 0x1f and length 1,
 * and ORs the data byte at bits31:24 -- one header, no FIFO payload.
 * executeCommand (...9a15624) refuses types above 11, so 0x14..0x1b are never
 * issued; they and newer XSPMI extensions remain refused.
 * A missing slave produces a reply with no ACK and no valid read frames. */
static int spmi_packet(uint32_t command, unsigned *input, unsigned *output)
{
    unsigned op=command & 255;
    if (command & 0x7000) return 0;
    if ((op <= 0x0f || (op >= 0x20 && op <= 0x2f)) && (command >> 24)) return 0;
    if (((op >= 0x10 && op <= 0x13) || op == 0x1c) && (command >> 16)) return 0;
    if (op == 0x80 && (command & 0x80ff0000U)) return 0;
    if (op == 0x60 && (command & 0xffe00000U)) return 0;
    if (op == 0x40 && (command & 0x00e00000U)) return 0;
    *input=*output=0;
    if (op <= 0x0f) *input=(op & 15)+1;
    else if (op >= 0x20 && op <= 0x2f) *output=(op & 15)+1;
    else if (op >= 0x30 && op <= 0x37) *input=(op & 7)+1;
    else if (op >= 0x38 && op <= 0x3f) *output=(op & 7)+1;
    else if (op == 0x1c) *output=10;
    else if (op == 0x60) *output=1;
    else if (op != 0x80 && op != 0x40 && (op < 0x10 || op > 0x13)) return 0;
    return 1;
}

static void spmi_complete(const struct device_model *d, struct device_state *s, uint64_t now)
{
    unsigned input=0, output=0;
    spmi_packet(s->spmi.command,&input,&output);
    uint8_t data[16]={0};
#if SNAP_SPMI_SCRATCH
    /* Scratch first: it never claims an RTC byte, and a served scratch
     * command must not count as an RTC rejection. */
    int success=d->kind==DEVICE_SPMI_PMU_RTC_V1 &&
        (pmu_scratch_transfer(&s->pmu_scratch,s->spmi.command,
                              (const uint8_t *)s->spmi.payload,data) ||
         pmu_rtc_transfer(&s->pmu_rtc,s->spmi.command,now,
                          (const uint8_t *)s->spmi.payload,data));
#else
    int success=d->kind==DEVICE_SPMI_PMU_RTC_V1 &&
        pmu_rtc_transfer(&s->pmu_rtc,s->spmi.command,now,
                         (const uint8_t *)s->spmi.payload,data);
#endif
    unsigned words=1+(output+3)/4;
    for (unsigned i=0; i<words; i++) {
        unsigned slot=(s->spmi.rx_head+s->spmi.rx_count++) % DEVICE_SPMI_FIFO_MAX;
        uint32_t value=s->spmi.command&0xfff;
        if (!i && success) value|=output ? ((1U<<output)-1)<<16 : 1U<<15;
        if (i) {
            value=0;
            for (unsigned j=0;j<4;j++) value|=(uint32_t)data[(i-1)*4+j]<<(8*j);
        }
        s->spmi.rx[slot]=value;
    }
    /* IRQ bank 8: failed read / missing write ACK; ALERT only on request. */
    if (!success) s->spmi.flags[8] |= 1U << (output ? 6 : 7);
    if (s->spmi.command & 0x8000) s->spmi.flags[8] |= 1;
    s->spmi.tx_words=s->spmi.tx_need=0;
}

static enum device_result spmi_access(const struct device_model *d,
    struct device_state *s, uint64_t now, uint64_t offset, unsigned width, int write, uint64_t *value)
{
    if (!s) return DEVICE_BAD_CONFIG;
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (write && *value > UINT32_MAX) return DEVICE_BAD_VALUE;
    uint64_t reg;
    if (offset >= d->config[0]) reg=offset-d->config[0];
    else if (offset == d->config[1] || offset == d->config[1]+8) {
        /* AppleSPMIController::dumpFaultQueue uses descriptor +30/+38,
         * separately from queuePop's +08/+18 response FIFO. Aliasing them
         * lets the fault IRQ handler steal the caller's negative reply.
         * This virtual empty bus has no diagnostic fault-record producer;
         * NACK/invalid-frame completion and its IRQ flags remain real. */
        if (write) return DEVICE_READ_ONLY;
        if (offset != d->config[1]) return DEVICE_BAD_VALUE;
        *value=1U<<24; /* independent fault queue: RX_EMPTY */
        return DEVICE_OK;
    }
    else return DEVICE_UNKNOWN_REGISTER;
    if (reg == 0) {
        if (write) return DEVICE_READ_ONLY;
        *value=(s->spmi.tx_words ? s->spmi.tx_words : 1U<<8) |
            (s->spmi.rx_count ? (s->spmi.rx_count & 255U)<<16 : 1U<<24) |
            (s->spmi.rx_count == DEVICE_SPMI_FIFO_MAX ? 1U<<25 : 0);
        return DEVICE_OK;
    }
    if (reg == 4) {
        if (!write) return DEVICE_READ_ONLY;
        if (s->spmi.tx_words) {
            s->spmi.payload[s->spmi.tx_words-1]=(uint32_t)*value;
            if (++s->spmi.tx_words == s->spmi.tx_need) spmi_complete(d,s,now);
            return DEVICE_OK;
        }
        unsigned input, output;
        if (!spmi_packet((uint32_t)*value,&input,&output)) return DEVICE_BAD_VALUE;
        /* Reserve the entire reply before accepting any part of a command. */
        if (1+(output+3)/4 > DEVICE_SPMI_FIFO_MAX-s->spmi.rx_count)
            return DEVICE_BAD_VALUE;
        s->spmi.command=(uint32_t)*value;
        s->spmi.tx_words=1; s->spmi.tx_need=1+(input+3)/4;
        if (s->spmi.tx_need == 1) spmi_complete(d,s,now);
        return DEVICE_OK;
    }
    if (reg == 8) {
        if (write) return DEVICE_READ_ONLY;
        if (!s->spmi.rx_count) return DEVICE_BAD_VALUE;
        *value=s->spmi.rx[s->spmi.rx_head];
        s->spmi.rx_head=(s->spmi.rx_head+1)%DEVICE_SPMI_FIFO_MAX;
        s->spmi.rx_count--;
        return DEVICE_OK;
    }
    if (reg >= 0x20 && reg <= 0x40) {
        unsigned bank=(reg-0x20)/4;
        if (write) s->spmi.enable[bank]=(uint32_t)*value;
        else *value=s->spmi.enable[bank];
        return DEVICE_OK;
    }
    if (reg >= 0x60 && reg <= 0x80) {
        unsigned bank=(reg-0x60)/4;
        if (write) s->spmi.flags[bank] &= ~(uint32_t)*value;
        else *value=s->spmi.flags[bank];
        return DEVICE_OK;
    }
    if (reg == 0xa0) {
        /* The selected gen-3 driver saves this word, writes zero, drains or
         * clears FIFOs, and restores it. This virtual bus owns no physical
         * master modes, so only its declared quiescent boot value zero is
         * supported. Do not adopt another SoC's undocumented mode bits.
         * Configuration writes alone never consume or acknowledge a reply. */
        if (write) {
            if (*value) return DEVICE_BAD_VALUE;
            if (s->spmi_recovery.config_writes != UINT32_MAX)
                s->spmi_recovery.config_writes++;
        } else {
            *value=0;
            if (s->spmi_recovery.config_reads != UINT32_MAX)
                s->spmi_recovery.config_reads++;
        }
        return DEVICE_OK;
    }
    if (reg == 0xa4) {
        if (!write) { *value=0; return DEVICE_OK; }
        if (*value > 1) return DEVICE_BAD_VALUE;
        if (*value) {
            s->spmi.rx_head=s->spmi.rx_count=0;
            s->spmi.tx_words=s->spmi.tx_need=0;
            if (s->spmi_recovery.fifo_clears != UINT32_MAX)
                s->spmi_recovery.fifo_clears++;
        }
        return DEVICE_OK;
    }
    return DEVICE_UNKNOWN_REGISTER;
}

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

static int i2c_valid(const struct device_i2c_empty *s)
{
    return s && s->ready==1 && s->tx_count<=DEVICE_I2C_FIFO_WORDS &&
        s->blocked<=1 && s->halt<=1 && !(s->status&~I2C_FLAGS) &&
        (!s->tx_count || s->blocked ||
         ((s->tx[0]&0x100) && !(s->tx[0]&~0x3ffU))) &&
        (!s->shadow_command || s->shadow_command==0x100000) &&
        !(s->control&~(I2C_CONTROL&~0x600U)) && !(s->address&~0x80000000U);
}

static uint32_t i2c_status(const struct device_i2c_empty *s)
{
    /* Empty slave TX, actual master FIFO levels, idle high SDA/SCL when
     * debug sensing is enabled. An ended transaction can still be a NACK. */
    return s->status | (1U<<8) | (s->tx_count ? 0 : 1U<<16) |
        (s->tx_count==DEVICE_I2C_FIFO_WORDS ? 1U<<17 : 0) |
        (s->address ? 0x18U : 0);
}

static void i2c_run(struct device_i2c_empty *s)
{
    if (s->halt || !(s->control&0x800) || s->blocked || !s->tx_count) return;
    /* HALT permits the driver to prefill a transaction before execution.
     * The first address encounters an empty bus and gets a NACK. Consume
     * that word only; later commands remain queued until a TX reset. */
    s->last_address=s->tx[0]&0xff;
    for (unsigned i=1;i<s->tx_count;i++) s->tx[i-1]=s->tx[i];
    s->tx[--s->tx_count]=0;
    s->status|=I2C_FLAGS;
    s->blocked=1;
    s->nacks++;
}

static int device_has_irq(const struct device_model *model)
{
    return model->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || model->kind == DEVICE_SPMI_PMU_RTC_V1 || model->kind == DEVICE_DOCK_FIFO_V1 ||
           model->kind == DEVICE_DART_T8110_V1 || model->kind == DEVICE_I2C_EMPTY_V1 ||
           model->kind == DEVICE_AES_SOFTWARE_V1 ||
           (model->kind == DEVICE_SEP_ASC_MAILBOX_V1 && model->config[1]);
}

enum device_result device_models_route_irqs(const struct device_model *models,
    struct device_state *states, unsigned count)
{
    if (count > DEVICE_MODEL_MAX || (count && (!models || !states))) return DEVICE_BAD_CONFIG;
    int aic=-1; unsigned sources=0;
    for (unsigned i=0; i<count; i++) {
        if (!valid(&models[i])) return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 &&
            !sep_asc_valid(&states[i].sep_asc,(unsigned)models[i].config[1]))
            return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_I2C_EMPTY_V1 && !i2c_valid(&states[i].i2c))
            return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_AES_SOFTWARE_V1 &&
            (states[i].aes.ready!=1 || (states[i].aes.irq_status&~0x20U) ||
             (states[i].aes.irq_enable&~0x3efffU))) return DEVICE_BAD_CONFIG;
        if (models[i].kind == DEVICE_AIC3_FLAT_V1) {
            if (aic >= 0) return DEVICE_BAD_CONFIG;
            aic=(int)i;
        }
        sources += device_has_irq(&models[i]);
    }
    if (!sources) return DEVICE_OK;
    if (aic < 0) return DEVICE_BAD_CONFIG;
    for (unsigned i=0; i<count; i++)
        if (device_has_irq(&models[i]) &&
            (models[i].config[2] >= models[aic].config[0] ||
             (models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 &&
              models[i].config[3] >= models[aic].config[0]))) return DEVICE_BAD_CONFIG;
    for (unsigned i=0; i<count; i++) if (device_has_irq(&models[i])) {
      unsigned lanes=models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 ? 2 : 1;
      for (unsigned lane=0;lane<lanes;lane++) {
        unsigned irq=(unsigned)models[i].config[2+lane];
        int level=0;
        for (unsigned j=0; j<count; j++) {
            if (!device_has_irq(&models[j])) continue;
            if (models[j].kind==DEVICE_SEP_ASC_MAILBOX_V1) {
                if (models[j].config[2]==irq)
                    level |= !!(states[j].sep_asc.enable[1] && states[j].sep_asc.reply_count);
                if (models[j].config[3]==irq)
                    level |= !!(states[j].sep_asc.enable[0] && !states[j].sep_asc.count);
                continue;
            }
            if (models[j].config[2]!=irq) continue;
            if (models[j].kind == DEVICE_SPMI_GEN3_EMPTY_V1 || models[j].kind == DEVICE_SPMI_PMU_RTC_V1)
                for (unsigned k=0; k<9; k++)
                    level |= !!(states[j].spmi.flags[k] & states[j].spmi.enable[k]);
            else if (models[j].kind == DEVICE_DART_T8110_V1)
                level |= dart_irq_pending(&states[j].dart);
            else if (models[j].kind == DEVICE_AES_SOFTWARE_V1)
                level |= !!(states[j].aes.irq_status&states[j].aes.irq_enable);
            else if (models[j].kind == DEVICE_I2C_EMPTY_V1) {
                if (!i2c_valid(&states[j].i2c)) return DEVICE_BAD_CONFIG;
                level |= !!(i2c_status(&states[j].i2c)&states[j].i2c.mask);
            }
            else level |= !!((states[j].dockfifo.flags | dockfifo_level(&states[j])) &
                             states[j].dockfifo.mask);
        }
        device_irq_set_level(&models[aic],&states[aic],irq,level);
      }
    }
    return DEVICE_OK;
}

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

enum device_result device_model_access_state(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value)
{
    if (!valid(model) || !value) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_SPMI_PMU_RTC_V1) return DEVICE_BAD_CONFIG;
    if (offset >= model->span) return DEVICE_NOT_FOUND;
    if (model->kind == DEVICE_PMGR_ACC_BOOT_POLICY_V1) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_SEP_ASC_MAILBOX_V1)
        return state ? sep_asc_access(&state->sep_asc,offset,width,write,value,
                                     (unsigned)model->config[1]) : DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_I2C_EMPTY_V1) {
        if (!state || !i2c_valid(&state->i2c)) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (write && *value>UINT32_MAX) return DEVICE_BAD_VALUE;
        struct device_i2c_empty *s=&state->i2c;
        uint32_t v=(uint32_t)*value;
        if (offset==0) {
            if (!write) return DEVICE_BAD_VALUE;
            if (!(s->control&0x800) || s->shadow_command!=0x100000 || (v&~0x7ffU) ||
                s->tx_count==DEVICE_I2C_FIFO_WORDS) return DEVICE_BAD_VALUE;
            if (!s->blocked && !s->tx_count) {
                if (!(v&0x100) || (v&0x400)) return DEVICE_BAD_VALUE;
            }
            s->tx[s->tx_count++]=v;
            i2c_run(s);
        } else if (offset==4 || offset==8 || offset==0xc || offset==0x28) {
            if (write) return DEVICE_READ_ONLY;
            *value=offset==4 ? 0x100 : offset==8 ? s->tx_count :
                   offset==0x28 ? model->config[1] : 0;
        } else if (offset==0x10) {
            if (write) {
                /* Debug line sensing only. Slave and bitbang modes are not
                 * implemented and must not silently acquire an endpoint. */
                if (v&~0x80000000U) return DEVICE_BAD_VALUE;
                s->address=v;
            } else *value=s->address;
        } else if (offset==0x14) {
            if (write) s->status&=~v; /* W1C never changes FIFO-derived bits. */
            else *value=i2c_status(s);
        } else if (offset==0x18) {
            if (write) s->mask=v;
            else *value=s->mask;
        } else if (offset==0x1c) {
            if (write) {
                if (v&~I2C_CONTROL) return DEVICE_BAD_VALUE;
                if (v&0x200) {
                    for (unsigned i=0;i<DEVICE_I2C_FIFO_WORDS;i++) s->tx[i]=0;
                    s->tx_count=s->blocked=0;
                }
                if (v&0x600) s->resets++;
                /* Reset commands self-clear after the queue is emptied.
                 * RX is always empty because this bus never gets an ACK. */
                s->control=v&~0x600U;
                i2c_run(s);
            } else *value=s->control;
        } else if (offset==0x40) {
            /* The pinned _checkBusStatus programs this before submitting a
             * command; its other references are diagnostic reads. Preserve
             * the exact programming contract without claiming a packed
             * interrupt-history format or inventing a completion. Transfers
             * require this admission; actual IRQs come from FIFO/status. */
            if (!write) return DEVICE_BAD_VALUE;
            if (v!=0x100000 || !(s->control&0x800) || s->mask || s->status ||
                s->tx_count || s->blocked) return DEVICE_BAD_VALUE;
            s->shadow_command=v;
            s->shadow_writes++;
        } else if (offset==0x44) {
            if (write) {
                if (v&~1U) return DEVICE_BAD_VALUE;
                s->halt=v;
                i2c_run(s);
            } else *value=s->halt;
        } else if (offset==0x2c || offset==0x30 || offset==0x38) {
            unsigned i=offset==0x2c ? 0 : offset==0x30 ? 1 : 2;
            if (write) s->timing[i]=v;
            else *value=s->timing[i];
        } else return DEVICE_UNKNOWN_REGISTER;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DWI_STARTUP_V1) {
        if (!state || state->dwi.ready!=1 || (state->dwi.written&~31U))
            return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* 26A428 AppleS8000DWI::_dwiSetConfig / start. nclk-div=1,
         * polarity=1, str-delay=8000 and lockout-us=5 produce these exact
         * values at 24 MHz. Retain programming, without inventing a
         * voltage/backlight completion or forwarding physical host MMIO.
         * +80/+84 are shared with transaction submission: other payloads
         * and commands (including 0x71) remain unsupported. */
        static const uint32_t offsets[5]={0,0xd0,4,0x84,0x80};
        static const uint32_t startup[5]={1,192000,120,0,0x41};
        unsigned i=0;
        while (i<5 && offset!=offsets[i]) i++;
        if (i==5) return DEVICE_UNKNOWN_REGISTER;
        if (!write) {
            /* Never return a made-up reset or transaction status. Only
             * the three non-command configuration words have readback. */
            if (i>=3 || !(state->dwi.written&(1U<<i))) return DEVICE_BAD_VALUE;
            *value=state->dwi.values[i];
            return DEVICE_OK;
        }
        if (*value!=startup[i] || (i==4 && (state->dwi.written&15)!=15))
            return DEVICE_BAD_VALUE;
        state->dwi.values[i]=(uint32_t)*value;
        state->dwi.written|=1U<<i;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_QSPI_BOOT_V1) {
        if (!state || state->qspi.ready!=1 ||
            state->qspi.tx_count>DEVICE_QSPI_FIFO_WORDS ||
            state->qspi.rx_count>DEVICE_QSPI_FIFO_WORDS) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* 26A428 AppleQSPIMCController::start: common VERSION at +3c,
         * peripheral FIFO capacities at +838 and RESET at +800. The two
         * overlapping DT windows share one state. Reset really clears our
         * queues synchronously, so bit8 is clear on subsequent readback.
         * Unknown control bits, transfers, status and IRQs stay trapped. */
        if (offset==0x3c || offset==0x838) {
            if (write) return DEVICE_READ_ONLY;
            *value=offset==0x3c ? 1 : DEVICE_QSPI_FIFO_WORDS | (DEVICE_QSPI_FIFO_WORDS<<8);
            return DEVICE_OK;
        }
        if (offset!=0x800) return DEVICE_UNKNOWN_REGISTER;
        if (!write) { *value=0;return DEVICE_OK; }
        if (*value!=0x100) return DEVICE_BAD_VALUE;
        for (unsigned i=0;i<DEVICE_QSPI_FIFO_WORDS;i++)
            state->qspi.tx[i]=state->qspi.rx[i]=0;
        state->qspi.tx_count=state->qspi.rx_count=0;
        if (state->qspi.resets!=UINT32_MAX) state->qspi.resets++;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_ENERGY_RESTORE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset!=0 && offset!=8) return DEVICE_UNKNOWN_REGISTER;
        /* Saved energy is a writable baseline, never a fabricated sample.
         * These writes do not alter CPU power or start an energy producer. */
        if (state->energy_restore.written&~3UL) return DEVICE_BAD_VALUE;
        unsigned slot=(unsigned)(offset/8);
        if (!write) {
            /* IOReport's _snapshotCPUEnergyAccumulators and _runEnergyModel:
             * nothing accumulates, so the restored baseline (0 if none) is
             * the reading and every delta is zero (PMGR-IOREPORT-20261017). */
            *value=state->energy_restore.written&(1UL<<slot) ? state->energy_restore.values[slot] : 0;
            return DEVICE_OK;
        }
        state->energy_restore.values[slot]=*value;
        state->energy_restore.written|=1UL<<slot;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_ACC_PERF_RESTORE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset==0x20) {
            /* DVFS command readback, not a live frequency/counter sample.
             * No frequency command is admitted by this virtual controller:
             * its reset command is zero and BUSY[31] is therefore clear.
             * cpuComplexIdleEnter polls that interlock before entering idle.
             * Reject every command write; +50 actual-P-state status and
             * transition timestamps remain unsupported. */
            if (write) return DEVICE_BAD_VALUE;
            *value=0;
            return DEVICE_OK;
        }
        int slot=acc_perf_slot((unsigned)model->config[0],offset);
        if (slot<0) return DEVICE_UNKNOWN_REGISTER;
        unsigned count=model->config[0] ? 18 : 8;
        uint64_t residency=(1UL<<count)-1;
        uint64_t allowed[2]={residency|(residency<<18)|
            (((1UL<<(model->config[0] ? 6 : 10))-1)<<36)|
            (model->config[0] ? 0 : 0xffUL<<46),0};
        for (unsigned i=0;i<count;i++) allowed[(54+i)/64]|=1UL<<((54+i)%64);
        if ((state->acc_perf.written[0]&~allowed[0]) ||
            (state->acc_perf.written[1]&~allowed[1])) return DEVICE_BAD_VALUE;
        if (!write) {
            /* IOReport's _snapshotPerfCountersACC: no event/time source runs,
             * so a counter holds its restored value (0 if never restored) and
             * every sample delta is zero (PMGR-IOREPORT-20261017). */
            *value=state->acc_perf.written[slot/64]&(1UL<<(slot%64)) ? state->acc_perf.values[slot] : 0;
            return DEVICE_OK;
        }
        state->acc_perf.values[slot]=*value;
        state->acc_perf.written[slot/64]|=1UL<<(slot%64);
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_PERF_RESTORE_V1)
        return soc_perf_access(model,state,offset,width,write,value);
    if (model->kind == DEVICE_PMGR_ACTIVE_BOOT_V1)
        return pmgr_boot_access(model,state,offset,width,write,value,0);
    if (model->kind == DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset==8 && model->config[0]) {
            /* Resource admission lives in the registry path. */
            if (state->pmgr_ave_cluster!=0 && state->pmgr_ave_cluster!=15) return DEVICE_BAD_VALUE;
            if (write) return DEVICE_BAD_CONFIG;
            *value=state->pmgr_ave_cluster;return DEVICE_OK;
        }
        if ((offset==0xc || offset==0x10) && model->config[0]) {
            /* Hash-bound soc-clusters rows 3/4, DISP and DCS: the IOReport
             * cluster power-state loop reads them. Both are always on in
             * this virtual SoC; a gate request needs its own contract. */
            if (write) return DEVICE_READ_ONLY;
            *value=15;return DEVICE_OK;
        }
        if (offset!=0 && offset!=4) return DEVICE_UNKNOWN_REGISTER;
        /* configCPUComplexPowerState requests nibble 15 for active and
         * waits for bit 4 to clear. Both virtual clusters are already
         * active; no transition is busy. Off/reset need CPU lifecycle work.
         * This register does not have the ordinary PS bank's 0xf0 status. */
        if (write) return *value==15 ? DEVICE_OK : DEVICE_BAD_VALUE;
        *value=15;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AVE_TVM_IDLE_V1) return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_PMC_DVMR_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if ((offset==0x5c18 || offset==0x5c1c) && !write) {
            *value=state->pmc_dvmr.venc_cluster;return DEVICE_OK;
        }
        if (offset==0x5c18 && write)
            return *value==state->pmc_dvmr.venc_cluster ? DEVICE_OK : DEVICE_BAD_VALUE;
        if (offset==0) {
            if (write) {
                if (*value & ~3UL) return DEVICE_BAD_VALUE;
                /* Both declared display agents are local configuration:
                 * acceptance commits the enable set synchronously. There
                 * is no pending voltage/frequency operation to acknowledge. */
                state->pmc_dvmr.enabled=(uint32_t)*value;
                state->pmc_dvmr.count_valid=0;
            } else *value=state->pmc_dvmr.enabled;
            return DEVICE_OK;
        }
        if (offset==0x20 && !write) {
            *value=0; /* configuration busy bit 0: synchronous commit above */
            return DEVICE_OK;
        }
        if (offset==0x5c14 && write) {
            unsigned enabled=state->pmc_dvmr.enabled;
            unsigned count=(enabled&1)+((enabled>>1)&1);
            if (*value!=count) return DEVICE_BAD_VALUE;
            state->pmc_dvmr.count=count;
            state->pmc_dvmr.count_valid=1;
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_PMC_RMBS_REQUEST_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset || !write) return DEVICE_UNKNOWN_REGISTER;
        if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
        /* pmcWriteLTR forwards an opaque u32 through writeRMBS; boot
         * submits getRMBSInitVal() == UINT32_MAX. Retain the preference,
         * without inventing applied state, readback or completion. */
        state->pmc_rmbs.value=(uint32_t)*value;
        state->pmc_rmbs.valid=1;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMC_ENABLE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        unsigned index;uint64_t mask;
        if (offset<=0xc) { index=(unsigned)offset/4;mask=0xf; }
        else if (offset==0x24) { index=4;mask=3; }
        else if (offset==0x28) { index=5;mask=0x3f; }
        else if (offset==0x20) { index=6;mask=7; }
        else return DEVICE_UNKNOWN_REGISTER;
        /* PMP/CLPC/GFX/AP have declared interfaces on DCS/SOC/DISP/AVE.
         * Enabling an interface does not synthesize votes or completion.
         * RMBS enable/keep-alive occupies bits 1/0. Six boost agents and
         * three active BWR agents have independent RMW enable bits; BWR
         * spare rows are disabled in the hash-bound agent table. */
        if (write) {
            if (*value & ~mask) return DEVICE_BAD_VALUE;
            state->pmc_enable[index]=(uint32_t)*value;
        } else *value=state->pmc_enable[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AXI2AF_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset!=0x104 && offset!=0x108) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-0x104)/4;
        /* _applyAxi2afWorkaround sets or clears bit 0 in two control
         * words. Retain policy only: no physical bus, idle transition,
         * transaction drain, readiness or completion status is supplied. */
        if (write) {
            if (*value & ~1UL) return DEVICE_BAD_VALUE;
            state->pmgr_axi2af[index]=(uint32_t)*value;
        } else *value=state->pmgr_axi2af[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_DPE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* restoreSOCDPE uses ten bases 0x2400..0x4800 in logical reg 78.
         * This model owns only pages +0x2000..0x4fff. Each group exposes
         * +0/+0x200/+0x300, except group 7 has no +0 operation. */
        if (offset<0x400 || offset>=0x2c00) return DEVICE_UNKNOWN_REGISTER;
        unsigned group=(unsigned)(offset-0x400)/0x400;
        unsigned word=(unsigned)(offset-0x400)%0x400, slot;
        if (word==0 && group!=7) slot=0;
        else if (word==0x200) slot=1;
        else if (word==0x300) slot=2;
        else return DEVICE_UNKNOWN_REGISTER;
        unsigned index=3*group+slot;
        if (write) {
            /* The audited consumer changes only bit 0. Retain enable
             * policy; no virtual idle producer, host gate or ready status. */
            if (*value & ~1UL) return DEVICE_BAD_VALUE;
            state->pmgr_soc_dpe[index]=(uint32_t)*value;
        } else *value=state->pmgr_soc_dpe[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_CORESIGHT_LOCK_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (state->coresight_unlocked>1) return DEVICE_BAD_VALUE;
        if (offset==0xfb0) {
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
            state->coresight_unlocked=(*value==0xc5acce55);
        } else if (offset==0xfb4) {
            if (write) return DEVICE_BAD_VALUE;
            /* SLI=1, SLK reflects our lock, nTT=0 (32-bit lock access). */
            *value=1 | (state->coresight_unlocked ? 0 : 2);
        } else return DEVICE_UNKNOWN_REGISTER;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_LLT_DISABLED_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset) return DEVICE_UNKNOWN_REGISTER;
        /* T8140 enableLltLimit reads SOC misc +0x10000, changes bit 0,
         * and writes the same word. This backend has no limiter: only
         * its disabled configuration can be read or written. */
        if (state->pmgr_llt_limit || (write && *value)) return DEVICE_BAD_VALUE;
        if (!write) *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_SOC_GATE_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        unsigned index;
        if (offset==0) index=0;
        else if (offset==0x40) index=1;
        else if (offset==0x60) index=2;
        else if (offset==0x68) index=3;
        else return DEVICE_UNKNOWN_REGISTER;
        /* restoreHW and enableCPMPowerDomainGating only change bit 31.
         * Retain that policy independently; no virtual idle producer can
         * gate a domain, and no physical power controller is touched. */
        if (write) {
            if (*value & ~0x80000000UL) return DEVICE_BAD_VALUE;
            state->pmgr_soc_gate[index]=(uint32_t)*value;
        } else *value=state->pmgr_soc_gate[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AP_WAKE_MASK_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* enableSlpDdrForS2R clears bit 0 at logical reg 66 +0x4000.
         * No DDR sleep controller is attached: retain the disabled
         * configuration, and reject every enable/reserved-bit request. */
        if (!offset) {
            if (write && *value) return DEVICE_BAD_VALUE;
            if (!write) *value=0;
            return DEVICE_OK;
        }
        /* T8140 setAPWakeupSources writes valid_mask & ~requested to
         * 0x4008..0x4024 through logical reg 66 (DT reg 4, base 0x4000).
         * Store the policy, independently per word. The distinct wake-cause
         * words at +0x28..0x44, mask reads and low-power commands stay trapped;
         * this does not claim to deliver an AOP/PMIC wake event. */
        if (!write || offset<8 || offset>0x24) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-8)/4;
        uint64_t valid_bits=index==7 ? 0x1fffff : UINT32_MAX;
        if (*value & ~valid_bits) return DEVICE_BAD_VALUE;
        state->pmgr_wake_mask[index]=(uint32_t)*value;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AON_COUNTER_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* Pinned perf-groups 6/7: _enableSOCPerfCounter(Ehjbbj) and
         * _enableSOCPerfCountersV2. Include the six secondary controls
         * selected by type-1 flags bit 1; these fill the primary-table gaps.
         * Group 6 starts halfway through its page; group 7 starts at zero. */
        unsigned base=model->config[0]==6 ? 0x800 : 0;
        unsigned count=model->config[0]==6 ? 6 : 69, index;
        if (offset>=base+0x100 && offset<base+0x100+count*0x20 &&
            (((offset-base-0x100)&0x1f)==0x10 || ((offset-base-0x100)&0x1f)==0x14)) {
            /* _snapshotPerfCountersV2 samples groups 6/7 too (high/low/high).
             * Nothing programs or restores an AON value and no clock runs:
             * both halves read 0, every delta is zero. Data writes stay
             * refused (PMGR-IOREPORT-20261017). */
            if (write) return DEVICE_READ_ONLY;
            *value=0;return DEVICE_OK;
        }
        if (offset==base) index=0;
        else if (offset>=base+0x100 && offset<base+0x100+count*0x20 &&
                 !((offset-base-0x100)&0x1f))
            index=1+(unsigned)(offset-base-0x100)/0x20;
        else return DEVICE_UNKNOWN_REGISTER;
        /* Mode 0/1 and enable bit 2 are configuration latches only.
         * Global bit 0 gates sampling but does not clear per-counter setup.
         * Other modes, data words, snapshots and reset controls stay trapped;
         * no Apple/Qualcomm clock telemetry or completed sampling is faked. */
        uint64_t mask=index ? 5 : 1;
        if (write) {
            if (*value & ~mask) return DEVICE_BAD_VALUE;
            state->pmgr_counter_config[index]=(uint32_t)*value;
        } else *value=state->pmgr_counter_config[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_AON_FUSES_V1) {
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        /* T8140CLPC::isRunningOnSilicon tests bits 31:28 of this word.
         * Declare the non-silicon branch for our virtual Apple platform;
         * there is no physical T8140 voltage/energy controller behind it.
         * 1 is our virtual type value, not a recovered Apple subtype code
         * or a characterization of the physical Qualcomm processor. */
        if (offset==0x80c) {
            if (write) return DEVICE_READ_ONLY;
            *value=UINT32_C(0x10000000);
            return DEVICE_OK;
        }
        /* Stock T8140 PMGR reports these ten characterization words; its
         * rail-IDS getter extracts fields from 0x114 and 0x124. This virtual
         * platform has no calibrated leakage or physical voltage backend.
         * Zero is our immutable characterization, not host fuse contents.
         * Other fuse/register consumers remain explicit unsupported stops. */
        if (!((offset>=0x114 && offset<=0x12c) ||
              (offset>=0x214 && offset<=0x21c))) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_CPU_PERF_BOOT_V1) {
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        /* Single declared CPU performance state: ACC 0xe78048/0xe78050. DVMR
         * weight[42:38] is zero; this backend has no voltage-margin engine.
         * Cluster 1's FANE indices [33:29], [38:34], [43:39] select the
         * backed active ANE state, index one. CLPC treats index zero as
         * inactive. Cluster 0 has no FANE index word.
         * Control writes and other performance-state entries stay trapped. */
        if (offset!=0x48 && !(model->config[0]==1 && offset==0x50))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=offset==0x50 ? (1UL<<29)|(1UL<<34)|(1UL<<39) : 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PMGR_DVMR_WEIGHTS_V1) {
        if (width!=8 || (offset&7)) return DEVICE_BAD_WIDTH;
        if (offset==0x178) {
            if (!state) return DEVICE_BAD_CONFIG;
            const uint64_t enabled=0xa800000000000000UL;
            /* The stock boolean setter changes all three enable bits.
             * Readback is requested configuration, not sampling readiness;
             * energy-value reads remain rejected by their separate banks. */
            if (state->pmgr_energy_control && state->pmgr_energy_control!=enabled)
                return DEVICE_BAD_VALUE;
            if (!write) *value=state->pmgr_energy_control;
            else {
                if (*value && *value!=enabled) return DEVICE_BAD_VALUE;
                state->pmgr_energy_control=*value;
            }
            return DEVICE_OK;
        }
        /* Pinned two-/four-entry DVMRWeightTable register lists. CLPC
         * treats an all-zero table as disabled. The P-cluster ANE-only
         * table therefore admits 0..2 CPUs at the sole state's weight 0,
         * with weight 31 in the unused 3..8 CPU lanes. Native topology
         * checks exclude those lanes even at weight 31. Other tables
         * remain disabled. This describes static guest frequency coupling;
         * it does not claim a physical voltage-margin engine or ANE work. */
        if (offset!=0xa8 && offset!=0xd0 &&
            !(model->config[0] && (offset==0xb0 || offset==0xd8)))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        *value=model->config[0] && offset==0xb0 ? 0x1fffffff8000UL : 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DART_T8110_V1) {
        enum dart_result r=dart_access(state ? &state->dart : 0,(unsigned)model->config[0],
                                      offset,width,write,value);
        switch (r) {
        case DART_OK: return DEVICE_OK;
        case DART_BAD_CONFIG: return DEVICE_BAD_CONFIG;
        case DART_BAD_WIDTH: return DEVICE_BAD_WIDTH;
        case DART_READ_ONLY: return DEVICE_READ_ONLY;
        case DART_UNKNOWN_REGISTER: return DEVICE_UNKNOWN_REGISTER;
        default: return DEVICE_BAD_VALUE;
        }
    }
    if (model->kind == DEVICE_SPMI_GEN3_EMPTY_V1)
        return spmi_access(model,state,0,offset,width,write,value);
    if (model->kind == DEVICE_DOCK_FIFO_V1)
        return dockfifo_access(state,offset,width,write,value);
    if (model->kind == DEVICE_SOCNI_ERRORS_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        /* _afxSocNiEnableErrors uses two masks per declared report source.
         * Captured six tables at c902c98 identify exact offsets and gaps;
         * status/acknowledgement registers are not part of this contract. */
        static const unsigned base[6]={0x1800,0x1a00,0x1400,0x2400,0x2000,0x1c00};
        static const unsigned count[6]={25,25,25,25,23,22};
        unsigned bank=(unsigned)model->config[0], n=count[bank];
        if (offset < base[bank] || offset >= base[bank]+8*n) return DEVICE_UNKNOWN_REGISTER;
        unsigned index=(unsigned)(offset-base[bank])/4, source=index%n;
        if ((bank < 4 && (source == 11 || source == 13)) ||
            (bank == 4 && source == 12) || (bank == 5 && source == 11))
            return DEVICE_UNKNOWN_REGISTER;
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->socni_error_mask[index]=(uint32_t)*value;
        } else *value=state->socni_error_mask[index];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_PLATFORM_ERROR_POLICY_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != model->config[0] || (!write && model->config[1]))
            return DEVICE_UNKNOWN_REGISTER;
        /* _afiNsDisableErrors writes a complete disable policy at +104;
         * its read semantics are not yet established. _afxPioGwEnableErrors
         * does a genuine RMW at +4084. Neither has a physical fault producer. */
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            state->platform_error_policy=(uint32_t)*value;
        } else *value=state->platform_error_policy;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_DOCK_ABSENT_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset != model->config[0]) return DEVICE_UNKNOWN_REGISTER;
        if (write) return DEVICE_READ_ONLY;
        /* Only the root dock-connect status word is exposed. The virtual
         * Apple dock is absent; neighboring PMGR registers remain trapped. */
        *value=0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_AES_IDLE_V1) {
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (!state || state->aes_idle.ready!=1 || state->aes_idle.running>1 ||
            (state->aes_idle.irq_enable&~0x3effeU) ||
            (state->aes_idle.fifo_threshold && state->aes_idle.fifo_threshold!=0x40))
            return DEVICE_BAD_CONFIG;
        if (write) {
            uint64_t v=*value;
            switch (offset) {
            case 0x08: /* Native _enableAES START/STOP; neither submits work. */
                if (v!=1 && v!=2) return DEVICE_BAD_VALUE;
                state->aes_idle.running=v==1;
                if (v==1) state->aes_idle.starts++;
                else state->aes_idle.stops++;
                break;
            case 0x18: /* W1C: no command has been accepted, hence no IRQ. */
                if (v&~0x3effeUL) return DEVICE_BAD_VALUE;
                break;
            case 0x1c:
                if (v&~0x3effeUL) return DEVICE_BAD_VALUE;
                state->aes_idle.irq_enable=(uint32_t)v;
                break;
            case 0x20: /* Audited half-full threshold for the 128-word FIFO. */
                if (v!=0x40) return DEVICE_BAD_VALUE;
                state->aes_idle.fifo_threshold=(uint32_t)v;
                break;
            case 0x0c: case 0x24: return DEVICE_READ_ONLY;
            default: return DEVICE_UNKNOWN_REGISTER;
            }
            state->aes_idle.writes |= 1U<<(offset/4);
        } else {
            uint64_t v;
            switch (offset) {
            case 0x0c: v=0x3f80; break; /* All audited version-5 engines idle. */
            case 0x18: v=0; break;      /* No completion or error producer. */
            case 0x24: v=2; break;      /* Empty FIFO, zero read/write pointers. */
            default: return DEVICE_UNKNOWN_REGISTER;
            }
            *value=v;
            state->aes_idle.reads |= 1U<<(offset/4);
        }
        /* In particular 0x200 never accepts a FIFO command. No guest buffer,
         * DMA mapping, key bytes, crypto result or interrupt is fabricated. */
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_AES_NO_KEYS_V1) {
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (model->config[4] && offset == model->config[4]) {
            /* PMGR's BPR (AppleT8140PMGR read32/write32 of range 1 +0x5c030):
             * a plain 32-bit word. It starts at 0 -- no earlier boot-progress or
             * panic state -- and only a guest write changes it. */
            if (!state) return DEVICE_BAD_CONFIG;
            if (write) {
                if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
                state->aes_pmgr_bpr=(uint32_t)*value;
                if (state->aes_pmgr_bpr_writes!=UINT32_MAX) state->aes_pmgr_bpr_writes++;
            } else {
                *value=state->aes_pmgr_bpr;
                if (state->aes_pmgr_bpr_reads!=UINT32_MAX) state->aes_pmgr_bpr_reads++;
            }
            return DEVICE_OK;
        }
        for (unsigned i=0; i<4; i++) if (offset == model->config[i]) {
            if (write) {
                /* Shipped disableHardwareKey: dedicated disable command
                 * a55ac33c, or one legacy disable bit. These keys are already
                 * absent, so repeat disabling is idempotent. Never accept the
                 * a050c030 enable sentinel or make any fused key available. */
                if (i ? *value!=0xa55ac33cUL :
                    (*value!=1 && *value!=2 && *value!=4 && *value!=8))
                    return DEVICE_BAD_VALUE;
                if (!state) return DEVICE_BAD_CONFIG;
                if (state->aes_key_disable_writes[i]!=UINT32_MAX)
                    state->aes_key_disable_writes[i]++;
                return DEVICE_OK;
            }
            /* Legacy disable bits include UID0 (bit 3). Dedicated UID1 /
             * GID words are disabled unless equal to 0xa050c030; zero is
             * deliberately NOT a claim that a hardware key is available. */
            *value=i ? 0 : 15;
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_GPIO_QUIET_V1 || model->kind == DEVICE_GPIO_UART_RX_IDLE_V1 ||
        model->kind == DEVICE_GPIO_IDLE_INPUTS_V1 || model->kind == DEVICE_GPIO_IDLE_PADS_V2) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
        if (offset < model->config[0]*4) {
            uint32_t *pin=&state->gpio_pin[offset/4];
            unsigned old_mode=(*pin >> 1) & 7, old_mux=(*pin >> 5) & 3;
            int route=gpio_idle_input(model,(unsigned)(offset/4),old_mux);
            /* The pad's current level: a driven output's latch, a declared
             * idle-high input route, or otherwise externally held low. */
            unsigned level=old_mode == 1 ? (*pin & 1U) :
                (unsigned)(route && old_mode == 7 && (*pin & (1U << 9)));
            if (!write) {
                *value=old_mode == 1 ? *pin : (*pin & ~1U) | level;
                return DEVICE_OK;
            }
            uint64_t v=*value;
            unsigned mode=(v >> 1) & 7, group=(v >> 16) & 7, mux=(v >> 5) & 3;
            int idle_route=mode == 7 && gpio_idle_input(model,(unsigned)(offset/4),mux);
            /* 26A428 AppleT8101GPIOIC::_decodeVectorInfo (...916086c) maps
             * interrupt types to modes 2 level-high, 3 level-low, 4 rising,
             * 5 falling and 6 either edge. initVector (...915f934) first
             * writes mode 7 with input enable; enableVector (...915fcec)
             * then replaces only bits 3:1, and disableVectorHard (...915fba8)
             * clears them to mode 0. No GPIO interrupt producer exists, so
             * an interrupt mode is admitted only on a GPIO-function pad
             * (mux 0: externally held low) whose condition can never become
             * true: level-high and rising edge always; falling or either
             * edge unless this very write releases a driven-high output.
             * Level-low would assert at once and stays unsupported. Pending
             * banks therefore truthfully remain zero. Declared idle-high
             * inputs have no asserted clock requests, edges or serial data. */
            int irq=mode >= 2 && mode <= 6;
            if (irq && (mux || mode == 3 || ((mode == 5 || mode == 6) && level)))
                return DEVICE_BAD_VALUE;
            if ((v & ~0xe78fefUL) || (!irq && mode != 0 && mode != 1 && mode != 7) ||
                (mux && !idle_route) || !(model->config[2] & (1UL << group)) ||
                ((*pin & (1U << 21)) && ((v ^ *pin) & ~1UL)))
                return DEVICE_BAD_VALUE;
            *pin=(uint32_t)v;
            return DEVICE_OK;
        }
        if (offset >= 0x800) {
            uint64_t group=(offset-0x800)/0x40, bank=((offset-0x800)%0x40)/4;
            if (group < model->config[1] && (model->config[2] & (1UL << group)) &&
                bank < (model->config[0]+31)/32) {
                /* W1C pending banks have no source in this backend. Ack of
                 * any mask (including unused final-bank bits) is harmless. */
                if (write && *value > UINT32_MAX) return DEVICE_BAD_VALUE;
                if (!write) *value=0;
                return DEVICE_OK;
            }
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_WATCHDOG_SMC_DISARM_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset!=model->config[0] || !write) return DEVICE_UNKNOWN_REGISTER;
        /* Native start and _disarmWatchdogMechanism clear this deadline.
         * Zero leaves the virtual SMC timer disarmed. Do not pretend an
         * unimplemented firmware timer can consume a nonzero deadline. */
        if (*value) return DEVICE_BAD_VALUE;
        if (state->watchdog_smc_disarms!=UINT32_MAX) state->watchdog_smc_disarms++;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_WATCHDOG_WD1_V1 || model->kind == DEVICE_AOP_TIMEBASE_V1)
        return DEVICE_BAD_CONFIG;
    if (model->kind == DEVICE_PTD_IRQ_CONFIG_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width!=4 || (offset&3)) return DEVICE_BAD_WIDTH;
        if (offset>=0x400 && offset<0x800) {
            /* _setIrq format 1 interleaves groups of four between the
             * low/high 0x200-byte halves. Keep state in entry order. */
            unsigned word=(unsigned)(((offset&0x1ff)/4)*2+((offset>>9)&1));
            if (write) {
                if (*value & ~0x1f1f1f1fUL) return DEVICE_BAD_VALUE;
                state->ptd_irq.route[word]=(uint32_t)*value;
            } else *value=state->ptd_irq.route[word];
            return DEVICE_OK;
        }
        if ((offset>=0x200 && offset<0x280) ||
            (offset>=0x300 && offset<0x380)) {
            /* _enableIrq / _disableIrq: W1S / W1C, not replacement. */
            if (!write) return DEVICE_UNKNOWN_REGISTER;
            if (*value>UINT32_MAX) return DEVICE_BAD_VALUE;
            unsigned word=(unsigned)((offset&0xff)/4);
            if (offset<0x300) state->ptd_irq.enabled[word]|=(uint32_t)*value;
            else state->ptd_irq.enabled[word]&=~(uint32_t)*value;
            return DEVICE_OK;
        }
        /* Pending, enable readback, status delivery and PMP readiness need
         * a producer contract. Never synthesize them from configuration. */
        return DEVICE_UNKNOWN_REGISTER;
    }
    if (model->kind == DEVICE_MCC_PTD_COHERENT_V1 || model->kind == DEVICE_PTD_PMP_ACTIVE_V1)
        return mcc_ptd_access(model, state, offset, width, write, value);
    if (model->kind == DEVICE_MCC_DCS_COHERENT_V1)
        return dcs_access(state, offset, width, write, value);
    if (model->kind == DEVICE_MCC_SOCNI_V1) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (offset == 0x100) {
            /* T8140 enablePerfCtrl starts the SOCNI bank after configuring
             * an individual counter. Keep the bank and source gates distinct. */
            if (width != 4) return DEVICE_BAD_WIDTH;
            if (write) {
                if (*value > 1) return DEVICE_BAD_VALUE;
                state->counter_enable[1] = *value;
            } else *value = state->counter_enable[1];
            return DEVICE_OK;
        }
        if (offset < model->config[0]*4) {
            if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
            uint64_t bit = 1UL << (offset/4);
            /* enableSocniCntr writes exactly 3 to start, 0 to stop.
             * Other control combinations need separate semantics. */
            if (write) {
                if (*value != 0 && *value != 3) return DEVICE_BAD_VALUE;
                if (*value) state->counter_enable[0] |= bit;
                else state->counter_enable[0] &= ~bit;
            } else *value = (state->counter_enable[0] & bit) ? 3 : 0;
            return DEVICE_OK;
        }
        if (offset >= 0x4000 && offset < 0x4000 + model->config[0]*8) {
            if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
            if (write) return DEVICE_READ_ONLY;
            *value = state->counter[0][(offset-0x4000)/8];
            return DEVICE_OK;
        }
        return DEVICE_UNKNOWN_REGISTER;
    }
    uint64_t bank = offset / 0x40000, reg = offset % 0x40000;
    if (model->kind == DEVICE_MCC_COHERENT_V1 && offset == 0x10082c) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        /* mccEnableCacheMode and mccFlush deassert the global flush request
         * with zero. cacheFlush asserts it with one and then uses per-DCS
         * +2844 completion: that active sequence is a separate contract.
         * No request has been admitted, so idle reads/clears are truthful. */
        if (write && *value) return DEVICE_BAD_VALUE;
        if (!write) *value = 0;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && offset == 0x102800) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        /* mccEnableCacheMode's requested way budget. The audited guest caps
         * it at twelve. With zero private cache capacity there are no lines
         * to move or evict; this policy never changes host cacheability. */
        if (write) {
            if (*value > 12) return DEVICE_BAD_VALUE;
            state->cache_way_policy = (uint32_t)*value;
        } else *value = state->cache_way_policy;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] && reg == 0x2804) {
        if (width != 4) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (write) return DEVICE_READ_ONLY;
        /* mccWaitForWaysPwrOn compares both seven-bit fields with the
         * requested way budget. This coherent, zero-capacity backend applies
         * that policy synchronously: no private lines need movement or power
         * sequencing. Report the applied policy, not physical Qualcomm ways. */
        *value = ((uint64_t)state->cache_way_policy << 24) |
                 ((uint64_t)state->cache_way_policy << 8);
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        reg >= 0x25000 && reg <= 0x25030 && !(reg & 7)) {
        if (!state) return DEVICE_BAD_CONFIG;
        if (width != 4) return DEVICE_BAD_WIDTH;
        /* _amccEnableErrors reads, ORs the driver's enable bits and clears
         * its disable bits before writing seven registers per DCS. These
         * are policy latches only; the coherent backend has no AMCC fault
         * producer. Adjacent error status/acknowledgement words stay trapped. */
        uint32_t *mask=&state->mcc_error_mask[bank][(reg-0x25000)/8];
        if (write) {
            if (*value > UINT32_MAX) return DEVICE_BAD_VALUE;
            *mask=(uint32_t)*value;
        } else *value=*mask;
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x2a000 || reg == 0x2a008 || reg == 0x2a010 || reg == 0x2e000)) {
        if (width != (reg == 0x2e000 ? 4 : 8)) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        unsigned slot = reg == 0x2e000 ? 3 : (reg-0x2a000)/8;
        /* enableDsidProfileCounters writes these configuration words. The
         * guest labels +2e000 as sampling interval and packs +2a008 as a
         * five-bit DSID plus a three-bit mode. Keep the other control words
         * opaque: bit 4 in +2a000 is not evidence of a reset or completion.
         * No profile sample/status registers are implemented by these latches. */
        if (write) {
            if ((slot == 0 && *value != 0 && *value != 1 && *value != 0x11) ||
                (slot == 1 && (*value & ~0x71fUL)) ||
                (slot == 2 && *value != 0 && *value != 0x10000000) ||
                (slot == 3 && *value != 0 && *value != 0x100))
                return DEVICE_BAD_VALUE;
            state->dsid_profile[bank][slot] = *value;
        } else *value = state->dsid_profile[bank][slot];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x2a058 || reg == 0x2a060)) {
        if (width != 8) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (write) return DEVICE_READ_ONLY;
        /* setDsidCntrCtrlParameters / DSID 0 Hits and DSID 0 Misses. */
        *value = state->counter[bank][32 + (reg == 0x2a060)];
        return DEVICE_OK;
    }
    if (model->kind == DEVICE_MCC_COHERENT_V1 && bank < model->config[0] &&
        (reg == 0x28000 || (reg >= 0x29000 && reg < 0x29100))) {
        /* setAmccCntrCtrlParameters selects 32 possible counter bits and
         * pairs each with read64 at DCS*0x40000 + 0x29000 + index*8.
         * Enable gates submitted virtual-fabric events; disabling preserves
         * accumulated values. No physical-host performance counts are used.
         * Register reset/selection beyond this fixed bank remains unsupported. */
        if (width != 8 || (offset & 7)) return DEVICE_BAD_WIDTH;
        if (!state) return DEVICE_BAD_CONFIG;
        if (reg == 0x28000) {
            if (write) {
                if (*value >> 32) return DEVICE_BAD_VALUE;
                state->counter_enable[bank] = *value;
            } else *value = state->counter_enable[bank];
            return DEVICE_OK;
        }
        if (write) return DEVICE_READ_ONLY;
        *value = state->counter[bank][(reg-0x29000)/8];
        return DEVICE_OK;
    }
    if (width != 4 || (offset & 3)) return DEVICE_BAD_WIDTH;
    if (model->kind == DEVICE_AIC3_FLAT_V1) {
        struct aic_config config = {(uint32_t)model->config[0],
                                    (uint32_t)model->config[3], model->config[2]};
        const enum device_result results[] = {DEVICE_OK, DEVICE_BAD_CONFIG,
            DEVICE_UNKNOWN_REGISTER, DEVICE_READ_ONLY, DEVICE_BAD_WIDTH, DEVICE_BAD_VALUE};
        return results[aic_access(&config, state ? &state->aic : 0,
                                  offset, width, write, value)];
    }
    /* MemCacheCIP::readCacheSize decodes bits 23:8 as KiB per DCS and
     * multiplies by DCS count. The coherent backend has no separate Apple
     * memory-side cache, so its capacity is zero. CPU caches remain real and
     * use architectural maintenance; this does not report their capacity or
     * claim to implement MCC flush, power, protection, or error registers. */
    /* getDSIDGroupQuota accepts indices 0..32 and decodes the low six
     * bits in units of 128 KiB per DCS. No private cache means no quota. */
    int quota = reg >= 0xa000 && reg <= 0xa080;
    /* AppleH17PPlatformErrorHandler::_initDSIDTimeoutReporter walks 191
     * client selectors at 9000..92f8, then indexes a800..a87c by the low
     * five bits. This coherent backend routes clients to group zero and
     * has no private-cache timeout engine: all timeout enables are clear.
     * These global tables are read-only; no error/completion is fabricated. */
    int timeout = (offset >= 0x9000 && offset <= 0x92f8) ||
                  (offset >= 0xa800 && offset <= 0xa87c);
    /* AppleH17PPlatformErrorHandler::_amccSramEventHandler sums sixteen
     * global counters at 34400 + index*16, masks each to nineteen bits and
     * scales by 512 bytes (26A428: 9b38eb4..ee0). This backend owns no
     * private MCC SRAM and accepts no SRAM allocation commands, so allocated
     * bytes are zero. These are not per-DCS banks or DRAM capacity registers;
     * adjacent status/control words and all writes remain unsupported. */
    int sram = model->kind == DEVICE_MCC_COHERENT_V1 &&
               offset >= 0x34400 && offset <= 0x344f0 && !(offset & 15);
    if (offset / 0x40000 >= model->config[0] ||
        (reg != 0x2c && !quota && !timeout && !sram))
        return DEVICE_UNKNOWN_REGISTER;
    if (write) return DEVICE_READ_ONLY;
    *value=0;
    return DEVICE_OK;
}

int device_irq_pending(const struct device_model *model, const struct device_state *state)
{
    if (!valid(model) || !state || model->kind != DEVICE_AIC3_FLAT_V1) return 0;
    struct aic_config config = {(uint32_t)model->config[0],
                                (uint32_t)model->config[3], model->config[2]};
    return aic_pending(&config, &state->aic);
}

enum device_result device_irq_set_level(const struct device_model *model,
    struct device_state *state, unsigned irq, int level)
{
    if (!valid(model) || !state || model->kind != DEVICE_AIC3_FLAT_V1)
        return DEVICE_BAD_CONFIG;
    struct aic_config config = {(uint32_t)model->config[0],
                                (uint32_t)model->config[3], model->config[2]};
    return aic_set_level(&config, &state->aic, irq, level) == AIC_OK ?
           DEVICE_OK : DEVICE_BAD_VALUE;
}
