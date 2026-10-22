/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_DEVICE_H
#define SNAP_COMPAT_DEVICE_H
#include <stdint.h>
#include "aic.h"
#include "watchdog.h"
#include "dart.h"
#include "aes-engine.h"

#define DEVICE_MODEL_MAX 128
#define DEVICE_RESET_WORDS ((DEVICE_MODEL_MAX+63)/64)
#define DEVICE_MODEL_WORDS 8
#define DEVICE_MCC_COHERENT_V1 1
#define DEVICE_MCC_DCS_COHERENT_V1 2
#define DEVICE_AIC3_FLAT_V1 3
#define DEVICE_MCC_SOCNI_V1 4
#define DEVICE_WATCHDOG_WD1_V1 5
#define DEVICE_MCC_PTD_COHERENT_V1 6
#define DEVICE_GPIO_QUIET_V1 7
#define DEVICE_AES_NO_KEYS_V1 8
#define DEVICE_SPMI_GEN3_EMPTY_V1 9
#define DEVICE_DOCK_ABSENT_V1 10
#define DEVICE_GPIO_UART_RX_IDLE_V1 11
#define DEVICE_GPIO_IDLE_INPUTS_V1 12
#define DEVICE_DOCK_FIFO_V1 13
#define DEVICE_SOCNI_ERRORS_V1 14
#define DEVICE_PLATFORM_ERROR_POLICY_V1 15
#define DEVICE_AOP_TIMEBASE_V1 16
#define DEVICE_DART_T8110_V1 17
#define DEVICE_PMGR_ACTIVE_BOOT_V1 18
/* config[1]: single running cpu0, five waiting CPUs, both cluster controls
 * held active; zero PMGR software votes are distinct from actual power. */
#define DEVICE_PMGR_CPU0_BOOT_V1 1
#define DEVICE_PMGR_AON_FUSES_V1 19
#define DEVICE_PMGR_CPU_PERF_BOOT_V1 20
#define DEVICE_PMGR_DVMR_WEIGHTS_V1 21
#define DEVICE_PMGR_AON_COUNTER_CONFIG_V1 22
#define DEVICE_PMGR_AP_WAKE_MASK_V1 23
#define DEVICE_PTD_IRQ_CONFIG_V1 24
#define DEVICE_PTD_PMP_ACTIVE_V1 25
#define DEVICE_PMGR_CPU_CLUSTER_ACTIVE_V1 26
#define DEVICE_PMGR_SOC_GATE_POLICY_V1 27
#define DEVICE_PMGR_SOC_DPE_POLICY_V1 28
#define DEVICE_PMGR_AXI2AF_POLICY_V1 29
#define DEVICE_PMC_ENABLE_POLICY_V1 30
#define DEVICE_PMC_RMBS_REQUEST_V1 31
#define DEVICE_PMC_DVMR_CONFIG_V1 32
#define DEVICE_PMGR_AVE_TVM_IDLE_V1 33
#define DEVICE_PMGR_SOC_PERF_RESTORE_V1 34
#define DEVICE_PMGR_ACC_PERF_RESTORE_V1 35
#define DEVICE_PMGR_ENERGY_RESTORE_V1 36
#define DEVICE_PMGR_ACC_BOOT_POLICY_V1 37
#define DEVICE_PMGR_LLT_DISABLED_V1 38
#define DEVICE_CORESIGHT_LOCK_V1 39
#define DEVICE_GPIO_IDLE_PADS_V2 40
#define DEVICE_QSPI_BOOT_V1 41
#define DEVICE_DWI_STARTUP_V1 42
#define DEVICE_I2C_EMPTY_V1 43
#define DEVICE_WATCHDOG_SMC_DISARM_V1 44
#define DEVICE_SEP_ASC_MAILBOX_V1 45
#define DEVICE_AES_IDLE_V1 46
#define DEVICE_AES_SOFTWARE_V1 47
#define DEVICE_SPMI_PMU_RTC_V1 48
/* Virtual ANS2 (compat/ans.h): the ASC mailbox at /arm-io/ans reg[0] and the
 * NVMe BAR at reg[3]. Both are served by the ANS module, never by
 * device_model_access; config[0] is the monitor-private reservation (state,
 * firmware page, RAM disk) that the loader places outside guest memory.
 * ASC: config[1] outbox IRQ 1010, config[2] inbox-empty IRQ 1007.
 * NVMe: config[1] RAM disk bytes, config[2] completion IRQ 1039. */
#define DEVICE_ANS_ASC_V1 49
#define DEVICE_ANS_NVME_V1 50
#include "pmu-rtc.h"
#define DEVICE_SEP_ASC_MESSAGES 8
#define DEVICE_I2C_FIFO_WORDS 16
#define DEVICE_QSPI_FIFO_WORDS 16
/* Kind 26 config[0]: retain the CPU controls and add owned AVE cluster 2. */
#define DEVICE_PMGR_AVE_CLUSTER_V1 1
/* PMP soc-device row bitmap with non-virtual PMGR active-state backends.
 * ANE-SYS-V-PMP and SEP-PEARL-V are separate virtual-device protocols. */
#define DEVICE_PMP_ACTIVE_MASK 0xffb80UL
#define DEVICE_PMP_AVD_BIT (1UL<<17)
#define DEVICE_PMP_ISP_BIT (1UL<<11)
#define DEVICE_PMP_PRORES_BIT (1UL<<14)
#define DEVICE_PMP_VENC0_BIT (1UL<<15)
#define DEVICE_PMP_VENC1_BIT (1UL<<16)
#define DEVICE_PMP_MSR_BIT (1UL<<18)
#define DEVICE_PMP_JPG_BIT (1UL<<19)
#define DEVICE_PMP_GFX_BIT (1UL<<9)
/* config[1]: 44-bit VA plus an audited controller policy. */
#define DEVICE_DART_SIO_BOOT_V1 (44UL | (1UL<<8))
#define DEVICE_DART_SEP_BOOT_V1 (44UL | (2UL<<8))
#define DEVICE_DART_ANE_INIT_V1 (44UL | (3UL<<8))
/* The Adreno virtual DART (/arm-io/dart-adreno, dart-id 31): an SIO-shaped
 * T8110 register model whose streams use TCR 1 (window below 4 GiB). Stream 0
 * is mirrored into the GPU SMMU (compat/adreno.h). */
#define DEVICE_DART_ADRENO_BOOT_V1 (44UL | (4UL<<8))
#define DEVICE_DOCK_FIFO_MAX 2048
#define DEVICE_SPMI_FIFO_MAX 256
#define DEVICE_GPIO_PINS_MAX 256

/* Guest IPA windows, never host MMIO pointers. Models own their register ABI;
 * board profiles supply placement and geometry. No descriptor permits physical
 * bus access. Configuration words not used by a model must be zero. */
struct device_model {
    uint64_t kind, base, span, config[5];
};
struct device_range { uint64_t base, span; };
/* One zero-initialized state per descriptor, owned by the virtual machine.
 * Call device_model_start to populate reset values before serving accesses.
 * DRAM policy is an opaque guest latch, not a physical DRAM controller value. */
/* Revision-6 master frontend on an empty virtual bus. No slave or DMA engine. */
struct device_i2c_empty {
    uint32_t control, mask, address, timing[3];
    uint32_t tx[DEVICE_I2C_FIFO_WORDS], tx_count, blocked, status;
    uint32_t ready, resets, nacks, last_address;
    /* Exact pre-transfer programming witness. The packed interrupt-shadow
     * diagnostic readback is not implemented or synthesized. */
    uint32_t shadow_command, shadow_writes;
    uint32_t halt;
};

#include "sep-bootstrap.h"
#include "sep-pnon.h"
#include "sep-xars.h"
#include "sep-sks-endpoint.h"
/* SEP ASC transport. config[1]=1 enables service-owned request consumption
 * and reply publication, with outbox IRQ config[2]=346 and inbox-empty IRQ
 * config[3]=343. The default capture
 * frontend has config[1:]=0. config[4]=1 selects the bounded virtual ROM
 * boot frontend; config[4]=3 also initializes the measured virtual service
 * resources, emits one active notification and serves fresh entropy through
 * the caller's source callback. config[4]=7 adds the bounded ordinary-recovery
 * endpoint and explicit virtual effective status: neither production SEP nor
 * secure SEP execution. config[4]=15 also publishes the bounded xars refusal
 * service. config[4]=59 extends installed pnon/xars config27 with SKS startup
 * configuration and explicit refusals for key/device-state operations.
 * No SEP code executes and no identity/key material is supplied. */
#define DEVICE_SEP_EFFECTIVE_STATUS 0UL
struct device_sep_asc {
    uint64_t request[DEVICE_SEP_ASC_MESSAGES][2], staged;
    uint64_t reads[2], writes[2], submitted;
    uint32_t ready, enable[2], count, staged_valid;
    uint64_t reply[DEVICE_SEP_ASC_MESSAGES][2];
    uint64_t consumed, published, delivered;
    uint32_t reply_count;
    uint64_t rom_status_replies, rom_last_request, rom_last_reply;
    uint64_t rom_stage, rom_firmware_iova, rom_firmware_size;
    uint64_t rom_shared_iova, rom_shared_size;
    uint64_t service_ready, service_notifications;
    struct sep_bootstrap bootstrap;
    uint64_t entropy_words, entropy_last_request; /* Never retain random DATA. */
    uint64_t status_queries, status_last_request;
    struct sep_pnon pnon;
    struct sep_xars xars;
    struct sep_sks_endpoint sks;
};

struct device_state {
    union {
        struct dart_state dart;
        struct device_sep_asc sep_asc;
        struct aes_engine aes;
        struct {
            /* Permanently absent fused keys; count accepted disable-only writes. */
            uint32_t aes_key_disable_writes[4];
            /* config[4]: PMGR's BPR word inside the shared key block (range 1
             * +0x5c030, read by the get-bpr user client). docs/PMGR-BPR-20261017.md */
            uint32_t aes_pmgr_bpr, aes_pmgr_bpr_reads, aes_pmgr_bpr_writes;
        };
        /* Version-5 AES control plane with no command/DMA backend. A stopped
         * or running empty engine is idle; key availability is a separate ROM. */
        struct {
            uint32_t ready, running, irq_enable, fifo_threshold;
            uint32_t starts, stops, reads, writes;
        } aes_idle;
        /* Explicit system and leaf power states; unowned shared domains
         * stay active. Registry/resource admission owns system transitions. */
        struct {
            uint32_t pmgr_policy[128];
            uint32_t pmgr_venc[10]; /* committed level plus W1C history */
            uint32_t pmgr_isp[13];
            uint32_t pmgr_atc[3]; /* USB AON, COMMON, USB; committed level/history */
            uint32_t pmgr_dpa[2]; /* DisplayPort audio leaves; shared parent stays active */
            uint32_t pmgr_spi[5]; /* SPI0..3 and QSPI; SPI_P stays active */
            uint32_t pmgr_i2c[5]; /* I2C0..4; SIO stays active */
            uint32_t pmgr_aux[5]; /* FPWM1/2, scaler ASE core, ISP sensor0/1 */
            uint32_t pmgr_ane; /* ANE_SYS only; virtual PMP vote remains unsupported */
            uint32_t pmgr_avd; /* AVD_SYS physical state feeds PMP row 17 */
            uint32_t pmgr_isp_sys; /* ISP_SYS parent and physical PMP row 11 */
            uint32_t pmgr_prores; /* APR physical power feeds PMP row 14 */
            uint32_t pmgr_venc_sys[2]; /* system parents, PMP rows 15/16 */
            uint32_t pmgr_msr; /* scaler system and ASE parent, PMP row 18 */
            uint32_t pmgr_jpg; /* shared JPEG system, PMP row 19 */
            uint32_t pmgr_gfx; /* GFX system, PMP row 9; external UAT ownership */
            uint32_t pmgr_misc[3]; /* SOC_RC, PMGR_SOC_OCLA, AP_TMM idle leaves */
            uint32_t pmgr_sep_aon; /* SEP_AON only; no SEP firmware/service completion */
            uint32_t pmgr_cpu_boot[8]; /* target/actual for six cores, ECPM, PCPM */
            uint32_t pmgr_cpu_reads, pmgr_cpu_writes; /* observed guest access masks */
            uint32_t pmgr_aes; /* AES leaf gate75; shared SIO/DART stays powered */
        };
        /* One global enable plus up to 69 exact AON configuration words.
         * Sample values and reset commands require a separate backend. */
        uint32_t pmgr_counter_config[70];
        /* SOC performance-counter restore, groups 0..5. The first 256
         * restored values use counter[][] below; the remaining 39 fit here.
         * written bits distinguish restored halves from absent sampling. */
        struct {
            uint32_t control[296];
            uint64_t extra[39];
            uint8_t written[295];
        } pmgr_perf;
        /* Programmed CPU residency/event baselines, not live measurements. */
        struct { uint64_t values[72], written[2]; } acc_perf;
        /* Core/CPM and SRAM energy baselines; no live energy producer. */
        struct { uint64_t values[2], written; } energy_restore;
        /* Requested energy-monitor enables in the DVMR-weight aperture. */
        uint64_t pmgr_energy_control;
        /* Opaque stock ACC startup policy; no frequency/status semantics. */
        struct {
            uint64_t acc_boot_policy;
            uint64_t acc_selectors[10], acc_selector_written;
        };
        /* No Apple LLT limiter is attached. Only the
         * disabled configuration is supported; enabling remains trapped. */
        uint32_t pmgr_llt_limit;
        /* Software lock only; debug execution/trace registers stay trapped. */
        uint32_t coresight_unlocked;
        /* Virtual QSPIMC reset/identity state. Command submission, DMA and
         * flash completion remain unsupported until a transaction backend
         * owns these queues. Version 1 describes this virtual implementation. */
        struct {
            uint32_t tx[DEVICE_QSPI_FIFO_WORDS], rx[DEVICE_QSPI_FIFO_WORDS];
            uint32_t tx_count, rx_count, ready, resets;
        } qspi;
        /* Retained DWI startup programming only. The command latch is not
         * a completed voltage/backlight request; status reads stay trapped. */
        struct { uint32_t values[5], written, ready; } dwi;
        struct device_i2c_empty i2c;
        /* Wake-source masking policy. Wake causes and sleep are separate. */
        uint32_t pmgr_wake_mask[8];
        /* Audited SOC power-gate enable policy; no idle transition source. */
        uint32_t pmgr_soc_gate[4];
        /* AVE SOC-cluster request, separate from the PMC virtual rail. */
        uint32_t pmgr_ave_cluster;
        /* Three SOC DPE policy positions per group; group 7 has no first
         * position. This stores enable bits, not transition/completion state. */
        uint32_t pmgr_soc_dpe[30];
        /* Two independent bus-workaround policy bits; no bus-status engine. */
        uint32_t pmgr_axi2af[2];
        /* Four rail voter masks, RMBS enable/keep-alive, boost and BWR
         * enables. Vote values and completion have separate interfaces. */
        uint32_t pmc_enable[7];
        /* Last submitted 32-bit RMBS/LTR request, not an applied rail state
         * or latency guarantee. Guest readback/completion is not exposed. */
        struct { uint32_t value, valid; } pmc_rmbs;
        /* Synchronous virtual DVMR agent configuration and the driver's
         * matching population count; no physical voltage/frequency data. */
        struct { uint32_t enabled, count, count_valid, venc_cluster; } pmc_dvmr;
        /* PTD v1 routing policy, separate from data/metadata producers.
         * Selectors are five bits per entry, four entries per word. */
        struct {
            uint32_t route[256], enabled[32];
        } ptd_irq;
        struct {
            uint64_t request, ack;
            uint32_t request_updated, ack_updated;
            /* PMP-STATUS is published by registry startup, not by a read
             * or a guest write. It describes this virtual service only. */
            uint32_t ready, ready_updated, status_reads;
        } pmp_active;
        /* SPMI has no physical master configuration: CONFIG1's supported
         * virtual boot value is zero. Count actual recovery accesses without
         * enlarging the shared runtime ABI; other model kinds own this union. */
        struct { uint32_t config_reads, config_writes, fifo_clears; } spmi_recovery;
        struct device_pmu_rtc pmu_rtc;
#if SNAP_SPMI_SCRATCH
        /* Opt-in PMU scratchpad bytes, placed after pmu_rtc's (pmu-rtc.h). */
        struct device_pmu_scratch pmu_scratch;
#endif
        /* Successful clears of the virtual SMC watchdog deadline. Nonzero
         * deadlines are unsupported until an SMC timer backend exists. */
        uint32_t watchdog_smc_disarms;
        /* Monitor-only read witnesses for kind20 offsets48/50. Each row is
         * count, PC, IPA, ESR, supplied value, restored register value, LR,
         * vCPU slot. Pure device reads never consult or alter this observer. */
        uint64_t cpu_perf_reads[2][8];
    };
    uint64_t dram_policy;
    uint64_t counter_enable[4];
    uint64_t counter[4][64];
    uint32_t dcs_select[10][6];
    uint32_t dcs_error_mask[15];
    uint32_t dcs_power_select;
    /* vDSID profile configuration only. No sampled profile engine, completion
     * interrupt or physical Apple-fabric telemetry is advertised. */
    uint64_t dsid_profile[4][4];
    uint32_t mcc_error_mask[4][7];
    uint32_t socni_error_mask[50];
    uint32_t platform_error_policy;
    uint32_t cache_way_policy;
    struct aic_state aic;
    struct watchdog_state watchdog;
    /* MCC's shared PTD request/reply transport. Four 16-bit quotas per word;
     * this backend owns no private cache and therefore grants zero capacity. */
    uint64_t ptd_request[10];
    uint16_t ptd_ack;
    unsigned ptd_payload_ready;
    uint32_t ptd_request_updated, ptd_reply_updated;
    /* Virtual pads: external inputs are held low; output data is latched.
     * No external interrupt producer or physical pad is attached. */
    uint32_t gpio_pin[DEVICE_GPIO_PINS_MAX];
    /* A gen-3 transport with no attached slaves. Failed read payload slots
     * are framing padding, never valid PMIC data (parity bitmap stays zero). */
    struct {
        uint32_t rx[DEVICE_SPMI_FIFO_MAX], enable[9], flags[9];
        uint32_t command, payload[4];
        unsigned rx_head, rx_count, tx_words, tx_need;
    } spmi;
    /* One full-duplex DockChannel. A side's TX queue is its peer's RX
     * queue. No MTP peer consumes bytes until a real backend reads them. */
    struct {
        uint8_t tx[2][DEVICE_DOCK_FIFO_MAX];
        unsigned head[2], count[2];
        uint32_t threshold[2][2], mask, flags;
    } dockfifo;
};
/* The context holds DEVICE_MODEL_MAX of these; a member that grows the union
 * would move every later context field (docs/PMGR-BPR-20261017.md). */
_Static_assert(sizeof(struct device_state) == 13000, "device_state size is pinned");
enum device_result {
    DEVICE_OK, DEVICE_NOT_FOUND, DEVICE_BAD_CONFIG, DEVICE_UNKNOWN_REGISTER,
    DEVICE_READ_ONLY, DEVICE_BAD_WIDTH, DEVICE_BAD_VALUE
};
int device_models_valid(const struct device_model *models, uint64_t count,
                        const struct device_range *exclude, uint64_t excluded);
/* Bind the CPU0 boot policy to the monitor's actual guest affinity. This
 * does not release secondary CPUs or implement CPU power transitions. */
int device_models_boot_cpu_valid(const struct device_model *models, unsigned count,
                                uint64_t boot_mpidr);
int device_model_find(const struct device_model *models, uint64_t count,
                      uint64_t ipa, uint64_t *offset);
enum device_result device_model_access(const struct device_model *model,
    uint64_t offset, unsigned width, int write, uint64_t *value);
enum device_result device_model_access_state(const struct device_model *model,
    struct device_state *state, uint64_t offset, unsigned width, int write,
    uint64_t *value);
/* PTD data/metadata or SEP ASC reply pair. Publish both lanes only after
 * validation; a refusal must not consume an indication or queued reply. */
enum device_result device_model_read_pair(const struct device_model *model,
    struct device_state *state, uint64_t offset, uint64_t values[2]);
/* Populate model reset state, including virtual GPIO pad configuration.
 * Timed models also require samples in the declared frequency; the untimed
 * access entry points intentionally refuse timed models. */
enum device_result device_model_start(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t frequency);
enum device_result device_aes_powered(const struct device_model *models,
    const struct device_state *states,unsigned count,unsigned index);
/* Initialize a validated registry before exposing it to the guest. Publish
 * PMP readiness only after every backend has successfully initialized.
 * On failure the caller must not expose any of these states. */
enum device_result device_models_start(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t now, uint64_t frequency);
enum device_result device_model_access_at(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t offset, unsigned width,
    int write, uint64_t *value);
uint64_t device_model_wait(const struct device_model *model,
    struct device_state *state, uint64_t now, uint64_t budget);
int device_reset_pending(const struct device_model *model,
    const struct device_state *state);
/* Latch all reset producers, including model indices above 63. */
enum device_result device_latch_resets(const struct device_model *models,
    const struct device_state *states, unsigned count,
    uint64_t bitmap[DEVICE_RESET_WORDS]);
/* Submit counted traffic from a virtual MCC producer. These count submitted
 * virtual events, never approximate Qualcomm PMU or physical DRAM traffic.
 * Disabled counters retain their value; VM reset clears state. */
enum device_result device_mcc_event(const struct device_model *model,
    struct device_state *state, unsigned bank, unsigned counter, uint64_t count);
/* The coherent backend has zero private cache capacity: submitted accesses
 * can miss but cannot hit. These DSID-0 counters run independently of PMU gates. */
enum device_result device_mcc_cache_event(const struct device_model *model,
    struct device_state *state, unsigned bank, int hit, uint64_t count);
/* Recompute the level after MMIO or a virtual producer changes AIC state. */
int device_irq_pending(const struct device_model *model, const struct device_state *state);
/* A virtual device producer owns its level and deasserts it when serviced. */
enum device_result device_irq_set_level(const struct device_model *model,
    struct device_state *state, unsigned irq, int level);
/* Route virtual producer levels into the single virtual AIC. Shared source
 * numbers are ORed. Validate the whole routing set before changing levels. */
enum device_result device_models_route_irqs(const struct device_model *models,
    struct device_state *states, unsigned count);
/* Atomic integer STP submission; refusals preserve the complete queue. */
enum device_result device_model_write_pair(const struct device_model *model,
    struct device_state *state, uint64_t offset, const uint64_t values[2]);

/* Virtual service interface; callers serialize these with guest MMIO and
 * route IRQ levels after a successful mutation, before resuming the guest.
 * Refusal preserves both queue state and output. Publication works while
 * the outbox is disabled; delivery and its level interrupt wait for enable. */
enum device_result device_sep_asc_take_request(const struct device_model *model,
    struct device_state *state, uint64_t values[2]);
enum device_result device_sep_asc_reply(const struct device_model *model,
    struct device_state *state, const uint64_t values[2]);
/* The callback validates the entire buffer before ownership is recorded.
 * kind0 is the pinned firmware payload; kind1 is managed, readable/writable
 * shared memory. Refusal must preserve resources. The caller holds the same
 * service lock through validation, queue commit and IRQ publication. */
struct device_sep_rom_resources {
    void *ctx;
    uint64_t firmware_size;
    int (*admit)(void *,unsigned kind,uint64_t iova,uint64_t size);
    int (*bootstrap)(void *,uint64_t iova,uint64_t size,struct sep_bootstrap *out);
    /* Fresh independent randomness; failure must not publish a success reply.
     * Called only after queue/history checks under the caller's service lock. */
    int (*entropy32)(void *,uint32_t *out);
    const struct sep_pnon_io *pnon;
    const struct sep_xars_io *xars;
    const struct sep_sks_endpoint_io *sks;
};
enum device_result device_sep_rom_step(const struct device_model *,
    struct device_state *,const struct device_sep_rom_resources *);
/* mac-v1 table 3 endpoint 6: capture the capabilities of an uninitialized
 * DART-only logical device. config[4] binds admitted logical IDs 0..31.
 * Devices with SMMU/APF instances have no binding until those contracts exist.
 * This does not power up, enable streams, or authorize a DMA producer. */
enum device_result device_dart_monitor_init(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t device_id);
/* Endpoint 5: SIO first power-up and non-restoring repeats; SEP initial
 * restoration and unchanged empty repeats. Loader policy fingerprints bind
 * stream topology. SEP retention with live resources requires a separate
 * saved-state restoration contract and is refused, never erased. */
enum device_result device_dart_monitor_powerup(const struct device_model *models,
    struct device_state *states, unsigned count, uint64_t device_id);
/* Read-only class-5 frame admission for the audited SIO policy. The monitor's
 * constructor validates the declared stream and its translation level.
 * Optional model_index is assigned only on success. */
enum device_result device_dart_admit_frame(const struct device_model *models,
    const struct device_state *states, unsigned count, unsigned iommu_class,
    unsigned device_id, unsigned sid, unsigned level, unsigned *model_index);
/* Registry-aware MMIO enforces ATC/ANE power and DART ownership in both
 * directions. Standalone access cannot authorize their level transitions. */
enum device_result device_models_access_at(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value);
/* Read-only admission for resources outside the MMIO state registry. Keep
 * resources stable through the transaction. Missing admission cannot grant
 * a GFX transition; future graphics producers must join this contract. */
struct device_power_resources { void *ctx; int (*gfx_idle)(void *ctx); };
enum device_result device_models_access_power_at(const struct device_model *models,
    struct device_state *states, unsigned count, unsigned index, uint64_t now,
    uint64_t offset, unsigned width, int write, uint64_t *value,
    const struct device_power_resources *resources);
#endif
