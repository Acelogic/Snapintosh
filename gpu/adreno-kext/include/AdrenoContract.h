/* SPDX-License-Identifier: MIT */
/*
 * AdrenoContract.h - values the Adreno X2-90 kext and the AdrenoMetal plug-in must agree on.
 *
 * Plain C, included by the kext (C++, -mkernel) and by the Metal plug-in and its host harness (Objective-C).
 * Every number here is checked against the 26A428 kernelcache or against Metal on the 26A428 host; the
 * comment next to each value says where it is read.
 */
#ifndef ADRENO_CONTRACT_H
#define ADRENO_CONTRACT_H

#include <stdint.h>
#include "../../../compat/adreno-submit.h"
#include "AdrenoA8xxRegs.h"

#if defined(__cplusplus)
#define ADRENO_STATIC_ASSERT(c, m) static_assert(c, m)
#else
#define ADRENO_STATIC_ASSERT(c, m) _Static_assert(c, m)
#endif

/* ---- Registry: what Metal reads from the IOAccelerator service ------------------------------------ */
/* Metal: IOServiceMatching("IOAccelerator") + kIOPublishNotification, then reads these two properties
 * once, on publish. The kext personality carries them, so they are on the service before registerService. */
#define ADRENO_METAL_PLUGIN_NAME        "AdrenoMetal"       /* bundle AdrenoMetal.bundle */
#define ADRENO_METAL_PLUGIN_CLASS       "AdrenoMTLDevice"   /* also the bundle's NSPrincipalClass */
#define ADRENO_KEXT_BUNDLE_ID           "org.snapintosh.driver.AdrenoX2"
#define ADRENO_ACCEL_CLASS              "AdrenoAcceleratorX2"
/* IOGPUConfig.accelName (accelerator+0x228). IOGPUDeviceUserClient::s_get_name (selector 1) does
 * strlcpy(out, accelName, 64) with no NULL check, so it must be a static, non-NULL string. */
#define ADRENO_ACCEL_NAME               "AdrenoX2"
/* IOGPUConfig +0x08 (accelerator+0x230), bit22 becomes mapping-options bit2.
 * Native Device::new_resource skips Resource::map unless that bit is set.
 * AppleParavirtGPU's 26A428 config also enables precisely this bit. */
#define ADRENO_RESOURCE_AUTO_MAP        (1u << 22)

/* ---- User clients (IOGPU::newUserClient, type & 0xffff) ------------------------------------------ */
#define ADRENO_UC_TYPE_DEVICE           5u     /* IOGPUDeviceUserClient; Metal opens 5 | options << 16 */

/* Device user-client selectors Metal calls at device creation (IOGPUDeviceCreateWithOptions), in order,
 * with the struct-output sizes from IOGPUDeviceUserClient::sDeviceMethods. */
#define ADRENO_SEL_GET_EVENT_MACHINE    2u
#define ADRENO_SEL_GET_EVENT_MACHINE_OUT 0x218u  /* u64 va; u32 x2 (cfg+0x26c); u32 (cfg+0x274); u32 n; u32 off[128] */
#define ADRENO_SEL_GET_CONFIG           0u
#define ADRENO_SEL_GET_CONFIG_OUT       0x40u
#define ADRENO_SEL_GET_DEVICE_INFO      5u
#define ADRENO_SEL_GET_DEVICE_INFO_OUT  0x20u

/* ---- Event machine --------------------------------------------------------------------------------- */
/* IOGPUEventMachine::init rejects more than 128 stamps; selector 2's output has room for exactly 128. */
#define ADRENO_NUM_STAMPS               128u
#define ADRENO_STAMP_BYTES              4u     /* IOGPUEventMachine::getStampOffset(i) == i << 2 */
#define ADRENO_WAIT_FOR_GPU_TIMEOUT_S   5u     /* IOGPUConfig +0x54 (accel+0x27c); base default 5 */

/* ---- New command queue arguments (selector 7, s_new_command_queue) --------------------------------- */
/* The kernel accepts the struct input only if size >= 0x408 and size == IOGPUConfig +0x90 (accel+0x2b8).
 * IOGPU's generic part is 0x408 bytes; the plug-in appends an 8-byte Adreno tail, as AGX does. */
#define ADRENO_IOGPU_QUEUE_ARGS_GENERIC 0x408u
#define ADRENO_QUEUE_ARGS_SIZE          0x410u
typedef struct __attribute__((packed)) {
    uint8_t  iogpu[ADRENO_IOGPU_QUEUE_ARGS_GENERIC]; /* filled by IOGPUMetalCommandQueue */
    uint32_t adrenoRingPriority;                     /* tail: ring / priority selection (unused by stage 2) */
    uint32_t reserved;
} AdrenoNewCommandQueueArgs;
ADRENO_STATIC_ASSERT(sizeof(AdrenoNewCommandQueueArgs) == ADRENO_QUEUE_ARGS_SIZE, "queue args size");

/* ---- New resource arguments (selector 9, IOGPUDevice::new_resource) --------------------------------- */
/* The kernel requires size >= 0x58 + IOGPUConfig +0x4c (accel+0x274). The kext leaves +0x4c at 0, so the
 * tail is accepted but not handed to the resource (copyResourcePrivate is only called when +0x4c != 0). */
#define ADRENO_IOGPU_RESOURCE_ARGS_GENERIC 0x58u
#define ADRENO_RESOURCE_ARGS_KERNEL_TAIL   0u
#define ADRENO_RESOURCE_ARGS_SIZE          0x68u
typedef struct __attribute__((packed)) {
    uint8_t  iogpu[ADRENO_IOGPU_RESOURCE_ARGS_GENERIC]; /* filled by IOGPUMetal{Buffer,Texture} */
    uint32_t adrenoFormat;                              /* tail: tiling / UBWC off in v1 */
    uint32_t adrenoFlags;
    uint64_t reserved;
} AdrenoNewResourceArgs;
ADRENO_STATIC_ASSERT(sizeof(AdrenoNewResourceArgs) == ADRENO_RESOURCE_ARGS_SIZE, "resource args size");
ADRENO_STATIC_ASSERT(ADRENO_RESOURCE_ARGS_SIZE >= ADRENO_IOGPU_RESOURCE_ARGS_GENERIC + ADRENO_RESOURCE_ARGS_KERNEL_TAIL,
                     "resource args shorter than the kernel minimum");

/* ---- Kernel commands inside a command buffer's segment ---------------------------------------------- */
/* sIOGPUKernelCommand = { u32 type; u32 size (>= 8, multiple of 4, includes this header); payload }.
 * IOGPUCommandQueue::processSegmentKernelCommand handles 0 (debug log) and 1 (collect timestamp) and marks
 * anything else as a submission error (0xa). The shared adreno-submit.h defines
 * the first vendor command: an 8-byte synchronous GPU fence. Other vendor
 * types remain errors until their GPU execution is implemented. */
ADRENO_STATIC_ASSERT(sizeof(struct adreno_submit_header) == 8, "kernel command header size");

/* ---- Draw submission (ADRENO_KCMD_IB, design S0) ---------------------------------------------------------- */
/* Wire format, limits and relocation rules: compat/adreno-submit.h (struct adreno_ib_command/adreno_ib_reloc);
 * monitor call: compat/adreno-guest.h (ADRENO_GUEST_IB). Every register, field, packet dword, descriptor
 * dword and enum the plug-in's packet builder and the kext's validator use comes from AdrenoA8xxRegs.h
 * (generated from Mesa's XML by tools/gen-a8xx-regs.py); no register number is typed by hand.
 * The kext publishes ADRENO_IB_REGISTRY_PROPERTY = ADRENO_GUEST_IB_ABI on the accelerator only when the
 * monitor advertises ADRENO_GUEST_IB_PROPERTY with that ABI and the start-time IB probe (one CP_NOP) completed;
 * the plug-in reads it once at device creation and refuses render pipelines (explicit exception) without it. */
#define ADRENO_IB_REGISTRY_PROPERTY     "AdrenoIBABI"

ADRENO_STATIC_ASSERT(ADRENO_KCMD_IB == ADRENO_KCMD_VENDOR_BASE + 2u, "IB follows FENCE and FILL32");
ADRENO_STATIC_ASSERT(ADRENO_IB_MAX_DWORDS <=
                     (A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE__MASK >> A8XX_PKT_A5XX_CP_INDIRECT_BUFFER_2__IB_SIZE__SHIFT),
                     "IB dword limit fits CP_INDIRECT_BUFFER IB_SIZE");
ADRENO_STATIC_ASSERT(ADRENO_IB_ALIGN_LOG2_TEXTURE == A8XX_DESC_A8XX_TEX_MEMOBJ_0__BASE_LO__SHR, "T# base alignment");
ADRENO_STATIC_ASSERT(ADRENO_IB_ALIGN_LOG2_TEXTURE >= A8XX_REG_SP_GFX_BINDLESS_BASE_DESCRIPTOR__ADDR__SHR,
                     "bindless set alignment");
ADRENO_STATIC_ASSERT(ADRENO_IB_ALIGN_LOG2_LOAD_STATE == A8XX_PKT_CP_LOAD_STATE6_1__EXT_SRC_ADDR__SHR,
                     "CP_LOAD_STATE6 external source alignment");
ADRENO_STATIC_ASSERT(ADRENO_IB_HI_BITS_DESC == A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__WIDTH &&
                     A8XX_DESC_A8XX_TEX_MEMOBJ_1__BASE_HI__SHIFT == 0 &&
                     ADRENO_IB_HI_BITS_DESC == A8XX_DESC_A6XX_UBO_1__BASE_HI__WIDTH &&
                     A8XX_DESC_A6XX_UBO_1__BASE_HI__SHIFT == 0, "descriptor BASE_HI width");
ADRENO_STATIC_ASSERT(A8XX_REG_RB_MRT_BASE__BIT_SIZE == 64 && ADRENO_IB_HI_BITS_REG64 == 32, "plain reg64 address");
ADRENO_STATIC_ASSERT(ADRENO_RING_NOP_MAX == A8XX_PKT7_COUNT_MASK, "ring pad CP_NOP count");
ADRENO_STATIC_ASSERT(ADRENO_RING_BUFSZ <= (A8XX_FIELDS_AXXX_CP_RB_CNTL__BUFSZ__MASK >> A8XX_FIELDS_AXXX_CP_RB_CNTL__BUFSZ__SHIFT) &&
                     ADRENO_RING_DWORDS(ADRENO_RING_BUFSZ) == 8192u, "q1n1's 32 KiB ring");
ADRENO_STATIC_ASSERT(ADRENO_IB_RBBM_INT_ERRORS ==
                     (A8XX_REG_RBBM_INT_0_STATUS__CP_AHB_ERROR__MASK | A8XX_REG_RBBM_INT_0_STATUS__RBBM_ATB_ASYNCFIFO_OVERFLOW__MASK |
                      A8XX_REG_RBBM_INT_0_STATUS__RBBM_GPC_ERROR__MASK | A8XX_REG_RBBM_INT_0_STATUS__CP_HW_ERROR__MASK |
                      A8XX_REG_RBBM_INT_0_STATUS__RBBM_ATB_BUS_OVERFLOW__MASK | A8XX_REG_RBBM_INT_0_STATUS__RBBM_HANG_DETECT__MASK |
                      A8XX_REG_RBBM_INT_0_STATUS__UCHE_OOB_ACCESS__MASK | A8XX_REG_RBBM_INT_0_STATUS__UCHE_TRAP_INTR__MASK |
                      A8XX_REG_RBBM_INT_0_STATUS__TSBWRITEERROR__MASK | A8XX_REG_RBBM_INT_0_STATUS__SWFUSEVIOLATION__MASK),
                     "RBBM error bits");
ADRENO_STATIC_ASSERT(ADRENO_IB_CP_GLOBAL_FAULTS ==
                     (A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTBR__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTBV__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTLPAC__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTAQE0__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTAQE1__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTDDEBR__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__HWFAULTDDEBV__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTBR__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTBV__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTLPAC__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTAQE0__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTAQE1__MASK |
                      A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTDDEBR__MASK | A8XX_REG_CP_INTERRUPT_STATUS_GLOBAL__SWFAULTDDEBV__MASK),
                     "CP fault bits");
ADRENO_STATIC_ASSERT(ADRENO_IB_RBBM_IDLE_IGNORE == A8XX_REG_RBBM_STATUS__CP_AHB_BUSY_CX_MASTER__MASK, "idle rule");

/* ---- Metal device ----------------------------------------------------------------------------------- */
/* _MTLDevice -initLimits accepts 10000..10002 for non-Apple GPUs; 10001 = Mac2 + Common1-3. */
#define ADRENO_FEATURE_PROFILE_DEFAULT  10001u

/* ---- Early stop (compat/early-stop.h, monitor call ADRENO_GUEST_STOP) ------------------------------- */
/* The kext publishes ADRENO_EARLY_STOP_REGISTRY_PROPERTY = 1 on the accelerator only when the monitor
 * advertised ADRENO_GUEST_STOP_PROPERTY for this launch; ordinary launches have neither and nothing below
 * does anything. Just before it raises an unrecoverable failure, the plug-in sets
 * ADRENO_EARLY_STOP_FAILURE_KEY on the accelerator to a 64-bit number, pid << 32 | failure site; the kext
 * forwards the first report as EARLY_STOP_REASON_PLUGIN_FAILURE with that detail. */
#define ADRENO_EARLY_STOP_REGISTRY_PROPERTY "AdrenoEarlyStopABI"
#define ADRENO_EARLY_STOP_FAILURE_KEY       "AdrenoEarlyStopPluginFailure"

#endif /* ADRENO_CONTRACT_H */
