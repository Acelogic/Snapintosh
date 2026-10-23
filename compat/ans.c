/* SPDX-License-Identifier: MIT */
/* Virtual ANS2 (compat/ans.h). Compact by design: the monitor has a fixed
 * code budget, and every branch here is a guest-reachable contract. */
#include "ans.h"

_Static_assert(sizeof(struct ans_state) <= ANS_STATE_BYTES, "state fits its reservation page");
_Static_assert(ANS_FW_OFFSET >= ANS_STATE_BYTES && ANS_DISK_OFFSET >= ANS_FW_OFFSET + 0x4000,
               "reservation layout: state, one reserved zero page, disk");

#if defined(__aarch64__) && !defined(ANS_HOST)
#define ANS_ORDER() __asm__ volatile("dmb ish" ::: "memory")
#else
#define ANS_ORDER() __asm__ volatile("" ::: "memory")
#endif

#define CAP_LO 0x14010040u        /* TO 20 (10 s), CQR, MQES 0x40 (65 entries) */
#define CAP_HI 0x00000020u        /* CSS NVM (bit 37); MPSMIN/MPSMAX 4 KiB, DSTRD 0 */
#define VERSION 0x00010100u       /* "NVMe Revision Supported" 1.10 */
#define BOOT_OK 0xde71ce55u       /* WaitDeviceActive (IONVMeFamily 0x1f190) */
#define STATUS_INVALID_OPCODE 0x01
#define STATUS_INVALID_FIELD 0x02
#define STATUS_INVALID_NS 0x0b
#define STATUS_LBA_RANGE 0x80
#define STATUS_WRITE_PROTECTED 0x20   /* Namespace is Write Protected */
#define STATUS_READ_ERROR 0x281       /* SCT 2: Unrecovered Read Error */
#define STATUS_AER_LIMIT 0x105
#define STATUS_CQ_INVALID 0x100   /* SCT 1: Completion Queue Invalid */
#define STATUS_QID 0x101          /* Invalid Queue Identifier */
#define STATUS_QSIZE 0x102        /* Invalid Queue Size */
#define STATUS_IV 0x108           /* Invalid Interrupt Vector */
#define STATUS_QDELETE 0x10c      /* Invalid Queue Deletion */

#include "ans/nvme_model.c"
#include "ans/sptm_dma.c"
