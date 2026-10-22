/* SPDX-License-Identifier: MIT */
/* The ID register space HCR_EL2.TID3 traps: op0=3, op1=0, CRn=0, CRm=0..7.
 *
 * A trapped read has to be answered with the real value, and a register
 * cannot be named from a variable, so every allocated one gets its own `mrs`.
 * Answering them all with zero instead -- which an earlier version did --
 * tells the kernel it is running on a CPU with no features at all.
 *
 * Only the architecturally allocated encodings are read (Arm ARM DDI 0487, the
 * AArch64 ID register index; 45 of the 64). Every other encoding is RAZ by
 * construction, the default case: CRm=0's op2 1-4 and 7 are unallocated, and
 * CRm 1-7's gaps are reserved, RAZ. The Oryon traps an EL2 MRS of an
 * unallocated encoding (FEAT_IDST: v48 faulted on S3_0_C0_C0_1), so a guest
 * read of one, which TID3 brings to the monitor as EC 0x18, must never become
 * an MRS here: the guest sees zero. Allocated encodings read the hardware as
 * before. tools/test-idregs.py checks this table against the Arm ARM list and
 * that no built monitor contains an MRS of an unallocated encoding. */
#ifndef IDREGS_H
#define IDREGS_H

static uint64_t id_register(uint32_t crm, uint32_t op2)
{
    uint64_t v = 0;
    switch ((crm << 3) | op2) {
    case 0x00: __asm__ volatile("mrs %0, s3_0_c0_c0_0" : "=r"(v)); break;   /* MIDR_EL1 */
    case 0x05: __asm__ volatile("mrs %0, s3_0_c0_c0_5" : "=r"(v)); break;   /* MPIDR_EL1 */
    case 0x06: __asm__ volatile("mrs %0, s3_0_c0_c0_6" : "=r"(v)); break;   /* REVIDR_EL1 */
    case 0x08: __asm__ volatile("mrs %0, s3_0_c0_c1_0" : "=r"(v)); break;   /* ID_PFR0_EL1 */
    case 0x09: __asm__ volatile("mrs %0, s3_0_c0_c1_1" : "=r"(v)); break;   /* ID_PFR1_EL1 */
    case 0x0a: __asm__ volatile("mrs %0, s3_0_c0_c1_2" : "=r"(v)); break;   /* ID_DFR0_EL1 */
    case 0x0b: __asm__ volatile("mrs %0, s3_0_c0_c1_3" : "=r"(v)); break;   /* ID_AFR0_EL1 */
    case 0x0c: __asm__ volatile("mrs %0, s3_0_c0_c1_4" : "=r"(v)); break;   /* ID_MMFR0_EL1 */
    case 0x0d: __asm__ volatile("mrs %0, s3_0_c0_c1_5" : "=r"(v)); break;   /* ID_MMFR1_EL1 */
    case 0x0e: __asm__ volatile("mrs %0, s3_0_c0_c1_6" : "=r"(v)); break;   /* ID_MMFR2_EL1 */
    case 0x0f: __asm__ volatile("mrs %0, s3_0_c0_c1_7" : "=r"(v)); break;   /* ID_MMFR3_EL1 */
    case 0x10: __asm__ volatile("mrs %0, s3_0_c0_c2_0" : "=r"(v)); break;   /* ID_ISAR0_EL1 */
    case 0x11: __asm__ volatile("mrs %0, s3_0_c0_c2_1" : "=r"(v)); break;   /* ID_ISAR1_EL1 */
    case 0x12: __asm__ volatile("mrs %0, s3_0_c0_c2_2" : "=r"(v)); break;   /* ID_ISAR2_EL1 */
    case 0x13: __asm__ volatile("mrs %0, s3_0_c0_c2_3" : "=r"(v)); break;   /* ID_ISAR3_EL1 */
    case 0x14: __asm__ volatile("mrs %0, s3_0_c0_c2_4" : "=r"(v)); break;   /* ID_ISAR4_EL1 */
    case 0x15: __asm__ volatile("mrs %0, s3_0_c0_c2_5" : "=r"(v)); break;   /* ID_ISAR5_EL1 */
    case 0x16: __asm__ volatile("mrs %0, s3_0_c0_c2_6" : "=r"(v)); break;   /* ID_MMFR4_EL1 */
    case 0x17: __asm__ volatile("mrs %0, s3_0_c0_c2_7" : "=r"(v)); break;   /* ID_ISAR6_EL1 */
    case 0x18: __asm__ volatile("mrs %0, s3_0_c0_c3_0" : "=r"(v)); break;   /* MVFR0_EL1 */
    case 0x19: __asm__ volatile("mrs %0, s3_0_c0_c3_1" : "=r"(v)); break;   /* MVFR1_EL1 */
    case 0x1a: __asm__ volatile("mrs %0, s3_0_c0_c3_2" : "=r"(v)); break;   /* MVFR2_EL1 */
    case 0x1c: __asm__ volatile("mrs %0, s3_0_c0_c3_4" : "=r"(v)); break;   /* ID_PFR2_EL1 */
    case 0x1d: __asm__ volatile("mrs %0, s3_0_c0_c3_5" : "=r"(v)); break;   /* ID_DFR1_EL1 */
    case 0x1e: __asm__ volatile("mrs %0, s3_0_c0_c3_6" : "=r"(v)); break;   /* ID_MMFR5_EL1 */
    case 0x20: __asm__ volatile("mrs %0, s3_0_c0_c4_0" : "=r"(v)); break;   /* ID_AA64PFR0_EL1 */
    case 0x21: __asm__ volatile("mrs %0, s3_0_c0_c4_1" : "=r"(v)); break;   /* ID_AA64PFR1_EL1 */
    case 0x22: __asm__ volatile("mrs %0, s3_0_c0_c4_2" : "=r"(v)); break;   /* ID_AA64PFR2_EL1 */
    case 0x24: __asm__ volatile("mrs %0, s3_0_c0_c4_4" : "=r"(v)); break;   /* ID_AA64ZFR0_EL1 */
    case 0x25: __asm__ volatile("mrs %0, s3_0_c0_c4_5" : "=r"(v)); break;   /* ID_AA64SMFR0_EL1 */
    case 0x27: __asm__ volatile("mrs %0, s3_0_c0_c4_7" : "=r"(v)); break;   /* ID_AA64FPFR0_EL1 */
    case 0x28: __asm__ volatile("mrs %0, s3_0_c0_c5_0" : "=r"(v)); break;   /* ID_AA64DFR0_EL1 */
    case 0x29: __asm__ volatile("mrs %0, s3_0_c0_c5_1" : "=r"(v)); break;   /* ID_AA64DFR1_EL1 */
    case 0x2a: __asm__ volatile("mrs %0, s3_0_c0_c5_2" : "=r"(v)); break;   /* ID_AA64DFR2_EL1 */
    case 0x2c: __asm__ volatile("mrs %0, s3_0_c0_c5_4" : "=r"(v)); break;   /* ID_AA64AFR0_EL1 */
    case 0x2d: __asm__ volatile("mrs %0, s3_0_c0_c5_5" : "=r"(v)); break;   /* ID_AA64AFR1_EL1 */
    case 0x30: __asm__ volatile("mrs %0, s3_0_c0_c6_0" : "=r"(v)); break;   /* ID_AA64ISAR0_EL1 */
    case 0x31: __asm__ volatile("mrs %0, s3_0_c0_c6_1" : "=r"(v)); break;   /* ID_AA64ISAR1_EL1 */
    case 0x32: __asm__ volatile("mrs %0, s3_0_c0_c6_2" : "=r"(v)); break;   /* ID_AA64ISAR2_EL1 */
    case 0x33: __asm__ volatile("mrs %0, s3_0_c0_c6_3" : "=r"(v)); break;   /* ID_AA64ISAR3_EL1 */
    case 0x38: __asm__ volatile("mrs %0, s3_0_c0_c7_0" : "=r"(v)); break;   /* ID_AA64MMFR0_EL1 */
    case 0x39: __asm__ volatile("mrs %0, s3_0_c0_c7_1" : "=r"(v)); break;   /* ID_AA64MMFR1_EL1 */
    case 0x3a: __asm__ volatile("mrs %0, s3_0_c0_c7_2" : "=r"(v)); break;   /* ID_AA64MMFR2_EL1 */
    case 0x3b: __asm__ volatile("mrs %0, s3_0_c0_c7_3" : "=r"(v)); break;   /* ID_AA64MMFR3_EL1 */
    case 0x3c: __asm__ volatile("mrs %0, s3_0_c0_c7_4" : "=r"(v)); break;   /* ID_AA64MMFR4_EL1 */
    default: break;   /* unallocated or reserved: RAZ, no MRS */
    }
    return v;
}

#endif
