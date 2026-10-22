/* SPDX-License-Identifier: MIT */
/* SNAP_LEAN_TRAPS (probes/xnuboot.c): fewer and cheaper lock-free
 * system-register exits. Pure helpers; the monitor supplies every hardware
 * access.
 *
 * Level 1. Run-ahead: after the lock-free path emulates an ESR_EL1, FAR_EL1 or
 * PMC read at EL1, the monitor reads the next instruction of the const-sealed
 * kernel image and, while it is an MRS the same path answers, emulates it with
 * the syndrome the hardware would report (XNU reads FAR/ESR and PMC0/PMC1 in
 * adjacent pairs: fleh_dispatch64, fleh_synchronous, recount_*). A
 * division-free counter conversion for the 24 MHz guest on the 19.2 MHz
 * counter.
 *
 * Level 2. FEAT_FGT in place of HCR_EL2.TVM/TRVM: the same registers trap,
 * except ESR_EL1/FAR_EL1 reads (their handlers return the real register) and
 * CONTEXTIDR_EL1 writes (dropped before; its reads still trap and read 0).
 * Needs SCR_EL3.FGTEn, which no record shows. */
#pragma once
#include <stdint.h>
#include "clock.h"
#include "fast-trap.h"

/* HFGRTR_EL2 (S3_4_C1_C1_4) / HFGWTR_EL2 (S3_4_C1_C1_5) bits, FEAT_FGT
 * (Arm's register database, q1n1/proxyclient/m1n1/arm_regs.json). */
#define LEAN_FGT_AFSR0      (UINT64_C(1)<<0)
#define LEAN_FGT_AFSR1      (UINT64_C(1)<<1)
#define LEAN_FGT_AMAIR      (UINT64_C(1)<<3)
#define LEAN_FGT_CONTEXTIDR (UINT64_C(1)<<11)
#define LEAN_FGT_ESR        (UINT64_C(1)<<16)
#define LEAN_FGT_FAR        (UINT64_C(1)<<17)
#define LEAN_FGT_MAIR       (UINT64_C(1)<<24)
#define LEAN_FGT_SCTLR      (UINT64_C(1)<<29)
#define LEAN_FGT_TCR        (UINT64_C(1)<<32)
#define LEAN_FGT_TTBR0      (UINT64_C(1)<<36)
#define LEAN_FGT_TTBR1      (UINT64_C(1)<<37)
/* Every register HCR_EL2.TVM/TRVM traps on a core without TCR2, SCTLR2,
 * S1PIE, S1POE, S2PIE/S2POE, AIE or D128 (lean_fgt_admit). */
#define LEAN_FGT_TVM (LEAN_FGT_AFSR0|LEAN_FGT_AFSR1|LEAN_FGT_AMAIR|LEAN_FGT_CONTEXTIDR| \
    LEAN_FGT_ESR|LEAN_FGT_FAR|LEAN_FGT_MAIR|LEAN_FGT_SCTLR|LEAN_FGT_TCR|LEAN_FGT_TTBR0|LEAN_FGT_TTBR1)
#define LEAN_HCR_TVM_TRVM ((UINT64_C(1)<<26)|(UINT64_C(1)<<30))

enum lean_fgt_status {
    LEAN_FGT_NONE,      /* not tried (level 1) */
    LEAN_FGT_ACTIVE,    /* FGT in place of TVM/TRVM on this CPU */
    LEAN_FGT_ABSENT,    /* ID_AA64MMFR0_EL1.FGT is 0 */
    LEAN_FGT_MMFR3,     /* a TVM register FEAT_FGT cannot name exists */
    LEAN_FGT_READBACK,  /* HFGRTR/HFGWTR did not read back as written */
    LEAN_FGT_OWNER      /* another CPU saved this vCPU's host values */
};
/* ACTIVE when FEAT_FGT can replace TVM/TRVM exactly on this core. MMFR3
 * [35:0]: TCRX, SCTLRX, S1PIE, S2PIE, S1POE, S2POE, AIE, MEC, D128; any of
 * them adds registers (or forms) TVM/TRVM trap that FEAT_FGT's HFGxTR cannot
 * name, so such a core keeps TVM/TRVM. */
static inline unsigned lean_fgt_admit(uint64_t mmfr0,uint64_t mmfr3)
{
    if(!((mmfr0>>56)&15))return LEAN_FGT_ABSENT;
    if(mmfr3&UINT64_C(0xfffffffff))return LEAN_FGT_MMFR3;
    return LEAN_FGT_ACTIVE;
}
/* The values to write: the host's bits kept, the TVM/TRVM set added, minus
 * ESR/FAR reads and CONTEXTIDR writes. */
static inline uint64_t lean_fgt_read(uint64_t host)
{return (host|LEAN_FGT_TVM)&~(LEAN_FGT_ESR|LEAN_FGT_FAR);}
static inline uint64_t lean_fgt_write(uint64_t host)
{return (host|LEAN_FGT_TVM)&~LEAN_FGT_CONTEXTIDR;}

/* One CPU's state, in the wide cache's arena pages (struct root_ext). Written
 * only by that CPU. Not reported: the census shows the effect. */
struct lean_trap_cpu {
    uint64_t status;        /* enum lean_fgt_status */
    uint64_t owner;         /* MPIDR that saved host_*; 0 = nothing to restore */
    uint64_t host_hfgrtr,host_hfgwtr,host_contextidr;
    uint64_t runs;          /* run-ahead attempts */
    uint64_t steps;         /* MRS emulated without a trap of their own */
    uint64_t ends;          /* runs ended by translation or range */
} __attribute__((aligned(64)));

/* At most this many instructions after one trap. */
#define LEAN_RUN_MAX 8u
/* An MRS with Op0=3 as the EC 0x18 ISS register tuple and Rt; 0 otherwise. */
static inline int lean_mrs(uint32_t word,uint64_t *reg,unsigned *rt)
{
    if((word&UINT32_C(0xfff80000))!=UINT32_C(0xd5380000))return 0;
    *reg=FAST_TRAP_SYSREG(3,(word>>16)&7,(word>>12)&15,(word>>8)&15,(word>>5)&7);
    *rt=word&31;
    return 1;
}
/* The syndrome a trap of that MRS reports: EC 0x18, IL, the tuple, Rt, read. */
static inline uint64_t lean_mrs_esr(uint64_t reg,unsigned rt)
{return (UINT64_C(0x18)<<26)|(UINT64_C(1)<<25)|reg|((uint64_t)rt<<5)|1;}
/* Apple PMC0..PMC9 (S3_2_C15_C{0..7,9,10}_0). */
static inline int lean_pmc(uint64_t reg)
{
    unsigned crm=(unsigned)((reg>>1)&15);
    return (reg&~(UINT64_C(15)<<1))==FAST_TRAP_SYSREG(3,2,15,0,0) && crm!=8 && crm<=10;
}
/* A run starts only where XNU has adjacent pairs: after ESR, FAR and PMC reads. */
static inline int lean_run_start(unsigned cls,uint64_t reg,int is_read)
{
    return is_read && (cls==FAST_TRAP_ESR || cls==FAST_TRAP_FAR ||
                       (cls==FAST_TRAP_IGNORE && lean_pmc(reg)));
}
/* Classes a run may emulate: reads whose lock-free emulation needs nothing
 * beyond the first trap's admission (no timer, key or IPI state). The caller
 * still applies the ignored registers' log-bit rule. */
static inline int lean_run_class(unsigned cls)
{
    return cls==FAST_TRAP_COUNTER || cls==FAST_TRAP_ESR || cls==FAST_TRAP_FAR ||
           cls==FAST_TRAP_IGNORE || cls==FAST_TRAP_ZERO || cls==FAST_TRAP_SPRR;
}

/* clock_rate_sample without its two divisions when guest/host is exactly 5/4
 * (24 MHz on 19.2 MHz): floor(5h/4) = h + floor(h/4), and clock_rate_sample is
 * that same floor for h < 2^62 (no overflow on either side). */
static inline uint64_t lean_rate_sample(const struct clock_rate *rate,uint64_t host)
{
    if(rate->host_hz && (uint64_t)rate->guest_hz*4==(uint64_t)rate->host_hz*5 &&
       host<(UINT64_C(1)<<62))
        return host+(host>>2);
    return clock_rate_sample(rate,host);
}
