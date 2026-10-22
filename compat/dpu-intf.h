/* SPDX-License-Identifier: MIT */
/*
 * The X2E (glymur) DPU's eDP interface timing engine, as one read-only page: shared by the monitor
 * (compat/display-timing.h, -DSNAP_DISPLAY_TIMING=1), the loader (probes/displaytiming.py), the kext
 * (AdrenoDisplayBeam.h, -DADRENO_BEAM=1) and the q1n1 survey (tools/survey-dpu-intf.py). Constants only.
 *
 * Address, from two independent sources (agents/tear-free FAILURE-MODES.md A1):
 *   glymur.dtsi mdss_mdp "mdp" reg 0x0ae01000 + dpu_12_2_glymur.h intf_5 .base 0x39000  = 0x0ae3a000;
 *   dpu_hw_interrupts.c MDP_INTF_REV_7xxx_OFF(5) = 0x34000 + 0x1000 * 5 = 0x39000 from the same "mdp" base.
 * intf_5 is the eDP interface: glymur.dtsi mdss_mdp port@5 (mdss_intf5_out) -> mdss_dp3 (the eDP controller,
 * mdss_dp3_phy "edp" at 0x0faac00); dpu_12_2_glymur.h intf_5 .controller_id = MSM_DP_CONTROLLER_3.
 *
 * Register offsets: Linux drivers/gpu/drm/msm/disp/dpu1/dpu_hw_intf.c. Every value is in the timing engine's
 * "vsync counter" units (pixel clocks from the start of the vsync pulse) except the two counters, which count
 * frames and lines from the same origin (dpu_encoder_vsync_time: time_to_vsync = line_time * (vtotal - line)).
 */
#ifndef SNAP_DPU_INTF_H
#define SNAP_DPU_INTF_H

#define DPU_MDSS_PA                 0x0AE00000ULL   /* glymur.dtsi mdss reg (HW_VERSION at +0) */
#define DPU_MDP_PA                  0x0AE01000ULL   /* glymur.dtsi mdss_mdp reg "mdp" */
#define DPU_INTF_INDEX              5u              /* eDP: mdss_dp3 */
#define DPU_INTF_STRIDE             0x1000ULL       /* MDP_INTF_REV_7xxx_OFF */
#define DPU_INTF_FIRST              0x34000ULL      /* intf_0 */
#define DPU_INTF_PA                 (DPU_MDP_PA + DPU_INTF_FIRST + DPU_INTF_STRIDE * DPU_INTF_INDEX)
#define DPU_INTF_PAGE               0x1000ULL

/* The registers the beam reads, and nothing else (FAILURE-MODES.md A1). */
#define DPU_INTF_TIMING_ENGINE_EN   0x000u
#define DPU_INTF_CONFIG             0x004u          /* bit 29 ACTIVE_H_EN, bit 30 ACTIVE_V_EN, bit 31 prog fetch */
#define DPU_INTF_HSYNC_CTL          0x008u          /* period << 16 | pulse width */
#define DPU_INTF_VSYNC_PERIOD_F0    0x00Cu          /* vtotal * htotal */
#define DPU_INTF_DISPLAY_V_START_F0 0x01Cu
#define DPU_INTF_DISPLAY_V_END_F0   0x024u
#define DPU_INTF_ACTIVE_V_START_F0  0x02Cu
#define DPU_INTF_ACTIVE_V_END_F0    0x034u
#define DPU_INTF_DISPLAY_HCTL       0x03Cu          /* end << 16 | start */
#define DPU_INTF_ACTIVE_HCTL        0x040u
#define DPU_INTF_CONFIG2            0x060u          /* bit 0 DATABUS_WIDEN: horizontal values in pixel pairs */
#define DPU_INTF_FRAME_LINE_COUNT_EN 0x0A8u         /* Linux writes 3; read only here */
#define DPU_INTF_FRAME_COUNT        0x0ACu
#define DPU_INTF_LINE_COUNT         0x0B0u
#define DPU_INTF_STATUS             0x26Cu          /* bit 0: timing engine enabled (DPU >= 5) */
#define DPU_INTF_AVR_CONTROL        0x270u          /* nonzero: adaptive refresh, refused */
#define DPU_INTF_CFG_ACTIVE_V_EN    (1u << 30)
#define DPU_INTF_CFG2_WIDEN         (1u << 0)
#define DPU_INTF_LAST_READ          DPU_INTF_AVR_CONTROL

/* The guest's discovery (properties on the GPU node, probes/displaytiming.py advertise()). */
#define DPU_INTF_ABI                1u
#define DPU_INTF_ABI_PROPERTY       "snapintosh,dpu-intf-abi"     /* u32 DPU_INTF_ABI */
#define DPU_INTF_PA_PROPERTY        "snapintosh,dpu-intf-pa"      /* u64 DPU_INTF_PA, little-endian */

/* The q1n1 survey's clock checks before any MDSS read (FAILURE-MODES.md A2): Linux dispcc-glymur.c. */
#define DPU_DISPCC_PA               0x0AF00000ULL
#define DPU_DISPCC_MDSS_MDP_CBCR    0x8010u
#define DPU_DISPCC_MDSS_AHB_CBCR    0x80B0u
#define DPU_DISPCC_MDSS_CORE_GDSCR  0x9000u
#define DPU_CBCR_CLK_OFF            (1u << 31)

#endif
