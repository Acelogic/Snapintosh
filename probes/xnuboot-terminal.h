/* SPDX-License-Identifier: MIT */
#pragma once
/* Native P_CALL result, separate from the guest's OUT_STATUS report word.
 * A nonzero value forbids host target I/O and RAM reuse until external recovery.
 * Keep probes/xnuboot_terminal.py in agreement; the replay checks this boundary. */
#define XNUBOOT_TERMINAL_OK        0
#define XNUBOOT_TERMINAL_OWNERSHIP 0x51554e01
#define XNUBOOT_TERMINAL_GPU       0x51554e02
