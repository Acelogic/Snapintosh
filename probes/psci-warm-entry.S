/* SPDX-License-Identifier: MIT */
/* Execute the selected stock secondary entry with read-only guest memory;
 * trap before its reset handler, then restore the watchdog and power off. */
#define COHERENT 1
#define WARM_ENTRY 1
#include "psci-watchdog.S"
