/* SPDX-License-Identifier: MIT */
#pragma once

/*240MiB in4KiB pages. Keep the free-list sentinel representable by uint16_t;
 * root-cache slot masks remain64 bits and are independent of this capacity.
 * probes/monitor_work.py must reserve exactly this capacity. */
#define MONITOR_ARENA_PAGES 61440u
