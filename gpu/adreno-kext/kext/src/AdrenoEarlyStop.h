/* SPDX-License-Identifier: MIT */
// AdrenoEarlyStop.h - ask the monitor to end this run early (compat/early-stop.h, ADRENO_GUEST_STOP).
//
// Opt-in per launch: the monitor advertises ADRENO_GUEST_STOP_PROPERTY (and its default delay) on the GPU node
// only when SNAP_EARLY_STOP=guest. Without it every call below returns without an HVC. With it, the first
// request -- the first successful AdrenoDisplay present, the plug-in's first unrecoverable failure, or the end of
// WindowServer's GPU task -- asks the monitor to stop the run after the advertised delay, so logs reach disk
// before every CPU quiesces. Later requests are counted and dropped; the monitor also keeps only the first.
#pragma once
#include <IOKit/IOService.h>
#include <stdint.h>

void AdrenoEarlyStopConfigure(IOService *gpuNode);    // reads the node's properties once, in configureDevice
bool AdrenoEarlyStopEnabled();
// EARLY_STOP_ACCEPTED (0) or _DUPLICATE (1) from the monitor, 1 when this kext already sent a request,
// EARLY_STOP_E_DISABLED without the launch's opt-in, or the monitor's negative refusal.
int AdrenoEarlyStopRequest(uint32_t reason, uint64_t detail);
void AdrenoEarlyStopPresented(uint64_t presents);     // AdrenoDisplay: a surface reached the panel
// AdrenoTask: WindowServer's GPU task was torn down after it had allocated GPU memory. WindowServer keeps its
// device for as long as it runs, so this is its process ending (a crash, as generation71's aborts). At most once.
void AdrenoEarlyStopClientDied(uint64_t detail);
