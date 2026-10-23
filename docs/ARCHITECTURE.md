# Architecture

This document explains how Snapintosh runs Apple's stock macOS 27 kernel on a
Snapdragon X2 Elite laptop, one layer at a time. The GPU and display path and
the Wi-Fi path get their own sections because they cross every layer.

```
 Mac host (tools/cycle.py, q1n1 proxy client)
      |  USB-C, NCM network link
      v
 A16 UEFI firmware
      |
 q1n1 ............................ EL2  UEFI proxy (fork of m1n1)
      |  uploads + chainloads
 Snapintosh monitor .............. EL2  compat/, shadow/, probes/xnuboot.*
      |  stage 2, traps, monitor calls
 XNU (stock J700/T8140) + AuxKC .. EL1  AdrenoX2 + AdrenoDisplay, SnapI2CHID, ...
      |
 macOS userspace ................. EL0  WindowServer, apps, AdrenoMetal.bundle
```

## 1. q1n1: the host side

[q1n1](https://github.com/Snapintosh/q1n1) is a UEFI application derived from
Asahi Linux's m1n1. It starts from the A16's firmware, calls
`ExitBootServices` and keeps the CPU at EL2. Then it brings up a USB device
port as an NCM network interface to the Mac and serves m1n1's proxy protocol
over UDP. Through that link the Mac can:

- read and write memory and registers, and call code at EL2;
- upload the Snapintosh monitor and guest image, and start them;
- chainload a fresh copy of itself (a new *generation*), so that a stopped
  guest can be inspected and then replaced without a cold reboot;
- run the A16-specific hardware steps: GPU power-up (GMU boot, HFI, OPP
  table), DDR and LLCC votes, the read-only surveys, the native NVMe reads and
  writes, and the battery and thermal queries.

The Mac selects the NCM interface with `--device udp://<interface>`. The
interface name depends on which USB port is used.

## 2. The Snapintosh monitor (EL2)

Apple silicon runs the macOS kernel under two higher-privileged monitors:

- **SPTM** owns the page tables and page types.
- **TXM** owns address-space and trust bookkeeping.

XNU reaches them through monitor calls and expects their contracts to hold.
The X2 Elite has neither, and it has no Apple devices either. The Snapintosh
monitor fills that gap. It is plain C and assembly (`compat/`, `shadow/`), and
the loader in `probes/xnuboot.*` builds it into the guest image.

| Concern | What the monitor does |
| --- | --- |
| SPTM/TXM calls | Implements the call endpoints the 26A428 kernel uses: page retyping, mapping, unmapping, nesting, region updates, address-space create and destroy, DART mappings. They are checked against Apple's real SPTM through the `tools/qemu-sptm-oracle/` ground-truth runs. |
| Page tables | XNU writes 16 KiB-granule tables. The X2 Elite's cores support 4 KiB and 64 KiB, not 16 KiB. `shadow/` walks the guest's tables and maintains 4 KiB shadow tables that the hardware uses. Hot paths have fast variants: root caches, hardware-walk user roots for 4 KiB user processes, and fine-grained locks. |
| CPU | Six vCPUs on physical cores. The ID registers are presented as an Apple core. Apple-only system registers and instructions are trapped and emulated or answered (see [APPLE-ENCODINGS.md](APPLE-ENCODINGS.md)). PSCI-based CPU start. |
| Interrupts and timers | Emulates Apple's AIC (interrupt controller, IPIs) and the timebase the kernel expects. Physical interrupts are forwarded. Fast paths exist for timer ticks and IPIs. |
| Device tree | The loader starts from Apple's J700 device tree, adapts it to this machine and adds nodes for Snapintosh devices (`probes/appledt.py`). |
| Storage | A virtual ANS2 (Apple's NVMe controller) in `compat/ans.c`, backed by the A16's real NVMe through `compat/nvme-host.c`. The guest sees an Apple SSD and boots its installed volumes from it. |
| GPU | Owns the Adreno's ring buffer and SMMU on the guest's behalf (section 4). |
| Console and stop | A console ring that the Mac reads through q1n1, an optional two-way console shell (`tools/guest-console.py`), a watchdog, and the early-stop path: a stop on request, on a kernel panic or on the thermal guard. Each stop leaves a report that `tools/cycle.py` decodes. |
| Guards | The thermal guard samples the SoC sensors and stops the run at a limit. The GPU and CPU DVFS governors stay off unless the guard is on. |

Most features are compile-time defines selected per run. `tools/cycle.py`
turns them on with one flag each, so the default monitor stays fixed and every
change can be compared with it. [COMPATIBILITY.md](COMPATIBILITY.md) lists the
contracts and their boundaries. [BOOT-CHAIN.md](BOOT-CHAIN.md) walks through
the boot.

## 3. The kernel and the AuxKC (EL1)

The kernel is Apple's stock J700/T8140 kernelcache from the 26A428 restore
image. By default it is not modified. A small set of opt-in patches exists for
hot traps that the monitor cannot make cheap, each found by instruction
pattern. See [KERNEL-PATCHES.md](KERNEL-PATCHES.md).

Snapintosh's kernel extensions are linked into an auxiliary kernel collection
(AuxKC) with `kmutil` against the KDK, and the loader places it:

- **AdrenoX2** (`gpu/adreno-kext/kext/`): an IOGPUFamily accelerator for the
  Adreno X2-90, with **AdrenoDisplay**, an IOMobileFramebuffer for the internal
  2880x1800 eDP panel. It also carries a small virtual Ethernet device for the
  guest network path.
- **SnapI2CHID** (`drivers/snap-i2c-hid/`): a GENI I2C controller and HID over
  I2C driver for the built-in keyboard and the precision touchpad. It presents
  the touchpad to macOS as an Apple multitouch device, so gestures work.
- **SnapintoshQCC2072** (`drivers/snap-qcc2072/`): the native Wi-Fi controller
  (section 5).
- **SnapintoshBootFramebuffer**: a codeless kext for early boot profiles.

## 4. The GPU and display stack

```
 app / WindowServer / Core Animation
      |  Metal API
 AdrenoMetal.bundle (EL0)        encoders -> Adreno command streams (IBs);
      |                          shaders via the air2ir3 runtime (AIR -> ir3)
      |  IOGPU user client: command buffers, resources, kernel commands
 AdrenoX2 kext (EL1)             resource lists, relocation, validation,
      |                          cache maintenance, fences, completion stamps
      |  monitor calls (IB START/POLL, FILL32, FENCE, DART map/unmap, cache)
 Snapintosh monitor (EL2)        validates each IB against the allowed
      |                          registers, writes the ring, owns the SMMU
 Adreno X2-90 (hardware)         CP executes; GMU firmware manages power
```

**The plug-in.** `AdrenoMetal.bundle` (`gpu/adreno-kext/plugin/AdrenoMetal/`)
is the Metal driver that IOGPU loads for the AdrenoX2 accelerator. The kext's
personality names it with `MetalPluginName`. The plug-in implements the device,
resources, render, blit and compute encoders and pipelines. It encodes Adreno
a8xx command streams (indirect buffers, IBs) and hands them to the kernel as
IOGPU command buffers. Shaders arrive as AIR. The air2ir3 compiler
([../gpu/air2ir3/README.md](../gpu/air2ir3/README.md)) turns them into ir3
machine code. Compiled shaders are cached on disk per user, and a precompiled
pack can be linked into the bundle. Staging memory for uniforms and copies
comes from size-classed arenas that return GPU address space when idle. Large
blits are split into chunks of at most 1 MiB, because a single very large
`CP_MEMCPY` can hang the GPU.

**The kext.** For each kernel command, AdrenoX2:

1. stages and relocates the IB;
2. validates it against the resource list;
3. maps the memory it uses into the GPU's address space (a DART-style mapper
   over the SMMU; `--gpu-va-wide` widens the GPU VA window from 3 GiB to 15 GiB);
4. cleans or invalidates CPU caches only for the bytes the GPU will touch;
5. asks the monitor to run it.

Completion goes back to IOGPU through event stamps, so command buffers complete
when the GPU retires them, not when the call returns. With pipelining on
(`--present-pipeline 1`), WindowServer's submission returns as soon as the IB
is in flight. Its CPU work for the next frame then overlaps the GPU work for
the current one.

**The monitor.** The guest never writes the GPU's ring or SMMU directly. The
monitor checks each IB for register writes that would break isolation, using
protect tables derived from the hardware catalogue. It then writes the ring,
starts the IB and answers polls. With `--ib-async` the GPU's execution no
longer holds the monitor's global lock. A budget bounds each IB. With
`--gpu-recover`, an IB that overruns is counted and the stack recovers instead
of latching the GPU off for the rest of the boot. The monitor also maps the GPU
memory the kext asks for and performs its cache maintenance.

**Present path and frame pacing.** WindowServer swaps a finished layer-0
surface to AdrenoDisplay. AdrenoDisplay copies it to the scanout buffer that
the panel's display controller (DPU) is already scanning. Snapintosh does not
reprogram the display controller. Four mechanisms keep that copy correct and
on time:

- **Present sync.** The plug-in's `commitAndWaitUntilSubmitted` waits until
  the kernel has the command buffer. The kext also marks each surface that a
  GPU job is still writing, and AdrenoDisplay does not copy a marked surface
  (within a bound). Together these removed the stale bands and flicker that
  came from copying frames before they were drawn.
- **Beam-synced present.** With `--present-beam`, the monitor maps one
  read-only page of the DPU's interface block into the guest. AdrenoDisplay
  reads the panel's real scan line and locks its present tick to the real
  vblank. The copy starts at the vblank and stays ahead of the scanout, which
  gives tear-free output without page flipping.
- **Late latch.** With `--present-latch`, input and frame data are taken as
  late as the measured render time allows, to cut touch-to-photon latency.
- **Cursor plane.** AdrenoDisplay advertises a hardware cursor plane and
  composites the cursor layer itself, so a cursor move does not need a new
  WindowServer frame.

**Clocks and bandwidth.** By default the GPU runs at its 310 MHz boot level:

- `--gpu-dvfs` lets the monitor vote the GPU between 310 MHz and a ceiling
  (`--gpu-dvfs-ceiling`) through the GMU's HFI interface, from busy time it
  measures.
- `--cpu-dvfs` sets the CPU clusters' SCMI performance levels.
- `--ddr-vote` and `--llcc` raise the DDR and interconnect votes and enable
  the last-level-cache slices before the GPU starts.

All of these need `--thermal-guard`. The governors clamp from 75 °C, and the
guard stops the run at its limit.

**Power-up and quiesce.** q1n1 powers up the GPU before the guest starts. That
covers the RPMh rails, clocks, the GMU firmware boot, HFI and the OPP table,
and the CP microcode. The monitor then adopts the GPU. After a run, the GPU is
quiesced gracefully (`cycle.py installed-fresh --quiesce`) before the next
preparation. The GPU is never re-initialised while it is running.

## 5. Wi-Fi (QCC2072)

The A16's Wi-Fi is a Qualcomm QCC2072 (ath12k family) on PCIe. Two pieces
exist:

- **The native controller.** `drivers/snap-qcc2072/` implements an
  IO80211-family controller for macOS, with the firmware download and the
  MHI/copy-engine transport. `tools/build-qcc2072-native.py` builds it and
  links it into a guest AuxKC. `cycle.py installed-fresh --qcc2072-wifi` passes
  the PCIe function through to the guest; the monitor maps its BARs and a DMA
  window. The controller loads, but it is not yet integrated with the macOS
  Wi-Fi menu and network stack.
- **The host-proxy harness.** The same transport and station code can also
  run on the Mac and drive the card through q1n1, with the guest not running.
  On the A16 it has scanned, completed a WPA2-PSK connection, obtained a DHCP
  lease and answered ping. The passphrase is read from the Mac's keychain,
  never from the command line, and key material is redacted from all traces.

The firmware comes from linux-firmware (`ath12k/QCC2072/hw1.0`), and the board
file from ASUS's Windows driver package. Neither is shipped.

## 6. Input

SnapI2CHID drives the keyboard and touchpad over the SoC's GENI I2C
controllers. The monitor gives the guest only the controller pages it needs.
The touchpad runs in precision-touchpad mode and reaches macOS as an Apple
multitouch device, so scrolling, gestures, Mission Control and app switching
work. While the touchpad is touched it is polled faster
(`--input-active-us`), which lowers latency.

## 7. The host tools

Everything is driven from the Mac:

- `tools/cycle.py` runs a boot cycle: prepare, check, boot, capture, preserve,
  quiesce, retire. It refuses unsafe states. See [RUNNING.md](RUNNING.md).
- `tools/inspect-logs.py` decodes a run's logs.
- `tools/guest-console.py` gives a live console into the running guest.
- `tools/kc-analyze.py`, `tools/kc-symbolicate.py`, `tools/sptm-map.py` and
  `tools/sptm-dispatch.py` read Apple's binaries to locate the contracts the
  monitor must meet.
- The native test suites in `tools/test-*.c` link the real monitor sources
  against models and run on the Mac without hardware.
