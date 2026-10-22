# Guest and host compatibility

Snapintosh is an XNU compatibility layer on non-Apple Arm hardware. This
document describes the boundaries between the guest (Apple's kernelcache and
firmware bundle), the guest ABI the monitor implements, and the host resources
it runs on, and what is needed before a second guest or host is supported.

The current proof target is the stock J700 `mac17p` kernelcache from macOS 27
build 26A428 on the Snapdragon X2E. That is one qualified input bundle, not a
promise that every XNU kernelcache or Arm CPU boots.

## Three boundaries

1. **Guest identity.** `probes/guestprofile.py` describes a complete, audited
   kernelcache/device-tree/SPTM/TXM bundle: its hashes, monitor ABI, vectors,
   initial memory attributes, boot CPU, console node, entry-path addresses and
   the early heap's packed-pointer encoding constraints. `get_profile(name)`
   rejects unknown names. The exact image passed to `build()` is verified,
   including an explicit `--kernelcache` override. `--record` prints candidate
   hashes; it cannot certify an unexamined image.

2. **Guest ABI implementation.** `probes/xnuboot.py`, `probes/xnuboot.c`,
   `compat/sptm.c`, `compat/sptm-unmap.c`, `compat/sptm-update.c`,
   `compat/sptm-refs.c`, `compat/sptm-slide.c` and `compat/txm.c` implement
   `sptm-mac-v1`: the measured Mac SPTM handoff, 16 KiB kernel tables, 16/4 KiB
   user tables, monitor-call decoding and emulated Apple devices. A non-SPTM,
   embedded or changed SPTM ABI needs its own implementation; hash changes alone
   do not establish ABI compatibility.
   - **Device models.** `compat/device.{c,h}` is a portable, bounded
     register-model registry; `probes/devicemodel.py` derives placement from the
     guest device tree and rejects conflicting ranges and unsupported geometry.
     Mutable state belongs to each model instance.
   - **Memory controller and interrupts.** `MCCBootSpec` selects
     cache-capacity/quota, DCS policy and AMCC/DCS/SOCNI counter contracts.
     Counter APIs accept submitted virtual events; they do not manufacture host
     DRAM telemetry. `AICBootSpec` selects the interrupt controller's
     identification/EVENT contract. Neither grants host physical MMIO access;
     AIC delivery is a separate backend.
   - **Clocks.** `CounterClockBootSpec` audits the watchdog's base-clock ID
     binding. `probes/clocktree.py` supplies the running CPU's
     `fixed-frequency`, which populates base ID 4 (nclk), separately from
     `timebase-frequency`.
   - **DART.** The profile's `DARTBootSpec` selects the device identity
     contract. `probes/iommu.py` supplies validated, unique loader IDs and
     carries the guest register inventory in `built['dart_devices']`.
     Assignment does not enable DMA. Guest IDs and streams are translated by a
     backend, never passed directly to a Qualcomm SMMU.
   - **NVRAM.** `NVRAMBootSpec` selects the boot-time variable format and
     geometry; `probes/nvram.py` encodes an empty CHRP v2 store into the audited
     device-tree reservation. Existing nonempty data is never silently
     replaced.
   - **Page-table operations.** RETYPE uses a host-independent
     memory/publication callback interface. User-root allocation supports
     formats 0/1 with flags 2, ARM64_32 flags 0x22, and format 1/flags 6 for the
     x86 commpage, with unique ASIDs. Empty-root recycling requires a host
     retirement callback with ownership checks and translation invalidation.
     Typed empty table construction supports inactive format-0/1 user roots
     (16/4 KiB pages, 47-bit VAs, restricted to 32 bits for ARM64_32),
     including the commpage L3. Commpage RW/RO/RX allocation preserves the
     initialized payload; inactive commpage leaves enforce permissions and
     reference counts. Detach retains populated commpage tables and removes
     empty ordinary tables with parent-link accounting. Four 4 KiB subtables
     link and detach together and count as one 16 KiB frame link; leaf
     references aggregate over the containing physical frame.
   - **Mapping and updates.** Empty table installation and region unmapping use
     the same memory interface; unmapping removes both guest leaves and their
     hardware shadow. MAP_PAGE's output pointer is translated through a bounded
     guest aperture (a physical PTE address is not a guest pointer). Frame-type
     descriptors come from the selected profile's audited SPTM image. Region and
     disjoint updates use bounded guest/shadow callbacks and preflight the whole
     batch; the host publishes the shadow and invalidates translations. A
     shared reference transaction accounts for allocator data aliases and L3
     entries across MAP_PAGE, updates and unmap. The physical aperture is
     excluded; the loader proves the initial allocator baseline before upload.
   - **SLIDE_REGION** uses a profile-selected segment allowlist resolved from
     Mach-O headers, a reserved destination window and bounded callbacks. It
     moves aliases and updates physical-to-virtual metadata while the guest is
     stopped; the host publishes tables and invalidates translations before
     resuming. Firmware addresses are not embedded in the portable C path.

   These are boot-compatibility semantics, not full SPTM security enforcement.

3. **Host resources.** `probes/bootcontract.py` contains immutable
   `HostRuntime`, `PhysicalRange` and `Framebuffer` values. The q1n1 adapter
   derives the counter frequency, heap and GOP framebuffer from boot
   information. Another transport or board adapter should produce the same
   values from its own evidence. Host resource discovery must not select an
   Apple kernel profile.

`configure_guest(name, directory)` configures one loader instance before a
build. It still uses loader globals, so simultaneous builds need separate
processes. The firmware directory applies consistently to the tree and both
monitors; firmware files are never modified.

## Safety and evidence contracts

- Physical ranges must be nonempty, aligned, within the implemented 36-bit
  stage-2 address space and nonoverlapping. This limit belongs to the current
  EL2 backend; a wider host must not silently truncate addresses.
- The flat frame map covers RAM/reserve and the optional panel. Holes carry
  type zero; stage 2 enforces ownership and leaves the gaps absent. The
  handoff's monitor stack fields describe VAs, not physical boundaries; the TXM
  stack pages and a separate CPU-stack window are reserved and zeroed, and the
  profile's audited stack count must agree with the guest device tree.
- EL2's address-translation helper preserves PAR_EL1 across instruction steps.
  The diagnostic `SNAP_WATCH_WRITE=<guest VA>` traps before writes to one mapped
  guest page and captures the writer; it never opens a new physical mapping.
- Signing-related monitor calls are outside the scope of the public
  documentation.
- The early-mapping recipe is derived from the selected device tree (console
  windows, CPU register windows, two AIC mappings and the panel) and must fit
  the loader's initial L3 reservation. Later table expansion is supported for
  empty 16 KiB children under the kernel root. It is a conservative preflight,
  not a bound on every future kernel mapping.
- Framebuffer stride is in bytes at the adapter boundary. GOP formats 0/1 are
  accepted; invalid dimensions, insufficient backing, unsupported formats and
  heap overlaps are errors.
- CPU requirements are checked by the EL2 probe. A host descriptor does not
  prove NV2, debug trapping, translation support, interrupt delivery or board
  qualification.
- The audited guest profile supplies the virtual kernel-return HCR value; NV2's
  VNCR backing is initialized from it, separate from the host's actual HCR.
  Leaving the virtual HCR zero while CurrentEL reports EL2 would select XNU's
  VM-exit path on ordinary kernel exceptions.
- `compat/uat.c` answers the audited GPU address-translation information
  queries from guest device-tree geometry and a bounded shared reserve. The
  Apple GPU itself is not modelled; the A16's Adreno GPU is driven by
  Snapintosh's own kext and Metal plug-in instead.
- Pointer authentication: `compat/pauth.c` handles the architectural PACGA
  operation for the guest through a host backend.
- `compat/exception.c` handles ordinary kernel page-fault delivery and plain
  ERET back to the nested kernel. Virtual EL2t/h becomes physical EL1t/h; saved
  flags and stack selection are preserved.
- Runs hash the complete framebuffer inside the EL2 probe immediately before
  guest entry and after the stop, while q1n1's UI is suspended, which separates
  guest drawing from q1n1's own redraws. A profile-specific memory witness reads
  the console's `vinfo`; missing witness metadata disables the diagnostic rather
  than reusing another kernel's addresses.

## Running the bundle checks

```sh
python3 tools/test-bootcontract.py
python3 tools/test-profile.py
python3 tools/test-classify.py
python3 probes/xnuboot.py --check --guest-profile j700ap-26A428

# Serial console, no panel mapping.
SNAP_NO_FB=1 python3 probes/run.py xnuboot --console serial
# Panel handed over, printf still to the UART.
python3 probes/run.py xnuboot --console serial
# Same mapping, serial output bit clear so printf draws on the panel.
python3 probes/run.py xnuboot --console panel
```

Loader and runner both accept `--guest-profile`, `--firmware-dir` and
`--kernelcache`. A directory override relocates an audited bundle; it does not
relax identity validation. `--device` selects the q1n1 transport endpoint
(for example `--device udp://<interface>`). Full boots are driven by
`tools/cycle.py`; see [RUNNING.md](RUNNING.md).

## Device boundary

Local reference implementations are listed in
[DEVICE-REFERENCES.md](DEVICE-REFERENCES.md): emuasi's portable AIC state model
and m1n1-j700's ASC/RTKit drivers. They are implementation references, not
Snapdragon qualification.

- **Watchdog.** The virtual WD1 primary bank has a timed counter, bite
  comparator, keepalive and a latched guest-reset request; a guest reset stops
  the harness, never the host.
- **AIC.** The flat-bank model supports global enable, masks, software
  requests, producer levels and EVENT auto-mask/acknowledge; the host adapter
  drives virtual IRQs separately from the timer's virtual FIQ.
- **Timers.** The kernel deadline timer is a separate portable model; a q1n1
  backend multiplexes the physical timer between guest deadlines, virtual device
  deadlines and the run budget. A rate adapter converts the host's 19.2 MHz
  counter to the profile's 24 MHz guest domain; Apple counter aliases,
  deadlines and WFE event edges agree with that conversion. Direct CNTFRQ
  consumers in scaled executable images are rejected before boot.
- Keep guest-facing AIC registers, mask/pending/acknowledge state and interrupt
  numbers separate from the host interrupt controller and timer adapter.
  Architectural timer delivery and AIC device interrupts are distinct paths.
- **ASC/mailbox transports** and the services above them are separate
  interfaces: queues, doorbells and interrupts first, service protocols such as
  SMC, AOP, SEP or ANS2 storage (see [FULL-INSTALL.md](FULL-INSTALL.md)) above
  them.
- Any driver the guest sees must receive real supported protocol behaviour or
  an explicit unsupported outcome; optional devices are withdrawn from the
  device tree instead. A SEP handshake is not secure-enclave firmware,
  persistent key services, Touch ID or Apple security enforcement.

## Before a second guest or host

For another kernelcache: identify its monitor family and granules, audit the
complete firmware bundle, re-derive the entry/vector and handoff consumers, and
add an explicit profile with evidence. Move the remaining J700 diagnostic
addresses in `probes/run.py`, the early-mapping recipe and ABI layout constants
into the guest backend before registering a second profile. A missing
diagnostic must disable that diagnostic, never substitute J700 addresses. Add
offline negative tests and run the same hardware acceptance gates. Report source
support, offline validation and live qualification separately.

For another host: implement resource discovery against `HostRuntime`, keep
board-specific reset, USB, interrupt-controller and display operations behind
its adapter, and verify the CPU's required features before entry. The C and
assembly entry path and q1n1 heap reservations still need an explicit,
versioned transport ABI; the Python resource contract is the first boundary,
not a finished HAL.
