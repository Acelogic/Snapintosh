# Booting stock XNU on the Snapdragon X2 Elite

This document explains how Snapintosh boots the unmodified macOS 27 kernelcache
(build `26A428`, board `j700ap`, SoC T8140, `kernelcache.release.mac17p`) on a
Snapdragon X2 Elite (X2E-96-100). It covers the privilege layout, how the
monitor stands in for SPTM and TXM, page-table translation, the boot
structures and device tree, CPU topology, interrupts and timers. For the
overall component map see [ARCHITECTURE.md](ARCHITECTURE.md); for the list of
opt-in kernel-code changes see [KERNEL-PATCHES.md](KERNEL-PATCHES.md); for why
the hardware needs any of this see [FEASIBILITY.md](FEASIBILITY.md).

No XNU binaries are recompiled. Hardware-specific drivers for the Snapdragon platform
are packaged as standard kernel extensions (AuxKC). Proprietary Apple firmware inputs
are extracted from user-supplied restore images.

## 1. What Apple's boot chain assumes, and what this machine has

Apple silicon has no EL3. Its privilege stack is EL0-EL2 plus GXF (Guarded
eXecution Feature), which adds a guarded shadow of each exception level,
entered with `genter` and left with `gexit`:

| Level | Normal world | Guarded world |
| --- | --- | --- |
| EL2 / GL2 | XNU (under VHE) | SPTM: owns every page table |
| EL1 / GL1 | - | TXM: on Apple hardware, responsible for code-signing policy |
| EL0 / GL0 | user space | - |

On Apple silicon iBoot hands over to SPTM, which builds the kernel's initial
address space and enters XNU. The Snapdragon has no GXF, cannot walk a 16 KiB
translation granule, and does not implement Apple's private instructions or
system registers. Snapintosh therefore runs this stack instead:

| Level | Component | Role |
| --- | --- | --- |
| EL2 | UEFI firmware, then q1n1 | q1n1 is a UEFI EL2 proxy derived from Asahi Linux's m1n1; it receives the monitor and guest image over USB and starts them |
| EL2 | Snapintosh monitor (`probes/xnuboot.c`) | stands in for SPTM and TXM, emulates Apple devices, owns stage 2 and the shadow page tables |
| EL1 | stock XNU | believes it runs at EL2; `FEAT_NV2` makes that work |
| EL0 | macOS user space | unchanged |

The loader (`probes/xnuboot.py`) prepares everything on the host: the rebased
kernelcache, XNU's initial 16 KiB tables, the boot structures and the device
tree. The monitor then does what can only be done at EL2.

| Apple mechanism | On this silicon | Replacement |
| --- | --- | --- |
| 16 KiB translation granule | absent (measured) | 4 KiB shadow tables built at EL2, both halves of the address space |
| `genter` into GL2/GL1 | undefined encoding | intercepted at EL2 (section 4) |
| SPTM / TXM | no guarded world | the monitor implements their call interfaces |
| Apple IMPDEF system registers | undefined encodings | `HCR_EL2.TIDCP` traps them to EL2 |
| XNU expects to be EL2 | EL2 belongs to the monitor | `FEAT_NV2` redirects its EL2 register accesses to memory |

## 2. Inputs

`tools/extract-firmware.py` reads `BuildManifest.plist` for the board, so the
components it extracts are the ones Apple ships together: the kernelcache
(an `MH_FILESET` of 362 kexts), SPTM (`sptm.t8140.release`), TXM, and
`DeviceTree.j700ap`. SPTM and TXM are never executed on the Snapdragon; the
monitor implements them. Their binaries are used as references, for example
`tools/sptm-dispatch.py` decodes SPTM's own endpoint table to map endpoint
numbers to Apple's `SPTM_FUNCTIONID_*` names.

`tools/kc-load.py` lays the segments out and applies all 1,001,004
`LC_DYLD_CHAINED_FIXUPS` rebases. Without that pass every pointer in
`__DATA_CONST` and `__DATA` is a packed rebase field, not an address. The
kernelcache carries a `__DATA_SPTM` segment with no compile-time pointers: it
is the window SPTM fills at boot, and here the loader fills it.

## 3. Exception levels: XNU at EL1, believing it is EL2

On Apple silicon `HCR_EL2.E2H` is RES1 and the kernel runs at EL2 under VHE,
with SPTM in the guarded shadow of EL2. The kernelcache accordingly writes EL2
registers such as `SMPRIMAP_EL2`. At EL1 those accesses are undefined, and an
undefined instruction at EL1 is delivered to EL1, where the hypervisor never
sees it.

The X2 Elite implements `FEAT_NV2` (`ID_AA64MMFR2_EL1.NV = 2`). With
`HCR_EL2.{NV, NV2}` set and a `VNCR_EL2` page per CPU, EL1 accesses to EL2
registers become loads and stores to that page. XNU runs unmodified and its
view of "EL2 state" lands in memory the monitor can read. `VNCR_EL2` takes an
address in EL2's own translation regime, not the guest's.

Other identity choices:

- The ID register group is passed through from the hardware with features the
  monitor cannot stand behind cleared (`probes/idregs.h`). Apple IMPDEF
  registers trap through `HCR_EL2.TIDCP`; unknown ones read as zero and drop
  writes, and are logged.
- `AMXIDR_EL1` must advertise a version or XNU panics; the monitor reports one
  while the AMX enable register stays zero, so XNU never uses AMX. See
  [APPLE-ENCODINGS.md](APPLE-ENCODINGS.md).
- `VMPIDR_EL2` gives each vCPU the affinity of its `cpu` node in the device
  tree. `MIDR_EL1` is left as Qualcomm's: the kernel reads it once.
- The monitor manages the guest's pointer-authentication keys across the
  EL1/EL2 boundary.

## 4. Monitor calls: standing in for SPTM and TXM

### The interface

XNU reaches its monitors with `genter` (`0x00201420`). Every call site is a
uniform stub that builds a routing word in `x16` from immediates -
`domain[55:48]`, `table[39:32]`, `endpoint[31:0]` - marshals eight arguments,
and executes either `genter` or a paired alternate encoding, `0xd4e00000`. A
byte in `__DATA_CONST` chooses between them, and XNU copies that byte from a
feature bit in SPTM's boot structure (section 6). Because the monitor builds
that structure, it keeps XNU on `genter`.

`tools/kc-analyze.py` replays each stub's writes to `x16` and lists the whole
interface. All 348 call sites sit in five 4 KiB pages:

| Domain | Table | Name | Stubs |
| --- | --- | --- | --- |
| 0 | 0 | `XNU_BOOTSTRAP` (endpoint from `x0`) | 56 |
| 0 | 3 | `T8110_DART_XNU` | 19 |
| 0 | 5 | `SART` | 3 |
| 0 | 6 | `NVME` | 10 |
| 0 | 7 | `UAT` (GPU MMU) | 14 |
| 0 | 9 | `CPUTRACE` | 13 |
| 0 | 10 | `HIB` | 6 |
| 0 | 11 | `GEN3_DART_XNU` | 19 |
| 0 | 13 | `T6000_DART_XNU` | 16 |
| 0 | 14 | unnamed | 16 |
| 2 | 0 | `TXM_XNU` | 1 |
| 3 | 0 | cL4 ringgate (exclaves) | 1 |

Only domain 0 matters for a first boot. Exclaves are deferred.

### How a call reaches EL2

An undefined instruction at EL1 cannot be routed to EL2 by any `HCR_EL2` bit.
The monitor has used three mechanisms, each cheaper than the last:

1. **Discovery mode.** The five call pages are execute-never at stage 2, so
   the fetch faults to EL2 (`ESR_EL2.EC = 0x20`). A fetch at a known call site
   is serviced and returned from; any other instruction on those pages is run
   by lifting the protection and single-stepping one instruction
   (`MDCR_EL2.TDE`, `MDSCR_EL1.SS`). This needs no knowledge of the stub
   layout and was used to find it.
2. **Native-call mode** (stock image, no code changes; `compat/native-call.h`,
   `probes/nativecalls.py`). The call instruction executes and raises an
   undefined-instruction exception to XNU's own vector. XNU's vector page is
   execute-never at stage 2, so the vector fetch traps to EL2. The monitor
   identifies the call by the faulting PC against a pinned inventory of
   call sites, services it, and restores EL1's exception registers. The few
   kernel instructions that write `ELR_EL1`/`SPSR_EL1` directly are handled on
   their own guarded pages. No call page is single-stepped.
3. **HVC call entry** (opt-in kernel patch 1). The 348 call words are replaced
   by `HVC #0x5350`, one instruction each, so a call is a single direct exit
   to EL2 with no EL1 exception state to repair.

The image is pinned by digest; a different kernelcache is refused rather than
patched.

### What the monitor implements

The endpoint implementations live in `compat/sptm.c` and the
`compat/sptm-*.c` files (mapping, unmapping, updates, references, slides,
DART), with `compat/txm.c` for the TXM domain. The main groups:

- **Bootstrap:** `FIXUPS_COMPLETE` (the loader already applied them),
  `REGISTER_CPU`, `REGISTER_EXC_RETURN`, `CPU_ID` (a 16-bit per-CPU slot),
  `SERIAL_PUTC` and `SERIAL_DISABLE` (early console through the monitor),
  `LOCKDOWN` (acknowledged; the monitor does not enforce CTRR-style text
  immutability).
- **Page tables:** `MAP_PAGE`, `UNMAP`, `UPDATE_REGION`, `UPDATE_DISJOINT`,
  `SLIDE_REGION` and retype operations, which keep XNU's 16 KiB view and the
  4 KiB shadow consistent as one transaction (section 5).
- **Frame table:** one entry per physical page holding a type and reference
  counts; zero (untyped) is the honest initial state.
- **Per-CPU output area** (`OUTPUT_AREA`, endpoint `0x32`): returns the
  virtual address of a per-CPU scratch page into which `MAP_PAGE` writes the
  replaced entry and the entry's address. Zero is the one value Apple's SPTM
  refuses to return, and the address must be one the guest can translate.
- **DART, NVMe and UAT tables**, so XNU's IOMMU and storage drivers can program
  their translation through the monitor as they would on Apple hardware.
- **TXM domain:** answered by the monitor at EL2. Boot-policy and signing
  questions are outside the scope of this document.

Behaviour that cannot be derived from XNU alone is checked against Apple's
real SPTM running under QEMU: `tools/qemu-sptm-oracle/setup.sh` builds the
`jprx/qemu-sptm` oracle and `tools/qemu-sptm-oracle/run.sh` records an
operation x frame-type x PTE matrix that `tools/test-sptm-oracle.c` keeps the
monitor honest against. See [DEVICE-REFERENCES.md](DEVICE-REFERENCES.md).

An unknown endpoint is never answered with a silent success. A call that
succeeds without doing its work lets XNU proceed on state that does not exist
and fail somewhere unrelated.

## 5. Page tables: a 16 KiB guest on a 4 KiB MMU

XNU is built for 16 KiB pages and the hardware walker only supports 4 KiB and
64 KiB granules. Virtualization does not route around that: stage 1 is walked
by the same MMU, and a walk raises no exception to trap.

On an SPTM system XNU does not write page tables; it asks SPTM to, with
arguments. That removes the expensive part of classic shadow paging (trapping
and chasing stores into guest tables). But XNU still reads its tables
directly (`pmap_pte` and friends dereference PTEs), so the tables it sees must
really be 16 KiB tables. The monitor keeps both:

| Layer | Granule | Written by | Walked by |
| --- | --- | --- | --- |
| XNU's view | 16 KiB | the monitor, on each SPTM call | XNU's software walker only |
| Shadow | 4 KiB | the monitor, derived from XNU's view | the hardware (`TTBR0_EL1`/`TTBR1_EL1`) |
| Stage 2 | 4 KiB | the monitor | the hardware |

`shadow/mmu.c` walks the 16 KiB tables in software and `shadow/shadow.c` emits
an equivalent 4 KiB translation: a 16 KiB page becomes four 4 KiB pages, a
32 MiB block becomes sixteen 2 MiB blocks, always using the largest descriptor
alignment allows. The property it is built around is that walking the shadow
gives the same answer as walking the guest for every address;
`tools/test-shadow.c` checks exactly that. After `MAP_PAGE` writes a guest
PTE, the monitor re-reads the leaf through the guest's own tables before
shadowing it, so a decoding error shows up as a disagreement rather than as
two consistent wrong answers.

Details that matter:

- **`TCR_EL1.TG1` is encoded differently from `TG0`** (`TG1`: `01`=16K,
  `10`=4K; `TG0`: `00`=4K, `10`=16K). One lookup table for both fields gives
  a shadow that is right in one half and silently wrong in the other.
- **The kernel regime is 47 bits** (`T1SZ = 17`, as XNU's own level
  descriptors state), even though the kernelcache is linked at
  `0xfffffe0000000000`. A narrower regime places top-level entries at indices
  the kernel never reads; see [APERTURE-FAULT.md](APERTURE-FAULT.md).
- **XNU also uses the low regime.** It walks and then accesses an identity
  mapped bootstrap reserve above declared DRAM, so `TTBR0_EL1` carries a
  second shadow built from the same guest tables.
- **The shadow's output size comes from the hardware.** XNU ships
  `TCR_EL1.IPS = 0`; the monitor sets IPS from `ID_AA64MMFR0_EL1.PARange` and
  hands XNU back its own `TCR` value on reads (`HCR_EL2.TRVM`).
- **Stage 2 maps only what exists** (`shadow/stage2.c`): declared DRAM and the
  reserve, the panel when handed over, and nothing else. Any other touch is a
  stage-2 fault at EL2 carrying the address.
- **Permissions.** Apple's kernels express page permissions through SPRR
  permission classes rather than plain AP bits. `shadow/sprr-view.c` turns the
  classes into concrete 4 KiB permissions, with private copies of the tables
  for the few paths whose permissions depend on the current SPRR state.
- **Physical aperture.** XNU translates physical to virtual addresses with a
  region table SPTM publishes (base, virtual base, page count, 24 bytes per
  entry). The loader publishes it, plus SPTM's own data region at its fixed
  virtual address.

There is also an opt-in kernel patch that creates user processes with 4 KiB
pmaps, using Apple's own 4K-pages switch, so user tables need no granule
translation ([KERNEL-PATCHES.md](KERNEL-PATCHES.md)).

## 6. Boot structures and the device tree

XNU's entry is the first word of `__TEXT_BOOT_EXEC`. The entry contract, read
off its first instructions:

| Register | Meaning |
| --- | --- |
| `x0` | entry mode / CPU index (0 = boot CPU) |
| `x1` | `boot_args` (virtual address) |
| `x2` | SPTM boot structure (virtual address) |

XNU locates its own Mach-O header from a stored link-time offset, so any slide
works. It never writes `SCTLR_EL1`: it must be entered with translation on and
the kernel already mapped at its link addresses, which on Apple hardware is
SPTM's job and here is the loader's.

**`boot_args`.** `x1` points at the classic 1,152-byte structure: revision,
virtual and physical base, memory size, top of kernel data, video, machine
type, device-tree pointer and length at `+0x60`/`+0x68`, and the 1,024-byte
command line at `+0x6c`. The command line is the one place a stock kernel
accepts new behaviour without code changes; `serial=3` sends both kprintf and
the console to the monitor's serial endpoint.

**SPTM boot structure.** `x2` points at an 856-byte structure whose first
quadword must be the magic `0xd00f...` (a wrong value spins forever). A
versioned table at `+0x1a0` is copied field by field into `__DATA_CONST`, with
the version gating how many fields are read. It carries the physical aperture
table, the frame-table root, the per-CPU scratch base and the feature bit that
selects the alternate call encoding. The last word is a build agreement
(`ARM_LARGE_MEMORY` must match what the kernel was compiled with).

**Device tree.** The tree is Apple's `DeviceTree.j700ap`, edited by
`probes/appledt.py`, which parses and re-serialises it so added properties do
not invalidate later offsets. The stock tree is unfinished by design; iBoot
completes it. The loader does the same:

- 51 properties ship with a placeholder flag (bit 31 of the length). XNU does
  not mask it and would walk `0x80000000` bytes too far; they are resolved.
- `clock-frequency` / `timebase-frequency` are filled in (section 9).
- `/chosen/dram-base` and `/chosen/dram-size` do not exist in the shipped tree
  and are created.
- Every `cpu` node ships as `state = "waiting"`. Exactly one must say
  `"running"`, or `ml_parse_cpu_topology` never finds the boot CPU and a
  release-build kernel dereferences NULL.
- Device nodes are placed and validated against the device models
  (`probes/devicemodel.py`); nodes for hardware this machine does not have are
  removed or quieted.

## 7. CPU topology

The guest keeps the J700 six-core topology: four efficiency cores at
affinities `0x0`-`0x3` and two performance cores at `0x100`-`0x101`. Each vCPU
is a fixed Snapdragon core; the boot CPU is started by q1n1 and the
secondaries are started with PSCI `CPU_ON` (`probes/secondary.c`), each with
its own `VNCR_EL2` page, stack and report. `VMPIDR_EL2` presents the Apple
affinity.

XNU brings secondaries up through PMGR register writes. Those land in the
monitor's PMGR models (`compat/device.c`), which release the corresponding
vCPU (`compat/cpu.c`) rather than touching real power controllers. Reducing
the topology with `cpus=1` is not an option for this kernel: it trips a PMGR
CPU-complex assertion earlier in boot.

Guest CPU identities describe the compatibility interface. They do not make an
Oryon core an Apple core, and the pairing of Apple core classes to Snapdragon
core tiers is a placement choice, not a measured equivalence.

## 8. Interrupts: a virtual AIC

The guest never sees the Snapdragon's GIC. It sees an Apple Interrupt
Controller modelled at EL2 (`compat/aic.c`):

- AIC3 layout at the address the J700 tree declares, with flat register banks,
  one die and one delivery cluster. The model reports revision 10 and 1,280
  interrupt lines; these are deliberate virtual choices, not measured T8140
  values, and are recorded in the guest profile.
- Reading `EVENT` returns the highest pending source and auto-masks it.
  Darwin's handler completes delivery by writing `MASK_CLR`, not a separate
  EOI, so the model follows that contract.
- Interrupts reach the guest as virtual IRQs (`HCR_EL2.VI`). The timer and
  IPIs use virtual FIQ (`HCR_EL2.VF`), matching Apple's convention.

Physical devices that the guest drives directly (for example the Adreno GPU)
raise level-triggered GIC SPIs. `compat/irq-forward.c` takes the SPI at EL2,
masks it at the distributor, completes it, and raises the mapped AIC line.
The guest's `MASK_CLR` is the resample point: if the line is still pending the
level stays up, otherwise the SPI is re-enabled. The model is pure and tested
natively by `tools/test-irq-forward.c`.

**IPIs.** Apple's fast-IPI system registers are emulated (`compat/ipi.c`):
local and global requests route to the target vCPU's pending state, and the
guest's write-one-to-clear acknowledgement consumes it. There is no physical
kick between cores, so every vCPU's EL2 timer is capped at a 1 ms poll to
notice pending IPIs. The fast path for that tick (`compat/fast-timer-irq.h`)
handles a secondary CPU's timer interrupt without the monitor's global lock.

## 9. Timers

The Snapdragon's generic timer runs at 19.2 MHz. The guest sees a 24 MHz
counter, matching Apple hardware; `timebase-frequency` in the tree says
24 MHz, and the monitor scales every counter read and deadline between the two
domains (`compat/clock.c`, integer quotient/remainder arithmetic so the
freestanding monitor needs no 128-bit division). The 24 MHz choice is forced
by the watchdog: its checked arithmetic overflows with the 19.2 MHz
nanosecond ratio.

- Apple's deadline timer programming is mapped onto the EL2 hypervisor timer
  (`CNTHP_*_EL2`); expiry is delivered as a virtual FIQ.
- `FEAT_ECV` and `CNTHCTL_EL2` trap controls keep the physical rate from
  leaking through the architectural virtual counter.
- The `CNTKCTL` event stream is emulated in software: WFE traps to EL2, and
  events coalesce into one pending bit.
- The WD1 watchdog is a timed model (`compat/watchdog.c`) in the guest
  counter domain; expiry latches a guest reset request.
- With the root `clock-frequency` left at zero, XNU computes an event-stream
  bit index of -2 and panics in `_enable_timebase_event_stream`; this was the
  first device-tree dependency found.

## 10. Lessons from bring-up

Bring-up was driven by what the kernel asked for, one stop per run: each
fault named the next missing piece. A few lessons generalise.

**One field, two consumers.** Several times a field's meaning was read
correctly from one consumer and then generalised, while a second consumer had
a different contract: a routing field with a fourth sub-field, a count that one
validator accepts as zero while a walker dereferences the pointer anyway, a
random-seed length one check accepts and another rejects, one status code
returned from six places. Each failure was silent. The habits that came out of
it: sweep the kernelcache for every reader of a global before concluding, make
shared error answers carry which cause produced them, and check the built image
rather than the code that builds it.

**Hardware traps.** `HPFAR_EL2` reads back zero on this silicon for a stage-2
permission fault on an instruction fetch, so the address comes from
`AT S1E1R` on `FAR_EL2`. The firmware leaves the OS Lock set, which silently
disables single-step; the monitor clears it before arming steps. EL1's fault
registers survive between runs and must be cleared before entry, or a stale
fault looks current.

**Read the machine after a stop.** The guest is gone when a run returns but
its memory is not, and every kernel virtual address in the image maps to a
known physical address. Reading structures back off the target answers in one
round trip what static reading takes much longer to narrow down.

## 11. Running without the hardware

`probes/run.py xnuboot --qemu` runs the identical monitor and image on QEMU
`-cpu max`, which has a 16 KiB granule, `FEAT_NV2` and working debug. It began
as the control that separates "this machine lacks the feature" from "this
probe is wrong". The physical layout is relative to whatever free memory the
target reports, so the same build places itself on either machine.

## 12. Re-running the evidence

```sh
tools/extract-firmware.py <restore image> j700ap
tools/kc-load.py <kernelcache> --out build/xnu.img
tools/kc-analyze.py <kernelcache>          # call sites, pages, x16 routing
python3 tools/sptm-dispatch.py <sptm image> --verify   # endpoint names

SNAP_STAGE=6 python3 probes/run.py shadowmmu   # a call answered by EL2
SNAP_STAGE=7 python3 probes/run.py shadowmmu   # the rest of the page still runs
SNAP_STAGE=8 python3 probes/run.py shadowmmu   # upper half, at kernel addresses

python3 probes/xnuboot.py --check               # build the address space offline
python3 probes/xnuboot.py --profile             # firmware hashes, ABI offsets, layout
python3 probes/run.py xnuboot --qemu            # whole entry path, no hardware
```

For installed boots on the laptop, see [RUNNING.md](RUNNING.md).
