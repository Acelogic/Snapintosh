# External references

Snapintosh models Apple devices at EL2 and drives Qualcomm hardware from its
own code. This document lists the external projects used as references, what
each was used for, and the limits of that use. A reference driver describes
one side of a protocol; an emulated device must implement the other side, so
none of these is a drop-in model.

| Project | URL | Used for |
| --- | --- | --- |
| m1n1 (Asahi Linux) | https://github.com/AsahiLinux/m1n1 | base of q1n1; RTKit, ASC mailbox and DART references; AGX prototype constants |
| q1n1 | https://github.com/Snapintosh/q1n1 | the EL2 proxy that loads and runs the monitor |
| XNU source (Apple open source) | https://github.com/apple-oss-distributions/xnu | reading kernel behaviour: `PAGE_RATIO`, `TRAP_DEBUGGER`, CPU topology parsing |
| Linux kernel | https://github.com/torvalds/linux | Apple watchdog register description; Adreno and Qualcomm platform references (read only) |
| Mesa (freedreno, ir3, Turnip) | https://gitlab.freedesktop.org/mesa/mesa | Adreno ISA and compiler backend for air2ir3; command-stream reference |
| qemu-sptm | https://github.com/jprx/qemu-sptm | oracle that runs Apple's real SPTM/TXM with this kernelcache |
| darwin-vm | https://github.com/jprx/darwin-vm | companion setup used by the qemu-sptm oracle |
| emuasi | - | portable Apple AIC model and tests |

## AIC (interrupt controller)

emuasi's portable AIC model covers AIC1/2/3 layouts, level and edge inputs,
masking, destructive `EVENT` reads, IPIs and processor-local inputs, with a
regression suite. It informed `compat/aic.c`, which was written for the EL2
dispatcher rather than imported. Differences that needed an audit, not a copy:

- The J700 driver masks the AIC revision to eight bits and takes extra
  topology paths at revision `0xb` and above. The reference does not answer
  that register, so the virtual revision (10) is a deliberate choice recorded
  in the guest profile.
- Darwin's handler completes delivery with a `MASK_CLR` write, not a separate
  EOI token, so the model follows the MMIO contract.
- The guest-facing AIC state is kept separate from the Qualcomm GIC and timer
  handling (`compat/irq-forward.c`).

## RTKit and ASC mailboxes

m1n1's `src/asc.c` (mailbox send and receive), `src/rtkit.c` (management
handshake, endpoint discovery, power states) and the proxyclient's ASC classes
are protocol references. They are drivers speaking to Apple firmware; an
emulated coprocessor must implement the firmware's side. Mailbox queues,
doorbells and interrupts are kept separate from RTKit management and service
endpoints, and a working transport does not provide SMC, AOP or SEP services.

## DART (IOMMU)

m1n1's DART drivers are register and translation references. The monitor's
backend (`compat/dart.c`, `compat/sptm-dart.c`) has its own state, validates
guest-owned page tables, and keeps guest DART stream IDs separate from any
Qualcomm SMMU configuration. A translated address never authorises host MMIO
or unowned memory.

## Watchdog

The Linux `apple_wdt` driver's register description, checked against the
J700 tree, informed the timed WD1 model in `compat/watchdog.c`.

## Adreno GPU

The Linux `msm` DRM driver and the Qualcomm platform device-tree sources are
read as references for Adreno register programming, power sequencing and
interrupt numbers. No Linux code is used. Mesa's freedreno headers and ir3
compiler are the ISA and compiler reference for air2ir3, which translates
Apple's AIR to ir3; see [air2ir3](../gpu/air2ir3/README.md).

## SPTM behaviour

Where XNU's side of the SPTM contract does not determine an answer, the
monitor is checked against Apple's own SPTM running under QEMU.
`tools/qemu-sptm-oracle/setup.sh` builds qemu-sptm with a call tracer, and
`tools/qemu-sptm-oracle/run.sh` boots this kernelcache under the real SPTM and
TXM (single CPU, no hardware) and records an operation x frame-type x PTE
matrix. `tools/test-sptm-oracle.c` keeps the monitor consistent with it. This
step relies on Apple software you supply.

## Limits

Agreement with a reference is not hardware evidence. Where a model's
constants come from reverse engineering, the model reproduces any error in
that work faithfully and its tests still pass. Only runs on the target break
the tie, and addresses, geometry and generation are always taken from the
audited guest device tree rather than from a reference's defaults.
