# Can the Snapdragon X2E-96-100 host XNU?

**Historical feasibility study.** This records the initial hardware probes
and the options considered before the stock-kernel route was chosen. The
project went on to boot the stock kernelcache with translated page tables;
see [BOOT-CHAIN.md](BOOT-CHAIN.md) and [COMPATIBILITY.md](COMPATIBILITY.md)
for the implemented approach.

**Result: the hardware cannot walk a 16 KiB translation table.** That is
measured with a control, not read from a register. Everything else on the
checklist passes, including pointer authentication and nested
virtualization.

## Why the granule decides the project

XNU on arm64 uses 16 KiB pages (`PAGE_SHIFT` 14); the pmap, the VM system and
the dyld shared cache are built around it. Virtualization does not route
around a missing granule: a guest's stage-1 translation is walked by the same
MMU as the host's, and stage 2 only translates its output. A table walk raises
no exception to trap, so an unsupported granule silently does the wrong thing.

## The claim being tested

`ID_AA64MMFR0_EL1` reads `0x2100122100001024`:

| Field | Bits | Value | Meaning |
| --- | --- | --- | --- |
| `TGran4` | 31:28 | `0x0` | 4K supported (0 means supported) |
| `TGran64` | 27:24 | `0x0` | 64K supported |
| `TGran16` | 23:20 | `0x0` | 16K not supported (0 means not supported here) |
| `TGran16_2` | 35:32 | `0x1` | 16K not supported at stage 2 |

Note the inverted convention between `TGran16` and `TGran4`/`TGran64`.

A register alone is not enough: the project that inspired this one, [macOS on
a Huawei Qingyun
laptop](https://kunagisa.moe/2026/09/14/finding-treasuries-mac-os-on-wahway-qingyun-w515y/),
found a vendor had hidden PAuth in `ID_AA64ISAR1_EL1` while the silicon had
it. So behaviour had to be checked.

## Two probes that do not settle it

- **Writing the granule to `TCR_EL1` and reading it back.** All encodings read
  back unchanged. `TCR` fields are storage; the granule is validated only when
  a walk happens.
- **Mapping entry 0 and translating `VA 0x1000`.** At `T0SZ=28` that address
  is index 0 under both granules, so a silent 4K fallback (which the
  architecture permits for an unsupported granule) passes identically. A test
  that cannot fail in the interesting direction is not a test.

## The method

`AT S1E1R` runs the hardware table walker over the EL1&0 regime and reports
the result in `PAR_EL1` without entering EL1. q1n1 runs the probe at EL2. The
probe sets, and each omission silently invalidates the result:

- `HCR_EL2.TGE = 0`, or `AT S1E1R` is routed to EL2's regime;
- `HCR_EL2.VM = 0`, or stage 2 is folded in;
- `HCR_EL2.RW = 1`, or EL1 is AArch32 and walks 32-bit descriptors (RES1 on
  the A16, so the omission was caught only by the QEMU control);
- `SCTLR_EL1.M = 1`, or the walk is bypassed and every trial passes.

One 16 KiB-aligned table serves both granules. At `T0SZ=28` the 4K regime
starts at level 1 (index `VA[35:30]`) and the 16K regime at level 2 (index
`VA[35:25]`). **The discriminator:** map only entry 1, to `PA 0x4000000`, and
translate `VA 0x2001000`. Under 16K that is index 1 and resolves to
`PA 0x4001000`; under 4K it is index 0 and faults.

| Trial | Granule | Table | VA | Expected |
| --- | --- | --- | --- | --- |
| A | 4K | entry 0 mapped | `0x1000` | resolves (harness works) |
| B | 4K | empty | `0x1000` | faults (`SCTLR_EL1.M` took effect) |
| C | 4K | entry 1 mapped | `0x2001000` | faults (discriminator works) |
| D | 16K | entry 1 mapped | `0x2001000` | the question |

## Results

Identical blob and harness on two machines:

| Trial | QEMU `-cpu max` (has 16K) | A16, X2E-96-100 |
| --- | --- | --- |
| A | `PA 0x1000` | `PA 0x1000` |
| B | fault, `FST 0x05` | fault, `FST 0x05` |
| C | fault, `FST 0x05` | fault, `FST 0x05` |
| D | `PA 0x4001000` | **fault, `FST 0x05`** |

The fault code corroborates it. `FST 0x05` is a level-1 translation fault. A
genuine 16K walk at `T0SZ=28` starts at level 2 and would have resolved. A
level-1 fault identical to the 4K trials means the walker substituted the 4K
structure for `TG0 = 0b10`.

## What else the silicon says

From `probes/run.py idregs`; `MIDR_EL1 = 0x512f0021` (implementer `0x51`,
Qualcomm).

| Feature | Value | Note |
| --- | --- | --- |
| PAuth | `APA3 = 5`, `GPA3 = 1` | present and honestly advertised (QARMA3, the `ISAR2` variant) |
| `FEAT_NV2` | `MMFR2.NV = 2` | nested virtualization |
| VHE | `MMFR1.VH = 1` | |
| VMID | 16-bit | |
| DIT / UAO / SSBS / SHA3 | present | |

## The options considered

**1. Build XNU with 4 KiB hardware pages.** XNU separates the VM page from the
hardware page: with `__ARM_16K_PG__` undefined and `PAGE_SHIFT` still 14,
`PAGE_RATIO == 4` backs each 16 KiB VM page with four 4 KiB PTEs, and user
space still sees 16 KiB pages. But `XNU_MONITOR` builds assert against it, so
it requires a non-PPL, non-SPTM kernel built from source: not a route to
booting stock macOS.

**2. Shadow paging at EL2.** Never give the guest's tables to the MMU; build
4 KiB shadow tables that reproduce each 16 KiB mapping. In the classic form
this is expensive, because every guest page-table store has to be caught and a
shadow miss surfaces as a guest EL1 fault that no bit routes to EL2. Its one
advantage is that it boots an unmodified kernel.

**3. A different target.** The Huawei project ran Apple's `vmapple` guest
(the Virtualization.framework kernel) under KVM, which needs no Secure
Enclave, AIC, DART or PMGR model. Bare-metal XNU needs all of those, plus
SPTM and TXM on current macOS.

## What was chosen, and why it was cheaper than expected

The project boots the stock bare-metal kernelcache with shadow paging. On an
SPTM kernel the classic cost largely disappears: XNU does not write its own
page tables but asks SPTM to, with arguments. The monitor stands in for SPTM,
so it is told about every mapping change as a call and never has to trap
stores into tables. XNU still reads its 16 KiB tables, so the monitor keeps
both XNU's 16 KiB view and the hardware's 4 KiB shadow. `FEAT_NV2` lets XNU,
which expects to run at EL2, run at EL1 under the monitor. Details are in
[BOOT-CHAIN.md](BOOT-CHAIN.md).

## Reproducing

```sh
python3 probes/run.py idregs              # feature registers
python3 probes/run.py tgran16             # the granule walk, on hardware
python3 probes/run.py tgran16 --qemu      # the same blob against -cpu max
```

Both probes are flat AArch64 blobs uploaded to q1n1 and executed at EL2; they
restore every register they touch. `--device` selects the q1n1 link. Sources:
`probes/tgran16.c`, `probes/idregs.S`, `probes/run.py`. To qualify another
candidate host, run trial D on it.
