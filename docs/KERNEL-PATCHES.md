# Kernel patches

This document lists every change Snapintosh can make to the guest kernel's
code: what each patch changes, why it exists, how its sites are found and
checked, and what it was measured to do. It also lists monitor features that
are easy to mistake for kernel patches, and patches that were studied and
rejected.

The kernel is Apple's stock J700 kernelcache for macOS 27 build 26A428
(`com.apple.kernel` UUID `F9F468D7-1F50-354A-BECD-6BD6C1C834AD`). See
[README.md](../README.md) for the project overview.

## Policy

The goal is to run stock kernels unmodified wherever possible. A trap cost is
fixed in the monitor first, and a kernel patch is considered only when:

- the trap is hot enough to matter in the trap census, and the monitor cannot
  make it cheap on its own;
- the patch sites are found by decoding instructions (an instruction pattern
  anchored on symbols, strings or operands), never by fixed address;
- the patch is opt-in: without its flag, the loaded image, page tables and
  parameters are byte-identical to a build without the patch code;
- the patch is admitted only for the reviewed kernel: the image digest must
  match a pinned value, every site must still hold its stock instruction, and
  the decoded site list must hash to a reviewed closure value;
- its effect is measured against the stock kernel under the same monitor.

The kernelcache file on disk is never rewritten. Each patch rewrites words in
the loader's in-memory copy (`probes/xnuboot.py`, `build()`), and the build
record lists the sites it changed and the closure hash. Every patch flag must be
given to every mode of one `tools/cycle.py` attempt (prepare, check and boot),
so the checked image is the booted image.

Boot-policy and signing questions are outside the scope of this document.

## Summary

| Patch | Define / flag | What it changes | Why | Measured effect |
| --- | --- | --- | --- | --- |
| SPTM call entry | `SNAP_SPTM_HVC_CALLS=1` (needs `SNAP_NATIVE_CALLS=1`), monitor `-DSNAP_SPTM_HVC_CALLS=1` | 348 SPTM call instructions in XNU become `HVC #0x5350` | Removes the undefined-instruction and vector detour of the stock call encodings; one monitor exit remains | About 32 ns less per SPTM call (about 239 to 207 ns, 13%) |
| System-register zeroing | `SNAP_KERNEL_SYSREG_ZERO=1`, `cycle.py installed-fresh --kernel-sysreg-zero` | 240 accesses to 18 registers the monitor answers with 0: reads become `MOVZ Xt,#0`, writes become `NOP` | The monitor already returns 0 and drops the writes; the patch removes the trap | About 44M fewer traps per 600 s, about 29% of all traps in the census |
| Reference-clear skip | `SNAP_KERNEL_REFMOD_SKIP=1`, `cycle.py installed-fresh --kernel-refmod-skip` | 2 page-aging reference clears become `NOP` | Each clear costs an SPTM page-table update and often a later Access-flag fault | Estimated 1.4 to 1.9M fewer SPTM updates per run and 0.25 to 0.9M fewer guest Access-flag faults |
| 4 KiB user pmaps | `SNAP_KERNEL_USER_4K=1`, `cycle.py installed-fresh --kernel-user-4k` | 4 branches: every process gets a 4 KiB user pmap, as with Apple's own 4K spawn switch | Lets the monitor's hardware-walk mode run XNU's own user tables instead of shadow copies | Estimated user-table lock hold about 967 s down to about 150 s per 30 min run (with `--user-hw-walk`) |
| Application AMX hide | `SNAP_HIDE_AMX=1`, `cycle.py installed-fresh --hide-amx` | 1 instruction: the AMX version bits are cleared from the published application capabilities | The A16 has no AMX unit; applications must not select AMX code paths | Compatibility, not speed: only capability bits 27 to 30 change |

The sections below give the details.

## SPTM call entry

**Define:** `SNAP_SPTM_HVC_CALLS=1` in the loader environment, which requires
`SNAP_NATIVE_CALLS=1`, plus the monitor define `-DSNAP_SPTM_HVC_CALLS=1`.

**What it changes.** XNU's private SPTM call instructions become
`HVC #0x5350`, one instruction for one instruction, at 348 sites. The stock
encodings reach the monitor through an undefined-instruction exception and a
vector detour; the `HVC` enters it directly. One monitor exit, the same
serialization and the same endpoint code remain, and the calling sequence
around each site is untouched.

**How sites are found.** `probes/nativecalls.py` (`patch_hvc_calls`) takes the
call sites from the native-call contract derived from the stock image, with a
complete-closure check. `tools/qualify-sptm-call-entry.py` checks all 348
sites, and a call-entry microbenchmark measured the saving on the A16.

**Where it runs.** `cycle.py bootstrap-smoke` and `cycle.py speed-test` build
with it (`tools/cycle_lib/bootstrap_smoke.py`, `tools/cycle_lib/speed_test.py`).
It is not used on the installed desktop route.

**Effect.** About 32 ns saved per SPTM call (239 ns to 207 ns, 13.4%).

## System-register zeroing

**Flag:** `cycle.py installed-fresh --kernel-sysreg-zero`
(`SNAP_KERNEL_SYSREG_ZERO=1`).

**What it changes.** Every `MRS Xt,<reg>` of the listed registers becomes
`MOVZ Xt,#0`; every `MSR <reg>,Xt`, and every `MRS` into `XZR`, becomes `NOP`.
The registers are the 18 that the monitor answers with 0 and whose writes it
drops: PMC0 to PMC9, PMCR0, UPMSR, GXF_STATUS_EL1, AMX_STATE_T_EL1 and four
Apple implementation-defined encodings (`S3_4_C15_C15_6`, `S3_4_C15_C10_4`,
`S3_1_C15_C1_5`, `S3_4_C15_C1_4`). The result is exactly what the monitor
already does, without the trap.

**Sites.** 240: 222 in `com.apple.kernel` and 18 in `AppleT8140CLPC`
(146 `MOVZ`, 94 `NOP`).

**How sites are found.** `probes/sysregzero.py` decodes every executable
`__text` word. Each site must still hold its stock word, the kernel digest must
be pinned, and the decoded set must equal the reviewed closure.

**Checks.** `tools/test-kernel-sysreg-zero.py`: only the site words change,
default builds are identical, and both monitor variants return 0 for every
listed register.

**Effect.** About 43.7M traps removed per 600 s, 29% of all traps in the census
run. Most come from the per-idle-iteration `cpc_hw_update` and from performance
counter reads on every context switch. In one control comparison, WindowServer's
share of time in `__ulock_wake` fell from about 18% to 0.3%. It has been part of
every installed desktop run since it was introduced.

## Reference-clear skip

**Flag:** `cycle.py installed-fresh --kernel-refmod-skip`
(`SNAP_KERNEL_REFMOD_SKIP=1`).

**What it changes.** XNU's page-aging reference clears,
`pmap_clear_refmod_options(pn, VM_MEM_REFERENCED, PMAP_OPTIONS_NOFLUSH, NULL)`,
are skipped: the `BL` to `phys_attribute_clear_with_flush_range` that follows
the four argument set-ups (`MOVZ W1,#0x40`, `MOVZ W2,#0x20`, `MOVZ X3,#0`,
`MOVZ X4,#0`) becomes `NOP`. Each such call cost one SPTM `UPDATE_DISJOINT`
(clear the Access flag). If the page was touched again, it also cost an
Access-flag fault and a second `UPDATE_DISJOINT`.

**Sites.** 2, both in `com.apple.kernel`: `vm_page_balance_inactive` (runs on
every active-queue insertion and inactive removal) and
`vm_fault_deactivate_behind`. The other 14 calls to the function are left alone.
Modify-bit clears (write protection), madvise, UPL, pageout and copy-on-write
paths are untouched.

**How sites are found.** `probes/refmodskip.py` identifies the callee as the
function that holds the only reference to each of its two
`phys_attribute_clear(...)` panic strings. A site is a `BL` to it after exactly
those four `MOVZ` instructions; no branch may land inside that window, and the
region may contain no indirect jump. Admission uses the digest pin and the
reviewed closure.

**Checks.** `tools/test-kernel-refmod-skip.py`: symbol and DWARF signature
checks against the Kernel Debug Kit, inline chains, an emulation of the skipped
call's entry (Access-flag clear only, no write protection), a caller-register
walk after the `NOP`, refusals, identical default builds, and composition with
the other patches.

**Effect.** Estimated from a 30 minute installed run: 1.4 to 1.9M fewer of
2.69M `UPDATE_DISJOINT` calls, about 30 to 43 s less of their 60.6 s token hold
and 190 to 250 s less of their 361 s lock wait, and 0.25 to 0.9M fewer guest
Access-flag faults. It has been part of every installed desktop run since it was
introduced.

**Cost.** Under memory pressure, `vm_pageout_scan` treats these pages as
referenced, so reclaim of them becomes first-in first-out instead of
second-chance.

## 4 KiB user pmaps

**Flag:** `cycle.py installed-fresh --kernel-user-4k`
(`SNAP_KERNEL_USER_4K=1`). It is used together with the monitor's
`--user-hw-walk` (`SNAP_USER_HW_WALK`).

**What it changes.** Every process is created as if it had been spawned with
Apple's own 4K testing switch (`psa_4k`, `_POSIX_SPAWN_FORCE_4K_PAGES`), so
every user pmap is SPTM format 1 (4 KiB tables, L0 root). Four branches change,
all in `com.apple.kernel`:

| Site | Source location (XNU) | Change |
| --- | --- | --- |
| Force flag in `load_machfile` | `mach_loader.c:781` | The spawn-attribute NULL test before the `psa_4k` test becomes an unconditional branch to the code that sets `PMAP_CREATE_FORCE_4K_PAGES` |
| Eligibility check in `load_machfile` | `mach_loader.c:1006` | The check that would refuse a forced-4K exec is branched past |
| Apple string in `exec_add_apple_strings` | `kern_exec.c:8165` | Same forced branch, so the process receives `vm_force_4k_pages=1` |
| Guard-object bucket in `vm_guard_object_find_space_anywhere` | `vm_map_store.c:1958` | A `B` becomes a `TBZ` on the page shift, so 4 KiB maps take the function's own fall-back exit |

`cambria_pagesize=4` is not needed; it only selects 4K for x86_64 processes.

The fourth site exists because of a real XNU limit. The guard-object allocator
buckets its slab by the bit length of the page-rounded size minus 14. In a
4 KiB map, a request of 4 KiB or less gives index -2, so the new chunk pointer
was written 16 bytes before the map's slab pair, inside the previous
`kalloc.1024` element ("element modified after free" panics). With the patch, a
4 KiB page shift returns the function's existing fall-back value (46), which its
only caller answers with the ordinary allocator; 16 KiB maps keep the stock
path.

**How sites are found.** `probes/user4k.py` matches the load / compare / test
sequence around the spawn-attribute fields and classifies each match by the
instruction at its branch target. The eligibility check is matched by
its position relative to the string it tests. The
guard-object site is matched by its own short sequence, and its fall-back must
be one of the function's own exits that returns the value in `X8`. Admission
uses the digest pin and the reviewed closure.

**Checks.** `tools/test-kernel-user-4k.py`: source file and line of each site
from the Kernel Debug Kit, before/after disassembly, forced paths never read the
absent spawn attributes, every exit of the eligibility check equals the new
target, the guard-object fall-back is one of the function's own exits, its
caller treats 46 as a fall-back, refusals, identical default builds, and
composition with the other patches.

**Effect.** On its own the patch is slower (see the rejected study below). With
`--user-hw-walk`, the hardware walks XNU's own user tables, and the monitor no
longer builds, caches or rebuilds shadow roots on `SWITCH_ROOT`. The estimate
from a 30 minute run is a user-table lock hold of about 967 s falling to about
150 s.

**History (October 2026).** The first hardware runs found, in order: a monitor
check that refused the first 4 KiB root switch; a copy-table compaction bug in
the monitor; the guard-object slab underflow above (fixed by the fourth site);
and a stage-2 fault caused by the SPTM model writing descriptors byte by byte.
After those fixes a full 30 minute desktop run completed with no faults, and
the patch has been on every installed desktop run since.

## Application AMX hide

**Flag:** `cycle.py installed-fresh --hide-amx` (`SNAP_HIDE_AMX=1`;
`tools/kc-load.py --hide-amx` for an offline image).

**Why.** The kernel panics at startup if `AMXIDR_EL1` reads as 0, so the
monitor gives it the compatibility value it needs. The kernel then publishes
an AMX version to applications in `_get_cpu_capabilities()` bits 27 to 30, and
libraries such as Accelerate may select AMX code paths. The Snapdragon X2 Elite
has no AMX unit, so those paths cannot run.

**What it changes.** One instruction in `commpage_populate`: the `ORR` that
merges the AMX version into the capability accumulator becomes an `AND` that
clears bits 27 to 30. The global capability value and its comm-page copies
(32-bit, 64-bit and the optional x86 alias) all receive the result. `AMXIDR`,
XNU's internal AMX version and every SME bit are unchanged; the patch does not
enable or advertise SME.

**How the site is found.** `tools/kc-load.py` (`hide_amx`) matches the
18-instruction publication sequence, resolves its three data addresses and
checks that they are distinct mapped data, that the shared load and store
offsets agree, and that the loaded words are still stock. All sites are checked
before any is written, and a second application is refused.

**Checks.** `tools/test-hide-amx.py` replays the patched and unpatched
publication sequence with all six AMX versions, several capability accumulators
(with and without SME and SME2 and unrelated bits) and with and without the x86
alias: only bits 27 to 30 change. It also checks identical default builds,
refusals, environment validation and the `installed-fresh` argument routing.

**Effect.** Applications see no AMX and take their non-AMX (NEON) paths. It is
used on installed desktop runs. A run without AMX crashes does not prove that
every application consults the capability bits before using AMX.

## Not kernel patches

These change no kernel instructions, even when their names say "kernel":

- **Monitor defines named `SNAP_KERNEL_*`**: `SNAP_KERNEL_PPERM_VARIANTS`,
  `SNAP_KERNEL_PPERM_FAST` (`--kernel-pperm-fast`), `SNAP_KERNEL_PPERM_REUSE`,
  `SNAP_KERNEL_VIEW_REUSE`, `SNAP_KERNEL_DIRTY_PUBLISH` and
  `SNAP_KERNEL_CLASS_PROOF` are monitor code. For example,
  `SNAP_KERNEL_PPERM_VARIANTS` keeps a second private copy of each CPU's kernel
  page tables and swaps to it on a permission flip; it touches page tables, not
  kernel code.
- **Monitor speed defines** such as `SNAP_ROOT_MISS_FAST`,
  `SNAP_UPDATE_DISJOINT_FAST`, `SNAP_ROOT_CACHE_WIDE`,
  `SNAP_UPDATE_CHECK_SPARSE`, `SNAP_FAST_TIMER_IRQ_CPU0` and the
  `ADRENO_IB_POLL_DIVISOR` override: monitor code only.
- **`--lean-traps [1|2]`** (`SNAP_LEAN_TRAPS`): at level 1, after a lock-free
  read of ESR, FAR or a performance counter, the monitor also emulates the
  adjacent read (XNU reads these in pairs), using the sealed kernel image; level
  2 uses fine-grained traps (FEAT_FGT) instead of `HCR_EL2.TVM`/`TRVM`, so
  `ESR_EL1`/`FAR_EL1` reads and `CONTEXTIDR_EL1` writes stop trapping.
- **`--class-proof-wide`** (`SNAP_CLASS_PROOF_WIDE`): the monitor's kernel
  page-class proof walks up to 61,440 tables instead of 8,192.
- **`--dart-wiredcnt`** (`SNAP_DART_WIREDCNT`): on each GPU unmap the monitor
  writes one XNU data word, lowering the 16-bit IOMMU-table count by the leaves
  it cleared, as `t8110dart_unmap` would. It locates `pmap_ref_iommu_table` by
  instruction pattern, decodes the globals it uses and checks every pointer; on
  any mismatch it writes nothing. Checked by `tools/test-dart-wiredcnt.py`.
- **`--panic-serve`** (`SNAP_PANIC_SERVE`): after XNU's panic entry the monitor
  keeps serving ordinary calls so the panic string is printed.
- **Pointer authentication** (`--native-pacga` and related monitor options) is
  handled entirely in the monitor and changes no kernel words.
- **Boot argument `-vm_compressor_wk_sw`** (installed route): XNU's own switch,
  not a patch. It makes the memory compressor use software WKdm instead of an
  Apple compression instruction the Snapdragon lacks, which otherwise stops the
  boot with an undefined-instruction exception in the compressor.
- **AuxKC colorimetry** (`tools/patch-auxkc-colorimetry.py`): one instruction in
  the project's own Adreno kext collection (the colour-element constant for
  sRGB). It changes the project's driver, not XNU, and the kext source now
  carries the same value.

## Proposed, not implemented

| Patch | What it would change | Expected effect | Status |
| --- | --- | --- | --- |
| `SNAP_KERNEL_USER_TIMEBASE` | One constant in `commpage_populate` so user `mach_absolute_time` reads `CNTVCTSS_EL0`, an architectural counter the monitor can serve quickly, instead of Apple's counter alias | About 2.3M user counter reads per run leave the slow path | Designed |
| `SNAP_KERNEL_NATIVE_COUNTER` | Apple counter aliases (about 1,060 sites) become the architectural counters, with a 19.2 MHz guest timebase (watchdog and microsecond constants, device-tree frequencies) | About 21% of traps in the census run; hundreds of millions of counter traps on a long installed run | Deferred: needs the timebase change; medium to high risk |

The A16 cannot scale the counter in hardware (`ID_AA64MMFR0_EL1.ECV` reports
offsets only), so there is no monitor-only route to untrapped 24 MHz counter
reads.

## Studied and rejected

- **4 KiB user pmaps under the shadow monitor.** Without the hardware walk, the
  4K patch is slower: the monitor shadows 4 KiB roots just like 16 KiB ones, two
  of its optimisations (roots cached at creation, shared-region linking) work
  only for 16 KiB, user page-map calls grow up to 4 times, and each root rebuild
  walks about 3,533 shared tables instead of 221. The estimate was 60 to 150%
  more lock hold at equal work. The patch exists only for the hardware-walk
  mode. The same study found the better lever of that time: a full 64-slot root
  cache was evicting and rebuilding tens of thousands of roots per run.
- **Skipping modify-bit write protection.** Most user `UPDATE_DISJOINT` records
  are an Access-flag clear plus write protection followed by a write fault. They
  come from `MADV_FREE`/`MADV_FREE_REUSABLE`, UPL commits and the pageout
  cleaning paths. Skipping them would lose dirty tracking (a written page could
  be discarded, or a file page could stay clean after a write); skipping the
  whole call would stop the "reusable" footprint ledger that jetsam limits rely
  on. Left as is.
- **The other reference-only clears** (`pmap_clear_reference` in
  `vm_page_deactivate_internal`, `vm_pageout_scan` and
  `vm_object_cache_evict`). They are the same kind of aging hint but did not
  appear in the recorded update traces, so they are left alone until there is
  evidence that they matter.
