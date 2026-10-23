# AGENTS.md

Mandatory instructions for coding agents and human contributors working in
Snapintosh. This is the complete policy, not an addendum to an earlier AGENTS.md.
Apply it to all new changes; do not perform unrelated rewrites of legacy code
merely to satisfy a newly introduced rule.

Correctness, hardware safety, reproducibility, and maintainability take
precedence over expedient implementation. An agent must not claim a result it
has not verified or cross a hardware/destructive boundary without authorization.

## Start Here: Project & Source of Truth

Before changing code, read the relevant sections of [README.md](README.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/BUILDING.md](docs/BUILDING.md),
and [docs/STATUS.md](docs/STATUS.md). For hardware execution, also read
[docs/RUNNING.md](docs/RUNNING.md). Do not rely on status summaries from earlier
sessions in place of the current tree.

Snapintosh targets the ASUS Zenbook A16 (UX3607OA) with the Snapdragon X2
Elite X2E-96-100 and macOS 27 build 26A428. The stock J700/T8140 kernel is
normally unmodified; Snapintosh mediates its platform contracts. The present
workflow still uses q1n1 and a Mac host over USB-C NCM. Standalone execution is
a direction, not an already implemented or authorized replacement for this flow.

| Layer / responsibility | Primary location |
| --- | --- |
| EL2 monitor, SPTM/TXM mediation and platform emulation | `compat/`, `probes/xnuboot.*` |
| 16 KiB guest / 4 KiB shadow page-table translation | `shadow/` |
| Boot orchestration, safety checks and logs | `tools/cycle.py`, `tools/cycle_lib/` |
| IOGPU kext, display and GPU kernel mediation | `gpu/adreno-kext/kext/` |
| Metal plug-in and Adreno command encoding | `gpu/adreno-kext/plugin/` |
| AIR to Mesa ir3 compiler | `gpu/air2ir3/` |
| QCC2072 Wi-Fi and I2C-HID input drivers | `drivers/` |
| Host tests, offline replays and diagnostics | `tools/test-*`, `tools/replay-*` |

The paths `gpu/adreno-kext/kext`, `gpu/adreno-kext/plugin`, `gpu/air2ir3`,
`drivers/snap-i2c-hid` and `drivers/snap-qcc2072` are git submodules (SnapAdreno, SnapMetal, air2ir3,
SnapI2CHID and SnapQCC2072 in the Snapintosh organization). Change a component in its own repository first,
then move the submodule pointer here in a separate `repo:` commit.

Priority: legal/credential restrictions and hardware safety are absolute;
verified ABI and architectural contracts outrank aesthetic preferences. Where
another document specifies an exact build or run procedure, follow it unless
it conflicts with these safety rules; disclose conflicts rather than guessing.

## Non-Negotiable Safety, Provenance & Compatibility

1. **Never commit vendor or locally reconstructed private inputs.** This
   includes Apple, Qualcomm or ASUS kernelcaches, firmware, restore-image parts,
   KDK files, kexts, dyld caches, ACPI dumps, disassembly/vtable/ABI dumps,
   reconstructed `*26A428.h` headers, and shader sets compiled from Apple's
   shaders. Obtain inputs independently and keep them under ignored local
   locations (for example `build/`, `downloads/`, and the excluded header paths).
   Preserve `.gitignore` protections. Do not paste protected source material
   into PRs, tickets, build logs or test fixtures.
2. **Never commit secrets or machine-identifying data.** No personal paths,
   usernames, hostnames, interface names, IP/MAC addresses, serial numbers,
   network SSIDs/passwords, SSH keys or device identifiers. Use parameterized
   paths, environment variables, ROOT-relative paths, and local
   `tools/cycle_lib/pins.json` copied from `pins.example.json`. Sanitize
   diagnostic excerpts before publication.
3. **Preserve opt-in semantics.** New runtime features require a compile-time
   gate (`ADRENO_*`, `SNAP_*`, or a subsystem-specific flag) and, where
   applicable, an explicit `tools/cycle.py` option or boot argument. With the
   gate disabled, the baseline must remain unchanged. Use the project's
   reproducible baseline procedure: compare monitor ELF bytes and kext sections
   when deterministic; investigate build-environment differences rather than
   waiving a meaningful mismatch. Never silently change default behavior.
4. **Honor upstream licenses and attribution.** New project-owned source files
   use `SPDX-License-Identifier: MIT`; derived files retain their original
   notices and appropriate entries in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
   `compat/adreno-ib-tables.h` is GPL-2.0-only, generated from q1n1's
   `tools/adreno_x2_protect.py`; do not mix GPL code into MIT files. For
   reference implementations in Linux/Mesa and elsewhere, preserve appropriate
   provenance, distinguish facts from copied expression, and reimplement
   independently where required by the project's licensing policy.
5. **Hardware safety is not optional.** `tools/cycle.py` can write the real
   internal NVMe. Only one hardware client may run at a time. Use AC power or
   maintain at least 50% battery, leave `--thermal-guard` enabled, respect
   `--gpu-dvfs-ceiling`, and never submit a single `CP_MEMCPY` larger than
   1 MiB (a 4 MiB copy previously hung the GPU). Never change tracked sources
   between `--prepare` and `--boot`. Require explicit permission for
   partition-table changes, persistent firmware modifications, or unsafe
   clock/voltage operations; do not treat user access to the repository as
   authorization for destructive tests.
6. **Host-first validation.** For risky changes, enumerate failure modes,
   build host-side models/harnesses (`tools/test-*.c` or `.py`), and add
   deliberately faulty cases the harness must reject. A successful host test
   does not authorize an unsupervised hardware run. Batch independent
   validated fixes into one controlled hardware session when practical.
7. **Do not discard known-good reference paths casually.** `gpu/agx*` contains
   retained virtual-AGX reference material. Its presence is an intentional
   exception to the prohibition on new parallel implementations. Do not
   delete it simply to satisfy a style mandate; obtain approval and establish
   a retirement plan if its removal is proposed.

## 1. Code Architecture & Repository Hygiene

### Compilation Unit Limits
- New or substantially expanded C/C++ implementation files must remain below 1,500 physical lines and 50 KiB, excluding generated code.
- Prefer refactoring before 1,000 lines when a file contains multiple unrelated responsibilities.
- Do not bypass limits by compressing source, hiding implementations in headers, introducing excessive macros, or creating artificial compilation units.
- Existing oversized files are technical debt, not justification for unrelated wholesale rewrites. Refactor incrementally while preserving tested behavior.

### Cohesive Header Boundaries
- Headers must represent stable subsystem interfaces and ownership boundaries.
- Do not create one-function or one-feature satellite headers merely to reduce agent context consumption.
- Separate public APIs, private implementation details, hardware register definitions, and generated ABI declarations when their responsibilities justify the separation.
- Avoid unnecessary cross-subsystem header dependencies and cyclic includes.

### No Disposable Source Artifacts
- Never commit prototype copies, abandoned implementations, backup files, raw analysis scratchpads, or temporary debugging outputs.
- Use ignored development directories for experiments.
- Git history is the mechanism for preserving superseded implementations.
- Keep intentional diagnostic utilities only when they serve a documented, reproducible purpose.

### No Parallel Implementation Proliferation
- Extend or refactor the existing implementation by default.
- Do not introduce competing versions of shader lowerers, register maps, page-table managers, or GPU submission paths without an explicit migration plan.
- When replacement is justified, define the new implementation's ownership, equivalence tests, cutover criteria, and retirement conditions.
- Preserve intentionally retained reference implementations until their removal is approved.

### Respect Subsystem Ownership
- EL2 owns privileged hardware mediation and authoritative translation state.
- Kernel drivers own their operating-system contracts, resource validation, and lifecycle.
- Userspace components own API translation, command encoding, and application-facing state.
- Host tools own deployment, diagnostics, and offline experimentation.
- Do not duplicate authoritative state across layers without defining synchronization and recovery semantics.

## 2. Memory Management, Translation & Synchronization

### No Global Lock Across Expensive Operations
- Do not hold the global monitor spinlock while walking guest page tables, waiting for GPU work, performing blocking I/O, or executing unbounded operations.
- Prefer appropriately scoped synchronization, immutable snapshots, or validated read-mostly structures.
- Lock-free and RCU-based implementations require explicit lifetime, memory-ordering, and reclamation guarantees.
- Establish lock-order rules and test concurrent updates, unmapping, invalidation, and address-space teardown.

### Architecturally Correct Translation Invalidation
- Batch translation invalidations where practical.
- Select TLBI operations according to translation stage, VMID, ASID, address range, shareability domain, and supported CPU features.
- Do not substitute stage-1 invalidations for stage-2 invalidations.
- Apply architecturally required barriers and break-before-make sequences where applicable.
- Prefer appropriately scoped invalidations. Whole-VMID invalidation requires a correctness or measured performance justification.

### Strict Memory Ownership & Lifetime
- Every shared buffer, shadow table, DMA mapping, and GPU resource must have defined ownership and retirement conditions.
- Never recycle memory while another CPU, hardware queue, or DMA engine can still access it.
- Model CPU/GPU cache visibility, mapping changes, fence completion, and device teardown explicitly.
- Add targeted tests for stale translations, use-after-free, double-unmapping, and interrupted completion.

### No Fabricated Hardware or ABI Contracts
- Never invent register layouts, interrupt meanings, firmware commands, SPTM/TXM return values, or private Apple ABI signatures.
- Distinguish observed behavior from inferred behavior.
- Unsupported behavior must fail explicitly rather than return fabricated success.
- Preserve exact verified ABI layouts and PAC-sensitive signatures.
- Revalidate private interfaces when changing the guest kernel build or target hardware profile.

## 3. Performance & Real-Time Execution

### No Blocking Operations in Critical Paths
- EL2 trap handlers, timer and interrupt handlers, GPU completion handlers, and presentation paths must not perform blocking console I/O, host RPC, or filesystem operations.
- Use bounded, asynchronous diagnostic buffers.
- Do not introduce unbounded polling or synchronous waits in latency-sensitive execution paths without demonstrated necessity.

### Steady-State Allocation Discipline
- Avoid heap allocations in steady-state presentation, interrupt, and GPU submission hot paths.
- Prefer initialized, bounded command pools, fence pools, and reusable staging arenas.
- Any exception must be documented and justified by profiling.
- Initialization and exceptional recovery paths may allocate when safe and appropriately bounded.

### Correct GPU Submission & Completion Semantics
- GPU commands must not reference resources that can be destroyed or recycled before retirement.
- Do not report command completion before the corresponding hardware work has completed.
- Validate command streams, resource ranges, and privileged register access before submission.
- Timeouts must follow explicit recovery procedures, not silently mark unfinished work as successful.

### Performance Regression Discipline
- Do not claim an optimization without reproducible before-and-after measurements.
- Report median, tail latency, frame pacing, and relevant correctness counters where applicable.
- Compare equivalent configurations, workload traces, thermal conditions, and clock ceilings.
- An apparent throughput improvement that introduces visual corruption, missed deadlines, data races, or additional hardware instability is not an accepted improvement.
- Do not use measurements collected during GPU recovery, latch-up, or incomplete test runs.

## 4. Hardware Evidence & Documentation

### Hardware Register Provenance
- Identify hardware registers using named blocks and symbolic offsets.
- Document the target SoC or device revision and the supporting technical evidence.
- Do not scatter unexplained physical addresses or magic register values throughout implementation code.
- Physical addresses must be obtained from verified platform mappings rather than assumed universal constants.
- Preserve relevant links to public technical documentation or locally reproducible evidence without committing restricted source material.

### Explain Non-Obvious Invariants
- Comments should explain hardware constraints, architectural reasoning, ordering requirements, and known failure modes.
- Comment why the code needs a particular implementation, not merely what its syntax does. Favor hardware constraints, invariants, assumptions, ordering and failure modes over narration.
- Exceptions: document what a public API guarantees (parameters, units, ownership, errors, threading), and explain unfamiliar algorithms when the implementation is not self-evident.
- Do not write comments that merely restate an if, assignment, function name, or assertion. Never use unexplained agent session tags such as `/* F4: ... */`.
- Use static assertions to verify sizes, offsets and alignments, but do not substitute long runs of assertions for an explanation of the hardware requirement.
- Explain why a workaround exists, which revisions it applies to, and the observable condition for safely removing it.
- Keep comments synchronized with behavior when code changes; delete stale speculation and do not present guesses as verified facts.

### Evidence Classification
- Distinguish VERIFIED, OBSERVED, INFERRED, EXPERIMENTAL, and UNIMPLEMENTED behavior.
- A successful compilation does not prove ABI correctness.
- A successful offline replay does not prove equivalent behavior on hardware.
- Reaching a boot milestone does not prove stability.
- Never upgrade a feature's reported status without the corresponding test evidence.

## 5. Testing & Agent Execution Discipline

### No Untested Behavioral Refactors
- Establish a reproducible baseline before altering functioning monitor, driver, or compiler code.
- Preserve existing tests and add regressions for changed behavior.
- Verify functional equivalence before attributing performance gains to a refactor.
- Report tests as PASS, FAIL, SKIP, or NOT RUN. Never describe skipped tests as successful.

### Bounded, Reviewable Changes
- Keep each change focused on a defined engineering objective.
- Do not combine unrelated refactors, new features, and performance experiments without explicit justification.
- Do not silently change defaults or weaken assertions to make a test pass.
- Never bypass failing tests by deleting them, relaxing expected outputs, or substituting fabricated results.

### Standalone-First Runtime Design
- New runtime drivers and EL2 services must not depend on a connected host for their fundamental operation unless explicitly approved as transitional.
- Python host tools remain appropriate for provisioning, diagnostics, offline regression testing, and current experimental boot workflows.
- Isolate host transport behind interfaces that can eventually support native on-device operation.
- Do not introduce new production-critical RPC dependencies without documenting their removal path.

### Accurate Milestone Reporting
- Every substantive hardware milestone must identify the tested revision, build identity, enabled flags, execution environment, and supporting log or report.
- Distinguish partial functionality from end-to-end operational readiness.
- Record known limitations and remaining failure modes.
- Never claim hardware validation when only simulated, compiled, or host-replayed evidence exists.

### Preserve Recoverability
- Hardware experiments must retain a documented stop, quiesce, and recovery path.
- Treat storage partition modifications, persistent firmware writes, and clock or voltage changes outside established safety limits as destructive operations requiring explicit authorization.
- Never disable established thermal, power, or storage safety guards merely to complete an experiment.

## 6. Commit Naming & Git Discipline

Use `module: imperative change` for every new commit title. This is a
repository-scoped prefix convention, not Conventional Commits with `feat(...)`
or an invitation to put the issue number in place of a subsystem.

```
<module>: <imperative, specific change>
```

- **Module Identifier:** Use a lowercase, hyphenated module identifier. Prefer the smallest stable
  owning subsystem: `shadow`, `compat`, `sptm`, `txm`, `gpu`, `adreno-kext`,
  `adreno-metal`, `air2ir3`, `display`, `wifi`, `input`, `nvme`, `probes`,
  `tools`, `cycle`, `build`, `tests`, `docs`, or `repo`. Introduce new scopes
  only for genuine long-lived modules, not individual files or sessions.
- **Imperative Verb:** Start the description with an imperative verb (`fix`, `batch`, `validate`,
  `remove`, `refactor`, `document`, `guard`, `rework`, `add`). Be specific about
  the behavior changed. Use sentence case only for proper nouns/symbols; do
  not end the subject with a period.
- **Subject Length:** Aim for 50 characters; the hard subject-line limit is 72 characters.
  When needed, add a blank line followed by a body explaining motivation,
  tradeoffs, implementation constraints, and test evidence. Wrap body lines at
  approximately 72 characters, except links and literal commands.
- **Single Conceptual Change:** Keep one conceptual change per commit. Do not bury unrelated refactors,
  generated files, benchmarks or policy edits inside a behavior change.
- **No Vague Titles:** Do not use `WIP`, `misc`, `cleanup stuff`, `fix bugs`, vague session labels,
  agent names, or promotional claims as final commit titles.
- **Authorization for Operations:** Do not amend, rebase, force-push, reset another contributor's work, or create
  commits unless the task authorizes that Git operation. Never claim a commit
  exists without confirming it.
- **Breaking Changes:** For incompatible interface changes, describe migration and compatibility
  implications in the commit body and PR. Do not casually reassign a public
  ABI, register layout, or feature flag under the guise of cleanup.

```
Good:
shadow: batch stage-2 TLB invalidations
compat: release the monitor lock before GPU waits
air2ir3: reject unsupported AIR texture operands
display: document present-fence ownership
wifi: validate QCC2072 ring descriptors
docs: define coding-agent contribution standards

Bad:
fixes
WIP changes
feat(shadow): improve things
AI: finished the hypervisor
update code
```

## 7. Comments, Documentation & Naming

The governing principle is **explain the why, not narrate the what**.

- Comments are warranted for unexpected ordering, architecture-specific
  constraints, non-obvious invariants, workarounds, concurrency ownership,
  error cases, hardware errata, and empirically observed failure modes.
- Public APIs still require clear *what* contracts: units, parameters,
  ownership, buffer lifetime, valid threading context, return values and
  failure semantics. Short algorithm summaries are appropriate for complex
  transforms or translation logic.
- Do not write `// Increment index` above `++i`, duplicate a function's name
  in prose, or use comments as a substitute for clear naming.
- Keep function and variable names descriptive of their actual responsibilities.
  Avoid session-generated prefixes, meaningless abbreviations and unexplained
  one-letter identifiers outside narrow mathematical contexts.
- Any hardware constant that could be revision-dependent needs a meaningful
  symbol and a source trail (register block, offset, SoC revision, and
  independently verifiable evidence). Do not publish confidential register
  dumps, extracted vendor blobs, or proprietary disassemblies as evidence.
- Use `_Static_assert` / `static_assert` for enforceable invariants. Explain
  why a layout is necessary nearby, especially for guest-visible structs,
  DMA descriptors, PAC-sensitive vtables, cache-line assumptions, and page
  sizes. Avoid using hundreds of assertions as replacement prose.
- `TODO` / `FIXME` comments must describe the missing behavior, observable
  failure or acceptance condition, and preferably a tracking issue. Do not
  leave vague `TODO: fix later`, session TODOs, or speculative claims of
  completeness. Remove obsolete TODOs when implementing the fix.
- Document feature flags, configuration defaults and behavioral changes in
  the relevant README or reference docs. Keep existing link targets and
  anchors functional; if a heading must move, update inbound links together.
- Avoid stale or overconfident comments: `OBSERVED` and `INFERRED` are not
  interchangeable with `VERIFIED`.

### Example

```c
// Good:
// The GPU may still read this IB after the submit call returns.
// Retire it only after the hardware completion fence is observed.
retire_ib_after_fence(ib, fence);
```

### Not

```c
// Bad:
// Retire IB after fence.
retire_ib_after_fence(ib, fence);
```

## 8. Agent Workflow, Scope & Failure Behavior

1. **Establish context before editing.** Identify the owning subsystem,
   existing implementation, relevant tests, feature flags, known failure
   modes and hardware-sensitive operations. Inspect before replacing.
2. **Define acceptance criteria.** State the observable behavior that must
   change, what must remain identical, and what would falsify success.
   For multi-layer fixes, document call boundaries and ownership before
   modifying both sides.
3. **Prefer the smallest correct change.** Do not create a replacement driver,
   header tree, compiler pass or RPC service just because modifying the
   existing code is more difficult. Respect existing deliberate references.
4. **Make errors explicit.** Fail closed on unrecognized monitor calls,
   unsupported firmware operations, malformed command streams, invalid
   mappings and ABI mismatches. Never fabricate a successful return value to
   bypass a failure. Capture enough context to diagnose the rejection without
   leaking secrets or causing hot-path latency.
5. **Preserve behavioral defaults.** Keep changes opt-in where required,
   account for cleanup/recovery paths, and test failure cases as well as the
   expected path. Never mute assertions or delete failing tests to create
   artificial success.
6. **Validate at the correct level.** Distinguish syntax/build checks,
   sanitizer tests, offline reference replays, ABI validation, and hardware
   validation. Report each separately: `PASS`, `FAIL`, `SKIP`, or
   `NOT RUN`, with a reproducible command and reason for non-execution.
7. **Do not invent artifacts or results.** Never fabricate compiler output,
   hashes, register traces, performance figures, logs, hardware status,
   screenshots or benchmark improvements. Do not claim testing on the A16
   when work was confined to a host or a mock environment.
8. **Close with a factual handoff.** Summarize changed files and rationale,
   tests executed and exact outcomes, known risks, and whether hardware
   qualification is still required. Do not imply completion if a prerequisite
   or regression remains unresolved.

### Change Acceptance Matrix

| Change category | Minimum acceptable evidence before requesting hardware time |
| --- | --- |
| Documentation / comments only | Links, anchors, examples and factual references reviewed |
| C/C++ refactor | Build or syntax validation, relevant host tests, equivalence checks |
| Shadow MMU, SPTM/TXM, TLBI | Translation models, invalidation/ordering cases, concurrency teardown cases |
| arm64e kext ABI, IOKit | KDK/kernelcache slot/signature verification and relevant stub checks |
| GPU commands, buffers or fences | Host replay, bounds/ownership checks, fault and timeout cases |
| AIR to ir3 lowering | IR tests, negative/unsupported opcode cases, pinned reference comparisons when available |
| Boot, storage, DVFS or firmware | Offline refusal-path tests and explicit, supervised hardware test plan |

This matrix describes minimum preparatory evidence, not blanket permission
for running privileged tools. Private inputs and dedicated hardware may not
be available to a contributor; mark the corresponding checks `NOT RUN` or
`SKIP` accurately and explain what remains unverified.

## 9. Pull Request Standards

Every PR should contain:

- **Purpose:** The concrete defect, feature or engineering problem and why it
  matters; refer to related issues when relevant.
- **Scope:** Subsystem(s), files and behavior affected; list what intentionally
  remains out of scope.
- **Design:** Architectural decisions, ABI or register assumptions, locks and
  lifetime rules, any new feature flags, fallback and recovery behavior.
- **Evidence:** Exact commands and PASS/FAIL/SKIP/NOT RUN outcomes; for
  performance PRs include reproducible before/after data and tail latencies,
  not just the best average FPS.
- **Safety and compatibility:** Changes to destructive operations, hardware
  ceilings, boot flow, license/provenance inputs, external dependencies,
  default-off equivalence or guest build assumptions.
- **Remaining limitations:** Failures, unresolved questions and required
  supervised hardware qualification.

One PR should address one coherent goal. Avoid formatting-only churn mixed
with functional changes. For policy-only PRs, no hardware run is necessary;
review Markdown links, preserved instructions and changed diff instead.

## Rebuilding What Is Not Distributed

Use [docs/BUILDING.md](docs/BUILDING.md) for the overall build. The following
inputs must be generated **locally from material the contributor is authorized
to use**, and must never be committed. A Mac with the matching macOS
27/26A428 userspace, Xcode, the KDK at
`/Library/Developer/KDKs/KDK_27.0_26A428.kdk`, and the J700 restore-image
kernelcache is required for the relevant workflows.

| Missing input | Local destination | Produce / recover it with | Verify with |
| --- | --- | --- | --- |
| `IOMobileGraphicsFamily26A428.h` | `gpu/adreno-kext/kext/include/` | `python3 tools/gen-iomfb-header.py --kc downloads/extracted/j700ap/<kernelcache>; optionally --kdk` | `python3 tools/check-iomfb-vtable.py` |
| `IOGPUFamily26A428.h` | `gpu/adreno-kext/kext/include/` | ABI reconstruction recipe below | Stub subclass vtable comparison |
| `IO80211Controller26A428.h`, `IO80211Interface26A428.h`, `IO80211WorkQueue26A428.h`, `IOSkywalkLifecycle26A428.h` | `drivers/snap-qcc2072/include/` | `python3 drivers/snap-qcc2072/re/recover-controller-abi.py --output build/controller-abi.json`, the `re/interface-abi/` scripts, then recipe below | `python3 drivers/snap-qcc2072/re/verify-controller-abi.py --binary <linked-kext> --report build/verify.json` |
| Study-only disassembly | `build/` | `tools/kc-disas.py`, `tools/kc-xref.py`, `tools/kc-symbolicate.py` on locally obtained inputs | Do not commit output |
| `render-shaders.pinned.json`, `p7-shaders*.json` | `gpu/air2ir3/tools/a16ref/`, `gpu/air2ir3/tools/p7ref/` | `AIR2IR3_TREE=<repo> OUT=build/p7 zsh gpu/air2ir3/tools/p7ref/make-p7-shaders.sh`; q1n1's `tools/a16gpu-render/make-render-shaders.sh` | `gpu/air2ir3/tools/p7check.py`, `a16check.py`; absent inputs mean SKIP |
| `probes.air` | `gpu/air2ir3/tools/a16ref/` | `gpu/air2ir3/tools/a16ref/build-probes-air.sh` | Local generator/build validation |
| Machine pins | `tools/cycle_lib/pins.json` | Copy `tools/cycle_lib/pins.example.json` and configure locally | `tools/cycle.py ... --prepare` |
| Mesa | `gpu/air2ir3/third_party/mesa` | `gpu/air2ir3/tools/mesa-setup.sh` at pinned revision | air2ir3 tests |

### Recipe: a header for a private Apple C++ class (arm64e)

**Do not remove or rename this heading without updating the existing links in
[docs/BUILDING.md](docs/BUILDING.md).** The recipe applies to `IOGPUFamily26A428.h`, the
IO80211/Skywalk headers, and comparable future private classes. It is about
rebuilding interfaces from the contributor's own licensed inputs, not
redistributing extracted or reconstructed Apple materials.

1. **List the required declarations.** Inspect usage in the local source,
   for example `grep -rhoE 'IOGPU[A-Za-z]+' gpu/adreno-kext/kext/src | sort -u`.
   Declare only the classes, methods/overrides and fields actually needed.
2. **Examine locally available arm64e vtables.** From the contributor's KDK,
   use `lipo -thin arm64e`, `nm -arch arm64e -m` (with `c++filt`) and
   `dyld_info -fixups` to identify vtable slots, targets and PAC diversity.
   The Itanium-style symbol form for a vtable is `__ZTV<len><Class>`.
3. **Reconstruct each declaration in the class introducing the slot.** Keep
   virtuals in slot order. PAC discrimination may depend on the declaration's
   mangled name: an incorrect signature can panic at load or first call,
   rather than merely misbehave. Return types are not generally encoded by
   ordinary C++ function name mangling; infer cautiously from callers and
   overriders and label those inferences.
4. **Verify sizes and member offsets.** Obtain class size from `OSMetaClass`
   construction and offsets from actual uses, preferring accessors instead of
   guessing layout or publishing extracted artifacts.
5. **Cross-check against the J700 kernelcache.** KDK agreement alone is
   insufficient: validate slot count, targets and PAC diversities against the
   actual kernelcache using local `tools/kc-xref.py` and
   `tools/kc-symbolicate.py` when applicable.
6. **Prove the ABI before loading a real kext.** Build a stub subclass with
   the same flags as `gpu/adreno-kext/kext/build.sh`, compare slots against
   local KDK/kernelcache evidence (as `tools/check-iomfb-vtable.py` does),
   and only then proceed to the real kext. Do not commit the reconstructed
   header or private source evidence.

## Day-to-Day Build, Test & Debugging Notes

The authoritative full sequences are in [docs/BUILDING.md](docs/BUILDING.md)
and [docs/RUNNING.md](docs/RUNNING.md). Commands below are examples, not an
invitation to operate on hardware without permission.

- **Host suite:** `python3 tools/test-<name>.py` or the matching C test's documented
  sanitizer build. Test drivers may compile their native C suites.
- **Kext:** `gpu/adreno-kext/kext/build.sh`; AuxKC link helpers include
  `tools/build-auxkc-user.py` and `tools/auxkc-autoload.py`.
- **Controlled boot workflow:** `python3 tools/cycle.py installed-fresh --prefix <name> ... --prepare; validate with --check`;
  boot with matching arguments, `--boot --generation 1 --qualification-sha256 <sha>`; then `--quiesce`.
- A prepared run is pinned to source hashes. Never modify tracked sources
  between prepare/qualification and boot.
- RAM-scanned plug-in log lines can persist across boots: filter by the
  current run stamp, or old messages will contaminate diagnosis.
- Reproduce userspace and Metal behavior offline on the matching macOS host
  via the interposed Metal plug-in and harnesses before testing on-device.
- Use only a run's actual performance windows for FPS/latency reporting.
  Measurements during GPU latch, recovery or incomplete runs are invalid.

## Agent Handoff Format

When finishing a task, provide a compact report with these headings:

```
Changes: [files and why]
Validation: PASS [command]; FAIL [command/reason];
            SKIP [unavailable prerequisite]; NOT RUN [reason]
Risks / limitations: [hardware, ABI, migration or reproducibility caveats]
Hardware status: NOT RUN unless an authorized, recorded run actually occurred
```

Never turn `SKIP` or `NOT RUN` into `PASS`, and never claim a successful PR,
commit, merge, benchmark, boot or hardware qualification unless it happened.
