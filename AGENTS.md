# AGENTS.md

Guidance for coding agents (and people) working in this repository. Read
[README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/BUILDING.md](docs/BUILDING.md) first. This file adds two things: the
rules the project works by, and how to rebuild the inputs that are not in the
repository.

## What this is

Snapintosh is an EL2 hypervisor plus a host toolchain. Together they boot
macOS 27 (build 26A428) on an ASUS A16 laptop with a Snapdragon X2 Elite. Its
companion, [q1n1](https://github.com/Acelogic/q1n1), is a fork of m1n1 that
runs as a UEFI app on the A16 and acts as the EL2 proxy. The Mac host drives
everything over USB-C NCM (`udp://enN`).

| Layer | Where |
| --- | --- |
| EL2 monitor: SPTM/TXM emulation, stage-2 and shadow page tables, compat devices | `probes/xnuboot.c`, `compat/`, `shadow/` |
| Boot and run orchestration | `tools/cycle.py`, `tools/cycle_lib/` |
| GPU kernel driver (IOGPU subclass, AdrenoDisplay IOMFB) | `gpu/adreno-kext/kext/` |
| Metal plug-in (`AdrenoMetal.bundle`, hand-written PM4) | `gpu/adreno-kext/plugin/` |
| Shader compiler, AIR to Mesa ir3 | `gpu/air2ir3/` |
| Wi-Fi (QCC2072), touchpad and keyboard (I2C-HID) | `drivers/` |
| Host tests and replays | `tools/test-*`, `tools/replay-*` |

## Rules

1. **Never commit Apple, Qualcomm or ASUS material.** That covers
   kernelcaches, KDK files, kexts, dyld caches, IPSW/IMG4 parts, firmware,
   ACPI dumps, disassembly listings, vtable or ABI dumps, the reconstructed
   `*26A428.h` headers, and shader sets compiled from Apple's shaders.
   `.gitignore` lists them. Generate them locally (next section) and keep the
   results under ignored paths such as `build/` and `downloads/`, or in the
   ignored `include/` targets named below.
2. **Never commit personal or machine data:** home paths, host names, user
   names, IP or MAC addresses, serial numbers, Wi-Fi names or passphrases,
   SSH key names, device interface names. Use arguments, environment
   variables, `tools/cycle_lib/pins.json` (ignored; copy
   `pins.example.json`) or `ROOT`-relative paths.
3. **New features are opt-in.** Put each one behind a compile-time define
   (`ADRENO_*`, `SNAP_*`) and a `tools/cycle.py` flag or boot-arg. With the
   define off, the build must stay identical: compare the monitor ELF byte for
   byte, and the kext section by section.
4. **Licensing.** New files carry `SPDX-License-Identifier: MIT`. Code derived
   from other projects keeps its upstream notice and is listed in
   [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
   `compat/adreno-ib-tables.h` is GPL-2.0-only: it is generated from q1n1's
   `tools/adreno_x2_protect.py`. Don't copy GPL code into MIT files. Treat
   Linux and other drivers as references: cite `file:line`, and
   re-implement.
5. **Hardware safety.** `tools/cycle.py` boots a real laptop and can write
   its internal NVMe.
   - Run only one hardware client at a time.
   - Keep the battery on AC or at 50% or more.
   - Leave `--thermal-guard` on.
   - Respect the GPU clock ceiling (`--gpu-dvfs-ceiling`).
   - Never issue a single `CP_MEMCPY` larger than 1 MiB. One 4 MiB copy hung
     the GPU.
   - `cycle.py` refuses a boot if tracked sources change between `--prepare`
     and `--boot`, so don't edit the tree while a run is prepared.
6. **Before hardware, write down the failure modes and test on the host.**
   - For risky changes, list the failure modes first.
   - Model the change in a host harness (`tools/test-*.c`/`.py`).
   - Add mutants the harness must catch.
   - Hardware runs are scarce, so batch independent fixes into one run.

## Rebuilding what is not distributed

You need:
- a Mac running macOS 26A428, the same build as the guest. The host can then
  reproduce the guest's userspace and Metal behaviour offline;
- Xcode;
- the KDK at `/Library/Developer/KDKs/KDK_27.0_26A428.kdk`;
- the J700 kernelcache from the restore image
  (`tools/fetch-ipsw.py`, then `tools/extract-firmware.py ... j700ap`; see
  BUILDING.md section 1).

Everything below runs on the host and never touches hardware.

| Missing input | Goes to | Produce it with | Check it with |
| --- | --- | --- | --- |
| `IOMobileGraphicsFamily26A428.h` | `gpu/adreno-kext/kext/include/` | `python3 tools/gen-iomfb-header.py --kc downloads/extracted/j700ap/<kernelcache>` (`--kdk` overrides the KDK path) | `python3 tools/check-iomfb-vtable.py` |
| `IOGPUFamily26A428.h` | `gpu/adreno-kext/kext/include/` | no generator yet: follow the recipe below | a stub subclass vtable compare, as `check-iomfb-vtable.py` does |
| `IO80211Controller26A428.h`, `IO80211Interface26A428.h`, `IO80211WorkQueue26A428.h`, `IOSkywalkLifecycle26A428.h` | `drivers/snap-qcc2072/include/` | `python3 drivers/snap-qcc2072/re/recover-controller-abi.py --output build/controller-abi.json` for the exact slots and PAC fixups, plus the `re/interface-abi/` scripts (run them from that directory; they import `evidence_guard.py`), then write the header from that evidence with the recipe below | `python3 drivers/snap-qcc2072/re/verify-controller-abi.py --binary <linked kext binary> --report build/verify.json` |
| Disassembly of Apple routines (for study only) | `build/` | `python3 tools/kc-disas.py <kernelcache> <address> --until-ret`; find addresses with `tools/kc-xref.py` / `tools/kc-symbolicate.py` | n/a |
| air2ir3 pinned shader sets (`render-shaders.pinned.json`, `p7-shaders*.json`) | `gpu/air2ir3/tools/a16ref/`, `gpu/air2ir3/tools/p7ref/` | `AIR2IR3_TREE=<this tree> OUT=build/p7 zsh gpu/air2ir3/tools/p7ref/make-p7-shaders.sh`; q1n1's `tools/a16gpu-render/make-render-shaders.sh` for the render set. Both compile Apple's own SkyLight/QuartzCore shaders from the host. | `gpu/air2ir3/tools/p7check.py`, `a16check.py`. Tests print SKIP when the sets are absent. |
| `probes.air` | `gpu/air2ir3/tools/a16ref/` | `gpu/air2ir3/tools/a16ref/build-probes-air.sh` | n/a |
| Machine pins | `tools/cycle_lib/pins.json` | copy `pins.example.json`, then set `device` and the q1n1 stage hashes | `tools/cycle.py ... --prepare` |
| Mesa | `gpu/air2ir3/third_party/mesa` | `gpu/air2ir3/tools/mesa-setup.sh` (pinned revision) | the air2ir3 tests |

### Recipe: a header for a private Apple C++ class (arm64e)

Use this for `IOGPUFamily26A428.h`, the IO80211/Skywalk headers, or any future
26A428 class. `tools/gen-iomfb-header.py` automates exactly this for IOMFB. If
you generalise it, that's the best contribution here.

1. **List what the code needs.** For example, run
   `grep -rhoE 'IOGPU[A-Za-z]+' gpu/adreno-kext/kext/src | sort -u`. Declare
   only those classes, the methods we call or override, and the fields we
   touch.
2. **Read the vtables from the KDK**, e.g.
   `.../KDK_27.0_26A428.kdk/System/Library/Extensions/IOGPUFamily.kext/Contents/MacOS/IOGPUFamily`.
   - Take the arm64e slice with `lipo -thin arm64e`.
   - The vtable symbols are `__ZTV<len><Class>`.
     `nm -arch arm64e -m` with `c++filt` names the exported methods.
   - `dyld_info -fixups` shows each slot's target and its PAC diversity.
3. **Declare every virtual in the class that introduces its slot**, in slot
   order, with parameter types exact enough that the mangled name matches.
   - On arm64e, a slot's PAC discriminator is derived from the mangled name of
     the declaration that introduces it. A wrong signature therefore fails
     pointer authentication and panics at kext load or on first call; it does
     not just misbehave.
   - Return types are not mangled. Infer them from callers or overriders, and
     mark the inferred ones (the IOMFB header uses `ret=` notes).
4. **Get the class sizes and offsets.**
   - `OSMetaClass` is constructed with each class's size, so read it from the
     metaclass constructor in the KDK binary.
   - Take field offsets only from code that uses them, and prefer accessor
     methods.
5. **Check against the J700 kernelcache, not just the KDK.** The device
   kernelcache is what runs. Use `tools/kc-xref.py` and `kc-symbolicate.py` to
   locate the same vtables there, and confirm slot count, targets and PAC
   diversities.
6. **Prove it.**
   - Compile a stub subclass with the flags from
     `gpu/adreno-kext/kext/build.sh`.
   - Compare its vtable slot by slot with the KDK and the kernelcache, as
     `tools/check-iomfb-vtable.py` does.
   - Only then build the real kext.

## Day-to-day commands

The full sequence is in [docs/BUILDING.md](docs/BUILDING.md); running on the
laptop is in [docs/RUNNING.md](docs/RUNNING.md).

- Host tests: `python3 tools/test-<name>.py`. The C tests are built by their
  matching `.py` driver.
- Kext: `gpu/adreno-kext/kext/build.sh`. AuxKC link: `tools/build-auxkc-user.py`,
  then `tools/auxkc-autoload.py`.
- A run: `python3 tools/cycle.py installed-fresh --prefix <name> ... --prepare`,
  then the same arguments with `--boot --generation 1 --qualification-sha256 <sha>`.
  After a run: `--quiesce`.

## Debugging notes

- Plug-in log lines found by RAM scans persist across boots. Filter them by
  the run's stamp, or you will chase an older run.
- The macOS host is the same build as the guest, so most userspace and Metal
  failures reproduce offline. Interpose the default `MTLDevice` with the
  plug-in and replay there before using hardware.
- Report fps and latency only from the run's perf windows. Never use numbers
  measured while the GPU is latched or recovering.
