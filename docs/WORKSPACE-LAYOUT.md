# Workspace layout

This document lists what lives where in a Snapintosh workspace: the tracked
source directories, the local inputs and outputs that are never committed, and
the Apple and vendor material that stays on the machine that downloaded it.

## Repositories

A workspace holds two repositories side by side:

| Directory | Role |
| --- | --- |
| `Snapintosh/` | The Apple guest compatibility runtime: monitor, loader, device models, GPU stack, drivers, tools and docs |
| `q1n1/` | The UEFI EL2 proxy (a fork of Asahi Linux's m1n1, [github.com/Snapintosh/q1n1](https://github.com/Snapintosh/q1n1)) that owns the A16 hardware and the USB transport |

Several tools import q1n1's Python modules from the sibling checkout, so keep
the two directories next to each other.

## Snapintosh source

| Path | Role |
| --- | --- |
| `README.md` | Overview and documentation map ([README](../README.md)) |
| `docs/` | Public documentation |
| `compat/` | Monitor contracts, CPU/platform adaptation and device models (SPTM, TXM, AIC, ANS2 storage, GPU passthrough) |
| `shadow/` | Guest page-table walking and the hardware translation tables |
| `probes/` | Guest profiles, the host-side loader and runner, image builders and stopped-state readers |
| `tools/` | Boot cycle tool, analysis, capture, validation and native test sources |
| `gpu/adreno-kext/` | The Adreno IOGPU kext (AdrenoX2, AdrenoDisplay) and the Metal plug-in (AdrenoMetal) |
| `gpu/air2ir3/` | The AIR to Mesa ir3 shader compiler ([README](../gpu/air2ir3/README.md)) |
| `drivers/` | Guest kexts: boot framebuffer, I2C HID input, QCC2072 Wi-Fi, a minimal test kext |
| `config/` | Guest and monitor configuration |
| `build/build-auxkc.py`, `build/kmutil-auxkc.sh` | The auxiliary kext collection (AuxKC) build steps; see [BUILDING.md](BUILDING.md) |

## Local inputs and outputs (never committed)

| Path | Contents | How it is recreated |
| --- | --- | --- |
| `downloads/` | Apple's macOS restore image (`UniversalMac_27.0_26A428_Restore.ipsw`) and everything extracted from it: kernelcache, SPTM/TXM, device trees, BaseSystem. Roughly 25 GB. | `tools/fetch-ipsw.py` and `tools/extract-firmware.py` |
| `build/` | Monitor binaries, per-run build directories with their pinned source hashes, AuxKC collections, installation images, run logs, stopped-state captures and panel images | Rebuilt by the build steps; run records are produced by each boot |
| `gpu/air2ir3/third_party/` | The private Mesa checkout at the pinned revision | `gpu/air2ir3/tools/mesa-setup.sh` |
| `gpu/air2ir3/build/`, `cache/`, `results/`, `scratch/` | Compiler build outputs, the precompiled shader cache and sweep results | The compiler's own scripts |
| `gpu/air2ir3/corpus` | Shader bitcode extracted from Apple's frameworks | Extracted locally from the Mac's own macOS |
| `gpu/adreno/` | Research inputs for the Adreno work (WindowServer's Metal usage, local conformance harness captures) | Captured locally |
| `candidates/` | Machine-specific run manifests | Written per machine |

Machine-specific pins (the transport interface, device identities, image
bases) are local too and are not published.

`build/` is not disposable: besides rebuildable objects it holds the unique
captures of past runs, installation images and backups. Archive rebuildable
objects only after confirming nothing references them.

### What is never committed

- **Apple software and anything derived from it:** the restore image, the
  extracted kernelcache, firmware and device trees, BaseSystem and installation
  images, shader bitcode from Apple frameworks, binaries compiled from Apple
  shaders, kernelcache disassembly and reconstructed private class headers
  (generated locally at build time).
- **Vendor material:** Qualcomm firmware and anything copied from the A16's
  firmware partitions, including the Wi-Fi firmware.
- **Machine state:** run logs, captures, panel images of local runs, and
  machine pins.

## Kernel Debug Kit

Kernel symbols come from Apple's Kernel Debug Kit for the same build, installed
in the standard location:

```text
/Library/Developer/KDKs/KDK_27.0_26A428.kdk
```

Its `kernel.release.t8140` and dSYM are the same binary as the kernelcache's
`com.apple.kernel` (UUID `F9F468D7-1F50-354A-BECD-6BD6C1C834AD`, segments
relocated). `tools/kc-symbolicate.py <kernelcache VA>...` translates a
kernelcache address by segment and resolves it through `atos` to a function and
`file:line`. Several build steps read private class layouts from the KDK, so it
must be installed before building the kexts.

## Related documents

- [BUILDING.md](BUILDING.md): building the monitor, kexts, Metal plug-in and
  compiler.
- [RUNNING.md](RUNNING.md): preparing and booting the A16.
- [FULL-INSTALL.md](FULL-INSTALL.md): the installation images and the SSD
  window.
