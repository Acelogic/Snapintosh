# A virtual Apple AGX GPU (historical, superseded)

> [!NOTE]
> **Superseded Architectural Reference:**
> This document details the initial prototype evaluating a virtual Apple AGX GPU abstraction. The production stack uses the native Adreno pipeline ([ARCHITECTURE.md](ARCHITECTURE.md)). This analysis is retained for its accurate hardware documentation of Apple's UAT and AGX device-tree contracts.

Target was `j700ap` / T8140 / G17P, `kernelcache.release.mac17p` (`26A428`).

## What the kernelcache contains

Of 362 kexts, three matter for rendering: `AGXG17P` (the driver, about 920 KB
of code), `IOGPUFamily` (the generic layer Metal talks to) and
`AGXFirmwareKextG17PRTBuddy` (a 12 KB firmware shim). The rest are display.
When sizing fileset members, use `__TEXT_EXEC`: each member's `__LINKEDIT`
load command describes the shared 25 MB `__LINKEDIT`.

The shim's `requestFirmwareBinary` returns a pointer and a length, and logs
"GFX firmware was not loaded by iBoot" when it is absent: the driver expects
the boot loader to place firmware in memory. Other strings pin the
architecture: submission is a ring in shared memory with host and firmware
indices, liveness is polled through `isGFXBooted`, and context IDs are the
driver side of the UAT's `SET_CTX_ID`.

`AGXG17P` reads `/arm-io/gfx-asc` and about 150 `gpu-*` power and performance
properties, none of which exist in the shipped `DeviceTree.j700ap`; iBoot
fills them in.

## What the device tree describes

| Node | Compatible | Notes |
| --- | --- | --- |
| `arm-io/sgx` | `gpu,t8140` | 64 MiB GPU block; 8 interrupts |
| `arm-io/gfx-asc` | `iop,ascwrap-v6` | GFX coprocessor, inside `sgx` |
| `arm-io/gfx1-asc` | `iop,ascwrap-v6` | second die's coprocessor |
| `gfx-asc/iop-gfx-nub`, `gfx1-asc/iop-gfx1-nub` | `iop-nub,rtbuddy-v2` | RTKit nubs |
| `arm-io/mapper-gfx-asc` | `iommu-mapper,gfx` | |

There are two GPU dies, each with its own coprocessor and firmware. Every
other window lies inside `sgx` reg[0], so decode order matters: matching
`sgx` first swallows both mailboxes. The `sgx` node also carries policy, for
example `issue-gmmu-tlbis-at-retype`, which ties the GPU MMU to SPTM's frame
retype path.

The current Adreno route withdraws the `sgx` node and reuses its interrupt
line for the Adreno (see `compat/adreno.h`).

## The UAT interface

XNU reaches the GPU MMU through SPTM domain 0, table 7: 14 endpoints on a
uniform 0x40-byte stub stride. Endpoints 0-12 are `INIT_STATE`,
`DESTROY_STATE`, `MAP_TABLE`, `UNMAP_TABLE`, `MAP_BEGIN`/`_CONTINUE`,
`PREP_FW_UNMAP_BEGIN`/`_CONTINUE`, `UNMAP_BEGIN`/`_CONTINUE`, `SET_CTX_ID`,
`REMOVE_CTX_ID` and `GET_INFO`. Endpoint 13 has a stub in macOS 27 and no
name in any available source.

The first argument points into XNU's own memory (one state object per GPU
address space) and the monitor writes roots and context ID back into it. The
GPU tables are 16 KiB granule, three levels of 11 index bits. Unlike the CPU
side there is nothing to shadow: the CPU's MMU never walks them. The current
monitor keeps a read-only UAT adapter for the private address-space mode
(`compat/uat.c`).

Two behaviours held by tests in the prototype:

- `REMOVE_CTX_ID` clears only the valid bit, and `SET_CTX_ID` requires an
  invalid slot, not a zero one; otherwise ordinary context reuse fails much
  later.
- An unmodelled endpoint returns an error and is counted, never a silent
  success.

## The firmware

The restore image ships one GPU firmware payload per die, each a flat
`rkosftab` table of named sub-images for the GFX coprocessor. Availability was
never the blocker: these are ARM64 images that drive AGX shader hardware this
machine does not have.

## The decision

Three options were weighed:

- **(a) Run Apple's firmware and model what it touches.** This means
  reimplementing undocumented AGX silicon well enough for code with no error
  tolerance, and the result would still issue AGX command streams to nothing.
  It also means executing Apple's firmware.
- **(b) Model just enough to attach quietly.** A useful first milestone (RTKit
  handshake, plausible rings) and a machine with no GPU at the end.
- **(c) Implement the firmware's protocol.** Answer the mailbox, RTKit and
  shared-memory ring contracts and translate at the draw/dispatch level. The
  firmware ABI is partly documented by Asahi Linux's `drm/asahi` driver, but
  that is the host side; the peer state machine would have to be inverted, and
  the ABI is locked to one firmware version.

The decisive problem was shader code. Metal compiles to AGX ISA in user
space, and the Adreno cannot run it. Every AGX route ends in AGX-to-Adreno
shader translation behind an opaque protocol. The native route instead
replaces the driver and the Metal plug-in, and compiles Apple's AIR
intermediate representation for the Adreno with Mesa's ir3 backend. That is
the route the project took.

## Files (prototype, retained for reference)

| File | What |
| --- | --- |
| `gpu/agx-inventory.py` | evidence tool: kexts, strings, device tree, UAT stubs, firmware |
| `gpu/agx.h` | register file, UAT geometry and state |
| `gpu/agx-uat.c` | GPU page tables and the table-7 endpoints |
| `gpu/agx-asc.c` | ASC mailbox, RTKit handshake, MMIO decode |
| `gpu/test-agx.c` | native checks, plus the list of unmodelled behaviour |

The UAT descriptor encodings, context-table layout and RTKit/ASC constants in
`gpu/agx*.{c,h}` come from m1n1 (Asahi Linux, MIT licence). Agreement with
that reference is not hardware evidence; if the reverse engineering were
wrong, the model would reproduce the error and its tests would still pass.

```sh
python3 gpu/agx-inventory.py --kexts --dt --uat
cc -std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -Igpu \
   gpu/test-agx.c gpu/agx-uat.c gpu/agx-asc.c -o build/test-agx && build/test-agx
```
