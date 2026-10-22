# Apple-only instructions and system registers

The X2 Elite's Oryon cores implement ARMv9. Apple silicon implements ARMv9
plus instructions in encodings Arm leaves unallocated, and a large space of
IMPLEMENTATION DEFINED system registers. On this machine every Apple-only
instruction raises an exception with `EC 0` ("unknown reason"), which looks
the same as a corrupt word; a handler has to look at the instruction. This
document lists what the stock macOS 27 kernelcache (`26A428`, `j700ap`) uses
and how the Snapintosh monitor handles each one.

Counts come from a linear scan of `__TEXT_EXEC`, attributing each address to
its fileset entry by that entry's own segment ranges.

## Inventory

| Encoding | What it is | In kernel | In kexts | Handling |
| --- | --- | --- | --- | --- |
| `0x00201420` | `genter`: enter the guarded world (SPTM/TXM call) | 174 | 0 | intercepted and emulated |
| `0xd4e00000` | alternate call encoding, paired 1:1 with `genter` | 174 | 0 | same path |
| `0x00201400` | `gexit` | 0 | 0 | nothing to do: only the monitor executes it |
| `0xe7ffdeff` | XNU's `TRAP_DEBUGGER` | 1 | 0 | must reach XNU's own vector, never emulated |
| `0xe7ffdefe` | `TRAP_DEBUGGER`, ARM32-ancestor spelling | 1 | 0 | same as above |
| `0x002010x0`, `0x0020122x` | AMX instructions | 175 | 0 | never executed (see below) |
| `0x00200820` | Apple compression instruction | - | - | avoided with XNU's `-vm_compressor_wk_sw` boot argument |

`genter`, `gexit` and AMX all live in the `0x00201xxx` block. That is Apple's
reserved region, so a scan for Apple instructions should sweep the block
rather than a list of constants.

## The monitor calls

XNU reaches SPTM and TXM with `genter`, and every call stub also carries the
alternate `0xd4e00000`. A byte in `__DATA_CONST`, copied from a feature bit in
the SPTM boot structure, selects which one executes. The monitor builds that
structure, so XNU stays on `genter`; both are intercepted anyway.
`lldb` names `0xd4e00000` `tenter`; `llvm-mc`, `llvm-objdump` and `otool`
decline it.

How a call reaches EL2 (stage-2 execute-never call pages, a guarded vector in
native-call mode, or the opt-in HVC replacement) is described in
[BOOT-CHAIN.md](BOOT-CHAIN.md), section 4, and the HVC patch in
[KERNEL-PATCHES.md](KERNEL-PATCHES.md).

## The debugger traps

`0xe7ffdeff` is not an instruction to emulate. It is XNU's `TRAP_DEBUGGER`,
defined in `osfmk/kern/debug.c` as a deliberately undefined word. XNU executes
it from `DebuggerTrapWithState()` after it has decided to panic.
`handle_uncategorized()` in `osfmk/arm64/sleh.c` recognises it with
`(instr & ~1) == ARM_GDB_INSTR`, so both spellings match, and advances `ELR`
itself. The surrounding code zeroes `db_op_return` before trapping and reads
it afterwards, so emulating or skipping the word would be wrong. The monitor
delivers it to XNU's vector and reads the panic record back after a run.

`0xe7ffdefe` is the whole body of a three-instruction function (`bti c`, the
trap, `ret`) in the KDP code and needs the same treatment.

## AMX

All 175 AMX words are in `com.apple.kernel`, starting in the thread
context-switch path. Emulating them would cost a trap per instruction in the
hottest code in the kernel.

They are never reached. XNU panics if `AMXIDR_EL1` advertises no known AMX
version, so the monitor reports version 1. But the save/restore path is
guarded by two Apple IMPDEF registers: one is read and must be non-zero, and
the other has an enable bit (bit 63) that XNU sets on first use. Both trap
through `HCR_EL2.TIDCP`, the monitor answers reads with zero and drops
writes, so the enable never sticks and the guard never opens. XNU's AMX
support is lazy per thread (state allocated on first use, "AMX exception"
handlers), so a machine where AMX is never enabled never executes those words.

This is a consequence of a good default rather than a guarantee: one call site
is gated by software flags, and the argument is that nothing sets them because
nothing enables AMX. User-space numeric code that tries AMX would arrive as an
`EC 0`. If that is ever needed, the right shape is to emulate at the exception
boundary XNU already provides (shadow state per thread, trap on first use, one
save or restore per switch), not per instruction.

## System registers

Apple's IMPDEF registers (`op0 = 3`, `CRn = 15` and similar) trap to EL2
through `HCR_EL2.TIDCP`. The monitor:

- models the ones that carry state XNU depends on: the fast-IPI request and
  status registers, the deadline timer aliases, the SPRR permission registers,
  `GXF_STATUS_EL1`, `AMXIDR_EL1`;
- answers every other read with zero and drops the write, and logs it.

"A feature XNU is told it does not have is a feature it does not then use."
The zero answers are cheap but frequent; an opt-in kernel patch
(`SNAP_KERNEL_SYSREG_ZERO`) rewrites the reads of the 18 registers the monitor
always answers with zero into `MOVZ Xt, #0` and their writes into `NOP`. See
[KERNEL-PATCHES.md](KERNEL-PATCHES.md).

## Method notes

- Capstone 5.0.6 mis-reports SME2 `ldr zt0` / `str zt0` as undecodable on this
  kernelcache. LLVM with the full ARMv9.6/SME2.2/SVE2.2 feature set is the
  reliable decoder.
- Undecodable is not the same as Apple. Restricted to real function bodies
  (from `LC_FUNCTION_STARTS`), most undecodable words are data in text: ASCII,
  jump-table deltas, permutation tables and hash constants.
- A word appearing exactly once proves nothing; hundreds of words are
  singletons. What identified `0xe7ffdeff` was the symbol table around it and
  XNU's own comparison against it.

## The rule

Cost is trap frequency times cost per trap, not the number of encodings. Trap
at the coarsest boundary the guest already defines: `genter` is a call, so
trap the call; AMX is a lazy per-thread state machine, so control the enable,
not the register moves; the debugger trap is XNU's own, so do not intercept it.
