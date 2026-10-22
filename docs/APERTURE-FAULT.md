# The aperture fault: a diagnosis write-up

**Historical (September 2026).** This records how one early boot stop was
diagnosed, when stock XNU answered about ten monitor calls and then died
dereferencing NULL. The layout values belong to that point in bring-up; the
current design is in [BOOT-CHAIN.md](BOOT-CHAIN.md). It is kept because the
reasoning, including the wrong turns, generalises.

## The symptom

XNU entered, answered ten monitor calls and took a data abort with
`FAR_EL1 = 0x3ff8`. That is `2047 * 8`: the last slot of a 2048-entry table,
indexed off a NULL base.

The loop that faulted reads a page-table entry, masks out its physical
address, and asks `phystokv` to turn it into a virtual address. On failure a
conditional select turns the result into NULL, the index is added anyway, and
the next load faults. There is no check, because on Apple hardware it cannot
fail: every table XNU walks is in memory SPTM published.

`phystokv` itself is a linear scan of the physical aperture table that SPTM
(here, the loader) publishes: entries of `{phys base, virt base, pages}`,
24 bytes each, after a count. The run confirmed the kernel was reading the
table the loader wrote. So the question was which physical address fell
outside every published region.

## First cause: the kernel and the loader disagreed about the address space

Reproducing the walk on the host over the loader's own tables showed the
level-1 entry was simply zero: the kernel followed an entry the loader never
filled in. The address being walked was built from three immediates
(`0xfffffecfffcfc000`), so no wrong answer of the monitor's produced it.

The instruction before the walk loaded the root entry at index 2028, which is
eleven raw VA bits (`46:36`). The loader had put that address at index 12,
because it indexed five bits from the kernel base. XNU's own level descriptor
array stated the regime: a 47-bit VA mask, i.e. `T1SZ = 17`. The loader used
`T1SZ = 23`, reasoning that 41 bits puts the bottom of the regime exactly at
the kernelcache link address `0xfffffe0000000000`. The arithmetic was right
and the conclusion did not follow: a kernel linked there sits just as well
near the bottom of a 47-bit regime. With 32 top-level entries where the kernel
expected 2048, every entry landed at an index it never read.

The prediction (the fix is `T1SZ = 17`, with everything derived from the
kernel base moving with it) was written down before the change. The change
was necessary, and it exposed the next gap rather than fixing the boot. A
narrower mask had been folding other walks onto populated entries by accident.
A correct geometry exposing a hidden gap is not a regression.

## Second cause: a structure above declared DRAM

The next fault walked addresses numerically equal to physical ones, starting
at the first byte past the declared DRAM. The loop sizes a region from the
memory size supplied at boot (10 MiB per 256 MiB, rounded) and places it
directly above the top of DRAM, then requires the page tables to resolve it.

A cheap experiment separated the two hypotheses (a structure SPTM must
allocate, or wrong declared bounds): changing the declared memory moved the
fault exactly with it, and the level-2 index times eight matched `FAR_EL1` in
both runs.

The fix holds back a bootstrap reserve from the memory the guest is given,
declares DRAM short by that amount, identity-maps the reserve (VA = PA), and
publishes it in the aperture with `virt == phys`, so `phystokv` agrees with
the mapping instead of merely sitting beside it. The loop then ran to
completion.

## Third cause: SPTM's own region at a fixed address

Execution then reached the fixed address again, now from further along. The
code after the faulting load registers page-table pages as frames, so it
needs the whole hierarchy down to level 3.

A scan for the `movk Xd, #0xfecf, lsl #32` idiom found a family of constants,
all within the top 3 MiB of the 64 GiB window that level-1 entry 2028 covers:
a fixed region with distinct structures at fixed offsets. SPTM's bootstrap
confirmed it creates this region itself, one 16 KiB page at a time.

Mapping zeroed RAM there would have quieted the fault while leaving every later
read wrong. Instead the region is backed from a reserved part of declared DRAM
at its fixed virtual address, inside the aperture so `phystokv` can name its
pages. The guest exception went away and the run ended on the next monitor
call: `MAP_PAGE`, with the loader's table root and an address in the reserve.
The kernel had finished bootstrapping and started building mappings of its
own.

## After `MAP_PAGE`

`MAP_PAGE` writes the caller's PTE into the 16 KiB tables, then re-reads that
leaf through the guest's tables and inserts it into the 4 KiB shadow, so a
mis-decoded PTE shows up as a disagreement. The next stop was a level-0
translation fault on a low address: the loader had disabled `TTBR0_EL1`
because the kernelcache is entirely upper-half. That reading of the image was
right; it did not cover the kernel accessing the low identity mapping it had
just walked. A second shadow from the same guest tables under `TTBR0_EL1`
fixed it, and acknowledging `SERIAL_DISABLE` (the kernel taking over its own
console) took the run from 15 to over 1,600 answered calls.

Two more stops followed:

- **A NULL from a short buffer.** The SPTM boot structure was allocated at
  `0x400` bytes, but XNU copies `0x358` bytes starting at its base, and a
  pointer it then used came from the tail. The offset was found by reading
  the copy back off the target and matching it against the structure, after
  an assumed offset produced an identical fault. The field relates to a
  feature this monitor does not implement, so the honest value is a valid
  pointer to a zero byte, not NULL and not an invented structure.
- **An "unknown instruction".** The next stop was `EC 0` on `0xe7ffdeff`.
  It was first read as a fourth Apple encoding that yields a value, because
  skipping it led to a branch to address zero. Both conclusions were wrong:
  it is XNU's `TRAP_DEBUGGER`, executed on purpose after deciding to panic,
  and skipping it lets the panic path run into uninitialised debugger state.
  The symbol table placed it next to `_Debugger` in `osfmk/kern/debug.c`;
  what the analysis lacked was not cleverness but symbols. See
  [APPLE-ENCODINGS.md](APPLE-ENCODINGS.md). Reading the panic record after
  each run turned the next stop into a sentence ("random seed field too
  short").

## Lessons

- **An unchecked failure in the guest points at a contract, not a bug.** When
  stock XNU dereferences NULL after a lookup, ask which promise SPTM makes
  that the lookup relied on.
- **Write the prediction down before the change.** It keeps a fix from being
  described as obvious after it works, and it makes a fix that moves the fault
  readable as progress or as accident.
- **Move the input and watch the fault move.** Changing the declared memory
  and seeing `FAR_EL1` follow exactly settled a placement question no amount
  of reading would have.
- **Do not paper over an address with an empty page.** A mapping that
  satisfies a walk but not the reads behind it moves the failure somewhere
  harder to find.
- **Measure offsets off the machine.** The guest's memory survives the stop;
  reading it back beats arithmetic about where a copy began.
- **Use the symbol table early.** Identity questions about kernel code are
  usually answered by what is next to it.
