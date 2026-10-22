/* SPDX-License-Identifier: MIT */
// AdrenoCodeScan.h - may an ir3 a8xx program write device memory? (agents/gpu-perf FAILURE-MODES.md U4)
//
// The UBO mirror (AdrenoDrawCommands.m, ADRENO_UBO_MIRROR) must know whether a draw can write a buffer it binds as a
// device buffer: the plug-in relocates every device buffer read-write, and Core Animation binds its uniform buffer both
// as a constant buffer and as a device buffer (vertex fetch, gamma tables, blur weights) in almost every pass. A program
// that holds no memory-writing instruction cannot write any buffer, whatever its bindings say.
//
// The scan is conservative: an instruction is harmless only when it matches one of the load, local/private or
// const-file forms below and none of the global/image store or atomic forms of Mesa's ISA description
// (src/freedreno/isa/ir3-cat6.xml, gen >= 600). Anything it does not recognise counts as a store. Only the instruction
// area is scanned (the constant data that follows the code is not code). tools/host/test-codescan.c checks it against
// Mesa's own decoder over every shader-cache record: it must never call a program store-free that Mesa decodes a
// store or atomic in.
#ifndef ADRENO_CODE_SCAN_H
#define ADRENO_CODE_SCAN_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// One 64-bit instruction: 1 when it may write memory outside the shader's private, local and const storage.
static inline int adreno_ir3_instr_may_store(uint64_t w) {
    if ((w >> 61) != 6) return 0;                         // not category 6 (memory): no memory write
    const unsigned opc = (unsigned)((w >> 54) & 0x1f);    // a3xx-form OPC (a6xx ibo load/store forms keep OFFSET_LO here)
    const unsigned opc6 = (unsigned)((w >> 14) & 0x3f);   // a6xx-form OPC
    // a6xx ibo forms (ldib.b, stib.b, atomic.b.*, resinfo.b, resbase): bits 20..22 = 0b110, OPC in 14..19, and the
    // a3xx OPC bits may hold an offset. Only the loads and queries are harmless; ldc (OPC 0x1e, a6xx generic form) can
    // have the same bits 20..22 and no store or atomic has its OPC.
    if (((w >> 20) & 7) == 6)
        return !(opc6 == 0x06 || opc6 == 0x0f || opc6 == 0x0c || opc6 == 0x1e);
    // a6xx generic form (bits 4..5 = 0, a3xx OPC = 0, bit 40 = 0): ldc, getspid/getwid/getfiberid. The a3xx ldg family
    // shares these bits and always has bit 0 set (ldg, ldg.a, ldg.k: loads). Anything else in this form counts as a store.
    if (opc == 0 && ((w >> 4) & 3) == 0 && ((w >> 40) & 1) == 0) {
        switch (opc6) {
            case 0x1e: case 0x24: case 0x25: case 0x26: return 0;
            default: return !(w & 1);
        }
    }
    switch (opc) {
        case 0x00:                                        // ldg, ldg.a, ldg.k (global loads)
        case 0x01: case 0x02: case 0x0a: case 0x1f:       // ldl, ldp, ldlw, ldlv (local/private loads)
        case 0x04: case 0x05: case 0x0b:                  // stl, stp, stlw: the shader's own local/private memory
        case 0x06: case 0x0f: case 0x1b:                  // ldib, resinfo, ldgb/shfl
            return 0;
        case 0x1c:                                        // stc (const file) on gen >= 600: bits 14..22 = 0, bit 23 = 1
            return !(((w >> 14) & 0x1ff) == 0 && ((w >> 23) & 1));
        case 0x1d:                                        // stsc (shared consts -> const file): bits 22..23 = 0b11
            return ((w >> 22) & 3) != 3;
        default:                                          // stg (3), g2l/l2g, atomics (0x10..0x1a), ray_intersection, ...
            return 1;
    }
}

// The program's instruction area: `bytes` of code (8-byte instructions). 1 when any instruction may store.
static inline int adreno_ir3_code_may_store(const void *code, size_t bytes) {
    const uint8_t *p = (const uint8_t *)code;
    if (!p) return 1;
    for (size_t at = 0; at + 8 <= bytes; at += 8) {
        uint64_t w;
        memcpy(&w, p + at, 8);
        if (adreno_ir3_instr_may_store(w)) return 1;
    }
    return 0;
}
#endif
