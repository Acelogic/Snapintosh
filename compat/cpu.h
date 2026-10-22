/* SPDX-License-Identifier: MIT */
#ifndef SNAP_COMPAT_CPU_H
#define SNAP_COMPAT_CPU_H
#include <stdint.h>

#define GUEST_CPU_COUNT 6U
#define GUEST_CPU_SCRATCH_STRIDE UINT64_C(0x8000)
#define GUEST_CPU_SCRATCH_SPAN (GUEST_CPU_COUNT * GUEST_CPU_SCRATCH_STRIDE)

/* J700's four E affinities and two P affinities. Registration is metadata;
 * it does not start a CPU or claim native machine-initialization completion.
 * The caller serializes these operations with the runtime service lock.
 * Execution identity comes from CPU-local
 * state, not this registry's active_slot diagnostic. */
struct guest_cpu_registry {
    uint64_t registered, registrations, id_queries, output_queries;
    uint64_t active_slot, last_affinity, last_slot, reserved;
};
struct guest_cpu_buffer { uint64_t pa, va; };
struct guest_cpu_address_space { uint64_t ttbr0, ttbr1; };
/* Conservative liveness check across every CPU, including a prepared CPU
 * whose root has been assigned before entry. ASID and CnP bits are not PA. */
int guest_cpu_root_busy(const struct guest_cpu_address_space spaces[GUEST_CPU_COUNT],
                        uint64_t root);
enum guest_cpu_result {
    CPU_OK, CPU_BAD_STATE, CPU_BAD_AFFINITY, CPU_NOT_REGISTERED,
    CPU_BAD_SLOT, CPU_BAD_BUFFER
};
enum guest_cpu_result guest_cpu_register(struct guest_cpu_registry *cpus, uint64_t affinity);
enum guest_cpu_result guest_cpu_id(struct guest_cpu_registry *cpus, uint64_t affinity,
                                  uint64_t *slot);
enum guest_cpu_result guest_cpu_buffer(const struct guest_cpu_registry *cpus,
    uint64_t slot, uint64_t base_pa, uint64_t base_va, uint64_t mem_low,
    uint64_t mem_high, struct guest_cpu_buffer *out);
enum guest_cpu_result guest_cpu_output(struct guest_cpu_registry *cpus,
    uint64_t slot, uint64_t base_pa, uint64_t base_va, uint64_t mem_low,
    uint64_t mem_high, struct guest_cpu_buffer *out);
int guest_cpu_buffers_valid(uint64_t base_pa, uint64_t base_va,
                            uint64_t mem_low, uint64_t mem_high);
#endif
