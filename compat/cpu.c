/* SPDX-License-Identifier: MIT */
#include "cpu.h"

int guest_cpu_root_busy(const struct guest_cpu_address_space spaces[GUEST_CPU_COUNT],
                        uint64_t root)
{
    const uint64_t mask = UINT64_C(0x0000ffffffffc000);
    if (!spaces || !root || (root & ~mask)) return 1;
    for (unsigned cpu = 0; cpu < GUEST_CPU_COUNT; cpu++)
        if ((spaces[cpu].ttbr0 & mask) == root || (spaces[cpu].ttbr1 & mask) == root)
            return 1;
    return 0;
}

static int valid(const struct guest_cpu_registry *cpus)
{
    return cpus && !(cpus->registered & ~UINT64_C(0x3f)) &&
           cpus->active_slot < GUEST_CPU_COUNT && !cpus->reserved;
}
static uint64_t count(uint64_t value) { return value == UINT64_MAX ? value : value+1; }
static int affinity_slot(uint64_t affinity)
{
    if (affinity < 4) return (int)affinity;
    if (affinity >= 0x100 && affinity < 0x102) return (int)(affinity-0x100+4);
    return -1;
}

enum guest_cpu_result guest_cpu_register(struct guest_cpu_registry *cpus, uint64_t affinity)
{
    if (!valid(cpus)) return CPU_BAD_STATE;
    int slot = affinity_slot(affinity);
    if (slot < 0) return CPU_BAD_AFFINITY;
    cpus->registered |= UINT64_C(1) << slot;
    cpus->registrations = count(cpus->registrations);
    cpus->last_affinity = affinity;
    cpus->last_slot = (uint64_t)slot;
    return CPU_OK;
}

enum guest_cpu_result guest_cpu_id(struct guest_cpu_registry *cpus, uint64_t affinity,
                                  uint64_t *out)
{
    if (!valid(cpus) || !out) return CPU_BAD_STATE;
    int slot = affinity_slot(affinity);
    if (slot < 0) return CPU_BAD_AFFINITY;
    if (!(cpus->registered & (UINT64_C(1) << slot))) return CPU_NOT_REGISTERED;
    cpus->id_queries = count(cpus->id_queries);
    cpus->last_affinity = affinity;
    cpus->last_slot = (uint64_t)slot;
    *out = (uint64_t)slot;
    return CPU_OK;
}

int guest_cpu_buffers_valid(uint64_t pa, uint64_t va, uint64_t low, uint64_t high)
{
    return low < high && pa >= low && pa <= high &&
        GUEST_CPU_SCRATCH_SPAN <= high-pa &&
        !(pa & (GUEST_CPU_SCRATCH_STRIDE-1)) &&
        !(va & (GUEST_CPU_SCRATCH_STRIDE-1)) &&
        va <= UINT64_MAX-GUEST_CPU_SCRATCH_SPAN && (va >> 47) == 0x1ffff;
}

enum guest_cpu_result guest_cpu_buffer(const struct guest_cpu_registry *cpus,
    uint64_t slot, uint64_t pa, uint64_t va, uint64_t low, uint64_t high,
    struct guest_cpu_buffer *out)
{
    if (!valid(cpus) || !out) return CPU_BAD_STATE;
    if (slot >= GUEST_CPU_COUNT) return CPU_BAD_SLOT;
    if (!(cpus->registered & (UINT64_C(1) << slot))) return CPU_NOT_REGISTERED;
    if (!guest_cpu_buffers_valid(pa, va, low, high)) return CPU_BAD_BUFFER;
    out->pa = pa+slot*GUEST_CPU_SCRATCH_STRIDE;
    out->va = va+slot*GUEST_CPU_SCRATCH_STRIDE;
    return CPU_OK;
}

enum guest_cpu_result guest_cpu_output(struct guest_cpu_registry *cpus,
    uint64_t slot, uint64_t pa, uint64_t va, uint64_t low, uint64_t high,
    struct guest_cpu_buffer *out)
{
    enum guest_cpu_result result = guest_cpu_buffer(cpus, slot, pa, va, low, high, out);
    if (result != CPU_OK) return result;
    cpus->output_queries = count(cpus->output_queries);
    cpus->last_slot = slot;
    return CPU_OK;
}
