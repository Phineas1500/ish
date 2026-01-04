#include <time.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"

void helper_cpuid(dword_t *a, dword_t *b, dword_t *c, dword_t *d) {
    do_cpuid(a, b, c, d);
}

void helper_rdtsc(struct cpu_state *cpu) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t tsc = now.tv_sec * 1000000000l + now.tv_nsec;
    cpu->eax = tsc & 0xffffffff;
    cpu->edx = tsc >> 32;
}

void helper_expand_flags(struct cpu_state *cpu) {
    expand_flags(cpu);
}

void helper_collapse_flags(struct cpu_state *cpu) {
    collapse_flags(cpu);
}

#include <stdio.h>
void helper_debug_store(uint64_t value, uint64_t addr) {
    static int count = 0;
    if (count < 20) {
        count++;
        fprintf(stderr, "DEBUG_STORE[%d]: value=0x%llx addr=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)addr);
    }
}

void helper_debug_load(uint64_t value, uint64_t addr) {
    static int count = 0;
    if (count < 30) {
        count++;
        fprintf(stderr, "DEBUG_LOAD[%d]: value=0x%llx from=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)addr);
    }
}

#ifdef ISH_GUEST_64BIT
void helper_debug_add_r9(uint64_t xtmp, uint64_t x8, struct cpu_state *cpu) {
    static int count = 0;
    if (count < 10) {
        count++;
        fprintf(stderr, "DEBUG_ADD_R9[%d]: xtmp=0x%llx x8=0x%llx cpu_r9=0x%llx\n",
                count, (unsigned long long)xtmp, (unsigned long long)x8,
                (unsigned long long)cpu->r9);
    }
}
#endif

// Debug: trace actual ARM64 x23 register (rdx alias)
void helper_debug_rdx(uint64_t rdx_value, uint64_t xtmp_value) {
    static int count = 0;
    if (count < 20) {
        count++;
        fprintf(stderr, "DEBUG_RDX[%d]: x23=0x%llx xtmp=0x%llx\n",
                count, (unsigned long long)rdx_value, (unsigned long long)xtmp_value);
    }
}

// Debug: trace save_xtmp_to_x8 - called AFTER the save
void helper_debug_save_x8(uint64_t x8_value, uint64_t xtmp_value) {
    static int count = 0;
    if (count < 10) {
        count++;
        fprintf(stderr, "DEBUG_SAVE_X8[%d]: x8=0x%llx xtmp=0x%llx\n",
                count, (unsigned long long)x8_value, (unsigned long long)xtmp_value);
    }
}
