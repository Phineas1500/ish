#include <time.h>
#include <stdio.h>
#include <string.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"
#include "emu/tlb.h"
#include "kernel/memory.h"

#ifdef ISH_64BIT
static int gret_count = 0;

void debug_gret_jump(unsigned long target_addr, unsigned long ip_value) {
    gret_count++;
    if (gret_count <= 10) {  // Only show first 10 gadget jumps
        fprintf(stderr, "DEBUG: gret %d jumping to 0x%lx, _ip=0x%lx\n", 
                gret_count, target_addr, ip_value);
    }
}

void debug_fiber_ret_reached(void) {
    fprintf(stderr, "DEBUG: Reached fiber_ret\n");
}

void debug_call64_reached(void) {
    fprintf(stderr, "DEBUG: Reached call64 gadget - about to execute\n");
}

void debug_call64_after_stack_setup(void) {
    fprintf(stderr, "DEBUG: call64 after stack setup\n");
}

void debug_call64_after_write_prep(void) {
    fprintf(stderr, "DEBUG: call64 after write_prep\n");
}

void debug_call64_after_load_retaddr(unsigned long retaddr) {
    fprintf(stderr, "DEBUG: call64 loaded return address 0x%lx\n", retaddr);
}

void debug_call64_after_store(void) {
    fprintf(stderr, "DEBUG: call64 after storing return address\n");
}

void debug_fiber_exit_reached(unsigned long interrupt_code) {
    fprintf(stderr, "DEBUG: Reached fiber_exit with interrupt=%ld\n", interrupt_code);
}

void debug_fiber_ip_value(unsigned long ip_value) {
    fprintf(stderr, "DEBUG: fiber_enter about to gret, _ip=0x%lx\n", ip_value);
    // Peek at the first gadget address
    unsigned long *gadget_ptr = (unsigned long *)ip_value;
    if (gadget_ptr) {
        fprintf(stderr, "DEBUG: First gadget address: 0x%lx\n", *gadget_ptr);
        fprintf(stderr, "DEBUG: Second gadget address: 0x%lx\n", *(gadget_ptr + 1));
    }
}

// Simple 64-bit compatible crosspage handler
bool simple_64bit_crosspage_read(void *tlb, uint64_t addr, void *value, unsigned size) {
    // For now, just fake success to test 64-bit emulation
    // In a real implementation, this would do proper memory translation
    if (value != NULL && (uintptr_t)value >= 0x10000) {
        memset(value, 0, size);
    }
    return true;  // Fake success
}

// Debug functions for 64-bit builds
void debug_call64_end(unsigned long cpu_ptr) {}
void debug_fiber_ret_chain_reached(unsigned long cpu_ptr) {}
void debug_print_tlb(unsigned long tlb) {}
void debug_print_tlb_setup(unsigned long tlb_base, unsigned long tlb_entries_ptr) {}
void debug_track_interrupt_code(unsigned long interrupt_code) {
    fprintf(stderr, "DEBUG_GADGET: Using %s gadget\n", interrupt_code == 32 ? "interrupt (32-bit)" : "interrupt64 (64-bit)");
}
void debug_track_x1_fiber_exit(unsigned long x1_value) {}
bool fixed_64bit_crosspage_read(void *tlb_ptr, uint64_t addr, void *value, unsigned size) {
    return simple_64bit_crosspage_read(tlb_ptr, addr, value, size);
}
#else
// Stub functions for 32-bit builds to satisfy assembly gadget references
void debug_gret_jump(unsigned long target_addr, unsigned long ip_value) {}
void debug_fiber_ip_value(unsigned long ip_value) {}
void debug_fiber_ret_reached(void) {}
void debug_call64_reached(void) {}
void debug_call64_after_stack_setup(void) {}
void debug_call64_after_write_prep(void) {}
void debug_call64_after_load_retaddr(unsigned long retaddr) {}
void debug_call64_after_store(void) {}
void debug_fiber_exit_reached(unsigned long interrupt_code) {}
void debug_fiber_ret_chain_reached(unsigned long cpu_ptr) {}
void debug_print_tlb(unsigned long tlb) {}
void debug_print_tlb_setup(unsigned long tlb_base, unsigned long tlb_entries_ptr) {}
void debug_track_interrupt_code(unsigned long interrupt_code) {
    fprintf(stderr, "DEBUG_GADGET: Using %s gadget\n", interrupt_code == 32 ? "interrupt (32-bit)" : "interrupt64 (64-bit)");
}
void debug_track_x1_fiber_exit(unsigned long x1_value) {}
bool fixed_64bit_crosspage_read(void *tlb_ptr, uint64_t addr, void *value, unsigned size) {
    return false;
}
#endif

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