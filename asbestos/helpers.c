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
    
    // Show all gadget jumps for Block 2 (starts around gret 13)
    if (gret_count >= 12) {  
        fprintf(stderr, "DEBUG: gret %d ENTERING gadget 0x%lx, _ip=0x%lx\n", 
                gret_count, target_addr, ip_value);
        
        // Check for obviously invalid jump targets
        if (target_addr < 0x1000) {
            fprintf(stderr, "ERROR: Invalid gadget address 0x%lx! This should be a parameter, not a gadget!\n", target_addr);
        }
        
        // Force flush to see output before crash
        fflush(stderr);
    }
}

void debug_gret_exit(unsigned long gadget_addr) {
    if (gret_count >= 12) {
        fprintf(stderr, "DEBUG: gret %d EXITING gadget 0x%lx\n", 
                gret_count, gadget_addr);
        fflush(stderr);
    }
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
void debug_poked_ptr_value(unsigned long ptr_value) {
    fprintf(stderr, "DEBUG: poked_ptr value = 0x%lx\n", ptr_value);
}
void debug_call64_target(unsigned long target) {
    fprintf(stderr, "DEBUG: call64 jumping to target 0x%lx\n", target);
}
void debug_fiber_ret_reached(void) {
    fprintf(stderr, "DEBUG: fiber_ret reached\n");
}
void debug_poked_value(unsigned long value) {
    fprintf(stderr, "DEBUG: poked byte value = %lu\n", value);
}
void debug_fiber_ret_chain_entry(void) {
    fprintf(stderr, "DEBUG: Entered fiber_ret_chain\n");
}
void debug_before_last_block_store(unsigned long block_offset) {
    fprintf(stderr, "DEBUG: About to store last_block, offset = 0x%lx\n", block_offset);
}
void debug_before_fiber_gret(void) {
    fprintf(stderr, "DEBUG: About to execute gret in fiber_ret_chain\n");
}
void debug_before_fiber_gret_state(unsigned long ip, unsigned long cpu) {
    fprintf(stderr, "DEBUG: Before gret: _ip=0x%lx, _cpu=0x%lx\n", ip, cpu);
}
void debug_fiber_chain_gret(unsigned long gadget_addr, unsigned long ip_value, unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: fiber_chain gret to gadget 0x%lx, _ip=0x%lx, cpu=0x%lx\n", 
            gadget_addr, ip_value, cpu_ptr);
}
void debug_call64_target_param(unsigned long target, unsigned long ip) {
    fprintf(stderr, "DEBUG: call64 target parameter = 0x%lx (from _ip=0x%lx)\n", target, ip);
}
void debug_call64_params_1(unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4) {
    fprintf(stderr, "DEBUG: call64 params: p1=0x%lx, p2=0x%lx, p3=0x%lx, p4=0x%lx\n", p1, p2, p3, p4);
}
void debug_call64_params_2(unsigned long p5, unsigned long ip) {
    fprintf(stderr, "DEBUG: call64 params: p5=0x%lx, from _ip=0x%lx\n", p5, ip);
}
void debug_ret64_address(unsigned long ret_addr) {
    fprintf(stderr, "DEBUG: ret64 return address = 0x%lx\n", ret_addr);
}
void debug_call64_jump_target(unsigned long target) {
    fprintf(stderr, "DEBUG: call64 jumping to target RIP = 0x%lx\n", target);
}
#else
// Stub functions for 32-bit builds to satisfy assembly gadget references
void debug_gret_jump(unsigned long target_addr, unsigned long ip_value) {}
void debug_gret_exit(unsigned long gadget_addr) {}
void debug_fiber_ip_value(unsigned long ip_value) {}
void debug_fiber_ret_reached(void) {}
void debug_poked_ptr_value(unsigned long ptr_value) {}
void debug_call64_target(unsigned long target) {}
void debug_poked_value(unsigned long value) {}
void debug_fiber_ret_chain_entry(void) {}
void debug_before_last_block_store(unsigned long block_offset) {}
void debug_before_fiber_gret(void) {}
void debug_before_fiber_gret_state(unsigned long ip, unsigned long cpu) {}
void debug_fiber_chain_gret(unsigned long gadget_addr, unsigned long ip_value, unsigned long cpu_ptr) {}
void debug_call64_target_param(unsigned long target, unsigned long ip) {}
void debug_call64_params_1(unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4) {}
void debug_call64_params_2(unsigned long p5, unsigned long ip) {}
void debug_ret64_address(unsigned long ret_addr) {}
void debug_call64_jump_target(unsigned long target) {}
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
void debug_store64_r8_reached(void) {
    fprintf(stderr, "DEBUG: store64_reg_r8 gadget reached!\n");
    fflush(stderr);
}

