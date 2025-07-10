#include <time.h>
#include <stdio.h>
#include <string.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"

#ifdef ISH_64BIT
// Debug functions disabled for cleaner testing
void debug_print_ip(unsigned long ip) {
    fprintf(stderr, "DEBUG: fiber_enter - _ip = 0x%lx\n", ip);
}

void debug_print_tlb_setup(unsigned long tlb_base, unsigned long tlb_entries_ptr) {
    fprintf(stderr, "DEBUG: TLB setup - base = 0x%lx, entries_ptr = 0x%lx\n", tlb_base, tlb_entries_ptr);
}

void debug_print_gadget(unsigned long gadget) {
    // fprintf(stderr, "DEBUG: fiber_enter - first gadget = 0x%lx\n", gadget);
}

void debug_track_x1_call64_entry(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 entry - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_call64_exit(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 exit - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_fiber_ret_chain(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: fiber_ret_chain entry - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_fiber_exit(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: fiber_exit entry - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_after_sub(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 after sub - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_before_write_prep(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 before write_prep - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_after_write_prep(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 after write_prep - x1 = 0x%lx\n", x1_value);
}

void debug_track_x1_before_write_done(unsigned long x1_value) {
    fprintf(stderr, "DEBUG: call64 before write_done - x1 = 0x%lx\n", x1_value);
}

void debug_check_registers_before_write_prep(unsigned long rsp_value, unsigned long xaddr_value) {
    fprintf(stderr, "DEBUG: before write_prep - rsp = 0x%lx, _xaddr = 0x%lx\n", rsp_value, xaddr_value);
}

void debug_check_xaddr_after_sub(unsigned long rsp_value, unsigned long xaddr_value) {
    fprintf(stderr, "DEBUG: after sub - rsp = 0x%lx, _xaddr = 0x%lx\n", rsp_value, xaddr_value);
}

void debug_call64_start(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: call64 START - cpu = 0x%lx\n", cpu_ptr);
}

void debug_call64_end(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: call64 END - cpu = 0x%lx\n", cpu_ptr);
}

void debug_fiber_ret_chain_reached(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: fiber_ret_chain REACHED - cpu = 0x%lx\n", cpu_ptr);
}

void debug_before_stack_write(unsigned long rsp, unsigned long xaddr, unsigned long ret_addr) {
    fprintf(stderr, "DEBUG: before stack write - rsp=0x%lx, _xaddr=0x%lx, ret_addr=0x%lx\n", rsp, xaddr, ret_addr);
}

void debug_write_prep_reached(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: write_prep REACHED - cpu = 0x%lx\n", cpu_ptr);
}

void debug_before_write_prep(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: BEFORE write_prep - cpu = 0x%lx\n", cpu_ptr);
}

void debug_after_write_prep(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: AFTER write_prep - cpu = 0x%lx\n", cpu_ptr);
}

void debug_crosspage_load_reached(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: crosspage_load REACHED - cpu = 0x%lx\n", cpu_ptr);
}

void debug_after_tlb_read_cross_page(unsigned long cpu_ptr) {
    fprintf(stderr, "DEBUG: after __tlb_read_cross_page - cpu = 0x%lx\n", cpu_ptr);
}

void debug_before_c_call(void) {
    fprintf(stderr, "DEBUG: about to call __tlb_read_cross_page\n");
}

// Simple test function to check if C calls work at all in 64-bit mode
bool test_simple_c_function(void) {
    fprintf(stderr, "DEBUG: simple C function called successfully\n");
    return true;
}

// Simple 64-bit compatible crosspage handler
bool simple_64bit_crosspage_read(void *tlb, uint64_t addr, void *value, unsigned size) {
    // For now, just fake success to test 64-bit emulation
    // In a real implementation, this would do proper memory translation
    fprintf(stderr, "DEBUG: simple_64bit_crosspage_read addr=0x%llx size=%u\n", 
            (unsigned long long)addr, size);
    
    // Zero out the value buffer to avoid garbage data
    memset(value, 0, size);
    return true;  // Fake success
}

void debug_print_fiber_ret_chain(unsigned long ip) {
    fprintf(stderr, "DEBUG: fiber_ret_chain - _ip = 0x%lx\n", ip);
    if (ip == 0) {
        fprintf(stderr, "DEBUG: *** NULL _IP DETECTED IN FIBER_RET_CHAIN ***\n");
    }
}

void debug_print_before_gret(unsigned long ip) {
    fprintf(stderr, "DEBUG: before gret - _ip = 0x%lx\n", ip);
}

void debug_print_tlb_access(unsigned long tlb_ptr, unsigned long xaddr) {
    fprintf(stderr, "DEBUG: TLB access - _tlb = 0x%lx, _xaddr = 0x%lx\n", tlb_ptr, xaddr);
    fprintf(stderr, "DEBUG: TLB offset calc - (-32+8) = -24, final addr = 0x%lx\n", tlb_ptr - 24);
}

void debug_print_next_gadget(unsigned long gadget) {
    // fprintf(stderr, "DEBUG: next gadget = 0x%lx\n", gadget);
}

void debug_print_rsp(unsigned long rsp) {
    fprintf(stderr, "DEBUG: call64 gadget - rsp = 0x%lx\n", rsp);
}

void debug_print_xaddr(unsigned long xaddr) {
    fprintf(stderr, "DEBUG: call64 gadget - _xaddr = 0x%lx\n", xaddr);
}

void debug_print_tlb(unsigned long tlb) {
    fprintf(stderr, "DEBUG: call64 gadget - _tlb = 0x%lx\n", tlb);
}

void debug_print_call64_target(unsigned long ip_addr, unsigned long target_addr_ptr, unsigned long target_addr) {
    fprintf(stderr, "DEBUG: call64 - ip=0x%lx, target_ptr=0x%lx, target=0x%lx\n", ip_addr, target_addr_ptr, target_addr);
    if (target_addr == 0) {
        fprintf(stderr, "DEBUG: *** NULL TARGET ADDRESS DETECTED ***\n");
    }
}

void debug_print_call64_ip_before_load(unsigned long ip) {
    fprintf(stderr, "DEBUG: call64 _ip before load = 0x%lx\n", ip);
}

void debug_print_call64_memory_at_ip_40(unsigned long addr, unsigned long value) {
    fprintf(stderr, "DEBUG: call64 memory at 0x%lx = 0x%lx\n", addr, value);
}

void debug_print_call64_target_loaded(unsigned long target_addr) {
    fprintf(stderr, "DEBUG: call64 loaded target = 0x%lx\n", target_addr);
    if (target_addr == 0) {
        fprintf(stderr, "DEBUG: *** NULL TARGET LOADED - WILL CRASH ***\n");
    }
}

void debug_dump_parameter_array(unsigned long *ip) {
    fprintf(stderr, "DEBUG: Parameter array dump (ip = 0x%lx):\n", (unsigned long)ip);
    for (int i = 0; i < 10; i++) {
        fprintf(stderr, "  [%d] offset %d = 0x%lx\n", i, i * 8, ip[i]);
    }
}

void debug_print_tlb_calc(unsigned long xaddr, unsigned long tlb, unsigned long x9) {
    fprintf(stderr, "DEBUG: TLB calc - _xaddr=0x%lx, _tlb=0x%lx, x9=0x%lx\n", xaddr, tlb, x9);
    if (x9 < 0x100000000UL) {
        fprintf(stderr, "DEBUG: *** SUSPICIOUS x9 VALUE - TOO LOW ***\n");
    }
}

void debug_print_gadget_params(unsigned long ip, unsigned long p0, unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4, unsigned long p5) {
    fprintf(stderr, "DEBUG: Gadget params - ip=0x%lx\n", ip);
    fprintf(stderr, "  p0=0x%lx, p1=0x%lx, p2=0x%lx\n", p0, p1, p2);
    fprintf(stderr, "  p3=0x%lx, p4=0x%lx, p5=0x%lx\n", p3, p4, p5);
    fprintf(stderr, "  p6 at [ip+48]=0x%lx\n", *(unsigned long*)(ip + 48));
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
