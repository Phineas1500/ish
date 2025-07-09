#include <time.h>
#include <stdio.h>
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

void debug_print_call64_target_loaded(unsigned long target_addr) {
    fprintf(stderr, "DEBUG: call64 loaded target = 0x%lx\n", target_addr);
    if (target_addr == 0) {
        fprintf(stderr, "DEBUG: *** NULL TARGET LOADED - WILL CRASH ***\n");
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
