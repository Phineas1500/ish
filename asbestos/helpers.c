#include <time.h>
#include <stdio.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"

#ifdef ISH_64BIT
// Debug functions disabled for cleaner testing
void debug_print_ip(unsigned long ip) {
    fprintf(stderr, "DEBUG: fiber_enter - _ip = 0x%lx\n", ip);
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
