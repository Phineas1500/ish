#include <time.h>
#include <execinfo.h>
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

// Debug: trace LEA result before storing
void helper_debug_lea(uint64_t result, uint64_t x8_value, uint64_t ip) {
    static int count = 0;
    if (count < 20) {
        count++;
        fprintf(stderr, "DEBUG_LEA[%d]: result=0x%llx x8=0x%llx ip=0x%llx\n",
                count, (unsigned long long)result, (unsigned long long)x8_value, (unsigned long long)ip);
    }
}

// Debug: trace FS segment override
void helper_debug_seg_fs(uint64_t addr_before, uint64_t fs_base, void *cpu) {
    static int count = 0;
    if (count < 10) {
        count++;
        fprintf(stderr, "DEBUG_SEG_FS[%d]: addr=0x%llx fs_base=0x%llx result=0x%llx cpu=%p\n",
                count, (unsigned long long)addr_before, (unsigned long long)fs_base,
                (unsigned long long)(addr_before + fs_base), cpu);
    }
}

// Debug: trace CMP reg, [mem] - called after swap, before actual compare
// reg_value = register value, mem_value = value loaded from memory
void helper_debug_cmp(uint64_t reg_value, uint64_t mem_value) {
    static int count = 0;
    if (count < 30) {
        count++;
        fprintf(stderr, "DEBUG_CMP[%d]: reg=0x%llx (%c) mem=0x%llx (%c)\n",
                count,
                (unsigned long long)reg_value,
                (reg_value >= 0x20 && reg_value < 0x7f) ? (char)reg_value : '?',
                (unsigned long long)mem_value,
                (mem_value >= 0x20 && mem_value < 0x7f) ? (char)mem_value : '?');
    }
}

// Debug: detect jump/return to address 0
void helper_debug_null_jump(uint64_t target_addr, uint64_t from_rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[unknown]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target_addr,
            (unsigned long long)from_rsp);
}

// Debug: NULL in specific gadgets
void helper_debug_null_jmp_indir(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[jmp_indir]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_call_indir(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[call_indir]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_ret(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[ret]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
static uint64_t last_good_rip = 0;
static uint64_t rip_history[16];
static int rip_history_idx = 0;
void helper_debug_trace_rip(uint64_t rip) {
    rip_history[rip_history_idx % 16] = rip;
    rip_history_idx++;
    if (rip != 0) {
        last_good_rip = rip;
    }
}
void helper_debug_print_rip_history(void) {
    fprintf(stderr, "  RIP history (most recent last):\n");
    for (int i = 0; i < 16 && i < rip_history_idx; i++) {
        int idx = (rip_history_idx - 16 + i) % 16;
        if (rip_history_idx >= 16) idx = (idx + 16) % 16;
        fprintf(stderr, "    [%d] 0x%llx\n", i, (unsigned long long)rip_history[idx]);
    }
}
void helper_debug_null_fiber_exit(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[fiber_exit]: target=0x%llx RSP=0x%llx last_good_rip=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp, (unsigned long long)last_good_rip);
    helper_debug_print_rip_history();
}
void helper_debug_null_fiber_ret(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[fiber_ret]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_exit(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[exit_gadget]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_poke(uint64_t target, uint64_t rsp) {
    fprintf(stderr, "DEBUG_NULL_JUMP[poke]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}

// Debug: syscall gadget NULL check
void helper_debug_syscall_null(uint64_t target_addr, uint64_t from_rsp) {
    fprintf(stderr, "DEBUG_SYSCALL_NULL: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target_addr,
            (unsigned long long)from_rsp);
}

// Debug: syscall gadget return value check
void helper_debug_syscall_return(uint64_t tmp_value, uint64_t rip_value) {
    static int count = 0;
    if (count < 5) {
        count++;
        fprintf(stderr, "DEBUG_SYSCALL_RETURN[%d]: _tmp=0x%llx rip=0x%llx\n",
                count, (unsigned long long)tmp_value, (unsigned long long)rip_value);
    }
}

// Debug: segfault handler - show what _ip points to
void helper_debug_segfault(uint64_t ip_ptr, uint64_t ip_contents, uint64_t segfault_addr) {
    fprintf(stderr, "DEBUG_SEGFAULT: _ip=0x%llx [_ip]=0x%llx segfault_addr=0x%llx\n",
            (unsigned long long)ip_ptr,
            (unsigned long long)ip_contents,
            (unsigned long long)segfault_addr);
}

// Debug: TLB miss - show state when TLB miss occurs (disabled)
void helper_debug_tlb_miss(uint64_t ip_ptr, uint64_t ip_contents, uint64_t access_addr) {
    (void)ip_ptr; (void)ip_contents; (void)access_addr;
}

// Debug: REP STOSQ - trace RDI/RCX/df_offset at start (disabled)
void helper_debug_rep_stosq(uint64_t rdi, uint64_t rcx, uint64_t df_offset_x8) {
    (void)rdi; (void)rcx; (void)df_offset_x8;
}

// Debug: REP STOSQ iteration - trace _addr at each iteration (disabled)
void helper_debug_stosq_iter(uint64_t addr, uint64_t remaining) {
    (void)addr; (void)remaining;
}
