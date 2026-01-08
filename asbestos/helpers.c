#include <time.h>
#include <string.h>
#include <execinfo.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"
#include "kernel/task.h"
#include "kernel/calls.h"
#include "kernel/memory.h"

// Debug output guard: define DEBUG_64BIT_VERBOSE=1 to enable verbose debug output
// By default, debug output is disabled for performance
#ifndef DEBUG_64BIT_VERBOSE
#define DEBUG_64BIT_VERBOSE 0
#endif

#if DEBUG_64BIT_VERBOSE
#define DEBUG_FPRINTF(...) fprintf(__VA_ARGS__)
#else
#define DEBUG_FPRINTF(...) ((void)0)
#endif

// Forward declarations
int helper_get_load8_count(void);

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
        DEBUG_FPRINTF(stderr, "DEBUG_STORE[%d]: value=0x%llx addr=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)addr);
    }
}

void helper_debug_load(uint64_t value, uint64_t addr) {
    static int count = 0;
    if (count < 30) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_LOAD[%d]: value=0x%llx from=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)addr);
    }
}

// Debug: trace all stores to RSI register with IP
void helper_debug_store64_si(uint64_t value) {
    // Keep for link compatibility
    (void)value;
}

void helper_debug_store64_si_with_ip(uint64_t value, uint64_t prev_ip) {
    static int count = 0;
    count++;
    // Only trace if value is the suspicious -128 value
    if (value == 0xffffffffffffff80) {
        DEBUG_FPRINTF(stderr, "STORE64_SI_SUSPICIOUS[%d]: value=0x%llx (signed=%lld) @ ip=0x%llx\n",
                count, (unsigned long long)value, (long long)value,
                (unsigned long long)prev_ip);
    }
}

// Debug: trace sign_extend8 operation
void helper_debug_sign_extend8(uint64_t before) {
    static int count = 0;
    count++;
    // Only trace if it's going to produce 0xffffffffffffff80
    uint8_t byte = before & 0xFF;
    int8_t signed_byte = (int8_t)byte;
    if (signed_byte == -128) {
        DEBUG_FPRINTF(stderr, "SIGN_EXTEND8[%d]: before=0x%llx byte=0x%02x -> will produce 0xffffffffffffff80\n",
                count, (unsigned long long)before, byte);
    }
}

// Debug: trace load64_imm when value is the suspicious one
void helper_debug_load64_imm_suspicious(uint64_t value) {
    if (value == 0xffffffffffffff80) {
        DEBUG_FPRINTF(stderr, "LOAD64_IMM_SUSPICIOUS: value=0x%llx (-128)\n",
                (unsigned long long)value);
    }
}

// Debug: trace load64_mem when value is the suspicious one
void helper_debug_load64_mem_suspicious(uint64_t value, uint64_t guest_addr) {
    if (value == 0xffffffffffffff80) {
        DEBUG_FPRINTF(stderr, "LOAD64_MEM_SUSPICIOUS: value=0x%llx from guest_addr=0x%llx\n",
                (unsigned long long)value, (unsigned long long)guest_addr);
    }
    // Also trace loads that return 0x7f0000000... addresses (path corruption)
    if ((value >> 36) == 0x7f0 && (value & 0xffffff) != 0) {
        static int count = 0;
        count++;
        if (count <= 10) {
            DEBUG_FPRINTF(stderr, "LOAD64_7F: loaded 0x%llx from guest 0x%llx\n",
                    (unsigned long long)value, (unsigned long long)guest_addr);
        }
    }
}

// Debug: trace load64 from register when value is suspicious
void helper_debug_load64_reg_suspicious(uint64_t value, const char *reg_name) {
    DEBUG_FPRINTF(stderr, "LOAD64_REG_SUSPICIOUS: reg=%s value=0x%llx (-128)\n",
            reg_name, (unsigned long long)value);
}

// Debug: trace store64 to RDX when value is suspicious
void helper_debug_store64_rdx_suspicious(uint64_t value) {
    DEBUG_FPRINTF(stderr, "STORE64_RDX_SUSPICIOUS: value=0x%llx (-128) -- THIS IS THE SOURCE!\n",
            (unsigned long long)value);
}

// Debug: trace sign_extend32 operation
void helper_debug_sign_extend32(uint64_t before) {
    uint32_t word = before & 0xFFFFFFFF;
    int32_t signed_word = (int32_t)word;
    int64_t extended = (int64_t)signed_word;
    // Trace all for debugging printf issue
    static int count = 0;
    count++;
    if (count <= 30) {
        DEBUG_FPRINTF(stderr, "SIGN_EXTEND32[%d]: before=0x%llx word=0x%08x -> 0x%llx\n",
                count, (unsigned long long)before, word, (unsigned long long)extended);
    }
}

#ifdef ISH_GUEST_64BIT
void helper_debug_add_r9(uint64_t xtmp, uint64_t x8, struct cpu_state *cpu) {
    static int count = 0;
    if (count < 10) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_ADD_R9[%d]: xtmp=0x%llx x8=0x%llx cpu_r9=0x%llx\n",
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
        DEBUG_FPRINTF(stderr, "DEBUG_RDX[%d]: x23=0x%llx xtmp=0x%llx\n",
                count, (unsigned long long)rdx_value, (unsigned long long)xtmp_value);
    }
}

// Debug: trace save_xtmp_to_x8 - called AFTER the save
void helper_debug_save_x8(uint64_t x8_value, uint64_t xtmp_value) {
    static int count = 0;
    if (count < 10) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_SAVE_X8[%d]: x8=0x%llx xtmp=0x%llx\n",
                count, (unsigned long long)x8_value, (unsigned long long)xtmp_value);
    }
}

// Debug: trace LEA result before storing
void helper_debug_lea(uint64_t result, uint64_t x8_value, uint64_t ip) {
    static int count = 0;
    if (count < 20) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_LEA[%d]: result=0x%llx x8=0x%llx ip=0x%llx\n",
                count, (unsigned long long)result, (unsigned long long)x8_value, (unsigned long long)ip);
    }
}

// Debug: trace FS segment override
void helper_debug_seg_fs(uint64_t addr_before, uint64_t fs_base, void *cpu) {
    static int count = 0;
    if (count < 10) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_SEG_FS[%d]: addr=0x%llx fs_base=0x%llx result=0x%llx cpu=%p\n",
                count, (unsigned long long)addr_before, (unsigned long long)fs_base,
                (unsigned long long)(addr_before + fs_base), cpu);
    }
}

// Debug: trace CMP reg, [mem] - called after swap, before actual compare
// Now: mem_value = _xtmp, reg_value = x8 (after swap)
void helper_debug_cmp(uint64_t mem_value, uint64_t reg_value) {
    // Disabled for now
    (void)mem_value; (void)reg_value;
}

// Debug: trace MOV to r12
void helper_debug_mov_r12(uint64_t value) {
    static int count = 0;
    count++;
    DEBUG_FPRINTF(stderr, "MOV_R12[%d]: value=0x%llx\n", count, (unsigned long long)value);
}

// Debug: detect jump/return to address 0
void helper_debug_null_jump(uint64_t target_addr, uint64_t from_rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[unknown]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target_addr,
            (unsigned long long)from_rsp);
}

// Debug: NULL in specific gadgets
void helper_debug_null_jmp_indir(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[jmp_indir]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_call_indir(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[call_indir]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
static int call_indir_entry_count = 0;
void helper_debug_call_indir_entry(uint64_t target, uint64_t rsp) {
    extern int fiber_exit_count;
    call_indir_entry_count++;
    // Trace during problem time (fiber_exit >= 37020)
    if (fiber_exit_count >= 37020) {
        fprintf(stderr, "CALL_INDIR_ENTRY[%d]: target=0x%llx rsp=0x%llx fiber_exit=%d\n",
                call_indir_entry_count, (unsigned long long)target,
                (unsigned long long)rsp, fiber_exit_count);
    }
}

static int crosspage_store_count = 0;
void helper_debug_crosspage_store(uint64_t guest_addr, uint64_t size) {
    extern int fiber_exit_count;
    crosspage_store_count++;
    if (crosspage_store_count <= 50 || fiber_exit_count >= 37020) {
        fprintf(stderr, "CROSSPAGE_STORE[%d]: addr=0x%llx size=%llu fiber_exit=%d\n",
                crosspage_store_count, (unsigned long long)guest_addr,
                (unsigned long long)size, fiber_exit_count);
    }
}

static int call_indir_after_restore_count = 0;
void helper_debug_call_indir_after_restore(uint64_t target) {
    extern int fiber_exit_count;
    call_indir_after_restore_count++;
    if (fiber_exit_count >= 37020) {
        fprintf(stderr, "CALL_INDIR_AFTER_RESTORE[%d]: target=0x%llx fiber_exit=%d\n",
                call_indir_after_restore_count, (unsigned long long)target, fiber_exit_count);
    }
}

static int call_indir_exit_count = 0;
void helper_debug_call_indir_exit(uint64_t target) {
    extern int fiber_exit_count;
    call_indir_exit_count++;
    if (fiber_exit_count >= 37020) {
        fprintf(stderr, "CALL_INDIR_EXIT[%d]: target=0x%llx fiber_exit=%d\n",
                call_indir_exit_count, (unsigned long long)target, fiber_exit_count);
    }
}
void helper_debug_null_ret(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[ret]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
static uint64_t last_good_rip = 0;
static uint64_t rip_history[16];
static int rip_history_idx = 0;
int fiber_exit_count = 0;  // Not static - referenced from other functions
void helper_debug_trace_rip(uint64_t rip) {
    fiber_exit_count++;
    rip_history[rip_history_idx % 16] = rip;
    rip_history_idx++;
    if (rip != 0) {
        last_good_rip = rip;
    }
    // Trace fiber exits after call 1476 (fiber_exit=37024)
    if (fiber_exit_count >= 37020) {
        fprintf(stderr, "FIBER_EXIT[%d]: rip=0x%llx\n", fiber_exit_count, (unsigned long long)rip);
    }
}
void helper_debug_print_rip_history(void) {
    DEBUG_FPRINTF(stderr, "  RIP history (most recent last):\n");
    for (int i = 0; i < 16 && i < rip_history_idx; i++) {
        int idx = (rip_history_idx - 16 + i) % 16;
        if (rip_history_idx >= 16) idx = (idx + 16) % 16;
        DEBUG_FPRINTF(stderr, "    [%d] 0x%llx\n", i, (unsigned long long)rip_history[idx]);
    }
}
void helper_debug_null_fiber_exit(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[fiber_exit]: target=0x%llx RSP=0x%llx last_good_rip=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp, (unsigned long long)last_good_rip);
    helper_debug_print_rip_history();
}
void helper_debug_null_fiber_ret(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[fiber_ret]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_exit(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[exit_gadget]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}
void helper_debug_null_poke(uint64_t target, uint64_t rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_NULL_JUMP[poke]: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target, (unsigned long long)rsp);
}

// Debug: syscall gadget NULL check
void helper_debug_syscall_null(uint64_t target_addr, uint64_t from_rsp) {
    DEBUG_FPRINTF(stderr, "DEBUG_SYSCALL_NULL: target=0x%llx RSP=0x%llx\n",
            (unsigned long long)target_addr,
            (unsigned long long)from_rsp);
}

// Debug: syscall gadget return value check
void helper_debug_syscall_return(uint64_t tmp_value, uint64_t rip_value) {
    static int count = 0;
    if (count < 5) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_SYSCALL_RETURN[%d]: _tmp=0x%llx rip=0x%llx\n",
                count, (unsigned long long)tmp_value, (unsigned long long)rip_value);
    }
}

// Debug: segfault handler - show what _ip points to
void helper_debug_segfault(uint64_t ip_ptr, uint64_t ip_contents, uint64_t segfault_addr) {
    DEBUG_FPRINTF(stderr, "DEBUG_SEGFAULT: _ip=0x%llx [_ip]=0x%llx segfault_addr=0x%llx\n",
            (unsigned long long)ip_ptr,
            (unsigned long long)ip_contents,
            (unsigned long long)segfault_addr);
}

// Debug: TLB miss - show state when TLB miss occurs
static int tlb_miss_count = 0;
void helper_debug_tlb_miss(uint64_t ip_ptr, uint64_t ip_contents, uint64_t access_addr) {
    extern int fiber_exit_count;
    tlb_miss_count++;
    // Trace TLB misses during problem time
    if (fiber_exit_count >= 37020) {
        fprintf(stderr, "TLB_MISS[%d]: addr=0x%llx fiber_exit=%d ip_ptr=0x%llx\n",
                tlb_miss_count, (unsigned long long)access_addr, fiber_exit_count,
                (unsigned long long)ip_ptr);
    }
}

// Debug: trace load64_mem in crash region
void helper_debug_load64_crash_region(uint64_t guest_addr) {
    DEBUG_FPRINTF(stderr, "LOAD64_CRASH_REGION: guest_addr=0x%llx\n",
            (unsigned long long)guest_addr);
    fflush(stderr);
}

// Debug: trace host addr after TLB translation
static int load64_host_count = 0;
void helper_debug_load64_host_addr(uint64_t guest_addr, uint64_t host_addr) {
    load64_host_count++;
    DEBUG_FPRINTF(stderr, "LOAD64_HOST[%d]: guest=0x%llx -> host=0x%llx\n",
            load64_host_count, (unsigned long long)guest_addr, (unsigned long long)host_addr);
    fflush(stderr);
}

// Debug: trace right after first restore_c
void helper_debug_after_restore(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "AFTER_RESTORE: addr=0x%llx\n", (unsigned long long)addr);
    fflush(stderr);
}

// Debug: trace before second save_c
void helper_debug_before_save2(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "BEFORE_SAVE2: addr=0x%llx\n", (unsigned long long)addr);
    fflush(stderr);
}

// Debug: trace at label 98: before final save_c
void helper_debug_at_98(uint64_t sp_val) {
    DEBUG_FPRINTF(stderr, "AT_98: sp=0x%llx\n", (unsigned long long)sp_val);
    fflush(stderr);
}

// Debug: trace after AT_98's restore_c
void helper_debug_after_at98(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "AFTER_AT98: addr=0x%llx\n", (unsigned long long)addr);
    fflush(stderr);
}

// Debug: trace right before final load call
void helper_debug_before_load(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "BEFORE_LOAD: addr=0x%llx\n", (unsigned long long)addr);
    fflush(stderr);
}

// Debug: trace sp after restore_c
void helper_debug_sp_after_restore(uint64_t sp) {
    DEBUG_FPRINTF(stderr, "SP_AFTER: sp=0x%llx\n", (unsigned long long)sp);
    fflush(stderr);
}

// Debug: called IMMEDIATELY before the ARM64 ldr instruction
// Attempts to read from addr to verify it's accessible from C
// Returns the loaded value so we can bypass the ARM64 ldr
uint64_t helper_debug_pre_ldr(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "PRE_LDR: addr=0x%llx\n", (unsigned long long)addr);
    // Try to read from this address in C - if it crashes here, address is bad
    volatile uint64_t *ptr = (volatile uint64_t *)addr;
    uint64_t val = *ptr;
    DEBUG_FPRINTF(stderr, "PRE_LDR: read 0x%llx from 0x%llx - SUCCESS\n",
            (unsigned long long)val, (unsigned long long)addr);
    return val;
}

// Debug: show _addr after restore_c
void helper_debug_post_restore(uint64_t addr) {
    DEBUG_FPRINTF(stderr, "POST_RESTORE: addr=0x%llx\n", (unsigned long long)addr);
}

// Debug: confirm bypass path was taken
void helper_debug_bypass_done(uint64_t value) {
    DEBUG_FPRINTF(stderr, "BYPASS_DONE: got value=0x%llx, continuing...\n", (unsigned long long)value);
}

// Debug: trace load64_mem entry BEFORE TLB
static int load64_entry_count = 0;
void helper_debug_load64_mem_entry(uint64_t guest_addr, uint64_t rip) {
    load64_entry_count++;
    // Only trace the last 10 entries before crash
    if (load64_entry_count > 11140) {
        DEBUG_FPRINTF(stderr, "LOAD64_MEM_ENTRY[%d]: guest_addr=0x%llx rip=0x%llx\n",
                load64_entry_count, (unsigned long long)guest_addr, (unsigned long long)rip);
        fflush(stderr);
    }
}

// Bypass ALL 64-bit loads via C
static int load64_count = 0;
uint64_t helper_load64_via_c(uint64_t host_addr) {
    volatile uint64_t *ptr = (volatile uint64_t *)host_addr;
    uint64_t val = *ptr;
    load64_count++;
    // Trace every load
    DEBUG_FPRINTF(stderr, "LOAD64[%d]: host=0x%llx val=0x%llx\n",
            load64_count, (unsigned long long)host_addr, (unsigned long long)val);
    fflush(stderr);
    return val;
}

// Bypass ALL 64-bit stores via C
static int store64_count = 0;
// Forward declaration for watchpoint check
void helper_check_watchpoint_store64(uint64_t value, uint64_t host_addr);

void helper_store64_via_c(uint64_t host_addr, uint64_t value) {
    // Check watchpoint before store
    helper_check_watchpoint_store64(value, host_addr);
    volatile uint64_t *ptr = (volatile uint64_t *)host_addr;
    *ptr = value;
    store64_count++;
    // Trace disabled - too noisy
    (void)store64_count;
}

// Debug: trace stores to crash page (before TLB)
void helper_debug_store64_crash_page(uint64_t guest_addr, uint64_t value) {
    DEBUG_FPRINTF(stderr, "STORE64_CRASH_PAGE: guest=0x%llx value=0x%llx\n",
            (unsigned long long)guest_addr, (unsigned long long)value);
}

// Debug: trace stores to crash page (after TLB, and do the store in C)
void helper_debug_store64_crash_page_host(uint64_t host_addr, uint64_t value) {
    DEBUG_FPRINTF(stderr, "STORE64_CRASH_PAGE_HOST: host=0x%llx value=0x%llx\n",
            (unsigned long long)host_addr, (unsigned long long)value);
    // Do the store in C
    volatile uint64_t *ptr = (volatile uint64_t *)host_addr;
    *ptr = value;
    DEBUG_FPRINTF(stderr, "STORE64_CRASH_PAGE_HOST: store completed OK\n");
}

// Debug: trace stores to r12
void helper_debug_store_r12(uint64_t new_value, uint64_t rbx_value, uint64_t r15_value) {
    static int count = 0;
    count++;
    DEBUG_FPRINTF(stderr, "STORE_R12[%d]: new=0x%llx rbx=0x%llx r15=0x%llx\n",
            count, (unsigned long long)new_value, (unsigned long long)rbx_value,
            (unsigned long long)r15_value);
}

// Debug: trace CALL arguments - called before CALL
static int g_call_count = 0;
// Helper to read a few bytes from guest memory (safe version without locks)
static void read_guest_string_safe(uint64_t addr, char *buf, size_t maxlen) {
    if (current && current->mem) {
        // Use mem_ptr with read lock already held
        void *ptr = mem_ptr(current->mem, addr, MEM_READ);
        if (ptr) {
            strncpy(buf, (char *)ptr, maxlen - 1);
            buf[maxlen - 1] = '\0';
        } else {
            snprintf(buf, maxlen, "(unmapped:%llx)", (unsigned long long)addr);
        }
    } else {
        snprintf(buf, maxlen, "(no-mem)");
    }
}

void helper_debug_call(uint64_t target, uint64_t rdi, uint64_t rsi, uint64_t ret_addr,
                       uint64_t rdx, uint64_t rcx) {
    g_call_count++;
    // Strip the fake_ip flag bit
    uint64_t real_target = target & 0x7FFFFFFFFFFFFFFF;

    // Trace busybox string parsing wrapper at 0xa02d (runtime 0x55555555e02d)
    // This is bb_strtoull_or_warn/strtol wrapper - rdi=string to parse, rdx=base
    if (real_target == 0x55555555e02d) {
        char str[64] = {0};
        read_guest_string_safe(rdi, str, sizeof(str));
        fprintf(stderr, "BB_STRTOL: rdi(str)=0x%llx=\"%s\" rsi(endptr)=0x%llx rdx(base)=%llu\n",
                (unsigned long long)rdi, str, (unsigned long long)rsi, (unsigned long long)rdx);
    }

    // Debug: trace all CALLs to busybox code (0x555555554000 - 0x555555700000)
    if (real_target >= 0x555555554000 && real_target < 0x555555700000) {
        static int bb_call_count = 0;
        bb_call_count++;
        if (bb_call_count <= 50) {
            fprintf(stderr, "BB_CALL[%d]: target=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx\n",
                    bb_call_count, (unsigned long long)real_target,
                    (unsigned long long)rdi, (unsigned long long)rsi, (unsigned long long)rdx);
        }
        // Trace the bb_error_msg call (target 0x55555555bb8c) - shows the invalid string
        if (real_target == 0x55555555bb8c) {
            char str[64] = {0};
            read_guest_string_safe(rsi, str, sizeof(str));
            fprintf(stderr, "BB_ERROR_MSG: format=0x%llx arg=\"%s\"\n",
                    (unsigned long long)rdi, str);
        }
        // Trace the duration parser at 0x5555555e6127 (file addr 0x92127)
        // rdi = buffer to store result, rsi = format/string to parse
        if (real_target == 0x5555555e6127) {
            char str[64] = {0};
            read_guest_string_safe(rsi, str, sizeof(str));
            fprintf(stderr, "BB_DURATION_PARSE: buf=0x%llx str=0x%llx=\"%s\" rdx=0x%llx\n",
                    (unsigned long long)rdi, (unsigned long long)rsi, str, (unsigned long long)rdx);
        }
        // Trace function at 0x5555555f1338 (file addr 0x9d338)
        if (real_target == 0x5555555f1338) {
            char str[64] = {0};
            read_guest_string_safe(rsi, str, sizeof(str));
            fprintf(stderr, "BB_FUNC_9d338: rdi=0x%llx rsi=0x%llx=\"%s\" rdx=0x%llx\n",
                    (unsigned long long)rdi, (unsigned long long)rsi, str, (unsigned long long)rdx);
        }
        // Trace sleep_main at 0x5555555cdb31 (file addr 0x79b31)
        // rdi = argc, rsi = argv pointer
        if (real_target == 0x5555555cdb31) {
            // Read argv pointers
            char arg0[64] = {0}, arg1[64] = {0};
            uint64_t argv_ptr[4] = {0};
            void *argv_mem = mem_ptr(current->mem, rsi, MEM_READ);
            if (argv_mem) {
                memcpy(argv_ptr, argv_mem, sizeof(argv_ptr));
            }
            read_guest_string_safe(argv_ptr[0], arg0, sizeof(arg0));
            read_guest_string_safe(argv_ptr[1], arg1, sizeof(arg1));
            fprintf(stderr, "SLEEP_MAIN: argc=%llu argv=0x%llx [0]=0x%llx=\"%s\" [1]=0x%llx=\"%s\"\n",
                    (unsigned long long)rdi, (unsigned long long)rsi,
                    (unsigned long long)argv_ptr[0], arg0,
                    (unsigned long long)argv_ptr[1], arg1);
        }
    }

    // After sleep_main is called, trace ALL calls (not just to busybox) to see what happens
    static int after_sleep_main = 0;
    if (real_target == 0x5555555cdb31) {
        after_sleep_main = 1;
        fprintf(stderr, "DEBUG: Set after_sleep_main=1 for sleep_main\n");
    }
    if (after_sleep_main > 0 && after_sleep_main <= 30) {
        fprintf(stderr, "CALL_AFTER_SLEEP[%d]: target=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx\n",
                after_sleep_main, (unsigned long long)real_target,
                (unsigned long long)rdi, (unsigned long long)rsi, (unsigned long long)rdx);
        after_sleep_main++;
    }

    // Minimal tracing - removed user_read calls that caused hangs

    // Trace calls where rdi (buffer) is 0x7f0000000xxx (heap)
    // This catches memcpy, strcpy, vsnprintf with heap destination
    if ((rdi >> 36) == 0x7f0) {
        static int heap_call_count = 0;
        heap_call_count++;
        if (heap_call_count <= 20) {
            DEBUG_FPRINTF(stderr, "CALL_HEAP_DST[%d]: target=0x%llx rdi=0x%llx rsi=0x%llx ret=0x%llx\n",
                    heap_call_count, (unsigned long long)real_target,
                    (unsigned long long)rdi, (unsigned long long)rsi,
                    (unsigned long long)ret_addr);
        }
    }

    // Trace calls to vsnprintf (musl offset 0x57390)
    // Runtime address = 0x7efffff5e000 + 0x57390 = 0x7efffffb5390
    // vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
    //   rdi=buf, rsi=n, rdx=fmt, rcx=va_list_ptr (GUEST address)
    // NOTE: user_read calls removed - they can cause deadlock when called from gadget context
    if (real_target == 0x7efffffb5390) {
        DEBUG_FPRINTF(stderr, "CALL_VSNPRINTF: buf=0x%llx size=%llu fmt=0x%llx va_list=0x%llx ret=0x%llx\n",
                (unsigned long long)rdi, (unsigned long long)rsi,
                (unsigned long long)rdx, (unsigned long long)rcx,
                (unsigned long long)ret_addr);
    }

    // Trace calls to vasprintf (musl offset 0x529ae)
    // Runtime address = 0x7efffff5e000 + 0x529ae = 0x7efffffb09ae
    // NOTE: user_read calls removed - they can cause deadlock when called from gadget context
    if (real_target == 0x7efffffb09ae) {
        DEBUG_FPRINTF(stderr, "CALL_VASPRINTF: rdi(outptr)=0x%llx rsi(fmt)=0x%llx rdx(va_list)=0x%llx ret=0x%llx\n",
                (unsigned long long)rdi, (unsigned long long)rsi, (unsigned long long)rdx,
                (unsigned long long)ret_addr);
    }

    // Trace calls to malloc (musl offset 0x14010)
    // Runtime address = 0x7efffff5e000 + 0x14010 = 0x7efffff72010
    if (real_target == 0x7efffff72010) {
        DEBUG_FPRINTF(stderr, "CALL_MALLOC: rdi(size)=%llu ret=0x%llx\n",
                (unsigned long long)rdi, (unsigned long long)ret_addr);
    }

    // Trace calls to sn_write (musl offset 0x572f0)
    // Runtime address = 0x7efffff5e000 + 0x572f0 = 0x7efffffb52f0
    // sn_write(FILE *f, const unsigned char *s, size_t l)
    //   rdi=FILE, rsi=source buffer, rdx=length to write
    // NOTE: user_read calls removed - they can cause deadlock when called from gadget context
    if (real_target == 0x7efffffb52f0) {
        DEBUG_FPRINTF(stderr, "CALL_SN_WRITE: file=0x%llx src=0x%llx len=%llu ret=0x%llx\n",
                (unsigned long long)rdi, (unsigned long long)rsi,
                (unsigned long long)rdx, (unsigned long long)ret_addr);
    }

    // Trace calls to out() function (musl offset 0x50c9b)
    // Runtime address = 0x7efffff5e000 + 0x50c9b = 0x7efffffaec9b
    // out(const char *s, size_t l, FILE *f) - note: different argument order!
    // NOTE: user_read calls removed - they can cause deadlock when called from gadget context
    if (real_target == 0x7efffffaec9b) {
        DEBUG_FPRINTF(stderr, "CALL_OUT: src=0x%llx len=%llu file=0x%llx ret=0x%llx\n",
                (unsigned long long)rdi, (unsigned long long)rsi,
                (unsigned long long)rdx, (unsigned long long)ret_addr);
    }

    // Trace calls to printf_core (musl offset 0x53c36)
    // Runtime: 0x7efffff5e000 + 0x53c36 = 0x7efffffb1c36
    // printf_core(FILE *f, const char *fmt, va_list *ap, union arg *nl_arg, int *nl_type)
    if (real_target == 0x7efffffb1c36) {
        static int pc_count = 0;
        pc_count++;
        DEBUG_FPRINTF(stderr, "CALL_PRINTF_CORE[%d]: FILE=0x%llx fmt=0x%llx va=0x%llx nl_arg=0x%llx\n",
                pc_count,
                (unsigned long long)rdi, (unsigned long long)rsi,
                (unsigned long long)rdx, (unsigned long long)rcx);
    }

    // Removed strtod/bb_* traces that used user_read (caused hangs)
}

// Debug: trace RET return value (RAX) after specific calls
static int g_ret_count = 0;
void helper_debug_ret(uint64_t rax, uint64_t ret_to) {
    g_ret_count++;

    // Unconditionally trace all returns in the range of interest
    if (ret_to >= 0x55555555b950 && ret_to <= 0x55555555bc00) {
        fprintf(stderr, "RET[%d]: rax=0x%llx -> 0x%llx\n",
                g_ret_count, (unsigned long long)rax, (unsigned long long)ret_to);
    }
    // Also trace all returns after 1460
    if (g_ret_count >= 1460) {
        fprintf(stderr, "RET_ALL[%d]: rax=0x%llx -> 0x%llx\n",
                g_ret_count, (unsigned long long)rax, (unsigned long long)ret_to);
    }

    // Trace returns FROM vsnprintf (ret_to is inside vasprintf)
    // vasprintf calls vsnprintf at 0x529df and 0x52a09 (offsets relative to musl base)
    // Runtime: 0x7efffff5e000 + 0x529df = 0x7efffffb09df
    //          0x7efffff5e000 + 0x52a09 = 0x7efffffb0a09
    if (ret_to == 0x7efffffb09e4 || ret_to == 0x7efffffb0a0e) {
        DEBUG_FPRINTF(stderr, "RET_VSNPRINTF: rax=%lld (length) ret_to=0x%llx\n",
                (long long)rax, (unsigned long long)ret_to);
    }

    // Trace returns FROM printf_core
    // First call (measuring): returns to 0x7efffff5e000 + 0x54978 = 0x7efffffb2978
    // Second call (actual): returns to 0x7efffff5e000 + 0x54a0b = 0x7efffffb2a0b
    if (ret_to == 0x7efffffb2978) {
        DEBUG_FPRINTF(stderr, "RET_PRINTF_CORE_1ST: rax=%lld (measuring pass) ret_to=0x%llx\n",
                (long long)rax, (unsigned long long)ret_to);
    }
    if (ret_to == 0x7efffffb2a0b) {
        DEBUG_FPRINTF(stderr, "RET_PRINTF_CORE_2ND: rax=%lld (actual output) ret_to=0x%llx\n",
                (long long)rax, (unsigned long long)ret_to);
    }

    // Check for key addresses (old traces)
    else if (ret_to == 0x55555555b11a || ret_to == 0x55555555b46d) {
        DEBUG_FPRINTF(stderr, "RET_STRCMP_KEY[%d]: rax=%lld (0x%llx) ret_to=0x%llx - should be non-zero for \"/\" vs \"--help\"\n",
                g_ret_count, (long long)(int)rax, (unsigned long long)rax, (unsigned long long)ret_to);
    }
}

// Debug: trace 32-bit memory loads from optind address (0x55555561a068)
// optind is at busybox+0xc6068, loaded by getopt32 to check remaining args
void helper_debug_load32_optind(uint64_t guest_addr, uint32_t value) {
    // optind is at 0x55555561a068
    if (guest_addr == 0x55555561a068) {
        DEBUG_FPRINTF(stderr, "LOAD32_OPTIND: addr=0x%llx value=%u (optind)\n",
                (unsigned long long)guest_addr, value);
    }
}

// Debug: trace CALL_INDIR arguments - rdx included
void helper_debug_call_indir(uint64_t target, uint64_t rdi, uint64_t rsi, uint64_t rdx) {
    static int count = 0;
    if (count < 500) {
        count++;
        // Only show if rsi or rdx is 0x61 ('a') or 0x62 ('b')
        if (rsi == 0x61 || rsi == 0x62 || rdx == 0x61 || rdx == 0x62) {
            DEBUG_FPRINTF(stderr, "CALL_INDIR[%d]: target=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx\n",
                    count, (unsigned long long)target, (unsigned long long)rdi,
                    (unsigned long long)rsi, (unsigned long long)rdx);
        }
    }
}

// Debug: trace RDI value when storing to r12=0
#ifdef ISH_GUEST_64BIT
void helper_debug_rbx_rdi(struct cpu_state *cpu) {
    DEBUG_FPRINTF(stderr, "DEBUG: rbx=0x%llx rdi=0x%llx rsi=0x%llx\n",
            (unsigned long long)cpu->rbx, (unsigned long long)cpu->rdi,
            (unsigned long long)cpu->rsi);
}
#endif

// Debug: REP STOSQ - trace RDI/RCX/df_offset at start
void helper_debug_rep_stosq(uint64_t rdi, uint64_t rcx, int64_t df_offset) {
    static int count = 0;
    if (count < 5) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_REP_STOSQ[%d]: rdi=0x%llx rcx=0x%llx df_offset=0x%llx (%lld)\n",
                count, (unsigned long long)rdi, (unsigned long long)rcx,
                (unsigned long long)df_offset, (long long)df_offset);
    }
}

// Debug: REP STOSQ iteration - trace _addr at each iteration (disabled)
void helper_debug_stosq_iter(uint64_t addr, uint64_t remaining) {
    (void)addr; (void)remaining;
}

// Debug: CMOVNE - trace before cmov decision
void helper_debug_cmovne(uint64_t xtmp_src, uint64_t x8_dst, uint64_t cpu_res, uint64_t flags_res) {
    static int count = 0;
    if (count < 30) {
        count++;
        DEBUG_FPRINTF(stderr, "DEBUG_CMOVNE[%d]: src=0x%llx dst=0x%llx res=0x%llx flags_res=0x%llx\n",
                count, (unsigned long long)xtmp_src, (unsigned long long)x8_dst,
                (unsigned long long)cpu_res, (unsigned long long)flags_res);
    }
}

// Debug: CMOVGE (cmovn_sxo) - trace before cmov decision
void helper_debug_cmovge(uint64_t xtmp_src, uint64_t x8_dst, uint64_t cpu_res, uint64_t of) {
    static int count = 0;
    count++;
    int load8 = helper_get_load8_count();
    // Disabled - too verbose
    (void)count; (void)load8; (void)xtmp_src; (void)x8_dst; (void)cpu_res; (void)of;
}

// Debug: CMOVL (cmov_sxo) - trace before cmov decision in printf_core range
// src = r8 (string length), dst = r11 (original value from r13)
// res = result of CMP r13, r8 = r13 - r8
// L condition: SF != OF (r13 < r8 signed)
void helper_debug_cmovl(uint64_t xtmp_src, uint64_t x8_dst, uint64_t cpu_res, uint64_t of) {
    static int count = 0;
    count++;
    // Calculate SF from res
    int sf = ((int64_t)cpu_res < 0) ? 1 : 0;
    int l_cond = (sf != of);  // L condition: SF != OF

    // Always print - we need to see this
    DEBUG_FPRINTF(stderr, "CMOVL[%d]: src(r8)=%lld dst(r11)=%lld res=%lld SF=%d OF=%llu L=%d -> %s\n",
            count, (long long)(int32_t)xtmp_src, (long long)(int32_t)x8_dst,
            (long long)(int32_t)cpu_res, sf, (unsigned long long)of, l_cond,
            l_cond ? "MOVE(keep src)" : "SKIP(keep dst)");
}

// Debug: r9 corruption detection
void helper_debug_r9_corrupt(uint64_t value, uint64_t ip) {
    DEBUG_FPRINTF(stderr, "R9_CORRUPT: value=0x%llx at ip=0x%llx\n",
            (unsigned long long)value, (unsigned long long)ip);
}

// Debug: rdi corruption detection
void helper_debug_rdi_corrupt(uint64_t value, uint64_t ip) {
    DEBUG_FPRINTF(stderr, "RDI_CORRUPT: value=0x%llx at ip=0x%llx\n",
            (unsigned long long)value, (unsigned long long)ip);
}

// Debug: load64 corruption detection
void helper_debug_load64_corrupt(uint64_t value, uint64_t ip, uint64_t addr) {
    DEBUG_FPRINTF(stderr, "LOAD64_CORRUPT: value=0x%llx at ip=0x%llx from addr=0x%llx\n",
            (unsigned long long)value, (unsigned long long)ip, (unsigned long long)addr);
}

// Debug: trace loads from argv area
void helper_debug_argv_load(uint64_t value, uint64_t addr) {
    static int count = 0;
    if (count < 20) {
        count++;
        // Print value as string if possible
        char str[9] = {0};
        memcpy(str, &value, 8);
        DEBUG_FPRINTF(stderr, "ARGV_LOAD64[%d]: addr=0x%llx value=0x%llx str='%s'\n",
                count, (unsigned long long)addr, (unsigned long long)value, str);
    }
}

// Debug: trace byte loads from argv area
void helper_debug_byte_load(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Trace byte loads to see what's being compared
    // Look for loads that might be optstring[0] comparisons
    if (count < 200) {
        char c = (value >= 32 && value < 127) ? (char)value : '.';
        DEBUG_FPRINTF(stderr, "BYTE[%d]: addr=0x%llx value=0x%02llx '%c'\n",
                count, (unsigned long long)addr, (unsigned long long)value, c);
    }
}

// Debug: trace 64-bit stores to stack
void helper_debug_store64(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Show only stores of 'a' (0x61) or 'b' (0x62)
    if (value == 0x61 || value == 0x62) {
        DEBUG_FPRINTF(stderr, "STORE64_AB[%d]: addr=0x%llx value=0x%llx ('%c')\n",
                count, (unsigned long long)addr, (unsigned long long)value, (char)value);
    }
}

// Ring buffer to track recent 32-bit loads
#define LOAD_RING_SIZE 32
static struct {
    uint64_t addr;
    uint32_t value;
} load_ring[LOAD_RING_SIZE];
static int load_ring_idx = 0;

static int g_load32_global_count = 0;

// Track ALL 32-bit memory loads for debugging
void helper_track_load32(uint32_t value, uint64_t addr) {
    load_ring[load_ring_idx].addr = addr;
    load_ring[load_ring_idx].value = value;
    load_ring_idx = (load_ring_idx + 1) % LOAD_RING_SIZE;
    g_load32_global_count++;

    // Trace ALL loads around seq 5700-5740 (near the STORE_R15 and STORE_R13)
    if (g_load32_global_count >= 5700 && g_load32_global_count <= 5740) {
        DEBUG_FPRINTF(stderr, "LOAD32[seq=%d]: addr=0x%llx value=%u (0x%x)\n",
                g_load32_global_count, (unsigned long long)addr, value, value);
    }
}

int helper_get_load32_count(void) { return g_load32_global_count; }

// Debug: trace optind loads
void helper_debug_optind_load(uint32_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Identify which variable based on address
    // optarg:   0x55555561a040
    // opterr:   0x55555561a048
    // __environ: 0x55555561a060
    // optind:   0x55555561a068
    const char *name = "???";
    if ((addr & 0xfff) == 0x040) name = "optarg";
    else if ((addr & 0xfff) == 0x048) name = "opterr";
    else if ((addr & 0xfff) == 0x060) name = "__environ";
    else if ((addr & 0xfff) == 0x068) name = "optind";
    else if ((addr & 0xfff) == 0x06c) name = "optopt";  // adjacent to optind
    DEBUG_FPRINTF(stderr, "OPT_LOAD32[%d]: %s addr=0x%llx value=%d\n",
            count, name, (unsigned long long)addr, (int)value);
}

void helper_debug_optind_load64(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    const char *name = "???";
    if ((addr & 0xfff) == 0x040) name = "optarg";
    else if ((addr & 0xfff) == 0x048) name = "opterr";
    else if ((addr & 0xfff) == 0x060) name = "__environ";
    else if ((addr & 0xfff) == 0x068) name = "optind";
    DEBUG_FPRINTF(stderr, "OPT_LOAD64[%d]: %s addr=0x%llx value=0x%llx\n",
            count, name, (unsigned long long)addr, (unsigned long long)value);
}

void helper_debug_optind_sub_load(uint32_t value, uint64_t addr) {
    static int count = 0;
    count++;
    const char *name = "???";
    if ((addr & 0xfff) == 0x068) name = "optind";
    else if ((addr & 0xfff) == 0x048) name = "opterr";
    DEBUG_FPRINTF(stderr, "OPT_SUB_LOAD[%d]: %s addr=0x%llx value=%d\n",
            count, name, (unsigned long long)addr, (int)value);
}

// Fix optind COPY relocation bug - return corrected value
// Returns: value to actually store (1 if this looks like a broken COPY, else original value)
uint32_t helper_debug_optind_store(uint32_t value, uint64_t addr) {
    static int count = 0;
    count++;
    (void)addr;

    // WORKAROUND: If first store to optind is 0, fix it to 1
    // This works around the bug where COPY reads from the wrong address
    uint32_t fixed_value = value;
    if (count == 1 && value == 0) {
        fixed_value = 1;
    }
    return fixed_value;
}

// Debug: trace the fix store operation
void helper_debug_optind_fix_store(uint64_t addr, uint32_t value) {
    DEBUG_FPRINTF(stderr, "OPTIND_FIX_STORE: about to write %d to guest addr 0x%llx\n",
            (int)value, (unsigned long long)addr);
    fflush(stderr);
}

// Debug: trace before/after restore_c
void helper_debug_before_restore(uint64_t cpu_ptr) {
    DEBUG_FPRINTF(stderr, "BEFORE_RESTORE: _cpu=0x%llx\n", (unsigned long long)cpu_ptr);
    fflush(stderr);
}

// Debug: trace GOT stores (for optind GOT entry)
void helper_debug_got_store(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    DEBUG_FPRINTF(stderr, "GOT_STORE[%d]: addr=0x%llx value=0x%llx\n",
            count, (unsigned long long)addr, (unsigned long long)value);
}

// Address of musl's optind (interp_base + 0x9f3dc, where interp_base=0x7efffff5e000)
// This will be set by exec.c
uint64_t musl_optind_addr = 0;

// Debug: trace ALL stores to busybox data segment (0x555555616000-0x55555561b000)
void helper_debug_busybox_store32(uint32_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Only show first 50 stores
    if (count <= 50) {
        DEBUG_FPRINTF(stderr, "BUSYBOX_STORE32[%d]: addr=0x%llx value=%d (0x%x)\n",
                count, (unsigned long long)addr, (int)value, (unsigned)value);
    }
}

void helper_debug_busybox_store64(uint64_t value, uint64_t addr) {
    (void)value; (void)addr;
}

void helper_debug_optind_store64(uint64_t value, uint64_t addr) {
    (void)value; (void)addr;
}

// Debug: trace stores to the getopt32 option table (flag field at offset 4)
// Option table is on stack around 0x7efffff5b540 - 0x7efffff5b680
// Each entry is 0x28 (40) bytes. Flag field is at offset 4.
// Track host address for entry 2 flag - WATCHPOINT
static uint64_t entry2_flag_host_addr = 0;
static int watchpoint_armed = 0;
static int opt_store_call_count = 0;

// Check if any store32 hits the watchpoint (entry 2 flag host address)
void helper_check_watchpoint_store32(uint32_t value, uint64_t host_addr) {
    if (watchpoint_armed && host_addr == entry2_flag_host_addr) {
        DEBUG_FPRINTF(stderr, "*** WATCHPOINT HIT store32: host=0x%llx value=%d (0x%x)\n",
                (unsigned long long)host_addr, (int)value, (unsigned)value);
    }
}

// Check if any store64 overlaps the watchpoint (entry 2 flag)
void helper_check_watchpoint_store64(uint64_t value, uint64_t host_addr) {
    if (watchpoint_armed) {
        // 64-bit store writes to [host_addr, host_addr+7]
        // Entry 2 flag is at entry2_flag_host_addr (4 bytes)
        if (host_addr <= entry2_flag_host_addr && (host_addr + 7) >= entry2_flag_host_addr) {
            int offset = (int)(entry2_flag_host_addr - host_addr);
            uint32_t byte_at_flag = (value >> (offset * 8)) & 0xFFFFFFFF;
            DEBUG_FPRINTF(stderr, "*** WATCHPOINT HIT store64: host=0x%llx value=0x%llx overlaps flag! offset=%d, bytes_at_flag=0x%x\n",
                    (unsigned long long)host_addr, (unsigned long long)value, offset, byte_at_flag);
        }
    }
}

// Check if any store8 hits the watchpoint
void helper_check_watchpoint_store8(uint8_t value, uint64_t host_addr) {
    if (watchpoint_armed && host_addr >= entry2_flag_host_addr && host_addr < entry2_flag_host_addr + 4) {
        DEBUG_FPRINTF(stderr, "*** WATCHPOINT HIT store8: host=0x%llx value=%d (0x%x)\n",
                (unsigned long long)host_addr, (int)value, (unsigned)value);
    }
}

// Check if any store16 overlaps the watchpoint
void helper_check_watchpoint_store16(uint16_t value, uint64_t host_addr) {
    if (watchpoint_armed) {
        // 16-bit store writes to [host_addr, host_addr+1]
        if (host_addr + 1 >= entry2_flag_host_addr && host_addr < entry2_flag_host_addr + 4) {
            DEBUG_FPRINTF(stderr, "*** WATCHPOINT HIT store16: host=0x%llx value=%d (0x%x)\n",
                    (unsigned long long)host_addr, (int)value, (unsigned)value);
        }
    }
}

void helper_debug_opt_table_store32(uint32_t value, uint64_t addr) {
    opt_store_call_count++;
    // Trace ALL stores in option table range
    uint64_t offset = (addr - 0x7efffff5b540) % 0x28;
    uint64_t entry = (addr - 0x7efffff5b540) / 0x28;
    DEBUG_FPRINTF(stderr, "OPT_TABLE_STORE32[call=%d,entry=%lld,off=%lld]: addr=0x%llx value=%d (0x%x)\n",
            opt_store_call_count, (long long)entry, (long long)offset, (unsigned long long)addr, (int)value, (unsigned)value);
}

// Called from store32_mem with host address (after TLB) to track entry 2 flag
// This is called BEFORE the actual store
void helper_debug_opt_table_store32_host(uint32_t value, uint64_t guest_addr, uint64_t host_addr) {
    // Only trace entry 2 flag (guest 0x7efffff5b594)
    if (guest_addr == 0x7efffff5b594) {
        entry2_flag_host_addr = host_addr;
        volatile uint32_t *ptr = (volatile uint32_t *)host_addr;
        uint32_t before = *ptr;
        DEBUG_FPRINTF(stderr, "STORE32_ENTRY2_FLAG: guest=0x%llx host=0x%llx value_to_store=%d (0x%x) mem_before=%d (0x%x)\n",
                (unsigned long long)guest_addr, (unsigned long long)host_addr,
                (int)value, (unsigned)value, (int)before, (unsigned)before);
    }
}

// Called right AFTER the store to verify it succeeded
void helper_debug_opt_table_store32_after(uint64_t guest_addr, uint64_t host_addr) {
    if (guest_addr == 0x7efffff5b594) {
        volatile uint32_t *ptr = (volatile uint32_t *)host_addr;
        uint32_t after = *ptr;
        DEBUG_FPRINTF(stderr, "STORE32_ENTRY2_FLAG_AFTER: host=0x%llx mem_after=%d (0x%x) - WATCHPOINT ARMED\n",
                (unsigned long long)host_addr, (int)after, (unsigned)after);
        // Arm the watchpoint for subsequent stores
        entry2_flag_host_addr = host_addr;
        watchpoint_armed = 1;
    }
}

void helper_debug_opt_table_store64(uint64_t value, uint64_t addr) {
    (void)value; (void)addr;
}

void helper_debug_check_flag(const char *point, uint64_t host_addr) {
    (void)point; (void)host_addr;
}

// Debug: trace musl data area loads
void helper_debug_musl_load(uint32_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Only show first 10 loads to avoid spam
    if (count <= 10) {
        DEBUG_FPRINTF(stderr, "MUSL_LOAD32[%d]: addr=0x%llx value=%d (0x%x)\n",
                count, (unsigned long long)addr, (int)value, (unsigned)value);
    }
}

// Debug: trace musl 64-bit loads
void helper_debug_musl_load64(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Only show first 10 loads to avoid spam
    if (count <= 10) {
        DEBUG_FPRINTF(stderr, "MUSL_LOAD64[%d]: addr=0x%llx value=0x%llx\n",
                count, (unsigned long long)addr, (unsigned long long)value);
    }
}

// Debug: trace 64-bit loads from memory
void helper_debug_load64(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // Trace loads from argv area (0x7efffff5bf*)
    if ((addr >> 8) == 0x7efffff5bfd || (addr >> 8) == 0x7efffff5bfc) {
        DEBUG_FPRINTF(stderr, "LOAD64_ARGV[%d]: addr=0x%llx value=0x%llx\n",
                count, (unsigned long long)addr, (unsigned long long)value);
    }
    // Trace loads from optind (0x55555561a068) or nearby
    if (addr >= 0x55555561a040 && addr < 0x55555561a080) {
        DEBUG_FPRINTF(stderr, "LOAD_OPTDATA[%d]: addr=0x%llx value=0x%llx\n",
                count, (unsigned long long)addr, (unsigned long long)value);
    }
}

// Debug: trace 32-bit loads from memory - look for pointer-sized loads
static int after_b_load = 0;
void helper_debug_load32(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // After seeing 'b' in store8, trace loads that look like truncated pointers
    // (high bits would be truncated by 32-bit load)
    if (after_b_load > 0 && after_b_load <= 20) {
        after_b_load++;
        // Look for values that could be truncated pointers (in 0x55555555* or 0x7efffff* range)
        if ((value & 0xFFFF0000) == 0x55550000 || (value & 0xFFFF0000) == 0xFFFF0000) {
            DEBUG_FPRINTF(stderr, "LOAD32_PTR?[%d]: addr=0x%llx value=0x%llx (possible truncated ptr)\n",
                    count, (unsigned long long)addr, (unsigned long long)value);
        }
    }
}

// Debug: trace 8-bit stores
static int store8_ab_count = 0;
void helper_debug_store8(uint64_t value, uint64_t addr) {
    static int count = 0;
    count++;
    // After storing 'b', trace next 10 stores
    if (store8_ab_count > 0 && store8_ab_count <= 10) {
        store8_ab_count++;
        char c = (value >= 32 && value < 127) ? (char)value : '?';
        DEBUG_FPRINTF(stderr, "STORE8_AFTER_B[%d]: addr=0x%llx value=0x%llx ('%c')\n",
                count, (unsigned long long)addr, (unsigned long long)value, c);
    }
    // Trace stores to output buffer area (0x7effffffe*)
    if ((addr >> 12) == 0x7effffffe) {
        char c = (value >= 32 && value < 127) ? (char)value : '?';
        DEBUG_FPRINTF(stderr, "STORE8_BUF[%d]: addr=0x%llx value=0x%llx ('%c')\n",
                count, (unsigned long long)addr, (unsigned long long)value, c);
    }
    // Also trace stores of 'a' or 'b' anywhere
    else if (value == 0x61 || value == 0x62) {
        char c = (char)value;
        DEBUG_FPRINTF(stderr, "STORE8[%d]: addr=0x%llx value=0x%llx ('%c')\n",
                count, (unsigned long long)addr, (unsigned long long)value, c);
        if (value == 0x62) store8_ab_count = 1;  // start tracing after 'b'
    }
}

// Debug: trace addr_r13 calculations
void helper_debug_addr_r13(uint64_t addr, uint64_t r13_value, uint64_t displacement) {
    static int count = 0;
    count++;
    // Trace ALL addr_r13 calls to see when they happen
    if (count < 100) {
        DEBUG_FPRINTF(stderr, "ADDR_R13[%d]: addr=0x%llx r13=0x%llx disp=%lld\n",
                count, (unsigned long long)addr, (unsigned long long)r13_value,
                (long long)displacement);
    }
}

// Debug: trace byte loads with full address info
void helper_debug_byte_load_full(uint64_t value, uint64_t host_addr, uint64_t guest_addr) {
    static int count = 0;
    count++;
    // Trace byte loads from 17000-19000 (should be near getopt32 and pwd code)
    if (count > 17000 && count < 19000) {
        char c = (value >= 32 && value < 127) ? (char)value : '.';
        DEBUG_FPRINTF(stderr, "BYTE[%d]: guest=0x%llx value=0x%02llx '%c'\n",
                count, (unsigned long long)guest_addr, (unsigned long long)value, c);
    }
}

// Debug: trace CMP32 x8 - called to trace comparisons
// At getopt32: mem_value = stack[-0x568], reg_value = r12d
void helper_debug_cmp32_x8(uint32_t mem_value, uint32_t reg_value) {
    static int count = 0;
    count++;
    // Always print for now to debug the issue
    DEBUG_FPRINTF(stderr, "CMP32_X8[%d]: _tmp=%d (0x%x) w8=%d (0x%x) result=%d\n",
            count, (int32_t)mem_value, mem_value, (int32_t)reg_value, reg_value,
            (int32_t)(mem_value - reg_value));
}

void helper_debug_cmp32_reg_entry(uint64_t reg_index, uint32_t tmp_value) {
    (void)reg_index; (void)tmp_value;
}

void helper_debug_cmp32_ebp(uint32_t tmp_value, uint32_t ebp_value) {
    (void)tmp_value; (void)ebp_value;
}

// Debug: trace store to r12 - normal (not 0x7f...)
void helper_debug_store64_r12(uint64_t value) {
    (void)value;  // Only trace 0x7f... values via helper_debug_store64_r12_with_rip
}

// Debug: trace store to r12 - with RIP for 0x7f... values
void helper_debug_store64_r12_with_rip(uint64_t value, uint64_t rip) {
    static int count = 0;
    count++;
    if (count <= 10) {
        DEBUG_FPRINTF(stderr, "R12_7F[%d]: storing 0x%llx to r12 at rip=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)rip);
    }
}

// External for correlation
int helper_get_load32_count(void);

// Debug: trace store to r15
static int g_store_r15_count = 0;
void helper_debug_store64_r15(uint64_t value, uint64_t guest_rip) {
    g_store_r15_count++;
    // Trace ALL stores in getopt32 range (0x93000 - 0x93500 offset)
    // busybox base = 0x555555554000, so getopt32 range is 0x5555555e7000 - 0x5555555e7500
    if (guest_rip >= 0x5555555e7000 && guest_rip <= 0x5555555e7500) {
        // Only trace small values (flag values) and the r15=0 zeroing at 0x931a4
        if (value < 0x1000 || value == 0x8000000 || guest_rip == 0x5555555e71a4) {
            DEBUG_FPRINTF(stderr, "STORE_R15[%d]: value=0x%llx @ rip=0x%llx\n",
                    g_store_r15_count, (unsigned long long)value,
                    (unsigned long long)guest_rip);
        }
    }
}

// Debug: trace the OR memory address
void helper_debug_or_mem_addr(uint64_t guest_addr, uint64_t guest_rip, uint64_t rsi_val) {
    static int count = 0;
    count++;
    // Trace at getopt32 OR instruction (0x93285 -> 0x5555555e7285)
    if (guest_rip >= 0x5555555e7280 && guest_rip <= 0x5555555e7290) {
        DEBUG_FPRINTF(stderr, "OR_MEM_ADDR[%d]: mem_addr=0x%llx rsi=0x%llx @ rip=0x%llx\n",
                count, (unsigned long long)guest_addr, (unsigned long long)rsi_val,
                (unsigned long long)guest_rip);
    }
}

static int g_store_r14_count = 0;
static int g_r14_trace_enabled = 1;
void helper_debug_store64_r14(uint64_t value, uint64_t guest_rip) {
    g_store_r14_count++;

    // Trace r14 stores in printf_core range (musl 0x53c36-0x54914)
    // Runtime: 0x7efffff5e000 + 0x53c36 = 0x7efffffb1c36 to 0x7efffffb2914
    // r14 is the length counter in printf_core
    if (guest_rip >= 0x7efffffb1c36 && guest_rip <= 0x7efffffb2914) {
        uint64_t offset = guest_rip - 0x7efffff5e000;
        DEBUG_FPRINTF(stderr, "STORE_R14_PRINTF[%d]: value=%lld (0x%llx) @ rip=0x%llx (musl+0x%llx)\n",
                g_store_r14_count, (long long)value, (unsigned long long)value,
                (unsigned long long)guest_rip, (unsigned long long)offset);
    }

    // Trace r14 stores in getopt32 range - r14 holds option string pointer
    // busybox base = 0x555555554000, getopt32 range is ~0x92e00-0x93500
    if (guest_rip >= 0x5555555e6000 && guest_rip <= 0x5555555e8000) {
        // Trace stores where r14 points to option string data (0x555555613*)
        // Also trace key positions: initial setup (0xee6), loop increment (0x7356), leaq (0x7352)
        uint64_t offset = guest_rip - 0x555555554000;
        if ((value >= 0x555555610000 && value <= 0x555555620000) ||
            offset == 0x92eec || offset == 0x931b4) {
            if (g_r14_trace_enabled) {
                DEBUG_FPRINTF(stderr, "STORE_R14[%d]: value=0x%llx @ rip=0x%llx (offset=0x%llx)\n",
                        g_store_r14_count, (unsigned long long)value,
                        (unsigned long long)guest_rip, (unsigned long long)offset);
            }
        }
    }
}

// Debug: trace add32_x8 gadget values (for ADD r8-r15, r8-r15)
static int g_add32_x8_count = 0;
void helper_debug_add32_x8(uint64_t src, uint64_t dst, uint64_t guest_rip) {
    g_add32_x8_count++;
    // Only trace in printf_core range (musl 0x53c36-0x54914)
    // Runtime: 0x7efffffb1c36 to 0x7efffffb2914
    if (guest_rip >= 0x7efffffb1c36 && guest_rip <= 0x7efffffb2914) {
        uint64_t result = (src + dst) & 0xFFFFFFFF;
        DEBUG_FPRINTF(stderr, "ADD32_X8[%d]: src=%lld dst=%lld result=%lld @ rip=0x%llx (musl+0x%llx)\n",
                g_add32_x8_count, (long long)(int32_t)src, (long long)(int32_t)dst,
                (long long)(int32_t)result, (unsigned long long)guest_rip,
                (unsigned long long)(guest_rip - 0x7efffff5e000));
    }
}

// Debug: trace stores to r11 in printf_core range
static int g_store_r11_count = 0;
void helper_debug_store64_r11(uint64_t value, uint64_t guest_rip) {
    g_store_r11_count++;
    // Trace r11 stores in printf_core range (musl 0x53c36-0x54914)
    // Runtime: 0x7efffffb1c36 to 0x7efffffb2914
    if (guest_rip >= 0x7efffffb1c36 && guest_rip <= 0x7efffffb2914) {
        uint64_t offset = guest_rip - 0x7efffff5e000;
        DEBUG_FPRINTF(stderr, "STORE_R11_PRINTF[%d]: value=%lld (0x%llx) @ rip=0x%llx (musl+0x%llx)\n",
                g_store_r11_count, (long long)(int32_t)value, (unsigned long long)value,
                (unsigned long long)guest_rip, (unsigned long long)offset);
    }
}

static int g_store_r13_count = 0;
void helper_debug_store64_r13(uint64_t value, uint64_t guest_rip) {
    g_store_r13_count++;
    // Trace key stores - look for 0x8000000 or 0 in busybox
    if (guest_rip >= 0x555555550000 && guest_rip <= 0x555555700000) {
        if (value == 0 || value == 0x8000000) {
            DEBUG_FPRINTF(stderr, "STORE_R13[%d]: value=0x%llx @ rip=0x%llx\n",
                    g_store_r13_count, (unsigned long long)value,
                    (unsigned long long)guest_rip);
        }
    }
}

void helper_debug_load64_r13(uint64_t value) {
    (void)value;
}

// Debug: trace OR reg, mem - show what memory is being read
void helper_debug_or_mem_load(uint64_t guest_addr, uint32_t loaded_value, uint64_t guest_rip) {
    static int count = 0;
    count++;
    // Trace if the loaded value is 0x8000000 (suspicious) or in the getopt32 range
    if (loaded_value == 0x8000000 || loaded_value == 0x50 ||
        (guest_rip >= 0x5555555e7280 && guest_rip <= 0x5555555e7290)) {
        DEBUG_FPRINTF(stderr, "OR_MEM_LOAD[%d]: guest_addr=0x%llx loaded_val=%u (0x%x) @ rip=0x%llx\n",
                count, (unsigned long long)guest_addr, loaded_value, loaded_value,
                (unsigned long long)guest_rip);
    }
}

// Debug: trace CMP byte to see option parsing
void helper_debug_cmpb_0x3a(uint8_t byte_val, uint64_t addr, uint64_t guest_rip) {
    static int count = 0;
    count++;
    // Trace in getopt32 range (0x93256 -> 0x5555555e7256) - THIS IS CRITICAL
    // If byte is NOT ':', the code jumps directly to OR and sets flags!
    if (guest_rip >= 0x5555555e7250 && guest_rip <= 0x5555555e7260) {
        const char *result = (byte_val == 0x3a) ? "MATCH (has arg)" : "NO MATCH (no arg, will OR flags!)";
        DEBUG_FPRINTF(stderr, "CMPB_3A[%d]: byte=0x%02x '%c' at addr=0x%llx -> %s @ rip=0x%llx\n",
                count, byte_val, (byte_val >= 0x20 && byte_val <= 0x7e) ? (char)byte_val : '?',
                (unsigned long long)addr, result, (unsigned long long)guest_rip);
    }
}

// Debug: trace load8_mem to find strlen issues
void helper_debug_load8_mem(uint32_t byte_value, uint64_t addr) {
    static int count = 0;
    count++;
    // The host address after TLB translation - we need to match the pattern
    // Just trace all loads of 'a' or 'b' bytes to find our "ab" string
    if (byte_value == 0x61 || byte_value == 0x62) {  // 'a' or 'b'
        DEBUG_FPRINTF(stderr, "LOAD8[%d]: addr=0x%llx byte=0x%02x '%c'\n",
                count, (unsigned long long)addr, byte_value, (char)byte_value);
    }
}

// Debug: trace byte loads with GUEST address to find our "ab" string at 0x7efffff5bfdb
// We access current RIP via extern - defined in gen64.c or similar
extern uint64_t g_current_orig_ip;  // Track what guest IP is being translated

extern void gadget_cmp8_imm(void);  // Declaration for comparing gadget pointers

static int g_load8_count = 0;
int helper_get_load8_count(void) { return g_load8_count; }
// All 4 cmpb $0, (%rax) IPs for strlen-like operations
static const uint64_t strlen_ips[] = {
    0x7efffff7a80b, 0x7efffffb7470, 0x7efffffb743b, 0x7efffffb2562
};
void helper_debug_load8_mem_full(uint32_t byte_value, uint64_t guest_addr, uint64_t orig_ip) {
    g_load8_count++;
    // Trace loads for CMP byte [r14+2], 0x3a at offset 0x93256 in busybox
    // Guest IP = 0x555555554000 + 0x93256 = 0x5555555e7256
    if (orig_ip == 0x5555555e7256) {
        char c = (byte_value >= 0x20 && byte_value < 0x7f) ? (char)byte_value : '.';
        DEBUG_FPRINTF(stderr, "LOAD8_CMP3A[%d]: guest_addr=0x%llx byte=0x%02x '%c' @ ip=0x%llx\n",
                g_load8_count, (unsigned long long)guest_addr, byte_value, c,
                (unsigned long long)orig_ip);
    }
    // Also trace CMP byte [r13], 0x5e at offset 0x92edf
    // Guest IP = 0x555555554000 + 0x92edf = 0x5555555e6edf
    if (orig_ip == 0x5555555e6edf) {
        char c = (byte_value >= 0x20 && byte_value < 0x7f) ? (char)byte_value : '.';
        DEBUG_FPRINTF(stderr, "LOAD8_CMP5E[%d]: guest_addr=0x%llx byte=0x%02x '%c' (expected '^'=0x5e) @ ip=0x%llx\n",
                g_load8_count, (unsigned long long)guest_addr, byte_value, c,
                (unsigned long long)orig_ip);
    }
}

void helper_debug_load8_mem_guest(uint32_t byte_value, uint64_t guest_addr) {
    // Old function - just call new one with dummy next_gadget
    static int count = 0;
    count++;
    if (guest_addr == 0x7efffff5bfdb || guest_addr == 0x7efffff5bfdc || guest_addr == 0x7efffff5bfdd) {
        char c = (byte_value >= 0x20 && byte_value < 0x7f) ? (char)byte_value : '.';
        DEBUG_FPRINTF(stderr, "LOAD8_AB[%d]: guest_addr=0x%llx byte=0x%02x '%c'\n",
                count, (unsigned long long)guest_addr, byte_value, c);
    }
}

// Debug: trace 64-bit loads from stack area
void helper_debug_load64_stack(uint64_t value, uint64_t guest_addr) {
    static int count = 0;
    count++;
    // Print the 8 bytes loaded
    char buf[9];
    for (int i = 0; i < 8; i++) {
        uint8_t b = (value >> (i * 8)) & 0xFF;
        buf[i] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
    }
    buf[8] = '\0';
    DEBUG_FPRINTF(stderr, "LOAD64_STACK[%d]: guest_addr=0x%llx value=0x%016llx '%s'\n",
            count, (unsigned long long)guest_addr, (unsigned long long)value, buf);
}

// Debug: trace CMP byte with 0 (used in strlen loop)
void helper_debug_cmp8_zero(uint32_t byte_value, uint32_t imm) {
    static int count = 0;
    count++;
    // Trace only printable chars or zero to reduce noise
    if (byte_value == 0 || (byte_value >= 0x20 && byte_value < 0x7f)) {
        char c = (byte_value >= 0x20 && byte_value < 0x7f) ? (char)byte_value : '.';
        DEBUG_FPRINTF(stderr, "CMP8_ZERO[%d]: byte=0x%02x '%c' cmp 0 => ZF=%s\n",
                count, byte_value, c, byte_value == 0 ? "1" : "0");
    }
}

// Debug: track when RAX is set to 0x7efffff5bfdd (null terminator of "ab")
static int g_store64_count = 0;
static int g_load64_count = 0;
extern int helper_get_load8_count(void);
void helper_debug_load64_any(uint64_t value, const char *source) {
    g_load64_count++;
    // Trace loads around store 18050 or when value is bfdd
    if (value == 0x7efffff5bfdd) {
        DEBUG_FPRINTF(stderr, "LOAD64[%d,store=%d,load8=%d]: bfdd from %s\n",
                g_load64_count, g_store64_count, helper_get_load8_count(), source);
    }
    // Also trace when value is bfdb (start of "ab" string)
    else if (value == 0x7efffff5bfdb) {
        DEBUG_FPRINTF(stderr, "LOAD64[%d,store=%d,load8=%d]: bfdb (start) from %s\n",
                g_load64_count, g_store64_count, helper_get_load8_count(), source);
    }
}
static int g_store_c_count = 0;
static int g_global_op = 0;  // Track all operations in order
void helper_debug_store64_c(uint64_t rcx_value) {
    g_store_c_count++;
    g_global_op++;
    // Trace all RCX stores around load8 12975-12978
    int load8 = helper_get_load8_count();
    if (load8 >= 12974 && load8 <= 12980) {
        DEBUG_FPRINTF(stderr, "OP[%d] STORE_C: RCX=0x%llx (load8=%d)\n",
                g_global_op, (unsigned long long)rcx_value, load8);
    }
}
void helper_debug_load64_c(uint64_t rcx_value) {
    g_global_op++;
    int load8 = helper_get_load8_count();
    if (load8 >= 12974 && load8 <= 12980) {
        DEBUG_FPRINTF(stderr, "OP[%d] LOAD_C:  RCX=0x%llx (load8=%d)\n",
                g_global_op, (unsigned long long)rcx_value, load8);
    }
}
void helper_debug_store64_a(uint64_t rax_value) {
    g_store64_count++;
    int load8 = helper_get_load8_count();
    // Trace ALL store64_a in range 12980-12990 (to find where RAX gets value 1)
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "STORE64_A[store=%d,load8=%d]: RAX=0x%llx (%llu)\n",
                g_store64_count, load8,
                (unsigned long long)rax_value, (unsigned long long)rax_value);
    }
}

// Debug: trace when RAX is set to exactly 1 (with guest IP)
void helper_debug_rax_eq_1(uint64_t rax_value, uint64_t guest_ip) {
    static int count = 0;
    count++;
    int load8 = helper_get_load8_count();
    // Only trace in critical range
    if (load8 >= 12983 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "RAX_EQ_1[%d,load8=%d]: RAX=1 at guest_ip=0x%llx\n",
                count, load8, (unsigned long long)guest_ip);
    }
}
void helper_debug_rax_set_bfdd(uint64_t rax_value) {
    DEBUG_FPRINTF(stderr, "RAX_BFDD: RAX=0x%llx (store64=%d,load8=%d) <-- strlen receives this!\n",
            (unsigned long long)rax_value, g_store64_count, helper_get_load8_count());
}

// Debug: trace TEST AL, AL when checking for null (mask=0xFF)
extern int helper_get_load8_count(void);
void helper_debug_test8_null_check(uint32_t byte_value) {
    static int count = 0;
    static uint32_t prev = 0, prev2 = 0;
    count++;
    // Look for 'a', 'b', '\0' or 'b', 'a', '\0' sequence
    if ((prev2 == 0x61 && prev == 0x62 && byte_value == 0) ||
        (prev2 == 0x62 && prev == 0x61 && byte_value == 0)) {
        char c = (byte_value >= 0x20 && byte_value < 0x7f) ? (char)byte_value : '.';
        DEBUG_FPRINTF(stderr, "TEST8_SEQ[%d,load8=%d]: %c->%c->%c (prev2=0x%02x prev=0x%02x cur=0x%02x)\n",
                count, helper_get_load8_count(),
                (prev2 >= 0x20 && prev2 < 0x7f) ? (char)prev2 : '.',
                (prev >= 0x20 && prev < 0x7f) ? (char)prev : '.',
                c, prev2, prev, byte_value);
    }
    prev2 = prev;
    prev = byte_value;
}

static int g_cmp8_3a_count = 0;
void helper_debug_cmp8_all_res(uint32_t byte_value, uint32_t imm, int64_t res) {
    // Trace CMP with ':' (0x3a) - critical for getopt32 option parsing
    // If byte != 0x3a, the option's flags get ORed in
    if (imm == 0x3a) {
        g_cmp8_3a_count++;
        // Only trace the last few comparisons (around when 0x8000000 gets set)
        // Also trace NULL bytes (potential end-of-string issues)
        if (byte_value == 0x00 || g_cmp8_3a_count >= 25) {
            const char *result = (byte_value == 0x3a) ? "MATCH (opt has arg)" : "NO MATCH (opt sets flags!)";
            DEBUG_FPRINTF(stderr, "CMP8_3A[%d]: byte=0x%02x '%c' -> %s\n",
                    g_cmp8_3a_count, byte_value,
                    (byte_value >= 0x20 && byte_value <= 0x7e) ? (char)byte_value : '?',
                    result);
        }
    }
}

void helper_debug_cmp8_all(uint32_t byte_value, uint32_t imm) {
    // Dummy - will be replaced by cmp8_all_res
}

// Debug: trace TEST reg, reg (r8-r15)
void helper_debug_test_r8_r15(uint32_t val1, uint32_t val2, int reg_idx) {
    static int count = 0;
    count++;
    // Only trace first 50 to reduce noise
    if (count <= 100) {
        DEBUG_FPRINTF(stderr, "TEST_R8_R15[%d]: r%d=%u (0x%x), r%d=%u (0x%x), AND=%u\n",
                count, 8 + (reg_idx >> 4), val1, val1,
                8 + (reg_idx & 0xf), val2, val2, val1 & val2);
    }
}

// Debug: trace test64_x8 gadget (used for TEST r8-r15, r8-r15)
// For testl %r15d, %r13d: _xtmp = r15, x8 = r13
void helper_debug_test64_x8(uint32_t val1, uint32_t val2, uint64_t guest_rip) {
    (void)val1; (void)val2; (void)guest_rip;
    // Disabled to reduce noise
}

// Debug: trace 32-bit TEST with x8 (for r8-r15 registers)
void helper_debug_test32_x8(uint32_t val_xtmp, uint32_t val_x8, uint64_t guest_rip) {
    // Trace tests in the getopt32 range (0x93480 to 0x93490 offset from busybox base)
    // 0x5555555e7480 to 0x5555555e7490
    if (guest_rip >= 0x5555555e7480 && guest_rip <= 0x5555555e7490) {
        uint32_t result = val_xtmp & val_x8;
        DEBUG_FPRINTF(stderr, "TEST32_X8: _xtmp=%u (0x%x) x8=%u (0x%x) result=%u ZF=%d @ rip=0x%llx\n",
                val_xtmp, val_xtmp, val_x8, val_x8, result, (result == 0) ? 1 : 0,
                (unsigned long long)guest_rip);
    }
}

// Debug: trace test32_imm gadget (used for TEST reg, reg -> TEST reg, 0xFFFFFFFF)
void helper_debug_test32_imm(uint32_t val, uint32_t mask, uint64_t guest_rip) {
    static int count = 0;
    count++;
    // Trace self-tests with mask=0xFFFFFFFF at specific addresses
    // 0x5555555e7480 = 0x555555554000 + 0x93480 (testl %r15d, %r15d)
    // Also trace all tests in the getopt32 range
    if (mask == 0xFFFFFFFF && (guest_rip >= 0x5555555e7470 && guest_rip <= 0x5555555e7490)) {
        DEBUG_FPRINTF(stderr, "TEST32_IMM[%d]: val=%u (0x%x) -> ZF=%d @ rip=0x%llx\n",
                count, val, val, (val == 0) ? 1 : 0, (unsigned long long)guest_rip);
    }
}

// Debug: trace test8_imm when value is 0 (testb %cl, %cl in option search loop)
void helper_debug_test8_imm_zero(uint32_t val, uint32_t mask) {
    static int count = 0;
    count++;
    DEBUG_FPRINTF(stderr, "TEST8_IMM_ZERO[%d]: val=%u mask=0x%x (ZF=1, JE would be taken)\n",
            count, val, mask);
}

// Debug: trace test8_imm when result is 0 (alignment checks, null byte checks)
void helper_debug_test8_imm_result_zero(uint32_t val, uint32_t mask, uint32_t result) {
    static int count = 0;
    count++;
    // Only trace alignment checks (mask=7) and null byte checks (mask=0xff with val=0)
    if (mask == 7) {
        DEBUG_FPRINTF(stderr, "TEST8_ALIGN[%d]: val=0x%02x & 7 = 0 (ALIGNED, ZF=1, JNE skipped) low_bits=%d\n",
                count, val, val & 7);
    } else if (val == 0) {
        DEBUG_FPRINTF(stderr, "TEST8_NULL[%d]: byte=0 & mask=0x%02x = 0 (ZF=1, null terminator found)\n",
                count, mask);
    } else {
        DEBUG_FPRINTF(stderr, "TEST8_ZERO[%d]: val=0x%02x & mask=0x%02x = 0 (ZF=1)\n",
                count, val, mask);
    }
}

// Debug: trace ALL test8_imm calls with mask=0xFF (strlen null byte checks)
void helper_debug_test8_imm_all(uint32_t val, uint32_t mask) {
    static int count = 0;
    count++;
    char c = (val >= 0x20 && val < 0x7f) ? (char)val : '.';
    DEBUG_FPRINTF(stderr, "STRLEN_TEST[%d]: byte=0x%02x '%c' test %s\n",
            count, val, c, (val == 0) ? "-> NULL (exit loop)" : "-> non-null (continue)");
}

void helper_debug_test8_imm_align(uint32_t val, uint32_t mask, uint32_t result) {
    (void)val; (void)mask; (void)result;
}

// Debug: trace return value from getopt_long (EAX after call)
void helper_debug_getopt_return(uint32_t eax, uint64_t ip) {
    // Only trace if we're near the getopt32 call return (0x5555555e73a1 = 0x933a1)
    if (ip >= 0x5555555e7390 && ip <= 0x5555555e73b0) {
        DEBUG_FPRINTF(stderr, "GETOPT_RETURN: eax=%d (0x%x) at ip=0x%llx\n",
                (int)eax, eax, (unsigned long long)ip);
    }
}

// Debug: trace CMP EAX, -1 (check getopt_long return)
void helper_debug_cmp32_neg1(uint32_t eax, uint32_t imm) {
    static int count = 0;
    count++;
    int32_t signed_eax = (int32_t)eax;
    DEBUG_FPRINTF(stderr, "CMP32_NEG1[%d]: eax=%d (0x%x) cmp %d => ZF=%s\n",
            count, signed_eax, eax, (int32_t)imm,
            (eax == imm) ? "1 (equal)" : "0 (not equal)");
}

// Debug: trace JMP_Z (JE/JZ) gadget
void helper_debug_jmp_z(uint32_t flags_res, uint64_t res) {
    (void)flags_res; (void)res;
}

// Debug: trace SETcc producing 1
void helper_debug_setcc_val1(uint32_t value) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "SETCC_VAL1[load8=%d]: tmp=%u\n", load8, value);
    }
}

// Debug: trace SETcc with condition name and flags
extern struct cpu_state *global_cpu;  // Need to pass this
void helper_debug_setcc_val1_cond(uint32_t value, const char *cond) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "SET_%s[load8=%d]: tmp=%u (flags not available here)\n", cond, load8, value);
    }
}

// Debug: trace SETLE with flags
void helper_debug_setle_val1(uint32_t value, int64_t res, uint32_t of) {
    int load8 = helper_get_load8_count();
    int sf = (res < 0) ? 1 : 0;
    int zf = (res == 0) ? 1 : 0;
    DEBUG_FPRINTF(stderr, "SETLE[load8=%d]: tmp=%u res=%lld SF=%d ZF=%d OF=%u (SF^OF=%d, condition=%s)\n",
            load8, value, (long long)res, sf, zf, of, sf ^ of,
            (zf || (sf != of)) ? "TRUE (<=)" : "FALSE (>)");
}

// Debug: trace generic SETcc with flags
void helper_debug_setcc_generic(uint32_t value, int64_t res, uint32_t of) {
    static int count = 0;
    count++;
    int load8 = helper_get_load8_count();
    // Only trace in the relevant range
    if (load8 >= 12980 && load8 <= 12990) {
        int sf = (res < 0) ? 1 : 0;
        int zf = (res == 0) ? 1 : 0;
        DEBUG_FPRINTF(stderr, "SETCC_TRUE[%d,load8=%d]: tmp=%u res=%lld SF=%d ZF=%d OF=%u\n",
                count, load8, value, (long long)res, sf, zf, of);
    }
}

// Debug: trace load64_mem when value is 1
void helper_debug_load64_mem_val1(uint64_t value, uint64_t guest_addr) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "LOAD64_MEM_VAL1[load8=%d]: addr=0x%llx value=%llu\n",
                load8, (unsigned long long)guest_addr, (unsigned long long)value);
    }
}

// Debug: trace RBX stores when value is 1
void helper_debug_store64_b_val1(uint64_t value) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "STORE64_B_VAL1[load8=%d]: RBX=%llu\n",
            load8, (unsigned long long)value);
}

// Debug: trace RBX stores when value is 2
void helper_debug_store64_b_val2(uint64_t value) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "STORE64_B_VAL2[load8=%d]: RBX=%llu (strlen result!)\n",
                load8, (unsigned long long)value);
    }
}

// Debug: trace ALL RDX stores in critical range
void helper_debug_store64_d_all(uint64_t value) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "STORE64_D[load8=%d]: RDX=%llu (0x%llx)\n",
                load8, (unsigned long long)value, (unsigned long long)value);
    }
}

// Debug: trace store64_mem when value is 2 (strlen result)
void helper_debug_store64_mem_val2(uint64_t value, uint64_t guest_addr) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12975 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "STORE64_MEM_VAL2[load8=%d]: addr=0x%llx value=%llu (strlen result?)\n",
                load8, (unsigned long long)guest_addr, (unsigned long long)value);
    }
    // Trace stores to busybox file entry array
    if (guest_addr >= 0x55555561c070 && guest_addr <= 0x55555561c200) {
        static int count = 0;
        count++;
        if (count <= 20) {
            DEBUG_FPRINTF(stderr, "STORE64_BBENTRY[%d]: addr=0x%llx value=0x%llx\n",
                    count, (unsigned long long)guest_addr, (unsigned long long)value);
        }
    }
}

// Debug: trace when RDI is set to 0x7f... addresses (path corruption)
void helper_trace_rdi_7f(uint64_t value, uint64_t guest_rip) {
    if ((value >> 36) == 0x7f0) {
        DEBUG_FPRINTF(stderr, "RDI_7F: rdi=0x%llx at rip=0x%llx\n",
                (unsigned long long)value, (unsigned long long)guest_rip);
    }
}

// Forward declaration
struct cpu_state;

#ifdef ISH_GUEST_64BIT
// Debug: trace stores of 0x7f... values (path corruption source)
void helper_debug_store64_7f_value(uint64_t value, uint64_t guest_addr, uint64_t rip, struct cpu_state *cpu) {
    static int count = 0;
    count++;
    // Only show first few and key entries
    if (count <= 6) {
        DEBUG_FPRINTF(stderr, "STORE64_7F[%d]: storing 0x%llx to guest 0x%llx at rip=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)guest_addr, (unsigned long long)rip);
        DEBUG_FPRINTF(stderr, "  regs: rax=0x%llx r8=0x%llx r12=0x%llx rdi=0x%llx\n",
                (unsigned long long)cpu->rax, (unsigned long long)cpu->r8,
                (unsigned long long)cpu->r12, (unsigned long long)cpu->rdi);
    }
}
#endif

// Debug: trace byte stores to 0x7f0000000xxx addresses (malloc'd heap)
void helper_debug_store8_7f(uint8_t value, uint64_t guest_addr) {
    static int count = 0;
    count++;
    if (count <= 50) {
        DEBUG_FPRINTF(stderr, "STORE8_7F[%d]: byte 0x%02x ('%c') to 0x%llx\n",
                count, value, (value >= 32 && value < 127) ? value : '.',
                (unsigned long long)guest_addr);
    }
}

// Debug: trace REP MOVSB when destination is 0x7f... (strdup/memcpy to heap)
void helper_debug_rep_movsb_7f(uint64_t src, uint64_t dst, uint64_t count) {
    static int rep_count = 0;
    rep_count++;
    if (rep_count <= 20) {
        DEBUG_FPRINTF(stderr, "REP_MOVSB_7F[%d]: src=0x%llx dst=0x%llx count=%llu\n",
                rep_count, (unsigned long long)src, (unsigned long long)dst, (unsigned long long)count);
    }
}

// Debug: trace REP MOVSQ when destination is 0x7f...
void helper_debug_rep_movsq_7f(uint64_t src, uint64_t dst, uint64_t count) {
    static int rep_count = 0;
    rep_count++;
    if (rep_count <= 20) {
        DEBUG_FPRINTF(stderr, "REP_MOVSQ_7F[%d]: src=0x%llx dst=0x%llx count=%llu\n",
                rep_count, (unsigned long long)src, (unsigned long long)dst, (unsigned long long)count);
    }
}

// Debug: trace ALL REP MOVSQ calls with RIP
void helper_debug_rep_movsq_all(uint64_t src, uint64_t dst, uint64_t count) {
    static int rep_count = 0;
    rep_count++;
    // Check if this looks like a string copy to heap (dst = 0x7f...)
    if ((dst >> 36) == 0x7f0 && count > 0) {
        DEBUG_FPRINTF(stderr, "REP_MOVSQ_7F[%d]: src=0x%llx dst=0x%llx count=%llu\n",
                rep_count, (unsigned long long)src, (unsigned long long)dst, (unsigned long long)count);
    } else if (rep_count <= 30) {
        DEBUG_FPRINTF(stderr, "REP_MOVSQ[%d]: src=0x%llx dst=0x%llx count=%llu\n",
                rep_count, (unsigned long long)src, (unsigned long long)dst, (unsigned long long)count);
    }
}

// Debug: trace store64 TO 0x7f... addresses (writing to heap) with RIP
void helper_debug_store64_to_7f_rip(uint64_t value, uint64_t guest_addr, uint64_t rip) {
    static int count = 0;
    count++;
    // Special case: trace when storing the 0x7f0000000a80 address (the problem)
    if (value == 0x7f0000000a80 && count <= 5) {
        DEBUG_FPRINTF(stderr, "STORE64_A80[%d]: storing 0x7f0000000a80 to 0x%llx @ rip=0x%llx\n",
                count, (unsigned long long)guest_addr, (unsigned long long)rip);
    } else if (count <= 40) {
        DEBUG_FPRINTF(stderr, "STORE64_TO_7F[%d]: val=0x%llx to 0x%llx @ rip=0x%llx\n",
                count, (unsigned long long)value, (unsigned long long)guest_addr, (unsigned long long)rip);
    }
}

// Debug: trace single_movsb byte copies (for string copy understanding)
void helper_debug_single_movsb(uint8_t byte, uint64_t src, uint64_t dst) {
    static int count = 0;
    static int dst_7f_count = 0;
    count++;
    // Show first 100 copies, focusing on interesting ranges
    if (count <= 100) {
        // Only show if dst is 0x7f... or src is getdents buffer (0x7efffff4a...)
        if ((dst >> 36) == 0x7f0 || ((src >> 12) == 0x7efffff4a)) {
            DEBUG_FPRINTF(stderr, "MOVSB[%d]: '%c' (0x%02x) from 0x%llx to 0x%llx\n",
                    count, (byte >= 32 && byte < 127) ? byte : '.',
                    byte, (unsigned long long)src, (unsigned long long)dst);
        }
    }
    // Count any copies to 0x7f... destination
    if ((dst >> 36) == 0x7f0) {
        dst_7f_count++;
        DEBUG_FPRINTF(stderr, "MOVSB_TO_7F[%d]: '%c' (0x%02x) from 0x%llx to 0x%llx\n",
                dst_7f_count, (byte >= 32 && byte < 127) ? byte : '.',
                byte, (unsigned long long)src, (unsigned long long)dst);
    }
}

// Debug: trace ALL loads that return 0x7f000000.... values (BSS base)
void helper_debug_load64_7f_base(uint64_t value, uint64_t guest_addr, uint64_t rip) {
    // Trace any load that returns a value in the 0x7f0000000 range
    if ((value >> 28) == 0x7f0000000) {
        static int count = 0;
        count++;
        if (count <= 20) {
            DEBUG_FPRINTF(stderr, "LOAD_7F[%d]: loaded 0x%llx from 0x%llx at rip=0x%llx\n",
                    count, (unsigned long long)value, (unsigned long long)guest_addr, (unsigned long long)rip);
        }
    }
}

// Debug: trace loads from reg_save_area (va_arg reads during vsnprintf)
// This helps understand what vsnprintf sees when reading varargs
void helper_debug_load64_reg_save_area(uint64_t value, uint64_t guest_addr) {
    static int count = 0;
    count++;
    // Calculate which register slot this is
    // reg_save_area is at 0x7efffff5bbf0, each slot is 8 bytes
    int slot = (guest_addr - 0x7efffff5bbf0) / 8;
    // Slot 0 = RDI, 1 = RSI, 2 = RDX, 3 = RCX, 4 = R8, 5 = R9
    const char *reg_names[] = {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    const char *reg = (slot >= 0 && slot < 6) ? reg_names[slot] : "???";
    DEBUG_FPRINTF(stderr, "VA_ARG_READ[%d]: slot %d (%s) @ 0x%llx = 0x%llx\n",
            count, slot, reg, (unsigned long long)guest_addr, (unsigned long long)value);
}

// Debug: trace loads from 0x7efffff5b930 (strlen result stored here)
void helper_debug_load64_mem_b930(uint64_t value, uint64_t guest_addr) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "LOAD64_MEM_B930[load8=%d]: addr=0x%llx value=%llu (should be strlen=2)\n",
            load8, (unsigned long long)guest_addr, (unsigned long long)value);
}

// Debug: trace load64_imm when value is 1
void helper_debug_load64_imm_val1(uint64_t value) {
    int load8 = helper_get_load8_count();
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "LOAD64_IMM_VAL1[load8=%d]: immediate=%llu\n",
                load8, (unsigned long long)value);
    }
}

// Debug: trace DIV64 when quotient is 1
void helper_debug_div64_rax1(uint64_t value) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "DIV64_RAX1[load8=%d]: quotient=%llu\n",
            load8, (unsigned long long)value);
}

// Debug: trace IDIV32 when quotient is 1
void helper_debug_idiv32_eax1(uint64_t value) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "IDIV32_EAX1[load8=%d]: quotient=%llu\n",
            load8, (unsigned long long)value);
}

// Debug: trace CMPXCHG64 not-equal path when RAX becomes 1
void helper_debug_cmpxchg64_rax1(uint64_t value) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "CMPXCHG64_RAX1[load8=%d]: RAX loaded from memory = %llu\n",
            load8, (unsigned long long)value);
}

// Debug: trace store32_a when value is 1
void helper_debug_store32_a_val1(uint64_t value) {
    int load8 = helper_get_load8_count();
    DEBUG_FPRINTF(stderr, "STORE32_A_VAL1[load8=%d]: EAX=%llu (RAX zeroed-extended)\n",
            load8, (unsigned long long)value);
}

// Debug: trace load64 gadgets that produce value 0x1
void helper_debug_load64_val1(uint64_t value, const char *regname) {
    int load8 = helper_get_load8_count();
    // Only trace in the range where iov[1].len is being set (load8=12980-12990)
    if (load8 >= 12980 && load8 <= 12990) {
        DEBUG_FPRINTF(stderr, "LOAD64_VAL1[load8=%d]: reg=%s value=%llu\n",
                load8, regname, (unsigned long long)value);
    }
}

// Debug: trace stores to iov area
static int g_iov_store_count = 0;
void helper_debug_iov_store64(uint64_t value, uint64_t addr) {
    g_iov_store_count++;
    int load8 = helper_get_load8_count();
    // iov[0].base at b860, iov[0].len at b868
    // iov[1].base at b870, iov[1].len at b878
    const char *field = "unknown";
    if (addr == 0x7efffff5b860) field = "iov[0].base";
    else if (addr == 0x7efffff5b868) field = "iov[0].len";
    else if (addr == 0x7efffff5b870) field = "iov[1].base";
    else if (addr == 0x7efffff5b878) field = "iov[1].len";
    DEBUG_FPRINTF(stderr, "IOV_STORE[%d,load8=%d,store64=%d]: %s (addr=0x%llx) = 0x%llx (%llu)\n",
            g_iov_store_count, load8, g_store64_count, field, (unsigned long long)addr,
            (unsigned long long)value, (unsigned long long)value);
}

// Debug: trace entry to load32_mem (after TLB, before ARM64 ldr)
static int g_load32_entry_count = 0;
void helper_debug_load32_entry(uint64_t host_addr, uint64_t guest_addr) {
    g_load32_entry_count++;
    // Trace disabled - too noisy
    (void)host_addr;
    (void)guest_addr;
}

// Debug: trace store64_a entry with next gadget address
static int g_store64_a_entry_count = 0;
void helper_debug_store64_entry_a_next(uint64_t value, uint64_t next_gadget) {
    g_store64_a_entry_count++;
    // Trace last 20 stores to RAX before potential crash
    if (g_store64_a_entry_count >= 18490) {
        DEBUG_FPRINTF(stderr, "STORE64_A[%d]: val=0x%llx next_gadget=0x%llx\n",
                g_store64_a_entry_count, (unsigned long long)value,
                (unsigned long long)next_gadget);
        fflush(stderr);
    }
}

#ifdef ISH_GUEST_64BIT
// Bypass load64_r10 via C code
static int g_load64_r10_count = 0;
uint64_t helper_load64_r10_via_c(struct cpu_state *cpu) {
    g_load64_r10_count++;
    uint64_t val = cpu->r10;
    // Trace last 20 calls before potential crash
    if (g_load64_r10_count >= 1680) {
        DEBUG_FPRINTF(stderr, "LOAD64_R10[%d]: cpu=%p r10=0x%llx\n",
                g_load64_r10_count, (void*)cpu, (unsigned long long)val);
        fflush(stderr);
    }
    return val;
}

// Counter for load64_r10 calls to find which one crashes
static int g_load64_r10_call_count = 0;
void helper_count_load64_r10(void) {
    g_load64_r10_call_count++;
    // Only trace around the crash point
    if (g_load64_r10_call_count >= 1660 && g_load64_r10_call_count <= 1670) {
        DEBUG_FPRINTF(stderr, "LOAD64_R10_CALL[%d]\n", g_load64_r10_call_count);
        fflush(stderr);
    }
}

// Counter with cpu pointer tracing
void helper_count_load64_r10_with_cpu(struct cpu_state *cpu) {
    g_load64_r10_call_count++;
    // Only trace around the crash point
    if (g_load64_r10_call_count >= 1663 && g_load64_r10_call_count <= 1670) {
        uint64_t r10_value = cpu->r10;
        DEBUG_FPRINTF(stderr, "LOAD64_R10_CALL[%d]: cpu=%p r10=0x%llx rip=0x%llx\n",
                g_load64_r10_call_count, (void*)cpu,
                (unsigned long long)r10_value,
                (unsigned long long)cpu->rip);
        fflush(stderr);
    }
}

// Verify cpu pointer after restore_c
void helper_verify_cpu_after_restore(struct cpu_state *cpu) {
    if (g_load64_r10_call_count >= 1663 && g_load64_r10_call_count <= 1670) {
        uint64_t r10_value = cpu->r10;
        DEBUG_FPRINTF(stderr, "VERIFY_AFTER_RESTORE[%d]: cpu=%p r10=0x%llx\n",
                g_load64_r10_call_count, (void*)cpu,
                (unsigned long long)r10_value);
        fflush(stderr);
    }
}

// Load r10 value via C
uint64_t helper_load_r10_value(struct cpu_state *cpu) {
    if (g_load64_r10_call_count >= 1663 && g_load64_r10_call_count <= 1670) {
        DEBUG_FPRINTF(stderr, "LOAD_R10_VIA_C[%d]: cpu=%p r10=0x%llx\n",
                g_load64_r10_call_count, (void*)cpu,
                (unsigned long long)cpu->r10);
        fflush(stderr);
    }
    return cpu->r10;
}

// Trace state right before gret
void helper_trace_before_gret(uint64_t xtmp, uint64_t ip) {
    if (g_load64_r10_call_count >= 1663 && g_load64_r10_call_count <= 1670) {
        DEBUG_FPRINTF(stderr, "BEFORE_GRET[%d]: xtmp=0x%llx ip=%p\n",
                g_load64_r10_call_count, (unsigned long long)xtmp, (void*)ip);
        fflush(stderr);
    }
}

// Trace gret: next gadget and current ip
void helper_trace_gret(uint64_t next_gadget, uint64_t ip) {
    if (g_load64_r10_call_count >= 1663 && g_load64_r10_call_count <= 1670) {
        DEBUG_FPRINTF(stderr, "GRET[%d]: next=%p ip=%p\n",
                g_load64_r10_call_count, (void*)next_gadget, (void*)ip);
        fflush(stderr);
    }
}

// Simple r10 load helper
uint64_t helper_load_r10_simple(struct cpu_state *cpu) {
    return cpu->r10;
}

// Simple r13 load helper - no tracing
uint64_t helper_load_r13_simple(struct cpu_state *cpu) {
    return cpu->r13;
}
#endif

// Stub debug functions (kept for link compatibility)
void helper_debug_r13_before_restore(void) {}
void helper_debug_r13_after_restore(void) {}
void helper_debug_r13_before_gret(uint64_t value, uint64_t next_gadget) { (void)value; (void)next_gadget; }
void helper_debug_before_gret_r13(struct cpu_state *cpu, void *ip, void *next_gadget, uint64_t r13_val) {
    (void)cpu; (void)ip; (void)next_gadget; (void)r13_val;
}
void helper_debug_div64_very_first(uint64_t xtmp_val, struct cpu_state *cpu) { (void)xtmp_val; (void)cpu; }
void helper_debug_div64_after_restore(uint64_t xtmp_val, struct cpu_state *cpu) { (void)xtmp_val; (void)cpu; }
void helper_debug_div64_after_str(uint64_t xtmp_val, struct cpu_state *cpu) { (void)xtmp_val; (void)cpu; }

static int div64_count = 0;

// Debug: trace address calculation for crash page
void helper_debug_addr_crash_page(uint64_t addr, uint64_t base_reg, uint64_t rip, const char *reg_name) {
    DEBUG_FPRINTF(stderr, "ADDR_CRASH_PAGE: addr=0x%llx base(%s)=0x%llx rip=0x%llx\n",
            (unsigned long long)addr, reg_name, (unsigned long long)base_reg,
            (unsigned long long)rip);
    fflush(stderr);
}

// Debug: trace load64_mem completion
static int load64_done_count = 0;
void helper_debug_load64_done(uint64_t value, uint64_t host_addr, uint64_t guest_addr) {
    (void)value; (void)host_addr; (void)guest_addr;
    load64_done_count++;
    // Disabled to reduce noise
}

void helper_debug_load64_after_restore(uint64_t xtmp, struct cpu_state *cpu, void *ip, void *orig_ip, void *next_gadget) {
    (void)xtmp; (void)cpu; (void)ip; (void)orig_ip; (void)next_gadget;
    // Disabled to reduce noise
}

// Debug: trace store64_a entry (the crashing gadget)
void helper_debug_store64_a_entry(uint64_t value, void *ip, void *next_gadget) {
    (void)value; (void)ip; (void)next_gadget;
    g_store64_a_entry_count++;
    // Disabled to reduce noise
}

// Debug: trace load64_a entry near crash
static int g_load64_a_entry_count = 0;
void helper_debug_load64_a_entry(uint64_t value, void *ip, void *next_gadget) {
    g_load64_a_entry_count++;
    if (load64_done_count > 11140) {
        DEBUG_FPRINTF(stderr, "LOAD64_A[%d]: value=0x%llx ip=%p next=%p\n",
                g_load64_a_entry_count, (unsigned long long)value, ip, next_gadget);
        fflush(stderr);
    }
}

// Debug: trace load64_a right before gret
void helper_debug_load64_a_before_gret(uint64_t xtmp, void *ip, void *next_gadget) {
    if (load64_done_count > 11140) {
        DEBUG_FPRINTF(stderr, "LOAD64_A_GRET[%d]: xtmp=0x%llx ip=%p next=%p\n",
                g_load64_a_entry_count, (unsigned long long)xtmp, ip, next_gadget);
        fflush(stderr);
    }
}

// Debug: trace save_xtmp_to_x8 entry
static int g_save_x8_entry_count = 0;
void helper_debug_save_xtmp_to_x8_entry(uint64_t xtmp, void *ip, void *next_gadget) {
    g_save_x8_entry_count++;
    if (load64_done_count > 11140) {
        DEBUG_FPRINTF(stderr, "SAVE_X8[%d]: xtmp=0x%llx ip=%p next=%p\n",
                g_save_x8_entry_count, (unsigned long long)xtmp, ip, next_gadget);
        fflush(stderr);
    }
}

// Debug: trace load64_r8 entry
static int g_load64_r8_entry_count = 0;
void helper_debug_load64_r8_entry(uint64_t r8_value, void *ip, void *next_gadget) {
    g_load64_r8_entry_count++;
    if (load64_done_count > 11140) {
        DEBUG_FPRINTF(stderr, "LOAD64_R8[%d]: r8=0x%llx ip=%p next=%p\n",
                g_load64_r8_entry_count, (unsigned long long)r8_value, ip, next_gadget);
        fflush(stderr);
    }
}

// Debug: trace mul32 entry
static int g_mul32_entry_count = 0;
void helper_debug_mul32_entry(uint64_t operand, uint32_t eax, void *ip, void *next_gadget) {
    g_mul32_entry_count++;
    if (load64_done_count > 11140) {
        DEBUG_FPRINTF(stderr, "MUL32[%d]: operand=0x%llx eax=0x%x ip=%p next=%p\n",
                g_mul32_entry_count, (unsigned long long)operand, eax, ip, next_gadget);
        fflush(stderr);
    }
}

// Debug: emit a marker string (for minimal tracing)
static int marker_count = 0;
void helper_debug_emit_marker(const char *marker) {
    marker_count++;
    if (marker_count > 1095) {  // Only trace near crash
        DEBUG_FPRINTF(stderr, "MARKER[%d]: %s\n", marker_count, marker);
        fflush(stderr);
    }
}

// Debug: trace CPU pointer value
void helper_debug_cpu_ptr(void *cpu) {
    if (marker_count > 1095) {
        DEBUG_FPRINTF(stderr, "CPU_PTR[%d]: cpu=%p\n", marker_count, cpu);
        fflush(stderr);
    }
}

#ifdef ISH_GUEST_64BIT
// Debug: trace entry to load64_r13
static int r13_entry_count = 0;
void helper_debug_load64_r13_entry(struct cpu_state *cpu) {
    r13_entry_count++;
    if (r13_entry_count > 1095) {  // Only trace after many calls
        DEBUG_FPRINTF(stderr, "LOAD64_R13_ENTRY[%d]: cpu=%p r13=0x%llx\n",
                r13_entry_count, (void*)cpu, (unsigned long long)cpu->r13);
        fflush(stderr);
    }
}

// Debug: trace step2 in load64_r13
void helper_debug_load64_r13_step2(struct cpu_state *cpu, uint64_t loaded_value) {
    if (r13_entry_count > 1095) {
        DEBUG_FPRINTF(stderr, "LOAD64_R13_STEP2[%d]: cpu=%p loaded=0x%llx\n",
                r13_entry_count, (void*)cpu, (unsigned long long)loaded_value);
        fflush(stderr);
    }
}

// Debug: trace step3 in load64_r13
void helper_debug_load64_r13_step3(uint64_t value) {
    if (r13_entry_count > 1095) {
        DEBUG_FPRINTF(stderr, "LOAD64_R13_STEP3[%d]: value=0x%llx\n",
                r13_entry_count, (unsigned long long)value);
        fflush(stderr);
    }
}
#endif

// Debug: trace div64 entry
// Note: div64_count defined earlier
void helper_debug_div64_entry(uint64_t rax, uint64_t rdx, uint64_t divisor) {
    div64_count++;
    // Always trace near crash
    DEBUG_FPRINTF(stderr, "DIV64_ENTRY[%d]: RAX=0x%llx RDX=0x%llx divisor=0x%llx\n",
            div64_count, (unsigned long long)rax, (unsigned long long)rdx,
            (unsigned long long)divisor);
    fflush(stderr);
}

// Debug: trace div64 division by zero
void helper_debug_div64_by_zero(uint64_t rax, uint64_t rdx) {
    DEBUG_FPRINTF(stderr, "DIV64_BY_ZERO: RAX=0x%llx RDX=0x%llx\n",
            (unsigned long long)rax, (unsigned long long)rdx);
    fflush(stderr);
}

// Debug: trace div64 result
void helper_debug_div64_result(uint64_t quotient, uint64_t remainder) {
    DEBUG_FPRINTF(stderr, "DIV64_RESULT: quotient=0x%llx remainder=0x%llx\n",
            (unsigned long long)quotient, (unsigned long long)remainder);
    fflush(stderr);
}

// Debug: trace ROL32 - verify rotation is correct
static int rol32_count = 0;
void helper_debug_rol32(uint32_t before, uint32_t after) {
    rol32_count++;
    if (rol32_count <= 50) {
        // Compute expected result
        uint32_t expected = (before << 1) | (before >> 31);
        DEBUG_FPRINTF(stderr, "ROL32[%d]: before=0x%08x after=0x%08x expected=0x%08x %s\n",
                rol32_count, before, after, expected,
                after == expected ? "OK" : "MISMATCH!");
    }
}

// Debug: trace XOR32_MEM
static int xor32_mem_count = 0;
void helper_debug_xor32_mem(uint32_t operand1, uint32_t memval, uint64_t addr) {
    xor32_mem_count++;
    (void)operand1; (void)memval; (void)addr;
    // Disabled - too verbose
}

// Debug: trace OR64_MEM - THIS IS LIKELY THE SOURCE OF THE FLAG CORRUPTION!
// The OR instruction was writing to option table memory without watchpoint checks
static int or64_mem_count = 0;

// Called BEFORE the OR to show what's in memory
void helper_debug_or64_mem_before(uint64_t mem_before, uint64_t guest_addr, uint64_t x8_operand) {
    or64_mem_count++;
    uint64_t offset = (guest_addr - 0x7efffff5b540) % 0x28;
    uint64_t entry = (guest_addr - 0x7efffff5b540) / 0x28;
    DEBUG_FPRINTF(stderr, "*** OR64_MEM_BEFORE[%d,entry=%lld,off=%lld]: addr=0x%llx mem_before=0x%llx x8=0x%llx\n",
            or64_mem_count, (long long)entry, (long long)offset,
            (unsigned long long)guest_addr, (unsigned long long)mem_before,
            (unsigned long long)x8_operand);
}

// Called AFTER the OR with the result
void helper_debug_or64_mem(uint64_t result, uint64_t guest_addr, uint64_t x8_operand) {
    // Use same count as before (incremented in _before)
    uint64_t offset = (guest_addr - 0x7efffff5b540) % 0x28;
    uint64_t entry = (guest_addr - 0x7efffff5b540) / 0x28;
    DEBUG_FPRINTF(stderr, "*** OR64_MEM_AFTER[%d,entry=%lld,off=%lld]: addr=0x%llx x8=0x%llx result=0x%llx\n",
            or64_mem_count, (long long)entry, (long long)offset,
            (unsigned long long)guest_addr, (unsigned long long)x8_operand,
            (unsigned long long)result);
}

// Debug: trace OR32_MEM (32-bit OR to memory)
static int or32_mem_count = 0;

void helper_debug_or32_mem_before(uint32_t mem_before, uint64_t guest_addr, uint32_t w8_operand) {
    or32_mem_count++;
    uint64_t offset = (guest_addr - 0x7efffff5b540) % 0x28;
    uint64_t entry = (guest_addr - 0x7efffff5b540) / 0x28;
    DEBUG_FPRINTF(stderr, "*** OR32_MEM_BEFORE[%d,entry=%lld,off=%lld]: addr=0x%llx mem_before=0x%x w8=0x%x\n",
            or32_mem_count, (long long)entry, (long long)offset,
            (unsigned long long)guest_addr, (unsigned)mem_before, (unsigned)w8_operand);
}

void helper_debug_or32_mem_after(uint32_t result, uint64_t guest_addr, uint32_t w8_operand) {
    uint64_t offset = (guest_addr - 0x7efffff5b540) % 0x28;
    uint64_t entry = (guest_addr - 0x7efffff5b540) / 0x28;
    DEBUG_FPRINTF(stderr, "*** OR32_MEM_AFTER[%d,entry=%lld,off=%lld]: addr=0x%llx w8=0x%x result=0x%x\n",
            or32_mem_count, (long long)entry, (long long)offset,
            (unsigned long long)guest_addr, (unsigned)w8_operand, (unsigned)result);
}

// Trace JNE decisions after strcmp CMP
void helper_debug_jne_strcmp(uint64_t ip, uint64_t zf_value) {
    // JNE at 0x591b5 in strcmp (interp + 0x591b5 = 0x7efffffb71b5)
    uint64_t jne_addr = 0x7efffff5e000 + 0x591b5;
    if (ip == jne_addr) {
        DEBUG_FPRINTF(stderr, "STRCMP_JNE: ip=0x%llx ZF=%llu (should jump if ZF=0)\n",
                (unsigned long long)ip, (unsigned long long)zf_value);
    }
}

// Debug: trace MOVDQU/MOVUPS load (128-bit load from memory to XMM)
// This is crucial for va_list copying in vasprintf
void helper_debug_movdqu_load(uint64_t low, uint64_t high, uint64_t guest_addr) {
    static int count = 0;
    count++;
    if (count <= 30) {
        // Parse va_list structure: gp_offset(4) + fp_offset(4) + overflow_arg_area(8)
        uint32_t gp_offset = (uint32_t)(low & 0xFFFFFFFF);
        uint32_t fp_offset = (uint32_t)((low >> 32) & 0xFFFFFFFF);
        DEBUG_FPRINTF(stderr, "MOVDQU_LOAD[%d]: addr=0x%llx low=0x%llx high=0x%llx\n",
                count, (unsigned long long)guest_addr,
                (unsigned long long)low, (unsigned long long)high);
        DEBUG_FPRINTF(stderr, "  -> gp_offset=%u fp_offset=%u overflow_area=0x%llx\n",
                gp_offset, fp_offset, (unsigned long long)high);
    }
}

// Debug: trace entry to movaps_load gadget
void helper_debug_movaps_load_entry(uint64_t guest_addr) {
    static int count = 0;
    count++;
    if (count <= 30) {
        DEBUG_FPRINTF(stderr, "MOVAPS_LOAD_ENTRY[%d]: guest_addr=0x%llx\n",
                count, (unsigned long long)guest_addr);
    }
}

// Debug: trace complete movaps_load - values and destination
void helper_debug_movaps_load_full(uint64_t guest_addr, uint64_t low, uint64_t high, uint64_t xmm_idx) {
    static int count = 0;
    count++;
    // Unconditionally print first 50 for debugging
    if (count <= 50) {
        fprintf(stderr, "MOVAPS_LOAD[%d]: from=0x%llx low=0x%llx high=0x%llx -> xmm%llu\n",
                count, (unsigned long long)guest_addr,
                (unsigned long long)low, (unsigned long long)high,
                (unsigned long long)xmm_idx);
    }
}

// Debug: trace movaps_store - what's being written
void helper_debug_movaps_store_full(uint64_t guest_addr, uint64_t low, uint64_t high, uint64_t xmm_idx) {
    static int count = 0;
    count++;
    if (count <= 50) {
        fprintf(stderr, "MOVAPS_STORE[%d]: xmm%llu -> 0x%llx low=0x%llx high=0x%llx\n",
                count, (unsigned long long)xmm_idx,
                (unsigned long long)guest_addr,
                (unsigned long long)low, (unsigned long long)high);
    }
}

// Debug: trace stores to xasprintf's va_list area (around 0x7efffff5bbd0-0x7efffff5bbe8)
// This should catch va_start setup
// Returns possibly-fixed value
uint32_t helper_debug_va_list_store32(uint32_t value, uint64_t guest_addr) {
    // Just pass through - xasprintf's gp_offset=8 is correct (1 named param)
    (void)guest_addr;
    return value;
}

void helper_debug_va_list_store64(uint64_t value, uint64_t guest_addr) {
    // Disabled for now
    (void)value;
    (void)guest_addr;
}

// Execution counter - called on basic block transitions to detect infinite loops
static int exec_counter = 0;
static int trace_enabled = 0;
static int trace_print_count = 0;

void helper_exec_trace(uint64_t rip) {
    exec_counter++;
    // Print first 50 executions after trace is enabled (syscall 8)
    if (trace_enabled && trace_print_count < 50) {
        trace_print_count++;
        fprintf(stderr, "EXEC[%d]: rip=0x%llx\n", exec_counter, (unsigned long long)rip);
        fflush(stderr);
    }
    // After 1000000 executions, print to detect infinite loops
    if (exec_counter == 1000000) {
        fprintf(stderr, "EXEC: reached 1M executions at rip=0x%llx, likely infinite loop\n",
                (unsigned long long)rip);
        fflush(stderr);
    }
}

// Called after syscall 8 (getuid) to enable per-instruction tracing
void helper_enable_exec_trace(void) {
    fprintf(stderr, "EXEC: Enabling trace after syscall 8 (counter=%d)\n", exec_counter);
    fflush(stderr);
    trace_enabled = 1;
}
