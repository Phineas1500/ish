#include "gadgets.h"
#include "emu/interrupt.h"

// Miscellaneous operations for 64-bit

// NOP - do nothing
.gadget nop
    gret

// CPUID - handled by helper
// Must save_regs first so helper can read cpu->rax (leaf number) from memory
.gadget cpuid
    save_regs
    save_c
    mov x0, _cpu
    bl NAME(helper_cpuid)
    restore_c
    load_regs
    gret

// RDTSC - Read Time-Stamp Counter
// Writes low 32 bits of TSC to EAX (zero-extended to RAX), high 32 bits to EDX (zero-extended to RDX)
.gadget rdtsc
    save_regs
    save_c
    mov x0, _cpu
    bl NAME(helper_rdtsc)
    restore_c
    load_regs
    gret

// CMPXCHG [mem], reg - Compare and exchange
// _addr = memory address to compare/exchange
// _xtmp = register value to store if comparison succeeds
// Compares [_addr] with RAX/EAX, if equal stores _xtmp to [_addr], else loads [_addr] to RAX
// Sets ZF based on comparison result

// 64-bit CMPXCHG
// Note: _addr contains guest address, we save it before read_prep modifies it
.gadget cmpxchg64_mem
    str _addr, [_cpu, LOCAL_value_addr]  // Save guest address
    read_prep 64, cmpxchg64_read
    ldr x8, [_addr]           // Load memory value from host address
    cmp x8, rax               // Compare with RAX
    b.ne 1f
    // Equal: store _xtmp to memory, set ZF
    ldr _addr, [_cpu, LOCAL_value_addr]  // Restore guest address for write_prep
    write_prep 64, cmpxchg64_write
    str _xtmp, [_addr]
    write_done 64, cmpxchg64_write
    // Set ZF=1 (result is 0 for flags)
    str xzr, [_cpu, CPU_res]
    ldr w9, [_cpu, CPU_flags_res]
    orr w9, w9, ZF_RES
    str w9, [_cpu, CPU_flags_res]
    gret 1
1:  // Not equal: load memory to RAX, clear ZF
    mov rax, x8               // RAX = memory value
    // Set ZF=0 (result is non-zero for flags)
    mov x9, 1
    str x9, [_cpu, CPU_res]
    ldr w9, [_cpu, CPU_flags_res]
    orr w9, w9, ZF_RES
    str w9, [_cpu, CPU_flags_res]
    gret 1
    read_bullshit 64, cmpxchg64_read
    write_bullshit 64, cmpxchg64_write

// 32-bit CMPXCHG
// Note: _addr contains guest address, we save it before read_prep modifies it
.gadget cmpxchg32_mem
    str _addr, [_cpu, LOCAL_value_addr]  // Save guest address
    read_prep 32, cmpxchg32_read
    ldr w8, [_addr]           // Load memory value (32-bit) from host address
    cmp w8, eax               // Compare with EAX
    b.ne 1f
    // Equal: store _tmp to memory, set ZF
    ldr _addr, [_cpu, LOCAL_value_addr]  // Restore guest address for write_prep
    write_prep 32, cmpxchg32_write
    str _tmp, [_addr]
    write_done 32, cmpxchg32_write
    // Set ZF=1 (result is 0 for flags)
    str xzr, [_cpu, CPU_res]
    ldr w9, [_cpu, CPU_flags_res]
    orr w9, w9, ZF_RES
    str w9, [_cpu, CPU_flags_res]
    gret 1
1:  // Not equal: load memory to EAX, clear ZF
    mov eax, w8               // EAX = memory value (zero-extends)
    // Set ZF=0 (result is non-zero for flags)
    mov x9, 1
    str x9, [_cpu, CPU_res]
    ldr w9, [_cpu, CPU_flags_res]
    orr w9, w9, ZF_RES
    str w9, [_cpu, CPU_flags_res]
    gret 1
    read_bullshit 32, cmpxchg32_read
    write_bullshit 32, cmpxchg32_write

// LOCK CMPXCHG - Atomic compare and exchange using ARM64 LSE atomics
// Uses write_prep to get host address with write permission, then casal for atomic CAS
// For crosspage accesses, falls through to non-atomic (crosspage atomics are pathological)

// 64-bit atomic CMPXCHG
// Uses write_prep to get writable host address, then casal for atomic CAS
// For crosspage (LOCAL_value buffer), falls back to non-atomic
.gadget lock_cmpxchg64_mem
    write_prep 64, lcmpxchg64
    // _addr = host address (writable), _xtmp = desired, rax = expected
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq lcmpxchg64_cross
    // Atomic CAS on host memory
    mov x9, rax               // x9 = expected (casal overwrites with old value)
    casal x9, _xtmp, [_addr]  // atomic: if [_addr]==x9 store _xtmp; x9 = old
    cmp x9, rax
    b.ne lcmpxchg64_fail
    // CAS succeeded: write_done needed (we wrote), then ZF=1
    write_done 64, lcmpxchg64
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg64_fail:
    // CAS failed: RAX = old value, ZF=0
    mov rax, x9
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg64_cross:
    // Crosspage fallback (non-atomic, data in LOCAL_value buffer)
    ldr x8, [_addr]
    cmp x8, rax
    b.ne lcmpxchg64_cross_fail
    str _xtmp, [_addr]
    // Jump to write_done (reuse the one label from the main path)
    b back_write_done_lcmpxchg64
lcmpxchg64_cross_fail:
    mov rax, x8
    b lcmpxchg64_fail
    write_bullshit 64, lcmpxchg64

// 32-bit atomic CMPXCHG
.gadget lock_cmpxchg32_mem
    write_prep 32, lcmpxchg32
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq lcmpxchg32_cross
    mov w9, eax
    casal w9, _tmp, [_addr]   // atomic 32-bit CAS
    cmp w9, eax
    b.ne lcmpxchg32_fail
    write_done 32, lcmpxchg32
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg32_fail:
    mov eax, w9
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg32_cross:
    ldr w8, [_addr]
    cmp w8, eax
    b.ne lcmpxchg32_cross_fail
    str _tmp, [_addr]
    b back_write_done_lcmpxchg32
lcmpxchg32_cross_fail:
    mov eax, w8
    b lcmpxchg32_fail
    write_bullshit 32, lcmpxchg32

// XCHG reg, [mem] - Exchange register with memory
// _addr = memory address
// _xtmp = register value to swap

// 64-bit XCHG
.gadget xchg64_mem
    str _addr, [_cpu, LOCAL_value_addr]  // Save guest address
    read_prep 64, xchg64_read
    ldr x8, [_addr]           // Load memory value
    str x8, [_cpu, LOCAL_value]  // Save memory value temporarily
    ldr _addr, [_cpu, LOCAL_value_addr]  // Restore guest address for write_prep
    write_prep 64, xchg64_write
    str _xtmp, [_addr]        // Store register value to memory
    write_done 64, xchg64_write
    ldr _xtmp, [_cpu, LOCAL_value]  // Load old memory value into _xtmp (for storing to reg)
    gret 1
    read_bullshit 64, xchg64_read
    write_bullshit 64, xchg64_write

// 32-bit XCHG
.gadget xchg32_mem
    str _addr, [_cpu, LOCAL_value_addr]  // Save guest address
    read_prep 32, xchg32_read
    ldr w8, [_addr]           // Load memory value (32-bit)
    str w8, [_cpu, LOCAL_value]  // Save memory value temporarily
    ldr _addr, [_cpu, LOCAL_value_addr]  // Restore guest address for write_prep
    write_prep 32, xchg32_write
    str _tmp, [_addr]         // Store register value to memory (32-bit)
    write_done 32, xchg32_write
    ldr _tmp, [_cpu, LOCAL_value]  // Load old memory value into _tmp (for storing to reg)
    gret 1
    read_bullshit 32, xchg32_read
    write_bullshit 32, xchg32_write

// Helper gadgets
.gadget helper_0
    save_c
    ldr x8, [_ip]
    mov x0, _cpu
    blr x8
    restore_c
    gret 1

.gadget helper_1
    save_c
    ldr x8, [_ip]
    mov x0, _cpu
    ldr x1, [_ip, 8]
    blr x8
    restore_c
    gret 2

.gadget helper_2
    save_c
    ldr x8, [_ip]
    mov x0, _cpu
    ldr x1, [_ip, 8]
    ldr x2, [_ip, 16]
    blr x8
    restore_c
    gret 3

// Placeholder gadget arrays
.pushsection_rodata
.global.name mul_gadgets
    .fill 15, 8, 0
.global.name imul1_gadgets
    .fill 15, 8, 0
.global.name div_gadgets
    .fill 15, 8, 0
.global.name idiv_gadgets
    .fill 15, 8, 0
.global.name cvt_gadgets
    .fill 15, 8, 0
.global.name cvte_gadgets
    .fill 15, 8, 0
.global.name inc_gadgets
    .fill 15, 8, 0
.global.name dec_gadgets
    .fill 15, 8, 0
.global.name cmpxchg_gadgets
    .fill 60, 8, 0
.global.name xadd_gadgets
    .fill 60, 8, 0
.global.name atomic_add_gadgets
    .fill 60, 8, 0
.global.name atomic_sub_gadgets
    .fill 60, 8, 0
.global.name atomic_and_gadgets
    .fill 60, 8, 0
.global.name atomic_or_gadgets
    .fill 60, 8, 0
.global.name atomic_xor_gadgets
    .fill 60, 8, 0
.global.name atomic_inc_gadgets
    .fill 60, 8, 0
.global.name atomic_dec_gadgets
    .fill 60, 8, 0
.global.name atomic_cmpxchg_gadgets
    .fill 60, 8, 0
.global.name atomic_xadd_gadgets
    .fill 60, 8, 0
.global.name atomic_btc_gadgets
    .fill 60, 8, 0
.global.name atomic_bts_gadgets
    .fill 60, 8, 0
.global.name atomic_btr_gadgets
    .fill 60, 8, 0
.global.name imul_gadgets
    .fill 60, 8, 0
.global.name bsf_gadgets
    .fill 60, 8, 0
.global.name bsr_gadgets
    .fill 60, 8, 0
.global.name adc_gadgets
    .fill 60, 8, 0
.global.name sbb_gadgets
    .fill 60, 8, 0
.global.name shld_cl_gadgets
    .fill 60, 8, 0
.global.name shld_imm_gadgets
    .fill 60, 8, 0
.global.name shrd_cl_gadgets
    .fill 60, 8, 0
.global.name shrd_imm_gadgets
    .fill 60, 8, 0
.global.name xchg_gadgets
    .fill 60, 8, 0
.popsection

// Debug gadget: dump all registers to stderr
// Called with no arguments
.gadget debug_regs
    save_regs
    save_c
    mov x0, _cpu
    ldr x1, [_ip]        // Load the guest IP argument
    bl NAME(debug_dump_regs)
    restore_c
    load_regs
    gret 1                // Skip past the guest IP argument

// TRACE: dump all registers (called from generated code at specific IPs)
.gadget trace_regs
    save_regs
    save_c
    mov x0, _cpu
    ldr x1, [_ip]       // Load the guest IP argument
    bl NAME(helper_trace_regs)
    restore_c
    load_regs
    gret 1
