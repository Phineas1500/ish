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

// 16-bit CMPXCHG
// Compare AX with [mem16], store src16 on match, else load mem16 into AX.
.gadget cmpxchg16_mem
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 16, cmpxchg16_read
    ldrh w8, [_addr]
    uxth w9, eax
    cmp w8, w9
    b.ne 1f
    // Equal: store source low16, set ZF=1
    ldr _addr, [_cpu, LOCAL_value_addr]
    write_prep 16, cmpxchg16_write
    strh _tmp, [_addr]
    write_done 16, cmpxchg16_write
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
1:  // Not equal: AX = mem16 (upper 48 bits preserved), set ZF=0
    bfxil rax, x8, 0, 16
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
    read_bullshit 16, cmpxchg16_read
    write_bullshit 16, cmpxchg16_write

// 8-bit CMPXCHG
// Compare AL with [mem8], store src8 on match, else load mem8 into AL.
.gadget cmpxchg8_mem
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 8, cmpxchg8_read
    ldrb w8, [_addr]
    uxtb w9, eax
    cmp w8, w9
    b.ne 1f
    // Equal: store source low8, set ZF=1
    ldr _addr, [_cpu, LOCAL_value_addr]
    write_prep 8, cmpxchg8_write
    strb _tmp, [_addr]
    write_done 8, cmpxchg8_write
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
1:  // Not equal: AL = mem8 (upper 56 bits preserved), set ZF=0
    bfxil rax, x8, 0, 8
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
    read_bullshit 8, cmpxchg8_read
    write_bullshit 8, cmpxchg8_write

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

// 16-bit atomic CMPXCHG
.gadget lock_cmpxchg16_mem
    write_prep 16, lcmpxchg16
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq lcmpxchg16_cross
    uxth w12, eax
    mov w9, w12
    uxth w10, _tmp
    casalh w9, w10, [_addr]   // atomic 16-bit CAS
    cmp w9, w12
    b.ne lcmpxchg16_fail
    write_done 16, lcmpxchg16
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg16_fail:
    bfxil rax, x9, 0, 16
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg16_cross:
    ldrh w8, [_addr]
    uxth w12, eax
    cmp w8, w12
    b.ne lcmpxchg16_cross_fail
    uxth w10, _tmp
    strh w10, [_addr]
    b back_write_done_lcmpxchg16
lcmpxchg16_cross_fail:
    mov w9, w8
    b lcmpxchg16_fail
    write_bullshit 16, lcmpxchg16

// 8-bit atomic CMPXCHG
.gadget lock_cmpxchg8_mem
    write_prep 8, lcmpxchg8
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq lcmpxchg8_cross
    uxtb w12, eax
    mov w9, w12
    uxtb w10, _tmp
    casalb w9, w10, [_addr]   // atomic 8-bit CAS
    cmp w9, w12
    b.ne lcmpxchg8_fail
    write_done 8, lcmpxchg8
    str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg8_fail:
    bfxil rax, x9, 0, 8
    mov x10, 1
    str x10, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret 1
lcmpxchg8_cross:
    ldrb w8, [_addr]
    uxtb w12, eax
    cmp w8, w12
    b.ne lcmpxchg8_cross_fail
    uxtb w10, _tmp
    strb w10, [_addr]
    b back_write_done_lcmpxchg8
lcmpxchg8_cross_fail:
    mov w9, w8
    b lcmpxchg8_fail
    write_bullshit 8, lcmpxchg8

// XCHG reg, [mem] - Exchange register with memory (implicit LOCK on x86)
// _addr = memory address
// _xtmp = register value to swap in

// 64-bit XCHG (atomic on non-crosspage)
.gadget xchg64_mem
    write_prep 64, xchg64
    mov x9, _xtmp
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq xchg64_cross
    swpal x9, _xtmp, [_addr]      // _xtmp = old memory, memory = x9
    b 1f
xchg64_cross:
    ldr x8, [_addr]
    str x9, [_addr]
    mov _xtmp, x8
1:
    write_done 64, xchg64
    gret 1
    write_bullshit 64, xchg64

// 32-bit XCHG (atomic on non-crosspage)
.gadget xchg32_mem
    write_prep 32, xchg32
    mov w9, _tmp
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq xchg32_cross
    swpal w9, _tmp, [_addr]       // _tmp = old memory, memory = w9
    b 1f
xchg32_cross:
    ldr w8, [_addr]
    str w9, [_addr]
    mov _tmp, w8
1:
    write_done 32, xchg32
    gret 1
    write_bullshit 32, xchg32

// 16-bit XCHG (atomic on non-crosspage)
.gadget xchg16_mem
    write_prep 16, xchg16
    uxth w9, _tmp
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq xchg16_cross
    swpalh w9, w8, [_addr]        // w8 = old memory, memory = low16(w9)
    mov _tmp, w8
    b 1f
xchg16_cross:
    ldrh w8, [_addr]
    strh w9, [_addr]
    mov _tmp, w8
1:
    write_done 16, xchg16
    gret 1
    write_bullshit 16, xchg16

// 8-bit XCHG (atomic on non-crosspage)
.gadget xchg8_mem
    write_prep 8, xchg8
    uxtb w9, _tmp
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq xchg8_cross
    swpalb w9, w8, [_addr]        // w8 = old memory, memory = low8(w9)
    mov _tmp, w8
    b 1f
xchg8_cross:
    ldrb w8, [_addr]
    strb w9, [_addr]
    mov _tmp, w8
1:
    write_done 8, xchg8
    gret 1
    write_bullshit 8, xchg8

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
