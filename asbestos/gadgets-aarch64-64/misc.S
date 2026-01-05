#include "gadgets.h"
#include "emu/interrupt.h"

// Miscellaneous operations for 64-bit

// NOP - do nothing
.gadget nop
    gret

// CPUID - handled by helper
.gadget cpuid
    save_c
    mov x0, _cpu
    bl NAME(helper_cpuid)
    restore_c
    // Reload registers that might have changed
    ldr rax, [_cpu, CPU_rax]
    ldr rbx, [_cpu, CPU_rbx]
    ldr rcx, [_cpu, CPU_rcx]
    ldr rdx, [_cpu, CPU_rdx]
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
