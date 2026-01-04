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
