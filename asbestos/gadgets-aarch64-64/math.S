#include "gadgets.h"
#include "math.h"

// Load address into temp register
.gadget load64_addr
    mov _xtmp, _addr
    gret

.gadget load32_addr
    mov _tmp, _waddr
    gret

// ============================================================
// Load gadgets - load value into _tmp/_xtmp
// ============================================================

// Load from registers (rax-rdi kept in ARM64 regs)
.macro load_reg64 name, reg64, reg32
    .gadget load64_\name
        mov _xtmp, \reg64
        gret
    .gadget load32_\name
        mov _xtmp, \reg64
        and _xtmp, _xtmp, 0xffffffff
        gret
.endm
.each_reg64 load_reg64
.purgem load_reg64

// Load immediate
.gadget load64_imm
    ldr _xtmp, [_ip]
    gret 1

.gadget load32_imm
    ldr _tmp, [_ip]
    gret 1

// Load from memory
.gadget load64_mem
    read_prep 64, load64_mem
    ldr _xtmp, [_addr]
    gret 1
    read_bullshit 64, load64_mem

.gadget load32_mem
    read_prep 32, load32_mem
    ldr _tmp, [_addr]
    gret 1
    read_bullshit 32, load32_mem

// Load 16-bit from memory (zero-extended)
.gadget load16_mem
    read_prep 16, load16_mem
    ldrh _tmp, [_addr]
    gret 1
    read_bullshit 16, load16_mem

// Load 8-bit from memory (zero-extended)
.gadget load8_mem
    read_prep 8, load8_mem
    ldrb _tmp, [_addr]
    gret 1
    read_bullshit 8, load8_mem

// Load from r8-r15 (stored in memory, not ARM64 registers)
.gadget load64_r8
    ldr _xtmp, [_cpu, CPU_r8]
    gret

.gadget load64_r9
    ldr _xtmp, [_cpu, CPU_r9]
    gret

.gadget load64_r10
    ldr _xtmp, [_cpu, CPU_r10]
    gret

.gadget load64_r11
    ldr _xtmp, [_cpu, CPU_r11]
    gret

.gadget load64_r12
    ldr _xtmp, [_cpu, CPU_r12]
    gret

.gadget load64_r13
    ldr _xtmp, [_cpu, CPU_r13]
    gret

.gadget load64_r14
    ldr _xtmp, [_cpu, CPU_r14]
    gret

.gadget load64_r15
    ldr _xtmp, [_cpu, CPU_r15]
    gret

// ============================================================
// Store gadgets - store value from _tmp/_xtmp
// ============================================================

// Store to registers
.macro store_reg64 name, reg64, reg32
    .gadget store64_\name
        mov \reg64, _xtmp
        gret
    .gadget store32_\name
        // 32-bit write zero-extends to 64-bit in x86_64
        mov \reg64, _xtmp
        and \reg64, \reg64, 0xffffffff
        gret
.endm
.each_reg64 store_reg64
.purgem store_reg64

// Store to memory
.gadget store64_mem
    write_prep 64, store64_mem
    str _xtmp, [_addr]
    write_done 64, store64_mem
    gret 1
    write_bullshit 64, store64_mem

.gadget store32_mem
    write_prep 32, store32_mem
    str _tmp, [_addr]
    write_done 32, store32_mem
    gret 1
    write_bullshit 32, store32_mem

// Store to r8-r15 (stored in memory, not ARM64 registers)
.gadget store64_r8
    str _xtmp, [_cpu, CPU_r8]
    gret

.gadget store64_r9
    str _xtmp, [_cpu, CPU_r9]
    gret

.gadget store64_r10
    str _xtmp, [_cpu, CPU_r10]
    gret

.gadget store64_r11
    str _xtmp, [_cpu, CPU_r11]
    gret

.gadget store64_r12
    str _xtmp, [_cpu, CPU_r12]
    gret

.gadget store64_r13
    str _xtmp, [_cpu, CPU_r13]
    gret

.gadget store64_r14
    str _xtmp, [_cpu, CPU_r14]
    gret

.gadget store64_r15
    str _xtmp, [_cpu, CPU_r15]
    gret

// ============================================================
// ADD gadgets
// ============================================================

.macro add_reg64 name, reg64, reg32
    .gadget add64_\name
        adds _xtmp, _xtmp, \reg64
        setf_oc
        setf_zsp
        gret
    .gadget add32_\name
        adds _tmp, _tmp, \reg32
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 add_reg64
.purgem add_reg64

.gadget add64_imm
    ldr x8, [_ip]
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1

.gadget add32_imm
    ldr w8, [_ip]
    adds _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1

.gadget add64_mem
    read_prep 64, add64_mem
    ldr x8, [_addr]
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1
    read_bullshit 64, add64_mem

.gadget add32_mem
    read_prep 32, add32_mem
    ldr w8, [_addr]
    adds _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, add32_mem

// ADD with x8 (for adding r8-r15 which are loaded into x8)
.gadget add64_x8
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret

// ============================================================
// SUB gadgets
// ============================================================

.macro sub_reg64 name, reg64, reg32
    .gadget sub64_\name
        subs _xtmp, _xtmp, \reg64
        setf_oc
        setf_zsp
        gret
    .gadget sub32_\name
        subs _tmp, _tmp, \reg32
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 sub_reg64
.purgem sub_reg64

.gadget sub64_imm
    ldr x8, [_ip]
    subs _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1

.gadget sub32_imm
    ldr w8, [_ip]
    subs _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1

.gadget sub64_mem
    read_prep 64, sub64_mem
    ldr x8, [_addr]
    subs _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1
    read_bullshit 64, sub64_mem

// SUB with x8 (for subtracting r8-r15 which are loaded into x8)
// Note: SUB dst, r8 means dst = dst - r8, but we have x8=dst, _xtmp=r8
// So we need: result = dst - r8 = x8 - _xtmp
.gadget sub64_x8
    subs _xtmp, x8, _xtmp
    setf_oc
    setf_zsp
    gret

.gadget sub32_mem
    read_prep 32, sub32_mem
    ldr w8, [_addr]
    subs _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, sub32_mem

// ============================================================
// XOR gadget (needed for xor rax, rax - common idiom)
// ============================================================

.macro xor_reg64 name, reg64, reg32
    .gadget xor64_\name
        eor _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
    .gadget xor32_\name
        eor _tmp, _tmp, \reg32
        clearf_oc
        setf_zsp w
        gret
.endm
.each_reg64 xor_reg64
.purgem xor_reg64

.gadget xor64_imm
    ldr x8, [_ip]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

.gadget xor32_imm
    ldr w8, [_ip]
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1

// ============================================================
// AND gadgets
// ============================================================

.gadget and64_imm
    ldr x8, [_ip]
    ands _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

.gadget and32_imm
    ldr w8, [_ip]
    ands _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1

// AND with register (x8 contains value to AND)
.gadget and64_x8
    ands _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret

// AND memory operand (read from _addr, AND with value in x8)
.gadget and64_mem
    read_prep 64, and64_mem
    ldr x9, [_addr]
    ands x9, x9, x8
    str x9, [_addr]
    clearf_oc
    mov _xtmp, x9
    setf_zsp
    gret 1
    read_bullshit 64, and64_mem

// ============================================================
// OR gadgets
// ============================================================

.gadget or64_imm
    ldr x8, [_ip]
    orr _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

.gadget or32_imm
    ldr w8, [_ip]
    orr _tmp, _tmp, w8
    and _xtmp, _xtmp, 0xffffffff
    clearf_oc
    setf_zsp w
    gret 1

// OR with register (x8 contains value to OR)
.gadget or64_x8
    orr _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret

// OR with register (for reg, reg - xtmp = xtmp | other_reg)
.macro or_reg64 name, reg64, reg32
    .gadget or64_\name
        orr _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
.endm
.each_reg64 or_reg64
.purgem or_reg64

// OR memory operand (read from _addr, OR with value in x8)
.gadget or64_mem
    read_prep 64, or64_mem
    ldr x9, [_addr]
    orr x9, x9, x8
    str x9, [_addr]
    clearf_oc
    mov _xtmp, x9
    setf_zsp
    gret 1
    read_bullshit 64, or64_mem

// ============================================================
// CMP gadgets (compare without storing)
// ============================================================

.gadget cmp64_imm
    ldr x8, [_ip]
    subs x9, _xtmp, x8    // Save result for flags (don't discard)
    setf_oc
    setf_zsp , x9         // Use the subtraction result for ZF/SF/PF
    gret 1

.gadget cmp32_imm
    ldr w8, [_ip]
    subs w9, _tmp, w8     // Save result for flags
    setf_oc
    setf_zsp w, x9        // Use the subtraction result
    gret 1

// CMP with register (index passed as immediate)
.gadget cmp64_reg
    // Load register index
    ldr x8, [_ip]
    // This is a bit hacky - we need to compare with a register by index
    // For now, use a switch-like approach via computed jump
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to rdi
    subs x9, _xtmp, rdi
    b 9f
1:  subs x9, _xtmp, rax
    b 9f
2:  subs x9, _xtmp, rcx
    b 9f
3:  subs x9, _xtmp, rdx
    b 9f
4:  subs x9, _xtmp, rbx
    b 9f
5:  subs x9, _xtmp, rsp
    b 9f
6:  subs x9, _xtmp, rbp
    b 9f
7:  subs x9, _xtmp, rsi
    b 9f
9:  setf_oc
    setf_zsp , x9
    gret 1

// ============================================================
// TEST gadgets (AND without storing, sets flags)
// ============================================================

.gadget test64_imm
    ldr x8, [_ip]
    ands x9, _xtmp, x8     // Save AND result for flags
    clearf_oc
    setf_zsp , x9
    gret 1

.gadget test32_imm
    ldr w8, [_ip]
    ands w9, _tmp, w8      // Save AND result for flags
    clearf_oc
    setf_zsp w, x9
    gret 1

// ============================================================
// Shift gadgets
// ============================================================

// SHR (logical shift right) - shift by immediate 1
.gadget shr64_one
    // Get MSB for OF flag (set if sign bit changed)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Get LSB (will become CF after shift)
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // Do the shift
    lsr _xtmp, _xtmp, 1
    setf_zsp
    gret

// SHR by CL (shift count in RCX)
.gadget shr64_cl
    ands w8, ecx, 63
    b.eq 1f
    // Save MSB for OF (only meaningful if shift is 1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w8, w8, 1
    lsr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    lsr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// SHR by immediate
.gadget shr64_imm
    ldr w8, [_ip]
    ands w8, w8, 63
    b.eq 1f
    // Save MSB for OF
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w8, w8, 1
    lsr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    lsr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// SHL (logical shift left) - shift by immediate 1
.gadget shl64_one
    // Shift by 1, check old MSB for CF
    lsr x8, _xtmp, 63
    lsl _xtmp, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF = CF XOR new MSB
    lsr x9, _xtmp, 63
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// SHL by CL
.gadget shl64_cl
    ands w8, ecx, 63
    b.eq 1f
    sub w8, w8, 1
    lsl _xtmp, _xtmp, x8
    // Get bit that will become CF
    lsr x9, _xtmp, 63
    // Shift one more
    lsl _xtmp, _xtmp, 1
    // CF = old MSB, OF = CF XOR new MSB
    lsr x10, _xtmp, 63
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp
1:  gret

// SHL by immediate
.gadget shl64_imm
    ldr w8, [_ip]
    ands w8, w8, 63
    b.eq 1f
    sub w8, w8, 1
    lsl _xtmp, _xtmp, x8
    lsr x9, _xtmp, 63
    lsl _xtmp, _xtmp, 1
    lsr x10, _xtmp, 63
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp
1:  gret 1

// SAR (arithmetic shift right) - shift by immediate 1
.gadget sar64_one
    // Get LSB for CF
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF is always 0 for SAR by 1
    strb wzr, [_cpu, CPU_of]
    // Do the arithmetic shift
    asr _xtmp, _xtmp, 1
    setf_zsp
    gret

// SAR by CL
.gadget sar64_cl
    ands w8, ecx, 63
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w8, w8, 1
    asr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    asr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// SAR by immediate
.gadget sar64_imm
    ldr w8, [_ip]
    ands w8, w8, 63
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w8, w8, 1
    asr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    asr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ============================================================
// Zero/Sign extend gadgets
// ============================================================

.gadget zero_extend8
    and _xtmp, _xtmp, 0xff
    gret

.gadget zero_extend16
    and _xtmp, _xtmp, 0xffff
    gret

.gadget zero_extend32
    and _xtmp, _xtmp, 0xffffffff
    gret

.gadget sign_extend8
    sxtb _xtmp, _tmp
    gret

.gadget sign_extend16
    sxth _xtmp, _tmp
    gret

.gadget sign_extend32
    sxtw _xtmp, _tmp
    gret

// ============================================================
// Gadget arrays for the generator
// ============================================================

.pushsection_rodata

// Gadget arrays - order matches x86 register encoding: a, c, d, b, sp, bp, si, di
// Then: imm, mem, addr, gs

// 64-bit load gadgets
.align 3
.global.name load64_gadgets
    .quad NAME(gadget_load64_a)
    .quad NAME(gadget_load64_c)
    .quad NAME(gadget_load64_d)
    .quad NAME(gadget_load64_b)
    .quad NAME(gadget_load64_sp)
    .quad NAME(gadget_load64_bp)
    .quad NAME(gadget_load64_si)
    .quad NAME(gadget_load64_di)
    .quad NAME(gadget_load64_imm)
    .quad NAME(gadget_load64_mem)
    .quad NAME(gadget_load64_addr)
    .quad 0  // gs

// 64-bit store gadgets
.align 3
.global.name store64_gadgets
    .quad NAME(gadget_store64_a)
    .quad NAME(gadget_store64_c)
    .quad NAME(gadget_store64_d)
    .quad NAME(gadget_store64_b)
    .quad NAME(gadget_store64_sp)
    .quad NAME(gadget_store64_bp)
    .quad NAME(gadget_store64_si)
    .quad NAME(gadget_store64_di)
    .quad 0  // imm
    .quad NAME(gadget_store64_mem)
    .quad 0  // addr
    .quad 0  // gs

// 32-bit load gadgets (for compatibility)
.align 3
.global.name load32_gadgets
    .quad NAME(gadget_load32_a)
    .quad NAME(gadget_load32_c)
    .quad NAME(gadget_load32_d)
    .quad NAME(gadget_load32_b)
    .quad NAME(gadget_load32_sp)
    .quad NAME(gadget_load32_bp)
    .quad NAME(gadget_load32_si)
    .quad NAME(gadget_load32_di)
    .quad NAME(gadget_load32_imm)
    .quad NAME(gadget_load32_mem)
    .quad NAME(gadget_load32_addr)
    .quad 0  // gs

// 32-bit store gadgets
.align 3
.global.name store32_gadgets
    .quad NAME(gadget_store32_a)
    .quad NAME(gadget_store32_c)
    .quad NAME(gadget_store32_d)
    .quad NAME(gadget_store32_b)
    .quad NAME(gadget_store32_sp)
    .quad NAME(gadget_store32_bp)
    .quad NAME(gadget_store32_si)
    .quad NAME(gadget_store32_di)
    .quad 0  // imm
    .quad NAME(gadget_store32_mem)
    .quad 0  // addr
    .quad 0  // gs

.popsection
