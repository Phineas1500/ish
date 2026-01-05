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

.gadget store16_mem
    write_prep 16, store16_mem
    strh _tmp, [_addr]
    write_done 16, store16_mem
    gret 1
    write_bullshit 16, store16_mem

.gadget store8_mem
    write_prep 8, store8_mem
    strb _tmp, [_addr]
    write_done 8, store8_mem
    gret 1
    write_bullshit 8, store8_mem

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
// ADC gadgets (Add with Carry)
// ============================================================

// ADC: dst = dst + src + CF
// _xtmp already has dst value, add immediate and carry flag

.gadget adc64_imm
    ldr x8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    adds _xtmp, _xtmp, x8   // Add immediate
    add _xtmp, _xtmp, x9    // Add carry (this won't set flags correctly, but simplifies)
    setf_oc
    setf_zsp
    gret 1

.gadget adc32_imm
    ldr w8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    adds _tmp, _tmp, w8     // Add immediate
    add _tmp, _tmp, w9      // Add carry
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1

// SBB (Subtract with Borrow) gadgets
// SBB dest, src: dest = dest - src - CF
.macro sbb_reg64 name, reg64, reg32
    .gadget sbb64_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        subs _xtmp, _xtmp, \reg64 // dest - src
        sub _xtmp, _xtmp, x9      // - CF
        setf_oc
        setf_zsp
        gret
    .gadget sbb32_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        subs _tmp, _tmp, \reg32   // dest - src
        sub _tmp, _tmp, w9        // - CF
        and _xtmp, _xtmp, 0xffffffff  // Zero-extend
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 sbb_reg64
.purgem sbb_reg64

.gadget sbb64_imm
    ldr x8, [_ip]            // Load immediate
    ldrb w9, [_cpu, CPU_cf]  // Load carry flag
    subs _xtmp, _xtmp, x8    // dest - imm
    sub _xtmp, _xtmp, x9     // - CF
    setf_oc
    setf_zsp
    gret 1

.gadget sbb32_imm
    ldr w8, [_ip]            // Load immediate
    ldrb w9, [_cpu, CPU_cf]  // Load carry flag
    subs _tmp, _tmp, w8      // dest - imm
    sub _tmp, _tmp, w9       // - CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1

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

// XOR gadgets for r8-r15: _xtmp = _xtmp XOR r[N]
.macro xor64_r8_r15 num, offset
.gadget xor64_r\num
    ldr x8, [_cpu, \offset]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret
.gadget xor32_r\num
    ldr w8, [_cpu, \offset]
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret
.endm
xor64_r8_r15 8, CPU_r8
xor64_r8_r15 9, CPU_r9
xor64_r8_r15 10, CPU_r10
xor64_r8_r15 11, CPU_r11
xor64_r8_r15 12, CPU_r12
xor64_r8_r15 13, CPU_r13
xor64_r8_r15 14, CPU_r14
xor64_r8_r15 15, CPU_r15

.pushsection_rodata
.align 3
.global NAME(xor64_r8_r15_gadgets)
NAME(xor64_r8_r15_gadgets):
    .quad NAME(gadget_xor64_r8)
    .quad NAME(gadget_xor64_r9)
    .quad NAME(gadget_xor64_r10)
    .quad NAME(gadget_xor64_r11)
    .quad NAME(gadget_xor64_r12)
    .quad NAME(gadget_xor64_r13)
    .quad NAME(gadget_xor64_r14)
    .quad NAME(gadget_xor64_r15)
.global NAME(xor32_r8_r15_gadgets)
NAME(xor32_r8_r15_gadgets):
    .quad NAME(gadget_xor32_r8)
    .quad NAME(gadget_xor32_r9)
    .quad NAME(gadget_xor32_r10)
    .quad NAME(gadget_xor32_r11)
    .quad NAME(gadget_xor32_r12)
    .quad NAME(gadget_xor32_r13)
    .quad NAME(gadget_xor32_r14)
    .quad NAME(gadget_xor32_r15)
.popsection

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

// AND with register (for reg, reg - xtmp = xtmp & other_reg)
.macro and_reg64 name, reg64, reg32
    .gadget and64_\name
        ands _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
.endm
.each_reg64 and_reg64
.purgem and_reg64

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

.gadget cmp16_imm
    ldrh w8, [_ip]
    and w10, _tmp, 0xffff       // Mask to 16 bits
    subs w9, w10, w8            // Compare 16-bit values
    setf_oc
    sxth x9, w9                 // Sign-extend for SF/PF
    setf_zsp h, x9
    gret 1

.gadget cmp8_imm
    ldrb w8, [_ip]
    and w10, _tmp, 0xff         // Mask to 8 bits
    subs w9, w10, w8            // Compare 8-bit values
    setf_oc
    sxtb x9, w9                 // Sign-extend for SF/PF
    setf_zsp b, x9
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

// 32-bit CMP reg, reg - compare low 32 bits only
// Uses same register aliases as cmp64_reg but with 32-bit (w) versions
.gadget cmp32_reg
    ldr x8, [_ip]
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
    // Default to edi (case 7)
    subs w9, _tmp, edi
    b 9f
1:  subs w9, _tmp, eax
    b 9f
2:  subs w9, _tmp, ecx
    b 9f
3:  subs w9, _tmp, edx
    b 9f
4:  subs w9, _tmp, ebx
    b 9f
5:  subs w9, _tmp, esp
    b 9f
6:  subs w9, _tmp, ebp
    b 9f
7:  subs w9, _tmp, esi
    b 9f
9:  setf_oc
    setf_zsp w, x9
    gret 1

// CMP _xtmp with x8 (for CMP [mem], reg where mem is loaded first)
// This compares memory value (_xtmp) with saved register value (x8)
// Flags are set based on: _xtmp - x8
.gadget cmp64_x8
    subs x9, _xtmp, x8
    setf_oc
    setf_zsp , x9
    gret

.gadget cmp32_x8
    subs w9, _tmp, w8
    setf_oc
    setf_zsp w, x9
    gret

.gadget cmp16_x8
    and w10, _tmp, 0xffff
    and w11, w8, 0xffff
    subs w9, w10, w11
    setf_oc
    sxth x9, w9
    setf_zsp h, x9
    gret

.gadget cmp8_x8
    and w10, _tmp, 0xff
    and w11, w8, 0xff
    subs w9, w10, w11
    setf_oc
    sxtb x9, w9
    setf_zsp b, x9
    gret

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

.gadget test16_imm
    ldrh w8, [_ip]
    and w10, _tmp, 0xffff       // Mask to 16 bits
    ands w9, w10, w8            // AND 16-bit values
    clearf_oc
    sxth x9, w9
    setf_zsp h, x9
    gret 1

.gadget test8_imm
    ldrb w8, [_ip]
    and w10, _tmp, 0xff         // Mask to 8 bits
    ands w9, w10, w8            // AND 8-bit values
    clearf_oc
    sxtb x9, w9
    setf_zsp b, x9
    gret 1

// TEST with x8 (for TEST reg, reg where second reg loaded to x8)
.gadget test64_x8
    ands x9, _xtmp, x8
    clearf_oc
    setf_zsp , x9
    gret

// TEST with register (for reg, reg - xtmp & other_reg, set flags)
.macro test_reg64 name, reg64, reg32
    .gadget test64_\name
        ands x9, _xtmp, \reg64
        clearf_oc
        setf_zsp , x9
        gret
.endm
.each_reg64 test_reg64
.purgem test_reg64

// ============================================================
// DIV/IDIV gadgets
// ============================================================

// DIV32: Unsigned divide EDX:EAX by _xtmp (32-bit divisor)
// Input: _xtmp = divisor, rax = low 32 bits of dividend, rdx = high 32 bits
// Output: rax = quotient, rdx = remainder
// Note: Uses 64-bit division since EDX:EAX fits in 64 bits
.gadget div32
    // Combine EDX:EAX into a 64-bit value
    and x8, rdx, 0xffffffff     // High 32 bits (zero-extended)
    lsl x8, x8, 32              // Shift to high position
    and x9, rax, 0xffffffff     // Low 32 bits
    orr x8, x8, x9              // x8 = EDX:EAX as 64-bit value
    // Divide
    and x9, _xtmp, 0xffffffff   // 32-bit divisor (zero-extended)
    udiv x10, x8, x9            // Quotient
    msub x11, x10, x9, x8       // Remainder = dividend - quotient * divisor
    // Store results
    and rax, rax, 0xffffffff00000000
    orr rax, rax, x10           // EAX = quotient (preserve upper 32 bits... actually x86 zeros them)
    mov eax, w10                // Store quotient in eax (zeros upper 32 bits)
    mov edx, w11                // Store remainder in edx (zeros upper 32 bits)
    gret

// DIV64: Unsigned divide RDX:RAX by _xtmp (64-bit divisor)
// This requires 128-bit division which ARM64 doesn't have natively
// For now, handle the common case where RDX=0 (dividend fits in 64 bits)
.gadget div64
    // If RDX != 0, we'd need multi-word division
    // For now, just do simple case: dividend = RAX, RDX = 0
    udiv x10, rax, _xtmp        // Quotient
    msub x11, x10, _xtmp, rax   // Remainder = RAX - quotient * divisor
    mov rax, x10                // Store quotient
    mov rdx, x11                // Store remainder
    gret

// IDIV32: Signed divide EDX:EAX by _xtmp (32-bit divisor)
.gadget idiv32
    // Combine EDX:EAX into a 64-bit signed value
    sxtw x8, edx                // Sign-extend EDX to 64-bit
    lsl x8, x8, 32              // Shift to high position
    and x9, rax, 0xffffffff     // Low 32 bits (unsigned)
    orr x8, x8, x9              // x8 = EDX:EAX as signed 64-bit value
    // Divide (signed)
    sxtw x9, _tmp               // Sign-extend 32-bit divisor
    sdiv x10, x8, x9            // Quotient (signed)
    msub x11, x10, x9, x8       // Remainder = dividend - quotient * divisor
    // Store results
    mov eax, w10                // Store quotient in eax
    mov edx, w11                // Store remainder in edx
    gret

// IDIV64: Signed divide RDX:RAX by _xtmp (64-bit divisor)
.gadget idiv64
    // Simple case: dividend = RAX (assume RDX is sign extension of RAX)
    sdiv x10, rax, _xtmp        // Quotient (signed)
    msub x11, x10, _xtmp, rax   // Remainder
    mov rax, x10                // Store quotient
    mov rdx, x11                // Store remainder
    gret

// MUL32: Unsigned multiply EAX * _xtmp -> EDX:EAX
.gadget mul32
    // Zero-extend both operands to 64-bit and multiply
    and x8, rax, 0xffffffff     // EAX zero-extended
    and x9, _xtmp, 0xffffffff   // operand zero-extended
    mul x10, x8, x9             // 64-bit result
    // Split into EDX:EAX
    mov eax, w10                // Low 32 bits -> EAX
    lsr x10, x10, 32
    mov edx, w10                // High 32 bits -> EDX
    // Set CF and OF if high half is non-zero
    cmp edx, 0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
    gret

// MUL64: Unsigned multiply RAX * _xtmp -> RDX:RAX
.gadget mul64
    // Use mul for low 64 bits, umulh for high 64 bits
    mul x10, rax, _xtmp         // Low 64 bits
    umulh x11, rax, _xtmp       // High 64 bits
    mov rax, x10                // Low -> RAX
    mov rdx, x11                // High -> RDX
    // Set CF and OF if high half (RDX) is non-zero
    cmp rdx, 0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
    gret

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
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget shr64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    // Save MSB for OF
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w11, w11, 1
    lsr _xtmp, _xtmp, x11
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
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget shl64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    sub w11, w11, 1
    lsl _xtmp, _xtmp, x11
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
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget sar64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w11, w11, 1
    asr _xtmp, _xtmp, x11
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

// ============================================================
// IMUL - Signed multiply
// ============================================================

// Two-operand form: IMUL dst, src
// Result goes into dst (truncated to register size)
// _xtmp has src, multiply with dst register

// IMUL 64-bit: _xtmp * reg64 -> reg64
.macro imul64_to name, reg64, reg32
.gadget imul64_\name
    mul _xtmp, _xtmp, \reg64
    mov \reg64, _xtmp
    // Set flags (simplified - OF/CF set if high bits would overflow)
    smulh x8, _xtmp, \reg64    // Get high 64 bits of signed multiply
    asr x9, \reg64, 63         // Sign extend of low result
    cmp x8, x9
    cset w10, ne               // OF = CF = (high bits != sign extension)
    strb w10, [_cpu, CPU_of]
    strb w10, [_cpu, CPU_cf]
    gret
.endm

imul64_to a, rax, eax
imul64_to c, rcx, ecx
imul64_to d, rdx, edx
imul64_to b, rbx, ebx
imul64_to sp, rsp, esp
imul64_to bp, rbp, ebp
imul64_to si, rsi, esi
imul64_to di, rdi, edi

// IMUL 32-bit: _tmp * reg32 -> reg32
.macro imul32_to name, reg32
.gadget imul32_\name
    // 32-bit multiply: src * dst, result in dst
    mul w8, _tmp, \reg32
    mov \reg32, w8
    // Zero-extend to 64-bit (mov already does this)
    // Set flags
    smull x9, _tmp, \reg32     // Signed 32x32 -> 64 result
    asr x10, x9, 32            // High 32 bits
    asr w11, w8, 31            // Sign extension of low 32 bits
    sxtw x11, w11
    cmp x10, x11
    cset w10, ne
    strb w10, [_cpu, CPU_of]
    strb w10, [_cpu, CPU_cf]
    gret
.endm

imul32_to a, eax
imul32_to c, ecx
imul32_to d, edx
imul32_to b, ebx
imul32_to sp, esp
imul32_to bp, ebp
imul32_to si, esi
imul32_to di, edi

// IMUL 64-bit for r8-r15: _xtmp * r[n] -> r[n]
// r8-r15 are stored in cpu_state, not ARM64 registers
.macro imul64_r8_r15 num, offset
.gadget imul64_r\num
    ldr x8, [_cpu, \offset]    // Load r[n] from cpu state
    mul x8, _xtmp, x8          // result = _xtmp * r[n]
    str x8, [_cpu, \offset]    // Store result back
    // Set flags (OF/CF if high bits would overflow)
    smulh x9, _xtmp, x8        // Get high 64 bits
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10
    cset w11, ne
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret
.endm
imul64_r8_r15 8, CPU_r8
imul64_r8_r15 9, CPU_r9
imul64_r8_r15 10, CPU_r10
imul64_r8_r15 11, CPU_r11
imul64_r8_r15 12, CPU_r12
imul64_r8_r15 13, CPU_r13
imul64_r8_r15 14, CPU_r14
imul64_r8_r15 15, CPU_r15

// IMUL 32-bit for r8-r15: _tmp * r[n]d -> r[n]d (32-bit)
.macro imul32_r8_r15 num, offset
.gadget imul32_r\num
    ldr w8, [_cpu, \offset]    // Load r[n]d (32-bit) from cpu state
    mul w9, _tmp, w8           // result = _tmp * r[n]d (32-bit)
    // Zero-extend to 64-bit and store full 64-bit value
    uxtw x9, w9                // Zero-extend to 64-bit
    str x9, [_cpu, \offset]    // Store full 64-bit value
    // Set flags
    smull x10, _tmp, w8        // Signed 32x32 -> 64
    asr x11, x10, 32           // High 32 bits
    asr w12, w9, 31            // Sign of 32-bit result
    sxtw x12, w12
    cmp x11, x12
    cset w13, ne
    strb w13, [_cpu, CPU_of]
    strb w13, [_cpu, CPU_cf]
    gret
.endm
imul32_r8_r15 8, CPU_r8
imul32_r8_r15 9, CPU_r9
imul32_r8_r15 10, CPU_r10
imul32_r8_r15 11, CPU_r11
imul32_r8_r15 12, CPU_r12
imul32_r8_r15 13, CPU_r13
imul32_r8_r15 14, CPU_r14
imul32_r8_r15 15, CPU_r15

.pushsection_rodata
.align 3
.global NAME(imul64_r8_r15_gadgets)
NAME(imul64_r8_r15_gadgets):
    .quad NAME(gadget_imul64_r8)
    .quad NAME(gadget_imul64_r9)
    .quad NAME(gadget_imul64_r10)
    .quad NAME(gadget_imul64_r11)
    .quad NAME(gadget_imul64_r12)
    .quad NAME(gadget_imul64_r13)
    .quad NAME(gadget_imul64_r14)
    .quad NAME(gadget_imul64_r15)
.global NAME(imul32_r8_r15_gadgets)
NAME(imul32_r8_r15_gadgets):
    .quad NAME(gadget_imul32_r8)
    .quad NAME(gadget_imul32_r9)
    .quad NAME(gadget_imul32_r10)
    .quad NAME(gadget_imul32_r11)
    .quad NAME(gadget_imul32_r12)
    .quad NAME(gadget_imul32_r13)
    .quad NAME(gadget_imul32_r14)
    .quad NAME(gadget_imul32_r15)
.popsection

// IMUL with immediate: _xtmp = src, immediate from [_ip]
// Result stored to destination register (specified by next gadget)
.gadget imul64_imm
    ldr x8, [_ip]              // Load immediate
    mul _xtmp, _xtmp, x8
    gret 1

.gadget imul32_imm
    ldr w8, [_ip]              // Load 32-bit immediate
    mul _tmp, _tmp, w8         // 32-bit multiply
    // Result in _tmp, zero-extended by 32-bit mul
    gret 1

// IMUL with memory operand: load from _addr, multiply with _xtmp
.gadget imul64_mem
    ldr x8, [_addr]
    mul _xtmp, _xtmp, x8
    gret

// ============================================================
// XMM/SSE register operations
// ============================================================

// MOVQ xmm, r/m64 - Move 64-bit value to lower half of XMM, zero upper
// _xtmp = source value (64-bit), [_ip] = XMM register index (0-15)
.gadget movq_to_xmm
    ldr x8, [_ip]              // XMM register index (0-15)
    lsl x8, x8, 4              // Multiply by 16 (sizeof xmm_reg)
    add x8, x8, CPU_xmm        // Add xmm array offset
    add x8, _cpu, x8           // Final address in cpu struct
    str _xtmp, [x8]            // Store value to xmm[n].qw[0]
    str xzr, [x8, 8]           // Zero upper 64 bits (xmm[n].qw[1])
    gret 1

// MOVQ r/m64, xmm - Move lower 64 bits of XMM to destination
// [_ip] = XMM register index, result in _xtmp
.gadget movq_from_xmm
    ldr x8, [_ip]              // XMM register index (0-15)
    lsl x8, x8, 4              // Multiply by 16 (sizeof xmm_reg)
    add x8, x8, CPU_xmm        // Add xmm array offset
    add x8, _cpu, x8           // Final address in cpu struct
    ldr _xtmp, [x8]            // Load xmm[n].qw[0]
    gret 1

// PUNPCKLQDQ xmm, xmm - Unpack and interleave low quadwords
// This is used for duplicating a value across the XMM register
// _xtmp contains source XMM index, [_ip] = destination XMM index
.gadget punpcklqdq
    // Load destination XMM index
    ldr x8, [_ip]              // Destination XMM index
    lsl x9, x8, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]

    // Source is in _xtmp (XMM index)
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]

    // xmm[dst].qw[1] = xmm[src].qw[0]
    ldr x10, [x8]              // Load src.qw[0]
    str x10, [x9, 8]           // Store to dst.qw[1]
    // xmm[dst].qw[0] stays unchanged
    gret 1

// MOVAPS/MOVUPS xmm, [mem] - Load 128-bit from memory to XMM
// _addr = memory address (GUEST address)
// [_ip] = orig_ip (for segfault handler), [_ip+8] = XMM register index
.gadget movaps_load
    // Save guest address for second half (read_prep modifies _addr to host addr)
    str _addr, [_cpu, LOCAL_value_addr]

    // Load first 64 bits from memory (low half)
    read_prep 64, movaps_load1
    ldr x8, [_addr]            // Load low 64 bits
    str x8, [_cpu, LOCAL_value]     // Temporarily store low

    // Load second 64 bits - use saved guest address + 8
    ldr _addr, [_cpu, LOCAL_value_addr]
    add _addr, _addr, 8        // Second half is at guest_addr + 8
    read_prep 64, movaps_load2
    ldr x9, [_addr]            // Load high 64 bits
    ldr x8, [_cpu, LOCAL_value]     // Restore low

    // Store to XMM register
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[n]
    str x8, [x10]              // Store low 64 bits
    str x9, [x10, 8]           // Store high 64 bits
    gret 2
    read_bullshit 64, movaps_load1
    read_bullshit 64, movaps_load2

// MOVAPS/MOVUPS [mem], xmm - Store 128-bit from XMM to memory
// _addr = memory address (GUEST address)
// [_ip] = orig_ip (for segfault handler), [_ip+8] = XMM register index
.gadget movaps_store
    // Save guest address for second half (write_prep modifies _addr to host addr)
    str _addr, [_cpu, LOCAL_value_addr]

    // Load from XMM register
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[n]
    ldr x8, [x10]              // Load low 64 bits
    ldr x9, [x10, 8]           // Load high 64 bits

    // Store to memory (16 bytes)
    str x8, [_cpu, LOCAL_value]     // Temporarily store low
    str x9, [_cpu, LOCAL_value+8]   // Temporarily store high

    // First 64-bit store (low half)
    write_prep 64, movaps_store1
    ldr x8, [_cpu, LOCAL_value]     // Restore low
    str x8, [_addr]            // Store low 64 bits
    write_done 64, movaps_store1

    // Second 64-bit store (high half) - use saved guest address + 8
    ldr _addr, [_cpu, LOCAL_value_addr]
    add _addr, _addr, 8        // Second half is at guest_addr + 8
    write_prep 64, movaps_store2
    ldr x9, [_cpu, LOCAL_value+8]   // Restore high
    str x9, [_addr]            // Store high 64 bits
    write_done 64, movaps_store2
    gret 2
    write_bullshit 64, movaps_store1
    write_bullshit 64, movaps_store2

// MOVAPS xmm, xmm - Copy 128 bits between XMM registers
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget movaps_xmm_xmm
    // Source XMM
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr x10, [x8]              // Load low
    ldr x11, [x8, 8]           // Load high (note: x11 is ok here, save_c preserves it)

    // Destination XMM
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    str x10, [x9]              // Store low
    str x11, [x9, 8]           // Store high
    gret 1

// PXOR xmm, xmm - XOR 128 bits between XMM registers
// Used commonly as PXOR xmm, xmm to zero a register
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget pxor_xmm
    // Destination XMM
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr x10, [x9]              // Load dst low
    ldr x12, [x9, 8]           // Load dst high (note: use x12, not x11 which is TLB scratch)

    // Source XMM
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr x13, [x8]              // Load src low
    ldr x14, [x8, 8]           // Load src high

    // XOR
    eor x10, x10, x13
    eor x12, x12, x14

    // Store result
    str x10, [x9]              // Store low
    str x12, [x9, 8]           // Store high
    gret 1
