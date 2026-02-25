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
    // Load r10 via C helper (ARM64 ldr crashed for unknown reason)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0                    // Save result in callee-saved reg
    restore_c
    mov _xtmp, x19                 // Put result in _xtmp
    gret

.gadget load64_r11
    ldr _xtmp, [_cpu, CPU_r11]
    gret

.gadget load64_r12
    ldr _xtmp, [_cpu, CPU_r12]
    gret

.gadget load64_r13
    // Load r13 via C helper (same pattern as load64_r10)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    mov _xtmp, x19
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
// MOV merge gadgets for 8/16-bit partial register writes
// x86-64: 8-bit and 16-bit MOV preserve upper bits of destination
// Expects: _xtmp = destination register, x8 = source value
// ============================================================

// Merge x8's low 8 bits into _xtmp at bits [7:0]
.gadget mov_merge8
    bfi _xtmp, x8, #0, #8
    gret

// Merge x8's low 8 bits into _xtmp at bits [15:8] (for AH/BH/CH/DH destination)
.gadget mov_merge8h
    bfi _xtmp, x8, #8, #8
    gret

// Merge x8's low 16 bits into _xtmp at bits [15:0]
.gadget mov_merge16
    bfi _xtmp, x8, #0, #16
    gret

// XCHG AL, AH: swap bits [7:0] and bits [15:8] of _xtmp, preserve upper bits
// Used for xchg ah, al / xchg al, ah (e.g., base64 byte-order conversion)
.gadget xchg_al_ah
    ubfx x9, _xtmp, 0, 8     // x9 = bits [7:0] (AL)
    ubfx x10, _xtmp, 8, 8    // x10 = bits [15:8] (AH)
    bfi _xtmp, x10, 0, 8     // _xtmp[7:0] = old AH
    bfi _xtmp, x9, 8, 8      // _xtmp[15:8] = old AL
    gret

// ============================================================
// ADD gadgets
// ============================================================

.macro add_reg64 name, reg64, reg32
    .gadget add64_\name
        adds _xtmp, _xtmp, \reg64
        setf_oc_add
        setf_zsp
        gret
    .gadget add32_\name
        adds _tmp, _tmp, \reg32
        setf_oc_add
        setf_zsp w
        gret
.endm
.each_reg64 add_reg64
.purgem add_reg64

.gadget add64_imm
    ldr x8, [_ip]
    adds _xtmp, _xtmp, x8
    setf_oc_add
    setf_zsp
    gret 1

// Flag-preserving add for LEA - does NOT modify CPU flags
.gadget lea_add64_imm
    ldr x8, [_ip]
    add _xtmp, _xtmp, x8    // add (not adds) - doesn't touch ARM flags
    gret 1

.gadget add32_imm
    ldr w8, [_ip]
    adds _tmp, _tmp, w8
    setf_oc_add
    setf_zsp w
    gret 1

.gadget add64_mem
    read_prep 64, add64_mem
    ldr x8, [_addr]
    adds _xtmp, _xtmp, x8
    setf_oc_add
    setf_zsp
    gret 1
    read_bullshit 64, add64_mem

.gadget add32_mem
    read_prep 32, add32_mem
    ldr w8, [_addr]
    adds _tmp, _tmp, w8
    setf_oc_add
    setf_zsp w
    gret 1
    read_bullshit 32, add32_mem

// ADD with x8 (for adding r8-r15 which are loaded into x8)
.gadget add64_x8
    adds _xtmp, _xtmp, x8
    setf_oc_add
    setf_zsp
    gret

// 32-bit ADD with x8 (for adding r8-r15 in 32-bit mode)
// Result is zero-extended to 64 bits (x86_64 semantics)
.gadget add32_x8
    adds _tmp, _tmp, w8        // 32-bit add with flags
    setf_oc_add
    setf_zsp w
    gret

// ============================================================
// ADC gadgets (Add with Carry)
// ============================================================

// ADC: dst = dst + src + CF
// _xtmp already has dst value, add immediate and carry flag

.gadget adc64_imm
    ldr x8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    lsl w9, w9, 29          // Position CF at NZCV.C (bit 29)
    msr nzcv, x9            // Set ARM64 carry flag
    adcs _xtmp, _xtmp, x8   // dest + src + CF (flags set correctly)
    setf_oc_add
    setf_zsp
    gret 1

.gadget adc32_imm
    ldr w8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    lsl w9, w9, 29          // Position CF at NZCV.C (bit 29)
    msr nzcv, x9            // Set ARM64 carry flag
    adcs _tmp, _tmp, w8     // dest + src + CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc_add
    setf_zsp w
    gret 1

// ADC with register (for ADC reg, reg)
.macro adc_reg64 name, reg64, reg32
    .gadget adc64_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        lsl w9, w9, 29            // Position CF at NZCV.C (bit 29)
        msr nzcv, x9              // Set ARM64 carry flag
        adcs _xtmp, _xtmp, \reg64 // dest + src + CF (flags correct)
        setf_oc_add
        setf_zsp
        gret
    .gadget adc32_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        lsl w9, w9, 29            // Position CF at NZCV.C (bit 29)
        msr nzcv, x9              // Set ARM64 carry flag
        adcs _tmp, _tmp, \reg32   // dest + src + CF
        and _xtmp, _xtmp, 0xffffffff  // Zero-extend
        setf_oc_add
        setf_zsp w
        gret
.endm
.each_reg64 adc_reg64
.purgem adc_reg64

// ADC with x8 (for r8-r15 source registers)
// _xtmp = _xtmp + x8 + CF
.gadget adc64_x8
    ldrb w9, [_cpu, CPU_cf]    // Load carry flag
    lsl w9, w9, 29             // Position CF at NZCV.C (bit 29)
    msr nzcv, x9               // Set ARM64 carry flag
    adcs _xtmp, _xtmp, x8      // dest + src + CF (flags correct)
    setf_oc_add
    setf_zsp
    gret

.gadget adc32_x8
    ldrb w9, [_cpu, CPU_cf]    // Load carry flag
    lsl w9, w9, 29             // Position CF at NZCV.C (bit 29)
    msr nzcv, x9               // Set ARM64 carry flag
    adcs _tmp, _tmp, w8        // dest + src + CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc_add
    setf_zsp w
    gret

// ADC with memory operand: dest = dest + [mem] + CF
.gadget adc64_mem
    read_prep 64, adc64_mem
    ldr x8, [_addr]
    ldrb w9, [_cpu, CPU_cf]    // Load carry flag
    lsl w9, w9, 29             // Position CF at NZCV.C (bit 29)
    msr nzcv, x9               // Set ARM64 carry flag
    adcs _xtmp, _xtmp, x8      // dest + [mem] + CF (flags correct)
    setf_oc_add
    setf_zsp
    gret 1
    read_bullshit 64, adc64_mem

.gadget adc32_mem
    read_prep 32, adc32_mem
    ldr w8, [_addr]
    ldrb w9, [_cpu, CPU_cf]    // Load carry flag
    lsl w9, w9, 29             // Position CF at NZCV.C (bit 29)
    msr nzcv, x9               // Set ARM64 carry flag
    adcs _tmp, _tmp, w8        // dest + [mem] + CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc_add
    setf_zsp w
    gret 1
    read_bullshit 32, adc32_mem

// SBB (Subtract with Borrow) gadgets
// SBB dest, src: dest = dest - src - CF
// ARM64 sbcs: Rd = Rn - Rm - !C, so set ARM64 C = !CF
.macro sbb_reg64 name, reg64, reg32
    .gadget sbb64_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
        lsl w9, w9, 29            // Position at NZCV.C (bit 29)
        msr nzcv, x9              // Set ARM64 carry flag
        sbcs _xtmp, _xtmp, \reg64 // dest - src - CF (flags correct)
        setf_oc
        setf_zsp
        gret
    .gadget sbb32_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
        lsl w9, w9, 29            // Position at NZCV.C (bit 29)
        msr nzcv, x9              // Set ARM64 carry flag
        sbcs _tmp, _tmp, \reg32   // dest - src - CF
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
    eor w9, w9, 1            // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29           // Position at NZCV.C (bit 29)
    msr nzcv, x9             // Set ARM64 carry flag
    sbcs _xtmp, _xtmp, x8    // dest - src - CF (flags correct)
    setf_oc
    setf_zsp
    gret 1

.gadget sbb32_imm
    ldr w8, [_ip]            // Load immediate
    ldrb w9, [_cpu, CPU_cf]  // Load carry flag
    eor w9, w9, 1            // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29           // Position at NZCV.C (bit 29)
    msr nzcv, x9             // Set ARM64 carry flag
    sbcs _tmp, _tmp, w8      // dest - src - CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1

// SBB with x8 (for r8-r15 source registers)
// _xtmp = _xtmp - x8 - CF
.gadget sbb64_x8
    ldrb w9, [_cpu, CPU_cf]   // Load carry flag
    eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29            // Position at NZCV.C (bit 29)
    msr nzcv, x9              // Set ARM64 carry flag
    sbcs _xtmp, _xtmp, x8     // dest - src - CF (flags correct)
    setf_oc
    setf_zsp
    gret

.gadget sbb32_x8
    ldrb w9, [_cpu, CPU_cf]   // Load carry flag
    eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29            // Position at NZCV.C (bit 29)
    msr nzcv, x9              // Set ARM64 carry flag
    sbcs _tmp, _tmp, w8       // dest - src - CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret

// SBB with memory operand: dest = dest - [mem] - CF
.gadget sbb64_mem
    read_prep 64, sbb64_mem
    ldr x8, [_addr]
    ldrb w9, [_cpu, CPU_cf]   // Load carry flag
    eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29            // Position at NZCV.C (bit 29)
    msr nzcv, x9              // Set ARM64 carry flag
    sbcs _xtmp, _xtmp, x8     // dest - [mem] - CF (flags correct)
    setf_oc
    setf_zsp
    gret 1
    read_bullshit 64, sbb64_mem

.gadget sbb32_mem
    read_prep 32, sbb32_mem
    ldr w8, [_addr]
    ldrb w9, [_cpu, CPU_cf]   // Load carry flag
    eor w9, w9, 1             // Invert: ARM64 needs C = !CF for sbcs
    lsl w9, w9, 29            // Position at NZCV.C (bit 29)
    msr nzcv, x9              // Set ARM64 carry flag
    sbcs _tmp, _tmp, w8       // dest - [mem] - CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, sbb32_mem

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

// DEC gadgets - decrement by 1, preserving CF
// DEC affects OF, ZF, SF, PF, AF but NOT CF!
.gadget dec64
    // Save CF before operation
    ldrb w8, [_cpu, CPU_cf]
    // Do the subtraction
    subs _xtmp, _xtmp, 1
    // Set OF (but not CF)
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    // Restore CF
    strb w8, [_cpu, CPU_cf]
    // Set ZF, SF, PF
    setf_zsp
    gret

.gadget dec32
    // Save CF before operation
    ldrb w8, [_cpu, CPU_cf]
    // Do the subtraction
    subs _tmp, _tmp, 1
    // Set OF (but not CF)
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    // Restore CF
    strb w8, [_cpu, CPU_cf]
    // Set ZF, SF, PF
    setf_zsp w
    gret

// INC gadgets - increment by 1, preserving CF
// INC affects OF, ZF, SF, PF, AF but NOT CF!
.gadget inc64
    // Save CF before operation
    ldrb w8, [_cpu, CPU_cf]
    // Do the addition
    adds _xtmp, _xtmp, 1
    // Set OF (but not CF)
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    // Restore CF
    strb w8, [_cpu, CPU_cf]
    // Set ZF, SF, PF
    setf_zsp
    gret

.gadget inc32
    // Save CF before operation
    ldrb w8, [_cpu, CPU_cf]
    // Do the addition
    adds _tmp, _tmp, 1
    // Set OF (but not CF)
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    // Restore CF
    strb w8, [_cpu, CPU_cf]
    // Set ZF, SF, PF
    setf_zsp w
    gret

// 16-bit INC - increment by 1, preserving CF, 16-bit flag semantics
.gadget inc16
    ldrb w8, [_cpu, CPU_cf]
    and _tmp, _tmp, 0xFFFF
    // OF=1 when incrementing 0x7FFF (positive max)
    mov w10, 0x7FFF
    cmp _tmp, w10
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    add _tmp, _tmp, 1
    and _tmp, _tmp, 0xFFFF
    strb w8, [_cpu, CPU_cf]
    setf_zsp h
    gret

// 8-bit INC - increment by 1, preserving CF, 8-bit flag semantics
.gadget inc8
    ldrb w8, [_cpu, CPU_cf]
    and _tmp, _tmp, 0xFF
    // OF=1 when incrementing 0x7F (positive max)
    cmp _tmp, 0x7F
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    add _tmp, _tmp, 1
    and _tmp, _tmp, 0xFF
    strb w8, [_cpu, CPU_cf]
    setf_zsp b
    gret

// 16-bit DEC - decrement by 1, preserving CF, 16-bit flag semantics
.gadget dec16
    ldrb w8, [_cpu, CPU_cf]
    and _tmp, _tmp, 0xFFFF
    // OF=1 when decrementing 0x8000 (negative min)
    mov w10, 0x8000
    cmp _tmp, w10
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    sub _tmp, _tmp, 1
    and _tmp, _tmp, 0xFFFF
    strb w8, [_cpu, CPU_cf]
    setf_zsp h
    gret

// 8-bit DEC - decrement by 1, preserving CF, 8-bit flag semantics
.gadget dec8
    ldrb w8, [_cpu, CPU_cf]
    and _tmp, _tmp, 0xFF
    // OF=1 when decrementing 0x80 (negative min)
    cmp _tmp, 0x80
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    sub _tmp, _tmp, 1
    and _tmp, _tmp, 0xFF
    strb w8, [_cpu, CPU_cf]
    setf_zsp b
    gret

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

.gadget sub32_x8
    subs _tmp, w8, _tmp
    setf_oc
    setf_zsp w
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

// XOR zeroing idiom - sets _xtmp=0 and flags as if XOR produced 0
// ZF=1, SF=0, CF=0, OF=0, PF=1
.gadget xor_zero
    eor _xtmp, _xtmp, _xtmp   // _xtmp = 0
    clearf_oc                  // CF=0, OF=0
    setf_zsp                   // Sets flags based on _xtmp (which is 0)
    gret

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

.gadget xor16_imm
    ldr w8, [_ip]
    and w8, w8, 0xffff          // Mask immediate to 16 bits
    eor w10, _tmp, w8           // XOR
    and w10, w10, 0xffff        // Keep only 16 bits of result
    bic _xtmp, _xtmp, 0xffff   // Clear low 16 bits (use x0 to preserve bits 63:32)
    orr _xtmp, _xtmp, x10      // Merge result
    sxth x10, w10               // Sign-extend for flag setting
    clearf_oc
    setf_zsp h, x10
    gret 1

.gadget xor8_imm
    ldr w8, [_ip]
    and w8, w8, 0xff            // Mask immediate to 8 bits
    eor w10, _tmp, w8           // XOR
    and w10, w10, 0xff          // Keep only 8 bits of result
    bic _xtmp, _xtmp, 0xff     // Clear low 8 bits (use x0 to preserve bits 63:32)
    orr _xtmp, _xtmp, x10      // Merge result
    sxtb x10, w10               // Sign-extend for flag setting
    clearf_oc
    setf_zsp b, x10
    gret 1

// XOR with memory: _xtmp = _xtmp XOR [_addr]
.gadget xor64_mem
    read_prep 64, xor64_mem
    ldr x8, [_addr]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1
    read_bullshit 64, xor64_mem

.gadget xor32_mem
    read_prep 32, xor32_mem
    ldr w8, [_addr]
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, xor32_mem

// XOR with x8 register (for read-modify-write [mem] operations)
.gadget xor64_x8
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret


.gadget xor32_x8
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret

.gadget xor16_x8
    and w8, w8, 0xffff            // Mask x8 to 16 bits
    eor w10, _tmp, w8             // XOR
    and w10, w10, 0xffff          // Keep only 16 bits of result
    bic _xtmp, _xtmp, 0xffff     // Clear low 16 bits (use x0 to preserve bits 63:32)
    orr _xtmp, _xtmp, x10        // Merge result
    sxth x10, w10                 // Sign-extend for flag setting
    clearf_oc
    setf_zsp h, x10
    gret

.gadget xor8_x8
    and w8, w8, 0xff              // Mask x8 to 8 bits
    eor w10, _tmp, w8             // XOR
    and w10, w10, 0xff            // Keep only 8 bits of result
    bic _xtmp, _xtmp, 0xff       // Clear low 8 bits (use x0 to preserve bits 63:32)
    orr _xtmp, _xtmp, x10        // Merge result
    sxtb x10, w10                 // Sign-extend for flag setting
    clearf_oc
    setf_zsp b, x10
    gret

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
// xor r10 gadgets: use C helper workaround for r10 load (offset 0x60 crash)
.gadget xor64_r10
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    eor _xtmp, _xtmp, x19
    clearf_oc
    setf_zsp
    gret
.gadget xor32_r10
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    and x19, x0, 0xffffffff
    restore_c
    eor _tmp, _tmp, w19
    clearf_oc
    setf_zsp w
    gret
xor64_r8_r15 11, CPU_r11
xor64_r8_r15 12, CPU_r12
// xor r13 gadgets: use C helper workaround for r13 load (offset 0x78 crash)
.gadget xor64_r13
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    eor _xtmp, _xtmp, x19
    clearf_oc
    setf_zsp
    gret
.gadget xor32_r13
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    and x19, x0, 0xffffffff
    restore_c
    eor _tmp, _tmp, w19
    clearf_oc
    setf_zsp w
    gret
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

// Flag-preserving AND for LEA 32-bit masking - does NOT modify CPU flags
.gadget lea_and64_imm
    ldr x8, [_ip]
    and _xtmp, _xtmp, x8    // and (not ands) - doesn't touch ARM flags
    gret 1

// Flag-preserving SHL for LEA scaled index - does NOT modify CPU flags
.gadget lea_shl64_imm
    ldr w11, [_ip]
    lsl _xtmp, _xtmp, x11   // plain lsl, no flag setting
    gret 1

// Flag-preserving ADD x8 for LEA - does NOT modify CPU flags
.gadget lea_add64_x8
    add _xtmp, _xtmp, x8    // add (not adds) - doesn't touch ARM flags
    gret

// Flag-preserving LSR for high-byte register extraction - does NOT modify CPU flags
.gadget lea_lsr64_imm
    ldr w11, [_ip]
    lsr _xtmp, _xtmp, x11   // plain lsr, no flag setting
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

// AND 32-bit with register (for reg, reg - tmp = tmp & other_reg32)
.macro and_reg32 name, reg64, reg32
    .gadget and32_\name
        ands _tmp, _tmp, \reg32
        clearf_oc
        setf_zsp w
        gret
.endm
.each_reg64 and_reg32
.purgem and_reg32

.gadget and32_x8
    ands _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
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

.gadget or16_imm
    ldr w8, [_ip]
    and w8, w8, 0xffff
    orr w10, _tmp, w8
    and w10, w10, 0xffff
    bic _xtmp, _xtmp, 0xffff
    orr _xtmp, _xtmp, x10
    sxth x10, w10
    clearf_oc
    setf_zsp h, x10
    gret 1

.gadget or8_imm
    ldr w8, [_ip]
    and w8, w8, 0xff
    orr w10, _tmp, w8
    and w10, w10, 0xff
    bic _xtmp, _xtmp, 0xff
    orr _xtmp, _xtmp, x10
    sxtb x10, w10
    clearf_oc
    setf_zsp b, x10
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

// OR 32-bit with register (for reg, reg - tmp = tmp | other_reg32)
.macro or_reg32 name, reg64, reg32
    .gadget or32_\name
        orr _tmp, _tmp, \reg32
        clearf_oc
        setf_zsp w
        gret
.endm
.each_reg64 or_reg32
.purgem or_reg32

.gadget or32_x8
    orr _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret

.gadget or16_x8
    and w8, w8, 0xffff
    orr w10, _tmp, w8
    and w10, w10, 0xffff
    bic _xtmp, _xtmp, 0xffff
    orr _xtmp, _xtmp, x10
    sxth x10, w10
    clearf_oc
    setf_zsp h, x10
    gret

.gadget or8_x8
    and w8, w8, 0xff
    orr w10, _tmp, w8
    and w10, w10, 0xff
    bic _xtmp, _xtmp, 0xff
    orr _xtmp, _xtmp, x10
    sxtb x10, w10
    clearf_oc
    setf_zsp b, x10
    gret

// OR 64-bit memory operand (read from _addr, OR with value in x8)
// NOTE: For 32-bit OR operations, use or32_mem instead to avoid
// corrupting adjacent memory with 64-bit writes.
.gadget or64_mem
    read_prep 64, or64_mem
    ldr x9, [_addr]                      // Load current 64-bit memory value
    orr x9, x9, x8                       // 64-bit OR
    str x9, [_addr]                      // 64-bit store back
    clearf_oc
    mov _xtmp, x9
    setf_zsp
    gret 1
    read_bullshit 64, or64_mem

// OR 32-bit memory operand (read from _addr, OR with value in w8)
// FIX: Use 32-bit operations to avoid corrupting adjacent memory
// The original or64_mem was doing 64-bit reads/writes which could corrupt
// adjacent memory fields in structures when used for 32-bit OR operations.
.gadget or32_mem
    read_prep 32, or32_mem
    ldr w9, [_addr]                      // Load current 32-bit memory value
    orr w9, w9, w8                       // 32-bit OR
    str w9, [_addr]                      // 32-bit store back
    clearf_oc
    uxtw _xtmp, w9                       // Zero-extend result to 64-bit
    setf_zsp w
    gret 1
    read_bullshit 32, or32_mem

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

// 16-bit CMP reg, reg - compare low 16 bits only
.gadget cmp16_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xffff       // Mask first operand to 16 bits
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
    // Default to di (case 7)
    and w11, edi, 0xffff
    subs w9, w10, w11
    b 9f
1:  and w11, eax, 0xffff
    subs w9, w10, w11
    b 9f
2:  and w11, ecx, 0xffff
    subs w9, w10, w11
    b 9f
3:  and w11, edx, 0xffff
    subs w9, w10, w11
    b 9f
4:  and w11, ebx, 0xffff
    subs w9, w10, w11
    b 9f
5:  and w11, esp, 0xffff
    subs w9, w10, w11
    b 9f
6:  and w11, ebp, 0xffff
    subs w9, w10, w11
    b 9f
7:  and w11, esi, 0xffff
    subs w9, w10, w11
    b 9f
9:  setf_oc
    sxth x9, w9                 // Sign-extend 16-bit result for SF/PF
    setf_zsp h, x9
    gret 1

// 8-bit CMP reg, reg - compare low 8 bits only
.gadget cmp8_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xff         // Mask first operand to 8 bits
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
    // Default to di low 8 bits (case 7)
    and w11, edi, 0xff
    subs w9, w10, w11
    b 9f
1:  and w11, eax, 0xff
    subs w9, w10, w11
    b 9f
2:  and w11, ecx, 0xff
    subs w9, w10, w11
    b 9f
3:  and w11, edx, 0xff
    subs w9, w10, w11
    b 9f
4:  and w11, ebx, 0xff
    subs w9, w10, w11
    b 9f
5:  and w11, esp, 0xff
    subs w9, w10, w11
    b 9f
6:  and w11, ebp, 0xff
    subs w9, w10, w11
    b 9f
7:  and w11, esi, 0xff
    subs w9, w10, w11
    b 9f
9:  setf_oc
    sxtb x9, w9                 // Sign-extend 8-bit result for SF/PF
    setf_zsp b, x9
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

// 32-bit TEST with x8 for r8-r15 registers
// Uses 32-bit ANDS for correct sign flag on bit 31
.gadget test32_x8
    ands w9, _tmp, w8   // 32-bit AND
    clearf_oc
    setf_zsp w, x9      // 32-bit result for flags
    gret

// 16-bit TEST with x8 for TEST [mem], reg operations
.gadget test16_x8
    and w10, _tmp, 0xffff       // Mask to 16 bits
    and w11, w8, 0xffff         // Mask x8 to 16 bits
    ands w9, w10, w11           // 16-bit AND
    clearf_oc
    sxth x9, w9                 // Sign extend from 16-bit for flags
    setf_zsp h, x9
    gret

// 8-bit TEST with x8 for TEST [mem], reg operations
.gadget test8_x8
    and w10, _tmp, 0xff         // Mask to 8 bits
    and w11, w8, 0xff           // Mask x8 to 8 bits
    ands w9, w10, w11           // 8-bit AND
    clearf_oc
    sxtb x9, w9                 // Sign extend from 8-bit for flags
    setf_zsp b, x9
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

// 8-bit TEST reg, reg - test low 8 bits only
// Same pattern as cmp8_reg - read register index from [_ip]
.gadget test8_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xff         // Mask first operand to 8 bits
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
    // Default to di low 8 bits (case 7)
    and w11, edi, 0xff
    b 9f
1:  and w11, eax, 0xff
    b 9f
2:  and w11, ecx, 0xff
    b 9f
3:  and w11, edx, 0xff
    b 9f
4:  and w11, ebx, 0xff
    b 9f
5:  and w11, esp, 0xff
    b 9f
6:  and w11, ebp, 0xff
    b 9f
7:  and w11, esi, 0xff
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp b, x9
    gret 1

// 16-bit TEST reg, reg - test low 16 bits only
.gadget test16_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xffff       // Mask first operand to 16 bits
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
    // Default to di low 16 bits (case 7)
    and w11, edi, 0xffff
    b 9f
1:  and w11, eax, 0xffff
    b 9f
2:  and w11, ecx, 0xffff
    b 9f
3:  and w11, edx, 0xffff
    b 9f
4:  and w11, ebx, 0xffff
    b 9f
5:  and w11, esp, 0xffff
    b 9f
6:  and w11, ebp, 0xffff
    b 9f
7:  and w11, esi, 0xffff
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp h, x9
    gret 1

// 32-bit TEST reg, reg - test low 32 bits only
.gadget test32_reg
    ldr x8, [_ip]
    mov w10, _tmp               // Copy 32-bit (w reg = already masked)
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
    mov w11, edi
    b 9f
1:  mov w11, eax
    b 9f
2:  mov w11, ecx
    b 9f
3:  mov w11, edx
    b 9f
4:  mov w11, ebx
    b 9f
5:  mov w11, esp
    b 9f
6:  mov w11, ebp
    b 9f
7:  mov w11, esi
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp w, x9
    gret 1

// ============================================================
// DIV/IDIV gadgets
// ============================================================

// DIV32: Unsigned divide EDX:EAX by _xtmp (32-bit divisor)
// Input: _xtmp = divisor, rax = low 32 bits of dividend, rdx = high 32 bits
// DIV8: Unsigned divide AX by _xtmp[7:0]
// Output: AL = quotient, AH = remainder (in rax, preserving bits 63:16)
.gadget div8
    and w8, w20, #0xffff        // w8 = AX (low 16 bits of RAX)
    and w9, _tmp, #0xff        // w9 = divisor (low 8 bits)
    udiv w10, w8, w9            // w10 = quotient
    msub w11, w10, w9, w8       // w11 = remainder
    // Write AL = quotient, AH = remainder, preserve bits 63:16
    bfi x20, x10, #0, #8       // bits 7:0 = quotient
    bfi x20, x11, #8, #8       // bits 15:8 = remainder
    gret

// DIV16: Unsigned divide DX:AX by _xtmp[15:0]
// Output: AX = quotient (in rax), DX = remainder (in rdx), preserving bits 63:16
.gadget div16
    and w8, w23, #0xffff        // w8 = DX low 16 bits
    lsl w8, w8, #16
    and w9, w20, #0xffff        // w9 = AX low 16 bits
    orr w8, w8, w9              // w8 = DX:AX as 32-bit unsigned
    and w9, _tmp, #0xffff      // w9 = divisor low 16 bits
    udiv w10, w8, w9            // quotient
    msub w11, w10, w9, w8       // remainder
    bfi x20, x10, #0, #16      // AX = quotient (preserve upper bits of rax)
    bfi x23, x11, #0, #16      // DX = remainder (preserve upper bits of rdx)
    gret

// DIV32: Unsigned divide EDX:EAX by _xtmp (32-bit divisor)
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
// Uses C helper for full 128-bit / 64-bit unsigned division
.gadget div64
    // _xtmp (x0) = divisor, _cpu (x1) = cpu pointer
    // Store rax/rdx to cpu_state so helper can read them
    str rax, [_cpu, CPU_rax]
    str rdx, [_cpu, CPU_rdx]
    // Call helper: x0 = divisor (already in _xtmp), x1 = cpu (already in _cpu)
    save_c
    mov x0, _xtmp
    mov x1, _cpu
    bl NAME(helper_div64)
    restore_c
    // Reload results from cpu_state
    ldr rax, [_cpu, CPU_rax]
    ldr rdx, [_cpu, CPU_rdx]
    gret

// IDIV8: Signed divide AX by _xtmp[7:0]
// Output: AL = quotient, AH = remainder (in rax, preserving bits 63:16)
.gadget idiv8
    sxth w8, w20                // w8 = sign-extend AX (16-bit) to 32-bit
    sxtb w9, _tmp               // w9 = sign-extend divisor (8-bit)
    sdiv w10, w8, w9            // signed quotient
    msub w11, w10, w9, w8       // signed remainder
    bfi x20, x10, #0, #8       // AL = quotient
    bfi x20, x11, #8, #8       // AH = remainder
    gret

// IDIV16: Signed divide DX:AX by _xtmp[15:0]
// Output: AX = quotient, DX = remainder, preserving bits 63:16
.gadget idiv16
    and w8, w23, #0xffff        // DX low 16 bits
    lsl w8, w8, #16
    and w9, w20, #0xffff        // AX low 16 bits
    orr w8, w8, w9              // DX:AX as 32-bit signed
    sxth w9, _tmp               // sign-extend 16-bit divisor
    sdiv w10, w8, w9            // signed quotient
    msub w11, w10, w9, w8       // signed remainder
    bfi x20, x10, #0, #16      // AX = quotient
    bfi x23, x11, #0, #16      // DX = remainder
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
// Uses C helper for full 128-bit / 64-bit signed division
.gadget idiv64
    // Store rax/rdx to cpu_state so helper can read them
    str rax, [_cpu, CPU_rax]
    str rdx, [_cpu, CPU_rdx]
    // Call helper: x0 = divisor (already in _xtmp), x1 = cpu (already in _cpu)
    save_c
    mov x0, _xtmp
    mov x1, _cpu
    bl NAME(helper_idiv64)
    restore_c
    // Reload results from cpu_state
    ldr rax, [_cpu, CPU_rax]
    ldr rdx, [_cpu, CPU_rdx]
    gret

// MUL32: Unsigned multiply EAX * _xtmp -> EDX:EAX
// MUL8: Unsigned multiply AL * _xtmp[7:0] -> AX
.gadget mul8
    and w8, w20, #0xff          // w8 = AL
    and w9, _tmp, #0xff         // w9 = operand (low 8 bits)
    mul w10, w8, w9             // w10 = result (16-bit fits in 32-bit)
    // Write AX = result, preserve bits 63:16
    bfi x20, x10, #0, #16      // AX = result
    // CF/OF set if AH (high byte of result) is non-zero
    lsr w8, w10, #8
    and w8, w8, #0xff
    cmp w8, #0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
    gret

// MUL16: Unsigned multiply AX * _xtmp[15:0] -> DX:AX
.gadget mul16
    and w8, w20, #0xffff        // w8 = AX
    and w9, _tmp, #0xffff       // w9 = operand low 16 bits
    mul w10, w8, w9             // w10 = 32-bit result
    // AX = low 16 bits, DX = high 16 bits
    bfi x20, x10, #0, #16      // AX = low 16 bits (preserve upper RAX)
    lsr w11, w10, #16
    bfi x23, x11, #0, #16      // DX = high 16 bits (preserve upper RDX)
    // CF/OF set if DX (high half) is non-zero
    cmp w11, #0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
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
// 32-bit Shift gadgets
// ============================================================
// 32-bit shifts use w-register (ARM64 auto-zero-extends to 64-bit)
// Shift count masked to 0-31 (not 0-63)
// MSB/OF flag check at bit 31 (not 63)
// setf_zsp w for proper 32-bit flag setting

// SHR32 (logical shift right 32-bit) - shift by 1
.gadget shr32_one
    // Get bit 31 for OF flag
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    // Get LSB for CF
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    // Do the 32-bit shift (w-register auto-zero-extends to x0)
    lsr _tmp, _tmp, 1
    setf_zsp w
    gret

// SHR32 by CL
.gadget shr32_cl
    ands w8, ecx, 31
    b.eq 1f
    // Save bit 31 for OF
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w8, w8, 1
    lsr _tmp, _tmp, w8
    and w9, _tmp, 1
    lsr _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret

// SHR32 by immediate
.gadget shr32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    // Save bit 31 for OF
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w11, w11, 1
    lsr _tmp, _tmp, w11
    and w9, _tmp, 1
    lsr _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// SHL32 (logical shift left 32-bit) - shift by 1
.gadget shl32_one
    // Get bit 31 (old MSB) for CF
    lsr w8, _tmp, 31
    // Do the 32-bit shift
    lsl _tmp, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF = CF XOR new MSB
    lsr w9, _tmp, 31
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp w
    gret

// SHL32 by CL
.gadget shl32_cl
    ands w8, ecx, 31
    b.eq 1f
    sub w8, w8, 1
    lsl _tmp, _tmp, w8
    // Get bit that will become CF
    lsr w9, _tmp, 31
    // Shift one more
    lsl _tmp, _tmp, 1
    // CF = old MSB, OF = CF XOR new MSB
    lsr w10, _tmp, 31
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp w
1:  gret

// SHL32 by immediate
.gadget shl32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    sub w11, w11, 1
    lsl _tmp, _tmp, w11
    lsr w9, _tmp, 31
    lsl _tmp, _tmp, 1
    lsr w10, _tmp, 31
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp w
1:  gret 1

// SAR32 (arithmetic shift right 32-bit) - shift by 1

// SHL8 by immediate - shift only low byte, preserving upper bits
// _xtmp contains full register value, only bits 7:0 are shifted
.gadget shl8_imm
    ldr w11, [_ip]
    ands w11, w11, 7               // Mask to 0-7 (8-bit shift count)
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    and _xtmp, _xtmp, 0xFF         // Isolate low byte
    // Compute CF: bit (8 - count) of the original byte
    mov w10, 8
    sub w10, w10, w11
    lsr x12, _xtmp, x10            // Shift right to get the bit that becomes CF
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    // Do the shift
    lsl _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF         // Mask to byte
    // Compute OF: MSB of result XOR CF (defined for shift by 1)
    lsr w10, _tmp, 7
    eor w10, w10, w12
    strb w10, [_cpu, CPU_of]
    // Merge: replace low byte of original with shifted result
    bic x9, x9, 0xFF               // Clear low byte of original
    orr _xtmp, x9, _xtmp           // Insert shifted byte
    setf_zsp b
1:  gret 1

// SHR8 by immediate - shift only low byte, preserving upper bits
.gadget shr8_imm
    ldr w11, [_ip]
    ands w11, w11, 7
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    and _xtmp, _xtmp, 0xFF         // Isolate low byte
    // Compute CF: bit (count - 1) of original byte
    sub w10, w11, 1
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    // Compute OF: MSB of original byte (defined for shift by 1)
    lsr w10, _tmp, 7
    strb w10, [_cpu, CPU_of]
    // Do the shift
    lsr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF         // Mask to byte
    // Merge: replace low byte
    bic x9, x9, 0xFF
    orr _xtmp, x9, _xtmp
    setf_zsp b
1:  gret 1

// SHL16 by immediate - shift only low 16 bits, preserving upper bits
.gadget shl16_imm
    ldr w11, [_ip]
    ands w11, w11, 15              // Mask to 0-15
    b.eq 1f
    mov x9, _xtmp                  // Save original
    and _xtmp, _xtmp, 0xFFFF       // Isolate low 16 bits
    mov w10, 16
    sub w10, w10, w11
    lsr x12, _xtmp, x10            // Get bit that becomes CF
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsl _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF       // Mask to 16 bits
    lsr w10, _tmp, 15
    eor w10, w10, w12
    strb w10, [_cpu, CPU_of]
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret 1

// SHR16 by immediate - shift only low 16 bits, preserving upper bits
.gadget shr16_imm
    ldr w11, [_ip]
    ands w11, w11, 15
    b.eq 1f
    mov x9, _xtmp
    and _xtmp, _xtmp, 0xFFFF
    sub w10, w11, 1
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsr w10, _tmp, 15
    strb w10, [_cpu, CPU_of]
    lsr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret 1

// SAR8 by immediate - arithmetic shift right only low byte, preserving upper bits
.gadget sar8_imm
    ldr w11, [_ip]
    ands w11, w11, 7               // Mask to 0-7 (8-bit shift count)
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    sxtb _xtmp, _tmp              // Sign-extend byte to 64-bit for arithmetic shift
    // Compute CF: bit (count - 1) of original byte
    sub w10, w11, 1
    asr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    // OF is 0 for SAR (defined for shift by 1: OF = 0)
    strb wzr, [_cpu, CPU_of]
    // Do the arithmetic shift
    asr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF         // Mask to byte
    // Merge: replace low byte of original with shifted result
    bic x9, x9, 0xFF               // Clear low byte of original
    orr _xtmp, x9, _xtmp           // Insert shifted byte
    setf_zsp b
1:  gret 1

// SAR16 by immediate - arithmetic shift right only low 16 bits, preserving upper bits
.gadget sar16_imm
    ldr w11, [_ip]
    ands w11, w11, 15              // Mask to 0-15
    b.eq 1f
    mov x9, _xtmp                  // Save original
    sxth _xtmp, _tmp              // Sign-extend halfword to 64-bit
    sub w10, w11, 1
    asr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    strb wzr, [_cpu, CPU_of]
    asr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF       // Mask to 16 bits
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret 1

// SAR8 by CL - arithmetic shift right low byte by CL count
.gadget sar8_cl
    ands w11, ecx, 7               // Mask CL to 0-7
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    sxtb _xtmp, _tmp              // Sign-extend byte to 64-bit
    sub w10, w11, 1
    asr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    strb wzr, [_cpu, CPU_of]
    asr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF         // Mask to byte
    bic x9, x9, 0xFF
    orr _xtmp, x9, _xtmp
    setf_zsp b
1:  gret

// SAR16 by CL - arithmetic shift right low 16 bits by CL count
.gadget sar16_cl
    ands w11, ecx, 15              // Mask CL to 0-15
    b.eq 1f
    mov x9, _xtmp                  // Save original
    sxth _xtmp, _tmp              // Sign-extend halfword to 64-bit
    sub w10, w11, 1
    asr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    strb wzr, [_cpu, CPU_of]
    asr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret

// SHR8 by CL - logical shift right low byte by CL count
.gadget shr8_cl
    ands w11, ecx, 7               // Mask CL to 0-7
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    and _xtmp, _xtmp, 0xFF         // Isolate low byte
    sub w10, w11, 1
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsr w10, _tmp, 7               // OF = MSB of original byte
    strb w10, [_cpu, CPU_of]
    lsr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF
    bic x9, x9, 0xFF
    orr _xtmp, x9, _xtmp
    setf_zsp b
1:  gret

// SHR16 by CL - logical shift right low 16 bits by CL count
.gadget shr16_cl
    ands w11, ecx, 15              // Mask CL to 0-15
    b.eq 1f
    mov x9, _xtmp
    and _xtmp, _xtmp, 0xFFFF
    sub w10, w11, 1
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsr w10, _tmp, 15
    strb w10, [_cpu, CPU_of]
    lsr _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret

// SHL8 by CL - logical shift left low byte by CL count
.gadget shl8_cl
    ands w11, ecx, 7               // Mask CL to 0-7
    b.eq 1f
    mov x9, _xtmp                  // Save original for upper bits
    and _xtmp, _xtmp, 0xFF         // Isolate low byte
    mov w10, 8
    sub w10, w10, w11
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsl _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFF
    lsr w10, _tmp, 7               // OF = MSB of result XOR CF
    eor w10, w10, w12
    strb w10, [_cpu, CPU_of]
    bic x9, x9, 0xFF
    orr _xtmp, x9, _xtmp
    setf_zsp b
1:  gret

// SHL16 by CL - logical shift left low 16 bits by CL count
.gadget shl16_cl
    ands w11, ecx, 15              // Mask CL to 0-15
    b.eq 1f
    mov x9, _xtmp
    and _xtmp, _xtmp, 0xFFFF
    mov w10, 16
    sub w10, w10, w11
    lsr x12, _xtmp, x10
    and w12, w12, 1
    strb w12, [_cpu, CPU_cf]
    lsl _xtmp, _xtmp, x11
    and _xtmp, _xtmp, 0xFFFF
    lsr w10, _tmp, 15
    eor w10, w10, w12
    strb w10, [_cpu, CPU_of]
    bic x9, x9, 0xFFFF
    orr _xtmp, x9, _xtmp
    setf_zsp h
1:  gret

.gadget sar32_one
    // Get LSB for CF
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF is always 0 for SAR by 1
    strb wzr, [_cpu, CPU_of]
    // Do the 32-bit arithmetic shift (w-register auto-zero-extends)
    asr _tmp, _tmp, 1
    setf_zsp w
    gret

// SAR32 by CL
.gadget sar32_cl
    ands w8, ecx, 31
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w8, w8, 1
    asr _tmp, _tmp, w8
    and w9, _tmp, 1
    asr _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret

// SAR32 by immediate
.gadget sar32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w11, w11, 1
    asr _tmp, _tmp, w11
    and w9, _tmp, 1
    asr _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ============================================================
// BSWAP (byte swap)
// ============================================================

// BSWAP r32 - reverse byte order of 32-bit register
// Result is zero-extended to 64-bit
.gadget bswap32
    rev _tmp, _tmp              // ARM64 REV reverses bytes of 32-bit Wn
    mov _xtmp, _xtmp            // Zero-extend to 64-bit (clear upper 32)
    gret

// BSWAP r64 - reverse byte order of 64-bit register
.gadget bswap64
    rev _xtmp, _xtmp            // ARM64 REV reverses bytes of 64-bit Xn
    gret

// ============================================================
// Rotate instructions (ROL/ROR)
// ============================================================

// ROL (rotate left) by 1 - 32-bit
// CF = bit shifted out (bit 31 before shift = bit 0 after shift)
// OF = MSB XOR CF (for shift by 1 only)
.gadget rol32_one
    // ROL by 1 = ROR by 31
    ror _tmp, _tmp, 31
    // CF = bit 0 (the bit that wrapped around)
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF = bit 31 XOR bit 0
    lsr w9, _tmp, 31
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp w
    gret

// ROL by 1 - 64-bit
.gadget rol64_one
    ror _xtmp, _xtmp, 63
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// ROL by CL - 32-bit
.gadget rol32_cl
    and w8, ecx, 31
    cbz w8, 1f
    // ROL by N = ROR by (32 - N)
    neg w8, w8
    add w8, w8, 32
    ror _tmp, _tmp, w8
    // CF = bit 0 (the bit that wrapped around)
    and w9, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    // OF is undefined when count != 1, so we skip
    setf_zsp w
1:  gret

// ROL by CL - 64-bit
.gadget rol64_cl
    and x8, rcx, 63
    cbz x8, 1f
    neg x8, x8
    add x8, x8, 64
    ror _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// ROL by immediate - 32-bit
.gadget rol32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    neg w11, w11
    add w11, w11, 32
    ror _tmp, _tmp, w11
    and w9, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ROL by immediate - 64-bit
.gadget rol64_imm
    ldr w11, [_ip]
    ands x11, x11, 63
    b.eq 1f
    neg x11, x11
    add x11, x11, 64
    ror _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ROR (rotate right) by 1 - 32-bit
// CF = bit shifted out (bit 0 before shift = bit 31 after shift)
// OF = MSB XOR (MSB-1) of result (for shift by 1 only)
.gadget ror32_one
    // CF = bit 0 before shift
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    ror _tmp, _tmp, 1
    // OF = bit 31 XOR bit 30 of result
    lsr w9, _tmp, 31
    lsr w10, _tmp, 30
    eor w9, w9, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_of]
    setf_zsp w
    gret

// ROR by 1 - 64-bit
.gadget ror64_one
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    ror _xtmp, _xtmp, 1
    lsr x9, _xtmp, 63
    lsr x10, _xtmp, 62
    eor w9, w9, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// ROR by CL - 32-bit
.gadget ror32_cl
    and w8, ecx, 31
    cbz w8, 1f
    // CF = last bit shifted out
    sub w9, w8, 1
    ror _tmp, _tmp, w9
    and w10, _tmp, 1
    ror _tmp, _tmp, 1
    strb w10, [_cpu, CPU_cf]
    setf_zsp w
1:  gret

// ROR by CL - 64-bit
.gadget ror64_cl
    and x8, rcx, 63
    cbz x8, 1f
    sub x9, x8, 1
    ror _xtmp, _xtmp, x9
    and x10, _xtmp, 1
    ror _xtmp, _xtmp, 1
    strb w10, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// ROL by immediate - 16-bit
// Rotate lower 16 bits of _xtmp left by immediate, preserve upper bits
// ROL16 by N: result = ((val << N) | (val >> (16 - N))) & 0xFFFF
.gadget rol16_imm
    ldr w11, [_ip]
    ands w11, w11, 15        // mask count to 0-15
    b.eq 1f
    and w9, _tmp, 0xffff     // w9 = lower 16 bits (val)
    mov w10, 16
    sub w10, w10, w11        // w10 = 16 - N
    lsl w12, w9, w11         // w12 = val << N
    lsr w10, w9, w10         // w10 = val >> (16 - N)
    orr w9, w12, w10         // w9 = rotated
    and w9, w9, 0xffff       // mask to 16 bits
    bic _tmp, _tmp, 0xffff   // clear lower 16 bits of original
    orr _tmp, _tmp, w9       // merge rotated value back
    uxtw _xtmp, _tmp         // zero-extend to 64 bits
    and w11, w9, 1            // CF = bit 0 of result
    strb w11, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ROR by immediate - 16-bit
// Rotate lower 16 bits of _xtmp right by immediate, preserve upper bits
// ROR16 by N: result = ((val >> N) | (val << (16 - N))) & 0xFFFF
.gadget ror16_imm
    ldr w11, [_ip]
    ands w11, w11, 15        // mask count to 0-15
    b.eq 1f
    and w9, _tmp, 0xffff     // w9 = lower 16 bits (val)
    mov w10, 16
    sub w10, w10, w11        // w10 = 16 - N
    lsr w12, w9, w11         // w12 = val >> N
    lsl w10, w9, w10         // w10 = val << (16 - N)
    orr w9, w12, w10         // w9 = rotated
    and w9, w9, 0xffff       // mask to 16 bits
    // CF = MSB of result (bit 15)
    ubfx w10, w9, 15, 1
    strb w10, [_cpu, CPU_cf]
    bic _tmp, _tmp, 0xffff   // clear lower 16 bits
    orr _tmp, _tmp, w9       // merge
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret 1

// ROR by immediate - 32-bit
.gadget ror32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    sub w11, w11, 1
    ror _tmp, _tmp, w11
    and w9, _tmp, 1
    ror _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ROR by immediate - 64-bit
.gadget ror64_imm
    ldr w11, [_ip]
    ands x11, x11, 63
    b.eq 1f
    sub x11, x11, 1
    ror _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    ror _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ============================================================
// SHRD (double precision shift right) gadgets
// SHRD dst, src, count: shift src:dst right by count, store low bits in dst
// Expects: _xtmp = dst, x8 = src (from save_xtmp_to_x8 + load src)
// ============================================================

// SHRD by immediate - 64-bit
// shrd rax, rdx, imm: result = (rax >> imm) | (rdx << (64 - imm))
.gadget shrd64_imm
    ldr w11, [_ip]
    and w11, w11, 63
    cbz w11, 1f
    // CF = bit (count-1) of dst before shift
    sub w10, w11, 1
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB of original dst (meaningful only if count=1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // result = (dst >> count) | (src << (64 - count))
    lsr _xtmp, _xtmp, x11
    neg w10, w11
    add w10, w10, 64
    lsl x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret 1

// SHRD by immediate - 32-bit
.gadget shrd32_imm
    ldr w11, [_ip]
    and w11, w11, 31
    cbz w11, 1f
    // CF = bit (count-1) of dst
    sub w10, w11, 1
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB of original dst
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    // result = (dst >> count) | (src << (32 - count))
    lsr _tmp, _tmp, w11
    neg w10, w11
    add w10, w10, 32
    lsl w9, w8, w10
    orr _tmp, _tmp, w9
    // Zero extend result to 64 bits (x86_64 semantics)
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret 1

// SHRD by CL - 64-bit
.gadget shrd64_cl
    and w11, ecx, 63
    cbz w11, 1f
    sub w10, w11, 1
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    lsr _xtmp, _xtmp, x11
    neg w10, w11
    add w10, w10, 64
    lsl x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret

// SHRD by CL - 32-bit
.gadget shrd32_cl
    and w11, ecx, 31
    cbz w11, 1f
    sub w10, w11, 1
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsr _tmp, _tmp, w11
    neg w10, w11
    add w10, w10, 32
    lsl w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret

// ============================================================
// SHLD (double precision shift left) gadgets
// SHLD dst, src, count: shift dst:src left by count, store high bits in dst
// Expects: _xtmp = dst, x8 = src
// ============================================================

// SHLD by immediate - 64-bit
// shld rax, rdx, imm: result = (rax << imm) | (rdx >> (64 - imm))
.gadget shld64_imm
    ldr w11, [_ip]
    and w11, w11, 63
    cbz w11, 1f
    // CF = bit (64-count) of dst before shift (the bit that's about to be shifted out)
    mov w10, 64
    sub w10, w10, w11
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB XOR CF of result (meaningful only if count=1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // result = (dst << count) | (src >> (64 - count))
    lsl _xtmp, _xtmp, x11
    lsr x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret 1

// SHLD by immediate - 32-bit
.gadget shld32_imm
    ldr w11, [_ip]
    and w11, w11, 31
    cbz w11, 1f
    mov w10, 32
    sub w10, w10, w11
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsl _tmp, _tmp, w11
    lsr w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret 1

// SHLD by CL - 64-bit
.gadget shld64_cl
    and w11, ecx, 63
    cbz w11, 1f
    mov w10, 64
    sub w10, w10, w11
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    lsl _xtmp, _xtmp, x11
    lsr x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret

// SHLD by CL - 32-bit
.gadget shld32_cl
    and w11, ecx, 31
    cbz w11, 1f
    mov w10, 32
    sub w10, w10, w11
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsl _tmp, _tmp, w11
    lsr w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret

// ============================================================
// BSF/BSR (bit scan forward/reverse) gadgets
// ============================================================

// BSF - Bit Scan Forward (find lowest set bit)
// If src is 0, ZF=1 and dst is undefined
// Otherwise, ZF=0 and dst = index of lowest set bit
.gadget bsf64
    cbz _xtmp, 1f               // If zero, set ZF and skip
    rbit x9, _xtmp              // Reverse bits
    clz x9, x9                  // Count leading zeros = trailing zeros in original
    mov _xtmp, x9               // Result = bit index
    // ZF = 0 (source was non-zero)
    mov w9, 1                   // Non-zero value for CPU_res
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  // Source was zero - set ZF, leave destination unchanged
    str xzr, [_cpu, CPU_res]    // Zero result for ZF=1
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

.gadget bsf32
    uxtw _xtmp, _tmp            // Zero extend for safety
    cbz _xtmp, 1f
    rbit w9, _tmp               // Reverse 32 bits
    clz w9, w9                  // Count leading zeros
    uxtw _xtmp, w9              // Result = bit index, zero extended
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

// BSR - Bit Scan Reverse (find highest set bit)
// If src is 0, ZF=1 and dst is undefined
// Otherwise, ZF=0 and dst = index of highest set bit
.gadget bsr64
    cbz _xtmp, 1f
    clz x9, _xtmp               // Count leading zeros
    mov x10, 63
    sub _xtmp, x10, x9          // Result = 63 - clz = bit index
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

.gadget bsr32
    uxtw _xtmp, _tmp
    cbz _xtmp, 1f
    clz w9, _tmp
    mov w10, 31
    sub w9, w10, w9
    uxtw _xtmp, w9
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

// ============================================================
// POPCNT - Population count (count set bits)
// ============================================================

.gadget popcnt64
    mov x9, xzr
1:  cbz _xtmp, 1f
    sub x10, _xtmp, 1
    and _xtmp, _xtmp, x10
    add x9, x9, 1
    b 1b
1:  mov _xtmp, x9
    setf_zsp
    gret

.gadget popcnt32
    mov w9, wzr
1:  cbz _tmp, 1f
    sub w10, _tmp, 1
    and _tmp, _tmp, w10
    add w9, w9, 1
    b 1b
1:  uxtw _xtmp, w9
    setf_zsp w
    gret

// ============================================================
// TZCNT - Count Trailing Zeros (BMI1)
// Unlike BSF, TZCNT defines the result for zero input and sets flags differently:
// ZF = (result == 0), CF = (source == 0)
// ============================================================

.gadget tzcnt64
    cbz _xtmp, 1f               // Source is zero?
    rbit x9, _xtmp              // Reverse bits
    clz x9, x9                  // Count trailing zeros
    mov _xtmp, x9               // Result = count
    str _xtmp, [_cpu, CPU_res]  // ZF = (result == 0)
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    strb wzr, [_cpu, CPU_cf]    // CF = 0 (source was non-zero)
    gret
1:  // Source is zero: result = 64, CF=1, ZF=0
    mov _xtmp, 64
    str _xtmp, [_cpu, CPU_res]  // 64 != 0, so ZF = 0
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    mov w10, 1
    strb w10, [_cpu, CPU_cf]    // CF = 1 (source was zero)
    gret

.gadget tzcnt32
    uxtw _xtmp, _tmp            // Zero extend
    cbz _xtmp, 1f
    rbit w9, _tmp               // Reverse 32 bits
    clz w9, w9                  // Count trailing zeros
    uxtw _xtmp, w9              // Result zero extended
    str _xtmp, [_cpu, CPU_res]  // ZF = (result == 0)
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    strb wzr, [_cpu, CPU_cf]    // CF = 0
    gret
1:  mov _xtmp, 32               // Result = 32
    str _xtmp, [_cpu, CPU_res]  // ZF = 0 (32 != 0)
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    mov w10, 1
    strb w10, [_cpu, CPU_cf]    // CF = 1
    gret

// ============================================================
// LZCNT - Count Leading Zeros (ABM/BMI1)
// ZF = (result == 0), CF = (source == 0)
// ============================================================

.gadget lzcnt64
    cbz _xtmp, 1f
    clz x9, _xtmp               // Count leading zeros
    mov _xtmp, x9
    str _xtmp, [_cpu, CPU_res]  // ZF = (result == 0)
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    strb wzr, [_cpu, CPU_cf]    // CF = 0
    gret
1:  mov _xtmp, 64               // Result = 64
    str _xtmp, [_cpu, CPU_res]  // ZF = 0
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    mov w10, 1
    strb w10, [_cpu, CPU_cf]    // CF = 1
    gret

.gadget lzcnt32
    uxtw _xtmp, _tmp
    cbz _xtmp, 1f
    clz w9, _tmp
    uxtw _xtmp, w9
    str _xtmp, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    strb wzr, [_cpu, CPU_cf]
    gret
1:  mov _xtmp, 32
    str _xtmp, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    mov w10, 1
    strb w10, [_cpu, CPU_cf]
    gret

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

// CWDE: Sign extend AX (16-bit) to EAX (32-bit), zero-extended to RAX
// Writing to _tmp (w0) automatically zero-extends to _xtmp (x0)
// CBW: Sign extend AL to AX (only low 16 bits of RAX are modified)
// _xtmp has RAX value loaded; result must preserve bits 63:16
.gadget cbw
    sxtb w9, _tmp              // Sign-extend AL (bits 7:0) to w9
    bfi _xtmp, x9, 0, 16      // Insert low 16 bits of result into _xtmp[15:0]
    gret

// CWDE: Sign extend AX to EAX
.gadget cwde
    sxth _tmp, _tmp
    gret

// CDQ: Sign extend EAX to EDX:EAX (EDX = sign_extend(EAX[31]))
// Sets EDX to 0xFFFFFFFF if EAX is negative, else 0
.gadget cdq
    asr w9, eax, #31       // Arithmetic shift right by 31 copies sign bit to all 32 bits
    mov edx, w9            // Store to EDX (w21 maps to edx, zero-extends to x21)
    gret

// CQO: Sign extend RAX to RDX:RAX (RDX = sign_extend(RAX[63]))
// Sets RDX to 0xFFFFFFFFFFFFFFFF if RAX is negative, else 0
.gadget cqo
    asr rdx, rax, #63      // Arithmetic shift right by 63 copies sign bit to all 64 bits
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
// imul64 r10: use C helper workaround for r10 load (offset 0x60 crash)
.gadget imul64_r10
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    mul x8, _xtmp, x19         // result = _xtmp * r10
    str x8, [_cpu, CPU_r10]    // Store result back
    // Set flags (OF/CF if high bits would overflow)
    smulh x9, _xtmp, x19       // Get high 64 bits (use original r10, not result!)
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10
    cset w11, ne
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret
imul64_r8_r15 11, CPU_r11
imul64_r8_r15 12, CPU_r12
// imul64 r13: use C helper workaround for r13 load (offset 0x78 crash)
.gadget imul64_r13
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    mul x8, _xtmp, x19         // result = _xtmp * r13
    str x8, [_cpu, CPU_r13]    // Store result back
    // Set flags (OF/CF if high bits would overflow)
    smulh x9, _xtmp, x19       // Get high 64 bits (use original r13, not result!)
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10
    cset w11, ne
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret
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
// imul32 r10: use C helper workaround for r10 load (offset 0x60 crash)
.gadget imul32_r10
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    and x19, x0, 0xffffffff    // Get 32-bit r10d
    restore_c
    mul w9, _tmp, w19          // result = _tmp * r10d (32-bit)
    uxtw x9, w9                // Zero-extend to 64-bit
    str x9, [_cpu, CPU_r10]    // Store full 64-bit value
    // Set flags
    smull x10, _tmp, w19       // Signed 32x32 -> 64
    asr x11, x10, 32           // High 32 bits
    asr w12, w9, 31            // Sign of 32-bit result
    sxtw x12, w12
    cmp x11, x12
    cset w13, ne
    strb w13, [_cpu, CPU_of]
    strb w13, [_cpu, CPU_cf]
    gret
imul32_r8_r15 11, CPU_r11
imul32_r8_r15 12, CPU_r12
// imul32 r13: use C helper workaround for r13 load (offset 0x78 crash)
.gadget imul32_r13
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    and x19, x0, 0xffffffff    // Get 32-bit r13d
    restore_c
    mul w9, _tmp, w19          // result = _tmp * r13d (32-bit)
    uxtw x9, w9                // Zero-extend to 64-bit
    str x9, [_cpu, CPU_r13]    // Store full 64-bit value
    // Set flags
    smull x10, _tmp, w19       // Signed 32x32 -> 64
    asr x11, x10, 32           // High 32 bits
    asr w12, w9, 31            // Sign of 32-bit result
    sxtw x12, w12
    cmp x11, x12
    cset w13, ne
    strb w13, [_cpu, CPU_of]
    strb w13, [_cpu, CPU_cf]
    gret
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

// Single-operand IMUL 64-bit: RDX:RAX = RAX * src
// _xtmp = src (from register or memory), result in RAX (low) and RDX (high)
.gadget imul64_wide
    mul x8, rax, _xtmp         // Low 64 bits: x8 = RAX * src
    smulh x9, rax, _xtmp       // High 64 bits: x9 = signed high bits
    mov rax, x8                // Store low to RAX
    mov rdx, x9                // Store high to RDX
    // Set OF/CF if result doesn't fit in RAX (high part is not sign-extension of low)
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10                // Compare high with sign-extension of low
    cset w11, ne               // OF/CF set if they differ
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret

// Single-operand IMUL 32-bit: EDX:EAX = EAX * src
// _tmp = src (32-bit), result in EAX (low) and EDX (high)
.gadget imul32_wide
    smull x8, eax, _tmp        // Signed 32x32 -> 64 result
    mov eax, w8                // Low 32 bits to EAX (zero-extends to 64)
    lsr x9, x8, 32             // High 32 bits
    mov edx, w9                // To EDX (zero-extends to 64)
    // Set OF/CF if result doesn't fit in EAX
    sxtw x10, w8               // Sign extend low 32 bits to 64
    cmp x8, x10                // Compare full result with sign-extension
    cset w11, ne               // OF/CF set if they differ
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
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
    // Single 128-bit read_prep handles cross-page atomically
    // (two separate read_prep 64 calls had a bug: crosspage_load for the
    // second half would clobber the first half's data in LOCAL_value)
    read_prep 128, movaps_load
    ldr x8, [_addr]            // Load low 64 bits
    ldr x9, [_addr, 8]         // Load high 64 bits

    // Store to XMM register
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[n]
    str x8, [x10]              // Store low 64 bits
    str x9, [x10, 8]           // Store high 64 bits
    gret 2
    read_bullshit 128, movaps_load

// MOVAPS/MOVUPS [mem], xmm - Store 128-bit from XMM to memory
// _addr = memory address (GUEST address)
// [_ip] = orig_ip (for segfault handler), [_ip+8] = XMM register index
.gadget movaps_store
    // Single 128-bit write_prep handles cross-page atomically
    write_prep 128, movaps_store
    save_c
    mov x0, _cpu
    ldr x1, [_ip, 8]           // XMM register index (after orig_ip)
    mov x2, _addr              // host memory address (or LOCAL_value for cross-page)
    bl NAME(helper_movdqu_store)
    restore_c
    write_done 128, movaps_store
    gret 2
    write_bullshit 128, movaps_store

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

// PXOR xmm, [mem] - XOR 128 bits from memory with XMM register
// _addr = GUEST memory address
// [_ip] = orig_ip, [_ip+8] = destination XMM index
.gadget pxor_xmm_mem
    // Single 128-bit read_prep handles cross-page atomically
    read_prep 128, pxor_mem
    ldr x12, [_addr]           // Load low 64 bits (mem)
    ldr x13, [_addr, 8]        // Load high 64 bits (mem)

    // Load destination XMM
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[dst]
    ldr x8, [x10]              // Load dst low
    ldr x9, [x10, 8]           // Load dst high

    // XOR
    eor x8, x8, x12           // low ^= mem_low
    eor x9, x9, x13           // high ^= mem_high

    // Store result
    str x8, [x10]              // Store low
    str x9, [x10, 8]           // Store high
    gret 2
    read_bullshit 128, pxor_mem

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

// ============================================================
// MOVSD (Move Scalar Double-Precision) - SSE instruction
// NOT the string operation MOVSD!
// ============================================================

// MOVSD xmm, xmm - Copy low 64 bits, preserve high 64 bits of dest
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget movsd_xmm_xmm
    // Source XMM - get low 64 bits
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr x10, [x8]              // Load src low 64 bits

    // Destination XMM
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    str x10, [x9]              // Store to dst low 64 bits (high preserved)
    gret 1

// MOVSD xmm, m64 - Load 64 bits from memory to XMM low, zero high
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movsd_xmm_mem
    read_prep 64, movsd_xmm_mem
    ldr _xtmp, [_addr]         // Load 64 bits from memory

    // Store to XMM register
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    str _xtmp, [x8]            // Store to low 64 bits
    str xzr, [x8, 8]           // Zero high 64 bits
    gret 2
    read_bullshit 64, movsd_xmm_mem

// MOVSD m64, xmm - Store XMM low 64 bits to memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movsd_mem_xmm
    // Load XMM low 64 bits
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr _xtmp, [x8]            // Load low 64 bits

    // Store to memory
    write_prep 64, movsd_mem_xmm
    str _xtmp, [_addr]         // Store 64 bits to memory
    write_done 64, movsd_mem_xmm
    gret 2
    write_bullshit 64, movsd_mem_xmm

// MOVSS xmm, xmm - Move low 32 bits, preserve upper 96 bits of dst
// _xtmp = src XMM index, [_ip] = dst XMM index
.gadget movss_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr w10, [x8]              // Load src low 32 bits

    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str w10, [x9]              // Store to dst low 32 bits (upper preserved)
    gret 1

// MOVSS xmm, m32 - Load 32 bits from memory to XMM low, zero upper
.gadget movss_xmm_mem
    read_prep 32, movss_xmm_mem
    ldr _tmp, [_addr]          // Load 32 bits from memory

    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    str wzr, [x8, 4]           // Zero bits 63:32
    str _tmp, [x8]             // Store 32-bit float to low dword
    str xzr, [x8, 8]           // Zero high 64 bits
    gret 2
    read_bullshit 32, movss_xmm_mem

// MOVSS m32, xmm - Store XMM low 32 bits to memory
.gadget movss_mem_xmm
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr _tmp, [x8]             // Load low 32 bits

    write_prep 32, movss_mem_xmm
    str _tmp, [_addr]          // Store 32 bits to memory
    write_done 32, movss_mem_xmm
    gret 2
    write_bullshit 32, movss_mem_xmm

// MOVHPS xmm, m64 - Load 64 bits from memory to XMM high, low preserved
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movhps_load
    read_prep 64, movhps_load
    ldr _xtmp, [_addr]         // Load 64 bits from memory

    // Store to XMM register HIGH half
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    str _xtmp, [x8, 8]         // Store to high 64 bits (low preserved)
    gret 2
    read_bullshit 64, movhps_load

// MOVHPS m64, xmm - Store XMM high 64 bits to memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movhps_store
    // Load XMM high 64 bits
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr _xtmp, [x8, 8]         // Load high 64 bits

    // Store to memory
    write_prep 64, movhps_store
    str _xtmp, [_addr]         // Store 64 bits to memory
    write_done 64, movhps_store
    gret 2
    write_bullshit 64, movhps_store

// MOVLPS xmm, m64 - Load 64 bits from memory to XMM low, high preserved
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movlps_load
    read_prep 64, movlps_load
    ldr _xtmp, [_addr]         // Load 64 bits from memory

    // Store to XMM register LOW half
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    str _xtmp, [x8]            // Store to low 64 bits (high preserved)
    gret 2
    read_bullshit 64, movlps_load

// MOVLPS m64, xmm - Store XMM low 64 bits to memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movlps_store
    // Load XMM low 64 bits
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr _xtmp, [x8]            // Load low 64 bits

    // Store to memory
    write_prep 64, movlps_store
    str _xtmp, [_addr]         // Store 64 bits to memory
    write_done 64, movlps_store
    gret 2
    write_bullshit 64, movlps_store

// MOVHLPS xmm, xmm - Move high qword of source to low qword of dest
// [_ip] = dest XMM index, [_ip+8] = source XMM index
.gadget movhlps
    // Load source XMM high 64 bits
    ldr x8, [_ip, 8]           // src XMM index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr x9, [x8, 8]            // x9 = src high qword

    // Store to dest XMM low 64 bits (high preserved)
    ldr x8, [_ip]              // dest XMM index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    str x9, [x8]               // dest low = src high
    gret 2

// MOVLHPS xmm, xmm - Move low qword of source to high qword of dest
// [_ip] = dest XMM index, [_ip+8] = source XMM index
.gadget movlhps
    // Load source XMM low 64 bits
    ldr x8, [_ip, 8]           // src XMM index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr x9, [x8]               // x9 = src low qword

    // Store to dest XMM high 64 bits (low preserved)
    ldr x8, [_ip]              // dest XMM index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    str x9, [x8, 8]            // dest high = src low
    gret 2

// ============================================================
// MOVD - Move Doubleword (32-bit) between GPR/memory and XMM
// ============================================================

// MOVD xmm, r/m32 - Move 32-bit value into low XMM, zero upper 96 bits
// _xtmp = source 32-bit value (zero-extended in _xtmp), [_ip] = dest XMM index
.gadget movd_xmm_reg
    // Store 32-bit value to XMM low, zero rest
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[dst]
    uxtw _xtmp, _tmp           // Zero-extend 32-bit to 64-bit
    str _xtmp, [x8]            // Store to low 64 bits (upper 32 of this qword are 0)
    str xzr, [x8, 8]           // Zero high 64 bits
    gret 1

// MOVD xmm, m32 - Load 32-bit from memory into low XMM, zero upper 96 bits
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movd_xmm_mem
    read_prep 32, movd_xmm_mem
    ldr w9, [_addr]            // Load 32 bits from memory

    // Store to XMM register
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    // Zero-extend 32-bit to 64-bit and store
    uxtw x9, w9
    str x9, [x8]               // Store to low 64 bits
    str xzr, [x8, 8]           // Zero high 64 bits
    gret 2
    read_bullshit 32, movd_xmm_mem

// MOVD r/m32, xmm - Move low 32 bits of XMM to GPR (zero-extended to 64-bit)
// [_ip] = source XMM index, result in _xtmp
.gadget movd_reg_xmm
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr w0, [x8]               // Load low 32 bits from XMM
    uxtw _xtmp, w0             // Zero-extend to 64-bit
    gret 1

// MOVD m32, xmm - Store low 32 bits of XMM to memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget movd_mem_xmm
    // Load XMM low 32 bits
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr w0, [x8]               // Load low 32 bits

    // Store to memory
    mov _xtmp, x0              // Move to _xtmp for write_prep
    write_prep 32, movd_mem_xmm
    str _tmp, [_addr]          // Store 32 bits to memory
    write_done 32, movd_mem_xmm
    gret 2
    write_bullshit 32, movd_mem_xmm

// ============================================================
// Packed SSE2 integer operations (via C helpers)
// All use: [_ip] = dst XMM index, [_ip+8] = src XMM index
// ============================================================

// Helper macro for XMM-XMM operations that take (cpu, dst_idx, src_idx)
.macro sse_xmm_xmm_op name
.gadget \name
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    bl NAME(helper_\name)
    restore_c
    gret 2
.endm

sse_xmm_xmm_op packuswb
sse_xmm_xmm_op packsswb
sse_xmm_xmm_op packssdw
sse_xmm_xmm_op punpcklbw
sse_xmm_xmm_op punpcklwd
sse_xmm_xmm_op punpckldq
sse_xmm_xmm_op punpckhbw
sse_xmm_xmm_op punpckhwd
sse_xmm_xmm_op punpckhdq
sse_xmm_xmm_op punpckhqdq
sse_xmm_xmm_op pcmpeqb
sse_xmm_xmm_op pcmpeqd
sse_xmm_xmm_op pcmpgtb
sse_xmm_xmm_op pcmpgtd
sse_xmm_xmm_op unpcklpd
sse_xmm_xmm_op unpckhpd
sse_xmm_xmm_op pand
sse_xmm_xmm_op pandn
sse_xmm_xmm_op por
sse_xmm_xmm_op paddb
sse_xmm_xmm_op paddw
sse_xmm_xmm_op paddd
sse_xmm_xmm_op paddq
sse_xmm_xmm_op psubb
sse_xmm_xmm_op psubw
sse_xmm_xmm_op psubq
sse_xmm_xmm_op psubd
sse_xmm_xmm_op orps
sse_xmm_xmm_op pminub
sse_xmm_xmm_op pmaxub
sse_xmm_xmm_op pminsw
sse_xmm_xmm_op pmaxsw

// Helper macro for XMM-MEM operations: reads 128 bits from [_addr], calls helper(cpu, dst_xmm, addr)
.macro sse_xmm_mem_op name
.gadget \name\()_mem
    read_prep 128, \name\()_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov x2, _addr              // host memory address
    bl NAME(helper_\name\()_mem)
    restore_c
    gret 2                     // skip 2: XMM index + orig_ip
    read_bullshit 128, \name\()_mem
.endm

sse_xmm_mem_op pand
sse_xmm_mem_op pandn
sse_xmm_mem_op por
sse_xmm_mem_op orps
sse_xmm_mem_op paddb
sse_xmm_mem_op paddw
sse_xmm_mem_op paddd
sse_xmm_mem_op paddq
sse_xmm_mem_op psubb
sse_xmm_mem_op psubw
sse_xmm_mem_op psubq
sse_xmm_mem_op psubd
sse_xmm_mem_op pminub
sse_xmm_mem_op pmaxub
sse_xmm_mem_op pminsw
sse_xmm_mem_op pmaxsw
sse_xmm_mem_op pcmpeqb
sse_xmm_mem_op pcmpeqd
sse_xmm_mem_op pcmpgtb
sse_xmm_mem_op pcmpgtd
sse_xmm_mem_op unpcklpd
sse_xmm_mem_op unpckhpd
sse_xmm_mem_op punpcklqdq
sse_xmm_mem_op packuswb
sse_xmm_mem_op packsswb
sse_xmm_mem_op packssdw
sse_xmm_mem_op punpcklbw
sse_xmm_mem_op punpcklwd
sse_xmm_mem_op punpckldq
sse_xmm_mem_op punpckhbw
sse_xmm_mem_op punpckhwd
sse_xmm_mem_op punpckhdq
sse_xmm_mem_op punpckhqdq

// PSRLDQ xmm, imm8 - Packed Shift Right Logical Double Quadword (byte shift)
// [_ip] = XMM index, [_ip+8] = imm8
.gadget psrldq
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_psrldq)
    restore_c
    gret 2

// PSLLDQ xmm, imm8 - Packed Shift Left Logical Double Quadword (byte shift)
// [_ip] = XMM index, [_ip+8] = imm8
.gadget pslldq
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_pslldq)
    restore_c
    gret 2

// PSRLQ xmm, imm8 - Packed Shift Right Logical Quadword
// [_ip] = XMM index, [_ip+8] = imm8
.gadget psrlq
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_psrlq)
    restore_c
    gret 2

// PSLLQ xmm, imm8 - Packed Shift Left Logical Quadword
// [_ip] = XMM index, [_ip+8] = imm8
.gadget psllq
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_psllq)
    restore_c
    gret 2

// PSRLD xmm, imm8 - Packed Shift Right Logical Doubleword
// [_ip] = XMM index, [_ip+8] = imm8
// PSRLW xmm, imm8 - Packed Shift Right Logical Word
.gadget psrlw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    bl NAME(helper_psrlw)
    restore_c
    gret 2

// PSLLW xmm, imm8 - Packed Shift Left Logical Word
.gadget psllw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    bl NAME(helper_psllw)
    restore_c
    gret 2

// PSRAW xmm, imm8 - Packed Shift Right Arithmetic Word
.gadget psraw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    bl NAME(helper_psraw)
    restore_c
    gret 2

// PSRAD xmm, imm8 - Packed Shift Right Arithmetic Doubleword
.gadget psrad
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    bl NAME(helper_psrad)
    restore_c
    gret 2

.gadget psrld
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_psrld)
    restore_c
    gret 2

// PSLLD xmm, imm8 - Packed Shift Left Logical Doubleword
// [_ip] = XMM index, [_ip+8] = imm8
.gadget pslld
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_pslld)
    restore_c
    gret 2

// PSHUFD xmm, xmm, imm8 - Shuffle packed doublewords
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = imm8
.gadget pshufd
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // imm8
    bl NAME(helper_pshufd)
    restore_c
    gret 3

// PSHUFD xmm, m128, imm8 - Shuffle packed doublewords from memory
// [_ip] = dst XMM index, [_ip+8] = imm8, [_ip+16] = orig_ip
.gadget pshufd_mem
    read_prep 128, pshufd_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_pshufd_mem)
    restore_c
    gret 3
    read_bullshit 128, pshufd_mem

// SHUFPS xmm, xmm, imm8 - Shuffle packed single-precision floats
// result[0] = dst[imm[1:0]], result[1] = dst[imm[3:2]]
// result[2] = src[imm[5:4]], result[3] = src[imm[7:6]]
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = imm8
.gadget shufps
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // imm8
    bl NAME(helper_shufps)
    restore_c
    gret 3

// PSHUFLW xmm, xmm, imm8 - Shuffle Packed Low Words
.gadget pshuflw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    ldr x3, [_ip, 16]
    bl NAME(helper_pshuflw)
    restore_c
    gret 3

.gadget pshuflw_mem
    read_prep 128, pshuflw_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_pshuflw_mem)
    restore_c
    gret 3
    read_bullshit 128, pshuflw_mem

// PSHUFHW xmm, xmm, imm8 - Shuffle Packed High Words
.gadget pshufhw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    ldr x3, [_ip, 16]
    bl NAME(helper_pshufhw)
    restore_c
    gret 3

.gadget pshufhw_mem
    read_prep 128, pshufhw_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_pshufhw_mem)
    restore_c
    gret 3
    read_bullshit 128, pshufhw_mem

// PALIGNR xmm, xmm, imm8 - Packed Align Right (SSSE3)
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = imm8
.gadget palignr
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // imm8
    bl NAME(helper_palignr)
    restore_c
    gret 3

// PSHUFB xmm, xmm - Packed Shuffle Bytes (SSSE3)
// [_ip] = dst XMM index, [_ip+8] = src XMM index
.gadget pshufb
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    bl NAME(helper_pshufb)
    restore_c
    gret 2

// MOVDQA xmm, xmm - Move aligned 128-bit (register to register)
// [_ip] = dst XMM index, [_ip+8] = src XMM index
sse_xmm_xmm_op movdqa_xmm

// MOVDQU/MOVDQA xmm, [mem] - Load 128-bit from memory to XMM
// _addr = memory address, [_ip] = dst XMM index
.gadget movdqu_load
    read_prep 128, movdqu_load
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov x2, _addr              // host memory address
    bl NAME(helper_movdqu_load)
    restore_c
    gret 1
    read_bullshit 128, movdqu_load

// MOVDQU/MOVDQA [mem], xmm - Store 128-bit from XMM to memory
// _addr = memory address, [_ip] = src XMM index
.gadget movdqu_store
    write_prep 128, movdqu_store
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // src XMM index
    mov x2, _addr              // host memory address
    bl NAME(helper_movdqu_store)
    restore_c
    write_done 128, movdqu_store
    gret 1
    write_bullshit 128, movdqu_store

// SHA256RNDS2 xmm, xmm - 2 rounds of SHA-256 compression (implicit XMM0)
// [_ip] = dst XMM index, [_ip+8] = src XMM index
.gadget sha256rnds2
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    bl NAME(helper_sha256rnds2)
    restore_c
    gret 2

// SHA256MSG1 xmm, xmm - SHA-256 message schedule intermediate
// [_ip] = dst XMM index, [_ip+8] = src XMM index
.gadget sha256msg1
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    bl NAME(helper_sha256msg1)
    restore_c
    gret 2

// SHA256MSG2 xmm, xmm - SHA-256 message schedule final
// [_ip] = dst XMM index, [_ip+8] = src XMM index
.gadget sha256msg2
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    bl NAME(helper_sha256msg2)
    restore_c
    gret 2

// MOVMSKPD r, xmm - Move sign bits of packed doubles to GPR
// [_ip] = src XMM index, result in _xtmp
.gadget movmskpd
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // src XMM index
    bl NAME(helper_movmskpd)
    mov x14, x0
    restore_c
    mov _xtmp, x14
    gret 1

// MOVMSKPS r, xmm - Move sign bits of packed singles to GPR
// [_ip] = src XMM index, result in _xtmp
.gadget movmskps
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // src XMM index
    bl NAME(helper_movmskps)
    mov x14, x0
    restore_c
    mov _xtmp, x14
    gret 1

// PMOVMSKB r, xmm - Move byte mask to GPR
// [_ip] = src XMM index, result in _xtmp
.gadget pmovmskb
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // src XMM index
    bl NAME(helper_pmovmskb)
    mov x14, x0               // Save result to x14 (not in save_c/restore_c set)
    restore_c
    mov _xtmp, x14             // Transfer result to _xtmp after restore_c
    gret 1

// PEXTRW r32, xmm, imm8 - Extract word from XMM
// [_ip] = src XMM index, [_ip+8] = imm8
.gadget pextrw
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // src XMM index
    ldr x2, [_ip, 8]           // imm8
    bl NAME(helper_pextrw)
    mov x14, x0
    restore_c
    mov _xtmp, x14
    gret 2

// PINSRW xmm, r32, imm8 - Insert word into XMM from register
// _xtmp = source value, [_ip] = dst XMM index, [_ip+8] = imm8
.gadget pinsrw_reg
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    and w2, _tmp, 0xffff       // value (16-bit)
    ldr x3, [_ip, 8]           // imm8
    bl NAME(helper_pinsrw)
    restore_c
    gret 2

// PINSRW xmm, m16, imm8 - Insert word into XMM from memory
.gadget pinsrw_mem
    read_prep 16, pinsrw_mem
    ldrh w14, [_addr]
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov w2, w14                // value (16-bit)
    ldr x3, [_ip, 8]           // imm8
    bl NAME(helper_pinsrw)
    restore_c
    gret 3                     // skip 3: XMM index + imm8 + orig_ip
    read_bullshit 16, pinsrw_mem

// ============================================================
// CVTSI2SD - Convert Signed Integer to Scalar Double
// ============================================================

// CVTSI2SD xmm, r64 - Convert 64-bit signed integer to double
// _xtmp = source integer (64-bit), [_ip] = destination XMM index
.gadget cvtsi2sd_reg64
    // Convert integer to double using ARM64 scvtf
    scvtf d0, _xtmp            // Convert signed int64 to double

    // Store to XMM register (low 64 bits)
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    str d0, [x8]               // Store double to low 64 bits
    // High 64 bits are preserved (per Intel docs for scalar operations)
    gret 1

// CVTSI2SD xmm, r32 - Convert 32-bit signed integer to double
// _xtmp = source integer (32-bit in low word), [_ip] = destination XMM index
.gadget cvtsi2sd_reg32
    // Sign-extend 32-bit to 64-bit, then convert
    sxtw x8, w0                // Sign-extend w0 (low 32 bits of _xtmp)
    scvtf d0, x8               // Convert signed int32 to double

    // Store to XMM register (low 64 bits)
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    str d0, [x8]               // Store double to low 64 bits
    gret 1

// CVTSI2SD xmm, m64 - Convert 64-bit integer from memory to double
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget cvtsi2sd_mem64
    read_prep 64, cvtsi2sd_mem64
    ldr x8, [_addr]            // Load 64-bit integer from memory

    // Convert integer to double
    scvtf d0, x8               // Convert signed int64 to double

    // Store to XMM register
    ldr x9, [_ip]              // XMM register index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[n]
    str d0, [x9]               // Store double to low 64 bits
    gret 2
    read_bullshit 64, cvtsi2sd_mem64

// CVTSI2SD xmm, m32 - Convert 32-bit integer from memory to double
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget cvtsi2sd_mem32
    read_prep 32, cvtsi2sd_mem32
    ldrsw x8, [_addr]          // Load 32-bit integer (sign-extended) from memory

    // Convert integer to double
    scvtf d0, x8               // Convert signed int32 to double

    // Store to XMM register
    ldr x9, [_ip]              // XMM register index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[n]
    str d0, [x9]               // Store double to low 64 bits
    gret 2
    read_bullshit 32, cvtsi2sd_mem32

// ============================================================
// CVTSI2SS - Convert Signed Integer to Scalar Single-Precision Float
// ============================================================

// CVTSI2SS xmm, r64 - Convert 64-bit signed integer to float
// _xtmp = source integer (64-bit), [_ip] = destination XMM index
.gadget cvtsi2ss_reg64
    scvtf s0, _xtmp            // Convert signed int64 to float32

    // Store to XMM register (low 32 bits only, upper 96 bits preserved)
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    str s0, [x8]               // Store float to low 32 bits
    gret 1

// CVTSI2SS xmm, r32 - Convert 32-bit signed integer to float
// _xtmp = source integer (32-bit in low word), [_ip] = destination XMM index
.gadget cvtsi2ss_reg32
    sxtw x8, w0                // Sign-extend w0
    scvtf s0, x8               // Convert signed int32 to float32

    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    str s0, [x8]               // Store float to low 32 bits
    gret 1

// CVTSI2SS xmm, m64 - Convert 64-bit integer from memory to float
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget cvtsi2ss_mem64
    read_prep 64, cvtsi2ss_mem64
    ldr x8, [_addr]
    scvtf s0, x8

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str s0, [x9]
    gret 2
    read_bullshit 64, cvtsi2ss_mem64

// CVTSI2SS xmm, m32 - Convert 32-bit integer from memory to float
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget cvtsi2ss_mem32
    read_prep 32, cvtsi2ss_mem32
    ldrsw x8, [_addr]
    scvtf s0, x8

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str s0, [x9]
    gret 2
    read_bullshit 32, cvtsi2ss_mem32

// ============================================================
// CVTTSD2SI - Convert with Truncation Scalar Double to Signed Integer
// Truncation means round toward zero (unlike CVTSD2SI which uses rounding mode)
// ============================================================

// CVTTSD2SI r64, xmm - Convert truncated double to 64-bit signed integer
// [_ip] = source XMM index, result in _xtmp
.gadget cvttsd2si_reg64
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr d0, [x8]               // Load double from XMM

    // Convert to signed 64-bit integer with truncation toward zero
    fcvtzs _xtmp, d0           // ARM64 fcvtzs = convert to signed int, toward zero
    gret 1

// CVTTSD2SI r32, xmm - Convert truncated double to 32-bit signed integer
// [_ip] = source XMM index, result in _tmp (low 32 bits of _xtmp)
.gadget cvttsd2si_reg32
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4              // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[n]
    ldr d0, [x8]               // Load double from XMM

    // Convert to signed 32-bit integer with truncation toward zero
    fcvtzs w0, d0              // Convert to 32-bit signed int
    uxtw _xtmp, w0             // Zero-extend to 64-bit in _xtmp
    gret 1

// CVTTSD2SI r64, m64 - Convert truncated double from memory to 64-bit signed integer
// _addr = memory address (GUEST), result in _xtmp
.gadget cvttsd2si_mem64
    read_prep 64, cvttsd2si_mem64
    ldr d0, [_addr]            // Load double from memory

    // Convert to signed 64-bit integer with truncation toward zero
    fcvtzs _xtmp, d0
    gret 1
    read_bullshit 64, cvttsd2si_mem64

// CVTTSD2SI r32, m64 - Convert truncated double from memory to 32-bit signed integer
// _addr = memory address (GUEST), result in _tmp
.gadget cvttsd2si_mem32
    read_prep 64, cvttsd2si_mem32
    ldr d0, [_addr]            // Load double from memory

    // Convert to signed 32-bit integer with truncation toward zero
    fcvtzs w0, d0
    uxtw _xtmp, w0             // Zero-extend to 64-bit in _xtmp
    gret 1
    read_bullshit 64, cvttsd2si_mem32

// ============================================================
// CVTSD2SI - Convert Scalar Double to Signed Integer (rounded)
// Uses fcvtns (round to nearest, ties to even) - x86 default rounding mode
// ============================================================

// CVTSD2SI r64, xmm
.gadget cvtsd2si_reg64
    ldr x8, [_ip]              // XMM register index
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]               // Load double from XMM
    fcvtns _xtmp, d0           // Round to nearest, ties to even
    gret 1

// CVTSD2SI r32, xmm
.gadget cvtsd2si_reg32
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]
    fcvtns w0, d0              // Round to nearest 32-bit
    uxtw _xtmp, w0
    gret 1

// CVTSD2SI r64, m64
.gadget cvtsd2si_mem64
    read_prep 64, cvtsd2si_mem64
    ldr d0, [_addr]
    fcvtns _xtmp, d0
    gret 1
    read_bullshit 64, cvtsd2si_mem64

// CVTSD2SI r32, m64
.gadget cvtsd2si_mem32
    read_prep 64, cvtsd2si_mem32
    ldr d0, [_addr]
    fcvtns w0, d0
    uxtw _xtmp, w0
    gret 1
    read_bullshit 64, cvtsd2si_mem32

// ============================================================
// CVTSS2SI - Convert Scalar Single to Signed Integer (rounded)
// ============================================================

// CVTSS2SI r64, xmm
.gadget cvtss2si_reg64
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]               // Load float from XMM
    fcvtns _xtmp, s0           // Round to nearest, ties to even
    gret 1

// CVTSS2SI r32, xmm
.gadget cvtss2si_reg32
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]
    fcvtns w0, s0
    uxtw _xtmp, w0
    gret 1

// CVTSS2SI r64, m32
.gadget cvtss2si_mem64
    read_prep 32, cvtss2si_mem64
    ldr s0, [_addr]
    fcvtns _xtmp, s0
    gret 1
    read_bullshit 32, cvtss2si_mem64

// CVTSS2SI r32, m32
.gadget cvtss2si_mem32
    read_prep 32, cvtss2si_mem32
    ldr s0, [_addr]
    fcvtns w0, s0
    uxtw _xtmp, w0
    gret 1
    read_bullshit 32, cvtss2si_mem32

// ============================================================
// ADDSD - Add Scalar Double-Precision
// ============================================================

// ADDSD xmm, xmm - Add two scalar doubles
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget addsd_xmm_xmm
    // Load source XMM low 64 bits
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr d0, [x8]               // Load src double

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Add
    fadd d1, d1, d0            // dst = dst + src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 1

// ADDSD xmm, m64 - Add scalar double from memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget addsd_xmm_mem
    read_prep 64, addsd_xmm_mem
    ldr d0, [_addr]            // Load double from memory

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Add
    fadd d1, d1, d0            // dst = dst + src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 2
    read_bullshit 64, addsd_xmm_mem

// ============================================================
// SUBSD - Subtract Scalar Double-Precision
// ============================================================

// SUBSD xmm, xmm - Subtract two scalar doubles
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget subsd_xmm_xmm
    // Load source XMM low 64 bits
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr d0, [x8]               // Load src double

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Subtract
    fsub d1, d1, d0            // dst = dst - src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 1

// SUBSD xmm, m64 - Subtract scalar double from memory
// _addr = memory address (GUEST), [_ip] = destination XMM index, [_ip+8] = orig_ip
.gadget subsd_xmm_mem
    read_prep 64, subsd_xmm_mem
    ldr d0, [_addr]            // Load double from memory

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Subtract
    fsub d1, d1, d0            // dst = dst - src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 2
    read_bullshit 64, subsd_xmm_mem

// ============================================================
// MULSD - Multiply Scalar Double-Precision
// ============================================================

// MULSD xmm, xmm - Multiply two scalar doubles
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget mulsd_xmm_xmm
    // Load source XMM low 64 bits
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr d0, [x8]               // Load src double

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Multiply
    fmul d1, d1, d0            // dst = dst * src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 1

// MULSD xmm, m64 - Multiply scalar double from memory
// _addr = memory address (GUEST), [_ip] = destination XMM index, [_ip+8] = orig_ip
.gadget mulsd_xmm_mem
    read_prep 64, mulsd_xmm_mem
    ldr d0, [_addr]            // Load double from memory

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Multiply
    fmul d1, d1, d0            // dst = dst * src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 2
    read_bullshit 64, mulsd_xmm_mem

// DIVSD xmm, xmm - Divide scalar double
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget divsd_xmm_xmm
    // Load source XMM low 64 bits
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr d0, [x8]               // Load src double

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Divide
    fdiv d1, d1, d0            // dst = dst / src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 1

// DIVSD xmm, m64 - Divide scalar double from memory
// _addr = memory address (GUEST), [_ip] = destination XMM index, [_ip+8] = orig_ip
.gadget divsd_xmm_mem
    read_prep 64, divsd_xmm_mem
    ldr d0, [_addr]            // Load double from memory

    // Load destination XMM low 64 bits
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr d1, [x9]               // Load dst double

    // Divide
    fdiv d1, d1, d0            // dst = dst / src

    // Store result
    str d1, [x9]               // Store to dst low 64 bits
    gret 2
    read_bullshit 64, divsd_xmm_mem

// MINSD xmm, xmm - Minimum scalar double
// _xtmp = source XMM index, [_ip] = dest XMM index
.gadget minsd_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]               // src double

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr d1, [x9]               // dst double

    fmin d1, d1, d0            // dst = min(dst, src)
    str d1, [x9]
    gret 1

// MINSD xmm, m64
.gadget minsd_xmm_mem
    read_prep 64, minsd_xmm_mem
    ldr d0, [_addr]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr d1, [x9]

    fmin d1, d1, d0
    str d1, [x9]
    gret 2
    read_bullshit 64, minsd_xmm_mem

// MAXSD xmm, xmm - Maximum scalar double
.gadget maxsd_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr d1, [x9]

    fmax d1, d1, d0
    str d1, [x9]
    gret 1

// MAXSD xmm, m64
.gadget maxsd_xmm_mem
    read_prep 64, maxsd_xmm_mem
    ldr d0, [_addr]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr d1, [x9]

    fmax d1, d1, d0
    str d1, [x9]
    gret 2
    read_bullshit 64, maxsd_xmm_mem

// ============================================================
// SQRTSD - Square Root Scalar Double-Precision
// ============================================================

// SQRTSD xmm, xmm - Square root of source, store in dst low 64 bits
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget sqrtsd_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]               // Load src double

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]

    fsqrt d0, d0               // sqrt(src)
    str d0, [x9]               // Store to dst low 64 bits
    gret 1

// SQRTSD xmm, m64
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget sqrtsd_xmm_mem
    read_prep 64, sqrtsd_xmm_mem
    ldr d0, [_addr]            // Load double from memory

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9

    fsqrt d0, d0
    str d0, [x9]
    gret 2
    read_bullshit 64, sqrtsd_xmm_mem

// ============================================================
// SQRTSS - Square Root Scalar Single-Precision
// ============================================================

// SQRTSS xmm, xmm
.gadget sqrtss_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]               // Load src float

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9

    fsqrt s0, s0               // sqrt(src)
    str s0, [x9]               // Store to dst low 32 bits
    gret 1

// SQRTSS xmm, m32
.gadget sqrtss_xmm_mem
    read_prep 32, sqrtss_xmm_mem
    ldr s0, [_addr]            // Load float from memory

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9

    fsqrt s0, s0
    str s0, [x9]
    gret 2
    read_bullshit 32, sqrtss_xmm_mem

// ============================================================
// MINSS/MAXSS - Min/Max Scalar Single-Precision
// ============================================================

// MINSS xmm, xmm
.gadget minss_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]               // src float

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]               // dst float

    fmin s1, s1, s0            // dst = min(dst, src)
    str s1, [x9]
    gret 1

// MINSS xmm, m32
.gadget minss_xmm_mem
    read_prep 32, minss_xmm_mem
    ldr s0, [_addr]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]

    fmin s1, s1, s0
    str s1, [x9]
    gret 2
    read_bullshit 32, minss_xmm_mem

// MAXSS xmm, xmm
.gadget maxss_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]

    fmax s1, s1, s0
    str s1, [x9]
    gret 1

// MAXSS xmm, m32
.gadget maxss_xmm_mem
    read_prep 32, maxss_xmm_mem
    ldr s0, [_addr]

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]

    fmax s1, s1, s0
    str s1, [x9]
    gret 2
    read_bullshit 32, maxss_xmm_mem

// ============================================================
// CMPSD xmm, xmm/m64, imm8 - Compare Scalar Double with predicate
// Uses C helper: helper_cmpsd(cpu, dst_idx, src_idx, pred)
// ============================================================

// CMPSD xmm, xmm, imm8
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = predicate
.gadget cmpsd_xmm_xmm
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // predicate imm8
    bl NAME(helper_cmpsd)
    restore_c
    gret 3

// CMPSD xmm, m64, imm8
// Address already in _addr, [_ip] = dst XMM index, [_ip+8] = predicate, [_ip+16] = orig_ip
.gadget cmpsd_xmm_mem
    read_prep 64, cmpsd_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov x2, _addr              // host memory address
    ldr x3, [_ip, 8]           // predicate imm8
    bl NAME(helper_cmpsd_mem)
    restore_c
    gret 3
    read_bullshit 64, cmpsd_xmm_mem

// ============================================================
// CMPSS xmm, xmm/m32, imm8 - Compare Scalar Single with predicate
// Uses C helper: helper_cmpss(cpu, dst_idx, src_idx, pred)
// ============================================================

// CMPSS xmm, xmm, imm8
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = predicate imm8
.gadget cmpss_xmm_xmm
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // predicate imm8
    bl NAME(helper_cmpss)
    restore_c
    gret 3

// CMPSS xmm, m32, imm8
// Address already in _addr, [_ip] = dst XMM index, [_ip+8] = predicate, [_ip+16] = orig_ip
.gadget cmpss_xmm_mem
    read_prep 32, cmpss_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov x2, _addr              // host memory address
    ldr x3, [_ip, 8]           // predicate imm8
    bl NAME(helper_cmpss_mem)
    restore_c
    gret 3
    read_bullshit 32, cmpss_xmm_mem

// ============================================================
// CMPPD xmm, xmm/m128, imm8 - Compare Packed Double-Precision
// ============================================================

.gadget cmppd_xmm_xmm
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    ldr x3, [_ip, 16]
    bl NAME(helper_cmppd)
    restore_c
    gret 3

.gadget cmppd_xmm_mem
    read_prep 128, cmppd_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_cmppd_mem)
    restore_c
    gret 3
    read_bullshit 128, cmppd_xmm_mem

// ============================================================
// CMPPS xmm, xmm/m128, imm8 - Compare Packed Single-Precision
// ============================================================

.gadget cmpps_xmm_xmm
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    ldr x2, [_ip, 8]
    ldr x3, [_ip, 16]
    bl NAME(helper_cmpps)
    restore_c
    gret 3

.gadget cmpps_xmm_mem
    read_prep 128, cmpps_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_cmpps_mem)
    restore_c
    gret 3
    read_bullshit 128, cmpps_xmm_mem

// ============================================================
// SHUFPD xmm, xmm/m128, imm8 - Shuffle Packed Double-Precision
// Uses C helper: helper_shufpd(cpu, dst_idx, src_idx, imm)
// ============================================================

// SHUFPD xmm, xmm, imm8
// [_ip] = dst XMM index, [_ip+8] = src XMM index, [_ip+16] = imm8
.gadget shufpd_xmm_xmm
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    ldr x2, [_ip, 8]           // src XMM index
    ldr x3, [_ip, 16]          // imm8
    bl NAME(helper_shufpd)
    restore_c
    gret 3

// SHUFPD xmm, m128, imm8
// Address already in _addr, [_ip] = dst XMM index, [_ip+8] = imm8, [_ip+16] = orig_ip
.gadget shufpd_xmm_mem
    read_prep 128, shufpd_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]              // dst XMM index
    mov x2, _addr              // host memory address
    ldr x3, [_ip, 8]           // imm8
    bl NAME(helper_shufpd_mem)
    restore_c
    gret 3
    read_bullshit 128, shufpd_xmm_mem

// ============================================================
// SHUFPS xmm, m128, imm8 - Shuffle Packed Single-Precision (memory form)
// ============================================================

.gadget shufps_xmm_mem
    read_prep 128, shufps_xmm_mem
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    mov x2, _addr
    ldr x3, [_ip, 8]
    bl NAME(helper_shufps_mem)
    restore_c
    gret 3
    read_bullshit 128, shufps_xmm_mem

// ============================================================
// COMISD/UCOMISD - Compare Scalar Double (sets x86 EFLAGS)
// Result in ZF, PF, CF:
//   src1 > src2:  ZF=0, PF=0, CF=0
//   src1 < src2:  ZF=0, PF=0, CF=1
//   src1 == src2: ZF=1, PF=0, CF=0
//   unordered:    ZF=1, PF=1, CF=1
// ============================================================

// COMISD xmm, xmm - Compare two scalar doubles
// _xtmp = first XMM index, [_ip] = second XMM index
.gadget comisd_xmm_xmm
    // Load first XMM
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src1]
    ldr d0, [x8]               // Load first double

    // Load second XMM
    ldr x9, [_ip]              // Second XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[src2]
    ldr d1, [x9]               // Load second double

    // Compare (ARM64 fcmp sets NZCV)
    fcmp d0, d1

    // Convert ARM64 flags to x86 flags
    // ARM64 fcmp results:
    //   d0 > d1:  N=0, Z=0, C=1, V=0
    //   d0 < d1:  N=1, Z=0, C=0, V=0
    //   d0 == d1: N=0, Z=1, C=1, V=0
    //   unordered: N=0, Z=0, C=1, V=1
    //
    // x86 COMISD results:
    //   d0 > d1:  ZF=0, PF=0, CF=0
    //   d0 < d1:  ZF=0, PF=0, CF=1
    //   d0 == d1: ZF=1, PF=0, CF=0
    //   unordered: ZF=1, PF=1, CF=1
    // Always: SF=0, OF=0

    // Clear SF, OF
    strb wzr, [_cpu, CPU_of]

    // Clear ZF_RES and PF_RES bits so flags are read from eflags
    ldr w10, [_cpu, CPU_flags_res]
    mov w11, (ZF_RES | PF_RES | SF_RES)
    bic w10, w10, w11
    str w10, [_cpu, CPU_flags_res]

    // Load eflags and clear ZF, PF, SF bits
    ldr w10, [_cpu, CPU_eflags]
    mov w11, (ZF_FLAG | PF_FLAG | SF_FLAG)
    bic w10, w10, w11

    // Default: CF=0
    strb wzr, [_cpu, CPU_cf]

    // Check for unordered (V=1)
    b.vs .Lcomisd_unordered
    // Check for equal (Z=1)
    b.eq .Lcomisd_equal
    // Check for less than (N=1, means d0 < d1)
    b.mi .Lcomisd_less
    // Otherwise greater (d0 > d1): ZF=0, PF=0, CF=0
    b .Lcomisd_done

.Lcomisd_unordered:
    // ZF=1, PF=1, CF=1
    mov w11, (ZF_FLAG | PF_FLAG)
    orr w10, w10, w11
    mov w11, 1
    strb w11, [_cpu, CPU_cf]
    b .Lcomisd_done

.Lcomisd_equal:
    // ZF=1, PF=0, CF=0
    orr w10, w10, ZF_FLAG
    b .Lcomisd_done

.Lcomisd_less:
    // ZF=0, PF=0, CF=1
    mov w11, 1
    strb w11, [_cpu, CPU_cf]
    // Fall through to done

.Lcomisd_done:
    str w10, [_cpu, CPU_eflags]
    gret 1

// COMISD xmm, m64 - Compare scalar double from XMM with memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget comisd_xmm_mem
    read_prep 64, comisd_xmm_mem
    ldr d1, [_addr]            // Load second double from memory

    // Load first XMM
    ldr x9, [_ip]              // XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[src1]
    ldr d0, [x9]               // Load first double

    // Compare (ARM64 fcmp sets NZCV)
    fcmp d0, d1

    // Clear SF, OF
    strb wzr, [_cpu, CPU_of]

    // Clear ZF_RES and PF_RES bits so flags are read from eflags
    ldr w10, [_cpu, CPU_flags_res]
    mov w11, (ZF_RES | PF_RES | SF_RES)
    bic w10, w10, w11
    str w10, [_cpu, CPU_flags_res]

    // Load eflags and clear ZF, PF, SF bits
    ldr w10, [_cpu, CPU_eflags]
    mov w11, (ZF_FLAG | PF_FLAG | SF_FLAG)
    bic w10, w10, w11

    // Default: CF=0
    strb wzr, [_cpu, CPU_cf]

    b.vs .Lcomisd_mem_unord
    b.eq .Lcomisd_mem_eq
    b.mi .Lcomisd_mem_lt
    b .Lcomisd_mem_done

.Lcomisd_mem_unord:
    // ZF=1, PF=1, CF=1
    mov w11, (ZF_FLAG | PF_FLAG)
    orr w10, w10, w11
    mov w11, 1
    strb w11, [_cpu, CPU_cf]
    b .Lcomisd_mem_done

.Lcomisd_mem_eq:
    // ZF=1, PF=0, CF=0
    orr w10, w10, ZF_FLAG
    b .Lcomisd_mem_done

.Lcomisd_mem_lt:
    // ZF=0, PF=0, CF=1
    mov w11, 1
    strb w11, [_cpu, CPU_cf]

.Lcomisd_mem_done:
    str w10, [_cpu, CPU_eflags]
    gret 2
    read_bullshit 64, comisd_xmm_mem

// ============================================================
// Scalar Single-Precision FP Operations (ADDSS, SUBSS, MULSS, DIVSS)
// ============================================================

// Helper macro for scalar single-precision xmm,xmm ops
// _xtmp = source XMM index, [_ip] = destination XMM index
.macro ss_xmm_xmm_op name, insn
.gadget \name\()_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]               // Load src float (low 32 bits)

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]               // Load dst float (low 32 bits)

    \insn s1, s1, s0           // dst = dst op src

    str s1, [x9]               // Store result to dst low 32 bits
    gret 1
.endm

// Helper macro for scalar single-precision xmm,mem ops
// _addr = GUEST mem addr, [_ip] = XMM index, [_ip+8] = orig_ip
.macro ss_xmm_mem_op name, insn
.gadget \name\()_xmm_mem
    read_prep 32, \name\()_xmm_mem
    ldr s0, [_addr]            // Load float from memory

    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s1, [x9]               // Load dst float

    \insn s1, s1, s0           // dst = dst op src

    str s1, [x9]               // Store result
    gret 2
    read_bullshit 32, \name\()_xmm_mem
.endm

ss_xmm_xmm_op addss, fadd
ss_xmm_mem_op addss, fadd
ss_xmm_xmm_op subss, fsub
ss_xmm_mem_op subss, fsub
ss_xmm_xmm_op mulss, fmul
ss_xmm_mem_op mulss, fmul
ss_xmm_xmm_op divss, fdiv
ss_xmm_mem_op divss, fdiv

// CVTSS2SD xmm, xmm - Convert scalar single to scalar double
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget cvtss2sd_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]               // Load src float
    fcvt d0, s0                // Convert float to double
    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str d0, [x9]               // Store double to dst low 64 bits
    gret 1

// CVTSS2SD xmm, m32 - Convert scalar single from memory to double
.gadget cvtss2sd_xmm_mem
    read_prep 32, cvtss2sd_xmm_mem
    ldr s0, [_addr]
    fcvt d0, s0                // float → double
    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str d0, [x9]
    gret 2
    read_bullshit 32, cvtss2sd_xmm_mem

// CVTSD2SS xmm, xmm - Convert scalar double to scalar single
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget cvtsd2ss_xmm_xmm
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr d0, [x8]               // Load src double
    fcvt s0, d0                // Convert double to float
    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str s0, [x9]               // Store float to dst low 32 bits
    gret 1

// CVTSD2SS xmm, m64 - Convert scalar double from memory to single
.gadget cvtsd2ss_xmm_mem
    read_prep 64, cvtsd2ss_xmm_mem
    ldr d0, [_addr]
    fcvt s0, d0                // double → float
    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    str s0, [x9]
    gret 2
    read_bullshit 64, cvtsd2ss_xmm_mem

// CVTTSS2SI r64, xmm - Convert truncated float to 64-bit signed integer
.gadget cvttss2si_reg64
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]
    fcvtzs _xtmp, s0           // Convert float to int64 with truncation
    gret 1

// CVTTSS2SI r32, xmm - Convert truncated float to 32-bit signed integer
.gadget cvttss2si_reg32
    ldr x8, [_ip]
    lsl x8, x8, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s0, [x8]
    fcvtzs w0, s0              // Convert float to int32 with truncation
    uxtw _xtmp, w0
    gret 1

// UCOMISS xmm, xmm - Unordered compare scalar single (sets EFLAGS)
// _xtmp = second XMM index, [_ip] = first XMM index
.gadget ucomiss_xmm_xmm
    // Load first XMM
    ldr x9, [_ip]
    lsl x9, x9, 4
    add x9, x9, CPU_xmm
    add x9, _cpu, x9
    ldr s0, [x9]               // first operand

    // Load second XMM
    lsl x8, _xtmp, 4
    add x8, x8, CPU_xmm
    add x8, _cpu, x8
    ldr s1, [x8]               // second operand

    fcmp s0, s1

    // Set flags (same logic as COMISD)
    strb wzr, [_cpu, CPU_of]
    ldr w10, [_cpu, CPU_flags_res]
    mov w11, (ZF_RES | PF_RES | SF_RES)
    bic w10, w10, w11
    str w10, [_cpu, CPU_flags_res]
    ldr w10, [_cpu, CPU_eflags]
    mov w11, (ZF_FLAG | PF_FLAG | SF_FLAG)
    bic w10, w10, w11
    strb wzr, [_cpu, CPU_cf]

    b.vs .Lucomiss_unord
    b.eq .Lucomiss_eq
    b.mi .Lucomiss_lt
    b .Lucomiss_done

.Lucomiss_unord:
    mov w11, (ZF_FLAG | PF_FLAG)
    orr w10, w10, w11
    mov w11, 1
    strb w11, [_cpu, CPU_cf]
    b .Lucomiss_done

.Lucomiss_eq:
    orr w10, w10, ZF_FLAG
    b .Lucomiss_done

.Lucomiss_lt:
    mov w11, 1
    strb w11, [_cpu, CPU_cf]

.Lucomiss_done:
    str w10, [_cpu, CPU_eflags]
    gret 1

// COMISS/UCOMISS xmm, m32 - Compare scalar single from XMM with memory
// _addr = memory address (GUEST), [_ip] = XMM index, [_ip+8] = orig_ip
.gadget comiss_xmm_mem
    read_prep 32, comiss_xmm_mem
    ldr s1, [_addr]            // Load second float from memory

    // Load first XMM
    ldr x9, [_ip]              // XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[src1]
    ldr s0, [x9]               // Load first float

    // Compare (ARM64 fcmp sets NZCV)
    fcmp s0, s1

    // Clear SF, OF
    strb wzr, [_cpu, CPU_of]

    // Clear ZF_RES and PF_RES bits so flags are read from eflags
    ldr w10, [_cpu, CPU_flags_res]
    mov w11, (ZF_RES | PF_RES | SF_RES)
    bic w10, w10, w11
    str w10, [_cpu, CPU_flags_res]

    // Load eflags and clear ZF, PF, SF bits
    ldr w10, [_cpu, CPU_eflags]
    mov w11, (ZF_FLAG | PF_FLAG | SF_FLAG)
    bic w10, w10, w11

    // Default: CF=0
    strb wzr, [_cpu, CPU_cf]

    b.vs .Lcomiss_mem_unord
    b.eq .Lcomiss_mem_eq
    b.mi .Lcomiss_mem_lt
    b .Lcomiss_mem_done

.Lcomiss_mem_unord:
    // ZF=1, PF=1, CF=1
    mov w11, (ZF_FLAG | PF_FLAG)
    orr w10, w10, w11
    mov w11, 1
    strb w11, [_cpu, CPU_cf]
    b .Lcomiss_mem_done

.Lcomiss_mem_eq:
    // ZF=1, PF=0, CF=0
    orr w10, w10, ZF_FLAG
    b .Lcomiss_mem_done

.Lcomiss_mem_lt:
    // ZF=0, PF=0, CF=1
    mov w11, 1
    strb w11, [_cpu, CPU_cf]

.Lcomiss_mem_done:
    str w10, [_cpu, CPU_eflags]
    gret 2
    read_bullshit 32, comiss_xmm_mem

// ============================================================================
// STMXCSR / LDMXCSR - Store/Load MXCSR register
// ============================================================================

// STMXCSR m32 - Store MXCSR to memory
// We always store 0x1F80 (default: round-to-nearest, all exceptions masked)
// _addr = memory address (GUEST), [_ip] = orig_ip
.gadget stmxcsr
    write_prep 32, stmxcsr
    mov w8, 0x1F80
    str w8, [_addr]
    write_done 32, stmxcsr
    gret 1
    write_bullshit 32, stmxcsr

// LDMXCSR m32 - Load MXCSR from memory (NOP - read and discard)
// _addr = memory address (GUEST), [_ip] = orig_ip
.gadget ldmxcsr
    read_prep 32, ldmxcsr
    // Read from memory but discard - we don't actually use MXCSR
    ldr w8, [_addr]
    gret 1
    read_bullshit 32, ldmxcsr

// ============================================================================
// x87 FPU Gadgets
// These call C helper functions for FPU operations
// ============================================================================

// FILD - Load Integer to FPU stack
// [_ip] = orig_ip for segfault handler
.gadget fpu_fild16
    read_prep 16, fpu_fild16
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fild16)
    restore_c
    gret 1
    read_bullshit 16, fpu_fild16

.gadget fpu_fild32
    read_prep 32, fpu_fild32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fild32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fild32

.gadget fpu_fild64
    read_prep 64, fpu_fild64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fild64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fild64

// FISTP - Store Integer and Pop
// FIST - Store Integer (without pop)
.gadget fpu_fist16
    write_prep 16, fpu_fist16
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fist16)
    restore_c
    write_done 16, fpu_fist16
    gret 1
    write_bullshit 16, fpu_fist16

.gadget fpu_fist32
    write_prep 32, fpu_fist32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fist32)
    restore_c
    write_done 32, fpu_fist32
    gret 1
    write_bullshit 32, fpu_fist32

// FISTP - Store Integer and Pop
.gadget fpu_fistp16
    write_prep 16, fpu_fistp16
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fistp16)
    restore_c
    write_done 16, fpu_fistp16
    gret 1
    write_bullshit 16, fpu_fistp16

.gadget fpu_fistp32
    write_prep 32, fpu_fistp32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fistp32)
    restore_c
    write_done 32, fpu_fistp32
    gret 1
    write_bullshit 32, fpu_fistp32

.gadget fpu_fistp64
    write_prep 64, fpu_fistp64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fistp64)
    restore_c
    write_done 64, fpu_fistp64
    gret 1
    write_bullshit 64, fpu_fistp64

// FLD - Load Float to FPU stack
.gadget fpu_fld32
    read_prep 32, fpu_fld32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fld32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fld32

.gadget fpu_fld64
    read_prep 64, fpu_fld64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fld64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fld64

.gadget fpu_fld80
    read_prep 128, fpu_fld80
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fld80)
    restore_c
    gret 1
    read_bullshit 128, fpu_fld80

// FLD ST(i) - Load from FPU register
// [_ip] = i (FPU stack index)
.gadget fpu_fld_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fld_sti)
    restore_c
    gret 1

// FSTP - Store Float and Pop
.gadget fpu_fstp32
    write_prep 32, fpu_fstp32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fstp32)
    restore_c
    write_done 32, fpu_fstp32
    gret 1
    write_bullshit 32, fpu_fstp32

.gadget fpu_fstp64
    write_prep 64, fpu_fstp64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fstp64)
    restore_c
    write_done 64, fpu_fstp64
    gret 1
    write_bullshit 64, fpu_fstp64

.gadget fpu_fstp80
    write_prep 128, fpu_fstp80
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fstp80)
    restore_c
    write_done 128, fpu_fstp80
    gret 1
    write_bullshit 128, fpu_fstp80

// FSTP ST(i) - Store to FPU register and pop
// [_ip] = i (FPU stack index)
.gadget fpu_fstp_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fstp_sti)
    restore_c
    gret 1

// FADD operations
// [_ip] = i (FPU stack index)
.gadget fpu_fadd
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fadd)
    restore_c
    gret 1

// FADD ST(i), ST(0) - result in ST(i)
.gadget fpu_fadd_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fadd_sti)
    restore_c
    gret 1

.gadget fpu_faddp
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_faddp)
    restore_c
    gret 1

.gadget fpu_fadd_m32
    read_prep 32, fpu_fadd_m32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fadd_m32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fadd_m32

.gadget fpu_fadd_m64
    read_prep 64, fpu_fadd_m64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fadd_m64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fadd_m64

// FSUB operations
.gadget fpu_fsub
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsub)
    restore_c
    gret 1

// FSUB ST(i), ST(0) - result in ST(i): ST(i) = ST(i) - ST(0)
.gadget fpu_fsub_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsub_sti)
    restore_c
    gret 1

.gadget fpu_fsubp
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsubp)
    restore_c
    gret 1

.gadget fpu_fsubr
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsubr)
    restore_c
    gret 1

// FSUBR ST(i), ST(0) - result in ST(i): ST(i) = ST(0) - ST(i)
.gadget fpu_fsubr_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsubr_sti)
    restore_c
    gret 1

.gadget fpu_fsubrp
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fsubrp)
    restore_c
    gret 1

.gadget fpu_fsub_m32
    read_prep 32, fpu_fsub_m32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fsub_m32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fsub_m32

.gadget fpu_fsub_m64
    read_prep 64, fpu_fsub_m64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fsub_m64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fsub_m64

// FMUL operations
.gadget fpu_fmul
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fmul)
    restore_c
    gret 1

// FMUL ST(i), ST(0) - result in ST(i): ST(i) = ST(i) * ST(0)
.gadget fpu_fmul_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fmul_sti)
    restore_c
    gret 1

.gadget fpu_fmulp
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fmulp)
    restore_c
    gret 1

.gadget fpu_fmul_m32
    read_prep 32, fpu_fmul_m32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fmul_m32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fmul_m32

.gadget fpu_fmul_m64
    read_prep 64, fpu_fmul_m64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fmul_m64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fmul_m64

// FDIV operations
.gadget fpu_fdiv
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fdiv)
    restore_c
    gret 1

// FDIV ST(i), ST(0) - result in ST(i): ST(i) = ST(i) / ST(0)
.gadget fpu_fdiv_sti
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fdiv_sti)
    restore_c
    gret 1

.gadget fpu_fdivp
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fdivp)
    restore_c
    gret 1

.gadget fpu_fdiv_m32
    read_prep 32, fpu_fdiv_m32
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fdiv_m32)
    restore_c
    gret 1
    read_bullshit 32, fpu_fdiv_m32

.gadget fpu_fdiv_m64
    read_prep 64, fpu_fdiv_m64
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fdiv_m64)
    restore_c
    gret 1
    read_bullshit 64, fpu_fdiv_m64

// FXCH - Exchange ST(0) and ST(i)
.gadget fpu_fxch
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fxch)
    restore_c
    gret 1

// FPREM - Partial Remainder
.gadget fpu_fprem
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fprem)
    restore_c
    gret

// FSCALE - Scale by Power of 2
.gadget fpu_fscale
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fscale)
    restore_c
    gret

// FRNDINT - Round to Integer
.gadget fpu_frndint
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_frndint)
    restore_c
    gret

// FABS - Absolute Value
.gadget fpu_fabs
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fabs)
    restore_c
    gret

// FCHS - Change Sign
.gadget fpu_fchs
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fchs)
    restore_c
    gret

// FINCSTP - Increment Stack Pointer
.gadget fpu_fincstp
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fincstp)
    restore_c
    gret

// Load Constants
.gadget fpu_fldz
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldz)
    restore_c
    gret

.gadget fpu_fld1
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fld1)
    restore_c
    gret

.gadget fpu_fldpi
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldpi)
    restore_c
    gret

.gadget fpu_fldl2e
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldl2e)
    restore_c
    gret

.gadget fpu_fldl2t
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldl2t)
    restore_c
    gret

.gadget fpu_fldlg2
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldlg2)
    restore_c
    gret

.gadget fpu_fldln2
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fldln2)
    restore_c
    gret

// FLDCW - Load Control Word
.gadget fpu_fldcw
    read_prep 16, fpu_fldcw
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fldcw)
    restore_c
    gret 1
    read_bullshit 16, fpu_fldcw

// FNSTCW - Store Control Word
.gadget fpu_fnstcw
    write_prep 16, fpu_fnstcw
    save_c
    mov x0, _cpu
    mov x1, _addr
    bl NAME(helper_fpu_fnstcw)
    restore_c
    write_done 16, fpu_fnstcw
    gret 1
    write_bullshit 16, fpu_fnstcw

// FNSTSW - Store Status Word to AX
// helper writes to cpu->rax in memory, but rax lives in ARM64 register x20
// must save_regs before (so helper sees current rax) and load_regs after
// (so x20 picks up the updated value). Without this, the FPREM+FNSTSW+TESTB
// loop in musl's fmodl spins forever because x20 retains stale AH with C2=1.
.gadget fpu_fnstsw
    save_regs
    save_c
    mov x0, _cpu
    bl NAME(helper_fpu_fnstsw)
    restore_c
    load_regs
    gret

// FUCOMIP - Unordered Compare, set EFLAGS, pop
// [_ip] = i (FPU stack index)
.gadget fpu_fucomip
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fucomip)
    restore_c
    gret 1

// FUCOMI - Unordered Compare, set EFLAGS (no pop)
// [_ip] = i (FPU stack index)
.gadget fpu_fucomi
    save_c
    mov x0, _cpu
    ldr x1, [_ip]
    bl NAME(helper_fpu_fucomi)
    restore_c
    gret 1
