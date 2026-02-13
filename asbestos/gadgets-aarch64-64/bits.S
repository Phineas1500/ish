#include "gadgets.h"

// Bitwise operations for 64-bit

// ============================================================
// BT/BTS/BTR/BTC - Bit Test instructions
// These test a bit and set CF to its value
// BT:  just test
// BTS: test and set the bit to 1
// BTR: test and reset the bit to 0
// BTC: test and complement (toggle) the bit
// ============================================================

// BT reg-reg: Test bit (_xtmp % 64) of x8
// Entry: x8 = value to test, _xtmp = bit index
// Exit: CF = bit value, x8 unchanged, _xtmp = x8
.gadget bt64_reg
    and x9, _xtmp, 63           // Bit position mod 64
    lsr x10, x8, x9             // Shift bit to position 0
    and w10, w10, 1             // Isolate the bit
    strb w10, [_cpu, CPU_cf]    // Set CF
    mov _xtmp, x8               // Return original value
    gret

// BTS reg-reg: Test and set bit (_xtmp % 64) of x8
// Entry: x8 = value, _xtmp = bit index
// Exit: CF = old bit value, _xtmp = value with bit set
.gadget bts64_reg
    and x9, _xtmp, 63           // Bit position mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask with bit set
    lsr x10, x8, x9             // Shift bit to position 0
    and w10, w10, 1             // Isolate the bit
    strb w10, [_cpu, CPU_cf]    // Set CF to old value
    orr _xtmp, x8, x11          // Set the bit
    gret

// BTR reg-reg: Test and reset (clear) bit (_xtmp % 64) of x8
// Entry: x8 = value, _xtmp = bit index
// Exit: CF = old bit value, _xtmp = value with bit cleared
.gadget btr64_reg
    and x9, _xtmp, 63           // Bit position mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask with bit set
    lsr x10, x8, x9             // Shift bit to position 0
    and w10, w10, 1             // Isolate the bit
    strb w10, [_cpu, CPU_cf]    // Set CF to old value
    bic _xtmp, x8, x11          // Clear the bit
    gret

// BTC reg-reg: Test and complement (toggle) bit (_xtmp % 64) of x8
// Entry: x8 = value, _xtmp = bit index
// Exit: CF = old bit value, _xtmp = value with bit toggled
.gadget btc64_reg
    and x9, _xtmp, 63           // Bit position mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask with bit set
    lsr x10, x8, x9             // Shift bit to position 0
    and w10, w10, 1             // Isolate the bit
    strb w10, [_cpu, CPU_cf]    // Set CF to old value
    eor _xtmp, x8, x11          // Toggle the bit
    gret

// BT with immediate bit index
// Entry: _xtmp = value to test, immediate = bit index
.gadget bt64_imm
    ldr w9, [_ip]               // Get immediate bit index
    and w9, w9, 63              // Mod 64
    lsr x10, _xtmp, x9          // Shift bit to position 0
    and w10, w10, 1             // Isolate
    strb w10, [_cpu, CPU_cf]    // Set CF
    gret 1

// BTS with immediate bit index
.gadget bts64_imm
    ldr w9, [_ip]               // Get immediate bit index
    and w9, w9, 63              // Mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask
    lsr x10, _xtmp, x9          // Get old bit
    and w10, w10, 1
    strb w10, [_cpu, CPU_cf]
    orr _xtmp, _xtmp, x11       // Set the bit
    gret 1

// BTR with immediate bit index
.gadget btr64_imm
    ldr w9, [_ip]               // Get immediate bit index
    and w9, w9, 63              // Mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask
    lsr x10, _xtmp, x9          // Get old bit
    and w10, w10, 1
    strb w10, [_cpu, CPU_cf]
    bic _xtmp, _xtmp, x11       // Clear the bit
    gret 1

// BTC with immediate bit index
.gadget btc64_imm
    ldr w9, [_ip]               // Get immediate bit index
    and w9, w9, 63              // Mod 64
    mov x11, 1
    lsl x11, x11, x9            // Create mask
    lsr x10, _xtmp, x9          // Get old bit
    and w10, w10, 1
    strb w10, [_cpu, CPU_cf]
    eor _xtmp, _xtmp, x11       // Toggle the bit
    gret 1

// ============================================================
// NOT - Bitwise NOT (one's complement)
// ============================================================

.gadget not64
    mvn _xtmp, _xtmp
    gret

.gadget not32
    mvn _tmp, _tmp
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend to 64-bit
    gret

// ============================================================
// NEG - Two's complement negation
// ============================================================

.gadget neg64
    negs _xtmp, _xtmp
    setf_oc
    setf_zsp
    gret

.gadget neg32
    negs _tmp, _tmp
    setf_oc
    setf_zsp w
    gret

// 16-bit NEG - two's complement negation with 16-bit flag semantics
.gadget neg16
    and _xtmp, _xtmp, 0xffff
    // OF = 1 only if source is 0x8000 (negating INT16_MIN overflows)
    mov w10, 0x8000
    cmp _tmp, w10
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    // Negate with flags for CF
    negs _tmp, _tmp
    setf_c
    // Mask result to 16 bits
    and _xtmp, _xtmp, 0xffff
    // ZF/SF/PF based on 16-bit result
    setf_zsp h
    gret

// 8-bit NEG - two's complement negation with 8-bit flag semantics
.gadget neg8
    and _xtmp, _xtmp, 0xff
    // OF = 1 only if source is 0x80 (negating INT8_MIN overflows)
    cmp _tmp, 0x80
    cset w10, eq
    strb w10, [_cpu, CPU_of]
    // Negate with flags for CF
    negs _tmp, _tmp
    setf_c
    // Mask result to 8 bits
    and _xtmp, _xtmp, 0xff
    // ZF/SF/PF based on 8-bit result
    setf_zsp b
    gret

// Placeholder gadget arrays to satisfy linker
.pushsection_rodata
.global.name shl_gadgets
    .fill 60, 8, 0
.global.name shr_gadgets
    .fill 60, 8, 0
.global.name sar_gadgets
    .fill 60, 8, 0
.global.name rol_gadgets
    .fill 60, 8, 0
.global.name ror_gadgets
    .fill 60, 8, 0
.global.name rcl_gadgets
    .fill 60, 8, 0
.global.name rcr_gadgets
    .fill 60, 8, 0
.global.name and_gadgets
    .fill 60, 8, 0
.global.name or_gadgets
    .fill 60, 8, 0
.global.name xor_gadgets
    .fill 60, 8, 0
.global.name bt_gadgets
    .fill 60, 8, 0
.global.name bts_gadgets
    .fill 60, 8, 0
.global.name btr_gadgets
    .fill 60, 8, 0
.global.name btc_gadgets
    .fill 60, 8, 0
.global.name not_gadgets
    .fill 15, 8, 0
.global.name bswap_gadgets
    .fill 8, 8, 0
.popsection
