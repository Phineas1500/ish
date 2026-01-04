#include "emu/interrupt.h"
#include "gadgets.h"

// fiber_enter(struct fiber_block *block, struct cpu_state *cpu, struct tlb *tlb)
// Entry point for the threaded code interpreter
.global NAME(fiber_enter)
.type_compat fiber_enter,function
NAME(fiber_enter):
    // Save callee-saved registers
    stp x18, x19, [sp, -0x70]!
    stp x20, x21, [sp, 0x10]
    stp x22, x23, [sp, 0x20]
    stp x24, x25, [sp, 0x30]
    stp x26, x27, [sp, 0x40]
    stp x28, x29, [sp, 0x50]
    str lr, [sp, 0x60]

    // Setup interpreter state
    add _ip, x0, FIBER_BLOCK_code  // x0 = block, point to code array
    // _cpu is already x1 (cpu_state pointer)
    add _tlb, x2, TLB_entries      // x2 = tlb, point to entries

    // Load x86_64 registers from cpu_state
    load_regs

    // Jump to first gadget
    gret

// Return via call chaining
.global fiber_ret_chain
fiber_ret_chain:
    cmp _ip, 0
    b.lt fiber_ret
    ldr x8, [_cpu, CPU_poked_ptr]
    ldrb w8, [x8]
    cmp w8, 0
    b.ne poke
    sub x8, _ip, FIBER_BLOCK_code
    str x8, [_cpu, LOCAL_last_block]
    gret

poke:
    ldr rip, [_ip, -FIBER_BLOCK_code+FIBER_BLOCK_addr]
    // fallthrough

// Return from fiber (normal exit)
.global fiber_ret
fiber_ret:
    // Strip the high bit from _ip if set (fake_ip marker)
    // The real IP is _ip & ~(1 << 63)
    and rip, _ip, 0x7fffffffffffffff
    // Load -1 as return value (indicates need to re-translate)
    mvn _tmp, wzr
    // fallthrough

// Exit fiber and return to C code
.global fiber_exit
fiber_exit:
    save_regs
    ldr lr, [sp, 0x60]
    ldp x28, x29, [sp, 0x50]
    ldp x26, x27, [sp, 0x40]
    ldp x24, x25, [sp, 0x30]
    ldp x22, x23, [sp, 0x20]
    ldp x20, x21, [sp, 0x10]
    ldp x18, x19, [sp], 0x70
    // _tmp (x0) is already the return value
    ret

// Interrupt gadget - called for exceptions/syscalls
// Parameters in gadget stream: interrupt number, ip, segfault_addr
.gadget interrupt
    ldr _tmp, [_ip]           // interrupt number
    ldr x8, [_ip, 16]         // segfault_addr (64-bit for 64-bit guest)
    str x8, [_cpu, CPU_segfault_addr]
    ldr rip, [_ip, 8]         // ip where interrupt occurred
    strb wzr, [_cpu, CPU_segfault_was_write]
    b fiber_exit

// Exit gadget - normal block termination
.gadget exit
    ldr rip, [_ip]
    b fiber_ret
