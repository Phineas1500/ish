#include "emu/interrupt.h"
#include "gadgets.h"

.global NAME(fiber_enter)
.type_compat fiber_enter,function
NAME(fiber_enter):
    stp x18, x19, [sp, -0x70]!
    stp x20, x21, [sp, 0x10]
    stp x22, x23, [sp, 0x20]
    stp x24, x25, [sp, 0x30]
    stp x26, x27, [sp, 0x40]
    stp x28, x29, [sp, 0x50]
    str lr, [sp, 0x60]
    
    // CRITICAL DEBUG: Check input parameters to fiber_enter
#ifdef ISH_64BIT
    // In 64-bit mode, x19 is the RIP register, so use x15-x17
    mov x15, x0  // Save x0
    mov x16, x1  // Save x1
    mov x17, x2  // Save x2
#else
    // In 32-bit mode, x19 is safe to use
    mov x19, x0  // Save x0
    mov x20, x1  // Save x1
    mov x21, x2  // Save x2
#endif
    
    // DISABLED: Debug call: pass x2 (TLB base) and x2+32 (TLB entries)
    // mov x0, x2   // TLB base
    // add x1, x2, TLB_entries  // TLB entries pointer
    // bl NAME(debug_print_tlb_setup)
    
#ifdef ISH_64BIT
    mov x0, x15  // Restore x0
    mov x1, x16  // Restore x1
    mov x2, x17  // Restore x2
#else
    mov x0, x19  // Restore x0
    mov x1, x20  // Restore x1
    mov x2, x21  // Restore x2
#endif
    
    add _ip, x0, FIBER_BLOCK_code
    # cpu is already x1
    add _tlb, x2, TLB_entries
    
    // DISABLED: Debug TLB register immediately after setup
    // #ifdef ISH_64BIT
    //     // In 64-bit mode, x19 is the RIP register, so use x15
    //     mov x15, x1  // Save x1
    //     mov x0, _tlb // Pass _tlb register value
    //     bl NAME(debug_print_tlb)
    //     mov x1, x15  // Restore x1
    // #else
    //     // In 32-bit mode, x19 is safe to use
    //     mov x19, x1  // Save x1
    //     mov x0, _tlb // Pass _tlb register value
    //     bl NAME(debug_print_tlb)
    //     mov x1, x19  // Restore x1
    // #endif
    
    load_regs
    
#ifdef ISH_64BIT
    // MINIMAL DEBUG: Check _ip value before first gret
    stp x0, x1, [sp, -16]!
    mov x0, _ip
    bl NAME(debug_fiber_ip_value)
    ldp x0, x1, [sp], 16
#endif
    
    gret

.global fiber_ret_chain
fiber_ret_chain:
    // DEBUG: Temporarily disabled to debug crash
    // #ifdef ISH_64BIT
    //     // In 64-bit mode, x19 is the RIP register, so use x15
    //     mov x15, x1  // Save x1
    //     mov x0, x1   // Pass CPU pointer
    //     bl NAME(debug_fiber_ret_chain_reached)
    //     mov x1, x15  // Restore x1
    // #else
    //     // In 32-bit mode, x19 is safe to use
    //     mov x19, x1  // Save x1
    //     mov x0, x1   // Pass CPU pointer
    //     bl NAME(debug_fiber_ret_chain_reached)
    //     mov x1, x19  // Restore x1
    // #endif
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
    ldr eip, [_ip, -FIBER_BLOCK_code+FIBER_BLOCK_addr]
    # fallthrough

.global fiber_ret
fiber_ret:
#ifdef ISH_64BIT
    // DEBUG: Track if we reach fiber_ret
    stp x0, x1, [sp, -16]!
    bl NAME(debug_fiber_ret_reached) 
    ldp x0, x1, [sp], 16
#endif
    # load -1
    mvn _tmp, wzr
    # fallthrough

.global fiber_exit
fiber_exit:
#ifdef ISH_64BIT
    // DEBUG: Track if we reach fiber_exit
    stp x0, x1, [sp, -16]!
    mov w0, _tmp  // _tmp is w0 (32-bit)
    bl NAME(debug_fiber_exit_reached)
    ldp x0, x1, [sp], 16
#endif
    // DISABLED DEBUG CODE TO FIX INTERRUPT CORRUPTION
    // // DEBUG: Track x1 at fiber_exit entry
    // mov x19, x1  // Save x1 in x19 (callee-saved register)
    // mov x0, x1   // Pass x1 value to debug function
    // bl NAME(debug_track_x1_fiber_exit)
    // mov x1, x19  // Restore x1 from x19
    // 
    // // DEBUG: Track _tmp (actual interrupt code) at fiber_exit
    // mov x19, x1  // Save x1
    // mov x20, x0  // Save _tmp (x0)
    // mov x0, x20  // Pass _tmp to debug function
    // bl NAME(debug_track_interrupt_code)
    // 
    // mov x0, x20  // Restore _tmp
    // mov x1, x19  // Restore x1
    
    save_regs
    ldr lr, [sp, 0x60]
    ldp x28, x29, [sp, 0x50]
    ldp x26, x27, [sp, 0x40]
    ldp x24, x25, [sp, 0x30]
    ldp x22, x23, [sp, 0x20]
    ldp x20, x21, [sp, 0x10]
    ldp x18, x19, [sp], 0x70
    # _tmp is already x0
    ret

.gadget interrupt
    ldr _tmp, [_ip]
    ldr w8, [_ip, 16]
    str w8, [_cpu, CPU_segfault_addr]
    ldr eip, [_ip, 8]
    strb wzr, [_cpu, CPU_segfault_was_write]
    b fiber_exit

.gadget interrupt64
    // Load interrupt value from parameters
    ldr w0, [_ip]
    mov _tmp, w0
    ldr x8, [_ip, 16]
    str x8, [_cpu, CPU_segfault_addr]
    ldr rip, [_ip, 8]
    strb wzr, [_cpu, CPU_segfault_was_write]
    b fiber_exit

.gadget exit
#ifdef ISH_64BIT
    ldr rip, [_ip]
#else
    ldr eip, [_ip]
#endif
    b fiber_ret
