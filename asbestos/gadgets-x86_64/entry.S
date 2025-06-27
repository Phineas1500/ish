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
    add _ip, x0, FIBER_BLOCK_code
    # cpu is already x1
    add _tlb, x2, TLB_entries
    load_regs
    gret

.global fiber_ret_chain
fiber_ret_chain:
    cmp _ip, 0
    b.lt fiber_ret
    ldr x8, [_cpu, CPU_poked_ptr]
    ldrb w8, [x8]
    cmp w8, 0
    b.ne poke
    sub x8, _ip, FIBER_BLOCK_code
    mov %r10, LOCAL_last_block(%_cpu)
    gret

poke:
    mov -FIBER_BLOCK_code+FIBER_BLOCK_addr(%_ip), %_eip
    # fallthrough

.global fiber_ret
fiber_ret:
    movl $-1, %_tmp
    # fallthrough

.global fiber_exit
fiber_exit:
    save_regs
    movl %_eip, CPU_eip(%_cpu)
    movq LOCAL_bp(%_cpu), %rsp
    add $0x8, %rsp # keep stack 16 byte aligned
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    mov %_tmp, %eax
    ret

.gadget interrupt
    movl (%_ip), %_tmp
    movl 16(%_ip), %r14d
    movl %r14d, CPU_segfault_addr(%_cpu)
    movl 8(%_ip), %_eip
    movb $0, CPU_segfault_was_write(%_cpu)
    jmp fiber_exit

.gadget exit
    movl (%_ip), %_eip
    jmp fiber_ret
