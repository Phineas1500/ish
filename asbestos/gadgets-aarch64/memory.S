#include "gadgets.h"
#include "emu/interrupt.h"

.gadget push
    sub _addr, esp, 4
    write_prep 32, push
    str _tmp, [_xaddr]
    write_done 32, push
    sub esp, esp, 4
    gret 1
    write_bullshit 32, push

#ifdef ISH_64BIT
.gadget push64
    sub _xaddr, rsp, 8
    write_prep 64, push64
    str _xtmp, [_xaddr]
    write_done 64, push64
    sub rsp, rsp, 8
    gret 1
    write_bullshit 64, push64
#endif
.gadget pop
    mov _addr, esp
    read_prep 32, pop
    ldr _tmp, [_xaddr]
    add esp, esp, 4
    gret 1
    read_bullshit 32, pop

#ifdef ISH_64BIT
.gadget pop64
    mov _xaddr, rsp
    read_prep 64, pop64
    ldr _xtmp, [_xaddr]
    add rsp, rsp, 8
    gret 1
    read_bullshit 64, pop64
#endif

.macro x name, reg
    .gadget addr_\name
        ldr _addr, [_ip]
        add _addr, _addr, \reg
        gret 1
.endm
.each_reg x
.purgem x
.gadget addr_none
    ldr _addr, [_ip]
    gret 1
.gadget addr_rip
    ldr _addr, [_ip]
    gret 1


.gadget_list addr, REG_LIST

.macro x name, reg
    .irp times, 1,2,4,8
        .gadget si_\name\()_\times
            .ifc \times,1
                add _addr, _addr, \reg
            .else N .ifc \times,2
                add _addr, _addr, \reg, lsl 1
            .else N .ifc \times,4
                add _addr, _addr, \reg, lsl 2
            .else N .ifc \times,8
                add _addr, _addr, \reg, lsl 3
            .endif N .endif N .endif N .endif
            gret
    .endr
.endm
.each_reg x
.purgem x

#ifdef ISH_64BIT
# Add missing si gadgets for R11-R15 (memory-based registers)
.gadget si_reg_r11_1
    ldr w8, [_cpu, #CPU_r11]
    add _addr, _addr, w8
    gret
.gadget si_reg_r11_2
    ldr w8, [_cpu, #CPU_r11]
    add _addr, _addr, w8, lsl 1
    gret
.gadget si_reg_r11_4
    ldr w8, [_cpu, #CPU_r11]
    add _addr, _addr, w8, lsl 2
    gret
.gadget si_reg_r11_8
    ldr w8, [_cpu, #CPU_r11]
    add _addr, _addr, w8, lsl 3
    gret

.gadget si_reg_r12_1
    ldr w8, [_cpu, #CPU_r12]
    add _addr, _addr, w8
    gret
.gadget si_reg_r12_2
    ldr w8, [_cpu, #CPU_r12]
    add _addr, _addr, w8, lsl 1
    gret
.gadget si_reg_r12_4
    ldr w8, [_cpu, #CPU_r12]
    add _addr, _addr, w8, lsl 2
    gret
.gadget si_reg_r12_8
    ldr w8, [_cpu, #CPU_r12]
    add _addr, _addr, w8, lsl 3
    gret

.gadget si_reg_r13_1
    ldr w8, [_cpu, #CPU_r13]
    add _addr, _addr, w8
    gret
.gadget si_reg_r13_2
    ldr w8, [_cpu, #CPU_r13]
    add _addr, _addr, w8, lsl 1
    gret
.gadget si_reg_r13_4
    ldr w8, [_cpu, #CPU_r13]
    add _addr, _addr, w8, lsl 2
    gret
.gadget si_reg_r13_8
    ldr w8, [_cpu, #CPU_r13]
    add _addr, _addr, w8, lsl 3
    gret

.gadget si_reg_r14_1
    ldr w8, [_cpu, #CPU_r14]
    add _addr, _addr, w8
    gret
.gadget si_reg_r14_2
    ldr w8, [_cpu, #CPU_r14]
    add _addr, _addr, w8, lsl 1
    gret
.gadget si_reg_r14_4
    ldr w8, [_cpu, #CPU_r14]
    add _addr, _addr, w8, lsl 2
    gret
.gadget si_reg_r14_8
    ldr w8, [_cpu, #CPU_r14]
    add _addr, _addr, w8, lsl 3
    gret

.gadget si_reg_r15_1
    ldr w8, [_cpu, #CPU_r15]
    add _addr, _addr, w8
    gret
.gadget si_reg_r15_2
    ldr w8, [_cpu, #CPU_r15]
    add _addr, _addr, w8, lsl 1
    gret
.gadget si_reg_r15_4
    ldr w8, [_cpu, #CPU_r15]
    add _addr, _addr, w8, lsl 2
    gret
.gadget si_reg_r15_8
    ldr w8, [_cpu, #CPU_r15]
    add _addr, _addr, w8, lsl 3
    gret
#endif

.pushsection_rodata
.global NAME(si_gadgets)
NAME(si_gadgets):
.irp reg, REG_LIST
    .irp times, 1,2,4,8
        .quad NAME(gadget_si_\reg\()_\times)
    .endr
.endr
.popsection

.gadget seg_gs
    ldr w8, [_cpu, CPU_tls_ptr]
    add _addr, _addr, w8
    gret

.irp type, read,write

.global handle_\type\()_miss
handle_\type\()_miss:
    save_c
    # %tlb actually points to tlb->entries
    sub x0, _tlb, TLB_entries
    mov w1, _addr
    .ifc \type,read
        mov x2, xzr
    .else
        mov x2, 1
    .endif
    bl NAME(tlb_handle_miss)
#ifdef ISH_64BIT
    // In 64-bit mode, x19 is the RIP register, so use x15
    mov x15, x0
    restore_c
    cbz x15, segfault_\type
    mov _xaddr, x15
#else
    // In 32-bit mode, x19 is safe to use
    mov x19, x0
    restore_c
    cbz x19, segfault_\type
    mov _xaddr, x19
#endif
    ret

.global segfault_\type
segfault_\type:
    ldr _addr, [_tlb, -TLB_entries+TLB_segfault_addr]
    str _addr, [_cpu, CPU_segfault_addr]
    .ifc \type,read
        mov w0, 0
    .else
        mov w0, 1
    .endif
    strb w0, [_cpu, CPU_segfault_was_write]
    ldr x0, [_ip]
    mov eip, w0
    sub w8, esp, 4
    tst x0, 1 << 62
    csel esp, esp, w8, eq
    mov x0, INT_GPF
    b fiber_exit

.endr

.global crosspage_load
crosspage_load:
    // x19 contains the size parameter from crosspage_load_\id macro
    // This function should return success/failure in x19
    
    save_c
    
    sub x0, _tlb, TLB_entries
    add x2, _cpu, LOCAL_value
#ifdef ISH_64BIT
    mov x1, _xaddr  // Use 64-bit address for 64-bit mode
#else
    mov w1, _addr   // Use 32-bit address for 32-bit mode
#endif
    mov x3, x19     // x3 = size parameter
    
    // DIRECT CALL: Use fixed 64-bit crosspage handler (debug calls removed)
    bl NAME(fixed_64bit_crosspage_read)
#ifdef ISH_64BIT
    // In 64-bit mode, x19 is the RIP register, so use x15
    mov x15, x0
    
    restore_c
    cbz x15, segfault_read
#else
    // In 32-bit mode, x19 is safe to use
    mov x19, x0
    
    restore_c
    cbz x19, segfault_read
#endif
#ifdef ISH_64BIT
    str _xaddr, [_cpu, LOCAL_value_addr]  // Store 64-bit address
#else
    str _addr, [_cpu, LOCAL_value_addr]   // Store 32-bit address
#endif
    add _xaddr, _cpu, LOCAL_value
    ret

.global crosspage_store
crosspage_store:
    save_c
    sub x0, _tlb, TLB_entries
    add x2, _cpu, LOCAL_value
#ifdef ISH_64BIT
    ldr x1, [_cpu, LOCAL_value_addr]  // Load 64-bit address for 64-bit mode
#else
    ldr w1, [_cpu, LOCAL_value_addr]  // Load 32-bit address for 32-bit mode
#endif
    mov x3, x19
    bl NAME(__tlb_write_cross_page)
#ifdef ISH_64BIT
    // In 64-bit mode, x19 is the RIP register, so use x15
    mov x15, x0
    restore_c
    cbz x15, segfault_write
#else
    // In 32-bit mode, x19 is safe to use
    mov x19, x0
    restore_c
    cbz x19, segfault_write
#endif
    ret

