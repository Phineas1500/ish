#include "gadgets.h"
#include "emu/interrupt.h"

// Push 64-bit value onto stack
.gadget push
    sub _addr, rsp, 8
    write_prep 64, push
    str _xtmp, [_addr]
    write_done 64, push
    sub rsp, rsp, 8
    gret 1
    write_bullshit 64, push

// Pop 64-bit value from stack
.gadget pop
    mov _addr, rsp
    read_prep 64, pop
    ldr _xtmp, [_addr]
    add rsp, rsp, 8
    gret 1
    read_bullshit 64, pop

// LEAVE = mov rsp, rbp; pop rbp
.gadget leave
    mov rsp, rbp
    mov _addr, rsp
    read_prep 64, leave
    ldr _xtmp, [_addr]
    mov rbp, _xtmp
    add rsp, rsp, 8
    gret 1
    read_bullshit 64, leave

// Push 32-bit value (for compatibility)
.gadget push32
    sub _addr, rsp, 4
    write_prep 32, push32
    str _tmp, [_addr]
    write_done 32, push32
    sub rsp, rsp, 4
    gret 1
    write_bullshit 32, push32

// Pop 32-bit value (for compatibility)
.gadget pop32
    mov _addr, rsp
    read_prep 32, pop32
    ldr _tmp, [_addr]
    add rsp, rsp, 4
    gret 1
    read_bullshit 32, pop32

// Address calculation gadgets for registers rax-rdi
.macro x name, reg64, reg32
    .gadget addr_\name
        ldr _addr, [_ip]
        add _addr, _addr, \reg64
        gret 1
.endm
.each_reg64 x
.purgem x

// Address with no base register
.gadget addr_none
    ldr _addr, [_ip]
    gret 1

// Address calculation gadgets for r8-r15 (stored in CPU struct, not ARM64 registers)
// IMPORTANT: Use x10 as scratch, not x8! x8 may hold saved values from earlier gadgets.
.gadget addr_r8
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r8]
    add _addr, _addr, x10
    gret 1

.gadget addr_r9
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r9]
    add _addr, _addr, x10
    gret 1

.gadget addr_r10
    ldr _addr, [_ip]
    // Use C helper to load r10 (workaround for ARM64 ldr crash at offset 0x60)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19
    gret 1

.gadget addr_r11
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r11]
    add _addr, _addr, x10
    gret 1

.gadget addr_r12
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r12]
    add _addr, _addr, x10
    gret 1

.gadget addr_r13
    ldr _addr, [_ip]
    // Use C helper to load r13 (workaround for ARM64 ldr crash at offset 0x78)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19
    gret 1

.gadget addr_r14
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r14]
    add _addr, _addr, x10
    gret 1

.gadget addr_r15
    ldr _addr, [_ip]
    ldr x10, [_cpu, CPU_r15]
    add _addr, _addr, x10
    gret 1

// Save/restore guest address for read-modify-write operations
// (load modifies _addr to host address, need to restore for store)
.gadget save_addr
    str _addr, [_cpu, LOCAL_value_addr]
    gret

.gadget restore_addr
    ldr _addr, [_cpu, LOCAL_value_addr]
    gret

// Address array includes REG_LIST plus 'none'
.gadget_list addr, REG_LIST,none

// Scaled index addressing (base + index * scale)
.macro x name, reg64, reg32
    .irp times, 1,2,4,8
        .gadget si_\name\()_\times
            .ifc \times,1
                add _addr, _addr, \reg64
            .else N .ifc \times,2
                add _addr, _addr, \reg64, lsl 1
            .else N .ifc \times,4
                add _addr, _addr, \reg64, lsl 2
            .else N .ifc \times,8
                add _addr, _addr, \reg64, lsl 3
            .endif N .endif N .endif N .endif
            gret
    .endr
.endm
.each_reg64 x
.purgem x

.pushsection_rodata
.align 3
.global NAME(si_gadgets)
NAME(si_gadgets):
.irp reg, REG_LIST
    .irp times, 1,2,4,8
        .quad NAME(gadget_si_\reg\()_\times)
    .endr
.endr
.popsection

// Scaled index gadgets for r8-r15 (stored in memory, not ARM64 registers)
.macro si_r8_r15 num, offset
    .irp times, 1,2,4,8
        .gadget si_r\num\()_\times
            ldr x10, [_cpu, \offset]
            .ifc \times,1
                add _addr, _addr, x10
            .else N .ifc \times,2
                add _addr, _addr, x10, lsl 1
            .else N .ifc \times,4
                add _addr, _addr, x10, lsl 2
            .else N .ifc \times,8
                add _addr, _addr, x10, lsl 3
            .endif N .endif N .endif N .endif
            gret
    .endr
.endm
si_r8_r15 8, CPU_r8
si_r8_r15 9, CPU_r9
// si_r10 gadgets: use C helper workaround for r10 load (offset 0x60 crash)
.gadget si_r10_1
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19
    gret
.gadget si_r10_2
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 1
    gret
.gadget si_r10_4
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 2
    gret
.gadget si_r10_8
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 3
    gret
si_r8_r15 11, CPU_r11
si_r8_r15 12, CPU_r12
// si_r13 gadgets: use C helper workaround for r13 load (offset 0x78 crash)
.gadget si_r13_1
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19
    gret
.gadget si_r13_2
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 1
    gret
.gadget si_r13_4
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 2
    gret
.gadget si_r13_8
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    add _addr, _addr, x19, lsl 3
    gret
si_r8_r15 14, CPU_r14
si_r8_r15 15, CPU_r15
.purgem si_r8_r15

.pushsection_rodata
.align 3
.global NAME(si_r8_r15_gadgets)
NAME(si_r8_r15_gadgets):
.irp reg, 8,9,10,11,12,13,14,15
    .irp times, 1,2,4,8
        .quad NAME(gadget_si_r\reg\()_\times)
    .endr
.endr
.popsection

// FS segment override (for TLS)
.gadget seg_fs
    ldr x8, [_cpu, CPU_fs_base]
    add _addr, _addr, x8
    gret

// GS segment override
.gadget seg_gs
    ldr x8, [_cpu, CPU_gs_base]
    add _addr, _addr, x8
    gret

// TLB miss handlers
.irp type, read,write

.global handle_\type\()_miss
handle_\type\()_miss:
    save_c
    // _tlb points to tlb->entries, get base
    sub x0, _tlb, TLB_entries
    mov x1, _addr
    .ifc \type,read
        mov x2, xzr
    .else
        mov x2, 1
    .endif
    bl NAME(tlb_handle_miss)
    mov x19, x0
    restore_c
    cbz x19, segfault_\type
    mov _addr, x19
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
    mov rip, x0
    sub x8, rsp, 8
    tst x0, 1 << 62
    csel rsp, rsp, x8, eq
    mov x0, INT_GPF
    b fiber_exit

.endr

// Cross-page read handler
.global crosspage_load
crosspage_load:
    save_c
    sub x0, _tlb, TLB_entries
    add x2, _cpu, LOCAL_value
    mov x1, _addr
    mov x3, x19
    bl NAME(__tlb_read_cross_page)
    mov x19, x0
    restore_c
    cbz x19, segfault_read
    str _addr, [_cpu, LOCAL_value_addr]
    add _addr, _cpu, LOCAL_value
    ret

// Cross-page write handler
.global crosspage_store
crosspage_store:
    save_c
    sub x0, _tlb, TLB_entries
    add x2, _cpu, LOCAL_value
    ldr x1, [_cpu, LOCAL_value_addr]
    mov x3, x19
    bl NAME(__tlb_write_cross_page)
    mov x19, x0
    restore_c
    cbz x19, segfault_write
    ret
