#include "../gadgets-generic.h"
#include "cpu-offsets.h"

# register assignments for 64-bit x86 emulation
# Main x86_64 registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP)
rax .req x20
eax .req w20
rbx .req x21  
ebx .req w21
rcx .req x22
ecx .req w22
rdx .req x23
edx .req w23
rsi .req x24
esi .req w24
rdi .req x25
edi .req w25
rbp .req x26
ebp .req w26
rsp .req x27
esp .req w27

# Extended registers R8-R15 for 64-bit mode
r8 .req x15
r8d .req w15
r9 .req x16
r9d .req w16
r10 .req x17
r10d .req w17
r11 .req x18
r11d .req w18
r12 .req x19
r12d .req w19
r13 .req x12
r13d .req w12
r14 .req x13
r14d .req w13
r15 .req x14
r15d .req w14

# Additional aliases for compatibility
xax .req x20
xcx .req x22
xdx .req x23

# Instruction pointer
_ip .req x28
rip .req x28
eip .req w28
_tmp .req w0
_xtmp .req x0
_cpu .req x1
_tlb .req x2
_addr .req w3
_xaddr .req x3

.extern fiber_exit

.macro .gadget name
    .global NAME(gadget_\()\name)
    .align 4
    NAME(gadget_\()\name) :
.endm
.macro gret pop=0
    ldr x8, [_ip, \pop*8]!
    add _ip, _ip, 8 /* TODO get rid of this */
    br x8
.endm

# memory reading and writing
.irp type, read,write

.macro \type\()_prep size, id
    and w8, _addr, 0xfff
    cmp x8, (0x1000-(\size/8))
    b.hi crosspage_load_\id
    and w8, _addr, 0xfffff000
    str w8, [_tlb, (-TLB_entries+TLB_dirty_page)]
    ubfx x9, _xaddr, 12, 10
    eor x9, x9, _xaddr, lsr 22
    lsl x9, x9, 4
    add x9, x9, _tlb
    .ifc \type,read
        ldr w10, [x9, TLB_ENTRY_page]
    .else
        ldr w10, [x9, TLB_ENTRY_page_if_writable]
    .endif
    cmp w8, w10
    b.ne handle_miss_\id
    ldr x10, [x9, TLB_ENTRY_data_minus_addr]
    add _xaddr, x10, _xaddr, uxtx
back_\id:
.endm

.macro \type\()_bullshit size, id
handle_miss_\id :
    bl handle_\type\()_miss
    b back_\id
crosspage_load_\id :
    mov x19, (\size/8)
    bl crosspage_load
    b back_\id
.ifc \type,write
crosspage_store_\id :
    mov x19, (\size/8)
    bl crosspage_store
    b back_write_done_\id
.endif
.endm

.endr
.macro write_done size, id
    add x8, _cpu, LOCAL_value
    cmp x8, _xaddr
    b.eq crosspage_store_\id
back_write_done_\id :
.endm

.macro .each_reg macro:vararg
    \macro reg_a, eax
    \macro reg_b, ebx
    \macro reg_c, ecx
    \macro reg_d, edx
    \macro reg_si, esi
    \macro reg_di, edi
    \macro reg_bp, ebp
    \macro reg_sp, esp
    # Extended registers for 64-bit mode
    \macro reg_r8, r8d
    \macro reg_r9, r9d
    \macro reg_r10, r10d
    \macro reg_r11, r11d
    \macro reg_r12, r12d
    \macro reg_r13, r13d
    \macro reg_r14, r14d
    \macro reg_r15, r15d
.endm

.macro .each_reg64 macro:vararg
    \macro reg_rax, rax
    \macro reg_rbx, rbx
    \macro reg_rcx, rcx
    \macro reg_rdx, rdx
    \macro reg_rsi, rsi
    \macro reg_rdi, rdi
    \macro reg_rbp, rbp
    \macro reg_rsp, rsp
    # Extended registers for 64-bit mode
    \macro reg_r8, r8
    \macro reg_r9, r9
    \macro reg_r10, r10
    \macro reg_r11, r11
    \macro reg_r12, r12
    \macro reg_r13, r13
    \macro reg_r14, r14
    \macro reg_r15, r15
.endm

.macro ss size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size,
        .else
            .error "bad size"
        .endif
    .else
        .if \size == 8
            \macro \size, b
        .elseif \size == 16
            \macro \size, h
        .elseif \size == 32
            \macro \size,
        .else
            .error "bad size"
        .endif
    .endif
.endm

.macro setf_c
    cset w10, cc
    strb w10, [_cpu, CPU_cf]
.endm
.macro setf_oc
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    setf_c
.endm
.macro setf_a src, dst
    str \src, [_cpu, CPU_op1]
    str \dst, [_cpu, CPU_op2]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, AF_OPS
    str w10, [_cpu, CPU_flags_res]
.endm
.macro clearf_a
    ldr w10, [_cpu, CPU_eflags]
    ldr w11, [_cpu, CPU_flags_res]
    bic w10, w10, AF_FLAG
    bic w11, w11, AF_OPS
    str w10, [_cpu, CPU_eflags]
    str w11, [_cpu, CPU_flags_res]
.endm
.macro clearf_oc
    strb wzr, [_cpu, CPU_of]
    strb wzr, [_cpu, CPU_cf]
.endm
.macro setf_zsp s, val=_tmp
    .ifnb \s
        sxt\s \val, \val
    .endif
    str \val, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, (ZF_RES|SF_RES|PF_RES)
    str w10, [_cpu, CPU_flags_res]
.endm

.macro save_c
    stp x0, x1, [sp, -0x60]!
    stp x2, x3, [sp, 0x10]
    stp x8, x9, [sp, 0x20]
    stp x10, x11, [sp, 0x30]
    stp x12, x13, [sp, 0x40]
    str lr, [sp, 0x50]
.endm
.macro restore_c
    ldr lr, [sp, 0x50]
    ldp x12, x13, [sp, 0x40]
    ldp x10, x11, [sp, 0x30]
    ldp x8, x9, [sp, 0x20]
    ldp x2, x3, [sp, 0x10]
    ldp x0, x1, [sp], 0x60
.endm

.macro movs dst, src, s
    .ifc \s,h
        bfxil \dst, \src, 0, 16
    .else N .ifc \s,b
        bfxil \dst, \src, 0, 8
    .else
        mov \dst, \src
    .endif N .endif
.endm
.macro op_s op, dst, src1, src2, s
    .ifb \s
        \op \dst, \src1, \src2
    .else
        movs w10, \dst, \s
        \op w10, \src1, \src2
        movs \dst, w10, \s
    .endif
.endm
.macro ldrs src, dst, s
    ldr\s w10, \dst
    movs \src, w10, \s
.endm

.macro uxts dst, src, s=
    .ifnb \s
        uxt\s \dst, \src
        .exitm
    .endif
    .ifnc \dst,\src
        mov \dst, \src
    .endif
.endm

.macro load_regs
    ldr rax, [_cpu, CPU_rax]
    ldr rbx, [_cpu, CPU_rbx]
    ldr rcx, [_cpu, CPU_rcx]
    ldr rdx, [_cpu, CPU_rdx]
    ldr rsi, [_cpu, CPU_rsi]
    ldr rdi, [_cpu, CPU_rdi]
    ldr rbp, [_cpu, CPU_rbp]
    ldr rsp, [_cpu, CPU_rsp]
.endm

.macro save_regs
    str rax, [_cpu, CPU_rax]
    str rbx, [_cpu, CPU_rbx]
    str rcx, [_cpu, CPU_rcx]
    str rdx, [_cpu, CPU_rdx]
    str rdi, [_cpu, CPU_rdi]
    str rsi, [_cpu, CPU_rsi]
    str rbp, [_cpu, CPU_rbp]
    str rsp, [_cpu, CPU_rsp]
    str rip, [_cpu, CPU_rip]
.endm

# vim: ft=gas
