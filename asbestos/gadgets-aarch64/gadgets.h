#include "../gadgets-generic.h"
#include "cpu-offsets.h"

# register assignments
eax .req w20
xax .req x20
ebx .req w21
ecx .req w22
xcx .req x22
edx .req w23
xdx .req x23
esi .req w24
edi .req w25
ebp .req w26
esp .req w27

# 64-bit register assignments (for ISH_64BIT mode)
rax .req x20
rbx .req x21
rcx .req x22
rdx .req x23
rsi .req x24
rdi .req x25
rbp .req x26
rsp .req x27

# Extended 64-bit registers R8-R15 - Conservative allocation strategy
# Phase 1: Use only the safest registers (x4-x6) for R8-R10
# Phase 2: R11-R15 will use memory-based approach
r8 .req x4
r9 .req x5
r10 .req x6
# r11-R15 will be memory-based (no register aliases yet)

# 32-bit versions of extended registers (Phase 1: R8-R10 only)
r8d .req w4
r9d .req w5
r10d .req w6
# r11d-R15d will be memory-based

# 16-bit versions of extended registers (Phase 1: R8-R10 only)
r8w .req w4
r9w .req w5
r10w .req w6
# r11w-R15w will be memory-based

# 8-bit versions of extended registers (Phase 1: R8-R10 only)
r8b .req w4
r9b .req w5
r10b .req w6
# r11b-R15b will be memory-based

# Memory-based register macros for R11 (use safe temporaries)
.macro load_r11_to_temp size
    .if \size == 64
        ldr _xtmp, [_cpu, CPU_r11]
    .else
        ldr _tmp, [_cpu, CPU_r11]
    .endif
.endm

.macro store_temp_to_r11 size
    .if \size == 64
        str _xtmp, [_cpu, CPU_r11]
    .else
        str _tmp, [_cpu, CPU_r11]
    .endif
.endm

# Memory-based register macros for R12-R15 (use safe temporaries)
.macro load_r12_to_temp size
    .if \size == 64
        ldr _xtmp, [_cpu, CPU_r12]
    .else
        ldr _tmp, [_cpu, CPU_r12]
    .endif
.endm

.macro store_temp_to_r12 size
    .if \size == 64
        str _xtmp, [_cpu, CPU_r12]
    .else
        str _tmp, [_cpu, CPU_r12]
    .endif
.endm

.macro load_r13_to_temp size
    .if \size == 64
        ldr _xtmp, [_cpu, CPU_r13]
    .else
        ldr _tmp, [_cpu, CPU_r13]
    .endif
.endm

.macro store_temp_to_r13 size
    .if \size == 64
        str _xtmp, [_cpu, CPU_r13]
    .else
        str _tmp, [_cpu, CPU_r13]
    .endif
.endm

.macro load_r14_to_temp size
    .if \size == 64
        ldr _xtmp, [_cpu, CPU_r14]
    .else
        ldr _tmp, [_cpu, CPU_r14]
    .endif
.endm

.macro store_temp_to_r14 size
    .if \size == 64
        str _xtmp, [_cpu, CPU_r14]
    .else
        str _tmp, [_cpu, CPU_r14]
    .endif
.endm

.macro load_r15_to_temp size
    .if \size == 64
        ldr _xtmp, [_cpu, CPU_r15]
    .else
        ldr _tmp, [_cpu, CPU_r15]
    .endif
.endm

.macro store_temp_to_r15 size
    .if \size == 64
        str _xtmp, [_cpu, CPU_r15]
    .else
        str _tmp, [_cpu, CPU_r15]
    .endif
.endm

# Note: Memory-based R11-R15 operations use existing safe temporaries (_tmp, _xtmp)

_ip .req x28
eip .req w28
rip .req x19
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
#ifdef ISH_64BIT
    and x8, _xaddr, 0xfff
    cmp x8, (0x1000-(\size/8))
    b.hi crosspage_load_\id
    and x8, _xaddr, 0xfffff000
    str x8, [_tlb, (-TLB_entries+TLB_dirty_page)]
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
#else
    and w8, _addr, 0xfff
    cmp w8, (0x1000-(\size/8))
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
#endif
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
# Hybrid approach - R8-R10 in registers, R11+ memory-based
#ifdef ISH_64BIT
    # R8-R10 confirmed working (ARM64 x4-x6), x7 has conflicts
    \macro reg_r8, r8d
    \macro reg_r9, r9d
    \macro reg_r10, r10d
    # R11-R15 will require special memory-based gadgets (not enabled in each_reg yet)
#endif
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
# Hybrid approach - R8-R10 in registers, R11+ memory-based
#ifdef ISH_64BIT
    # R8-R10 confirmed working (ARM64 x4-x6), x7 has conflicts
    \macro reg_r8, r8
    \macro reg_r9, r9
    \macro reg_r10, r10
    # R11-R15 will require special memory-based gadgets (not enabled in each_reg yet)
#endif
.endm

# Specialized macros for different instruction types in 64-bit mode
.macro ss_load size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size,
        .elseif \size == 64
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
        .elseif \size == 64
            \macro \size,
        .else
            .error "bad size"
        .endif
    .endif
.endm

.macro ss_atomic size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size,
        .elseif \size == 64
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
        .elseif \size == 64
            \macro \size,
        .else
            .error "bad size"
        .endif
    .endif
.endm

.macro ss_extend size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size,
        .elseif \size == 64
            \macro \args, \size, w
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
        .elseif \size == 64
            \macro \size, w
        .else
            .error "bad size"
        .endif
    .endif
.endm

.macro ss size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size,
        .elseif \size == 64
            \macro \args, \size, x
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
        .elseif \size == 64
            \macro \size, x
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
        .ifc \s,x
            # 64-bit case - sign extend to 64-bit register then store 32-bit part
            sxtw x12, \val
            str w12, [_cpu, CPU_res]
        .else
            sxt\s \val, \val
            str \val, [_cpu, CPU_res]
        .endif
    .else
        str \val, [_cpu, CPU_res]
    .endif
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, (ZF_RES|SF_RES|PF_RES)
    str w10, [_cpu, CPU_flags_res]
.endm

.macro save_c
    stp x0, x1, [sp, -0x80]!
    stp x2, x3, [sp, 0x10]
    stp x4, x5, [sp, 0x20]  // Save r8, r9 (x4, x5)
    stp x6, x7, [sp, 0x30]  // Save r10 and x7 (for future use)
    stp x8, x9, [sp, 0x40]
    stp x10, x11, [sp, 0x50]
    stp x12, x13, [sp, 0x60]
    str lr, [sp, 0x70]
.endm
.macro restore_c
    ldr lr, [sp, 0x70]
    ldp x12, x13, [sp, 0x60]
    ldp x10, x11, [sp, 0x50]
    ldp x8, x9, [sp, 0x40]
    ldp x6, x7, [sp, 0x30]  // Restore r10 and x7
    ldp x4, x5, [sp, 0x20]  // Restore r8, r9 (x4, x5)
    ldp x2, x3, [sp, 0x10]
    ldp x0, x1, [sp], 0x80
.endm

.macro movs dst, src, s
    .ifc \s,h
        bfxil \dst, \src, 0, 16
    .else N .ifc \s,b
        bfxil \dst, \src, 0, 8
    .else N .ifc \s,x
        mov \dst, \src
    .else
        mov \dst, \src
    .endif N .endif N .endif
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
    .ifc \s,x
        ldr x10, \dst
        movs \src, w10, \s
    .else
        ldr\s w10, \dst
        movs \src, w10, \s
    .endif
.endm

.macro uxts dst, src, s=
    .ifnb \s
        .ifc \s,x
            uxtw \dst, \src
        .else
            uxt\s \dst, \src
        .endif
        .exitm
    .endif
    .ifnc \dst,\src
        mov \dst, \src
    .endif
.endm

.macro load_regs
#ifdef ISH_64BIT
    ldr rax, [_cpu, CPU_rax]
    ldr rbx, [_cpu, CPU_rbx]
    ldr rcx, [_cpu, CPU_rcx]
    ldr rdx, [_cpu, CPU_rdx]
    ldr rsi, [_cpu, CPU_rsi]
    ldr rdi, [_cpu, CPU_rdi]
    ldr rbp, [_cpu, CPU_rbp]
    ldr rsp, [_cpu, CPU_rsp]
    ldr rip, [_cpu, CPU_rip]
    # Load extended registers (Final: R8-R10 only, R11+ memory-based)
    ldr r8, [_cpu, CPU_r8]
    ldr r9, [_cpu, CPU_r9]
    ldr r10, [_cpu, CPU_r10]
    # R11-R15 are memory-based, loaded on-demand
#else
    ldr eax, [_cpu, CPU_eax]
    ldr ebx, [_cpu, CPU_ebx]
    ldr ecx, [_cpu, CPU_ecx]
    ldr edx, [_cpu, CPU_edx]
    ldr esi, [_cpu, CPU_esi]
    ldr edi, [_cpu, CPU_edi]
    ldr ebp, [_cpu, CPU_ebp]
    ldr esp, [_cpu, CPU_esp]
#endif
.endm

.macro save_regs
#ifdef ISH_64BIT
    str rax, [_cpu, CPU_rax]
    str rbx, [_cpu, CPU_rbx]
    str rcx, [_cpu, CPU_rcx]
    str rdx, [_cpu, CPU_rdx]
    str rdi, [_cpu, CPU_rdi]
    str rsi, [_cpu, CPU_rsi]
    str rbp, [_cpu, CPU_rbp]
    str rsp, [_cpu, CPU_rsp]
    str rip, [_cpu, CPU_rip]
    # Save extended registers (Final: R8-R10 only, R11+ memory-based)
    str r8, [_cpu, CPU_r8]
    str r9, [_cpu, CPU_r9]
    str r10, [_cpu, CPU_r10]
    # R11-R15 are memory-based, saved on-demand
#else
    str eax, [_cpu, CPU_eax]
    str ebx, [_cpu, CPU_ebx]
    str ecx, [_cpu, CPU_ecx]
    str edx, [_cpu, CPU_edx]
    str edi, [_cpu, CPU_edi]
    str esi, [_cpu, CPU_esi]
    str ebp, [_cpu, CPU_ebp]
    str esp, [_cpu, CPU_esp]
    str eip, [_cpu, CPU_eip]
#endif
.endm

# vim: ft=gas
