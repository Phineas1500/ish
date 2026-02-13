#include "../gadgets-generic.h"
#include "cpu-offsets.h"

// Override REG_LIST to use short names (a, c, d, b, sp, bp, si, di)
// This matches the naming in .each_reg64 macro
#undef REG_LIST
#define REG_LIST a,c,d,b,sp,bp,si,di

// Register assignments for 64-bit guest emulation on ARM64 host
// We use ARM64 x registers (64-bit) to hold x86_64 registers
// rax-rdi are kept in ARM64 registers for speed
// r8-r15 are stored in memory (cpu_state) due to limited ARM64 registers

// 64-bit x86 registers in ARM64 registers
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

// Instruction pointer
_ip .req x28
rip .req x28

// Temporaries and special registers
_tmp .req w0
_xtmp .req x0
_tmp2 .req w8
_xtmp2 .req x8
_cpu .req x1
_tlb .req x2
_addr .req x3
_waddr .req w3

.extern fiber_exit

.macro .gadget name
    .global NAME(gadget_\()\name)
    .align 4
    NAME(gadget_\()\name) :
.endm

// Gadget return - advance to next gadget and jump
// IMPORTANT: Uses x16 (IP0) as scratch to avoid clobbering x8 which is used
// for passing values between gadgets (e.g., save_xtmp_to_x8)
.macro gret pop=0
    ldr x16, [_ip, \pop*8]!
    add _ip, _ip, 8
    br x16
.endm

// Memory reading and writing for 64-bit addresses
// TLB lookup uses 64-bit addresses but 4KB pages
// TLB has 1024 entries (10 bits), indexed by XOR-folding page number bits
// IMPORTANT: Uses x11 as scratch (not x8!) because x8 is used to pass values
// between gadgets (e.g., save_xtmp_to_x8 for CMP reg, [mem])
.irp type, read,write

.macro \type\()_prep size, id
    // Check if access crosses page boundary
    and x11, _addr, 0xfff
    cmp x11, (0x1000-(\size/8))
    b.hi crosspage_load_\id
    // Get page-aligned address
    and x11, _addr, ~0xfff
    str x11, [_tlb, (-TLB_entries+TLB_dirty_page)]
    // TLB index calculation (XOR fold for 64-bit addresses)
    // ubfx extracts 10 bits at position 12, giving us (addr >> 12) & 0x3ff
    ubfx x9, _addr, 12, 10
    eor x9, x9, _addr, lsr 22
    and x9, x9, 0x3ff           // TLB_SIZE - 1 = 1023 = 0x3ff
    // Multiply by 24 (sizeof(struct tlb_entry) for 64-bit guest: 8+8+8 bytes)
    add x9, x9, x9, lsl 1       // x9 = x9 * 3
    lsl x9, x9, 3               // x9 = x9 * 8 = original * 24
    add x9, x9, _tlb
    .ifc \type,read
        ldr x10, [x9, TLB_ENTRY_page]
    .else
        ldr x10, [x9, TLB_ENTRY_page_if_writable]
    .endif
    cmp x11, x10
    b.ne handle_miss_\id
    ldr x10, [x9, TLB_ENTRY_data_minus_addr]
    add _addr, x10, _addr
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
    add x11, _cpu, LOCAL_value
    cmp x11, _addr
    b.eq crosspage_store_\id
back_write_done_\id :
.endm

// Register iteration macros for 64-bit
// First 8 registers (rax-rdi) are in ARM64 registers
// Names match gadget array indexing: a, c, d, b, sp, bp, si, di (matches x86 encoding order)
.macro .each_reg64 macro:vararg
    \macro a, rax, eax
    \macro c, rcx, ecx
    \macro d, rdx, edx
    \macro b, rbx, ebx
    \macro sp, rsp, esp
    \macro bp, rbp, ebp
    \macro si, rsi, esi
    \macro di, rdi, edi
.endm

// For 32-bit compatibility (same order)
.macro .each_reg macro:vararg
    \macro a, eax
    \macro c, ecx
    \macro d, edx
    \macro b, ebx
    \macro sp, esp
    \macro bp, ebp
    \macro si, esi
    \macro di, edi
.endm

// Size suffix macros for load/store
.macro ss size, macro, args:vararg
    .ifnb \args
        .if \size == 8
            \macro \args, \size, b
        .elseif \size == 16
            \macro \args, \size, h
        .elseif \size == 32
            \macro \args, \size, w
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
            \macro \size, w
        .elseif \size == 64
            \macro \size,
        .else
            .error "bad size"
        .endif
    .endif
.endm

// Flag setting macros
// IMPORTANT: ARM64 carry flag semantics differ between ADD and SUB:
// - ADD: ARM64 C=1 means carry (same as x86 CF=1). Use "cs" (carry set).
// - SUB/CMP: ARM64 C=0 means borrow (x86 CF=1). Use "cc" (carry clear).
// The 32-bit gadgets handle this correctly in do_add macro (math.h).
// For 64-bit, we need separate macros for ADD and SUB operations.

// setf_c for SUB/CMP operations (ARM64 C inverted from x86 CF)
.macro setf_c
    cset w10, cc
    strb w10, [_cpu, CPU_cf]
.endm
// setf_c for ADD operations (ARM64 C same as x86 CF)
.macro setf_c_add
    cset w10, cs
    strb w10, [_cpu, CPU_cf]
.endm
// setf_oc for SUB/CMP operations
.macro setf_oc
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    setf_c
.endm
// setf_oc for ADD operations
.macro setf_oc_add
    cset w10, vs
    strb w10, [_cpu, CPU_of]
    setf_c_add
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
.macro setf_zsp s, val=_xtmp
    .ifnb \s
        sxt\s x9, \val
        str x9, [_cpu, CPU_res]
    .else
        str \val, [_cpu, CPU_res]
    .endif
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, (ZF_RES|SF_RES|PF_RES)
    str w10, [_cpu, CPU_flags_res]
.endm

// Save/restore caller-saved registers
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

// Move with size suffix (for partial register updates)
.macro movs64 dst, src, s
    .ifc \s,h
        bfxil \dst, \src, 0, 16
    .else N .ifc \s,b
        bfxil \dst, \src, 0, 8
    .else N .ifc \s,w
        mov w\dst, w\src
    .else
        mov \dst, \src
    .endif N .endif N .endif
.endm

// Load/store with size
.macro ldrs64 reg, addr, s
    ldr\s _xtmp, \addr
.endm

// Load all x86_64 registers from cpu_state
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

// Save all x86_64 registers to cpu_state
.macro save_regs
    str rax, [_cpu, CPU_rax]
    str rbx, [_cpu, CPU_rbx]
    str rcx, [_cpu, CPU_rcx]
    str rdx, [_cpu, CPU_rdx]
    str rsi, [_cpu, CPU_rsi]
    str rdi, [_cpu, CPU_rdi]
    str rbp, [_cpu, CPU_rbp]
    str rsp, [_cpu, CPU_rsp]
    str rip, [_cpu, CPU_rip]
.endm

// Load r8-r15 from memory (these aren't kept in ARM64 registers)
.macro load_r8 reg
    ldr \reg, [_cpu, CPU_r8]
.endm
.macro load_r9 reg
    ldr \reg, [_cpu, CPU_r9]
.endm
.macro load_r10 reg
    ldr \reg, [_cpu, CPU_r10]
.endm
.macro load_r11 reg
    ldr \reg, [_cpu, CPU_r11]
.endm
.macro load_r12 reg
    ldr \reg, [_cpu, CPU_r12]
.endm
.macro load_r13 reg
    ldr \reg, [_cpu, CPU_r13]
.endm
.macro load_r14 reg
    ldr \reg, [_cpu, CPU_r14]
.endm
.macro load_r15 reg
    ldr \reg, [_cpu, CPU_r15]
.endm

// Store r8-r15 to memory
.macro store_r8 reg
    str \reg, [_cpu, CPU_r8]
.endm
.macro store_r9 reg
    str \reg, [_cpu, CPU_r9]
.endm
.macro store_r10 reg
    str \reg, [_cpu, CPU_r10]
.endm
.macro store_r11 reg
    str \reg, [_cpu, CPU_r11]
.endm
.macro store_r12 reg
    str \reg, [_cpu, CPU_r12]
.endm
.macro store_r13 reg
    str \reg, [_cpu, CPU_r13]
.endm
.macro store_r14 reg
    str \reg, [_cpu, CPU_r14]
.endm
.macro store_r15 reg
    str \reg, [_cpu, CPU_r15]
.endm

# vim: ft=gas
