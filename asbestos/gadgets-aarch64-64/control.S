#include "gadgets.h"
#include "emu/interrupt.h"

// Ensure INT_SYSCALL64 is defined for assembly (may not get ISH_GUEST_64BIT from meson)
#ifndef INT_SYSCALL64
#define INT_SYSCALL64 0x100
#endif

// ============================================================
// CALL - push return address and jump
// ============================================================

.gadget call
    // Save return address (next instruction) to stack
    sub _addr, rsp, 8
    write_prep 64, call
    ldr x8, [_ip, 16]           // Return address from gadget args
    str x8, [_addr]
    // Push stack pointer
    sub rsp, rsp, 8
    // Save ip-to-arguments to return cache
    ubfx x12, x8, 4, 12
    write_done 64, call
    add x13, _cpu, LOCAL_ret_cache
    str _ip, [x13, x12, lsl 3]
    // Jump to target
    ldr _ip, [_ip, 32]
    b fiber_ret_chain
    write_bullshit 64, call

.gadget call_indir
    // Save return address to stack
    sub _addr, rsp, 8
    write_prep 64, call_indir
    ldr x8, [_ip, 16]           // Return address
    str x8, [_addr]
    // Push stack pointer
    sub rsp, rsp, 8
    // Save ip-to-arguments to return cache
    ubfx x12, x8, 4, 12
    write_done 64, call_indir
    add x13, _cpu, LOCAL_ret_cache
    str _ip, [x13, x12, lsl 3]
    // Jump to target (address in _xtmp)
    mov rip, _xtmp
    mvn _tmp, wzr    // return -1 (re-translate)
    b fiber_exit
    write_bullshit 64, call_indir

// ============================================================
// RET - pop return address and jump
// ============================================================

.gadget ret
    mov _addr, rsp
    // Load return address from stack
    read_prep 64, ret
    ldr _xtmp, [_addr]

    // DEBUG: validate popped return address is a guest address
    lsr x14, _xtmp, 32
    cbz x14, .Lret_addr_ok     // < 4GB: skip
    cmp x14, 0x100
    b.hs .Lret_addr_ok         // >= 1TB: guest address, OK
    // HOST ADDRESS POPPED FROM STACK!
    // _xtmp has the corrupt value, _addr has the stack location
    save_regs
    save_c
    mov x0, _cpu
    mov x1, _xtmp               // corrupt return addr
    mov x2, _addr                // stack addr where it was found
    bl NAME(debug_ret_popped_host_addr)
    brk #0x44
.Lret_addr_ok:

    // Pop stack (add immediate from gadget args)
    ldr x8, [_ip, 8]
    add rsp, rsp, x8
    // Load saved ip from return cache
    ubfx x12, _xtmp, 4, 12
    add x13, _cpu, LOCAL_ret_cache
    ldr _ip, [x13, x12, lsl 3]
    // Found in cache?
    cbz _ip, 2f
    // Check if we jumped to the correct CALL instruction
    ldr x9, [_ip, 16]
    cmp _xtmp, x9
    b.ne 2f                     // Address mismatch - no chaining
    // Check if chaining is available
    ldr x9, [_ip, 24]           // Chain target (negative = no chaining)
    cmp x9, 0
    b.le 2f                     // No chaining available
    // Check if block pointer is valid (not -1/unpatched)
    ldr x8, [_ip, 8]
    cmp x8, 0
    b.lt 2f                     // Block pointer not patched yet
    // Good, do return chaining
    sub x8, x9, FIBER_BLOCK_code
    str x8, [_cpu, LOCAL_last_block]
    mov _ip, x9
    gret
2:
    // No return chaining - do normal fiber_ret
    mov rip, _xtmp
    mvn _tmp, wzr    // return -1 (re-translate)
    b fiber_exit
    read_bullshit 64, ret

// ============================================================
// JMP - unconditional jump
// ============================================================

.gadget jmp_indir
    mov rip, _xtmp
    mvn _tmp, wzr    // return -1 (re-translate)
    b fiber_exit

.gadget jmp
    ldr _ip, [_ip]
    b fiber_ret_chain

// JRCXZ - jump if RCX is zero
.gadget jrcxz
    cbnz rcx, 1f
    ldr _ip, [_ip]
    b fiber_ret_chain
1:
    ldr _ip, [_ip, 8]
    b fiber_ret_chain

// ============================================================
// SYSCALL - 64-bit system call
// ============================================================

// x86_64 syscall convention:
// - RAX = syscall number
// - RDI, RSI, RDX, R10, R8, R9 = arguments
// - RCX = return address (saved by syscall)
// - R11 = saved RFLAGS
// We trigger INT_SYSCALL64 to let the kernel handle it

.gadget syscall
    // RCX gets return address (current RIP)
    ldr x9, [_ip]               // Get current IP from gadget args (use x9 to avoid clobber)
    str x9, [_cpu, CPU_rcx]     // Store in RCX
    // R11 gets RFLAGS (we'll let the kernel handle this)
    ldr w8, [_cpu, CPU_eflags]
    str x8, [_cpu, CPU_r11]
    // Trigger syscall interrupt
    mov _tmp, INT_SYSCALL64
    mov rip, x9                 // Set RIP to return address
    b fiber_exit

// ============================================================
// Conditional jumps
// ============================================================

#define COND_LIST o,c,z,cz,s,p,sxo,sxoz

// NOTE: These macros use w9/x9 as scratch to avoid clobbering x8 which is used
// by CMOV gadgets to hold the destination value.
.macro check_res_or_flag resflag, flag, target, fallthrough
    ldr w9, [_cpu, CPU_flags_res]
    tbnz w9, \resflag, 2f
    ldr w9, [_cpu, CPU_eflags]
    tbnz w9, \flag, \target
    b \fallthrough
2:
.endm

.macro do_jump cond, target
    .ifc \cond,o
        ldrb w9, [_cpu, CPU_of]
        cbnz w9, \target
    .else N .ifc \cond,c
        ldrb w9, [_cpu, CPU_cf]
        cbnz w9, \target
    .else N .ifc \cond,z
        check_res_or_flag 1, 6, \target, 3f
        ldr x9, [_cpu, CPU_res]
        cbz x9, \target
    3:
    .else N .ifc \cond,cz
        ldrb w9, [_cpu, CPU_cf]
        cbnz w9, \target
        check_res_or_flag 1, 6, \target, 3f
        ldr x9, [_cpu, CPU_res]
        cbz x9, \target
    3:
    .else N .ifc \cond,s
        check_res_or_flag 2, 7, \target, 3f
        ldr x9, [_cpu, CPU_res]
        cmp x9, 0
        b.lt \target
    3:
    .else N .ifc \cond,p
        check_res_or_flag 0, 2, \target, 3f
        ldr x9, [_cpu, CPU_res]
        uxtb w9, w9
        fmov s0, w9
        cnt v0.8b, v0.8b
        uaddlv h0, v0.8b
        fmov w9, s0
        tbz w9, 0, \target
    3:
    .else N .ifc \cond,sxo
        // SF != OF: must check SF_RES to get SF from correct source
        ldr w9, [_cpu, CPU_flags_res]
        tbnz w9, 2, 4f                     // bit 2 = SF_RES -> compute from res
        // SF from eflags bit 7
        ldr w9, [_cpu, CPU_eflags]
        ubfx w9, w9, 7, 1                  // extract SF bit
        b 5f
    4:  // SF from CPU_res
        ldr x9, [_cpu, CPU_res]
        cmp x9, 0
        cset w9, lt                         // SF = (res < 0)
    5:  ldrb w10, [_cpu, CPU_of]
        cmp w9, w10
        b.ne \target
    .else N .ifc \cond,sxoz
        // SF != OF || ZF=1: check both with proper SF_RES/ZF_RES dispatch
        // First check ZF
        check_res_or_flag 1, 6, \target, 3f
        ldr x9, [_cpu, CPU_res]
        cbz x9, \target
    3:  // ZF=0, now check SF != OF
        ldr w9, [_cpu, CPU_flags_res]
        tbnz w9, 2, 4f                     // bit 2 = SF_RES -> compute from res
        ldr w9, [_cpu, CPU_eflags]
        ubfx w9, w9, 7, 1
        b 5f
    4:  ldr x9, [_cpu, CPU_res]
        cmp x9, 0
        cset w9, lt
    5:  ldrb w10, [_cpu, CPU_of]
        cmp w9, w10
        b.ne \target
    .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
.endm

.irp cond, COND_LIST
    .gadget jmp_\cond
        do_jump \cond, 1f
        ldr _ip, [_ip, 8]
        b fiber_ret_chain
    1:  ldr _ip, [_ip]
        b fiber_ret_chain

    .gadget set_\cond
        do_jump \cond, 1f
        mov _tmp, 0
        gret
    1:  mov _tmp, 1
        gret

    .gadget setn_\cond
        do_jump \cond, 1f
        mov _tmp, 1
        gret
    1:  mov _tmp, 0
        gret

    .gadget skip_\cond
        do_jump \cond, 1f
        gret 1
    1:  ldr x8, [_ip]
        add _ip, _ip, x8
        gret 1

    .gadget skipn_\cond
        do_jump \cond, 1f
        ldr x8, [_ip]
        add _ip, _ip, x8
    1:  gret 1
.endr

.gadget_list jmp, COND_LIST
.gadget_list set, COND_LIST
.gadget_list setn, COND_LIST
.gadget_list skip, COND_LIST
.gadget_list skipn, COND_LIST

// JRCXZ - Jump short if RCX is zero
// Same layout as jmp_\cond: [_ip] = taken, [_ip+8] = not-taken
.gadget jmp_rcxz
    cbnz rcx, 1f
    ldr _ip, [_ip]
    b fiber_ret_chain
1:  ldr _ip, [_ip, 8]
    b fiber_ret_chain

// LOOP - Decrement RCX and jump if RCX != 0
.gadget loop
    sub rcx, rcx, 1
    cbz rcx, 1f
    ldr _ip, [_ip]
    b fiber_ret_chain
1:  ldr _ip, [_ip, 8]
    b fiber_ret_chain

// LOOPE - Decrement RCX and jump if RCX != 0 AND ZF == 1
.gadget loope
    sub rcx, rcx, 1
    cbz rcx, 1f
    // Check ZF
    ldr w8, [_cpu, CPU_flags_res]
    tbnz w8, 0, 2f          // bit 0 = ZF_RES -> check CPU_res
    ldr w8, [_cpu, CPU_eflags]
    tbnz w8, 6, 3f           // ZF bit in eflags
    b 1f
2:  ldr x8, [_cpu, CPU_res]
    cbnz x8, 1f              // ZF=0 if res!=0
3:  // ZF==1 and RCX!=0: take the branch
    ldr _ip, [_ip]
    b fiber_ret_chain
1:  ldr _ip, [_ip, 8]
    b fiber_ret_chain

// LOOPNE - Decrement RCX and jump if RCX != 0 AND ZF == 0
.gadget loopne
    sub rcx, rcx, 1
    cbz rcx, 1f
    // Check ZF - jump if ZF==0
    ldr w8, [_cpu, CPU_flags_res]
    tbnz w8, 0, 2f          // bit 0 = ZF_RES -> check CPU_res
    ldr w8, [_cpu, CPU_eflags]
    tbnz w8, 6, 1f           // ZF=1 in eflags -> don't branch
    b 3f
2:  ldr x8, [_cpu, CPU_res]
    cbz x8, 1f               // ZF=1 if res==0 -> don't branch
3:  // ZF==0 and RCX!=0: take the branch
    ldr _ip, [_ip]
    b fiber_ret_chain
1:  ldr _ip, [_ip, 8]
    b fiber_ret_chain

// Helper gadget: save _xtmp to x8 for cmov operations
.gadget save_xtmp_to_x8
    mov x8, _xtmp
    gret

// Helper gadget: restore _xtmp from x8
.gadget restore_xtmp_from_x8
    mov _xtmp, x8
    gret

// Swap _xtmp and x8
.gadget swap_xtmp_x8
    mov x9, _xtmp
    mov _xtmp, x8
    mov x8, x9
    gret

// Merge low 16 bits of _xtmp into x8, preserving x8's upper bits.
// Used for 16-bit CMOV (which only updates the low 16 bits of the destination).
.gadget merge16_x8
    mov x9, x8
    bfi x9, _xtmp, #0, #16
    mov _xtmp, x9
    gret

// CMOVcc gadgets - conditional move
// Expects: _xtmp = source value, x8 = original destination value
// If condition is true, keep _xtmp (source); if false, _xtmp = x8 (keep dst)
.irp cond, COND_LIST
    .gadget cmov_\cond
        do_jump \cond, 1f
        // Condition is FALSE - keep destination (x8)
        mov _xtmp, x8
    1:  // Condition is TRUE - keep source (_xtmp) - no action needed
        gret

    .gadget cmovn_\cond
        do_jump \cond, 1f
        // Condition is FALSE - keep source (_xtmp) - no action needed
        b 2f
    1:  // Condition is TRUE - keep destination (x8)
        mov _xtmp, x8
    2:  gret
.endr

.gadget_list cmov, COND_LIST
.gadget_list cmovn, COND_LIST


// ============================================================
// Flags operations
// ============================================================

.gadget pushf
    save_c
    mov x0, _cpu
    bl NAME(helper_collapse_flags)
    restore_c

    sub rsp, rsp, 8
    mov _addr, rsp
    write_prep 64, pushf
    ldr x8, [_cpu, CPU_eflags]
    str x8, [_addr]
    write_done 64, pushf
    gret
    write_bullshit 64, pushf

.gadget popf
    mov _addr, rsp
    read_prep 64, popf
    ldr x8, [_addr]
    str w8, [_cpu, CPU_eflags]
    add rsp, rsp, 8

    save_c
    mov x0, _cpu
    bl NAME(helper_expand_flags)
    restore_c
    gret
    read_bullshit 64, popf

.gadget cld
    ldr w8, [_cpu, CPU_eflags]
    bic w8, w8, DF_FLAG
    str w8, [_cpu, CPU_eflags]
    mov w8, 1
    str w8, [_cpu, CPU_df_offset]  // Use 32-bit store - df_offset is dword_t
    gret

.gadget std
    ldr w8, [_cpu, CPU_eflags]
    orr w8, w8, DF_FLAG
    str w8, [_cpu, CPU_eflags]
    mov w8, -1  // -1 as 32-bit (0xffffffff)
    str w8, [_cpu, CPU_df_offset]  // Use 32-bit store - df_offset is dword_t
    gret
