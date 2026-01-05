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
    // Debug: check for NULL call target
    cbnz _xtmp, 1f
    save_c
    mov x0, _xtmp    // target (should be 0)
    mov x1, rsp      // current rsp
    bl NAME(helper_debug_null_call_indir)
    restore_c
1:
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
    // Debug: check for NULL return address
    cbnz _xtmp, 3f
    save_c
    mov x0, _xtmp    // target (should be 0)
    mov x1, rsp      // current rsp
    bl NAME(helper_debug_null_ret)
    restore_c
3:
    mov rip, _xtmp
    mvn _tmp, wzr    // return -1 (re-translate)
    b fiber_exit
    read_bullshit 64, ret

// ============================================================
// JMP - unconditional jump
// ============================================================

.gadget jmp_indir
    // Debug: check for NULL jump
    cbnz _xtmp, 1f
    save_c
    mov x0, _xtmp    // target (should be 0)
    mov x1, rsp      // current rsp
    bl NAME(helper_debug_null_jmp_indir)
    restore_c
1:
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
    // Debug: check if syscall IP is 0
    cbnz x9, 1f
    save_c
    mov x0, x9       // target (should be 0)
    mov x1, rsp      // current rsp
    bl NAME(helper_debug_syscall_null)
    restore_c
1:
    // Trigger syscall interrupt
    mov _tmp, INT_SYSCALL64
    mov rip, x9                 // Set RIP to return address
    b fiber_exit

// ============================================================
// Conditional jumps
// ============================================================

#define COND_LIST o,c,z,cz,s,p,sxo,sxoz

.macro check_res_or_flag resflag, flag, target, fallthrough
    ldr w8, [_cpu, CPU_flags_res]
    tbnz w8, \resflag, 2f
    ldr w8, [_cpu, CPU_eflags]
    tbnz w8, \flag, \target
    b \fallthrough
2:
.endm

.macro do_jump cond, target
    .ifc \cond,o
        ldrb w8, [_cpu, CPU_of]
        cbnz w8, \target
    .else N .ifc \cond,c
        ldrb w8, [_cpu, CPU_cf]
        cbnz w8, \target
    .else N .ifc \cond,z
        check_res_or_flag 1, 6, \target, 3f
        ldr x8, [_cpu, CPU_res]
        cbz x8, \target
    3:
    .else N .ifc \cond,cz
        ldrb w8, [_cpu, CPU_cf]
        cbnz w8, \target
        check_res_or_flag 1, 6, \target, 3f
        ldr x8, [_cpu, CPU_res]
        cbz x8, \target
    3:
    .else N .ifc \cond,s
        check_res_or_flag 2, 7, \target, 3f
        ldr x8, [_cpu, CPU_res]
        cmp x8, 0
        b.lt \target
    3:
    .else N .ifc \cond,p
        check_res_or_flag 0, 2, \target, 3f
        ldr x8, [_cpu, CPU_res]
        uxtb w8, w8
        fmov s0, w8
        cnt v0.8b, v0.8b
        uaddlv h0, v0.8b
        fmov w8, s0
        tbz w8, 0, \target
    3:
    .else N .ifc \cond,sxo
        ldr x8, [_cpu, CPU_res]
        cmp x8, 0
        cset w8, lt
        ldrb w9, [_cpu, CPU_of]
        cmp w8, w9
        b.ne \target
    .else N .ifc \cond,sxoz
        ldr x8, [_cpu, CPU_res]
        cmp x8, 0
        b.eq \target
        cset w8, lt
        ldrb w9, [_cpu, CPU_of]
        cmp w8, w9
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

// Helper gadget: save _xtmp to x8 for cmov operations
.gadget save_xtmp_to_x8
    mov x8, _xtmp
    gret

// Swap _xtmp and x8
.gadget swap_xtmp_x8
    mov x9, _xtmp
    mov _xtmp, x8
    mov x8, x9
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
    mov x8, 1
    str x8, [_cpu, CPU_df_offset]
    gret

.gadget std
    ldr w8, [_cpu, CPU_eflags]
    orr w8, w8, DF_FLAG
    str w8, [_cpu, CPU_eflags]
    mov x8, -1
    str x8, [_cpu, CPU_df_offset]
    gret

// Debug gadget to trace stores
// Called with _xtmp = value being stored, _addr = destination address
.gadget debug_store
    save_c
    mov x0, _xtmp   // value
    mov x1, _addr   // address
    bl NAME(helper_debug_store)
    restore_c
    gret

// Debug gadget to trace loads
// Called AFTER load with _xtmp = loaded value, _addr = source address
.gadget debug_load
    save_c
    mov x0, _xtmp   // value that was loaded
    mov x1, _addr   // address loaded from
    bl NAME(helper_debug_load)
    restore_c
    gret

// Debug gadget to trace ADD r9 (for debugging base address corruption)
// Called with x8 = original dst, _xtmp = r9 value
.gadget debug_add_r9
    save_c
    mov x2, _cpu    // cpu struct (_cpu is x1, save before overwriting)
    mov x0, _xtmp   // xtmp (should be r9)
    mov x1, x8      // x8 (should be original destination)
    bl NAME(helper_debug_add_r9)
    restore_c
    gret

// Debug gadget to trace actual x23 (rdx) register value
// Shows both x23 and current _xtmp for comparison
.gadget debug_rdx
    save_c
    mov x0, rdx     // x23 (rdx alias)
    mov x1, _xtmp   // current _xtmp for comparison
    bl NAME(helper_debug_rdx)
    restore_c
    gret

// Debug gadget to trace AFTER save_xtmp_to_x8
// Called immediately after mov x8, _xtmp
// At this point x8 and _xtmp (x0) should have the SAME value
.gadget debug_save_x8
    // Save values FIRST before save_c clobbers registers
    mov x9, _xtmp   // x9 = original _xtmp value
    mov x10, x8     // x10 = x8 value
    save_c
    mov x0, x10     // x8 value
    mov x1, x9      // original _xtmp value
    bl NAME(helper_debug_save_x8)
    restore_c
    gret

// Debug gadget for CMP reg, [mem] - called after swap, before cmp
// _xtmp = reg value, x8 = mem value
.gadget debug_cmp
    mov x9, _xtmp   // preserve
    mov x10, x8
    save_c
    mov x0, x9      // reg value
    mov x1, x10     // mem value
    bl NAME(helper_debug_cmp)
    restore_c
    gret

// Debug gadget for LEA r8-r15 - trace result after add64_x8
// _xtmp = result, x8 = base value (r9 etc), need to load IP too
.gadget debug_lea
    mov x9, _xtmp   // x9 = result (preserve before save_c)
    mov x10, x8     // x10 = x8 (base value)
    save_c
    mov x0, x9      // result
    mov x1, x10     // x8 (base)
    mov x2, _ip     // IP (_ip survives save_c)
    bl NAME(helper_debug_lea)
    restore_c
    gret
