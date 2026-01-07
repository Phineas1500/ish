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
    // Watchpoint check BEFORE the store
    save_c
    mov x0, x8           // value (return address)
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store64)
    restore_c
    ldr x8, [_ip, 16]           // Reload x8 (clobbered by call)
    str x8, [_addr]
    // Push stack pointer
    sub rsp, rsp, 8
    // Debug: trace call target and return address
    save_c
    ldr x0, [_ip, 32]           // target address
    mov x1, rdi                 // rdi argument
    mov x2, rsi                 // rsi argument
    mov x3, x8                  // return address
    bl NAME(helper_debug_call)
    restore_c
    ldr x8, [_ip, 16]           // Reload x8 (clobbered by call)
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
    // Watchpoint check BEFORE the store
    save_c
    mov x0, x8           // value (return address)
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store64)
    restore_c
    ldr x8, [_ip, 16]           // Reload x8 (clobbered by call)
    str x8, [_addr]
    // Push stack pointer
    sub rsp, rsp, 8
    // Debug: trace indirect call target
    save_c
    mov x0, _xtmp               // target address
    mov x1, rdi                 // rdi argument
    mov x2, rsi                 // rsi argument
    mov x3, x8                  // return address
    bl NAME(helper_debug_call)
    restore_c
    ldr x8, [_ip, 16]           // Reload x8 (clobbered by call)
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

    // Debug: unconditionally trace ALL returns
    // NOTE: _xtmp IS x0, so save it first!
    mov x9, _xtmp    // Save return address before save_c
    save_c
    mov x0, rax      // x0 = rax (return value)
    mov x1, x9       // x1 = return address (saved copy)
    bl NAME(helper_debug_ret)
    restore_c

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
        ldr x9, [_cpu, CPU_res]
        cmp x9, 0
        cset w9, lt
        ldrb w10, [_cpu, CPU_of]
        cmp w9, w10
        b.ne \target
    .else N .ifc \cond,sxoz
        ldr x9, [_cpu, CPU_res]
        cmp x9, 0
        b.eq \target
        cset w9, lt
        ldrb w10, [_cpu, CPU_of]
        cmp w9, w10
        b.ne \target
    .endif N .endif N .endif N .endif N .endif N .endif N .endif N .endif
.endm

.irp cond, COND_LIST
    .gadget jmp_\cond
        // Debug: trace JMP_Z when taken or not taken
        .ifc \cond,z
            save_c
            ldr w9, [_cpu, CPU_flags_res]
            ldr x10, [_cpu, CPU_res]
            mov x0, x9                   // flags_res
            mov x1, x10                  // res
            bl NAME(helper_debug_jmp_z)
            restore_c
        .endif
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

// Debug wrapper for cmovn_z - just print debug info then do normal cmovn_z
.gadget debug_cmovn_z
    // Push our values FIRST, then call save_c
    // save_c uses sp, -0x60 so we go beyond that
    stp _xtmp, x8, [sp, -0x70]!         // sp -= 0x70, [sp] = _xtmp, [sp+8] = x8
    save_c                               // sp -= 0x60 more
    // Now sp is at original - 0xd0
    // Our values are at sp + 0x60 and sp + 0x68
    ldr x0, [sp, 0x60]                  // arg0 = source (_xtmp)
    ldr x1, [sp, 0x68]                  // arg1 = destination (x8)
    ldr x2, [_cpu, CPU_res]             // arg2 = cpu_res
    ldr w3, [_cpu, CPU_flags_res]       // arg3 = flags_res
    bl NAME(helper_debug_cmovne)
    restore_c                            // sp += 0x60
    // sp is now at original - 0x70, our values are at [sp]
    ldp _xtmp, x8, [sp], 0x70           // restore and sp += 0x70
    // Now do the actual cmovn_z logic (copied from the macro expansion)
    // Check ZF: bit 1 of flags_res means ZF comes from result
    ldr w9, [_cpu, CPU_flags_res]
    tbnz w9, 1, 2f
    // Check ZF in eflags (bit 6)
    ldr w9, [_cpu, CPU_eflags]
    tbnz w9, 6, 1f
    b 3f                                // ZF=0, keep source
2:
    ldr x9, [_cpu, CPU_res]
    cbz x9, 1f                          // result==0 means ZF=1
    b 3f                                // result!=0, ZF=0, keep source
1:  // ZF=1, keep destination
    mov _xtmp, x8
3:  // ZF=0 or after setting _xtmp=x8
    gret

// Debug wrapper for cmovn_sxo (CMOVGE) - trace before cmov decision
.gadget debug_cmovn_sxo
    // Save values before save_c clobbers them
    stp _xtmp, x8, [sp, -0x70]!         // sp -= 0x70, [sp] = _xtmp (src), [sp+8] = x8 (dst)
    save_c                               // sp -= 0x60 more
    // Load CPU values BEFORE clobbering x1 (which is _cpu!)
    ldr x2, [_cpu, CPU_res]             // arg2 = cpu_res (load FIRST while _cpu valid)
    ldrb w3, [_cpu, CPU_of]             // arg3 = OF flag (load FIRST while _cpu valid)
    // Now load args that clobber _cpu (x1)
    ldr x0, [sp, 0x60]                  // arg0 = source (_xtmp)
    ldr x1, [sp, 0x68]                  // arg1 = destination (x8) - safe to clobber x1 now
    bl NAME(helper_debug_cmovge)
    restore_c                            // sp += 0x60
    ldp _xtmp, x8, [sp], 0x70           // restore and sp += 0x70
    // Now do the actual cmovn_sxo logic (GE = NOT L = NOT (SF XOR OF))
    // If L (SF != OF), keep destination (x8)
    // If GE (SF == OF), keep source (_xtmp)
    ldr x9, [_cpu, CPU_res]
    cmp x9, 0
    cset w9, lt                          // SF = (res < 0)
    ldrb w10, [_cpu, CPU_of]
    cmp w9, w10
    b.ne 1f                              // SF != OF (L condition true), keep dst
    b 2f                                 // SF == OF (GE condition true), keep src
1:  // L condition true, keep destination
    mov _xtmp, x8
2:  gret

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
    // Watchpoint check BEFORE the store
    save_c
    mov x0, x8           // value (flags)
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store64)
    restore_c
    ldr x8, [_cpu, CPU_eflags]  // Reload x8 (clobbered by call)
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
