#include "gadgets.h"

// String operations for 64-bit
// df_offset stores 1 for forward, -1 for backward (dword_t = 32-bit signed)

// ============================================================
// REP STOSQ - Store RAX to [RDI], repeat RCX times
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by write_prep, must reload in loop!
// ============================================================
.gadget rep_stosq
    cbz rcx, .Lrep_stosq_done
.Lrep_stosq_loop:
    mov _addr, rdi
    write_prep 64, rep_stosq
    // Watchpoint check
    save_c
    mov x0, rax          // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store64)
    restore_c
    str rax, [_addr]
    write_done 64, rep_stosq
    // Reload x11 - clobbered by write_prep!
    // Use ldrsw to sign-extend 32-bit df_offset to 64-bit
    ldrsw x11, [_cpu, CPU_df_offset]
    lsl x11, x11, 3              // x11 = df_offset * 8
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_stosq_loop
.Lrep_stosq_done:
    gret 1
    write_bullshit 64, rep_stosq

// REP STOSD - Store EAX to [RDI], repeat RCX times (32-bit)
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by write_prep, must reload in loop!
.gadget rep_stosd
    cbz rcx, .Lrep_stosd_done
.Lrep_stosd_loop:
    mov _addr, rdi
    write_prep 32, rep_stosd
    // Watchpoint check for entry 2 flag
    save_c
    uxtw x0, eax         // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store32)
    restore_c
    str eax, [_addr]
    write_done 32, rep_stosd
    // Reload x11 - clobbered by write_prep!
    ldrsw x11, [_cpu, CPU_df_offset]
    lsl x11, x11, 2              // x11 = df_offset * 4
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_stosd_loop
.Lrep_stosd_done:
    gret 1
    write_bullshit 32, rep_stosd

// REP STOSB - Store AL to [RDI], repeat RCX times (8-bit)
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by write_prep, must reload in loop!
.gadget rep_stosb
    cbz rcx, .Lrep_stosb_done
.Lrep_stosb_loop:
    mov _addr, rdi
    write_prep 8, rep_stosb
    // Watchpoint check
    save_c
    uxtb x0, eax         // value (byte)
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store8)
    restore_c
    strb eax, [_addr]
    write_done 8, rep_stosb
    // Reload x11 - clobbered by write_prep!
    ldrsw x11, [_cpu, CPU_df_offset]  // x11 = 1 or -1 (sign-extended)
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_stosb_loop
.Lrep_stosb_done:
    gret 1
    write_bullshit 8, rep_stosb

// ============================================================
// REP MOVSQ - Move [RSI] to [RDI], repeat RCX times
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by read_prep/write_prep, must reload in loop!
// ============================================================
.gadget rep_movsq
    cbz rcx, .Lrep_movsq_done
.Lrep_movsq_loop:
    mov _addr, rsi
    read_prep 64, rep_movsq_r
    ldr _xtmp, [_addr]
    mov _addr, rdi
    write_prep 64, rep_movsq_w
    // Watchpoint check
    save_c
    mov x0, _xtmp        // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store64)
    restore_c
    str _xtmp, [_addr]
    write_done 64, rep_movsq_w
    // Reload x11 - clobbered by read_prep/write_prep!
    ldrsw x11, [_cpu, CPU_df_offset]
    lsl x11, x11, 3              // x11 = df_offset * 8
    add rsi, rsi, x11
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_movsq_loop
.Lrep_movsq_done:
    gret 1
    read_bullshit 64, rep_movsq_r
    write_bullshit 64, rep_movsq_w

// REP MOVSD - Move dword [RSI] to [RDI], repeat RCX times
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by read_prep/write_prep, must reload in loop!
.gadget rep_movsd
    cbz rcx, .Lrep_movsd_done
.Lrep_movsd_loop:
    mov _addr, rsi
    read_prep 32, rep_movsd_r
    ldr _tmp, [_addr]
    mov _addr, rdi
    write_prep 32, rep_movsd_w
    // Watchpoint check
    save_c
    uxtw x0, _tmp        // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store32)
    restore_c
    str _tmp, [_addr]
    write_done 32, rep_movsd_w
    // Reload x11 - clobbered by read_prep/write_prep!
    ldrsw x11, [_cpu, CPU_df_offset]
    lsl x11, x11, 2              // x11 = df_offset * 4
    add rsi, rsi, x11
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_movsd_loop
.Lrep_movsd_done:
    gret 1
    read_bullshit 32, rep_movsd_r
    write_bullshit 32, rep_movsd_w

// REP MOVSB - Move byte [RSI] to [RDI], repeat RCX times
// Note: First argument at [_ip] is orig_ip for segfault handler
// IMPORTANT: x11 is clobbered by read_prep/write_prep, must reload in loop!
.gadget rep_movsb
    cbz rcx, .Lrep_movsb_done
.Lrep_movsb_loop:
    mov _addr, rsi
    read_prep 8, rep_movsb_r
    ldrb _tmp, [_addr]
    mov _addr, rdi
    write_prep 8, rep_movsb_w
    // Watchpoint check
    save_c
    uxtb x0, _tmp        // value (byte)
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store8)
    restore_c
    strb _tmp, [_addr]
    write_done 8, rep_movsb_w
    // Reload x11 - clobbered by read_prep/write_prep!
    ldrsw x11, [_cpu, CPU_df_offset]  // x11 = 1 or -1 (sign-extended)
    add rsi, rsi, x11
    add rdi, rdi, x11
    sub rcx, rcx, 1
    cbnz rcx, .Lrep_movsb_loop
.Lrep_movsb_done:
    gret 1
    read_bullshit 8, rep_movsb_r
    write_bullshit 8, rep_movsb_w

// Single MOVSB - Move exactly one byte from [RSI] to [RDI], then update RSI/RDI
// Used when MOVSB appears without REP prefix
.gadget single_movsb
    mov _addr, rsi
    read_prep 8, single_movsb_r
    ldrb _tmp, [_addr]
    mov _addr, rdi
    write_prep 8, single_movsb_w
    strb _tmp, [_addr]
    write_done 8, single_movsb_w
    // Update RSI and RDI based on direction flag
    ldrsw x11, [_cpu, CPU_df_offset]  // x11 = 1 or -1 (sign-extended)
    add rsi, rsi, x11
    add rdi, rdi, x11
    gret
    read_bullshit 8, single_movsb_r
    write_bullshit 8, single_movsb_w

// Placeholder gadget arrays (kept for compatibility)
.pushsection_rodata
.global.name lods_gadgets
    .fill 15, 8, 0
.global.name stos_gadgets
    .fill 15, 8, 0
.global.name movs_gadgets
    .fill 15, 8, 0
.global.name cmps_gadgets
    .fill 15, 8, 0
.global.name scas_gadgets
    .fill 15, 8, 0
.popsection
