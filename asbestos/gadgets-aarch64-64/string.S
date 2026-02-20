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
// Note: First argument at [_ip] is orig_ip for segfault handler
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
    gret 1
    read_bullshit 8, single_movsb_r
    write_bullshit 8, single_movsb_w

// Single MOVSQ - Move exactly one qword from [RSI] to [RDI], then update RSI/RDI
// Used when MOVSQ appears without REP prefix
// Note: First argument at [_ip] is orig_ip for segfault handler
.gadget single_movsq
    mov _addr, rsi
    read_prep 64, single_movsq_r
    ldr _xtmp, [_addr]
    mov _addr, rdi
    write_prep 64, single_movsq_w
    str _xtmp, [_addr]
    write_done 64, single_movsq_w
    // Update RSI and RDI based on direction flag
    ldrsw x11, [_cpu, CPU_df_offset]  // x11 = 1 or -1 (sign-extended)
    lsl x11, x11, 3                   // x11 = df_offset * 8
    add rsi, rsi, x11
    add rdi, rdi, x11
    gret 1
    read_bullshit 64, single_movsq_r
    write_bullshit 64, single_movsq_w

// ============================================================
// REPNE SCASB - Scan string for byte in AL
// Compares AL with [RDI], sets flags, increments RDI, decrements RCX
// Repeats while RCX != 0 AND ZF == 0 (byte not found)
// Used for strlen: set AL=0, point RDI at string, scan for null
// ============================================================
.gadget repne_scasb
    cbz rcx, .Lrepne_scasb_done
.Lrepne_scasb_loop:
    mov _addr, rdi
    read_prep 8, repne_scasb_r
    ldrb _tmp, [_addr]
    // Compare AL with byte at [RDI]
    and w9, eax, 0xff           // w9 = AL
    subs _tmp, _tmp, w9         // _tmp = [RDI] - AL, sets flags
    // Update RDI based on direction flag
    ldrsw x11, [_cpu, CPU_df_offset]
    add rdi, rdi, x11
    // Decrement RCX
    sub rcx, rcx, 1
    // Store comparison result for flags
    // ZF is set if [RDI] == AL
    setf_zsp w
    clearf_oc  // SCAS clears OF and CF like CMP would for small values
    // Check loop condition: continue if RCX != 0 AND ZF == 0 (not equal)
    cbz rcx, .Lrepne_scasb_done
    cbnz _tmp, .Lrepne_scasb_loop  // If not equal, continue
.Lrepne_scasb_done:
    gret 1
    read_bullshit 8, repne_scasb_r

// REPE SCASB - Scan string while equal
// Repeats while RCX != 0 AND ZF == 1 (bytes are equal)
.gadget repe_scasb
    cbz rcx, .Lrepe_scasb_done
.Lrepe_scasb_loop:
    mov _addr, rdi
    read_prep 8, repe_scasb_r
    ldrb _tmp, [_addr]
    // Compare AL with byte at [RDI]
    and w9, eax, 0xff           // w9 = AL
    subs _tmp, _tmp, w9         // _tmp = [RDI] - AL, sets flags
    // Update RDI based on direction flag
    ldrsw x11, [_cpu, CPU_df_offset]
    add rdi, rdi, x11
    // Decrement RCX
    sub rcx, rcx, 1
    // Store comparison result for flags
    setf_zsp w
    clearf_oc
    // Check loop condition: continue if RCX != 0 AND ZF == 1 (equal)
    cbz rcx, .Lrepe_scasb_done
    cbz _tmp, .Lrepe_scasb_loop  // If equal, continue
.Lrepe_scasb_done:
    gret 1
    read_bullshit 8, repe_scasb_r

// Single SCASB - Compare AL with [RDI], update RDI, no repeat
// Note: First argument at [_ip] is orig_ip for segfault handler
.gadget single_scasb
    mov _addr, rdi
    read_prep 8, single_scasb_r
    ldrb _tmp, [_addr]
    // Compare AL with byte at [RDI]
    and w9, eax, 0xff           // w9 = AL
    subs _tmp, _tmp, w9         // _tmp = [RDI] - AL, sets flags
    // Update RDI based on direction flag
    ldrsw x11, [_cpu, CPU_df_offset]
    add rdi, rdi, x11
    // Store comparison result for flags
    setf_zsp w
    clearf_oc
    gret 1
    read_bullshit 8, single_scasb_r

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
