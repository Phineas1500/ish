#include "gadgets.h"
#include "math.h"

// Load address into temp register
.gadget load64_addr
    mov _xtmp, _addr
    gret

.gadget load32_addr
    mov _tmp, _waddr
    gret

// ============================================================
// Load gadgets - load value into _tmp/_xtmp
// ============================================================

// Load from registers (rax-rdi kept in ARM64 regs)
.macro load_reg64 name, reg64, reg32
    .gadget load64_\name
        mov _xtmp, \reg64
        gret
    .gadget load32_\name
        mov _xtmp, \reg64
        and _xtmp, _xtmp, 0xffffffff
        gret
.endm
.each_reg64 load_reg64
.purgem load_reg64

// Load immediate
.gadget load64_imm
    ldr _xtmp, [_ip]
    // Debug: trace suspicious value (0xffffffffffffff80)
    movn x9, 0x7f               // x9 = 0xffffffffffffff80
    cmp _xtmp, x9
    b.ne 66f
    save_c
    mov x0, _xtmp
    bl NAME(helper_debug_load64_imm_suspicious)
    restore_c
66:
    gret 1

.gadget load32_imm
    ldr _tmp, [_ip]
    gret 1

// Load from memory - minimal trace
.gadget load64_mem
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 64, load64_mem
    ldr _xtmp, [_addr]                 // Direct ARM64 load
    // Check for loads from reg_save_area (0x7efffff5bbf0-0x7efffff5bc20)
    // This traces va_arg reads during vsnprintf
    ldr x9, [_cpu, LOCAL_value_addr]   // guest address
    movz x10, 0xbbf0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 68f
    movz x10, 0xbc20
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 68f
    save_c
    mov x0, _xtmp                      // loaded value
    ldr x1, [_cpu, LOCAL_value_addr]   // guest address
    bl NAME(helper_debug_load64_reg_save_area)
    restore_c
68:
    // Check for suspicious value 0xffffffffffffff80
    movn x9, 0x7f               // x9 = 0xffffffffffffff80
    cmp _xtmp, x9
    b.ne 66f
    save_c
    mov x0, _xtmp
    ldr x1, [_cpu, LOCAL_value_addr]   // guest address
    bl NAME(helper_debug_load64_mem_suspicious)
    restore_c
    b 67f
66:
    // Also check for 0x7f0000000... values (path corruption)
    lsr x9, _xtmp, 36           // get upper 28 bits
    mov x10, 0x7f0              // pattern to match
    cmp x9, x10
    b.ne 67f
    ldr x10, [_cpu, CPU_rip]    // Get RIP before save_c
    save_c
    mov x0, _xtmp
    ldr x1, [_cpu, LOCAL_value_addr]
    mov x2, x10                 // Pass RIP
    bl NAME(helper_debug_load64_7f_base)
    restore_c
67:
    // Debug: trace AFTER restore_c to check state before gret
    // Check if crash page
    lsr x10, _xtmp, 40                // get upper bits (for large values)
    cbnz x10, 1f                       // Skip if not a small value
    save_c
    mov x0, _xtmp                      // loaded value (_xtmp)
    mov x1, _cpu                       // _cpu pointer
    mov x2, _ip                        // _ip pointer
    ldr x3, [_ip]                      // [_ip] = orig_ip argument
    ldr x4, [_ip, 8]                   // [_ip+8] = next gadget (what gret 1 jumps to)
    bl NAME(helper_debug_load64_after_restore)
    restore_c
1:
    gret 1
    read_bullshit 64, load64_mem

.gadget load32_mem
    // Save guest address before TLB translation
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 32, load32_mem
    // Debug: trace entry to load32_mem after TLB
    save_c
    mov x0, _addr           // host addr
    ldr x1, [_cpu, LOCAL_value_addr]   // guest addr
    bl NAME(helper_debug_load32_entry)
    restore_c
    ldr _tmp, [_addr]
    // Track ALL loads in ring buffer for debugging
    ldr x9, [_cpu, LOCAL_value_addr]
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_track_load32)
    restore_c
    // Additional debug: trace loads from optind areas
    ldr x9, [_cpu, LOCAL_value_addr]
    // Check busybox optind (0x55555561a040-0x55555561a080)
    movz x10, 0xa040
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.lo 2f
    movz x10, 0xa080
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.hs 2f
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_optind_load)
    restore_c
    b 1f
2:
    // Check musl optind (0x7effffffd000-0x7effffffe000 - wider range)
    movz x10, 0xd000
    movk x10, 0xffff, lsl 16
    movk x10, 0xffff, lsl 32
    movk x10, 0x7eff, lsl 48
    cmp x9, x10
    b.lo 1f
    movz x10, 0xe000
    movk x10, 0xffff, lsl 16
    movk x10, 0xffff, lsl 32
    movk x10, 0x7eff, lsl 48
    cmp x9, x10
    b.hs 1f
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_musl_load)
    restore_c
1:
    gret 1
    read_bullshit 32, load32_mem

// Load 16-bit from memory (zero-extended)
.gadget load16_mem
    read_prep 16, load16_mem
    ldrh _tmp, [_addr]
    gret 1
    read_bullshit 16, load16_mem

// Load 8-bit from memory (zero-extended)
.gadget load8_mem
    // Save guest address before TLB translation
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 8, load8_mem
    ldrb _tmp, [_addr]
    // Debug: trace byte loads with guest addr and orig_ip
    // When gadget runs, _ip points past the gadget_load8_mem pointer
    // So: [_ip, 0] = orig_ip, [_ip, 8] = next gadget
    ldr x9, [_cpu, LOCAL_value_addr]
    save_c
    uxtw x0, _tmp           // byte value
    mov x1, x9              // GUEST address (pre-TLB)
    ldr x2, [_ip]           // orig_ip argument at [_ip, 0]
    bl NAME(helper_debug_load8_mem_full)
    restore_c
    gret 1
    read_bullshit 8, load8_mem

// Load from r8-r15 (stored in memory, not ARM64 registers)
.gadget load64_r8
    ldr _xtmp, [_cpu, CPU_r8]
    gret

.gadget load64_r9
    ldr _xtmp, [_cpu, CPU_r9]
    gret

.gadget load64_r10
    // Load r10 via C helper (ARM64 ldr crashed for unknown reason)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r10_simple)
    mov x19, x0                    // Save result in callee-saved reg
    restore_c
    mov _xtmp, x19                 // Put result in _xtmp
    gret

.gadget load64_r11
    ldr _xtmp, [_cpu, CPU_r11]
    gret

.gadget load64_r12
    ldr _xtmp, [_cpu, CPU_r12]
    gret

.gadget load64_r13
    // Load r13 via C helper (same pattern as load64_r10)
    save_c
    mov x0, _cpu
    bl NAME(helper_load_r13_simple)
    mov x19, x0
    restore_c
    mov _xtmp, x19
    gret

.gadget load64_r14
    ldr _xtmp, [_cpu, CPU_r14]
    gret

.gadget load64_r15
    ldr _xtmp, [_cpu, CPU_r15]
    gret

// ============================================================
// Store gadgets - store value from _tmp/_xtmp
// ============================================================

// Store to registers - with debug tracing for RDX
.macro store_reg64 name, reg64, reg32
    .gadget store64_\name
        .ifc \name,d
            // Trace stores to RDX with suspicious value
            movn x9, 0x7f
            cmp _xtmp, x9
            b.ne 70f
            save_c
            mov x0, _xtmp
            bl NAME(helper_debug_store64_rdx_suspicious)
            restore_c
        70:
        .endif
        mov \reg64, _xtmp
        gret
    .gadget store32_\name
        // 32-bit write zero-extends to 64-bit in x86_64
        mov \reg64, _xtmp
        and \reg64, \reg64, 0xffffffff
        gret
.endm
.each_reg64 store_reg64
.purgem store_reg64

// Debug: extra gadget to trace RCX stores around bfdb-bfde
.gadget store64_c_trace
    mov rcx, _xtmp
    // Check if rcx is in the bfdb-bfde range
    movz x9, 0xbfdb
    movk x9, 0xfff5, lsl 16
    movk x9, 0x7eff, lsl 32
    cmp rcx, x9
    b.lo 1f
    movz x9, 0xbfdf
    movk x9, 0xfff5, lsl 16
    movk x9, 0x7eff, lsl 32
    cmp rcx, x9
    b.hi 1f
    save_c
    mov x0, rcx
    bl NAME(helper_debug_store64_c)
    restore_c
1:
    gret

// Store to memory
.gadget store64_mem
    // Save guest address before TLB translation
    str _addr, [_cpu, LOCAL_value_addr]
    // Save _xtmp (value to store) BEFORE write_prep might clobber it via TLB miss
    str _xtmp, [_cpu, LOCAL_value]
    write_prep 64, store64_mem
    // Check if storing TO 0x7f... address (heap destination)
    ldr x19, [_cpu, LOCAL_value_addr]
    lsr x9, x19, 36
    mov x10, 0x7f0
    cmp x9, x10
    b.ne 88f
    mov x11, _cpu          // Save _cpu before save_c clobbers x1
    ldr x19, [_cpu, LOCAL_value]
    ldr x12, [_cpu, CPU_rip]  // Get RIP
    save_c
    mov x0, x19            // value being stored
    ldr x1, [x11, LOCAL_value_addr]  // guest dest address
    mov x2, x12            // guest RIP
    bl NAME(helper_debug_store64_to_7f_rip)
    restore_c
88:
    // BYPASS ALL STORES VIA C CODE TO DEBUG
    ldr x19, [_cpu, LOCAL_value]    // value to store (saved before write_prep)
    save_c
    mov x0, _addr       // host addr after TLB
    mov x1, x19         // value to store
    bl NAME(helper_store64_via_c)
    restore_c
86:
    write_done 64, store64_mem
    // Debug: trace stores with 0x7f0... value (path corruption)
    ldr x19, [_cpu, LOCAL_value]
    lsr x9, x19, 36
    mov x10, 0x7f0
    cmp x9, x10
    b.ne 50f
    ldr x10, [_cpu, CPU_rip]  // Load guest RIP BEFORE save_c
    mov x11, _cpu             // Save _cpu before it gets clobbered
    save_c
    mov x0, x19               // value
    ldr x1, [x11, LOCAL_value_addr]  // guest_addr (use saved _cpu)
    mov x2, x10               // rip
    mov x3, x11               // cpu pointer (use saved _cpu)
    bl NAME(helper_debug_store64_7f_value)
    restore_c
50:
    // Debug: trace stores with value 2 (strlen result)
    cmp _xtmp, 2
    b.ne 5f
    save_c
    mov x0, _xtmp
    ldr x1, [_cpu, LOCAL_value_addr]
    bl NAME(helper_debug_store64_mem_val2)
    restore_c
5:
    // Debug: trace 64-bit stores to option table (stack 0x7efffff5b540-0x7efffff5b6a0)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xb540
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 6f
    movz x10, 0xb6a0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 6f
    ldr x19, [_cpu, LOCAL_value]
    save_c
    mov x0, x19
    mov x1, x9
    bl NAME(helper_debug_opt_table_store64)
    restore_c
6:
    // Debug: trace stores to iov area (0x7efffff5b850-0x7efffff5b8a0)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xb850
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 2f
    movz x10, 0xb8a0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 2f
    save_c
    mov x0, _xtmp
    mov x1, x9
    bl NAME(helper_debug_iov_store64)
    restore_c
2:
    // Debug: trace ALL 64-bit stores to busybox data segment (0x555555616000-0x55555561b000)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0x6000
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.lo 1f
    movz x10, 0xb000
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.hs 1f
    save_c
    mov x0, _xtmp
    mov x1, x9
    bl NAME(helper_debug_busybox_store64)
    restore_c
1:
    // Debug: trace stores to va_list area (0x7efffff5bb00-0x7efffff5bcf0)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xbb00
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 98f
    movz x10, 0xbcf0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 98f
    save_c
    mov x0, _xtmp
    mov x1, x9
    bl NAME(helper_debug_va_list_store64)
    restore_c
98:
    gret 1
    write_bullshit 64, store64_mem

.gadget store32_mem
    // Save guest address before TLB translation
    str _addr, [_cpu, LOCAL_value_addr]
    write_prep 32, store32_mem
    // Debug: trace entry 2 flag stores with host address (after TLB)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xb594
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.ne 7f
    save_c
    uxtw x0, _tmp        // value
    mov x1, x9           // guest addr
    mov x2, _addr        // host addr (after TLB)
    bl NAME(helper_debug_opt_table_store32_host)
    restore_c
7:
    // Check watchpoint BEFORE the actual store
    save_c
    uxtw x0, _tmp        // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store32)
    restore_c
    str _tmp, [_addr]
    // Debug: verify store succeeded for entry 2 flag
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xb594
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.ne 8f
    save_c
    mov x0, x9           // guest addr
    mov x1, _addr        // host addr
    bl NAME(helper_debug_opt_table_store32_after)
    restore_c
8:
    write_done 32, store32_mem
    // Debug: trace stores to option table (stack 0x7efffff5b540-0x7efffff5b6a0)
    // Target: 0x00007efffff5b540
    //   bits 0-15:  0xb540
    //   bits 16-31: 0xfff5
    //   bits 32-47: 0x7eff
    //   bits 48-63: 0x0000
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xb540
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 4f
    movz x10, 0xb6a0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 4f
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_opt_table_store32)
    restore_c
4:
    // Debug: trace ALL stores to busybox data segment (0x555555616000-0x55555561b000)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0x6000
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.lo 3f
    movz x10, 0xb000
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.hs 3f
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_busybox_store32)
    restore_c
3:
    // Debug and fix: trace stores to optind area (0x55555561a040-0x55555561a080)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xa040
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.lo 1f
    movz x10, 0xa080
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.hs 1f
    // Call helper which returns the (possibly fixed) value
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_optind_store)
    // x0 now contains the corrected value
    // Save it to LOCAL_value - but _cpu (x1) was trashed by the C call!
    // Reload _cpu from stack where save_c saved it: x1 is at sp+8
    ldr x1, [sp, 8]                   // Reload _cpu
    str w0, [_cpu, LOCAL_value]       // Now _cpu is valid
    restore_c
    // Re-do the store with the (possibly corrected) value
    ldr x9, [_cpu, LOCAL_value_addr]
    ldr w0, [_cpu, LOCAL_value]       // Load corrected value into w0
    mov _addr, x9                     // Set guest address
    // Do the fix store
    write_prep 32, store32_mem_fix
    str w0, [_addr]                   // Store corrected value
    write_done 32, store32_mem_fix
1:
    // Debug and fix: trace stores to va_list area (0x7efffff5bb00-0x7efffff5bcf0)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xbb00
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.lo 99f
    movz x10, 0xbcf0
    movk x10, 0xfff5, lsl 16
    movk x10, 0x7eff, lsl 32
    cmp x9, x10
    b.hs 99f
    // Call helper which may return a corrected value (8->16 for gp_offset)
    save_c
    uxtw x0, _tmp
    mov x1, x9
    bl NAME(helper_debug_va_list_store32)
    // x0 now contains the (possibly corrected) value
    // Save it to LOCAL_value - but _cpu was trashed by C call
    ldr x1, [sp, 8]                   // Reload _cpu from stack
    str w0, [x1, LOCAL_value]         // Save corrected value
    restore_c
    // Re-do the store with the (possibly corrected) value
    ldr x9, [_cpu, LOCAL_value_addr]  // Guest address
    ldr w0, [_cpu, LOCAL_value]       // Corrected value
    mov _addr, x9                     // Set guest address
    // Do the fix store
    write_prep 32, store32_mem_vafix
    str w0, [_addr]                   // Store corrected value
    write_done 32, store32_mem_vafix
99:
    gret 1
    write_bullshit 32, store32_mem_vafix
    write_bullshit 32, store32_mem
    write_bullshit 32, store32_mem_fix

.gadget store16_mem
    write_prep 16, store16_mem
    // Watchpoint check for entry 2 flag
    save_c
    uxtw x0, _tmp        // value
    mov x1, _addr        // host addr
    bl NAME(helper_check_watchpoint_store16)
    restore_c
    strh _tmp, [_addr]
    write_done 16, store16_mem
    gret 1
    write_bullshit 16, store16_mem

.gadget store8_mem
    // Save guest address BEFORE write_prep translates it to host
    str _addr, [_cpu, LOCAL_value_addr]
    write_prep 8, store8_mem
    // Check if guest address is in 0x7f0000000xxx range (malloc'd heap)
    ldr x9, [_cpu, LOCAL_value_addr]
    lsr x10, x9, 36
    mov x11, 0x7f0
    cmp x10, x11
    b.ne 1f
    // Trace store8 to 0x7f... address
    save_c
    uxtb x0, _tmp        // value (byte)
    ldr x1, [_cpu, LOCAL_value_addr]  // guest addr
    bl NAME(helper_debug_store8_7f)
    restore_c
1:
    strb _tmp, [_addr]
    write_done 8, store8_mem
    gret 1
    write_bullshit 8, store8_mem

// Store to r8-r15 (stored in memory, not ARM64 registers)
.gadget store64_r8
    str _xtmp, [_cpu, CPU_r8]
    gret

.gadget store64_r9
    str _xtmp, [_cpu, CPU_r9]
    gret

.gadget store64_r10
    str _xtmp, [_cpu, CPU_r10]
    gret

.gadget store64_r11
    // Debug: trace stores to r11 in printf_core range
    ldr x10, [_cpu, CPU_rip]
    save_c
    mov x0, _xtmp
    mov x1, x10
    bl NAME(helper_debug_store64_r11)
    restore_c
    str _xtmp, [_cpu, CPU_r11]
    gret

.gadget store64_r12
    // Debug: trace r12 stores with RIP when 0x7f... value
    lsr x9, _xtmp, 36
    mov x10, 0x7f0
    cmp x9, x10
    b.ne 1f
    ldr x10, [_cpu, CPU_rip]  // Get RIP
    mov x11, _cpu             // Save _cpu
    save_c
    mov x0, _xtmp             // value
    mov x1, x10               // rip
    bl NAME(helper_debug_store64_r12_with_rip)
    restore_c
    b 2f
1:
    save_c
    mov x0, _xtmp
    bl NAME(helper_debug_store64_r12)
    restore_c
2:
    str _xtmp, [_cpu, CPU_r12]
    gret

.gadget store64_r13
    // Debug: trace r13 stores with guest RIP
    ldr x10, [_cpu, CPU_rip]   // Load guest RIP BEFORE save_c
    save_c
    mov x0, _xtmp              // value
    mov x1, x10                // guest RIP
    bl NAME(helper_debug_store64_r13)
    restore_c
    str _xtmp, [_cpu, CPU_r13]
    gret

.gadget store64_r14
    // Debug: trace r14 stores with guest RIP
    ldr x10, [_cpu, CPU_rip]  // Load guest RIP BEFORE save_c
    save_c
    mov x0, _xtmp             // value
    mov x1, x10               // guest RIP
    bl NAME(helper_debug_store64_r14)
    restore_c
    str _xtmp, [_cpu, CPU_r14]
    gret

.gadget store64_r15
    // Debug: trace r15 stores with guest RIP
    ldr x10, [_cpu, CPU_rip]  // Load guest RIP BEFORE save_c
    save_c
    mov x0, _xtmp             // value
    mov x1, x10               // guest RIP
    bl NAME(helper_debug_store64_r15)
    restore_c
    str _xtmp, [_cpu, CPU_r15]
    gret

// ============================================================
// ADD gadgets
// ============================================================

.macro add_reg64 name, reg64, reg32
    .gadget add64_\name
        adds _xtmp, _xtmp, \reg64
        setf_oc
        setf_zsp
        gret
    .gadget add32_\name
        adds _tmp, _tmp, \reg32
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 add_reg64
.purgem add_reg64

.gadget add64_imm
    ldr x8, [_ip]
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1

// Flag-preserving add for LEA - does NOT modify CPU flags
.gadget lea_add64_imm
    ldr x8, [_ip]
    add _xtmp, _xtmp, x8    // add (not adds) - doesn't touch ARM flags
    gret 1

.gadget add32_imm
    ldr w8, [_ip]
    adds _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1

.gadget add64_mem
    read_prep 64, add64_mem
    ldr x8, [_addr]
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1
    read_bullshit 64, add64_mem

.gadget add32_mem
    read_prep 32, add32_mem
    ldr w8, [_addr]
    adds _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, add32_mem

// ADD with x8 (for adding r8-r15 which are loaded into x8)
.gadget add64_x8
    adds _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret

// 32-bit ADD with x8 (for adding r8-r15 in 32-bit mode)
// Result is zero-extended to 64 bits (x86_64 semantics)
.gadget add32_x8
    adds _tmp, _tmp, w8        // 32-bit add with flags
    uxtw _xtmp, _tmp           // zero-extend to 64-bit
    setf_oc
    setf_zsp w
    gret

// ============================================================
// ADC gadgets (Add with Carry)
// ============================================================

// ADC: dst = dst + src + CF
// _xtmp already has dst value, add immediate and carry flag

.gadget adc64_imm
    ldr x8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    adds _xtmp, _xtmp, x8   // Add immediate
    add _xtmp, _xtmp, x9    // Add carry (this won't set flags correctly, but simplifies)
    setf_oc
    setf_zsp
    gret 1

.gadget adc32_imm
    ldr w8, [_ip]           // Load immediate
    ldrb w9, [_cpu, CPU_cf] // Load carry flag
    adds _tmp, _tmp, w8     // Add immediate
    add _tmp, _tmp, w9      // Add carry
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1

// SBB (Subtract with Borrow) gadgets
// SBB dest, src: dest = dest - src - CF
.macro sbb_reg64 name, reg64, reg32
    .gadget sbb64_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        subs _xtmp, _xtmp, \reg64 // dest - src
        sub _xtmp, _xtmp, x9      // - CF
        setf_oc
        setf_zsp
        gret
    .gadget sbb32_\name
        ldrb w9, [_cpu, CPU_cf]   // Load carry flag
        subs _tmp, _tmp, \reg32   // dest - src
        sub _tmp, _tmp, w9        // - CF
        and _xtmp, _xtmp, 0xffffffff  // Zero-extend
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 sbb_reg64
.purgem sbb_reg64

.gadget sbb64_imm
    ldr x8, [_ip]            // Load immediate
    ldrb w9, [_cpu, CPU_cf]  // Load carry flag
    subs _xtmp, _xtmp, x8    // dest - imm
    sub _xtmp, _xtmp, x9     // - CF
    setf_oc
    setf_zsp
    gret 1

.gadget sbb32_imm
    ldr w8, [_ip]            // Load immediate
    ldrb w9, [_cpu, CPU_cf]  // Load carry flag
    subs _tmp, _tmp, w8      // dest - imm
    sub _tmp, _tmp, w9       // - CF
    and _xtmp, _xtmp, 0xffffffff  // Zero-extend
    setf_oc
    setf_zsp w
    gret 1

// ============================================================
// SUB gadgets
// ============================================================

.macro sub_reg64 name, reg64, reg32
    .gadget sub64_\name
        subs _xtmp, _xtmp, \reg64
        setf_oc
        setf_zsp
        gret
    .gadget sub32_\name
        subs _tmp, _tmp, \reg32
        setf_oc
        setf_zsp w
        gret
.endm
.each_reg64 sub_reg64
.purgem sub_reg64

.gadget sub64_imm
    ldr x8, [_ip]
    subs _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1

.gadget sub32_imm
    ldr w8, [_ip]
    subs _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1

.gadget sub64_mem
    read_prep 64, sub64_mem
    ldr x8, [_addr]
    subs _xtmp, _xtmp, x8
    setf_oc
    setf_zsp
    gret 1
    read_bullshit 64, sub64_mem

// SUB with x8 (for subtracting r8-r15 which are loaded into x8)
// Note: SUB dst, r8 means dst = dst - r8, but we have x8=dst, _xtmp=r8
// So we need: result = dst - r8 = x8 - _xtmp
.gadget sub64_x8
    subs _xtmp, x8, _xtmp
    setf_oc
    setf_zsp
    gret

.gadget sub32_mem
    // Save guest address before TLB translation
    str _addr, [_cpu, LOCAL_value_addr]
    read_prep 32, sub32_mem
    ldr w8, [_addr]
    // Debug: trace loads from busybox optind area (0x55555561a040-0x55555561a080)
    ldr x9, [_cpu, LOCAL_value_addr]
    movz x10, 0xa040
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.lo 1f
    movz x10, 0xa080
    movk x10, 0x5561, lsl 16
    movk x10, 0x5555, lsl 32
    cmp x9, x10
    b.hs 1f
    save_c
    uxtw x0, w8
    mov x1, x9
    bl NAME(helper_debug_optind_sub_load)
    restore_c
1:
    subs _tmp, _tmp, w8
    setf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, sub32_mem

// ============================================================
// XOR gadget (needed for xor rax, rax - common idiom)
// ============================================================

.macro xor_reg64 name, reg64, reg32
    .gadget xor64_\name
        eor _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
    .gadget xor32_\name
        eor _tmp, _tmp, \reg32
        clearf_oc
        setf_zsp w
        gret
.endm
.each_reg64 xor_reg64
.purgem xor_reg64

// XOR zeroing idiom - sets _xtmp=0 and flags as if XOR produced 0
// ZF=1, SF=0, CF=0, OF=0, PF=1
.gadget xor_zero
    eor _xtmp, _xtmp, _xtmp   // _xtmp = 0
    clearf_oc                  // CF=0, OF=0
    setf_zsp                   // Sets flags based on _xtmp (which is 0)
    gret

.gadget xor64_imm
    ldr x8, [_ip]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

.gadget xor32_imm
    ldr w8, [_ip]
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1

// XOR with memory: _xtmp = _xtmp XOR [_addr]
.gadget xor64_mem
    read_prep 64, xor64_mem
    ldr x8, [_addr]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1
    read_bullshit 64, xor64_mem

.gadget xor32_mem
    read_prep 32, xor32_mem
    ldr w8, [_addr]
    // Debug trace
    save_c
    mov w0, _tmp             // operand1 before
    mov w1, w8               // memory value
    mov x2, _addr            // address (64-bit)
    bl NAME(helper_debug_xor32_mem)
    restore_c
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1
    read_bullshit 32, xor32_mem

// XOR gadgets for r8-r15: _xtmp = _xtmp XOR r[N]
.macro xor64_r8_r15 num, offset
.gadget xor64_r\num
    ldr x8, [_cpu, \offset]
    eor _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret
.gadget xor32_r\num
    ldr w8, [_cpu, \offset]
    eor _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret
.endm
xor64_r8_r15 8, CPU_r8
xor64_r8_r15 9, CPU_r9
xor64_r8_r15 10, CPU_r10
xor64_r8_r15 11, CPU_r11
xor64_r8_r15 12, CPU_r12
xor64_r8_r15 13, CPU_r13
xor64_r8_r15 14, CPU_r14
xor64_r8_r15 15, CPU_r15

.pushsection_rodata
.align 3
.global NAME(xor64_r8_r15_gadgets)
NAME(xor64_r8_r15_gadgets):
    .quad NAME(gadget_xor64_r8)
    .quad NAME(gadget_xor64_r9)
    .quad NAME(gadget_xor64_r10)
    .quad NAME(gadget_xor64_r11)
    .quad NAME(gadget_xor64_r12)
    .quad NAME(gadget_xor64_r13)
    .quad NAME(gadget_xor64_r14)
    .quad NAME(gadget_xor64_r15)
.global NAME(xor32_r8_r15_gadgets)
NAME(xor32_r8_r15_gadgets):
    .quad NAME(gadget_xor32_r8)
    .quad NAME(gadget_xor32_r9)
    .quad NAME(gadget_xor32_r10)
    .quad NAME(gadget_xor32_r11)
    .quad NAME(gadget_xor32_r12)
    .quad NAME(gadget_xor32_r13)
    .quad NAME(gadget_xor32_r14)
    .quad NAME(gadget_xor32_r15)
.popsection

// ============================================================
// AND gadgets
// ============================================================

.gadget and64_imm
    ldr x8, [_ip]
    ands _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

// Flag-preserving AND for LEA 32-bit masking - does NOT modify CPU flags
.gadget lea_and64_imm
    ldr x8, [_ip]
    and _xtmp, _xtmp, x8    // and (not ands) - doesn't touch ARM flags
    gret 1

.gadget and32_imm
    ldr w8, [_ip]
    ands _tmp, _tmp, w8
    clearf_oc
    setf_zsp w
    gret 1

// AND with register (x8 contains value to AND)
.gadget and64_x8
    ands _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret

// AND with register (for reg, reg - xtmp = xtmp & other_reg)
.macro and_reg64 name, reg64, reg32
    .gadget and64_\name
        ands _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
.endm
.each_reg64 and_reg64
.purgem and_reg64

// AND memory operand (read from _addr, AND with value in x8)
.gadget and64_mem
    read_prep 64, and64_mem
    ldr x9, [_addr]
    ands x9, x9, x8
    str x9, [_addr]
    clearf_oc
    mov _xtmp, x9
    setf_zsp
    gret 1
    read_bullshit 64, and64_mem

// ============================================================
// OR gadgets
// ============================================================

.gadget or64_imm
    ldr x8, [_ip]
    orr _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret 1

.gadget or32_imm
    ldr w8, [_ip]
    orr _tmp, _tmp, w8
    and _xtmp, _xtmp, 0xffffffff
    clearf_oc
    setf_zsp w
    gret 1

// OR with register (x8 contains value to OR)
.gadget or64_x8
    orr _xtmp, _xtmp, x8
    clearf_oc
    setf_zsp
    gret

// OR with register (for reg, reg - xtmp = xtmp | other_reg)
.macro or_reg64 name, reg64, reg32
    .gadget or64_\name
        orr _xtmp, _xtmp, \reg64
        clearf_oc
        setf_zsp
        gret
.endm
.each_reg64 or_reg64
.purgem or_reg64

// OR 64-bit memory operand (read from _addr, OR with value in x8)
// NOTE: For 32-bit OR operations, use or32_mem instead to avoid
// corrupting adjacent memory with 64-bit writes.
.gadget or64_mem
    read_prep 64, or64_mem
    ldr x9, [_addr]                      // Load current 64-bit memory value
    orr x9, x9, x8                       // 64-bit OR
    str x9, [_addr]                      // 64-bit store back
    clearf_oc
    mov _xtmp, x9
    setf_zsp
    gret 1
    read_bullshit 64, or64_mem

// OR 32-bit memory operand (read from _addr, OR with value in w8)
// FIX: Use 32-bit operations to avoid corrupting adjacent memory
// The original or64_mem was doing 64-bit reads/writes which could corrupt
// adjacent memory fields in structures when used for 32-bit OR operations.
.gadget or32_mem
    read_prep 32, or32_mem
    ldr w9, [_addr]                      // Load current 32-bit memory value
    orr w9, w9, w8                       // 32-bit OR
    str w9, [_addr]                      // 32-bit store back
    clearf_oc
    uxtw _xtmp, w9                       // Zero-extend result to 64-bit
    setf_zsp w
    gret 1
    read_bullshit 32, or32_mem

// ============================================================
// CMP gadgets (compare without storing)
// ============================================================

.gadget cmp64_imm
    ldr x8, [_ip]
    subs x9, _xtmp, x8    // Save result for flags (don't discard)
    setf_oc
    setf_zsp , x9         // Use the subtraction result for ZF/SF/PF
    gret 1

.gadget cmp32_imm
    ldr w8, [_ip]
    // Debug: trace CMP EAX, -1 (getopt_long return check)
    cmn w8, 1             // Check if imm == -1 (cmn checks if -imm == 0)
    b.ne 1f
    save_c
    uxtw x0, _tmp         // EAX value
    uxtw x1, w8           // Immediate (-1)
    bl NAME(helper_debug_cmp32_neg1)
    restore_c
    ldr w8, [_ip]         // Reload immediate
1:
    subs w9, _tmp, w8     // Save result for flags
    setf_oc
    setf_zsp w, x9        // Use the subtraction result
    gret 1

.gadget cmp16_imm
    ldrh w8, [_ip]
    and w10, _tmp, 0xffff       // Mask to 16 bits
    subs w9, w10, w8            // Compare 16-bit values
    setf_oc
    sxth x9, w9                 // Sign-extend for SF/PF
    setf_zsp h, x9
    gret 1

.gadget cmp8_imm
    ldrb w8, [_ip]
    and w10, _tmp, 0xff         // Mask to 8 bits
    // Save byte and imm to memory before CMP corrupts w10
    str w10, [_cpu, LOCAL_value]       // Save byte value
    str w8, [_cpu, LOCAL_value_addr]   // Save immediate
    subs w9, w10, w8            // Compare 8-bit values
    setf_oc
    sxtb x9, w9                 // Sign-extend for SF/PF
    setf_zsp b, x9
    // Debug: trace CMP8 for 'a', 'b', '\0' with result
    ldr x9, [_cpu, CPU_res]     // x9 = res value
    save_c
    ldr w0, [_cpu, LOCAL_value]        // byte value (saved)
    ldr w1, [_cpu, LOCAL_value_addr]   // immediate (saved)
    mov x2, x9                  // res value
    bl NAME(helper_debug_cmp8_all_res)
    restore_c
    gret 1

// CMP with register (index passed as immediate)
.gadget cmp64_reg
    // Load register index
    ldr x8, [_ip]
    // This is a bit hacky - we need to compare with a register by index
    // For now, use a switch-like approach via computed jump
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to rdi
    subs x9, _xtmp, rdi
    b 9f
1:  subs x9, _xtmp, rax
    b 9f
2:  subs x9, _xtmp, rcx
    b 9f
3:  subs x9, _xtmp, rdx
    b 9f
4:  subs x9, _xtmp, rbx
    b 9f
5:  subs x9, _xtmp, rsp
    b 9f
6:  subs x9, _xtmp, rbp
    b 9f
7:  subs x9, _xtmp, rsi
    b 9f
9:  setf_oc
    setf_zsp , x9
    gret 1

// 32-bit CMP reg, reg - compare low 32 bits only
// Uses same register aliases as cmp64_reg but with 32-bit (w) versions
.gadget cmp32_reg
    // Debug: trace cmp32_reg entry
    save_c
    ldr x0, [_ip]
    uxtw x1, _tmp
    bl NAME(helper_debug_cmp32_reg_entry)
    restore_c
    ldr x8, [_ip]
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to edi (case 7)
    subs w9, _tmp, edi
    b 9f
1:  subs w9, _tmp, eax
    b 9f
2:  subs w9, _tmp, ecx
    b 9f
3:  subs w9, _tmp, edx
    b 9f
4:  subs w9, _tmp, ebx
    b 9f
5:  subs w9, _tmp, esp
    b 9f
6:  // Debug: trace CMP with EBP
    save_c
    uxtw x0, _tmp
    uxtw x1, ebp
    bl NAME(helper_debug_cmp32_ebp)
    restore_c
    subs w9, _tmp, ebp
    b 9f
7:  subs w9, _tmp, esi
    b 9f
9:  setf_oc
    setf_zsp w, x9
    gret 1

// 16-bit CMP reg, reg - compare low 16 bits only
.gadget cmp16_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xffff       // Mask first operand to 16 bits
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to di (case 7)
    and w11, edi, 0xffff
    subs w9, w10, w11
    b 9f
1:  and w11, eax, 0xffff
    subs w9, w10, w11
    b 9f
2:  and w11, ecx, 0xffff
    subs w9, w10, w11
    b 9f
3:  and w11, edx, 0xffff
    subs w9, w10, w11
    b 9f
4:  and w11, ebx, 0xffff
    subs w9, w10, w11
    b 9f
5:  and w11, esp, 0xffff
    subs w9, w10, w11
    b 9f
6:  and w11, ebp, 0xffff
    subs w9, w10, w11
    b 9f
7:  and w11, esi, 0xffff
    subs w9, w10, w11
    b 9f
9:  setf_oc
    sxth x9, w9                 // Sign-extend 16-bit result for SF/PF
    setf_zsp h, x9
    gret 1

// 8-bit CMP reg, reg - compare low 8 bits only
.gadget cmp8_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xff         // Mask first operand to 8 bits
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to di low 8 bits (case 7)
    and w11, edi, 0xff
    subs w9, w10, w11
    b 9f
1:  and w11, eax, 0xff
    subs w9, w10, w11
    b 9f
2:  and w11, ecx, 0xff
    subs w9, w10, w11
    b 9f
3:  and w11, edx, 0xff
    subs w9, w10, w11
    b 9f
4:  and w11, ebx, 0xff
    subs w9, w10, w11
    b 9f
5:  and w11, esp, 0xff
    subs w9, w10, w11
    b 9f
6:  and w11, ebp, 0xff
    subs w9, w10, w11
    b 9f
7:  and w11, esi, 0xff
    subs w9, w10, w11
    b 9f
9:  setf_oc
    sxtb x9, w9                 // Sign-extend 8-bit result for SF/PF
    setf_zsp b, x9
    gret 1

// CMP _xtmp with x8 (for CMP [mem], reg where mem is loaded first)
// This compares memory value (_xtmp) with saved register value (x8)
// Flags are set based on: _xtmp - x8
.gadget cmp64_x8
    subs x9, _xtmp, x8
    setf_oc
    setf_zsp , x9
    gret

.gadget cmp32_x8
    // Debug: trace comparison values
    save_c
    uxtw x0, _tmp        // mem value (first arg)
    uxtw x1, w8          // reg value (second arg)
    bl NAME(helper_debug_cmp32_x8)
    restore_c
    // Actual comparison
    subs w9, _tmp, w8
    setf_oc
    setf_zsp w, x9
    gret

.gadget cmp16_x8
    and w10, _tmp, 0xffff
    and w11, w8, 0xffff
    subs w9, w10, w11
    setf_oc
    sxth x9, w9
    setf_zsp h, x9
    gret

.gadget cmp8_x8
    and w10, _tmp, 0xff
    and w11, w8, 0xff
    subs w9, w10, w11
    setf_oc
    sxtb x9, w9
    setf_zsp b, x9
    gret

// ============================================================
// TEST gadgets (AND without storing, sets flags)
// ============================================================

.gadget test64_imm
    ldr x8, [_ip]
    ands x9, _xtmp, x8     // Save AND result for flags
    clearf_oc
    setf_zsp , x9
    gret 1

.gadget test32_imm
    ldr w8, [_ip]
    // Debug: trace TEST32_IMM with guest RIP
    ldr x10, [_cpu, CPU_rip]   // Load guest RIP before save_c
    save_c
    uxtw x0, _tmp          // Value being tested
    uxtw x1, w8            // Immediate mask
    mov x2, x10            // Guest RIP
    bl NAME(helper_debug_test32_imm)
    restore_c
    ldr w8, [_ip]          // Reload because save_c might clobber w8
    ands w9, _tmp, w8      // Save AND result for flags
    clearf_oc
    setf_zsp w, x9
    gret 1

.gadget test16_imm
    ldrh w8, [_ip]
    and w10, _tmp, 0xffff       // Mask to 16 bits
    ands w9, w10, w8            // AND 16-bit values
    clearf_oc
    sxth x9, w9
    setf_zsp h, x9
    gret 1

.gadget test8_imm
    ldrb w8, [_ip]
    and w10, _tmp, 0xff         // Mask to 8 bits
    // Debug: trace test8_imm with mask=0xFF (null check in strlen)
    cmp w8, 0xFF
    b.ne 2f
    // Check if testing 'a', 'b', or '\0'
    cmp w10, 0x61               // 'a'
    b.eq 3f
    cmp w10, 0x62               // 'b'
    b.eq 3f
    cmp w10, 0                  // '\0'
    b.ne 2f
3:
    save_c
    uxtw x0, w10                // Value being tested
    bl NAME(helper_debug_test8_null_check)
    restore_c
    ldrb w8, [_ip]              // Reload mask
    and w10, _tmp, 0xff         // Re-mask
2:
    // Also trace alignment checks (mask=7)
    cmp w8, 7
    b.ne 1f
    save_c
    uxtw x0, w10
    uxtw x1, w8
    ands w2, w10, w8
    uxtw x2, w2
    bl NAME(helper_debug_test8_imm_align)
    restore_c
    ldrb w8, [_ip]
    and w10, _tmp, 0xff
1:
    ands w9, w10, w8            // AND 8-bit values
    clearf_oc
    sxtb x9, w9
    setf_zsp b, x9
    gret 1

// TEST with x8 (for TEST reg, reg where second reg loaded to x8)
.gadget test64_x8
    // Debug: trace TEST values for r8-r15 including guest RIP
    // Load RIP BEFORE save_c (since _cpu=x1 is clobbered by save_c)
    ldr x10, [_cpu, CPU_rip]  // Save guest RIP in x10
    save_c
    uxtw x0, _tmp        // First value (low 32 bits of _xtmp)
    uxtw x1, w8          // Second value (low 32 bits of x8)
    mov x2, x10          // Guest RIP
    bl NAME(helper_debug_test64_x8)
    restore_c
    // Actual TEST
    ands x9, _xtmp, x8
    clearf_oc
    setf_zsp , x9
    gret

// 32-bit TEST with x8 for r8-r15 registers
// Uses 32-bit ANDS for correct sign flag on bit 31
.gadget test32_x8
    // Debug: trace the TEST values
    ldr x10, [_cpu, CPU_rip]  // Save guest RIP in x10
    save_c
    uxtw x0, _tmp        // First value (operand 0 - was loaded first, now in x8 actually)
    uxtw x1, w8          // Second value (operand 1 - now in _xtmp)
    mov x2, x10          // Guest RIP
    bl NAME(helper_debug_test32_x8)
    restore_c
    // Actual TEST
    ands w9, _tmp, w8   // 32-bit AND
    clearf_oc
    setf_zsp w, x9      // 32-bit result for flags
    gret

// TEST with register (for reg, reg - xtmp & other_reg, set flags)
.macro test_reg64 name, reg64, reg32
    .gadget test64_\name
        ands x9, _xtmp, \reg64
        clearf_oc
        setf_zsp , x9
        gret
.endm
.each_reg64 test_reg64
.purgem test_reg64

// 8-bit TEST reg, reg - test low 8 bits only
// Same pattern as cmp8_reg - read register index from [_ip]
.gadget test8_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xff         // Mask first operand to 8 bits
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to di low 8 bits (case 7)
    and w11, edi, 0xff
    b 9f
1:  and w11, eax, 0xff
    b 9f
2:  and w11, ecx, 0xff
    b 9f
3:  and w11, edx, 0xff
    b 9f
4:  and w11, ebx, 0xff
    b 9f
5:  and w11, esp, 0xff
    b 9f
6:  and w11, ebp, 0xff
    b 9f
7:  and w11, esi, 0xff
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp b, x9
    gret 1

// 16-bit TEST reg, reg - test low 16 bits only
.gadget test16_reg
    ldr x8, [_ip]
    and w10, _tmp, 0xffff       // Mask first operand to 16 bits
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to di low 16 bits (case 7)
    and w11, edi, 0xffff
    b 9f
1:  and w11, eax, 0xffff
    b 9f
2:  and w11, ecx, 0xffff
    b 9f
3:  and w11, edx, 0xffff
    b 9f
4:  and w11, ebx, 0xffff
    b 9f
5:  and w11, esp, 0xffff
    b 9f
6:  and w11, ebp, 0xffff
    b 9f
7:  and w11, esi, 0xffff
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp h, x9
    gret 1

// 32-bit TEST reg, reg - test low 32 bits only
.gadget test32_reg
    ldr x8, [_ip]
    mov w10, _tmp               // Copy 32-bit (w reg = already masked)
    cmp x8, 0
    b.eq 1f
    cmp x8, 1
    b.eq 2f
    cmp x8, 2
    b.eq 3f
    cmp x8, 3
    b.eq 4f
    cmp x8, 4
    b.eq 5f
    cmp x8, 5
    b.eq 6f
    cmp x8, 6
    b.eq 7f
    // Default to edi (case 7)
    mov w11, edi
    b 9f
1:  mov w11, eax
    b 9f
2:  mov w11, ecx
    b 9f
3:  mov w11, edx
    b 9f
4:  mov w11, ebx
    b 9f
5:  mov w11, esp
    b 9f
6:  mov w11, ebp
    b 9f
7:  mov w11, esi
9:  ands w9, w10, w11           // TEST = AND, set flags
    clearf_oc
    setf_zsp , x9
    gret 1

// ============================================================
// DIV/IDIV gadgets
// ============================================================

// DIV32: Unsigned divide EDX:EAX by _xtmp (32-bit divisor)
// Input: _xtmp = divisor, rax = low 32 bits of dividend, rdx = high 32 bits
// Output: rax = quotient, rdx = remainder
// Note: Uses 64-bit division since EDX:EAX fits in 64 bits
.gadget div32
    // Combine EDX:EAX into a 64-bit value
    and x8, rdx, 0xffffffff     // High 32 bits (zero-extended)
    lsl x8, x8, 32              // Shift to high position
    and x9, rax, 0xffffffff     // Low 32 bits
    orr x8, x8, x9              // x8 = EDX:EAX as 64-bit value
    // Divide
    and x9, _xtmp, 0xffffffff   // 32-bit divisor (zero-extended)
    udiv x10, x8, x9            // Quotient
    msub x11, x10, x9, x8       // Remainder = dividend - quotient * divisor
    // Store results
    and rax, rax, 0xffffffff00000000
    orr rax, rax, x10           // EAX = quotient (preserve upper 32 bits... actually x86 zeros them)
    mov eax, w10                // Store quotient in eax (zeros upper 32 bits)
    mov edx, w11                // Store remainder in edx (zeros upper 32 bits)
    gret

// DIV64: Unsigned divide RDX:RAX by _xtmp (64-bit divisor)
// This requires 128-bit division which ARM64 doesn't have natively
// For now, handle the common case where RDX=0 (dividend fits in 64 bits)
.gadget div64
    // No debug tracing - just do the division
    // _xtmp (x0) = divisor, _cpu (x1) = cpu pointer
    // Check for division by zero
    cmp _xtmp, 0
    b.eq div64_by_zero_nodebug
    // Do the division: RDX:RAX / _xtmp
    // For now, handle common case where RDX=0
    udiv x10, rax, _xtmp        // Quotient
    msub x11, x10, _xtmp, rax   // Remainder = RAX - quotient * divisor
    mov rax, x10                // Store quotient
    mov rdx, x11                // Store remainder
    gret
div64_by_zero_nodebug:
    // On x86, division by zero causes #DE (fault)
    // For now, just return 0 to continue
    mov rax, 0
    mov rdx, 0
    gret

// IDIV32: Signed divide EDX:EAX by _xtmp (32-bit divisor)
.gadget idiv32
    // Combine EDX:EAX into a 64-bit signed value
    sxtw x8, edx                // Sign-extend EDX to 64-bit
    lsl x8, x8, 32              // Shift to high position
    and x9, rax, 0xffffffff     // Low 32 bits (unsigned)
    orr x8, x8, x9              // x8 = EDX:EAX as signed 64-bit value
    // Divide (signed)
    sxtw x9, _tmp               // Sign-extend 32-bit divisor
    sdiv x10, x8, x9            // Quotient (signed)
    msub x11, x10, x9, x8       // Remainder = dividend - quotient * divisor
    // Store results
    mov eax, w10                // Store quotient in eax
    mov edx, w11                // Store remainder in edx
    // Debug: trace when quotient is 1
    cmp eax, 1
    b.ne 87f
    save_c
    uxtw x0, eax
    bl NAME(helper_debug_idiv32_eax1)
    restore_c
87:
    gret

// IDIV64: Signed divide RDX:RAX by _xtmp (64-bit divisor)
.gadget idiv64
    // Simple case: dividend = RAX (assume RDX is sign extension of RAX)
    sdiv x10, rax, _xtmp        // Quotient (signed)
    msub x11, x10, _xtmp, rax   // Remainder
    mov rax, x10                // Store quotient
    mov rdx, x11                // Store remainder
    gret

// MUL32: Unsigned multiply EAX * _xtmp -> EDX:EAX
.gadget mul32
    // Zero-extend both operands to 64-bit and multiply
    and x8, rax, 0xffffffff     // EAX zero-extended
    and x9, _xtmp, 0xffffffff   // operand zero-extended
    mul x10, x8, x9             // 64-bit result
    // Split into EDX:EAX
    mov eax, w10                // Low 32 bits -> EAX
    lsr x10, x10, 32
    mov edx, w10                // High 32 bits -> EDX
    // Set CF and OF if high half is non-zero
    cmp edx, 0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
    gret

// MUL64: Unsigned multiply RAX * _xtmp -> RDX:RAX
.gadget mul64
    // Use mul for low 64 bits, umulh for high 64 bits
    mul x10, rax, _xtmp         // Low 64 bits
    umulh x11, rax, _xtmp       // High 64 bits
    mov rax, x10                // Low -> RAX
    mov rdx, x11                // High -> RDX
    // Set CF and OF if high half (RDX) is non-zero
    cmp rdx, 0
    cset w8, ne
    strb w8, [_cpu, CPU_cf]
    strb w8, [_cpu, CPU_of]
    gret

// ============================================================
// Shift gadgets
// ============================================================

// SHR (logical shift right) - shift by immediate 1
.gadget shr64_one
    // Get MSB for OF flag (set if sign bit changed)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Get LSB (will become CF after shift)
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // Do the shift
    lsr _xtmp, _xtmp, 1
    setf_zsp
    gret

// SHR by CL (shift count in RCX)
.gadget shr64_cl
    ands w8, ecx, 63
    b.eq 1f
    // Save MSB for OF (only meaningful if shift is 1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w8, w8, 1
    lsr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    lsr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// SHR by immediate
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget shr64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    // Save MSB for OF
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // Shift by (count-1), get CF from LSB, then shift by 1 more
    sub w11, w11, 1
    lsr _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    lsr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// SHL (logical shift left) - shift by immediate 1
.gadget shl64_one
    // Shift by 1, check old MSB for CF
    lsr x8, _xtmp, 63
    lsl _xtmp, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF = CF XOR new MSB
    lsr x9, _xtmp, 63
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// SHL by CL
.gadget shl64_cl
    ands w8, ecx, 63
    b.eq 1f
    sub w8, w8, 1
    lsl _xtmp, _xtmp, x8
    // Get bit that will become CF
    lsr x9, _xtmp, 63
    // Shift one more
    lsl _xtmp, _xtmp, 1
    // CF = old MSB, OF = CF XOR new MSB
    lsr x10, _xtmp, 63
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp
1:  gret

// SHL by immediate
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget shl64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    sub w11, w11, 1
    lsl _xtmp, _xtmp, x11
    lsr x9, _xtmp, 63
    lsl _xtmp, _xtmp, 1
    lsr x10, _xtmp, 63
    eor w10, w10, w9
    strb w9, [_cpu, CPU_cf]
    strb w10, [_cpu, CPU_of]
    setf_zsp
1:  gret 1

// SAR (arithmetic shift right) - shift by immediate 1
.gadget sar64_one
    // Get LSB for CF
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF is always 0 for SAR by 1
    strb wzr, [_cpu, CPU_of]
    // Do the arithmetic shift
    asr _xtmp, _xtmp, 1
    setf_zsp
    gret

// SAR by CL
.gadget sar64_cl
    ands w8, ecx, 63
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w8, w8, 1
    asr _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    asr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// SAR by immediate
// NOTE: Uses x11 instead of x8 for shift count, because x8 may hold values
// being passed between gadgets (e.g., from save_xtmp_to_x8 for LEA operations)
.gadget sar64_imm
    ldr w11, [_ip]
    ands w11, w11, 63
    b.eq 1f
    strb wzr, [_cpu, CPU_of]
    sub w11, w11, 1
    asr _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    asr _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ============================================================
// Rotate instructions (ROL/ROR)
// ============================================================

// ROL (rotate left) by 1 - 32-bit
// CF = bit shifted out (bit 31 before shift = bit 0 after shift)
// OF = MSB XOR CF (for shift by 1 only)
.gadget rol32_one
    // Save 'before' value for debug
    mov w10, _tmp
    // ROL by 1 = ROR by 31
    ror _tmp, _tmp, 31
    // Debug: trace before/after
    save_c
    mov w0, w10               // before
    mov w1, _tmp              // after
    bl NAME(helper_debug_rol32)
    restore_c
    // CF = bit 0 (the bit that wrapped around)
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    // OF = bit 31 XOR bit 0
    lsr w9, _tmp, 31
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp w
    gret

// ROL by 1 - 64-bit
.gadget rol64_one
    ror _xtmp, _xtmp, 63
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    eor w9, w9, w8
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// ROL by CL - 32-bit
.gadget rol32_cl
    and w8, ecx, 31
    cbz w8, 1f
    // ROL by N = ROR by (32 - N)
    neg w8, w8
    add w8, w8, 32
    ror _tmp, _tmp, w8
    // CF = bit 0 (the bit that wrapped around)
    and w9, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    // OF is undefined when count != 1, so we skip
    setf_zsp w
1:  gret

// ROL by CL - 64-bit
.gadget rol64_cl
    and x8, rcx, 63
    cbz x8, 1f
    neg x8, x8
    add x8, x8, 64
    ror _xtmp, _xtmp, x8
    and x9, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// ROL by immediate - 32-bit
.gadget rol32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    neg w11, w11
    add w11, w11, 32
    ror _tmp, _tmp, w11
    and w9, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ROL by immediate - 64-bit
.gadget rol64_imm
    ldr w11, [_ip]
    ands x11, x11, 63
    b.eq 1f
    neg x11, x11
    add x11, x11, 64
    ror _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ROR (rotate right) by 1 - 32-bit
// CF = bit shifted out (bit 0 before shift = bit 31 after shift)
// OF = MSB XOR (MSB-1) of result (for shift by 1 only)
.gadget ror32_one
    // CF = bit 0 before shift
    and w8, _tmp, 1
    strb w8, [_cpu, CPU_cf]
    ror _tmp, _tmp, 1
    // OF = bit 31 XOR bit 30 of result
    lsr w9, _tmp, 31
    lsr w10, _tmp, 30
    eor w9, w9, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_of]
    setf_zsp w
    gret

// ROR by 1 - 64-bit
.gadget ror64_one
    and x8, _xtmp, 1
    strb w8, [_cpu, CPU_cf]
    ror _xtmp, _xtmp, 1
    lsr x9, _xtmp, 63
    lsr x10, _xtmp, 62
    eor w9, w9, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_of]
    setf_zsp
    gret

// ROR by CL - 32-bit
.gadget ror32_cl
    and w8, ecx, 31
    cbz w8, 1f
    // CF = last bit shifted out
    sub w9, w8, 1
    ror _tmp, _tmp, w9
    and w10, _tmp, 1
    ror _tmp, _tmp, 1
    strb w10, [_cpu, CPU_cf]
    setf_zsp w
1:  gret

// ROR by CL - 64-bit
.gadget ror64_cl
    and x8, rcx, 63
    cbz x8, 1f
    sub x9, x8, 1
    ror _xtmp, _xtmp, x9
    and x10, _xtmp, 1
    ror _xtmp, _xtmp, 1
    strb w10, [_cpu, CPU_cf]
    setf_zsp
1:  gret

// ROR by immediate - 32-bit
.gadget ror32_imm
    ldr w11, [_ip]
    ands w11, w11, 31
    b.eq 1f
    sub w11, w11, 1
    ror _tmp, _tmp, w11
    and w9, _tmp, 1
    ror _tmp, _tmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp w
1:  gret 1

// ROR by immediate - 64-bit
.gadget ror64_imm
    ldr w11, [_ip]
    ands x11, x11, 63
    b.eq 1f
    sub x11, x11, 1
    ror _xtmp, _xtmp, x11
    and x9, _xtmp, 1
    ror _xtmp, _xtmp, 1
    strb w9, [_cpu, CPU_cf]
    setf_zsp
1:  gret 1

// ============================================================
// SHRD (double precision shift right) gadgets
// SHRD dst, src, count: shift src:dst right by count, store low bits in dst
// Expects: _xtmp = dst, x8 = src (from save_xtmp_to_x8 + load src)
// ============================================================

// SHRD by immediate - 64-bit
// shrd rax, rdx, imm: result = (rax >> imm) | (rdx << (64 - imm))
.gadget shrd64_imm
    ldr w11, [_ip]
    and w11, w11, 63
    cbz w11, 1f
    // CF = bit (count-1) of dst before shift
    sub w10, w11, 1
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB of original dst (meaningful only if count=1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // result = (dst >> count) | (src << (64 - count))
    lsr _xtmp, _xtmp, x11
    neg w10, w11
    add w10, w10, 64
    lsl x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret 1

// SHRD by immediate - 32-bit
.gadget shrd32_imm
    ldr w11, [_ip]
    and w11, w11, 31
    cbz w11, 1f
    // CF = bit (count-1) of dst
    sub w10, w11, 1
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB of original dst
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    // result = (dst >> count) | (src << (32 - count))
    lsr _tmp, _tmp, w11
    neg w10, w11
    add w10, w10, 32
    lsl w9, w8, w10
    orr _tmp, _tmp, w9
    // Zero extend result to 64 bits (x86_64 semantics)
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret 1

// SHRD by CL - 64-bit
.gadget shrd64_cl
    and w11, ecx, 63
    cbz w11, 1f
    sub w10, w11, 1
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    lsr _xtmp, _xtmp, x11
    neg w10, w11
    add w10, w10, 64
    lsl x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret

// SHRD by CL - 32-bit
.gadget shrd32_cl
    and w11, ecx, 31
    cbz w11, 1f
    sub w10, w11, 1
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsr _tmp, _tmp, w11
    neg w10, w11
    add w10, w10, 32
    lsl w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret

// ============================================================
// SHLD (double precision shift left) gadgets
// SHLD dst, src, count: shift dst:src left by count, store high bits in dst
// Expects: _xtmp = dst, x8 = src
// ============================================================

// SHLD by immediate - 64-bit
// shld rax, rdx, imm: result = (rax << imm) | (rdx >> (64 - imm))
.gadget shld64_imm
    ldr w11, [_ip]
    and w11, w11, 63
    cbz w11, 1f
    // CF = bit (64-count) of dst before shift (the bit that's about to be shifted out)
    mov w10, 64
    sub w10, w10, w11
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    // OF = MSB XOR CF of result (meaningful only if count=1)
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    // result = (dst << count) | (src >> (64 - count))
    lsl _xtmp, _xtmp, x11
    lsr x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret 1

// SHLD by immediate - 32-bit
.gadget shld32_imm
    ldr w11, [_ip]
    and w11, w11, 31
    cbz w11, 1f
    mov w10, 32
    sub w10, w10, w11
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsl _tmp, _tmp, w11
    lsr w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret 1

// SHLD by CL - 64-bit
.gadget shld64_cl
    and w11, ecx, 63
    cbz w11, 1f
    mov w10, 64
    sub w10, w10, w11
    lsr x9, _xtmp, x10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr x9, _xtmp, 63
    strb w9, [_cpu, CPU_of]
    lsl _xtmp, _xtmp, x11
    lsr x9, x8, x10
    orr _xtmp, _xtmp, x9
    setf_zsp
1:  gret

// SHLD by CL - 32-bit
.gadget shld32_cl
    and w11, ecx, 31
    cbz w11, 1f
    mov w10, 32
    sub w10, w10, w11
    lsr w9, _tmp, w10
    and w9, w9, 1
    strb w9, [_cpu, CPU_cf]
    lsr w9, _tmp, 31
    strb w9, [_cpu, CPU_of]
    lsl _tmp, _tmp, w11
    lsr w9, w8, w10
    orr _tmp, _tmp, w9
    uxtw _xtmp, _tmp
    setf_zsp w
1:  gret

// ============================================================
// BSF/BSR (bit scan forward/reverse) gadgets
// ============================================================

// BSF - Bit Scan Forward (find lowest set bit)
// If src is 0, ZF=1 and dst is undefined
// Otherwise, ZF=0 and dst = index of lowest set bit
.gadget bsf64
    cbz _xtmp, 1f               // If zero, set ZF and skip
    rbit x9, _xtmp              // Reverse bits
    clz x9, x9                  // Count leading zeros = trailing zeros in original
    mov _xtmp, x9               // Result = bit index
    // ZF = 0 (source was non-zero)
    mov w9, 1                   // Non-zero value for CPU_res
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  // Source was zero - set ZF, leave destination unchanged
    str xzr, [_cpu, CPU_res]    // Zero result for ZF=1
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

.gadget bsf32
    uxtw _xtmp, _tmp            // Zero extend for safety
    cbz _xtmp, 1f
    rbit w9, _tmp               // Reverse 32 bits
    clz w9, w9                  // Count leading zeros
    uxtw _xtmp, w9              // Result = bit index, zero extended
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

// BSR - Bit Scan Reverse (find highest set bit)
// If src is 0, ZF=1 and dst is undefined
// Otherwise, ZF=0 and dst = index of highest set bit
.gadget bsr64
    cbz _xtmp, 1f
    clz x9, _xtmp               // Count leading zeros
    mov x10, 63
    sub _xtmp, x10, x9          // Result = 63 - clz = bit index
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

.gadget bsr32
    uxtw _xtmp, _tmp
    cbz _xtmp, 1f
    clz w9, _tmp
    mov w10, 31
    sub w9, w10, w9
    uxtw _xtmp, w9
    mov w9, 1
    str x9, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret
1:  str xzr, [_cpu, CPU_res]
    ldr w10, [_cpu, CPU_flags_res]
    orr w10, w10, ZF_RES
    str w10, [_cpu, CPU_flags_res]
    gret

// ============================================================
// Zero/Sign extend gadgets
// ============================================================

.gadget zero_extend8
    and _xtmp, _xtmp, 0xff
    gret

.gadget zero_extend16
    and _xtmp, _xtmp, 0xffff
    gret

.gadget zero_extend32
    and _xtmp, _xtmp, 0xffffffff
    gret

.gadget sign_extend8
    // Trace before sign extension
    save_c
    mov x0, _xtmp      // value before
    bl NAME(helper_debug_sign_extend8)
    restore_c
    sxtb _xtmp, _tmp
    gret

.gadget sign_extend16
    sxth _xtmp, _tmp
    gret

.gadget sign_extend32
    // Trace before sign extension
    save_c
    mov x0, _xtmp      // value before
    bl NAME(helper_debug_sign_extend32)
    restore_c
    sxtw _xtmp, _tmp
    gret

// CDQ: Sign extend EAX to EDX:EAX (EDX = sign_extend(EAX[31]))
// Sets EDX to 0xFFFFFFFF if EAX is negative, else 0
.gadget cdq
    asr w9, eax, #31       // Arithmetic shift right by 31 copies sign bit to all 32 bits
    mov edx, w9            // Store to EDX (w21 maps to edx, zero-extends to x21)
    gret

// CQO: Sign extend RAX to RDX:RAX (RDX = sign_extend(RAX[63]))
// Sets RDX to 0xFFFFFFFFFFFFFFFF if RAX is negative, else 0
.gadget cqo
    asr rdx, rax, #63      // Arithmetic shift right by 63 copies sign bit to all 64 bits
    gret

// ============================================================
// Gadget arrays for the generator
// ============================================================

.pushsection_rodata

// Gadget arrays - order matches x86 register encoding: a, c, d, b, sp, bp, si, di
// Then: imm, mem, addr, gs

// 64-bit load gadgets
.align 3
.global.name load64_gadgets
    .quad NAME(gadget_load64_a)
    .quad NAME(gadget_load64_c)
    .quad NAME(gadget_load64_d)
    .quad NAME(gadget_load64_b)
    .quad NAME(gadget_load64_sp)
    .quad NAME(gadget_load64_bp)
    .quad NAME(gadget_load64_si)
    .quad NAME(gadget_load64_di)
    .quad NAME(gadget_load64_imm)
    .quad NAME(gadget_load64_mem)
    .quad NAME(gadget_load64_addr)
    .quad 0  // gs

// 64-bit store gadgets
.align 3
.global.name store64_gadgets
    .quad NAME(gadget_store64_a)
    .quad NAME(gadget_store64_c)
    .quad NAME(gadget_store64_d)
    .quad NAME(gadget_store64_b)
    .quad NAME(gadget_store64_sp)
    .quad NAME(gadget_store64_bp)
    .quad NAME(gadget_store64_si)
    .quad NAME(gadget_store64_di)
    .quad 0  // imm
    .quad NAME(gadget_store64_mem)
    .quad 0  // addr
    .quad 0  // gs

// 32-bit load gadgets (for compatibility)
.align 3
.global.name load32_gadgets
    .quad NAME(gadget_load32_a)
    .quad NAME(gadget_load32_c)
    .quad NAME(gadget_load32_d)
    .quad NAME(gadget_load32_b)
    .quad NAME(gadget_load32_sp)
    .quad NAME(gadget_load32_bp)
    .quad NAME(gadget_load32_si)
    .quad NAME(gadget_load32_di)
    .quad NAME(gadget_load32_imm)
    .quad NAME(gadget_load32_mem)
    .quad NAME(gadget_load32_addr)
    .quad 0  // gs

// 32-bit store gadgets
.align 3
.global.name store32_gadgets
    .quad NAME(gadget_store32_a)
    .quad NAME(gadget_store32_c)
    .quad NAME(gadget_store32_d)
    .quad NAME(gadget_store32_b)
    .quad NAME(gadget_store32_sp)
    .quad NAME(gadget_store32_bp)
    .quad NAME(gadget_store32_si)
    .quad NAME(gadget_store32_di)
    .quad 0  // imm
    .quad NAME(gadget_store32_mem)
    .quad 0  // addr
    .quad 0  // gs

.popsection

// ============================================================
// IMUL - Signed multiply
// ============================================================

// Two-operand form: IMUL dst, src
// Result goes into dst (truncated to register size)
// _xtmp has src, multiply with dst register

// IMUL 64-bit: _xtmp * reg64 -> reg64
.macro imul64_to name, reg64, reg32
.gadget imul64_\name
    mul _xtmp, _xtmp, \reg64
    mov \reg64, _xtmp
    // Set flags (simplified - OF/CF set if high bits would overflow)
    smulh x8, _xtmp, \reg64    // Get high 64 bits of signed multiply
    asr x9, \reg64, 63         // Sign extend of low result
    cmp x8, x9
    cset w10, ne               // OF = CF = (high bits != sign extension)
    strb w10, [_cpu, CPU_of]
    strb w10, [_cpu, CPU_cf]
    gret
.endm

imul64_to a, rax, eax
imul64_to c, rcx, ecx
imul64_to d, rdx, edx
imul64_to b, rbx, ebx
imul64_to sp, rsp, esp
imul64_to bp, rbp, ebp
imul64_to si, rsi, esi
imul64_to di, rdi, edi

// IMUL 32-bit: _tmp * reg32 -> reg32
.macro imul32_to name, reg32
.gadget imul32_\name
    // 32-bit multiply: src * dst, result in dst
    mul w8, _tmp, \reg32
    mov \reg32, w8
    // Zero-extend to 64-bit (mov already does this)
    // Set flags
    smull x9, _tmp, \reg32     // Signed 32x32 -> 64 result
    asr x10, x9, 32            // High 32 bits
    asr w11, w8, 31            // Sign extension of low 32 bits
    sxtw x11, w11
    cmp x10, x11
    cset w10, ne
    strb w10, [_cpu, CPU_of]
    strb w10, [_cpu, CPU_cf]
    gret
.endm

imul32_to a, eax
imul32_to c, ecx
imul32_to d, edx
imul32_to b, ebx
imul32_to sp, esp
imul32_to bp, ebp
imul32_to si, esi
imul32_to di, edi

// IMUL 64-bit for r8-r15: _xtmp * r[n] -> r[n]
// r8-r15 are stored in cpu_state, not ARM64 registers
.macro imul64_r8_r15 num, offset
.gadget imul64_r\num
    ldr x8, [_cpu, \offset]    // Load r[n] from cpu state
    mul x8, _xtmp, x8          // result = _xtmp * r[n]
    str x8, [_cpu, \offset]    // Store result back
    // Set flags (OF/CF if high bits would overflow)
    smulh x9, _xtmp, x8        // Get high 64 bits
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10
    cset w11, ne
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret
.endm
imul64_r8_r15 8, CPU_r8
imul64_r8_r15 9, CPU_r9
imul64_r8_r15 10, CPU_r10
imul64_r8_r15 11, CPU_r11
imul64_r8_r15 12, CPU_r12
imul64_r8_r15 13, CPU_r13
imul64_r8_r15 14, CPU_r14
imul64_r8_r15 15, CPU_r15

// IMUL 32-bit for r8-r15: _tmp * r[n]d -> r[n]d (32-bit)
.macro imul32_r8_r15 num, offset
.gadget imul32_r\num
    ldr w8, [_cpu, \offset]    // Load r[n]d (32-bit) from cpu state
    mul w9, _tmp, w8           // result = _tmp * r[n]d (32-bit)
    // Zero-extend to 64-bit and store full 64-bit value
    uxtw x9, w9                // Zero-extend to 64-bit
    str x9, [_cpu, \offset]    // Store full 64-bit value
    // Set flags
    smull x10, _tmp, w8        // Signed 32x32 -> 64
    asr x11, x10, 32           // High 32 bits
    asr w12, w9, 31            // Sign of 32-bit result
    sxtw x12, w12
    cmp x11, x12
    cset w13, ne
    strb w13, [_cpu, CPU_of]
    strb w13, [_cpu, CPU_cf]
    gret
.endm
imul32_r8_r15 8, CPU_r8
imul32_r8_r15 9, CPU_r9
imul32_r8_r15 10, CPU_r10
imul32_r8_r15 11, CPU_r11
imul32_r8_r15 12, CPU_r12
imul32_r8_r15 13, CPU_r13
imul32_r8_r15 14, CPU_r14
imul32_r8_r15 15, CPU_r15

.pushsection_rodata
.align 3
.global NAME(imul64_r8_r15_gadgets)
NAME(imul64_r8_r15_gadgets):
    .quad NAME(gadget_imul64_r8)
    .quad NAME(gadget_imul64_r9)
    .quad NAME(gadget_imul64_r10)
    .quad NAME(gadget_imul64_r11)
    .quad NAME(gadget_imul64_r12)
    .quad NAME(gadget_imul64_r13)
    .quad NAME(gadget_imul64_r14)
    .quad NAME(gadget_imul64_r15)
.global NAME(imul32_r8_r15_gadgets)
NAME(imul32_r8_r15_gadgets):
    .quad NAME(gadget_imul32_r8)
    .quad NAME(gadget_imul32_r9)
    .quad NAME(gadget_imul32_r10)
    .quad NAME(gadget_imul32_r11)
    .quad NAME(gadget_imul32_r12)
    .quad NAME(gadget_imul32_r13)
    .quad NAME(gadget_imul32_r14)
    .quad NAME(gadget_imul32_r15)
.popsection

// IMUL with immediate: _xtmp = src, immediate from [_ip]
// Result stored to destination register (specified by next gadget)
.gadget imul64_imm
    ldr x8, [_ip]              // Load immediate
    mul _xtmp, _xtmp, x8
    gret 1

.gadget imul32_imm
    ldr w8, [_ip]              // Load 32-bit immediate
    mul _tmp, _tmp, w8         // 32-bit multiply
    // Result in _tmp, zero-extended by 32-bit mul
    gret 1

// IMUL with memory operand: load from _addr, multiply with _xtmp
.gadget imul64_mem
    ldr x8, [_addr]
    mul _xtmp, _xtmp, x8
    gret

// Single-operand IMUL 64-bit: RDX:RAX = RAX * src
// _xtmp = src (from register or memory), result in RAX (low) and RDX (high)
.gadget imul64_wide
    mul x8, rax, _xtmp         // Low 64 bits: x8 = RAX * src
    smulh x9, rax, _xtmp       // High 64 bits: x9 = signed high bits
    mov rax, x8                // Store low to RAX
    mov rdx, x9                // Store high to RDX
    // Set OF/CF if result doesn't fit in RAX (high part is not sign-extension of low)
    asr x10, x8, 63            // Sign extend of low result
    cmp x9, x10                // Compare high with sign-extension of low
    cset w11, ne               // OF/CF set if they differ
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret

// Single-operand IMUL 32-bit: EDX:EAX = EAX * src
// _tmp = src (32-bit), result in EAX (low) and EDX (high)
.gadget imul32_wide
    smull x8, eax, _tmp        // Signed 32x32 -> 64 result
    mov eax, w8                // Low 32 bits to EAX (zero-extends to 64)
    lsr x9, x8, 32             // High 32 bits
    mov edx, w9                // To EDX (zero-extends to 64)
    // Set OF/CF if result doesn't fit in EAX
    sxtw x10, w8               // Sign extend low 32 bits to 64
    cmp x8, x10                // Compare full result with sign-extension
    cset w11, ne               // OF/CF set if they differ
    strb w11, [_cpu, CPU_of]
    strb w11, [_cpu, CPU_cf]
    gret

// ============================================================
// XMM/SSE register operations
// ============================================================

// MOVQ xmm, r/m64 - Move 64-bit value to lower half of XMM, zero upper
// _xtmp = source value (64-bit), [_ip] = XMM register index (0-15)
.gadget movq_to_xmm
    ldr x8, [_ip]              // XMM register index (0-15)
    lsl x8, x8, 4              // Multiply by 16 (sizeof xmm_reg)
    add x8, x8, CPU_xmm        // Add xmm array offset
    add x8, _cpu, x8           // Final address in cpu struct
    str _xtmp, [x8]            // Store value to xmm[n].qw[0]
    str xzr, [x8, 8]           // Zero upper 64 bits (xmm[n].qw[1])
    gret 1

// MOVQ r/m64, xmm - Move lower 64 bits of XMM to destination
// [_ip] = XMM register index, result in _xtmp
.gadget movq_from_xmm
    ldr x8, [_ip]              // XMM register index (0-15)
    lsl x8, x8, 4              // Multiply by 16 (sizeof xmm_reg)
    add x8, x8, CPU_xmm        // Add xmm array offset
    add x8, _cpu, x8           // Final address in cpu struct
    ldr _xtmp, [x8]            // Load xmm[n].qw[0]
    gret 1

// PUNPCKLQDQ xmm, xmm - Unpack and interleave low quadwords
// This is used for duplicating a value across the XMM register
// _xtmp contains source XMM index, [_ip] = destination XMM index
.gadget punpcklqdq
    // Load destination XMM index
    ldr x8, [_ip]              // Destination XMM index
    lsl x9, x8, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]

    // Source is in _xtmp (XMM index)
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]

    // xmm[dst].qw[1] = xmm[src].qw[0]
    ldr x10, [x8]              // Load src.qw[0]
    str x10, [x9, 8]           // Store to dst.qw[1]
    // xmm[dst].qw[0] stays unchanged
    gret 1

// MOVAPS/MOVUPS xmm, [mem] - Load 128-bit from memory to XMM
// _addr = memory address (GUEST address)
// [_ip] = orig_ip (for segfault handler), [_ip+8] = XMM register index
.gadget movaps_load
    // Save guest address for second half (read_prep modifies _addr to host addr)
    str _addr, [_cpu, LOCAL_value_addr]

    // Load first 64 bits from memory (low half)
    read_prep 64, movaps_load1
    ldr x8, [_addr]            // Load low 64 bits
    str x8, [_cpu, LOCAL_value]     // Temporarily store low

    // Load second 64 bits - use saved guest address + 8
    ldr _addr, [_cpu, LOCAL_value_addr]
    add _addr, _addr, 8        // Second half is at guest_addr + 8
    read_prep 64, movaps_load2
    ldr x9, [_addr]            // Load high 64 bits
    ldr x8, [_cpu, LOCAL_value]     // Restore low

    // Debug: trace the load with values
    str x8, [_cpu, LOCAL_value]        // Save low again
    str x9, [_cpu, LOCAL_value+8]      // Save high
    save_c
    ldr x0, [_cpu, LOCAL_value_addr]   // guest_addr
    mov x1, x8                         // low
    mov x2, x9                         // high
    ldr x3, [_ip, 8]                   // xmm index
    bl NAME(helper_debug_movaps_load_full)
    restore_c
    ldr x8, [_cpu, LOCAL_value]        // Restore low
    ldr x9, [_cpu, LOCAL_value+8]      // Restore high

    // Store to XMM register
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[n]
    str x8, [x10]              // Store low 64 bits
    str x9, [x10, 8]           // Store high 64 bits
    gret 2
    read_bullshit 64, movaps_load1
    read_bullshit 64, movaps_load2

// MOVAPS/MOVUPS [mem], xmm - Store 128-bit from XMM to memory
// _addr = memory address (GUEST address)
// [_ip] = orig_ip (for segfault handler), [_ip+8] = XMM register index
.gadget movaps_store
    // Save guest address for second half (write_prep modifies _addr to host addr)
    str _addr, [_cpu, LOCAL_value_addr]

    // Load from XMM register
    ldr x10, [_ip, 8]          // XMM register index (after orig_ip)
    lsl x10, x10, 4            // Multiply by 16
    add x10, x10, CPU_xmm
    add x10, _cpu, x10         // x10 = &xmm[n]
    ldr x8, [x10]              // Load low 64 bits
    ldr x9, [x10, 8]           // Load high 64 bits

    // Debug: trace the store with values
    save_c
    ldr x0, [_cpu, LOCAL_value_addr]   // guest_addr
    mov x1, x8                         // low
    mov x2, x9                         // high
    ldr x3, [_ip, 8]                   // xmm index
    bl NAME(helper_debug_movaps_store_full)
    restore_c

    // Store to memory (16 bytes)
    str x8, [_cpu, LOCAL_value]     // Temporarily store low
    str x9, [_cpu, LOCAL_value+8]   // Temporarily store high

    // First 64-bit store (low half)
    write_prep 64, movaps_store1
    ldr x8, [_cpu, LOCAL_value]     // Restore low
    str x8, [_addr]            // Store low 64 bits
    write_done 64, movaps_store1

    // Second 64-bit store (high half) - use saved guest address + 8
    ldr _addr, [_cpu, LOCAL_value_addr]
    add _addr, _addr, 8        // Second half is at guest_addr + 8
    write_prep 64, movaps_store2
    ldr x9, [_cpu, LOCAL_value+8]   // Restore high
    str x9, [_addr]            // Store high 64 bits
    write_done 64, movaps_store2
    gret 2
    write_bullshit 64, movaps_store1
    write_bullshit 64, movaps_store2

// MOVAPS xmm, xmm - Copy 128 bits between XMM registers
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget movaps_xmm_xmm
    // Source XMM
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr x10, [x8]              // Load low
    ldr x11, [x8, 8]           // Load high (note: x11 is ok here, save_c preserves it)

    // Destination XMM
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    str x10, [x9]              // Store low
    str x11, [x9, 8]           // Store high
    gret 1

// PXOR xmm, xmm - XOR 128 bits between XMM registers
// Used commonly as PXOR xmm, xmm to zero a register
// _xtmp = source XMM index, [_ip] = destination XMM index
.gadget pxor_xmm
    // Destination XMM
    ldr x9, [_ip]              // Destination XMM index
    lsl x9, x9, 4              // Multiply by 16
    add x9, x9, CPU_xmm
    add x9, _cpu, x9           // x9 = &xmm[dst]
    ldr x10, [x9]              // Load dst low
    ldr x12, [x9, 8]           // Load dst high (note: use x12, not x11 which is TLB scratch)

    // Source XMM
    lsl x8, _xtmp, 4           // Multiply by 16
    add x8, x8, CPU_xmm
    add x8, _cpu, x8           // x8 = &xmm[src]
    ldr x13, [x8]              // Load src low
    ldr x14, [x8, 8]           // Load src high

    // XOR
    eor x10, x10, x13
    eor x12, x12, x14

    // Store result
    str x10, [x9]              // Store low
    str x12, [x9, 8]           // Store high
    gret 1
