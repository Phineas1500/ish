#include "asbestos/asbestos.h"
#include "asbestos/frame.h"
#include "emu/cpu.h"
#include "emu/tlb.h"

void cpu() {
#ifdef ISH_GUEST_64BIT
    // 64-bit registers
    OFFSET(CPU, cpu_state, rax);
    OFFSET(CPU, cpu_state, rbx);
    OFFSET(CPU, cpu_state, rcx);
    OFFSET(CPU, cpu_state, rdx);
    OFFSET(CPU, cpu_state, rsi);
    OFFSET(CPU, cpu_state, rdi);
    OFFSET(CPU, cpu_state, rbp);
    OFFSET(CPU, cpu_state, rsp);
    OFFSET(CPU, cpu_state, r8);
    OFFSET(CPU, cpu_state, r9);
    OFFSET(CPU, cpu_state, r10);
    OFFSET(CPU, cpu_state, r11);
    OFFSET(CPU, cpu_state, r12);
    OFFSET(CPU, cpu_state, r13);
    OFFSET(CPU, cpu_state, r14);
    OFFSET(CPU, cpu_state, r15);
    OFFSET(CPU, cpu_state, rip);
    // 32-bit low parts (via union)
    OFFSET(CPU, cpu_state, eax);
    OFFSET(CPU, cpu_state, ebx);
    OFFSET(CPU, cpu_state, ecx);
    OFFSET(CPU, cpu_state, edx);
    OFFSET(CPU, cpu_state, esi);
    OFFSET(CPU, cpu_state, edi);
    OFFSET(CPU, cpu_state, ebp);
    OFFSET(CPU, cpu_state, esp);
    // TLS base registers
    OFFSET(CPU, cpu_state, fs_base);
    OFFSET(CPU, cpu_state, gs_base);
#else
    OFFSET(CPU, cpu_state, eax);
    OFFSET(CPU, cpu_state, ebx);
    OFFSET(CPU, cpu_state, ecx);
    OFFSET(CPU, cpu_state, edx);
    OFFSET(CPU, cpu_state, esi);
    OFFSET(CPU, cpu_state, edi);
    OFFSET(CPU, cpu_state, ebp);
    OFFSET(CPU, cpu_state, esp);
    OFFSET(CPU, cpu_state, ax);
    OFFSET(CPU, cpu_state, bx);
    OFFSET(CPU, cpu_state, cx);
    OFFSET(CPU, cpu_state, dx);
    OFFSET(CPU, cpu_state, si);
    OFFSET(CPU, cpu_state, di);
    OFFSET(CPU, cpu_state, bp);
    OFFSET(CPU, cpu_state, sp);
    OFFSET(CPU, cpu_state, eip);
    OFFSET(CPU, cpu_state, gs);
    OFFSET(CPU, cpu_state, tls_ptr);
#endif

    OFFSET(CPU, cpu_state, eflags);
    OFFSET(CPU, cpu_state, of);
    OFFSET(CPU, cpu_state, cf);
    OFFSET(CPU, cpu_state, res);
    OFFSET(CPU, cpu_state, op1);
    OFFSET(CPU, cpu_state, op2);
    OFFSET(CPU, cpu_state, flags_res);
    OFFSET(CPU, cpu_state, df_offset);
    OFFSET(CPU, cpu_state, fsw);
    OFFSET(CPU, cpu_state, fp);
    OFFSET(CPU, cpu_state, xmm);
    MACRO(PF_RES);
    MACRO(ZF_RES);
    MACRO(SF_RES);
    MACRO(AF_OPS);
    MACRO(PF_FLAG);
    MACRO(AF_FLAG);
    MACRO(ZF_FLAG);
    MACRO(SF_FLAG);
    MACRO(DF_FLAG);

    OFFSET(LOCAL, fiber_frame, bp);
    OFFSET(LOCAL, fiber_frame, value);
    OFFSET(LOCAL, fiber_frame, value_addr);
    OFFSET(LOCAL, fiber_frame, last_block);
    OFFSET(LOCAL, fiber_frame, ret_cache);
    OFFSET(CPU, cpu_state, segfault_addr);
    OFFSET(CPU, cpu_state, segfault_was_write);
    OFFSET(CPU, cpu_state, poked_ptr);
    MACRO(MEM_READ);
    MACRO(MEM_WRITE);

    OFFSET(FIBER_BLOCK, fiber_block, addr);
    OFFSET(FIBER_BLOCK, fiber_block, code);

    OFFSET(TLB, tlb, entries);
    OFFSET(TLB, tlb, dirty_page);
    OFFSET(TLB, tlb, segfault_addr);
    OFFSET(TLB_ENTRY, tlb_entry, page);
    OFFSET(TLB_ENTRY, tlb_entry, page_if_writable);
    OFFSET(TLB_ENTRY, tlb_entry, data_minus_addr);
}
