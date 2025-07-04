#include "emu/cpu.h"
#include "emu/tlb.h"
#include "kernel/calls.h"
#include <stdio.h>

void tlb_refresh(struct tlb *tlb, struct mmu *mmu) {
    if (tlb->mmu == mmu && tlb->mem_changes == mmu->changes)
        return;
    tlb->mmu = mmu;
    tlb->dirty_page = TLB_PAGE_EMPTY;
    tlb->mem_changes = mmu->changes;
    tlb_flush(tlb);
}

void tlb_flush(struct tlb *tlb) {
    tlb->mem_changes = tlb->mmu->changes;
    for (unsigned i = 0; i < TLB_SIZE; i++)
        tlb->entries[i] = (struct tlb_entry) {.page = 1, .page_if_writable = 1};
}

void tlb_free(struct tlb *tlb) {
    free(tlb);
}

bool __tlb_read_cross_page(struct tlb *tlb, addr_t addr, char *value, unsigned size) {
    char *ptr1 = __tlb_read_ptr(tlb, addr);
    if (ptr1 == NULL)
        return false;
    char *ptr2 = __tlb_read_ptr(tlb, (PAGE(addr) + 1) << PAGE_BITS);
    if (ptr2 == NULL)
        return false;
    size_t part1 = PAGE_SIZE - PGOFFSET(addr);
    assert(part1 < size);
    memcpy(value, ptr1, part1);
    memcpy(value + part1, ptr2, size - part1);
    return true;
}

bool __tlb_write_cross_page(struct tlb *tlb, addr_t addr, const char *value, unsigned size) {
    char *ptr1 = __tlb_write_ptr(tlb, addr);
    if (ptr1 == NULL)
        return false;
    char *ptr2 = __tlb_write_ptr(tlb, (PAGE(addr) + 1) << PAGE_BITS);
    if (ptr2 == NULL)
        return false;
    size_t part1 = PAGE_SIZE - PGOFFSET(addr);
    assert(part1 < size);
    memcpy(ptr1, value, part1);
    memcpy(ptr2, value + part1, size - part1);
    return true;
}

__no_instrument void *tlb_handle_miss(struct tlb *tlb, addr_t addr, int type) {
    char *ptr = mmu_translate(tlb->mmu, TLB_PAGE(addr), type);
    if (tlb->mmu->changes != tlb->mem_changes)
        tlb_flush(tlb);
    if (ptr == NULL) {
        tlb->segfault_addr = addr;
        // Enhanced debug: Log the failing address with CPU context
        FILE *f = fopen("/tmp/debug_tlb.txt", "a");
        if (f) {
            // Get current task and CPU state
            if (current && current->cpu.rip) {
                fprintf(f, "TLB miss: addr=0x%llx, type=%s, page=0x%llx, ip=0x%llx, pid=%d\n", 
                        (unsigned long long)addr, 
                        type == 0 ? "READ" : type == 1 ? "WRITE" : "OTHER",
                        (unsigned long long)TLB_PAGE(addr),
                        (unsigned long long)current->cpu.rip,
                        current->pid);
                
                // Dump first few bytes of instruction for context
                fprintf(f, "  Instruction bytes at 0x%llx: ", (unsigned long long)current->cpu.rip);
                for (int i = 0; i < 8; i++) {
                    uint8_t byte;
                    if (!user_read_task(current, current->cpu.rip + i, &byte, 1)) {
                        fprintf(f, "%02x ", byte);
                    } else {
                        fprintf(f, "?? ");
                    }
                }
                fprintf(f, "\n");
                
                // Dump register state for problematic address
                if (addr == 0xa8478b49f7f8e544ULL) {
                    fprintf(f, "  PROBLEM ADDR ACCESSED - Register dump:\n");
                    fprintf(f, "    RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                            (unsigned long long)current->cpu.rax, (unsigned long long)current->cpu.rbx,
                            (unsigned long long)current->cpu.rcx, (unsigned long long)current->cpu.rdx);
                    fprintf(f, "    RSI=0x%llx RDI=0x%llx RSP=0x%llx RBP=0x%llx\n",
                            (unsigned long long)current->cpu.rsi, (unsigned long long)current->cpu.rdi,
                            (unsigned long long)current->cpu.rsp, (unsigned long long)current->cpu.rbp);
                    
                    // Check if this address is anywhere on the stack
                    fprintf(f, "  Checking stack for this address pattern:\n");
                    for (int i = 0; i < 64; i += 8) {
                        uint64_t stack_val;
                        if (!user_read_task(current, current->cpu.rsp + i, &stack_val, 8)) {
                            if (stack_val == 0xa8478b49f7f8e544ULL) {
                                fprintf(f, "    FOUND problematic addr at RSP+%d!\n", i);
                            }
                            fprintf(f, "    RSP+%02d: 0x%llx\n", i, (unsigned long long)stack_val);
                        }
                    }
                }
            } else {
                fprintf(f, "TLB miss: addr=0x%llx, type=%s, page=0x%llx (no CPU context)\n", 
                        (unsigned long long)addr, 
                        type == 0 ? "READ" : type == 1 ? "WRITE" : "OTHER",
                        (unsigned long long)TLB_PAGE(addr));
            }
            fclose(f);
        }
        return NULL;
    }
    tlb->dirty_page = TLB_PAGE(addr);

    struct tlb_entry *tlb_ent = &tlb->entries[TLB_INDEX(addr)];
    tlb_ent->page = TLB_PAGE(addr);
    if (type == MEM_WRITE)
        tlb_ent->page_if_writable = tlb_ent->page;
    else
        // 1 is not a valid page so this won't look like a hit
        tlb_ent->page_if_writable = TLB_PAGE_EMPTY;
    tlb_ent->data_minus_addr = (uintptr_t) ptr - TLB_PAGE(addr);
    return (void *) (tlb_ent->data_minus_addr + addr);
}
