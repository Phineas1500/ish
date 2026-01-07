#include <stdio.h>
#include "emu/cpu.h"
#include "emu/tlb.h"

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
    // Trace ALL translations for crash page (both READ and WRITE)
    page_t crash_page = 0x55555561c000;
    if (TLB_PAGE(addr) == crash_page) {
        unsigned part1 = (addr >> PAGE_BITS) & (TLB_SIZE - 1);
        unsigned part2 = (addr >> (PAGE_BITS + TLB_BITS)) & (TLB_SIZE - 1);
        unsigned idx = part1 ^ part2;
        fprintf(stderr, "TLB_C[%s]: addr=0x%llx page=0x%llx ptr=%p index=%u\n",
                type == 0 ? "READ" : "WRITE",
                (unsigned long long)addr, (unsigned long long)TLB_PAGE(addr),
                (void*)ptr, idx);
    }
    if (tlb->mmu->changes != tlb->mem_changes)
        tlb_flush(tlb);
    if (ptr == NULL) {
        tlb->segfault_addr = addr;
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

    void *result = (void *) (tlb_ent->data_minus_addr + addr);
    // Trace final host address for crash page
    if (TLB_PAGE(addr) == 0x55555561c000) {
        fprintf(stderr, "TLB_RESULT: guest=0x%llx -> host=%p (data_minus_addr=0x%llx) index=%lu\n",
                (unsigned long long)addr, result, (unsigned long long)tlb_ent->data_minus_addr,
                (unsigned long)TLB_INDEX(addr));
    }
    return result;
}
