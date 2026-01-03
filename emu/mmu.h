#ifndef EMU_CPU_MEM_H
#define EMU_CPU_MEM_H

#include "misc.h"

// Page number type: top bits of an address (addr >> 12)
// For 32-bit: 20 bits (4GB / 4KB = 1M pages)
// For 64-bit: 36 bits (48-bit VA - 12-bit offset = 256T pages theoretically)
#ifdef ISH_GUEST_64BIT
typedef uint64_t page_t;
typedef uint64_t pages_t;
#define BAD_PAGE 0x1000000000ULL  // Invalid page marker for 64-bit
#define MEM_PAGES 0x1000000000ULL // 2^36 pages (48-bit address space)
#else
typedef dword_t page_t;
typedef dword_t pages_t;
#define BAD_PAGE 0x10000
#define MEM_PAGES (1 << 20) // 1M pages for 32-bit (4GB)
#endif

#ifndef __KERNEL__
#define PAGE_BITS 12
#undef PAGE_SIZE // defined in system headers somewhere
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE(addr) ((addr) >> PAGE_BITS)
#define PGOFFSET(addr) ((addr) & (PAGE_SIZE - 1))
// bytes MUST be unsigned if you would like this to overflow to zero
#define PAGE_ROUND_UP(bytes) (PAGE((bytes) + PAGE_SIZE - 1))
#endif

struct mmu {
    struct mmu_ops *ops;
    struct asbestos *asbestos;
    uint64_t changes;
};

#define MEM_READ 0
#define MEM_WRITE 1
#define MEM_WRITE_PTRACE 2

struct mmu_ops {
    // type is MEM_READ or MEM_WRITE
    void *(*translate)(struct mmu *mmu, addr_t addr, int type);
};

static inline void *mmu_translate(struct mmu *mmu, addr_t addr, int type) {
    return mmu->ops->translate(mmu, addr, type);
}

#endif