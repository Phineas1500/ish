#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Debug output guard: define DEBUG_64BIT_VERBOSE=1 to enable verbose debug
// output
#ifndef DEBUG_64BIT_VERBOSE
#define DEBUG_64BIT_VERBOSE 0
#endif

#if DEBUG_64BIT_VERBOSE
#define DEBUG_FPRINTF(...) fprintf(__VA_ARGS__)
#else
#define DEBUG_FPRINTF(...) ((void)0)
#endif

#define DEFAULT_CHANNEL memory
#include "asbestos/asbestos.h"
#include "debug.h"
#include "fs/fd.h"
#include "kernel/errno.h"
#include "kernel/memory.h"
#include "kernel/signal.h"
#include "kernel/task.h"
#include "kernel/vdso.h"

// increment the change count
static void mem_changed(struct mem *mem);
static struct mmu_ops mem_mmu_ops;

#ifdef ISH_GUEST_64BIT
// 64-bit: Hash table implementation for sparse page lookups

static inline size_t page_hash(page_t page) {
  // Simple hash function - XOR folding
  return ((page >> MEM_HASH_BITS) ^ page) & (MEM_HASH_SIZE - 1);
}

void mem_init(struct mem *mem) {
  mem->hash_table = calloc(MEM_HASH_SIZE, sizeof(struct pt_hash_entry *));
  mem->pages_mapped = 0;
  mem->mmu.ops = &mem_mmu_ops;
  mem->mmu.asbestos = asbestos_new(&mem->mmu);
  mem->mmu.changes = 0;
  wrlock_init(&mem->lock);
}

void mem_destroy(struct mem *mem) {
  write_wrlock(&mem->lock);
  // Free all hash entries
  for (size_t i = 0; i < MEM_HASH_SIZE; i++) {
    struct pt_hash_entry *entry = mem->hash_table[i];
    while (entry != NULL) {
      struct pt_hash_entry *next = entry->next;
      // Handle data cleanup
      if (entry->entry.data != NULL) {
        struct data *data = entry->entry.data;
        if (--data->refcount == 0) {
          if (data->data != vdso_data) {
            munmap(data->data, data->size);
          }
          if (data->fd != NULL) {
            fd_close(data->fd);
          }
          free(data);
        }
      }
      free(entry);
      entry = next;
    }
  }
  asbestos_free(mem->mmu.asbestos);
  free(mem->hash_table);
  write_wrunlock(&mem->lock);
  wrlock_destroy(&mem->lock);
}

static struct pt_entry *mem_pt_new(struct mem *mem, page_t page) {
  size_t hash = page_hash(page);

  // Check if entry already exists
  struct pt_hash_entry *entry = mem->hash_table[hash];
  while (entry != NULL) {
    if (entry->page == page)
      return &entry->entry;
    entry = entry->next;
  }

  // Create new entry
  entry = calloc(1, sizeof(struct pt_hash_entry));
  entry->page = page;
  entry->next = mem->hash_table[hash];
  mem->hash_table[hash] = entry;
  mem->pages_mapped++;

  // Debug: trace 0x7f... page creations
  if (page >= 0x7f0000000ULL && page <= 0x7f0000010ULL) {
    DEBUG_FPRINTF(stderr, "MEM_PT_NEW: creating page 0x%llx\n",
                  (unsigned long long)page);
  }
  return &entry->entry;
}

struct pt_entry *mem_pt(struct mem *mem, page_t page) {
  size_t hash = page_hash(page);
  struct pt_hash_entry *entry = mem->hash_table[hash];
  while (entry != NULL) {
    if (entry->page == page) {
      if (entry->entry.data == NULL)
        return NULL;
      // Debug: trace 0x7f... page lookups
      static int trace_count = 0;
      if (page >= 0x7f0000000ULL && page <= 0x7f0000010ULL && trace_count < 5) {
        trace_count++;
        DEBUG_FPRINTF(stderr, "MEM_PT: found page 0x%llx data=%p offset=%zu\n",
                      (unsigned long long)page, entry->entry.data,
                      entry->entry.offset);
      }
      return &entry->entry;
    }
    entry = entry->next;
  }
  return NULL;
}

static void mem_pt_del(struct mem *mem, page_t page) {
  size_t hash = page_hash(page);
  struct pt_hash_entry **prev = &mem->hash_table[hash];
  struct pt_hash_entry *entry = *prev;

  while (entry != NULL) {
    if (entry->page == page) {
      *prev = entry->next;
      free(entry);
      mem->pages_mapped--;
      return;
    }
    prev = &entry->next;
    entry = entry->next;
  }
}

void mem_next_page(struct mem *mem, page_t *page) {
  // For 64-bit, we need to iterate through the hash table
  // This is less efficient than 32-bit but necessary for sparse address space
  (*page)++;
  // In 64-bit mode, just increment and let caller check if page exists
  // A more sophisticated implementation would track mapped ranges
}

#else
// 32-bit: Traditional 2-level page table implementation

void mem_init(struct mem *mem) {
  mem->pgdir = calloc(MEM_PGDIR_SIZE, sizeof(struct pt_entry *));
  mem->pgdir_used = 0;
  mem->mmu.ops = &mem_mmu_ops;
  mem->mmu.asbestos = asbestos_new(&mem->mmu);
  mem->mmu.changes = 0;
  wrlock_init(&mem->lock);
}

void mem_destroy(struct mem *mem) {
  write_wrlock(&mem->lock);
  pt_unmap_always(mem, 0, MEM_PAGES);
  asbestos_free(mem->mmu.asbestos);
  for (int i = 0; i < MEM_PGDIR_SIZE; i++) {
    if (mem->pgdir[i] != NULL)
      free(mem->pgdir[i]);
  }
  free(mem->pgdir);
  write_wrunlock(&mem->lock);
  wrlock_destroy(&mem->lock);
}

#define PGDIR_TOP(page) ((page) >> 10)
#define PGDIR_BOTTOM(page) ((page) & (MEM_PGDIR_SIZE - 1))

static struct pt_entry *mem_pt_new(struct mem *mem, page_t page) {
  struct pt_entry *pgdir = mem->pgdir[PGDIR_TOP(page)];
  if (pgdir == NULL) {
    pgdir = mem->pgdir[PGDIR_TOP(page)] =
        calloc(MEM_PGDIR_SIZE, sizeof(struct pt_entry));
    mem->pgdir_used++;
  }
  return &pgdir[PGDIR_BOTTOM(page)];
}

struct pt_entry *mem_pt(struct mem *mem, page_t page) {
  // Debug: check for out of bounds access
  if (PGDIR_TOP(page) >= MEM_PGDIR_SIZE) {
    DEBUG_FPRINTF(stderr, "MEM_PT OOB: page=0x%llx PGDIR_TOP=0x%llx\n",
                  (unsigned long long)page,
                  (unsigned long long)PGDIR_TOP(page));
  }
  struct pt_entry *pgdir = mem->pgdir[PGDIR_TOP(page)];
  if (pgdir == NULL)
    return NULL;
  struct pt_entry *entry = &pgdir[PGDIR_BOTTOM(page)];
  if (entry->data == NULL)
    return NULL;
  return entry;
}

static void mem_pt_del(struct mem *mem, page_t page) {
  struct pt_entry *entry = mem_pt(mem, page);
  if (entry != NULL)
    entry->data = NULL;
}

void mem_next_page(struct mem *mem, page_t *page) {
  (*page)++;
  if (*page >= MEM_PAGES)
    return;
  while (*page < MEM_PAGES && mem->pgdir[PGDIR_TOP(*page)] == NULL)
    *page = (*page - PGDIR_BOTTOM(*page)) + MEM_PGDIR_SIZE;
}
#endif

page_t pt_find_hole(struct mem *mem, pages_t size) {
  page_t hole_end =
      0; // this can never be used before initializing but gcc doesn't realize
  bool in_hole = false;

#ifdef ISH_GUEST_64BIT
  // For 64-bit, search in typical mmap region (below stack, above heap)
  // Linux x86_64 typically uses 0x7f0000000000 - 0x7fffffffffff for mmap
  // We'll use a smaller range for efficiency
  page_t search_start = 0x7f0000000ULL; // ~127 TB
  page_t search_end = 0x400000ULL;      // 16 GB (above typical heap)
#else
  page_t search_start = 0xf7ffd;
  page_t search_end = 0x40000;
#endif

  for (page_t page = search_start; page > search_end; page--) {
    if (!in_hole && mem_pt(mem, page) == NULL) {
      in_hole = true;
      hole_end = page + 1;
    }
    if (mem_pt(mem, page) != NULL)
      in_hole = false;
    else if (hole_end - page == size)
      return page;
  }
  return BAD_PAGE;
}

bool pt_is_hole(struct mem *mem, page_t start, pages_t pages) {
  for (page_t page = start; page < start + pages; page++) {
    if (mem_pt(mem, page) != NULL)
      return false;
  }
  return true;
}

int pt_map(struct mem *mem, page_t start, pages_t pages, void *memory,
           size_t offset, unsigned flags) {
  if (memory == MAP_FAILED)
    return errno_map();

  // If this fails, the munmap in pt_unmap would probably fail.
  assert((uintptr_t)memory % real_page_size == 0 || memory == vdso_data);

  struct data *data = malloc(sizeof(struct data));
  if (data == NULL)
    return _ENOMEM;
  *data = (struct data){
      .data = memory,
      .size = pages * PAGE_SIZE + offset,

#if LEAK_DEBUG
      .pid = current ? current->pid : 0,
      .dest = start << PAGE_BITS,
#endif
  };

  for (page_t page = start; page < start + pages; page++) {
    if (mem_pt(mem, page) != NULL)
      pt_unmap(mem, page, 1);
    data->refcount++;
    struct pt_entry *pt = mem_pt_new(mem, page);
    pt->data = data;
    pt->offset = ((page - start) << PAGE_BITS) + offset;
    pt->flags = flags;
    // Debug: trace 0x7f... page mappings
    if (page >= 0x7f0000000ULL && page <= 0x7f0000010ULL) {
      DEBUG_FPRINTF(
          stderr,
          "PT_MAP: page 0x%llx start=0x%llx pages=%u offset=%zu flags=0x%x\n",
          (unsigned long long)page, (unsigned long long)start,
          (unsigned int)pages, offset, flags);
    }
  }
  return 0;
}

int pt_unmap(struct mem *mem, page_t start, pages_t pages) {
  for (page_t page = start; page < start + pages; page++)
    if (mem_pt(mem, page) == NULL)
      return -1;
  return pt_unmap_always(mem, start, pages);
}

int pt_unmap_always(struct mem *mem, page_t start, pages_t pages) {
  for (page_t page = start; page < start + pages; mem_next_page(mem, &page)) {
    struct pt_entry *pt = mem_pt(mem, page);
    if (pt == NULL)
      continue;
    asbestos_invalidate_page(mem->mmu.asbestos, page);
    struct data *data = pt->data;
    mem_pt_del(mem, page);
    if (--data->refcount == 0) {
      // vdso wasn't allocated with mmap, it's just in our data segment
      if (data->data != vdso_data) {
        int err = munmap(data->data, data->size);
        if (err != 0)
          die("munmap(%p, %lu) failed: %s", data->data, data->size,
              strerror(errno));
      }
      if (data->fd != NULL) {
        fd_close(data->fd);
      }
      free(data);
    }
  }
  mem_changed(mem);
  return 0;
}

int pt_map_nothing(struct mem *mem, page_t start, pages_t pages,
                   unsigned flags) {
  if (pages == 0)
    return 0;
  void *memory = mmap(NULL, pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  return pt_map(mem, start, pages, memory, 0, flags | P_ANONYMOUS);
}

int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags) {
  for (page_t page = start; page < start + pages; page++)
    if (mem_pt(mem, page) == NULL)
      return _ENOMEM;
  for (page_t page = start; page < start + pages; page++) {
    struct pt_entry *entry = mem_pt(mem, page);
    int old_flags = entry->flags;
    entry->flags = flags;
    // check if protection is increasing
    if ((flags & ~old_flags) & (P_READ | P_WRITE)) {
      void *data = (char *)entry->data->data + entry->offset;
      // force to be page aligned
      data = (void *)((uintptr_t)data & ~(real_page_size - 1));
      int prot = PROT_READ;
      if (flags & P_WRITE)
        prot |= PROT_WRITE;
      if (mprotect(data, real_page_size, prot) < 0)
        return errno_map();
    }
  }
  mem_changed(mem);
  return 0;
}

int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start,
                     page_t pages) {
#ifdef ISH_GUEST_64BIT
  // 64-bit: iterate hash table buckets directly instead of scanning
  // 68 billion pages one at a time (which would be an infinite loop)
  for (size_t i = 0; i < MEM_HASH_SIZE; i++) {
    struct pt_hash_entry *entry = src->hash_table[i];
    while (entry != NULL) {
      struct pt_hash_entry *next = entry->next;
      page_t page = entry->page;
      if (entry->entry.data != NULL && page >= start && page < start + pages) {
        if (pt_unmap_always(dst, page, 1) < 0)
          return -1;
        if (!(entry->entry.flags & P_SHARED))
          entry->entry.flags |= P_COW;
        entry->entry.data->refcount++;
        struct pt_entry *dst_entry = mem_pt_new(dst, page);
        dst_entry->data = entry->entry.data;
        dst_entry->offset = entry->entry.offset;
        dst_entry->flags = entry->entry.flags;
      }
      entry = next;
    }
  }
  mem_changed(src);
  mem_changed(dst);
  return 0;
#else
  for (page_t page = start; page < start + pages; mem_next_page(src, &page)) {
    struct pt_entry *entry = mem_pt(src, page);
    if (entry == NULL)
      continue;
    if (pt_unmap_always(dst, page, 1) < 0)
      return -1;
    if (!(entry->flags & P_SHARED))
      entry->flags |= P_COW;
    entry->data->refcount++;
    struct pt_entry *dst_entry = mem_pt_new(dst, page);
    dst_entry->data = entry->data;
    dst_entry->offset = entry->offset;
    dst_entry->flags = entry->flags;
  }
  mem_changed(src);
  mem_changed(dst);
  return 0;
#endif
}

static void mem_changed(struct mem *mem) { mem->mmu.changes++; }

// This version will return NULL instead of making necessary pagetable changes.
// Used by the emulator to avoid deadlocks.
static void *mem_ptr_nofault(struct mem *mem, addr_t addr, int type) {
  struct pt_entry *entry = mem_pt(mem, PAGE(addr));
  if (entry == NULL)
    return NULL;
  if (type == MEM_WRITE && !P_WRITABLE(entry->flags))
    return NULL;
  void *result = entry->data->data + entry->offset + PGOFFSET(addr);
  // Trace crash page
  if (PAGE(addr) == 0x55555561c) {
    DEBUG_FPRINTF(
        stderr,
        "MEM_PTR: page=0x%llx data=%p size=0x%zx offset=0x%zx flags=0x%x "
        "result=%p\n",
        (unsigned long long)PAGE(addr), entry->data->data, entry->data->size,
        entry->offset, entry->flags, result);
    // Check if offset is within data size
    if (entry->offset + PAGE_SIZE > entry->data->size) {
      fprintf(
          stderr,
          "MEM_PTR WARNING: offset+PAGE_SIZE (0x%zx) > data size (0x%zx)!\n",
          entry->offset + PAGE_SIZE, entry->data->size);
    }
    // Try to read from result to verify it's accessible
    volatile char *test = (volatile char *)result;
    DEBUG_FPRINTF(stderr, "MEM_PTR TEST: reading from %p...\n", result);
    char c = test[0x150]; // Read at offset 0x150 where crash happens
    DEBUG_FPRINTF(stderr, "MEM_PTR TEST: read byte 0x%02x OK\n",
                  (unsigned char)c);
  }
  return result;
}

void *mem_ptr(struct mem *mem, addr_t addr, int type) {
  void *old_ptr = mem_ptr_nofault(mem, addr, type); // just for an assert

  page_t page = PAGE(addr);
  struct pt_entry *entry = mem_pt(mem, page);

  if (entry == NULL) {
    // page does not exist
    // look to see if the next VM region is willing to grow down
    page_t p = page + 1;
#ifdef ISH_GUEST_64BIT
    // Limit search range to avoid scanning billions of unmapped pages
    page_t search_limit = page + 0x100; // search at most 256 pages (1MB)
    while (p < MEM_PAGES && p < search_limit && mem_pt(mem, p) == NULL)
      p++;
    if (p >= MEM_PAGES || p >= search_limit)
      return NULL;
#else
    while (p < MEM_PAGES && mem_pt(mem, p) == NULL)
      p++;
    if (p >= MEM_PAGES)
      return NULL;
#endif
    if (!(mem_pt(mem, p)->flags & P_GROWSDOWN))
      return NULL;
    // Debug: trace growsdown allocations
    if (page >= 0x7f0000000ULL) {
      DEBUG_FPRINTF(
          stderr, "GROWSDOWN: allocating page 0x%llx (growsdown from 0x%llx)\n",
          (unsigned long long)page, (unsigned long long)p);
    }

    // Changing memory maps must be done with the write lock. But this is
    // called with the read lock.
    // This locking stuff is copy/pasted for all the code in this function
    // which changes memory maps.
    // TODO: factor the lock/unlock code here into a new function. Do this
    // next time you touch this function.
    read_wrunlock(&mem->lock);
    write_wrlock(&mem->lock);
    pt_map_nothing(mem, page, 1, P_WRITE | P_GROWSDOWN);
    write_wrunlock(&mem->lock);
    read_wrlock(&mem->lock);

    entry = mem_pt(mem, page);
  }

  if (entry != NULL && (type == MEM_WRITE || type == MEM_WRITE_PTRACE)) {
    // if page is unwritable, well tough luck
    if (type != MEM_WRITE_PTRACE && !(entry->flags & P_WRITE))
      return NULL;
    if (type == MEM_WRITE_PTRACE) {
      // TODO: Is P_WRITE really correct? The page shouldn't be writable without
      // ptrace.
      entry->flags |= P_WRITE | P_COW;
    }
    // get rid of any compiled blocks in this page
    asbestos_invalidate_page(mem->mmu.asbestos, page);
    // if page is cow, ~~milk~~ copy it
    if (entry->flags & P_COW) {
      void *data = (char *)entry->data->data + entry->offset;
      void *copy = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

      // copy/paste from above
      read_wrunlock(&mem->lock);
      write_wrlock(&mem->lock);
      memcpy(copy, data, PAGE_SIZE);
      pt_map(mem, page, 1, copy, 0, entry->flags & ~P_COW);
      write_wrunlock(&mem->lock);
      read_wrlock(&mem->lock);
    }
  }

  void *ptr = mem_ptr_nofault(mem, addr, type);
  assert(old_ptr == NULL || old_ptr == ptr || type == MEM_WRITE_PTRACE);
  return ptr;
}

static void *mem_mmu_translate(struct mmu *mmu, addr_t addr, int type) {
  return mem_ptr_nofault(container_of(mmu, struct mem, mmu), addr, type);
}

static struct mmu_ops mem_mmu_ops = {
    .translate = mem_mmu_translate,
};

int mem_segv_reason(struct mem *mem, addr_t addr) {
  struct pt_entry *pt = mem_pt(mem, PAGE(addr));
  if (pt == NULL)
    return SEGV_MAPERR_;
  return SEGV_ACCERR_;
}

size_t real_page_size;
__attribute__((constructor)) static void get_real_page_size() {
  real_page_size = sysconf(_SC_PAGESIZE);
}

void mem_coredump(struct mem *mem, const char *file) {
  int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (fd < 0) {
    perror("open");
    return;
  }

#ifdef ISH_GUEST_64BIT
  // For 64-bit, iterate through hash table instead of entire address space
  int pages = 0;
  for (size_t i = 0; i < MEM_HASH_SIZE; i++) {
    struct pt_hash_entry *entry = mem->hash_table[i];
    while (entry != NULL) {
      if (entry->entry.data != NULL) {
        pages++;
        off_t offset = (off_t)entry->page << PAGE_BITS;
        if (lseek(fd, offset, SEEK_SET) < 0) {
          perror("lseek");
          close(fd);
          return;
        }
        if (write(fd, entry->entry.data->data + entry->entry.offset,
                  PAGE_SIZE) < 0) {
          perror("write");
          close(fd);
          return;
        }
      }
      entry = entry->next;
    }
  }
  printk("dumped %d pages\n", pages);
#else
  if (ftruncate(fd, 0xffffffff) < 0) {
    perror("ftruncate");
    close(fd);
    return;
  }

  int pages = 0;
  for (page_t page = 0; page < MEM_PAGES; page++) {
    struct pt_entry *entry = mem_pt(mem, page);
    if (entry == NULL)
      continue;
    pages++;
    if (lseek(fd, page << PAGE_BITS, SEEK_SET) < 0) {
      perror("lseek");
      close(fd);
      return;
    }
    if (write(fd, entry->data->data, PAGE_SIZE) < 0) {
      perror("write");
      close(fd);
      return;
    }
  }
  printk("dumped %d pages\n", pages);
#endif
  close(fd);
}
