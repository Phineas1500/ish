#include "kernel/signal.h"
#include "task.h"
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#include "fs/fd.h"
#include "kernel/calls.h"
#include "kernel/elf.h"
#include "kernel/errno.h"
#include "kernel/memory.h"
#include "kernel/random.h"
#include "kernel/vdso.h"
#include "misc.h"
#include "tools/ptraceomatic-config.h"

#define ARGV_MAX 32 * PAGE_SIZE

struct exec_args {
  // number of arguments
  size_t count;
  // series of count null-terminated strings, plus an extra null for good
  // measure
  const char *args;
};

static inline addr_t align_stack(addr_t sp);
static inline ssize_t user_strlen(addr_t p);
static inline int user_memset(addr_t start, byte_t val, dword_t len);
static inline addr_t copy_string(addr_t sp, const char *string);
static inline addr_t args_copy(addr_t sp, struct exec_args args);
static size_t args_size(struct exec_args args);

#ifdef ISH_GUEST_64BIT
static int read_header64(struct fd *fd, struct elf_header64 *header) {
  int err;
  if (fd->ops->lseek(fd, 0, SEEK_SET))
    return _EIO;
  if ((err = fd->ops->read(fd, header, sizeof(*header))) != sizeof(*header)) {
    if (err < 0)
      return _EIO;
    return _ENOEXEC;
  }
  if (memcmp(&header->magic, ELF_MAGIC, sizeof(header->magic)) != 0 ||
      (header->type != ELF_EXECUTABLE && header->type != ELF_DYNAMIC) ||
      header->bitness != ELF_64BIT || header->endian != ELF_LITTLEENDIAN ||
      header->elfversion1 != 1 || header->machine != ELF_X86_64)
    return _ENOEXEC;
  return 0;
}
#endif

static int read_header(struct fd *fd, struct elf_header *header) {
  int err;
  if (fd->ops->lseek(fd, 0, SEEK_SET))
    return _EIO;
  if ((err = fd->ops->read(fd, header, sizeof(*header))) != sizeof(*header)) {
    if (err < 0)
      return _EIO;
    return _ENOEXEC;
  }
  if (memcmp(&header->magic, ELF_MAGIC, sizeof(header->magic)) != 0 ||
      (header->type != ELF_EXECUTABLE && header->type != ELF_DYNAMIC) ||
      header->bitness != ELF_32BIT || header->endian != ELF_LITTLEENDIAN ||
      header->elfversion1 != 1 || header->machine != ELF_X86)
    return _ENOEXEC;
  return 0;
}

#ifdef ISH_GUEST_64BIT
static int read_prg_headers64(struct fd *fd, struct elf_header64 header,
                              struct prg_header64 **ph_out) {
  ssize_t ph_size = sizeof(struct prg_header64) * header.phent_count;
  struct prg_header64 *ph = malloc(ph_size);
  if (ph == NULL)
    return _ENOMEM;

  if (fd->ops->lseek(fd, header.prghead_off, SEEK_SET) < 0) {
    free(ph);
    return _EIO;
  }
  if (fd->ops->read(fd, ph, ph_size) != ph_size) {
    free(ph);
    if (errno != 0)
      return _EIO;
    return _ENOEXEC;
  }

  *ph_out = ph;
  return 0;
}
#endif

static int read_prg_headers(struct fd *fd, struct elf_header header,
                            struct prg_header **ph_out) {
  ssize_t ph_size = sizeof(struct prg_header) * header.phent_count;
  struct prg_header *ph = malloc(ph_size);
  if (ph == NULL)
    return _ENOMEM;

  if (fd->ops->lseek(fd, header.prghead_off, SEEK_SET) < 0) {
    free(ph);
    return _EIO;
  }
  if (fd->ops->read(fd, ph, ph_size) != ph_size) {
    free(ph);
    if (errno != 0)
      return _EIO;
    return _ENOEXEC;
  }

  *ph_out = ph;
  return 0;
}

#ifdef ISH_GUEST_64BIT
static int load_entry64(struct prg_header64 ph, addr_t bias, struct fd *fd) {
  int err;

  addr_t addr = ph.vaddr + bias;
  addr_t offset = ph.offset;
  addr_t memsize = ph.memsize;
  addr_t filesize = ph.filesize;

  DEBUG_FPRINTF(
      stderr,
      "ELF64: load_entry64 vaddr=%llx offset=%llx filesz=%llx memsz=%llx\n",
      (unsigned long long)ph.vaddr, (unsigned long long)offset,
      (unsigned long long)filesize, (unsigned long long)memsize);

  // For now, always make segments writable so dynamic linker can apply
  // relocations
  // TODO: properly handle RELRO - make read-only after relocations are done
  int flags = P_READ | P_WRITE;
  // if (ph.flags & PH_W) flags |= P_WRITE;

  if ((err = fd->ops->mmap(fd, current->mem, PAGE(addr),
                           PAGE_ROUND_UP(filesize + PGOFFSET(addr)),
                           offset - PGOFFSET(addr), flags, MMAP_PRIVATE)) < 0)
    return err;
  mem_pt(current->mem, PAGE(addr))->data->fd = fd_retain(fd);
  mem_pt(current->mem, PAGE(addr))->data->file_offset = offset - PGOFFSET(addr);

  if (memsize > filesize) {
    addr_t bss_size = memsize - filesize;
    addr_t file_end = addr + filesize;
    addr_t tail_size = PAGE_SIZE - PGOFFSET(file_end);
    if (tail_size == PAGE_SIZE)
      tail_size = 0;

    DEBUG_FPRINTF(
        stderr,
        "ELF64: BSS addr=%llx file_end=%llx bss_size=%llx tail_size=%llx\n",
        (unsigned long long)addr, (unsigned long long)file_end,
        (unsigned long long)bss_size, (unsigned long long)tail_size);

    if (tail_size != 0) {
      write_wrunlock(&current->mem->lock);
      user_memset(file_end, 0, tail_size);
      write_wrlock(&current->mem->lock);
    }
    if (tail_size > bss_size)
      tail_size = bss_size;

    if (bss_size - tail_size != 0) {
      DEBUG_FPRINTF(stderr,
                    "ELF64: pt_map_nothing start_page=%llx pages=%llx\n",
                    (unsigned long long)PAGE_ROUND_UP(addr + filesize),
                    (unsigned long long)PAGE_ROUND_UP(bss_size - tail_size));
      if ((err = pt_map_nothing(current->mem, PAGE_ROUND_UP(addr + filesize),
                                PAGE_ROUND_UP(bss_size - tail_size), flags)) <
          0)
        return err;
    }
  }
  return 0;
}

static addr_t find_hole_for_elf64(struct elf_header64 *header,
                                  struct prg_header64 *ph) {
  struct prg_header64 *first = NULL, *last = NULL;
  for (int i = 0; i < header->phent_count; i++) {
    if (ph[i].type == PT_LOAD) {
      if (first == NULL)
        first = &ph[i];
      last = &ph[i];
    }
  }
  pages_t size = 0;
  if (first != NULL) {
    pages_t a = PAGE_ROUND_UP(last->vaddr + last->memsize);
    pages_t b = PAGE(first->vaddr);
    size = a - b;
  }
  return pt_find_hole(current->mem, size) << PAGE_BITS;
}

static int elf_exec64(struct fd *fd, const char *file, struct exec_args argv,
                      struct exec_args envp) {
  int err = 0;

  // read the headers
  struct elf_header64 header;
  if ((err = read_header64(fd, &header)) < 0)
    return err;
  struct prg_header64 *ph;
  if ((err = read_prg_headers64(fd, header, &ph)) < 0)
    return err;

  // look for an interpreter
  char *interp_name = NULL;
  struct fd *interp_fd = NULL;
  struct elf_header64 interp_header;
  struct prg_header64 *interp_ph = NULL;
  for (unsigned i = 0; i < header.phent_count; i++) {
    if (ph[i].type != PT_INTERP)
      continue;
    if (interp_name) {
      err = _EINVAL;
      goto out_free_interp;
    }

    interp_name = malloc(ph[i].filesize);
    err = _ENOMEM;
    if (interp_name == NULL)
      goto out_free_ph;

    err = _EIO;
    if (fd->ops->lseek(fd, ph[i].offset, SEEK_SET) < 0)
      goto out_free_interp;
    if (fd->ops->read(fd, interp_name, ph[i].filesize) !=
        (ssize_t)ph[i].filesize)
      goto out_free_interp;

    interp_fd = generic_open(interp_name, O_RDONLY, 0);
    if (IS_ERR(interp_fd)) {
      err = PTR_ERR(interp_fd);
      goto out_free_interp;
    }
    if ((err = read_header64(interp_fd, &interp_header)) < 0) {
      if (err == _ENOEXEC)
        err = _ELIBBAD;
      goto out_free_interp;
    }
    if ((err = read_prg_headers64(interp_fd, interp_header, &interp_ph)) < 0) {
      if (err == _ENOEXEC)
        err = _ELIBBAD;
      goto out_free_interp;
    }
  }

  // free the process's memory
  lock(&current->general_lock);
  mm_release(current->mm);
  task_set_mm(current, mm_new());
  unlock(&current->general_lock);
  write_wrlock(&current->mem->lock);

  current->mm->exefile = fd_retain(fd);

  addr_t load_addr = 0;
  bool load_addr_set = false;
  addr_t bias = 0;

  // map segments
  for (unsigned i = 0; i < header.phent_count; i++) {
    if (ph[i].type != PT_LOAD)
      continue;

    if (!load_addr_set && header.type == ELF_DYNAMIC) {
      if (interp_name)
        bias = 0x555555554000; // standard PIE base for x86_64
      else
        bias = find_hole_for_elf64(&header, ph);
    }

    if ((err = load_entry64(ph[i], bias, fd)) < 0)
      goto beyond_hope;

    if (!load_addr_set) {
      load_addr = bias + ph[i].vaddr - ph[i].offset;
      load_addr_set = true;
    }

    addr_t brk = bias + ph[i].vaddr + ph[i].memsize;
    if (brk > current->mm->start_brk)
      current->mm->start_brk = current->mm->brk = BYTES_ROUND_UP(brk);
  }

  addr_t entry = bias + header.entry_point;
  addr_t interp_base = 0;

  if (interp_name) {
    interp_base = find_hole_for_elf64(&interp_header, interp_ph);
    DEBUG_FPRINTF(stderr, "ELF64: loading interpreter at base=%llx\n",
                  (unsigned long long)interp_base);
    for (int i = interp_header.phent_count - 1; i >= 0; i--) {
      if (interp_ph[i].type != PT_LOAD)
        continue;
      DEBUG_FPRINTF(
          stderr, "ELF64: interp segment vaddr=%llx memsz=%llx flags=%x\n",
          (unsigned long long)interp_ph[i].vaddr,
          (unsigned long long)interp_ph[i].memsize, interp_ph[i].flags);
      if ((err = load_entry64(interp_ph[i], interp_base, interp_fd)) < 0)
        goto beyond_hope;
    }
    entry = interp_base + interp_header.entry_point;

    // Debug: check interpreter's optind value (at vaddr 0x9f3dc)
    // We already hold the write lock, so we can't use user_get (would deadlock)
    addr_t interp_optind_addr = interp_base + 0x9f3dc;
    page_t optind_page = PAGE(interp_optind_addr);
    DEBUG_FPRINTF(
        stderr,
        "ELF64: checking optind at 0x%llx (page 0x%llx, offset 0x%lx)\n",
        (unsigned long long)interp_optind_addr, (unsigned long long)optind_page,
        (unsigned long)PGOFFSET(interp_optind_addr));
    fflush(stderr);
    struct pt_entry *optind_pt = mem_pt(current->mem, optind_page);
    if (optind_pt && optind_pt->data) {
      DEBUG_FPRINTF(
          stderr, "ELF64: pt_entry found: data=%p, offset=0x%lx, flags=0x%x\n",
          (void *)optind_pt->data->data, (unsigned long)optind_pt->offset,
          optind_pt->flags);
      // Calculate actual host address
      char *host_data = (char *)optind_pt->data->data;
      uint32_t *optind_ptr = (uint32_t *)(host_data + optind_pt->offset +
                                          PGOFFSET(interp_optind_addr));
      DEBUG_FPRINTF(stderr,
                    "ELF64: interp optind = %d (should be 1) at host addr %p\n",
                    *optind_ptr, (void *)optind_ptr);
      // Also dump a few bytes around it
      unsigned char *bytes = (unsigned char *)optind_ptr;
      DEBUG_FPRINTF(
          stderr,
          "ELF64: bytes at optind: %02x %02x %02x %02x %02x %02x %02x %02x\n",
          bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
          bytes[7]);
    } else {
      DEBUG_FPRINTF(stderr, "ELF64: optind page not mapped! pt=%p\n",
                    (void *)optind_pt);
    }
    fflush(stderr);
  }

  // For 64-bit, we skip vdso for now (it's 32-bit)
  // TODO: create 64-bit vdso
  current->mm->vdso = 0;

  // STACK TIME - 64-bit uses higher addresses
  // Allocate 2048 pages (8MB) of stack - matches Linux default stack rlimit.
  // The dynamic linker maps libraries just below the stack, so we need enough
  // pages to prevent the stack from growing into library read-only pages.
  err = _ENOMEM;
#define INIT_STACK_PAGES 2048
  page_t stack_page = pt_find_hole(current->mem, INIT_STACK_PAGES);
  if (stack_page == BAD_PAGE)
    goto beyond_hope;
  // Map all pages - the lowest one has P_GROWSDOWN for future growth
  if ((err = pt_map_nothing(current->mem, stack_page, 1,
                            P_WRITE | P_GROWSDOWN)) < 0)
    goto beyond_hope;
  if ((err = pt_map_nothing(current->mem, stack_page + 1, INIT_STACK_PAGES - 1,
                            P_WRITE)) < 0)
    goto beyond_hope;
  write_wrunlock(&current->mem->lock);

  // sp points to leave 2 pages above for guard space
  addr_t sp = ((addr_t)stack_page + INIT_STACK_PAGES - 2) << PAGE_BITS;
  DEBUG_FPRINTF(stderr, "ELF64: stack_page=%llx sp=%llx top_page=%llx\n",
                (unsigned long long)stack_page, (unsigned long long)sp,
                (unsigned long long)(stack_page + INIT_STACK_PAGES - 1));
  addr_t initial_sp = sp;

  err = _EFAULT;
  // copy strings pointed to by argv/envp/auxv
  addr_t file_addr = sp = copy_string(sp, file);
  if (sp == 0)
    goto beyond_hope;
  addr_t envp_addr = sp = args_copy(sp, envp);
  if (sp == 0)
    goto beyond_hope;
  current->mm->argv_end = sp;
  addr_t argv_addr = sp = args_copy(sp, argv);
  if (sp == 0)
    goto beyond_hope;
  current->mm->argv_start = sp;
  sp = align_stack(sp);

  addr_t platform_addr = sp = copy_string(sp, "x86_64");
  if (sp == 0)
    goto beyond_hope;

  char random[16] = {};
  get_random(random, sizeof(random));
  addr_t random_addr = sp -= sizeof(random);
  if (user_put(sp, random))
    goto beyond_hope;

  DEBUG_FPRINTF(
      stderr,
      "ELF64: file_addr=%llx argv_addr=%llx envp_addr=%llx platform=%llx "
      "random=%llx\n",
      (unsigned long long)file_addr, (unsigned long long)argv_addr,
      (unsigned long long)envp_addr, (unsigned long long)platform_addr,
      (unsigned long long)random_addr);
  DEBUG_FPRINTF(stderr,
                "ELF64: load_addr=%llx interp_base=%llx bias=%llx entry=%llx\n",
                (unsigned long long)load_addr, (unsigned long long)interp_base,
                (unsigned long long)bias,
                (unsigned long long)(bias + header.entry_point));

  // 64-bit auxiliary vector
  struct aux_ent64 aux[] = {{AX_HWCAP, 0x00000000},
                            {AX_PAGESZ, PAGE_SIZE},
                            {AX_CLKTCK, 0x64},
                            {AX_PHDR, load_addr + header.prghead_off},
                            {AX_PHENT, sizeof(struct prg_header64)},
                            {AX_PHNUM, header.phent_count},
                            {AX_BASE, interp_base},
                            {AX_FLAGS, 0},
                            {AX_ENTRY, bias + header.entry_point},
                            {AX_UID, 0},
                            {AX_EUID, 0},
                            {AX_GID, 0},
                            {AX_EGID, 0},
                            {AX_SECURE, 0},
                            {AX_RANDOM, random_addr},
                            {AX_HWCAP2, 0},
                            {AX_EXECFN, file_addr},
                            {AX_PLATFORM, platform_addr},
                            {0, 0}};

  // Calculate stack space needed - 64-bit uses 8-byte pointers
  sp -= ((argv.count + 1) + (envp.count + 1) + 1) * sizeof(uint64_t);
  sp -= sizeof(aux);
  sp &= ~0xf; // 16-byte align

  addr_t p = sp;

  // argc (64-bit)
  uint64_t argc64 = argv.count;
  if (user_put(p, argc64))
    return _EFAULT;
  p += sizeof(uint64_t);

  // argv pointers (64-bit)
  size_t argc = argv.count;
  while (argc-- > 0) {
    uint64_t ptr = argv_addr;
    if (user_put(p, ptr))
      return _EFAULT;
    argv_addr += user_strlen(argv_addr) + 1;
    p += sizeof(uint64_t);
  }
  // null terminator for argv
  uint64_t null_ptr = 0;
  if (user_put(p, null_ptr))
    return _EFAULT;
  p += sizeof(uint64_t);

  // envp pointers (64-bit)
  size_t envc = envp.count;
  while (envc-- > 0) {
    uint64_t ptr = envp_addr;
    if (user_put(p, ptr))
      return _EFAULT;
    envp_addr += user_strlen(envp_addr) + 1;
    p += sizeof(uint64_t);
  }
  // null terminator for envp
  if (user_put(p, null_ptr))
    return _EFAULT;
  p += sizeof(uint64_t);

  // auxv
  current->mm->auxv_start = p;
  if (user_put(p, aux))
    goto beyond_hope;
  p += sizeof(aux);
  current->mm->auxv_end = p;

  // Debug: dump the auxv entries we just wrote
  DEBUG_FPRINTF(stderr, "ELF64: auxv written at %llx:\n",
                (unsigned long long)current->mm->auxv_start);
  for (int i = 0; aux[i].type != 0; i++) {
    DEBUG_FPRINTF(stderr, "  aux[%d]: type=%llu value=%llx\n", i,
                  (unsigned long long)aux[i].type,
                  (unsigned long long)aux[i].value);
  }

  current->mm->stack_start = sp;
  current->cpu.rsp = sp;
  current->cpu.rip = entry;
  current->cpu.df_offset = 1; // Direction flag: 1 = forward, -1 = backward
  DEBUG_FPRINTF(stderr, "ELF64: final sp=%llx entry=%llx\n",
                (unsigned long long)sp, (unsigned long long)entry);

  // WORKAROUND: Manually perform COPY relocations that musl's linker isn't
  // handling This is a temporary fix until we figure out why COPY relocations
  // fail optind is at bias + 0xc6068 in busybox, musl's optind is at
  // interp_base + 0x9f3dc
  if (interp_base != 0) {
    addr_t bb_optind = bias + 0xc6068;          // busybox's optind COPY target
    addr_t musl_optind = interp_base + 0x9f3dc; // musl's optind source

    // Read musl's optind value
    struct pt_entry *src_pt = mem_pt(current->mem, PAGE(musl_optind));
    struct pt_entry *dst_pt = mem_pt(current->mem, PAGE(bb_optind));

    if (src_pt && src_pt->data && dst_pt && dst_pt->data) {
      char *src_data =
          (char *)src_pt->data->data + src_pt->offset + PGOFFSET(musl_optind);
      char *dst_data =
          (char *)dst_pt->data->data + dst_pt->offset + PGOFFSET(bb_optind);
      uint32_t optind_val = *(uint32_t *)src_data;
      *(uint32_t *)dst_data = optind_val;
      DEBUG_FPRINTF(
          stderr,
          "ELF64: WORKAROUND - manually copied optind=%d from musl to "
          "busybox\n",
          optind_val);
    }
  }

  current->cpu.fcw = 0x37f;

  // Clear all registers (x86_64 ABI)
  current->cpu.rax = 0;
  current->cpu.rbx = 0;
  current->cpu.rcx = 0;
  current->cpu.rdx = 0;
  current->cpu.rsi = 0;
  current->cpu.rdi = 0;
  current->cpu.rbp = 0;
  current->cpu.r8 = 0;
  current->cpu.r9 = 0;
  current->cpu.r10 = 0;
  current->cpu.r11 = 0;
  current->cpu.r12 = 0;
  current->cpu.r13 = 0;
  current->cpu.r14 = 0;
  current->cpu.r15 = 0;
  collapse_flags(&current->cpu);
  current->cpu.eflags = 0;

  err = 0;
out_free_interp:
  if (interp_name != NULL)
    free(interp_name);
  if (interp_fd != NULL && !IS_ERR(interp_fd))
    fd_close(interp_fd);
  if (interp_ph != NULL)
    free(interp_ph);
out_free_ph:
  free(ph);
  return err;

beyond_hope:
  write_wrunlock(&current->mem->lock);
  goto out_free_interp;
}
#endif

static int load_entry(struct prg_header ph, addr_t bias, struct fd *fd) {
  int err;

  addr_t addr = ph.vaddr + bias;
  addr_t offset = ph.offset;
  addr_t memsize = ph.memsize;
  addr_t filesize = ph.filesize;

  int flags = P_READ;
  if (ph.flags & PH_W)
    flags |= P_WRITE;

  if ((err = fd->ops->mmap(fd, current->mem, PAGE(addr),
                           PAGE_ROUND_UP(filesize + PGOFFSET(addr)),
                           offset - PGOFFSET(addr), flags, MMAP_PRIVATE)) < 0)
    return err;
  // TODO find a better place for these to avoid code duplication
  mem_pt(current->mem, PAGE(addr))->data->fd = fd_retain(fd);
  mem_pt(current->mem, PAGE(addr))->data->file_offset = offset - PGOFFSET(addr);

  if (memsize > filesize) {
    // put zeroes between addr + filesize and addr + memsize, call that bss
    dword_t bss_size = memsize - filesize;

    // first zero the tail from the end of the file mapping to the end
    // of the load entry or the end of the page, whichever comes first
    addr_t file_end = addr + filesize;
    dword_t tail_size = PAGE_SIZE - PGOFFSET(file_end);
    if (tail_size == PAGE_SIZE)
      // if you can calculate tail_size better and not have to do this please
      // let me know
      tail_size = 0;

    if (tail_size != 0) {
      // Unlock and lock the mem because the user functions must be
      // called without locking mem.
      write_wrunlock(&current->mem->lock);
      user_memset(file_end, 0, tail_size);
      write_wrlock(&current->mem->lock);
    }
    if (tail_size > bss_size)
      tail_size = bss_size;

    // then map the pages from after the file mapping up to and including the
    // end of bss
    if (bss_size - tail_size != 0)
      if ((err = pt_map_nothing(current->mem, PAGE_ROUND_UP(addr + filesize),
                                PAGE_ROUND_UP(bss_size - tail_size), flags)) <
          0)
        return err;
  }
  return 0;
}

static addr_t find_hole_for_elf(struct elf_header *header,
                                struct prg_header *ph) {
  struct prg_header *first = NULL, *last = NULL;
  for (int i = 0; i < header->phent_count; i++) {
    if (ph[i].type == PT_LOAD) {
      if (first == NULL)
        first = &ph[i];
      last = &ph[i];
    }
  }
  pages_t size = 0;
  if (first != NULL) {
    pages_t a = PAGE_ROUND_UP(last->vaddr + last->memsize);
    pages_t b = PAGE(first->vaddr);
    size = a - b;
  }
  return pt_find_hole(current->mem, size) << PAGE_BITS;
}

static int elf_exec(struct fd *fd, const char *file, struct exec_args argv,
                    struct exec_args envp) {
  int err = 0;

  // read the headers
  struct elf_header header;
  if ((err = read_header(fd, &header)) < 0)
    return err;
  struct prg_header *ph;
  if ((err = read_prg_headers(fd, header, &ph)) < 0)
    return err;

  // look for an interpreter
  char *interp_name = NULL;
  struct fd *interp_fd = NULL;
  struct elf_header interp_header;
  struct prg_header *interp_ph = NULL;
  for (unsigned i = 0; i < header.phent_count; i++) {
    if (ph[i].type != PT_INTERP)
      continue;
    if (interp_name) {
      // can't have two interpreters
      err = _EINVAL;
      goto out_free_interp;
    }

    interp_name = malloc(ph[i].filesize);
    err = _ENOMEM;
    if (interp_name == NULL)
      goto out_free_ph;

    // read the interpreter name out of the file
    err = _EIO;
    if (fd->ops->lseek(fd, ph[i].offset, SEEK_SET) < 0)
      goto out_free_interp;
    if (fd->ops->read(fd, interp_name, ph[i].filesize) != ph[i].filesize)
      goto out_free_interp;

    // open interpreter and read headers
    interp_fd = generic_open(interp_name, O_RDONLY, 0);
    if (IS_ERR(interp_fd)) {
      err = PTR_ERR(interp_fd);
      goto out_free_interp;
    }
    if ((err = read_header(interp_fd, &interp_header)) < 0) {
      if (err == _ENOEXEC)
        err = _ELIBBAD;
      goto out_free_interp;
    }
    if ((err = read_prg_headers(interp_fd, interp_header, &interp_ph)) < 0) {
      if (err == _ENOEXEC)
        err = _ELIBBAD;
      goto out_free_interp;
    }
  }

  // free the process's memory.
  // from this point on, if any error occurs the process will have to be
  // killed before it even starts. please don't be too sad about it, it's
  // just a process.
  //
  // general_lock protects current->mm. otherwise procfs might read the
  // pointer before it's released and then try to lock it after it's
  // released.
  lock(&current->general_lock);
  mm_release(current->mm);
  task_set_mm(current, mm_new());
  unlock(&current->general_lock);
  write_wrlock(&current->mem->lock);

  current->mm->exefile = fd_retain(fd);

  addr_t load_addr = 0; // used for AX_PHDR
  bool load_addr_set = false;
  addr_t bias = 0; // offset for loading shared libraries as executables

  // map dat shit!
  for (unsigned i = 0; i < header.phent_count; i++) {
    if (ph[i].type != PT_LOAD)
      continue;

    if (!load_addr_set && header.type == ELF_DYNAMIC) {
      // see giant comment in linux/fs/binfmt_elf.c, around line 950
      if (interp_name)
        bias = 0x56555000; // I have no idea how this number was arrived at
      else
        bias = find_hole_for_elf(&header, ph);
    }

    if ((err = load_entry(ph[i], bias, fd)) < 0)
      goto beyond_hope;

    // load_addr is used to get a value for AX_PHDR et al
    if (!load_addr_set) {
      load_addr = bias + ph[i].vaddr - ph[i].offset;
      load_addr_set = true;
    }

    // we have to know where the brk starts
    addr_t brk = bias + ph[i].vaddr + ph[i].memsize;
    if (brk > current->mm->start_brk)
      current->mm->start_brk = current->mm->brk = BYTES_ROUND_UP(brk);
  }

  addr_t entry = bias + header.entry_point;
  addr_t interp_base = 0;

  if (interp_name) {
    // map dat shit! interpreter edition
    interp_base = find_hole_for_elf(&interp_header, interp_ph);
    for (int i = interp_header.phent_count - 1; i >= 0; i--) {
      if (interp_ph[i].type != PT_LOAD)
        continue;
      if ((err = load_entry(interp_ph[i], interp_base, interp_fd)) < 0)
        goto beyond_hope;
    }
    entry = interp_base + interp_header.entry_point;
  }

  // map vdso
  err = _ENOMEM;
  pages_t vdso_pages = sizeof(vdso_data) >> PAGE_BITS;
  // FIXME disgusting hack: musl's dynamic linker has a one-page hole, and
  // I'd rather not put the vdso in that hole. so find a two-page hole and
  // add one.
  page_t vdso_page = pt_find_hole(current->mem, vdso_pages + 1);
  if (vdso_page == BAD_PAGE)
    goto beyond_hope;
  vdso_page += 1;
  if ((err = pt_map(current->mem, vdso_page, vdso_pages, (void *)vdso_data, 0,
                    0)) < 0)
    goto beyond_hope;
  mem_pt(current->mem, vdso_page)->data->name = "[vdso]";
  current->mm->vdso = vdso_page << PAGE_BITS;
  addr_t vdso_entry =
      current->mm->vdso + ((struct elf_header *)vdso_data)->entry_point;

  // map 3 empty "vvar" pages to satisfy ptraceomatic
  page_t vvar_page = pt_find_hole(current->mem, VVAR_PAGES);
  if (vvar_page == BAD_PAGE)
    goto beyond_hope;
  if ((err = pt_map_nothing(current->mem, vvar_page, VVAR_PAGES, 0)) < 0)
    goto beyond_hope;
  mem_pt(current->mem, vvar_page)->data->name = "[vvar]";

  // STACK TIME!

  // allocate 1 page of stack at 0xffffd, and let it grow down
  if ((err = pt_map_nothing(current->mem, 0xffffd, 1, P_WRITE | P_GROWSDOWN)) <
      0)
    goto beyond_hope;
  // that was the last memory mapping
  write_wrunlock(&current->mem->lock);
  dword_t sp = 0xffffe000;
  // on 32-bit linux, there's 4 empty bytes at the very bottom of the stack.
  // on 64-bit linux, there's 8. make ptraceomatic happy. (a major theme in this
  // file)
  sp -= sizeof(void *);

  err = _EFAULT;
  // first, copy stuff pointed to by argv/envp/auxv
  // filename, argc, argv
  addr_t file_addr = sp = copy_string(sp, file);
  if (sp == 0)
    goto beyond_hope;
  addr_t envp_addr = sp = args_copy(sp, envp);
  if (sp == 0)
    goto beyond_hope;
  current->mm->argv_end = sp;
  addr_t argv_addr = sp = args_copy(sp, argv);
  if (sp == 0)
    goto beyond_hope;
  current->mm->argv_start = sp;
  sp = align_stack(sp);

#ifdef ISH_GUEST_64BIT
  addr_t platform_addr = sp = copy_string(sp, "x86_64");
#else
  addr_t platform_addr = sp = copy_string(sp, "i686");
#endif
  if (sp == 0)
    goto beyond_hope;
  // 16 random bytes so no system call is needed to seed a userspace RNG
  char random[16] = {};
  get_random(random,
             sizeof(random)); // if this fails, eh, no one's really using it
  addr_t random_addr = sp -= sizeof(random);
  if (user_put(sp, random))
    goto beyond_hope;

  // the way linux aligns the stack at this point is kinda funky
  // calculate how much space is needed for argv, envp, and auxv, subtract
  // that from sp, then align, then copy argv/envp/auxv from that down

  // declare elf aux now so we can know how big it is
  struct aux_ent aux[] = {{AX_SYSINFO, vdso_entry},
                          {AX_SYSINFO_EHDR, current->mm->vdso},
                          {AX_HWCAP, 0x00000000}, // suck that
                          {AX_PAGESZ, PAGE_SIZE},
                          {AX_CLKTCK, 0x64},
                          {AX_PHDR, load_addr + header.prghead_off},
                          {AX_PHENT, sizeof(struct prg_header)},
                          {AX_PHNUM, header.phent_count},
                          {AX_BASE, interp_base},
                          {AX_FLAGS, 0},
                          {AX_ENTRY, bias + header.entry_point},
                          {AX_UID, 0},
                          {AX_EUID, 0},
                          {AX_GID, 0},
                          {AX_EGID, 0},
                          {AX_SECURE, 0},
                          {AX_RANDOM, random_addr},
                          {AX_HWCAP2, 0}, // suck that too
                          {AX_EXECFN, file_addr},
                          {AX_PLATFORM, platform_addr},
                          {0, 0}};
  sp -= ((argv.count + 1) + (envp.count + 1) + 1) * sizeof(dword_t);
  sp -= sizeof(aux);
  sp &= ~0xf;

  // now copy down, start using p so sp is preserved
  addr_t p = sp;

  // argc
  if (user_put(p, argv.count))
    return _EFAULT;
  p += sizeof(dword_t);

  // argv
  size_t argc = argv.count;
  while (argc-- > 0) {
    if (user_put(p, argv_addr))
      return _EFAULT;
    argv_addr += user_strlen(argv_addr) + 1;
    p += sizeof(dword_t); // null terminator
  }
  p += sizeof(dword_t); // null terminator

  // envp
  size_t envc = envp.count;
  while (envc-- > 0) {
    if (user_put(p, envp_addr))
      return _EFAULT;
    envp_addr += user_strlen(envp_addr) + 1;
    p += sizeof(dword_t);
  }
  p += sizeof(dword_t); // null terminator

  // copy auxv
  current->mm->auxv_start = p;
  if (user_put(p, aux))
    goto beyond_hope;
  p += sizeof(aux);
  current->mm->auxv_end = p;

  current->mm->stack_start = sp;
  current->cpu.esp = sp;
  current->cpu.eip = entry;
  current->cpu.fcw = 0x37f;

  // This code was written when I discovered that the glibc entry point
  // interprets edx as the address of a function to call on exit, as
  // specified in the ABI. This register is normally set by the dynamic
  // linker, so everything works fine until you run a static executable.
  current->cpu.eax = 0;
  current->cpu.ebx = 0;
  current->cpu.ecx = 0;
  current->cpu.edx = 0;
  current->cpu.esi = 0;
  current->cpu.edi = 0;
  current->cpu.ebp = 0;
  collapse_flags(&current->cpu);
  current->cpu.eflags = 0;

  err = 0;
out_free_interp:
  if (interp_name != NULL)
    free(interp_name);
  if (interp_fd != NULL && !IS_ERR(interp_fd))
    fd_close(interp_fd);
  if (interp_ph != NULL)
    free(interp_ph);
out_free_ph:
  free(ph);
  return err;

beyond_hope:
  // TODO force sigsegv
  write_wrunlock(&current->mem->lock);
  goto out_free_interp;
}

static size_t args_size(struct exec_args args) {
  const char *args_end = args.args;
  for (size_t i = 0; i < args.count; i++) {
    args_end += strlen(args_end) + 1;
  }
  // don't forget the very last null terminator
  assert(args_end[0] == '\0');
  args_end++;
  return args_end - args.args;
}

static inline addr_t align_stack(addr_t sp) { return sp & ~0xf; }

static inline addr_t copy_string(addr_t sp, const char *string) {
  sp -= strlen(string) + 1;
  if (user_write_string(sp, string))
    return 0;
  return sp;
}

static inline addr_t args_copy(addr_t sp, struct exec_args args) {
  size_t size = args_size(args);
  sp -= size;
  if (user_write(sp, args.args, size))
    return 0;
  return sp;
}

static inline ssize_t user_strlen(addr_t p) {
  size_t i = 0;
  char c;
  do {
    if (user_get(p + i, c))
      return -1;
    i++;
  } while (c != '\0');
  return i - 1;
}

static inline int user_memset(addr_t start, byte_t val, dword_t len) {
  while (len--)
    if (user_put(start++, val))
      return 1;
  return 0;
}

static int format_exec(struct fd *fd, const char *file, struct exec_args argv,
                       struct exec_args envp) {
#ifdef ISH_GUEST_64BIT
  // For 64-bit guest, try 64-bit ELF first
  int err = elf_exec64(fd, file, argv, envp);
  if (err != _ENOEXEC)
    return err;
#else
  int err = elf_exec(fd, file, argv, envp);
  if (err != _ENOEXEC)
    return err;
#endif
  // other formats would go here
  return _ENOEXEC;
}

static int shebang_exec(struct fd *fd, const char *file, struct exec_args argv,
                        struct exec_args envp) {
  // read the first 128 bytes to get the shebang line out of
  if (fd->ops->lseek(fd, 0, SEEK_SET))
    return _EIO;
  char header[128];
  int size = fd->ops->read(fd, header, sizeof(header) - 1);
  if (size < 0)
    return _EIO;
  header[size] = '\0';

  // only look at the first line
  char *newline = strchr(header, '\n');
  if (newline == NULL)
    return _ENOEXEC;
  *newline = '\0';

  // format: #![spaces]interpreter[spaces]argument[spaces]
  char *p = header;
  if (p[0] != '#' || p[1] != '!')
    return _ENOEXEC;
  p += 2;
  while (*p == ' ')
    p++;
  if (*p == '\0')
    return _ENOEXEC;

  char *interpreter = p;
  while (*p != ' ' && *p != '\0')
    p++;
  if (*p != '\0') {
    *p++ = '\0';
    while (*p == ' ')
      p++;
  }

  char *argument = p;
  // strip trailing whitespace
  p = strchr(p, '\0') - 1;
  while (*p == ' ')
    *p-- = '\0';
  if (*argument == '\0')
    argument = NULL;

  struct exec_args argv_rest = {
      .count = argv.count - 1,
      .args = argv.args + strlen(argv.args) + 1,
  };
  size_t args_rest_size = args_size(argv_rest);
  size_t extra_args_size = strlen(interpreter) + 1 + strlen(file) + 1;
  if (argument)
    extra_args_size += strlen(argument) + 1;
  if (args_rest_size + extra_args_size >= ARGV_MAX)
    return _E2BIG;

  char new_argv_buf[ARGV_MAX];
  struct exec_args new_argv = {.args = new_argv_buf};
  size_t n = 0;
  strcpy(new_argv_buf, interpreter);
  new_argv.count++;
  n += strlen(interpreter) + 1;
  if (argument) {
    strcpy(new_argv_buf + n, argument);
    new_argv.count++;
    n += strlen(argument) + 1;
  }
  strcpy(new_argv_buf + n, file);
  n += strlen(file) + 1;
  new_argv.count++;
  memcpy(new_argv_buf + n, argv_rest.args, args_rest_size);
  new_argv.count += argv_rest.count;

  struct fd *interpreter_fd = generic_open(interpreter, O_RDONLY_, 0);
  if (IS_ERR(interpreter_fd))
    return PTR_ERR(interpreter_fd);
  int err = format_exec(interpreter_fd, interpreter, new_argv, envp);
  fd_close(interpreter_fd);
  return err;
}

int __do_execve(const char *file, struct exec_args argv,
                struct exec_args envp) {
  struct fd *fd = generic_open(file, O_RDONLY, 0);
  if (IS_ERR(fd))
    return PTR_ERR(fd);

  struct statbuf stat;
  int err = fd->mount->fs->fstat(fd, &stat);
  if (err < 0) {
    fd_close(fd);
    return err;
  }

  // if nobody has permission to execute, it should be safe to not execute
  if (!(stat.mode & 0111)) {
    fd_close(fd);
    return _EACCES;
  }

  err = format_exec(fd, file, argv, envp);
  if (err == _ENOEXEC) {
    err = shebang_exec(fd, file, argv, envp);
  }
  fd_close(fd);
  if (err < 0)
    return err;

  // setuid/setgid
  if (stat.mode & S_ISUID) {
    current->suid = current->euid;
    current->euid = stat.uid;
  }
  if (stat.mode & S_ISGID) {
    current->sgid = current->egid;
    current->egid = stat.gid;
  }

  // save current->comm
  lock(&current->general_lock);
  const char *basename = strrchr(file, '/');
  if (basename == NULL)
    basename = file;
  else
    basename++;
  strncpy(current->comm, basename, sizeof(current->comm));
  unlock(&current->general_lock);

  update_thread_name();

  // cloexec
  // consider putting this in fd.c?
  fdtable_do_cloexec(current->files);

  // reset signal handlers
  lock(&current->sighand->lock);
  for (int sig = 0; sig < NUM_SIGS; sig++) {
    struct sigaction_ *action = &current->sighand->action[sig];
    if (action->handler != SIG_IGN_)
      action->handler = SIG_DFL_;
  }
  current->sighand->altstack = 0;
  unlock(&current->sighand->lock);

  current->did_exec = true;
  vfork_notify(current);

  if (current->ptrace.traced) {
    lock(&pids_lock);
    send_signal(current, SIGTRAP_,
                (struct siginfo_){
                    .code = SI_USER_,
                    .kill.pid = current->pid,
                    .kill.uid = current->uid,
                });
    unlock(&pids_lock);
  }

  return 0;
}

int do_execve(const char *file, size_t argc, const char *argv_p,
              const char *envp_p) {
  struct exec_args argv = {.count = argc, .args = argv_p};
  struct exec_args envp = {.args = envp_p};
  while (*envp_p != '\0') {
    envp_p += strlen(envp_p) + 1;
    envp.count++;
  }
  return __do_execve(file, argv, envp);
}

static ssize_t user_read_string_array(addr_t addr, char *buf, size_t max) {
  size_t i = 0;
  size_t p = 0;
  for (;;) {
    addr_t str_addr;
    if (user_get(addr + i * sizeof(addr_t), str_addr))
      return _EFAULT;
    if (str_addr == 0)
      break;
    size_t str_p = 0;
    for (;;) {
      if (p >= max)
        return _E2BIG;
      if (user_get(str_addr + str_p, buf[p]))
        return _EFAULT;
      str_p++;
      p++;
      if (buf[p - 1] == '\0')
        break;
    }
    i++;
  }
  if (p >= max)
    return _E2BIG;
  buf[p] = '\0';
  return i;
}

dword_t sys_execve(addr_t filename_addr, addr_t argv_addr, addr_t envp_addr) {
  char filename[MAX_PATH];
  if (user_read_string(filename_addr, filename, sizeof(filename)))
    return _EFAULT;

  int err = _ENOMEM;
  char *argv = malloc(ARGV_MAX);
  if (argv == NULL)
    goto err_free_argv;
  ssize_t argc = user_read_string_array(argv_addr, argv, ARGV_MAX);
  if (argc < 0) {
    err = argc;
    goto err_free_argv;
  }

  char *envp = malloc(ARGV_MAX);
  if (envp == NULL)
    goto err_free_envp;
  if (envp_addr != 0) {
    err = user_read_string_array(envp_addr, envp, ARGV_MAX);
    if (err < 0)
      goto err_free_envp;
  } else {
    // Do not take advantage of this nonstandard and nonportable misfeature!
    // - Michael Kerrisk, execve(2)
    envp[0] = envp[1] = '\0';
  }

  STRACE("execve(\"%.1000s\", {", filename);
  const char *args = argv;
  while (*args != '\0') {
    STRACE("\"%.1000s\", ", args);
    args += strlen(args) + 1;
  }
  STRACE("}, {");
  args = envp;
  while (*args != '\0') {
    STRACE("\"%.1000s\", ", args);
    args += strlen(args) + 1;
  }
  STRACE("})");

  err = do_execve(filename, argc, argv, envp);

err_free_envp:
  free(envp);
err_free_argv:
  free(argv);
  return err;
}
