#include "kernel/signal.h"
#include "task.h"
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "kernel/calls.h"
#include "kernel/random.h"
#include "kernel/errno.h"
#include "fs/fd.h"
#include "kernel/elf.h"
#include "kernel/vdso.h"
#include "tools/ptraceomatic-config.h"

#define ARGV_MAX 32 * PAGE_SIZE

struct exec_args {
    // number of arguments
    size_t count;
    // series of count null-terminated strings, plus an extra null for good measure
    const char *args;
};

static inline addr_t align_stack(addr_t sp);
static inline ssize_t user_strlen(addr_t p);
static inline int user_memset(addr_t start, byte_t val, dword_t len);
static inline addr_t copy_string(addr_t sp, const char *string);
static inline addr_t args_copy(addr_t sp, struct exec_args args);
static size_t args_size(struct exec_args args);

static int read_header(struct fd *fd, struct elf_header_unified *header) {
    int err;
    if (fd->ops->lseek(fd, 0, SEEK_SET))
        return _EIO;
    
    // First read the common part to determine bitness
    byte_t temp_header[24]; // Size of common fields before bitness-dependent fields
    if ((err = fd->ops->read(fd, temp_header, sizeof(temp_header))) != sizeof(temp_header)) {
        if (err < 0)
            return _EIO;
        return _ENOEXEC;
    }
    
    // Extract bitness from the common part
    byte_t bitness = temp_header[4];
    
    // Reset file position and read the appropriate structure
    if (fd->ops->lseek(fd, 0, SEEK_SET))
        return _EIO;
        
    if (bitness == ELF_32BIT) {
        struct elf_header header32;
        if ((err = fd->ops->read(fd, &header32, sizeof(header32))) != sizeof(header32)) {
            if (err < 0)
                return _EIO;
            return _ENOEXEC;
        }
        
        // Convert 32-bit header to unified format
        header->magic = header32.magic;
        header->bitness = header32.bitness;
        header->endian = header32.endian;
        header->elfversion1 = header32.elfversion1;
        header->abi = header32.abi;
        header->abi_version = header32.abi_version;
        memcpy(header->padding, header32.padding, sizeof(header32.padding));
        header->type = header32.type;
        header->machine = header32.machine;
        header->elfversion2 = header32.elfversion2;
        header->entry_point = header32.entry_point;
        header->prghead_off = header32.prghead_off;
        header->secthead_off = header32.secthead_off;
        header->flags = header32.flags;
        header->header_size = header32.header_size;
        header->phent_size = header32.phent_size;
        header->phent_count = header32.phent_count;
        header->shent_size = header32.shent_size;
        header->shent_count = header32.shent_count;
        header->sectname_index = header32.sectname_index;
        
    } else if (bitness == ELF_64BIT) {
        struct elf_header_64 header64;
        if ((err = fd->ops->read(fd, &header64, sizeof(header64))) != sizeof(header64)) {
            if (err < 0)
                return _EIO;
            return _ENOEXEC;
        }
        
        // Convert 64-bit header to unified format
        header->magic = header64.magic;
        header->bitness = header64.bitness;
        header->endian = header64.endian;
        header->elfversion1 = header64.elfversion1;
        header->abi = header64.abi;
        header->abi_version = header64.abi_version;
        memcpy(header->padding, header64.padding, sizeof(header64.padding));
        header->type = header64.type;
        header->machine = header64.machine;
        header->elfversion2 = header64.elfversion2;
        header->entry_point = header64.entry_point;
        header->prghead_off = header64.prghead_off;
        header->secthead_off = header64.secthead_off;
        header->flags = header64.flags;
        header->header_size = header64.header_size;
        header->phent_size = header64.phent_size;
        header->phent_count = header64.phent_count;
        header->shent_size = header64.shent_size;
        header->shent_count = header64.shent_count;
        header->sectname_index = header64.sectname_index;
        
    } else {
        return _ENOEXEC;
    }
    
    if (memcmp(&header->magic, ELF_MAGIC, sizeof(header->magic)) != 0
            || (header->type != ELF_EXECUTABLE && header->type != ELF_DYNAMIC)
            || header->endian != ELF_LITTLEENDIAN
            || header->elfversion1 != 1)
        return _ENOEXEC;
    
    // Validate bitness and machine type
#ifdef ISH_64BIT
    // 64-bit builds can run both 32-bit and 64-bit programs
    if ((header->bitness == ELF_32BIT && header->machine != ELF_X86) ||
        (header->bitness == ELF_64BIT && header->machine != ELF_X86_64) ||
        (header->bitness != ELF_32BIT && header->bitness != ELF_64BIT))
        return _ENOEXEC;
#else
    // 32-bit builds only support 32-bit programs
    if (header->bitness != ELF_32BIT || header->machine != ELF_X86)
        return _ENOEXEC;
#endif
    return 0;
}

static int read_prg_headers(struct fd *fd, struct elf_header_unified header, struct prg_header_unified **ph_out) {
    struct prg_header_unified *ph = malloc(sizeof(struct prg_header_unified) * header.phent_count);
    if (ph == NULL)
        return _ENOMEM;

    if (fd->ops->lseek(fd, header.prghead_off, SEEK_SET) < 0) {
        free(ph);
        return _EIO;
    }

    if (header.bitness == ELF_32BIT) {
        // Read 32-bit program headers
        ssize_t ph_size = sizeof(struct prg_header) * header.phent_count;
        struct prg_header *ph32 = malloc(ph_size);
        if (ph32 == NULL) {
            free(ph);
            return _ENOMEM;
        }
        
        if (fd->ops->read(fd, ph32, ph_size) != ph_size) {
            free(ph32);
            free(ph);
            if (errno != 0)
                return _EIO;
            return _ENOEXEC;
        }
        
        // Convert 32-bit program headers to unified format
        for (int i = 0; i < header.phent_count; i++) {
            ph[i].type = ph32[i].type;
            ph[i].flags = ph32[i].flags;
            ph[i].offset = ph32[i].offset;
            ph[i].vaddr = ph32[i].vaddr;
            ph[i].paddr = ph32[i].paddr;
            ph[i].filesize = ph32[i].filesize;
            ph[i].memsize = ph32[i].memsize;
            ph[i].alignment = ph32[i].alignment;
        }
        
        free(ph32);
        
    } else if (header.bitness == ELF_64BIT) {
        // Read 64-bit program headers
        ssize_t ph_size = sizeof(struct prg_header_64) * header.phent_count;
        struct prg_header_64 *ph64 = malloc(ph_size);
        if (ph64 == NULL) {
            free(ph);
            return _ENOMEM;
        }
        
        if (fd->ops->read(fd, ph64, ph_size) != ph_size) {
            free(ph64);
            free(ph);
            if (errno != 0)
                return _EIO;
            return _ENOEXEC;
        }
        
        // Convert 64-bit program headers to unified format
        for (int i = 0; i < header.phent_count; i++) {
            ph[i].type = ph64[i].type;
            ph[i].flags = ph64[i].flags;
            ph[i].offset = ph64[i].offset;
            ph[i].vaddr = ph64[i].vaddr;
            ph[i].paddr = ph64[i].paddr;
            ph[i].filesize = ph64[i].filesize;
            ph[i].memsize = ph64[i].memsize;
            ph[i].alignment = ph64[i].alignment;
        }
        
        free(ph64);
        
    } else {
        free(ph);
        return _ENOEXEC;
    }

    *ph_out = ph;
    return 0;
}

static int load_entry(struct prg_header_unified ph, addr_t bias, struct fd *fd) {
    int err;

    addr_t addr = ph.vaddr + bias;
    addr_t offset = ph.offset;
    addr_t memsize = ph.memsize;
    addr_t filesize = ph.filesize;

    int flags = P_READ;
    if (ph.flags & PH_W) flags |= P_WRITE;

    TRACE_memory("Loading ELF segment: vaddr=0x%llx, bias=0x%llx, final_addr=0x%llx, filesize=0x%llx, memsize=0x%llx, flags=0x%x\n",
                 ph.vaddr, bias, addr, filesize, memsize, flags);

    if ((err = fd->ops->mmap(fd, current->mem, PAGE(addr),
                    PAGE_ROUND_UP(filesize + PGOFFSET(addr)),
                    offset - PGOFFSET(addr), flags, MMAP_PRIVATE)) < 0) {
        TRACE_memory("mmap failed for addr=0x%llx, pages=%d, error=%d\n", addr, PAGE_ROUND_UP(filesize + PGOFFSET(addr)), err);
        return err;
    }
    
    TRACE_memory("mmap succeeded for addr=0x%llx, pages=%d\n", addr, PAGE_ROUND_UP(filesize + PGOFFSET(addr)));
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
            // if you can calculate tail_size better and not have to do this please let me know
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

        // then map the pages from after the file mapping up to and including the end of bss
        if (bss_size - tail_size != 0)
            if ((err = pt_map_nothing(current->mem, PAGE_ROUND_UP(addr + filesize),
                    PAGE_ROUND_UP(bss_size - tail_size), flags)) < 0)
                return err;
    }
    return 0;
}

static addr_t find_hole_for_elf(struct elf_header_unified *header, struct prg_header_unified *ph) {
    struct prg_header_unified *first = NULL, *last = NULL;
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
    
#ifdef ISH_64BIT
    if (header->bitness == ELF_64BIT) {
        // For 64-bit programs, find holes in the 64-bit address space
        // Use a simple approach: start at high 64-bit addresses and work down
        // This matches Linux's typical mmap behavior for 64-bit processes
        for (page_t start_page = 0x7ffe00000; start_page > 0x100000; start_page -= 0x10000) {
            if (pt_is_hole(current->mem, start_page, size)) {
                return start_page << PAGE_BITS;
            }
        }
    }
#endif
    
    // Fallback to 32-bit address space or when above fails
    return pt_find_hole(current->mem, size) << PAGE_BITS;
}

static int elf_exec(struct fd *fd, const char *file, struct exec_args argv, struct exec_args envp) {
    fprintf(stderr, "elf_exec: Loading %s\n", file);
    TRACE_memory("elf_exec called for file: %s\n", file);
    int err = 0;

    // read the headers
    struct elf_header_unified header;
    if ((err = read_header(fd, &header)) < 0) {
        TRACE_memory("read_header failed for file: %s, error: %d\n", file, err);
        return err;
    }
    TRACE_memory("read_header succeeded for file: %s\n", file);
    fprintf(stderr, "elf_exec: ELF bitness=%d (1=32bit, 2=64bit)\n", header.bitness);
    struct prg_header_unified *ph;
    if ((err = read_prg_headers(fd, header, &ph)) < 0)
        return err;

    // look for an interpreter
    char *interp_name = NULL;
    struct fd *interp_fd = NULL;
    struct elf_header_unified interp_header;
    struct prg_header_unified *interp_ph = NULL;
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
            if (err == _ENOEXEC) err = _ELIBBAD;
            goto out_free_interp;
        }
        if ((err = read_prg_headers(interp_fd, interp_header, &interp_ph)) < 0) {
            if (err == _ENOEXEC) err = _ELIBBAD;
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
#ifdef ISH_64BIT
                bias = 0x555555554000ULL; // 64-bit load address for PIE executables
#else
                bias = 0x56555000; // I have no idea how this number was arrived at
#endif
            else
                bias = find_hole_for_elf(&header, ph);
                
            // Debug: Log bias calculation
            FILE *f = fopen("/tmp/debug_exec.txt", "a");
            if (f) { 
                fprintf(f, "ELF type: %d (ELF_DYNAMIC=%d), interp_name: %s, bias: 0x%llx\n", 
                        header.type, ELF_DYNAMIC, interp_name ? interp_name : "NULL", (unsigned long long)bias);
                fclose(f); 
            }
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
        
        // Debug: Log interpreter loading
        FILE *f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { 
            fprintf(f, "Interpreter: %s, bitness: %d, interp_base: 0x%llx, entry_point: 0x%llx\n", 
                    interp_name, interp_header.bitness, (unsigned long long)interp_base, (unsigned long long)interp_header.entry_point);
            fclose(f); 
        }
        
        for (int i = interp_header.phent_count - 1; i >= 0; i--) {
            if (interp_ph[i].type != PT_LOAD)
                continue;
            if ((err = load_entry(interp_ph[i], interp_base, interp_fd)) < 0)
                goto beyond_hope;
        }
        entry = interp_base + interp_header.entry_point;
        
        // Debug: Log final entry point
        f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { 
            fprintf(f, "Final entry point: 0x%llx (interp_base + interp_header.entry_point)\n", (unsigned long long)entry);
            fclose(f); 
        }
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
    if ((err = pt_map(current->mem, vdso_page, vdso_pages, (void *) vdso_data, 0, 0)) < 0)
        goto beyond_hope;
    mem_pt(current->mem, vdso_page)->data->name = "[vdso]";
    current->mm->vdso = vdso_page << PAGE_BITS;
    addr_t vdso_entry = current->mm->vdso + ((struct elf_header *) vdso_data)->entry_point;

    // map 3 empty "vvar" pages to satisfy ptraceomatic
    page_t vvar_page = pt_find_hole(current->mem, VVAR_PAGES);
    if (vvar_page == BAD_PAGE)
        goto beyond_hope;
    if ((err = pt_map_nothing(current->mem, vvar_page, VVAR_PAGES, 0)) < 0)
        goto beyond_hope;
    mem_pt(current->mem, vvar_page)->data->name = "[vvar]";

    // STACK TIME!

    // allocate 1 page of stack 
#ifdef ISH_64BIT
    // allocate in high memory for 64-bit (around 0x7fffff000)
    if ((err = pt_map_nothing(current->mem, 0x7fffff, 1, P_WRITE | P_GROWSDOWN)) < 0)
        goto beyond_hope;
    // ALSO map 32-bit stack region for ESP compatibility
    // This prevents segfault when 32-bit instructions use ESP instead of RSP
    // Map at 0xfffff000 (where the actual failure occurs)
    if ((err = pt_map_nothing(current->mem, 0xfffff, 1, P_WRITE | P_GROWSDOWN)) < 0)
        goto beyond_hope;
    addr_t sp = 0x7fffffff8;  // Start 8 bytes from the top of the page
    // on 64-bit linux, there's 8 empty bytes at the very bottom of the stack
    // (these are already accounted for by starting at 0x7fffffff8)
#else
    // allocate at 0xffffd for 32-bit, and let it grow down
    if ((err = pt_map_nothing(current->mem, 0xffffd, 1, P_WRITE | P_GROWSDOWN)) < 0)
        goto beyond_hope;
    addr_t sp = 0xffffe000;
    // on 32-bit linux, there's 4 empty bytes at the very bottom of the stack
    sp -= sizeof(void *);
#endif
    
    // that was the last memory mapping - unlock once for both branches
    write_wrunlock(&current->mem->lock);

    err = _EFAULT;
    // first, copy stuff pointed to by argv/envp/auxv
    // filename, argc, argv
    addr_t file_addr = sp = copy_string(sp, file);
    if (sp == 0)
        goto beyond_hope_unlocked;
    addr_t envp_addr = sp = args_copy(sp, envp);
    if (sp == 0)
        goto beyond_hope_unlocked;
    current->mm->argv_end = sp;
    addr_t argv_addr = sp = args_copy(sp, argv);
    if (sp == 0)
        goto beyond_hope_unlocked;
    current->mm->argv_start = sp;
    sp = align_stack(sp);

#ifdef ISH_64BIT
    addr_t platform_addr = sp = copy_string(sp, "x86_64");
#else
    addr_t platform_addr = sp = copy_string(sp, "i686");
#endif
    if (sp == 0)
        goto beyond_hope_unlocked;
    // 16 random bytes so no system call is needed to seed a userspace RNG
    char random[16] = {};
    get_random(random, sizeof(random)); // if this fails, eh, no one's really using it
    addr_t random_addr = sp -= sizeof(random);
    // Debug: Log the random bytes
    FILE *rf = fopen("/tmp/debug_exec.txt", "a");
    if (rf) { 
        fprintf(rf, "Random bytes at 0x%llx: ", (unsigned long long)random_addr);
        for (int i = 0; i < 16; i++) fprintf(rf, "%02x", (unsigned char)random[i]);
        fprintf(rf, "\n");
        // Also check if these bytes contain our problematic address
        uint64_t *p64 = (uint64_t*)random;
        fprintf(rf, "As 64-bit values: 0x%llx 0x%llx\n", (unsigned long long)p64[0], (unsigned long long)p64[1]);
        fclose(rf); 
    }
    if (user_put(sp, random)) {
        goto beyond_hope_unlocked;
    }

    // the way linux aligns the stack at this point is kinda funky
    // calculate how much space is needed for argv, envp, and auxv, subtract
    // that from sp, then align, then copy argv/envp/auxv from that down

    // declare elf aux now so we can know how big it is
    // Use different aux vector structures for 32-bit vs 64-bit programs
    size_t aux_size;
    // Debug: Log which path we're taking
    FILE *f = fopen("/tmp/debug_exec.txt", "a");
    if (f) { fprintf(f, "Program bitness: %d (ELF_64BIT=%d)\n", header.bitness, ELF_64BIT); fclose(f); }
    
    if (header.bitness == ELF_64BIT) {
        // 64-bit auxiliary vector
        f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { 
            fprintf(f, "Using 64-bit auxiliary vector, entry=0x%llx, interp_base=0x%llx\n", 
                    (unsigned long long)(bias + header.entry_point), (unsigned long long)interp_base);
            fclose(f); 
        }
        struct aux_ent_64 aux[] = {
            // {AX_SYSINFO, vdso_entry},  // Disable VDSO for 64-bit for now
            // {AX_SYSINFO_EHDR, current->mm->vdso},
            {AX_HWCAP, 0x00000000}, // suck that
            {AX_PAGESZ, PAGE_SIZE},
            {AX_CLKTCK, 0x64},
            {AX_PHDR, load_addr + header.prghead_off},
            {AX_PHENT, sizeof(struct prg_header_64)},
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
            {0, 0}
        };
        aux_size = sizeof(aux);
        sp -= ((argv.count + 1) + (envp.count + 1) + 1) * sizeof(addr_t);
        sp -= aux_size;
        sp &=~ 0xf;
        
        // now copy down, start using p so sp is preserved
        addr_t p = sp;

        // argc
        if (user_put(p, argv.count)) {
            return _EFAULT;
        }
        p += sizeof(addr_t);

        // argv
        size_t argc = argv.count;
        while (argc-- > 0) {
            if (user_put(p, argv_addr))
                return _EFAULT;
            argv_addr += user_strlen(argv_addr) + 1;
            p += sizeof(addr_t); // move to next pointer slot
        }
        p += sizeof(addr_t); // null terminator

        // envp
        size_t envc = envp.count;
        while (envc-- > 0) {
            if (user_put(p, envp_addr))
                return _EFAULT;
            envp_addr += user_strlen(envp_addr) + 1;
            p += sizeof(addr_t);
        }
        p += sizeof(addr_t); // null terminator

        // copy auxv (64-bit version)
        current->mm->auxv_start = p;
        if (user_put(p, aux))
            goto beyond_hope_unlocked;
        p += aux_size;
        current->mm->auxv_end = p;
        
        // Debug: Log auxiliary vector contents
        FILE *af = fopen("/tmp/debug_exec.txt", "a");
        if (af) {
            fprintf(af, "64-bit auxiliary vector at 0x%llx:\n", (unsigned long long)current->mm->auxv_start);
            for (size_t i = 0; i < sizeof(aux)/sizeof(aux[0]); i++) {
                fprintf(af, "  aux[%zu]: type=0x%llx, value=0x%llx\n", i, 
                        (unsigned long long)aux[i].type, (unsigned long long)aux[i].value);
            }
            fclose(af);
        }
        
    } else {
        // 32-bit auxiliary vector (original)
        f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { fprintf(f, "Using 32-bit auxiliary vector\n"); fclose(f); }
        struct aux_ent aux[] = {
            {AX_SYSINFO, vdso_entry},
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
            {0, 0}
        };
        aux_size = sizeof(aux);
        sp -= ((argv.count + 1) + (envp.count + 1) + 1) * sizeof(addr_t);
        sp -= aux_size;
        sp &=~ 0xf;
        
        // now copy down, start using p so sp is preserved
        addr_t p = sp;

        // argc
        if (user_put(p, argv.count)) {
            return _EFAULT;
        }
        p += sizeof(addr_t);

        // argv
        size_t argc = argv.count;
        while (argc-- > 0) {
            if (user_put(p, argv_addr))
                return _EFAULT;
            argv_addr += user_strlen(argv_addr) + 1;
            p += sizeof(addr_t); // move to next pointer slot
        }
        p += sizeof(addr_t); // null terminator

        // envp
        size_t envc = envp.count;
        while (envc-- > 0) {
            if (user_put(p, envp_addr))
                return _EFAULT;
            envp_addr += user_strlen(envp_addr) + 1;
            p += sizeof(addr_t);
        }
        p += sizeof(addr_t); // null terminator

        // copy auxv (32-bit version)
        current->mm->auxv_start = p;
        if (user_put(p, aux))
            goto beyond_hope_unlocked;
        p += aux_size;
        current->mm->auxv_end = p;
    }

    current->mm->stack_start = sp;
    
    // Initialize registers based on the PROGRAM's bitness, not iSH's build mode
    if (header.bitness == ELF_64BIT) {
        // 64-bit program initialization
#ifdef ISH_64BIT
        // Debug: Log 64-bit program initialization
        FILE *f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { fprintf(f, "64-bit program: sp=0x%llx, entry=0x%llx\n", (unsigned long long)sp, (unsigned long long)entry); fclose(f); }
        // Initialize all 16 registers (RAX-RDI + R8-R15) for 64-bit programs
        for (int i = 0; i < 16; i++) {
            current->cpu.regs[i] = 0;
        }
        current->cpu.rsp = sp;   // Set 64-bit stack pointer
        current->cpu.rip = entry; // Set 64-bit instruction pointer
        // Debug: Log final register values
        f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { fprintf(f, "Final RSP=0x%llx, ESP=0x%x, RIP=0x%llx\n", (unsigned long long)current->cpu.rsp, current->cpu.esp, (unsigned long long)current->cpu.rip); fclose(f); }
#else
        // 32-bit iSH build cannot run 64-bit programs - this should have been caught earlier
        // But handle gracefully just in case
        current->cpu.eax = current->cpu.ebx = current->cpu.ecx = current->cpu.edx = 0;
        current->cpu.esi = current->cpu.edi = current->cpu.ebp = 0;
        current->cpu.esp = sp;
        current->cpu.eip = entry;
#endif
    } else {
        // 32-bit program initialization (works on both 32-bit and 64-bit iSH builds)
        current->cpu.eax = 0;
        current->cpu.ebx = 0;
        current->cpu.ecx = 0;
        current->cpu.edx = 0;
        current->cpu.esi = 0;
        current->cpu.edi = 0;
        current->cpu.ebp = 0;
#ifdef ISH_64BIT
        // Debug: Log 32-bit program initialization  
        FILE *f = fopen("/tmp/debug_exec.txt", "a");
        if (f) { fprintf(f, "32-bit program: sp=0x%llx, entry=0x%llx\n", (unsigned long long)sp, (unsigned long long)entry); fclose(f); }
        // Clear the upper 32 bits of registers for 32-bit programs on 64-bit iSH
        current->cpu.rsp = sp;   // This sets both rsp and esp due to union
        current->cpu.rip = entry; // This sets both rip and eip due to union
#else
        current->cpu.esp = sp;   // 32-bit stack pointer
        current->cpu.eip = entry; // 32-bit instruction pointer
#endif
    }
    current->cpu.fcw = 0x37f;

    // This code was written when I discovered that the glibc entry point
    // interprets edx as the address of a function to call on exit, as
    // specified in the ABI. This register is normally set by the dynamic
    // linker, so everything works fine until you run a static executable.
    collapse_flags(&current->cpu);
    current->cpu.eflags = 0;

    err = 0;
    fprintf(stderr, "elf_exec: Successfully loaded, entry=0x%llx, sp=0x%llx\n", 
            (unsigned long long)entry, (unsigned long long)sp);
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

beyond_hope_unlocked:
    // Memory was already unlocked - skip the unlock
    goto out_free_interp;

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

static inline addr_t align_stack(addr_t sp) {
    return sp &~ 0xf;
}

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

static int format_exec(struct fd *fd, const char *file, struct exec_args argv, struct exec_args envp) {
    TRACE_memory("format_exec called for file: %s\n", file);
    int err = elf_exec(fd, file, argv, envp);
    TRACE_memory("elf_exec returned: %d for file: %s\n", err, file);
    if (err != _ENOEXEC)
        return err;
    // other formats would go here
    return _ENOEXEC;
}

static int shebang_exec(struct fd *fd, const char *file, struct exec_args argv, struct exec_args envp) {
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

int __do_execve(const char *file, struct exec_args argv, struct exec_args envp) {
    TRACE_memory("__do_execve called for file: %s\n", file);
    
    struct fd *fd = generic_open(file, O_RDONLY, 0);
    if (IS_ERR(fd)) {
        TRACE_memory("Failed to open file: %s, error: %ld\n", file, PTR_ERR(fd));
        return PTR_ERR(fd);
    }

    struct statbuf stat;
    int err = fd->mount->fs->fstat(fd, &stat);
    if (err < 0) {
        TRACE_memory("Failed to fstat file: %s, error: %d\n", file, err);
        fd_close(fd);
        return err;
    }

    // if nobody has permission to execute, it should be safe to not execute
    if (!(stat.mode & 0111)) {
        TRACE_memory("File not executable: %s, mode: %o\n", file, stat.mode);
        fd_close(fd);
        return _EACCES;
    }

    TRACE_memory("About to call format_exec for file: %s\n", file);
    err = format_exec(fd, file, argv, envp);
    if (err == _ENOEXEC)
        err = shebang_exec(fd, file, argv, envp);
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

    // reset signal handlers and signal mask
    lock(&current->sighand->lock);
    for (int sig = 0; sig < NUM_SIGS; sig++) {
        struct sigaction_ *action = &current->sighand->action[sig];
        if (action->handler != SIG_IGN_)
            action->handler = SIG_DFL_;
    }
    current->sighand->altstack = 0;
    // Reset signal mask to unblocked (CRITICAL FIX for 64-bit signal timing issues)
    current->blocked = 0;
    current->pending = 0;  // Clear any pending signals
    unlock(&current->sighand->lock);

    current->did_exec = true;
    vfork_notify(current);

    if (current->ptrace.traced) {
        lock(&pids_lock);
        send_signal(current, SIGTRAP_, (struct siginfo_) {
            .code = SI_USER_,
            .kill.pid = current->pid,
            .kill.uid = current->uid,
        });
        unlock(&pids_lock);
    }

    return 0;
}

int do_execve(const char *file, size_t argc, const char *argv_p, const char *envp_p) {
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
#ifdef ISH_64BIT
        // In 64-bit builds running 32-bit programs, argv contains 32-bit pointers
        dword_t str_addr_32;
        if (user_get(addr + i * sizeof(dword_t), str_addr_32))
            return _EFAULT;
        str_addr = str_addr_32;
#else
        if (user_get(addr + i * sizeof(addr_t), str_addr))
            return _EFAULT;
#endif
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
