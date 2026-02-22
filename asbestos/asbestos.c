#define DEFAULT_CHANNEL instr
#include "debug.h"
#include "asbestos/asbestos.h"
#include "asbestos/gen.h"
#include "asbestos/frame.h"
#include "emu/cpu.h"
#include "emu/interrupt.h"
#include "util/list.h"
#include <stdio.h>

extern int current_pid(void);

#ifdef ISH_GUEST_64BIT
// Called from fiber_exit when rip contains a host address instead of guest address
extern void gadget_nop(void);  // Known gadget for ASLR slide calculation
extern void gadget_call(void);
extern void gadget_ret(void);
extern void gadget_jmp(void);
extern void gadget_jmp_indir(void);
void debug_host_addr_in_rip(struct cpu_state *cpu, uint64_t corrupt_rip, uint64_t interrupt_code) {
    uint64_t nop_runtime = (uint64_t)&gadget_nop;
    int64_t offset_from_nop = (int64_t)(corrupt_rip - nop_runtime);
    fprintf(stderr, "\n=== HOST ADDRESS LEAKED INTO RIP ===\n");
    fprintf(stderr, "corrupt rip = %#llx (gadget_nop%+lld)\n",
            (unsigned long long)corrupt_rip, (long long)offset_from_nop);
    fprintf(stderr, "interrupt code (_tmp) = %#llx", (unsigned long long)interrupt_code);
    if ((int64_t)interrupt_code == -1)
        fprintf(stderr, " (re-translate: poke/fiber_ret/jmp_indir/ret/exit)");
    else if (interrupt_code == 0x100)
        fprintf(stderr, " (INT_SYSCALL64)");
    else
        fprintf(stderr, " (interrupt %llu)", (unsigned long long)interrupt_code);
    fprintf(stderr, "\n");
    fprintf(stderr, "rax=%#llx rbx=%#llx rcx=%#llx rdx=%#llx\n",
            (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx,
            (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
    fprintf(stderr, "rsi=%#llx rdi=%#llx rbp=%#llx rsp=%#llx\n",
            (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi,
            (unsigned long long)cpu->rbp, (unsigned long long)cpu->rsp);
    fprintf(stderr, "r8=%#llx r9=%#llx r10=%#llx r11=%#llx\n",
            (unsigned long long)cpu->r8, (unsigned long long)cpu->r9,
            (unsigned long long)cpu->r10, (unsigned long long)cpu->r11);
    fprintf(stderr, "r12=%#llx r13=%#llx r14=%#llx r15=%#llx\n",
            (unsigned long long)cpu->r12, (unsigned long long)cpu->r13,
            (unsigned long long)cpu->r14, (unsigned long long)cpu->r15);
    fprintf(stderr, "eflags=%#x cf=%d of=%d res=%#llx\n",
            cpu->eflags, cpu->cf, cpu->of, (unsigned long long)cpu->res);
    // Also check rip stored in cpu (from save_regs)
    fprintf(stderr, "cpu->rip (from save_regs) = %#llx\n",
            (unsigned long long)cpu->rip);
    abort();
}

// Called from segfault handler when [_ip] is a host address instead of orig_ip
// This means _ip is misaligned (pointing to a function pointer slot instead of an argument)
void debug_segfault_misaligned_ip(struct cpu_state *cpu, uint64_t ip_value, uint64_t segfault_addr) {
    uint64_t nop_runtime = (uint64_t)&gadget_nop;
    fprintf(stderr, "\n=== SEGFAULT HANDLER: [_ip] IS HOST ADDRESS (MISALIGNED!) ===\n");
    fprintf(stderr, "_ip = %p\n", (void *)ip_value);
    fprintf(stderr, "segfault_addr = %#llx\n", (unsigned long long)segfault_addr);
    fprintf(stderr, "rsp=%#llx\n", (unsigned long long)cpu->rsp);
    // Dump code stream around _ip
    uint64_t *code_ptr = (uint64_t *)ip_value;
    fprintf(stderr, "code stream around _ip:\n");
    for (int i = -8; i <= 8; i++) {
        uint64_t val = code_ptr[i];
        int64_t off = (int64_t)(val - nop_runtime);
        fprintf(stderr, "  [%+d] %p = %#llx", i, &code_ptr[i], (unsigned long long)val);
        if (off > -0x100000 && off < 0x100000)
            fprintf(stderr, " <- gadget (nop%+lld)", (long long)off);
        else if (val > 0x555500000000ULL && val < 0x800000000000ULL)
            fprintf(stderr, " <- guest addr");
        else if ((val & 0x8000000000000000ULL) && (val & 0x7FFFFFFFFFFFFFFFULL) > 0x555500000000ULL)
            fprintf(stderr, " <- fake_ip (guest %#llx)", (unsigned long long)(val & 0x7FFFFFFFFFFFFFFFULL));
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "registers: rax=%#llx rdi=%#llx\n",
            (unsigned long long)cpu->rax, (unsigned long long)cpu->rdi);
    abort();
}

// Called from RET gadget when popped return address is a host address
void debug_ret_popped_host_addr(struct cpu_state *cpu, uint64_t corrupt_addr, uint64_t stack_addr) {
    uint64_t nop_runtime = (uint64_t)&gadget_nop;
    int64_t offset = (int64_t)(corrupt_addr - nop_runtime);
    fprintf(stderr, "\n=== RET POPPED HOST ADDRESS FROM STACK ===\n");
    fprintf(stderr, "corrupt ret addr = %#llx (offset from gadget_nop = %+lld)\n",
            (unsigned long long)corrupt_addr, (long long)offset);
    fprintf(stderr, "stack location   = %#llx (host addr after TLB)\n", (unsigned long long)stack_addr);
    fprintf(stderr, "rsp=%#llx\n", (unsigned long long)cpu->rsp);
    // Dump a few words around the stack location to see context
    uint64_t *host_stack = (uint64_t *)stack_addr;
    fprintf(stderr, "stack context (host ptr %p):\n", (void *)host_stack);
    for (int i = -2; i <= 6; i++) {
        uint64_t val = host_stack[i];
        fprintf(stderr, "  [%+d] = %#llx", i, (unsigned long long)val);
        int64_t off = (int64_t)(val - nop_runtime);
        if (off > -0x100000 && off < 0x100000)
            fprintf(stderr, " (gadget_nop%+lld)", (long long)off);
        fprintf(stderr, "\n");
    }
    abort();
}

#endif

static void fiber_block_disconnect(struct asbestos *asbestos, struct fiber_block *block);
static void fiber_block_free(struct asbestos *asbestos, struct fiber_block *block);
static void fiber_free_jetsam(struct asbestos *asbestos);
static void fiber_resize_hash(struct asbestos *asbestos, size_t new_size);

struct asbestos *asbestos_new(struct mmu *mmu) {
    struct asbestos *asbestos = calloc(1, sizeof(struct asbestos));
    asbestos->mmu = mmu;
    fiber_resize_hash(asbestos, FIBER_INITIAL_HASH_SIZE);
    asbestos->page_hash = calloc(FIBER_PAGE_HASH_SIZE, sizeof(*asbestos->page_hash));
    list_init(&asbestos->jetsam);
    lock_init(&asbestos->lock);
    wrlock_init(&asbestos->jetsam_lock);
    return asbestos;
}

void asbestos_free(struct asbestos *asbestos) {
    for (size_t i = 0; i < asbestos->hash_size; i++) {
        struct fiber_block *block, *tmp;
        if (list_null(&asbestos->hash[i]))
            continue;
        list_for_each_entry_safe(&asbestos->hash[i], block, tmp, chain) {
            fiber_block_free(asbestos, block);
        }
    }
    fiber_free_jetsam(asbestos);
    free(asbestos->page_hash);
    free(asbestos->hash);
    free(asbestos);
}

static inline struct list *blocks_list(struct asbestos *asbestos, page_t page, int i) {
    // TODO is this a good hash function?
    return &asbestos->page_hash[page % FIBER_PAGE_HASH_SIZE].blocks[i];
}

void asbestos_invalidate_range(struct asbestos *absestos, page_t start, page_t end) {
    lock(&absestos->lock);
    struct fiber_block *block, *tmp;
    for (page_t page = start; page < end; page++) {
        for (int i = 0; i <= 1; i++) {
            struct list *blocks = blocks_list(absestos, page, i);
            if (list_null(blocks))
                continue;
            list_for_each_entry_safe(blocks, block, tmp, page[i]) {
                fiber_block_disconnect(absestos, block);
                block->is_jetsam = true;
                list_add(&absestos->jetsam, &block->jetsam);
            }
        }
    }
    unlock(&absestos->lock);
}

void asbestos_invalidate_page(struct asbestos *asbestos, page_t page) {
    asbestos_invalidate_range(asbestos, page, page + 1);
}
void asbestos_invalidate_all(struct asbestos *asbestos) {
    asbestos_invalidate_range(asbestos, 0, MEM_PAGES);
}

static void fiber_resize_hash(struct asbestos *asbestos, size_t new_size) {
    TRACE_(verbose, "%d resizing hash to %lu, using %lu bytes for gadgets\n", current_pid(), new_size, asbestos->mem_used);
    struct list *new_hash = calloc(new_size, sizeof(struct list));
    for (size_t i = 0; i < asbestos->hash_size; i++) {
        if (list_null(&asbestos->hash[i]))
            continue;
        struct fiber_block *block, *tmp;
        list_for_each_entry_safe(&asbestos->hash[i], block, tmp, chain) {
            list_remove(&block->chain);
            list_init_add(&new_hash[block->addr % new_size], &block->chain);
        }
    }
    free(asbestos->hash);
    asbestos->hash = new_hash;
    asbestos->hash_size = new_size;
}

static void fiber_insert(struct asbestos *asbestos, struct fiber_block *block) {
    asbestos->mem_used += block->used;
    asbestos->num_blocks++;
    // target an average hash chain length of 1-2
    if (asbestos->num_blocks >= asbestos->hash_size * 2)
        fiber_resize_hash(asbestos, asbestos->hash_size * 2);

    list_init_add(&asbestos->hash[block->addr % asbestos->hash_size], &block->chain);
    list_init_add(blocks_list(asbestos, PAGE(block->addr), 0), &block->page[0]);
    if (PAGE(block->addr) != PAGE(block->end_addr))
        list_init_add(blocks_list(asbestos, PAGE(block->end_addr), 1), &block->page[1]);
}

static struct fiber_block *fiber_lookup(struct asbestos *asbestos, addr_t addr) {
    struct list *bucket = &asbestos->hash[addr % asbestos->hash_size];
    if (list_null(bucket))
        return NULL;
    struct fiber_block *block;
    list_for_each_entry(bucket, block, chain) {
        if (block->addr == addr)
            return block;
    }
    return NULL;
}

static struct fiber_block *fiber_block_compile(addr_t ip, struct tlb *tlb) {
    struct gen_state state;
    TRACE("%d %08x --- compiling:\n", current_pid(), ip);
    gen_start(ip, &state);
    while (true) {
        if (!gen_step(&state, tlb))
            break;
        // no block should span more than 2 pages
        // guarantee this by limiting total block size to 1 page
        // guarantee that by stopping as soon as there's less space left than
        // the maximum length of an x86 instruction
        // TODO refuse to decode instructions longer than 15 bytes
        if (state.ip - ip >= PAGE_SIZE - 15) {
            gen_exit(&state);
            break;
        }
    }
    gen_end(&state);
    assert(state.ip - ip <= PAGE_SIZE);
    state.block->used = state.capacity;
    return state.block;
}

// Remove all pointers to the block. It can't be freed yet because another
// thread may be executing it.
static void fiber_block_disconnect(struct asbestos *asbestos, struct fiber_block *block) {
    if (asbestos != NULL) {
        asbestos->mem_used -= block->used;
        asbestos->num_blocks--;
    }
    list_remove(&block->chain);
    for (int i = 0; i <= 1; i++) {
        list_remove(&block->page[i]);
        list_remove_safe(&block->jumps_from_links[i]);

        struct fiber_block *prev_block, *tmp;
        list_for_each_entry_safe(&block->jumps_from[i], prev_block, tmp, jumps_from_links[i]) {
            if (prev_block->jump_ip[i] != NULL)
                *prev_block->jump_ip[i] = prev_block->old_jump_ip[i];
            list_remove(&prev_block->jumps_from_links[i]);
        }
    }
}

static void fiber_block_free(struct asbestos *asbestos, struct fiber_block *block) {
    fiber_block_disconnect(asbestos, block);
    free(block);
}

static void fiber_free_jetsam(struct asbestos *asbestos) {
    struct fiber_block *block, *tmp;
    list_for_each_entry_safe(&asbestos->jetsam, block, tmp, jetsam) {
        list_remove(&block->jetsam);
        free(block);
    }
}

int fiber_enter(struct fiber_block *block, struct fiber_frame *frame, struct tlb *tlb);

static inline size_t fiber_cache_hash(addr_t ip) {
    return (ip ^ (ip >> 12)) % FIBER_CACHE_SIZE;
}

static int cpu_step_to_interrupt(struct cpu_state *cpu, struct tlb *tlb) {
    struct asbestos *asbestos = cpu->mmu->asbestos;
    read_wrlock(&asbestos->jetsam_lock);

    struct fiber_block **cache = calloc(FIBER_CACHE_SIZE, sizeof(*cache));
    struct fiber_frame *frame = malloc(sizeof(struct fiber_frame));
    memset(frame, 0, sizeof(*frame));
    frame->cpu = *cpu;
    assert(asbestos->mmu == cpu->mmu);

    int interrupt = INT_NONE;
    while (interrupt == INT_NONE) {
        addr_t ip = CPU_IP(&frame->cpu);
        size_t cache_index = fiber_cache_hash(ip);
        struct fiber_block *block = cache[cache_index];
        if (block == NULL || block->addr != ip) {
            lock(&asbestos->lock);
            block = fiber_lookup(asbestos, ip);
            if (block == NULL) {
                block = fiber_block_compile(ip, tlb);
                fiber_insert(asbestos, block);
            } else {
                TRACE("%d %08x --- missed cache\n", current_pid(), ip);
            }
            cache[cache_index] = block;
            unlock(&asbestos->lock);
        }
        struct fiber_block *last_block = frame->last_block;
        if (last_block != NULL &&
                (last_block->jump_ip[0] != NULL ||
                 last_block->jump_ip[1] != NULL)) {
            lock(&asbestos->lock);
            // can't mint new pointers to a block that has been marked jetsam
            // and is thus assumed to have no pointers left
            if (!last_block->is_jetsam && !block->is_jetsam) {
                for (int i = 0; i <= 1; i++) {
                    if (last_block->jump_ip[i] != NULL &&
                            (*last_block->jump_ip[i] & 0xffffffff) == block->addr) {
                        *last_block->jump_ip[i] = (unsigned long) block->code;
                        list_add(&block->jumps_from[i], &last_block->jumps_from_links[i]);
                    }
                }
            }

            unlock(&asbestos->lock);
        }
        frame->last_block = block;

        // block may be jetsam, but that's ok, because it can't be freed until
        // every thread on this asbestos is not executing anything

        TRACE("%d %08x --- cycle %ld\n", current_pid(), ip, frame->cpu.cycle);

        interrupt = fiber_enter(block, frame, tlb);
        if (interrupt == INT_NONE && __atomic_exchange_n(cpu->poked_ptr, false, __ATOMIC_SEQ_CST))
            interrupt = INT_TIMER;
        if (interrupt == INT_NONE && ++frame->cpu.cycle % (1 << 10) == 0)
            interrupt = INT_TIMER;
        *cpu = frame->cpu;
    }

    free(frame);
    free(cache);
    read_wrunlock(&asbestos->jetsam_lock);
    return interrupt;
}

static int cpu_single_step(struct cpu_state *cpu, struct tlb *tlb) {
    struct gen_state state;
    gen_start(CPU_IP(cpu), &state);
    gen_step(&state, tlb);
    gen_exit(&state);
    gen_end(&state);

    struct fiber_block *block = state.block;
    struct fiber_frame frame = {.cpu = *cpu};
    int interrupt = fiber_enter(block, &frame, tlb);
    *cpu = frame.cpu;
    fiber_block_free(NULL, block);
    if (interrupt == INT_NONE)
        interrupt = INT_DEBUG;
    return interrupt;
}

int cpu_run_to_interrupt(struct cpu_state *cpu, struct tlb *tlb) {
    if (cpu->poked_ptr == NULL)
        cpu->poked_ptr = &cpu->_poked;
    tlb_refresh(tlb, cpu->mmu);
    int interrupt = (cpu->tf ? cpu_single_step : cpu_step_to_interrupt)(cpu, tlb);
    cpu->trapno = interrupt;

    struct asbestos *asbestos = cpu->mmu->asbestos;
    lock(&asbestos->lock);
    if (!list_empty(&asbestos->jetsam)) {
        // write-lock the jetsam_lock to wait until other asbestos threads get
        // to this point, so they will all clear out their block pointers
        // TODO: use RCU for better performance
        unlock(&asbestos->lock);
        write_wrlock(&asbestos->jetsam_lock);
        lock(&asbestos->lock);
        fiber_free_jetsam(asbestos);
        write_wrunlock(&asbestos->jetsam_lock);
    }
    unlock(&asbestos->lock);

    return interrupt;
}

void cpu_poke(struct cpu_state *cpu) {
    __atomic_store_n(cpu->poked_ptr, true, __ATOMIC_SEQ_CST);
}

#ifdef ISH_GUEST_64BIT
void debug_dump_regs(struct cpu_state *cpu, uint64_t guest_ip) {
    fprintf(stderr, "[BP] ip=%#llx rax=%#llx rbx=%#llx rcx=%#llx rdx=%#llx\n",
           (unsigned long long)guest_ip,
           (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx,
           (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
    fprintf(stderr, "     rsi=%#llx rdi=%#llx rbp=%#llx rsp=%#llx\n",
           (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi,
           (unsigned long long)cpu->rbp, (unsigned long long)cpu->rsp);
}
#endif
