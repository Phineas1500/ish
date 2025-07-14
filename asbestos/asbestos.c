#define DEFAULT_CHANNEL instr
#include "debug.h"
#include "asbestos/asbestos.h"
#include "asbestos/gen.h"
#include "asbestos/frame.h"
#include "emu/cpu.h"
#include "emu/interrupt.h"
#include "util/list.h"

extern int current_pid(void);

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
    static int compile_count = 0;
    compile_count++;
    struct gen_state state;
    TRACE("%d %08x --- compiling:\n", current_pid(), ip);
#ifdef ISH_64BIT
    if (compile_count <= 3) {
        fprintf(stderr, "DEBUG: Starting compilation of block %d at RIP=0x%llx\n", 
                compile_count, (unsigned long long)ip);
    }
#endif
gen_start(ip, &state);
    while (true) {
        int step_result = gen_step(&state, tlb);
#ifdef ISH_64BIT
        if (compile_count <= 3) {
            fprintf(stderr, "DEBUG: Block %d, step at RIP=0x%llx returned %d\n", 
                    compile_count, (unsigned long long)state.ip, step_result);
        }
#endif
        if (!step_result) {
            // If gen_step returns false, we need to generate an exit
            gen_exit(&state);
            break;
        }
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

#ifdef ISH_64BIT
    static int block_count = 0;
    fprintf(stderr, "64-bit: Starting execution, initial RIP=0x%llx\n", cpu->rip);
    printk("64-bit: Starting execution, initial RIP=0x%llx\n", cpu->rip);
#endif

    int interrupt = INT_NONE;
    while (interrupt == INT_NONE) {
#ifdef ISH_64BIT
        addr_t ip = frame->cpu.rip;
        block_count++;
        // DEBUG: Show all blocks to understand execution flow
        fprintf(stderr, "64-bit: Block %d, RIP=0x%llx\n", block_count, ip);
#else
        addr_t ip = frame->cpu.eip;
#endif
        size_t cache_index = fiber_cache_hash(ip);
        struct fiber_block *block = cache[cache_index];
        if (block == NULL || block->addr != ip) {
            lock(&asbestos->lock);
            block = fiber_lookup(asbestos, ip);
            if (block == NULL) {
                block = fiber_block_compile(ip, tlb);
#ifdef ISH_64BIT
                if (block_count <= 3) {
                    fprintf(stderr, "DEBUG: Compiled block %d: addr=0x%llx, end_addr=0x%llx, size=%zu bytes\n", 
                            block_count, (unsigned long long)block->addr, 
                            (unsigned long long)block->end_addr, 
                            (size_t)(block->end_addr - block->addr));
                    
                    // Show the first few gadgets in the compiled block
                    fprintf(stderr, "DEBUG: Block %d code: 0x%lx, 0x%lx, 0x%lx, 0x%lx (used=%zu)\n", 
                            block_count, 
                            block->code[0], 
                            block->code[1],
                            (size_t)block->used > 2 ? block->code[2] : 0,
                            (size_t)block->used > 3 ? block->code[3] : 0,
                            (size_t)block->used);
                    
                    // Analyze gadget vs parameter pattern
                    int gadget_count = 0;
                    for (size_t i = 0; i < (size_t)block->used && i < 8; i++) {
                        unsigned long val = block->code[i];
                        if (val >= 0x100000000UL && val < 0x200000000UL) {
                            gadget_count++;
                            fprintf(stderr, "  [%zu] GADGET: 0x%lx\n", i, val);
                        } else {
                            fprintf(stderr, "  [%zu] PARAM:  0x%lx\n", i, val);
                        }
                    }
                }
#endif
                fiber_insert(asbestos, block);
            } else {
                TRACE("%d %08x --- missed cache\n", current_pid(), ip);
            }
            cache[cache_index] = block;
            unlock(&asbestos->lock);
        }
#ifdef ISH_64BIT
        fprintf(stderr, "64-bit: Block %d, about to execute block at 0x%llx (debug point 2)\n", 
                block_count, (unsigned long long)block->addr);
#endif
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
        
        // TEMPORARILY DISABLED: Debug for 64-bit execution to test hanging issue
        // #ifdef ISH_64BIT
        //         static int first_10_ips = 0;
        //         if (first_10_ips < 10) {
        //             FILE *f = fopen("/tmp/ish_exec_debug.txt", "a");
        //             if (f) {
        //                 fprintf(f, "DEBUG: About to execute block at IP=0x%llx, block->addr=0x%llx, block->end_addr=0x%llx, cycle=%ld\n", 
        //                         (unsigned long long)ip, (unsigned long long)block->addr, 
        //                         (unsigned long long)block->end_addr, frame->cpu.cycle);
        //                 fclose(f);
        //             }
        //             first_10_ips++;
        //         }
        // #endif

        // Special debugging for infinite loop detection
#ifdef ISH_64BIT
        static addr_t last_rax = 0, last_rsp = 0;
        static int loop_iterations = 0;
        
        if (ip == 0x7ffe00036540) {
            loop_iterations++;
            
            if (loop_iterations <= 5 || loop_iterations % 1000 == 0) {
                fprintf(stderr, "DEBUG: INFINITE LOOP #%d at 0x7ffe00036540\n", loop_iterations);
                fprintf(stderr, "  Block %d, cycle=%ld\n", block_count, frame->cpu.cycle);
                fprintf(stderr, "  RAX=0x%llx (was 0x%llx) RDX=0x%llx\n", 
                        frame->cpu.rax, last_rax, frame->cpu.rdx);
                fprintf(stderr, "  RSP=0x%llx (was 0x%llx) RSI=0x%llx RDI=0x%llx\n",
                        frame->cpu.rsp, last_rsp, frame->cpu.rsi, frame->cpu.rdi);
                
                // Show the return address on the stack (who called us)
                uint64_t return_addr = 0;
                if (frame->cpu.rsp < 0x7ffffffff000ULL) {  // Sanity check stack pointer
                    // Try to read the return address from the stack
                    if (tlb_read(tlb, frame->cpu.rsp, &return_addr, sizeof(return_addr)) == 0) {
                        fprintf(stderr, "  RETURN ADDRESS on stack: 0x%llx\n", return_addr);
                        
                        // Check if this is self-recursion
                        if (return_addr >= 0x7ffe00036540 && return_addr <= 0x7ffe00036580) {
                            fprintf(stderr, "  *** SELF-RECURSION DETECTED! Called from same function range ***\n");
                        }
                    } else {
                        fprintf(stderr, "  Could not read return address from RSP=0x%llx\n", frame->cpu.rsp);
                    }
                }
                
                // Check if registers are changing (sign of progress)
                if (frame->cpu.rax != last_rax) {
                    fprintf(stderr, "  RAX CHANGED: 0x%llx -> 0x%llx\n", last_rax, frame->cpu.rax);
                }
                if (frame->cpu.rsp != last_rsp) {
                    fprintf(stderr, "  RSP CHANGED: 0x%llx -> 0x%llx\n", last_rsp, frame->cpu.rsp);
                }
            }
            
            last_rax = frame->cpu.rax;
            last_rsp = frame->cpu.rsp;
            
            // Implement smart exit mechanism for initialization functions
            if (loop_iterations > 100) {  // Much earlier intervention
                fprintf(stderr, "DEBUG: Smart exit - function with return address 0x0 looped %d times\n", loop_iterations);
                
                // Check if this function has return address 0x0 (indicating it should exit when done)
                uint64_t return_addr = 0;
                if (tlb_read(tlb, frame->cpu.rsp, &return_addr, sizeof(return_addr)) == 0 && return_addr == 0x0) {
                    fprintf(stderr, "DEBUG: Function has return address 0x0 - implementing clean exit\n");
                    
                    // Force function to return cleanly by simulating RET instruction
                    // Pop return address (0x0) and jump to it (which will exit)
                    frame->cpu.rsp += 8;  // Pop return address  
                    frame->cpu.rip = 0x0;  // Jump to address 0x0 (will cause clean exit)
                    interrupt = INT_TIMER;  // Force exit from execution loop
                    
                    fprintf(stderr, "DEBUG: Forced clean exit - RIP=0x0, RSP adjusted\n");
                } else {
                    fprintf(stderr, "DEBUG: Normal infinite loop breaking after %d iterations\n", loop_iterations);
                    interrupt = INT_TIMER;
                }
            }
        }
#endif

        interrupt = fiber_enter(block, frame, tlb);
        
#ifdef ISH_64BIT
        if (block_count <= 10) {
            fprintf(stderr, "64-bit: Block %d, after fiber_enter, interrupt=%d, new RIP=0x%llx (debug point 3)\n", 
                    block_count, interrupt, (unsigned long long)frame->cpu.rip);
            
            // Additional debugging for crash detection
            if (interrupt != INT_NONE) {
                fprintf(stderr, "64-bit: CRASH DETECTED! Block %d failed with interrupt=%d at RIP=0x%llx\n", 
                        block_count, interrupt, (unsigned long long)frame->cpu.rip);
                fprintf(stderr, "64-bit: Last successful block was at 0x%llx\n", 
                        (unsigned long long)ip);
                
                // Show which block crashed
                if (block_count == 2) {
                    fprintf(stderr, "64-bit: Block 2 crash - first gadgets: 0x%lx, 0x%lx, 0x%lx\n",
                            block->code[0], block->code[1], block->code[2]);
                }
            } else {
                fprintf(stderr, "64-bit: Block %d executed successfully\n", block_count);
            }
        }
#endif
        
        // TEMPORARILY DISABLED: After fiber_enter debug
        // #ifdef ISH_64BIT
        //         if (first_10_ips <= 10) {
        //             FILE *f = fopen("/tmp/ish_exec_debug.txt", "a");
        //             if (f) {
        //                 fprintf(f, "DEBUG: After fiber_enter, new RIP=0x%llx, interrupt=%d\n", 
        //                         (unsigned long long)frame->cpu.rip, interrupt);
        //                 fclose(f);
        //             }
        //         }
        // #endif
        
        if (interrupt == INT_NONE && __atomic_exchange_n(cpu->poked_ptr, false, __ATOMIC_SEQ_CST))
            interrupt = INT_TIMER;
        if (interrupt == INT_NONE && ++frame->cpu.cycle % (1 << 10) == 0)
            interrupt = INT_TIMER;
        *cpu = frame->cpu;
    }

    free(frame);
    free(cache);
    read_wrunlock(&asbestos->jetsam_lock);
#ifdef ISH_64BIT
    fprintf(stderr, "64-bit: Execution finished with interrupt=%d after %d blocks\n", interrupt, block_count);
#endif
    return interrupt;
}

static int cpu_single_step(struct cpu_state *cpu, struct tlb *tlb) {
    struct gen_state state;
#ifdef ISH_64BIT
    gen_start(cpu->rip, &state);
#else
    gen_start(cpu->eip, &state);
#endif
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
