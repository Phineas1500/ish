#define DEFAULT_CHANNEL instr
#include "debug.h"
#include "asbestos/asbestos.h"
#include "asbestos/gen.h"
#include "asbestos/frame.h"
#include "emu/cpu.h"
#include "emu/interrupt.h"
#include "util/list.h"
#include <stdio.h>
#include "kernel/calls.h"

extern int current_pid(void);

// Retained as no-op hooks because debug callsites may still exist in kernel/*.c.
void dump_rip_ring(void) {}
void dump_rip_ring_v8_bytes(void) {}

#ifdef ISH_GUEST_64BIT
enum {
    V8_HASH_FIELD_TYPE_MASK = 0x3,
    V8_HASH_FIELD_HASH = 0x2,
    V8_HASH_FIELD_EMPTY = 0x3,
    V8_HASH_FIELD_SHIFT = 2,
    V8_HASH_FIELD_HASH_MASK = 0x3fffffff,
    V8_ZERO_HASH = 27,
    V8_SEQ_ONE_BYTE_STRING_TYPE = 0x0008,
    V8_STRING_MAX_FIXUP_LEN = 1u << 20,
    V8_INV_1P2_3 = 0x38e38e39u,
    V8_INV_1P2_10 = 0xc00ffc01u,
    V8_INV_1P2_15 = 0x3fff8001u,
};

static bool node24_patch_empty_one_byte_string(addr_t string, uint32_t *patched_hash);
static bool node24_hash_seed_known = false;
static uint32_t node24_hash_seed = 0;

static bool node24_match_hash_helper(addr_t ip) {
    // Prologue signature for the V8 helper at text offsets 0xe47780/0xe47960.
    static const uint8_t sig[] = {
        0x55, 0x49, 0x89, 0xf8, 0x49, 0x89, 0xf3, 0x48,
        0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x38,
    };
    for (unsigned i = 0; i < sizeof(sig); i++) {
        uint8_t b;
        if (user_get((addr_t)(ip + i), b) || b != sig[i])
            return false;
    }
    return true;
}

static bool node24_match_forwarding_lookup(addr_t ip) {
    // Signature for V8's forwarding-table lookup helper (offset 0x142b8f0).
    static const uint8_t sig[] = {
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10,
        0x8b, 0x47, 0x28, 0x39, 0xc6, 0x0f, 0x8d,
    };
    for (unsigned i = 0; i < sizeof(sig); i++) {
        uint8_t b;
        if (user_get((addr_t)(ip + i), b) || b != sig[i])
            return false;
    }
    return true;
}

static uint32_t node24_unxorshr32(uint32_t y, int shift) {
    uint32_t x = y;
    for (int s = shift; s < 32; s <<= 1)
        x ^= x >> s;
    return x;
}

static uint32_t node24_hash_bytes_with_seed(const uint8_t *chars, uint32_t length, uint32_t seed) {
    uint32_t running = seed;
    for (uint32_t i = 0; i < length; i++) {
        running += chars[i];
        running += running << 10;
        running ^= running >> 6;
    }
    running += running << 3;
    running ^= running >> 11;
    running += running << 15;

    uint32_t hash = running & V8_HASH_FIELD_HASH_MASK;
    if (hash == 0)
        hash = V8_ZERO_HASH;
    return (hash << V8_HASH_FIELD_SHIFT) | V8_HASH_FIELD_HASH;
}

static bool node24_hash_seed_candidates(const uint8_t *chars, uint32_t length, uint32_t raw_hash,
                                        uint32_t out[4], int *out_count) {
    if ((raw_hash & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_HASH)
        return false;

    uint32_t hash30 = raw_hash >> V8_HASH_FIELD_SHIFT;
    int n = 0;
    for (uint32_t hi = 0; hi < 4; hi++) {
        uint32_t x = hash30 | (hi << 30);
        uint32_t x2 = x * V8_INV_1P2_15;
        uint32_t x1 = node24_unxorshr32(x2, 11);
        uint32_t v = x1 * V8_INV_1P2_3;

        for (uint32_t i = length; i > 0; i--) {
            uint32_t u = node24_unxorshr32(v, 6);
            uint32_t t = u * V8_INV_1P2_10;
            v = t - chars[i - 1];
        }

        uint32_t seed = v;
        if (node24_hash_bytes_with_seed(chars, length, seed) != raw_hash)
            continue;

        bool dup = false;
        for (int j = 0; j < n; j++) {
            if (out[j] == seed) {
                dup = true;
                break;
            }
        }
        if (!dup)
            out[n++] = seed;
    }

    *out_count = n;
    return n > 0;
}

static void node24_try_learn_hash_seed(addr_t base) {
    if (node24_hash_seed_known)
        return;

    struct {
        uint32_t raw_hash;
        uint32_t len;
        uint8_t chars[32];
    } pairs[6];
    int pair_count = 0;

    for (int64_t off = -0x400; off <= 0x400 && pair_count < 6; off += 8) {
        addr_t addr = (addr_t)(base + off);
        uint64_t map_ptr;
        uint32_t raw_hash;
        uint32_t len;
        uint16_t type;
        if (user_get(addr, map_ptr) || user_get(addr + 8, raw_hash) || user_get(addr + 12, len))
            continue;
        if ((raw_hash & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_HASH)
            continue;
        if (len == 0 || len > 32)
            continue;
        if ((map_ptr & 1) == 0 || user_get((addr_t)(map_ptr - 1 + 12), type))
            continue;
        if (type != V8_SEQ_ONE_BYTE_STRING_TYPE)
            continue;

        bool ok = true;
        for (uint32_t i = 0; i < len; i++) {
            uint8_t ch;
            if (user_get((addr_t)(addr + 16 + i), ch) || ch < 0x20 || ch > 0x7e) {
                ok = false;
                break;
            }
            pairs[pair_count].chars[i] = ch;
        }
        if (!ok)
            continue;
        pairs[pair_count].raw_hash = raw_hash;
        pairs[pair_count].len = len;
        pair_count++;
    }

    if (pair_count == 0)
        return;

    uint32_t candidates[4];
    int candidate_count = 0;
    for (int i = 0; i < pair_count; i++) {
        uint32_t local[4];
        int local_count = 0;
        if (!node24_hash_seed_candidates(pairs[i].chars, pairs[i].len, pairs[i].raw_hash, local, &local_count))
            continue;

        if (candidate_count == 0) {
            for (int j = 0; j < local_count; j++)
                candidates[j] = local[j];
            candidate_count = local_count;
            continue;
        }

        uint32_t intersection[4];
        int intersection_count = 0;
        for (int j = 0; j < candidate_count; j++) {
            for (int k = 0; k < local_count; k++) {
                if (candidates[j] == local[k]) {
                    intersection[intersection_count++] = candidates[j];
                    break;
                }
            }
        }
        for (int j = 0; j < intersection_count; j++)
            candidates[j] = intersection[j];
        candidate_count = intersection_count;
        if (candidate_count <= 1)
            break;
    }

    if (candidate_count == 1) {
        node24_hash_seed = candidates[0];
        node24_hash_seed_known = true;
        fprintf(stderr, "[node24] inferred V8 hash seed %#x\n", node24_hash_seed);
    }
}

static bool maybe_bypass_node24_forwarding_lookup(struct cpu_state *cpu, addr_t ip) {
    static uint32_t bypasses_logged = 0;
    static uint32_t fallback_logged = 0;

    // Fast path: known helper entry ends in ...8f0.
    if ((ip & 0xfff) != 0x8f0)
        return false;
    if (!node24_match_forwarding_lookup(ip))
        return false;

    uint32_t size;
    if (user_get((addr_t)(cpu->rdi + 0x28), size))
        return false;

    uint32_t index = (uint32_t) cpu->rsi;
    if (!(index == 0 && size == 0))
        return false;

    uint64_t ret_addr;
    if (user_get((addr_t)CPU_SP(cpu), ret_addr))
        return false;

    uint32_t return_hash = V8_HASH_FIELD_HASH;
    addr_t patched_string = 0;
    int patched_reg = -1;
    static const char *reg_names[] = {
        "rax", "rbx", "rcx", "rdx", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    addr_t candidates[] = {
        cpu->rax, cpu->rbx, cpu->rcx, cpu->rdx, cpu->rbp,
        cpu->r8, cpu->r9, cpu->r10, cpu->r11, cpu->r12, cpu->r13, cpu->r14, cpu->r15,
    };
    for (unsigned i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        uint32_t patched;
        if (node24_patch_empty_one_byte_string(candidates[i], &patched)) {
            return_hash = patched;
            patched_string = candidates[i];
            patched_reg = (int) i;
            break;
        }
    }

    // Short-circuit return from helper with a non-empty hash field.
    cpu->rax = return_hash;
    CPU_SP(cpu) += 8;
    CPU_IP(cpu) = ret_addr;

    if (patched_string == 0 && fallback_logged < 8) {
        fallback_logged++;
        fprintf(stderr, "[node24] forwarding lookup fallback at %#llx ret=%#llx\n",
                (unsigned long long)ip, (unsigned long long)ret_addr);
    }

    if (bypasses_logged < 8) {
        bypasses_logged++;
        fprintf(stderr, "[node24] bypassed empty forwarding-table lookup at %#llx ret=%#llx hash=%#x",
                (unsigned long long)ip, (unsigned long long)ret_addr, return_hash);
        if (patched_string)
            fprintf(stderr, " patched=%#llx(%s)", (unsigned long long)(patched_string - 1), reg_names[patched_reg]);
        fprintf(stderr, "\n");
    }
    return true;
}

static uint32_t node24_hash_one_byte_string(addr_t chars, uint32_t length) {
    uint32_t running = node24_hash_seed_known ? node24_hash_seed : 0;
    for (uint32_t i = 0; i < length; i++) {
        uint8_t c;
        if (user_get((addr_t)(chars + i), c))
            return 0;
        running += c;
        running += running << 10;
        running ^= running >> 6;
    }
    running += running << 3;
    running ^= running >> 11;
    running += running << 15;

    uint32_t hash = running & V8_HASH_FIELD_HASH_MASK;
    if (hash == 0)
        hash = V8_ZERO_HASH;
    return (hash << V8_HASH_FIELD_SHIFT) | V8_HASH_FIELD_HASH;
}

static bool node24_patch_empty_one_byte_string(addr_t string, uint32_t *patched_hash) {
    static bool bulk_patch_done = false;
    if ((string & 1) == 0)
        return false;

    uint32_t raw_hash;
    if (user_get((addr_t)(string + 7), raw_hash))
        return false;
    if ((raw_hash & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_EMPTY)
        return false;

    uint64_t map_ptr;
    uint16_t instance_type;
    uint32_t length;
    if (user_get((addr_t)(string - 1), map_ptr))
        return false;
    if ((map_ptr & 1) == 0)
        return false;
    if (user_get((addr_t)(map_ptr - 1 + 12), instance_type))
        return false;
    if (instance_type != V8_SEQ_ONE_BYTE_STRING_TYPE)
        return false;
    if (user_get((addr_t)(string + 11), length))
        return false;
    if (length == 0 || length > V8_STRING_MAX_FIXUP_LEN)
        return false;

    if (!node24_hash_seed_known)
        node24_try_learn_hash_seed(string - 1);

    uint32_t hash = node24_hash_one_byte_string((addr_t)(string + 15), length);
    if (hash == 0 || (hash & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_HASH)
        return false;
    if (user_put((addr_t)(string + 7), hash))
        return false;

    if (patched_hash != NULL)
        *patched_hash = hash;

    if (node24_hash_seed_known && !bulk_patch_done) {
        bulk_patch_done = true;
        addr_t base = string - 1;
        for (int64_t off = -0x1000; off <= 0x1000; off += 8) {
            addr_t addr = (addr_t)(base + off);
            uint64_t mp2;
            uint32_t hf2;
            uint32_t len2;
            uint16_t it2;
            if (user_get(addr, mp2) || user_get(addr + 8, hf2) || user_get(addr + 12, len2))
                continue;
            if ((hf2 & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_EMPTY)
                continue;
            if (len2 == 0 || len2 > V8_STRING_MAX_FIXUP_LEN)
                continue;
            if ((mp2 & 1) == 0 || user_get((addr_t)(mp2 - 1 + 12), it2))
                continue;
            if (it2 != V8_SEQ_ONE_BYTE_STRING_TYPE)
                continue;

            uint32_t h2 = node24_hash_one_byte_string((addr_t)(addr + 16), len2);
            if (h2 != 0 && (h2 & V8_HASH_FIELD_TYPE_MASK) == V8_HASH_FIELD_HASH)
                user_put((addr_t)(addr + 8), h2);
        }
    }
    return true;
}

static void maybe_fix_node24_empty_hash(struct cpu_state *cpu, addr_t ip) {
    static uint32_t fixups_logged = 0;

    // Fast path: helper entry offsets currently end with ...780 / ...960.
    uint64_t low12 = ip & 0xfff;
    if (low12 != 0x780 && low12 != 0x960)
        return;

    if (!node24_match_hash_helper(ip))
        return;

    addr_t string = cpu->rdx;
    uint32_t patched_hash;
    if (!node24_patch_empty_one_byte_string(string, &patched_hash))
        return;

    if (fixups_logged < 8) {
        fixups_logged++;
        fprintf(stderr, "[node24] fixed empty V8 string hash at %#llx -> %#x\n",
                (unsigned long long)(string - 1), patched_hash);
    }
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
#ifdef ISH_GUEST_64BIT
        if (maybe_bypass_node24_forwarding_lookup(&frame->cpu, ip))
            continue;
        maybe_fix_node24_empty_hash(&frame->cpu, ip);
#endif
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
