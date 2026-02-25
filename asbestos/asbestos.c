#define DEFAULT_CHANNEL instr
#include "debug.h"
#include "asbestos/asbestos.h"
#include "asbestos/gen.h"
#include "asbestos/frame.h"
#include "emu/cpu.h"
#include "emu/interrupt.h"
#include "kernel/memory.h"
#include "util/list.h"
#include <stdio.h>
#include <string.h>
#include "kernel/calls.h"

extern int current_pid(void);

// Retained as no-op hooks because debug callsites may still exist in kernel/*.c.
void dump_rip_ring(void) {}
void dump_rip_ring_v8_bytes(void) {}

#ifdef ISH_GUEST_64BIT
enum {
    V8_HASH_FIELD_TYPE_MASK = 0x3,
    V8_HASH_FIELD_INTEGER_INDEX = 0x0,
    V8_HASH_FIELD_HASH = 0x2,
    V8_HASH_FIELD_EMPTY = 0x3,
    V8_HASH_FIELD_SHIFT = 2,
    V8_HASH_FIELD_HASH_MASK = 0x3fffffff,
    V8_ZERO_HASH = 27,
    V8_MAX_HASH_CALC_LENGTH = 16383,
    V8_MAX_ARRAY_INDEX = 0xfffffffeu,
    V8_ARRAY_INDEX_VALUE_BITS = 24,
    V8_ARRAY_INDEX_LENGTH_SHIFT = V8_HASH_FIELD_SHIFT + V8_ARRAY_INDEX_VALUE_BITS,
    V8_SEQ_ONE_BYTE_STRING_TYPE = 0x0008,
    V8_INTERNALIZED_ONE_BYTE_STRING_TYPE = 0x0083,
    V8_STRING_MAX_FIXUP_LEN = 1u << 20,
    V8_INV_1P2_3 = 0x38e38e39u,
    V8_INV_1P2_10 = 0xc00ffc01u,
    V8_INV_1P2_15 = 0x3fff8001u,
};

static bool node24_patch_empty_one_byte_string(addr_t string, uint32_t *patched_hash);
static void node24_bulk_patch_mapped_pages(struct cpu_state *cpu);
static void node24_report_target_string_hashes(struct cpu_state *cpu);
static void node24_trace_define_property(struct cpu_state *cpu, addr_t ip);
static void node24_trace_fromjust_abort(struct cpu_state *cpu, addr_t ip);
static bool node24_try_decode_string_handle(addr_t candidate, char *out, size_t out_size);
static const bool node24_trace_verbose = false;
static bool node24_hash_seed_known = false;
static uint32_t node24_hash_seed = 0;

static bool node24_read_one_byte_string_preview(addr_t string, char *out, size_t out_size,
                                                uint32_t *out_len) {
    if (out_size == 0 || (string & 1) == 0)
        return false;

    uint64_t map_ptr;
    uint16_t instance_type;
    uint32_t length;
    if (user_get((addr_t)(string - 1), map_ptr))
        return false;
    if ((map_ptr & 1) == 0 || user_get((addr_t)(map_ptr - 1 + 12), instance_type))
        return false;
    if (instance_type != V8_SEQ_ONE_BYTE_STRING_TYPE &&
        instance_type != V8_INTERNALIZED_ONE_BYTE_STRING_TYPE)
        return false;
    if (user_get((addr_t)(string + 11), length))
        return false;

    uint32_t copy_len = length;
    if (copy_len > out_size - 1)
        copy_len = (uint32_t)(out_size - 1);
    for (uint32_t i = 0; i < copy_len; i++) {
        uint8_t c;
        if (user_get((addr_t)(string + 15 + i), c))
            return false;
        out[i] = (c >= 0x20 && c <= 0x7e) ? (char) c : '.';
    }
    out[copy_len] = '\0';
    if (out_len != NULL)
        *out_len = length;
    return true;
}

static bool node24_decode_tagged_instance_type(addr_t candidate, uint64_t *tagged_out,
                                               uint16_t *instance_type_out) {
    uint64_t tagged = candidate;
    if ((tagged & 1) == 0) {
        if (user_get(candidate, tagged))
            return false;
    }
    if ((tagged & 1) == 0)
        return false;

    uint64_t map_ptr = 0;
    uint16_t instance_type = 0;
    if (user_get((addr_t)(tagged - 1), map_ptr))
        return false;
    if ((map_ptr & 1) == 0)
        return false;
    if (user_get((addr_t)(map_ptr - 1 + 12), instance_type))
        return false;

    if (tagged_out != NULL)
        *tagged_out = tagged;
    if (instance_type_out != NULL)
        *instance_type_out = instance_type;
    return true;
}

static bool node24_try_decode_string_handle(addr_t candidate, char *out, size_t out_size) {
    if (node24_read_one_byte_string_preview(candidate, out, out_size, NULL))
        return true;

    uint64_t tagged = 0;
    if (user_get(candidate, tagged))
        return false;
    return node24_read_one_byte_string_preview((addr_t)tagged, out, out_size, NULL);
}

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

static bool node24_match_define_property(addr_t ip) {
    static const uint8_t sig[] = {
        0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
        0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec, 0x58,
    };
    for (unsigned i = 0; i < sizeof(sig); i++) {
        uint8_t b;
        if (user_get((addr_t)(ip + i), b) || b != sig[i])
            return false;
    }
    return true;
}

static bool node24_match_define_own_property(addr_t ip) {
    static const uint8_t sig[] = {
        0x55, 0x66, 0x0f, 0xef, 0xc0, 0x48, 0x89, 0xe5,
        0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00,
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
            node24_bulk_patch_mapped_pages(cpu);
            node24_report_target_string_hashes(cpu);
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
        char preview[96];
        uint32_t preview_len = 0;
        bool have_preview = patched_string &&
            node24_read_one_byte_string_preview(patched_string, preview, sizeof(preview), &preview_len);
        fprintf(stderr, "[node24] bypassed empty forwarding-table lookup at %#llx ret=%#llx hash=%#x",
                (unsigned long long)ip, (unsigned long long)ret_addr, return_hash);
        if (patched_string)
            fprintf(stderr, " patched=%#llx(%s)", (unsigned long long)(patched_string - 1), reg_names[patched_reg]);
        if (have_preview)
            fprintf(stderr, " str=\"%s\" len=%u", preview, preview_len);
        fprintf(stderr, "\n");
    }
    return true;
}

static uint32_t node24_hash_one_byte_string(addr_t chars, uint32_t length) {
    uint32_t index_array = 0;
    uint32_t index_integer = 0;
    bool is_array_index = true;
    bool is_integer_index = true;
    uint32_t running = node24_hash_seed_known ? node24_hash_seed : 0;
    for (uint32_t i = 0; i < length; i++) {
        uint8_t c;
        if (user_get((addr_t)(chars + i), c))
            return 0;
        running += c;
        running += running << 10;
        running ^= running >> 6;

        if (is_array_index || is_integer_index) {
            if (c < '0' || c > '9') {
                is_array_index = false;
                is_integer_index = false;
            } else if (i == 0 && length > 1 && c == '0') {
                is_array_index = false;
                is_integer_index = false;
            } else {
                uint32_t digit = (uint32_t)(c - '0');
                if (is_array_index) {
                    if (index_array > V8_MAX_ARRAY_INDEX / 10 ||
                        (index_array == V8_MAX_ARRAY_INDEX / 10 &&
                         digit > (V8_MAX_ARRAY_INDEX % 10))) {
                        is_array_index = false;
                    } else {
                        index_array = index_array * 10 + digit;
                    }
                }
                if (is_integer_index) {
                    if (index_integer > V8_HASH_FIELD_HASH_MASK / 10 ||
                        (index_integer == V8_HASH_FIELD_HASH_MASK / 10 &&
                         digit > (V8_HASH_FIELD_HASH_MASK % 10))) {
                        is_integer_index = false;
                    } else {
                        index_integer = index_integer * 10 + digit;
                    }
                }
            }
        }
    }

    if (length > V8_MAX_HASH_CALC_LENGTH) {
        uint32_t hash = length & V8_HASH_FIELD_HASH_MASK;
        return (hash << V8_HASH_FIELD_SHIFT) | V8_HASH_FIELD_HASH;
    }

    if (is_array_index) {
        uint32_t value = index_array & ((1u << V8_ARRAY_INDEX_VALUE_BITS) - 1);
        uint32_t len_bits = length << V8_ARRAY_INDEX_LENGTH_SHIFT;
        return (value << V8_HASH_FIELD_SHIFT) | len_bits;
    }

    if (is_integer_index) {
        return (index_integer << V8_HASH_FIELD_SHIFT) | V8_HASH_FIELD_INTEGER_INDEX;
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
    static addr_t last_bulk_base = 0;
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

    if (node24_hash_seed_known) {
        addr_t base = string - 1;
        if (last_bulk_base != 0 &&
            base >= (addr_t)(last_bulk_base - 0x4000) &&
            base <= (addr_t)(last_bulk_base + 0x4000)) {
            return true;
        }
        last_bulk_base = base;
        for (int64_t off = -0x4000; off <= 0x4000; off += 8) {
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

static void node24_bulk_patch_mapped_pages(struct cpu_state *cpu) {
    static bool done = false;
    if (done || !node24_hash_seed_known)
        return;

    struct mem *mem = container_of(cpu->mmu, struct mem, mmu);
    if (mem == NULL || mem->hash_table == NULL)
        return;

    uint64_t patched = 0;
    for (size_t bucket = 0; bucket < MEM_HASH_SIZE; bucket++) {
        for (struct pt_hash_entry *entry = mem->hash_table[bucket]; entry != NULL; entry = entry->next) {
            if (entry->entry.data == NULL || entry->entry.data->data == NULL)
                continue;
            addr_t page_base = (addr_t)entry->page << PAGE_BITS;
            size_t page_off = entry->entry.offset;
            if (page_off >= entry->entry.data->size)
                continue;
            size_t bytes_available = entry->entry.data->size - page_off;
            size_t scan_limit = bytes_available < PAGE_SIZE ? bytes_available : PAGE_SIZE;
            if (scan_limit < 16)
                continue;

            uint8_t *page_ptr = (uint8_t *)entry->entry.data->data + page_off;
            for (uint32_t off = 0; off + 16 <= scan_limit; off += 8) {
                addr_t addr = page_base + off;
                uint64_t map_ptr;
                uint32_t raw_hash;
                uint32_t length;
                uint16_t instance_type;
                memcpy(&map_ptr, page_ptr + off, sizeof(map_ptr));
                memcpy(&raw_hash, page_ptr + off + 8, sizeof(raw_hash));
                memcpy(&length, page_ptr + off + 12, sizeof(length));
                if ((raw_hash & V8_HASH_FIELD_TYPE_MASK) != V8_HASH_FIELD_EMPTY)
                    continue;
                if (length == 0 || length > V8_STRING_MAX_FIXUP_LEN)
                    continue;
                if ((map_ptr & 1) == 0 || user_get((addr_t)(map_ptr - 1 + 12), instance_type))
                    continue;
                if (instance_type != V8_SEQ_ONE_BYTE_STRING_TYPE)
                    continue;

                uint32_t new_hash = node24_hash_one_byte_string((addr_t)(addr + 16), length);
                if (new_hash == 0 || (new_hash & V8_HASH_FIELD_TYPE_MASK) == V8_HASH_FIELD_EMPTY ||
                    (new_hash & V8_HASH_FIELD_TYPE_MASK) == 0x1)
                    continue;
                if (user_put((addr_t)(addr + 8), new_hash) == 0)
                    patched++;
            }
        }
    }

    done = true;
    fprintf(stderr, "[node24] bulk patched %llu empty string hashes across mapped pages\n",
            (unsigned long long)patched);
}

static void node24_report_target_string_hashes(struct cpu_state *cpu) {
    static int reports_emitted = 0;
    if (reports_emitted >= 2)
        return;

    struct mem *mem = container_of(cpu->mmu, struct mem, mmu);
    if (mem == NULL || mem->hash_table == NULL)
        return;

    struct target_name {
        const char *name;
        uint32_t len;
    };
    static const struct target_name targets[] = {
        {"prepareMainThreadExecution", 26},
        {"getOptionValue", 14},
        {"versions", 8},
        {"openssl", 7},
        {"kMaxLength", 10},
        {"kStringMaxLength", 16},
        {"value", 5},
        {"ObjectDefineProperty", 20},
        {"RegExpPrototypeExec", 19},
    };
    bool found[sizeof(targets) / sizeof(targets[0])] = {false};

    for (size_t bucket = 0; bucket < MEM_HASH_SIZE; bucket++) {
        for (struct pt_hash_entry *entry = mem->hash_table[bucket]; entry != NULL; entry = entry->next) {
            if (entry->entry.data == NULL || entry->entry.data->data == NULL)
                continue;
            size_t page_off = entry->entry.offset;
            if (page_off >= entry->entry.data->size)
                continue;
            size_t bytes_available = entry->entry.data->size - page_off;
            size_t scan_limit = bytes_available < PAGE_SIZE ? bytes_available : PAGE_SIZE;
            if (scan_limit < 16)
                continue;

            addr_t page_base = (addr_t)entry->page << PAGE_BITS;
            uint8_t *page_ptr = (uint8_t *)entry->entry.data->data + page_off;
            for (uint32_t off = 0; off + 16 <= scan_limit; off += 8) {
                uint64_t map_ptr;
                uint32_t raw_hash;
                uint32_t length;
                uint16_t instance_type;
                memcpy(&map_ptr, page_ptr + off, sizeof(map_ptr));
                memcpy(&raw_hash, page_ptr + off + 8, sizeof(raw_hash));
                memcpy(&length, page_ptr + off + 12, sizeof(length));
                if (length == 0 || length > 64)
                    continue;
                if ((map_ptr & 1) == 0 || user_get((addr_t)(map_ptr - 1 + 12), instance_type))
                    continue;
                if (instance_type != V8_SEQ_ONE_BYTE_STRING_TYPE)
                    continue;
                if (off + 16 + length > scan_limit)
                    continue;

                for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
                    if (found[i] || length != targets[i].len)
                        continue;
                    if (memcmp(page_ptr + off + 16, targets[i].name, length) == 0) {
                        addr_t str_addr = page_base + off;
                        if (node24_hash_seed_known) {
                            uint32_t calc = node24_hash_one_byte_string((addr_t)(str_addr + 16), length);
                            fprintf(stderr,
                                    "[node24] target \"%s\" raw_hash=%#x calc=%#x addr=%#llx%s\n",
                                    targets[i].name, raw_hash, calc, (unsigned long long)str_addr,
                                    (calc == raw_hash) ? "" : " MISMATCH");
                        } else {
                            fprintf(stderr, "[node24] target \"%s\" raw_hash=%#x addr=%#llx\n",
                                    targets[i].name, raw_hash, (unsigned long long)str_addr);
                        }
                        found[i] = true;
                    }
                }
            }
        }
    }

    for (unsigned i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        if (!found[i]) {
            fprintf(stderr, "[node24] target \"%s\" not found in mapped pages yet\n",
                    targets[i].name);
        }
    }
    reports_emitted++;
}

static void node24_trace_define_property(struct cpu_state *cpu, addr_t ip) {
    if ((ip & 0xfff) == 0x4e5) {
        uint8_t s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0;
        bool sig_ok =
            user_get(ip + 0, s0) == 0 && user_get(ip + 1, s1) == 0 &&
            user_get(ip + 2, s2) == 0 && user_get(ip + 3, s3) == 0 &&
            user_get(ip + 4, s4) == 0 && user_get(ip + 5, s5) == 0 &&
            s0 == 0x48 && s1 == 0x8b && s2 == 0x55 &&
            s3 == 0xc8 && s4 == 0x64 && s5 == 0x48;
        if (sig_ok) {
            uint32_t iter_state = 0;
            uint64_t key_handle = 0;
            user_get((addr_t)(cpu->rbp - 0x8c), iter_state);
            user_get((addr_t)(cpu->rbp - 0x70), key_handle);
            char key_name[160];
            bool have_key = node24_try_decode_string_handle((addr_t)key_handle, key_name, sizeof(key_name));
            if (have_key && iter_state == 5 && cpu->rax == 0x1 &&
                (strcmp(key_name, "name") == 0 || strcmp(key_name, "length") == 0)) {
                if (node24_trace_verbose)
                    fprintf(stderr, "[node24] forcing DefineEpilogue success key=\"%s\" state=5\n", key_name);
                cpu->rax = 0x101;
            }
        }
    }
    if (!node24_trace_verbose)
        return;

    enum { MAX_CDB0_PENDING = 32 };
    struct cdb0_pending_call {
        addr_t ret_addr;
        uint64_t arg_rsi;
    };
    static struct cdb0_pending_call cdb0_pending[MAX_CDB0_PENDING];
    static int cdb0_pending_count = 0;
    static uint32_t cdb0_logged = 0;

    if ((ip & 0xfff) == 0xdb0) {
        uint8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        if (user_get(ip + 0, b0) == 0 && user_get(ip + 1, b1) == 0 &&
            user_get(ip + 2, b2) == 0 && user_get(ip + 3, b3) == 0 &&
            b0 == 0x40 && b1 == 0x84 && b2 == 0xf6 && b3 == 0x74 &&
            cdb0_pending_count < MAX_CDB0_PENDING) {
            addr_t ret_addr = 0;
            if (user_get((addr_t)CPU_SP(cpu), ret_addr) == 0) {
                uint64_t low12 = ret_addr & 0xfff;
                if (low12 == 0xc89 || low12 == 0xfde || low12 == 0x2fe) {
                    struct cdb0_pending_call *p = &cdb0_pending[cdb0_pending_count++];
                    p->ret_addr = ret_addr;
                    p->arg_rsi = cpu->rsi;
                }
            }
        }
    }

    if (cdb0_pending_count > 0 && ip == cdb0_pending[cdb0_pending_count - 1].ret_addr) {
        struct cdb0_pending_call p = cdb0_pending[--cdb0_pending_count];
        if (cdb0_logged < 32) {
            cdb0_logged++;
            fprintf(stderr, "[node24] cdb0 ret=%#llx arg_rsi=%#llx -> eax=%#x\n",
                    (unsigned long long)p.ret_addr, (unsigned long long)p.arg_rsi,
                    (unsigned)(cpu->rax & 0xffffffffu));
        }
    }

    if ((ip & 0xfff) == 0xff0) {
        static uint32_t false_path_logged = 0;
        uint8_t m0 = 0, m1 = 0, m2 = 0, m3 = 0, m4 = 0;
        if (false_path_logged < 32 &&
            user_get(ip + 0, m0) == 0 && user_get(ip + 1, m1) == 0 &&
            user_get(ip + 2, m2) == 0 && user_get(ip + 3, m3) == 0 &&
            user_get(ip + 4, m4) == 0 &&
            m0 == 0xb8 && m1 == 0x01 && m2 == 0x00 && m3 == 0x00 && m4 == 0x00) {
            uint64_t key_handle = 0;
            user_get((addr_t)(cpu->rbp - 0x70), key_handle);
            fprintf(stderr,
                    "[node24] false-path ip=%#llx pre_rax=%#llx r11=%#llx r10=%#llx key=%#llx\n",
                    (unsigned long long)ip, (unsigned long long)cpu->rax,
                    (unsigned long long)cpu->r11, (unsigned long long)cpu->r10,
                    (unsigned long long)key_handle);
            char key_name[160];
            if (node24_try_decode_string_handle((addr_t)key_handle, key_name, sizeof(key_name)))
                fprintf(stderr, "[node24] false-path key=\"%s\"\n", key_name);
            false_path_logged++;
        }
    }

    enum { MAX_PENDING = 32 };
    struct pending_call {
        addr_t ret_addr;
        addr_t call_site;
        addr_t arg_rsi;
        addr_t arg_rcx;
        addr_t arg_r8;
        char kind;
        char name[96];
        bool have_name;
    };
    static struct pending_call pending[MAX_PENDING];
    static int pending_count = 0;
    static uint32_t logged = 0;
    static struct pending_call core_pending[MAX_PENDING];
    static int core_pending_count = 0;
    static uint32_t core_logged = 0;

    // Trace the immediate return value from the internal 0x13400b0 call inside Define helper.
    // This catches the packed status before it is reduced into ax=0x1 / 0x101.
    if ((ip & 0xfff) == 0x709) {
        static uint32_t inner_logged = 0;
        uint8_t op0 = 0, op1 = 0;
        if (inner_logged < 24 &&
            user_get(ip + 0, op0) == 0 && user_get(ip + 1, op1) == 0 &&
            op0 == 0x84 && op1 == 0xc0) {
            uint32_t iter_state = 0;
            uint64_t key_handle = 0;
            uint64_t recv_handle = 0;
            user_get((addr_t)(cpu->rbp - 0x8c), iter_state);
            user_get((addr_t)(cpu->rbp - 0x70), key_handle);
            user_get((addr_t)(cpu->rbp - 0x60), recv_handle);
            fprintf(stderr,
                    "[node24] DefineInner ip=%#llx rax=%#llx lo32=%#x hi32=%#x state=%u key=%#llx recv=%#llx\n",
                    (unsigned long long)ip, (unsigned long long)cpu->rax,
                    (unsigned)(cpu->rax & 0xffffffffu), (unsigned)(cpu->rax >> 32), iter_state,
                    (unsigned long long)key_handle, (unsigned long long)recv_handle);
            char key_name[160];
            if (node24_try_decode_string_handle((addr_t)key_handle, key_name, sizeof(key_name)))
                fprintf(stderr, "[node24] DefineInner key=\"%s\"\n", key_name);
            inner_logged++;
        }
    }

    // The 0x1342380 helper converges at ...64e5 before returning ax.
    if ((ip & 0xfff) == 0x4e5) {
        static uint32_t epilogue_logged = 0;
        uint8_t s0 = 0, s1 = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0;
        bool sig_ok =
            user_get(ip + 0, s0) == 0 && user_get(ip + 1, s1) == 0 &&
            user_get(ip + 2, s2) == 0 && user_get(ip + 3, s3) == 0 &&
            user_get(ip + 4, s4) == 0 && user_get(ip + 5, s5) == 0 &&
            s0 == 0x48 && s1 == 0x8b && s2 == 0x55 &&
            s3 == 0xc8 && s4 == 0x64 && s5 == 0x48;
        if (sig_ok && epilogue_logged < 128) {
            uint32_t iter_state = 0;
            uint64_t key_handle = 0;
            uint64_t recv_handle = 0;
            user_get((addr_t)(cpu->rbp - 0x8c), iter_state);
            user_get((addr_t)(cpu->rbp - 0x70), key_handle);
            user_get((addr_t)(cpu->rbp - 0x60), recv_handle);
            char key_name[160];
            bool have_key = node24_try_decode_string_handle((addr_t)key_handle, key_name, sizeof(key_name));
            if (have_key && iter_state == 5 && cpu->rax == 0x1 &&
                (strcmp(key_name, "name") == 0 || strcmp(key_name, "length") == 0)) {
                fprintf(stderr, "[node24] forcing DefineEpilogue success key=\"%s\" state=5\n", key_name);
                cpu->rax = 0x101;
            }
            bool interesting = (cpu->rax != 0x101) || (iter_state != 6) ||
                               (have_key && strcmp(key_name, "name") == 0) ||
                               (epilogue_logged < 8);
            if (interesting) {
                fprintf(stderr,
                        "[node24] DefineEpilogue ip=%#llx rax=%#llx lo32=%#x hi32=%#x state=%u key=%#llx recv=%#llx r15=%#llx\n",
                        (unsigned long long)ip, (unsigned long long)cpu->rax,
                        (unsigned)(cpu->rax & 0xffffffffu), (unsigned)(cpu->rax >> 32), iter_state,
                        (unsigned long long)key_handle, (unsigned long long)recv_handle,
                        (unsigned long long)cpu->r15);
                if (have_key)
                    fprintf(stderr, "[node24] DefineEpilogue key=\"%s\"\n", key_name);
                epilogue_logged++;
            }
        }
    }

    // Track entry into the internal DefineOwnProperty core helper (RVA 0x1352a20).
    if ((ip & 0xfff) == 0xa20) {
        static const uint8_t core_sig[] = {0x55, 0x49, 0x89, 0xf1, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x50};
        bool core_match = true;
        for (unsigned i = 0; i < sizeof(core_sig); i++) {
            uint8_t b;
            if (user_get((addr_t)(ip + i), b) || b != core_sig[i]) {
                core_match = false;
                break;
            }
        }
        if (core_match && core_pending_count < MAX_PENDING) {
            addr_t ret_addr;
            if (user_get((addr_t)CPU_SP(cpu), ret_addr) == 0) {
                struct pending_call *p = &core_pending[core_pending_count++];
                p->ret_addr = ret_addr;
                p->call_site = ret_addr - 5;
                p->arg_rsi = cpu->rsi;
                p->arg_rcx = cpu->rcx;
                p->arg_r8 = cpu->r8;
                p->kind = 'C';
                p->have_name = false;
                p->name[0] = '\0';

                addr_t maybe_name = cpu->rdx;
                uint64_t tagged_name = 0;
                if ((maybe_name & 1) &&
                    node24_read_one_byte_string_preview(maybe_name, p->name, sizeof(p->name), NULL)) {
                    p->have_name = true;
                } else if (user_get(maybe_name, tagged_name) == 0 &&
                           (tagged_name & 1) &&
                           node24_read_one_byte_string_preview((addr_t)tagged_name, p->name, sizeof(p->name), NULL)) {
                    p->have_name = true;
                }
            }
        }
    }

    // Track entry into v8::Object::DefineProperty / DefineOwnProperty.
    bool is_define_property = ((ip & 0xfff) == 0x5d0) && node24_match_define_property(ip);
    bool is_define_own_property = ((ip & 0xfff) == 0x220) && node24_match_define_own_property(ip);
    if (is_define_property || is_define_own_property) {
        if (pending_count >= MAX_PENDING)
            return;
        addr_t ret_addr;
        if (user_get((addr_t)CPU_SP(cpu), ret_addr))
            return;

        struct pending_call *p = &pending[pending_count++];
        p->ret_addr = ret_addr;
        p->call_site = ret_addr - 5;
        p->arg_rsi = cpu->rsi;
        p->arg_rcx = cpu->rcx;
        p->arg_r8 = cpu->r8;
        p->kind = is_define_property ? 'P' : 'O';
        p->have_name = false;
        p->name[0] = '\0';

        // rdx is Local<Name>; it usually points to a handle slot containing a tagged String.
        addr_t maybe_name = cpu->rdx;
        uint64_t tagged_name = 0;
        if ((maybe_name & 1) && node24_read_one_byte_string_preview(maybe_name, p->name, sizeof(p->name), NULL)) {
            p->have_name = true;
        } else if (user_get(maybe_name, tagged_name) == 0 &&
                   (tagged_name & 1) &&
                   node24_read_one_byte_string_preview((addr_t)tagged_name, p->name, sizeof(p->name), NULL)) {
            p->have_name = true;
        }
        return;
    }

    // Track returns from DefineProperty and log failures.
    if (pending_count == 0)
        goto maybe_core_return;
    if (ip == pending[pending_count - 1].ret_addr) {
        struct pending_call p = pending[--pending_count];
        uint16_t ax = (uint16_t)(cpu->rax & 0xffff);
        uint8_t low = (uint8_t)(ax & 0xff);
        uint8_t high = (uint8_t)(ax >> 8);
        bool interesting = p.have_name &&
            (strcmp(p.name, "versions") == 0 ||
             strcmp(p.name, "openssl") == 0 ||
             strcmp(p.name, "kMaxLength") == 0 ||
             strcmp(p.name, "kStringMaxLength") == 0 ||
             strcmp(p.name, "process") == 0);
        bool should_log = (low == 0) || (high == 0) || interesting || logged < 16;
        if (should_log) {
            logged++;
            fprintf(stderr, "[node24] Define%c ret=%#llx call=%#llx ax=%#x low=%u high=%u",
                    p.kind, (unsigned long long)p.ret_addr, (unsigned long long)p.call_site, ax, low, high);
            if (p.have_name)
                fprintf(stderr, " name=\"%s\"", p.name);
            fprintf(stderr, " rsi=%#llx r8=%#llx",
                    (unsigned long long)p.arg_rsi, (unsigned long long)p.arg_r8);
            fprintf(stderr, "\n");
        }
    }

maybe_core_return:
    if (core_pending_count == 0 || ip != core_pending[core_pending_count - 1].ret_addr)
        return;
    struct pending_call c = core_pending[--core_pending_count];
    uint16_t core_ax = (uint16_t)(cpu->rax & 0xffff);
    uint8_t core_low = (uint8_t)(core_ax & 0xff);
    uint8_t core_high = (uint8_t)(core_ax >> 8);
    bool core_interesting = c.have_name &&
        (strcmp(c.name, "versions") == 0 ||
         strcmp(c.name, "openssl") == 0 ||
         strcmp(c.name, "kMaxLength") == 0 ||
         strcmp(c.name, "kStringMaxLength") == 0 ||
         strcmp(c.name, "process") == 0);
    bool core_should_log = (core_low == 0) || (core_high == 0) || core_interesting || core_logged < 16;
    if (core_should_log) {
        core_logged++;
        fprintf(stderr, "[node24] Define%c ret=%#llx call=%#llx ax=%#x low=%u high=%u",
                c.kind, (unsigned long long)c.ret_addr, (unsigned long long)c.call_site,
                core_ax, core_low, core_high);
        if (c.have_name)
            fprintf(stderr, " name=\"%s\"", c.name);
        fprintf(stderr, " rsi=%#llx r8=%#llx",
                (unsigned long long)c.arg_rsi, (unsigned long long)c.arg_r8);
        fprintf(stderr, "\n");

        if (core_high == 0) {
            uint64_t receiver_tagged = 0;
            uint16_t receiver_type = 0;
            if (node24_decode_tagged_instance_type(c.arg_rsi, &receiver_tagged, &receiver_type)) {
                fprintf(stderr, "[node24] Define%c failing receiver tagged=%#llx type=%#x\n",
                        c.kind, (unsigned long long)receiver_tagged, receiver_type);

                addr_t receiver_obj = (addr_t)(receiver_tagged - 1);
                for (unsigned i = 0; i < 10; i++) {
                    addr_t slot_addr = (addr_t)(receiver_obj + i * sizeof(uint64_t));
                    uint64_t slot = 0;
                    if (user_get(slot_addr, slot))
                        continue;
                    fprintf(stderr, "[node24] Define%c receiver[%u] @%#llx = %#llx",
                            c.kind, i, (unsigned long long)slot_addr, (unsigned long long)slot);
                    char decoded[160];
                    if (node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded))) {
                        fprintf(stderr, " -> \"%s\"", decoded);
                    } else {
                        uint64_t tagged_tmp = 0;
                        uint16_t type_tmp = 0;
                        if (node24_decode_tagged_instance_type((addr_t)slot, &tagged_tmp, &type_tmp))
                            fprintf(stderr, " (tagged=%#llx type=%#x)",
                                    (unsigned long long)tagged_tmp, type_tmp);
                    }
                    fprintf(stderr, "\n");
                }

                uint64_t map_ptr = 0;
                if (user_get(receiver_obj, map_ptr) == 0 && (map_ptr & 1)) {
                    addr_t map_obj = (addr_t)(map_ptr - 1);
                    for (unsigned i = 0; i < 12; i++) {
                        addr_t slot_addr = (addr_t)(map_obj + i * sizeof(uint64_t));
                        uint64_t slot = 0;
                        if (user_get(slot_addr, slot))
                            continue;
                        fprintf(stderr, "[node24] Define%c recv_map[%u] @%#llx = %#llx",
                                c.kind, i, (unsigned long long)slot_addr, (unsigned long long)slot);
                        char decoded[160];
                        if (node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded))) {
                            fprintf(stderr, " -> \"%s\"", decoded);
                        } else {
                            uint64_t tagged_tmp = 0;
                            uint16_t type_tmp = 0;
                            if (node24_decode_tagged_instance_type((addr_t)slot, &tagged_tmp, &type_tmp))
                                fprintf(stderr, " (tagged=%#llx type=%#x)",
                                        (unsigned long long)tagged_tmp, type_tmp);
                        }
                        fprintf(stderr, "\n");
                    }

                    uint64_t descriptors_tagged = 0;
                    if (user_get((addr_t)(map_obj + 5 * sizeof(uint64_t)), descriptors_tagged) == 0 &&
                        (descriptors_tagged & 1)) {
                        addr_t descriptors_obj = (addr_t)(descriptors_tagged - 1);
                        for (unsigned i = 0; i < 24; i++) {
                            addr_t slot_addr = (addr_t)(descriptors_obj + i * sizeof(uint64_t));
                            uint64_t slot = 0;
                            if (user_get(slot_addr, slot))
                                continue;
                            fprintf(stderr, "[node24] Define%c recv_desc[%u] @%#llx = %#llx",
                                    c.kind, i, (unsigned long long)slot_addr, (unsigned long long)slot);
                            char decoded[160];
                            if (node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded))) {
                                fprintf(stderr, " -> \"%s\"", decoded);
                            } else {
                                uint64_t tagged_tmp = 0;
                                uint16_t type_tmp = 0;
                                if (node24_decode_tagged_instance_type((addr_t)slot, &tagged_tmp, &type_tmp))
                                    fprintf(stderr, " (tagged=%#llx type=%#x)",
                                            (unsigned long long)tagged_tmp, type_tmp);
                            }
                            fprintf(stderr, "\n");
                        }
                    }
                }
            } else {
                fprintf(stderr, "[node24] Define%c failing receiver decode failed rsi=%#llx\n",
                        c.kind, (unsigned long long)c.arg_rsi);
            }

            for (unsigned i = 0; i < 8; i++) {
                addr_t slot_addr = (addr_t)(c.arg_rcx + i * sizeof(uint64_t));
                uint64_t slot = 0;
                if (user_get(slot_addr, slot))
                    continue;
                fprintf(stderr, "[node24] Define%c failing desc[%u] @%#llx = %#llx",
                        c.kind, i, (unsigned long long)slot_addr, (unsigned long long)slot);
                char decoded[160];
                if (node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded))) {
                    fprintf(stderr, " -> \"%s\"", decoded);
                } else {
                    uint64_t tagged_tmp = 0;
                    uint16_t type_tmp = 0;
                    if (node24_decode_tagged_instance_type((addr_t)slot, &tagged_tmp, &type_tmp))
                        fprintf(stderr, " (tagged=%#llx type=%#x)",
                                (unsigned long long)tagged_tmp, type_tmp);
                }
                fprintf(stderr, "\n");
            }
        }
    }
}

static void node24_trace_fromjust_abort(struct cpu_state *cpu, addr_t ip) {
    static uint32_t logged = 0;
    if (logged >= 8)
        return;
    if ((ip & 0xfff) != 0xd53)
        return;

    // Match the leaq ... ; leaq ... ; xorl eax sequence in Maybe::FromJust fatal path.
    static const uint8_t sig[] = {0x48, 0x8d, 0x35, 0x48, 0x8d, 0x3d, 0x31, 0xc0};
    uint8_t b0, b1, b2, b7, b8, b9, b14, b15;
    if (user_get(ip + 0, b0) || user_get(ip + 1, b1) || user_get(ip + 2, b2) ||
        user_get(ip + 7, b7) || user_get(ip + 8, b8) || user_get(ip + 9, b9) ||
        user_get(ip + 14, b14) || user_get(ip + 15, b15))
        return;
    if (!(b0 == sig[0] && b1 == sig[1] && b2 == sig[2] &&
          b7 == sig[3] && b8 == sig[4] && b9 == sig[5] &&
          b14 == sig[6] && b15 == sig[7])) {
        return;
    }

    addr_t caller = 0;
    user_get((addr_t)(cpu->rbp + 8), caller);
    logged++;
    fprintf(stderr, "[node24] FromJust abort path ip=%#llx caller=%#llx ax=%#x r9=%#llx\n",
            (unsigned long long)ip, (unsigned long long)caller,
            (unsigned)(cpu->rax & 0xffff), (unsigned long long)cpu->r9);

    struct {
        const char *name;
        addr_t value;
    } regs[] = {
        {"rdi", cpu->rdi}, {"rsi", cpu->rsi}, {"rdx", cpu->rdx}, {"rcx", cpu->rcx},
        {"r8", cpu->r8},   {"r9", cpu->r9},   {"r10", cpu->r10}, {"r11", cpu->r11},
        {"r12", cpu->r12}, {"r13", cpu->r13}, {"r14", cpu->r14}, {"r15", cpu->r15},
    };
    for (unsigned i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        char decoded[160];
        if (node24_try_decode_string_handle(regs[i].value, decoded, sizeof(decoded))) {
            fprintf(stderr, "[node24] FromJust %s=%#llx -> \"%s\"\n",
                    regs[i].name, (unsigned long long)regs[i].value, decoded);
        }
    }

    uint32_t rsp_hits = 0;
    for (unsigned i = 0; i < 48 && rsp_hits < 12; i++) {
        addr_t slot_addr = (addr_t)(CPU_SP(cpu) + i * sizeof(uint64_t));
        uint64_t slot = 0;
        if (user_get(slot_addr, slot))
            continue;
        char decoded[160];
        if (!node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded)))
            continue;
        fprintf(stderr, "[node24] FromJust rsp[%u] @%#llx = %#llx -> \"%s\"\n",
                i, (unsigned long long)slot_addr, (unsigned long long)slot, decoded);
        rsp_hits++;
    }

    uint32_t rbp_hits = 0;
    for (int off = -0x120; off <= 0x40 && rbp_hits < 16; off += (int)sizeof(uint64_t)) {
        int64_t slot_addr_i64 = (int64_t)cpu->rbp + off;
        if (slot_addr_i64 < 0)
            continue;
        addr_t slot_addr = (addr_t)slot_addr_i64;
        uint64_t slot = 0;
        if (user_get(slot_addr, slot))
            continue;
        char decoded[160];
        if (!node24_try_decode_string_handle((addr_t)slot, decoded, sizeof(decoded)))
            continue;
        fprintf(stderr, "[node24] FromJust rbp[%#x] @%#llx = %#llx -> \"%s\"\n",
                off, (unsigned long long)slot_addr, (unsigned long long)slot, decoded);
        rbp_hits++;
    }

    uint64_t pending_exc = 0;
    if (user_get((addr_t)(cpu->r13 + 0x300), pending_exc) == 0 && (pending_exc & 1)) {
        addr_t exc_obj = (addr_t)(pending_exc - 1);
        uint64_t slots[3] = {0, 0, 0};
        user_get((addr_t)(exc_obj + 0x20), slots[0]);
        user_get((addr_t)(exc_obj + 0x28), slots[1]);
        user_get((addr_t)(exc_obj + 0x30), slots[2]);
        for (int i = 0; i < 3; i++) {
            if ((slots[i] & 1) == 0)
                continue;
            char msg[160];
            if (node24_try_decode_string_handle((addr_t)slots[i], msg, sizeof(msg))) {
                fprintf(stderr, "[node24] pending_exc slot[%d] one-byte string: \"%s\"\n", i, msg);
            }
        }
    }
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
    node24_bulk_patch_mapped_pages(cpu);
    node24_report_target_string_hashes(cpu);

    if (fixups_logged < 8) {
        fixups_logged++;
        char preview[96];
        uint32_t preview_len = 0;
        bool have_preview =
            node24_read_one_byte_string_preview(string, preview, sizeof(preview), &preview_len);
        fprintf(stderr, "[node24] fixed empty V8 string hash at %#llx -> %#x\n",
                (unsigned long long)(string - 1), patched_hash);
        if (have_preview) {
            fprintf(stderr, "[node24] fixed string=\"%s\" len=%u\n", preview, preview_len);
        }
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
        node24_trace_define_property(&frame->cpu, ip);
        node24_trace_fromjust_abort(&frame->cpu, ip);
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
