// 64-bit code generator for iSH
// Uses Zydis decoder and 64-bit gadgets

#include "misc.h"

#ifdef ISH_GUEST_64BIT

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "asbestos/gen.h"
#include "emu/decode64.h"
#include "emu/interrupt.h"

// Gadget function type
typedef void (*gadget_t)(void);

// External gadget arrays (from assembly files)
extern gadget_t load64_gadgets[];
extern gadget_t load32_gadgets[];
extern gadget_t store64_gadgets[];
extern gadget_t store32_gadgets[];

// External gadgets
extern void gadget_exit(void);
extern void gadget_interrupt(void);
extern void gadget_syscall(void);
extern void gadget_nop(void);
extern void gadget_jmp(void);
extern void gadget_jmp_indir(void);
extern void gadget_call(void);
extern void gadget_call_indir(void);
extern void gadget_ret(void);
extern void gadget_push(void);
extern void gadget_pop(void);
// Debug gadgets (keep for future debugging if needed)
// extern void gadget_debug_store(void);
// extern void gadget_debug_load(void);
// extern void gadget_debug_add_r9(void);
// extern void gadget_debug_rdx(void);
// extern void gadget_debug_save_x8(void);

// Add gadgets for add/sub/xor
extern void gadget_add64_a(void);
extern void gadget_add64_c(void);
extern void gadget_add64_d(void);
extern void gadget_add64_b(void);
extern void gadget_add64_sp(void);
extern void gadget_add64_bp(void);
extern void gadget_add64_si(void);
extern void gadget_add64_di(void);
extern void gadget_add64_imm(void);
extern void gadget_add64_mem(void);
extern void gadget_add64_x8(void);  // For adding r8-r15
extern void gadget_add32_imm(void);
extern void gadget_sub64_a(void);
extern void gadget_sub64_c(void);
extern void gadget_sub64_d(void);
extern void gadget_sub64_b(void);
extern void gadget_sub64_sp(void);
extern void gadget_sub64_bp(void);
extern void gadget_sub64_si(void);
extern void gadget_sub64_di(void);
extern void gadget_sub64_imm(void);
extern void gadget_sub64_mem(void);
extern void gadget_sub64_x8(void);  // For subtracting r8-r15
extern void gadget_sub32_imm(void);
extern void gadget_xor64_a(void);
extern void gadget_xor64_c(void);
extern void gadget_xor64_d(void);
extern void gadget_xor64_b(void);
extern void gadget_xor64_sp(void);
extern void gadget_xor64_bp(void);
extern void gadget_xor64_si(void);
extern void gadget_xor64_di(void);
extern void gadget_xor64_imm(void);
extern void gadget_xor32_imm(void);
extern void gadget_and64_imm(void);
extern void gadget_and64_x8(void);
extern void gadget_and64_mem(void);
extern void gadget_or64_imm(void);
extern void gadget_or64_x8(void);
extern void gadget_or64_mem(void);
extern void gadget_or64_a(void);
extern void gadget_or64_c(void);
extern void gadget_or64_d(void);
extern void gadget_or64_b(void);
extern void gadget_or64_sp(void);
extern void gadget_or64_bp(void);
extern void gadget_or64_si(void);
extern void gadget_or64_di(void);
extern void gadget_and32_imm(void);
extern void gadget_sign_extend8(void);
extern void gadget_sign_extend16(void);
extern void gadget_sign_extend32(void);
extern void gadget_cmp64_imm(void);
extern void gadget_cmp64_reg(void);
extern void gadget_test64_imm(void);
extern void gadget_load16_mem(void);
extern void gadget_load8_mem(void);

// Shift gadgets
extern void gadget_shr64_one(void);
extern void gadget_shr64_cl(void);
extern void gadget_shr64_imm(void);
extern void gadget_shl64_one(void);
extern void gadget_shl64_cl(void);
extern void gadget_shl64_imm(void);
extern void gadget_sar64_one(void);
extern void gadget_sar64_cl(void);
extern void gadget_sar64_imm(void);

// Bit test gadgets
extern void gadget_bt64_reg(void);
extern void gadget_bt64_imm(void);
extern void gadget_bts64_reg(void);
extern void gadget_bts64_imm(void);
extern void gadget_btr64_reg(void);
extern void gadget_btr64_imm(void);
extern void gadget_btc64_reg(void);
extern void gadget_btc64_imm(void);

// NOT/NEG gadgets
extern void gadget_not64(void);
extern void gadget_not32(void);
extern void gadget_neg64(void);
extern void gadget_neg32(void);

// Gadget arrays for register operations
static gadget_t add64_gadgets[] = {
    gadget_add64_a, gadget_add64_c, gadget_add64_d, gadget_add64_b,
    gadget_add64_sp, gadget_add64_bp, gadget_add64_si, gadget_add64_di
};
static gadget_t sub64_gadgets[] = {
    gadget_sub64_a, gadget_sub64_c, gadget_sub64_d, gadget_sub64_b,
    gadget_sub64_sp, gadget_sub64_bp, gadget_sub64_si, gadget_sub64_di
};
static gadget_t xor64_gadgets[] = {
    gadget_xor64_a, gadget_xor64_c, gadget_xor64_d, gadget_xor64_b,
    gadget_xor64_sp, gadget_xor64_bp, gadget_xor64_si, gadget_xor64_di
};
static gadget_t or64_gadgets[] = {
    gadget_or64_a, gadget_or64_c, gadget_or64_d, gadget_or64_b,
    gadget_or64_sp, gadget_or64_bp, gadget_or64_si, gadget_or64_di
};

// Conditional jump gadgets
extern void gadget_jmp_o(void);
extern void gadget_jmp_c(void);
extern void gadget_jmp_z(void);
extern void gadget_jmp_cz(void);
extern void gadget_jmp_s(void);
extern void gadget_jmp_p(void);
extern void gadget_jmp_sxo(void);
extern void gadget_jmp_sxoz(void);

// Conditional move gadgets (condition true = use source)
extern void gadget_cmov_o(void);
extern void gadget_cmov_c(void);
extern void gadget_cmov_z(void);
extern void gadget_cmov_cz(void);
extern void gadget_cmov_s(void);
extern void gadget_cmov_p(void);
extern void gadget_cmov_sxo(void);
extern void gadget_cmov_sxoz(void);
// Conditional move gadgets (condition true = keep dest)
extern void gadget_cmovn_o(void);
extern void gadget_cmovn_c(void);
extern void gadget_cmovn_z(void);
extern void gadget_cmovn_cz(void);
extern void gadget_cmovn_s(void);
extern void gadget_cmovn_p(void);
extern void gadget_cmovn_sxo(void);
extern void gadget_cmovn_sxoz(void);
// Helper for cmov: save _xtmp to x8
extern void gadget_save_xtmp_to_x8(void);

// r8-r15 load/store gadgets (these are in memory, not ARM64 registers)
extern void gadget_load64_r8(void);
extern void gadget_load64_r9(void);
extern void gadget_load64_r10(void);
extern void gadget_load64_r11(void);
extern void gadget_load64_r12(void);
extern void gadget_load64_r13(void);
extern void gadget_load64_r14(void);
extern void gadget_load64_r15(void);
extern void gadget_store64_r8(void);
extern void gadget_store64_r9(void);
extern void gadget_store64_r10(void);
extern void gadget_store64_r11(void);
extern void gadget_store64_r12(void);
extern void gadget_store64_r13(void);
extern void gadget_store64_r14(void);
extern void gadget_store64_r15(void);

// Address calculation gadgets for r8-r15
extern void gadget_addr_r8(void);
extern void gadget_addr_r9(void);
extern void gadget_addr_r10(void);
extern void gadget_addr_r11(void);
extern void gadget_addr_r12(void);
extern void gadget_addr_r13(void);
extern void gadget_addr_r14(void);
extern void gadget_addr_r15(void);

// Address gadgets for r8-r15 (indexed by reg - arg64_r8)
static gadget_t addr_r8_r15[] = {
    gadget_addr_r8, gadget_addr_r9, gadget_addr_r10, gadget_addr_r11,
    gadget_addr_r12, gadget_addr_r13, gadget_addr_r14, gadget_addr_r15
};

// Helper to emit code
static void gen(struct gen_state *state, unsigned long thing) {
    assert(state->size <= state->capacity);
    if (state->size >= state->capacity) {
        state->capacity *= 2;
        struct fiber_block *bigger_block = realloc(state->block,
                sizeof(struct fiber_block) + state->capacity * sizeof(unsigned long));
        if (bigger_block == NULL) {
            die("out of memory while generating 64-bit code");
        }
        state->block = bigger_block;
    }
    assert(state->size < state->capacity);
    state->block->code[state->size++] = thing;
}

#define GEN(thing) gen(state, (unsigned long)(thing))
#define g(gadget_name) GEN(gadget_##gadget_name)

void gen_start(addr_t addr, struct gen_state *state) {
    state->capacity = FIBER_BLOCK_INITIAL_CAPACITY;
    state->size = 0;
    state->ip = addr;
    for (int i = 0; i <= 1; i++) {
        state->jump_ip[i] = 0;
    }
    state->block_patch_ip = 0;

    struct fiber_block *block = malloc(sizeof(struct fiber_block) + state->capacity * sizeof(unsigned long));
    state->block = block;
    block->addr = addr;
}

void gen_end(struct gen_state *state) {
    struct fiber_block *block = state->block;
    for (int i = 0; i <= 1; i++) {
        if (state->jump_ip[i] != 0) {
            block->jump_ip[i] = &block->code[state->jump_ip[i]];
            block->old_jump_ip[i] = *block->jump_ip[i];
        } else {
            block->jump_ip[i] = NULL;
        }
        list_init(&block->jumps_from[i]);
        list_init(&block->jumps_from_links[i]);
    }
    if (state->block_patch_ip != 0) {
        block->code[state->block_patch_ip] = (unsigned long) block;
    }
    if (block->addr != state->ip)
        block->end_addr = state->ip - 1;
    else
        block->end_addr = block->addr;
    list_init(&block->chain);
    block->is_jetsam = false;
    for (int i = 0; i <= 1; i++) {
        list_init(&block->page[i]);
    }
}

void gen_exit(struct gen_state *state) {
    g(exit);
    GEN(state->ip);
}

// Load gadgets for r8-r15 (indexed by reg - arg64_r8)
static gadget_t load64_r8_r15[] = {
    gadget_load64_r8, gadget_load64_r9, gadget_load64_r10, gadget_load64_r11,
    gadget_load64_r12, gadget_load64_r13, gadget_load64_r14, gadget_load64_r15
};

// Store gadgets for r8-r15 (indexed by reg - arg64_r8)
static gadget_t store64_r8_r15[] = {
    gadget_store64_r8, gadget_store64_r9, gadget_store64_r10, gadget_store64_r11,
    gadget_store64_r12, gadget_store64_r13, gadget_store64_r14, gadget_store64_r15
};

// Get load gadget for a register
static gadget_t get_load64_reg_gadget(enum arg64 reg) {
    if (reg >= arg64_rax && reg <= arg64_rdi) {
        return load64_gadgets[reg - arg64_rax];
    }
    // r8-r15 are stored in memory
    if (reg >= arg64_r8 && reg <= arg64_r15) {
        return load64_r8_r15[reg - arg64_r8];
    }
    return NULL;
}

// Get store gadget for a register
static gadget_t get_store64_reg_gadget(enum arg64 reg) {
    if (reg >= arg64_rax && reg <= arg64_rdi) {
        return store64_gadgets[reg - arg64_rax];
    }
    // r8-r15 are stored in memory
    if (reg >= arg64_r8 && reg <= arg64_r15) {
        return store64_r8_r15[reg - arg64_r8];
    }
    return NULL;
}

// Helper to check if a type is a general purpose register (rax-rdi or r8-r15)
static inline bool is_gpr(enum arg64 type) {
    return (type >= arg64_rax && type <= arg64_rdi) ||
           (type >= arg64_r8 && type <= arg64_r15);
}

// Helper to check if a type is a memory operand (including RIP-relative)
static inline bool is_mem(enum arg64 type) {
    return type == arg64_mem || type == arg64_rip_rel;
}

// Address calculation gadgets
extern gadget_t addr_gadgets[];

// Scaled index gadgets: si_gadgets[reg * 4 + scale_idx]
// where scale_idx = {0,1,2,3} for scales {1,2,4,8}
extern gadget_t si_gadgets[];

// Helper to get scale index (0,1,2,3 for scale 1,2,4,8)
static inline int get_scale_idx(int scale) {
    switch (scale) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 2;
        case 8: return 3;
        default: return -1;
    }
}

// Generate address calculation for memory operand
static bool gen_addr(struct gen_state *state, struct decoded_op64 *op) {
    if (op->type != arg64_mem && op->type != arg64_rip_rel) return false;

    // RIP-relative addressing (common in x86_64)
    if (op->type == arg64_rip_rel || op->mem.rip_relative) {
        // Compute: state->ip (after instruction) + displacement
        int64_t effective_addr = state->ip + op->mem.disp;
        GEN(addr_gadgets[8]); // addr_none
        GEN(effective_addr);
        return true;
    }

    // Base register only (most common case for rax-rdi)
    if (op->mem.base >= arg64_rax && op->mem.base <= arg64_rdi &&
        op->mem.index == arg64_invalid) {
        // Load base into addr with displacement
        GEN(addr_gadgets[op->mem.base - arg64_rax]);
        GEN(op->mem.disp);
        return true;
    }

    // Base register r8-r15 (stored in memory)
    if (op->mem.base >= arg64_r8 && op->mem.base <= arg64_r15 &&
        op->mem.index == arg64_invalid) {
        GEN(addr_r8_r15[op->mem.base - arg64_r8]);
        GEN(op->mem.disp);
        return true;
    }

    // No base - displacement only
    if (op->mem.base == arg64_invalid && op->mem.index == arg64_invalid) {
        GEN(addr_gadgets[8]); // addr_none
        GEN(op->mem.disp);
        return true;
    }

    // No base + scaled index: [index*scale + disp]
    if (op->mem.base == arg64_invalid &&
        op->mem.index >= arg64_rax && op->mem.index <= arg64_rdi) {
        int scale_idx = get_scale_idx(op->mem.scale);
        if (scale_idx < 0) return false;

        // Start with displacement only
        GEN(addr_gadgets[8]); // addr_none
        GEN(op->mem.disp);

        // Apply scaled index: _addr = _addr + index * scale
        int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
        GEN(si_gadgets[si_index]);

        return true;
    }

    // No base + scaled index with r8-r15 as index
    // TODO: Add support for this when needed
    // if (op->mem.base == arg64_invalid &&
    //     op->mem.index >= arg64_r8 && op->mem.index <= arg64_r15) {
    //     return false; // Not yet implemented
    // }

    // Base + scaled index (base must be rax-rdi, index must be rax-rdi for now)
    if (op->mem.base >= arg64_rax && op->mem.base <= arg64_rdi &&
        op->mem.index >= arg64_rax && op->mem.index <= arg64_rdi) {
        int scale_idx = get_scale_idx(op->mem.scale);
        if (scale_idx < 0) return false;

        // Load base + displacement into _addr
        GEN(addr_gadgets[op->mem.base - arg64_rax]);
        GEN(op->mem.disp);

        // Apply scaled index: _addr = _addr + index * scale
        int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
        GEN(si_gadgets[si_index]);

        return true;
    }

    // Base r8-r15 + scaled index (rax-rdi)
    if (op->mem.base >= arg64_r8 && op->mem.base <= arg64_r15 &&
        op->mem.index >= arg64_rax && op->mem.index <= arg64_rdi) {
        int scale_idx = get_scale_idx(op->mem.scale);
        if (scale_idx < 0) return false;

        GEN(addr_r8_r15[op->mem.base - arg64_r8]);
        GEN(op->mem.disp);

        int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
        GEN(si_gadgets[si_index]);

        return true;
    }

    // More complex addressing modes not yet supported
    return false;
}

// Generate code for MOV instruction
static bool gen_mov(struct gen_state *state, struct decoded_inst64 *inst) {
    struct decoded_op64 *dst = &inst->operands[0];
    struct decoded_op64 *src = &inst->operands[1];

    // Determine operand size
    bool is64 = (dst->size == size64_64 || src->size == size64_64);
    bool is32 = (dst->size == size64_32 || src->size == size64_32);

    // MOV reg, reg (any GPR including r8-r15)
    if (is_gpr(dst->type) && is_gpr(src->type)) {
        gadget_t load_gadget = get_load64_reg_gadget(src->type);
        if (!load_gadget) return false;
        GEN(load_gadget);

        gadget_t store_gadget = get_store64_reg_gadget(dst->type);
        if (!store_gadget) return false;
        GEN(store_gadget);

        return true;
    }

    // MOV reg, imm (any GPR including r8-r15)
    if (is_gpr(dst->type) && src->type == arg64_imm) {
        if (is64) {
            GEN(load64_gadgets[8]); // load64_imm
        } else {
            GEN(load32_gadgets[8]); // load32_imm
        }
        GEN(src->imm);

        gadget_t store_gadget = get_store64_reg_gadget(dst->type);
        if (!store_gadget) return false;
        GEN(store_gadget);

        return true;
    }

    // MOV reg, [mem] (any GPR including r8-r15)
    if (is_gpr(dst->type) && is_mem(src->type)) {
        if (!gen_addr(state, src)) return false;
        if (is64) {
            GEN(load64_gadgets[9]); // load64_mem
        } else {
            GEN(load32_gadgets[9]); // load32_mem
        }
        GEN(state->orig_ip);

        gadget_t store_gadget = get_store64_reg_gadget(dst->type);
        if (!store_gadget) return false;
        GEN(store_gadget);

        return true;
    }

    // MOV [mem], reg (any GPR including r8-r15)
    if (is_mem(dst->type) && is_gpr(src->type)) {
        gadget_t load_gadget = get_load64_reg_gadget(src->type);
        if (!load_gadget) return false;
        GEN(load_gadget);

        if (!gen_addr(state, dst)) return false;
        if (is64) {
            GEN(store64_gadgets[9]); // store64_mem
        } else {
            GEN(store32_gadgets[9]); // store32_mem
        }
        GEN(state->orig_ip);

        return true;
    }

    // MOV [mem], imm
    if (is_mem(dst->type) && src->type == arg64_imm) {
        // Load immediate
        if (is64) {
            GEN(load64_gadgets[8]); // load64_imm
        } else {
            GEN(load32_gadgets[8]); // load32_imm
        }
        GEN(src->imm);

        // Calculate address and store
        if (!gen_addr(state, dst)) return false;
        if (is64) {
            GEN(store64_gadgets[9]); // store64_mem
        } else {
            GEN(store32_gadgets[9]); // store32_mem
        }
        GEN(state->orig_ip);

        return true;
    }

    // Unimplemented MOV variant
    return false;
}

// Generate code for a single instruction
int gen_step(struct gen_state *state, struct tlb *tlb) {
    state->orig_ip = state->ip;
    state->orig_ip_extra = 0;

    // Read instruction bytes from TLB
    uint8_t code[15];
    for (int i = 0; i < 15; i++) {
        if (!tlb_read(tlb, state->ip + i, &code[i], 1)) {
            // Generate interrupt for segfault
            g(interrupt);
            GEN(INT_GPF);
            GEN(state->orig_ip);
            GEN(tlb->segfault_addr);
            return 0;
        }
    }

    // Decode the instruction
    struct decoded_inst64 inst;
    int len = decode64_inst(code, 15, state->ip, &inst);
    if (len == 0) {
        // Decode failed - undefined instruction
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
    }

    // Advance IP past this instruction
    state->ip += len;

    // Mark fake_ip for jump patching
    #define fake_ip (state->ip | (1ul << 63))

    bool end_block = false;

    // Generate code based on mnemonic
    switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_NOP:
        case ZYDIS_MNEMONIC_ENDBR64:
            // Do nothing
            break;

        case ZYDIS_MNEMONIC_MOV:
            if (!gen_mov(state, &inst)) {
                // Fallback to interrupt for unimplemented
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_XOR:
            // Common case: xor rax, rax (zeroing)
            if (inst.operand_count >= 2 &&
                inst.operands[0].type == inst.operands[1].type &&
                is_gpr(inst.operands[0].type)) {
                // Load register
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                // XOR with itself using xor64_imm with value 0xFFFFFFFFFFFFFFFF then AND
                // Actually, XOR with same register zeros it. We need xor gadgets per reg.
                // For now, just load 0 and store - the xor gadget needs to be indexed.
                // TODO: proper xor gadget array
                GEN(load64_gadgets[8]); // load64_imm
                GEN(0);  // XOR with itself = 0
                // Store back
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_SYSCALL:
            g(syscall);
            end_block = true;
            break;

        case ZYDIS_MNEMONIC_JMP:
            // Unconditional jump
            if (inst.operand_count > 0 && inst.operands[0].type == arg64_imm) {
                // Relative jump
                int64_t target = state->ip + inst.operands[0].imm;
                g(jmp);
                GEN(target | (1ul << 63));
                state->jump_ip[0] = state->size - 1;
            } else if (inst.operand_count > 0 && is_gpr(inst.operands[0].type)) {
                // Indirect jump via register (JMP RAX, etc)
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                g(jmp_indir);
            } else if (inst.operand_count > 0 && inst.operands[0].type == arg64_mem) {
                // Indirect jump via memory (JMP [mem])
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                GEN(load64_gadgets[9]); // load64_mem
                GEN(state->orig_ip);
                g(jmp_indir);
            } else {
                // Unknown jump type
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            end_block = true;
            break;

        // Conditional jumps
        // jmp_* gadgets expect: [_ip] = taken target, [_ip+8] = not-taken target
        case ZYDIS_MNEMONIC_JO:  // Jump if Overflow
        case ZYDIS_MNEMONIC_JNO: // Jump if Not Overflow
        case ZYDIS_MNEMONIC_JB:  // Jump if Below (Carry)
        case ZYDIS_MNEMONIC_JNB: // Jump if Not Below (No Carry)
        case ZYDIS_MNEMONIC_JZ:  // Jump if Zero
        case ZYDIS_MNEMONIC_JNZ: // Jump if Not Zero
        case ZYDIS_MNEMONIC_JBE: // Jump if Below or Equal (Carry or Zero)
        case ZYDIS_MNEMONIC_JNBE: // Jump if Not Below or Equal
        case ZYDIS_MNEMONIC_JS:  // Jump if Sign
        case ZYDIS_MNEMONIC_JNS: // Jump if Not Sign
        case ZYDIS_MNEMONIC_JP:  // Jump if Parity
        case ZYDIS_MNEMONIC_JNP: // Jump if Not Parity
        case ZYDIS_MNEMONIC_JL:  // Jump if Less (Sign != Overflow)
        case ZYDIS_MNEMONIC_JNL: // Jump if Not Less (Sign == Overflow)
        case ZYDIS_MNEMONIC_JLE: // Jump if Less or Equal
        case ZYDIS_MNEMONIC_JNLE: // Jump if Not Less or Equal
            if (inst.operand_count > 0 && inst.operands[0].type == arg64_imm) {
                int64_t target = state->ip + inst.operands[0].imm;
                int64_t not_target = state->ip;  // Fall through

                // Select gadget and possibly swap targets for negated conditions
                gadget_t jcc_gadget = NULL;
                bool negate = false;

                switch (inst.mnemonic) {
                    case ZYDIS_MNEMONIC_JO:  jcc_gadget = gadget_jmp_o; break;
                    case ZYDIS_MNEMONIC_JNO: jcc_gadget = gadget_jmp_o; negate = true; break;
                    case ZYDIS_MNEMONIC_JB:  jcc_gadget = gadget_jmp_c; break;
                    case ZYDIS_MNEMONIC_JNB: jcc_gadget = gadget_jmp_c; negate = true; break;
                    case ZYDIS_MNEMONIC_JZ:  jcc_gadget = gadget_jmp_z; break;
                    case ZYDIS_MNEMONIC_JNZ: jcc_gadget = gadget_jmp_z; negate = true; break;
                    case ZYDIS_MNEMONIC_JBE: jcc_gadget = gadget_jmp_cz; break;
                    case ZYDIS_MNEMONIC_JNBE: jcc_gadget = gadget_jmp_cz; negate = true; break;
                    case ZYDIS_MNEMONIC_JS:  jcc_gadget = gadget_jmp_s; break;
                    case ZYDIS_MNEMONIC_JNS: jcc_gadget = gadget_jmp_s; negate = true; break;
                    case ZYDIS_MNEMONIC_JP:  jcc_gadget = gadget_jmp_p; break;
                    case ZYDIS_MNEMONIC_JNP: jcc_gadget = gadget_jmp_p; negate = true; break;
                    case ZYDIS_MNEMONIC_JL:  jcc_gadget = gadget_jmp_sxo; break;
                    case ZYDIS_MNEMONIC_JNL: jcc_gadget = gadget_jmp_sxo; negate = true; break;
                    case ZYDIS_MNEMONIC_JLE: jcc_gadget = gadget_jmp_sxoz; break;
                    case ZYDIS_MNEMONIC_JNLE: jcc_gadget = gadget_jmp_sxo; negate = true; break;
                    default: break;
                }

                if (jcc_gadget) {
                    GEN(jcc_gadget);
                    if (negate) {
                        // Swap taken/not-taken for negated conditions
                        GEN(not_target | (1ul << 63));
                        GEN(target | (1ul << 63));
                    } else {
                        GEN(target | (1ul << 63));
                        GEN(not_target | (1ul << 63));
                    }
                    state->jump_ip[0] = state->size - 2;
                    state->jump_ip[1] = state->size - 1;
                    end_block = true;
                }
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_RET:
            g(ret);
            GEN(state->orig_ip);
            GEN(8);  // pop 8 bytes for return address
            end_block = true;
            break;

        case ZYDIS_MNEMONIC_CALL:
            if (inst.operand_count > 0 && inst.operands[0].type == arg64_imm) {
                // Relative call
                int64_t target = state->ip + inst.operands[0].imm;
                g(call);
                GEN(state->orig_ip);
                GEN(-1);  // Will be patched to block address
                GEN(state->ip);  // Return address (actual, not fake)
                GEN(fake_ip);  // Return target for block chaining (patchable)
                GEN(target | (1ul << 63));
                state->block_patch_ip = state->size - 4;
                state->jump_ip[0] = state->size - 2;
                state->jump_ip[1] = state->size - 1;
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            end_block = true;
            break;

        case ZYDIS_MNEMONIC_PUSH:
            if (inst.operand_count > 0) {
                // Load the value to push
                if (is_gpr(inst.operands[0].type)) {
                    gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                    if (load) GEN(load);
                } else if (inst.operands[0].type == arg64_imm) {
                    GEN(load64_gadgets[8]); // load64_imm
                    GEN(inst.operands[0].imm);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                g(push);
                GEN(state->orig_ip);
            }
            break;

        case ZYDIS_MNEMONIC_POP:
            if (inst.operand_count > 0 && is_gpr(inst.operands[0].type)) {
                g(pop);
                GEN(state->orig_ip);
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_ADD:
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                // ADD reg, ...
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operands[1].type == arg64_imm) {
                    // ADD reg, imm
                    GEN(gadget_add64_imm);
                    GEN(inst.operands[1].imm);
                } else if (inst.operands[1].type >= arg64_rax &&
                           inst.operands[1].type <= arg64_rdi) {
                    // ADD reg, reg (rax-rdi)
                    GEN(add64_gadgets[inst.operands[1].type - arg64_rax]);
                } else if (inst.operands[1].type >= arg64_r8 &&
                           inst.operands[1].type <= arg64_r15) {
                    // ADD reg, r8-r15 (need to load r8-r15 from memory first)
                    // Save _xtmp (dst) to x8
                    GEN(gadget_save_xtmp_to_x8);
                    // Load r8-r15 into _xtmp
                    gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
                    if (load_src) GEN(load_src);
                    // add64_x8 does: _xtmp = _xtmp + x8 = src + dst
                    GEN(gadget_add64_x8);
                } else if (is_mem(inst.operands[1].type)) {
                    // ADD reg, [mem]
                    // We have: _xtmp = dst value
                    // Need: _addr = memory address, then add64_mem adds [_addr] to _xtmp
                    // gen_addr sets _addr and doesn't touch _xtmp
                    if (!gen_addr(state, &inst.operands[1])) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    GEN(gadget_add64_mem);
                    GEN(state->orig_ip);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }

                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else if (inst.operand_count >= 2 &&
                       inst.operands[0].type == arg64_mem &&
                       inst.operands[1].type >= arg64_rax &&
                       inst.operands[1].type <= arg64_rdi) {
                // ADD [mem], reg
                // 1. Calculate address
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                // 2. Load from memory
                GEN(load64_gadgets[9]); // load64_mem
                GEN(state->orig_ip);
                // 3. Add source register
                GEN(add64_gadgets[inst.operands[1].type - arg64_rax]);
                // 4. Recalculate address and store
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                GEN(store64_gadgets[9]); // store64_mem
                GEN(state->orig_ip);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_SUB:
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operands[1].type == arg64_imm) {
                    // SUB reg, imm
                    GEN(gadget_sub64_imm);
                    GEN(inst.operands[1].imm);
                } else if (inst.operands[1].type >= arg64_rax &&
                           inst.operands[1].type <= arg64_rdi) {
                    // SUB reg, reg (rax-rdi)
                    GEN(sub64_gadgets[inst.operands[1].type - arg64_rax]);
                } else if (inst.operands[1].type >= arg64_r8 &&
                           inst.operands[1].type <= arg64_r15) {
                    // SUB reg, r8-r15
                    // Save dst to x8
                    GEN(gadget_save_xtmp_to_x8);
                    // Load r8-r15 into _xtmp
                    gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
                    if (load_src) GEN(load_src);
                    // sub64_x8 does: _xtmp = x8 - _xtmp = dst - src. Correct!
                    GEN(gadget_sub64_x8);
                } else if (is_mem(inst.operands[1].type)) {
                    // SUB reg, [mem]
                    if (!gen_addr(state, &inst.operands[1])) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    GEN(gadget_sub64_mem);
                    GEN(state->orig_ip);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }

                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_CDQE:
            // Sign-extend eax to rax (48 98)
            GEN(load64_gadgets[0]); // load64_a (load rax)
            GEN(gadget_sign_extend32);
            GEN(store64_gadgets[0]); // store64_a
            break;

        case ZYDIS_MNEMONIC_CMP:
            // Compare - sets flags without storing result
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                // Load first operand
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                // Compare with second operand
                if (inst.operands[1].type == arg64_imm) {
                    GEN(gadget_cmp64_imm);
                    GEN(inst.operands[1].imm);
                } else if (inst.operands[1].type >= arg64_rax &&
                           inst.operands[1].type <= arg64_rdi) {
                    // CMP with register (only rax-rdi for now, r8-r15 needs separate gadgets)
                    GEN(gadget_cmp64_reg);
                    GEN(inst.operands[1].type - arg64_rax);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_TEST:
            // Test - AND without storing, sets flags
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operands[1].type == arg64_imm) {
                    GEN(gadget_test64_imm);
                    GEN(inst.operands[1].imm);
                } else if (is_gpr(inst.operands[1].type) &&
                           inst.operands[1].type == inst.operands[0].type) {
                    // TEST reg, reg (same register)
                    GEN(gadget_test64_imm);
                    GEN(-1ULL); // -1 ANDed with anything is itself
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else if (inst.operand_count >= 2 &&
                       inst.operands[0].type == arg64_imm &&
                       is_gpr(inst.operands[1].type)) {
                // Alternate ordering: (imm, reg)
                gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
                if (load) GEN(load);
                GEN(gadget_test64_imm);
                GEN(inst.operands[0].imm);
            } else if (inst.operand_count == 1 &&
                       inst.operands[0].type == arg64_imm) {
                // TEST AL, imm8 (short form a8) - AL is implicit
                // Load RAX and test (only low byte matters for flags)
                GEN(load64_gadgets[0]); // load64_a
                GEN(gadget_test64_imm);
                GEN(inst.operands[0].imm & 0xFF); // 8-bit immediate
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_AND:
            // Simple AND reg, imm
            if (inst.operand_count >= 2 &&
                is_gpr(inst.operands[0].type) &&
                inst.operands[1].type == arg64_imm) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                GEN(gadget_and64_imm);
                GEN(inst.operands[1].imm);
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_OR:
            // OR instruction
            if (inst.operand_count >= 2) {
                if (is_gpr(inst.operands[0].type)) {
                    // OR reg, ...
                    gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                    if (load) GEN(load);

                    if (inst.operands[1].type == arg64_imm) {
                        GEN(gadget_or64_imm);
                        GEN(inst.operands[1].imm);
                    } else if (is_gpr(inst.operands[1].type)) {
                        int reg_idx = inst.operands[1].type - arg64_rax;
                        if (reg_idx >= 0 && reg_idx < 8) {
                            GEN(or64_gadgets[reg_idx]);
                        } else {
                            // r8-r15: load to x8, use or64_x8
                            gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
                            if (load2) {
                                GEN(gadget_save_xtmp_to_x8);
                                GEN(load2);
                                // Swap: we want dst | src, but now _xtmp=src, x8=dst
                                // or64_x8 does _xtmp | x8, so swap first
                                GEN(gadget_or64_x8);
                            }
                        }
                    } else if (is_mem(inst.operands[1].type)) {
                        GEN(gadget_save_xtmp_to_x8);
                        if (!gen_addr(state, &inst.operands[1])) {
                            g(interrupt);
                            GEN(INT_UNDEFINED);
                            GEN(state->orig_ip);
                            GEN(state->orig_ip);
                            return 0;
                        }
                        GEN(load64_gadgets[9]); // load64_mem
                        GEN(state->orig_ip);
                        GEN(gadget_or64_x8);
                    } else {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }

                    gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                    if (store) GEN(store);
                } else if (is_mem(inst.operands[0].type)) {
                    // OR mem, reg - need to load reg to x8 first
                    if (is_gpr(inst.operands[1].type)) {
                        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
                        if (load_src) GEN(load_src);
                        GEN(gadget_save_xtmp_to_x8);
                        if (!gen_addr(state, &inst.operands[0])) {
                            g(interrupt);
                            GEN(INT_UNDEFINED);
                            GEN(state->orig_ip);
                            GEN(state->orig_ip);
                            return 0;
                        }
                        GEN(gadget_or64_mem);
                        GEN(state->orig_ip);
                    } else {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_SHR:
            // Logical shift right
            if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operand_count == 1) {
                    // Implicit 1 (opcode d1) - shift by 1
                    GEN(gadget_shr64_one);
                } else if (inst.operands[1].type == arg64_imm) {
                    if (inst.operands[1].imm == 1) {
                        GEN(gadget_shr64_one);
                    } else {
                        GEN(gadget_shr64_imm);
                        GEN(inst.operands[1].imm);
                    }
                } else if (inst.operands[1].type == arg64_rcx) {
                    GEN(gadget_shr64_cl);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }

                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_SHL:
            // Logical shift left
            if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operand_count == 1) {
                    // Implicit 1 (opcode d1) - shift by 1
                    GEN(gadget_shl64_one);
                } else if (inst.operands[1].type == arg64_imm) {
                    if (inst.operands[1].imm == 1) {
                        GEN(gadget_shl64_one);
                    } else {
                        GEN(gadget_shl64_imm);
                        GEN(inst.operands[1].imm);
                    }
                } else if (inst.operands[1].type == arg64_rcx) {
                    GEN(gadget_shl64_cl);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }

                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_SAR:
            // Arithmetic shift right
            if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);

                if (inst.operand_count == 1) {
                    // Implicit 1 (opcode d1) - shift by 1
                    GEN(gadget_sar64_one);
                } else if (inst.operands[1].type == arg64_imm) {
                    if (inst.operands[1].imm == 1) {
                        GEN(gadget_sar64_one);
                    } else {
                        GEN(gadget_sar64_imm);
                        GEN(inst.operands[1].imm);
                    }
                } else if (inst.operands[1].type == arg64_rcx) {
                    GEN(gadget_sar64_cl);
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }

                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_LEA:
            // LEA - load effective address
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                // Handle RIP-relative addressing (very common in x86_64)
                if (inst.operands[1].type == arg64_rip_rel ||
                    (inst.operands[1].type == arg64_mem && inst.operands[1].mem.rip_relative)) {
                    // LEA reg, [RIP + disp]
                    // Compute: state->ip (after instruction) + displacement
                    int64_t effective_addr = state->ip + inst.operands[1].mem.disp;
                    // Debug: trace RIP-relative LEA in _dlstart (entry area)
                    // 0x62984 offset = 0x7efffff5e000 + 0x62984 = 0x7efffffc0984
                    if (state->orig_ip >= 0x7efffffc0980 && state->orig_ip <= 0x7efffffc09a0) {
                        fprintf(stderr, "LEA RIP-rel: ip=0x%llx next_ip=0x%llx disp=0x%llx eff=0x%llx\n",
                                (unsigned long long)state->orig_ip,
                                (unsigned long long)state->ip,
                                (long long)inst.operands[1].mem.disp,
                                (unsigned long long)effective_addr);
                    }
                    GEN(load64_gadgets[8]); // load64_imm
                    GEN(effective_addr);
                    gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                    if (store) GEN(store);
                } else if (inst.operands[1].type == arg64_mem &&
                           is_gpr(inst.operands[1].mem.base) &&
                           inst.operands[1].mem.index == arg64_invalid) {
                    // LEA reg, [base + disp]
                    gadget_t load = get_load64_reg_gadget(inst.operands[1].mem.base);
                    if (load) GEN(load);
                    if (inst.operands[1].mem.disp != 0) {
                        GEN(gadget_add64_imm);
                        GEN(inst.operands[1].mem.disp);
                    }
                    gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                    if (store) GEN(store);
                } else if (inst.operands[1].type == arg64_mem &&
                           inst.operands[1].mem.base >= arg64_rax &&
                           inst.operands[1].mem.base <= arg64_rdi &&
                           inst.operands[1].mem.index >= arg64_rax &&
                           inst.operands[1].mem.index <= arg64_rdi) {
                    // LEA reg, [base + index*scale + disp]
                    // Use addr_gadgets for base + disp, then si_gadgets for scaled index
                    int scale_idx = get_scale_idx(inst.operands[1].mem.scale);
                    if (scale_idx < 0) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }

                    // Load base + displacement into _tmp via addr calculation
                    GEN(addr_gadgets[inst.operands[1].mem.base - arg64_rax]);
                    GEN(inst.operands[1].mem.disp);

                    // Apply scaled index
                    int si_index = (inst.operands[1].mem.index - arg64_rax) * 4 + scale_idx;
                    GEN(si_gadgets[si_index]);

                    // _addr now has the effective address, load it into dst
                    GEN(load64_gadgets[10]); // load64_addr - load _addr into _xtmp
                    gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                    if (store) GEN(store);
                } else if (inst.operands[1].type == arg64_mem &&
                           inst.operands[1].mem.base == arg64_invalid &&
                           inst.operands[1].mem.index >= arg64_rax &&
                           inst.operands[1].mem.index <= arg64_rdi) {
                    // LEA reg, [index*scale + disp] (no base register)
                    int scale_idx = get_scale_idx(inst.operands[1].mem.scale);
                    if (scale_idx < 0) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }

                    // Start with displacement only
                    GEN(addr_gadgets[8]); // addr_none - load displacement only
                    GEN(inst.operands[1].mem.disp);

                    // Apply scaled index
                    int si_index = (inst.operands[1].mem.index - arg64_rax) * 4 + scale_idx;
                    GEN(si_gadgets[si_index]);

                    // _addr now has the effective address, load it into dst
                    GEN(load64_gadgets[10]); // load64_addr - load _addr into _xtmp
                    gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                    if (store) GEN(store);
                } else {
                    // More complex LEA forms not yet supported
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        // CMOVcc - conditional move instructions
        case ZYDIS_MNEMONIC_CMOVO:
        case ZYDIS_MNEMONIC_CMOVNO:
        case ZYDIS_MNEMONIC_CMOVB:   // Also CMOVC, CMOVNAE
        case ZYDIS_MNEMONIC_CMOVNB:  // Also CMOVNC, CMOVAE
        case ZYDIS_MNEMONIC_CMOVZ:   // Also CMOVE
        case ZYDIS_MNEMONIC_CMOVNZ:  // Also CMOVNE
        case ZYDIS_MNEMONIC_CMOVBE:  // Also CMOVNA
        case ZYDIS_MNEMONIC_CMOVNBE: // Also CMOVA
        case ZYDIS_MNEMONIC_CMOVS:
        case ZYDIS_MNEMONIC_CMOVNS:
        case ZYDIS_MNEMONIC_CMOVP:   // Also CMOVPE
        case ZYDIS_MNEMONIC_CMOVNP:  // Also CMOVPO
        case ZYDIS_MNEMONIC_CMOVL:   // Also CMOVNGE
        case ZYDIS_MNEMONIC_CMOVNL:  // Also CMOVGE
        case ZYDIS_MNEMONIC_CMOVLE:  // Also CMOVNG
        case ZYDIS_MNEMONIC_CMOVNLE: // Also CMOVG
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type) &&
                (is_gpr(inst.operands[1].type) || is_mem(inst.operands[1].type))) {
                // CMOVcc: if condition, dst = src; else dst = dst
                // Gadget expects: x8 = dst (original value), _xtmp = src (potential new value)

                // Step 1: Load destination value into _xtmp, then save to x8
                gadget_t load_dst = get_load64_reg_gadget(inst.operands[0].type);
                if (load_dst) GEN(load_dst);
                GEN(gadget_save_xtmp_to_x8);

                // Step 2: Load source into _xtmp
                if (is_gpr(inst.operands[1].type)) {
                    gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
                    if (load_src) GEN(load_src);
                } else {
                    // Memory source
                    if (!gen_addr(state, &inst.operands[1])) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    GEN(load64_gadgets[9]); // load64_mem
                    GEN(state->orig_ip);
                }

                // Step 3: Select the right cmov gadget based on condition
                gadget_t cmov_gadget = NULL;
                switch (inst.mnemonic) {
                    case ZYDIS_MNEMONIC_CMOVO:   cmov_gadget = gadget_cmov_o; break;
                    case ZYDIS_MNEMONIC_CMOVNO:  cmov_gadget = gadget_cmovn_o; break;
                    case ZYDIS_MNEMONIC_CMOVB:   cmov_gadget = gadget_cmov_c; break;
                    case ZYDIS_MNEMONIC_CMOVNB:  cmov_gadget = gadget_cmovn_c; break;
                    case ZYDIS_MNEMONIC_CMOVZ:   cmov_gadget = gadget_cmov_z; break;
                    case ZYDIS_MNEMONIC_CMOVNZ:  cmov_gadget = gadget_cmovn_z; break;
                    case ZYDIS_MNEMONIC_CMOVBE:  cmov_gadget = gadget_cmov_cz; break;
                    case ZYDIS_MNEMONIC_CMOVNBE: cmov_gadget = gadget_cmovn_cz; break;
                    case ZYDIS_MNEMONIC_CMOVS:   cmov_gadget = gadget_cmov_s; break;
                    case ZYDIS_MNEMONIC_CMOVNS:  cmov_gadget = gadget_cmovn_s; break;
                    case ZYDIS_MNEMONIC_CMOVP:   cmov_gadget = gadget_cmov_p; break;
                    case ZYDIS_MNEMONIC_CMOVNP:  cmov_gadget = gadget_cmovn_p; break;
                    case ZYDIS_MNEMONIC_CMOVL:   cmov_gadget = gadget_cmov_sxo; break;
                    case ZYDIS_MNEMONIC_CMOVNL:  cmov_gadget = gadget_cmovn_sxo; break;
                    case ZYDIS_MNEMONIC_CMOVLE:  cmov_gadget = gadget_cmov_sxoz; break;
                    case ZYDIS_MNEMONIC_CMOVNLE: cmov_gadget = gadget_cmovn_sxoz; break;
                    default: break;
                }

                // Step 4: Apply conditional move (selects between x8 and _xtmp)
                if (cmov_gadget) {
                    GEN(cmov_gadget);
                }

                // Step 5: Store result to destination
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_MOVZX:
            // Zero-extend load
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                // Determine source size from operand
                if (is_mem(inst.operands[1].type)) {
                    // MOVZX reg, [mem]
                    if (!gen_addr(state, &inst.operands[1])) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    if (inst.operands[1].size == size64_8) {
                        GEN(gadget_load8_mem);
                    } else if (inst.operands[1].size == size64_16) {
                        GEN(gadget_load16_mem);
                    } else {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    GEN(state->orig_ip);
                } else if (is_gpr(inst.operands[1].type)) {
                    // MOVZX reg, reg (zero-extend smaller register)
                    gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
                    if (load) GEN(load);
                    // Apply appropriate mask
                    if (inst.operands[1].size == size64_8) {
                        GEN(gadget_and64_imm);
                        GEN(0xFF);
                    } else if (inst.operands[1].size == size64_16) {
                        GEN(gadget_and64_imm);
                        GEN(0xFFFF);
                    }
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                // Store to destination (writes to 32-bit or 64-bit reg)
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_MOVSX:
        case ZYDIS_MNEMONIC_MOVSXD:
            // Sign-extend load
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                if (is_mem(inst.operands[1].type)) {
                    // MOVSX reg, [mem]
                    if (!gen_addr(state, &inst.operands[1])) {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                    if (inst.operands[1].size == size64_8) {
                        GEN(gadget_load8_mem);
                        GEN(state->orig_ip);
                        GEN(gadget_sign_extend8);
                    } else if (inst.operands[1].size == size64_16) {
                        GEN(gadget_load16_mem);
                        GEN(state->orig_ip);
                        GEN(gadget_sign_extend16);
                    } else if (inst.operands[1].size == size64_32) {
                        GEN(load32_gadgets[9]); // load32_mem
                        GEN(state->orig_ip);
                        GEN(gadget_sign_extend32);
                    } else {
                        g(interrupt);
                        GEN(INT_UNDEFINED);
                        GEN(state->orig_ip);
                        GEN(state->orig_ip);
                        return 0;
                    }
                } else if (is_gpr(inst.operands[1].type)) {
                    // MOVSX reg, reg
                    gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
                    if (load) GEN(load);
                    if (inst.operands[1].size == size64_8) {
                        GEN(gadget_sign_extend8);
                    } else if (inst.operands[1].size == size64_16) {
                        GEN(gadget_sign_extend16);
                    } else if (inst.operands[1].size == size64_32) {
                        GEN(gadget_sign_extend32);
                    }
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_BT:
        case ZYDIS_MNEMONIC_BTS:
        case ZYDIS_MNEMONIC_BTR:
        case ZYDIS_MNEMONIC_BTC:
            // Bit test instructions: BT, BTS, BTR, BTC
            // BT r/m64, r64: test bit (op2 % 64) in op1, set CF
            // BTS: same but also set bit to 1
            // BTR: same but also clear bit to 0
            // BTC: same but also toggle bit
            if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
                // Load destination (value to test)
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                GEN(gadget_save_xtmp_to_x8);

                if (is_gpr(inst.operands[1].type)) {
                    // reg-reg form
                    gadget_t load_idx = get_load64_reg_gadget(inst.operands[1].type);
                    if (load_idx) GEN(load_idx);

                    switch (inst.mnemonic) {
                        case ZYDIS_MNEMONIC_BT:  GEN(gadget_bt64_reg); break;
                        case ZYDIS_MNEMONIC_BTS: GEN(gadget_bts64_reg); break;
                        case ZYDIS_MNEMONIC_BTR: GEN(gadget_btr64_reg); break;
                        case ZYDIS_MNEMONIC_BTC: GEN(gadget_btc64_reg); break;
                        default: break;
                    }

                    // BTS/BTR/BTC modify the value, store it back
                    if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
                        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                        if (store) GEN(store);
                    }
                } else if (inst.operands[1].type == arg64_imm) {
                    // immediate form - bit index is immediate
                    switch (inst.mnemonic) {
                        case ZYDIS_MNEMONIC_BT:  GEN(gadget_bt64_imm); break;
                        case ZYDIS_MNEMONIC_BTS: GEN(gadget_bts64_imm); break;
                        case ZYDIS_MNEMONIC_BTR: GEN(gadget_btr64_imm); break;
                        case ZYDIS_MNEMONIC_BTC: GEN(gadget_btc64_imm); break;
                        default: break;
                    }
                    GEN(inst.operands[1].imm);

                    // BTS/BTR/BTC modify the value, store it back
                    if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
                        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                        if (store) GEN(store);
                    }
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else if (inst.operand_count >= 2 && inst.operands[0].type == arg64_mem) {
                // Memory form - need to read, modify, write
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                GEN(load64_gadgets[9]); // load64_mem
                GEN(state->orig_ip);
                GEN(gadget_save_xtmp_to_x8);

                if (is_gpr(inst.operands[1].type)) {
                    gadget_t load_idx = get_load64_reg_gadget(inst.operands[1].type);
                    if (load_idx) GEN(load_idx);

                    switch (inst.mnemonic) {
                        case ZYDIS_MNEMONIC_BT:  GEN(gadget_bt64_reg); break;
                        case ZYDIS_MNEMONIC_BTS: GEN(gadget_bts64_reg); break;
                        case ZYDIS_MNEMONIC_BTR: GEN(gadget_btr64_reg); break;
                        case ZYDIS_MNEMONIC_BTC: GEN(gadget_btc64_reg); break;
                        default: break;
                    }

                    if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
                        GEN(store64_gadgets[9]); // store64_mem
                        GEN(state->orig_ip);
                    }
                } else if (inst.operands[1].type == arg64_imm) {
                    switch (inst.mnemonic) {
                        case ZYDIS_MNEMONIC_BT:  GEN(gadget_bt64_imm); break;
                        case ZYDIS_MNEMONIC_BTS: GEN(gadget_bts64_imm); break;
                        case ZYDIS_MNEMONIC_BTR: GEN(gadget_btr64_imm); break;
                        case ZYDIS_MNEMONIC_BTC: GEN(gadget_btc64_imm); break;
                        default: break;
                    }
                    GEN(inst.operands[1].imm);

                    if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
                        GEN(store64_gadgets[9]); // store64_mem
                        GEN(state->orig_ip);
                    }
                } else {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_NOT:
            // NOT - one's complement
            if (is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                GEN(gadget_not64);
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else if (inst.operands[0].type == arg64_mem) {
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                GEN(load64_gadgets[9]); // load64_mem
                GEN(state->orig_ip);
                GEN(gadget_not64);
                GEN(store64_gadgets[9]); // store64_mem
                GEN(state->orig_ip);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        case ZYDIS_MNEMONIC_NEG:
            // NEG - two's complement
            if (is_gpr(inst.operands[0].type)) {
                gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
                if (load) GEN(load);
                GEN(gadget_neg64);
                gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
                if (store) GEN(store);
            } else if (inst.operands[0].type == arg64_mem) {
                if (!gen_addr(state, &inst.operands[0])) {
                    g(interrupt);
                    GEN(INT_UNDEFINED);
                    GEN(state->orig_ip);
                    GEN(state->orig_ip);
                    return 0;
                }
                GEN(load64_gadgets[9]); // load64_mem
                GEN(state->orig_ip);
                GEN(gadget_neg64);
                GEN(store64_gadgets[9]); // store64_mem
                GEN(state->orig_ip);
            } else {
                g(interrupt);
                GEN(INT_UNDEFINED);
                GEN(state->orig_ip);
                GEN(state->orig_ip);
                return 0;
            }
            break;

        default:
            // Unimplemented instruction
            fprintf(stderr, "UNHANDLED: ip=0x%llx mnemonic=%d bytes=%02x %02x %02x %02x\n",
                    (unsigned long long)state->orig_ip, inst.mnemonic,
                    code[0], code[1], code[2], code[3]);
            g(interrupt);
            GEN(INT_UNDEFINED);
            GEN(state->orig_ip);
            GEN(state->orig_ip);
            return 0;
    }

    #undef fake_ip

    return !end_block;
}

#endif // ISH_GUEST_64BIT
