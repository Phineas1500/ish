#ifndef DECODE64_H
#define DECODE64_H

#ifdef ISH_GUEST_64BIT

#include <stdint.h>
#include <stdbool.h>
#include "misc.h"

// Zydis headers
#include <Zydis/Zydis.h>

// Operand types for 64-bit - extends the 32-bit enum arg
// Must stay in sync with gadget arrays for 64-bit
enum arg64 {
    // 64-bit GPRs (matches register order)
    arg64_rax, arg64_rcx, arg64_rdx, arg64_rbx,
    arg64_rsp, arg64_rbp, arg64_rsi, arg64_rdi,
    arg64_r8,  arg64_r9,  arg64_r10, arg64_r11,
    arg64_r12, arg64_r13, arg64_r14, arg64_r15,
    // Other operand types
    arg64_imm,      // Immediate value
    arg64_mem,      // Memory operand
    arg64_rip_rel,  // RIP-relative addressing (common in x86_64)
    arg64_gs,       // GS segment
    arg64_fs,       // FS segment (TLS)
    arg64_count,
    arg64_invalid,
};

// Operand sizes for 64-bit
enum size64 {
    size64_8,
    size64_16,
    size64_32,
    size64_64,
    size64_128,  // XMM
    size64_256,  // YMM (if we ever support AVX)
    size64_count,
};

// Condition codes (same as 32-bit)
enum cond64 {
    cond64_O,   // Overflow
    cond64_B,   // Below (unsigned <)
    cond64_E,   // Equal
    cond64_BE,  // Below or equal (unsigned <=)
    cond64_S,   // Sign (negative)
    cond64_P,   // Parity
    cond64_L,   // Less (signed <)
    cond64_LE,  // Less or equal (signed <=)
    cond64_count,
};

// Decoded operand information for gadget generation
struct decoded_op64 {
    enum arg64 type;
    enum size64 size;

    // For memory operands
    struct {
        enum arg64 base;    // Base register (arg64_invalid if none)
        enum arg64 index;   // Index register (arg64_invalid if none)
        uint8_t scale;      // 1, 2, 4, or 8
        int64_t disp;       // Displacement
        bool rip_relative;  // RIP-relative addressing
    } mem;

    // For immediate operands
    int64_t imm;
};

// Decoded instruction for 64-bit
struct decoded_inst64 {
    ZydisMnemonic mnemonic;         // Zydis mnemonic
    uint8_t length;                 // Instruction length in bytes
    uint8_t operand_count;          // Number of operands (up to 4)
    struct decoded_op64 operands[4];

    // Prefix information
    bool has_lock;
    bool has_rep;
    bool has_repne;
    bool has_segment_override;
    ZydisRegister segment;

    // Original Zydis structures (for detailed access if needed)
    ZydisDecodedInstruction raw_inst;
    ZydisDecodedOperand raw_operands[ZYDIS_MAX_OPERAND_COUNT];
};

// Initialize the 64-bit decoder
// Returns true on success
bool decode64_init(void);

// Cleanup the 64-bit decoder
void decode64_cleanup(void);

// Decode a single instruction at the given address
// Returns the number of bytes decoded, or 0 on error
// The decoded instruction is stored in *inst
int decode64_inst(const uint8_t *code, size_t code_size,
                  uint64_t runtime_address,
                  struct decoded_inst64 *inst);

// Helper: Convert Zydis register to our arg64 enum
enum arg64 zydis_reg_to_arg64(ZydisRegister reg);

// Helper: Convert Zydis condition to our cond64 enum
enum cond64 zydis_cond_to_cond64(ZydisDecodedInstruction *inst);

// Helper: Get operand size as enum
enum size64 decode64_op_size(const ZydisDecodedOperand *op);

// Helper: Check if instruction is a branch
bool decode64_is_branch(const struct decoded_inst64 *inst);

// Helper: Check if instruction is a call
bool decode64_is_call(const struct decoded_inst64 *inst);

// Helper: Check if instruction is a ret
bool decode64_is_ret(const struct decoded_inst64 *inst);

// Helper: Check if instruction is syscall
bool decode64_is_syscall(const struct decoded_inst64 *inst);

// Helper: Get branch target (for relative branches)
// Returns 0 if not a relative branch
int64_t decode64_branch_target(const struct decoded_inst64 *inst, uint64_t ip);

#endif // ISH_GUEST_64BIT

#endif // DECODE64_H
