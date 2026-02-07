#include "misc.h"

#ifdef ISH_GUEST_64BIT

#include "emu/decode64.h"
#include <string.h>

// Global decoder instance
static ZydisDecoder decoder;
static bool decoder_initialized = false;

bool decode64_init(void) {
    if (decoder_initialized)
        return true;

    // Initialize decoder for 64-bit long mode
    ZyanStatus status = ZydisDecoderInit(&decoder,
                                          ZYDIS_MACHINE_MODE_LONG_64,
                                          ZYDIS_STACK_WIDTH_64);
    if (ZYAN_FAILED(status)) {
        return false;
    }

    decoder_initialized = true;
    return true;
}

void decode64_cleanup(void) {
    decoder_initialized = false;
}

// Convert Zydis register to our arg64 enum
enum arg64 zydis_reg_to_arg64(ZydisRegister reg) {
    switch (reg) {
        // 64-bit registers
        case ZYDIS_REGISTER_RAX: return arg64_rax;
        case ZYDIS_REGISTER_RCX: return arg64_rcx;
        case ZYDIS_REGISTER_RDX: return arg64_rdx;
        case ZYDIS_REGISTER_RBX: return arg64_rbx;
        case ZYDIS_REGISTER_RSP: return arg64_rsp;
        case ZYDIS_REGISTER_RBP: return arg64_rbp;
        case ZYDIS_REGISTER_RSI: return arg64_rsi;
        case ZYDIS_REGISTER_RDI: return arg64_rdi;
        case ZYDIS_REGISTER_R8:  return arg64_r8;
        case ZYDIS_REGISTER_R9:  return arg64_r9;
        case ZYDIS_REGISTER_R10: return arg64_r10;
        case ZYDIS_REGISTER_R11: return arg64_r11;
        case ZYDIS_REGISTER_R12: return arg64_r12;
        case ZYDIS_REGISTER_R13: return arg64_r13;
        case ZYDIS_REGISTER_R14: return arg64_r14;
        case ZYDIS_REGISTER_R15: return arg64_r15;

        // 32-bit registers (lower 32 bits of 64-bit regs)
        case ZYDIS_REGISTER_EAX: return arg64_rax;
        case ZYDIS_REGISTER_ECX: return arg64_rcx;
        case ZYDIS_REGISTER_EDX: return arg64_rdx;
        case ZYDIS_REGISTER_EBX: return arg64_rbx;
        case ZYDIS_REGISTER_ESP: return arg64_rsp;
        case ZYDIS_REGISTER_EBP: return arg64_rbp;
        case ZYDIS_REGISTER_ESI: return arg64_rsi;
        case ZYDIS_REGISTER_EDI: return arg64_rdi;
        case ZYDIS_REGISTER_R8D:  return arg64_r8;
        case ZYDIS_REGISTER_R9D:  return arg64_r9;
        case ZYDIS_REGISTER_R10D: return arg64_r10;
        case ZYDIS_REGISTER_R11D: return arg64_r11;
        case ZYDIS_REGISTER_R12D: return arg64_r12;
        case ZYDIS_REGISTER_R13D: return arg64_r13;
        case ZYDIS_REGISTER_R14D: return arg64_r14;
        case ZYDIS_REGISTER_R15D: return arg64_r15;

        // 16-bit registers
        case ZYDIS_REGISTER_AX: return arg64_rax;
        case ZYDIS_REGISTER_CX: return arg64_rcx;
        case ZYDIS_REGISTER_DX: return arg64_rdx;
        case ZYDIS_REGISTER_BX: return arg64_rbx;
        case ZYDIS_REGISTER_SP: return arg64_rsp;
        case ZYDIS_REGISTER_BP: return arg64_rbp;
        case ZYDIS_REGISTER_SI: return arg64_rsi;
        case ZYDIS_REGISTER_DI: return arg64_rdi;
        case ZYDIS_REGISTER_R8W:  return arg64_r8;
        case ZYDIS_REGISTER_R9W:  return arg64_r9;
        case ZYDIS_REGISTER_R10W: return arg64_r10;
        case ZYDIS_REGISTER_R11W: return arg64_r11;
        case ZYDIS_REGISTER_R12W: return arg64_r12;
        case ZYDIS_REGISTER_R13W: return arg64_r13;
        case ZYDIS_REGISTER_R14W: return arg64_r14;
        case ZYDIS_REGISTER_R15W: return arg64_r15;

        // 8-bit registers (low byte)
        case ZYDIS_REGISTER_AL: return arg64_rax;
        case ZYDIS_REGISTER_CL: return arg64_rcx;
        case ZYDIS_REGISTER_DL: return arg64_rdx;
        case ZYDIS_REGISTER_BL: return arg64_rbx;
        case ZYDIS_REGISTER_SPL: return arg64_rsp;
        case ZYDIS_REGISTER_BPL: return arg64_rbp;
        case ZYDIS_REGISTER_SIL: return arg64_rsi;
        case ZYDIS_REGISTER_DIL: return arg64_rdi;
        case ZYDIS_REGISTER_R8B:  return arg64_r8;
        case ZYDIS_REGISTER_R9B:  return arg64_r9;
        case ZYDIS_REGISTER_R10B: return arg64_r10;
        case ZYDIS_REGISTER_R11B: return arg64_r11;
        case ZYDIS_REGISTER_R12B: return arg64_r12;
        case ZYDIS_REGISTER_R13B: return arg64_r13;
        case ZYDIS_REGISTER_R14B: return arg64_r14;
        case ZYDIS_REGISTER_R15B: return arg64_r15;

        // Legacy 8-bit high registers
        case ZYDIS_REGISTER_AH: return arg64_rax;  // Note: need special handling
        case ZYDIS_REGISTER_CH: return arg64_rcx;
        case ZYDIS_REGISTER_DH: return arg64_rdx;
        case ZYDIS_REGISTER_BH: return arg64_rbx;

        // Segment registers for special cases
        case ZYDIS_REGISTER_GS: return arg64_gs;
        case ZYDIS_REGISTER_FS: return arg64_fs;

        // RIP for RIP-relative
        case ZYDIS_REGISTER_RIP: return arg64_rip_rel;

        // XMM registers
        case ZYDIS_REGISTER_XMM0:  return arg64_xmm0;
        case ZYDIS_REGISTER_XMM1:  return arg64_xmm1;
        case ZYDIS_REGISTER_XMM2:  return arg64_xmm2;
        case ZYDIS_REGISTER_XMM3:  return arg64_xmm3;
        case ZYDIS_REGISTER_XMM4:  return arg64_xmm4;
        case ZYDIS_REGISTER_XMM5:  return arg64_xmm5;
        case ZYDIS_REGISTER_XMM6:  return arg64_xmm6;
        case ZYDIS_REGISTER_XMM7:  return arg64_xmm7;
        case ZYDIS_REGISTER_XMM8:  return arg64_xmm8;
        case ZYDIS_REGISTER_XMM9:  return arg64_xmm9;
        case ZYDIS_REGISTER_XMM10: return arg64_xmm10;
        case ZYDIS_REGISTER_XMM11: return arg64_xmm11;
        case ZYDIS_REGISTER_XMM12: return arg64_xmm12;
        case ZYDIS_REGISTER_XMM13: return arg64_xmm13;
        case ZYDIS_REGISTER_XMM14: return arg64_xmm14;
        case ZYDIS_REGISTER_XMM15: return arg64_xmm15;

        // x87 FPU stack registers
        case ZYDIS_REGISTER_ST0: return arg64_st0;
        case ZYDIS_REGISTER_ST1: return arg64_st1;
        case ZYDIS_REGISTER_ST2: return arg64_st2;
        case ZYDIS_REGISTER_ST3: return arg64_st3;
        case ZYDIS_REGISTER_ST4: return arg64_st4;
        case ZYDIS_REGISTER_ST5: return arg64_st5;
        case ZYDIS_REGISTER_ST6: return arg64_st6;
        case ZYDIS_REGISTER_ST7: return arg64_st7;

        default:
            return arg64_invalid;
    }
}

// Get operand size from Zydis operand
enum size64 decode64_op_size(const ZydisDecodedOperand *op) {
    switch (op->size) {
        case 8:   return size64_8;
        case 16:  return size64_16;
        case 32:  return size64_32;
        case 64:  return size64_64;
        case 80:  return size64_80;
        case 128: return size64_128;
        case 256: return size64_256;
        default:  return size64_64;  // Default to 64-bit
    }
}

// Decode a memory operand
static void decode_memory_operand(const ZydisDecodedOperand *zop,
                                  struct decoded_op64 *op) {
    op->type = arg64_mem;
    op->size = decode64_op_size(zop);

    // Base register
    if (zop->mem.base != ZYDIS_REGISTER_NONE) {
        if (zop->mem.base == ZYDIS_REGISTER_RIP) {
            op->mem.rip_relative = true;
            op->mem.base = arg64_invalid;
        } else {
            op->mem.base = zydis_reg_to_arg64(zop->mem.base);
            op->mem.rip_relative = false;
        }
    } else {
        op->mem.base = arg64_invalid;
        op->mem.rip_relative = false;
    }

    // Index register
    if (zop->mem.index != ZYDIS_REGISTER_NONE) {
        op->mem.index = zydis_reg_to_arg64(zop->mem.index);
    } else {
        op->mem.index = arg64_invalid;
    }

    // Scale
    op->mem.scale = zop->mem.scale ? zop->mem.scale : 1;

    // Displacement (check size > 0 to see if there's a displacement)
    if (zop->mem.disp.size > 0) {
        op->mem.disp = zop->mem.disp.value;
    } else {
        op->mem.disp = 0;
    }

    // Special case: RIP-relative
    if (op->mem.rip_relative) {
        op->type = arg64_rip_rel;
    }
}

// Decode a single operand
// Check if a Zydis register is a high-byte register (AH, BH, CH, DH)
bool zydis_is_high_byte_reg(ZydisRegister reg) {
    return reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH ||
           reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH;
}

static void decode_operand(const ZydisDecodedOperand *zop,
                           struct decoded_op64 *op) {
    op->imm = 0;
    op->mem.base = arg64_invalid;
    op->mem.index = arg64_invalid;
    op->mem.scale = 1;
    op->mem.disp = 0;
    op->mem.rip_relative = false;

    switch (zop->type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            op->type = zydis_reg_to_arg64(zop->reg.value);
            op->size = decode64_op_size(zop);
            break;

        case ZYDIS_OPERAND_TYPE_MEMORY:
            decode_memory_operand(zop, op);
            break;

        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            op->type = arg64_imm;
            op->size = decode64_op_size(zop);
            if (zop->imm.is_signed) {
                op->imm = (int64_t)zop->imm.value.s;
            } else {
                op->imm = (int64_t)zop->imm.value.u;
            }
            break;

        case ZYDIS_OPERAND_TYPE_POINTER:
            // Far pointers - rare in 64-bit mode
            op->type = arg64_invalid;
            op->size = decode64_op_size(zop);
            break;

        default:
            op->type = arg64_invalid;
            op->size = size64_64;
            break;
    }
}

int decode64_inst(const uint8_t *code, size_t code_size,
                  uint64_t runtime_address,
                  struct decoded_inst64 *inst) {
    (void)runtime_address;  // May be used later for RIP-relative calculations

    if (!decoder_initialized) {
        if (!decode64_init())
            return 0;
    }

    memset(inst, 0, sizeof(*inst));

    // Decode the instruction
    ZyanStatus status = ZydisDecoderDecodeFull(
        &decoder,
        code, code_size,
        &inst->raw_inst,
        inst->raw_operands
    );

    if (ZYAN_FAILED(status)) {
        return 0;
    }

    // Copy basic info
    inst->mnemonic = inst->raw_inst.mnemonic;
    inst->length = inst->raw_inst.length;

    // Count visible operands (include implicit for instructions like CMP rax, imm)
    inst->operand_count = 0;
    for (int i = 0; i < inst->raw_inst.operand_count && i < 4; i++) {
        ZydisOperandVisibility vis = inst->raw_operands[i].visibility;
        // Include both EXPLICIT and IMPLICIT operands
        // IMPLICIT operands are things like RAX in "CMP rax, imm" (opcode 3d)
        // HIDDEN operands are things like FLAGS which we don't need
        if (vis == ZYDIS_OPERAND_VISIBILITY_EXPLICIT ||
            vis == ZYDIS_OPERAND_VISIBILITY_IMPLICIT) {
            decode_operand(&inst->raw_operands[i],
                          &inst->operands[inst->operand_count]);
            inst->operand_count++;
        }
    }

    // Check prefixes
    inst->has_lock = (inst->raw_inst.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0;
    inst->has_rep = (inst->raw_inst.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;
    inst->has_repne = (inst->raw_inst.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;

    // Check for segment override
    inst->has_segment_override = false;
    if (inst->raw_inst.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) {
        inst->has_segment_override = true;
        inst->segment = ZYDIS_REGISTER_GS;
    } else if (inst->raw_inst.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) {
        inst->has_segment_override = true;
        inst->segment = ZYDIS_REGISTER_FS;
    }

    return inst->length;
}

// Convert Zydis condition to our condition enum
enum cond64 zydis_cond_to_cond64(ZydisDecodedInstruction *inst) {
    // Map Jcc/SETcc/CMOVcc opcodes to conditions
    // The condition is encoded in the low 4 bits of the second opcode byte
    switch (inst->mnemonic) {
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_SETO:
        case ZYDIS_MNEMONIC_CMOVO:
            return cond64_O;

        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_SETB:
        case ZYDIS_MNEMONIC_CMOVB:
            return cond64_B;

        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_SETZ:
        case ZYDIS_MNEMONIC_CMOVZ:
            return cond64_E;

        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_SETBE:
        case ZYDIS_MNEMONIC_CMOVBE:
            return cond64_BE;

        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_SETS:
        case ZYDIS_MNEMONIC_CMOVS:
            return cond64_S;

        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_SETP:
        case ZYDIS_MNEMONIC_CMOVP:
            return cond64_P;

        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_SETL:
        case ZYDIS_MNEMONIC_CMOVL:
            return cond64_L;

        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_SETLE:
        case ZYDIS_MNEMONIC_CMOVLE:
            return cond64_LE;

        default:
            return cond64_O;  // Shouldn't happen
    }
}

bool decode64_is_branch(const struct decoded_inst64 *inst) {
    switch (inst->mnemonic) {
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
        case ZYDIS_MNEMONIC_JKNZD:
        case ZYDIS_MNEMONIC_JKZD:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JRCXZ:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_LOOP:
        case ZYDIS_MNEMONIC_LOOPE:
        case ZYDIS_MNEMONIC_LOOPNE:
            return true;
        default:
            return false;
    }
}

bool decode64_is_call(const struct decoded_inst64 *inst) {
    return inst->mnemonic == ZYDIS_MNEMONIC_CALL;
}

bool decode64_is_ret(const struct decoded_inst64 *inst) {
    return inst->mnemonic == ZYDIS_MNEMONIC_RET;
}

bool decode64_is_syscall(const struct decoded_inst64 *inst) {
    return inst->mnemonic == ZYDIS_MNEMONIC_SYSCALL;
}

int64_t decode64_branch_target(const struct decoded_inst64 *inst, uint64_t ip) {
    if (!decode64_is_branch(inst) && !decode64_is_call(inst))
        return 0;

    // Check if first operand is immediate (relative branch)
    if (inst->operand_count > 0 && inst->operands[0].type == arg64_imm) {
        return ip + inst->length + inst->operands[0].imm;
    }

    // Check raw operand for relative offset
    if (inst->raw_inst.operand_count > 0 &&
        inst->raw_operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return ip + inst->length + inst->raw_operands[0].imm.value.s;
    }

    return 0;  // Indirect branch
}

#endif // ISH_GUEST_64BIT
