#ifndef MODRM_H
#define MODRM_H

#include "debug.h"
#include "misc.h"
#include "emu/cpu.h"
#include "emu/tlb.h"

#undef DEFAULT_CHANNEL
#define DEFAULT_CHANNEL instr

// ModR/M structure with conditional register types
struct modrm {
    union {
#ifdef ISH_64BIT
        enum reg64 reg;
#else
        enum reg32 reg;
#endif
        unsigned opcode;
    };
    enum {
        modrm_reg, modrm_mem, modrm_mem_si
    } type;
    union {
#ifdef ISH_64BIT
        enum reg64 base;
#else
        enum reg32 base;
#endif
        unsigned rm_opcode;
    };
    int32_t offset;
#ifdef ISH_64BIT
    enum reg64 index;
#else
    enum reg32 index;
#endif
    enum {
        times_1 = 0,
        times_2 = 1,
        times_4 = 2,
    } shift;
};

// Constants for special register values
#ifdef ISH_64BIT
static const unsigned rm_sib = reg_rsp;
static const unsigned rm_none = reg_rsp;
static const unsigned rm_disp32 = reg_rbp;
#else
static const unsigned rm_sib = reg_esp;
static const unsigned rm_none = reg_esp;
static const unsigned rm_disp32 = reg_ebp;
#endif

#define MOD(byte) ((byte & 0b11000000) >> 6)
#define REG(byte) ((byte & 0b00111000) >> 3)
#define RM(byte)  ((byte & 0b00000111) >> 0)

// REX-aware ModR/M decoder for 64-bit mode
#ifdef ISH_64BIT
static inline bool modrm_decode64(addr_t *ip, struct tlb *tlb, struct modrm *modrm,
                                  byte_t rex_r, byte_t rex_x, byte_t rex_b) {
#define READ(thing) \
    *ip += sizeof(thing); \
    if (!tlb_read(tlb, *ip - sizeof(thing), &(thing), sizeof(thing))) \
        return false

    byte_t modrm_byte;
    READ(modrm_byte);

    enum {
        mode_disp0,
        mode_disp8,
        mode_disp32,
        mode_reg,
    } mode = MOD(modrm_byte);

    modrm->type = modrm_mem;
    
    // Apply REX.R extension to reg field  
    modrm->reg = REG(modrm_byte) + (rex_r << 3);
    
    // Apply REX.B extension to r/m field
    modrm->rm_opcode = RM(modrm_byte) + (rex_b << 3);
    
    if (mode == mode_reg) {
        modrm->type = modrm_reg;
        modrm->base = modrm->rm_opcode;  // In reg mode, base = r/m register
    } else if (RM(modrm_byte) == rm_disp32 && mode == mode_disp0) {
        // In 64-bit mode, mod=00 and r/m=101 (original, before REX) is RIP-relative
        modrm->base = reg_rip;
        mode = mode_disp32;
    } else if ((RM(modrm_byte) + (rex_b << 3)) == rm_sib && mode != mode_reg) {
        byte_t sib_byte;
        READ(sib_byte);
        
        // Apply REX.B to SIB base field
        modrm->base = RM(sib_byte) + (rex_b << 3);
        
        // Handle special case for disp32
        if (RM(modrm_byte) == rm_disp32) {
            if (mode == mode_disp0) {
                modrm->base = reg_none;
                mode = mode_disp32;
            } else {
                modrm->base = reg_rbp + (rex_b << 3);
            }
        }
        
        // Apply REX.X to SIB index field
        modrm->index = REG(sib_byte) + (rex_x << 3);
        modrm->shift = MOD(sib_byte);
        
        if (REG(sib_byte) != rm_none)  // Check base value before REX extension
            modrm->type = modrm_mem_si;
    } else {
        modrm->base = modrm->rm_opcode;
    }

    if (mode == mode_disp0) {
        modrm->offset = 0;
    } else if (mode == mode_disp8) {
        int8_t offset;
        READ(offset);
        modrm->offset = offset;
    } else if (mode == mode_disp32) {
        int32_t offset;
        READ(offset);
        modrm->offset = offset;
    }
#undef READ

    TRACE("reg=%s opcode=%d ", reg64_name(modrm->reg), modrm->opcode);
    TRACE("base=%s ", reg64_name(modrm->base));
    if (modrm->type != modrm_reg)
        TRACE("offset=%s0x%x ", modrm->offset < 0 ? "-" : "", modrm->offset);
    if (modrm->type == modrm_mem_si)
        TRACE("index=%s<<%d ", reg64_name(modrm->index), modrm->shift);

    return true;
}
#endif

// Original 32-bit ModR/M decoder (unchanged for compatibility)
static inline bool modrm_decode32(addr_t *ip, struct tlb *tlb, struct modrm *modrm) {
#define READ(thing) \
    *ip += sizeof(thing); \
    if (!tlb_read(tlb, *ip - sizeof(thing), &(thing), sizeof(thing))) \
        return false

    byte_t modrm_byte;
    READ(modrm_byte);

    enum {
        mode_disp0,
        mode_disp8,
        mode_disp32,
        mode_reg,
    } mode = MOD(modrm_byte);
    modrm->type = modrm_mem;
    modrm->reg = REG(modrm_byte);
    modrm->rm_opcode = RM(modrm_byte);
    if (mode == mode_reg) {
        modrm->type = modrm_reg;
        modrm->base = modrm->rm_opcode;
    } else if (modrm->rm_opcode == rm_disp32 && mode == mode_disp0) {
        modrm->base = reg_none;
        mode = mode_disp32;
    } else if (modrm->rm_opcode == rm_sib && mode != mode_reg) {
        byte_t sib_byte;
        READ(sib_byte);
        modrm->base = RM(sib_byte);
        // wtf intel
        if (modrm->rm_opcode == rm_disp32) {
            if (mode == mode_disp0) {
                modrm->base = reg_none;
                mode = mode_disp32;
            } else {
#ifdef ISH_64BIT
                modrm->base = reg_rbp;
#else
                modrm->base = reg_ebp;
#endif
            }
        }
        modrm->index = REG(sib_byte);
        modrm->shift = MOD(sib_byte);
        if (modrm->index != rm_none)
            modrm->type = modrm_mem_si;
    } else {
        modrm->base = modrm->rm_opcode;
    }

    if (mode == mode_disp0) {
        modrm->offset = 0;
    } else if (mode == mode_disp8) {
        int8_t offset;
        READ(offset);
        modrm->offset = offset;
    } else if (mode == mode_disp32) {
        int32_t offset;
        READ(offset);
        modrm->offset = offset;
    }
#undef READ

#ifdef ISH_64BIT
    TRACE("reg=%s opcode=%d ", reg64_name(modrm->reg), modrm->opcode);
    TRACE("base=%s ", reg64_name(modrm->base));
    if (modrm->type != modrm_reg)
        TRACE("offset=%s0x%x ", modrm->offset < 0 ? "-" : "", modrm->offset);
    if (modrm->type == modrm_mem_si)
        TRACE("index=%s<<%d ", reg64_name(modrm->index), modrm->shift);
#else
    TRACE("reg=%s opcode=%d ", reg32_name(modrm->reg), modrm->opcode);
    TRACE("base=%s ", reg32_name(modrm->base));
    if (modrm->type != modrm_reg)
        TRACE("offset=%s0x%x ", modrm->offset < 0 ? "-" : "", modrm->offset);
    if (modrm->type == modrm_mem_si)
        TRACE("index=%s<<%d ", reg32_name(modrm->index), modrm->shift);
#endif

    return true;
}

#endif
