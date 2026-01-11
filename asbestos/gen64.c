// 64-bit code generator for iSH
// Uses Zydis decoder and 64-bit gadgets

#include "misc.h"

#ifdef ISH_GUEST_64BIT

#include "asbestos/gen.h"
#include "emu/decode64.h"
#include "emu/interrupt.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

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

// Gadget function type
typedef void (*gadget_t)(void);

// Helper to get mnemonic name for debugging
const char *zydis_mnemonic_name(int mnemonic) {
  switch (mnemonic) {
  case ZYDIS_MNEMONIC_MOV:
    return "MOV";
  case ZYDIS_MNEMONIC_MOVSX:
    return "MOVSX";
  case ZYDIS_MNEMONIC_MOVSXD:
    return "MOVSXD";
  case ZYDIS_MNEMONIC_MOVZX:
    return "MOVZX";
  case ZYDIS_MNEMONIC_ADD:
    return "ADD";
  case ZYDIS_MNEMONIC_SUB:
    return "SUB";
  case ZYDIS_MNEMONIC_LEA:
    return "LEA";
  case ZYDIS_MNEMONIC_XOR:
    return "XOR";
  case ZYDIS_MNEMONIC_AND:
    return "AND";
  case ZYDIS_MNEMONIC_OR:
    return "OR";
  case ZYDIS_MNEMONIC_CMP:
    return "CMP";
  case ZYDIS_MNEMONIC_TEST:
    return "TEST";
  case ZYDIS_MNEMONIC_PUSH:
    return "PUSH";
  case ZYDIS_MNEMONIC_POP:
    return "POP";
  case ZYDIS_MNEMONIC_CALL:
    return "CALL";
  case ZYDIS_MNEMONIC_RET:
    return "RET";
  case ZYDIS_MNEMONIC_JMP:
    return "JMP";
  case ZYDIS_MNEMONIC_SHL:
    return "SHL";
  case ZYDIS_MNEMONIC_SHR:
    return "SHR";
  case ZYDIS_MNEMONIC_SAR:
    return "SAR";
  case ZYDIS_MNEMONIC_IMUL:
    return "IMUL";
  case ZYDIS_MNEMONIC_MUL:
    return "MUL";
  case ZYDIS_MNEMONIC_DIV:
    return "DIV";
  case ZYDIS_MNEMONIC_IDIV:
    return "IDIV";
  default:
    return "???";
  }
}

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
extern void gadget_seg_fs(void);
extern void gadget_seg_gs(void);
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
extern void gadget_lea_add64_imm(void); // Flag-preserving add for LEA
extern void
gadget_lea_and64_imm(void); // Flag-preserving and for LEA 32-bit masking
extern void gadget_add64_mem(void);
extern void gadget_add64_x8(void); // For adding r8-r15 (64-bit)
extern void gadget_add32_x8(void); // For adding r8-r15 (32-bit)
extern void gadget_add32_imm(void);
extern void gadget_add32_mem(void);
extern void gadget_add32_a(void);
extern void gadget_add32_c(void);
extern void gadget_add32_d(void);
extern void gadget_add32_b(void);
extern void gadget_add32_sp(void);
extern void gadget_add32_bp(void);
extern void gadget_add32_si(void);
extern void gadget_add32_di(void);
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
extern void gadget_sub64_x8(void); // For subtracting r8-r15
extern void gadget_sub32_imm(void);
extern void gadget_sub32_mem(void);
extern void gadget_sub32_a(void);
extern void gadget_sub32_c(void);
extern void gadget_sub32_d(void);
extern void gadget_sub32_b(void);
extern void gadget_sub32_sp(void);
extern void gadget_sub32_bp(void);
extern void gadget_sub32_si(void);
extern void gadget_sub32_di(void);
extern void gadget_sbb64_a(void);
extern void gadget_sbb64_c(void);
extern void gadget_sbb64_d(void);
extern void gadget_sbb64_b(void);
extern void gadget_sbb64_sp(void);
extern void gadget_sbb64_bp(void);
extern void gadget_sbb64_si(void);
extern void gadget_sbb64_di(void);
extern void gadget_sbb64_imm(void);
extern void gadget_sbb32_a(void);
extern void gadget_sbb32_c(void);
extern void gadget_sbb32_d(void);
extern void gadget_sbb32_b(void);
extern void gadget_sbb32_sp(void);
extern void gadget_sbb32_bp(void);
extern void gadget_sbb32_si(void);
extern void gadget_sbb32_di(void);
extern void gadget_sbb32_imm(void);
extern void gadget_sbb64_x8(void);
extern void gadget_sbb32_x8(void);
extern void gadget_adc64_a(void);
extern void gadget_adc64_c(void);
extern void gadget_adc64_d(void);
extern void gadget_adc64_b(void);
extern void gadget_adc64_sp(void);
extern void gadget_adc64_bp(void);
extern void gadget_adc64_si(void);
extern void gadget_adc64_di(void);
extern void gadget_adc32_a(void);
extern void gadget_adc32_c(void);
extern void gadget_adc32_d(void);
extern void gadget_adc32_b(void);
extern void gadget_adc32_sp(void);
extern void gadget_adc32_bp(void);
extern void gadget_adc32_si(void);
extern void gadget_adc32_di(void);
extern void gadget_xor64_a(void);
extern void gadget_xor64_c(void);
extern void gadget_xor64_d(void);
extern void gadget_xor64_b(void);
extern void gadget_xor64_sp(void);
extern void gadget_xor64_bp(void);
extern void gadget_xor64_si(void);
extern void gadget_xor64_di(void);
extern void gadget_xor_zero(void); // XOR zeroing idiom with proper flag setting
extern void gadget_xor64_imm(void);
extern void gadget_xor32_imm(void);
extern void gadget_xor16_imm(void);
extern void gadget_xor8_imm(void);
extern void gadget_xor32_a(void);
extern void gadget_xor32_c(void);
extern void gadget_xor32_d(void);
extern void gadget_xor32_b(void);
extern void gadget_xor32_sp(void);
extern void gadget_xor32_bp(void);
extern void gadget_xor32_si(void);
extern void gadget_xor32_di(void);
extern void gadget_xor64_mem(void);
extern void gadget_xor32_mem(void);
extern gadget_t xor64_r8_r15_gadgets[];
extern gadget_t xor32_r8_r15_gadgets[];
extern void gadget_and64_imm(void);
extern void gadget_and64_x8(void);
extern void gadget_and64_mem(void);
extern void gadget_and64_a(void);
extern void gadget_and64_c(void);
extern void gadget_and64_d(void);
extern void gadget_and64_b(void);
extern void gadget_and64_sp(void);
extern void gadget_and64_bp(void);
extern void gadget_and64_si(void);
extern void gadget_and64_di(void);
extern void gadget_or64_imm(void);
extern void gadget_or64_x8(void);
extern void gadget_or64_mem(void);
extern void
gadget_or32_mem(void); // 32-bit OR to memory (avoids corrupting adjacent bytes)
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
extern void gadget_cdq(void); // Sign extend EAX to EDX:EAX
extern void gadget_cqo(void); // Sign extend RAX to RDX:RAX
extern void gadget_cmp64_imm(void);
extern void gadget_cmp32_imm(void);
extern void gadget_cmp16_imm(void);
extern void gadget_cmp8_imm(void);
extern void gadget_cmp64_reg(void);
extern void gadget_cmp32_reg(void);
extern void gadget_cmp16_reg(void);
extern void gadget_cmp8_reg(void);
extern void gadget_cmp64_x8(void);
extern void gadget_cmp32_x8(void);
extern void gadget_cmp16_x8(void);
extern void gadget_cmp8_x8(void);
extern void gadget_test64_imm(void);
extern void gadget_test32_imm(void);
extern void gadget_test16_imm(void);
extern void gadget_test8_imm(void);
extern void gadget_test64_x8(void);
extern void gadget_test32_x8(void);
extern void gadget_test16_x8(void);
extern void gadget_test8_x8(void);
extern void gadget_test64_a(void);
extern void gadget_test64_c(void);
extern void gadget_test64_d(void);
extern void gadget_test64_b(void);
extern void gadget_test64_sp(void);
extern void gadget_test64_bp(void);
extern void gadget_test64_si(void);
extern void gadget_test64_di(void);
extern void gadget_test32_reg(void);
extern void gadget_test16_reg(void);
extern void gadget_test8_reg(void);
extern void gadget_load16_mem(void);
extern void gadget_load8_mem(void);
extern void gadget_store16_mem(void);
extern void gadget_store8_mem(void);

// DIV/IDIV gadgets
extern void gadget_div32(void);
extern void gadget_div64(void);
extern void gadget_idiv32(void);
extern void gadget_idiv64(void);

// MUL gadgets (unsigned multiply: RDX:RAX = RAX * r/m)
extern void gadget_mul32(void);
extern void gadget_mul64(void);

// IMUL gadgets
extern void gadget_imul64_a(void);
extern void gadget_imul64_c(void);
extern void gadget_imul64_d(void);
extern void gadget_imul64_b(void);
extern void gadget_imul64_sp(void);
extern void gadget_imul64_bp(void);
extern void gadget_imul64_si(void);
extern void gadget_imul64_di(void);
extern void gadget_imul32_a(void);
extern void gadget_imul32_c(void);
extern void gadget_imul32_d(void);
extern void gadget_imul32_b(void);
extern void gadget_imul32_sp(void);
extern void gadget_imul32_bp(void);
extern void gadget_imul32_si(void);
extern void gadget_imul32_di(void);
extern void gadget_imul64_imm(void);
extern void gadget_imul32_imm(void);
extern void gadget_imul64_wide(void); // Single-operand: RDX:RAX = RAX * src
extern void gadget_imul32_wide(void); // Single-operand: EDX:EAX = EAX * src
extern gadget_t imul64_r8_r15_gadgets[];
extern gadget_t imul32_r8_r15_gadgets[];

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
extern void gadget_rol32_one(void);
extern void gadget_rol64_one(void);
extern void gadget_rol32_cl(void);
extern void gadget_rol64_cl(void);
extern void gadget_rol32_imm(void);
extern void gadget_rol64_imm(void);
extern void gadget_ror32_one(void);
extern void gadget_ror64_one(void);
extern void gadget_ror32_cl(void);
extern void gadget_ror64_cl(void);
extern void gadget_ror32_imm(void);
extern void gadget_ror64_imm(void);
extern void gadget_shrd32_imm(void);
extern void gadget_shrd64_imm(void);
extern void gadget_shrd32_cl(void);
extern void gadget_shrd64_cl(void);
extern void gadget_shld32_imm(void);
extern void gadget_shld64_imm(void);
extern void gadget_shld32_cl(void);
extern void gadget_shld64_cl(void);
extern void gadget_bsf32(void);
extern void gadget_bsf64(void);
extern void gadget_bsr32(void);
extern void gadget_bsr64(void);

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

// XMM/SSE gadgets
extern void gadget_movq_to_xmm(void);
extern void gadget_movq_from_xmm(void);
extern void gadget_punpcklqdq(void);
extern void gadget_movaps_load(void);
extern void gadget_movaps_store(void);
extern void gadget_movaps_xmm_xmm(void);
extern void gadget_pxor_xmm(void);

// String operation gadgets
extern void gadget_rep_stosq(void);
extern void gadget_rep_stosd(void);
extern void gadget_rep_stosb(void);
extern void gadget_rep_movsq(void);
extern void gadget_rep_movsd(void);
extern void gadget_rep_movsb(void);
extern void gadget_single_movsb(void); // Single MOVSB without REP prefix
// SSE MOVSD (Move Scalar Double-Precision) - NOT the string operation!
extern void gadget_movsd_xmm_xmm(void);  // movsd xmm, xmm
extern void gadget_movsd_xmm_mem(void);  // movsd xmm, m64
extern void gadget_movsd_mem_xmm(void);  // movsd m64, xmm
// SSE CVTSI2SD - Convert Integer to Scalar Double
extern void gadget_cvtsi2sd_reg64(void); // cvtsi2sd xmm, r64
extern void gadget_cvtsi2sd_reg32(void); // cvtsi2sd xmm, r32
extern void gadget_cvtsi2sd_mem64(void); // cvtsi2sd xmm, m64
extern void gadget_cvtsi2sd_mem32(void); // cvtsi2sd xmm, m32
extern void gadget_cvttsd2si_reg64(void); // cvttsd2si r64, xmm
extern void gadget_cvttsd2si_reg32(void); // cvttsd2si r32, xmm
extern void gadget_cvttsd2si_mem64(void); // cvttsd2si r64, m64
extern void gadget_cvttsd2si_mem32(void); // cvttsd2si r32, m32
// SSE ADDSD - Add Scalar Double
extern void gadget_addsd_xmm_xmm(void);  // addsd xmm, xmm
extern void gadget_addsd_xmm_mem(void);  // addsd xmm, m64
// SSE SUBSD - Subtract Scalar Double
extern void gadget_subsd_xmm_xmm(void);  // subsd xmm, xmm
extern void gadget_subsd_xmm_mem(void);  // subsd xmm, m64
// SSE MULSD - Multiply Scalar Double
extern void gadget_mulsd_xmm_xmm(void);  // mulsd xmm, xmm
extern void gadget_mulsd_xmm_mem(void);  // mulsd xmm, m64
// SSE COMISD - Compare Scalar Double (sets EFLAGS)
extern void gadget_comisd_xmm_xmm(void); // comisd xmm, xmm
extern void gadget_comisd_xmm_mem(void); // comisd xmm, m64
extern void
gadget_repne_scasb(void); // REPNE SCASB - scan for byte not equal to AL
extern void gadget_repe_scasb(void);   // REPE SCASB - scan for byte equal to AL
extern void gadget_single_scasb(void); // Single SCASB without REP prefix

// Gadget arrays for register operations
static gadget_t add64_gadgets[] = {
    gadget_add64_a,  gadget_add64_c,  gadget_add64_d,  gadget_add64_b,
    gadget_add64_sp, gadget_add64_bp, gadget_add64_si, gadget_add64_di};
static gadget_t sub64_gadgets[] = {
    gadget_sub64_a,  gadget_sub64_c,  gadget_sub64_d,  gadget_sub64_b,
    gadget_sub64_sp, gadget_sub64_bp, gadget_sub64_si, gadget_sub64_di};
static gadget_t add32_gadgets[] = {
    gadget_add32_a,  gadget_add32_c,  gadget_add32_d,  gadget_add32_b,
    gadget_add32_sp, gadget_add32_bp, gadget_add32_si, gadget_add32_di};
static gadget_t sub32_gadgets[] = {
    gadget_sub32_a,  gadget_sub32_c,  gadget_sub32_d,  gadget_sub32_b,
    gadget_sub32_sp, gadget_sub32_bp, gadget_sub32_si, gadget_sub32_di};
static gadget_t sbb64_gadgets[] = {
    gadget_sbb64_a,  gadget_sbb64_c,  gadget_sbb64_d,  gadget_sbb64_b,
    gadget_sbb64_sp, gadget_sbb64_bp, gadget_sbb64_si, gadget_sbb64_di};
static gadget_t sbb32_gadgets[] = {
    gadget_sbb32_a,  gadget_sbb32_c,  gadget_sbb32_d,  gadget_sbb32_b,
    gadget_sbb32_sp, gadget_sbb32_bp, gadget_sbb32_si, gadget_sbb32_di};
static gadget_t adc64_gadgets[] = {
    gadget_adc64_a,  gadget_adc64_c,  gadget_adc64_d,  gadget_adc64_b,
    gadget_adc64_sp, gadget_adc64_bp, gadget_adc64_si, gadget_adc64_di};
static gadget_t adc32_gadgets[] = {
    gadget_adc32_a,  gadget_adc32_c,  gadget_adc32_d,  gadget_adc32_b,
    gadget_adc32_sp, gadget_adc32_bp, gadget_adc32_si, gadget_adc32_di};
static gadget_t xor64_gadgets[] = {
    gadget_xor64_a,  gadget_xor64_c,  gadget_xor64_d,  gadget_xor64_b,
    gadget_xor64_sp, gadget_xor64_bp, gadget_xor64_si, gadget_xor64_di};
static gadget_t xor32_gadgets[] = {
    gadget_xor32_a,  gadget_xor32_c,  gadget_xor32_d,  gadget_xor32_b,
    gadget_xor32_sp, gadget_xor32_bp, gadget_xor32_si, gadget_xor32_di};
static gadget_t or64_gadgets[] = {
    gadget_or64_a,  gadget_or64_c,  gadget_or64_d,  gadget_or64_b,
    gadget_or64_sp, gadget_or64_bp, gadget_or64_si, gadget_or64_di};
static gadget_t and64_gadgets[] = {
    gadget_and64_a,  gadget_and64_c,  gadget_and64_d,  gadget_and64_b,
    gadget_and64_sp, gadget_and64_bp, gadget_and64_si, gadget_and64_di};
static gadget_t test64_gadgets[] = {
    gadget_test64_a,  gadget_test64_c,  gadget_test64_d,  gadget_test64_b,
    gadget_test64_sp, gadget_test64_bp, gadget_test64_si, gadget_test64_di};
static gadget_t imul64_gadgets[] = {
    gadget_imul64_a,  gadget_imul64_c,  gadget_imul64_d,  gadget_imul64_b,
    gadget_imul64_sp, gadget_imul64_bp, gadget_imul64_si, gadget_imul64_di};
static gadget_t imul32_gadgets[] = {
    gadget_imul32_a,  gadget_imul32_c,  gadget_imul32_d,  gadget_imul32_b,
    gadget_imul32_sp, gadget_imul32_bp, gadget_imul32_si, gadget_imul32_di};

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
extern void gadget_debug_cmov_sxo(void); // Debug wrapper for CMOVL
extern void gadget_cmov_sxoz(void);
// Conditional move gadgets (condition true = keep dest)
extern void gadget_cmovn_o(void);
extern void gadget_cmovn_c(void);
extern void gadget_cmovn_z(void);
extern void gadget_debug_cmovn_z(void);
extern void gadget_cmovn_cz(void);
extern void gadget_cmovn_s(void);
extern void gadget_cmovn_p(void);
extern void gadget_cmovn_sxo(void);
extern void gadget_debug_cmovn_sxo(void); // Debug wrapper for CMOVGE
extern void gadget_cmovn_sxoz(void);
// SETcc gadgets (condition true = set byte to 1)
extern void gadget_set_o(void);
extern void gadget_set_c(void);
extern void gadget_set_z(void);
extern void gadget_set_cz(void);
extern void gadget_set_s(void);
extern void gadget_set_p(void);
extern void gadget_set_sxo(void);
extern void gadget_set_sxoz(void);
// SETNcc gadgets (condition true = set byte to 0)
extern void gadget_setn_o(void);
extern void gadget_setn_c(void);
extern void gadget_setn_z(void);
extern void gadget_setn_cz(void);
extern void gadget_setn_s(void);
extern void gadget_setn_p(void);
extern void gadget_setn_sxo(void);
extern void gadget_setn_sxoz(void);
// Helper for cmov: save _xtmp to x8
extern void gadget_save_xtmp_to_x8(void);
extern void gadget_restore_xtmp_from_x8(void);
extern void gadget_swap_xtmp_x8(void);
// Debug gadgets
extern void gadget_debug_lea(void);
extern void gadget_debug_cmp(void);

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

// CMPXCHG gadgets
extern void gadget_cmpxchg64_mem(void);
extern void gadget_cmpxchg32_mem(void);

// XCHG gadgets
extern void gadget_xchg64_mem(void);
extern void gadget_xchg32_mem(void);

// ADC imm gadgets (register versions declared earlier)
extern void gadget_adc64_imm(void);
extern void gadget_adc32_imm(void);

// CLD/STD gadgets
extern void gadget_cld(void);
extern void gadget_std(void);

// Address save/restore gadgets
extern void gadget_save_addr(void);
extern void gadget_restore_addr(void);

// Address calculation gadgets for r8-r15
extern void gadget_addr_r8(void);
extern void gadget_addr_r9(void);
extern void gadget_addr_r10(void);
extern void gadget_addr_r11(void);
extern void gadget_addr_r12(void);
extern void gadget_addr_r13(void);
extern void gadget_addr_r14(void);
extern void gadget_addr_r15(void);

// x87 FPU gadgets
extern void gadget_fpu_fild16(void);
extern void gadget_fpu_fild32(void);
extern void gadget_fpu_fild64(void);
extern void gadget_fpu_fistp16(void);
extern void gadget_fpu_fistp32(void);
extern void gadget_fpu_fistp64(void);
extern void gadget_fpu_fld32(void);
extern void gadget_fpu_fld64(void);
extern void gadget_fpu_fld80(void);
extern void gadget_fpu_fld_sti(void);
extern void gadget_fpu_fstp32(void);
extern void gadget_fpu_fstp64(void);
extern void gadget_fpu_fstp80(void);
extern void gadget_fpu_fstp_sti(void);
extern void gadget_fpu_fadd(void);
extern void gadget_fpu_faddp(void);
extern void gadget_fpu_fadd_m32(void);
extern void gadget_fpu_fadd_m64(void);
extern void gadget_fpu_fsub(void);
extern void gadget_fpu_fsubp(void);
extern void gadget_fpu_fsubr(void);
extern void gadget_fpu_fsubrp(void);
extern void gadget_fpu_fsub_m32(void);
extern void gadget_fpu_fsub_m64(void);
extern void gadget_fpu_fmul(void);
extern void gadget_fpu_fmulp(void);
extern void gadget_fpu_fmul_m32(void);
extern void gadget_fpu_fmul_m64(void);
extern void gadget_fpu_fdiv(void);
extern void gadget_fpu_fdivp(void);
extern void gadget_fpu_fdiv_m32(void);
extern void gadget_fpu_fdiv_m64(void);
extern void gadget_fpu_fxch(void);
extern void gadget_fpu_fprem(void);
extern void gadget_fpu_fscale(void);
extern void gadget_fpu_frndint(void);
extern void gadget_fpu_fabs(void);
extern void gadget_fpu_fchs(void);
extern void gadget_fpu_fincstp(void);
extern void gadget_fpu_fldz(void);
extern void gadget_fpu_fld1(void);
extern void gadget_fpu_fldpi(void);
extern void gadget_fpu_fldl2e(void);
extern void gadget_fpu_fldl2t(void);
extern void gadget_fpu_fldlg2(void);
extern void gadget_fpu_fldln2(void);
extern void gadget_fpu_fldcw(void);
extern void gadget_fpu_fnstcw(void);
extern void gadget_fpu_fnstsw(void);
extern void gadget_fpu_fucomip(void);
extern void gadget_fpu_fucomi(void);

// Address gadgets for r8-r15 (indexed by reg - arg64_r8)
static gadget_t addr_r8_r15[] = {
    gadget_addr_r8,  gadget_addr_r9,  gadget_addr_r10, gadget_addr_r11,
    gadget_addr_r12, gadget_addr_r13, gadget_addr_r14, gadget_addr_r15};

// Helper to emit code
static void gen(struct gen_state *state, unsigned long thing) {
  assert(state->size <= state->capacity);
  if (state->size >= state->capacity) {
    state->capacity *= 2;
    struct fiber_block *bigger_block =
        realloc(state->block, sizeof(struct fiber_block) +
                                  state->capacity * sizeof(unsigned long));
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

  struct fiber_block *block = malloc(sizeof(struct fiber_block) +
                                     state->capacity * sizeof(unsigned long));
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
    block->code[state->block_patch_ip] = (unsigned long)block;
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
    gadget_load64_r8,  gadget_load64_r9,  gadget_load64_r10, gadget_load64_r11,
    gadget_load64_r12, gadget_load64_r13, gadget_load64_r14, gadget_load64_r15};

// Store gadgets for r8-r15 (indexed by reg - arg64_r8)
static gadget_t store64_r8_r15[] = {gadget_store64_r8,  gadget_store64_r9,
                                    gadget_store64_r10, gadget_store64_r11,
                                    gadget_store64_r12, gadget_store64_r13,
                                    gadget_store64_r14, gadget_store64_r15};

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

// Helper to check if a type is an XMM register
static inline bool is_xmm(enum arg64 type) {
  return type >= arg64_xmm0 && type <= arg64_xmm15;
}

// Helper to get XMM register index (0-15)
static inline int get_xmm_index(enum arg64 type) { return type - arg64_xmm0; }

// Helper to check if a type is a memory operand (including RIP-relative)
static inline bool is_mem(enum arg64 type) {
  return type == arg64_mem || type == arg64_rip_rel;
}

// Address calculation gadgets
extern gadget_t addr_gadgets[];

// Scaled index gadgets: si_gadgets[reg * 4 + scale_idx]
// where scale_idx = {0,1,2,3} for scales {1,2,4,8}
extern gadget_t si_gadgets[];

// Scaled index gadgets for r8-r15: si_r8_r15_gadgets[(reg-8) * 4 + scale_idx]
extern gadget_t si_r8_r15_gadgets[];

// Helper to get scale index (0,1,2,3 for scale 1,2,4,8)
static inline int get_scale_idx(int scale) {
  switch (scale) {
  case 1:
    return 0;
  case 2:
    return 1;
  case 4:
    return 2;
  case 8:
    return 3;
  default:
    return -1;
  }
}

// Helper to emit segment override gadget if needed
static void gen_segment_override(struct gen_state *state,
                                 struct decoded_inst64 *inst) {
  if (inst->has_segment_override) {
    if (inst->segment == ZYDIS_REGISTER_FS) {
      GEN(gadget_seg_fs);
    } else if (inst->segment == ZYDIS_REGISTER_GS) {
      GEN(gadget_seg_gs);
    }
  }
}

// Generate address calculation for memory operand (internal helper)
static bool gen_addr_internal(struct gen_state *state,
                              struct decoded_op64 *op) {
  if (op->type != arg64_mem && op->type != arg64_rip_rel)
    return false;

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
  if (op->mem.base == arg64_invalid && op->mem.index >= arg64_rax &&
      op->mem.index <= arg64_rdi) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    // Start with displacement only
    GEN(addr_gadgets[8]); // addr_none
    GEN(op->mem.disp);

    // Apply scaled index: _addr = _addr + index * scale
    int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
    GEN(si_gadgets[si_index]);

    return true;
  }

  // No base + scaled index with r8-r15 as index: [r8-r15 * scale + disp]
  if (op->mem.base == arg64_invalid && op->mem.index >= arg64_r8 &&
      op->mem.index <= arg64_r15) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    // Start with displacement only
    GEN(addr_gadgets[8]); // addr_none
    GEN(op->mem.disp);

    // Apply scaled index with r8-r15: _addr = _addr + index * scale
    int si_index = (op->mem.index - arg64_r8) * 4 + scale_idx;
    GEN(si_r8_r15_gadgets[si_index]);

    return true;
  }

  // Base + scaled index (base must be rax-rdi, index must be rax-rdi for now)
  if (op->mem.base >= arg64_rax && op->mem.base <= arg64_rdi &&
      op->mem.index >= arg64_rax && op->mem.index <= arg64_rdi) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    // Load base + displacement into _addr
    GEN(addr_gadgets[op->mem.base - arg64_rax]);
    GEN(op->mem.disp);

    // Apply scaled index: _addr = _addr + index * scale
    int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
    GEN(si_gadgets[si_index]);

    return true;
  }

  // Base rax-rdi + scaled index r8-r15
  if (op->mem.base >= arg64_rax && op->mem.base <= arg64_rdi &&
      op->mem.index >= arg64_r8 && op->mem.index <= arg64_r15) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    // Load base + displacement into _addr
    GEN(addr_gadgets[op->mem.base - arg64_rax]);
    GEN(op->mem.disp);

    // Apply scaled index with r8-r15: _addr = _addr + index * scale
    int si_index = (op->mem.index - arg64_r8) * 4 + scale_idx;
    GEN(si_r8_r15_gadgets[si_index]);

    return true;
  }

  // Base r8-r15 + scaled index (rax-rdi)
  if (op->mem.base >= arg64_r8 && op->mem.base <= arg64_r15 &&
      op->mem.index >= arg64_rax && op->mem.index <= arg64_rdi) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    GEN(addr_r8_r15[op->mem.base - arg64_r8]);
    GEN(op->mem.disp);

    int si_index = (op->mem.index - arg64_rax) * 4 + scale_idx;
    GEN(si_gadgets[si_index]);

    return true;
  }

  // Base r8-r15 + scaled index r8-r15
  if (op->mem.base >= arg64_r8 && op->mem.base <= arg64_r15 &&
      op->mem.index >= arg64_r8 && op->mem.index <= arg64_r15) {
    int scale_idx = get_scale_idx(op->mem.scale);
    if (scale_idx < 0)
      return false;

    GEN(addr_r8_r15[op->mem.base - arg64_r8]);
    GEN(op->mem.disp);

    int si_index = (op->mem.index - arg64_r8) * 4 + scale_idx;
    GEN(si_r8_r15_gadgets[si_index]);

    return true;
  }

  // More complex addressing modes not yet supported
  return false;
}

// Generate address calculation with segment override support
static bool gen_addr(struct gen_state *state, struct decoded_op64 *op,
                     struct decoded_inst64 *inst) {
  if (!gen_addr_internal(state, op))
    return false;
  // Emit segment override if present (adds segment base to _addr)
  if (inst)
    gen_segment_override(state, inst);
  return true;
}

// Generate code for MOV instruction
static bool gen_mov(struct gen_state *state, struct decoded_inst64 *inst) {
  struct decoded_op64 *dst = &inst->operands[0];
  struct decoded_op64 *src = &inst->operands[1];

  // Determine operand size from destination (or source for mem operands)
  int size_bits = 0;
  if (dst->size == size64_64 || src->size == size64_64)
    size_bits = 64;
  else if (dst->size == size64_32 || src->size == size64_32)
    size_bits = 32;
  else if (dst->size == size64_16 || src->size == size64_16)
    size_bits = 16;
  else if (dst->size == size64_8 || src->size == size64_8)
    size_bits = 8;
  else
    size_bits = 32; // default to 32-bit

  // MOV reg, reg (any GPR including r8-r15)
  if (is_gpr(dst->type) && is_gpr(src->type)) {
    gadget_t load_gadget = get_load64_reg_gadget(src->type);
    if (!load_gadget)
      return false;
    GEN(load_gadget);

    // For 32-bit MOV, mask to zero-extend (x86_64 semantics)
    // IMPORTANT: Use flag-preserving AND - MOV does NOT modify flags!
    if (size_bits == 32) {
      GEN(gadget_lea_and64_imm); // Flag-preserving AND
      GEN(0xFFFFFFFF);
    } else if (size_bits == 16) {
      GEN(gadget_lea_and64_imm); // Flag-preserving AND
      GEN(0xFFFF);
    } else if (size_bits == 8) {
      GEN(gadget_lea_and64_imm); // Flag-preserving AND
      GEN(0xFF);
    }

    gadget_t store_gadget = get_store64_reg_gadget(dst->type);
    if (!store_gadget)
      return false;
    // Debug: trace MOV to r11 or r12
    if (dst->type == arg64_r11) {
      DEBUG_FPRINTF(stderr, "GEN_MOV_R11: ip=0x%llx src=%d size=%d\n",
              (unsigned long long)state->orig_ip, src->type, size_bits);
    }
    if (dst->type == arg64_r12) {
      DEBUG_FPRINTF(stderr, "GEN: MOV r12, reg at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
    }
    GEN(store_gadget);

    return true;
  }

  // MOV reg, imm (any GPR including r8-r15)
  if (is_gpr(dst->type) && src->type == arg64_imm) {
    // Debug: trace MOV to r8-r15 with imm
    if (dst->type >= arg64_r8 && dst->type <= arg64_r15) {
      DEBUG_FPRINTF(stderr,
              "GEN_MOV_R8_R15_IMM: ip=0x%llx dst=%d (r%d) size=%d imm=0x%llx\n",
              (unsigned long long)state->orig_ip, dst->type,
              8 + (dst->type - arg64_r8), size_bits,
              (unsigned long long)src->imm);
    }
    // Debug: trace MOV rdx, imm with suspicious value
    if (dst->type == arg64_rdx &&
        (src->imm == 0xffffffffffffff80 || src->imm == 0xffffff80 ||
         src->imm == 0x80)) {
      DEBUG_FPRINTF(stderr,
              "GEN_MOV_RDX_IMM: ip=0x%llx size=%d imm=0x%llx (signed=%lld)\n",
              (unsigned long long)state->orig_ip, size_bits,
              (unsigned long long)src->imm, (long long)src->imm);
    }
    if (size_bits == 64) {
      GEN(load64_gadgets[8]); // load64_imm
    } else {
      GEN(load32_gadgets[8]); // load32_imm
    }
    GEN(src->imm);

    gadget_t store_gadget = get_store64_reg_gadget(dst->type);
    if (!store_gadget)
      return false;
    GEN(store_gadget);

    return true;
  }

  // MOV reg, [mem] (any GPR including r8-r15)
  if (is_gpr(dst->type) && is_mem(src->type)) {
    if (!gen_addr(state, src, inst))
      return false;
    switch (size_bits) {
    case 64:
      GEN(load64_gadgets[9]); // load64_mem
      break;
    case 32:
      GEN(load32_gadgets[9]); // load32_mem
      break;
    case 16:
      GEN(gadget_load16_mem);
      break;
    case 8:
      GEN(gadget_load8_mem);
      break;
    }
    GEN(state->orig_ip);

    gadget_t store_gadget = get_store64_reg_gadget(dst->type);
    if (!store_gadget)
      return false;
    GEN(store_gadget);

    return true;
  }

  // MOV [mem], reg (any GPR including r8-r15)
  if (is_mem(dst->type) && is_gpr(src->type)) {
    gadget_t load_gadget = get_load64_reg_gadget(src->type);
    if (!load_gadget)
      return false;
    GEN(load_gadget);

    if (!gen_addr(state, dst, inst))
      return false;
    switch (size_bits) {
    case 64:
      GEN(store64_gadgets[9]); // store64_mem
      break;
    case 32:
      GEN(store32_gadgets[9]); // store32_mem
      break;
    case 16:
      GEN(gadget_store16_mem);
      break;
    case 8:
      GEN(gadget_store8_mem);
      break;
    }
    GEN(state->orig_ip);

    return true;
  }

  // MOV [mem], imm
  if (is_mem(dst->type) && src->type == arg64_imm) {
    // Debug: trace mov [mem], imm with value 8 (likely gp_offset setup)
    if (src->imm == 8 && size_bits == 32) {
      DEBUG_FPRINTF(stderr,
              "GEN: MOV [mem], imm8 at ip=0x%llx (likely va_start gp_offset)\n",
              (unsigned long long)state->orig_ip);
    }
    // Load immediate
    if (size_bits == 64) {
      GEN(load64_gadgets[8]); // load64_imm
    } else {
      GEN(load32_gadgets[8]); // load32_imm
    }
    GEN(src->imm);

    // Calculate address and store
    if (!gen_addr(state, dst, inst))
      return false;
    switch (size_bits) {
    case 64:
      GEN(store64_gadgets[9]); // store64_mem
      break;
    case 32:
      GEN(store32_gadgets[9]); // store32_mem
      break;
    case 16:
      GEN(gadget_store16_mem);
      break;
    case 8:
      GEN(gadget_store8_mem);
      break;
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

  // Debug trace disabled

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
    DEBUG_FPRINTF(stderr,
            "DECODE FAILED at ip=0x%llx bytes: %02x %02x %02x %02x %02x %02x "
            "%02x %02x\n",
            (unsigned long long)state->orig_ip, code[0], code[1], code[2],
            code[3], code[4], code[5], code[6], code[7]);
    g(interrupt);
    GEN(INT_UNDEFINED);
    GEN(state->orig_ip);
    GEN(state->orig_ip);
    return 0;
  }

  // Advance IP past this instruction
  state->ip += len;

  // Special tracing for the stuck area (0x55555555b950 - 0x55555555bb00)
  // Also trace duration parsing at 0x55555555c744 and strtod at 0x7efffffb83bd
  // strtod offset = 0x583bd in musl
  if ((state->orig_ip >= 0x55555555b950 && state->orig_ip <= 0x55555555bc00) ||
      (state->orig_ip >= 0x55555555c740 && state->orig_ip <= 0x55555555c900) ||
      (state->orig_ip >= 0x7efffffb83b0 && state->orig_ip <= 0x7efffffb8500)) {
    fprintf(stderr, "TRANSLATE[0x%llx]: mnemonic=%d len=%d bytes:",
            (unsigned long long)state->orig_ip, inst.mnemonic, len);
    for (int i = 0; i < len && i < 10; i++) {
      fprintf(stderr, " %02x", code[i]);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
  }

// Debug trace disabled

// CMOV trace disabled

// Mark fake_ip for jump patching
#define fake_ip (state->ip | (1ul << 63))

  bool end_block = false;

  // Generate code based on mnemonic
  switch (inst.mnemonic) {
  case ZYDIS_MNEMONIC_NOP:
  case ZYDIS_MNEMONIC_ENDBR64:
    // Do nothing
    break;

  case ZYDIS_MNEMONIC_CLD:
    // Clear Direction Flag (DF=0, increment in string ops)
    GEN(gadget_cld);
    break;

  case ZYDIS_MNEMONIC_STD:
    // Set Direction Flag (DF=1, decrement in string ops)
    GEN(gadget_std);
    break;

  case ZYDIS_MNEMONIC_HLT:
    // HLT is used as a trap/crash instruction in musl libc
    // Generate a GPF interrupt
    g(interrupt);
    GEN(INT_GPF);
    GEN(state->orig_ip);
    GEN(state->orig_ip);
    end_block = true;
    break;

  case ZYDIS_MNEMONIC_MOV:
    if (!gen_mov(state, &inst)) {
      // Fallback to interrupt for unimplemented
      DEBUG_FPRINTF(stderr,
              "GEN_MOV_FAILED: ip=0x%llx op0.type=%d op1.type=%d size=%d\n",
              (unsigned long long)state->orig_ip, inst.operands[0].type,
              inst.operands[1].type, inst.operands[0].size);
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_XOR:
    // XOR dst, src -> dst = dst XOR src
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      // Special case: xor reg, reg (zeroing idiom) - MUST set flags properly!
      // XOR sets ZF=1, SF=0, CF=0, OF=0 when result is 0
      if (inst.operands[0].type == inst.operands[1].type) {
        // Load reg into _xtmp, then XOR with itself (uses proper flag-setting)
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        // XOR with immediate 0 doesn't give correct flags, use xor64_imm with
        // the register value Actually simpler: just XOR with itself via
        // xor64_imm 0 which will set flags correctly No wait - we need to XOR
        // _xtmp with _xtmp, but we don't have that gadget So use xor64_imm with
        // 0xFFFFFFFFFFFFFFFF to flip all bits, then with itself again...
        // Actually the easiest is to use the reg gadget: load reg, then XOR
        // with same reg But that requires self-referential XOR gadget Best
        // approach: use dedicated zeroing gadget that sets flags
        GEN(gadget_xor_zero); // Sets _xtmp=0 and flags (ZF=1, SF=0, CF=0, OF=0)
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (is_gpr(inst.operands[1].type)) {
        // XOR reg, reg (different registers)
        // Load destination into _xtmp
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);

        // XOR with source register
        if (inst.operands[1].type >= arg64_rax &&
            inst.operands[1].type <= arg64_rdi) {
          int src_idx = inst.operands[1].type - arg64_rax;
          if (inst.operands[0].size == size64_32) {
            GEN(xor32_gadgets[src_idx]);
          } else {
            GEN(xor64_gadgets[src_idx]);
          }
        } else if (inst.operands[1].type >= arg64_r8 &&
                   inst.operands[1].type <= arg64_r15) {
          int src_idx = inst.operands[1].type - arg64_r8;
          if (inst.operands[0].size == size64_32) {
            GEN(xor32_r8_r15_gadgets[src_idx]);
          } else {
            GEN(xor64_r8_r15_gadgets[src_idx]);
          }
        } else {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }

        // Store result back to destination
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_imm) {
        // XOR reg, imm
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_xor32_imm);
        } else {
          GEN(gadget_xor64_imm);
        }
        GEN(inst.operands[1].imm);
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_mem ||
                 inst.operands[1].type == arg64_rip_rel) {
        // XOR reg, mem
        gen_addr(state, &inst.operands[1], &inst);
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_xor32_mem);
        } else {
          GEN(gadget_xor64_mem);
        }
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // XOR [mem], imm - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int size_bits = inst.operands[0].size;
      // Load from memory
      if (size_bits == size64_64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else if (size_bits == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else if (size_bits == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // Save address before XOR (which will overwrite it)
      GEN(gadget_save_addr);
      // XOR with immediate
      if (size_bits == size64_64) {
        GEN(gadget_xor64_imm);
      } else if (size_bits == size64_32) {
        GEN(gadget_xor32_imm);
      } else if (size_bits == size64_16) {
        GEN(gadget_xor16_imm);
      } else {
        GEN(gadget_xor8_imm);
      }
      GEN(inst.operands[1].imm);
      // Restore address and store result
      GEN(gadget_restore_addr);
      if (size_bits == size64_64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else if (size_bits == size64_32) {
        GEN(store32_gadgets[9]); // store32_mem
      } else if (size_bits == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SYSCALL:
    DEBUG_FPRINTF(stderr, "GEN: syscall at ip=0x%llx\n",
            (unsigned long long)state->orig_ip);
    g(syscall);
    GEN(state->ip); // Return address (next instruction after SYSCALL)
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
      if (load)
        GEN(load);
      g(jmp_indir);
    } else if (inst.operand_count > 0 && is_mem(inst.operands[0].type)) {
      // Indirect jump via memory (JMP [mem] or JMP [RIP+disp])
      if (!gen_addr(state, &inst.operands[0], &inst)) {
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
  case ZYDIS_MNEMONIC_JO:   // Jump if Overflow
  case ZYDIS_MNEMONIC_JNO:  // Jump if Not Overflow
  case ZYDIS_MNEMONIC_JB:   // Jump if Below (Carry)
  case ZYDIS_MNEMONIC_JNB:  // Jump if Not Below (No Carry)
  case ZYDIS_MNEMONIC_JZ:   // Jump if Zero
  case ZYDIS_MNEMONIC_JNZ:  // Jump if Not Zero
  case ZYDIS_MNEMONIC_JBE:  // Jump if Below or Equal (Carry or Zero)
  case ZYDIS_MNEMONIC_JNBE: // Jump if Not Below or Equal
  case ZYDIS_MNEMONIC_JS:   // Jump if Sign
  case ZYDIS_MNEMONIC_JNS:  // Jump if Not Sign
  case ZYDIS_MNEMONIC_JP:   // Jump if Parity
  case ZYDIS_MNEMONIC_JNP:  // Jump if Not Parity
  case ZYDIS_MNEMONIC_JL:   // Jump if Less (Sign != Overflow)
  case ZYDIS_MNEMONIC_JNL:  // Jump if Not Less (Sign == Overflow)
  case ZYDIS_MNEMONIC_JLE:  // Jump if Less or Equal
  case ZYDIS_MNEMONIC_JNLE: // Jump if Not Less or Equal
    if (inst.operand_count > 0 && inst.operands[0].type == arg64_imm) {
      int64_t target = state->ip + inst.operands[0].imm;
      int64_t not_target = state->ip; // Fall through

      // Select gadget and possibly swap targets for negated conditions
      gadget_t jcc_gadget = NULL;
      bool negate = false;

      switch (inst.mnemonic) {
      case ZYDIS_MNEMONIC_JO:
        jcc_gadget = gadget_jmp_o;
        break;
      case ZYDIS_MNEMONIC_JNO:
        jcc_gadget = gadget_jmp_o;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JB:
        jcc_gadget = gadget_jmp_c;
        break;
      case ZYDIS_MNEMONIC_JNB:
        jcc_gadget = gadget_jmp_c;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JZ:
        jcc_gadget = gadget_jmp_z;
        break;
      case ZYDIS_MNEMONIC_JNZ:
        jcc_gadget = gadget_jmp_z;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JBE:
        jcc_gadget = gadget_jmp_cz;
        break;
      case ZYDIS_MNEMONIC_JNBE:
        jcc_gadget = gadget_jmp_cz;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JS:
        jcc_gadget = gadget_jmp_s;
        break;
      case ZYDIS_MNEMONIC_JNS:
        jcc_gadget = gadget_jmp_s;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JP:
        jcc_gadget = gadget_jmp_p;
        break;
      case ZYDIS_MNEMONIC_JNP:
        jcc_gadget = gadget_jmp_p;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JL:
        jcc_gadget = gadget_jmp_sxo;
        break;
      case ZYDIS_MNEMONIC_JNL:
        jcc_gadget = gadget_jmp_sxo;
        negate = true;
        break;
      case ZYDIS_MNEMONIC_JLE:
        jcc_gadget = gadget_jmp_sxoz;
        break;
      case ZYDIS_MNEMONIC_JNLE:
        jcc_gadget = gadget_jmp_sxoz;
        negate = true;
        break;
      default:
        break;
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
    GEN(8); // pop 8 bytes for return address
    end_block = true;
    break;

  case ZYDIS_MNEMONIC_CALL:
    if (inst.operand_count > 0 && inst.operands[0].type == arg64_imm) {
      // Relative call
      int64_t target = state->ip + inst.operands[0].imm;
      g(call);
      GEN(state->orig_ip);
      GEN(-1);        // Will be patched to block address
      GEN(state->ip); // Return address (actual, not fake)
      GEN(fake_ip);   // Return target for block chaining (patchable)
      GEN(target | (1ul << 63));
      state->block_patch_ip = state->size - 4;
      state->jump_ip[0] = state->size - 2;
      state->jump_ip[1] = state->size - 1;
    } else if (inst.operand_count > 0 && is_mem(inst.operands[0].type)) {
      // Indirect call through memory: call [mem]
      // Load target address from memory into _xtmp
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(load64_gadgets[9]); // load64_mem
      GEN(state->orig_ip);
      // Now _xtmp has the target address, use call_indir
      // call_indir layout: [_ip,0]=orig_ip, [_ip,8]=block_ptr,
      // [_ip,16]=ret_addr, [_ip,24]=chain_target For indirect calls, we can't
      // do return chaining since target is runtime-computed
      g(call_indir);
      GEN(state->orig_ip);
      GEN(-1);        // [_ip,8] block ptr slot (unpatched = -1)
      GEN(state->ip); // [_ip,16] return address
      GEN(-1);        // [_ip,24] return chain target (-1 = no chaining)
    } else if (inst.operand_count > 0 && is_gpr(inst.operands[0].type)) {
      // Indirect call through register: call reg
      // call_indir layout: [_ip,0]=orig_ip, [_ip,8]=block_ptr,
      // [_ip,16]=ret_addr, [_ip,24]=chain_target
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      g(call_indir);
      GEN(state->orig_ip);
      GEN(-1);        // [_ip,8] block ptr slot (unpatched = -1)
      GEN(state->ip); // [_ip,16] return address
      GEN(-1);        // [_ip,24] return chain target (-1 = no chaining)
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
        if (load)
          GEN(load);
      } else if (inst.operands[0].type == arg64_imm) {
        GEN(load64_gadgets[8]); // load64_imm
        GEN(inst.operands[0].imm);
      } else if (is_mem(inst.operands[0].type)) {
        // PUSH [mem]
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(load64_gadgets[9]); // load64_mem
        GEN(state->orig_ip);
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
      if (store)
        GEN(store);
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
      // Determine operand size
      bool is64 = (inst.operands[0].size == size64_64);

      // ADD reg, ...
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // ADD reg, imm
        if (is64) {
          GEN(gadget_add64_imm);
        } else {
          GEN(gadget_add32_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type >= arg64_rax &&
                 inst.operands[1].type <= arg64_rdi) {
        // ADD reg, reg (rax-rdi)
        if (is64) {
          GEN(add64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(add32_gadgets[inst.operands[1].type - arg64_rax]);
        }
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // ADD reg, r8-r15 (need to load r8-r15 from memory first)
        // Debug: trace ADD r14, r11 at printf_core accumulation
        if (inst.operands[0].type == arg64_r14 &&
            inst.operands[1].type == arg64_r11) {
          DEBUG_FPRINTF(stderr, "GEN_ADD_R14_R11: ip=0x%llx size=%d\n",
                  (unsigned long long)state->orig_ip, is64 ? 64 : 32);
        }
        // Save _xtmp (dst) to x8
        GEN(gadget_save_xtmp_to_x8);
        // Load r8-r15 into _xtmp
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
        // add_x8 does: _xtmp = _xtmp + x8 = src + dst
        if (is64) {
          GEN(gadget_add64_x8);
        } else {
          GEN(gadget_add32_x8);
        }
      } else if (is_mem(inst.operands[1].type)) {
        // ADD reg, [mem]
        // We have: _xtmp = dst value
        // Need: _addr = memory address, then add_mem adds [_addr] to _xtmp
        // gen_addr sets _addr and doesn't touch _xtmp
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(gadget_add64_mem);
        } else {
          GEN(gadget_add32_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // ADD [mem], reg
      bool is64 = (inst.operands[0].size == size64_64);
      if (inst.operands[1].type >= arg64_rax &&
          inst.operands[1].type <= arg64_rdi) {
        // ADD [mem], rax-rdi
        // 1. Calculate address
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        // 2. Load from memory
        if (is64) {
          GEN(load64_gadgets[9]); // load64_mem
        } else {
          GEN(load32_gadgets[9]); // load32_mem
        }
        GEN(state->orig_ip);
        // 3. Add source register
        if (is64) {
          GEN(add64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(add32_gadgets[inst.operands[1].type - arg64_rax]);
        }
        // 4. Recalculate address and store
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(store64_gadgets[9]); // store64_mem
        } else {
          GEN(store32_gadgets[9]); // store32_mem
        }
        GEN(state->orig_ip);
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // ADD [mem], r8-r15
        // Load source register (r8-r15) to x8 first
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
        GEN(gadget_save_xtmp_to_x8); // x8 = source value
        // 1. Calculate address
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        // 2. Load from memory
        if (is64) {
          GEN(load64_gadgets[9]); // load64_mem
        } else {
          GEN(load32_gadgets[9]); // load32_mem
        }
        GEN(state->orig_ip);
        // 3. Add x8 (source): _xtmp = _xtmp + x8 = mem + src
        if (is64) {
          GEN(gadget_add64_x8);
        } else {
          GEN(gadget_add32_x8);
        }
        // 4. Recalculate address and store
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(store64_gadgets[9]); // store64_mem
        } else {
          GEN(store32_gadgets[9]); // store32_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // ADD [mem], imm (including RIP-relative) - read-modify-write
      bool is64 = (inst.operands[0].size == size64_64);
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Save address, load, add, restore address, store
      GEN(gadget_save_addr);
      if (is64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else {
        GEN(load32_gadgets[9]); // load32_mem
      }
      GEN(state->orig_ip);
      if (is64) {
        GEN(gadget_add64_imm);
      } else {
        GEN(gadget_add32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (is64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else {
        GEN(store32_gadgets[9]); // store32_mem
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_ADC:
    // ADC: Add with Carry (dst = dst + src + CF)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      bool is64 = (inst.operands[0].size == size64_64);
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // ADC reg, imm
        if (is64) {
          GEN(gadget_adc64_imm);
        } else {
          GEN(gadget_adc32_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type >= arg64_rax &&
                 inst.operands[1].type <= arg64_rdi) {
        // ADC reg, reg (rax-rdi)
        if (is64) {
          GEN(adc64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(adc32_gadgets[inst.operands[1].type - arg64_rax]);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SBB:
    // SBB: Subtract with Borrow (dst = dst - src - CF)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      bool is64 = (inst.operands[0].size == size64_64);
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // SBB reg, imm
        if (is64) {
          GEN(gadget_sbb64_imm);
        } else {
          GEN(gadget_sbb32_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type >= arg64_rax &&
                 inst.operands[1].type <= arg64_rdi) {
        // SBB reg, reg (rax-rdi)
        if (is64) {
          GEN(sbb64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(sbb32_gadgets[inst.operands[1].type - arg64_rax]);
        }
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // SBB reg, r8-r15 (need to load r8-r15 from memory first)
        // Save _xtmp (dst) to x8
        GEN(gadget_save_xtmp_to_x8);
        // Load r8-r15 into _xtmp
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
        // sbb_x8 does: _xtmp = _xtmp - x8 - CF = src - dst - CF
        // But we want: dst - src - CF, so we need to swap
        // Actually: _xtmp has src (r8-r15), x8 has dst
        // sbb_x8: _xtmp = _xtmp - x8 - CF = src - dst - CF
        // That's wrong! We need: dst - src - CF
        // So swap x8 and _xtmp before the operation
        // Actually let's just use a different pattern:
        // 1. Load dst to _xtmp (already done)
        // 2. Load src (r8-r15) to x8
        // 3. SBB _xtmp - x8 - CF
        // So we DON'T swap, we load src to x8 differently:
        // After save_xtmp_to_x8: x8 = dst
        // Load r8-r15 to _xtmp: _xtmp = src
        // Then sbb_x8: _xtmp = _xtmp - x8 - CF = src - dst - CF (WRONG!)
        // We need: dst - src - CF = x8 - _xtmp - CF
        // Let me do it differently:
        // 1. Load r8-r15 to x8 (using save_xtmp, load r8-r15, move to x8)
        // Actually easier: swap after loading
        // Current: _xtmp = dst
        // After save_xtmp_to_x8: x8 = dst, _xtmp unchanged
        // Load r8-r15: _xtmp = src
        // Now we have: x8 = dst, _xtmp = src
        // sbb_x8: _xtmp = _xtmp - x8 - CF = src - dst - CF (STILL WRONG)
        // Let's swap before sbb:
        GEN(gadget_swap_xtmp_x8); // Now x8 = src, _xtmp = dst
        // sbb_x8: _xtmp = _xtmp - x8 - CF = dst - src - CF (CORRECT!)
        if (is64) {
          GEN(gadget_sbb64_x8);
        } else {
          GEN(gadget_sbb32_x8);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
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
      // Determine operand size
      bool is64 = (inst.operands[0].size == size64_64);

      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // SUB reg, imm
        if (is64) {
          GEN(gadget_sub64_imm);
        } else {
          GEN(gadget_sub32_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type >= arg64_rax &&
                 inst.operands[1].type <= arg64_rdi) {
        // SUB reg, reg (rax-rdi)
        if (is64) {
          GEN(sub64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(sub32_gadgets[inst.operands[1].type - arg64_rax]);
        }
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // SUB reg, r8-r15
        // Save dst to x8
        GEN(gadget_save_xtmp_to_x8);
        // Load r8-r15 into _xtmp
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
        // sub64_x8 does: _xtmp = x8 - _xtmp = dst - src. Correct!
        GEN(gadget_sub64_x8);
      } else if (is_mem(inst.operands[1].type)) {
        // SUB reg, [mem]
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(gadget_sub64_mem);
        } else {
          GEN(gadget_sub32_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // SUB [mem], imm - read-modify-write
      bool is64 = (inst.operands[0].size == size64_64);
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Save address, load, subtract, restore address, store
      GEN(gadget_save_addr);
      if (is64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else {
        GEN(load32_gadgets[9]); // load32_mem
      }
      GEN(state->orig_ip);
      if (is64) {
        GEN(gadget_sub64_imm);
      } else {
        GEN(gadget_sub32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (is64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else {
        GEN(store32_gadgets[9]); // store32_mem
      }
      GEN(state->orig_ip);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type >= arg64_rax &&
               inst.operands[1].type <= arg64_rdi) {
      // SUB [mem], reg (rax-rdi source)
      bool is64 = (inst.operands[0].size == size64_64);
      // 1. Calculate address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // 2. Load from memory
      if (is64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else {
        GEN(load32_gadgets[9]); // load32_mem
      }
      GEN(state->orig_ip);
      // 3. Subtract source register
      if (is64) {
        GEN(sub64_gadgets[inst.operands[1].type - arg64_rax]);
      } else {
        GEN(sub32_gadgets[inst.operands[1].type - arg64_rax]);
      }
      // 4. Recalculate address and store
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (is64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else {
        GEN(store32_gadgets[9]); // store32_mem
      }
      GEN(state->orig_ip);
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

  case ZYDIS_MNEMONIC_CDQ:
    // Sign extend EAX to EDX:EAX (opcode 99)
    // EDX becomes all 1s if EAX negative, else all 0s
    GEN(gadget_cdq);
    break;

  case ZYDIS_MNEMONIC_CQO:
    // Sign extend RAX to RDX:RAX (opcode 48 99)
    // RDX becomes all 1s if RAX negative, else all 0s
    GEN(gadget_cqo);
    break;

  case ZYDIS_MNEMONIC_CMP:
    // Compare - sets flags without storing result
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      // CMP reg, ...
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // CMP reg, imm - use size-appropriate compare
        switch (inst.operands[0].size) {
        case size64_8:
          GEN(gadget_cmp8_imm);
          GEN(inst.operands[1].imm & 0xFF);
          break;
        case size64_16:
          GEN(gadget_cmp16_imm);
          GEN(inst.operands[1].imm & 0xFFFF);
          break;
        case size64_32:
          GEN(gadget_cmp32_imm);
          GEN(inst.operands[1].imm & 0xFFFFFFFF);
          break;
        default:
          GEN(gadget_cmp64_imm);
          GEN(inst.operands[1].imm);
          break;
        }
      } else if (inst.operands[1].type >= arg64_rax &&
                 inst.operands[1].type <= arg64_rdi) {
        // CMP with register (rax-rdi)
        switch (inst.operands[0].size) {
        case size64_8:
          GEN(gadget_cmp8_reg);
          break;
        case size64_16:
          GEN(gadget_cmp16_reg);
          break;
        case size64_32:
          GEN(gadget_cmp32_reg);
          break;
        default:
          GEN(gadget_cmp64_reg);
          break;
        }
        GEN(inst.operands[1].type - arg64_rax);
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // CMP with r8-r15: compare _xtmp with r[N] from cpu_state
        // Save destination (in _xtmp) to x8
        GEN(gadget_save_xtmp_to_x8);
        // Load r8-r15 into _xtmp
        gadget_t load_r = get_load64_reg_gadget(inst.operands[1].type);
        if (load_r)
          GEN(load_r);
        // Swap so x8 = r[N], _xtmp = original dest
        GEN(gadget_swap_xtmp_x8);
        // Now cmp_x8 does _xtmp - x8 = dest - r[N]
        switch (inst.operands[0].size) {
        case size64_8:
          GEN(gadget_cmp8_x8);
          break;
        case size64_16:
          GEN(gadget_cmp16_x8);
          break;
        case size64_32:
          GEN(gadget_cmp32_x8);
          break;
        default:
          GEN(gadget_cmp64_x8);
          break;
        }
      } else if (is_mem(inst.operands[1].type)) {
        // CMP reg, [mem] - compute reg - mem, set flags
        GEN(gadget_save_xtmp_to_x8); // x8 = reg value
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        // Load from memory into _xtmp
        switch (inst.operands[1].size) {
        case size64_8:
          GEN(gadget_load8_mem);
          break;
        case size64_16:
          GEN(gadget_load16_mem);
          break;
        case size64_32:
          GEN(load32_gadgets[9]); // load32_mem
          break;
        default:
          GEN(load64_gadgets[9]); // load64_mem
          break;
        }
        GEN(state->orig_ip);
        // Now: x8 = reg, _xtmp = mem
        // We want: reg - mem (flags for CMP reg, mem)
        // cmp_x8 does: _xtmp - x8 = mem - reg (wrong order)
        // Swap to get: _xtmp = reg, x8 = mem
        // Then cmp_x8 does: reg - mem (correct)
        GEN(gadget_swap_xtmp_x8);
        // Use size-appropriate compare
        switch (inst.operands[1].size) {
        case size64_8:
          GEN(gadget_cmp8_x8);
          break;
        case size64_16:
          GEN(gadget_cmp16_x8);
          break;
        case size64_32:
          GEN(gadget_cmp32_x8);
          break;
        default:
          GEN(gadget_cmp64_x8);
          break;
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // CMP [mem], imm
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load from memory with correct size
      switch (inst.operands[0].size) {
      case size64_8:
        GEN(gadget_load8_mem);
        GEN(state->orig_ip);
        GEN(gadget_cmp8_imm);
        GEN(inst.operands[1].imm & 0xFF);
        break;
      case size64_16:
        GEN(gadget_load16_mem);
        GEN(state->orig_ip);
        GEN(gadget_cmp16_imm);
        GEN(inst.operands[1].imm & 0xFFFF);
        break;
      case size64_32:
        GEN(load32_gadgets[9]); // load32_mem
        GEN(state->orig_ip);
        GEN(gadget_cmp32_imm);
        GEN(inst.operands[1].imm & 0xFFFFFFFF);
        break;
      default:
        GEN(load64_gadgets[9]); // load64_mem
        GEN(state->orig_ip);
        GEN(gadget_cmp64_imm);
        GEN(inst.operands[1].imm);
        break;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // CMP [mem], reg
      // For correct flag setting, we need to compare at the operand size
      // Strategy: load mem to _xtmp, save to x8, load reg to _xtmp, use cmp_x8
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load from memory into _xtmp
      switch (inst.operands[0].size) {
      case size64_8:
        GEN(gadget_load8_mem);
        break;
      case size64_16:
        GEN(gadget_load16_mem);
        break;
      case size64_32:
        GEN(load32_gadgets[9]);
        break;
      default:
        GEN(load64_gadgets[9]);
        break;
      }
      GEN(state->orig_ip);
      // Save memory value to x8
      GEN(gadget_save_xtmp_to_x8);
      // Load register into _xtmp
      gadget_t load_reg = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_reg) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(load_reg);
      // Compare: we now have x8=mem, _xtmp=reg
      // We want to compute mem - reg (x8 - _xtmp), but cmp_x8 does _xtmp - x8
      // So we need to swap: save _xtmp, reload x8 into _xtmp, compare with
      // saved Actually, for flag correctness, we need to compute mem - reg
      // Since cmp8_x8 does: _xtmp - x8 (which is reg - mem)
      // The flags would be inverted for signed comparisons
      // Let's swap: put mem in _xtmp, reg in x8
      // Save reg to temp, reload mem
      // Actually, simpler: use the comparison order we have
      // x8 = mem value, _xtmp = reg value
      // We want flags for: mem - reg (comparison of mem with reg)
      // cmp_x8 does: _xtmp - x8 = reg - mem
      // This gives wrong flags for conditions like JL, JG
      // Need to swap operands. Let me restructure:
      // 1. Load mem to _xtmp
      // 2. Save _xtmp to x8 (now x8 = mem)
      // 3. Load reg to _xtmp (now _xtmp = reg)
      // 4. Swap: save _xtmp somewhere, put x8 in _xtmp, put saved in x8
      // This is getting complicated. Let me use cmp with the right order.
      // Actually, let me just use size-specific cmp gadget that takes reg index
      // For now, swap x8 and _xtmp before comparing
      GEN(gadget_swap_xtmp_x8); // Now _xtmp = mem, x8 = reg
      // Now use size-appropriate compare
      switch (inst.operands[0].size) {
      case size64_8:
        // DEBUG: trace all CMP [mem], reg byte-sized
        GEN(gadget_debug_cmp);
        GEN(gadget_cmp8_x8);
        break;
      case size64_16:
        GEN(gadget_cmp16_x8);
        break;
      case size64_32:
        GEN(gadget_cmp32_x8);
        break;
      default:
        GEN(gadget_cmp64_x8);
        break;
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
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        // TEST reg, imm - use size-appropriate test
        switch (inst.operands[0].size) {
        case size64_8:
          GEN(gadget_test8_imm);
          GEN(inst.operands[1].imm & 0xFF);
          break;
        case size64_16:
          GEN(gadget_test16_imm);
          GEN(inst.operands[1].imm & 0xFFFF);
          break;
        case size64_32:
          GEN(gadget_test32_imm);
          GEN(inst.operands[1].imm & 0xFFFFFFFF);
          break;
        default:
          GEN(gadget_test64_imm);
          GEN(inst.operands[1].imm);
          break;
        }
      } else if (is_gpr(inst.operands[1].type)) {
        // TEST reg, reg - must use size-appropriate test for correct flags
        // For testb %al, %al we need to test only the relevant bits
        int reg_idx = inst.operands[1].type - arg64_rax;

        // For same-register test (e.g., testb %al, %al), just use TEST with
        // mask The size determines the mask value
        if (inst.operands[0].type == inst.operands[1].type) {
          // Self-test: TEST r, r is equivalent to AND r, r (flags only)
          // Use test_imm with the appropriate mask
          switch (inst.operands[0].size) {
          case size64_8:
            GEN(gadget_test8_imm);
            GEN(0xFF); // TEST AL, 0xFF tests all 8 bits of AL
            break;
          case size64_16:
            GEN(gadget_test16_imm);
            GEN(0xFFFF);
            break;
          case size64_32:
            GEN(gadget_test32_imm);
            GEN(0xFFFFFFFF);
            break;
          default:
            GEN(gadget_test64_imm);
            GEN(-1);
            break;
          }
        } else if (reg_idx >= 0 && reg_idx < 8) {
          // Different registers in rax-rdi range
          // Use size-appropriate test gadgets
          switch (inst.operands[0].size) {
          case size64_8:
            GEN(gadget_test8_reg);
            GEN(reg_idx);
            break;
          case size64_16:
            GEN(gadget_test16_reg);
            GEN(reg_idx);
            break;
          case size64_32:
            GEN(gadget_test32_reg);
            GEN(reg_idx);
            break;
          default:
            GEN(test64_gadgets[reg_idx]);
            break;
          }
        } else {
          // r8-r15: load to x8, use size-appropriate test gadget
          DEBUG_FPRINTF(stderr,
                  "GEN: TEST r8-r15 at ip=0x%llx op0=%d op1=%d reg_idx=%d "
                  "size=%d\n",
                  (unsigned long long)state->orig_ip, inst.operands[0].type,
                  inst.operands[1].type, reg_idx, inst.operands[0].size);
          gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
          if (load2) {
            GEN(gadget_save_xtmp_to_x8);
            GEN(load2);
            // Use 32-bit TEST for 32-bit operands, 64-bit otherwise
            if (inst.operands[0].size == size64_32) {
              GEN(gadget_test32_x8);
            } else {
              GEN(gadget_test64_x8);
            }
          }
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else if (inst.operand_count >= 2 && inst.operands[0].type == arg64_imm &&
               is_gpr(inst.operands[1].type)) {
      // Alternate ordering: (imm, reg)
      gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
      if (load)
        GEN(load);
      switch (inst.operands[1].size) {
      case size64_8:
        GEN(gadget_test8_imm);
        GEN(inst.operands[0].imm & 0xFF);
        break;
      case size64_16:
        GEN(gadget_test16_imm);
        GEN(inst.operands[0].imm & 0xFFFF);
        break;
      case size64_32:
        GEN(gadget_test32_imm);
        GEN(inst.operands[0].imm & 0xFFFFFFFF);
        break;
      default:
        GEN(gadget_test64_imm);
        GEN(inst.operands[0].imm);
        break;
      }
    } else if (inst.operand_count == 1 && inst.operands[0].type == arg64_imm) {
      // TEST AL, imm8 (short form a8) - AL is implicit
      // Load RAX and test (only low byte matters for flags)
      GEN(load64_gadgets[0]); // load64_a
      GEN(gadget_test8_imm);
      GEN(inst.operands[0].imm & 0xFF); // 8-bit immediate
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // TEST [mem], imm
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load from memory with correct size
      switch (inst.operands[0].size) {
      case size64_8:
        GEN(gadget_load8_mem);
        GEN(state->orig_ip);
        GEN(gadget_test8_imm);
        GEN(inst.operands[1].imm & 0xFF);
        break;
      case size64_16:
        GEN(gadget_load16_mem);
        GEN(state->orig_ip);
        GEN(gadget_test16_imm);
        GEN(inst.operands[1].imm & 0xFFFF);
        break;
      case size64_32:
        GEN(load32_gadgets[9]); // load32_mem
        GEN(state->orig_ip);
        GEN(gadget_test32_imm);
        GEN(inst.operands[1].imm & 0xFFFFFFFF);
        break;
      default:
        GEN(load64_gadgets[9]); // load64_mem
        GEN(state->orig_ip);
        GEN(gadget_test64_imm);
        GEN(inst.operands[1].imm);
        break;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // TEST [mem], reg - load from memory, AND with reg, set flags (no store)
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load from memory with correct size
      int size_bits = inst.operands[0].size;
      if (size_bits == size64_64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else if (size_bits == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else if (size_bits == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // Save memory value to x8
      GEN(gadget_save_xtmp_to_x8);
      // Load source register
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (load_src)
        GEN(load_src);
      // Use size-appropriate TEST gadget
      switch (size_bits) {
      case size64_8:
        GEN(gadget_test8_x8);
        break;
      case size64_16:
        GEN(gadget_test16_x8);
        break;
      case size64_32:
        GEN(gadget_test32_x8);
        break;
      default:
        GEN(gadget_test64_x8);
        break;
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_AND:
    // AND instruction
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      // AND reg, ...
      // Debug: trace 8/16-bit AND to see if they're causing issues
      if (inst.operands[0].size == size64_8 ||
          inst.operands[0].size == size64_16) {
        DEBUG_FPRINTF(stderr, "GEN: AND%d at ip=0x%llx op0=%d imm=0x%llx\n",
                inst.operands[0].size == size64_8 ? 8 : 16,
                (unsigned long long)state->orig_ip, inst.operands[0].type,
                (unsigned long long)(inst.operands[1].type == arg64_imm
                                         ? inst.operands[1].imm
                                         : 0));
      }
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[1].type == arg64_imm) {
        GEN(gadget_and64_imm);
        GEN(inst.operands[1].imm);
      } else if (is_gpr(inst.operands[1].type)) {
        int reg_idx = inst.operands[1].type - arg64_rax;
        if (reg_idx >= 0 && reg_idx < 8) {
          GEN(and64_gadgets[reg_idx]);
        } else {
          // r8-r15: load to x8, use and64_x8
          gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
          if (load2) {
            GEN(gadget_save_xtmp_to_x8);
            GEN(load2);
            GEN(gadget_and64_x8);
          }
        }
      } else if (is_mem(inst.operands[1].type)) {
        GEN(gadget_save_xtmp_to_x8);
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(load64_gadgets[9]); // load64_mem
        GEN(state->orig_ip);
        GEN(gadget_and64_x8);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // AND [mem], imm - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      bool is64 = (inst.operands[0].size == size64_64);
      // Save address, load, modify, restore address, store
      GEN(gadget_save_addr); // Save guest address
      if (is64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else {
        GEN(load32_gadgets[9]); // load32_mem
      }
      GEN(state->orig_ip);
      // AND with immediate
      if (is64) {
        GEN(gadget_and64_imm);
      } else {
        GEN(gadget_and32_imm);
      }
      GEN(inst.operands[1].imm);
      // Restore address and store
      GEN(gadget_restore_addr);
      if (is64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else {
        GEN(store32_gadgets[9]); // store32_mem
      }
      GEN(state->orig_ip);
    } else if (is_mem(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
      // AND [mem], reg - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int size_bits = inst.operands[0].size;
      // Save address, load from memory
      GEN(gadget_save_addr);
      if (size_bits == size64_64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else if (size_bits == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else if (size_bits == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // Load source reg to x8, AND
      GEN(gadget_save_xtmp_to_x8);
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (load_src)
        GEN(load_src);
      GEN(gadget_and64_x8);
      // Mask result for smaller sizes
      if (size_bits == size64_32) {
        GEN(gadget_and64_imm);
        GEN(0xFFFFFFFF);
      } else if (size_bits == size64_16) {
        GEN(gadget_and64_imm);
        GEN(0xFFFF);
      } else if (size_bits == size64_8) {
        GEN(gadget_and64_imm);
        GEN(0xFF);
      }
      // Restore address and store
      GEN(gadget_restore_addr);
      if (size_bits == size64_64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else if (size_bits == size64_32) {
        GEN(store32_gadgets[9]); // store32_mem
      } else if (size_bits == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
      }
      GEN(state->orig_ip);
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
        if (load)
          GEN(load);

        if (inst.operands[1].type == arg64_imm) {
          // For 8-bit OR operations, we need special handling
          int64_t imm = inst.operands[1].imm;
          if (inst.operands[0].size == size64_8) {
            // Mask immediate to 8 bits (in case Zydis sign-extended)
            imm = imm & 0xff;
            // Check if destination is a high-byte register (AH, BH, CH, DH)
            if (inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
              // High-byte register: shift immediate to bits [15:8]
              imm = imm << 8;
            }
          }
          GEN(gadget_or64_imm);
          GEN(imm);
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
          if (!gen_addr(state, &inst.operands[1], &inst)) {
            g(interrupt);
            GEN(INT_UNDEFINED);
            GEN(state->orig_ip);
            GEN(state->orig_ip);
            return 0;
          }
          // Use size-appropriate load from memory
          switch (inst.operands[1].size) {
          case size64_8:
            GEN(gadget_load8_mem);
            break;
          case size64_16:
            GEN(gadget_load16_mem);
            break;
          case size64_32:
            GEN(load32_gadgets[9]); // load32_mem
            break;
          default:
            GEN(load64_gadgets[9]); // load64_mem
            break;
          }
          GEN(state->orig_ip);
          // Use size-appropriate OR with x8
          // For 32-bit ops on r8-r15, or64_x8 works since we loaded 32 bits
          // zero-extended
          GEN(gadget_or64_x8);
        } else {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }

        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (is_mem(inst.operands[0].type)) {
        if (is_gpr(inst.operands[1].type)) {
          // OR mem, reg - need to load reg to x8 first
          gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
          if (load_src)
            GEN(load_src);
          GEN(gadget_save_xtmp_to_x8);
          if (!gen_addr(state, &inst.operands[0], &inst)) {
            g(interrupt);
            GEN(INT_UNDEFINED);
            GEN(state->orig_ip);
            GEN(state->orig_ip);
            return 0;
          }
          // FIX: Use size-appropriate OR gadget to avoid corrupting adjacent
          // memory
          if (inst.operands[0].size == size64_64) {
            GEN(gadget_or64_mem);
          } else {
            GEN(gadget_or32_mem); // 32-bit (or smaller) OR
          }
          GEN(state->orig_ip);
        } else if (inst.operands[1].type == arg64_imm) {
          // OR [mem], imm - read-modify-write
          if (!gen_addr(state, &inst.operands[0], &inst)) {
            g(interrupt);
            GEN(INT_UNDEFINED);
            GEN(state->orig_ip);
            GEN(state->orig_ip);
            return 0;
          }
          bool is64 = (inst.operands[0].size == size64_64);
          // Save address, load, modify, restore address, store
          GEN(gadget_save_addr); // Save guest address
          if (is64) {
            GEN(load64_gadgets[9]); // load64_mem
          } else {
            GEN(load32_gadgets[9]); // load32_mem
          }
          GEN(state->orig_ip);
          // OR with immediate
          GEN(gadget_or64_imm);
          GEN(inst.operands[1].imm);
          // Restore address and store
          GEN(gadget_restore_addr);
          if (is64) {
            GEN(store64_gadgets[9]); // store64_mem
          } else {
            GEN(store32_gadgets[9]); // store32_mem
          }
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
      if (load)
        GEN(load);

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
      if (store)
        GEN(store);
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
      if (load)
        GEN(load);

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
      if (store)
        GEN(store);
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
      if (load)
        GEN(load);

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
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_ROL:
    // Rotate left
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      bool is_32bit = (inst.operands[0].size == size64_32);

      if (inst.operand_count == 1) {
        // Implicit 1 (opcode d1) - rotate by 1
        GEN(is_32bit ? gadget_rol32_one : gadget_rol64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[1].imm == 1) {
          GEN(is_32bit ? gadget_rol32_one : gadget_rol64_one);
        } else {
          GEN(is_32bit ? gadget_rol32_imm : gadget_rol64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(is_32bit ? gadget_rol32_cl : gadget_rol64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_ROR:
    // Rotate right
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      bool is_32bit = (inst.operands[0].size == size64_32);

      if (inst.operand_count == 1) {
        // Implicit 1 - rotate by 1
        GEN(is_32bit ? gadget_ror32_one : gadget_ror64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[1].imm == 1) {
          GEN(is_32bit ? gadget_ror32_one : gadget_ror64_one);
        } else {
          GEN(is_32bit ? gadget_ror32_imm : gadget_ror64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(is_32bit ? gadget_ror32_cl : gadget_ror64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SHRD:
    // SHRD dst, src, count - double precision shift right
    // Gadget expects: _xtmp = dst, x8 = src
    if (inst.operand_count >= 3 && is_gpr(inst.operands[0].type) &&
        is_gpr(inst.operands[1].type)) {
      // Load dst into _xtmp
      gadget_t load_dst = get_load64_reg_gadget(inst.operands[0].type);
      if (load_dst)
        GEN(load_dst);

      // Save dst to x8, then load src into _xtmp, then swap
      GEN(gadget_save_xtmp_to_x8);
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (load_src)
        GEN(load_src);
      GEN(gadget_swap_xtmp_x8); // Now _xtmp = dst, x8 = src

      bool is_32bit = (inst.operands[0].size == size64_32);

      if (inst.operands[2].type == arg64_imm) {
        // SHRD reg, reg, imm
        GEN(is_32bit ? gadget_shrd32_imm : gadget_shrd64_imm);
        GEN(inst.operands[2].imm);
      } else if (inst.operands[2].type == arg64_rcx) {
        // SHRD reg, reg, cl
        GEN(is_32bit ? gadget_shrd32_cl : gadget_shrd64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SHLD:
    // SHLD dst, src, count - double precision shift left
    // Gadget expects: _xtmp = dst, x8 = src
    if (inst.operand_count >= 3 && is_gpr(inst.operands[0].type) &&
        is_gpr(inst.operands[1].type)) {
      // Load dst into _xtmp
      gadget_t load_dst = get_load64_reg_gadget(inst.operands[0].type);
      if (load_dst)
        GEN(load_dst);

      // Save dst to x8, then load src into _xtmp, then swap
      GEN(gadget_save_xtmp_to_x8);
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (load_src)
        GEN(load_src);
      GEN(gadget_swap_xtmp_x8); // Now _xtmp = dst, x8 = src

      bool is_32bit = (inst.operands[0].size == size64_32);

      if (inst.operands[2].type == arg64_imm) {
        // SHLD reg, reg, imm
        GEN(is_32bit ? gadget_shld32_imm : gadget_shld64_imm);
        GEN(inst.operands[2].imm);
      } else if (inst.operands[2].type == arg64_rcx) {
        // SHLD reg, reg, cl
        GEN(is_32bit ? gadget_shld32_cl : gadget_shld64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_BSF:
    // BSF dst, src - Bit Scan Forward (find lowest set bit)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type) &&
        is_gpr(inst.operands[1].type)) {
      // Load source into _xtmp
      gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
      if (load)
        GEN(load);

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_bsf32 : gadget_bsf64);

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_BSR:
    // BSR dst, src - Bit Scan Reverse (find highest set bit)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type) &&
        is_gpr(inst.operands[1].type)) {
      // Load source into _xtmp
      gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
      if (load)
        GEN(load);

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_bsr32 : gadget_bsr64);

      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
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
          (inst.operands[1].type == arg64_mem &&
           inst.operands[1].mem.rip_relative)) {
        // LEA reg, [RIP + disp]
        // Compute: state->ip (after instruction) + displacement
        int64_t effective_addr = state->ip + inst.operands[1].mem.disp;
        // Debug: trace RIP-relative LEA around the problem area
        // 0x648d2 offset = 0x7efffff5e000 + 0x648d2 = 0x7effffc48d2
        if (state->orig_ip >= 0x7effffc48d0 &&
            state->orig_ip <= 0x7effffc48e0) {
          DEBUG_FPRINTF(stderr,
                  "LEA RIP-rel[string]: ip=0x%llx next_ip=0x%llx disp=0x%llx "
                  "eff=0x%llx dst=%d\n",
                  (unsigned long long)state->orig_ip,
                  (unsigned long long)state->ip,
                  (long long)inst.operands[1].mem.disp,
                  (unsigned long long)effective_addr, inst.operands[0].type);
        }
        GEN(load64_gadgets[8]); // load64_imm
        GEN(effective_addr);
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_mem &&
                 is_gpr(inst.operands[1].mem.base) &&
                 inst.operands[1].mem.index == arg64_invalid) {
        // LEA reg, [base + disp]
        gadget_t load = get_load64_reg_gadget(inst.operands[1].mem.base);
        if (load)
          GEN(load);
        if (inst.operands[1].mem.disp != 0) {
          // LEA does NOT modify flags, use flag-preserving add
          GEN(gadget_lea_add64_imm);
          GEN(inst.operands[1].mem.disp);
        }
        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
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

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_mem &&
                 inst.operands[1].mem.base >= arg64_rax &&
                 inst.operands[1].mem.base <= arg64_rdi &&
                 inst.operands[1].mem.index >= arg64_r8 &&
                 inst.operands[1].mem.index <= arg64_r15) {
        // LEA reg, [base + r8-r15*scale + disp] where index is r8-r15
        int scale_idx = get_scale_idx(inst.operands[1].mem.scale);
        if (scale_idx < 0) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }

        // Load base + displacement into _addr
        GEN(addr_gadgets[inst.operands[1].mem.base - arg64_rax]);
        GEN(inst.operands[1].mem.disp);

        // Apply scaled index from r8-r15
        int si_index = (inst.operands[1].mem.index - arg64_r8) * 4 + scale_idx;
        GEN(si_r8_r15_gadgets[si_index]);

        // _addr now has the effective address, load it into dst
        GEN(load64_gadgets[10]); // load64_addr - load _addr into _xtmp

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
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

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_mem &&
                 inst.operands[1].mem.base == arg64_invalid &&
                 inst.operands[1].mem.index >= arg64_r8 &&
                 inst.operands[1].mem.index <= arg64_r15) {
        // LEA reg, [r8-r15*scale + disp] (no base, r8-r15 as scaled index)
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

        // Apply scaled index with r8-r15
        int si_index = (inst.operands[1].mem.index - arg64_r8) * 4 + scale_idx;
        GEN(si_r8_r15_gadgets[si_index]);

        // _addr now has the effective address, load it into dst
        GEN(load64_gadgets[10]); // load64_addr - load _addr into _xtmp

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (inst.operands[1].type == arg64_mem &&
                 inst.operands[1].mem.base >= arg64_r8 &&
                 inst.operands[1].mem.base <= arg64_r15) {
        // LEA reg, [r8-r15 + index*scale + disp] or [r8-r15 + disp]
        // Need to load base (r8-r15) first, then add scaled index and
        // displacement
        gadget_t load_base = get_load64_reg_gadget(inst.operands[1].mem.base);
        if (!load_base) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(load_base); // Load r8-r15 into _xtmp

        // Add displacement (LEA does NOT modify flags)
        if (inst.operands[1].mem.disp != 0) {
          GEN(gadget_lea_add64_imm);
          GEN(inst.operands[1].mem.disp);
        }

        // If there's a scaled index, add it
        if (inst.operands[1].mem.index != arg64_invalid &&
            inst.operands[1].mem.index >= arg64_rax &&
            inst.operands[1].mem.index <= arg64_rdi) {
          int scale_idx = get_scale_idx(inst.operands[1].mem.scale);
          if (scale_idx >= 0) {
            // Save _xtmp (base+disp) to x8
            GEN(gadget_save_xtmp_to_x8);
            // Load index register
            gadget_t load_idx =
                get_load64_reg_gadget(inst.operands[1].mem.index);
            if (load_idx) {
              GEN(load_idx);
            }
            // Scale it
            if (inst.operands[1].mem.scale == 2) {
              GEN(gadget_shl64_imm);
              GEN(1);
            } else if (inst.operands[1].mem.scale == 4) {
              GEN(gadget_shl64_imm);
              GEN(2);
            } else if (inst.operands[1].mem.scale == 8) {
              GEN(gadget_shl64_imm);
              GEN(3);
            }
            // Add scaled index to base+disp (x8)
            GEN(gadget_add64_x8);
          }
        } else if (inst.operands[1].mem.index != arg64_invalid &&
                   inst.operands[1].mem.index >= arg64_r8 &&
                   inst.operands[1].mem.index <= arg64_r15) {
          // Index is r8-r15: save _xtmp to x8, load index, scale, add
          int scale_idx = get_scale_idx(inst.operands[1].mem.scale);
          if (scale_idx >= 0) {
            // Save _xtmp (base+disp) to x8
            GEN(gadget_save_xtmp_to_x8);
            // Load index register (r8-r15)
            gadget_t load_idx =
                get_load64_reg_gadget(inst.operands[1].mem.index);
            if (load_idx) {
              GEN(load_idx);
            }
            // Scale it (LEA does NOT modify flags)
            if (inst.operands[1].mem.scale == 2) {
              GEN(gadget_shl64_imm);
              GEN(1);
            } else if (inst.operands[1].mem.scale == 4) {
              GEN(gadget_shl64_imm);
              GEN(2);
            } else if (inst.operands[1].mem.scale == 8) {
              GEN(gadget_shl64_imm);
              GEN(3);
            }
            // Add scaled index to base+disp (x8)
            // NOTE: This uses flag-modifying add, but LEA shouldn't modify
            // flags For now, use lea_add64_x8 if available, otherwise regular
            // add
            GEN(gadget_add64_x8);
          }
        }

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        // Store result
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
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

  // SETcc - conditional set byte instructions
  case ZYDIS_MNEMONIC_SETO:
  case ZYDIS_MNEMONIC_SETNO:
  case ZYDIS_MNEMONIC_SETB:   // Also SETC, SETNAE
  case ZYDIS_MNEMONIC_SETNB:  // Also SETNC, SETAE
  case ZYDIS_MNEMONIC_SETZ:   // Also SETE
  case ZYDIS_MNEMONIC_SETNZ:  // Also SETNE
  case ZYDIS_MNEMONIC_SETBE:  // Also SETNA
  case ZYDIS_MNEMONIC_SETNBE: // Also SETA
  case ZYDIS_MNEMONIC_SETS:
  case ZYDIS_MNEMONIC_SETNS:
  case ZYDIS_MNEMONIC_SETP:   // Also SETPE
  case ZYDIS_MNEMONIC_SETNP:  // Also SETPO
  case ZYDIS_MNEMONIC_SETL:   // Also SETNGE
  case ZYDIS_MNEMONIC_SETNL:  // Also SETGE
  case ZYDIS_MNEMONIC_SETLE:  // Also SETNG
  case ZYDIS_MNEMONIC_SETNLE: // Also SETG
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      // SETcc reg8 - set byte register based on condition
      gadget_t set_gadget = NULL;
      switch (inst.mnemonic) {
      case ZYDIS_MNEMONIC_SETO:
        set_gadget = gadget_set_o;
        break;
      case ZYDIS_MNEMONIC_SETNO:
        set_gadget = gadget_setn_o;
        break;
      case ZYDIS_MNEMONIC_SETB:
        set_gadget = gadget_set_c;
        break;
      case ZYDIS_MNEMONIC_SETNB:
        set_gadget = gadget_setn_c;
        break;
      case ZYDIS_MNEMONIC_SETZ:
        set_gadget = gadget_set_z;
        break;
      case ZYDIS_MNEMONIC_SETNZ:
        set_gadget = gadget_setn_z;
        break;
      case ZYDIS_MNEMONIC_SETBE:
        set_gadget = gadget_set_cz;
        break;
      case ZYDIS_MNEMONIC_SETNBE:
        set_gadget = gadget_setn_cz;
        break;
      case ZYDIS_MNEMONIC_SETS:
        set_gadget = gadget_set_s;
        break;
      case ZYDIS_MNEMONIC_SETNS:
        set_gadget = gadget_setn_s;
        break;
      case ZYDIS_MNEMONIC_SETP:
        set_gadget = gadget_set_p;
        break;
      case ZYDIS_MNEMONIC_SETNP:
        set_gadget = gadget_setn_p;
        break;
      case ZYDIS_MNEMONIC_SETL:
        set_gadget = gadget_set_sxo;
        break;
      case ZYDIS_MNEMONIC_SETNL:
        set_gadget = gadget_setn_sxo;
        break;
      case ZYDIS_MNEMONIC_SETLE:
        set_gadget = gadget_set_sxoz;
        break;
      case ZYDIS_MNEMONIC_SETNLE:
        set_gadget = gadget_setn_sxoz;
        break;
      default:
        break;
      }
      if (set_gadget) {
        GEN(set_gadget);
        // SETcc writes to _tmp (w0), need to store to byte portion of reg
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      }
    } else if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
      // SETcc [mem] - set byte in memory based on condition
      gadget_t set_gadget = NULL;
      switch (inst.mnemonic) {
      case ZYDIS_MNEMONIC_SETO:
        set_gadget = gadget_set_o;
        break;
      case ZYDIS_MNEMONIC_SETNO:
        set_gadget = gadget_setn_o;
        break;
      case ZYDIS_MNEMONIC_SETB:
        set_gadget = gadget_set_c;
        break;
      case ZYDIS_MNEMONIC_SETNB:
        set_gadget = gadget_setn_c;
        break;
      case ZYDIS_MNEMONIC_SETZ:
        set_gadget = gadget_set_z;
        break;
      case ZYDIS_MNEMONIC_SETNZ:
        set_gadget = gadget_setn_z;
        break;
      case ZYDIS_MNEMONIC_SETBE:
        set_gadget = gadget_set_cz;
        break;
      case ZYDIS_MNEMONIC_SETNBE:
        set_gadget = gadget_setn_cz;
        break;
      case ZYDIS_MNEMONIC_SETS:
        set_gadget = gadget_set_s;
        break;
      case ZYDIS_MNEMONIC_SETNS:
        set_gadget = gadget_setn_s;
        break;
      case ZYDIS_MNEMONIC_SETP:
        set_gadget = gadget_set_p;
        break;
      case ZYDIS_MNEMONIC_SETNP:
        set_gadget = gadget_setn_p;
        break;
      case ZYDIS_MNEMONIC_SETL:
        set_gadget = gadget_set_sxo;
        break;
      case ZYDIS_MNEMONIC_SETNL:
        set_gadget = gadget_setn_sxo;
        break;
      case ZYDIS_MNEMONIC_SETLE:
        set_gadget = gadget_set_sxoz;
        break;
      case ZYDIS_MNEMONIC_SETNLE:
        set_gadget = gadget_setn_sxoz;
        break;
      default:
        break;
      }
      if (set_gadget) {
        GEN(set_gadget);
        // Store byte to memory
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_store8_mem);
        GEN(state->orig_ip);
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
      // Gadget expects: x8 = dst (original value), _xtmp = src (potential new
      // value)

      // Step 1: Load destination value into _xtmp, then save to x8
      gadget_t load_dst = get_load64_reg_gadget(inst.operands[0].type);
      if (load_dst)
        GEN(load_dst);
      GEN(gadget_save_xtmp_to_x8);

      // Step 2: Load source into _xtmp
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
      } else {
        // Memory source
        if (!gen_addr(state, &inst.operands[1], &inst)) {
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
      case ZYDIS_MNEMONIC_CMOVO:
        cmov_gadget = gadget_cmov_o;
        break;
      case ZYDIS_MNEMONIC_CMOVNO:
        cmov_gadget = gadget_cmovn_o;
        break;
      case ZYDIS_MNEMONIC_CMOVB:
        cmov_gadget = gadget_cmov_c;
        break;
      case ZYDIS_MNEMONIC_CMOVNB:
        cmov_gadget = gadget_cmovn_c;
        break;
      case ZYDIS_MNEMONIC_CMOVZ:
        cmov_gadget = gadget_cmov_z;
        break;
      case ZYDIS_MNEMONIC_CMOVNZ:
        cmov_gadget = gadget_cmovn_z;
        break;
      case ZYDIS_MNEMONIC_CMOVBE:
        cmov_gadget = gadget_cmov_cz;
        break;
      case ZYDIS_MNEMONIC_CMOVNBE:
        cmov_gadget = gadget_cmovn_cz;
        break;
      case ZYDIS_MNEMONIC_CMOVS:
        cmov_gadget = gadget_cmov_s;
        break;
      case ZYDIS_MNEMONIC_CMOVNS:
        cmov_gadget = gadget_cmovn_s;
        break;
      case ZYDIS_MNEMONIC_CMOVP:
        cmov_gadget = gadget_cmov_p;
        break;
      case ZYDIS_MNEMONIC_CMOVNP:
        cmov_gadget = gadget_cmovn_p;
        break;
      case ZYDIS_MNEMONIC_CMOVL:
        cmov_gadget = gadget_debug_cmov_sxo;
        break; // Use debug wrapper
      case ZYDIS_MNEMONIC_CMOVNL:
        cmov_gadget = gadget_debug_cmovn_sxo;
        break; // Use debug wrapper
      case ZYDIS_MNEMONIC_CMOVLE:
        cmov_gadget = gadget_cmov_sxoz;
        break;
      case ZYDIS_MNEMONIC_CMOVNLE:
        cmov_gadget = gadget_cmovn_sxoz;
        break;
      default:
        break;
      }

      // Step 4: Apply conditional move (selects between x8 and _xtmp)
      if (cmov_gadget) {
        GEN(cmov_gadget);
      }

      // Step 5: Store result to destination
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
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
        if (!gen_addr(state, &inst.operands[1], &inst)) {
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
        if (load)
          GEN(load);
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
      if (store)
        GEN(store);
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
        if (!gen_addr(state, &inst.operands[1], &inst)) {
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
        if (load)
          GEN(load);
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
      if (store)
        GEN(store);
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
      if (load)
        GEN(load);
      GEN(gadget_save_xtmp_to_x8);

      if (is_gpr(inst.operands[1].type)) {
        // reg-reg form
        gadget_t load_idx = get_load64_reg_gadget(inst.operands[1].type);
        if (load_idx)
          GEN(load_idx);

        switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_BT:
          GEN(gadget_bt64_reg);
          break;
        case ZYDIS_MNEMONIC_BTS:
          GEN(gadget_bts64_reg);
          break;
        case ZYDIS_MNEMONIC_BTR:
          GEN(gadget_btr64_reg);
          break;
        case ZYDIS_MNEMONIC_BTC:
          GEN(gadget_btc64_reg);
          break;
        default:
          break;
        }

        // BTS/BTR/BTC modify the value, store it back
        if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
          gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
          if (store)
            GEN(store);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        // immediate form - bit index is immediate
        switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_BT:
          GEN(gadget_bt64_imm);
          break;
        case ZYDIS_MNEMONIC_BTS:
          GEN(gadget_bts64_imm);
          break;
        case ZYDIS_MNEMONIC_BTR:
          GEN(gadget_btr64_imm);
          break;
        case ZYDIS_MNEMONIC_BTC:
          GEN(gadget_btc64_imm);
          break;
        default:
          break;
        }
        GEN(inst.operands[1].imm);

        // BTS/BTR/BTC modify the value, store it back
        if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
          gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
          if (store)
            GEN(store);
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
      if (!gen_addr(state, &inst.operands[0], &inst)) {
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
        if (load_idx)
          GEN(load_idx);

        switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_BT:
          GEN(gadget_bt64_reg);
          break;
        case ZYDIS_MNEMONIC_BTS:
          GEN(gadget_bts64_reg);
          break;
        case ZYDIS_MNEMONIC_BTR:
          GEN(gadget_btr64_reg);
          break;
        case ZYDIS_MNEMONIC_BTC:
          GEN(gadget_btc64_reg);
          break;
        default:
          break;
        }

        if (inst.mnemonic != ZYDIS_MNEMONIC_BT) {
          GEN(store64_gadgets[9]); // store64_mem
          GEN(state->orig_ip);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_BT:
          GEN(gadget_bt64_imm);
          break;
        case ZYDIS_MNEMONIC_BTS:
          GEN(gadget_bts64_imm);
          break;
        case ZYDIS_MNEMONIC_BTR:
          GEN(gadget_btr64_imm);
          break;
        case ZYDIS_MNEMONIC_BTC:
          GEN(gadget_btc64_imm);
          break;
        default:
          break;
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

  case ZYDIS_MNEMONIC_CMPXCHG:
    // CMPXCHG [mem], reg - Compare and exchange
    // Compare accumulator (RAX/EAX) with [mem]
    // If equal: ZF=1, store reg to [mem]
    // If not equal: ZF=0, load [mem] to accumulator
    if (is_mem(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
      // Calculate memory address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load source register into _xtmp
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_src) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(load_src);
      // Use appropriate cmpxchg gadget based on operand size
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_cmpxchg64_mem);
      } else {
        GEN(gadget_cmpxchg32_mem);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_XCHG:
    // XCHG - Exchange register with register or memory
    if (is_gpr(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
      // XCHG reg1, reg2 - Exchange two registers
      // Load reg1 into _xtmp, save to temp, load reg2, store to reg1, restore
      // temp, store to reg2
      gadget_t load1 = get_load64_reg_gadget(inst.operands[0].type);
      gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
      gadget_t store1 = get_store64_reg_gadget(inst.operands[0].type);
      gadget_t store2 = get_store64_reg_gadget(inst.operands[1].type);
      if (!load1 || !load2 || !store1 || !store2) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load reg1, save to x8
      GEN(load1);
      GEN(gadget_save_xtmp_to_x8);
      // Load reg2, store to reg1
      GEN(load2);
      GEN(store1);
      // Restore x8 (old reg1), store to reg2
      GEN(gadget_restore_xtmp_from_x8);
      GEN(store2);
    } else if (is_gpr(inst.operands[0].type) && is_mem(inst.operands[1].type)) {
      // XCHG reg, [mem] - operand order is reg, mem
      if (!gen_addr(state, &inst.operands[1], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load register value into _xtmp
      gadget_t load_reg = get_load64_reg_gadget(inst.operands[0].type);
      if (!load_reg) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(load_reg);
      // Exchange
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_xchg64_mem);
      } else {
        GEN(gadget_xchg32_mem);
      }
      GEN(state->orig_ip);
      // Store memory value (now in _xtmp) back to register
      gadget_t store_reg = get_store64_reg_gadget(inst.operands[0].type);
      if (store_reg)
        GEN(store_reg);
    } else if (is_mem(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
      // XCHG [mem], reg - operand order is mem, reg
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load register value into _xtmp
      gadget_t load_reg = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_reg) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(load_reg);
      // Exchange
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_xchg64_mem);
      } else {
        GEN(gadget_xchg32_mem);
      }
      GEN(state->orig_ip);
      // Store memory value (now in _xtmp) back to register
      gadget_t store_reg = get_store64_reg_gadget(inst.operands[1].type);
      if (store_reg)
        GEN(store_reg);
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
      if (load)
        GEN(load);
      GEN(gadget_not64);
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
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
      if (load)
        GEN(load);
      GEN(gadget_neg64);
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
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

  case ZYDIS_MNEMONIC_INC:
    // INC - increment by 1 (note: INC doesn't modify CF, but we'll use ADD for
    // simplicity)
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_add32_imm);
      } else {
        GEN(gadget_add64_imm);
      }
      GEN(1);
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else {
        GEN(load64_gadgets[9]); // load64_mem
      }
      GEN(state->orig_ip);
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_add32_imm);
      } else {
        GEN(gadget_add64_imm);
      }
      GEN(1);
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(store32_gadgets[9]); // store32_mem
      } else {
        GEN(store64_gadgets[9]); // store64_mem
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_DEC:
    // DEC - decrement by 1 (note: DEC doesn't modify CF, but we'll use SUB for
    // simplicity)
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_sub32_imm);
      } else {
        GEN(gadget_sub64_imm);
      }
      GEN(1);
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else {
        GEN(load64_gadgets[9]); // load64_mem
      }
      GEN(state->orig_ip);
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_sub32_imm);
      } else {
        GEN(gadget_sub64_imm);
      }
      GEN(1);
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(store32_gadgets[9]); // store32_mem
      } else {
        GEN(store64_gadgets[9]); // store64_mem
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_IMUL:
    // IMUL has three forms:
    // 1. IMUL r/m - one operand, EDX:EAX = EAX * r/m (not commonly used)
    // 2. IMUL r, r/m - two operand, r = r * r/m
    // 3. IMUL r, r/m, imm - three operand, r = r/m * imm
    if (inst.operand_count == 3) {
      // Three operand form: IMUL dst, src, imm
      // dst = src * imm
      if (!is_gpr(inst.operands[0].type)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      // Load source into _xtmp
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      // Multiply by immediate
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_imul32_imm);
      } else {
        GEN(gadget_imul64_imm);
      }
      GEN(inst.operands[2].imm);

      // Store result to destination
      gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
      if (store)
        GEN(store);
    } else if (inst.operand_count == 2) {
      // Two operand form: IMUL dst, src
      // dst = dst * src
      if (!is_gpr(inst.operands[0].type)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      // Get destination register index
      int dst_idx = -1;
      if (inst.operands[0].type >= arg64_rax &&
          inst.operands[0].type <= arg64_rdi) {
        dst_idx = inst.operands[0].type - arg64_rax;
      }

      // Load source into _xtmp
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      // Multiply src * dst -> dst
      if (dst_idx >= 0 && dst_idx < 8) {
        if (inst.operands[0].size == size64_32) {
          GEN(imul32_gadgets[dst_idx]);
        } else {
          GEN(imul64_gadgets[dst_idx]);
        }
      } else if (inst.operands[0].type >= arg64_r8 &&
                 inst.operands[0].type <= arg64_r15) {
        // r8-r15 destination
        int r_idx = inst.operands[0].type - arg64_r8;
        if (inst.operands[0].size == size64_32) {
          GEN(imul32_r8_r15_gadgets[r_idx]);
        } else {
          GEN(imul64_r8_r15_gadgets[r_idx]);
        }
      } else {
        // Unknown destination
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else {
      // Single operand form: RDX:RAX = RAX * src
      // Load source into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Perform wide multiply (RAX * src -> RDX:RAX)
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_imul32_wide);
      } else {
        GEN(gadget_imul64_wide);
      }
    }
    break;

  case ZYDIS_MNEMONIC_DIV:
    // Unsigned divide: EDX:EAX / src -> EAX (quotient), EDX (remainder)
    // For 64-bit: RDX:RAX / src -> RAX (quotient), RDX (remainder)
    if (inst.operand_count >= 1) {
      // Load divisor into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Perform division (RAX/RDX are implicitly used)
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_div32);
      } else {
        GEN(gadget_div64);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_IDIV:
    // Signed divide: EDX:EAX / src -> EAX (quotient), EDX (remainder)
    if (inst.operand_count >= 1) {
      // Load divisor into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Perform signed division
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_idiv32);
      } else {
        GEN(gadget_idiv64);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MUL:
    // Unsigned multiply: RDX:RAX = RAX * r/m
    if (inst.operand_count >= 1) {
      // Load multiplier into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(load64_gadgets[9]); // load64_mem
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Perform unsigned multiplication (RAX * _xtmp -> RDX:RAX)
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_mul32);
      } else {
        GEN(gadget_mul64);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVQ:
    // MOVQ - Move quadword
    // Can be: MOVQ xmm, r/m64 or MOVQ r/m64, xmm
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
        // MOVQ xmm, reg: load GPR value to XMM lower 64 bits
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
        GEN(gadget_movq_to_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else if (is_xmm(inst.operands[0].type) &&
                 is_mem(inst.operands[1].type)) {
        // MOVQ xmm, [mem]: load from memory to XMM lower 64 bits
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(load64_gadgets[9]); // load64_mem
        GEN(state->orig_ip);
        GEN(gadget_movq_to_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else if (is_gpr(inst.operands[0].type) &&
                 is_xmm(inst.operands[1].type)) {
        // MOVQ reg, xmm: extract XMM lower 64 bits to GPR
        GEN(gadget_movq_from_xmm);
        GEN(get_xmm_index(inst.operands[1].type));
        gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
        if (store)
          GEN(store);
      } else if (is_mem(inst.operands[0].type) &&
                 is_xmm(inst.operands[1].type)) {
        // MOVQ [mem], xmm: store XMM lower 64 bits to memory
        GEN(gadget_movq_from_xmm);
        GEN(get_xmm_index(inst.operands[1].type));
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(store64_gadgets[9]); // store64_mem
        GEN(state->orig_ip);
      } else if (is_xmm(inst.operands[0].type) &&
                 is_xmm(inst.operands[1].type)) {
        // MOVQ xmm, xmm: copy XMM lower 64 bits (zero upper)
        GEN(gadget_movq_from_xmm);
        GEN(get_xmm_index(inst.operands[1].type));
        GEN(gadget_movq_to_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else {
        goto movq_unhandled;
      }
    } else {
    movq_unhandled:
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_PUNPCKLQDQ:
    // PUNPCKLQDQ xmm, xmm/m128: Unpack and interleave low quadwords
    // xmm1[127:64] = xmm2[63:0], xmm1[63:0] unchanged
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      if (is_xmm(inst.operands[1].type)) {
        // Both XMM registers
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index to _xtmp
        GEN(get_xmm_index(inst.operands[1].type));
        GEN(gadget_punpcklqdq);
        GEN(get_xmm_index(inst.operands[0].type));
      } else {
        // Memory operand - more complex, not yet implemented
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

  case ZYDIS_MNEMONIC_MOVAPS:
  case ZYDIS_MNEMONIC_MOVUPS:
  case ZYDIS_MNEMONIC_MOVDQA:
  case ZYDIS_MNEMONIC_MOVDQU:
    // MOVAPS/MOVUPS/MOVDQA/MOVDQU - Move 128 bits (aligned/unaligned)
    DEBUG_FPRINTF(stderr,
            "GEN: MOVDQU/MOVAPS at ip=0x%llx operands=%d op0=%d op1=%d "
            "is_xmm(%d,%d) is_mem(%d,%d)\n",
            (unsigned long long)state->orig_ip, inst.operand_count,
            inst.operands[0].type, inst.operands[1].type,
            is_xmm(inst.operands[0].type), is_xmm(inst.operands[1].type),
            is_mem(inst.operands[0].type), is_mem(inst.operands[1].type));
    fflush(stderr);
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // xmm, xmm: Copy between XMM registers
        DEBUG_FPRINTF(stderr, "  -> xmm, xmm form\n");
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(get_xmm_index(inst.operands[1].type));
        GEN(gadget_movaps_xmm_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else if (is_xmm(inst.operands[0].type) &&
                 is_mem(inst.operands[1].type)) {
        // xmm, [mem]: Load from memory to XMM
        DEBUG_FPRINTF(stderr, "  -> xmm, [mem] form\n");
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_movaps_load);
        GEN(state->orig_ip); // For segfault handler
        GEN(get_xmm_index(inst.operands[0].type));
      } else if (is_mem(inst.operands[0].type) &&
                 is_xmm(inst.operands[1].type)) {
        // [mem], xmm: Store XMM to memory
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_movaps_store);
        GEN(state->orig_ip); // For segfault handler
        GEN(get_xmm_index(inst.operands[1].type));
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

  case ZYDIS_MNEMONIC_PXOR:
  case ZYDIS_MNEMONIC_XORPS:
  case ZYDIS_MNEMONIC_XORPD:
    // PXOR/XORPS/XORPD xmm, xmm - XOR 128 bits
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      if (is_xmm(inst.operands[1].type)) {
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(get_xmm_index(inst.operands[1].type));
        GEN(gadget_pxor_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else {
        // Memory operand - not yet implemented
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

  case ZYDIS_MNEMONIC_CVTSI2SD:
    // CVTSI2SD xmm, r/m32 or r/m64 - Convert integer to scalar double
    // Converts a signed integer to double-precision floating-point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      // Determine if 64-bit by checking operand type
      // 64-bit registers are rax-rdi (arg64_rax to arg64_rdi) and r8-r15
      bool is_64bit = false;
      if (is_gpr(inst.operands[1].type)) {
        // Check if it's a 64-bit register (not 32-bit like eax, r8d, etc.)
        // arg64_rax through arg64_r15 are 64-bit
        // Our decoder already distinguishes between eax (32-bit) and rax (64-bit)
        enum arg64 op = inst.operands[1].type;
        is_64bit = (op >= arg64_rax && op <= arg64_rdi) ||
                   (op >= arg64_r8 && op <= arg64_r15);
      } else {
        // For memory operands, check the instruction operand width from inst
        // The instruction f2 48 0f 2a has REX.W (48), making it 64-bit
        // Check the code bytes for REX.W prefix
        is_64bit = (code[0] == 0x48 ||
                    (code[0] == 0xf2 && code[1] == 0x48) ||
                    (code[0] == 0xf3 && code[1] == 0x48));
      }

      if (is_gpr(inst.operands[1].type)) {
        // Register source
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load) {
          GEN(load);
        }
        fprintf(stderr, "GEN: CVTSI2SD xmm%d, reg (%s) at ip=0x%llx\n",
                dst_xmm, is_64bit ? "64-bit" : "32-bit",
                (unsigned long long)state->orig_ip);
        if (is_64bit) {
          GEN(gadget_cvtsi2sd_reg64);
        } else {
          GEN(gadget_cvtsi2sd_reg32);
        }
        GEN(dst_xmm);
      } else {
        // Memory source
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: CVTSI2SD xmm%d, mem (%s) at ip=0x%llx\n",
                dst_xmm, is_64bit ? "64-bit" : "32-bit",
                (unsigned long long)state->orig_ip);
        if (is_64bit) {
          GEN(gadget_cvtsi2sd_mem64);
        } else {
          GEN(gadget_cvtsi2sd_mem32);
        }
        GEN(dst_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_ADDSD:
    // ADDSD xmm, xmm/m64 - Add Scalar Double-Precision Floating-Point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: ADDSD xmm%d, xmm%d at ip=0x%llx\n",
                dst_xmm, src_xmm, (unsigned long long)state->orig_ip);
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(src_xmm);
        GEN(gadget_addsd_xmm_xmm);
        GEN(dst_xmm);
      } else {
        // xmm, m64
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: ADDSD xmm%d, mem at ip=0x%llx\n",
                dst_xmm, (unsigned long long)state->orig_ip);
        GEN(gadget_addsd_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SUBSD:
    // SUBSD xmm, xmm/m64 - Subtract Scalar Double-Precision Floating-Point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: SUBSD xmm%d, xmm%d at ip=0x%llx\n",
                dst_xmm, src_xmm, (unsigned long long)state->orig_ip);
        GEN(load64_gadgets[8]); /* load64_imm: Load source XMM index */
        GEN(src_xmm);
        GEN(gadget_subsd_xmm_xmm);
        GEN(dst_xmm);
      } else {
        // xmm, m64
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: SUBSD xmm%d, mem at ip=0x%llx\n",
                dst_xmm, (unsigned long long)state->orig_ip);
        GEN(gadget_subsd_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MULSD:
    // MULSD xmm, xmm/m64 - Multiply Scalar Double-Precision Floating-Point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: MULSD xmm%d, xmm%d at ip=0x%llx\n",
                dst_xmm, src_xmm, (unsigned long long)state->orig_ip);
        GEN(load64_gadgets[8]); /* load64_imm: Load source XMM index */
        GEN(src_xmm);
        GEN(gadget_mulsd_xmm_xmm);
        GEN(dst_xmm);
      } else {
        // xmm, m64
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: MULSD xmm%d, mem at ip=0x%llx\n",
                dst_xmm, (unsigned long long)state->orig_ip);
        GEN(gadget_mulsd_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_COMISD:
  case ZYDIS_MNEMONIC_UCOMISD:
    // COMISD/UCOMISD xmm, xmm/m64 - Compare Scalar Double, set EFLAGS
    // UCOMISD is unordered (doesn't signal on QNaN), COMISD signals
    // Both set ZF, PF, CF based on comparison result
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int src1_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src2_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: COMISD xmm%d, xmm%d at ip=0x%llx\n",
                src1_xmm, src2_xmm, (unsigned long long)state->orig_ip);
        GEN(load64_gadgets[8]); // load64_imm: Load first XMM index
        GEN(src1_xmm);
        GEN(gadget_comisd_xmm_xmm);
        GEN(src2_xmm);
      } else {
        // xmm, m64
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: COMISD xmm%d, mem at ip=0x%llx\n",
                src1_xmm, (unsigned long long)state->orig_ip);
        GEN(gadget_comisd_xmm_mem);
        GEN(src1_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_CVTTSD2SI:
    // CVTTSD2SI r32/r64, xmm/m64 - Convert with Truncation Scalar Double to Signed Integer
    if (inst.operand_count >= 2) {
      // Determine if 64-bit from operand size
      int is_64bit = (inst.operands[0].size == size64_64);

      // Get destination register
      enum arg64 dst_type = inst.operands[0].type;

      if (is_xmm(inst.operands[1].type)) {
        // CVTTSD2SI reg, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: CVTTSD2SI dst=%d, xmm%d at ip=0x%llx (64bit=%d)\n",
                dst_type, src_xmm, (unsigned long long)state->orig_ip, is_64bit);
        GEN(is_64bit ? gadget_cvttsd2si_reg64 : gadget_cvttsd2si_reg32);
        GEN(src_xmm);
        // Store to destination register
        // For r8-r15, we always use store64 since 32-bit ops zero-extend
        if (dst_type >= arg64_r8 && dst_type <= arg64_r15) {
          GEN(store64_r8_r15[dst_type - arg64_r8]);
        } else {
          GEN(is_64bit ? store64_gadgets[dst_type] : store32_gadgets[dst_type]);
        }
      } else {
        // CVTTSD2SI reg, m64
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        fprintf(stderr, "GEN: CVTTSD2SI dst=%d, mem at ip=0x%llx (64bit=%d)\n",
                dst_type, (unsigned long long)state->orig_ip, is_64bit);
        GEN(is_64bit ? gadget_cvttsd2si_mem64 : gadget_cvttsd2si_mem32);
        GEN(state->orig_ip);
        // Store to destination register
        if (dst_type >= arg64_r8 && dst_type <= arg64_r15) {
          GEN(store64_r8_r15[dst_type - arg64_r8]);
        } else {
          GEN(is_64bit ? store64_gadgets[dst_type] : store32_gadgets[dst_type]);
        }
      }
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_STOSQ:
    // REP STOSQ - store RAX to [RDI], repeat RCX times
    // Check for REP prefix (handled implicitly by our gadget)
    GEN(gadget_rep_stosq);
    GEN(state->orig_ip); // For segfault handler
    break;

  case ZYDIS_MNEMONIC_STOSD:
    // REP STOSD - store EAX to [RDI], repeat RCX times
    GEN(gadget_rep_stosd);
    GEN(state->orig_ip); // For segfault handler
    break;

  case ZYDIS_MNEMONIC_STOSB:
    // REP STOSB - store AL to [RDI], repeat RCX times
    GEN(gadget_rep_stosb);
    GEN(state->orig_ip); // For segfault handler
    break;

  case ZYDIS_MNEMONIC_MOVSQ:
    // REP MOVSQ - move [RSI] to [RDI], repeat RCX times
    DEBUG_FPRINTF(stderr, "GEN: REP MOVSQ at ip=0x%llx\n",
            (unsigned long long)state->orig_ip);
    GEN(gadget_rep_movsq);
    GEN(state->orig_ip); // For segfault handler
    break;

  case ZYDIS_MNEMONIC_MOVSB:
    // MOVSB - move byte [RSI] to [RDI]
    // Check if REP prefix is present
    if (inst.has_rep) {
      // REP MOVSB - repeat RCX times
      DEBUG_FPRINTF(stderr, "GEN: REP MOVSB at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_rep_movsb);
      GEN(state->orig_ip); // For segfault handler
    } else {
      // Single MOVSB - copy exactly one byte
      DEBUG_FPRINTF(stderr, "GEN: single MOVSB at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_single_movsb);
    }
    break;

  case ZYDIS_MNEMONIC_MOVSD:
    // MOVSD has two completely different meanings:
    // 1. SSE: Move Scalar Double-Precision (uses XMM registers)
    // 2. String: Move String Dword (uses RSI/RDI implicitly)
    if (inst.operand_count >= 2 &&
        (is_xmm(inst.operands[0].type) || is_xmm(inst.operands[1].type))) {
      // SSE MOVSD - Move Scalar Double-Precision Floating-Point
      // movsd xmm1, xmm2/m64 or movsd xmm1/m64, xmm2
      if (is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // xmm to xmm: copy low 64 bits, preserve high 64 bits of dest
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: SSE MOVSD xmm%d, xmm%d at ip=0x%llx\n",
                dst_xmm, src_xmm, (unsigned long long)state->orig_ip);
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(src_xmm);
        GEN(gadget_movsd_xmm_xmm);
        GEN(dst_xmm);
      } else if (is_xmm(inst.operands[0].type)) {
        // xmm, m64: load scalar double from memory into XMM low 64 bits
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        fprintf(stderr, "GEN: SSE MOVSD xmm%d, mem at ip=0x%llx\n",
                dst_xmm, (unsigned long long)state->orig_ip);
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_movsd_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else {
        // m64, xmm: store scalar double from XMM low 64 bits to memory
        int src_xmm = get_xmm_index(inst.operands[1].type);
        fprintf(stderr, "GEN: SSE MOVSD mem, xmm%d at ip=0x%llx\n",
                src_xmm, (unsigned long long)state->orig_ip);
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_movsd_mem_xmm);
        GEN(src_xmm);
        GEN(state->orig_ip);
      }
    } else {
      // String MOVSD - REP MOVSD moves dwords from [RSI] to [RDI]
      DEBUG_FPRINTF(stderr, "GEN: REP MOVSD (string) at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_rep_movsd);
      GEN(state->orig_ip); // For segfault handler
    }
    break;

  case ZYDIS_MNEMONIC_SCASB:
    // SCASB - Compare AL with byte at [RDI]
    if (inst.has_repne) {
      // REPNE SCASB - scan for byte not equal to AL (used for strlen)
      DEBUG_FPRINTF(stderr, "GEN: REPNE SCASB at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_repne_scasb);
    } else if (inst.has_rep) {
      // REPE SCASB - scan for byte equal to AL
      DEBUG_FPRINTF(stderr, "GEN: REPE SCASB at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_repe_scasb);
    } else {
      // Single SCASB
      DEBUG_FPRINTF(stderr, "GEN: single SCASB at ip=0x%llx\n",
              (unsigned long long)state->orig_ip);
      GEN(gadget_single_scasb);
    }
    break;

  // ======================================================================
  // x87 FPU Instructions
  // ======================================================================

  case ZYDIS_MNEMONIC_FILD:
    // FILD m16/m32/m64 - Load Integer to FPU stack
    if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_16) {
        GEN(gadget_fpu_fild16);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fild32);
      } else {
        GEN(gadget_fpu_fild64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FISTP:
    // FISTP m16/m32/m64 - Store Integer and Pop
    if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_16) {
        GEN(gadget_fpu_fistp16);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fistp32);
      } else {
        GEN(gadget_fpu_fistp64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FLD:
    // FLD m32/m64/m80 or ST(i)
    if (inst.operand_count >= 1) {
      if (inst.operands[0].type == arg64_mem || inst.operands[0].type == arg64_rip_rel) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_fpu_fld32);
        } else if (inst.operands[0].size == size64_64) {
          GEN(gadget_fpu_fld64);
        } else {
          GEN(gadget_fpu_fld80);
        }
        GEN(state->orig_ip);
      } else if (inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
        int i = inst.operands[0].type - arg64_st0;
        GEN(gadget_fpu_fld_sti);
        GEN(i);
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

  case ZYDIS_MNEMONIC_FSTP:
    // FSTP m32/m64/m80 or ST(i)
    if (inst.operand_count >= 1) {
      if (inst.operands[0].type == arg64_mem) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_fpu_fstp32);
        } else if (inst.operands[0].size == size64_64) {
          GEN(gadget_fpu_fstp64);
        } else {
          GEN(gadget_fpu_fstp80);
        }
        GEN(state->orig_ip);
      } else if (inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
        int i = inst.operands[0].type - arg64_st0;
        GEN(gadget_fpu_fstp_sti);
        GEN(i);
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

  case ZYDIS_MNEMONIC_FADD:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fadd);
      GEN(i);
    } else if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fadd_m32);
      } else {
        GEN(gadget_fpu_fadd_m64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FADDP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_faddp);
      GEN(i);
    } else {
      // FADDP with no operands defaults to ST(1)
      GEN(gadget_fpu_faddp);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FSUB:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fsub);
      GEN(i);
    } else if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fsub_m32);
      } else {
        GEN(gadget_fpu_fsub_m64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FSUBP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_fsubp);
      GEN(i);
    } else {
      GEN(gadget_fpu_fsubp);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FSUBR:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fsubr);
      GEN(i);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FSUBRP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_fsubrp);
      GEN(i);
    } else {
      GEN(gadget_fpu_fsubrp);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FMUL:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fmul);
      GEN(i);
    } else if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fmul_m32);
      } else {
        GEN(gadget_fpu_fmul_m64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FMULP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_fmulp);
      GEN(i);
    } else {
      GEN(gadget_fpu_fmulp);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FDIV:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fdiv);
      GEN(i);
    } else if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fdiv_m32);
      } else {
        GEN(gadget_fpu_fdiv_m64);
      }
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FDIVP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_fdivp);
      GEN(i);
    } else {
      GEN(gadget_fpu_fdivp);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FXCH:
    if (inst.operand_count >= 1 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7) {
      int i = inst.operands[0].type - arg64_st0;
      GEN(gadget_fpu_fxch);
      GEN(i);
    } else {
      // FXCH with no operands defaults to ST(1)
      GEN(gadget_fpu_fxch);
      GEN(1);
    }
    break;

  case ZYDIS_MNEMONIC_FPREM:
    GEN(gadget_fpu_fprem);
    break;

  case ZYDIS_MNEMONIC_FSCALE:
    GEN(gadget_fpu_fscale);
    break;

  case ZYDIS_MNEMONIC_FRNDINT:
    GEN(gadget_fpu_frndint);
    break;

  case ZYDIS_MNEMONIC_FABS:
    GEN(gadget_fpu_fabs);
    break;

  case ZYDIS_MNEMONIC_FCHS:
    GEN(gadget_fpu_fchs);
    break;

  case ZYDIS_MNEMONIC_FINCSTP:
    GEN(gadget_fpu_fincstp);
    break;

  case ZYDIS_MNEMONIC_FLDZ:
    GEN(gadget_fpu_fldz);
    break;

  case ZYDIS_MNEMONIC_FLD1:
    GEN(gadget_fpu_fld1);
    break;

  case ZYDIS_MNEMONIC_FLDPI:
    GEN(gadget_fpu_fldpi);
    break;

  case ZYDIS_MNEMONIC_FLDL2E:
    GEN(gadget_fpu_fldl2e);
    break;

  case ZYDIS_MNEMONIC_FLDL2T:
    GEN(gadget_fpu_fldl2t);
    break;

  case ZYDIS_MNEMONIC_FLDLG2:
    GEN(gadget_fpu_fldlg2);
    break;

  case ZYDIS_MNEMONIC_FLDLN2:
    GEN(gadget_fpu_fldln2);
    break;

  case ZYDIS_MNEMONIC_FLDCW:
    if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(gadget_fpu_fldcw);
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FNSTCW:
    if (inst.operand_count >= 1 && inst.operands[0].type == arg64_mem) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(gadget_fpu_fnstcw);
      GEN(state->orig_ip);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FNSTSW:
    // FNSTSW AX
    GEN(gadget_fpu_fnstsw);
    break;

  case ZYDIS_MNEMONIC_FUCOMIP:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fucomip);
      GEN(i);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FUCOMI:
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fucomi);
      GEN(i);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_FCOMIP:
    // FCOMIP is same as FUCOMIP for our purposes (we don't handle FP exceptions differently)
    if (inst.operand_count >= 2 &&
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int i = inst.operands[1].type - arg64_st0;
      GEN(gadget_fpu_fucomip);
      GEN(i);
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
    fprintf(stderr,
            "UNHANDLED: ip=0x%llx mnemonic=%d bytes=%02x %02x %02x %02x\n",
            (unsigned long long)state->orig_ip, inst.mnemonic, code[0], code[1],
            code[2], code[3]);
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
