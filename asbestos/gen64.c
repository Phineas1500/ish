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
  case ZYDIS_MNEMONIC_BSWAP:
    return "BSWAP";
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
extern void gadget_debug_regs(void);
extern void gadget_cpuid(void);
extern void gadget_jmp(void);
extern void gadget_jmp_indir(void);
extern void gadget_call(void);
extern void gadget_call_indir(void);
extern void gadget_ret(void);
extern void gadget_push(void);
extern void gadget_pop(void);
extern void gadget_leave(void);
extern void gadget_seg_fs(void);
extern void gadget_seg_gs(void);

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
extern void gadget_sub32_x8(void);
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
extern void gadget_sbb64_mem(void);
extern void gadget_sbb32_mem(void);
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
extern void gadget_adc64_x8(void);
extern void gadget_adc32_x8(void);
extern void gadget_adc64_mem(void);
extern void gadget_adc32_mem(void);
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
extern void gadget_xor64_x8(void);
extern void gadget_xor32_x8(void);
extern void gadget_xor16_x8(void);
extern void gadget_xor8_x8(void);
extern gadget_t xor64_r8_r15_gadgets[];
extern gadget_t xor32_r8_r15_gadgets[];
extern void gadget_and64_imm(void);
extern void gadget_and64_x8(void);
extern void gadget_and32_x8(void);
extern void gadget_and64_mem(void);
extern void gadget_and64_a(void);
extern void gadget_and64_c(void);
extern void gadget_and64_d(void);
extern void gadget_and64_b(void);
extern void gadget_and64_sp(void);
extern void gadget_and64_bp(void);
extern void gadget_and64_si(void);
extern void gadget_and64_di(void);
extern void gadget_and32_a(void);
extern void gadget_and32_c(void);
extern void gadget_and32_d(void);
extern void gadget_and32_b(void);
extern void gadget_and32_sp(void);
extern void gadget_and32_bp(void);
extern void gadget_and32_si(void);
extern void gadget_and32_di(void);
extern void gadget_or64_imm(void);
extern void gadget_or32_imm(void);
extern void gadget_or64_x8(void);
extern void gadget_or32_x8(void);
extern void gadget_or64_mem(void);
extern void gadget_or32_mem(void);
extern void gadget_or64_a(void);
extern void gadget_or64_c(void);
extern void gadget_or64_d(void);
extern void gadget_or64_b(void);
extern void gadget_or64_sp(void);
extern void gadget_or64_bp(void);
extern void gadget_or64_si(void);
extern void gadget_or64_di(void);
extern void gadget_or32_a(void);
extern void gadget_or32_c(void);
extern void gadget_or32_d(void);
extern void gadget_or32_b(void);
extern void gadget_or32_sp(void);
extern void gadget_or32_bp(void);
extern void gadget_or32_si(void);
extern void gadget_or32_di(void);
extern void gadget_and32_imm(void);
extern void gadget_sign_extend8(void);
extern void gadget_sign_extend16(void);
extern void gadget_sign_extend32(void);
extern void gadget_cwde(void);
extern void gadget_zero_extend8(void);
extern void gadget_zero_extend16(void);
extern void gadget_zero_extend32(void);
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
extern void gadget_div8(void);
extern void gadget_div16(void);
extern void gadget_div32(void);
extern void gadget_div64(void);
extern void gadget_idiv8(void);
extern void gadget_idiv16(void);
extern void gadget_idiv32(void);
extern void gadget_idiv64(void);

// MUL gadgets (unsigned multiply: RDX:RAX = RAX * r/m)
extern void gadget_mul8(void);
extern void gadget_mul16(void);
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
extern void gadget_shr32_one(void);
extern void gadget_shr32_cl(void);
extern void gadget_shr32_imm(void);
extern void gadget_shl64_one(void);
extern void gadget_shl64_cl(void);
extern void gadget_shl64_imm(void);
extern void gadget_shl32_one(void);
extern void gadget_shl32_cl(void);
extern void gadget_shl32_imm(void);
extern void gadget_sar64_one(void);
extern void gadget_sar64_cl(void);
extern void gadget_sar64_imm(void);
extern void gadget_sar32_one(void);
extern void gadget_sar32_cl(void);
extern void gadget_sar32_imm(void);
extern void gadget_shl8_imm(void);
extern void gadget_shr8_imm(void);
extern void gadget_shl16_imm(void);
extern void gadget_shr16_imm(void);
extern void gadget_sar8_imm(void);
extern void gadget_sar16_imm(void);
extern void gadget_sar8_cl(void);
extern void gadget_sar16_cl(void);
extern void gadget_shr8_cl(void);
extern void gadget_shr16_cl(void);
extern void gadget_shl8_cl(void);
extern void gadget_shl16_cl(void);
extern void gadget_rol32_one(void);
extern void gadget_rol64_one(void);
extern void gadget_rol32_cl(void);
extern void gadget_rol64_cl(void);
extern void gadget_rol16_imm(void);
extern void gadget_rol32_imm(void);
extern void gadget_rol64_imm(void);
extern void gadget_ror32_one(void);
extern void gadget_ror64_one(void);
extern void gadget_ror32_cl(void);
extern void gadget_ror64_cl(void);
extern void gadget_ror16_imm(void);
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

// Byte swap
extern void gadget_bswap32(void);
extern void gadget_bswap64(void);
extern void gadget_bsf32(void);
extern void gadget_bsf64(void);
extern void gadget_bsr32(void);
extern void gadget_bsr64(void);
extern void gadget_popcnt32(void);
extern void gadget_popcnt64(void);
extern void gadget_tzcnt32(void);
extern void gadget_tzcnt64(void);
extern void gadget_lzcnt32(void);
extern void gadget_lzcnt64(void);

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
extern void gadget_neg16(void);
extern void gadget_neg8(void);

// XMM/SSE gadgets
extern void gadget_movq_to_xmm(void);
extern void gadget_movq_from_xmm(void);
extern void gadget_punpcklqdq(void);
extern void gadget_movaps_load(void);
extern void gadget_movaps_store(void);
extern void gadget_movaps_xmm_xmm(void);
extern void gadget_pxor_xmm(void);
extern void gadget_pxor_xmm_mem(void);

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
extern void gadget_movss_xmm_xmm(void);  // movss xmm, xmm
extern void gadget_movss_xmm_mem(void);  // movss xmm, m32
extern void gadget_movss_mem_xmm(void);  // movss m32, xmm
// SSE MOVHPS/MOVLPS - Move High/Low Packed Single-Precision
extern void gadget_movhlps(void);       // movhlps xmm, xmm
extern void gadget_movlhps(void);       // movlhps xmm, xmm
extern void gadget_movhps_load(void);   // movhps xmm, m64
extern void gadget_movhps_store(void);  // movhps m64, xmm
extern void gadget_movlps_load(void);   // movlps xmm, m64
extern void gadget_movlps_store(void);  // movlps m64, xmm
// SSE MOVD - Move Doubleword (32-bit) between GPR/memory and XMM
extern void gadget_movd_xmm_reg(void);   // movd xmm, r32
extern void gadget_movd_xmm_mem(void);   // movd xmm, m32
extern void gadget_movd_reg_xmm(void);   // movd r32, xmm
extern void gadget_movd_mem_xmm(void);   // movd m32, xmm
// SSE packed integer operations
extern void gadget_packuswb(void);
extern void gadget_packsswb(void);
extern void gadget_packssdw(void);
extern void gadget_punpcklbw(void);
extern void gadget_punpcklwd(void);
extern void gadget_punpckldq(void);
extern void gadget_punpckhbw(void);
extern void gadget_punpckhwd(void);
extern void gadget_punpckhdq(void);
extern void gadget_pcmpeqb(void);
extern void gadget_pcmpeqd(void);
extern void gadget_pcmpgtd(void);
extern void gadget_pand(void);
extern void gadget_paddd(void);
extern void gadget_paddq(void);
extern void gadget_psubq(void);
extern void gadget_psubd(void);
extern void gadget_orps(void);
extern void gadget_pshufd(void);
extern void gadget_shufps(void);
extern void gadget_punpckhqdq(void);
extern void gadget_por(void);
extern void gadget_pandn(void);
// Memory-form packed SSE2 gadgets
extern void gadget_pand_mem(void);
extern void gadget_pandn_mem(void);
extern void gadget_por_mem(void);
extern void gadget_orps_mem(void);
extern void gadget_paddd_mem(void);
extern void gadget_paddq_mem(void);
extern void gadget_psubq_mem(void);
extern void gadget_psubd_mem(void);
extern void gadget_pcmpeqb_mem(void);
extern void gadget_pcmpeqd_mem(void);
extern void gadget_pcmpgtd_mem(void);
extern void gadget_packuswb_mem(void);
extern void gadget_packsswb_mem(void);
extern void gadget_packssdw_mem(void);
extern void gadget_punpcklbw_mem(void);
extern void gadget_punpcklwd_mem(void);
extern void gadget_punpckldq_mem(void);
extern void gadget_punpckhbw_mem(void);
extern void gadget_punpckhwd_mem(void);
extern void gadget_punpckhdq_mem(void);
extern void gadget_punpckhqdq_mem(void);
extern void gadget_psrlw(void);
extern void gadget_psllw(void);
extern void gadget_psraw(void);
extern void gadget_psrad(void);
extern void gadget_psrld(void);
extern void gadget_pslld(void);
extern void gadget_palignr(void);
extern void gadget_pshufb(void);
extern void gadget_sha256rnds2(void);
extern void gadget_sha256msg1(void);
extern void gadget_sha256msg2(void);
extern void gadget_pmovmskb(void);
extern void gadget_psrlq(void);
extern void gadget_psllq(void);
extern void gadget_psrldq(void);
extern void gadget_pslldq(void);
// SSE CVTSI2SD - Convert Integer to Scalar Double
extern void gadget_cvtsi2sd_reg64(void); // cvtsi2sd xmm, r64
extern void gadget_cvtsi2sd_reg32(void); // cvtsi2sd xmm, r32
extern void gadget_cvtsi2sd_mem64(void); // cvtsi2sd xmm, m64
extern void gadget_cvtsi2sd_mem32(void); // cvtsi2sd xmm, m32
// SSE CVTSI2SS - Convert Integer to Scalar Single
extern void gadget_cvtsi2ss_reg64(void); // cvtsi2ss xmm, r64
extern void gadget_cvtsi2ss_reg32(void); // cvtsi2ss xmm, r32
extern void gadget_cvtsi2ss_mem64(void); // cvtsi2ss xmm, m64
extern void gadget_cvtsi2ss_mem32(void); // cvtsi2ss xmm, m32
// SSE Scalar Single-Precision Arithmetic
extern void gadget_addss_xmm_xmm(void);
extern void gadget_addss_xmm_mem(void);
extern void gadget_subss_xmm_xmm(void);
extern void gadget_subss_xmm_mem(void);
extern void gadget_mulss_xmm_xmm(void);
extern void gadget_mulss_xmm_mem(void);
extern void gadget_divss_xmm_xmm(void);
extern void gadget_divss_xmm_mem(void);
// SSE Scalar Single/Double Conversions
extern void gadget_cvtss2sd_xmm_xmm(void);
extern void gadget_cvtss2sd_xmm_mem(void);
extern void gadget_cvtsd2ss_xmm_xmm(void);
extern void gadget_cvtsd2ss_xmm_mem(void);
extern void gadget_cvttss2si_reg64(void);
extern void gadget_cvttss2si_reg32(void);
// SSE UCOMISS - Unordered Compare Scalar Single
extern void gadget_ucomiss_xmm_xmm(void);
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
// SSE DIVSD - Divide Scalar Double
extern void gadget_divsd_xmm_xmm(void);  // divsd xmm, xmm
extern void gadget_divsd_xmm_mem(void);  // divsd xmm, m64
extern void gadget_minsd_xmm_xmm(void);  // minsd xmm, xmm
extern void gadget_minsd_xmm_mem(void);  // minsd xmm, m64
extern void gadget_maxsd_xmm_xmm(void);  // maxsd xmm, xmm
extern void gadget_maxsd_xmm_mem(void);  // maxsd xmm, m64
// SSE CMPSD - Compare Scalar Double with predicate
extern void gadget_cmpsd_xmm_xmm(void);  // cmpsd xmm, xmm, imm8
extern void gadget_cmpsd_xmm_mem(void);  // cmpsd xmm, m64, imm8
// SSE SHUFPD - Shuffle Packed Double-Precision
extern void gadget_shufpd_xmm_xmm(void);  // shufpd xmm, xmm, imm8
extern void gadget_shufpd_xmm_mem(void);  // shufpd xmm, m128, imm8
// SSE SHUFPS - Shuffle Packed Single-Precision (memory form)
extern void gadget_shufps_xmm_mem(void);  // shufps xmm, m128, imm8
// SSE PSHUFLW/PSHUFHW - Shuffle Packed Words
extern void gadget_pshuflw(void);
extern void gadget_pshuflw_mem(void);
extern void gadget_pshufhw(void);
extern void gadget_pshufhw_mem(void);
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
static gadget_t or32_gadgets[] = {
    gadget_or32_a,  gadget_or32_c,  gadget_or32_d,  gadget_or32_b,
    gadget_or32_sp, gadget_or32_bp, gadget_or32_si, gadget_or32_di};
static gadget_t and64_gadgets[] = {
    gadget_and64_a,  gadget_and64_c,  gadget_and64_d,  gadget_and64_b,
    gadget_and64_sp, gadget_and64_bp, gadget_and64_si, gadget_and64_di};
static gadget_t and32_gadgets[] = {
    gadget_and32_a,  gadget_and32_c,  gadget_and32_d,  gadget_and32_b,
    gadget_and32_sp, gadget_and32_bp, gadget_and32_si, gadget_and32_di};
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
extern void gadget_merge16_x8(void);

// MOV merge gadgets for 8/16-bit partial register writes
extern void gadget_mov_merge8(void);
extern void gadget_mov_merge8h(void);
extern void gadget_mov_merge16(void);

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
extern void gadget_xchg_al_ah(void);

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
extern void gadget_fpu_fist16(void);
extern void gadget_fpu_fist32(void);
extern void gadget_fpu_fistp16(void);
extern void gadget_fpu_fistp32(void);
extern void gadget_fpu_fistp64(void);
extern void gadget_dec64(void);
extern void gadget_dec32(void);
extern void gadget_dec16(void);
extern void gadget_dec8(void);
extern void gadget_inc64(void);
extern void gadget_inc32(void);
extern void gadget_inc16(void);
extern void gadget_inc8(void);
extern void gadget_fpu_fld32(void);
extern void gadget_fpu_fld64(void);
extern void gadget_fpu_fld80(void);
extern void gadget_fpu_fld_sti(void);
extern void gadget_fpu_fstp32(void);
extern void gadget_fpu_fstp64(void);
extern void gadget_fpu_fstp80(void);
extern void gadget_fpu_fstp_sti(void);
extern void gadget_fpu_fadd(void);
extern void gadget_fpu_fadd_sti(void);
extern void gadget_fpu_faddp(void);
extern void gadget_breadcrumb(void);
extern void gadget_trace_xa(void);
extern void gadget_trace_regs(void);
extern void gadget_trace_rp(void);
extern void gadget_lea_shl64_imm(void);
extern void gadget_lea_add64_x8(void);
extern void gadget_lea_lsr64_imm(void);
extern void gadget_trace_xmm(void);
extern void gadget_fpu_fadd_m32(void);
extern void gadget_fpu_fadd_m64(void);
extern void gadget_fpu_fsub(void);
extern void gadget_fpu_fsub_sti(void);
extern void gadget_fpu_fsubp(void);
extern void gadget_fpu_fsubr(void);
extern void gadget_fpu_fsubr_sti(void);
extern void gadget_fpu_fsubrp(void);
extern void gadget_fpu_fsub_m32(void);
extern void gadget_fpu_fsub_m64(void);
extern void gadget_fpu_fmul(void);
extern void gadget_fpu_fmul_sti(void);
extern void gadget_fpu_fmulp(void);
extern void gadget_fpu_fmul_m32(void);
extern void gadget_fpu_fmul_m64(void);
extern void gadget_fpu_fdiv(void);
extern void gadget_fpu_fdiv_sti(void);
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

// Helper to store _xtmp to a register with proper 8/16-bit partial register
// semantics. For 8-bit and 16-bit operands, preserves upper bits of destination.
// For 32-bit operands, zero-extends to 64 bits. For 64-bit, stores directly.
// _xtmp must contain the computed result (low 8/16/32/64 bits).
// raw_operand_idx is the index into inst->raw_operands for high-byte detection.
static inline void gen_store_reg_partial(struct gen_state *state,
    struct decoded_inst64 *inst, int operand_idx) {
  enum size64 size = inst->operands[operand_idx].size;
  enum arg64 reg = inst->operands[operand_idx].type;

  // Only do the merge for non-bitwise instructions.
  // For OR/AND/XOR/NOT, the handler already loads the full register and
  // operates on it, so the result in _xtmp already has upper bits preserved.
  // EXCEPTION: for high-byte registers (AH/BH/CH/DH), the handler shifts
  // right by 8 first, so the result needs merge back into bits [15:8].
  // Also skip for instructions that have dedicated 8/16-bit gadgets which
  // already handle the merge (SHL/SHR/SAR 8/16-bit).
  bool do_merge = (size == size64_8 || size == size64_16);
  int mnem = inst->mnemonic;
  bool is_high_byte_dst = (size == size64_8 &&
      inst->raw_operands[operand_idx].type == ZYDIS_OPERAND_TYPE_REGISTER &&
      zydis_is_high_byte_reg(inst->raw_operands[operand_idx].reg.value));
  // Skip merge for bitwise ops on non-high-byte registers
  // (they already produce full-register results with upper bits preserved)
  // For high-byte destinations, merge IS needed since the handler shifts
  // right by 8, losing the upper bits.
  if (mnem == ZYDIS_MNEMONIC_OR || mnem == ZYDIS_MNEMONIC_AND ||
      mnem == ZYDIS_MNEMONIC_XOR || mnem == ZYDIS_MNEMONIC_NOT ||
      mnem == ZYDIS_MNEMONIC_BTS || mnem == ZYDIS_MNEMONIC_BTR ||
      mnem == ZYDIS_MNEMONIC_BTC) {
    if (!is_high_byte_dst)
      do_merge = false;
  }
  // Skip merge for shift instructions that have dedicated 8/16-bit gadgets
  if (mnem == ZYDIS_MNEMONIC_SHL || mnem == ZYDIS_MNEMONIC_SHR ||
      mnem == ZYDIS_MNEMONIC_SAR)
    do_merge = false;
  // Skip SETcc for now - merge breaks awk and libssl cipher registration
  if (mnem >= ZYDIS_MNEMONIC_SETB && mnem <= ZYDIS_MNEMONIC_SETZ)
    do_merge = false;

  if (do_merge) {
    // 8-bit/16-bit: preserve upper bits of destination register
    GEN(gadget_save_xtmp_to_x8); // x8 = computed result
    gadget_t load_dst = get_load64_reg_gadget(reg);
    if (load_dst)
      GEN(load_dst); // _xtmp = full destination register (upper bits to preserve)
    if (size == size64_8) {
      bool dst_high = zydis_is_high_byte_reg(
          inst->raw_operands[operand_idx].reg.value);
      GEN(dst_high ? gadget_mov_merge8h : gadget_mov_merge8);
    } else {
      GEN(gadget_mov_merge16);
    }
  }

  gadget_t store = get_store64_reg_gadget(reg);
  if (store)
    GEN(store);
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

    if (size_bits == 8 || size_bits == 16) {
      // x86-64: 8-bit and 16-bit MOV preserve upper bits of destination
      // Pattern: load src → (shift if high-byte src) → save to x8 → load dst → merge → store dst
      GEN(load_gadget);

      // If source is a high-byte register (AH/BH/CH/DH), shift right by 8
      bool src_high = (size_bits == 8 &&
          zydis_is_high_byte_reg(inst->raw_operands[1].reg.value));
      if (src_high) {
        GEN(gadget_lea_lsr64_imm);
        GEN(8);
      }

      GEN(gadget_save_xtmp_to_x8); // x8 = source value

      gadget_t load_dst = get_load64_reg_gadget(dst->type);
      if (!load_dst)
        return false;
      GEN(load_dst); // _xtmp = destination (upper bits to preserve)

      bool dst_high = (size_bits == 8 &&
          zydis_is_high_byte_reg(inst->raw_operands[0].reg.value));
      if (size_bits == 8) {
        GEN(dst_high ? gadget_mov_merge8h : gadget_mov_merge8);
      } else {
        GEN(gadget_mov_merge16);
      }

      gadget_t store_gadget = get_store64_reg_gadget(dst->type);
      if (!store_gadget)
        return false;
      GEN(store_gadget);
    } else {
      // 32-bit and 64-bit: simple load + mask + store
      GEN(load_gadget);
      if (size_bits == 32) {
        GEN(gadget_lea_and64_imm); // Flag-preserving zero-extend
        GEN(0xFFFFFFFF);
      }
      gadget_t store_gadget = get_store64_reg_gadget(dst->type);
      if (!store_gadget)
        return false;
      GEN(store_gadget);
    }

    return true;
  }

  // MOV reg, imm (any GPR including r8-r15)
  if (is_gpr(dst->type) && src->type == arg64_imm) {
    if (size_bits == 8 || size_bits == 16) {
      // 8/16-bit: preserve upper bits of destination
      GEN(load32_gadgets[8]); // load32_imm
      GEN(src->imm);
      GEN(gadget_save_xtmp_to_x8); // x8 = immediate value

      gadget_t load_dst = get_load64_reg_gadget(dst->type);
      if (!load_dst)
        return false;
      GEN(load_dst); // _xtmp = destination

      bool dst_high = (size_bits == 8 &&
          zydis_is_high_byte_reg(inst->raw_operands[0].reg.value));
      if (size_bits == 8) {
        GEN(dst_high ? gadget_mov_merge8h : gadget_mov_merge8);
      } else {
        GEN(gadget_mov_merge16);
      }

      gadget_t store_gadget = get_store64_reg_gadget(dst->type);
      if (!store_gadget)
        return false;
      GEN(store_gadget);
    } else {
      // 32/64-bit: simple load + store
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
    }

    return true;
  }

  // MOV reg, [mem] (any GPR including r8-r15)
  if (is_gpr(dst->type) && is_mem(src->type)) {
    if (!gen_addr(state, src, inst))
      return false;

    if (size_bits == 8 || size_bits == 16) {
      // 8/16-bit: preserve upper bits of destination
      if (size_bits == 16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      GEN(gadget_save_xtmp_to_x8); // x8 = memory value

      gadget_t load_dst = get_load64_reg_gadget(dst->type);
      if (!load_dst)
        return false;
      GEN(load_dst); // _xtmp = destination

      bool dst_high = (size_bits == 8 &&
          zydis_is_high_byte_reg(inst->raw_operands[0].reg.value));
      if (size_bits == 8) {
        GEN(dst_high ? gadget_mov_merge8h : gadget_mov_merge8);
      } else {
        GEN(gadget_mov_merge16);
      }

      gadget_t store_gadget = get_store64_reg_gadget(dst->type);
      if (!store_gadget)
        return false;
      GEN(store_gadget);
    } else {
      // 32/64-bit: simple load + store
      switch (size_bits) {
      case 64:
        GEN(load64_gadgets[9]); // load64_mem
        break;
      case 32:
        GEN(load32_gadgets[9]); // load32_mem
        break;
      }
      GEN(state->orig_ip);

      gadget_t store_gadget = get_store64_reg_gadget(dst->type);
      if (!store_gadget)
        return false;
      GEN(store_gadget);
    }

    return true;
  }

  // MOV [mem], reg (any GPR including r8-r15)
  if (is_mem(dst->type) && is_gpr(src->type)) {
    gadget_t load_gadget = get_load64_reg_gadget(src->type);
    if (!load_gadget)
      return false;
    GEN(load_gadget);

    // If source is a high-byte register (AH/BH/CH/DH), shift right 8
    // to put the high byte into bits [7:0] for the store gadget
    if (size_bits == 8 &&
        zydis_is_high_byte_reg(inst->raw_operands[1].reg.value)) {
      GEN(gadget_lea_lsr64_imm);
      GEN(8);
    }

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

  // Trace points (empty array = disabled, add IPs here when debugging)
  {
    static const uint64_t trace_ips[] = {
    };
    for (int i = 0; i < (int)(sizeof(trace_ips)/sizeof(trace_ips[0])); i++) {
      if (state->orig_ip == trace_ips[i]) {
        GEN(gadget_trace_regs);
        GEN(state->orig_ip);
        break;
      }
    }
  }

  // Generate code based on mnemonic
  switch (inst.mnemonic) {
  case ZYDIS_MNEMONIC_NOP:
  case ZYDIS_MNEMONIC_ENDBR64:
  case ZYDIS_MNEMONIC_PREFETCH:
  case ZYDIS_MNEMONIC_PREFETCHNTA:
  case ZYDIS_MNEMONIC_PREFETCHT0:
  case ZYDIS_MNEMONIC_PREFETCHT1:
  case ZYDIS_MNEMONIC_PREFETCHT2:
    // Cache hints - treat as NOP
    break;

  case ZYDIS_MNEMONIC_CLD:
    // Clear Direction Flag (DF=0, increment in string ops)
    GEN(gadget_cld);
    break;

  case ZYDIS_MNEMONIC_STD:
    // Set Direction Flag (DF=1, decrement in string ops)
    GEN(gadget_std);
    break;

  case ZYDIS_MNEMONIC_CPUID:
    GEN(gadget_cpuid);
    break;

  case ZYDIS_MNEMONIC_HLT:
    // HLT is used as a trap/crash instruction in musl libc (a]__crash)
    // Generate a GPF interrupt with segfault_addr=0 (unmapped) so the
    // GPF handler delivers SIGSEGV instead of retrying the instruction
    g(interrupt);
    GEN(INT_GPF);
    GEN(state->orig_ip);
    GEN(0);  // segfault_addr = 0 forces SIGSEGV delivery
    end_block = true;
    break;

  case ZYDIS_MNEMONIC_LEAVE:
    // LEAVE = mov rsp, rbp; pop rbp
    GEN(gadget_leave);
    GEN(state->orig_ip);
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
        gen_store_reg_partial(state, &inst, 0);
      } else if (is_gpr(inst.operands[1].type)) {
        // XOR reg, reg (different registers)
        if (inst.operands[0].size == size64_8 ||
            inst.operands[0].size == size64_16) {
          // 8/16-bit: use x8 pattern for correct flag setting
          gadget_t load_dst = get_load64_reg_gadget(inst.operands[0].type);
          if (load_dst) GEN(load_dst);
          GEN(gadget_save_xtmp_to_x8);
          gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
          if (load_src) GEN(load_src);
          GEN(inst.operands[0].size == size64_8 ? gadget_xor8_x8 : gadget_xor16_x8);
        } else {
          // 32/64-bit: use per-register gadgets
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
        }

        // Store result back to destination (preserving upper bits for 8/16-bit)
        gen_store_reg_partial(state, &inst, 0);
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
        gen_store_reg_partial(state, &inst, 0);
      } else if (inst.operands[1].type == arg64_mem ||
                 inst.operands[1].type == arg64_rip_rel) {
        // XOR reg, [mem] - load from memory and XOR
        gen_addr(state, &inst.operands[1], &inst);
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        // Save reg value to x8, load from mem to _xtmp, then XOR
        GEN(gadget_save_xtmp_to_x8);
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
        // XOR _xtmp (mem value) with x8 (reg value)
        switch (inst.operands[0].size) {
        case size64_8:
          GEN(gadget_xor8_x8);
          break;
        case size64_16:
          GEN(gadget_xor16_x8);
          break;
        case size64_32:
          GEN(gadget_xor32_x8);
          break;
        default:
          GEN(gadget_xor64_x8);
          break;
        }
        gen_store_reg_partial(state, &inst, 0);
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
      // Save guest address before load (load converts _addr to host address)
      GEN(gadget_save_addr);
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
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // XOR [mem], reg - read-modify-write
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
      // Save loaded memory value to x8, load source reg
      GEN(gadget_save_xtmp_to_x8);
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (load_src)
        GEN(load_src);
      // XOR: _xtmp (reg value) XOR x8 (mem value) → _xtmp
      GEN(gadget_xor64_x8);
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

  case ZYDIS_MNEMONIC_SYSCALL:
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
      gen_store_reg_partial(state, &inst, 0);
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

      gen_store_reg_partial(state, &inst, 0);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // ADD [mem], reg
      int add_mem_sz = inst.operands[0].size;
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
        // 2. Load from memory (size-appropriate)
        if (add_mem_sz == size64_64) {
          GEN(load64_gadgets[9]);
        } else if (add_mem_sz == size64_32) {
          GEN(load32_gadgets[9]);
        } else if (add_mem_sz == size64_16) {
          GEN(gadget_load16_mem);
        } else {
          GEN(gadget_load8_mem);
        }
        GEN(state->orig_ip);
        // 3. Add source register
        if (add_mem_sz == size64_64) {
          GEN(add64_gadgets[inst.operands[1].type - arg64_rax]);
        } else {
          GEN(add32_gadgets[inst.operands[1].type - arg64_rax]);
        }
        // 4. Recalculate address and store (size-appropriate)
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (add_mem_sz == size64_64) {
          GEN(store64_gadgets[9]);
        } else if (add_mem_sz == size64_32) {
          GEN(store32_gadgets[9]);
        } else if (add_mem_sz == size64_16) {
          GEN(gadget_store16_mem);
        } else {
          GEN(gadget_store8_mem);
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
        // 2. Load from memory (size-appropriate)
        if (add_mem_sz == size64_64) {
          GEN(load64_gadgets[9]);
        } else if (add_mem_sz == size64_32) {
          GEN(load32_gadgets[9]);
        } else if (add_mem_sz == size64_16) {
          GEN(gadget_load16_mem);
        } else {
          GEN(gadget_load8_mem);
        }
        GEN(state->orig_ip);
        // 3. Add x8 (source): _xtmp = _xtmp + x8 = mem + src
        if (add_mem_sz == size64_64) {
          GEN(gadget_add64_x8);
        } else {
          GEN(gadget_add32_x8);
        }
        // 4. Recalculate address and store (size-appropriate)
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (add_mem_sz == size64_64) {
          GEN(store64_gadgets[9]);
        } else if (add_mem_sz == size64_32) {
          GEN(store32_gadgets[9]);
        } else if (add_mem_sz == size64_16) {
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
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // ADD [mem], imm (including RIP-relative) - read-modify-write
      int add_imm_sz = inst.operands[0].size;
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Save address, load, add, restore address, store
      GEN(gadget_save_addr);
      if (add_imm_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (add_imm_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (add_imm_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      if (add_imm_sz == size64_64) {
        GEN(gadget_add64_imm);
      } else {
        GEN(gadget_add32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (add_imm_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (add_imm_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (add_imm_sz == size64_16) {
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
      } else if (inst.operands[1].type >= arg64_r8 &&
                 inst.operands[1].type <= arg64_r15) {
        // ADC reg, r8-r15 (need to load r8-r15 from memory first)
        // Save dst to x8
        GEN(gadget_save_xtmp_to_x8);
        // Load r8-r15 into _xtmp
        gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
        if (load_src)
          GEN(load_src);
        // x8 = dst, _xtmp = src
        // adc_x8 does: _xtmp = _xtmp + x8 + CF = src + dst + CF (commutative, so correct!)
        if (is64) {
          GEN(gadget_adc64_x8);
        } else {
          GEN(gadget_adc32_x8);
        }
      } else if (is_mem(inst.operands[1].type)) {
        // ADC reg, [mem]
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(gadget_adc64_mem);
        } else {
          GEN(gadget_adc32_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // ADC [mem], imm - read-modify-write
      int adc_imm_sz = inst.operands[0].size;
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      GEN(gadget_save_addr);
      if (adc_imm_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (adc_imm_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (adc_imm_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      if (adc_imm_sz == size64_64) {
        GEN(gadget_adc64_imm);
      } else {
        GEN(gadget_adc32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (adc_imm_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (adc_imm_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (adc_imm_sz == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
      }
      GEN(state->orig_ip);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // ADC [mem], reg - read-modify-write
      int adc_reg_sz = inst.operands[0].size;
      // 1. Load source register, save to x8
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_src) { g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0; }
      GEN(load_src);
      GEN(gadget_save_xtmp_to_x8);
      // 2. Calculate address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      GEN(gadget_save_addr);
      // 3. Size-appropriate load from [mem]
      if (adc_reg_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (adc_reg_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (adc_reg_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // 4. ADC: _xtmp = _xtmp + x8 + CF = [mem] + reg + CF (commutative)
      if (adc_reg_sz == size64_64) {
        GEN(gadget_adc64_x8);
      } else {
        GEN(gadget_adc32_x8);
      }
      // 5. Restore address and store
      GEN(gadget_restore_addr);
      if (adc_reg_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (adc_reg_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (adc_reg_sz == size64_16) {
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
      } else if (is_mem(inst.operands[1].type)) {
        // SBB reg, [mem]
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (is64) {
          GEN(gadget_sbb64_mem);
        } else {
          GEN(gadget_sbb32_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // SBB [mem], imm - read-modify-write
      int sbb_imm_sz = inst.operands[0].size;
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      GEN(gadget_save_addr);
      if (sbb_imm_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (sbb_imm_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (sbb_imm_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      if (sbb_imm_sz == size64_64) {
        GEN(gadget_sbb64_imm);
      } else {
        GEN(gadget_sbb32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (sbb_imm_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (sbb_imm_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (sbb_imm_sz == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
      }
      GEN(state->orig_ip);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // SBB [mem], reg - read-modify-write
      int sbb_reg_sz = inst.operands[0].size;
      // 1. Load source register, save to x8
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_src) { g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0; }
      GEN(load_src);
      GEN(gadget_save_xtmp_to_x8);
      // 2. Calculate address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      GEN(gadget_save_addr);
      // 3. Size-appropriate load from [mem]
      if (sbb_reg_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (sbb_reg_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (sbb_reg_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // 4. SBB: _xtmp = _xtmp - x8 - CF = [mem] - reg - CF (sbb_x8 does _xtmp - x8 - CF)
      if (sbb_reg_sz == size64_64) {
        GEN(gadget_sbb64_x8);
      } else {
        GEN(gadget_sbb32_x8);
      }
      // 5. Restore address and store
      GEN(gadget_restore_addr);
      if (sbb_reg_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (sbb_reg_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (sbb_reg_sz == size64_16) {
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
        // sub_x8 does: _xtmp = x8 - _xtmp = dst - src. Correct!
        if (is64) {
          GEN(gadget_sub64_x8);
        } else {
          GEN(gadget_sub32_x8);
        }
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

      gen_store_reg_partial(state, &inst, 0);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               inst.operands[1].type == arg64_imm) {
      // SUB [mem], imm - read-modify-write
      int sub_imm_sz = inst.operands[0].size;
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Save address, load, subtract, restore address, store
      GEN(gadget_save_addr);
      if (sub_imm_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (sub_imm_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (sub_imm_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      if (sub_imm_sz == size64_64) {
        GEN(gadget_sub64_imm);
      } else {
        GEN(gadget_sub32_imm);
      }
      GEN(inst.operands[1].imm);
      GEN(gadget_restore_addr);
      if (sub_imm_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (sub_imm_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (sub_imm_sz == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
      }
      GEN(state->orig_ip);
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type) &&
               is_gpr(inst.operands[1].type)) {
      // SUB [mem], reg (any register source including r8-r15)
      int sub_reg_sz = inst.operands[0].size;
      // 1. Load source register value, save to x8
      gadget_t load_src = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_src) { GEN(gadget_interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0; }
      GEN(load_src);
      GEN(gadget_save_xtmp_to_x8);
      // 2. Calculate address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(gadget_save_addr);
      // 3. Load from memory (size-appropriate)
      if (sub_reg_sz == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (sub_reg_sz == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (sub_reg_sz == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // 4. Subtract: _xtmp = _xtmp - x8 = [mem] - reg  (sub64_x8 does x8 - _xtmp, so swap first)
      GEN(gadget_swap_xtmp_x8);
      if (sub_reg_sz == size64_64) {
        GEN(gadget_sub64_x8);
      } else {
        GEN(gadget_sub32_x8);
      }
      // 5. Restore address and store (size-appropriate)
      GEN(gadget_restore_addr);
      if (sub_reg_sz == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (sub_reg_sz == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (sub_reg_sz == size64_16) {
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

  case ZYDIS_MNEMONIC_CDQE:
    // Sign-extend eax to rax (48 98)
    GEN(load64_gadgets[0]); // load64_a (load rax)
    GEN(gadget_sign_extend32);
    GEN(store64_gadgets[0]); // store64_a
    break;

  case ZYDIS_MNEMONIC_CWDE:
    // Sign-extend ax to eax (98 without REX.W)
    GEN(load64_gadgets[0]); // load rax
    GEN(gadget_cwde);
    GEN(store64_gadgets[0]); // store rax (zero-extended to 64 bits)
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

      // Handle high-byte registers (AH, BH, CH, DH)
      if (inst.operands[0].size == size64_8 &&
          inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
        GEN(gadget_lea_lsr64_imm);
        GEN(8);
      }

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

      // Handle high-byte registers (AH, BH, CH, DH)
      // Need to shift right by 8 to get the high byte into bits 7:0
      if (inst.operands[0].size == size64_8 &&
          inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
        GEN(gadget_lea_lsr64_imm);
        GEN(8);
      }

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
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      // Handle high-byte register destination (AH, BH, CH, DH)
      // Must shift right by 8 to operate on the correct byte
      if (inst.operands[0].size == size64_8 &&
          inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
        GEN(gadget_lea_lsr64_imm);
        GEN(8);
      }

      if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_and32_imm);
        } else {
          GEN(gadget_and64_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (is_gpr(inst.operands[1].type)) {
        int reg_idx = inst.operands[1].type - arg64_rax;
        if (reg_idx >= 0 && reg_idx < 8) {
          if (inst.operands[0].size == size64_32) {
            GEN(and32_gadgets[reg_idx]);
          } else {
            GEN(and64_gadgets[reg_idx]);
          }
        } else {
          // r8-r15: load to x8, use and_x8
          gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
          if (load2) {
            GEN(gadget_save_xtmp_to_x8);
            GEN(load2);
            if (inst.operands[0].size == size64_32) {
              GEN(gadget_and32_x8);
            } else {
              GEN(gadget_and64_x8);
            }
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
        if (inst.operands[1].size == size64_32) {
          GEN(load32_gadgets[9]);
        } else {
          GEN(load64_gadgets[9]);
        }
        GEN(state->orig_ip);
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_and32_x8);
        } else {
          GEN(gadget_and64_x8);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
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
      int and_mem_size = inst.operands[0].size;
      // Save address, load, modify, restore address, store
      GEN(gadget_save_addr); // Save guest address
      if (and_mem_size == size64_64) {
        GEN(load64_gadgets[9]); // load64_mem
      } else if (and_mem_size == size64_32) {
        GEN(load32_gadgets[9]); // load32_mem
      } else if (and_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // AND with immediate
      if (and_mem_size == size64_64) {
        GEN(gadget_and64_imm);
      } else {
        GEN(gadget_and32_imm);
      }
      GEN(inst.operands[1].imm);
      // Restore address and store
      GEN(gadget_restore_addr);
      if (and_mem_size == size64_64) {
        GEN(store64_gadgets[9]); // store64_mem
      } else if (and_mem_size == size64_32) {
        GEN(store32_gadgets[9]); // store32_mem
      } else if (and_mem_size == size64_16) {
        GEN(gadget_store16_mem);
      } else {
        GEN(gadget_store8_mem);
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
              // High-byte register: extract AH to low byte first, then OR
              // with unshifted immediate. gen_store_reg_partial merge8h
              // will put the result back into bits [15:8].
              // DON'T shift the immediate - let the merge handle placement.
              GEN(gadget_lea_lsr64_imm);
              GEN(8);
            }
          }
          if (inst.operands[0].size == size64_32) {
            GEN(gadget_or32_imm);
          } else {
            GEN(gadget_or64_imm);
          }
          GEN(imm);
        } else if (is_gpr(inst.operands[1].type)) {
          int reg_idx = inst.operands[1].type - arg64_rax;
          if (reg_idx >= 0 && reg_idx < 8) {
            if (inst.operands[0].size == size64_32) {
              GEN(or32_gadgets[reg_idx]);
            } else {
              GEN(or64_gadgets[reg_idx]);
            }
          } else {
            // r8-r15: load to x8, use or_x8
            gadget_t load2 = get_load64_reg_gadget(inst.operands[1].type);
            if (load2) {
              GEN(gadget_save_xtmp_to_x8);
              GEN(load2);
              if (inst.operands[0].size == size64_32) {
                GEN(gadget_or32_x8);
              } else {
                GEN(gadget_or64_x8);
              }
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
          if (inst.operands[0].size == size64_32) {
            GEN(gadget_or32_x8);
          } else {
            GEN(gadget_or64_x8);
          }
        } else {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }

        gen_store_reg_partial(state, &inst, 0);
      } else if (is_mem(inst.operands[0].type)) {
        if (is_gpr(inst.operands[1].type)) {
          // OR [mem], reg - read-modify-write
          // Must use separate load+or+store to go through write_prep for CoW
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
          int or_reg_mem_size = inst.operands[0].size;
          // Save address, load from memory
          GEN(gadget_save_addr);
          if (or_reg_mem_size == size64_64) {
            GEN(load64_gadgets[9]); // load64_mem
          } else if (or_reg_mem_size == size64_32) {
            GEN(load32_gadgets[9]); // load32_mem
          } else if (or_reg_mem_size == size64_16) {
            GEN(gadget_load16_mem);
          } else {
            GEN(gadget_load8_mem);
          }
          GEN(state->orig_ip);
          // OR with x8 (source register value)
          GEN(gadget_or64_x8);
          // Restore address and store
          GEN(gadget_restore_addr);
          if (or_reg_mem_size == size64_64) {
            GEN(store64_gadgets[9]); // store64_mem
          } else if (or_reg_mem_size == size64_32) {
            GEN(store32_gadgets[9]); // store32_mem
          } else if (or_reg_mem_size == size64_16) {
            GEN(gadget_store16_mem);
          } else {
            GEN(gadget_store8_mem);
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
          int or_mem_size = inst.operands[0].size;
          // Save address, load, modify, restore address, store
          GEN(gadget_save_addr); // Save guest address
          if (or_mem_size == size64_64) {
            GEN(load64_gadgets[9]); // load64_mem
          } else if (or_mem_size == size64_32) {
            GEN(load32_gadgets[9]); // load32_mem
          } else if (or_mem_size == size64_16) {
            GEN(gadget_load16_mem);
          } else {
            GEN(gadget_load8_mem);
          }
          GEN(state->orig_ip);
          // OR with immediate
          GEN(gadget_or64_imm);
          GEN(inst.operands[1].imm);
          // Restore address and store
          GEN(gadget_restore_addr);
          if (or_mem_size == size64_64) {
            GEN(store64_gadgets[9]); // store64_mem
          } else if (or_mem_size == size64_32) {
            GEN(store32_gadgets[9]); // store32_mem
          } else if (or_mem_size == size64_16) {
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

      int shr_size = inst.operands[0].size;

      if (inst.operand_count == 1) {
        if (shr_size == size64_8) {
          GEN(gadget_shr8_imm); GEN(1);
        } else if (shr_size == size64_16) {
          GEN(gadget_shr16_imm); GEN(1);
        } else {
          GEN(shr_size == size64_32 ? gadget_shr32_one : gadget_shr64_one);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        if (shr_size == size64_8) {
          GEN(gadget_shr8_imm); GEN(inst.operands[1].imm);
        } else if (shr_size == size64_16) {
          GEN(gadget_shr16_imm); GEN(inst.operands[1].imm);
        } else if (inst.operands[1].imm == 1) {
          GEN(shr_size == size64_32 ? gadget_shr32_one : gadget_shr64_one);
        } else {
          GEN(shr_size == size64_32 ? gadget_shr32_imm : gadget_shr64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        if (shr_size == size64_8) {
          GEN(gadget_shr8_cl);
        } else if (shr_size == size64_16) {
          GEN(gadget_shr16_cl);
        } else {
          GEN(shr_size == size64_32 ? gadget_shr32_cl : gadget_shr64_cl);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      // SHR [mem], imm/1/CL - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int shr_mem_size = inst.operands[0].size;
      GEN(gadget_save_addr);
      if (shr_mem_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (shr_mem_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (shr_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);

      bool shr_mem_is32 = (shr_mem_size == size64_32);
      if (inst.operand_count == 1) {
        GEN(shr_mem_is32 ? gadget_shr32_one : gadget_shr64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[1].imm == 1) {
          GEN(shr_mem_is32 ? gadget_shr32_one : gadget_shr64_one);
        } else {
          GEN(shr_mem_is32 ? gadget_shr32_imm : gadget_shr64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(shr_mem_is32 ? gadget_shr32_cl : gadget_shr64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      GEN(gadget_restore_addr);
      if (shr_mem_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (shr_mem_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (shr_mem_size == size64_16) {
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

  case ZYDIS_MNEMONIC_SHL:
    // Logical shift left
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      int shl_size = inst.operands[0].size;

      if (inst.operand_count == 1) {
        // SHL by 1: use _one for 32/64, _imm with 1 for 8/16
        if (shl_size == size64_8) {
          GEN(gadget_shl8_imm); GEN(1);
        } else if (shl_size == size64_16) {
          GEN(gadget_shl16_imm); GEN(1);
        } else {
          GEN(shl_size == size64_32 ? gadget_shl32_one : gadget_shl64_one);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        if (shl_size == size64_8) {
          GEN(gadget_shl8_imm); GEN(inst.operands[1].imm);
        } else if (shl_size == size64_16) {
          GEN(gadget_shl16_imm); GEN(inst.operands[1].imm);
        } else if (inst.operands[1].imm == 1) {
          GEN(shl_size == size64_32 ? gadget_shl32_one : gadget_shl64_one);
        } else {
          GEN(shl_size == size64_32 ? gadget_shl32_imm : gadget_shl64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        if (shl_size == size64_8) {
          GEN(gadget_shl8_cl);
        } else if (shl_size == size64_16) {
          GEN(gadget_shl16_cl);
        } else {
          GEN(shl_size == size64_32 ? gadget_shl32_cl : gadget_shl64_cl);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      // SHL [mem], imm/1/CL - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int shl_mem_size = inst.operands[0].size;
      bool shl_mem_is32 = (shl_mem_size == size64_32);
      GEN(gadget_save_addr);
      if (shl_mem_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (shl_mem_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (shl_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);

      if (inst.operand_count == 1) {
        GEN(shl_mem_is32 ? gadget_shl32_one : gadget_shl64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[1].imm == 1) {
          GEN(shl_mem_is32 ? gadget_shl32_one : gadget_shl64_one);
        } else {
          GEN(shl_mem_is32 ? gadget_shl32_imm : gadget_shl64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(shl_mem_is32 ? gadget_shl32_cl : gadget_shl64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      GEN(gadget_restore_addr);
      if (shl_mem_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (shl_mem_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (shl_mem_size == size64_16) {
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

  case ZYDIS_MNEMONIC_SAR:
    // Arithmetic shift right
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      int sar_size = inst.operands[0].size;
      bool sar_is32 = (sar_size == size64_32);

      if (inst.operand_count == 1) {
        if (sar_size == size64_8) {
          GEN(gadget_sar8_imm); GEN(1);
        } else if (sar_size == size64_16) {
          GEN(gadget_sar16_imm); GEN(1);
        } else {
          GEN(sar_is32 ? gadget_sar32_one : gadget_sar64_one);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        if (sar_size == size64_8) {
          GEN(gadget_sar8_imm); GEN(inst.operands[1].imm);
        } else if (sar_size == size64_16) {
          GEN(gadget_sar16_imm); GEN(inst.operands[1].imm);
        } else if (inst.operands[1].imm == 1) {
          GEN(sar_is32 ? gadget_sar32_one : gadget_sar64_one);
        } else {
          GEN(sar_is32 ? gadget_sar32_imm : gadget_sar64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        if (sar_size == size64_8) {
          GEN(gadget_sar8_cl);
        } else if (sar_size == size64_16) {
          GEN(gadget_sar16_cl);
        } else {
          GEN(sar_is32 ? gadget_sar32_cl : gadget_sar64_cl);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      // SAR [mem], imm/1/CL - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int sar_mem_size = inst.operands[0].size;
      bool sar_mem_is32 = (sar_mem_size == size64_32);
      GEN(gadget_save_addr);
      if (sar_mem_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (sar_mem_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (sar_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);

      // Sign-extend for SAR with 16/8-bit operands using 64-bit shift
      // (32-bit uses sar32 gadgets which handle sign bit at bit 31 natively)
      if (sar_mem_size == size64_16) {
        GEN(gadget_sign_extend16);
      } else if (sar_mem_size == size64_8) {
        GEN(gadget_sign_extend8);
      }

      if (inst.operand_count == 1) {
        GEN(sar_mem_is32 ? gadget_sar32_one : gadget_sar64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (inst.operands[1].imm == 1) {
          GEN(sar_mem_is32 ? gadget_sar32_one : gadget_sar64_one);
        } else {
          GEN(sar_mem_is32 ? gadget_sar32_imm : gadget_sar64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(sar_mem_is32 ? gadget_sar32_cl : gadget_sar64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      GEN(gadget_restore_addr);
      if (sar_mem_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (sar_mem_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (sar_mem_size == size64_16) {
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

  case ZYDIS_MNEMONIC_ROL:
    // Rotate left
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      int rol_size = inst.operands[0].size;

      if (inst.operand_count == 1) {
        // Implicit 1 (opcode d1) - rotate by 1
        if (rol_size == size64_16) {
          GEN(gadget_rol16_imm);
          GEN(1);
        } else {
          GEN(rol_size == size64_32 ? gadget_rol32_one : gadget_rol64_one);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        if (rol_size == size64_16) {
          GEN(gadget_rol16_imm);
          GEN(inst.operands[1].imm);
        } else if (inst.operands[1].imm == 1) {
          GEN(rol_size == size64_32 ? gadget_rol32_one : gadget_rol64_one);
        } else {
          GEN(rol_size == size64_32 ? gadget_rol32_imm : gadget_rol64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(rol_size == size64_32 ? gadget_rol32_cl : gadget_rol64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      // ROL [mem], imm/1/cl - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      int rol_mem_size = inst.operands[0].size;
      GEN(gadget_save_addr);
      if (rol_mem_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (rol_mem_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (rol_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // Apply rotate
      if (inst.operand_count == 1 || (inst.operands[1].type == arg64_imm && inst.operands[1].imm == 1)) {
        GEN(rol_mem_size == size64_32 ? gadget_rol32_one : gadget_rol64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (rol_mem_size == size64_16) {
          GEN(gadget_rol16_imm);
        } else {
          GEN(rol_mem_size == size64_32 ? gadget_rol32_imm : gadget_rol64_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(rol_mem_size == size64_32 ? gadget_rol32_cl : gadget_rol64_cl);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      // Store back
      GEN(gadget_restore_addr);
      if (rol_mem_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (rol_mem_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (rol_mem_size == size64_16) {
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

  case ZYDIS_MNEMONIC_ROR:
    // Rotate right
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      int ror_size = inst.operands[0].size;

      if (inst.operand_count == 1) {
        // Implicit 1 - rotate by 1
        if (ror_size == size64_16) {
          GEN(gadget_ror16_imm);
          GEN(1);
        } else {
          GEN(ror_size == size64_32 ? gadget_ror32_one : gadget_ror64_one);
        }
      } else if (inst.operands[1].type == arg64_imm) {
        if (ror_size == size64_16) {
          GEN(gadget_ror16_imm);
          GEN(inst.operands[1].imm);
        } else if (inst.operands[1].imm == 1) {
          GEN(ror_size == size64_32 ? gadget_ror32_one : gadget_ror64_one);
        } else {
          GEN(ror_size == size64_32 ? gadget_ror32_imm : gadget_ror64_imm);
          GEN(inst.operands[1].imm);
        }
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(ror_size == size64_32 ? gadget_ror32_cl : gadget_ror64_cl);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      // ROR [mem], imm/1/cl - read-modify-write
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      int ror_mem_size = inst.operands[0].size;
      GEN(gadget_save_addr);
      if (ror_mem_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (ror_mem_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (ror_mem_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // Apply rotate
      if (inst.operand_count == 1 || (inst.operands[1].type == arg64_imm && inst.operands[1].imm == 1)) {
        GEN(ror_mem_size == size64_32 ? gadget_ror32_one : gadget_ror64_one);
      } else if (inst.operands[1].type == arg64_imm) {
        if (ror_mem_size == size64_16) {
          GEN(gadget_ror16_imm);
        } else {
          GEN(ror_mem_size == size64_32 ? gadget_ror32_imm : gadget_ror64_imm);
        }
        GEN(inst.operands[1].imm);
      } else if (inst.operands[1].type == arg64_rcx) {
        GEN(ror_mem_size == size64_32 ? gadget_ror32_cl : gadget_ror64_cl);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
      // Store back
      GEN(gadget_restore_addr);
      if (ror_mem_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (ror_mem_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (ror_mem_size == size64_16) {
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

      gen_store_reg_partial(state, &inst, 0);
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

      gen_store_reg_partial(state, &inst, 0);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_BSWAP:
    // BSWAP reg - byte swap (reverse byte order)
    if (inst.operand_count >= 1 && is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);

      if (inst.operands[0].size == size64_64) {
        GEN(gadget_bswap64);
      } else {
        GEN(gadget_bswap32);
      }

      gen_store_reg_partial(state, &inst, 0);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_TZCNT:
    // TZCNT dst, src - Count Trailing Zeros (BMI1)
    // Different flag semantics from BSF: ZF = (result==0), CF = (source==0)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        if (inst.operands[0].size == size64_64) {
          GEN(load64_gadgets[9]);
        } else if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]);
        } else {
          GEN(gadget_load16_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_tzcnt32 : gadget_tzcnt64);

      gen_store_reg_partial(state, &inst, 0);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_LZCNT:
    // LZCNT dst, src - Count Leading Zeros (ABM/BMI1)
    // ZF = (result==0), CF = (source==0)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        if (inst.operands[0].size == size64_64) {
          GEN(load64_gadgets[9]);
        } else if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]);
        } else {
          GEN(gadget_load16_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_lzcnt32 : gadget_lzcnt64);

      gen_store_reg_partial(state, &inst, 0);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_BSF:
    // BSF dst, src - Bit Scan Forward (find lowest set bit)
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        if (inst.operands[0].size == size64_64) {
          GEN(load64_gadgets[9]); // load64_mem
        } else if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(gadget_load16_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_bsf32 : gadget_bsf64);

      gen_store_reg_partial(state, &inst, 0);
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
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load)
          GEN(load);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        if (inst.operands[0].size == size64_64) {
          GEN(load64_gadgets[9]); // load64_mem
        } else if (inst.operands[0].size == size64_32) {
          GEN(load32_gadgets[9]); // load32_mem
        } else {
          GEN(gadget_load16_mem);
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_bsr32 : gadget_bsr64);

      gen_store_reg_partial(state, &inst, 0);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_POPCNT:
    // POPCNT dst, src - Population count
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type)) {
      enum size64 src_size = inst.operands[1].size;
      if (is_gpr(inst.operands[1].type)) {
        // Source is register
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (!load) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(load);

        if (src_size == size64_16) {
          // Narrow register reads to 16-bit for 16-bit POPCNT.
          GEN(gadget_lea_and64_imm);
          GEN(0xffff);
        } else if (src_size == size64_8) {
          // Narrow 8-bit register reads to 8 bits, including high-byte regs.
          if (inst.raw_operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
              zydis_is_high_byte_reg(inst.raw_operands[1].reg.value)) {
            GEN(gadget_lea_lsr64_imm);
            GEN(8);
          }
          GEN(gadget_lea_and64_imm);
          GEN(0xff);
        }
      } else if (is_mem(inst.operands[1].type)) {
        // Source is memory
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (src_size == size64_64) {
          GEN(load64_gadgets[9]);
        } else if (src_size == size64_32) {
          GEN(load32_gadgets[9]);
        } else if (src_size == size64_16) {
          GEN(gadget_load16_mem);
        } else if (src_size == size64_8) {
          GEN(gadget_load8_mem);
        } else {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(state->orig_ip);
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }

      bool is_32bit = (inst.operands[0].size == size64_32);
      GEN(is_32bit ? gadget_popcnt32 : gadget_popcnt64);
      gen_store_reg_partial(state, &inst, 0);
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
        GEN(load64_gadgets[8]); // load64_imm
        GEN(effective_addr);
        gen_store_reg_partial(state, &inst, 0);
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
        gen_store_reg_partial(state, &inst, 0);
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

        gen_store_reg_partial(state, &inst, 0);
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

        gen_store_reg_partial(state, &inst, 0);
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

        gen_store_reg_partial(state, &inst, 0);
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

        gen_store_reg_partial(state, &inst, 0);
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
            // Scale it (LEA does NOT modify flags - use flag-preserving shift)
            if (inst.operands[1].mem.scale == 2) {
              GEN(gadget_lea_shl64_imm);
              GEN(1);
            } else if (inst.operands[1].mem.scale == 4) {
              GEN(gadget_lea_shl64_imm);
              GEN(2);
            } else if (inst.operands[1].mem.scale == 8) {
              GEN(gadget_lea_shl64_imm);
              GEN(3);
            }
            // Add scaled index to base+disp (x8) - flag-preserving
            GEN(gadget_lea_add64_x8);
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
            // Scale it (LEA does NOT modify flags - use flag-preserving shift)
            if (inst.operands[1].mem.scale == 2) {
              GEN(gadget_lea_shl64_imm);
              GEN(1);
            } else if (inst.operands[1].mem.scale == 4) {
              GEN(gadget_lea_shl64_imm);
              GEN(2);
            } else if (inst.operands[1].mem.scale == 8) {
              GEN(gadget_lea_shl64_imm);
              GEN(3);
            }
            // Add scaled index to base+disp (x8) - flag-preserving
            GEN(gadget_lea_add64_x8);
          }
        }

        // For 32-bit LEA (leal), truncate to 32 bits (zero-extend)
        // LEA does NOT modify flags, use flag-preserving and
        if (inst.operands[0].size == size64_32) {
          GEN(gadget_lea_and64_imm);
          GEN(0xFFFFFFFF);
        }

        // Store result
        gen_store_reg_partial(state, &inst, 0);
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
        // SETcc writes 0/1 to _xtmp. Use partial store to preserve upper bits.
        gen_store_reg_partial(state, &inst, 0);
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
	      enum size64 cmov_size = inst.operands[0].size;
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
	        if (cmov_size == size64_32) {
	          GEN(load32_gadgets[9]); // load32_mem
	        } else if (cmov_size == size64_16) {
	          GEN(gadget_load16_mem);
	        } else {
	          GEN(load64_gadgets[9]); // load64_mem
	        }
	        GEN(state->orig_ip);
	      }

	      // CMOV does not modify flags; any masking/merging here must be
	      // flag-preserving.
	      if (cmov_size == size64_32) {
	        // Taken path must zero-extend the 32-bit source.
	        // Can't use lea_and64_imm here since it clobbers x8 (cmov keeps dst in x8).
	        GEN(gadget_zero_extend32);
	      } else if (cmov_size == size64_16) {
	        // Taken path updates only low 16 bits of the destination.
	        GEN(gadget_zero_extend16);
	        GEN(gadget_merge16_x8);
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
        cmov_gadget = gadget_cmov_sxo;
        break;
      case ZYDIS_MNEMONIC_CMOVNL:
        cmov_gadget = gadget_cmovn_sxo;
        break;
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
      // Note: For 16-bit CMOV, the merge was already done above (merge16_x8).
      // Must use a direct store here, not gen_store_reg_partial which would double-merge.
      {
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
        // Check for high-byte register (AH, BH, CH, DH)
        bool is_high_byte = inst.operands[1].size == size64_8 &&
            inst.raw_operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            zydis_is_high_byte_reg(inst.raw_operands[1].reg.value);
        if (is_high_byte) {
          // High-byte: shift right by 8 first, then mask
          GEN(gadget_lea_lsr64_imm);
          GEN(8);
          GEN(gadget_lea_and64_imm);
          GEN(0xFF);
        } else if (inst.operands[1].size == size64_8) {
          // Apply appropriate mask (flag-preserving - MOVZX doesn't modify flags)
          GEN(gadget_lea_and64_imm);
          GEN(0xFF);
        } else if (inst.operands[1].size == size64_16) {
          GEN(gadget_lea_and64_imm);
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
      gen_store_reg_partial(state, &inst, 0);
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
        // Check for high-byte register (AH, BH, CH, DH)
        bool is_high_byte_sx = inst.operands[1].size == size64_8 &&
            inst.raw_operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            zydis_is_high_byte_reg(inst.raw_operands[1].reg.value);
        if (is_high_byte_sx) {
          // High-byte: shift right by 8 first, then sign-extend byte
          GEN(gadget_lea_lsr64_imm);
          GEN(8);
          GEN(gadget_sign_extend8);
        } else if (inst.operands[1].size == size64_8) {
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
      gen_store_reg_partial(state, &inst, 0);
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
          gen_store_reg_partial(state, &inst, 0);
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
          gen_store_reg_partial(state, &inst, 0);
        }
      } else {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
    } else if (inst.operand_count >= 2 && is_mem(inst.operands[0].type)) {
      // Memory form - need to read, modify, write
      // Must save guest address since read_prep replaces _addr with host address
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      GEN(gadget_save_addr); // Save guest address for store
      GEN(load64_gadgets[9]); // load64_mem (clobbers _addr with host addr)
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
          GEN(gadget_restore_addr); // Restore guest address
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
          GEN(gadget_restore_addr); // Restore guest address
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
      // Special case: XCHG AL, AH (or AH, AL) - 8-bit swap within same register
      // Both high-byte and low-byte map to the same parent register (e.g., arg64_rax)
      if (inst.operands[0].size == size64_8 &&
          inst.operands[0].type == inst.operands[1].type) {
        bool op0_high = zydis_is_high_byte_reg(
            inst.raw_operands[0].reg.value);
        bool op1_high = zydis_is_high_byte_reg(
            inst.raw_operands[1].reg.value);
        if (op0_high != op1_high) {
          // XCHG low_byte, high_byte within same register
          gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
          if (load) GEN(load);
          GEN(gadget_xchg_al_ah);
          gadget_t store = get_store64_reg_gadget(inst.operands[0].type);
          if (store) GEN(store);
        }
        // If both same byte position (xchg al, al), it's a NOP - do nothing
        break;
      }
      // XCHG reg1, reg2 - Exchange two full registers
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
      gen_store_reg_partial(state, &inst, 0);
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
      gen_store_reg_partial(state, &inst, 1);
    } else {
      g(interrupt);
      GEN(INT_UNDEFINED);
      GEN(state->orig_ip);
      GEN(state->orig_ip);
      return 0;
    }
    break;

  case ZYDIS_MNEMONIC_XADD:
    // XADD [mem], reg: temp=[mem]; [mem]=[mem]+reg; reg=temp; flags from add
    if (is_mem(inst.operands[0].type) && is_gpr(inst.operands[1].type)) {
      // Compute address
      gen_addr(state, &inst.operands[0], &inst);
      GEN(gadget_save_addr);
      // Load [mem] → _xtmp (old value)
      int xadd_size = inst.operands[0].size;
      if (xadd_size == size64_64) GEN(load64_gadgets[9]);
      else GEN(load32_gadgets[9]);
      GEN(state->orig_ip);
      // _xtmp = old [mem]. Save it to x8.
      GEN(gadget_save_xtmp_to_x8);  // x8 = old [mem]
      // Load reg → _xtmp
      gadget_t load_reg = get_load64_reg_gadget(inst.operands[1].type);
      if (!load_reg) { GEN(gadget_interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0; }
      GEN(load_reg);
      // Add: _xtmp = reg + old_[mem] (with flags). x8 still = old [mem].
      if (xadd_size == size64_64) GEN(gadget_add64_x8);
      else GEN(gadget_add32_x8);
      // Store sum to [mem]
      GEN(gadget_restore_addr);
      if (xadd_size == size64_64) GEN(store64_gadgets[9]);
      else GEN(store32_gadgets[9]);
      GEN(state->orig_ip);
      // Store old [mem] (x8) to register
      GEN(gadget_restore_xtmp_from_x8);
      gen_store_reg_partial(state, &inst, 1);
    } else {
      GEN(gadget_interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_NOT:
    // NOT - one's complement
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      GEN(inst.operands[0].size == size64_32 ? gadget_not32 : gadget_not64);
      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int not_size = inst.operands[0].size;
      GEN(gadget_save_addr);
      if (not_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (not_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (not_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      GEN(not_size == size64_32 ? gadget_not32 : gadget_not64);
      GEN(gadget_restore_addr);
      if (not_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (not_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (not_size == size64_16) {
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

  case ZYDIS_MNEMONIC_NEG:
    // NEG - two's complement
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      switch (inst.operands[0].size) {
        case size64_8:  GEN(gadget_neg8); break;
        case size64_16: GEN(gadget_neg16); break;
        case size64_32: GEN(gadget_neg32); break;
        default:        GEN(gadget_neg64); break;
      }
      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      int neg_size = inst.operands[0].size;
      GEN(gadget_save_addr);
      if (neg_size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (neg_size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (neg_size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      switch (neg_size) {
        case size64_8:  GEN(gadget_neg8); break;
        case size64_16: GEN(gadget_neg16); break;
        case size64_32: GEN(gadget_neg32); break;
        default:        GEN(gadget_neg64); break;
      }
      GEN(gadget_restore_addr);
      if (neg_size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (neg_size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (neg_size == size64_16) {
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

  case ZYDIS_MNEMONIC_INC:
    // INC - increment by 1 (INC doesn't modify CF, unlike ADD!)
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_inc64);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_inc32);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_inc16);
      } else {
        GEN(gadget_inc8);
      }
      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (inst.operands[0].size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // INC with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_inc64);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_inc32);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_inc16);
      } else {
        GEN(gadget_inc8);
      }
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Store with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (inst.operands[0].size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (inst.operands[0].size == size64_16) {
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

  case ZYDIS_MNEMONIC_DEC:
    // DEC - decrement by 1 (DEC doesn't modify CF, unlike SUB!)
    if (is_gpr(inst.operands[0].type)) {
      gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
      if (load)
        GEN(load);
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_dec64);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_dec32);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_dec16);
      } else {
        GEN(gadget_dec8);
      }
      gen_store_reg_partial(state, &inst, 0);
    } else if (is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Load with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(load64_gadgets[9]);
      } else if (inst.operands[0].size == size64_32) {
        GEN(load32_gadgets[9]);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_load16_mem);
      } else {
        GEN(gadget_load8_mem);
      }
      GEN(state->orig_ip);
      // DEC with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(gadget_dec64);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_dec32);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_dec16);
      } else {
        GEN(gadget_dec8);
      }
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      // Store with correct size
      if (inst.operands[0].size == size64_64) {
        GEN(store64_gadgets[9]);
      } else if (inst.operands[0].size == size64_32) {
        GEN(store32_gadgets[9]);
      } else if (inst.operands[0].size == size64_16) {
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
      gen_store_reg_partial(state, &inst, 0);
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
    // Unsigned divide: 8-bit: AX / r/m8 -> AL=quot, AH=rem
    // 16-bit: DX:AX / r/m16 -> AX=quot, DX=rem
    // 32-bit: EDX:EAX / r/m32 -> EAX=quot, EDX=rem
    // 64-bit: RDX:RAX / r/m64 -> RAX=quot, RDX=rem
    if (inst.operand_count >= 1) {
      // Load divisor into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        // High-byte register (AH/BH/CH/DH): shift right by 8
        if (inst.operands[0].size == size64_8 &&
            inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
          GEN(gadget_lea_lsr64_imm);
          GEN(8);
        }
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_8) {
          GEN(gadget_load8_mem);
        } else if (inst.operands[0].size == size64_16) {
          GEN(gadget_load16_mem);
        } else if (inst.operands[0].size == size64_32) {
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
      // Perform division
      if (inst.operands[0].size == size64_8) {
        GEN(gadget_div8);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_div16);
      } else if (inst.operands[0].size == size64_32) {
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
    // Signed divide: 8-bit: AX / r/m8 -> AL=quot, AH=rem
    // 16-bit: DX:AX / r/m16 -> AX=quot, DX=rem
    // 32-bit: EDX:EAX / r/m32 -> EAX=quot, EDX=rem
    // 64-bit: RDX:RAX / r/m64 -> RAX=quot, RDX=rem
    if (inst.operand_count >= 1) {
      // Load divisor into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        // High-byte register (AH/BH/CH/DH): shift right by 8
        if (inst.operands[0].size == size64_8 &&
            inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
          GEN(gadget_lea_lsr64_imm);
          GEN(8);
        }
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_8) {
          GEN(gadget_load8_mem);
        } else if (inst.operands[0].size == size64_16) {
          GEN(gadget_load16_mem);
        } else if (inst.operands[0].size == size64_32) {
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
      if (inst.operands[0].size == size64_8) {
        GEN(gadget_idiv8);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_idiv16);
      } else if (inst.operands[0].size == size64_32) {
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
    // Unsigned multiply: 8-bit: AL * r/m8 -> AX
    // 16-bit: AX * r/m16 -> DX:AX
    // 32-bit: EAX * r/m32 -> EDX:EAX
    // 64-bit: RAX * r/m64 -> RDX:RAX
    if (inst.operand_count >= 1) {
      // Load multiplier into _xtmp
      if (is_gpr(inst.operands[0].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[0].type);
        if (load)
          GEN(load);
        // High-byte register (AH/BH/CH/DH): shift right by 8
        if (inst.operands[0].size == size64_8 &&
            inst.raw_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            zydis_is_high_byte_reg(inst.raw_operands[0].reg.value)) {
          GEN(gadget_lea_lsr64_imm);
          GEN(8);
        }
      } else if (is_mem(inst.operands[0].type)) {
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        if (inst.operands[0].size == size64_8) {
          GEN(gadget_load8_mem);
        } else if (inst.operands[0].size == size64_16) {
          GEN(gadget_load16_mem);
        } else if (inst.operands[0].size == size64_32) {
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
      // Perform unsigned multiplication
      if (inst.operands[0].size == size64_8) {
        GEN(gadget_mul8);
      } else if (inst.operands[0].size == size64_16) {
        GEN(gadget_mul16);
      } else if (inst.operands[0].size == size64_32) {
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
        gen_store_reg_partial(state, &inst, 0);
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
  case ZYDIS_MNEMONIC_MOVAPD:
  case ZYDIS_MNEMONIC_MOVUPS:
  case ZYDIS_MNEMONIC_MOVUPD:
  case ZYDIS_MNEMONIC_MOVDQA:
  case ZYDIS_MNEMONIC_MOVDQU:
    // MOVAPS/MOVAPD/MOVUPS/MOVUPD/MOVDQA/MOVDQU - Move 128 bits (aligned/unaligned)
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // xmm, xmm: Copy between XMM registers
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(get_xmm_index(inst.operands[1].type));
        GEN(gadget_movaps_xmm_xmm);
        GEN(get_xmm_index(inst.operands[0].type));
      } else if (is_xmm(inst.operands[0].type) &&
                 is_mem(inst.operands[1].type)) {
        // xmm, [mem]: Load from memory to XMM
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
      } else if (is_mem(inst.operands[1].type)) {
        // PXOR xmm, [mem] - XOR 128 bits from memory
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(gadget_pxor_xmm_mem);
        GEN(state->orig_ip);
        GEN(get_xmm_index(inst.operands[0].type));
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

  case ZYDIS_MNEMONIC_CVTSI2SS:
    // CVTSI2SS xmm, r/m32 or r/m64 - Convert integer to scalar single
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      bool is_64bit = false;
      if (is_gpr(inst.operands[1].type)) {
        enum arg64 op = inst.operands[1].type;
        is_64bit = (op >= arg64_rax && op <= arg64_rdi) ||
                   (op >= arg64_r8 && op <= arg64_r15);
      } else {
        is_64bit = (code[0] == 0x48 ||
                    (code[0] == 0xf2 && code[1] == 0x48) ||
                    (code[0] == 0xf3 && code[1] == 0x48));
      }

      if (is_gpr(inst.operands[1].type)) {
        gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
        if (load) {
          GEN(load);
        }
        GEN(is_64bit ? gadget_cvtsi2ss_reg64 : gadget_cvtsi2ss_reg32);
        GEN(dst_xmm);
      } else {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt);
          GEN(INT_UNDEFINED);
          GEN(state->orig_ip);
          GEN(state->orig_ip);
          return 0;
        }
        GEN(is_64bit ? gadget_cvtsi2ss_mem64 : gadget_cvtsi2ss_mem32);
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

  case ZYDIS_MNEMONIC_ADDSS:
  case ZYDIS_MNEMONIC_SUBSS:
  case ZYDIS_MNEMONIC_MULSS:
  case ZYDIS_MNEMONIC_DIVSS: {
    // Scalar single-precision float ops
    gadget_t xmm_gadget, mem_gadget;
    switch (inst.mnemonic) {
      case ZYDIS_MNEMONIC_ADDSS: xmm_gadget = gadget_addss_xmm_xmm; mem_gadget = gadget_addss_xmm_mem; break;
      case ZYDIS_MNEMONIC_SUBSS: xmm_gadget = gadget_subss_xmm_xmm; mem_gadget = gadget_subss_xmm_mem; break;
      case ZYDIS_MNEMONIC_MULSS: xmm_gadget = gadget_mulss_xmm_xmm; mem_gadget = gadget_mulss_xmm_mem; break;
      default:                   xmm_gadget = gadget_divss_xmm_xmm; mem_gadget = gadget_divss_xmm_mem; break;
    }
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]);
        GEN(src_xmm);
        GEN(xmm_gadget);
        GEN(dst_xmm);
      } else {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(mem_gadget);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_CVTSS2SD:
    // CVTSS2SD xmm, xmm/m32 - Convert scalar single to double
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]); GEN(src_xmm);
        GEN(gadget_cvtss2sd_xmm_xmm); GEN(dst_xmm);
      } else {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_cvtss2sd_xmm_mem); GEN(dst_xmm); GEN(state->orig_ip);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_CVTSD2SS:
    // CVTSD2SS xmm, xmm/m64 - Convert scalar double to single
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]); GEN(src_xmm);
        GEN(gadget_cvtsd2ss_xmm_xmm); GEN(dst_xmm);
      } else {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_cvtsd2ss_xmm_mem); GEN(dst_xmm); GEN(state->orig_ip);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_CVTTSS2SI:
    // CVTTSS2SI r, xmm - Convert truncated float to integer
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int src_xmm = get_xmm_index(inst.operands[1].type);
      enum arg64 op = inst.operands[0].type;
      bool is_64bit = (op >= arg64_rax && op <= arg64_rdi) ||
                      (op >= arg64_r8 && op <= arg64_r15);
      GEN(is_64bit ? gadget_cvttss2si_reg64 : gadget_cvttss2si_reg32);
      GEN(src_xmm);
      enum arg64 dst = inst.operands[0].type;
      if (dst >= arg64_r8 && dst <= arg64_r15) {
        GEN(store64_r8_r15[dst - arg64_r8]);
      } else {
        GEN(is_64bit ? store64_gadgets[dst] : store32_gadgets[dst]);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_UCOMISS:
  case ZYDIS_MNEMONIC_COMISS:
    // UCOMISS/COMISS xmm, xmm - Compare scalar single (sets EFLAGS)
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(load64_gadgets[8]); GEN(src_xmm);
      GEN(gadget_ucomiss_xmm_xmm); GEN(dst_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED); GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_ADDSD:
    // ADDSD xmm, xmm/m64 - Add Scalar Double-Precision Floating-Point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
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

  case ZYDIS_MNEMONIC_DIVSD:
    // DIVSD xmm, xmm/m64 - Divide Scalar Double-Precision Floating-Point
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]); /* load64_imm: Load source XMM index */
        GEN(src_xmm);
        GEN(gadget_divsd_xmm_xmm);
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
        GEN(gadget_divsd_xmm_mem);
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

  case ZYDIS_MNEMONIC_MINSD:
  case ZYDIS_MNEMONIC_MAXSD: {
    // MINSD/MAXSD xmm, xmm/m64
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      bool is_min = (inst.mnemonic == ZYDIS_MNEMONIC_MINSD);
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]);
        GEN(src_xmm);
        GEN(is_min ? gadget_minsd_xmm_xmm : gadget_maxsd_xmm_xmm);
        GEN(dst_xmm);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(is_min ? gadget_minsd_xmm_mem : gadget_maxsd_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_CMPSD: {
    // CMPSD xmm, xmm/m64, imm8 - Compare Scalar Double with predicate
    // Writes all-1s or all-0s to dst low qword based on predicate comparison
    if (inst.operand_count >= 3 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      // imm8 predicate is operand[2]
      uint8_t pred = inst.operands[2].imm;
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(gadget_cmpsd_xmm_xmm);
        GEN(dst_xmm);
        GEN(src_xmm);
        GEN(pred);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_cmpsd_xmm_mem);
        GEN(dst_xmm);
        GEN(pred);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_SHUFPD:
  case ZYDIS_MNEMONIC_SHUFPS: {
    // SHUFPD/SHUFPS xmm, xmm/m128, imm8 - Shuffle Packed FP
    bool is_pd = (inst.mnemonic == ZYDIS_MNEMONIC_SHUFPD);
    if (inst.operand_count >= 3 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      uint8_t imm = inst.operands[2].imm;
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(is_pd ? gadget_shufpd_xmm_xmm : gadget_shufps);
        GEN(dst_xmm);
        GEN(src_xmm);
        GEN(imm);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(is_pd ? gadget_shufpd_xmm_mem : gadget_shufps_xmm_mem);
        GEN(dst_xmm);
        GEN(imm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

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
    GEN(gadget_rep_movsq);
    GEN(state->orig_ip); // For segfault handler
    break;

  case ZYDIS_MNEMONIC_MOVSB:
    // MOVSB - move byte [RSI] to [RDI]
    // Check if REP prefix is present
    if (inst.has_rep) {
      // REP MOVSB - repeat RCX times
      GEN(gadget_rep_movsb);
      GEN(state->orig_ip); // For segfault handler
    } else {
      // Single MOVSB - copy exactly one byte
      GEN(gadget_single_movsb);
      GEN(state->orig_ip); // For segfault handler
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
        GEN(load64_gadgets[8]); // load64_imm: Load source XMM index
        GEN(src_xmm);
        GEN(gadget_movsd_xmm_xmm);
        GEN(dst_xmm);
      } else if (is_xmm(inst.operands[0].type)) {
        // xmm, m64: load scalar double from memory into XMM low 64 bits
        int dst_xmm = get_xmm_index(inst.operands[0].type);
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
      GEN(gadget_rep_movsd);
      GEN(state->orig_ip); // For segfault handler
    }
    break;

  case ZYDIS_MNEMONIC_MOVSS:
    // MOVSS xmm, xmm/m32 or MOVSS m32, xmm - Move Scalar Single-Precision
    if (inst.operand_count >= 2 &&
        (is_xmm(inst.operands[0].type) || is_xmm(inst.operands[1].type))) {
      if (is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // xmm, xmm: copy low 32 bits, preserve upper 96 bits of dest
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(load64_gadgets[8]); // load64_imm
        GEN(src_xmm);
        GEN(gadget_movss_xmm_xmm);
        GEN(dst_xmm);
      } else if (is_xmm(inst.operands[0].type)) {
        // xmm, m32: load 32-bit float, zero upper bits
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movss_xmm_mem);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else {
        // m32, xmm: store low 32-bit float to memory
        int src_xmm = get_xmm_index(inst.operands[1].type);
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movss_mem_xmm);
        GEN(src_xmm);
        GEN(state->orig_ip);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVHLPS:
    // MOVHLPS xmm, xmm - Move high qword of src to low qword of dst
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_movhlps);
      GEN(dst_xmm);
      GEN(src_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVLHPS:
    // MOVLHPS xmm, xmm - Move low qword of src to high qword of dst
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_movlhps);
      GEN(dst_xmm);
      GEN(src_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVHPS:
  case ZYDIS_MNEMONIC_MOVHPD:
    // MOVHPS/MOVHPD xmm, m64 or m64, xmm - Move high 64 bits
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type) && is_mem(inst.operands[1].type)) {
        // xmm, m64: load into XMM high half
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movhps_load);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else if (is_mem(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // m64, xmm: store XMM high half to memory
        int src_xmm = get_xmm_index(inst.operands[1].type);
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movhps_store);
        GEN(src_xmm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVLPS:
  case ZYDIS_MNEMONIC_MOVLPD:
    // MOVLPS/MOVLPD xmm, m64 or m64, xmm - Move low 64 bits
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type) && is_mem(inst.operands[1].type)) {
        // xmm, m64: load into XMM low half (high preserved)
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movlps_load);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else if (is_mem(inst.operands[0].type) && is_xmm(inst.operands[1].type)) {
        // m64, xmm: store XMM low half to memory
        int src_xmm = get_xmm_index(inst.operands[1].type);
        if (!gen_addr(state, &inst.operands[0], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(gadget_movlps_store);
        GEN(src_xmm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_MOVD:
    // MOVD xmm, r/m32 or MOVD r/m32, xmm
    // Moves 32-bit value between GPR/memory and XMM register
    if (inst.operand_count >= 2) {
      if (is_xmm(inst.operands[0].type)) {
        // MOVD xmm, r/m32 - load into XMM
        int dst_xmm = get_xmm_index(inst.operands[0].type);
        if (is_gpr(inst.operands[1].type)) {
          // MOVD xmm, r32
          gadget_t load = get_load64_reg_gadget(inst.operands[1].type);
          if (load) GEN(load);
          GEN(gadget_movd_xmm_reg);
          GEN(dst_xmm);
        } else if (is_mem(inst.operands[1].type)) {
          // MOVD xmm, m32
          if (!gen_addr(state, &inst.operands[1], &inst)) {
            g(interrupt); GEN(INT_UNDEFINED);
            GEN(state->orig_ip); GEN(state->orig_ip); return 0;
          }
          GEN(gadget_movd_xmm_mem);
          GEN(dst_xmm);
          GEN(state->orig_ip);
        } else {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
      } else if (is_xmm(inst.operands[1].type)) {
        // MOVD r/m32, xmm - store from XMM
        int src_xmm = get_xmm_index(inst.operands[1].type);
        if (is_gpr(inst.operands[0].type)) {
          // MOVD r32, xmm
          GEN(gadget_movd_reg_xmm);
          GEN(src_xmm);
          // Store result (32-bit zero-extended) to destination register
          enum arg64 dst = inst.operands[0].type;
          if (dst >= arg64_r8 && dst <= arg64_r15) {
            GEN(store64_r8_r15[dst - arg64_r8]);
          } else {
            GEN(store32_gadgets[dst]);
          }
        } else if (is_mem(inst.operands[0].type)) {
          // MOVD m32, xmm
          if (!gen_addr(state, &inst.operands[0], &inst)) {
            g(interrupt); GEN(INT_UNDEFINED);
            GEN(state->orig_ip); GEN(state->orig_ip); return 0;
          }
          GEN(gadget_movd_mem_xmm);
          GEN(src_xmm);
          GEN(state->orig_ip);
        } else {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_PACKUSWB:
  case ZYDIS_MNEMONIC_PACKSSWB:
  case ZYDIS_MNEMONIC_PACKSSDW:
  case ZYDIS_MNEMONIC_PUNPCKLBW:
  case ZYDIS_MNEMONIC_PUNPCKLWD:
  case ZYDIS_MNEMONIC_PUNPCKLDQ:
  case ZYDIS_MNEMONIC_PUNPCKHBW:
  case ZYDIS_MNEMONIC_PUNPCKHWD:
  case ZYDIS_MNEMONIC_PUNPCKHDQ:
  case ZYDIS_MNEMONIC_PUNPCKHQDQ:
  case ZYDIS_MNEMONIC_PCMPEQB:
  case ZYDIS_MNEMONIC_PCMPEQD:
  case ZYDIS_MNEMONIC_PCMPGTD:
  case ZYDIS_MNEMONIC_PAND:
  case ZYDIS_MNEMONIC_PANDN:
  case ZYDIS_MNEMONIC_POR:
  case ZYDIS_MNEMONIC_PADDD:
  case ZYDIS_MNEMONIC_PADDQ:
  case ZYDIS_MNEMONIC_PSUBQ:
  case ZYDIS_MNEMONIC_PSUBD:
  case ZYDIS_MNEMONIC_ORPS:
  case ZYDIS_MNEMONIC_ORPD:
  case ZYDIS_MNEMONIC_ANDPD:
  case ZYDIS_MNEMONIC_ANDPS: {
    // Packed SSE2 integer/bitwise xmm, xmm/m128 operations
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      if (is_xmm(inst.operands[1].type)) {
        // xmm, xmm form
        int src_xmm = get_xmm_index(inst.operands[1].type);
        gadget_t gadget;
        switch (inst.mnemonic) {
          case ZYDIS_MNEMONIC_PACKUSWB:    gadget = gadget_packuswb; break;
          case ZYDIS_MNEMONIC_PACKSSWB:    gadget = gadget_packsswb; break;
          case ZYDIS_MNEMONIC_PACKSSDW:    gadget = gadget_packssdw; break;
          case ZYDIS_MNEMONIC_PUNPCKLBW:   gadget = gadget_punpcklbw; break;
          case ZYDIS_MNEMONIC_PUNPCKLWD:   gadget = gadget_punpcklwd; break;
          case ZYDIS_MNEMONIC_PUNPCKLDQ:  gadget = gadget_punpckldq; break;
          case ZYDIS_MNEMONIC_PUNPCKHBW:   gadget = gadget_punpckhbw; break;
          case ZYDIS_MNEMONIC_PUNPCKHWD:   gadget = gadget_punpckhwd; break;
          case ZYDIS_MNEMONIC_PUNPCKHDQ:  gadget = gadget_punpckhdq; break;
          case ZYDIS_MNEMONIC_PUNPCKHQDQ: gadget = gadget_punpckhqdq; break;
          case ZYDIS_MNEMONIC_PCMPEQB:    gadget = gadget_pcmpeqb; break;
          case ZYDIS_MNEMONIC_PCMPEQD:    gadget = gadget_pcmpeqd; break;
          case ZYDIS_MNEMONIC_PCMPGTD:    gadget = gadget_pcmpgtd; break;
          case ZYDIS_MNEMONIC_PAND:        gadget = gadget_pand; break;
          case ZYDIS_MNEMONIC_PANDN:       gadget = gadget_pandn; break;
          case ZYDIS_MNEMONIC_POR:         gadget = gadget_por; break;
          case ZYDIS_MNEMONIC_PADDD:       gadget = gadget_paddd; break;
          case ZYDIS_MNEMONIC_PADDQ:       gadget = gadget_paddq; break;
          case ZYDIS_MNEMONIC_PSUBQ:       gadget = gadget_psubq; break;
          case ZYDIS_MNEMONIC_PSUBD:       gadget = gadget_psubd; break;
          case ZYDIS_MNEMONIC_ORPS:        gadget = gadget_orps; break;
          case ZYDIS_MNEMONIC_ORPD:        gadget = gadget_orps; break;
          case ZYDIS_MNEMONIC_ANDPD:       gadget = gadget_pand; break;
          case ZYDIS_MNEMONIC_ANDPS:       gadget = gadget_pand; break;
          default: gadget = gadget_punpckldq; break; // unreachable
        }
        GEN(gadget);
        GEN(dst_xmm);
        GEN(src_xmm);
      } else if (is_mem(inst.operands[1].type)) {
        // xmm, m128 form
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        gadget_t gadget;
        switch (inst.mnemonic) {
          case ZYDIS_MNEMONIC_PACKUSWB:    gadget = gadget_packuswb_mem; break;
          case ZYDIS_MNEMONIC_PACKSSWB:    gadget = gadget_packsswb_mem; break;
          case ZYDIS_MNEMONIC_PACKSSDW:    gadget = gadget_packssdw_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKLBW:   gadget = gadget_punpcklbw_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKLWD:   gadget = gadget_punpcklwd_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKLDQ:  gadget = gadget_punpckldq_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKHBW:   gadget = gadget_punpckhbw_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKHWD:   gadget = gadget_punpckhwd_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKHDQ:  gadget = gadget_punpckhdq_mem; break;
          case ZYDIS_MNEMONIC_PUNPCKHQDQ: gadget = gadget_punpckhqdq_mem; break;
          case ZYDIS_MNEMONIC_PCMPEQB:    gadget = gadget_pcmpeqb_mem; break;
          case ZYDIS_MNEMONIC_PCMPEQD:    gadget = gadget_pcmpeqd_mem; break;
          case ZYDIS_MNEMONIC_PCMPGTD:    gadget = gadget_pcmpgtd_mem; break;
          case ZYDIS_MNEMONIC_PAND:        gadget = gadget_pand_mem; break;
          case ZYDIS_MNEMONIC_PANDN:       gadget = gadget_pandn_mem; break;
          case ZYDIS_MNEMONIC_POR:         gadget = gadget_por_mem; break;
          case ZYDIS_MNEMONIC_PADDD:       gadget = gadget_paddd_mem; break;
          case ZYDIS_MNEMONIC_PADDQ:       gadget = gadget_paddq_mem; break;
          case ZYDIS_MNEMONIC_PSUBQ:       gadget = gadget_psubq_mem; break;
          case ZYDIS_MNEMONIC_PSUBD:       gadget = gadget_psubd_mem; break;
          case ZYDIS_MNEMONIC_ORPS:        gadget = gadget_orps_mem; break;
          case ZYDIS_MNEMONIC_ORPD:        gadget = gadget_orps_mem; break;
          case ZYDIS_MNEMONIC_ANDPD:       gadget = gadget_pand_mem; break;
          case ZYDIS_MNEMONIC_ANDPS:       gadget = gadget_pand_mem; break;
          default: gadget = gadget_pand_mem; break; // unreachable
        }
        GEN(gadget);
        GEN(dst_xmm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_PSHUFD:
    // PSHUFD xmm, xmm/m128, imm8 - Shuffle packed doublewords
    if (inst.operand_count >= 3 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type) && inst.operands[2].type == arg64_imm) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_pshufd);
      GEN(dst_xmm);
      GEN(src_xmm);
      GEN(inst.operands[2].imm & 0xFF);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_PSHUFLW:
  case ZYDIS_MNEMONIC_PSHUFHW: {
    // PSHUFLW/PSHUFHW xmm, xmm/m128, imm8
    bool is_low = (inst.mnemonic == ZYDIS_MNEMONIC_PSHUFLW);
    if (inst.operand_count >= 3 && is_xmm(inst.operands[0].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      uint8_t imm = inst.operands[2].imm;
      if (is_xmm(inst.operands[1].type)) {
        int src_xmm = get_xmm_index(inst.operands[1].type);
        GEN(is_low ? gadget_pshuflw : gadget_pshufhw);
        GEN(dst_xmm);
        GEN(src_xmm);
        GEN(imm);
      } else if (is_mem(inst.operands[1].type)) {
        if (!gen_addr(state, &inst.operands[1], &inst)) {
          g(interrupt); GEN(INT_UNDEFINED);
          GEN(state->orig_ip); GEN(state->orig_ip); return 0;
        }
        GEN(is_low ? gadget_pshuflw_mem : gadget_pshufhw_mem);
        GEN(dst_xmm);
        GEN(imm);
        GEN(state->orig_ip);
      } else {
        g(interrupt); GEN(INT_UNDEFINED);
        GEN(state->orig_ip); GEN(state->orig_ip); return 0;
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_PALIGNR:
    // PALIGNR xmm, xmm, imm8 - Packed Align Right (SSSE3)
    if (inst.operand_count >= 3 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type) && inst.operands[2].type == arg64_imm) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_palignr);
      GEN(dst_xmm);
      GEN(src_xmm);
      GEN(inst.operands[2].imm & 0xFF);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_PSHUFB:
    // PSHUFB xmm, xmm - Packed Shuffle Bytes (SSSE3)
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_pshufb);
      GEN(dst_xmm);
      GEN(src_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SHA256RNDS2:
    // SHA256RNDS2 xmm, xmm (implicit XMM0) - 2 rounds SHA-256 compression
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_sha256rnds2);
      GEN(dst_xmm);
      GEN(src_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SHA256MSG1:
  case ZYDIS_MNEMONIC_SHA256MSG2: {
    // SHA256MSG1/MSG2 xmm, xmm - SHA-256 message schedule
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int dst_xmm = get_xmm_index(inst.operands[0].type);
      int src_xmm = get_xmm_index(inst.operands[1].type);
      gadget_t gadget = (inst.mnemonic == ZYDIS_MNEMONIC_SHA256MSG1) ?
                        gadget_sha256msg1 : gadget_sha256msg2;
      GEN(gadget);
      GEN(dst_xmm);
      GEN(src_xmm);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;
  }

  case ZYDIS_MNEMONIC_PSRLQ:
  case ZYDIS_MNEMONIC_PSLLQ:
  case ZYDIS_MNEMONIC_PSRLW:
  case ZYDIS_MNEMONIC_PSLLW:
  case ZYDIS_MNEMONIC_PSRAW:
  case ZYDIS_MNEMONIC_PSRAD:
  case ZYDIS_MNEMONIC_PSRLD:
  case ZYDIS_MNEMONIC_PSLLD:
  case ZYDIS_MNEMONIC_PSRLDQ:
  case ZYDIS_MNEMONIC_PSLLDQ:
    // Packed shift by immediate
    if (inst.operand_count >= 2 && is_xmm(inst.operands[0].type) &&
        inst.operands[1].type == arg64_imm) {
      int xmm_idx = get_xmm_index(inst.operands[0].type);
      gadget_t gadget;
      switch (inst.mnemonic) {
        case ZYDIS_MNEMONIC_PSRLQ: gadget = gadget_psrlq; break;
        case ZYDIS_MNEMONIC_PSLLQ: gadget = gadget_psllq; break;
        case ZYDIS_MNEMONIC_PSRLW: gadget = gadget_psrlw; break;
        case ZYDIS_MNEMONIC_PSLLW: gadget = gadget_psllw; break;
        case ZYDIS_MNEMONIC_PSRAW: gadget = gadget_psraw; break;
        case ZYDIS_MNEMONIC_PSRAD: gadget = gadget_psrad; break;
        case ZYDIS_MNEMONIC_PSRLD: gadget = gadget_psrld; break;
        case ZYDIS_MNEMONIC_PSLLD: gadget = gadget_pslld; break;
        case ZYDIS_MNEMONIC_PSRLDQ: gadget = gadget_psrldq; break;
        case ZYDIS_MNEMONIC_PSLLDQ: gadget = gadget_pslldq; break;
        default: gadget = gadget_psrlq; break;
      }
      GEN(gadget);
      GEN(xmm_idx);
      GEN(inst.operands[1].imm & 0xFF);
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_PMOVMSKB:
    // PMOVMSKB r32, xmm - Move byte mask
    if (inst.operand_count >= 2 && is_gpr(inst.operands[0].type) &&
        is_xmm(inst.operands[1].type)) {
      int src_xmm = get_xmm_index(inst.operands[1].type);
      GEN(gadget_pmovmskb);
      GEN(src_xmm);
      // Store result to GPR (32-bit zero-extended)
      enum arg64 dst = inst.operands[0].type;
      if (dst >= arg64_r8 && dst <= arg64_r15) {
        GEN(store64_r8_r15[dst - arg64_r8]);
      } else {
        GEN(store32_gadgets[dst]);
      }
    } else {
      g(interrupt); GEN(INT_UNDEFINED);
      GEN(state->orig_ip); GEN(state->orig_ip); return 0;
    }
    break;

  case ZYDIS_MNEMONIC_SCASB:
    // SCASB - Compare AL with byte at [RDI]
    if (inst.has_repne) {
      // REPNE SCASB - scan for byte not equal to AL (used for strlen)
      GEN(gadget_repne_scasb);
    } else if (inst.has_rep) {
      // REPE SCASB - scan for byte equal to AL
      GEN(gadget_repe_scasb);
    } else {
      // Single SCASB
      GEN(gadget_single_scasb);
    }
    GEN(state->orig_ip); // For segfault handler
    break;

  // ======================================================================
  // x87 FPU Instructions
  // ======================================================================

  case ZYDIS_MNEMONIC_FILD:
    // FILD m16/m32/m64 - Load Integer to FPU stack
    if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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

  case ZYDIS_MNEMONIC_FIST:
    // FIST m16/m32 - Store Integer without Pop
    // Note: FIST doesn't support m64, only m16 and m32
    if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
      if (!gen_addr(state, &inst.operands[0], &inst)) {
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
      }
      if (inst.operands[0].size == size64_16) {
        GEN(gadget_fpu_fist16);
      } else if (inst.operands[0].size == size64_32) {
        GEN(gadget_fpu_fist32);
      } else {
        // FIST m64 is not a valid instruction, fall through to undefined
        g(interrupt);
        GEN(INT_UNDEFINED);
        GEN(state->orig_ip);
        GEN(state->orig_ip);
        return 0;
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
    if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
      if (is_mem(inst.operands[0].type)) {
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
      // FADD can be: FADD ST(0), ST(i) or FADD ST(i), ST(0)
      // operands[0] = destination, operands[1] = source
      int dst = inst.operands[0].type - arg64_st0;
      int src = inst.operands[1].type - arg64_st0;
      if (dst == 0) {
        // FADD ST(0), ST(i) - result in ST(0)
        GEN(gadget_fpu_fadd);
        GEN(src);
      } else {
        // FADD ST(i), ST(0) - result in ST(i)
        GEN(gadget_fpu_fadd_sti);
        GEN(dst);
      }
    } else if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
      int dst = inst.operands[0].type - arg64_st0;
      int src = inst.operands[1].type - arg64_st0;
      if (dst == 0) {
        // FSUB ST(0), ST(i) - result in ST(0): ST(0) = ST(0) - ST(i)
        GEN(gadget_fpu_fsub);
        GEN(src);
      } else {
        // FSUB ST(i), ST(0) - result in ST(i): ST(i) = ST(i) - ST(0)
        GEN(gadget_fpu_fsub_sti);
        GEN(dst);
      }
    } else if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
        inst.operands[0].type >= arg64_st0 && inst.operands[0].type <= arg64_st7 &&
        inst.operands[1].type >= arg64_st0 && inst.operands[1].type <= arg64_st7) {
      int dst = inst.operands[0].type - arg64_st0;
      int src = inst.operands[1].type - arg64_st0;
      if (dst == 0) {
        // FSUBR ST(0), ST(i) - result in ST(0): ST(0) = ST(i) - ST(0)
        GEN(gadget_fpu_fsubr);
        GEN(src);
      } else {
        // FSUBR ST(i), ST(0) - result in ST(i): ST(i) = ST(0) - ST(i)
        GEN(gadget_fpu_fsubr_sti);
        GEN(dst);
      }
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
      int dst = inst.operands[0].type - arg64_st0;
      int src = inst.operands[1].type - arg64_st0;
      if (dst == 0) {
        // FMUL ST(0), ST(i) - result in ST(0)
        GEN(gadget_fpu_fmul);
        GEN(src);
      } else {
        // FMUL ST(i), ST(0) - result in ST(i)
        GEN(gadget_fpu_fmul_sti);
        GEN(dst);
      }
    } else if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
      int dst = inst.operands[0].type - arg64_st0;
      int src = inst.operands[1].type - arg64_st0;
      if (dst == 0) {
        // FDIV ST(0), ST(i) - result in ST(0)
        GEN(gadget_fpu_fdiv);
        GEN(src);
      } else {
        // FDIV ST(i), ST(0) - result in ST(i)
        GEN(gadget_fpu_fdiv_sti);
        GEN(dst);
      }
    } else if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
    if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
    if (inst.operand_count >= 1 && is_mem(inst.operands[0].type)) {
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
