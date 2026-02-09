#include <time.h>
#include <string.h>
#include "emu/cpu.h"
#include "emu/cpuid.h"

void helper_cpuid(dword_t *a, dword_t *b, dword_t *c, dword_t *d) {
    do_cpuid(a, b, c, d);
}

void helper_rdtsc(struct cpu_state *cpu) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t tsc = now.tv_sec * 1000000000l + now.tv_nsec;
    cpu->eax = tsc & 0xffffffff;
    cpu->edx = tsc >> 32;
}

void helper_expand_flags(struct cpu_state *cpu) {
    expand_flags(cpu);
}

void helper_collapse_flags(struct cpu_state *cpu) {
    collapse_flags(cpu);
}

void helper_store64_via_c(uint64_t host_addr, uint64_t value) {
    volatile uint64_t *ptr = (volatile uint64_t *)host_addr;
    *ptr = value;
}

#ifdef ISH_GUEST_64BIT

// Simple r10 load helper - used by load64_r10 workaround
uint64_t helper_load_r10_simple(struct cpu_state *cpu) {
    return cpu->r10;
}

// Simple r13 load helper
uint64_t helper_load_r13_simple(struct cpu_state *cpu) {
    return cpu->r13;
}
#endif

// ============================================================================
// x87 FPU Helper Functions
// ============================================================================

#include "emu/float80.h"

// FILD - Load Integer to FPU stack
void helper_fpu_fild16(struct cpu_state *cpu, int16_t *addr) {
    float80 f = f80_from_int(*addr);
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f;
}

void helper_fpu_fild32(struct cpu_state *cpu, int32_t *addr) {
    int32_t val = *addr;
    float80 f = f80_from_int(val);
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f;
}

void helper_fpu_fild64(struct cpu_state *cpu, int64_t *addr) {
    int64_t val = *addr;
    float80 f = f80_from_int(val);
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f;
}

// FIST - Store Integer (without pop)
void helper_fpu_fist16(struct cpu_state *cpu, int16_t *addr) {
    *addr = (int16_t)f80_to_int(cpu->fp[cpu->top]);
}

void helper_fpu_fist32(struct cpu_state *cpu, int32_t *addr) {
    *addr = (int32_t)f80_to_int(cpu->fp[cpu->top]);
}

// FISTP - Store Integer and Pop
void helper_fpu_fistp16(struct cpu_state *cpu, int16_t *addr) {
    *addr = (int16_t)f80_to_int(cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fistp32(struct cpu_state *cpu, int32_t *addr) {
    *addr = (int32_t)f80_to_int(cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fistp64(struct cpu_state *cpu, int64_t *addr) {
    *addr = f80_to_int(cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

// FLD - Load Float to FPU stack
void helper_fpu_fld32(struct cpu_state *cpu, float *addr) {
    float80 f = f80_from_double((double)*addr);
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f;
}

void helper_fpu_fld64(struct cpu_state *cpu, double *addr) {
    double val = *addr;
    float80 f = f80_from_double(val);
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f;
}

void helper_fpu_fld80(struct cpu_state *cpu, float80 *addr) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = *addr;
}

void helper_fpu_fld_sti(struct cpu_state *cpu, int i) {
    int src_idx = (cpu->top + i) & 7;
    float80 val = cpu->fp[src_idx];
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = val;
}

// FSTP - Store Float and Pop
void helper_fpu_fstp32(struct cpu_state *cpu, float *addr) {
    *addr = (float)f80_to_double(cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fstp64(struct cpu_state *cpu, double *addr) {
    *addr = f80_to_double(cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fstp80(struct cpu_state *cpu, float80 *addr) {
    *addr = cpu->fp[cpu->top];
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fstp_sti(struct cpu_state *cpu, int i) {
    int dst_idx = (cpu->top + i) & 7;
    cpu->fp[dst_idx] = cpu->fp[cpu->top];
    cpu->top = (cpu->top + 1) & 7;
}

// FADD - Addition
void helper_fpu_fadd(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[cpu->top] = f80_add(cpu->fp[cpu->top], cpu->fp[idx]);
}

// FADD ST(i), ST(0) - result stored in ST(i)
void helper_fpu_fadd_sti(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_add(cpu->fp[idx], cpu->fp[cpu->top]);
}

void helper_fpu_faddp(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_add(cpu->fp[idx], cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fadd_m32(struct cpu_state *cpu, float *addr) {
    float80 val = f80_from_double((double)*addr);
    cpu->fp[cpu->top] = f80_add(cpu->fp[cpu->top], val);
}

void helper_fpu_fadd_m64(struct cpu_state *cpu, double *addr) {
    float80 val = f80_from_double(*addr);
    cpu->fp[cpu->top] = f80_add(cpu->fp[cpu->top], val);
}

// FSUB - Subtraction
void helper_fpu_fsub(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[cpu->top] = f80_sub(cpu->fp[cpu->top], cpu->fp[idx]);
}

// FSUB ST(i), ST(0) - result stored in ST(i): ST(i) = ST(i) - ST(0)
void helper_fpu_fsub_sti(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_sub(cpu->fp[idx], cpu->fp[cpu->top]);
}

// FSUBR ST(i), ST(0) - reverse subtract, result in ST(i): ST(i) = ST(0) - ST(i)
void helper_fpu_fsubr_sti(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_sub(cpu->fp[cpu->top], cpu->fp[idx]);
}

void helper_fpu_fsubp(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_sub(cpu->fp[idx], cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fsubr(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[cpu->top] = f80_sub(cpu->fp[idx], cpu->fp[cpu->top]);
}

void helper_fpu_fsubrp(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_sub(cpu->fp[cpu->top], cpu->fp[idx]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fsub_m32(struct cpu_state *cpu, float *addr) {
    float80 val = f80_from_double((double)*addr);
    cpu->fp[cpu->top] = f80_sub(cpu->fp[cpu->top], val);
}

void helper_fpu_fsub_m64(struct cpu_state *cpu, double *addr) {
    float80 val = f80_from_double(*addr);
    cpu->fp[cpu->top] = f80_sub(cpu->fp[cpu->top], val);
}

// FMUL - Multiplication
void helper_fpu_fmul(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[cpu->top] = f80_mul(cpu->fp[cpu->top], cpu->fp[idx]);
}

// FMUL ST(i), ST(0) - result stored in ST(i): ST(i) = ST(i) * ST(0)
void helper_fpu_fmul_sti(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_mul(cpu->fp[idx], cpu->fp[cpu->top]);
}

void helper_fpu_fmulp(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_mul(cpu->fp[idx], cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fmul_m32(struct cpu_state *cpu, float *addr) {
    float80 val = f80_from_double((double)*addr);
    cpu->fp[cpu->top] = f80_mul(cpu->fp[cpu->top], val);
}

void helper_fpu_fmul_m64(struct cpu_state *cpu, double *addr) {
    float80 val = f80_from_double(*addr);
    cpu->fp[cpu->top] = f80_mul(cpu->fp[cpu->top], val);
}

// FDIV - Division
void helper_fpu_fdiv(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[cpu->top] = f80_div(cpu->fp[cpu->top], cpu->fp[idx]);
}

// FDIV ST(i), ST(0) - result stored in ST(i): ST(i) = ST(i) / ST(0)
void helper_fpu_fdiv_sti(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_div(cpu->fp[idx], cpu->fp[cpu->top]);
}

void helper_fpu_fdivp(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    cpu->fp[idx] = f80_div(cpu->fp[idx], cpu->fp[cpu->top]);
    cpu->top = (cpu->top + 1) & 7;
}

void helper_fpu_fdiv_m32(struct cpu_state *cpu, float *addr) {
    float80 val = f80_from_double((double)*addr);
    cpu->fp[cpu->top] = f80_div(cpu->fp[cpu->top], val);
}

void helper_fpu_fdiv_m64(struct cpu_state *cpu, double *addr) {
    float80 val = f80_from_double(*addr);
    cpu->fp[cpu->top] = f80_div(cpu->fp[cpu->top], val);
}

// FXCH - Exchange ST(0) and ST(i)
void helper_fpu_fxch(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    float80 tmp = cpu->fp[cpu->top];
    cpu->fp[cpu->top] = cpu->fp[idx];
    cpu->fp[idx] = tmp;
}

// FPREM - Partial Remainder
void helper_fpu_fprem(struct cpu_state *cpu) {
    int st1_idx = (cpu->top + 1) & 7;
    cpu->fp[cpu->top] = f80_mod(cpu->fp[cpu->top], cpu->fp[st1_idx]);
    cpu->c2 = 0;  // Reduction complete
}

// FSCALE - Scale by Power of 2
void helper_fpu_fscale(struct cpu_state *cpu) {
    int st1_idx = (cpu->top + 1) & 7;
    int scale = (int)f80_to_int(f80_round(cpu->fp[st1_idx]));
    cpu->fp[cpu->top] = f80_scale(cpu->fp[cpu->top], scale);
}

// FRNDINT - Round to Integer
void helper_fpu_frndint(struct cpu_state *cpu) {
    cpu->fp[cpu->top] = f80_round(cpu->fp[cpu->top]);
}

// FABS - Absolute Value
void helper_fpu_fabs(struct cpu_state *cpu) {
    cpu->fp[cpu->top] = f80_abs(cpu->fp[cpu->top]);
}

// FCHS - Change Sign
void helper_fpu_fchs(struct cpu_state *cpu) {
    cpu->fp[cpu->top] = f80_neg(cpu->fp[cpu->top]);
}

// FINCSTP - Increment Stack Pointer
void helper_fpu_fincstp(struct cpu_state *cpu) {
    cpu->top = (cpu->top + 1) & 7;
}

// Load Constants
void helper_fpu_fldz(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(0.0);
}

void helper_fpu_fld1(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(1.0);
}

void helper_fpu_fldpi(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(3.14159265358979323846);
}

void helper_fpu_fldl2e(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(1.4426950408889634);  // log2(e)
}

void helper_fpu_fldl2t(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(3.3219280948873626);  // log2(10)
}

void helper_fpu_fldlg2(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(0.3010299956639812);  // log10(2)
}

void helper_fpu_fldln2(struct cpu_state *cpu) {
    cpu->top = (cpu->top - 1) & 7;
    cpu->fp[cpu->top] = f80_from_double(0.6931471805599453);  // ln(2)
}

// FLDCW/FNSTCW - Load/Store Control Word
void helper_fpu_fldcw(struct cpu_state *cpu, uint16_t *addr) {
    cpu->fcw = *addr;
    // Update rounding mode based on RC field (bits 10-11)
    f80_rounding_mode = (cpu->fcw >> 10) & 3;
}

void helper_fpu_fnstcw(struct cpu_state *cpu, uint16_t *addr) {
    *addr = cpu->fcw;
}

// FNSTSW - Store Status Word to AX
void helper_fpu_fnstsw(struct cpu_state *cpu) {
#ifdef ISH_GUEST_64BIT
    cpu->rax = (cpu->rax & 0xFFFFFFFFFFFF0000ULL) | cpu->fsw;
#else
    cpu->eax = (cpu->eax & 0xFFFF0000) | cpu->fsw;
#endif
}

// FUCOMIP - Unordered Compare, set EFLAGS, pop
void helper_fpu_fucomip(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    float80 st0 = cpu->fp[cpu->top];
    float80 sti = cpu->fp[idx];

    // All cases: OF=0, SF=0 (x87 comparisons always clear these)
    cpu->of = 0;
    cpu->eflags &= ~(SF_FLAG);  // SF = 0

    // Force JIT to read ZF, PF, SF from eflags (not from stale cpu->res)
    cpu->flags_res &= ~(ZF_RES | PF_RES | SF_RES);

    // Set EFLAGS based on comparison
    if (f80_uncomparable(st0, sti)) {
        cpu->cf = 1;
        cpu->eflags |= ZF_FLAG;
        cpu->eflags |= PF_FLAG;
    } else if (f80_eq(st0, sti)) {
        cpu->cf = 0;
        cpu->eflags |= ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    } else if (f80_lt(st0, sti)) {
        cpu->cf = 1;
        cpu->eflags &= ~ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    } else {
        // st0 > sti
        cpu->cf = 0;
        cpu->eflags &= ~ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    }

    // Pop
    cpu->top = (cpu->top + 1) & 7;
}

// FUCOMI - Unordered Compare, set EFLAGS (no pop)
void helper_fpu_fucomi(struct cpu_state *cpu, int i) {
    int idx = (cpu->top + i) & 7;
    float80 st0 = cpu->fp[cpu->top];
    float80 sti = cpu->fp[idx];

    cpu->of = 0;
    cpu->eflags &= ~(SF_FLAG);

    cpu->flags_res &= ~(ZF_RES | PF_RES | SF_RES);

    if (f80_uncomparable(st0, sti)) {
        cpu->cf = 1;
        cpu->eflags |= ZF_FLAG;
        cpu->eflags |= PF_FLAG;
    } else if (f80_eq(st0, sti)) {
        cpu->cf = 0;
        cpu->eflags |= ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    } else if (f80_lt(st0, sti)) {
        cpu->cf = 1;
        cpu->eflags &= ~ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    } else {
        cpu->cf = 0;
        cpu->eflags &= ~ZF_FLAG;
        cpu->eflags &= ~PF_FLAG;
    }
}

// ============================================================================
// SSE Helper Functions
// ============================================================================

#ifdef ISH_GUEST_64BIT

// PUNPCKLDQ xmm, xmm - Unpack and interleave low doublewords
void helper_punpckldq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    uint32_t result[4];
    result[0] = dst[0];
    result[1] = src[0];
    result[2] = dst[1];
    result[3] = src[1];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PCMPEQD xmm, xmm - Compare packed doublewords for equality
void helper_pcmpeqd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] == src[i]) ? 0xFFFFFFFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PAND xmm, xmm - Bitwise AND of packed 128-bit values
void helper_pand(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] &= src[0];
    dst[1] &= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PADDD xmm, xmm - Add packed 32-bit integers
void helper_paddd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 4; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PSUBD xmm, xmm - Subtract packed 32-bit integers
void helper_psubd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 4; i++)
        dst[i] -= src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PSHUFD xmm, xmm/m128, imm8 - Shuffle packed doublewords
void helper_pshufd(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint32_t src[4], result[4];
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = src[(imm >> 0) & 3];
    result[1] = src[(imm >> 2) & 3];
    result[2] = src[(imm >> 4) & 3];
    result[3] = src[(imm >> 6) & 3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PMOVMSKB r, xmm - Move byte mask (extract MSB of each byte into integer)
int helper_pmovmskb(struct cpu_state *cpu, int src_idx) {
    uint8_t src[16];
    memcpy(src, &cpu->xmm[src_idx], 16);
    int mask = 0;
    for (int i = 0; i < 16; i++)
        if (src[i] & 0x80)
            mask |= (1 << i);
    return mask;
}

#endif
