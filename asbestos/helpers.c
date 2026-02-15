#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include "emu/cpu.h"
#include "emu/mmu.h"

// Debug: verify MUL64 results
void helper_verify_mul64(uint64_t a, uint64_t b, uint64_t lo, uint64_t hi) {
    __uint128_t expected = (__uint128_t)a * (__uint128_t)b;
    uint64_t exp_lo = (uint64_t)expected;
    uint64_t exp_hi = (uint64_t)(expected >> 64);
    if (lo != exp_lo || hi != exp_hi) {
        fprintf(stderr, "MUL64 WRONG: %#llx * %#llx = %#llx:%#llx (expected %#llx:%#llx)\n",
                (unsigned long long)a, (unsigned long long)b,
                (unsigned long long)hi, (unsigned long long)lo,
                (unsigned long long)exp_hi, (unsigned long long)exp_lo);
    }
}

// Debug: verify ADC64 results
void helper_verify_adc64(uint64_t a, uint64_t b, uint64_t cf_in, uint64_t result, uint64_t cf_out) {
    __uint128_t expected = (__uint128_t)a + (__uint128_t)b + (__uint128_t)cf_in;
    uint64_t exp_result = (uint64_t)expected;
    uint64_t exp_cf = (uint64_t)(expected >> 64);
    if (result != exp_result || cf_out != exp_cf) {
        fprintf(stderr, "ADC64 WRONG: %#llx + %#llx + %llu = %#llx cf=%llu (expected %#llx cf=%llu)\n",
                (unsigned long long)a, (unsigned long long)b, (unsigned long long)cf_in,
                (unsigned long long)result, (unsigned long long)cf_out,
                (unsigned long long)exp_result, (unsigned long long)exp_cf);
    }
}
#include "emu/cpuid.h"

void helper_cpuid(
#ifdef ISH_GUEST_64BIT
    struct cpu_state *cpu
#else
    dword_t *a, dword_t *b, dword_t *c, dword_t *d
#endif
) {
#ifdef ISH_GUEST_64BIT
    dword_t a32 = (dword_t)cpu->rax;
    dword_t b32 = (dword_t)cpu->rbx;
    dword_t c32 = (dword_t)cpu->rcx;
    dword_t d32 = (dword_t)cpu->rdx;
    dword_t input_leaf = a32;
    do_cpuid(&a32, &b32, &c32, &d32);
    fprintf(stderr, "[CPUID] leaf=%u: eax=%#x ebx=%#x ecx=%#x edx=%#x\n",
           input_leaf, a32, b32, c32, d32);
    cpu->rax = a32;
    cpu->rbx = b32;
    cpu->rcx = c32;
    cpu->rdx = d32;
#else
    do_cpuid(a, b, c, d);
#endif
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

// 128/64-bit unsigned division: RDX:RAX / divisor -> RAX (quotient), RDX (remainder)
// x0 = divisor, x1 = cpu_state pointer (ARM64 calling convention)
void helper_div64(uint64_t divisor, struct cpu_state *cpu) {
    unsigned __int128 dividend = ((unsigned __int128)cpu->rdx << 64) | cpu->rax;
    cpu->rax = (uint64_t)(dividend / divisor);
    cpu->rdx = (uint64_t)(dividend % divisor);
}

// 128/64-bit signed division: RDX:RAX / divisor -> RAX (quotient), RDX (remainder)
void helper_idiv64(uint64_t divisor, struct cpu_state *cpu) {
    __int128 dividend = ((__int128)(int64_t)cpu->rdx << 64) | (unsigned __int128)cpu->rax;
    __int128 sdivisor = (int64_t)divisor;
    cpu->rax = (uint64_t)(int64_t)(dividend / sdivisor);
    cpu->rdx = (uint64_t)(int64_t)(dividend % sdivisor);
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

// PCMPGTD xmm, xmm - Compare packed doublewords for greater than (signed)
void helper_pcmpgtd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    int32_t dst[4], src[4];
    uint32_t result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] > src[i]) ? 0xFFFFFFFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
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

// SHUFPS xmm, xmm, imm8 - Shuffle packed single-precision floats
// Low 2 dwords from dst, high 2 dwords from src
void helper_shufps(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = dst[(imm >> 0) & 3];
    result[1] = dst[(imm >> 2) & 3];
    result[2] = src[(imm >> 4) & 3];
    result[3] = src[(imm >> 6) & 3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PSRLQ xmm, imm8 - Packed Shift Right Logical Quadword
void helper_psrlq(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint64_t qw[2];
    memcpy(qw, &cpu->xmm[xmm_idx], 16);
    if (imm >= 64) {
        qw[0] = 0;
        qw[1] = 0;
    } else {
        qw[0] >>= imm;
        qw[1] >>= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], qw, 16);
}

// PSLLQ xmm, imm8 - Packed Shift Left Logical Quadword
void helper_psllq(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint64_t qw[2];
    memcpy(qw, &cpu->xmm[xmm_idx], 16);
    if (imm >= 64) {
        qw[0] = 0;
        qw[1] = 0;
    } else {
        qw[0] <<= imm;
        qw[1] <<= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], qw, 16);
}

// PSRLDQ xmm, imm8 - Packed Shift Right Logical Double Quadword (byte shift)
void helper_psrldq(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint8_t src[16], dst[16];
    memcpy(src, &cpu->xmm[xmm_idx], 16);
    memset(dst, 0, 16);
    if (imm < 16) {
        for (int i = 0; i < 16 - imm; i++)
            dst[i] = src[i + imm];
    }
    memcpy(&cpu->xmm[xmm_idx], dst, 16);
}

// PSLLDQ xmm, imm8 - Packed Shift Left Logical Double Quadword (byte shift)
void helper_pslldq(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint8_t src[16], dst[16];
    memcpy(src, &cpu->xmm[xmm_idx], 16);
    memset(dst, 0, 16);
    if (imm < 16) {
        for (int i = 0; i < 16 - imm; i++)
            dst[i + imm] = src[i];
    }
    memcpy(&cpu->xmm[xmm_idx], dst, 16);
}

// ORPS/ORPD xmm, xmm - Bitwise OR of packed values (128-bit OR)
void helper_orps(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] |= src[0];
    dst[1] |= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// POR xmm, xmm - Bitwise OR of packed 128-bit values
void helper_por(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] |= src[0];
    dst[1] |= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PANDN xmm, xmm - Bitwise AND NOT of packed 128-bit values (dst = ~dst & src)
void helper_pandn(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] = ~dst[0] & src[0];
    dst[1] = ~dst[1] & src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// Memory-form helpers for packed SSE2 operations
// These take a host memory pointer instead of an XMM source index

void helper_pand_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[0] &= src[0];
    dst[1] &= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_pandn_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[0] = ~dst[0] & src[0];
    dst[1] = ~dst[1] & src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_por_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[0] |= src[0];
    dst[1] |= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_orps_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[0] |= src[0];
    dst[1] |= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_paddd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 4; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 4; i++)
        dst[i] -= src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_pcmpeqd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] == src[i]) ? 0xFFFFFFFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_pcmpgtd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    int32_t dst[4], src[4];
    uint32_t result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] > src[i]) ? 0xFFFFFFFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpckldq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[0]; result[1] = src[0];
    result[2] = dst[1]; result[3] = src[1];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpckhqdq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2], result[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[1];
    result[1] = src[1];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PSRLD xmm, imm8 - Packed Shift Right Logical Doubleword
void helper_psrld(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint32_t dw[4];
    memcpy(dw, &cpu->xmm[xmm_idx], 16);
    if (imm >= 32) {
        memset(dw, 0, 16);
    } else {
        for (int i = 0; i < 4; i++) dw[i] >>= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], dw, 16);
}

// PSLLD xmm, imm8 - Packed Shift Left Logical Doubleword
void helper_pslld(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint32_t dw[4];
    memcpy(dw, &cpu->xmm[xmm_idx], 16);
    if (imm >= 32) {
        memset(dw, 0, 16);
    } else {
        for (int i = 0; i < 4; i++) dw[i] <<= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], dw, 16);
}

// PUNPCKHQDQ xmm, xmm - Unpack and interleave high quadwords
// Result: dst = {src[127:64], dst[127:64]}
void helper_punpckhqdq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] = dst[1];
    dst[1] = src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PUNPCKLQDQ xmm, xmm - Unpack and interleave low quadwords
// Result: dst = {src[63:0], dst[63:0]}
void helper_punpcklqdq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[1] = src[0];
    // dst[0] stays as dst[0]
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// MOVDQU xmm, [mem] / [mem], xmm - Move unaligned 128-bit
void helper_movdqu_load(struct cpu_state *cpu, int dst_idx, void *addr) {
    memcpy(&cpu->xmm[dst_idx], addr, 16);
}

void helper_movdqu_store(struct cpu_state *cpu, int src_idx, void *addr) {
    memcpy(addr, &cpu->xmm[src_idx], 16);
}

// MOVDQA xmm, xmm - Move aligned 128-bit (register to register)
void helper_movdqa_xmm(struct cpu_state *cpu, int dst_idx, int src_idx) {
    memcpy(&cpu->xmm[dst_idx], &cpu->xmm[src_idx], 16);
}

// PXOR xmm, xmm - Bitwise XOR of packed 128-bit values
void helper_pxor(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] ^= src[0];
    dst[1] ^= src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PALIGNR xmm, xmm, imm8 - Packed Align Right
// Concatenates dst:src into 256-bit value, shifts right by imm*8 bits, takes low 128
void helper_palignr(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint8_t temp[32];
    memcpy(temp, &cpu->xmm[src_idx], 16);      // low 128 bits = src
    memcpy(temp + 16, &cpu->xmm[dst_idx], 16);  // high 128 bits = dst
    uint8_t result[16];
    if (imm >= 32) {
        memset(result, 0, 16);
    } else {
        for (int i = 0; i < 16; i++) {
            int idx = i + imm;
            result[i] = (idx < 32) ? temp[idx] : 0;
        }
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PSHUFB xmm, xmm - Packed Shuffle Bytes (SSSE3)
// For each byte in dst: if src byte bit 7 is set, result byte = 0;
// otherwise result byte = dst[src_byte & 0xF]
void helper_pshufb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 16; i++) {
        if (src[i] & 0x80)
            result[i] = 0;
        else
            result[i] = dst[src[i] & 0xF];
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// ============================================================================
// SHA Extension Helper Functions
// ============================================================================

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 Σ0(a) = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
static inline uint32_t sha256_Sigma0(uint32_t a) {
    return rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
}

// SHA-256 Σ1(e) = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
static inline uint32_t sha256_Sigma1(uint32_t e) {
    return rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
}

// SHA-256 Ch(e,f,g) = (e & f) ^ (~e & g)
static inline uint32_t sha256_Ch(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

// SHA-256 Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
static inline uint32_t sha256_Maj(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

// SHA-256 σ0(w) = ROTR(w,7) ^ ROTR(w,18) ^ SHR(w,3)
static inline uint32_t sha256_sigma0(uint32_t w) {
    return rotr32(w, 7) ^ rotr32(w, 18) ^ (w >> 3);
}

// SHA-256 σ1(w) = ROTR(w,17) ^ ROTR(w,19) ^ SHR(w,10)
static inline uint32_t sha256_sigma1(uint32_t w) {
    return rotr32(w, 17) ^ rotr32(w, 19) ^ (w >> 10);
}

// SHA256RNDS2 xmm1, xmm2, <XMM0>
// Performs 2 rounds of SHA-256 compression
// SRC1 (dst) = {C, D, G, H} = dst[127:96]=C, dst[95:64]=D, dst[63:32]=G, dst[31:0]=H
// SRC2       = {A, B, E, F} = src[127:96]=A, src[95:64]=B, src[63:32]=E, src[31:0]=F
// XMM0       = {?, ?, WK1, WK0} = xmm0[31:0]=WK0, xmm0[63:32]=WK1
void helper_sha256rnds2(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4], wk[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    memcpy(wk, &cpu->xmm[0], 8);  // only low 64 bits of XMM0

    uint32_t A = src[3], B = src[2], C = dst[3], D = dst[2];
    uint32_t E = src[1], F = src[0], G = dst[1], H = dst[0];

    // Round 0
    uint32_t T1 = H + sha256_Sigma1(E) + sha256_Ch(E, F, G) + wk[0];
    uint32_t T2 = sha256_Sigma0(A) + sha256_Maj(A, B, C);
    H = G; G = F; F = E; E = D + T1;
    D = C; C = B; B = A; A = T1 + T2;

    // Round 1
    T1 = H + sha256_Sigma1(E) + sha256_Ch(E, F, G) + wk[1];
    T2 = sha256_Sigma0(A) + sha256_Maj(A, B, C);
    H = G; G = F; F = E; E = D + T1;
    D = C; C = B; B = A; A = T1 + T2;

    // Result: dst = {A, B, E, F}
    uint32_t result[4] = { F, E, B, A };
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// SHA256MSG1 xmm1, xmm2
// Intermediate computation for SHA-256 message schedule
// dst = W[3:0], src = W[7:4]
// For each i: dst[i] += σ0(next_word)
// where next_word is: dst[1],dst[2],dst[3],src[0] for i=0,1,2,3
void helper_sha256msg1(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);

    uint32_t w[5] = { dst[0], dst[1], dst[2], dst[3], src[0] };
    uint32_t result[4];
    for (int i = 0; i < 4; i++)
        result[i] = dst[i] + sha256_sigma0(w[i + 1]);
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// SHA256MSG2 xmm1, xmm2
// Final computation for SHA-256 message schedule
// SRC = {W17, W16, W15, W14} (src[0]=W14, src[1]=W15, src[2]=W16, src[3]=W17)
// DST contains partial sums
// W16 = dst[0] + σ1(src[2])  -- src[2]=W14
// W17 = dst[1] + σ1(src[3])  -- src[3]=W15
// W18 = dst[2] + σ1(W16)
// W19 = dst[3] + σ1(W17)
void helper_sha256msg2(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);

    uint32_t W16 = dst[0] + sha256_sigma1(src[2]);
    uint32_t W17 = dst[1] + sha256_sigma1(src[3]);
    uint32_t W18 = dst[2] + sha256_sigma1(W16);
    uint32_t W19 = dst[3] + sha256_sigma1(W17);

    uint32_t result[4] = { W16, W17, W18, W19 };
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

// Diagnostic helper: dump x25519 inputs and output
static void dump_hex(const char *label, uint8_t *buf, int len) {
    fprintf(stderr, "%s: ", label);
    for (int i = 0; i < len; i++)
        fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\n");
}

void helper_trace_regs(struct cpu_state *cpu, uint64_t guest_ip) {
    // APK signature verification tracing
    // libapk.so.2.14.0 base address (from mmap log)
    uint64_t apk_base = 0x7effffa41000ULL;  // mmap_text(0x7effffa4a000) - text_vaddr(0x9000)
    uint64_t offset = guest_ip - apk_base;

    // Log ALL trace hits for debugging
    fprintf(stderr, "[APK-TRACE] ip=%#llx offset=%#llx\n",
           (unsigned long long)guest_ip, (unsigned long long)offset);

    // mpart_cb entry (0x10011)
    // At entry: rdi=sign_ctx (saved to rbx), esi=part, rcx=data.ptr, edx=data.len
    if (offset == 0x10011ULL) {
        uint32_t part = (uint32_t)(cpu->rsi & 0xFFFFFFFF);
        // Read flags byte from sign_ctx+0x14 (rdi points to sign_ctx at entry)
        uint64_t sctx = cpu->rdi;
        void *flags_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x14), MEM_READ);
        uint8_t flags = flags_ptr ? *(uint8_t*)flags_ptr : 0xFF;
        void *algo_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x04), MEM_READ);
        uint32_t algo = algo_ptr ? *(uint32_t*)algo_ptr : 0;
        void *action_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x00), MEM_READ);
        uint32_t action = action_ptr ? *(uint32_t*)action_ptr : 0;
        const char *part_name = (part == 1) ? "DATA" : (part == 2) ? "BOUNDARY" : (part == 3) ? "END" : "?";
        fprintf(stderr, "[APK] mpart_cb: part=%s(%d) flags=0x%02x algo=%d action=%d data.len=%u sctx=%#llx\n",
               part_name, part, flags, algo, action,
               (uint32_t)(cpu->rdx & 0xFFFFFFFF),
               (unsigned long long)sctx);
    }

    // -129 ("BAD signature") return at 0x10059
    if (offset == 0x10059ULL) {
        fprintf(stderr, "[APK] *** BAD SIGNATURE (-129) RETURN at 0x10059 ***\n");
        // rbx = sign_ctx at this point
        uint64_t sctx = cpu->rbx;
        void *flags_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x14), MEM_READ);
        uint8_t flags = flags_ptr ? *(uint8_t*)flags_ptr : 0xFF;
        void *algo_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x04), MEM_READ);
        uint32_t algo = algo_ptr ? *(uint32_t*)algo_ptr : 0;
        fprintf(stderr, "[APK]   sctx=%#llx flags=0x%02x algo=%d ebp(part)=%d\n",
               (unsigned long long)sctx, flags, algo,
               (int32_t)(cpu->rbp & 0xFFFFFFFF));
    }

    // First memcmp (data hash check) at 0x100eb
    // rdi=computed, rsi=expected(sctx+0x15), rdx=length
    if (offset == 0x100ebULL) {
        int len = (int)(cpu->rdx & 0xFF);
        if (len > 64) len = 64;
        fprintf(stderr, "[APK] memcmp#1 (data hash): computed=%#llx expected=%#llx len=%d\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi, len);
        // Read hash bytes directly from sctx (rbx=sctx)
        uint64_t sctx = cpu->rbx;
        fprintf(stderr, "[APK]   sctx=%#llx rbx=%#llx rdi=%#llx rbp=%#llx\n",
               (unsigned long long)sctx, (unsigned long long)cpu->rbx,
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rbp);
        // Read expected hash from sctx+0x15
        fprintf(stderr, "[APK]   EXPECTED(sctx+0x15): ");
        for (int i = 0; i < len; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x15 + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else { fprintf(stderr, "??"); }
        }
        fprintf(stderr, "\n");
        // Read computed hash from rdi
        fprintf(stderr, "[APK]   COMPUTED(rdi): ");
        for (int i = 0; i < len; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(cpu->rdi + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else { fprintf(stderr, "??"); }
        }
        fprintf(stderr, "\n");
    }

    // Second memcmp (checksum check) at 0x1021c
    // rdi=computed(r12), rsi=expected(sctx+0x55), rdx=length(from 0x69)
    if (offset == 0x1021cULL) {
        int len = (int)(cpu->rdx & 0xFF);
        if (len > 64) len = 64;
        fprintf(stderr, "[APK] memcmp#2 (checksum): computed=%#llx expected=%#llx len=%d\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi, len);
        uint64_t sctx = cpu->rbx;
        // Read expected hash from sctx+0x55
        fprintf(stderr, "[APK]   EXPECTED(sctx+0x55): ");
        for (int i = 0; i < len; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x55 + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else { fprintf(stderr, "??"); }
        }
        fprintf(stderr, "\n");
        // Read computed hash from rdi
        fprintf(stderr, "[APK]   COMPUTED(rdi): ");
        for (int i = 0; i < len; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(cpu->rdi + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else { fprintf(stderr, "??"); }
        }
        fprintf(stderr, "\n");
    }

    // VERIFY_IDENTITY path (0x10247): EVP_DigestFinal_ex → sctx+0x55
    if (offset == 0x10247ULL) {
        fprintf(stderr, "[APK] verify_identity path at 0x10247 (ip=%#llx)\n",
               (unsigned long long)guest_ip);
    }

    // -ECANCELED return at 0x10273
    if (offset == 0x10273ULL) {
        fprintf(stderr, "[APK] -ECANCELED (-125) return at 0x10273\n");
        uint64_t sctx = cpu->rbx;
        void *flags_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x14), MEM_READ);
        uint8_t flags = flags_ptr ? *(uint8_t*)flags_ptr : 0xFF;
        fprintf(stderr, "[APK]   flags=0x%02x (has_data_checksum=%d)\n",
               flags, (flags >> 2) & 1);
    }

    // algo dispatch at 0x10127 (skip sig verification, go to algo switch)
    if (offset == 0x10127ULL) {
        fprintf(stderr, "[APK] algo dispatch at 0x10127\n");
        uint64_t sctx = cpu->rbx;
        void *algo_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x04), MEM_READ);
        uint32_t algo = algo_ptr ? *(uint32_t*)algo_ptr : 0;
        fprintf(stderr, "[APK]   algo=%d\n", algo);
    }

    // apk_pkg_read after apk_tar_parse returns (0x11a4d)
    // eax = return value from tar_parse
    if (offset == 0x11a4dULL) {
        fprintf(stderr, "[APK] apk_pkg_read: tar_parse returned %d (0x%x)\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF),
               (uint32_t)(cpu->rax & 0xFFFFFFFF));
    }

    // apk_pkg_read error path at 0x11ab3 (-ENOMSG = -95)
    if (offset == 0x11ab3ULL) {
        fprintf(stderr, "[APK] apk_pkg_read: returning -95 (ENOMSG)\n");
    }

    // process_file entry (0x11199)
    if (offset == 0x11199ULL) {
        // rdi=sign_ctx, rsi=file_info, rdx=istream
        fprintf(stderr, "[APK] process_file: sctx=%#llx fi=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi);
    }

    // EVP_DigestUpdate at 0x102bf (BOUNDARY+data_started / DATA path)
    // At this point: rdi=ctx, rsi=data.ptr(r12), rdx=data.len
    if (offset == 0x102bfULL) {
        uint64_t data_ptr = cpu->rsi;
        uint64_t data_len = cpu->rdx;
        uint64_t ctx = cpu->rdi;
        fprintf(stderr, "[APK] EVP_DigestUpdate@0x102bf: ptr=%#llx len=%llu ctx=%#llx\n",
               (unsigned long long)data_ptr, (unsigned long long)data_len,
               (unsigned long long)ctx);
        // Check SHA256 state at algctx (ctx+0x38) to detect corruption
        if (ctx) {
            void *algctx_ptr = mmu_translate(cpu->mmu, (addr_t)(ctx + 0x38), MEM_READ);
            uint64_t algctx = algctx_ptr ? *(uint64_t*)algctx_ptr : 0;
            if (algctx && data_len == 29063) {
                // SHA256 IV check: first 32 bytes should be the standard IV
                static const uint8_t sha256_iv[] = {
                    0x67,0xe6,0x09,0x6a, 0x85,0xae,0x67,0xbb,
                    0x72,0xf3,0x6e,0x3c, 0x3a,0xf5,0x4f,0xa5,
                    0x7f,0x52,0x0e,0x51, 0x8c,0x68,0x05,0x9b,
                    0xab,0xd9,0x83,0x1f, 0x19,0xcd,0xe0,0x5b
                };
                int corrupted = 0;
                fprintf(stderr, "[APK]   SHA256 state at algctx=%#llx: ", (unsigned long long)algctx);
                for (int i = 0; i < 32; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    uint8_t b = bp ? *(uint8_t*)bp : 0xFF;
                    fprintf(stderr, "%02x", b);
                    if (b != sha256_iv[i]) corrupted = 1;
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
                if (corrupted) {
                    fprintf(stderr, "[APK]   *** SHA256 STATE CORRUPTED BEFORE DIGESTUPDATE! ***\n");
                } else {
                    fprintf(stderr, "[APK]   SHA256 IV intact before DigestUpdate\n");
                }
                // Also dump Nl, Nh, num counters (after h[8])
                fprintf(stderr, "[APK]   counters (Nl,Nh,data[0..3],num,md_len): ");
                for (int i = 32; i < 64; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    else fprintf(stderr, "??");
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
            }
        }
        // Read first 16 bytes of data
        fprintf(stderr, "[APK]   first 16 bytes: ");
        for (int i = 0; i < 16 && (uint64_t)i < data_len; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(data_ptr + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else { fprintf(stderr, "??"); }
        }
        fprintf(stderr, "\n");
        // For the tree package data (29063 bytes), dump full data to file for verification
        if (data_len == 29063) {
            FILE *dumpf = fopen("/tmp/apk_data_dump.bin", "wb");
            if (dumpf) {
                uint32_t checksum = 0;
                for (uint64_t off = 0; off < data_len; ) {
                    addr_t guest_addr = (addr_t)(data_ptr + off);
                    void *host_ptr = mmu_translate(cpu->mmu, guest_addr, MEM_READ);
                    if (!host_ptr) { fprintf(stderr, "[APK]   mmu_translate failed at off=%llu\n", (unsigned long long)off); break; }
                    uint64_t page_remaining = 4096 - (guest_addr & 0xFFF);
                    uint64_t data_remaining = data_len - off;
                    uint64_t chunk = (page_remaining < data_remaining) ? page_remaining : data_remaining;
                    fwrite(host_ptr, 1, chunk, dumpf);
                    // Compute simple checksum
                    for (uint64_t j = 0; j < chunk; j++)
                        checksum += ((uint8_t*)host_ptr)[j];
                    off += chunk;
                }
                fclose(dumpf);
                fprintf(stderr, "[APK]   dumped %llu bytes to /tmp/apk_data_dump.bin, checksum=0x%08x\n",
                       (unsigned long long)data_len, checksum);
            }
        }
    }

    // EVP_DigestUpdate at 0x1008a (main body - control hash / END path)
    // At this point: rdi=[rbx+0x70]=ctx, rsi=r12=data.ptr, rdx is passed from earlier
    if (offset == 0x1008aULL) {
        uint64_t data_ptr = cpu->rsi;
        // rdx may not be set properly here; r12 holds data.ptr but rdx was passed through
        // Actually looking at disasm: at 0x1008a, rdi=[rbx+0x70], rsi=r12, rdx=original from entry
        // BUT for END path, rdx was never explicitly set to data.len... hmm
        // Let's just log what we can
        fprintf(stderr, "[APK] EVP_DigestUpdate@0x1008a: rdi=%#llx rsi(data)=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)data_ptr);
    }

    // EVP_DigestInit_ex at 0x10288 (common tail - reinit for next phase)
    // rdi=[rbx+0x70]=ctx, rsi=[rbx+0x08]=EVP_MD*, rdx=0
    if (offset == 0x10288ULL) {
        uint64_t ctx = cpu->rdi;
        // Read flags at ctx+0x18 (unsigned long = 8 bytes on x86_64)
        void *flags_ptr = mmu_translate(cpu->mmu, (addr_t)(ctx + 0x18), MEM_READ);
        uint64_t flags = 0;
        if (flags_ptr) flags = *(uint64_t*)flags_ptr;
        int no_init = (flags >> 8) & 1;
        fprintf(stderr, "[APK] EVP_DigestInit_ex@0x10288: ctx=%#llx evp_md=%#llx flags=0x%llx NO_INIT=%d ONESHOT=%d\n",
               (unsigned long long)ctx, (unsigned long long)cpu->rsi,
               (unsigned long long)flags, no_init, (int)(flags & 1));
        // Also dump first 96 bytes of ctx to see structure
        fprintf(stderr, "[APK]   ctx dump: ");
        for (int i = 0; i < 96; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(ctx + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else fprintf(stderr, "??");
            if ((i % 8) == 7) fprintf(stderr, " ");
        }
        fprintf(stderr, "\n");
    }

    // After EVP_DigestInit_ex returns at 0x1028e
    // eax = return value (1=success, 0=failure)
    if (offset == 0x1028eULL) {
        int ret = (int)(cpu->rax & 0xFFFFFFFF);
        uint64_t ctx = cpu->rdi;  // rdi was set at 0x1028e: mov rdi, [rbx+0x70]
        // Actually at 0x1028e, rdi is being reloaded from [rbx+0x70]
        // Let me read rbx+0x70 to get ctx
        uint64_t sctx = cpu->rbx;
        void *ctx_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x70), MEM_READ);
        ctx = ctx_ptr ? *(uint64_t*)ctx_ptr : 0;
        fprintf(stderr, "[APK] EVP_DigestInit_ex returned %d, ctx=%#llx\n", ret, (unsigned long long)ctx);
        if (ctx) {
            // Dump ctx after init
            fprintf(stderr, "[APK]   ctx after init: ");
            for (int i = 0; i < 96; i++) {
                void *bp = mmu_translate(cpu->mmu, (addr_t)(ctx + i), MEM_READ);
                if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                else fprintf(stderr, "??");
                if ((i % 8) == 7) fprintf(stderr, " ");
            }
            fprintf(stderr, "\n");
            // Read algctx at ctx+0x38 (offset 56)
            void *algctx_ptr = mmu_translate(cpu->mmu, (addr_t)(ctx + 0x38), MEM_READ);
            uint64_t algctx = algctx_ptr ? *(uint64_t*)algctx_ptr : 0;
            fprintf(stderr, "[APK]   algctx=%#llx\n", (unsigned long long)algctx);
            if (algctx) {
                // Dump first 64 bytes of algctx (should contain SHA256 state h[0..7])
                // SHA256 IV in LE: 67e6096a 85ae67bb 72f36e3c 3af54fa5 7f520e51 8c68059b abd9831f 19cde05b
                fprintf(stderr, "[APK]   algctx dump (expect SHA256 IV): ");
                for (int i = 0; i < 64; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    else fprintf(stderr, "??");
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
            }
        }
    }

    // After EVP_DigestUpdate returns at 0x102c5 - dump SHA256 state
    if (offset == 0x102c5ULL) {
        // rbx = sctx, ctx is at [rbx+0x70]
        uint64_t sctx = cpu->rbx;
        void *ctx_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x70), MEM_READ);
        uint64_t ctx = ctx_ptr ? *(uint64_t*)ctx_ptr : 0;
        if (ctx) {
            void *algctx_ptr = mmu_translate(cpu->mmu, (addr_t)(ctx + 0x38), MEM_READ);
            uint64_t algctx = algctx_ptr ? *(uint64_t*)algctx_ptr : 0;
            if (algctx) {
                fprintf(stderr, "[APK] after DigestUpdate@0x102c5: algctx=%#llx\n",
                       (unsigned long long)algctx);
                // Dump h[0..7] (32 bytes) - should show intermediate SHA256 state
                fprintf(stderr, "[APK]   h[0..7]: ");
                for (int i = 0; i < 32; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    else fprintf(stderr, "??");
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
                // Dump Nl, Nh, num, md_len
                fprintf(stderr, "[APK]   counters: ");
                for (int i = 32; i < 56; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    else fprintf(stderr, "??");
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
                // Reference after processing 29063 bytes:
                // After 453 blocks (28992 bytes) by Update, then Final processes remaining
                // Full data SHA256 should be: 2ea9e4bca97b173e256ff21b3cf013d52810d73142951cffaed9a0f17b6a16dc
            }
        }
    }

    // sha256_block_data_order traces (libcrypto)
    uint64_t crypto_base = 0x7effffa89000ULL; // APK run: mmap 0x7effffada000 - text_vaddr 0x51000
    uint64_t crypto_offset = guest_ip - crypto_base;

    // Dispatch entry at 0x27f3c0
    if (crypto_offset == 0x27f3c0ULL) {
        fprintf(stderr, "[SHA256] sha256_block_data_order ENTRY: rdi(ctx)=%#llx rsi(data)=%#llx rdx(blocks)=%llu\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (unsigned long long)cpu->rdx);
        // Dump first 32 bytes of ctx (h[0..7])
        fprintf(stderr, "[SHA256]   ctx h[0..7]: ");
        for (int i = 0; i < 32; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(cpu->rdi + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else fprintf(stderr, "??");
            if ((i % 4) == 3) fprintf(stderr, " ");
        }
        fprintf(stderr, "\n");
        // Dump first 16 bytes of data
        fprintf(stderr, "[SHA256]   data[0..15]: ");
        for (int i = 0; i < 16; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(cpu->rsi + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else fprintf(stderr, "??");
        }
        fprintf(stderr, "\n");
    }

    // SSSE3 entry at 0x280900
    if (crypto_offset == 0x280900ULL) {
        fprintf(stderr, "[SHA256] SSSE3 path taken!\n");
    }

    // Basic entry at 0x27f41e
    if (crypto_offset == 0x27f41eULL) {
        fprintf(stderr, "[SHA256] BASIC path taken!\n");
    }


    // Common tail entry at 0x1027e
    if (offset == 0x1027eULL) {
        fprintf(stderr, "[APK] common_tail@0x1027e: rbx(sctx)=%#llx\n",
               (unsigned long long)cpu->rbx);
        uint64_t sctx = cpu->rbx;
        void *flags_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x14), MEM_READ);
        uint8_t flags = flags_ptr ? *(uint8_t*)flags_ptr : 0xFF;
        fprintf(stderr, "[APK]   flags=0x%02x\n", flags);
    }

    // algo==1 entry at 0x10161: check pkey
    if (offset == 0x10161ULL) {
        uint64_t sctx = cpu->rbx;
        void *pkey_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x88), MEM_READ);
        uint64_t pkey = pkey_ptr ? *(uint64_t*)pkey_ptr : 0;
        void *sig_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x80), MEM_READ);
        uint64_t sig = sig_ptr ? *(uint64_t*)sig_ptr : 0;
        void *siglen_ptr = mmu_translate(cpu->mmu, (addr_t)(sctx + 0x78), MEM_READ);
        uint32_t siglen = siglen_ptr ? *(uint32_t*)siglen_ptr : 0;
        fprintf(stderr, "[APK] algo==1 entry: pkey=%#llx sig=%#llx siglen=%u\n",
               (unsigned long long)pkey, (unsigned long long)sig, siglen);
    }

    // EVP_VerifyFinal call at 0x1017b
    if (offset == 0x1017bULL) {
        fprintf(stderr, "[APK] EVP_VerifyFinal: ctx(rdi)=%#llx sig(rsi)=%#llx siglen(edx)=%u pkey(rcx)=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (uint32_t)(cpu->rdx & 0xFFFFFFFF), (unsigned long long)cpu->rcx);
        // Dump first 16 bytes of signature
        fprintf(stderr, "[APK]   sig[0..15]: ");
        for (int i = 0; i < 16; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(cpu->rsi + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else fprintf(stderr, "??");
        }
        fprintf(stderr, "\n");
    }

    // After EVP_VerifyFinal returns at 0x10181
    if (offset == 0x10181ULL) {
        fprintf(stderr, "[APK] EVP_VerifyFinal returned: eax=%d\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF));
    }

    // Inside EVP_VerifyFinal_ex (crypto offsets):
    // After EVP_MD_CTX_test_flags at crypto 0x15a49d
    if (crypto_offset == 0x15a49dULL) {
        fprintf(stderr, "[VERIFY] test_flags(0x200) returned: eax=%d\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF));
    }

    // After EVP_MD_CTX_copy_ex at crypto 0x15a53b
    if (crypto_offset == 0x15a53bULL) {
        fprintf(stderr, "[VERIFY] EVP_MD_CTX_copy_ex returned: eax=%d\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF));
    }

    // Before EVP_DigestFinal_ex (copy path) at crypto 0x15a54f
    if (crypto_offset == 0x15a54fULL) {
        // rdi = ctx (either temp copy or original)
        uint64_t ctx = cpu->rdi;
        fprintf(stderr, "[VERIFY] before DigestFinal_ex: ctx(rdi)=%#llx\n",
               (unsigned long long)ctx);
        if (ctx) {
            void *algctx_ptr = mmu_translate(cpu->mmu, (addr_t)(ctx + 0x38), MEM_READ);
            uint64_t algctx = algctx_ptr ? *(uint64_t*)algctx_ptr : 0;
            fprintf(stderr, "[VERIFY]   algctx=%#llx\n", (unsigned long long)algctx);
            if (algctx) {
                // Dump SHA1 state: h[0..4]=20 bytes, Nl=4, Nh=4, data[0..63]=64, num=4
                fprintf(stderr, "[VERIFY]   SHA1 h[0..4]: ");
                for (int i = 0; i < 20; i++) {
                    void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + i), MEM_READ);
                    if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    if ((i % 4) == 3) fprintf(stderr, " ");
                }
                fprintf(stderr, "\n");
                // Nl, Nh at offset 20
                void *nl_ptr = mmu_translate(cpu->mmu, (addr_t)(algctx + 20), MEM_READ);
                void *nh_ptr = mmu_translate(cpu->mmu, (addr_t)(algctx + 24), MEM_READ);
                uint32_t nl = nl_ptr ? *(uint32_t*)nl_ptr : 0;
                uint32_t nh = nh_ptr ? *(uint32_t*)nh_ptr : 0;
                fprintf(stderr, "[VERIFY]   Nl=%#x (%u bits = %u bytes) Nh=%#x\n",
                       nl, nl, nl/8, nh);
                // num at offset 20+8+64=92
                void *num_ptr = mmu_translate(cpu->mmu, (addr_t)(algctx + 92), MEM_READ);
                uint32_t num = num_ptr ? *(uint32_t*)num_ptr : 0;
                fprintf(stderr, "[VERIFY]   num=%u (buffered bytes)\n", num);
                // Dump buffered data (first 64 bytes at offset 28)
                if (num > 0) {
                    fprintf(stderr, "[VERIFY]   buffered data: ");
                    for (uint32_t i = 0; i < num && i < 64; i++) {
                        void *bp = mmu_translate(cpu->mmu, (addr_t)(algctx + 28 + i), MEM_READ);
                        if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
                    }
                    fprintf(stderr, "\n");
                }
            }
        }
    }

    // After EVP_DigestFinal_ex (copy path) at crypto 0x15a555
    if (crypto_offset == 0x15a555ULL) {
        fprintf(stderr, "[VERIFY] EVP_DigestFinal_ex returned: eax=%d\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF));
        // Dump hash from [rsp+0x28] - need guest rsp
        uint64_t rsp = cpu->rsp;
        uint32_t hash_len = 0;
        void *hlen_ptr = mmu_translate(cpu->mmu, (addr_t)(rsp + 0x24), MEM_READ);
        if (hlen_ptr) hash_len = *(uint32_t*)hlen_ptr;
        fprintf(stderr, "[VERIFY]   hash_len=%u hash: ", hash_len);
        for (uint32_t i = 0; i < hash_len && i < 32; i++) {
            void *bp = mmu_translate(cpu->mmu, (addr_t)(rsp + 0x28 + i), MEM_READ);
            if (bp) fprintf(stderr, "%02x", *(uint8_t*)bp);
            else fprintf(stderr, "??");
        }
        fprintf(stderr, "\n");
    }

    // After EVP_PKEY_verify at crypto 0x15a5b7
    if (crypto_offset == 0x15a5b7ULL) {
        fprintf(stderr, "[VERIFY] EVP_PKEY_verify returned: eax=%d\n",
               (int32_t)(cpu->rax & 0xFFFFFFFF));
    }
}

#endif
