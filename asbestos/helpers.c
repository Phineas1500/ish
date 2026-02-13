#include <stdio.h>
#include <time.h>
#include <string.h>
#include "emu/cpu.h"
#include "emu/mmu.h"
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
    do_cpuid(&a32, &b32, &c32, &d32);
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
    uint64_t lib_base = 0x7effffb2f000ULL;
    uint64_t offset = guest_ip - lib_base;

    // x25519_scalar_mult entry: rdi=out, rsi=point, rdx=scalar
    if (offset == 0xdb636ULL) {
        fprintf(stderr, "X25519 ENTRY: out=%#llx point=%#llx scalar=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (unsigned long long)cpu->rdx);
        void *h_point = mmu_translate(cpu->mmu, (addr_t)cpu->rsi, MEM_READ);
        void *h_scalar = mmu_translate(cpu->mmu, (addr_t)cpu->rdx, MEM_READ);
        if (h_point) dump_hex("  POINT", (uint8_t*)h_point, 32);
        if (h_scalar) dump_hex("  SCALAR", (uint8_t*)h_scalar, 32);
    }

    // fe_frombytes combining code start (0xdbc18: mov rdi, r10)
    // At this point: r10=load_7(s+0), rsi=load_6(s+7)<<5, r8=load_7(s+13)*4,
    //                r9=load_6(s+20)<<7, rax=load_6(s+26)
    if (offset == 0xdbc18ULL) {
        fprintf(stderr, "FE_FROMBYTES at 0xdbc18:\n");
        // Dump point data bytes from r14
        void *point_host = mmu_translate(cpu->mmu, (addr_t)cpu->r14, MEM_READ);
        if (point_host) {
            uint8_t *s = (uint8_t *)point_host;
            dump_hex("  POINT_DATA", s, 32);
            // Compute expected register values from actual point data
            // load_7_bytes(s+0): edx=s[4], eax=s[5], ecx=*(uint32_t*)(s)
            //   rax = (s[6]<<48) | (s[5]<<40) | (s[4]<<32) | *(uint32_t*)(s)
            uint64_t exp_r10 = ((uint64_t)s[6] << 48) | ((uint64_t)s[5] << 40) |
                               ((uint64_t)s[4] << 32) | *(uint32_t*)(s);
            // load_6_bytes(s+7): eax=s[11], edx=s[12], ecx=*(uint32_t*)(s+7)
            //   rax = (s[12]<<40) | (s[11]<<32) | *(uint32_t*)(s+7), then <<5
            uint64_t exp_rsi = (((uint64_t)s[12] << 40) | ((uint64_t)s[11] << 32) |
                                *(uint32_t*)(s+7)) << 5;
            // load_7_bytes(s+13) * 4
            uint64_t load7_13 = ((uint64_t)s[19] << 48) | ((uint64_t)s[18] << 40) |
                                ((uint64_t)s[17] << 32) | *(uint32_t*)(s+13);
            uint64_t exp_r8 = load7_13 * 4;
            // load_6_bytes(s+20) << 7
            uint64_t exp_r9 = (((uint64_t)s[25] << 40) | ((uint64_t)s[24] << 32) |
                               *(uint32_t*)(s+20)) << 7;
            // load_6_bytes(s+26)
            uint64_t exp_rax = ((uint64_t)s[31] << 40) | ((uint64_t)s[30] << 32) |
                               *(uint32_t*)(s+26);
            fprintf(stderr, "  r10 = %#018llx  expect %#018llx  %s\n",
                   (unsigned long long)cpu->r10, (unsigned long long)exp_r10,
                   cpu->r10 == exp_r10 ? "OK" : "MISMATCH!");
            fprintf(stderr, "  rsi = %#018llx  expect %#018llx  %s\n",
                   (unsigned long long)cpu->rsi, (unsigned long long)exp_rsi,
                   cpu->rsi == exp_rsi ? "OK" : "MISMATCH!");
            fprintf(stderr, "  r8  = %#018llx  expect %#018llx  %s\n",
                   (unsigned long long)cpu->r8, (unsigned long long)exp_r8,
                   cpu->r8 == exp_r8 ? "OK" : "MISMATCH!");
            fprintf(stderr, "  r9  = %#018llx  expect %#018llx  %s\n",
                   (unsigned long long)cpu->r9, (unsigned long long)exp_r9,
                   cpu->r9 == exp_r9 ? "OK" : "MISMATCH!");
            fprintf(stderr, "  rax = %#018llx  expect %#018llx  %s\n",
                   (unsigned long long)cpu->rax, (unsigned long long)exp_rax,
                   cpu->rax == exp_rax ? "OK" : "MISMATCH!");
        }
        fprintf(stderr, "  r14 = %#018llx  rdi = %#018llx\n",
                (unsigned long long)cpu->r14, (unsigned long long)cpu->rdi);
    }

    // After x25519_scalar_mult returns: rbx = output buffer
    if (offset == 0xdea36ULL) {
        void *host_out = mmu_translate(cpu->mmu, (addr_t)cpu->rbx, MEM_READ);
        if (host_out) {
            dump_hex("X25519 OUTPUT", (uint8_t*)host_out, 32);
        }
        fprintf(stderr, "  rax=%#llx (return value)\n", (unsigned long long)cpu->rax);
    }

    // Montgomery ladder loop head: dump bit index, bit value, swap flag, field elements
    if (offset == 0xdbd13ULL) {
        static int ladder_iter = 0;
        // At this point: eax = previous_bit (just loaded from [rsp+0x1c])
        //                ebp = bit counter (254 down to 0)
        // Field elements on stack: x2 at rsp+0x48, z2 at rsp+0x70, x3 at rsp+0x98, z3 at rsp+0xC0
        uint64_t rsp_val = cpu->rsp;
        int32_t bit_index = (int32_t)(cpu->rbp & 0xFFFFFFFF);  // ebp
        uint32_t prev_bit = (uint32_t)(cpu->rax & 0x1);

        // Read first limb of each field element from guest stack
        uint64_t x2_0 = 0, z2_0 = 0, x3_0 = 0, z3_0 = 0;
        void *p;
        p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + 0x48), MEM_READ);
        if (p) x2_0 = *(uint64_t*)p;
        p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + 0x70), MEM_READ);
        if (p) z2_0 = *(uint64_t*)p;
        p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + 0x98), MEM_READ);
        if (p) x3_0 = *(uint64_t*)p;
        p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + 0xC0), MEM_READ);
        if (p) z3_0 = *(uint64_t*)p;

        fprintf(stderr, "LADDER[%3d] bit_idx=%d prev_bit=%u x2[0]=%013llx z2[0]=%013llx x3[0]=%013llx z3[0]=%013llx\n",
               ladder_iter, bit_index, prev_bit,
               (unsigned long long)x2_0, (unsigned long long)z2_0,
               (unsigned long long)x3_0, (unsigned long long)z3_0);

        // For first 3 iterations, dump all 5 limbs of all 4 field elements
        if (ladder_iter < 3 || bit_index <= 1) {
            for (int fe = 0; fe < 4; fe++) {
                uint64_t fe_offset = (fe == 0) ? 0x48 : (fe == 1) ? 0x70 : (fe == 2) ? 0x98 : 0xC0;
                const char *fe_name = (fe == 0) ? "x2" : (fe == 1) ? "z2" : (fe == 2) ? "x3" : "z3";
                uint64_t limbs[5] = {0};
                for (int j = 0; j < 5; j++) {
                    p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + fe_offset + j*8), MEM_READ);
                    if (p) limbs[j] = *(uint64_t*)p;
                }
                fprintf(stderr, "  %s: [%013llx, %013llx, %013llx, %013llx, %013llx]\n",
                       fe_name,
                       (unsigned long long)limbs[0], (unsigned long long)limbs[1],
                       (unsigned long long)limbs[2], (unsigned long long)limbs[3],
                       (unsigned long long)limbs[4]);
            }
        }
        ladder_iter++;
    }

    // Montgomery ladder loop exit: dump final x2, z2 before inversion
    if (offset == 0xdbe85ULL) {
        uint64_t rsp_val = cpu->rsp;
        fprintf(stderr, "LADDER EXIT: ebp=%d\n", (int32_t)(cpu->rbp & 0xFFFFFFFF));
        for (int fe = 0; fe < 2; fe++) {
            uint64_t fe_offset = (fe == 0) ? 0x48 : 0x70;
            const char *fe_name = (fe == 0) ? "x2_final" : "z2_final";
            uint64_t limbs[5] = {0};
            void *p;
            for (int j = 0; j < 5; j++) {
                p = mmu_translate(cpu->mmu, (addr_t)(rsp_val + fe_offset + j*8), MEM_READ);
                if (p) limbs[j] = *(uint64_t*)p;
            }
            fprintf(stderr, "  %s: [%013llx, %013llx, %013llx, %013llx, %013llx]\n",
                   fe_name,
                   (unsigned long long)limbs[0], (unsigned long long)limbs[1],
                   (unsigned long long)limbs[2], (unsigned long long)limbs[3],
                   (unsigned long long)limbs[4]);
        }
    }

    // AES_encrypt entry: rdi=in, rsi=out, rdx=key_schedule
    // Only trace first 2 calls per connection
    {
        static int aes_trace_count = 0;
        if (offset == 0x4a5a0ULL && aes_trace_count < 20) {
            aes_trace_count++;
            fprintf(stderr, "AES_encrypt #%d: in=%#llx out=%#llx key=%#llx\n",
                   aes_trace_count,
                   (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
                   (unsigned long long)cpu->rdx);
            void *h_in = mmu_translate(cpu->mmu, (addr_t)cpu->rdi, MEM_READ);
            if (h_in) dump_hex("  AES INPUT", (uint8_t*)h_in, 16);
        }
    }

    // AES_encrypt return: dump output
    {
        static int aes_ret_count = 0;
        if (offset == 0x4a653ULL && aes_ret_count < 30) {
            aes_ret_count++;
            // r9 = output pointer (from movq 0x10(%rsp), %r9 at 0x4a61f)
            fprintf(stderr, "AES_encrypt #%d OUTPUT: r9=%#llx\n",
                   aes_ret_count, (unsigned long long)cpu->r9);
            void *h_out = mmu_translate(cpu->mmu, (addr_t)cpu->r9, MEM_READ);
            if (h_out) dump_hex("  AES OUTPUT", (uint8_t*)h_out, 16);
        }
    }


    // CRYPTO_gcm128_init ENTRY: rdi=ctx, rsi=key, rdx=encrypt_fn
    if (offset == 0x224851ULL) {
        fprintf(stderr, "GCM INIT ENTRY: ctx=%#llx key=%#llx encrypt_fn=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (unsigned long long)cpu->rdx);
    }

    // CRYPTO_gcm128_init: just before callq *%r8 (AES encrypt call)
    if (offset == 0x22487eULL) {
        fprintf(stderr, "GCM INIT CALL AES: in=%#llx out=%#llx key=%#llx fn=%#llx\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (unsigned long long)cpu->rdx, (unsigned long long)cpu->r8);
        void *h_in = mmu_translate(cpu->mmu, (addr_t)cpu->rdi, MEM_READ);
        if (h_in) dump_hex("  H INPUT (should be 0)", (uint8_t*)h_in, 16);
        void *h_key = mmu_translate(cpu->mmu, (addr_t)cpu->rdx, MEM_READ);
        if (h_key) dump_hex("  AES KEY SCHED (first 32 bytes)", (uint8_t*)h_key, 32);
        // Also dump the number of rounds (at offset 0xf0 in AES_KEY)
        void *h_nr = mmu_translate(cpu->mmu, (addr_t)(cpu->rdx + 0xf0), MEM_READ);
        if (h_nr) fprintf(stderr, "  AES rounds: %d\n", *(int*)h_nr);
    }

    // CRYPTO_gcm128_init: after H = AES_K(0^128) computed
    // At this point: rbx=ctx, rax=[ctx+0x50] (just loaded H high qword)
    if (offset == 0x224881ULL) {
        fprintf(stderr, "GCM INIT: ctx=%#llx (rbx)\n", (unsigned long long)cpu->rbx);
        void *h_val = mmu_translate(cpu->mmu, (addr_t)(cpu->rbx + 0x50), MEM_READ);
        if (h_val) dump_hex("  H value (AES_K(0))", (uint8_t*)h_val, 16);
        // Also dump EK0 at ctx+0x20 and GHASH accum at ctx+0x40
        void *ek0_init = mmu_translate(cpu->mmu, (addr_t)(cpu->rbx + 0x20), MEM_READ);
        if (ek0_init) dump_hex("  EK0 at init", (uint8_t*)ek0_init, 16);
    }

    // CRYPTO_gcm128_setiv: after setting counter block
    // At offset 0x224a51: movl %ebp, 0xc(%rbx) - stores final counter
    if (offset == 0x224a54ULL) {
        fprintf(stderr, "GCM SETIV: ctx=%#llx (rbx)\n", (unsigned long long)cpu->rbx);
        void *ctr_block = mmu_translate(cpu->mmu, (addr_t)cpu->rbx, MEM_READ);
        if (ctr_block) dump_hex("  Counter block J0", (uint8_t*)ctr_block, 16);
        // Also dump EK0 at ctx+0x20
        void *ek0 = mmu_translate(cpu->mmu, (addr_t)(cpu->rbx + 0x20), MEM_READ);
        if (ek0) dump_hex("  EK0 (encrypted J0)", (uint8_t*)ek0, 16);
    }


    // gcm_ghash_4bit entry: rdi=Xi, rsi=Htable, rdx=data, rcx=len
    if (offset == 0x225ae0ULL) {
        static int ghash_count = 0;
        ghash_count++;
        if (ghash_count <= 6) {
            uint64_t len = cpu->rcx;
            fprintf(stderr, "GHASH #%d: Xi=%#llx Htable=%#llx data=%#llx len=%llu\n",
                   ghash_count, (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
                   (unsigned long long)cpu->rdx, (unsigned long long)len);
            void *xi = mmu_translate(cpu->mmu, (addr_t)cpu->rdi, MEM_READ);
            if (xi) dump_hex("  Xi INPUT", (uint8_t*)xi, 16);
            // Dump ALL input data (up to 64 bytes for visibility)
            int dump_len = len < 64 ? (int)len : 64;
            void *data = mmu_translate(cpu->mmu, (addr_t)cpu->rdx, MEM_READ);
            if (data) dump_hex("  DATA", (uint8_t*)data, dump_len);
            if (ghash_count == 1) {
                void *htable = mmu_translate(cpu->mmu, (addr_t)cpu->rsi, MEM_READ);
                if (htable) dump_hex("  Htable[0:32]", (uint8_t*)htable, 32);
            }
        }
    }

    // gcm_ghash_4bit loop HEAD: xor r9, [r14]
    // At this point: r8=Xi_high, r9=Xi_low, r14=input_ptr
    if (offset == 0x225dd0ULL) {
        static int ghash_loop_count = 0;
        static int ghash_call_iter = 0;  // iteration within current GHASH call
        // Track which GHASH call we're in
        static uint64_t last_r15 = 0;
        if (cpu->r15 != last_r15) {
            ghash_call_iter = 0;  // new call
            last_r15 = cpu->r15;
        }
        int total_iters = (int)((cpu->r15 - cpu->r14) / 16) + 1;
        int iters_left = (int)((cpu->r15 - cpu->r14) / 16);
        // Trace first 5, every 50th, and last 3
        if (ghash_loop_count < 5 || (ghash_call_iter % 50 == 0) || iters_left <= 3) {
            fprintf(stderr, "GHASH_LOOP[%d] (call_iter=%d, left=%d) HEAD: r8=%016llx r9=%016llx r14=%#llx\n",
                   ghash_loop_count, ghash_call_iter, iters_left,
                   (unsigned long long)cpu->r8, (unsigned long long)cpu->r9,
                   (unsigned long long)cpu->r14);
            void *inp = mmu_translate(cpu->mmu, (addr_t)cpu->r14, MEM_READ);
            if (inp) dump_hex("  INPUT_BLOCK", (uint8_t*)inp, 16);
        }
        ghash_loop_count++;
        ghash_call_iter++;
    }

    // gcm_ghash_4bit loop TAIL: cmp r14, r15
    if (offset == 0x2262abULL) {
        static int ghash_tail_count = 0;
        int iters_left = (int)((cpu->r15 - cpu->r14) / 16);
        // Trace first 5, every 50th, and last 3
        if (ghash_tail_count < 5 || (ghash_tail_count % 50 == 0) || iters_left <= 3) {
            fprintf(stderr, "GHASH_LOOP[%d] (left=%d) TAIL: r8=%016llx r9=%016llx\n",
                   ghash_tail_count, iters_left,
                   (unsigned long long)cpu->r8, (unsigned long long)cpu->r9);
        }
        ghash_tail_count++;
    }

    // gcm_ghash_4bit EXIT: after mov [rdi+8], r8 and mov [rdi], r9
    if (offset == 0x2262bbULL) {
        static int ghash_exit_count = 0;
        ghash_exit_count++;
        fprintf(stderr, "GHASH_EXIT #%d: rdi=%#llx\n", ghash_exit_count,
               (unsigned long long)cpu->rdi);
        void *xi = mmu_translate(cpu->mmu, (addr_t)cpu->rdi, MEM_READ);
        if (xi) dump_hex("  Xi OUTPUT", (uint8_t*)xi, 16);
    }

    // ASN1_item_d2i: rdi=pval, rsi=const unsigned char **in, rdx=len, rcx=it
    if (offset == 0x706fcULL) {
        static int asn1_count = 0;
        asn1_count++;
        // Only trace X509 item (rcx == X509_it result) and keep it concise
        if (asn1_count <= 200) {
            void *in_ptr = mmu_translate(cpu->mmu, (addr_t)cpu->rsi, MEM_READ);
            if (in_ptr) {
                uint64_t data_ptr = *(uint64_t*)in_ptr;
                void *data = mmu_translate(cpu->mmu, (addr_t)data_ptr, MEM_READ);
                if (data) {
                    uint8_t *der = (uint8_t*)data;
                    // Only trace for SEQUENCE tag (top-level cert) with reasonable length
                    if (der[0] == 0x30 && cpu->rdx > 100) {
                        fprintf(stderr, "ASN1_item_d2i #%d: len=%lld DER[0:32]=",
                               asn1_count, (long long)cpu->rdx);
                        for (int i = 0; i < 32 && i < (int)cpu->rdx; i++)
                            fprintf(stderr, "%02x", der[i]);
                        fprintf(stderr, "\n");
                    }
                }
            }
        }
    }

    // ERR_set_error: rdi=lib, rsi=reason, rdx=fmt
    if (offset == 0x133ae8ULL) {
        static int err_count = 0;
        err_count++;
        if (err_count <= 500) {
            fprintf(stderr, "OpenSSL ERR #%d: lib=%lld reason=%lld\n",
                   err_count, (long long)cpu->rdi, (long long)cpu->rsi);
        }
    }

    // c2i_ibuf entry: after mov r10,rcx; mov rax,rdx
    // At this point: rdx=cont, rcx=plen, rdi=out_buf, rsi=pneg
    if (offset == 0x60228ULL) {
        static int c2i_count = 0;
        c2i_count++;
        if (c2i_count <= 200) {
            // rdx = cont (not yet moved to rax at trace point, but register state is at entry)
            // Actually at 0x60228, the instruction is mov r10,rcx. rdx still has cont.
            uint64_t cont = cpu->rdx;
            int64_t plen = (int64_t)cpu->rcx;
            void *data = mmu_translate(cpu->mmu, (addr_t)cont, MEM_READ);
            if (data && plen > 0 && plen < 32) {
                uint8_t *p = (uint8_t*)data;
                fprintf(stderr, "c2i_ibuf #%d: plen=%lld data=", c2i_count, (long long)plen);
                for (int i = 0; i < (int)plen && i < 20; i++)
                    fprintf(stderr, "%02x", p[i]);
                fprintf(stderr, "\n");
            }
        }
    }

    // c2i_ibuf illegal padding error: ERR_new call at 0x60296
    // At this point: rax=cont, r10=plen (maybe), ecx=movsbl(cont[0])
    if (offset == 0x60296ULL) {
        fprintf(stderr, "*** c2i_ibuf ILLEGAL PADDING ERROR ***\n");
        fprintf(stderr, "  rax=%#llx rcx=%#llx rdx=%#llx rsi=%#llx rdi=%#llx r10=%#llx\n",
               (unsigned long long)cpu->rax, (unsigned long long)cpu->rcx,
               (unsigned long long)cpu->rdx, (unsigned long long)cpu->rsi,
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->r10);
        // rax should still point to cont
        void *data = mmu_translate(cpu->mmu, (addr_t)cpu->rax, MEM_READ);
        if (data) {
            uint8_t *p = (uint8_t*)data;
            int plen = (int)cpu->r10;
            if (plen > 20) plen = 20;
            if (plen <= 0) plen = 8;
            fprintf(stderr, "  cont bytes: ");
            for (int i = 0; i < plen; i++)
                fprintf(stderr, "%02x", p[i]);
            fprintf(stderr, "\n");
        }
    }

    // X509_PUBKEY_get0: rdi=const X509_PUBKEY *key
    if (offset == 0x2af699ULL) {
        static int pubkey_count = 0;
        pubkey_count++;
        fprintf(stderr, "X509_PUBKEY_get0 #%d: key=%#llx\n",
               pubkey_count, (unsigned long long)cpu->rdi);
    }

    // d2i_X509: rdi=X509**, rsi=const unsigned char **in, rdx=len
    if (offset == 0x2b0c25ULL) {
        static int d2i_count = 0;
        d2i_count++;
        fprintf(stderr, "d2i_X509 #%d: a=%#llx in=%#llx len=%lld\n",
               d2i_count, (unsigned long long)cpu->rdi,
               (unsigned long long)cpu->rsi, (long long)cpu->rdx);
        // Dereference *in to get the data pointer
        void *in_ptr = mmu_translate(cpu->mmu, (addr_t)cpu->rsi, MEM_READ);
        if (in_ptr) {
            uint64_t data_ptr = *(uint64_t*)in_ptr;
            fprintf(stderr, "  *in=%#llx\n", (unsigned long long)data_ptr);
            void *data = mmu_translate(cpu->mmu, (addr_t)data_ptr, MEM_READ);
            if (data) {
                int dump_len = cpu->rdx < 64 ? (int)cpu->rdx : 64;
                dump_hex("  DER data (first 64)", (uint8_t*)data, dump_len);
            }
        }
    }

    // CRYPTO_gcm128_finish -> CRYPTO_memcmp: rdi=computed, rsi=expected, rdx=len
    if (offset == 0x2258daULL) {
        uint64_t tag_len = cpu->rdx;
        fprintf(stderr, "GCM TAG CHECK: computed=%#llx expected=%#llx len=%llu\n",
               (unsigned long long)cpu->rdi, (unsigned long long)cpu->rsi,
               (unsigned long long)tag_len);
        void *h_computed = mmu_translate(cpu->mmu, (addr_t)cpu->rdi, MEM_READ);
        void *h_expected = mmu_translate(cpu->mmu, (addr_t)cpu->rsi, MEM_READ);
        if (h_computed && tag_len <= 16) dump_hex("  COMPUTED TAG", (uint8_t*)h_computed, (int)tag_len);
        if (h_expected && tag_len <= 16) dump_hex("  EXPECTED TAG", (uint8_t*)h_expected, (int)tag_len);
    }

}

#endif
