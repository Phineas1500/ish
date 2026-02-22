#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
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
#ifdef ISH_GUEST_64BIT
    cpu->rax = tsc & 0xffffffff;  // zero-extended to 64 bits
    cpu->rdx = tsc >> 32;
#else
    cpu->eax = tsc & 0xffffffff;
    cpu->edx = tsc >> 32;
#endif
}

void helper_expand_flags(struct cpu_state *cpu) {
    expand_flags(cpu);
}

void helper_collapse_flags(struct cpu_state *cpu) {
    collapse_flags(cpu);
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

// PCMPEQB xmm, xmm - Compare packed bytes for equality
void helper_pcmpeqb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 16; i++)
        result[i] = (dst[i] == src[i]) ? 0xFF : 0;
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
void helper_paddb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 16; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_paddw(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 8; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_paddd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 4; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 16; i++)
        dst[i] -= src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubw(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 8; i++)
        dst[i] -= src[i];
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

void helper_pshufd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t imm) {
    uint32_t src[4], result[4];
    memcpy(src, src_addr, 16);
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

void helper_paddb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint8_t dst[16], src[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 16; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_paddw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 8; i++)
        dst[i] += src[i];
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

void helper_psubb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint8_t dst[16], src[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 16; i++)
        dst[i] -= src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 8; i++)
        dst[i] -= src[i];
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

// PADDQ xmm, xmm - Add packed 64-bit integers
void helper_paddq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 2; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_paddq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 2; i++)
        dst[i] += src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 2; i++)
        dst[i] -= src[i];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_psubq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 2; i++)
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

void helper_pcmpeqb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 16; i++)
        result[i] = (dst[i] == src[i]) ? 0xFF : 0;
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

// PSRLW xmm, imm8 - Packed Shift Right Logical Word (16-bit)
void helper_psrlw(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint16_t w[8];
    memcpy(w, &cpu->xmm[xmm_idx], 16);
    if (imm >= 16) {
        memset(w, 0, 16);
    } else {
        for (int i = 0; i < 8; i++) w[i] >>= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], w, 16);
}

// PSLLW xmm, imm8 - Packed Shift Left Logical Word (16-bit)
void helper_psllw(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    uint16_t w[8];
    memcpy(w, &cpu->xmm[xmm_idx], 16);
    if (imm >= 16) {
        memset(w, 0, 16);
    } else {
        for (int i = 0; i < 8; i++) w[i] <<= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], w, 16);
}

// PSRAW xmm, imm8 - Packed Shift Right Arithmetic Word (16-bit)
void helper_psraw(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    int16_t w[8];
    memcpy(w, &cpu->xmm[xmm_idx], 16);
    if (imm >= 16) {
        for (int i = 0; i < 8; i++) w[i] = (w[i] < 0) ? -1 : 0;
    } else {
        for (int i = 0; i < 8; i++) w[i] >>= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], w, 16);
}

// PSRAD xmm, imm8 - Packed Shift Right Arithmetic Doubleword
void helper_psrad(struct cpu_state *cpu, int xmm_idx, uint8_t imm) {
    int32_t dw[4];
    memcpy(dw, &cpu->xmm[xmm_idx], 16);
    if (imm >= 32) {
        for (int i = 0; i < 4; i++) dw[i] = (dw[i] < 0) ? -1 : 0;
    } else {
        for (int i = 0; i < 4; i++) dw[i] >>= imm;
    }
    memcpy(&cpu->xmm[xmm_idx], dw, 16);
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

// PCMPGTB xmm, xmm - Packed Compare Greater Than Bytes (signed)
void helper_pcmpgtb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    int8_t dst[16], src[16];
    uint8_t result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 16; i++)
        result[i] = (dst[i] > src[i]) ? 0xFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_pcmpgtb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    int8_t dst[16], src[16];
    uint8_t result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 16; i++)
        result[i] = (dst[i] > src[i]) ? 0xFF : 0;
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// UNPCKLPD xmm, xmm/m128 - Unpack Low Packed Doubles
// Same operation as PUNPCKLQDQ: dst[0] = dst[0], dst[1] = src[0]
void helper_unpcklpd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[1] = src[0];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_unpcklpd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[1] = src[0];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// UNPCKHPD xmm, xmm/m128 - Unpack High Packed Doubles
// Same operation as PUNPCKHQDQ: dst[0] = dst[1], dst[1] = src[1]
void helper_unpckhpd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    dst[0] = dst[1];
    dst[1] = src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

void helper_unpckhpd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[0] = dst[1];
    dst[1] = src[1];
    memcpy(&cpu->xmm[dst_idx], dst, 16);
}

// PUNPCKLQDQ xmm, m128 - Unpack Low Quadwords from memory
void helper_punpcklqdq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    dst[1] = src[0];
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

// MOVMSKPD r32, xmm - Move sign bits of packed doubles into integer
int helper_movmskpd(struct cpu_state *cpu, int src_idx) {
    uint64_t src[2];
    memcpy(src, &cpu->xmm[src_idx], 16);
    int mask = 0;
    if (src[0] >> 63) mask |= 1;
    if (src[1] >> 63) mask |= 2;
    return mask;
}

// MOVMSKPS r32, xmm - Move sign bits of packed singles into integer
int helper_movmskps(struct cpu_state *cpu, int src_idx) {
    uint32_t src[4];
    memcpy(src, &cpu->xmm[src_idx], 16);
    int mask = 0;
    for (int i = 0; i < 4; i++)
        if (src[i] >> 31) mask |= (1 << i);
    return mask;
}

// PEXTRW r32, xmm, imm8 - Extract word from XMM
int helper_pextrw(struct cpu_state *cpu, int src_idx, uint8_t imm) {
    uint16_t w[8];
    memcpy(w, &cpu->xmm[src_idx], 16);
    return w[imm & 7];
}

// PINSRW xmm, r32/m16, imm8 - Insert word into XMM
void helper_pinsrw(struct cpu_state *cpu, int dst_idx, uint16_t val, uint8_t imm) {
    uint16_t w[8];
    memcpy(w, &cpu->xmm[dst_idx], 16);
    w[imm & 7] = val;
    memcpy(&cpu->xmm[dst_idx], w, 16);
}

// CMPSD xmm, xmm/m64, imm8 - Compare Scalar Double-Precision FP
// Predicate: 0=EQ, 1=LT, 2=LE, 3=UNORD, 4=NEQ, 5=NLT, 6=NLE, 7=ORD
// Result: all-1s (0xFFFFFFFFFFFFFFFF) or all-0s in dst low qword
void helper_cmpsd(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t pred) {
    double a, b;
    memcpy(&a, &cpu->xmm[dst_idx], 8);
    memcpy(&b, &cpu->xmm[src_idx], 8);
    int result;
    switch (pred & 7) {
    case 0: result = (a == b); break;
    case 1: result = (a < b); break;
    case 2: result = (a <= b); break;
    case 3: result = __builtin_isunordered(a, b); break;
    case 4: result = (a != b); break;
    case 5: result = !(a < b); break;
    case 6: result = !(a <= b); break;
    case 7: result = !__builtin_isunordered(a, b); break;
    default: result = 0; break;
    }
    uint64_t mask = result ? 0xFFFFFFFFFFFFFFFFULL : 0;
    memcpy(&cpu->xmm[dst_idx], &mask, 8);
}

void helper_cmpsd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t pred) {
    double a, b;
    memcpy(&a, &cpu->xmm[dst_idx], 8);
    memcpy(&b, src_addr, 8);
    int result;
    switch (pred & 7) {
    case 0: result = (a == b); break;
    case 1: result = (a < b); break;
    case 2: result = (a <= b); break;
    case 3: result = __builtin_isunordered(a, b); break;
    case 4: result = (a != b); break;
    case 5: result = !(a < b); break;
    case 6: result = !(a <= b); break;
    case 7: result = !__builtin_isunordered(a, b); break;
    default: result = 0; break;
    }
    uint64_t mask = result ? 0xFFFFFFFFFFFFFFFFULL : 0;
    memcpy(&cpu->xmm[dst_idx], &mask, 8);
}

// CMPSS xmm, xmm, imm8 - Compare Scalar Single with predicate
void helper_cmpss(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t pred) {
    float a, b;
    memcpy(&a, &cpu->xmm[dst_idx], 4);
    memcpy(&b, &cpu->xmm[src_idx], 4);
    int result;
    switch (pred & 7) {
    case 0: result = (a == b); break;
    case 1: result = (a < b); break;
    case 2: result = (a <= b); break;
    case 3: result = __builtin_isunordered(a, b); break;
    case 4: result = (a != b); break;
    case 5: result = !(a < b); break;
    case 6: result = !(a <= b); break;
    case 7: result = !__builtin_isunordered(a, b); break;
    default: result = 0; break;
    }
    uint32_t mask = result ? 0xFFFFFFFFU : 0;
    memcpy(&cpu->xmm[dst_idx], &mask, 4);
}

void helper_cmpss_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t pred) {
    float a, b;
    memcpy(&a, &cpu->xmm[dst_idx], 4);
    memcpy(&b, src_addr, 4);
    int result;
    switch (pred & 7) {
    case 0: result = (a == b); break;
    case 1: result = (a < b); break;
    case 2: result = (a <= b); break;
    case 3: result = __builtin_isunordered(a, b); break;
    case 4: result = (a != b); break;
    case 5: result = !(a < b); break;
    case 6: result = !(a <= b); break;
    case 7: result = !__builtin_isunordered(a, b); break;
    default: result = 0; break;
    }
    uint32_t mask = result ? 0xFFFFFFFFU : 0;
    memcpy(&cpu->xmm[dst_idx], &mask, 4);
}

// PUNPCKLWD xmm, xmm - Unpack and interleave low words
void helper_punpcklwd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint16_t dst[8], src[8], result[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = dst[0]; result[1] = src[0];
    result[2] = dst[1]; result[3] = src[1];
    result[4] = dst[2]; result[5] = src[2];
    result[6] = dst[3]; result[7] = src[3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpcklwd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint16_t dst[8], src[8], result[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[0]; result[1] = src[0];
    result[2] = dst[1]; result[3] = src[1];
    result[4] = dst[2]; result[5] = src[2];
    result[6] = dst[3]; result[7] = src[3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PUNPCKLBW xmm, xmm - Unpack and interleave low bytes
void helper_punpcklbw(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 8; i++) {
        result[i*2] = dst[i];
        result[i*2+1] = src[i];
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpcklbw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 8; i++) {
        result[i*2] = dst[i];
        result[i*2+1] = src[i];
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PACKUSWB xmm, xmm - Pack with unsigned saturation (words to bytes)
void helper_packuswb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    int16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    uint8_t result[16];
    for (int i = 0; i < 8; i++)
        result[i] = (dst[i] < 0) ? 0 : (dst[i] > 255) ? 255 : (uint8_t)dst[i];
    for (int i = 0; i < 8; i++)
        result[i+8] = (src[i] < 0) ? 0 : (src[i] > 255) ? 255 : (uint8_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_packuswb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    int16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    uint8_t result[16];
    for (int i = 0; i < 8; i++)
        result[i] = (dst[i] < 0) ? 0 : (dst[i] > 255) ? 255 : (uint8_t)dst[i];
    for (int i = 0; i < 8; i++)
        result[i+8] = (src[i] < 0) ? 0 : (src[i] > 255) ? 255 : (uint8_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PACKSSWB xmm, xmm - Pack with signed saturation (words to bytes)
void helper_packsswb(struct cpu_state *cpu, int dst_idx, int src_idx) {
    int16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    int8_t result[16];
    for (int i = 0; i < 8; i++)
        result[i] = (dst[i] < -128) ? -128 : (dst[i] > 127) ? 127 : (int8_t)dst[i];
    for (int i = 0; i < 8; i++)
        result[i+8] = (src[i] < -128) ? -128 : (src[i] > 127) ? 127 : (int8_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_packsswb_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    int16_t dst[8], src[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    int8_t result[16];
    for (int i = 0; i < 8; i++)
        result[i] = (dst[i] < -128) ? -128 : (dst[i] > 127) ? 127 : (int8_t)dst[i];
    for (int i = 0; i < 8; i++)
        result[i+8] = (src[i] < -128) ? -128 : (src[i] > 127) ? 127 : (int8_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PACKSSDW xmm, xmm - Pack with signed saturation (dwords to words)
void helper_packssdw(struct cpu_state *cpu, int dst_idx, int src_idx) {
    int32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    int16_t result[8];
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] < -32768) ? -32768 : (dst[i] > 32767) ? 32767 : (int16_t)dst[i];
    for (int i = 0; i < 4; i++)
        result[i+4] = (src[i] < -32768) ? -32768 : (src[i] > 32767) ? 32767 : (int16_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_packssdw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    int32_t dst[4], src[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    int16_t result[8];
    for (int i = 0; i < 4; i++)
        result[i] = (dst[i] < -32768) ? -32768 : (dst[i] > 32767) ? 32767 : (int16_t)dst[i];
    for (int i = 0; i < 4; i++)
        result[i+4] = (src[i] < -32768) ? -32768 : (src[i] > 32767) ? 32767 : (int16_t)src[i];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PUNPCKHBW xmm, xmm - Unpack and interleave high bytes
void helper_punpckhbw(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    for (int i = 0; i < 8; i++) {
        result[i*2] = dst[i+8];
        result[i*2+1] = src[i+8];
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpckhbw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint8_t dst[16], src[16], result[16];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    for (int i = 0; i < 8; i++) {
        result[i*2] = dst[i+8];
        result[i*2+1] = src[i+8];
    }
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PUNPCKHWD xmm, xmm - Unpack and interleave high words
void helper_punpckhwd(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint16_t dst[8], src[8], result[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = dst[4]; result[1] = src[4];
    result[2] = dst[5]; result[3] = src[5];
    result[4] = dst[6]; result[5] = src[6];
    result[6] = dst[7]; result[7] = src[7];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpckhwd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint16_t dst[8], src[8], result[8];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[4]; result[1] = src[4];
    result[2] = dst[5]; result[3] = src[5];
    result[4] = dst[6]; result[5] = src[6];
    result[6] = dst[7]; result[7] = src[7];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PUNPCKHDQ xmm, xmm - Unpack and interleave high doublewords
void helper_punpckhdq(struct cpu_state *cpu, int dst_idx, int src_idx) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = dst[2]; result[1] = src[2];
    result[2] = dst[3]; result[3] = src[3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_punpckhdq_mem(struct cpu_state *cpu, int dst_idx, void *src_addr) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[2]; result[1] = src[2];
    result[2] = dst[3]; result[3] = src[3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PSHUFLW xmm, xmm/m128, imm8 - Shuffle Packed Low Words
// Shuffles low 4 words, copies high 4 words unchanged
void helper_pshuflw(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint16_t src[8], result[8];
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = src[(imm >> 0) & 3];
    result[1] = src[(imm >> 2) & 3];
    result[2] = src[(imm >> 4) & 3];
    result[3] = src[(imm >> 6) & 3];
    result[4] = src[4]; result[5] = src[5];
    result[6] = src[6]; result[7] = src[7];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_pshuflw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t imm) {
    uint16_t src[8], result[8];
    memcpy(src, src_addr, 16);
    result[0] = src[(imm >> 0) & 3];
    result[1] = src[(imm >> 2) & 3];
    result[2] = src[(imm >> 4) & 3];
    result[3] = src[(imm >> 6) & 3];
    result[4] = src[4]; result[5] = src[5];
    result[6] = src[6]; result[7] = src[7];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// PSHUFHW xmm, xmm/m128, imm8 - Shuffle Packed High Words
// Copies low 4 words unchanged, shuffles high 4 words
void helper_pshufhw(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint16_t src[8], result[8];
    memcpy(src, &cpu->xmm[src_idx], 16);
    result[0] = src[0]; result[1] = src[1];
    result[2] = src[2]; result[3] = src[3];
    result[4] = src[4 + ((imm >> 0) & 3)];
    result[5] = src[4 + ((imm >> 2) & 3)];
    result[6] = src[4 + ((imm >> 4) & 3)];
    result[7] = src[4 + ((imm >> 6) & 3)];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_pshufhw_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t imm) {
    uint16_t src[8], result[8];
    memcpy(src, src_addr, 16);
    result[0] = src[0]; result[1] = src[1];
    result[2] = src[2]; result[3] = src[3];
    result[4] = src[4 + ((imm >> 0) & 3)];
    result[5] = src[4 + ((imm >> 2) & 3)];
    result[6] = src[4 + ((imm >> 4) & 3)];
    result[7] = src[4 + ((imm >> 6) & 3)];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// SHUFPS xmm, m128, imm8 - memory form
void helper_shufps_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t imm) {
    uint32_t dst[4], src[4], result[4];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    result[0] = dst[(imm >> 0) & 3];
    result[1] = dst[(imm >> 2) & 3];
    result[2] = src[(imm >> 4) & 3];
    result[3] = src[(imm >> 6) & 3];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

// SHUFPD xmm, xmm/m128, imm8 - Shuffle Packed Double-Precision
// dst[0] = (imm8[0]) ? dst[1] : dst[0]
// dst[1] = (imm8[1]) ? src[1] : src[0]
void helper_shufpd(struct cpu_state *cpu, int dst_idx, int src_idx, uint8_t imm) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, &cpu->xmm[src_idx], 16);
    uint64_t result[2];
    result[0] = (imm & 1) ? dst[1] : dst[0];
    result[1] = (imm & 2) ? src[1] : src[0];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_shufpd_mem(struct cpu_state *cpu, int dst_idx, void *src_addr, uint8_t imm) {
    uint64_t dst[2], src[2];
    memcpy(dst, &cpu->xmm[dst_idx], 16);
    memcpy(src, src_addr, 16);
    uint64_t result[2];
    result[0] = (imm & 1) ? dst[1] : dst[0];
    result[1] = (imm & 2) ? src[1] : src[0];
    memcpy(&cpu->xmm[dst_idx], result, 16);
}

void helper_trace_regs(struct cpu_state *cpu, uint64_t guest_ip) {
    fprintf(stderr, "[TRACE] ip=%#llx rax=%#llx rbx=%#llx rcx=%#llx rdx=%#llx\n",
           (unsigned long long)guest_ip,
           (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx,
           (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
    fprintf(stderr, "[TRACE]  rsi=%#llx rdi=%#llx rbp=%#llx rsp=%#llx\n",
           (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi,
           (unsigned long long)cpu->rbp, (unsigned long long)cpu->rsp);
}

#endif
