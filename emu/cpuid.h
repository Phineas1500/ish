#ifndef CPUID_H
#define CPUID_H

#include "misc.h"

static inline void do_cpuid(dword_t *eax, dword_t *ebx, dword_t *ecx, dword_t *edx) {
    dword_t leaf = *eax;
    switch (leaf) {
        case 0:
            *eax = 0x01; // we support barely anything
            *ebx = 0x756e6547; // Genu
            *edx = 0x49656e69; // ineI
            *ecx = 0x6c65746e; // ntel
            break;
        case 1:
            *eax = 0x0; // say nothing about cpu model number
            *ebx = 0x0; // processor number 0, flushes 0 bytes on clflush
            *ecx = 0; // we support none of the features in ecx
            *edx = (1 << 0)  // fpu - x87 FPU on chip
                | (1 << 8)   // cx8 - CMPXCHG8B instruction
                | (1 << 15)  // cmov - conditional move instructions
                | (1 << 23)  // mmx
                | (1 << 24)  // fxsr - FXSAVE/FXRSTOR
                | (1 << 25)  // sse
                | (1 << 26)  // sse2
                ;
            break;
        case 0x80000000:
            // Report highest extended function supported
            *eax = 0x80000001;
            *ebx = *ecx = *edx = 0;
            break;
        case 0x80000001:
            // Extended processor info
            *eax = *ebx = *ecx = 0;
            *edx = (1 << 11)  // syscall/sysret
#ifdef ISH_64BIT
                | (1 << 29)   // long mode (64-bit)
#endif
                ;
            break;
        default: // if leaf is too high or unsupported
            *eax = *ebx = *ecx = *edx = 0;
            break;
    }
}

#endif
