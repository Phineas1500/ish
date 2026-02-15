#ifndef CPUID_H
#define CPUID_H

#include "misc.h"

static inline void do_cpuid(dword_t *eax, dword_t *ebx, dword_t *ecx, dword_t *edx) {
    dword_t leaf = *eax;
    switch (leaf) {
        case 0:
#ifdef ISH_GUEST_64BIT
            *eax = 0x07; // max supported leaf
#else
            *eax = 0x01; // we support barely anything
#endif
            *ebx = 0x756e6547; // Genu
            *edx = 0x49656e69; // ineI
            *ecx = 0x6c65746e; // ntel
            break;
        default: // if leaf is too high, use highest supported leaf
        case 1:
            *eax = 0x0; // say nothing about cpu model number
            *ebx = 0x0; // processor number 0, flushes 0 bytes on clflush
            *ecx = 0
#ifdef ISH_GUEST_64BIT
                | (1 << 0) // SSE3
                | (1 << 9) // SSSE3
#endif
                ;
            *edx = (1 << 0) // fpu
                | (1 << 15) // cmov
                | (1 << 23) // mmx
                | (1 << 26) // sse2
#ifdef ISH_GUEST_64BIT
                | (1 << 4) // tsc
                | (1 << 6) // pae (required for 64-bit)
                | (1 << 25) // sse
#endif
                ;
            break;
#ifdef ISH_GUEST_64BIT
        case 7:
            // Extended features (sub-leaf in ECX)
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
            break;
        case 0x80000000:
            *eax = 0x80000001; // max extended leaf
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
            break;
        case 0x80000001:
            *eax = 0;
            *ebx = 0;
            *ecx = (1 << 0); // LAHF/SAHF in 64-bit mode
            *edx = (1 << 0)  // fpu
                | (1 << 11) // SYSCALL/SYSRET
                | (1 << 29) // LM (Long Mode - x86_64)
                ;
            break;
#endif
    }
}

#endif
