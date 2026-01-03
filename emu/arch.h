#ifndef EMU_ARCH_H
#define EMU_ARCH_H

// Guest architecture configuration
// ISH_GUEST_64BIT is defined by meson when guest_arch=x86_64

#ifdef ISH_GUEST_64BIT
    #define GUEST_ARCH_X86_64 1
    #define GUEST_ARCH_BITS 64
    #define GUEST_REG_COUNT 16
    #define GUEST_XMM_COUNT 16
#else
    #define GUEST_ARCH_X86 1
    #define GUEST_ARCH_BITS 32
    #define GUEST_REG_COUNT 8
    #define GUEST_XMM_COUNT 8
#endif

#endif // EMU_ARCH_H
