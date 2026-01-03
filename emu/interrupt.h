// Intel standard interrupts
// Any interrupt not handled specially becomes a SIGSEGV
#define INT_NONE -1
#define INT_DIV 0
#define INT_DEBUG 1
#define INT_NMI 2
#define INT_BREAKPOINT 3
#define INT_OVERFLOW 4
#define INT_BOUND 5
#define INT_UNDEFINED 6
#define INT_FPU 7 // do not try to use the fpu. instead, try to realize the truth: there is no fpu.
#define INT_DOUBLE 8 // interrupt during interrupt, i.e. interruptception
#define INT_GPF 13
#define INT_TIMER 32
#define INT_SYSCALL 0x80

#ifdef ISH_GUEST_64BIT
// x86_64 uses the syscall instruction instead of int 0x80
// This is a synthetic interrupt number used internally
#define INT_SYSCALL64 0x100
#endif
