#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <execinfo.h>
#include "kernel/calls.h"
#include "kernel/task.h"
#include "xX_main_Xx.h"

static void crash_handler(int sig) {
    void *array[50];
    int size;
    fprintf(stderr, "\n=== Signal %d caught ===\n", sig);
    size = backtrace(array, 50);
    fprintf(stderr, "Backtrace (%d frames):\n", size);
    backtrace_symbols_fd(array, size, 2);
    if (current) {
        struct cpu_state *cpu = &current->cpu;
#ifdef ISH_GUEST_64BIT
        fprintf(stderr, "x86_64 CPU state at crash:\n");
        fprintf(stderr, "  RIP=0x%llx RSP=0x%llx RBP=0x%llx\n",
                (unsigned long long)cpu->rip, (unsigned long long)cpu->rsp,
                (unsigned long long)cpu->rbp);
        fprintf(stderr, "  RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx,
                (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
        fprintf(stderr, "  RSI=0x%llx RDI=0x%llx\n",
                (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi);
#else
        fprintf(stderr, "x86 CPU state at crash:\n");
        fprintf(stderr, "  EIP=0x%x ESP=0x%x EBP=0x%x\n",
                cpu->eip, cpu->esp, cpu->ebp);
        fprintf(stderr, "  EAX=0x%x EBX=0x%x ECX=0x%x EDX=0x%x\n",
                cpu->eax, cpu->ebx, cpu->ecx, cpu->edx);
        fprintf(stderr, "  ESI=0x%x EDI=0x%x\n",
                cpu->esi, cpu->edi);
#endif
    }
    fprintf(stderr, "======================\n");
    _exit(128 + sig);
}

int main(int argc, char *const argv[]) {
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGFPE, crash_handler);
    char envp[100] = {0};
    if (getenv("TERM"))
        strcpy(envp, getenv("TERM") - strlen("TERM") - 1);
    int err = xX_main_Xx(argc, argv, envp);
    if (err < 0) {
        fprintf(stderr, "xX_main_Xx: %s\n", strerror(-err));
        return err;
    }
    do_mount(&procfs, "proc", "/proc", "", 0);
    do_mount(&devptsfs, "devpts", "/dev/pts", "", 0);
    task_run_current();
}
