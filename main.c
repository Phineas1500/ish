#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <execinfo.h>
#include "kernel/calls.h"
#include "kernel/task.h"
#include "xX_main_Xx.h"

// Declared in helpers.c
void helper_debug_print_rip_history(void);

// Declared in kernel/task.h (thread-local)
#include "kernel/task.h"

static void sigsegv_handler(int sig) {
    void *array[50];
    int size;
    fprintf(stderr, "\n=== SIGSEGV caught ===\n");
    size = backtrace(array, 50);
    fprintf(stderr, "Backtrace (%d frames):\n", size);
    backtrace_symbols_fd(array, size, 2);
    // Print x86_64 register state
    if (current) {
        struct cpu_state *cpu = &current->cpu;
        fprintf(stderr, "x86_64 CPU state at crash:\n");
        fprintf(stderr, "  RIP=0x%llx RSP=0x%llx RBP=0x%llx\n",
                (unsigned long long)cpu->rip, (unsigned long long)cpu->rsp,
                (unsigned long long)cpu->rbp);
        fprintf(stderr, "  RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
                (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx,
                (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
        fprintf(stderr, "  RSI=0x%llx RDI=0x%llx\n",
                (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi);
    }
    helper_debug_print_rip_history();
    fprintf(stderr, "======================\n");
    _exit(139);
}

int main(int argc, char *const argv[]) {
    signal(SIGSEGV, sigsegv_handler);
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
