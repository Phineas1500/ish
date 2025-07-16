#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "kernel/calls.h"
#include "kernel/task.h"
#include "xX_main_Xx.h"

int main(int argc, char *const argv[]) {
#ifdef ISH_64BIT
    fprintf(stderr, "ISH 64-bit: main() reached with argc=%d\n", argc);
#else
    fprintf(stderr, "ISH: main() reached with argc=%d\n", argc);
#endif
    printf("main: ENTRY with argc=%d\n", argc);
    char envp[100] = {0};
    if (getenv("TERM")) {
        const char *term = getenv("TERM");
        snprintf(envp, sizeof(envp), "TERM=%s", term);
    }
    printf("main: calling xX_main_Xx\n");
    int err = xX_main_Xx(argc, argv, envp);
    if (err < 0) {
        fprintf(stderr, "xX_main_Xx: %s\n", strerror(-err));
        return err;
    }
    printf("main: xX_main_Xx succeeded, mounting filesystems\n");
    do_mount(&procfs, "proc", "/proc", "", 0);
    do_mount(&devptsfs, "devpts", "/dev/pts", "", 0);
    printf("main: calling task_run_current()\n");
    task_run_current();
}
