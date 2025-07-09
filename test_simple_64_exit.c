/* Simple 64-bit test program that just exits */

void _exit(int status) {
    /* x86-64 exit syscall: syscall number 60 */
    __asm__ __volatile__ (
        "movq $60, %%rax\n\t"     /* sys_exit */
        "movq %0, %%rdi\n\t"      /* exit status */
        "syscall\n\t"
        :
        : "r" ((long)status)
        : "rax", "rdi"
    );
}

int main() {
    _exit(42);
}