__asm__(".text\n"
".globl _start\n"
"_start:\n"
"    mov $60, %rax\n"    /* sys_exit */
"    xor %rbp, %rbp\n"   /* The specific instruction that was failing: 48 31 ed */
"    mov $42, %rdi\n"    /* exit code */
"    syscall\n");