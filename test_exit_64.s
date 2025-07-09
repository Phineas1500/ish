.text
.global _start

_start:
    movq $1, %rax
    movq $42, %rdi
    syscall