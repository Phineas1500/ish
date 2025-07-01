.global _start
.text
_start:
    mov $60, %rax       # sys_exit system call number
    mov $42, %rdi       # exit status
    syscall             # invoke system call