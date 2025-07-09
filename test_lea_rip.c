// Test program with LEA RIP-relative instruction
int main() {
    char data[] = "test";
    void *ptr;
    // This should generate: leaq data(%rip), %rax
    asm("leaq %1(%%rip), %%rax; movq %%rax, %0" : "=m"(ptr) : "m"(data) : "rax");
    return 0;
}