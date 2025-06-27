#include "emu/cpu.h"
#include <stdio.h>

int main() {
    struct cpu_state cpu = {};
    printf("Initial IP: %llx\n", (unsigned long long)cpu_ip(&cpu));
    cpu_set_ip(&cpu, 0x1234);
    printf("After set IP: %llx\n", (unsigned long long)cpu_ip(&cpu));
    return 0;
}