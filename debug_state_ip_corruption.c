#include <stdio.h>
int main() {
    long long rbp = 0x12345678;
    printf("Before XOR: rbp = 0x%llx\n", rbp);
    rbp ^= rbp;
    printf("After XOR: rbp = 0x%llx\n", rbp);
    return 0;
}
