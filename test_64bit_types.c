#include "misc.h"
#include <stdio.h>

int main() {
    printf("Testing 64-bit type definitions:\n");
    printf("sizeof(addr_t) = %zu bytes\n", sizeof(addr_t));
    printf("sizeof(uint_t) = %zu bytes\n", sizeof(uint_t));
    printf("sizeof(int_t) = %zu bytes\n", sizeof(int_t));
    
#ifdef ISH_64BIT
    printf("ISH_64BIT is defined - 64-bit mode\n");
    if (sizeof(addr_t) == 8) {
        printf("✓ 64-bit types working correctly\n");
        return 0;
    } else {
        printf("✗ 64-bit types not working\n");
        return 1;
    }
#else
    printf("ISH_64BIT not defined - 32-bit mode\n");
    if (sizeof(addr_t) == 4) {
        printf("✓ 32-bit types working correctly\n");
        return 0;
    } else {
        printf("✗ 32-bit types not working\n");
        return 1;
    }
#endif
}