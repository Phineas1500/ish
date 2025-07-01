// Simple test program to verify R8-R10 extended registers work
#include <stdio.h>

int main() {
    unsigned long r8_val = 0x1234567890ABCDEF;
    unsigned long r9_val = 0xFEDCBA0987654321;
    unsigned long r10_val = 0xAABBCCDDEEFF0011;
    unsigned long result = 0;
    
    // Use inline assembly to test R8-R10 registers
    __asm__ volatile (
        "movq %1, %%r8\n\t"         // Load test value into R8
        "movq %2, %%r9\n\t"         // Load test value into R9  
        "movq %3, %%r10\n\t"        // Load test value into R10
        "addq %%r8, %%r9\n\t"       // Add R8 to R9
        "addq %%r10, %%r9\n\t"      // Add R10 to R9
        "movq %%r9, %0\n\t"         // Store result
        : "=m" (result)
        : "m" (r8_val), "m" (r9_val), "m" (r10_val)
        : "r8", "r9", "r10"
    );
    
    printf("R8: 0x%016lx\n", r8_val);
    printf("R9: 0x%016lx\n", r9_val);  
    printf("R10: 0x%016lx\n", r10_val);
    printf("Result (R8+R9+R10): 0x%016lx\n", result);
    
    // Expected: 0x1234567890ABCDEF + 0xFEDCBA0987654321 + 0xAABBCCDDEEFF0011
    unsigned long expected = r8_val + r9_val + r10_val;
    printf("Expected: 0x%016lx\n", expected);
    
    if (result == expected) {
        printf("SUCCESS: R8-R10 registers working correctly!\n");
        return 0;
    } else {
        printf("FAILED: R8-R10 register test failed!\n");
        return 1;
    }
}