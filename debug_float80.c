#include <stdio.h>
#include <stdint.h>
#include "emu/float80.h"

void print_float80(const char* label, float80 f) {
    printf("%s: signif=0x%016llx, exp=0x%04x, sign=%d\n", 
           label, (unsigned long long)f.signif, f.exp, f.sign);
    printf("  -> as double: %g\n", f80_to_double(f));
}

int main() {
    printf("Testing float80 implementation:\n\n");
    
    // Test f80_from_int with simple values
    printf("=== f80_from_int tests ===\n");
    float80 f123 = f80_from_int(123);
    print_float80("f80_from_int(123)", f123);
    
    float80 f0 = f80_from_int(0);
    print_float80("f80_from_int(0)", f0);
    
    float80 f1 = f80_from_int(1);
    print_float80("f80_from_int(1)", f1);
    
    float80 f_neg1 = f80_from_int(-1);
    print_float80("f80_from_int(-1)", f_neg1);
    
    // Test constants
    printf("\n=== Constants ===\n");
    float80 one = (float80) {.signif = 0x8000000000000000, .exp = 0x3fff, .sign = 0};
    print_float80("manual 1.0", one);
    
    float80 two = f80_from_int(2);
    print_float80("f80_from_int(2)", two);
    
    return 0;
}