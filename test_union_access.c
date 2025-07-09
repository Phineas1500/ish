#include <stdio.h>
#include "emu/float80.h"

union f80 {
    float80 f;
    long double ld;
};

int main() {
    union f80 u;
    u.f = f80_from_int(123);
    printf("f80_from_int(123) via union access: %.20Le\n", u.ld);
    printf("f80_from_int(123) via f80_to_double: %g\n", f80_to_double(u.f));
    
    // Let's also check the raw memory layout
    printf("float80 layout: signif=0x%016llx, exp=0x%04x, sign=%d\n", 
           (unsigned long long)u.f.signif, u.f.exp, u.f.sign);
    
    // Check if long double is actually 80-bit or something else
    printf("sizeof(long double) = %zu\n", sizeof(long double));
    printf("sizeof(float80) = %zu\n", sizeof(float80));
    
    return 0;
}