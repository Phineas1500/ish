#include <stdio.h>
#include <string.h>
#include "emu/float80.h"

union f80 {
    float80 f;
    long double ld;
    unsigned char bytes[16];
};

int main() {
    union f80 u;
    memset(&u, 0, sizeof(u));
    
    u.f = f80_from_int(123);
    
    printf("Raw bytes of float80 structure:\n");
    for (int i = 0; i < 16; i++) {
        printf("byte[%2d] = 0x%02x\n", i, u.bytes[i]);
    }
    
    printf("\nInterpretation as long double (8 bytes): %.20Le\n", u.ld);
    printf("Correct conversion via f80_to_double: %g\n", f80_to_double(u.f));
    
    // Test with a manual long double
    long double native_123 = 123.0L;
    union f80 native;
    memset(&native, 0, sizeof(native));
    native.ld = native_123;
    
    printf("\nNative long double 123.0L bytes:\n");
    for (int i = 0; i < 16; i++) {
        printf("byte[%2d] = 0x%02x\n", i, native.bytes[i]);
    }
    
    return 0;
}