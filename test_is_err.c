#include <stdio.h>
#include <stdint.h>

// 64-bit version
#define IS_ERR_64(ptr) ((uintptr_t) (ptr) > (uintptr_t) -0xfff)
#define PTR_ERR_64(ptr) (intptr_t) (ptr)

// 32-bit version for comparison
#define IS_ERR_32(ptr) ((uint32_t) (ptr) > (uint32_t) -0xfff)
#define PTR_ERR_32(ptr) (int32_t) (ptr)

int main() {
    void *test_ptrs[] = {
        (void*)-1, (void*)-2, (void*)-4095, (void*)-4096,
        (void*)0x1000, (void*)0, NULL
    };
    
    printf("Testing IS_ERR behavior:\n");
    printf("sizeof(uintptr_t) = %zu\n", sizeof(uintptr_t));
    printf("sizeof(intptr_t) = %zu\n", sizeof(intptr_t));
    printf("\n");
    
    for (int i = 0; i < 7; i++) {
        void *ptr = test_ptrs[i];
        printf("ptr = %p\n", ptr);
        printf("  64-bit IS_ERR: %s\n", IS_ERR_64(ptr) ? "true" : "false");
        printf("  32-bit IS_ERR: %s\n", IS_ERR_32(ptr) ? "true" : "false");
        printf("  PTR_ERR_64: %ld\n", PTR_ERR_64(ptr));
        printf("  PTR_ERR_32: %d\n", PTR_ERR_32(ptr));
        printf("\n");
    }
    
    return 0;
}