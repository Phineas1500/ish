#include <stdio.h>
#include <stdint.h>

// The actual macros from misc.h
#define PTR_ERR(ptr) (intptr_t) (ptr)
#define IS_ERR(ptr) ((uintptr_t) (ptr) > (uintptr_t) -0xfff)
#define ERR_PTR(err) (void *) (intptr_t) (err)

int main() {
    printf("Testing filesystem initialization error handling:\n");
    
    // Simulate generic_open returning -2 (ENOENT)
    void *fake_fd = (void *) -2;
    
    printf("fake_fd = %p\n", fake_fd);
    printf("IS_ERR(fake_fd) = %s\n", IS_ERR(fake_fd) ? "true" : "false");
    printf("PTR_ERR(fake_fd) = %ld\n", PTR_ERR(fake_fd));
    
    if (IS_ERR(fake_fd)) {
        printf("Error detected correctly! Should return ERR_PTR(PTR_ERR(fake_fd))\n");
        void *result = ERR_PTR(PTR_ERR(fake_fd));
        printf("ERR_PTR(PTR_ERR(fake_fd)) = %p\n", result);
    } else {
        printf("ERROR: IS_ERR failed to detect error value!\n");
    }
    
    return 0;
}