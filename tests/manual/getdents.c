#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main() {
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    char buf[1000];
    // Use direct syscall number for getdents64 (217 on x86)
    int count = syscall(217, fd, buf, sizeof(buf));
    if (count > 0) {
        write(STDOUT_FILENO, "getdents64 returned: ", 21);
        write(STDOUT_FILENO, buf, count < 100 ? count : 100);
        write(STDOUT_FILENO, "\n", 1);
    } else {
        write(STDOUT_FILENO, "getdents64 failed\n", 18);
    }
    close(fd);
    return 0;
}
