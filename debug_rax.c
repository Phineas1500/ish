#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - run the 64-bit test
        execl("./build-64bit/ish", "ish", "-f", "alpine-64bit-processed", "/bin/busybox", "echo", "test", NULL);
        exit(1);
    } else if (pid > 0) {
        // Parent process - wait for child and check exit status
        int status;
        waitpid(pid, &status, 0);
        printf("Child exit code: %d\n", WEXITSTATUS(status));
        if (WIFSIGNALED(status)) {
            printf("Child killed by signal: %d\n", WTERMSIG(status));
        }
    }
    return 0;
}