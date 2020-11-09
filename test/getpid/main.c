#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, const char *argv[]) {
    printf("Run a new process with pid = %d, ppid = %d, pgid = %d\n", getpid(), getppid(),
           getpgid(0));
    return 0;
}
