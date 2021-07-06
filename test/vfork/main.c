#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "test.h"

// Note: This test intends to test the case that child process directly calls _exit()
// after vfork. "exit", "_exit" and returning from main function are different.
// And here the exit function must be "_exit" to prevent undefined bevaviour.
int test_vfork_exit() {
    pid_t child_pid = vfork();
    if (child_pid == 0) {
        _exit(0);
    } else {
        printf ("Comming back to parent process from child with pid = %d\n", child_pid);
    }
    return 0;
}

int test_multiple_vfork_execve() {
    char **child_argv = calloc(1, sizeof(char *) * 2); // "hello_world", NULL
    child_argv[0] = strdup("naughty_child");
    for (int i = 0; i < 3; i++ ) {
        pid_t child_pid = vfork();
        if (child_pid == 0) {
            int ret = execve("/bin/naughty_child", child_argv, NULL);
            if (ret != 0) {
                printf("child process execve error");
            }
            _exit(1);
        } else {
            printf ("Comming back to parent process from child with pid = %d\n", child_pid);
            int ret = waitpid(child_pid, 0, 0);
            if (ret != child_pid) {
                THROW_ERROR("wait child error, child pid = %d\n", child_pid);
            }
        }
    }
    return 0;
}

// Create a pipe between parent and child and check file status.
int test_vfork_isolate_file_table() {
    int pipe_fds[2];
    // struct stat stat_bufs[2];
    if (pipe(pipe_fds) < 0) {
        THROW_ERROR("failed to create a pipe");
    }

    pid_t child_pid = vfork();
    if (child_pid == 0) {
        close(pipe_fds[1]); // close write end
        char **child_argv = calloc(1,
                                   sizeof(char *) * (5 + 1)); // naughty_child -t vfork reader_fd writer_fd
        child_argv[0] = "naughty_child";
        child_argv[1] = "-t";
        child_argv[2] = "vfork";
        asprintf(&child_argv[3], "%d", pipe_fds[0]);
        asprintf(&child_argv[4], "%d", pipe_fds[1]);
        int ret = execve("/bin/naughty_child", child_argv, NULL);
        if (ret != 0) {
            printf("child process execve error\n");
        }
        _exit(1);
    } else {
        printf ("Comming back to parent process from child with pid = %d\n", child_pid);
        if (close(pipe_fds[0]) < 0) { // close read end
            printf("close pipe reader error\n");
            goto parent_exit;
        }
        char *greetings = "Hello from parent\n";
        if (write(pipe_fds[1], greetings, strlen(greetings) + 1) < 0) {
            printf("parent write pipe error\n");
            goto parent_exit;
        }
        int ret = waitpid(child_pid, 0, 0);
        if (ret != child_pid) {
            THROW_ERROR("wait child error, child pid = %d\n", child_pid);
        }
    }

    return 0;

parent_exit:
    kill(child_pid, SIGKILL);
    exit(1);
}

static test_case_t test_cases[] = {
    TEST_CASE(test_vfork_exit),
    TEST_CASE(test_multiple_vfork_execve),
    TEST_CASE(test_vfork_isolate_file_table),
};

int main() {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
