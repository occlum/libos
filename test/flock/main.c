#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include "test.h"

// ============================================================================
// Helper structs & variables & functions
// ============================================================================

const char **g_argv;
int g_argc;
const char *g_file_path = "/root/test_flock_file.txt";
int g_fd;
off_t g_file_len = 128;

// Expected child arguments
const int child_argc = 2;
const char *child_argv[3] = {
    "flock",
    "child",
    NULL
};

static int open_or_create_file() {
    int flags = O_RDWR | O_CREAT;
    int mode = 00666;

    int fd = open(g_file_path, flags, mode);
    if (fd < 0) {
        THROW_ERROR("failed to open or create file");
    }
    if (ftruncate(fd, g_file_len) < 0) {
        THROW_ERROR("failed to expand the file len");
    }
    return fd;
}

static int remove_file() {
    if (unlink(g_file_path) < 0) {
        THROW_ERROR("failed to unlink the created file");
    }
    return 0;
}

// ============================================================================
// Test cases for file POSIX advisory lock
// ============================================================================

static int test_getlk() {
    struct flock fl = { F_RDLCK, SEEK_SET, 0, 0, 0 };
    if (fcntl(g_fd, F_GETLK, &fl) < 0) {
        THROW_ERROR("failed to call getlk");
    }
    if (fl.l_type != F_UNLCK) {
        THROW_ERROR("failed to get correct fl type");
    }
    return 0;
}

static int test_setlk() {
    struct flock fl = { F_RDLCK, SEEK_SET, 0, g_file_len / 2, 0 };
    if (fcntl(g_fd, F_SETLK, &fl) < 0) {
        THROW_ERROR("failed to call setlk");
    }
    fl.l_len = g_file_len;
    if (fcntl(g_fd, F_SETLK, &fl) < 0) {
        THROW_ERROR("failed to expand the lock");
    }
    fl.l_type = F_WRLCK;
    fl.l_len = g_file_len / 2;
    if (fcntl(g_fd, F_SETLK, &fl) < 0) {
        THROW_ERROR("failed change the lock type of existing lock");
    }
    return 0;
}

static int test_spawn_child_and_unlock() {
    int status, child_pid;
    int ret = posix_spawn(&child_pid,
                          "/bin/flock", NULL, NULL,
                          (char *const *)child_argv,
                          NULL);
    if (ret < 0) {
        THROW_ERROR("spawn process error");
    }
    printf("Spawn a child process with pid=%d\n", child_pid);
    // Sleep 3s for the child to run setlkw test and wait, is 3s enough?
    sleep(3);
    struct flock fl = { F_UNLCK, SEEK_SET, 0, 0, 0 };
    if (fcntl(g_fd, F_SETLK, &fl) < 0) {
        THROW_ERROR("failed to unlock the lock");
    }
    // Unlock the flock will cause child process to finish running
    ret = wait4(-1, &status, 0, NULL);
    if (ret < 0) {
        THROW_ERROR("failed to wait4 the child process");
    }
    if (!WIFEXITED(status)) {
        THROW_ERROR("test cases in child faild");
    }
    return 0;
}

// ============================================================================
// Child Test cases
// ============================================================================

static int test_child_getlk() {
    struct flock fl = { F_RDLCK, SEEK_SET, 0, g_file_len / 4, 0 };
    if (fcntl(g_fd, F_GETLK, &fl) < 0) {
        THROW_ERROR("failed to call getlk");
    }
    if (fl.l_type != F_WRLCK) {
        THROW_ERROR("failed to get correct fl type");
    }
    if (fl.l_pid == 0) {
        THROW_ERROR("failed to get correct fl pid");
    }
    if (fl.l_len != g_file_len / 2) {
        THROW_ERROR("failed to get correct fl len");
    }
    return 0;
}

static int test_child_setlk() {
    struct flock fl = { F_RDLCK, SEEK_SET, 0, g_file_len / 4, 0 };
    int res = fcntl(g_fd, F_SETLK, &fl);
    if (!(res < 0 && errno == EAGAIN)) {
        THROW_ERROR("failed to check the result of setlk with conflict lock");
    }
    return 0;
}

static int test_child_setlkw() {
    struct flock fl = { F_RDLCK, SEEK_SET, 0, g_file_len / 4, 0 };
    int res = fcntl(g_fd, F_SETLKW, &fl);
    if (res < 0 && errno != EINTR) {
        THROW_ERROR("failed to check the result of setlkw with conflict lock");
    }
    return 0;
}

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    TEST_CASE(test_getlk),
    TEST_CASE(test_setlk),
    TEST_CASE(test_spawn_child_and_unlock),
};

static test_case_t child_test_cases[] = {
    TEST_CASE(test_child_getlk),
    TEST_CASE(test_child_setlk),
    TEST_CASE(test_child_setlkw),
};

int main(int argc, const char *argv[]) {
    // Save argument for test cases
    g_argc = argc;
    g_argv = argv;
    g_fd = open_or_create_file();
    if (g_fd < 0) {
        THROW_ERROR("failed to open/create file");
    }
    // Test argc
    if (argc == 2) {
        if (test_suite_run(child_test_cases, ARRAY_SIZE(child_test_cases)) < 0) {
            THROW_ERROR("failed run child test");
        }
        close(g_fd);
    } else  {
        if (test_suite_run(test_cases, ARRAY_SIZE(test_cases)) < 0) {
            THROW_ERROR("failed run test");
        }
        close(g_fd);
        if (remove_file() < 0) {
            THROW_ERROR("failed to remove file after test");
        }
    }
    return 0;
}
