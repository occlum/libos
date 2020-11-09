#include <unistd.h>
#include <spawn.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>

#include "test.h"

// ============================================================================
// Test cases for process group
// ============================================================================
int test_child_getpgid() {
    int pgid = getpgid(0);
    int ret, child_pid, status;

    printf("Run a parent process with pid = %d, ppid = %d, pgid = %d\n", getpid(), getppid(),
           pgid);

    ret = posix_spawn(&child_pid, "/bin/getpid", NULL, NULL, NULL, NULL);
    if (ret < 0) {
        printf("ERROR: failed to spawn a child process\n");
        return -1;
    }
    printf("Spawn a child proces successfully with pid = %d\n", child_pid);

    // child process group should have same pgid with parent
    int child_pgid = getpgid(child_pid);
    if (child_pgid != pgid) {
        THROW_ERROR("child process group error");
    }

    ret = wait4(-1, &status, 0, NULL);
    if (ret < 0) {
        printf("ERROR: failed to wait4 the child process\n");
        return -1;
    }
    printf("Child process exited with status = %d\n", status);

    return 0;
}

int test_self_setpgid() {
    int pid = getpid();
    int new_pgid;

    // make self process to be the leader of new process group
    if (setpgid(0, 0) != 0) {
        THROW_ERROR("set self process group error");
    }

    new_pgid = getpgid(0);
    if (new_pgid != pid) {
        THROW_ERROR("get process group error");
    }
    return 0;
}

int test_child_setpgid() {
    int ret, child_pid, status;
    posix_spawnattr_t attr;

    printf("Parent process: pid = %d, ppid = %d, pgid = %d\n", getpid(), getppid(),
           getpgid(0));

    // set child process spawn attribute
    ret = posix_spawnattr_init(&attr);
    if (ret != 0) {
        THROW_ERROR("init spawnattr error");
    }
    ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (ret != 0) {
        THROW_ERROR("set attribute flag error");
    }
    // child process will have its own process group
    ret = posix_spawnattr_setpgroup(&attr, 0);
    if (ret != 0) {
        THROW_ERROR("set process group attribute error");
    }

    ret = posix_spawn(&child_pid, "/bin/getpid", NULL, &attr, NULL, NULL);
    if (ret < 0) {
        printf("ERROR: failed to spawn a child process\n");
        return -1;
    }
    printf("Spawn a new proces successfully pid = %d\n", child_pid);

    // child pgid should be same as its pid
    int child_pgid = getpgid(child_pid);
    if (child_pgid != child_pid) {
        THROW_ERROR("child process group error");
    }

    ret = wait4(-1, &status, 0, NULL);
    if (ret < 0) {
        printf("ERROR: failed to wait4 the child process\n");
        return -1;
    }
    printf("Child process exited with status = %d\n", status);

    return 0;
}

int test_child_setpgid_to_other_child() {
    //int pgid = getpgid(0);
    int ret, first_child_pid, second_child_pid, status;
    posix_spawnattr_t attr;

    ret = posix_spawnattr_init(&attr);
    if (ret != 0) {
        THROW_ERROR("init spawnattr error");
    }

    ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (ret != 0) {
        THROW_ERROR("set attribute flag error");
    }

    // child process will have its own process group
    ret = posix_spawnattr_setpgroup(&attr, 0);
    if (ret != 0) {
        THROW_ERROR("set process group attribute error");
    }

    // We need the first child to run longer time to join his process group
    ret = posix_spawn(&first_child_pid, "/bin/spawn", NULL, &attr, NULL, NULL);
    if (ret < 0) {
        printf("ERROR: failed to spawn a child process\n");
        return -1;
    }
    printf("Spawn a new proces successfully pid = %d\n", first_child_pid);

    // child pgid should be same as its pid
    int child_pgid = getpgid(first_child_pid);
    if (child_pgid != first_child_pid) {
        THROW_ERROR("first child process group error");
    }

    // add the second child to the first child's process group
    ret = posix_spawnattr_setpgroup(&attr, child_pgid);
    ret = posix_spawn(&second_child_pid, "/bin/getpid", NULL, &attr, NULL, NULL);
    if (ret < 0) {
        THROW_ERROR("failed to spawn second child process\n");

    }

    // second child pgid should be same as the the first child pgid
    int second_child_pgid = getpgid(second_child_pid);
    if (second_child_pgid != child_pgid) {
        THROW_ERROR("second child process group error");
    }

    // parent process waits for all the child processes
    int wpid;
    while ((wpid = wait(&status)) > 0) {
        printf("Child process %d exited with status = %d\n", wpid, status);
    };

    return 0;
}

int test_setpgid_to_running_child() {
    int ret, child_pid, status;

    ret = posix_spawn(&child_pid, "/bin/getpid", NULL, NULL, NULL, NULL);
    if (ret != 0) {
        THROW_ERROR("failed to spawn a child process");
    }

    // set child pgrp to itself
    if (setpgid(child_pid, 0) == 0 || errno != EACCES)  {
        printf("child pgid = %d, errno = %d\n", getpgid(child_pid), errno);
        THROW_ERROR("set child process group error not catching");
    }

    ret = wait4(-1, &status, 0, NULL);
    if (ret < 0) {
        printf("ERROR: failed to wait4 the child process\n");
        return -1;
    }

    return 0;
}

int test_setpgid_non_existent_pgrp() {
    int ret, child_pid;
    posix_spawnattr_t attr;
    int non_existent_pgid = 10;

    // make self process to join a non-existent process group
    if (setpgid(0, non_existent_pgid) == 0 || errno != EPERM ) {
        THROW_ERROR("set self process group error not catching");
    }

    // set child process group to a non-existent pgroup
    ret = posix_spawnattr_init(&attr);
    if (ret != 0) {
        THROW_ERROR("init spawnattr error");
    }
    ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (ret != 0) {
        THROW_ERROR("set attribute flag error");
    }
    ret = posix_spawnattr_setpgroup(&attr, non_existent_pgid);
    if (ret != 0) {
        THROW_ERROR("set process group attribute error");
    }
    ret = posix_spawn(&child_pid, "/bin/getpid", NULL, &attr, NULL, NULL);
    if (ret == 0 || errno != EPERM ) {
        THROW_ERROR("child process spawn error not catching\n");
    }

    //posix_spawn will fail. No need to wait for child.

    return 0;
}

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    TEST_CASE(test_child_getpgid),
    TEST_CASE(test_self_setpgid),
    TEST_CASE(test_child_setpgid),
    TEST_CASE(test_child_setpgid_to_other_child),
    TEST_CASE(test_setpgid_to_running_child),
    TEST_CASE(test_setpgid_non_existent_pgrp),
};

int main() {
    int ret;
    ret = test_suite_run(test_cases, ARRAY_SIZE(test_cases));
    return ret;
}
