#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "test.h"

#define SYS_ut 363

int main(int argc, const char *argv[]) {
    if (argc == 1) {
        int ret = syscall(SYS_ut, NULL);
        if (ret == -1 && errno == ENOSYS) {
            printf("\033[31;1mWARNING:\033[0m\n"
                   "The unit tests are not compiled into occlum.\n"
                   "To compile the tests, add OCCLUM_UT=1 to the make command.\n\n");
            return 0;
        } else {
            return ret == 0 ? 0 : -1;
        }
    } else if (argc == 2) {
        // Assign the name_prefix, like net::socket::iovs::tests::test_iov to
        // NAME_PRE to run one specific test and untrusted::slice_ext::tests to
        // run tests inside the tests module. For example:
        // make test NAME_PRE=<name_prefix> TESTS=unit_test
        return syscall(SYS_ut, argv[1]) == 0 ? 0 : -1;
    } else {
        THROW_ERROR("At most one input is accepted.");
    }
}
