#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sgx_report.h>
#include <sgx_quote.h>
#ifndef OCCLUM_DISABLE_DCAP
#include <sgx_ql_quote.h>
#include <sgx_qve_header.h>
#endif
#include "test.h"

// ============================================================================
// Test cases for TTY ioctls
// ============================================================================

int test_tty_ioctl_TIOCGWINSZ(void) {
    struct winsize winsize;
    if (isatty(STDOUT_FILENO)) {
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) < 0) {
            THROW_ERROR("failed to ioctl TIOCGWINSZ");
        }
    } else {
        // FIXME: /dev/tty should be opened. But it has not been implemented in Occlum yet.
        // So we just skip this test if STDOUT is redirected.
        printf("Warning: test_tty_ioctl_TIOCGWINSZ is skipped\n");
    }
    return 0;
}

int test_ioctl_TCGETS_TCSETS(void) {
    struct termios term;
    // FIXME: /dev/tty should be opened. But it has not been implemented in Occlum yet.
    // So we just skip this test if STDOUT is redirected.
    if (!isatty(STDOUT_FILENO)) {
        printf("Warning: test_tty_ioctl_TIOCGWINSZ is skipped\n");
        return 0;
    }

    if (ioctl(STDOUT_FILENO, TCGETS, &term) < 0) {
        THROW_ERROR("failed to ioctl TCGETS");
    }

    if (ioctl(STDOUT_FILENO, TCSETS, &term) < 0) {
        THROW_ERROR("failed to ioctl TCSETS");
    }

    const char *file_path = "/root/test_ioctl.txt";
    int flags = O_RDONLY | O_CREAT | O_TRUNC;
    int mode = 00666;
    int fd = open(file_path, flags, mode);
    if (fd < 0) {
        THROW_ERROR("failed to open test file");
    }

    int pipefds[2];
    int ret = pipe(pipefds);
    if (ret != 0) {
        THROW_ERROR("failed to create pipe");
    }

    ret = ioctl(fd, TCGETS, &term);
    if (ret != -1 || errno != ENOTTY) {
        THROW_ERROR("failed catch error");
    }

    ret = ioctl(pipefds[0], TCGETS, &term);
    if (ret != -1 || errno != ENOTTY) {
        THROW_ERROR("failed catch error");
    }

    close(fd);
    close(pipefds[0]);
    close(pipefds[1]);

    return 0;
}

// ============================================================================
// Test cases for SGX ioctls
// ============================================================================

typedef struct {
    sgx_report_data_t           report_data;        // input
    sgx_quote_sign_type_t       quote_type;         // input
    sgx_spid_t                  spid;               // input
    sgx_quote_nonce_t           nonce;              // input
    const uint8_t              *sigrl_ptr;          // input (optional)
    uint32_t                    sigrl_len;          // input (optional)
    uint32_t                    quote_buf_len;      // input
    union {
        uint8_t                *as_buf;
        sgx_quote_t            *as_quote;
    } quote;                                        // output
} sgxioc_gen_epid_quote_arg_t;

typedef struct {
    const sgx_target_info_t    *target_info;        // input (optinal)
    const sgx_report_data_t    *report_data;        // input (optional)
    sgx_report_t               *report;             // output
} sgxioc_create_report_arg_t;

#ifndef OCCLUM_DISABLE_DCAP
typedef struct {
    sgx_report_data_t      *report_data; // input
    uint32_t               *quote_len;   // input/output
    uint8_t                *quote_buf;   // output
} sgxioc_gen_dcap_quote_arg_t;

typedef struct {
    const uint8_t                 *quote_buf;                    // input
    uint32_t                      quote_size;                    // input
    uint32_t                      *collateral_expiration_status; // output
    sgx_ql_qv_result_t            *quote_verification_result;    // output
    uint32_t                      supplemental_data_size;        // input
    uint8_t                       *supplemental_data;            // output
} sgxioc_ver_dcap_quote_arg_t;
#endif

#define SGXIOC_IS_EDMM_SUPPORTED          _IOR('s', 0, int)
#define SGXIOC_GET_EPID_GROUP_ID          _IOR('s', 1, sgx_epid_group_id_t)
#define SGXIOC_GEN_EPID_QUOTE             _IOWR('s', 2, sgxioc_gen_epid_quote_arg_t)
#define SGXIOC_SELF_TARGET                _IOR('s', 3, sgx_target_info_t)
#define SGXIOC_CREATE_REPORT              _IOWR('s', 4, sgxioc_create_report_arg_t)
#define SGXIOC_VERIFY_REPORT              _IOW('s', 5, sgx_report_t)
#define SGXIOC_DETECT_DCAP_DRIVER         _IOR('s', 6, int)

#ifndef OCCLUM_DISABLE_DCAP
#define SGXIOC_GET_DCAP_QUOTE_SIZE        _IOR('s', 7, uint32_t)
#define SGXIOC_GEN_DCAP_QUOTE             _IOWR('s', 8, sgxioc_gen_dcap_quote_arg_t)
#define SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE _IOR('s', 9, uint32_t)
#define SGXIOC_VER_DCAP_QUOTE             _IOWR('s', 10, sgxioc_ver_dcap_quote_arg_t)
#endif

// The max number of retries if ioctl returns EBUSY
#define IOCTL_MAX_RETRIES       20

typedef int(*sgx_ioctl_test_body_t)(int sgx_fd);

static int do_SGXIOC_IS_EDMM_SUPPORTED(int sgx_fd) {
    int is_edmm_supported = 0;
    if (ioctl(sgx_fd, SGXIOC_IS_EDMM_SUPPORTED, &is_edmm_supported) < 0) {
        THROW_ERROR("failed to ioctl /dev/sgx");
    }

    printf("    SGX EDMM support: %d\n", is_edmm_supported);
    return 0;
}

static int do_SGXIOC_GET_EPID_GROUP_ID(int sgx_fd) {
    int nretries = 0;
    while (nretries < IOCTL_MAX_RETRIES) {
        sgx_epid_group_id_t epid_group_id = { 0 };
        int ret = ioctl(sgx_fd, SGXIOC_GET_EPID_GROUP_ID, &epid_group_id);
        if (ret == 0) {
            break;
        } else if (errno != EBUSY) {
            THROW_ERROR("failed to ioctl /dev/sgx");
        }

        printf("WARN: /dev/sgx is temporarily busy. Try again after 1 second.");
        sleep(1);
        nretries++;
    }
    if (nretries == IOCTL_MAX_RETRIES) {
        THROW_ERROR("failed to ioctl /dev/sgx due to timeout");
    }
    return 0;
}

static int do_SGXIOC_GEN_QUOTE(int sgx_fd) {
    uint8_t quote_buf[2048] = { 0 };
    sgxioc_gen_epid_quote_arg_t gen_quote_arg = {
        .report_data = { { 0 } },                       // input (empty is ok)
        .quote_type = SGX_LINKABLE_SIGNATURE,           // input
        .spid = { { 0 } },                              // input (empty is ok)
        .nonce = { { 0 } },                             // input (empty is ok)
        .sigrl_ptr = NULL,                              // input (optional)
        .sigrl_len = 0,                                 // input (optional)
        .quote_buf_len = sizeof(quote_buf),             // input
        .quote = { .as_buf = (uint8_t *) quote_buf }    // output
    };
    int nretries = 0;
    while (nretries < IOCTL_MAX_RETRIES) {
        int ret = ioctl(sgx_fd, SGXIOC_GEN_EPID_QUOTE, &gen_quote_arg);
        if (ret == 0) {
            break;
        } else if (errno != EBUSY) {
            THROW_ERROR("failed to ioctl /dev/sgx");
        }

        printf("WARN: /dev/sgx is temporarily busy. Try again after 1 second.");
        sleep(1);
        nretries++;
    }
    if (nretries == IOCTL_MAX_RETRIES) {
        THROW_ERROR("failed to ioctl /dev/sgx due to timeout");
    }

    sgx_quote_t *quote = (sgx_quote_t *)quote_buf;
    if (quote->sign_type != SGX_LINKABLE_SIGNATURE) {
        THROW_ERROR("invalid quote: wrong sign type");
    }
    if (quote->signature_len == 0) {
        THROW_ERROR("invalid quote: zero-length signature");
    }
    if (memcmp(&gen_quote_arg.report_data, &quote->report_body.report_data,
               sizeof(sgx_report_data_t)) != 0) {
        THROW_ERROR("invalid quote: wrong report data");
    }
    return 0;
}

static int do_sgx_ioctl_test(sgx_ioctl_test_body_t test_body) {
    // Init test
    int sgx_fd;
    if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
        THROW_ERROR("failed to open /dev/sgx ");
    }

    // Do test
    int ret = test_body(sgx_fd);

    // Clean up test
    close(sgx_fd);
    return ret;
}

static int do_SGXIOC_SELF_TARGET(int sgx_fd) {
    sgx_target_info_t target_info;
    if (ioctl(sgx_fd, SGXIOC_SELF_TARGET, &target_info) < 0) {
        THROW_ERROR("failed to ioctl /dev/sgx");
    }
    return 0;
}

static int do_SGXIOC_CREATE_AND_VERIFY_REPORT(int sgx_fd) {
    sgx_target_info_t target_info;
    if (ioctl(sgx_fd, SGXIOC_SELF_TARGET, &target_info) < 0) {
        THROW_ERROR("failed to ioctl /dev/sgx");
    }
    sgx_report_data_t report_data;
    sgx_report_t report;

    sgxioc_create_report_arg_t args[] = {
        {
            .target_info = (const sgx_target_info_t *) &target_info,
            .report_data = NULL,
            .report = &report
        },
        {
            .target_info = (const sgx_target_info_t *) &target_info,
            .report_data = (const sgx_report_data_t *) &report_data,
            .report = &report
        }
    };
    for (int arg_i = 0; arg_i < ARRAY_SIZE(args); arg_i++) {
        memset(&report, 0, sizeof(report));
        sgxioc_create_report_arg_t *arg = &args[arg_i];
        if (ioctl(sgx_fd, SGXIOC_CREATE_REPORT, arg) < 0) {
            THROW_ERROR("failed to create report");
        }
        if (ioctl(sgx_fd, SGXIOC_VERIFY_REPORT, &report) < 0) {
            THROW_ERROR("failed to verify report");
        }
    }
    return 0;
}

#ifndef OCCLUM_DISABLE_DCAP
#define REPORT_BODY_OFFSET 48
static int generate_and_verify_dcap_quote(int sgx_fd) {
    // get quote size
    uint32_t quote_size = 0;
    if (ioctl(sgx_fd, SGXIOC_GET_DCAP_QUOTE_SIZE, &quote_size) < 0) {
        THROW_ERROR("failed to get quote size");
    }

    // get quote
    uint8_t *quote_buffer = (uint8_t *)malloc(quote_size);
    if (NULL == quote_buffer) {
        THROW_ERROR("Couldn't allocate quote_buffer");
    }
    memset(quote_buffer, 0, quote_size);

    sgx_report_data_t report_data = { 0 };
    char *data = "ioctl DCAP report data example";
    memcpy(report_data.d, data, strlen(data));

    sgxioc_gen_dcap_quote_arg_t gen_quote_arg = {
        .report_data = &report_data,
        .quote_len = &quote_size,
        .quote_buf = quote_buffer
    };

    if (ioctl(sgx_fd, SGXIOC_GEN_DCAP_QUOTE, &gen_quote_arg) < 0) {
        THROW_ERROR("failed to get quote");
    }

    if (memcmp((void *) & ((sgx_report_body_t *)(quote_buffer +
                           REPORT_BODY_OFFSET))->report_data,
               (void *)&report_data, sizeof(sgx_report_data_t)) != 0) {
        THROW_ERROR("mismathced report data");
    }

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    uint32_t supplemental_size = 0;
    if (ioctl(sgx_fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_size) < 0) {
        THROW_ERROR("failed to get supplemental data size");
    }
    uint8_t *supplemental_buffer = (uint8_t *)malloc(supplemental_size);
    if (NULL == supplemental_buffer) {
        THROW_ERROR("Couldn't allocate quote_buffer");
    }
    memset(supplemental_buffer, 0, supplemental_size);

    sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
        .quote_buf = quote_buffer,
        .quote_size = quote_size,
        .collateral_expiration_status = &collateral_expiration_status,
        .quote_verification_result = &quote_verification_result,
        .supplemental_data_size = supplemental_size,
        .supplemental_data = supplemental_buffer
    };

    if (ioctl(sgx_fd, SGXIOC_VER_DCAP_QUOTE, &ver_quote_arg) < 0) {
        THROW_ERROR("failed to verify quote");
    }

    if (collateral_expiration_status != 0) {
        THROW_ERROR("the verification collateral has expired");
    }

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            return 0;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("WARN: App: Verification completed with Non-terminal result: %x\n",
                   quote_verification_result);
            return 0;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            THROW_ERROR("\tError: App: Verification completed with Terminal result: %x\n",
                        quote_verification_result);
    }
}

static int do_SGXIOC_GENERATE_AND_VERIFY_DCAP_QUOTE(int sgx_fd) {
    int is_dcap_driver_installed = 0;
    if (ioctl(sgx_fd, SGXIOC_DETECT_DCAP_DRIVER, &is_dcap_driver_installed) < 0) {
        THROW_ERROR("failed to detect DCAP driver");
    }

    if (is_dcap_driver_installed == 0) {
        printf("Warning: test_sgx_ioctl_SGXIOC_GENERATE_AND_VERIFY_DCAP_QUOTE is skipped\n");
        return 0;
    }

    int nretries = 0;
    while (nretries < IOCTL_MAX_RETRIES) {
        int ret = generate_and_verify_dcap_quote(sgx_fd);
        if (ret == 0) {
            break;
        } else if (errno != EBUSY) {
            THROW_ERROR("failed to ioctl /dev/sgx");
        }

        printf("WARN: /dev/sgx is temporarily busy. Try again after 1 second.");
        sleep(1);
        nretries++;
    }
    if (nretries == IOCTL_MAX_RETRIES) {
        THROW_ERROR("failed to ioctl /dev/sgx due to timeout");
    }

    return 0;
}

int test_sgx_ioctl_SGXIOC_GENERATE_AND_VERIFY_DCAP_QUOTE(void) {
    return do_sgx_ioctl_test(do_SGXIOC_GENERATE_AND_VERIFY_DCAP_QUOTE);
}
#endif

int test_sgx_ioctl_SGXIOC_IS_EDMM_SUPPORTED(void) {
    return do_sgx_ioctl_test(do_SGXIOC_IS_EDMM_SUPPORTED);
}

int test_sgx_ioctl_SGXIOC_GET_EPID_GROUP_ID(void) {
    return do_sgx_ioctl_test(do_SGXIOC_GET_EPID_GROUP_ID);
}

int test_sgx_ioctl_SGXIOC_GEN_EPID_QUOTE(void) {
    return do_sgx_ioctl_test(do_SGXIOC_GEN_QUOTE);
}

int test_sgx_ioctl_SGXIOC_SELF_TARGET(void) {
    return do_sgx_ioctl_test(do_SGXIOC_SELF_TARGET);
}

int test_sgx_ioctl_SGXIOC_CREATE_AND_VERIFY_REPORT(void) {
    return do_sgx_ioctl_test(do_SGXIOC_CREATE_AND_VERIFY_REPORT);
}

#define CONFIG_SIZE  512
int test_ioctl_SIOCGIFCONF(void) {
    struct ifreq *req;
    struct ifconf conf;
    char *buf = (char *)malloc(CONFIG_SIZE);
    if (buf == NULL) {
        THROW_ERROR("malloc failed");
    }
    memset(buf, 0, CONFIG_SIZE);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    conf.ifc_len = 0;
    conf.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &conf) < 0) {
        close(sock);
        THROW_ERROR("empty length ioctl failed");
    }

    if (conf.ifc_len != 0) {
        close(sock);
        THROW_ERROR("wrong returned length");
    }

    conf.ifc_len = CONFIG_SIZE;
    conf.ifc_buf = 0;
    if (ioctl(sock, SIOCGIFCONF, &conf) < 0) {
        close(sock);
        THROW_ERROR("empty buffer ioctl failed");
    }

    int ret_len = conf.ifc_len;

    // use a larger buffer when the original one is insufficient
    if (ret_len > CONFIG_SIZE) {
        free(buf);

        char *new_buf = (char *)malloc(ret_len);
        if (new_buf == NULL) {
            close(sock);
            THROW_ERROR("malloc failed");
        }
        buf = new_buf;
        memset(buf, 0, ret_len);
    } else {
        conf.ifc_len = CONFIG_SIZE;
    }

    conf.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &conf) < 0) {
        close(sock);
        THROW_ERROR("buffer passed ioctl failed");
    }

    if (conf.ifc_len != ret_len) {
        close(sock);
        THROW_ERROR("wrong return length");
    }

    close(sock);

    req = (struct ifreq *)buf;
    int num = conf.ifc_len / sizeof (struct ifreq);

    printf("    interface names got:\n");
    for (int i = 0; i < num; i++) {
        printf("    %d: %s\n", i + 1, req->ifr_name);
        req ++;
    }

    return 0;
}

int test_ioctl_FIONBIO(void) {
    int test_sock[2], sock;
    test_sock[0] = socket(AF_INET, SOCK_STREAM, 0);
    test_sock[1] = socket(AF_UNIX, SOCK_STREAM, 0);

    for (int i = 0; i < 2; i++) {
        sock = test_sock[i];
        int on = 1;
        if (ioctl(sock, FIONBIO, &on) < 0) {
            close(sock);
            THROW_ERROR("ioctl FIONBIO failed");
        }

        int actual_flags = fcntl(sock, F_GETFL);
        if ((actual_flags & O_NONBLOCK) == 0) {
            close(sock);
            THROW_ERROR("failed to check the O_NONBLOCK flag after FIONBIO");
        }

        close(sock);
    }
    return 0;
}

int test_ioctl_FIOCLEX(void) {
    // Open a file with O_CLOEXEC (close-on-exec)
    char *tmp_file = "/tmp/test_fioclex";
    int fd = open(tmp_file, O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0) {
        THROW_ERROR("failed to open the tmp file");
    }

    // change this fd to "no close-on-exec"
    int ret = ioctl(fd, FIONCLEX, NULL);
    if (ret != 0) {
        THROW_ERROR("ioctl FIONCLEX failed");
    }

    int pipefds[2];
    ret = pipe(pipefds);
    if (ret != 0) {
        THROW_ERROR("failed to create pipe");
    }

    // set close on exec on reader end
    ret = ioctl(pipefds[0], FIOCLEX, NULL);
    if (ret != 0) {
        THROW_ERROR("ioctl FIOCLEX failed");
    }

    // construct child process args
    int child_pid, status;
    int child_argc =
        6; // ./nauty_child -t fioclex regular_file_fd pipe_reader_fd pipe_writer_fd
    char **child_argv = calloc(1, sizeof(char *) * (child_argc + 1));
    child_argv[0] = strdup("naughty_child");
    child_argv[1] = strdup("-t");
    child_argv[2] = strdup("fioclex");
    asprintf(&child_argv[3], "%d", fd);
    asprintf(&child_argv[4], "%d", pipefds[0]);
    asprintf(&child_argv[5], "%d", pipefds[1]);

    ret = posix_spawn(&child_pid, "/bin/naughty_child", NULL, NULL, child_argv, NULL);
    if (ret != 0) {
        THROW_ERROR("failed to spawn a child process\n");
    }

    ret = waitpid(child_pid, &status, 0);
    if (ret < 0) {
        THROW_ERROR("failed to wait4 the child process");
    }
    printf("child process %d exit status = %d\n", child_pid, status);

    return 0;
}

// ============================================================================
// Test suite
// ============================================================================

static test_case_t test_cases[] = {
    TEST_CASE(test_tty_ioctl_TIOCGWINSZ),
    TEST_CASE(test_ioctl_TCGETS_TCSETS),
    TEST_CASE(test_sgx_ioctl_SGXIOC_IS_EDMM_SUPPORTED),
    TEST_CASE(test_sgx_ioctl_SGXIOC_GET_EPID_GROUP_ID),
    TEST_CASE(test_sgx_ioctl_SGXIOC_GEN_EPID_QUOTE),
    TEST_CASE(test_sgx_ioctl_SGXIOC_SELF_TARGET),
    TEST_CASE(test_sgx_ioctl_SGXIOC_CREATE_AND_VERIFY_REPORT),
#ifndef OCCLUM_DISABLE_DCAP
    TEST_CASE(test_sgx_ioctl_SGXIOC_GENERATE_AND_VERIFY_DCAP_QUOTE),
#endif
    TEST_CASE(test_ioctl_SIOCGIFCONF),
    TEST_CASE(test_ioctl_FIONBIO),
    TEST_CASE(test_ioctl_FIOCLEX),
};

int main() {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
