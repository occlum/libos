#include <occlum_pal_api.h>
#include "Enclave_u.h"
#include "pal_enclave.h"
#include "pal_error.h"
#include "pal_load_resolv_conf.h"
#include "pal_interrupt_thread.h"
#include "pal_log.h"
#include "pal_sig_handler.h"
#include "pal_syscall.h"
#include "pal_thread_counter.h"
#include "pal_check_fsgsbase.h"
#include "errno2str.h"
#include <linux/limits.h>

int occlum_pal_get_version(void) {
    return OCCLUM_PAL_VERSION;
}

int pal_run_init_process() {
    const char *init_path = "/bin/init";
    const char *init_argv[2] = {
        "init",
        NULL,
    };
    struct occlum_stdio_fds init_io_fds = {
        .stdin_fd = STDIN_FILENO,
        .stdout_fd = STDOUT_FILENO,
        .stderr_fd = STDERR_FILENO,
    };
    int libos_tid = 0;
    struct occlum_pal_create_process_args init_process_args = {
        .path = init_path,
        .argv = init_argv,
        .env = NULL,
        .stdio = &init_io_fds,
        .pid = &libos_tid,
    };
    if (occlum_pal_create_process(&init_process_args) < 0) {
        return -1;
    }

    int exit_status = 0;
    struct occlum_pal_exec_args init_exec_args = {
        .pid = libos_tid,
        .exit_value = &exit_status,
    };
    if (occlum_pal_exec(&init_exec_args) < 0) {
        return -1;
    }

    // Convert the exit status to a value in a shell-like encoding
    if (WIFEXITED(exit_status)) { // terminated normally
        exit_status = WEXITSTATUS(exit_status) & 0x7F; // [0, 127]
    } else { // killed by signal
        exit_status = 128 + WTERMSIG(exit_status); // [128 + 1, 128 + 64]
    }
    if (exit_status != 0) {
        errno = EINVAL;
        PAL_ERROR("The init process exit with code: %d", exit_status);
        return -1;
    }

    return 0;
}

int occlum_pal_init(const struct occlum_pal_attr *attr) {
    if (attr == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (attr->instance_dir == NULL) {
        errno = EINVAL;
        return -1;
    }

    char resolved_path[PATH_MAX] = {0};
    if (realpath(attr->instance_dir, resolved_path) == NULL) {
        PAL_ERROR("realpath returns %s", errno2str(errno));
        return -1;
    }

// Check only for SGX hardware mode
#ifdef SGX_MODE_HW
    if (check_fsgsbase_enablement() != 0) {
        PAL_ERROR("FSGSBASE enablement check failed.");
        return -1;
    }
#endif

    sgx_enclave_id_t eid = pal_get_enclave_id();
    if (eid != SGX_INVALID_ENCLAVE_ID) {
        PAL_ERROR("Enclave has been initialized.");
        errno = EEXIST;
        return -1;
    }

    if (pal_register_sig_handlers() < 0) {
        return -1;
    }

    if (pal_init_enclave(resolved_path) < 0) {
        return -1;
    }
    eid = pal_get_enclave_id();

    int ecall_ret = 0;
    char *resolv_conf_ptr = pal_load_resolv_conf();
    sgx_status_t ecall_status = occlum_ecall_init(eid, &ecall_ret, attr->log_level,
                                resolved_path, (const char *) resolv_conf_ptr);
    free(resolv_conf_ptr);
    resolv_conf_ptr = NULL;
    if (ecall_status != SGX_SUCCESS) {
        const char *sgx_err = pal_get_sgx_error_msg(ecall_status);
        PAL_ERROR("Failed to do ECall with error code 0x%x: %s", ecall_status, sgx_err);
        goto on_destroy_enclave;
    }
    if (ecall_ret < 0) {
        errno = -ecall_ret;
        PAL_ERROR("occlum_ecall_init returns %s", errno2str(errno));
        goto on_destroy_enclave;
    }

    if (pal_interrupt_thread_start() < 0) {
        PAL_ERROR("Failed to start the interrupt thread: %s", errno2str(errno));
        goto on_destroy_enclave;
    }

    if (pal_run_init_process() < 0) {
        PAL_ERROR("Failed to run the init process: %s", errno2str(errno));
        goto on_destroy_enclave;
    }

    return 0;
on_destroy_enclave:
    if (pal_destroy_enclave() < 0) {
        PAL_WARN("Cannot destroy the enclave");
    }
    return -1;
}

int occlum_pal_create_process(struct occlum_pal_create_process_args *args) {
    int ecall_ret = 0; // libos_tid

    if (args->path == NULL || args->argv == NULL || args->pid == NULL) {
        errno = EINVAL;
        return -1;
    }

    sgx_enclave_id_t eid = pal_get_enclave_id();
    if (eid == SGX_INVALID_ENCLAVE_ID) {
        PAL_ERROR("Enclave is not initialized yet.");
        errno = ENOENT;
        return -1;
    }

    sgx_status_t ecall_status = occlum_ecall_new_process(eid, &ecall_ret, args->path,
                                args->argv, args->env, args->stdio);
    if (ecall_status != SGX_SUCCESS) {
        const char *sgx_err = pal_get_sgx_error_msg(ecall_status);
        PAL_ERROR("Failed to do ECall with error code 0x%x: %s", ecall_status, sgx_err);
        return -1;
    }
    if (ecall_ret < 0) {
        errno = -ecall_ret;
        PAL_ERROR("occlum_ecall_new_process returns %s", errno2str(errno));
        return -1;
    }

    *args->pid = ecall_ret;
    return 0;
}

int occlum_pal_exec(struct occlum_pal_exec_args *args) {
    int host_tid = GETTID();
    int ecall_ret = 0;

    if (args->exit_value == NULL) {
        errno = EINVAL;
        return -1;
    }

    sgx_enclave_id_t eid = pal_get_enclave_id();
    if (eid == SGX_INVALID_ENCLAVE_ID) {
        PAL_ERROR("Enclave is not initialized yet.");
        errno = ENOENT;
        return -1;
    }

    pal_thread_counter_inc();
    sgx_status_t ecall_status = occlum_ecall_exec_thread(eid, &ecall_ret, args->pid,
                                host_tid);
    pal_thread_counter_dec();
    if (ecall_status != SGX_SUCCESS) {
        const char *sgx_err = pal_get_sgx_error_msg(ecall_status);
        PAL_ERROR("Failed to do ECall: %s", sgx_err);
        return -1;
    }
    if (ecall_ret < 0) {
        errno = -ecall_ret;
        PAL_ERROR("occlum_ecall_exec_thread returns %s", errno2str(errno));
        return -1;
    }

    *args->exit_value = ecall_ret;

    return 0;
}

int occlum_pal_kill(int pid, int sig) {
    sgx_enclave_id_t eid = pal_get_enclave_id();
    if (eid == SGX_INVALID_ENCLAVE_ID) {
        errno = ENOENT;
        PAL_ERROR("Enclave is not initialized yet.");
        return -1;
    }

    int ecall_ret = 0;
    sgx_status_t ecall_status = occlum_ecall_kill(eid, &ecall_ret, pid, sig);
    if (ecall_status != SGX_SUCCESS) {
        const char *sgx_err = pal_get_sgx_error_msg(ecall_status);
        PAL_ERROR("Failed to do ECall with error code 0x%x: %s", ecall_status, sgx_err);
        return -1;
    }
    if (ecall_ret < 0) {
        errno = -ecall_ret;
        PAL_ERROR("Failed to occlum_ecall_kill: %s", errno2str(errno));
        return -1;
    }

    return 0;
}

int occlum_pal_destroy(void) {
    sgx_enclave_id_t eid = pal_get_enclave_id();
    if (eid == SGX_INVALID_ENCLAVE_ID) {
        PAL_ERROR("Enclave is not initialized yet.");
        errno = ENOENT;
        return -1;
    }

    int ret = 0;

    if (pal_interrupt_thread_stop() < 0) {
        ret = -1;
        PAL_WARN("Cannot stop the interrupt thread: %s", errno2str(errno));
    }

    if (pal_destroy_enclave() < 0) {
        ret = -1;
        PAL_WARN("Cannot destroy the enclave");
    }
    return ret;
}

int pal_get_version(void) __attribute__((weak, alias ("occlum_pal_get_version")));

int pal_init(const struct occlum_pal_attr *attr)\
__attribute__ ((weak, alias ("occlum_pal_init")));

int pal_create_process(struct occlum_pal_create_process_args *args)\
__attribute__ ((weak, alias ("occlum_pal_create_process")));

int pal_exec(struct occlum_pal_exec_args *args)\
__attribute__ ((weak, alias ("occlum_pal_exec")));

int pal_kill(int pid, int sig) __attribute__ ((weak, alias ("occlum_pal_kill")));

int pal_destroy(void) __attribute__ ((weak, alias ("occlum_pal_destroy")));
