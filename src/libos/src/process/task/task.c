#include <assert.h>
#include "task.h"

/* See /<path-to-linux-sgx>/common/inc/internal/thread_data.h */
typedef struct _thread_data_t {
    uint64_t  reserved1[2];
    uint64_t  stack_base_addr;
    uint64_t  stack_limit_addr;
    uint64_t  reserved2[15];
    uint64_t  stack_commit_addr;
} thread_data_t;

extern thread_data_t *get_thread_data(void);


extern void __exec_task(struct Task *task);

extern uint64_t __get_stack_guard(void);
extern void __set_stack_guard(uint64_t new_val);

// From SGX SDK
int sgx_enable_user_stack(size_t stack_base, size_t stack_limit);
void sgx_disable_user_stack(void);

#define OCCLUM_PAGE_SIZE 4096

static uint64_t get_syscall_stack(struct Task *this_task) {
#define LARGE_ENOUGH_GAP        (8192)
    char libos_stack_var = 0;
    uint64_t libos_stack = ((uint64_t) &libos_stack_var) - LARGE_ENOUGH_GAP;
    libos_stack &= ~0x0FUL; // stack must be 16-byte aligned
    return libos_stack;
}

#define SET_CURRENT_TASK(task)                  \
    long stack_guard = __get_stack_guard();     \
    __set_current_task(task);

#define RESET_CURRENT_TASK()                    \
    __set_stack_guard(stack_guard);

int do_exec_task(struct Task *task) {
    jmp_buf libos_state = {0};
    thread_data_t *td = get_thread_data();
    task->saved_state = &libos_state;
    task->kernel_rsp = get_syscall_stack(task);
    task->kernel_stack_base = td->stack_base_addr;
    task->kernel_stack_limit = td->stack_limit_addr;

    //Reserve two pages stack for exception handler
    //The SGX SDK exception handler depends on the two pages as stack to handle exceptions in user's code
    //TODO:Add a check in the sysreturn logic to confirm the stack is not corrupted
    assert(task->kernel_stack_limit + OCCLUM_PAGE_SIZE * 2 <= task->kernel_rsp);

    SET_CURRENT_TASK(task);

    int second = setjmp(libos_state);
    if (!second) {
        __exec_task(task);
    }

    // Jump from do_exit_task
    RESET_CURRENT_TASK();
    return 0;
}

void do_exit_task(void) {
    struct Task *task = __get_current_task();
    jmp_buf *jb = task->saved_state;
    longjmp(*jb, 1);
}
