#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include "test.h"

// ============================================================================
// Helper macros
// ============================================================================

#define NTHREADS                (3)
#define STACK_SIZE              (8 * 1024)

// ============================================================================
// The test case of concurrent counter
// ============================================================================

#define LOCAL_COUNT             (1000UL)
#define EXPECTED_GLOBAL_COUNT   (LOCAL_COUNT * NTHREADS)

struct thread_arg {
    int                         ti;
    long                        local_count;
    volatile unsigned long     *global_count;
    pthread_mutex_t            *mutex;
};

static void *thread_func(void *_arg) {
    struct thread_arg *arg = _arg;
    for (long i = 0; i < arg->local_count; i++) {
        pthread_mutex_lock(arg->mutex);
        (*arg->global_count)++;
        pthread_mutex_unlock(arg->mutex);
    }
    return NULL;
}

static int test_mutex_with_concurrent_counter(void) {
    /*
     * Multiple threads are to increase a global counter concurrently
     */
    volatile unsigned long global_count = 0;
    pthread_t threads[NTHREADS];
    struct thread_arg thread_args[NTHREADS];
    /*
     * Protect the counter with a mutex
     */
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);
    /*
     * Start the threads
     */
    for (int ti = 0; ti < NTHREADS; ti++) {
        struct thread_arg *thread_arg = &thread_args[ti];
        thread_arg->ti = ti;
        thread_arg->local_count = LOCAL_COUNT;
        thread_arg->global_count = &global_count;
        thread_arg->mutex = &mutex;

        if (pthread_create(&threads[ti], NULL, thread_func, thread_arg) < 0) {
            printf("ERROR: pthread_create failed (ti = %d)\n", ti);
            return -1;
        }
    }
    /*
     * Wait for the threads to finish
     */
    for (int ti = 0; ti < NTHREADS; ti++) {
        if (pthread_join(threads[ti], NULL) < 0) {
            printf("ERROR: pthread_join failed (ti = %d)\n", ti);
            return -1;
        }
    }
    /*
     * Check the correctness of the concurrent counter
     */
    if (global_count != EXPECTED_GLOBAL_COUNT) {
        printf("ERROR: incorrect global_count (actual = %ld, expected = %ld)\n",
               global_count, EXPECTED_GLOBAL_COUNT);
        return -1;
    }

    pthread_mutex_destroy(&mutex);
    return 0;
}

// ============================================================================
// The test case of robust mutex
// ============================================================================

struct thread_robust_arg {
    int                         ti;
    volatile int                *global_count;
    pthread_mutex_t             *mutex;
};

static void *thread_worker(void *_arg) {
    struct thread_robust_arg *arg = _arg;
    int err = pthread_mutex_lock(arg->mutex);
    if (err == EOWNERDEAD) {
        // The next owner should call pthread_mutex_consistent to make mutex consistent again
        pthread_mutex_consistent(arg->mutex);
    }
    (*arg->global_count)++;
    // Wait for other threads to acquire the lock
    sleep(1);
    // Exit without unlocking the mutex, this will makes the mutex in an inconsistent state.
    return NULL;
}

static int test_robust_mutex_with_concurrent_counter(void) {
    volatile int global_count = 0;
    pthread_t threads[NTHREADS];
    struct thread_robust_arg thread_args[NTHREADS];
    // Init robust mutex
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&mutex, &attr);
    // Start the threads
    for (int ti = 0; ti < NTHREADS; ti++) {
        struct thread_robust_arg *thread_arg = &thread_args[ti];
        thread_arg->ti = ti;
        thread_arg->global_count = &global_count;
        thread_arg->mutex = &mutex;

        if (pthread_create(&threads[ti], NULL, thread_worker, thread_arg) < 0) {
            THROW_ERROR("pthread_create failed (ti = %d)", ti);
        }
    }
    // Wait for the threads to finish
    for (int ti = 0; ti < NTHREADS; ti++) {
        if (pthread_join(threads[ti], NULL) < 0) {
            THROW_ERROR("pthread_join failed (ti = %d)", ti);
        }
    }
    // Check the result
    if (global_count != NTHREADS) {
        THROW_ERROR("incorrect global_count (actual = %d, expected = %d)", global_count,
                    NTHREADS);
    }

    pthread_mutex_destroy(&mutex);
    return 0;
}

// ============================================================================
// The test case of waiting condition variable
// ============================================================================

#define WAIT_ROUND          (100000)

struct thread_cond_arg {
    int                         ti;
    volatile unsigned int      *val;
    volatile int               *exit_thread_count;
    pthread_cond_t             *cond_val;
    pthread_mutex_t            *mutex;
};

static void *thread_cond_wait(void *_arg) {
    struct thread_cond_arg *arg = _arg;
    printf("Thread #%d: start to wait on condition variable.\n", arg->ti);
    for (unsigned int i = 0; i < WAIT_ROUND; ++i) {
        pthread_mutex_lock(arg->mutex);
        while (*(arg->val) == 0) {
            pthread_cond_wait(arg->cond_val, arg->mutex);
        }
        pthread_mutex_unlock(arg->mutex);
    }
    (*arg->exit_thread_count)++;
    printf("Thread #%d: exited.\n", arg->ti);
    return NULL;
}

static int test_mutex_with_cond_wait(void) {
    volatile unsigned int val = 0;
    volatile int exit_thread_count = 0;
    pthread_t threads[NTHREADS];
    struct thread_cond_arg thread_args[NTHREADS];
    pthread_cond_t cond_val = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    /*
     * Start the threads waiting on the condition variable
     */
    for (int ti = 0; ti < NTHREADS; ti++) {
        struct thread_cond_arg *thread_arg = &thread_args[ti];
        thread_arg->ti = ti;
        thread_arg->val = &val;
        thread_arg->exit_thread_count = &exit_thread_count;
        thread_arg->cond_val = &cond_val;
        thread_arg->mutex = &mutex;

        if (pthread_create(&threads[ti], NULL, thread_cond_wait, thread_arg) < 0) {
            printf("ERROR: pthread_create failed (ti = %d)\n", ti);
            return -1;
        }
    }
    /*
     * Unblock all threads currently waiting on the condition variable
     */
    while (exit_thread_count < NTHREADS) {
        pthread_mutex_lock(&mutex);
        val = 1;
        pthread_cond_broadcast(&cond_val);
        pthread_mutex_unlock(&mutex);

        pthread_mutex_lock(&mutex);
        val = 0;
        pthread_mutex_unlock(&mutex);
    }
    /*
     * Wait for the threads to finish
     */
    for (int ti = 0; ti < NTHREADS; ti++) {
        if (pthread_join(threads[ti], NULL) < 0) {
            printf("ERROR: pthread_join failed (ti = %d)\n", ti);
            return -1;
        }
    }
    return 0;
}

// ============================================================================
// The test case of timed lock
// ============================================================================

static int test_mutex_timedlock() {
    int err;
    struct timespec ts;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&lock);
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    /*
     * This will cause a deadlock, a timeout error will return
     */
    err = pthread_mutex_timedlock(&lock, &ts);
    if (err != ETIMEDOUT) {
        THROW_ERROR("mutex timed lock failed");
    }
    return 0;
}

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    TEST_CASE(test_mutex_with_concurrent_counter),
    TEST_CASE(test_robust_mutex_with_concurrent_counter),
    TEST_CASE(test_mutex_with_cond_wait),
    TEST_CASE(test_mutex_timedlock),
};

int main() {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
