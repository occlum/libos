#ifndef __OCCLUM_EDL_TYPES_H__
#define __OCCLUM_EDL_TYPES_H__

typedef long                time_t;
typedef long                suseconds_t;
typedef long                syscall_slong_t;
typedef int                 clockid_t;

struct timeval {
    time_t      tv_sec;     /* seconds */
    suseconds_t tv_usec;    /* microseconds */
};

struct occlum_stdio_fds {
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
};

typedef struct mytimespec{
    time_t tv_sec;
    syscall_slong_t tv_nsec;
};

typedef struct itimerspec{
    struct mytimespec it_interval;
    struct mytimespec it_value;
} itimerspec_t;

#define FD_SETSIZE 1024
typedef struct {
    unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_set;

#endif /* __OCCLUM_EDL_TYPES_H__ */
