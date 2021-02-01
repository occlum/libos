//! System call handler
//!
//! # Syscall processing flow
//!
//! 1. Libc calls `__occlum_syscall` (in `syscall_entry_x86_64.S`)
//! 2. Do user/LibOS switch and then call `occlum_syscall` (in this file)
//! 3. Preprocess the system call and then call `dispatch_syscall` (in this file)
//! 4. Call `do_*` to process the system call (in other modules)

use aligned::{Aligned, A16};
use core::arch::x86_64::{_fxrstor, _fxsave};
use std::any::Any;
use std::convert::TryFrom;
use std::default::Default;
use std::ffi::{CStr, CString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::ptr;
use time::{clockid_t, timespec_t, timeval_t};
use util::log::{self, LevelFilter};
use util::mem_util::from_user::*;

use crate::exception::do_handle_exception;
use crate::fs::{
    do_access, do_chdir, do_chmod, do_chown, do_close, do_dup, do_dup2, do_dup3, do_eventfd,
    do_eventfd2, do_faccessat, do_fchmod, do_fchmodat, do_fchown, do_fchownat, do_fcntl,
    do_fdatasync, do_fstat, do_fstatat, do_fsync, do_ftruncate, do_getcwd, do_getdents,
    do_getdents64, do_ioctl, do_lchown, do_link, do_linkat, do_lseek, do_lstat, do_mkdir,
    do_mkdirat, do_open, do_openat, do_pipe, do_pipe2, do_pread, do_pwrite, do_read, do_readlink,
    do_readlinkat, do_readv, do_rename, do_renameat, do_rmdir, do_sendfile, do_stat, do_symlink,
    do_symlinkat, do_sync, do_truncate, do_unlink, do_unlinkat, do_write, do_writev, iovec_t, File,
    FileDesc, FileRef, HostStdioFds, Stat,
};
use crate::interrupt::{do_handle_interrupt, sgx_interrupt_info_t};
use crate::misc::{resource_t, rlimit_t, sysinfo_t, utsname_t};
use crate::net::{
    do_accept, do_accept4, do_bind, do_connect, do_epoll_create, do_epoll_create1, do_epoll_ctl,
    do_epoll_pwait, do_epoll_wait, do_getpeername, do_getsockname, do_getsockopt, do_listen,
    do_poll, do_recvfrom, do_recvmsg, do_select, do_sendmsg, do_sendto, do_setsockopt, do_shutdown,
    do_socket, do_socketpair, msghdr, msghdr_mut,
};
use crate::process::{
    do_arch_prctl, do_clone, do_exit, do_exit_group, do_futex, do_getegid, do_geteuid, do_getgid,
    do_getpgid, do_getpid, do_getppid, do_gettid, do_getuid, do_prctl, do_set_tid_address,
    do_spawn_for_glibc, do_spawn_for_musl, do_wait4, pid_t, FdOp, SpawnFileActions, ThreadStatus,
};
use crate::sched::{do_getcpu, do_sched_getaffinity, do_sched_setaffinity, do_sched_yield};
use crate::signal::{
    do_kill, do_rt_sigaction, do_rt_sigpending, do_rt_sigprocmask, do_rt_sigreturn,
    do_rt_sigtimedwait, do_sigaltstack, do_tgkill, do_tkill, sigaction_t, siginfo_t, sigset_t,
    stack_t,
};
use crate::vm::{MMapFlags, MRemapFlags, MSyncFlags, VMPerms};
use crate::{fs, process, std, vm};

use super::*;

/// System call table defined in a macro.
///
/// To keep the info about system calls in a centralized place and avoid redundant code, the system
/// call table is defined in this macro. This macro takes as input a callback macro, which
/// can then process the system call table defined in this macro and generated code accordingly.
///
/// # Why callback?
///
/// Since the system call table is quite big, we do not want to repeat it more than once in code. But
/// passing a block of grammarly malformed code (such as the system call table shown below) seems
/// difficult due to some limitations of Rust macros.
///
/// So instead of passing the syscall table to another macro, we do this the other way around: accepting
/// a macro callback as input, and then internally pass the system call table to the callback.
macro_rules! process_syscall_table_with_callback {
    ($callback: ident) => {
        $callback! {
            // System call table.
            //
            // Format:
            // (<SyscallName> = <SyscallNum>) => <SyscallFunc>(<SyscallArgs>),
            //
            // If the system call is implemented, <SyscallFunc> is the function that implements the system call.
            // Otherwise, it is set to an proper error handler function.
            //
            // Limitation:
            // <SyscallFunc> must be an identifier, not a path.
            //
            // TODO: Unify the use of C types. For example, u8 or i8 or char_c for C string?
            (Read = 0) => do_read(fd: FileDesc, buf: *mut u8, size: usize),
            (Write = 1) => do_write(fd: FileDesc, buf: *const u8, size: usize),
            (Open = 2) => do_open(path: *const i8, flags: u32, mode: u32),
            (Close = 3) => do_close(fd: FileDesc),
            (Stat = 4) => do_stat(path: *const i8, stat_buf: *mut Stat),
            (Fstat = 5) => do_fstat(fd: FileDesc, stat_buf: *mut Stat),
            (Lstat = 6) => do_lstat(path: *const i8, stat_buf: *mut Stat),
            (Poll = 7) => do_poll(fds: *mut libc::pollfd, nfds: libc::nfds_t, timeout: c_int),
            (Lseek = 8) => do_lseek(fd: FileDesc, offset: off_t, whence: i32),
            (Mmap = 9) => do_mmap(addr: usize, size: usize, perms: i32, flags: i32, fd: FileDesc, offset: off_t),
            (Mprotect = 10) => do_mprotect(addr: usize, len: usize, prot: u32),
            (Munmap = 11) => do_munmap(addr: usize, size: usize),
            (Brk = 12) => do_brk(new_brk_addr: usize),
            (RtSigaction = 13) => do_rt_sigaction(signum_c: c_int, new_sa_c: *const sigaction_t, old_sa_c: *mut sigaction_t),
            (RtSigprocmask = 14) => do_rt_sigprocmask(how: c_int, set: *const sigset_t, oldset: *mut sigset_t, sigset_size: size_t),
            (RtSigreturn = 15) => do_rt_sigreturn(context: *mut CpuContext),
            (Ioctl = 16) => do_ioctl(fd: FileDesc, cmd: u32, argp: *mut u8),
            (Pread64 = 17) => do_pread(fd: FileDesc, buf: *mut u8, size: usize, offset: off_t),
            (Pwrite64 = 18) => do_pwrite(fd: FileDesc, buf: *const u8, size: usize, offset: off_t),
            (Readv = 19) => do_readv(fd: FileDesc, iov: *mut iovec_t, count: i32),
            (Writev = 20) => do_writev(fd: FileDesc, iov: *const iovec_t, count: i32),
            (Access = 21) => do_access(path: *const i8, mode: u32),
            (Pipe = 22) => do_pipe(fds_u: *mut i32),
            (Select = 23) => do_select(nfds: c_int, readfds: *mut libc::fd_set, writefds: *mut libc::fd_set, exceptfds: *mut libc::fd_set, timeout: *mut timeval_t),
            (SchedYield = 24) => do_sched_yield(),
            (Mremap = 25) => do_mremap(old_addr: usize, old_size: usize, new_size: usize, flags: i32, new_addr: usize),
            (Msync = 26) => do_msync(addr: usize, size: usize, flags: u32),
            (Mincore = 27) => handle_unsupported(),
            (Madvise = 28) => handle_unsupported(),
            (Shmget = 29) => handle_unsupported(),
            (Shmat = 30) => handle_unsupported(),
            (Shmctl = 31) => handle_unsupported(),
            (Dup = 32) => do_dup(old_fd: FileDesc),
            (Dup2 = 33) => do_dup2(old_fd: FileDesc, new_fd: FileDesc),
            (Pause = 34) => handle_unsupported(),
            (Nanosleep = 35) => do_nanosleep(req_u: *const timespec_t, rem_u: *mut timespec_t),
            (Getitimer = 36) => handle_unsupported(),
            (Alarm = 37) => handle_unsupported(),
            (Setitimer = 38) => handle_unsupported(),
            (Getpid = 39) => do_getpid(),
            (Sendfile = 40) => do_sendfile(out_fd: FileDesc, in_fd: FileDesc, offset_ptr: *mut off_t, count: usize),
            (Socket = 41) => do_socket(domain: c_int, socket_type: c_int, protocol: c_int),
            (Connect = 42) => do_connect(fd: c_int, addr: *const libc::sockaddr, addr_len: libc::socklen_t),
            (Accept = 43) => do_accept(fd: c_int, addr: *mut libc::sockaddr, addr_len: *mut libc::socklen_t),
            (Sendto = 44) => do_sendto(fd: c_int, base: *const c_void, len: size_t, flags: c_int, addr: *const libc::sockaddr, addr_len: libc::socklen_t),
            (Recvfrom = 45) => do_recvfrom(fd: c_int, base: *mut c_void, len: size_t, flags: c_int, addr: *mut libc::sockaddr, addr_len: *mut libc::socklen_t),
            (Sendmsg = 46) => do_sendmsg(fd: c_int, msg_ptr: *const msghdr, flags_c: c_int),
            (Recvmsg = 47) => do_recvmsg(fd: c_int, msg_mut_ptr: *mut msghdr_mut, flags_c: c_int),
            (Shutdown = 48) => do_shutdown(fd: c_int, how: c_int),
            (Bind = 49) => do_bind(fd: c_int, addr: *const libc::sockaddr, addr_len: libc::socklen_t),
            (Listen = 50) => do_listen(fd: c_int, backlog: c_int),
            (Getsockname = 51) => do_getsockname(fd: c_int, addr: *mut libc::sockaddr, addr_len: *mut libc::socklen_t),
            (Getpeername = 52) => do_getpeername(fd: c_int, addr: *mut libc::sockaddr, addr_len: *mut libc::socklen_t),
            (Socketpair = 53) => do_socketpair(domain: c_int, socket_type: c_int, protocol: c_int, sv: *mut c_int),
            (Setsockopt = 54) => do_setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: libc::socklen_t),
            (Getsockopt = 55) => do_getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut libc::socklen_t),
            (Clone = 56) => do_clone(flags: u32, stack_addr: usize, ptid: *mut pid_t, ctid: *mut pid_t, new_tls: usize),
            (Fork = 57) => handle_unsupported(),
            (Vfork = 58) => handle_unsupported(),
            (Execve = 59) => handle_unsupported(),
            (Exit = 60) => do_exit(exit_status: i32),
            (Wait4 = 61) => do_wait4(pid: i32, _exit_status: *mut i32),
            (Kill = 62) => do_kill(pid: i32, sig: c_int),
            (Uname = 63) => do_uname(name: *mut utsname_t),
            (Semget = 64) => handle_unsupported(),
            (Semop = 65) => handle_unsupported(),
            (Semctl = 66) => handle_unsupported(),
            (Shmdt = 67) => handle_unsupported(),
            (Msgget = 68) => handle_unsupported(),
            (Msgsnd = 69) => handle_unsupported(),
            (Msgrcv = 70) => handle_unsupported(),
            (Msgctl = 71) => handle_unsupported(),
            (Fcntl = 72) => do_fcntl(fd: FileDesc, cmd: u32, arg: u64),
            (Flock = 73) => handle_unsupported(),
            (Fsync = 74) => do_fsync(fd: FileDesc),
            (Fdatasync = 75) => do_fdatasync(fd: FileDesc),
            (Truncate = 76) => do_truncate(path: *const i8, len: usize),
            (Ftruncate = 77) => do_ftruncate(fd: FileDesc, len: usize),
            (Getdents = 78) => do_getdents(fd: FileDesc, buf: *mut u8, buf_size: usize),
            (Getcwd = 79) => do_getcwd(buf: *mut u8, size: usize),
            (Chdir = 80) => do_chdir(path: *const i8),
            (Fchdir = 81) => handle_unsupported(),
            (Rename = 82) => do_rename(oldpath: *const i8, newpath: *const i8),
            (Mkdir = 83) => do_mkdir(path: *const i8, mode: usize),
            (Rmdir = 84) => do_rmdir(path: *const i8),
            (Creat = 85) => handle_unsupported(),
            (Link = 86) => do_link(oldpath: *const i8, newpath: *const i8),
            (Unlink = 87) => do_unlink(path: *const i8),
            (Symlink = 88) => do_symlink(target: *const i8, link_path: *const i8),
            (Readlink = 89) => do_readlink(path: *const i8, buf: *mut u8, size: usize),
            (Chmod = 90) => do_chmod(path: *const i8, mode: u16),
            (Fchmod = 91) => do_fchmod(fd: FileDesc, mode: u16),
            (Chown = 92) => do_chown(path: *const i8, uid: u32, gid: u32),
            (Fchown = 93) => do_fchown(fd: FileDesc, uid: u32, gid: u32),
            (Lchown = 94) => do_lchown(path: *const i8, uid: u32, gid: u32),
            (Umask = 95) => handle_unsupported(),
            (Gettimeofday = 96) => do_gettimeofday(tv_u: *mut timeval_t),
            (Getrlimit = 97) => handle_unsupported(),
            (Getrusage = 98) => handle_unsupported(),
            (SysInfo = 99) => do_sysinfo(info: *mut sysinfo_t),
            (Times = 100) => handle_unsupported(),
            (Ptrace = 101) => handle_unsupported(),
            (Getuid = 102) => do_getuid(),
            (SysLog = 103) => handle_unsupported(),
            (Getgid = 104) => do_getgid(),
            (Setuid = 105) => handle_unsupported(),
            (Setgid = 106) => handle_unsupported(),
            (Geteuid = 107) => do_geteuid(),
            (Getegid = 108) => do_getegid(),
            (Setpgid = 109) => handle_unsupported(),
            (Getppid = 110) => do_getppid(),
            (Getpgrp = 111) => handle_unsupported(),
            (Setsid = 112) => handle_unsupported(),
            (Setreuid = 113) => handle_unsupported(),
            (Setregid = 114) => handle_unsupported(),
            (Getgroups = 115) => handle_unsupported(),
            (Setgroups = 116) => handle_unsupported(),
            (Setresuid = 117) => handle_unsupported(),
            (Getresuid = 118) => handle_unsupported(),
            (Setresgid = 119) => handle_unsupported(),
            (Getresgid = 120) => handle_unsupported(),
            (Getpgid = 121) => do_getpgid(),
            (Setfsuid = 122) => handle_unsupported(),
            (Setfsgid = 123) => handle_unsupported(),
            (Getsid = 124) => handle_unsupported(),
            (Capget = 125) => handle_unsupported(),
            (Capset = 126) => handle_unsupported(),
            (RtSigpending = 127) => do_rt_sigpending(buf_ptr: *mut sigset_t, buf_size: usize),
            (RtSigtimedwait = 128) => do_rt_sigtimedwait(mask_ptr: *const sigset_t, info_ptr: *mut siginfo_t, timeout_ptr: *const timespec_t, mask_size: usize),
            (RtSigqueueinfo = 129) => handle_unsupported(),
            (RtSigsuspend = 130) => handle_unsupported(),
            (Sigaltstack = 131) => do_sigaltstack(ss: *const stack_t, old_ss: *mut stack_t, context: *const CpuContext),
            (Utime = 132) => handle_unsupported(),
            (Mknod = 133) => handle_unsupported(),
            (Uselib = 134) => handle_unsupported(),
            (Personality = 135) => handle_unsupported(),
            (Ustat = 136) => handle_unsupported(),
            (Statfs = 137) => handle_unsupported(),
            (Fstatfs = 138) => handle_unsupported(),
            (SysFs = 139) => handle_unsupported(),
            (Getpriority = 140) => handle_unsupported(),
            (Setpriority = 141) => handle_unsupported(),
            (SchedSetparam = 142) => handle_unsupported(),
            (SchedGetparam = 143) => handle_unsupported(),
            (SchedSetscheduler = 144) => handle_unsupported(),
            (SchedGetscheduler = 145) => handle_unsupported(),
            (SchedGetPriorityMax = 146) => handle_unsupported(),
            (SchedGetPriorityMin = 147) => handle_unsupported(),
            (SchedRrGetInterval = 148) => handle_unsupported(),
            (Mlock = 149) => handle_unsupported(),
            (Munlock = 150) => handle_unsupported(),
            (Mlockall = 151) => handle_unsupported(),
            (Munlockall = 152) => handle_unsupported(),
            (Vhangup = 153) => handle_unsupported(),
            (ModifyLdt = 154) => handle_unsupported(),
            (PivotRoot = 155) => handle_unsupported(),
            (SysCtl = 156) => handle_unsupported(),
            (Prctl = 157) => do_prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64),
            (ArchPrctl = 158) => do_arch_prctl(code: u32, addr: *mut usize),
            (Adjtimex = 159) => handle_unsupported(),
            (Setrlimit = 160) => handle_unsupported(),
            (Chroot = 161) => handle_unsupported(),
            (Sync = 162) => do_sync(),
            (Acct = 163) => handle_unsupported(),
            (Settimeofday = 164) => handle_unsupported(),
            (Mount = 165) => handle_unsupported(),
            (Umount2 = 166) => handle_unsupported(),
            (Swapon = 167) => handle_unsupported(),
            (Swapoff = 168) => handle_unsupported(),
            (Reboot = 169) => handle_unsupported(),
            (Sethostname = 170) => handle_unsupported(),
            (Setdomainname = 171) => handle_unsupported(),
            (Iopl = 172) => handle_unsupported(),
            (Ioperm = 173) => handle_unsupported(),
            (CreateModule = 174) => handle_unsupported(),
            (InitModule = 175) => handle_unsupported(),
            (DeleteModule = 176) => handle_unsupported(),
            (GetKernelSyms = 177) => handle_unsupported(),
            (QueryModule = 178) => handle_unsupported(),
            (Quotactl = 179) => handle_unsupported(),
            (Nfsservctl = 180) => handle_unsupported(),
            (Getpmsg = 181) => handle_unsupported(),
            (Putpmsg = 182) => handle_unsupported(),
            (AfsSysCall = 183) => handle_unsupported(),
            (Tuxcall = 184) => handle_unsupported(),
            (Security = 185) => handle_unsupported(),
            (Gettid = 186) => do_gettid(),
            (Readahead = 187) => handle_unsupported(),
            (Setxattr = 188) => handle_unsupported(),
            (Lsetxattr = 189) => handle_unsupported(),
            (Fsetxattr = 190) => handle_unsupported(),
            (Getxattr = 191) => handle_unsupported(),
            (Lgetxattr = 192) => handle_unsupported(),
            (Fgetxattr = 193) => handle_unsupported(),
            (Listxattr = 194) => handle_unsupported(),
            (Llistxattr = 195) => handle_unsupported(),
            (Flistxattr = 196) => handle_unsupported(),
            (Removexattr = 197) => handle_unsupported(),
            (Lremovexattr = 198) => handle_unsupported(),
            (Fremovexattr = 199) => handle_unsupported(),
            (Tkill = 200) => do_tkill(tid: pid_t, sig: c_int),
            (Time = 201) => handle_unsupported(),
            (Futex = 202) => do_futex(futex_addr: *const i32, futex_op: u32, futex_val: i32, timeout: u64, futex_new_addr: *const i32, bitset: u32),
            (SchedSetaffinity = 203) => do_sched_setaffinity(pid: pid_t, cpusize: size_t, buf: *const c_uchar),
            (SchedGetaffinity = 204) => do_sched_getaffinity(pid: pid_t, cpusize: size_t, buf: *mut c_uchar),
            (SetThreadArea = 205) => handle_unsupported(),
            (IoSetup = 206) => handle_unsupported(),
            (IoDestroy = 207) => handle_unsupported(),
            (IoGetevents = 208) => handle_unsupported(),
            (IoSubmit = 209) => handle_unsupported(),
            (IoCancel = 210) => handle_unsupported(),
            (GetThreadArea = 211) => handle_unsupported(),
            (LookupDcookie = 212) => handle_unsupported(),
            (EpollCreate = 213) => do_epoll_create(size: c_int),
            (EpollCtlOld = 214) => handle_unsupported(),
            (EpollWaitOld = 215) => handle_unsupported(),
            (RemapFilePages = 216) => handle_unsupported(),
            (Getdents64 = 217) => do_getdents64(fd: FileDesc, buf: *mut u8, buf_size: usize),
            (SetTidAddress = 218) => do_set_tid_address(tidptr: *mut pid_t),
            (RestartSysCall = 219) => handle_unsupported(),
            (Semtimedop = 220) => handle_unsupported(),
            (Fadvise64 = 221) => handle_unsupported(),
            (TimerCreate = 222) => handle_unsupported(),
            (TimerSettime = 223) => handle_unsupported(),
            (TimerGettime = 224) => handle_unsupported(),
            (TimerGetoverrun = 225) => handle_unsupported(),
            (TimerDelete = 226) => handle_unsupported(),
            (ClockSettime = 227) => handle_unsupported(),
            (ClockGettime = 228) => do_clock_gettime(clockid: clockid_t, ts_u: *mut timespec_t),
            (ClockGetres = 229) => do_clock_getres(clockid: clockid_t, res_u: *mut timespec_t),
            (ClockNanosleep = 230) => handle_unsupported(),
            (ExitGroup = 231) => do_exit_group(exit_status: i32),
            (EpollWait = 232) => do_epoll_wait(epfd: c_int, events: *mut libc::epoll_event, maxevents: c_int, timeout: c_int),
            (EpollCtl = 233) => do_epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *const libc::epoll_event),
            (Tgkill = 234) => do_tgkill(pid: i32, tid: pid_t, sig: c_int),
            (Utimes = 235) => handle_unsupported(),
            (Vserver = 236) => handle_unsupported(),
            (Mbind = 237) => handle_unsupported(),
            (SetMempolicy = 238) => handle_unsupported(),
            (GetMempolicy = 239) => handle_unsupported(),
            (MqOpen = 240) => handle_unsupported(),
            (MqUnlink = 241) => handle_unsupported(),
            (MqTimedsend = 242) => handle_unsupported(),
            (MqTimedreceive = 243) => handle_unsupported(),
            (MqNotify = 244) => handle_unsupported(),
            (MqGetsetattr = 245) => handle_unsupported(),
            (KexecLoad = 246) => handle_unsupported(),
            (Waitid = 247) => handle_unsupported(),
            (AddKey = 248) => handle_unsupported(),
            (RequestKey = 249) => handle_unsupported(),
            (Keyctl = 250) => handle_unsupported(),
            (IoprioSet = 251) => handle_unsupported(),
            (IoprioGet = 252) => handle_unsupported(),
            (InotifyInit = 253) => handle_unsupported(),
            (InotifyAddWatch = 254) => handle_unsupported(),
            (InotifyRmWatch = 255) => handle_unsupported(),
            (MigratePages = 256) => handle_unsupported(),
            (Openat = 257) => do_openat(dirfd: i32, path: *const i8, flags: u32, mode: u32),
            (Mkdirat = 258) => do_mkdirat(dirfd: i32, path: *const i8, mode: usize),
            (Mknodat = 259) => handle_unsupported(),
            (Fchownat = 260) => do_fchownat(dirfd: i32, path: *const i8, uid: u32, gid: u32, flags: i32),
            (Futimesat = 261) => handle_unsupported(),
            (Fstatat = 262) => do_fstatat(dirfd: i32, path: *const i8, stat_buf: *mut Stat, flags: u32),
            (Unlinkat = 263) => do_unlinkat(dirfd: i32, path: *const i8, flags: i32),
            (Renameat = 264) => do_renameat(olddirfd: i32, oldpath: *const i8, newdirfd: i32, newpath: *const i8),
            (Linkat = 265) => do_linkat(olddirfd: i32, oldpath: *const i8, newdirfd: i32, newpath: *const i8, flags: i32),
            (Symlinkat = 266) => do_symlinkat(target: *const i8, new_dirfd: i32, link_path: *const i8),
            (Readlinkat = 267) => do_readlinkat(dirfd: i32, path: *const i8, buf: *mut u8, size: usize),
            (Fchmodat = 268) => do_fchmodat(dirfd: i32, path: *const i8, mode: u16),
            (Faccessat = 269) => do_faccessat(dirfd: i32, path: *const i8, mode: u32, flags: u32),
            (Pselect6 = 270) => handle_unsupported(),
            (Ppoll = 271) => handle_unsupported(),
            (Unshare = 272) => handle_unsupported(),
            (SetRobustList = 273) => handle_unsupported(),
            (GetRobustList = 274) => handle_unsupported(),
            (Splice = 275) => handle_unsupported(),
            (Tee = 276) => handle_unsupported(),
            (SyncFileRange = 277) => handle_unsupported(),
            (Vmsplice = 278) => handle_unsupported(),
            (MovePages = 279) => handle_unsupported(),
            (Utimensat = 280) => handle_unsupported(),
            (EpollPwait = 281) => do_epoll_pwait(epfd: c_int, events: *mut libc::epoll_event, maxevents: c_int, timeout: c_int, sigmask: *const usize),
            (Signalfd = 282) => handle_unsupported(),
            (TimerfdCreate = 283) => handle_unsupported(),
            (Eventfd = 284) => do_eventfd(init_val: u32),
            (Fallocate = 285) => handle_unsupported(),
            (TimerfdSettime = 286) => handle_unsupported(),
            (TimerfdGettime = 287) => handle_unsupported(),
            (Accept4 = 288) => do_accept4(fd: c_int, addr: *mut libc::sockaddr, addr_len: *mut libc::socklen_t, flags: c_int),
            (Signalfd4 = 289) => handle_unsupported(),
            (Eventfd2 = 290) => do_eventfd2(init_val: u32, flags: i32),
            (EpollCreate1 = 291) => do_epoll_create1(flags: c_int),
            (Dup3 = 292) => do_dup3(old_fd: FileDesc, new_fd: FileDesc, flags: u32),
            (Pipe2 = 293) => do_pipe2(fds_u: *mut i32, flags: u32),
            (InotifyInit1 = 294) => handle_unsupported(),
            (Preadv = 295) => handle_unsupported(),
            (Pwritev = 296) => handle_unsupported(),
            (RtTgsigqueueinfo = 297) => handle_unsupported(),
            (PerfEventOpen = 298) => handle_unsupported(),
            (Recvmmsg = 299) => handle_unsupported(),
            (FanotifyInit = 300) => handle_unsupported(),
            (FanotifyMark = 301) => handle_unsupported(),
            (Prlimit64 = 302) => do_prlimit(pid: pid_t, resource: u32, new_limit: *const rlimit_t, old_limit: *mut rlimit_t),
            (NameToHandleAt = 303) => handle_unsupported(),
            (OpenByHandleAt = 304) => handle_unsupported(),
            (ClockAdjtime = 305) => handle_unsupported(),
            (Syncfs = 306) => handle_unsupported(),
            (Sendmmsg = 307) => handle_unsupported(),
            (Setns = 308) => handle_unsupported(),
            (Getcpu = 309) => do_getcpu(cpu_ptr: *mut u32, node_ptr: *mut u32),
            (ProcessVmReadv = 310) => handle_unsupported(),
            (ProcessVmWritev = 311) => handle_unsupported(),
            (Kcmp = 312) => handle_unsupported(),
            (FinitModule = 313) => handle_unsupported(),
            (SchedSetattr = 314) => handle_unsupported(),
            (SchedGetattr = 315) => handle_unsupported(),
            (Renameat2 = 316) => handle_unsupported(),
            (Seccomp = 317) => handle_unsupported(),
            (Getrandom = 318) => handle_unsupported(),
            (MemfdCreate = 319) => handle_unsupported(),
            (KexecFileLoad = 320) => handle_unsupported(),
            (Bpf = 321) => handle_unsupported(),
            (Execveat = 322) => handle_unsupported(),
            (Userfaultfd = 323) => handle_unsupported(),
            (Membarrier = 324) => handle_unsupported(),
            (Mlock2 = 325) => handle_unsupported(),

            // Occlum-specific system calls
            (SpawnGlibc = 359) => do_spawn_for_glibc(child_pid_ptr: *mut u32, path: *const i8, argv: *const *const i8, envp: *const *const i8, fa: *const SpawnFileActions),
            (SpawnMusl = 360) => do_spawn_for_musl(child_pid_ptr: *mut u32, path: *const i8, argv: *const *const i8, envp: *const *const i8, fdop_list: *const FdOp),
            (HandleException = 361) => do_handle_exception(info: *mut sgx_exception_info_t, fpregs: *mut FpRegs, context: *mut CpuContext),
            (HandleInterrupt = 362) => do_handle_interrupt(info: *mut sgx_interrupt_info_t, fpregs: *mut FpRegs, context: *mut CpuContext),
            (RunUnitTests = 363) => run_unit_tests(name_prefix: *const c_char),
        }
    };
}

fn run_unit_tests(name_prefix: *const c_char) -> Result<isize> {
    #[cfg(feature = "unit_test")]
    return unit_test::run_unit_tests(name_prefix);

    #[cfg(not(feature = "unit_test"))]
    handle_unsupported()
}

/// System call numbers.
///
/// The enum is implemented with macros, which expands into the code looks like below:
/// ```
/// pub enum SyscallNum {
///     Read = 0,
///     Write = 1,
///     // ...
/// }
/// ```
/// The system call nubmers are named in a way consistent with libc.
macro_rules! impl_syscall_nums {
    ($( ( $name: ident = $num: expr ) => $_impl_fn: ident ( $($arg_name:tt : $arg_type: ty),* ) ),+,) => {
        #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
        #[repr(u32)]
        pub enum SyscallNum {
            $(
                $name = $num,
            )*
        }

        impl SyscallNum {
            pub fn as_str(&self) -> &'static str {
                use SyscallNum::*;
                match *self {
                    #![deny(unreachable_patterns)]
                    $(
                        $name => stringify!($name),
                    )*
                }
            }
        }

        impl TryFrom<u32> for SyscallNum {
            type Error = error::Error;

            fn try_from(raw_num: u32) -> Result<Self> {
                match raw_num {
                    $(
                        $num => Ok(Self::$name),
                    )*
                    _ => return_errno!(SyscallNumError::new(raw_num)),
                }
            }
        }

        #[derive(Copy, Clone, Debug)]
        pub struct SyscallNumError {
            invalid_num: u32,
        }

        impl SyscallNumError {
            pub fn new(invalid_num: u32) -> Self {
                Self { invalid_num }
            }
        }

        impl ToErrno for SyscallNumError {
            fn errno(&self) -> Errno {
                EINVAL
            }
        }

        impl std::fmt::Display for SyscallNumError {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "Invalid system call number ({})", self.invalid_num)
            }
        }
    }
}
/// Generate system call numbers.
process_syscall_table_with_callback!(impl_syscall_nums);

/// A struct that represents a system call
struct Syscall {
    num: SyscallNum,
    args: [isize; 6],
}

impl Syscall {
    pub fn new(
        num: u32,
        arg0: isize,
        arg1: isize,
        arg2: isize,
        arg3: isize,
        arg4: isize,
        arg5: isize,
    ) -> Result<Self> {
        let num = SyscallNum::try_from(num)?;
        let args = [arg0, arg1, arg2, arg3, arg4, arg5];
        Ok(Self { num, args })
    }
}

/// Generate the code that can format any system call.
macro_rules! impl_fmt_syscall {
    // Internal rules
    (@fmt_args $self_:ident, $f:ident, $arg_i:expr, ($(,)?)) => {};
    (@fmt_args $self_:ident, $f:ident, $arg_i:expr, ($arg_name:ident : $arg_type:ty, $($more_args:tt)*)) => {
        let arg_val = $self_.args[$arg_i] as $arg_type;
        write!($f, ", {} = {:?}", stringify!($arg_name), arg_val)?;
        impl_fmt_syscall!(@fmt_args $self_, $f, ($arg_i + 1), ($($more_args)*));
    };

    // Main rule
    ($( ( $name:ident = $num:expr ) => $fn:ident ( $($args:tt)* ) ),+,) => {
        impl std::fmt::Debug for Syscall {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Syscall {{ num = {:?}", self.num)?;
                match self.num {
                    #![deny(unreachable_patterns)]
                    $(
                        // Expands into something like below:
                        //
                        // SyscallNum::Read => {
                        //     let arg_val = self.args[0] as FileDesc;
                        //     write!(f, ", {} = {:?}", "fd", arg_val);
                        //     let arg_val = self.args[1] as *mut u8;
                        //     write!(f, ", {} = {:?}", "buf", arg_val);
                        //     let arg_val = self.args[2] as usize;
                        //     write!(f, ", {} = {:?}", "size", arg_val);
                        // }
                        SyscallNum::$name => {
                            impl_fmt_syscall!(@fmt_args self, f, 0, ($($args)*,));
                        },
                    )*
                };
                write!(f, " }}")
            }
        }
    }
}
process_syscall_table_with_callback!(impl_fmt_syscall);

/// Generate the code that can dispatch any system call to its actual implementation function.
macro_rules! impl_dispatch_syscall {
    (@do_syscall $fn:ident, $syscall:ident, $arg_i:expr, ($(,)?) -> ($($output:tt)*) ) => {
        impl_dispatch_syscall!(@as_expr $fn($($output)*));
    };
    (@do_syscall $fn:ident, $syscall:ident, $arg_i:expr, ($_arg_name:ident : $arg_type:ty, $($more_args:tt)*) -> ($($output:tt)*)) => {
        impl_dispatch_syscall!(@do_syscall $fn, $syscall, ($arg_i + 1), ($($more_args)*) -> ($($output)* ($syscall.args[$arg_i] as $arg_type),));
    };
    (@as_expr $e:expr) => { $e };

    ($( ( $name:ident = $num:expr ) => $fn:ident ( $($args:tt)* ) ),+,) => {
        fn dispatch_syscall(syscall: Syscall) -> Result<isize> {
            match syscall.num {
                #![deny(unreachable_patterns)]
                $(
                    // Expands into something like below:
                    //
                    // SyscallNum::Read => {
                    //     let fd = self.args[0] as FileDesc;
                    //     let buf = self.args[1] as *mut u8;
                    //     let size = self.args[2] as usize;
                    //     do_read(fd, buf, size)
                    // }
                    SyscallNum::$name => {
                        impl_dispatch_syscall!(@do_syscall $fn, syscall, 0, ($($args)*,) -> ())
                    },
                )*
            }
        }
    }
}
process_syscall_table_with_callback!(impl_dispatch_syscall);

#[no_mangle]
pub extern "C" fn occlum_syscall(user_context: *mut CpuContext) -> ! {
    // Start a new round of log messages for this system call. But we do not
    // set the description of this round, yet. We will do so after checking the
    // given system call number is a valid.
    log::next_round(None);

    let user_context = unsafe {
        // TODO: validate pointer
        &mut *user_context
    };

    // Do system call
    do_syscall(user_context);

    // Back to the user space
    do_sysret(user_context)
}

fn do_syscall(user_context: &mut CpuContext) {
    // Extract arguments from the CPU context. The arguments follows Linux's syscall ABI.
    let num = user_context.rax as u32;
    let arg0 = user_context.rdi as isize;
    let arg1 = user_context.rsi as isize;
    let arg2 = user_context.rdx as isize;
    let arg3 = user_context.r10 as isize;
    let arg4 = user_context.r8 as isize;
    let arg5 = user_context.r9 as isize;

    let ret = Syscall::new(num, arg0, arg1, arg2, arg3, arg4, arg5).and_then(|mut syscall| {
        log::set_round_desc(Some(syscall.num.as_str()));
        trace!("{:?}", &syscall);
        let syscall_num = syscall.num;

        // Pass user_context as an extra argument to two special syscalls that
        // need to modify it
        if syscall_num == SyscallNum::RtSigreturn {
            syscall.args[0] = user_context as *mut _ as isize;
        } else if syscall_num == SyscallNum::HandleException {
            // syscall.args[0] == info
            // syscall.args[1] == fpregs
            syscall.args[2] = user_context as *mut _ as isize;
        } else if syscall.num == SyscallNum::HandleInterrupt {
            // syscall.args[0] == info
            // syscall.args[1] == fpregs
            syscall.args[2] = user_context as *mut _ as isize;
        } else if syscall.num == SyscallNum::Sigaltstack {
            // syscall.args[0] == new_ss
            // syscall.args[1] == old_ss
            syscall.args[2] = user_context as *const _ as isize;
        }

        #[cfg(feature = "syscall_timing")]
        current!()
            .profiler()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .syscall_enter(syscall_num)
            .expect("unexpected error from profiler to enter syscall");

        let ret = dispatch_syscall(syscall);

        #[cfg(feature = "syscall_timing")]
        current!()
            .profiler()
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .syscall_exit(syscall_num, ret.is_err())
            .expect("unexpected error from profiler to exit syscall");

        ret
    });

    let retval = match ret {
        Ok(retval) => retval as isize,
        Err(e) => {
            let should_log_err = |errno| {
                // If the log level requires every detail, don't ignore any error
                if log::max_level() == LevelFilter::Trace {
                    return true;
                }

                // All other log levels require errors to be outputed. But
                // some errnos are usually benign and may occur in a very high
                // frequency. So we want to ignore them to keep noises at a
                // minimum level in the log.
                //
                // TODO: use a smarter, frequency-based strategy to decide whether
                // to suppress error messages.
                match errno {
                    EAGAIN | ETIMEDOUT => false,
                    _ => true,
                }
            };
            if should_log_err(e.errno()) {
                error!("Error = {}", e.backtrace());
            }

            let retval = -(e.errno() as isize);
            debug_assert!(retval != 0);
            retval
        }
    };
    trace!("Retval = {:?}", retval);

    // Put the return value into user_context.rax, except for syscalls that may
    // modify user_context directly. Currently, there are three such syscalls:
    // SigReturn, HandleException, and HandleInterrupt.
    //
    // Sigreturn restores `user_context` to the state when the last signal
    // handler is executed. So in the case of sigreturn, `user_context` should
    // be kept intact.
    if num != SyscallNum::RtSigreturn as u32
        && num != SyscallNum::HandleException as u32
        && num != SyscallNum::HandleInterrupt as u32
    {
        user_context.rax = retval as u64;
    }

    crate::signal::deliver_signal(user_context);

    crate::process::handle_force_exit();
}

/// Return to the user space according to the given CPU context
fn do_sysret(user_context: &mut CpuContext) -> ! {
    // Rust compiler would complain about passing to external C functions a CpuContext
    // pointer, which includes a FpRegs pointer that is not safe to use by external
    // modules. In our case, the FpRegs pointer will not be used actually. So the
    // Rust warning is a false alarm. We suppress it here.
    #[allow(improper_ctypes)]
    extern "C" {
        fn __occlum_sysret(user_context: *mut CpuContext) -> !;
        fn do_exit_task() -> !;
    }
    if current!().status() != ThreadStatus::Exited {
        // Restore the floating point registers
        // Todo: Is it correct to do fxstor in kernel?
        let fpregs = user_context.fpregs;
        if (fpregs != ptr::null_mut()) {
            if user_context.fpregs_on_heap == 1 {
                let fpregs = unsafe { Box::from_raw(user_context.fpregs as *mut FpRegs) };
                fpregs.restore();
            } else {
                unsafe { fpregs.as_ref().unwrap().restore() };
            }
        }
        unsafe { __occlum_sysret(user_context) } // jump to user space
    } else {
        if user_context.fpregs != ptr::null_mut() && user_context.fpregs_on_heap == 1 {
            drop(unsafe { Box::from_raw(user_context.fpregs as *mut FpRegs) });
        }
        unsafe { do_exit_task() } // exit enclave
    }
    unreachable!("__occlum_sysret never returns!");
}

/*
 * This Rust-version of fdop correspond to the C-version one in Occlum.
 * See <path_to_musl_libc>/src/process/fdop.h.
 */
const FDOP_CLOSE: u32 = 1;
const FDOP_DUP2: u32 = 2;
const FDOP_OPEN: u32 = 3;

fn do_mmap(
    addr: usize,
    size: usize,
    perms: i32,
    flags: i32,
    fd: FileDesc,
    offset: off_t,
) -> Result<isize> {
    let perms = VMPerms::from_u32(perms as u32)?;
    let flags = MMapFlags::from_u32(flags as u32)?;
    let addr = vm::do_mmap(addr, size, perms, flags, fd, offset as usize)?;
    Ok(addr as isize)
}

fn do_munmap(addr: usize, size: usize) -> Result<isize> {
    vm::do_munmap(addr, size)?;
    Ok(0)
}

fn do_mremap(
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_addr: usize,
) -> Result<isize> {
    let flags = MRemapFlags::from_raw(flags as u32, new_addr)?;
    let addr = vm::do_mremap(old_addr, old_size, new_size, flags)?;
    Ok(addr as isize)
}

fn do_mprotect(addr: usize, len: usize, perms: u32) -> Result<isize> {
    let perms = VMPerms::from_u32(perms as u32)?;
    vm::do_mprotect(addr, len, perms)?;
    Ok(0)
}

fn do_brk(new_brk_addr: usize) -> Result<isize> {
    let ret_brk_addr = vm::do_brk(new_brk_addr)?;
    Ok(ret_brk_addr as isize)
}

fn do_msync(addr: usize, size: usize, flags: u32) -> Result<isize> {
    let flags = MSyncFlags::from_u32(flags)?;
    vm::do_msync(addr, size, flags)?;
    Ok(0)
}

fn do_sysinfo(info: *mut sysinfo_t) -> Result<isize> {
    check_mut_ptr(info)?;
    let info = unsafe { &mut *info };
    *info = misc::do_sysinfo()?;
    Ok(0)
}

// TODO: handle tz: timezone_t
fn do_gettimeofday(tv_u: *mut timeval_t) -> Result<isize> {
    check_mut_ptr(tv_u)?;
    let tv = time::do_gettimeofday();
    unsafe {
        *tv_u = tv;
    }
    Ok(0)
}

fn do_clock_gettime(clockid: clockid_t, ts_u: *mut timespec_t) -> Result<isize> {
    check_mut_ptr(ts_u)?;
    let clockid = time::ClockID::from_raw(clockid)?;
    let ts = time::do_clock_gettime(clockid)?;
    unsafe {
        *ts_u = ts;
    }
    Ok(0)
}

fn do_clock_getres(clockid: clockid_t, res_u: *mut timespec_t) -> Result<isize> {
    if res_u.is_null() {
        return Ok(0);
    }
    check_mut_ptr(res_u)?;
    let clockid = time::ClockID::from_raw(clockid)?;
    let res = time::do_clock_getres(clockid)?;
    unsafe {
        *res_u = res;
    }
    Ok(0)
}

// TODO: handle remainder
fn do_nanosleep(req_u: *const timespec_t, rem_u: *mut timespec_t) -> Result<isize> {
    let req = {
        check_ptr(req_u)?;
        timespec_t::from_raw_ptr(req_u)?
    };
    let rem = if !rem_u.is_null() {
        check_mut_ptr(rem_u)?;
        Some(unsafe { &mut *rem_u })
    } else {
        None
    };
    time::do_nanosleep(&req, rem)?;
    Ok(0)
}

fn do_uname(name: *mut utsname_t) -> Result<isize> {
    check_mut_ptr(name)?;
    let name = unsafe { &mut *name };
    misc::do_uname(name).map(|_| 0)
}

fn do_prlimit(
    pid: pid_t,
    resource: u32,
    new_limit: *const rlimit_t,
    old_limit: *mut rlimit_t,
) -> Result<isize> {
    let resource = resource_t::from_u32(resource)?;
    let new_limit = {
        if new_limit != ptr::null() {
            check_ptr(new_limit)?;
            Some(unsafe { &*new_limit })
        } else {
            None
        }
    };
    let old_limit = {
        if old_limit != ptr::null_mut() {
            check_mut_ptr(old_limit)?;
            Some(unsafe { &mut *old_limit })
        } else {
            None
        }
    };
    misc::do_prlimit(pid, resource, new_limit, old_limit).map(|_| 0)
}

fn handle_unsupported() -> Result<isize> {
    return_errno!(ENOSYS, "Unimplemented or unknown syscall")
}

/// Floating point registers
///
/// Note. The area is used to save fxsave result
//#[derive(Clone, Copy)]
#[repr(C)]
pub struct FpRegs {
    inner: Aligned<A16, [u8; 512]>,
}

impl FpRegs {
    /// Save the current CPU floating pointer states to an instance of FpRegs
    pub fn save() -> Self {
        let mut fpregs = MaybeUninit::<Self>::uninit();
        unsafe {
            _fxsave(fpregs.as_mut_ptr() as *mut u8);
            fpregs.assume_init()
        }
    }

    /// Restore the current CPU floating pointer states from this FpRegs instance
    pub fn restore(&self) {
        unsafe { _fxrstor(self.inner.as_ptr()) };
    }

    /// Construct a FpRegs from a slice of u8.
    ///
    /// It is up to the caller to ensure that the src slice contains data that
    /// is the xsave/xrstor format.
    pub unsafe fn from_slice(src: &[u8]) -> Self {
        let mut uninit = MaybeUninit::<Self>::uninit();
        let dst_buf: &mut [u8] = std::slice::from_raw_parts_mut(
            uninit.as_mut_ptr() as *mut u8,
            std::mem::size_of::<FpRegs>(),
        );
        dst_buf.copy_from_slice(&src);
        uninit.assume_init()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

/// Cpu context.
///
/// Note. The definition of this struct must be kept in sync with the assembly
/// code in `syscall_entry_x86-64.S`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CpuContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fpregs_on_heap: u64,
    pub fpregs: *mut FpRegs,
}

impl CpuContext {
    pub fn from_sgx(src: &sgx_cpu_context_t) -> CpuContext {
        Self {
            r8: src.r8,
            r9: src.r9,
            r10: src.r10,
            r11: src.r11,
            r12: src.r12,
            r13: src.r13,
            r14: src.r14,
            r15: src.r15,
            rdi: src.rdi,
            rsi: src.rsi,
            rbp: src.rbp,
            rbx: src.rbx,
            rdx: src.rdx,
            rax: src.rax,
            rcx: src.rcx,
            rsp: src.rsp,
            rip: src.rip,
            rflags: src.rflags,
            fpregs_on_heap: 0,
            fpregs: ptr::null_mut(),
        }
    }
}

// exception and interrupt syscalls share the same c abi
//
// num: occlum syscall number
// info: pointer to sgx_exception_info_t or sgx_interrupt_info_t
// fpregs: pointer to FpRegs. Rust compiler would complain about passing
//  to external C functions a CpuContext pointer, which includes a FpRegs
//  pointer that is not safe to use by external modules. In our case, the
//  FpRegs pointer will not be used actually. So the Rust warning is a
//  false alarm. We suppress it here.
pub unsafe fn exception_interrupt_syscall_c_abi(
    num: u32,
    info: *mut c_void,
    fpregs: *mut FpRegs,
) -> u32 {
    #[allow(improper_ctypes)]
    extern "C" {
        pub fn __occlum_syscall_c_abi(num: u32, info: *mut c_void, fpregs: *mut FpRegs) -> u32;
    }
    __occlum_syscall_c_abi(num, info, fpregs)
}
