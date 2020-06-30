use super::do_arch_prctl::ArchPrctlCode;
use super::do_clone::CloneFlags;
use super::do_futex::{FutexFlags, FutexOp};
use super::do_spawn::{spawn_attr::spawnattr_t, FileAction};
use super::pgrp::*;
use super::prctl::PrctlCmd;
use super::process::ProcessFilter;
use super::table;
use crate::prelude::*;
use crate::time::timespec_t;
use crate::util::mem_util::from_user::*;
use std::ptr::NonNull;

pub fn do_spawn(
    child_pid_ptr: *mut u32,
    path: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
    fdop_list: *const FdOp,
    attr_ptr: *const spawnattr_t,
) -> Result<isize> {
    check_mut_ptr(child_pid_ptr)?;
    let path = clone_cstring_safely(path)?.to_string_lossy().into_owned();
    let argv = clone_cstrings_safely(argv)?;
    let envp = clone_cstrings_safely(envp)?;
    let file_actions = clone_file_actions_safely(fdop_list)?;
    let attr = if attr_ptr != std::ptr::null() {
        Some(spawnattr_t::from_raw_ptr(attr_ptr)?)
    } else {
        None
    };
    let current = current!();
    debug!(
        "spawn: path: {:?}, argv: {:?}, envp: {:?}, fdop: {:?}, attr: {:?}",
        path, argv, envp, file_actions, attr
    );

    let child_pid = super::do_spawn::do_spawn(&path, &argv, &envp, &file_actions, attr, &current)?;

    unsafe { *child_pid_ptr = child_pid };
    Ok(0)
}

#[repr(C)]
#[derive(Debug)]
pub struct FdOp {
    // We actually switch the prev and next fields in the libc definition.
    prev: *const FdOp,
    next: *const FdOp,
    cmd: u32,
    fd: u32,
    srcfd: u32,
    oflag: u32,
    mode: u32,
    path: *const i8,
}

// This Rust-version of fdop correspond to the C-version one in Occlum.
// See <path_to_musl_libc>/src/process/fdop.h.
const FDOP_CLOSE: u32 = 1;
const FDOP_DUP2: u32 = 2;
const FDOP_OPEN: u32 = 3;

fn clone_file_actions_safely(fdop_ptr: *const FdOp) -> Result<Vec<FileAction>> {
    let mut file_actions = Vec::new();

    let mut fdop_ptr = fdop_ptr;
    while fdop_ptr != std::ptr::null() {
        check_ptr(fdop_ptr)?;
        let fdop = unsafe { &*fdop_ptr };

        #[deny(unreachable_patterns)]
        let file_action = match fdop.cmd {
            FDOP_CLOSE => FileAction::Close(fdop.fd),
            FDOP_DUP2 => FileAction::Dup2(fdop.srcfd, fdop.fd),
            FDOP_OPEN => FileAction::Open {
                path: clone_cstring_safely(fdop.path)?
                    .to_string_lossy()
                    .into_owned(),
                mode: fdop.mode,
                oflag: fdop.oflag,
                fd: fdop.fd,
            },
            _ => {
                return_errno!(EINVAL, "Unknown file action command");
            }
        };
        file_actions.push(file_action);

        fdop_ptr = fdop.next;
    }

    Ok(file_actions)
}

pub fn do_clone(
    flags: u32,
    stack_addr: usize,
    ptid: *mut pid_t,
    ctid: *mut pid_t,
    new_tls: usize,
) -> Result<isize> {
    let flags = CloneFlags::from_bits_truncate(flags);
    check_mut_ptr(stack_addr as *mut u64)?;
    let ptid = {
        if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
            check_mut_ptr(ptid)?;
            NonNull::new(ptid)
        } else {
            None
        }
    };
    let ctid = {
        if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
            check_mut_ptr(ctid)?;
            NonNull::new(ctid)
        } else {
            None
        }
    };
    let new_tls = {
        if flags.contains(CloneFlags::CLONE_SETTLS) {
            check_mut_ptr(new_tls as *mut usize)?;
            Some(new_tls)
        } else {
            None
        }
    };

    let child_pid = super::do_clone::do_clone(flags, stack_addr, ptid, ctid, new_tls)?;

    Ok(child_pid as isize)
}

pub fn do_futex(
    futex_addr: *const i32,
    futex_op: u32,
    futex_val: i32,
    timeout: u64,
    futex_new_addr: *const i32,
) -> Result<isize> {
    check_ptr(futex_addr)?;
    let (futex_op, futex_flags) = super::do_futex::futex_op_and_flags_from_u32(futex_op)?;

    let get_futex_val = |val| -> Result<usize> {
        if val < 0 {
            return_errno!(EINVAL, "the futex val must not be negative");
        }
        Ok(val as usize)
    };

    match futex_op {
        FutexOp::FUTEX_WAIT => {
            let timeout = {
                let timeout = timeout as *const timespec_t;
                if timeout.is_null() {
                    None
                } else {
                    let ts = timespec_t::from_raw_ptr(timeout)?;
                    ts.validate()?;
                    if futex_flags.contains(FutexFlags::FUTEX_CLOCK_REALTIME) {
                        warn!("CLOCK_REALTIME is not supported yet, use monotonic clock");
                    }
                    Some(ts)
                }
            };
            super::do_futex::futex_wait(futex_addr, futex_val, &timeout).map(|_| 0)
        }
        FutexOp::FUTEX_WAKE => {
            let max_count = get_futex_val(futex_val)?;
            super::do_futex::futex_wake(futex_addr, max_count).map(|count| count as isize)
        }
        FutexOp::FUTEX_REQUEUE => {
            check_ptr(futex_new_addr)?;
            let max_nwakes = get_futex_val(futex_val)?;
            let max_nrequeues = get_futex_val(timeout as i32)?;
            super::do_futex::futex_requeue(futex_addr, max_nwakes, max_nrequeues, futex_new_addr)
                .map(|nwakes| nwakes as isize)
        }
        _ => return_errno!(ENOSYS, "the futex operation is not supported"),
    }
}

pub fn do_prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<isize> {
    let prctl_cmd = super::prctl::PrctlCmd::from_raw(option, arg2, arg3, arg4, arg5)?;
    super::prctl::do_prctl(prctl_cmd)
}

pub fn do_arch_prctl(code: u32, addr: *mut usize) -> Result<isize> {
    let code = ArchPrctlCode::from_u32(code)?;
    check_mut_ptr(addr)?;
    super::do_arch_prctl::do_arch_prctl(code, addr).map(|_| 0)
}

pub fn do_set_tid_address(tidptr: *mut pid_t) -> Result<isize> {
    if !tidptr.is_null() {
        check_mut_ptr(tidptr)?;
    }
    super::do_set_tid_address::do_set_tid_address(tidptr).map(|tid| tid as isize)
}

pub fn do_exit(status: i32) -> Result<isize> {
    debug!("exit: {}", status);
    super::do_exit::do_exit(status);
    Ok(0)
}

pub fn do_exit_group(status: i32) -> Result<isize> {
    debug!("exit_group: {}", status);
    super::do_exit::do_exit_group(status);
    Ok(0)
}

pub fn do_wait4(pid: i32, exit_status_ptr: *mut i32) -> Result<isize> {
    if !exit_status_ptr.is_null() {
        check_mut_ptr(exit_status_ptr)?;
    }

    let child_process_filter = match pid {
        pid if pid < -1 => ProcessFilter::WithPgid((-pid) as pid_t),
        -1 => ProcessFilter::WithAnyPid,
        0 => {
            let pgid = current!().process().pgid();
            ProcessFilter::WithPgid(pgid)
        }
        pid if pid > 0 => ProcessFilter::WithPid(pid as pid_t),
        _ => unreachable!(),
    };
    let mut exit_status = 0;
    match super::do_wait4::do_wait4(&child_process_filter) {
        Ok((pid, exit_status)) => {
            if !exit_status_ptr.is_null() {
                unsafe {
                    *exit_status_ptr = exit_status;
                }
            }
            Ok(pid as isize)
        }
        Err(e) => Err(e),
    }
}

pub fn do_getpid() -> Result<isize> {
    let pid = super::do_getpid::do_getpid();
    Ok(pid as isize)
}

pub fn do_gettid() -> Result<isize> {
    let tid = super::do_getpid::do_gettid();
    Ok(tid as isize)
}

pub fn do_getppid() -> Result<isize> {
    let ppid = super::do_getpid::do_getppid();
    Ok(ppid as isize)
}

pub fn do_getpgid(pid: i32) -> Result<isize> {
    if pid < 0 {
        return_errno!(ESRCH, "process with negative pid is not found");
    }

    let real_pid = if pid == 0 {
        do_getpid()? as pid_t
    } else {
        pid as pid_t
    };
    let pgid = super::pgrp::do_getpgid(real_pid)?;
    Ok(pgid as isize)
}

pub fn do_setpgid(pid: i32, pgid: i32) -> Result<isize> {
    if pgid < 0 {
        return_errno!(EINVAL, "pgid can't be negative");
    }

    let pid = pid as pid_t;
    let pgid = pgid as pid_t;
    // Pid should be the calling process or a child of the calling process.
    let current_pid = current!().process().pid();
    if pid != 0 && pid != current_pid && current!().process().inner().is_child_of(pid) == false {
        return_errno!(ESRCH, "pid not calling process or child processes");
    }

    // When this function is calling, the process must be executing.
    let is_executing = true;
    let ret = super::pgrp::do_setpgid(pid, pgid, is_executing)?;

    Ok(ret)
}

// TODO: implement uid, gid, euid, egid

pub fn do_getuid() -> Result<isize> {
    Ok(0)
}

pub fn do_getgid() -> Result<isize> {
    Ok(0)
}

pub fn do_geteuid() -> Result<isize> {
    Ok(0)
}

pub fn do_getegid() -> Result<isize> {
    Ok(0)
}
