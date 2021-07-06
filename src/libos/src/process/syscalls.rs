use super::do_arch_prctl::ArchPrctlCode;
use super::do_clone::CloneFlags;
use super::do_exec::do_exec;
use super::do_futex::{FutexFlags, FutexOp, FutexTimeout};
use super::do_robust_list::RobustListHead;
use super::do_spawn::FileAction;
use super::do_wait4::WaitOptions;
use super::prctl::PrctlCmd;
use super::process::ProcessFilter;
use super::spawn_attribute::{clone_spawn_atrributes_safely, posix_spawnattr_t, SpawnAttr};
use crate::prelude::*;
use crate::time::{timespec_t, ClockID};
use crate::util::mem_util::from_user::*;
use std::ptr::NonNull;

pub fn do_spawn_for_musl(
    child_pid_ptr: *mut u32,
    path: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
    fdop_list: *const FdOp,
    attribute_list: *const posix_spawnattr_t,
) -> Result<isize> {
    check_mut_ptr(child_pid_ptr)?;
    let path = clone_cstring_safely(path)?.to_string_lossy().into_owned();
    let argv = clone_cstrings_safely(argv)?;
    let envp = clone_cstrings_safely(envp)?;
    let file_actions = clone_file_actions_safely(fdop_list)?;
    let spawn_attrs = clone_spawn_atrributes_safely(attribute_list)?;
    let current = current!();
    debug!(
        "spawn: path: {:?}, argv: {:?}, envp: {:?}, fdop: {:?}, spawn_attr: {:?}",
        path, argv, envp, file_actions, spawn_attrs
    );

    let child_pid =
        super::do_spawn::do_spawn(&path, &argv, &envp, &file_actions, spawn_attrs, &current)?;

    unsafe { *child_pid_ptr = child_pid };
    Ok(0)
}

#[repr(C)]
#[derive(Debug)]
pub struct FdOp {
    // We actually switch the prev and next fields in the musl definition.
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

pub fn do_spawn_for_glibc(
    child_pid_ptr: *mut u32,
    path: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
    fa: *const SpawnFileActions,
    attribute_list: *const posix_spawnattr_t,
) -> Result<isize> {
    check_mut_ptr(child_pid_ptr)?;
    let path = clone_cstring_safely(path)?.to_string_lossy().into_owned();
    let argv = clone_cstrings_safely(argv)?;
    let envp = clone_cstrings_safely(envp)?;
    let file_actions = clone_file_actions_from_fa_safely(fa)?;
    let spawn_attrs = clone_spawn_atrributes_safely(attribute_list)?;
    let current = current!();
    debug!(
        "spawn: path: {:?}, argv: {:?}, envp: {:?}, actions: {:?}, attributes: {:?}",
        path, argv, envp, file_actions, spawn_attrs
    );

    let child_pid =
        super::do_spawn::do_spawn(&path, &argv, &envp, &file_actions, spawn_attrs, &current)?;

    unsafe { *child_pid_ptr = child_pid };
    Ok(0)
}

#[repr(C)]
pub struct SpawnFileActions {
    allocated: u32,
    used: u32,
    actions: *const SpawnAction,
    pad: [u32; 16],
}

#[repr(C)]
struct SpawnAction {
    tag: u32,
    action: Action,
}

impl SpawnAction {
    pub fn to_file_action(&self) -> Result<FileAction> {
        #[deny(unreachable_patterns)]
        Ok(match self.tag {
            SPAWN_DO_CLOSE => FileAction::Close(unsafe { self.action.close_action.fd }),
            SPAWN_DO_DUP2 => FileAction::Dup2(unsafe { self.action.dup2_action.fd }, unsafe {
                self.action.dup2_action.newfd
            }),
            SPAWN_DO_OPEN => FileAction::Open {
                path: clone_cstring_safely(unsafe { self.action.open_action.path })?
                    .to_string_lossy()
                    .into_owned(),
                mode: unsafe { self.action.open_action.mode },
                oflag: unsafe { self.action.open_action.oflag },
                fd: unsafe { self.action.open_action.fd },
            },
            _ => return_errno!(EINVAL, "Unknown file action tag"),
        })
    }
}

// See <path_to_glibc>/posix/spawn_int.h
const SPAWN_DO_CLOSE: u32 = 0;
const SPAWN_DO_DUP2: u32 = 1;
const SPAWN_DO_OPEN: u32 = 2;

#[repr(C)]
union Action {
    close_action: CloseAction,
    dup2_action: Dup2Action,
    open_action: OpenAction,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CloseAction {
    fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Dup2Action {
    fd: u32,
    newfd: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OpenAction {
    fd: u32,
    path: *const i8,
    oflag: u32,
    mode: u32,
}

fn clone_file_actions_from_fa_safely(fa_ptr: *const SpawnFileActions) -> Result<Vec<FileAction>> {
    let mut file_actions = Vec::new();
    if fa_ptr == std::ptr::null() {
        return Ok(file_actions);
    }

    let sa_slice = {
        check_ptr(fa_ptr)?;
        let fa = unsafe { &*fa_ptr };
        let sa_ptr = fa.actions;
        let sa_len = fa.used as usize;
        check_array(sa_ptr, sa_len)?;
        unsafe { std::slice::from_raw_parts(sa_ptr, sa_len) }
    };

    for sa in sa_slice {
        let file_action = sa.to_file_action()?;
        file_actions.push(file_action);
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
    bitset: u32,
) -> Result<isize> {
    check_ptr(futex_addr)?;
    let (futex_op, futex_flags) = super::do_futex::futex_op_and_flags_from_u32(futex_op)?;

    let get_futex_val = |val| -> Result<usize> {
        if val < 0 {
            return_errno!(EINVAL, "the futex val must not be negative");
        }
        Ok(val as usize)
    };

    let get_futex_timeout = |timeout| -> Result<Option<FutexTimeout>> {
        let timeout = timeout as *const timespec_t;
        if timeout.is_null() {
            return Ok(None);
        }
        let ts = timespec_t::from_raw_ptr(timeout)?;
        ts.validate()?;
        // TODO: use a secure clock to transfer the real time to monotonic time
        let clock_id = if futex_flags.contains(FutexFlags::FUTEX_CLOCK_REALTIME) {
            ClockID::CLOCK_REALTIME
        } else {
            ClockID::CLOCK_MONOTONIC
        };
        Ok(Some(FutexTimeout::new(clock_id, ts)))
    };

    match futex_op {
        FutexOp::FUTEX_WAIT => {
            let timeout = get_futex_timeout(timeout)?;
            super::do_futex::futex_wait(futex_addr, futex_val, &timeout).map(|_| 0)
        }
        FutexOp::FUTEX_WAIT_BITSET => {
            let timeout = get_futex_timeout(timeout)?;
            super::do_futex::futex_wait_bitset(futex_addr, futex_val, &timeout, bitset).map(|_| 0)
        }
        FutexOp::FUTEX_WAKE => {
            let max_count = get_futex_val(futex_val)?;
            super::do_futex::futex_wake(futex_addr, max_count).map(|count| count as isize)
        }
        FutexOp::FUTEX_WAKE_BITSET => {
            let max_count = get_futex_val(futex_val)?;
            super::do_futex::futex_wake_bitset(futex_addr, max_count, bitset)
                .map(|count| count as isize)
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

pub fn do_wait4(pid: i32, exit_status_ptr: *mut i32, options: u32) -> Result<isize> {
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

    let wait_options =
        WaitOptions::from_bits(options).ok_or_else(|| errno!(EINVAL, "options not recognized"))?;
    let mut exit_status = 0;
    match super::do_wait4::do_wait4(&child_process_filter, wait_options) {
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

pub fn do_getpgid() -> Result<isize> {
    let pgid = super::do_getpid::do_getpgid();
    Ok(pgid as isize)
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

// Occlum is a single user enviroment, so only group 0 is supported
pub fn do_getgroups(size: isize, buf_ptr: *mut u32) -> Result<isize> {
    if size < 0 {
        return_errno!(EINVAL, "buffer size is incorrect");
    } else if size == 0 {
        //Occlum only has 1 group
        Ok(1)
    } else {
        let size = size as usize;
        check_array(buf_ptr, size)?;

        let group_list = unsafe { std::slice::from_raw_parts_mut(buf_ptr, size) };
        group_list[0] = 0;

        //Occlum only has 1 group
        Ok(1)
    }
}

pub fn do_execve(path: *const i8, argv: *const *const i8, envp: *const *const i8) -> Result<isize> {
    let path = clone_cstring_safely(path)?.to_string_lossy().into_owned();
    let argv = clone_cstrings_safely(argv)?;
    let envp = clone_cstrings_safely(envp)?;
    let current = current!();
    debug!(
        "execve: path: {:?}, argv: {:?}, envp: {:?}",
        path, argv, envp
    );

    do_exec(&path, &argv, &envp, &current)
}

pub fn do_set_robust_list(list_head_ptr: *mut RobustListHead, len: usize) -> Result<isize> {
    if !list_head_ptr.is_null() {
        check_mut_ptr(list_head_ptr)?;
    }
    super::do_robust_list::do_set_robust_list(list_head_ptr, len)?;
    Ok(0)
}

pub fn do_get_robust_list(
    tid: pid_t,
    list_head_ptr_ptr: *mut *mut RobustListHead,
    len_ptr: *mut usize,
) -> Result<isize> {
    check_mut_ptr(list_head_ptr_ptr)?;
    check_mut_ptr(len_ptr)?;
    let list_head_ptr = super::do_robust_list::do_get_robust_list(tid)?;
    unsafe {
        list_head_ptr_ptr.write(list_head_ptr);
        len_ptr.write(std::mem::size_of::<RobustListHead>());
    }
    Ok(0)
}
