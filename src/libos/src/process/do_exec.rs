use std::ffi::{CStr, CString};
use std::path::Path;

use super::do_exit::exit_old_process_for_execve;
use super::do_spawn::new_process_for_exec;
use super::do_vfork::{check_vfork_for_exec, vfork_return_to_parent};
use super::process::ProcessFilter;
use super::term_status::TermStatus;
use super::wait::Waiter;
use super::{do_exit, do_exit_group};
use super::{table, ProcessRef, ProcessStatus};
use super::{task, ThreadRef};
use crate::interrupt::broadcast_interrupts;
use crate::prelude::*;
use crate::syscall::CpuContext;

// FIXME: `occlum exec` command will return early if the application calls execve successfully.
// Because the "execved"-ed application will run on a new thread and the current thread will exit.
// `occlum run` will not have this problem.

pub fn do_exec(
    path: &str,
    argv: &[CString],
    envp: &[CString],
    current_ref: &ThreadRef,
    context: *mut CpuContext,
) -> Result<isize> {
    trace!(
        "exec current process pid = {:?}",
        current_ref.process().pid()
    );

    let current = current!();
    let (is_forked, tid, parent_process) = check_vfork_for_exec(current_ref);

    let new_process_ref = super::do_spawn::new_process_for_exec(
        path,
        argv,
        envp,
        current_ref,
        Some(tid),
        parent_process,
    );

    if let Ok(new_process_ref) = new_process_ref {
        let new_main_thread = new_process_ref
            .main_thread()
            .expect("the main thread is just created; it must exist");

        if is_forked {
            // Don't exit current process if this is a vforked child process.
            table::add_process(new_process_ref.clone());
            table::add_thread(new_process_ref.main_thread().unwrap());
            task::enqueue_and_exec(new_main_thread);

            return vfork_return_to_parent(context, current_ref.process().pid());
        }

        // Force exit all child threads of current process
        let term_status = TermStatus::Exited(0 as u8);
        current.process().force_exit(term_status);

        // Don't hesitate. Interrupt all threads right now (except the calling thread).
        broadcast_interrupts();

        // Wait for all threads (except calling thread) to exit
        wait_for_other_threads_to_exit(current);

        // Exit current thread and let new process to adopt current's child process
        exit_old_process_for_execve(term_status, new_process_ref.clone());

        // Update process and thread in global table
        table::replace_process(new_process_ref.pid(), new_process_ref.clone());
        table::replace_thread(
            new_process_ref.pid(),
            new_process_ref.main_thread().unwrap(),
        );

        // Finally, enqueue the new thread for execution
        task::enqueue_and_exec(new_main_thread);
        return Ok(0);
    } else {
        // There is something wrong when constructing new process. Just return the error.
        let error = new_process_ref.unwrap_err();
        return Err(error);
    }
}

// Blocking wait until there is only one thread in the calling process
fn wait_for_other_threads_to_exit(current_ref: ThreadRef) {
    use super::do_futex::{self, FutexTimeout};
    use crate::time::{timespec_t, ClockID};
    use core::time::Duration;

    // Set timeout to 50ms
    let timeout = FutexTimeout::new(
        ClockID::CLOCK_MONOTONIC,
        timespec_t::from(Duration::from_millis(50)),
    );
    // Use calling process's pointer as futex value
    let futex_val = Arc::as_ptr(&current_ref.process()) as *const i32;
    loop {
        let thread_num = current_ref.process().threads().len();
        if thread_num == 1 {
            return;
        }
        // Blocking wait here. When a thread exit, it will notify us.
        unsafe {
            do_futex::futex_wait(
                Arc::as_ptr(&current_ref.process()) as *const i32,
                *futex_val,
                &Some(timeout),
            )
        };
    }
}
