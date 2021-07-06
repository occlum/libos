use super::{ProcessRef, ThreadId, ThreadRef};
use crate::fs::FileTable;
use crate::prelude::*;
use crate::syscall::{do_sysret, CpuContext};
use std::collections::HashMap;

// From Man page: The calling thread is suspended until the child terminates (either normally, by calling
// _exit(2), or abnormally, after delivery of a fatal signal), or it makes a call to execve(2).
// Until that point, the child shares all memory with its parent, including the stack.
//
// Thus in this implementation, the main idea is to let child use parent's task until exit or execve.
//
// Limitation:
// The child process will not have a complete process structure before execve. Thus during the time from vfork
// to new child process execve or exit, the child process just reuse the parent process's everything, including
// task, pid and etc. And also the log of child process will not start from the point that vfork returns but the
// point that execve returns.

lazy_static! {
    // Track parent and his vforked child. A parent only has one vforked child at a time.
    // K: parent pid, V: child pid
    static ref VFORK_PROCESS_TABLE: SgxMutex<HashMap<pid_t, pid_t>> = SgxMutex::new(HashMap::new());
    // Store all the parents's file tables who call vfork. It will be recovered when the child exits or has its own task.
    // K: parent pid, V: parent file table
    static ref VFORK_PARENT_FILE_TABLES: SgxMutex<HashMap<pid_t, FileTable>> = SgxMutex::new(HashMap::new());
}

thread_local! {
    // Store the current thread's cpu context in thread local storage when current thread calls vfork.
    static VFORK_CPUCONTEXT: RefCell<Option<CpuContext>> = Default::default();
}

pub fn do_vfork(mut context: *mut CpuContext) -> Result<isize> {
    trace!(
        "vfork parent process pid = {:?}",
        current!().process().pid()
    );

    // Generate a new pid for child process
    let new_pid = {
        let new_tid = ThreadId::new();
        new_tid.as_u32() as pid_t
    };

    // Store parent and the vforked child
    let parent_pid = current!().process().pid();
    let mut vfork_process_table = VFORK_PROCESS_TABLE.lock().unwrap();
    if let Some(_) = vfork_process_table.insert(parent_pid, new_pid) {
        return_errno!(EINVAL, "current process's vfork has not returned yet");
    }

    // Save parent's user context in TLS
    VFORK_CPUCONTEXT.with(|cell| {
        let mut p_context = cell.borrow_mut();
        *p_context = unsafe { Some((*context).clone()) };
    });

    // Save parent's file table
    let mut vfork_file_tables = VFORK_PARENT_FILE_TABLES.lock().unwrap();
    let file_table = current!().files().lock().unwrap().clone();
    if let Some(_) = vfork_file_tables.insert(parent_pid, file_table) {
        return_errno!(EINVAL, "current process's vfork has not returned yet");
    }

    // This is the first time return and will return as child.
    // The second time return will return as parent in vfork_return_to_parent.
    info!("vfork child pid = {:?}", new_pid);
    return Ok(0 as isize);
}

// Check if the calling process is a vforked child process that reuse parent's task and pid.
pub fn is_vforked_child_process() -> bool {
    // Due to current limitation, the child process is reusing parent process's task and pid.
    // Thus parent pid is current pid.
    let parent_pid = current!().process().pid();
    let vfork_process_table = VFORK_PROCESS_TABLE.lock().unwrap();

    if let Some(_) = vfork_process_table.get(&parent_pid) {
        return true;
    } else {
        return false;
    }
}

// Return to parent process to continue executing
pub fn vfork_return_to_parent(mut context: *mut CpuContext, current_pid: pid_t) -> Result<isize> {
    restore_parent_process(context, current_pid)?;
    unsafe { do_sysret(&mut (*context)) };
    Ok(0)
}

fn restore_parent_process(mut context: *mut CpuContext, current_pid: pid_t) -> Result<isize> {
    VFORK_CPUCONTEXT.with(|cell| {
        let mut previous_context = cell.borrow_mut().unwrap();
        unsafe { *context = previous_context }
    });

    // Restore parent file table
    let current_thread = current!();
    let mut current_file_table = current_thread.files().lock().unwrap();
    let parent_file_table = {
        let mut parent_file_tables = VFORK_PARENT_FILE_TABLES.lock().unwrap();
        if let Some(table) = parent_file_tables.remove(&current_pid) {
            table
        } else {
            return_errno!(EFAULT, "couldn't restore parent file table");
        }
    };
    *current_file_table = parent_file_table;

    // Get child pid
    let child_pid = {
        let mut vfork_process_table = VFORK_PROCESS_TABLE.lock().unwrap();
        if let Some(pid) = vfork_process_table.remove(&current_pid) {
            pid
        } else {
            return_errno!(EFAULT, "couldn't find parent in vfork table");
        }
    };

    // Set return value to child_pid
    // This will be the second time return
    unsafe {
        (*context).rax = child_pid as u64;
    }

    Ok(0)
}

// Return:
// (bool, ThreadId, Option<ProcessRef>): (is_vforked, reuse_tid, parent_process)
pub fn check_vfork_for_exec(current_ref: &ThreadRef) -> (bool, ThreadId, Option<ProcessRef>) {
    let current_pid = current_ref.process().pid();
    if is_vforked_child_process() {
        let child_pid = {
            let vfork_process_table = VFORK_PROCESS_TABLE.lock().unwrap();
            // is_vforked_child_process can make sure the key exits
            vfork_process_table[&current_pid]
        };
        return (
            true,
            // Reuse tid which was generated when do_vfork
            ThreadId {
                tid: child_pid as u32,
            },
            // By default, use current process as parent
            None,
        );
    } else {
        // Without vfork, current process directly calls execve.
        // Construct new process structure but with same parent, pid, tid
        return (
            false,
            // Reuse self tid
            ThreadId {
                tid: current_ref.process().pid() as u32,
            },
            // Reuse parent process as parent
            Some(current_ref.process().parent().clone()),
        );
    }
}
