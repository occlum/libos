use super::super::{current, TermStatus, ThreadRef};
use super::Task;
use crate::interrupt;
use crate::prelude::*;

/// Enqueue a new thread so that it can be executed later.
pub fn enqueue(new_thread: ThreadRef) {
    let existing_thread = NEW_THREAD_TABLE
        .lock()
        .unwrap()
        .insert(new_thread.tid(), new_thread);
    // There should NOT have any pending process with the same ID
    assert!(existing_thread.is_none());
}

/// Enqueue a new thread and execute it in a separate host thread.
pub fn enqueue_and_exec(new_thread: ThreadRef) {
    let new_tid = new_thread.tid();
    enqueue(new_thread);

    let mut ret = 0;
    let ocall_status = unsafe { occlum_ocall_exec_thread_async(&mut ret, new_tid) };
    // TODO: check if there are any free TCS before do the OCall
    assert!(ocall_status == sgx_status_t::SGX_SUCCESS && ret == 0);
}

fn dequeue(libos_tid: pid_t) -> Result<ThreadRef> {
    NEW_THREAD_TABLE
        .lock()
        .unwrap()
        .remove(&libos_tid)
        .ok_or_else(|| errno!(ESRCH, "the given TID does not match any pending thread"))
}

/// Execute the specified LibOS thread in the current host thread.
pub fn exec(libos_tid: pid_t, host_tid: pid_t) -> Result<i32> {
    let this_thread: ThreadRef = dequeue(libos_tid)?;
    this_thread.start(host_tid);

    // Enable current::get() from now on
    current::set(this_thread.clone());

    interrupt::enable_current_thread();

    unsafe {
        // task may only be modified by this function; so no lock is needed
        do_exec_task(this_thread.task() as *const Task as *mut Task);
    }

    debug!("thread {:?} exit", this_thread.tid());

    interrupt::disable_current_thread();

    let term_status = this_thread.inner().term_status().unwrap();
    match term_status {
        TermStatus::Exited(status) => {
            info!("Thread exited: tid = {}, status = {}", libos_tid, status);
        }
        TermStatus::Killed(signum) => {
            info!("Thread killed: tid = {}, signum = {:?}", libos_tid, signum);
        }
    }

    // Disable current::get()
    current::reset();

    Ok(term_status.as_u32() as i32)
}

lazy_static! {
    static ref NEW_THREAD_TABLE: SgxMutex<HashMap<pid_t, ThreadRef>> =
        { SgxMutex::new(HashMap::new()) };
}

extern "C" {
    fn occlum_ocall_exec_thread_async(ret: *mut i32, libos_tid: pid_t) -> sgx_status_t;
    fn do_exec_task(task: *mut Task) -> i32;
}
