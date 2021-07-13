/// Process/thread subsystem.
///
/// The subsystem implements process/thread-related system calls, which are
/// mainly based on the three concepts below:
///
/// * [`Process`]. A process has a parent and may have multiple child processes and
/// can own multiple threads.
/// * [`Thread`]. A thread belongs to one and only one process and owns a set
/// of OS resources, e.g., virtual memory, file tables, etc.
/// * [`Task`]. A task belongs to one and only one thread, for which it deals with
/// the low-level details about thread execution.
use crate::fs::{FileRef, FileTable, FsView};
use crate::misc::ResourceLimits;
use crate::prelude::*;
use crate::sched::SchedAgent;
use crate::signal::{SigDispositions, SigQueues};
use crate::vm::ProcessVM;

use self::process::{ProcessBuilder, ProcessInner};
use self::thread::{ThreadBuilder, ThreadId, ThreadInner};
use self::wait::{WaitQueue, Waiter};

pub use self::do_exit::handle_force_exit;
pub use self::do_futex::{futex_wait, futex_wake};
pub use self::do_robust_list::RobustListHead;
pub use self::do_spawn::do_spawn_without_exec;
pub use self::process::{Process, ProcessFilter, ProcessStatus, IDLE};
pub use self::spawn_attribute::posix_spawnattr_t;
pub use self::syscalls::*;
pub use self::task::Task;
pub use self::term_status::{ForcedExitStatus, TermStatus};
pub use self::thread::{Thread, ThreadStatus};

mod do_arch_prctl;
mod do_clone;
mod do_exec;
mod do_exit;
mod do_futex;
mod do_getpid;
mod do_robust_list;
mod do_set_tid_address;
mod do_spawn;
mod do_wait4;
mod prctl;
mod process;
mod spawn_attribute;
mod syscalls;
mod term_status;
mod thread;
mod wait;

pub mod current;
pub mod elf_file;
pub mod table;
pub mod task;

// TODO: need to separate C's version pid_t with Rust version Pid.
// pid_t must be signed as negative values may have special meaning
// (check wait4 and kill for examples), while Pid should be a
// non-negative value.
#[allow(non_camel_case_types)]
pub type pid_t = u32;
#[allow(non_camel_case_types)]
pub type uid_t = u32;

pub type ProcessRef = Arc<Process>;
pub type ThreadRef = Arc<Thread>;
pub type FileTableRef = Arc<SgxMutex<FileTable>>;
pub type ProcessVMRef = Arc<ProcessVM>;
pub type FsViewRef = Arc<RwLock<FsView>>;
pub type SchedAgentRef = Arc<SgxMutex<SchedAgent>>;
pub type ResourceLimitsRef = Arc<SgxMutex<ResourceLimits>>;
