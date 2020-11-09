use std::fmt;

use super::wait::WaitQueue;
use super::{ForcedExitStatus, ProcessGrpRef, ProcessRef, TermStatus, ThreadRef};
use crate::prelude::*;
use crate::signal::{SigDispositions, SigNum, SigQueues};

pub use self::builder::ProcessBuilder;
pub use self::idle::IDLE;

mod builder;
mod idle;

pub struct Process {
    // Immutable info
    pid: pid_t,
    exec_path: String,
    // Mutable info
    parent: Option<RwLock<ProcessRef>>,
    pgrp: RwLock<Option<ProcessGrpRef>>,
    inner: SgxMutex<ProcessInner>,
    // Signal
    sig_dispositions: RwLock<SigDispositions>,
    sig_queues: RwLock<SigQueues>,
    forced_exit_status: ForcedExitStatus,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ProcessStatus {
    Running,
    Stopped,
    Zombie,
}

impl Process {
    /// Get process ID.
    pub fn pid(&self) -> pid_t {
        self.pid
    }

    /// Get process group ID
    pub fn pgid(&self) -> pid_t {
        self.pgrp().pgid()
    }

    /// Get the parent process.
    ///
    /// Precondition. The process is not the idle process.
    pub fn parent(&self) -> ProcessRef {
        debug_assert!(self.pid() != 0);
        self.parent
            .as_ref()
            // All non-idle process has a parent
            .unwrap()
            .read()
            .unwrap()
            .clone()
    }

    /// Get the process group.
    pub fn pgrp(&self) -> ProcessGrpRef {
        self.pgrp
            .read()
            .unwrap()
            .as_ref()
            // Process must be assigned a process group
            .unwrap()
            .clone()
    }

    /// Update process group when setpgid is called
    pub fn update_pgrp(&self, new_pgrp: ProcessGrpRef) {
        let mut pgrp = self.pgrp.write().unwrap();
        *pgrp = Some(new_pgrp);
    }

    /// Remove process group when process exit
    pub fn remove_pgrp(&self) {
        let mut pgrp = self.pgrp.write().unwrap();
        *pgrp = None;
    }

    /// Get the main thread.
    ///
    /// The main thread is a thread whose tid equals to the process's pid.
    /// Usually, the main thread is the last thread that exits in a process.
    pub fn main_thread(&self) -> Option<ThreadRef> {
        if let Some(leader) = self.leader_thread() {
            if leader.tid() == self.pid() {
                Some(leader)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the leader thread.
    ///
    /// As long as there are some threads in the process, there is a leader.
    /// The leader thread is usually the main thread, but not always.
    pub fn leader_thread(&self) -> Option<ThreadRef> {
        self.inner().leader_thread()
    }

    /// Get threads.
    pub fn threads(&self) -> Vec<ThreadRef> {
        self.inner()
            .threads()
            .map(|vec_ref| vec_ref.clone())
            .unwrap_or_else(|| Vec::new())
    }

    /// Get status.
    pub fn status(&self) -> ProcessStatus {
        self.inner().status()
    }

    /// Get the path of the executable
    pub fn exec_path(&self) -> &str {
        &self.exec_path
    }

    /// Get the signal queues for process-directed signals.
    pub fn sig_queues(&self) -> &RwLock<SigQueues> {
        &self.sig_queues
    }

    /// Get the process-wide signal dispositions.
    pub fn sig_dispositions(&self) -> &RwLock<SigDispositions> {
        &self.sig_dispositions
    }

    pub fn term_status(&self) -> Option<TermStatus> {
        self.forced_exit_status.term_status()
    }

    /// Check whether the process has been forced to exit.
    pub fn is_forced_to_exit(&self) -> bool {
        self.forced_exit_status.is_forced_to_exit()
    }

    /// Force a process to exit.
    ///
    /// There are two reasons to force a process to exit:
    /// 1. Receiving a fatal signal;
    /// 2. Performing exit_group syscall.
    ///
    /// A process may be forced to exit many times, but only the first time counts.
    pub fn force_exit(&self, term_status: TermStatus) {
        self.forced_exit_status.force_exit(term_status);
    }

    /// Get the internal representation of the process.
    ///
    /// For the purpose of encapsulation, this method is invisible to other subsystems.
    pub(super) fn inner(&self) -> SgxMutexGuard<ProcessInner> {
        self.inner.lock().unwrap()
    }
}

pub enum ProcessInner {
    Live {
        status: LiveStatus,
        children: Vec<ProcessRef>,
        waiting_children: WaitQueue<ProcessFilter, pid_t>,
        threads: Vec<ThreadRef>,
    },
    Zombie {
        term_status: TermStatus,
    },
}

impl ProcessInner {
    pub fn new() -> Self {
        Self::Live {
            status: LiveStatus::Running,
            children: Vec::new(),
            waiting_children: WaitQueue::new(),
            threads: Vec::new(),
        }
    }

    pub fn status(&self) -> ProcessStatus {
        match self {
            Self::Live { status, .. } => (*status).into(),
            Self::Zombie { .. } => ProcessStatus::Zombie,
        }
    }

    pub fn children(&self) -> Option<&Vec<ProcessRef>> {
        match self {
            Self::Live { children, .. } => Some(children),
            Self::Zombie { .. } => None,
        }
    }

    pub fn children_mut(&mut self) -> Option<&mut Vec<ProcessRef>> {
        match self {
            Self::Live { children, .. } => Some(children),
            Self::Zombie { .. } => None,
        }
    }

    pub fn num_children(&mut self) -> usize {
        self.children().map(|children| children.len()).unwrap_or(0)
    }

    pub fn is_child_of(&self, pid: pid_t) -> bool {
        match self.children() {
            Some(children) => children.iter().find(|&child| child.pid() == pid).is_some(),
            None => false,
        }
    }

    pub fn threads(&self) -> Option<&Vec<ThreadRef>> {
        match self {
            Self::Live { threads, .. } => Some(threads),
            Self::Zombie { .. } => None,
        }
    }

    pub fn threads_mut(&mut self) -> Option<&mut Vec<ThreadRef>> {
        match self {
            Self::Live { threads, .. } => Some(threads),
            Self::Zombie { .. } => None,
        }
    }

    pub fn num_threads(&mut self) -> usize {
        self.threads().map(|threads| threads.len()).unwrap_or(0)
    }

    pub fn leader_thread(&self) -> Option<ThreadRef> {
        match self.threads() {
            Some(threads) => {
                if threads.len() > 0 {
                    Some(threads[0].clone())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    pub fn waiting_children_mut(&mut self) -> Option<&mut WaitQueue<ProcessFilter, pid_t>> {
        match self {
            Self::Live {
                waiting_children, ..
            } => Some(waiting_children),
            _ => None,
        }
    }

    pub fn remove_zombie_child(&mut self, zombie_pid: pid_t) -> ProcessRef {
        let mut children = self.children_mut().unwrap();
        let zombie_i = children
            .iter()
            .position(|child| child.pid() == zombie_pid)
            .unwrap();
        children.swap_remove(zombie_i)
    }

    /// Exit means two things: 1) transfer all children to a new parent; 2) update the status.
    ///
    /// A lock guard for the new parent process is passed so that the transfer can be done
    /// atomically.
    pub fn exit(
        &mut self,
        term_status: TermStatus,
        new_parent_ref: &ProcessRef,
        new_parent_inner: &mut SgxMutexGuard<ProcessInner>,
    ) {
        // Check preconditions
        debug_assert!(self.status() == ProcessStatus::Running);
        debug_assert!(self.num_threads() == 0);

        // When this process exits, its children are adopted by the init process
        for child in self.children().unwrap() {
            let child_inner = child.inner();
            let mut parent = child.parent.as_ref().unwrap().write().unwrap();
            *parent = new_parent_ref.clone();

            new_parent_inner.children_mut().unwrap().push(child.clone());
        }

        *self = Self::Zombie { term_status };
    }

    pub fn term_status(&self) -> Option<TermStatus> {
        // Check preconditions
        debug_assert!(self.status() == ProcessStatus::Zombie);

        match self {
            Self::Zombie { term_status } => Some(*term_status),
            _ => None,
        }
    }
}

impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        self.pid() == other.pid()
    }
}

// Why manual implementation of Debug trait?
//
// An explict implementation of Debug trait is required since Process and Thread
// structs refer to each other. Thus, the automatically-derived implementation
// of Debug trait for the two structs may lead to infinite loop.

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ppid = if self.pid() > 0 {
            Some(self.parent().pid())
        } else {
            None
        };

        f.debug_struct("Process")
            .field("pid", &self.pid())
            .field("exec_path", &self.exec_path())
            .field("ppid", &ppid)
            .field("inner", &self.inner())
            .finish()
    }
}

impl fmt::Debug for ProcessInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessInner::Live {
                status,
                children,
                threads,
                ..
            } => f
                .debug_struct("ProcessInner::Live")
                .field("status", &status)
                .field(
                    "child_pids",
                    &children
                        .iter()
                        .map(|child| child.pid())
                        .collect::<Vec<pid_t>>(),
                )
                .field(
                    "thread_tids",
                    &threads
                        .iter()
                        .map(|thread| thread.tid())
                        .collect::<Vec<pid_t>>(),
                )
                .finish(),
            ProcessInner::Zombie { term_status, .. } => f
                .debug_struct("ProcessInner::Zombie")
                .field("term_status", term_status)
                .finish(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LiveStatus {
    Running,
    Stopped,
}

impl Into<ProcessStatus> for LiveStatus {
    fn into(self) -> ProcessStatus {
        match self {
            Self::Running => ProcessStatus::Running,
            Self::Stopped => ProcessStatus::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProcessFilter {
    WithAnyPid,
    WithPid(pid_t),
    WithPgid(pid_t),
}

// TODO: is this necessary?
unsafe impl Send for ProcessFilter {}
