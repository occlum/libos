use super::*;
use crate::process;

#[derive(Debug)]
struct PgrpInner {
    pgid: pid_t,
    process_group: HashMap<pid_t, ProcessRef>, // process id, process ref
    leader_process: Option<ProcessRef>,
}

#[derive(Debug)]
pub struct ProcessGrp {
    inner: RwLock<PgrpInner>,
}

impl ProcessGrp {
    pub fn default() -> Self {
        ProcessGrp {
            inner: RwLock::new(PgrpInner {
                pgid: 0,
                process_group: HashMap::new(),
                leader_process: None,
            }),
        }
    }

    pub fn pgid(&self) -> pid_t {
        self.inner.read().unwrap().pgid
    }

    pub fn get_process_number(&self) -> usize {
        self.inner.read().unwrap().process_group.len()
    }

    pub fn set_pgid(&self, pgid: pid_t) {
        self.inner.write().unwrap().pgid = pgid;
    }

    pub fn leader_process_is_set(&self) -> bool {
        self.inner.read().unwrap().leader_process.is_some()
    }

    pub fn get_leader_process(&self) -> Option<ProcessRef> {
        self.inner.read().unwrap().leader_process.clone()
    }

    pub fn set_leader_process(&self, new_leader: ProcessRef) {
        self.inner.write().unwrap().leader_process = Some(new_leader);
    }

    pub fn add_new_process(&self, process: ProcessRef) {
        self.inner
            .write()
            .unwrap()
            .process_group
            .insert(process.pid(), process);
    }

    // Create a new process group with given pid
    pub fn new(pid: pid_t) -> Result<Self> {
        let pgrp = Self::default();
        let leader_process = table::get_process(pid)?;
        pgrp.set_pgid(pid);
        pgrp.set_leader_process(leader_process.clone());
        pgrp.add_new_process(leader_process);
        Ok(pgrp)
    }

    // Remove process from process group when process exit
    pub fn remove_process(&self, process: &ProcessRef) -> Result<isize> {
        let pgid = self.pgid();
        let leader_process_is_set = self.leader_process_is_set();
        let pgrp_process_num = self.inner.read().unwrap().process_group.len();
        let process_pid = process.pid();

        if pgrp_process_num < 1 {
            return_errno!(EINVAL, "This process group is empty");
        }

        {
            // Release lock after checking to avoid deadlock
            let processes_in_pgrp = &self.inner.read().unwrap().process_group;
            if !processes_in_pgrp.contains_key(&process_pid) {
                return_errno!(EINVAL, "This process doesn't belong to this pgrp");
            }
        }

        let leader_process_pid = if leader_process_is_set {
            Some(self.get_leader_process().unwrap().pid())
        } else {
            None
        };

        if pgrp_process_num == 1 {
            table::del_pgrp(pgid);
        }

        {
            // Release lock after removing to avoid deadlock
            let mut process_group_inner = &mut self.inner.write().unwrap().process_group;
            process_group_inner.remove(&process_pid);
        }

        if leader_process_pid.is_some() && leader_process_pid.unwrap() == process.pid() {
            self.inner.write().unwrap().leader_process = None;
        }
        return Ok(0);
    }
}

pub fn do_getpgid(pid: pid_t) -> Result<pid_t> {
    let process =
        table::get_process(pid).map_err(|e| errno!(ESRCH, "pid does not match any process"))?;
    Ok(process.pgid())
}

// do_setpgid can be called under two cases:
// 1. a running process is calling for itself
// 2. a parent process is calling for its children
// Thus, parent can't setpgid to child if it is executing and only can do that when creating
// it.
pub fn do_setpgid(pid: pid_t, pgid: pid_t, is_executing: bool) -> Result<isize> {
    // If pid is zero, pid is the calling process's pid.
    let pid = if pid == 0 { do_getpid()? as pid_t } else { pid };

    // If pgid is zero, pgid is made the same as process ID specified by "pid"
    let pgid = if pgid == 0 { pid } else { pgid };

    debug!("setpgid: pid: {:?}, pgid: {:?}", pid, pgid);

    let process = table::get_process(pid)?;
    let current_pid = current!().process().pid();

    // if setpgid to a pgroup other than self, the pgroup must exist
    if pgid != pid && table::get_pgrp(pgid).is_err() {
        return_errno!(EPERM, "process group not exist");
    }

    // can't setpgid to a running process other than self
    if current_pid != pid && is_executing {
        return_errno!(EACCES, "can't setpgid to a running child process");
    }

    if let Ok(pgrp) = table::get_pgrp(pgid) {
        // pgrp exists
        process.update_pgrp(pgrp.clone());
        pgrp.add_new_process(process);
    } else {
        // pgrp not exist
        if is_executing {
            // First remove process from previous process group. New process
            // setpgid doesn't need this. This is done for self only.
            debug_assert!(current_pid == pid);
            let pgrp_ref = process.pgrp();
            pgrp_ref.remove_process(&process);
        }

        let pgrp_ref = Arc::new(ProcessGrp::new(pid)?);
        process.update_pgrp(pgrp_ref.clone());
        table::add_pgrp(pgrp_ref);
    }
    Ok(0)
}
