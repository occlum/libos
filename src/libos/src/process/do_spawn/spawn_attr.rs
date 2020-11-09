use crate::prelude::*;
use crate::signal::sigset_t;
use crate::util::mem_util::from_user::check_ptr;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(i16)]
pub enum spawn_attr_flags {
    POSIX_SPAWN_RESETIDS = 1,
    POSIX_SPAWN_SETPGROUP = 2,
    POSIX_SPAWN_SETSIGDEF = 4,
    POSIX_SPAWN_SETSIGMASK = 8,
    POSIX_SPAWN_SETSCHEDPARAM = 16,
    POSIX_SPAWN_SETSCHEDULER = 32,
    POSIX_SPAWN_USEVFORK = 64,
    POSIX_SPAWN_SETSID = 128,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct sched_param {
    __sched_priority: i32,
}

// Rust version of posix_spawnattr_t
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct spawnattr_t {
    pub __flags: i16,
    pub __pgrp: pid_t,
    __sd: sigset_t,
    __ss: sigset_t,
    __sp: sched_param,
    __policy: i32,
}

impl spawnattr_t {
    pub fn from_raw_ptr(attr_ptr: *const spawnattr_t) -> Result<Self> {
        check_ptr(attr_ptr)?;
        let attr = unsafe { *attr_ptr };
        attr.validate()?;
        Ok(attr)
    }

    pub fn is_set(&self, flag: spawn_attr_flags) -> bool {
        (self.__flags & flag as i16) == flag as i16
    }

    pub fn get_pgrp(&self) -> pid_t {
        self.__pgrp
    }

    fn validate(&self) -> Result<()> {
        // TODO: Add more rules when needed
        if self.__flags >= 0 {
            Ok(())
        } else {
            return_errno!(EINVAL, "invalid value for spawnattr_t");
        }
    }
}
