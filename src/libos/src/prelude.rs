pub use sgx_trts::libc;
pub use sgx_trts::libc::off_t;
pub use sgx_types::*;

use std;
pub use std::cell::{Cell, RefCell};
pub use std::cmp::{max, min};
pub use std::collections::{HashMap, VecDeque};
pub use std::fmt::{Debug, Display};
pub use std::prelude::v1::*;
pub use std::sync::{
    Arc, SgxMutex, SgxMutexGuard, SgxRwLock, SgxRwLockReadGuard, SgxRwLockWriteGuard,
};

// Override prelude::Result with error::Result
pub use crate::error::Result;
pub use crate::error::*;
pub use crate::fs::{File, FileDesc, FileRef};
pub use crate::process::{pid_t, uid_t};
pub use crate::util::sync::RwLock;
pub use test_proc_macro::occlum_test;

macro_rules! debug_trace {
    () => {
        debug!("> Line = {}, File = {}", line!(), file!())
    };
}

macro_rules! current {
    () => {
        crate::process::current::get()
    };
}

pub fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align != 0 && align.is_power_of_two());
    align_down(addr + (align - 1), align)
}

pub fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align != 0 && align.is_power_of_two());
    addr & !(align - 1)
}

pub fn unbox<T>(value: Box<T>) -> T {
    *value
}
