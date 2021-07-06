use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::prelude::*;

pub fn do_set_robust_list(list_head_ptr: *mut RobustListHead, len: usize) -> Result<()> {
    debug!(
        "set_robust_list: list_head_ptr: {:?}, len: {}",
        list_head_ptr, len
    );
    if std::mem::size_of::<RobustListHead>() != len {
        return_errno!(EINVAL, "unknown size of RobustListHead");
    }
    let robust_list = NonNull::new(list_head_ptr);
    let current = current!();
    current.set_robust_list(robust_list);
    Ok(())
}

pub fn do_get_robust_list(tid: pid_t) -> Result<*mut RobustListHead> {
    debug!("get_robust_list: tid: {}", tid);
    let thread = if tid == 0 {
        current!()
    } else {
        super::table::get_thread(tid)?
    };
    let robust_list_ptr = thread
        .robust_list()
        .map(|robust_list| robust_list.as_ptr())
        .unwrap_or(std::ptr::null_mut());
    Ok(robust_list_ptr)
}

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;
const ROBUST_LIST_LIMIT: u16 = 2048;

/// This struct is same with Linux's robust_list
#[repr(C)]
struct RobustList {
    next: *const RobustList,
}

/// This struct is same with Linux's robust_list_head
#[repr(C)]
pub struct RobustListHead {
    list: RobustList,
    futex_offset: usize,
    list_op_pending: *const RobustList,
}

impl RobustListHead {
    pub fn wake(&self, tid: pid_t) -> Result<()> {
        debug!("wake rubust list of the dying thread(tid: {})", tid);
        let mut list_cnt = 0;
        let mut entry_ptr = self.list.next;
        while entry_ptr != &self.list {
            let next_entry_ptr = {
                if entry_ptr.is_null() {
                    return_errno!(EFAULT, "entry_ptr is null pointer");
                }
                unsafe { (*entry_ptr).next }
            };
            if entry_ptr != self.list_op_pending {
                let futex_key_addr = unsafe { Self::futex_key_addr(entry_ptr, self.futex_offset) };
                Self::wake_one_futex(futex_key_addr, tid)?;
            }
            entry_ptr = next_entry_ptr;
            list_cnt += 1;
            // Avoid excessively long or circular lists
            if list_cnt >= ROBUST_LIST_LIMIT {
                break;
            }
        }
        if !self.list_op_pending.is_null() {
            let pending_key_addr =
                unsafe { Self::futex_key_addr(self.list_op_pending, self.futex_offset) };
            Self::wake_one_futex(pending_key_addr, tid)?;
        }
        Ok(())
    }

    unsafe fn futex_key_addr(robust_list_ptr: *const RobustList, offset: usize) -> *mut u32 {
        (robust_list_ptr as *mut u8).add(offset) as *mut u32
    }

    fn wake_one_futex(key_addr: *mut u32, tid: pid_t) -> Result<()> {
        let atomic_val = {
            if key_addr.is_null() {
                return_errno!(EFAULT, "futex key addr is null pointer");
            }
            unsafe { AtomicU32::from_mut(&mut *key_addr) }
        };
        let mut futex_val = atomic_val.load(Ordering::SeqCst);
        loop {
            // This futex may held by another thread
            if futex_val & FUTEX_TID_MASK != tid {
                break;
            }
            let new_futex_val = (futex_val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
            if let Err(cur_futex_val) = atomic_val.compare_exchange(
                futex_val,
                new_futex_val,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                // The futex has changed, let's retry with current value
                futex_val = cur_futex_val;
                continue;
            }
            // Wake one robust futex
            if atomic_val.load(Ordering::SeqCst) & FUTEX_WAITERS != 0 {
                debug!("wake robust addr: {:?}", key_addr);
                super::do_futex::futex_wake(key_addr as *const i32, 1)?;
            }
            break;
        }
        Ok(())
    }
}
