/// File POSIX advisory lock
use super::*;
use crate::events::{Waiter, WaiterQueue};
use crate::util::sync::rw_lock::RwLockWriteGuard;
use process::pid_t;
use rcore_fs::vfs::{INodeLockList, INodeLockListCreater};

/// C struct for a lock
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flock {
    pub l_type: u16,
    pub l_whence: u16,
    pub l_start: off_t,
    pub l_len: off_t,
    pub l_pid: pid_t,
}

impl flock {
    pub fn copy_from_safe(&mut self, lock: &Flock) {
        self.l_type = lock.type_ as u16;
        if FlockType::F_UNLCK != lock.type_ {
            self.l_whence = FlockWhence::SEEK_SET as u16;
            self.l_start = lock.start;
            self.l_len = if lock.end == off_t::max_value() {
                0
            } else {
                lock.end - lock.start + 1
            };
            self.l_pid = lock.owner;
        }
    }
}

/// Type safe representation of flock
pub struct Flock {
    pub type_: FlockType,
    start: off_t,
    end: off_t,
    owner: pid_t,
    waiters: WaiterQueue,
    is_nonblocking: bool,
}

impl Flock {
    pub fn from_c(flock_c: &flock, file: &FileRef, is_nonblocking: bool) -> Result<Self> {
        let type_ = FlockType::from_u16(flock_c.l_type)?;
        let (start, end) = {
            let whence = FlockWhence::from_u16(flock_c.l_whence)?;
            let start = match whence {
                FlockWhence::SEEK_SET => flock_c.l_start,
                FlockWhence::SEEK_CUR => file
                    .position()?
                    .checked_add(flock_c.l_start)
                    .ok_or_else(|| errno!(EOVERFLOW, "start overflow"))?,
                FlockWhence::SEEK_END => (file.metadata()?.size as off_t)
                    .checked_add(flock_c.l_start)
                    .ok_or_else(|| errno!(EOVERFLOW, "start overflow"))?,
            };
            if start < 0 {
                return_errno!(EINVAL, "invalid start");
            }
            if flock_c.l_len > 0 {
                let end = start
                    .checked_add(flock_c.l_len - 1)
                    .ok_or_else(|| errno!(EOVERFLOW, "end overflow"))?;
                (start, end)
            } else if flock_c.l_len == 0 {
                let end = off_t::max_value();
                (start, end)
            } else {
                // l_len < 0, must recalculate the start
                let end = start - 1;
                let new_start = start + flock_c.l_len;
                if new_start < 0 {
                    return_errno!(EINVAL, "invalid len");
                }
                (new_start, end)
            }
        };
        Ok(Self {
            type_,
            start,
            end,
            owner: current!().process().pid(),
            waiters: WaiterQueue::new(),
            is_nonblocking,
        })
    }

    pub fn from(lock: &Self) -> Self {
        Self {
            type_: lock.type_,
            start: lock.start,
            end: lock.end,
            owner: lock.owner,
            waiters: WaiterQueue::new(),
            is_nonblocking: lock.is_nonblocking,
        }
    }

    pub fn new(type_: FlockType, start: off_t, end: off_t, is_nonblocking: bool) -> Result<Self> {
        if start > end {
            return_errno!(EINVAL, "end is less than start");
        }
        Ok(Self {
            type_,
            start,
            end,
            owner: current!().process().pid(),
            waiters: WaiterQueue::new(),
            is_nonblocking,
        })
    }

    pub fn reset_by(&mut self, lock: &Self) {
        self.type_ = lock.type_;
        self.start = lock.start;
        self.end = lock.end;
        self.owner = lock.owner;
    }

    pub fn is_nonblocking(&self) -> bool {
        self.is_nonblocking
    }

    pub fn enqueue_waiter(&mut self, waiter: &Waiter) {
        self.waiters.reset_and_enqueue(waiter)
    }

    pub fn dequeue_and_wake_all_waiters(&mut self) -> usize {
        self.waiters.dequeue_and_wake_all()
    }

    pub fn conflict_with(&self, other: &Self) -> bool {
        // locks owned by the same process do not conflict
        if self.same_owner_with(other) {
            return false;
        }
        // locks do not conflict if not overlap
        if !self.overlap_with(other) {
            return false;
        }
        // write lock is exclusive
        if self.type_ == FlockType::F_WRLCK || other.type_ == FlockType::F_WRLCK {
            return true;
        }
        false
    }

    pub fn overlap_with(&self, other: &Self) -> bool {
        self.start <= other.end && self.end >= other.start
    }

    pub fn same_owner_with(&self, other: &Self) -> bool {
        self.owner == other.owner
    }

    pub fn same_type_with(&self, other: &Self) -> bool {
        self.type_ == other.type_
    }

    pub fn set_start(&mut self, new_start: off_t) {
        assert!(new_start <= self.end);
        let old_start = self.start;
        self.start = new_start;
        if old_start < new_start {
            // Shrink the range, should wake the waiters
            self.dequeue_and_wake_all_waiters();
        }
    }

    pub fn set_end(&mut self, new_end: off_t) {
        assert!(new_end >= self.start);
        let old_end = self.end;
        self.end = new_end;
        if old_end > new_end {
            // Shrink the range, should wake the waiters
            self.dequeue_and_wake_all_waiters();
        }
    }
}

impl Drop for Flock {
    fn drop(&mut self) {
        self.dequeue_and_wake_all_waiters();
    }
}

impl Debug for Flock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flock")
            .field("owner", &self.owner)
            .field("type_", &self.type_)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("is_nonblocking", &self.is_nonblocking)
            .finish()
    }
}

/// Used to allocate the lock list for INode
pub struct FlockListCreater;

impl INodeLockListCreater for FlockListCreater {
    fn new_empty_list(&self) -> Arc<dyn INodeLockList> {
        Arc::new(FlockList::new())
    }
}

/// File POSIX lock list
/// Locks are sorted by owner process, then by starting offset.
/// The List will merge adjacent & overlapping locks whenever possible.
pub struct FlockList {
    inner: RwLock<VecDeque<Flock>>,
}

impl INodeLockList for FlockList {
    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}

impl FlockList {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(VecDeque::new()),
        }
    }

    pub fn test_lock(&self, lock: &mut Flock) -> Result<()> {
        debug!("test_lock with Flock: {:?}", lock);
        let list = self.inner.read().unwrap();
        for existing_lock in list.iter() {
            if lock.conflict_with(existing_lock) {
                // Return the details about the conflict lock
                lock.reset_by(existing_lock);
                return Ok(());
            }
        }
        // The advisory lock could be placed
        lock.type_ = FlockType::F_UNLCK;
        Ok(())
    }

    pub fn set_lock_wait(&self, lock: &Flock) -> Result<()> {
        debug!("set_lock_wait with Flock: {:?}", lock);
        loop {
            let mut list = self.inner.write().unwrap();
            if let Some(mut conflict_lock) = list.iter_mut().find(|l| l.conflict_with(lock)) {
                if lock.is_nonblocking() {
                    return_errno!(EAGAIN, "lock conflict, try again later");
                }
                // Start to wait
                let waiter = Waiter::new();
                // TODO: Add deadlock detection, and returns EDEADLK
                warn!("Do not support deadlock detection, maybe wait infinitely");
                conflict_lock.enqueue_waiter(&waiter);
                // Ensure that we drop any locks before wait
                drop(list);
                waiter.wait(None)?;
                // Wake up, let's try to set lock again
                continue;
            }
            // No conflict here, insert the lock
            return Self::insert_lock_into_list(&mut list, lock);
        }
    }

    fn insert_lock_into_list(
        list: &mut RwLockWriteGuard<VecDeque<Flock>>,
        lock: &Flock,
    ) -> Result<()> {
        let first_same_owner_idx = match list.iter().position(|l| l.same_owner_with(lock)) {
            Some(idx) => idx,
            None => {
                // Can't find the old lock with same owner, just insert it at front.
                list.push_front(Flock::from(lock));
                return Ok(());
            }
        };
        // Let's start to process the locks with same owner.
        let mut idx = first_same_owner_idx;
        let mut added_maybe_adjacent_or_overlap_with_next = false;
        loop {
            if idx > list.len() {
                break;
            }
            if idx == list.len() || !list[idx].same_owner_with(lock) {
                if !added_maybe_adjacent_or_overlap_with_next {
                    list.insert(idx, Flock::from(lock));
                }
                break;
            }
            if list[idx].same_type_with(lock) {
                // Use 'start - 1' instead of 'end + 1' to avoid overflow
                if list[idx].end < lock.start - 1 {
                    idx += 1;
                    continue;
                }
                if lock.end < list[idx].start - 1 {
                    // Found the position to insert the new lock
                    if !added_maybe_adjacent_or_overlap_with_next {
                        list.insert(idx, Flock::from(lock));
                    }
                    break;
                }
                // Found adjacent or overlapping locks with same type
                if added_maybe_adjacent_or_overlap_with_next {
                    if lock.end < list[idx].end {
                        // Merge this lock to the previous lock
                        let end = list[idx].end;
                        list[idx - 1].set_end(end);
                        list.remove(idx);
                        break;
                    } else {
                        // Previous lock can replace this lock
                        list.remove(idx);
                        continue;
                    }
                }
                // Merge adjacent or overlapping locks
                if lock.start < list[idx].start {
                    list[idx].set_start(lock.start);
                }
                if lock.end <= list[idx].end {
                    break;
                }
                list[idx].set_end(lock.end);
                added_maybe_adjacent_or_overlap_with_next = true;
                idx += 1;
            } else {
                // Process locks with different type
                if list[idx].end < lock.start {
                    idx += 1;
                    continue;
                }
                if lock.end < list[idx].start {
                    // Found the position to insert the new lock
                    if !added_maybe_adjacent_or_overlap_with_next {
                        list.insert(idx, Flock::from(lock));
                    }
                    break;
                }
                // Found overlapping locks with different type
                if lock.end < list[idx].end {
                    if lock.start <= list[idx].start {
                        // Shrink the old lock and insert new lock before the old lock
                        list[idx].set_start(lock.end + 1);
                        if !added_maybe_adjacent_or_overlap_with_next {
                            list.insert(idx, Flock::from(lock));
                        }
                    } else {
                        // The new lock is in the middle of old lock, making the old lock to split
                        let r_lk = {
                            let mut r_lk = Flock::from(&list[idx]);
                            r_lk.set_start(lock.end + 1);
                            r_lk
                        };
                        list.insert(idx + 1, r_lk);
                        list.insert(idx + 1, Flock::from(lock));
                        list[idx].set_end(lock.start - 1);
                    }
                    break;
                }
                // lock.end >= list[idx].end
                if lock.start <= list[idx].start {
                    // New lock can replace the old lock
                    list.remove(idx);
                    if !added_maybe_adjacent_or_overlap_with_next {
                        list.insert(idx, Flock::from(lock));
                        added_maybe_adjacent_or_overlap_with_next = true;
                        idx += 1;
                    }
                } else {
                    // Shrink the old lock and insert new lock after the old lock
                    list[idx].set_end(lock.start - 1);
                    list.insert(idx + 1, Flock::from(lock));
                    added_maybe_adjacent_or_overlap_with_next = true;
                    idx += 2;
                }
            }
        }
        Ok(())
    }

    pub fn unlock(&self, lock: &Flock) -> Result<()> {
        debug!("unlock with Flock: {:?}", lock);
        let mut list = self.inner.write().unwrap();
        let mut skipped = 0;
        loop {
            let idx = match list
                .iter()
                .skip(skipped)
                .position(|l| l.same_owner_with(lock) && l.overlap_with(lock))
            {
                Some(idx) => idx,
                None => break,
            };
            if lock.end < list[idx].end {
                if lock.start <= list[idx].start {
                    // Shrink the lock
                    list[idx].set_start(lock.end + 1);
                } else {
                    // Split the lock
                    let r_lk = {
                        let mut r_lk = Flock::from(&list[idx]);
                        r_lk.set_start(lock.end + 1);
                        r_lk
                    };
                    list[idx].set_end(lock.start - 1);
                    list.insert(idx + 1, r_lk);
                }
                // The next lock must have a higher offset, finish to unlock
                break;
            }
            // lock.end >= list[idx].end
            if lock.start <= list[idx].start {
                // The lock can be deleted from the list
                list.remove(idx);
                skipped = idx;
            } else {
                // Shrink the lock
                list[idx].set_end(lock.start - 1);
                skipped = idx + 1;
            }
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum FlockType {
    F_RDLCK = 0,
    F_WRLCK = 1,
    F_UNLCK = 2,
}

impl FlockType {
    pub fn from_u16(_type: u16) -> Result<Self> {
        Ok(match _type {
            0 => FlockType::F_RDLCK,
            1 => FlockType::F_WRLCK,
            2 => FlockType::F_UNLCK,
            _ => return_errno!(EINVAL, "invalid flock type"),
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(u16)]
pub enum FlockWhence {
    SEEK_SET = 0,
    SEEK_CUR = 1,
    SEEK_END = 2,
}

impl FlockWhence {
    pub fn from_u16(whence: u16) -> Result<Self> {
        Ok(match whence {
            0 => FlockWhence::SEEK_SET,
            1 => FlockWhence::SEEK_CUR,
            2 => FlockWhence::SEEK_END,
            _ => return_errno!(EINVAL, "Invalid whence"),
        })
    }
}
