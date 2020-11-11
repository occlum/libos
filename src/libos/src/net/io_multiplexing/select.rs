use std::time::Duration;

use super::poll_new::{do_poll_new, PollFd};
use crate::fs::IoEvents;
use crate::prelude::*;

pub fn do_select(
    num_fds: FileDesc,
    mut readfds: Option<&mut libc::fd_set>,
    mut writefds: Option<&mut libc::fd_set>,
    mut exceptfds: Option<&mut libc::fd_set>,
    timeout: Option<&mut Duration>,
) -> Result<isize> {
    debug!(
        "do_select: read: {}, write: {}, exception: {}, timeout: {:?}",
        readfds.format(),
        writefds.format(),
        exceptfds.format(),
        timeout,
    );

    if num_fds as usize > libc::FD_SETSIZE {
        return_errno!(EINVAL, "the value is too large");
    }

    // Convert the three fd_set's to an array of PollFd
    let poll_fds = {
        let mut poll_fds = Vec::new();
        for fd in (0..num_fds).into_iter() {
            let events = {
                let (mut readable, mut writable, mut except) = (false, false, false);
                if let Some(readfds) = readfds.as_ref() {
                    if readfds.is_set(fd) {
                        readable = true;
                    }
                }
                if let Some(writefds) = writefds.as_ref() {
                    if writefds.is_set(fd) {
                        writable = true;
                    }
                }
                if let Some(exceptfds) = exceptfds.as_ref() {
                    if exceptfds.is_set(fd) {
                        except = true;
                    }
                }
                convert_rwe_to_events(readable, writable, except)
            };

            if events.is_empty() {
                continue;
            }

            let poll_fd = PollFd::new(fd, events);
            poll_fds.push(poll_fd);
        }
        poll_fds
    };
    // Clear up the three input fd_set's, which will be used for output as well
    if let Some(readfds) = readfds.as_mut() {
        readfds.clear();
    }
    if let Some(writefds) = writefds.as_mut() {
        writefds.clear();
    }
    if let Some(exceptfds) = exceptfds.as_mut() {
        exceptfds.clear();
    }

    // Do the poll syscall that is equivalent to the select syscall
    let num_ready_fds = do_poll_new(&poll_fds, timeout)?;
    if num_ready_fds == 0 {
        return Ok(0);
    }

    // Convert poll's pollfd results to select's fd_set results
    let mut num_events = 0;
    for poll_fd in &poll_fds {
        let fd = poll_fd.fd();
        let revents = poll_fd.revents().get();
        let (readable, writable, exception) = convert_events_to_rwe(&revents);
        if readable {
            readfds.set(fd);
            num_events += 1;
        }
        if writable {
            writefds.set(fd);
            num_events += 1;
        }
        if exception {
            exceptfds.set(fd);
            num_events += 1;
        }
    }
    Ok(num_events)
}

// Convert select's rwe input to poll's IoEvents input accordingg to Linux's
// behavior.
fn convert_rwe_to_events(readable: bool, writable: bool, except: bool) -> IoEvents {
    let mut events = IoEvents::empty();
    if readable {
        events |= IoEvents::IN;
    }
    if writable {
        events |= IoEvents::OUT;
    }
    if except {
        events |= IoEvents::PRI;
    }
    events
}

// Convert poll's IoEvents results to select's rwe results according to Linux's
// behavior.
fn convert_events_to_rwe(events: &IoEvents) -> (bool, bool, bool) {
    let readable = events.intersects(IoEvents::IN | IoEvents::HUP | IoEvents::ERR);
    let writable = events.intersects(IoEvents::OUT | IoEvents::ERR);
    let exception = events.contains(IoEvents::PRI);
    (readable, writable, exception)
}

/// Safe methods for `libc::fd_set`
pub trait FdSetExt {
    fn new_empty() -> Self;
    fn unset(&mut self, fd: FileDesc) -> Result<()>;
    fn is_set(&self, fd: FileDesc) -> bool;
    fn set(&mut self, fd: FileDesc) -> Result<()>;
    fn clear(&mut self);
    fn is_empty(&self) -> bool;
    fn as_raw_ptr_mut(&mut self) -> *mut Self;
    fn format(&self) -> String;
}

impl FdSetExt for libc::fd_set {
    fn new_empty() -> Self {
        unsafe { core::mem::zeroed() }
    }

    fn unset(&mut self, fd: FileDesc) -> Result<()> {
        if fd as usize >= libc::FD_SETSIZE {
            return_errno!(EINVAL, "fd exceeds FD_SETSIZE");
        }
        unsafe {
            libc::FD_CLR(fd as c_int, self);
        }
        Ok(())
    }

    fn set(&mut self, fd: FileDesc) -> Result<()> {
        if fd as usize >= libc::FD_SETSIZE {
            return_errno!(EINVAL, "fd exceeds FD_SETSIZE");
        }
        unsafe {
            libc::FD_SET(fd as c_int, self);
        }
        Ok(())
    }

    fn clear(&mut self) {
        unsafe {
            libc::FD_ZERO(self);
        }
    }

    fn is_set(&self, fd: FileDesc) -> bool {
        if fd as usize >= libc::FD_SETSIZE {
            return false;
        }
        unsafe { libc::FD_ISSET(fd as c_int, self as *const Self as *mut Self) }
    }

    fn is_empty(&self) -> bool {
        let set = unsafe {
            std::slice::from_raw_parts(self as *const Self as *const u64, libc::FD_SETSIZE / 64)
        };
        set.iter().all(|&x| x == 0)
    }

    fn as_raw_ptr_mut(&mut self) -> *mut Self {
        if self.is_empty() {
            std::ptr::null_mut()
        } else {
            self as *mut libc::fd_set
        }
    }

    fn format(&self) -> String {
        let set = unsafe {
            std::slice::from_raw_parts(self as *const Self as *const u64, libc::FD_SETSIZE / 64)
        };
        format!("libc::fd_set: {:x?}", set)
    }
}

trait FdSetOptionExt {
    fn format(&self) -> String;
    fn set(&mut self, fd: FileDesc) -> Result<()>;
}

impl FdSetOptionExt for Option<&mut libc::fd_set> {
    fn format(&self) -> String {
        if let Some(self_) = self.as_ref() {
            self_.format()
        } else {
            "(empty)".to_string()
        }
    }

    fn set(&mut self, fd: FileDesc) -> Result<()> {
        if let Some(inner) = self.as_mut() {
            inner.set(fd)
        } else {
            Ok(())
        }
    }
}
