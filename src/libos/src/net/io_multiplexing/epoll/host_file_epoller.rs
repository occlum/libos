use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{EpollCtl, EpollEvent, EpollFlags};
use crate::fs::{HostFd, IoEvents};
use crate::prelude::*;

/// An epoll-based helper type to poll the states of a set of host files.
#[derive(Debug)]
pub struct HostFileEpoller {
    /// A map from host fd to HostFile, which maintains the set of the interesting
    /// host files.
    host_files: SgxMutex<HashMap<FileDesc, FileRef>>,
    /// The number of the interesting host files.
    count: AtomicUsize,
    /// The host fd of the underlying host epoll file.
    host_epoll_fd: HostFd,
    /// Whether the host epoll file has any events.
    is_ready: AtomicBool,
}

// TODO: the `add/mod/del_file` operation can be postponed until a `poll_files` operation,
// thus reducing the number of OCalls.

impl HostFileEpoller {
    pub fn new() -> Self {
        let host_files = Default::default();
        let count = Default::default();
        let host_epoll_fd = {
            let raw_host_fd = (|| -> Result<u32> {
                let raw_host_fd = try_libc!(libc::ocall::epoll_create1(0)) as u32;
                Ok(raw_host_fd)
            })()
            .expect("epoll_create should never fail");

            HostFd::new(raw_host_fd)
        };
        let is_ready = Default::default();
        Self {
            host_files,
            count,
            host_epoll_fd,
            is_ready,
        }
    }

    pub fn add_file(&self, host_file: FileRef, event: EpollEvent, flags: EpollFlags) -> Result<()> {
        let mut host_files = self.host_files.lock().unwrap();
        let host_fd = host_file.host_fd().unwrap().to_raw();
        let already_added = host_files.insert(host_fd, host_file.clone()).is_some();
        if already_added {
            // TODO: handle the case where one host file is somehow to be added more than once.
            warn!(
                "Cannot handle the case of adding the same host file twice in a robust way.
                This can happen if the same `HostFile` is accessible via two different LibOS fds."
            );
            return Ok(());
        }

        self.count.fetch_add(1, Ordering::Relaxed);
        self.do_epoll_ctl(libc::EPOLL_CTL_ADD, &host_file, Some((event, flags)))

        // Concurrency note:
        // The lock on self.host_files must be hold while invoking
        // do_epoll_ctl to prevent race conditions that cause the OCall to fail.
        // This same argument applies to mod_file and del_file methods.
    }

    pub fn mod_file(
        &self,
        host_file: &FileRef,
        event: EpollEvent,
        flags: EpollFlags,
    ) -> Result<()> {
        let host_files = self.host_files.lock().unwrap();
        let host_fd = host_file.host_fd().unwrap().to_raw();
        let not_added = !host_files.contains_key(&host_fd);
        if not_added {
            return_errno!(ENOENT, "the host file must be added before modifying");
        }

        self.do_epoll_ctl(libc::EPOLL_CTL_MOD, &host_file, Some((event, flags)))
    }

    pub fn del_file(&self, host_file: &FileRef) -> Result<()> {
        let mut host_files = self.host_files.lock().unwrap();
        let host_fd = host_file.host_fd().unwrap().to_raw();
        let not_added = !host_files.remove(&host_fd).is_some();
        if not_added {
            return_errno!(ENOENT, "the host file must be added before deleting");
        }

        self.count.fetch_sub(1, Ordering::Relaxed);
        self.do_epoll_ctl(libc::EPOLL_CTL_DEL, &host_file, None)
    }

    fn do_epoll_ctl(
        &self,
        raw_cmd: i32,
        host_file: &FileRef,
        event_and_flags: Option<(EpollEvent, EpollFlags)>,
    ) -> Result<()> {
        let host_epoll_fd = self.host_epoll_fd.to_raw();
        let host_fd = host_file.host_fd().unwrap().to_raw();

        let c_event = event_and_flags.map(|(event, flags)| {
            let mut c_event = event.to_c();
            c_event.events |= flags.bits() as u32;
            c_event.u64 = host_fd as u64;
            c_event
        });

        try_libc!(libc::ocall::epoll_ctl(
            host_epoll_fd as i32,
            raw_cmd,
            host_file.host_fd().unwrap().to_raw() as i32,
            c_event.as_ref().map_or(ptr::null(), |c_event| c_event) as *mut _,
        ));
        Ok(())
    }

    pub fn poll_events(&self, max_count: usize) -> usize {
        // Quick check to avoid unnecessary OCall
        if self.count.load(Ordering::Relaxed) == 0 {
            return 0;
        }

        // Do OCall to poll the host files monitored by the host epoll file
        let mut raw_events = vec![MaybeUninit::<libc::epoll_event>::uninit(); max_count];
        let timeout = 0;
        let ocall_res = || -> Result<usize> {
            let count = try_libc!(libc::ocall::epoll_wait(
                self.host_epoll_fd.to_raw() as i32,
                raw_events.as_mut_ptr() as *mut _,
                raw_events.len() as c_int,
                timeout,
            )) as usize;
            assert!(count <= max_count);
            Ok(count)
        }();

        let mut count = match ocall_res {
            Ok(count) => count,
            Err(e) => {
                warn!("Unexpected error from ocall::epoll_wait(): {:?}", e);
                0
            }
        };
        if count == 0 {
            return 0;
        }

        // Use the polled events from the host to update the states of the
        // corresponding host files
        let mut host_files = self.host_files.lock().unwrap();
        for raw_event in &raw_events[..count] {
            let raw_event = unsafe { raw_event.assume_init() };
            let io_events = IoEvents::from_bits_truncate(raw_event.events as u32);
            let host_fd = raw_event.u64 as u32;

            let host_file = match host_files.get(&host_fd) {
                None => {
                    count -= 1;
                    // The corresponding host file may be deleted
                    continue;
                }
                Some(host_file) => host_file,
            };

            host_file.recv_host_events(&io_events, true);
        }
        count
    }

    pub fn host_fd(&self) -> &HostFd {
        &self.host_epoll_fd
    }

    pub fn poll(&self) -> IoEvents {
        if self.is_ready.load(Ordering::Acquire) {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    pub fn recv_host_events(&self, events: &IoEvents) {
        let is_ready = events.contains(IoEvents::IN);
        self.is_ready.store(is_ready, Ordering::Release);
    }
}

impl Drop for HostFileEpoller {
    fn drop(&mut self) {
        unsafe {
            libc::ocall::close(self.host_epoll_fd.to_raw() as i32);
        }
    }
}
