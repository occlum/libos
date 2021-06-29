use super::*;

use crate::time::{itimerspec_t, timespec_t};
use atomic::{Atomic, Ordering};
use std::time::Duration;

/// Native Linux timerfd
#[derive(Debug)]
pub struct TimerFile {
    host_fd: HostFd,
    host_events: Atomic<IoEvents>,
    notifier: IoNotifier,
}

impl TimerFile {
    pub fn new(clockid: u32, flags: TimerCreationFlags) -> Result<Self> {
        let raw_host_fd = try_libc!({
            let mut ret: i32 = 0;
            let status = occlum_ocall_timerfd_create(&mut ret, clockid, flags.bits());
            assert!(status == sgx_status_t::SGX_SUCCESS);
            ret
        }) as FileDesc;
        let host_fd = HostFd::new(raw_host_fd);
        let host_events = Atomic::new(IoEvents::empty());
        let notifier = IoNotifier::new();
        Ok(Self {
            host_fd,
            host_events,
            notifier,
        })
    }

    pub fn host_fd(&self) -> c_int {
        self.host_fd.to_raw() as c_int
    }

    pub fn timerfd_settime(
        &self,
        flags: u32,
        new_value: *const itimerspec_t,
        old_value: Option<&mut itimerspec_t>,
    ) -> Result<i32> {
        unsafe {
            let mut ret = 0;
            let duration = Duration::new(0, 0);
            let mut u_old_value: itimerspec_t =
                itimerspec_t::new(timespec_t::from(duration), timespec_t::from(duration));
            let fd = self.host_fd() as FileDesc;
            let sgx_status =
                occlum_ocall_timerfd_settime(&mut ret, fd, flags, new_value, &mut u_old_value);
            assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
            assert!(ret == 0 || libc::errno() == Errno::EINTR as i32);
            if ret != 0 {
                if let Some(old_value) = old_value {
                    *old_value = u_old_value;
                }
                return_errno!(EINTR, "settime interrupted");
            }
            Ok(ret)
        }
    }

    pub fn timerfd_gettime(&self, curr_value: Option<&mut itimerspec_t>) -> Result<i32> {
        unsafe {
            let mut ret = 0;
            let duration = Duration::new(0, 0);
            let mut u_curr_value: itimerspec_t =
                itimerspec_t::new(timespec_t::from(duration), timespec_t::from(duration));
            let fd = self.host_fd() as FileDesc;
            let sgx_status = occlum_ocall_timerfd_gettime(&mut ret, fd, &mut u_curr_value);
            assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
            assert!(ret == 0 || libc::errno() == Errno::EINTR as i32);
            if ret != 0 {
                if let Some(curr_value) = curr_value {
                    *curr_value = u_curr_value;
                }
                return_errno!(EINTR, "gettime interrupted");
            }
            Ok(ret)
        }
    }
}

bitflags! {
    pub struct TimerCreationFlags: i32 {
        /// Provides semaphore-like semantics for reads from the new file descriptor
        /// Non-blocking
        const TFD_NONBLOCK  = 1 << 11;
        /// Close on exec
        const TFD_CLOEXEC   = 1 << 19;
    }
}

extern "C" {
    fn occlum_ocall_timerfd_create(ret: *mut i32, clockid: u32, flags: i32) -> sgx_status_t;
}

extern "C" {
    fn occlum_ocall_timerfd_settime(
        ret: *mut i32,
        fd: u32,
        flags: u32,
        new_value: *const itimerspec_t,
        old_value: *mut itimerspec_t,
    ) -> sgx_status_t;
}

extern "C" {
    fn occlum_ocall_timerfd_gettime(
        ret: *mut i32,
        fd: u32,
        curr_value: *mut itimerspec_t,
    ) -> sgx_status_t;
}

impl File for TimerFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let (buf_ptr, buf_len) = buf.as_mut().as_mut_ptr_and_len();

        let ret = try_libc!(libc::ocall::read(
            self.host_fd.to_raw() as i32,
            buf_ptr as *mut c_void,
            buf_len
        )) as usize;
        assert!(ret <= buf.len());
        Ok(ret)
    }

    // TODO: implement ioctl
    // fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
    //     self.ioctl_impl(cmd)
    // }

    fn access_mode(&self) -> Result<AccessMode> {
        Ok(AccessMode::O_RDWR)
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        let ret = try_libc!(libc::ocall::fcntl_arg0(self.host_fd(), libc::F_GETFL));
        Ok(StatusFlags::from_bits_truncate(ret as u32))
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        let valid_flags_mask = StatusFlags::O_APPEND
            | StatusFlags::O_ASYNC
            | StatusFlags::O_DIRECT
            | StatusFlags::O_NOATIME
            | StatusFlags::O_NONBLOCK;
        let raw_status_flags = (new_status_flags & valid_flags_mask).bits();
        try_libc!(libc::ocall::fcntl_arg1(
            self.host_fd(),
            libc::F_SETFL,
            raw_status_flags as c_int
        ));
        Ok(())
    }

    fn poll_new(&self) -> IoEvents {
        self.host_events.load(Ordering::Acquire)
    }

    fn notifier(&self) -> Option<&IoNotifier> {
        Some(&self.notifier)
    }

    fn host_fd(&self) -> Option<&HostFd> {
        Some(&self.host_fd)
    }

    fn update_host_events(&self, ready: &IoEvents, mask: &IoEvents, trigger_notifier: bool) {
        self.host_events.update(ready, mask, Ordering::Release);

        if trigger_notifier {
            self.notifier.broadcast(ready);
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait AsTimer {
    fn as_timer(&self) -> Result<&TimerFile>;
}

impl AsTimer for FileRef {
    fn as_timer(&self) -> Result<&TimerFile> {
        self.as_any()
            .downcast_ref::<TimerFile>()
            .ok_or_else(|| errno!(EBADF, "not an timer file"))
    }
}
