use super::*;

use crate::fs::{
    occlum_ocall_ioctl, AccessMode, CreationFlags, File, FileRef, IoctlCmd, StatusFlags,
};
use std::any::Any;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;

/// Native linux socket
#[derive(Debug)]
pub struct HostSocket {
    host_fd: c_int,
}

impl HostSocket {
    pub fn new(
        domain: AddressFamily,
        socket_type: SocketType,
        file_flags: FileFlags,
        protocol: i32,
    ) -> Result<Self> {
        let host_fd = try_libc!(libc::ocall::socket(
            domain as i32,
            socket_type as i32 | file_flags.bits(),
            protocol
        ));
        Ok(Self { host_fd })
    }

    pub fn host_fd(&self) -> c_int {
        self.host_fd
    }

    pub fn bind(&self, addr: &SockAddr) -> Result<()> {
        let (addr_ptr, addr_len) = addr.as_ptr_and_len();

        let ret = try_libc!(libc::ocall::bind(
            self.host_fd(),
            addr_ptr as *const libc::sockaddr,
            addr_len as u32
        ));
        Ok(())
    }

    pub fn listen(&self, backlog: i32) -> Result<()> {
        let ret = try_libc!(libc::ocall::listen(self.host_fd(), backlog));
        Ok(())
    }

    pub fn accept(&self, flags: FileFlags) -> Result<(Self, Option<SockAddr>)> {
        let mut sockaddr = SockAddr::default();
        let mut addr_len = sockaddr.len();

        let ret = try_libc!(libc::ocall::accept4(
            self.host_fd(),
            sockaddr.as_mut_ptr() as *mut _,
            &mut addr_len as *mut _ as *mut _,
            flags.bits()
        ));

        let addr_option = if addr_len != 0 {
            sockaddr.set_len(addr_len)?;
            Some(sockaddr)
        } else {
            None
        };
        Ok((Self { host_fd: ret }, addr_option))
    }

    pub fn connect(&self, addr: &Option<SockAddr>) -> Result<()> {
        debug!("host_fd: {} addr {:?}", self.host_fd(), addr);

        let (addr_ptr, addr_len) = if let Some(sock_addr) = addr {
            sock_addr.as_ptr_and_len()
        } else {
            (std::ptr::null(), 0)
        };

        let ret = try_libc!(libc::ocall::connect(
            self.host_fd(),
            addr_ptr,
            addr_len as u32
        ));
        Ok(())
    }

    pub fn sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        addr_option: &Option<SockAddr>,
    ) -> Result<usize> {
        let bufs = vec![buf];
        let name_option = addr_option.as_ref().map(|addr| addr.as_slice());
        self.do_sendmsg(&bufs, flags, name_option, None)
    }

    pub fn recvfrom(&self, buf: &mut [u8], flags: RecvFlags) -> Result<(usize, Option<SockAddr>)> {
        let mut sockaddr = SockAddr::default();
        let mut bufs = vec![buf];
        let (bytes_recv, addr_len, _, _) =
            self.do_recvmsg(&mut bufs, flags, Some(sockaddr.as_mut_slice()), None)?;

        let addr_option = if addr_len != 0 {
            sockaddr.set_len(addr_len)?;
            Some(sockaddr)
        } else {
            None
        };
        Ok((bytes_recv, addr_option))
    }
}

impl Drop for HostSocket {
    fn drop(&mut self) {
        let ret = unsafe { libc::ocall::close(self.host_fd) };
        assert!(ret == 0);
    }
}

pub trait HostSocketType {
    fn as_host_socket(&self) -> Result<&HostSocket>;
}

impl HostSocketType for FileRef {
    fn as_host_socket(&self) -> Result<&HostSocket> {
        self.as_any()
            .downcast_ref::<HostSocket>()
            .ok_or_else(|| errno!(EBADF, "not a host socket"))
    }
}
