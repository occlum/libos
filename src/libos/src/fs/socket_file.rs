use super::*;
use std::any::Any;

/// Native Linux socket
#[derive(Debug)]
pub struct SocketFile {
    fd: c_int,
}

impl SocketFile {
    pub fn new(domain: c_int, socket_type: c_int, protocol: c_int) -> Result<Self, Error> {
        let ret = unsafe { libc::ocall::socket(domain, socket_type, protocol) };
        if ret < 0 {
            Err(Error::new(Errno::from_retval(ret as i32), ""))
        } else {
            Ok(SocketFile { fd: ret })
        }
    }

    pub fn accept(
        &self,
        addr: *mut libc::sockaddr,
        addr_len: *mut libc::socklen_t,
        flags: c_int,
    ) -> Result<Self, Error> {
        let ret = unsafe { libc::ocall::accept4(self.fd, addr, addr_len, flags) };
        if ret < 0 {
            Err(Error::new(Errno::from_retval(ret as i32), ""))
        } else {
            Ok(SocketFile { fd: ret })
        }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let ret = unsafe { libc::ocall::close(self.fd) };
        if ret < 0 {
            warn!("socket (host fd: {}) close failed", self.fd);
        }
    }
}

impl File for SocketFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let ret = unsafe { libc::ocall::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if ret < 0 {
            Err(Error::new(Errno::from_retval(ret as i32), ""))
        } else {
            Ok(ret as usize)
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        let ret = unsafe { libc::ocall::write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if ret < 0 {
            Err(Error::new(Errno::from_retval(ret as i32), ""))
        } else {
            Ok(ret as usize)
        }
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        unimplemented!()
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize, Error> {
        unimplemented!()
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize, Error> {
        unimplemented!()
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize, Error> {
        unimplemented!()
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t, Error> {
        Err(Error::new(Errno::ESPIPE, "Socket does not support seek"))
    }

    fn metadata(&self) -> Result<Metadata, Error> {
        unimplemented!()
    }

    fn set_len(&self, len: u64) -> Result<(), Error> {
        unimplemented!()
    }

    fn sync_all(&self) -> Result<(), Error> {
        unimplemented!()
    }

    fn sync_data(&self) -> Result<(), Error> {
        unimplemented!()
    }

    fn read_entry(&self) -> Result<String, Error> {
        unimplemented!()
    }

    fn as_any(&self) -> &Any {
        self
    }
}