use super::*;

pub trait ToErrno: fmt::Display + fmt::Debug {
    fn errno(&self) -> Errno;
}

impl ToErrno for Errno {
    fn errno(&self) -> Errno {
        *self
    }
}

impl<T> From<T> for Error
where
    T: ToErrno + 'static,
{
    fn from(t: T) -> Error {
        Error::boxed(t, None)
    }
}

impl From<std::io::ErrorKind> for Errno {
    fn from(kind: std::io::ErrorKind) -> Errno {
        use std::io::ErrorKind::*;
        match kind {
            NotFound => ENOENT,
            PermissionDenied => EPERM,
            ConnectionRefused => ECONNREFUSED,
            ConnectionReset => ECONNRESET,
            ConnectionAborted => ECONNABORTED,
            NotConnected => ENOTCONN,
            AddrInUse => EADDRINUSE,
            AddrNotAvailable => EADDRNOTAVAIL,
            BrokenPipe => EPIPE,
            AlreadyExists => EEXIST,
            WouldBlock => EWOULDBLOCK,
            InvalidInput => EINVAL,
            InvalidData => EBADMSG, /* TODO: correct? */
            TimedOut => ETIMEDOUT,
            Interrupted => EINTR,
            WriteZero => EINVAL,
            UnexpectedEof => EIO,
            Other => EIO,
            _ => EIO,
        }
    }
}

impl ToErrno for std::io::Error {
    fn errno(&self) -> Errno {
        Errno::from(self.kind())
    }
}

impl ToErrno for std::ffi::NulError {
    fn errno(&self) -> Errno {
        EINVAL
    }
}

impl ToErrno for std::num::ParseIntError {
    fn errno(&self) -> Errno {
        EINVAL
    }
}

impl ToErrno for serde_json::Error {
    fn errno(&self) -> Errno {
        EINVAL
    }
}

impl ToErrno for rcore_fs::vfs::FsError {
    fn errno(&self) -> Errno {
        use rcore_fs::vfs::FsError;
        match *self {
            FsError::NotSupported => ENOSYS,
            FsError::NotFile => EISDIR,
            FsError::IsDir => EISDIR,
            FsError::NotDir => ENOTDIR,
            FsError::EntryNotFound => ENOENT,
            FsError::EntryExist => EEXIST,
            FsError::NotSameFs => EXDEV,
            FsError::InvalidParam => EINVAL,
            FsError::NoDeviceSpace => ENOMEM,
            FsError::DirRemoved => ENOENT,
            FsError::DirNotEmpty => ENOTEMPTY,
            FsError::WrongFs => EINVAL,
            FsError::DeviceError(err) => EIO,
            FsError::SymLoop => ELOOP,
            FsError::NoDevice => ENXIO,
            FsError::IOCTLError => EINVAL,
            FsError::Again => EAGAIN,
            FsError::Busy => EBUSY,
            FsError::WrProtected => EROFS,
            FsError::NoIntegrity => EIO,
            FsError::PermError => EPERM,
            FsError::NameTooLong => ENAMETOOLONG,
            FsError::FileTooBig => EFBIG,
            FsError::OpNotSupported => EOPNOTSUPP,
        }
    }
}

impl ToErrno for std::alloc::AllocError {
    fn errno(&self) -> Errno {
        ENOMEM
    }
}

impl ToErrno for std::alloc::LayoutErr {
    fn errno(&self) -> Errno {
        EINVAL
    }
}
