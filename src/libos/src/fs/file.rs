use super::*;

macro_rules! return_op_unsupported_error {
    ($op_name: expr, $errno: expr) => {{
        let errno = $errno;
        // FIXME: use the safe core::any::type_name when we upgrade to Rust 1.38 or above
        let type_name = unsafe { core::intrinsics::type_name::<Self>() };
        let op_name = $op_name;
        let error = FileOpNotSupportedError::new(errno, type_name, op_name);
        return_errno!(error)
    }};
    ($op_name: expr) => {{
        return_op_unsupported_error!($op_name, ENOSYS)
    }};
}

pub trait File: Debug + Sync + Send + Any {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        return_op_unsupported_error!("read")
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        return_op_unsupported_error!("write")
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        return_op_unsupported_error!("read_at")
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        return_op_unsupported_error!("write_at")
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        return_op_unsupported_error!("readv")
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        return_op_unsupported_error!("writev")
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        return_op_unsupported_error!("seek")
    }

    fn position(&self) -> Result<off_t> {
        return_op_unsupported_error!("position")
    }

    fn metadata(&self) -> Result<Metadata> {
        return_op_unsupported_error!("metadata")
    }

    fn set_metadata(&self, metadata: &Metadata) -> Result<()> {
        return_op_unsupported_error!("set_metadata")
    }

    fn set_len(&self, len: u64) -> Result<()> {
        return_op_unsupported_error!("set_len")
    }

    fn iterate_entries(&self, writer: &mut dyn DirentWriter) -> Result<usize> {
        return_op_unsupported_error!("iterate_entries")
    }

    fn sync_all(&self) -> Result<()> {
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        Ok(())
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        return_op_unsupported_error!("ioctl")
    }

    fn access_mode(&self) -> Result<AccessMode> {
        return_op_unsupported_error!("access_mode")
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        return_op_unsupported_error!("status_flags")
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        return_op_unsupported_error!("set_status_flags")
    }

    fn test_advisory_lock(&self, lock: &mut Flock) -> Result<()> {
        return_op_unsupported_error!("test_advisory_lock")
    }

    fn set_advisory_lock(&self, lock: &Flock) -> Result<()> {
        return_op_unsupported_error!("set_advisory_lock")
    }

    fn fallocate(&self, _mode: u32, _offset: u64, _len: u64) -> Result<()> {
        return_op_unsupported_error!("fallocate")
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        return_op_unsupported_error!("fs")
    }

    // TODO: remove this function after all users of this code are removed
    fn poll(&self) -> Result<(crate::net::PollEventFlags)> {
        return_op_unsupported_error!("poll")
    }

    // TODO: remove this function after all users of this code are removed
    fn enqueue_event(&self, _: crate::net::IoEvent) -> Result<()> {
        return_op_unsupported_error!("enqueue_event");
    }

    // TODO: remove this function after all users of this code are removed
    fn dequeue_event(&self) -> Result<()> {
        return_op_unsupported_error!("dequeue_event");
    }

    // TODO: rename poll_new to poll
    fn poll_new(&self) -> IoEvents {
        IoEvents::empty()
    }

    /// Returns a notifier that broadcast events on this file.
    ///
    /// Not every file has an associated event notifier.
    fn notifier(&self) -> Option<&IoNotifier> {
        None
    }

    /// Return the host fd, if the file is backed by an underlying host file.
    fn host_fd(&self) -> Option<&HostFd> {
        return None;
    }

    /// Update the ready events of a host file.
    ///
    /// After calling this method, the `poll` method of the `File` trait will
    /// return the latest event state on the `HostFile`.
    ///
    /// This method has no effect if the `host_fd` method returns `None`.
    fn update_host_events(&self, ready: &IoEvents, mask: &IoEvents, trigger_notifier: bool) {}

    fn as_any(&self) -> &dyn Any;
}

pub type FileRef = Arc<dyn File>;

#[derive(Copy, Clone, Debug)]
struct FileOpNotSupportedError {
    errno: Errno,
    type_name: &'static str,
    op_name: &'static str,
}

impl FileOpNotSupportedError {
    pub fn new(
        errno: Errno,
        type_name: &'static str,
        op_name: &'static str,
    ) -> FileOpNotSupportedError {
        FileOpNotSupportedError {
            errno,
            type_name,
            op_name,
        }
    }
}

impl fmt::Display for FileOpNotSupportedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} does not support {}", self.type_name, self.op_name)
    }
}

impl ToErrno for FileOpNotSupportedError {
    fn errno(&self) -> Errno {
        self.errno
    }
}
