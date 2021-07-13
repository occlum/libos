use super::*;
use crate::net::PollEventFlags;
use rcore_fs_sefs::dev::SefsMac;

pub struct INodeFile {
    inode: Arc<dyn INode>,
    abs_path: String,
    offset: SgxMutex<usize>,
    access_mode: AccessMode,
    status_flags: RwLock<StatusFlags>,
}

impl File for INodeFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let mut offset = self.offset.lock().unwrap();
        let len = self.inode.read_at(*offset, buf).map_err(|e| errno!(e))?;
        *offset += len;
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let mut offset = self.offset.lock().unwrap();
        if self.status_flags.read().unwrap().always_append() {
            let info = self.inode.metadata()?;
            *offset = info.size;
        }
        let len = self.inode.write_at(*offset, buf)?;
        *offset += len;
        Ok(len)
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let len = self.inode.read_at(offset, buf)?;
        Ok(len)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let len = self.inode.write_at(offset, buf)?;
        Ok(len)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let mut offset = self.offset.lock().unwrap();
        let mut total_len = 0;
        for buf in bufs {
            match self.inode.read_at(*offset, buf) {
                Ok(len) => {
                    total_len += len;
                    *offset += len;
                }
                Err(_) if total_len != 0 => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total_len)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let mut offset = self.offset.lock().unwrap();
        if self.status_flags.read().unwrap().always_append() {
            let info = self.inode.metadata()?;
            *offset = info.size;
        }
        let mut total_len = 0;
        for buf in bufs {
            match self.inode.write_at(*offset, buf) {
                Ok(len) => {
                    total_len += len;
                    *offset += len;
                }
                Err(_) if total_len != 0 => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total_len)
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        let mut offset = self.offset.lock().unwrap();
        let new_offset = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::End(off) => (self.inode.metadata()?.size as i64)
                .checked_add(off)
                .ok_or_else(|| errno!(EOVERFLOW, "file offset overflow"))?,
            SeekFrom::Current(off) => (*offset as i64)
                .checked_add(off)
                .ok_or_else(|| errno!(EOVERFLOW, "file offset overflow"))?,
        };
        if new_offset < 0 {
            return_errno!(EINVAL, "file offset is negative");
        }
        *offset = new_offset as usize;
        Ok(*offset as i64)
    }

    fn metadata(&self) -> Result<Metadata> {
        let metadata = self.inode.metadata()?;
        Ok(metadata)
    }

    fn set_metadata(&self, metadata: &Metadata) -> Result<()> {
        self.inode.set_metadata(metadata)?;
        Ok(())
    }

    fn fallocate(&self, mode: FallocateMode, offset: usize, len: usize) -> Result<()> {
        if !self.access_mode.writable() {
            return_errno!(EBADF, "File is not opened for writing");
        }
        self.inode.fallocate(mode, offset, len)?;
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable. Can't set len.");
        }
        self.inode.resize(len as usize)?;
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        self.inode.sync_all()?;
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        self.inode.sync_data()?;
        Ok(())
    }

    fn iterate_entries(&self, writer: &mut dyn DirentWriter) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable. Can't read entry.");
        }
        let mut offset = self.offset.lock().unwrap();
        let mut dir_ctx = DirentWriterContext::new(*offset, writer);
        let written_size = self.inode.iterate_entries(&mut dir_ctx)?;
        *offset = dir_ctx.pos();
        Ok(written_size)
    }

    fn access_mode(&self) -> Result<AccessMode> {
        Ok(self.access_mode.clone())
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        let status_flags = self.status_flags.read().unwrap();
        Ok(status_flags.clone())
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        let mut status_flags = self.status_flags.write().unwrap();
        // Currently, F_SETFL can change only the O_APPEND,
        // O_ASYNC, O_NOATIME, and O_NONBLOCK flags
        let valid_flags_mask = StatusFlags::O_APPEND
            | StatusFlags::O_ASYNC
            | StatusFlags::O_NOATIME
            | StatusFlags::O_NONBLOCK;
        status_flags.remove(valid_flags_mask);
        status_flags.insert(new_status_flags & valid_flags_mask);
        Ok(())
    }

    fn test_advisory_lock(&self, lock: &mut Flock) -> Result<()> {
        // Let the advisory lock could be placed
        // TODO: Implement the real advisory lock
        lock.l_type = FlockType::F_UNLCK;
        Ok(())
    }

    fn set_advisory_lock(&self, lock: &Flock) -> Result<()> {
        match lock.l_type {
            FlockType::F_RDLCK => {
                if !self.access_mode.readable() {
                    return_errno!(EACCES, "File not readable");
                }
            }
            FlockType::F_WRLCK => {
                if !self.access_mode.writable() {
                    return_errno!(EACCES, "File not writable");
                }
            }
            _ => (),
        }
        // Let the advisory lock could be acquired or released
        // TODO: Implement the real advisory lock
        Ok(())
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        match cmd {
            IoctlCmd::TCGETS(_) => return_errno!(ENOTTY, "not tty device"),
            IoctlCmd::TCSETS(_) => return_errno!(ENOTTY, "not tty device"),
            _ => {}
        };
        let cmd_num = cmd.cmd_num();
        let cmd_argp = cmd.arg_ptr() as usize;
        self.inode.io_control(cmd_num, cmd_argp)?;
        Ok(0)
    }

    fn poll_new(&self) -> IoEvents {
        match self.inode.poll() {
            Ok(poll_status) => IoEvents::from_poll_status(&poll_status),
            Err(_) => IoEvents::empty(),
        }
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        Ok(self.inode.fs())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl INodeFile {
    pub fn open(inode: Arc<dyn INode>, abs_path: &str, flags: u32) -> Result<Self> {
        let access_mode = AccessMode::from_u32(flags)?;
        if (access_mode.readable() && !inode.allow_read()?) {
            return_errno!(EACCES, "File not readable");
        }
        if (access_mode.writable() && !inode.allow_write()?) {
            return_errno!(EACCES, "File not writable");
        }
        if access_mode.writable() && inode.metadata()?.type_ == FileType::Dir {
            return_errno!(EISDIR, "Directory cannot be open to write");
        }
        let creation_flags = CreationFlags::from_bits_truncate(flags);
        if creation_flags.should_truncate()
            && inode.metadata()?.type_ == FileType::File
            && access_mode.writable()
        {
            // truncate the length to 0
            inode.resize(0)?;
        }
        let status_flags = StatusFlags::from_bits_truncate(flags);
        Ok(INodeFile {
            inode,
            abs_path: abs_path.to_owned(),
            offset: SgxMutex::new(0),
            access_mode,
            status_flags: RwLock::new(status_flags),
        })
    }

    pub fn abs_path(&self) -> &str {
        &self.abs_path
    }
}

impl Debug for INodeFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "INodeFile {{ inode: ???, abs_path: {}, pos: {}, access_mode: {:?}, status_flags: {:#o} }}",
            self.abs_path,
            *self.offset.lock().unwrap(),
            self.access_mode,
            *self.status_flags.read().unwrap()
        )
    }
}

pub trait INodeExt {
    fn read_as_vec(&self) -> Result<Vec<u8>>;
    fn allow_write(&self) -> Result<bool>;
    fn allow_read(&self) -> Result<bool>;
}

impl INodeExt for dyn INode {
    fn read_as_vec(&self) -> Result<Vec<u8>> {
        let size = self.metadata()?.size;
        let mut buf = Vec::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }
        self.read_at(0, buf.as_mut_slice())?;
        Ok(buf)
    }

    fn allow_write(&self) -> Result<bool> {
        let info = self.metadata()?;
        let file_mode = FileMode::from_bits_truncate(info.mode);
        Ok(file_mode.is_writable())
    }

    fn allow_read(&self) -> Result<bool> {
        let info = self.metadata()?;
        let file_mode = FileMode::from_bits_truncate(info.mode);
        Ok(file_mode.is_readable())
    }
}

pub trait AsINodeFile {
    fn as_inode_file(&self) -> Result<&INodeFile>;
}

impl AsINodeFile for FileRef {
    fn as_inode_file(&self) -> Result<&INodeFile> {
        self.as_any()
            .downcast_ref::<INodeFile>()
            .ok_or_else(|| errno!(EBADF, "not an inode file"))
    }
}
