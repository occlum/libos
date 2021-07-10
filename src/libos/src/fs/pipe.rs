use atomic::{Atomic, Ordering};

use super::channel::{Channel, Consumer, Producer};
use super::*;
use net::PollEventFlags;

// TODO: Add F_SETPIPE_SZ in fcntl to dynamically change the size of pipe
// to improve memory efficiency. This value is got from /proc/sys/fs/pipe-max-size on linux.
pub const PIPE_BUF_SIZE: usize = 1024 * 1024;

pub fn pipe(flags: StatusFlags) -> Result<(PipeReader, PipeWriter)> {
    let channel = Channel::new(PIPE_BUF_SIZE)?;
    let channel_uid = channel.uid();
    let (producer, consumer) = channel.split();
    debug!("pipe channel uid = {}", channel_uid);

    // Only O_NONBLOCK and O_DIRECT can be applied during pipe creation
    let valid_flags = flags & (StatusFlags::O_NONBLOCK | StatusFlags::O_DIRECT);
    if valid_flags.contains(StatusFlags::O_NONBLOCK) {
        producer.set_nonblocking(true);
        consumer.set_nonblocking(true);
    }

    Ok((
        PipeReader {
            consumer: consumer,
            status_flags: Atomic::new(valid_flags),
            channel_uid,
        },
        PipeWriter {
            producer: producer,
            status_flags: Atomic::new(valid_flags),
            channel_uid,
        },
    ))
}

pub struct PipeReader {
    consumer: Consumer<u8>,
    status_flags: Atomic<StatusFlags>,
    channel_uid: usize,
}

impl File for PipeReader {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.consumer.pop_slice(buf)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        self.consumer.pop_slices(bufs)
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: 0,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::NamedPipe,
            mode: 0o600,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
        })
    }

    fn access_mode(&self) -> Result<AccessMode> {
        Ok(AccessMode::O_RDONLY)
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        let status_flags = self.status_flags.load(Ordering::Acquire);
        Ok(status_flags.clone())
    }

    fn set_status_flags(&self, mut new_status_flags: StatusFlags) -> Result<()> {
        // Only O_NONBLOCK, O_ASYNC and O_DIRECT can be set
        new_status_flags &=
            (StatusFlags::O_NONBLOCK | StatusFlags::O_ASYNC | StatusFlags::O_DIRECT);

        let is_nonblocking = new_status_flags.contains(StatusFlags::O_NONBLOCK);
        self.consumer.set_nonblocking(is_nonblocking);

        let unsupported_flags = StatusFlags::O_ASYNC | StatusFlags::O_DIRECT;
        if new_status_flags.intersects(unsupported_flags) {
            warn!("unsupported flags of pipe: {:?}", unsupported_flags);
        }

        self.status_flags.store(new_status_flags, Ordering::Release);
        Ok(())
    }

    fn poll(&self) -> Result<PollEventFlags> {
        warn!("poll is not supported for pipe");
        let events = PollEventFlags::empty();
        Ok(events)
    }

    fn poll_new(&self) -> IoEvents {
        self.consumer.poll()
    }

    fn notifier(&self) -> Option<&IoNotifier> {
        Some(self.consumer.notifier())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        match cmd {
            IoctlCmd::TCGETS(_) => return_errno!(ENOTTY, "not tty device"),
            IoctlCmd::TCSETS(_) => return_errno!(ENOTTY, "not tty device"),
            IoctlCmd::FIONREAD(arg) => {
                let ready_len = self.get_ready_len().min(std::i32::MAX as usize) as i32;
                **arg = ready_len;
                return Ok(0);
            }
            _ => return_errno!(ENOSYS, "not supported"),
        };
        unreachable!();
    }
}

impl PipeReader {
    fn get_ready_len(&self) -> usize {
        self.consumer.ready_len()
    }
}

pub struct PipeWriter {
    producer: Producer<u8>,
    status_flags: Atomic<StatusFlags>,
    channel_uid: usize,
}

impl File for PipeWriter {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.producer.push_slice(buf)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        self.producer.push_slices(bufs)
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        return_errno!(ESPIPE, "Pipe does not support seek")
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: 0,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::NamedPipe,
            mode: 0o600,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
        })
    }

    fn access_mode(&self) -> Result<AccessMode> {
        Ok(AccessMode::O_WRONLY)
    }

    fn status_flags(&self) -> Result<StatusFlags> {
        let status_flags = self.status_flags.load(Ordering::Acquire);
        Ok(status_flags.clone())
    }

    fn set_status_flags(&self, mut new_status_flags: StatusFlags) -> Result<()> {
        // Only O_NONBLOCK, O_ASYNC and O_DIRECT can be set
        new_status_flags &=
            (StatusFlags::O_NONBLOCK | StatusFlags::O_ASYNC | StatusFlags::O_DIRECT);

        let is_nonblocking = new_status_flags.contains(StatusFlags::O_NONBLOCK);
        self.producer.set_nonblocking(is_nonblocking);

        let unsupported_flags = StatusFlags::O_ASYNC | StatusFlags::O_DIRECT;
        if new_status_flags.intersects(unsupported_flags) {
            warn!("unsupported flags of pipe: {:?}", unsupported_flags);
        }

        self.status_flags.store(new_status_flags, Ordering::Release);
        Ok(())
    }

    fn poll(&self) -> Result<PollEventFlags> {
        warn!("poll is not supported for pipe");
        let events = PollEventFlags::empty();
        Ok(events)
    }

    fn poll_new(&self) -> IoEvents {
        self.producer.poll()
    }

    fn notifier(&self) -> Option<&IoNotifier> {
        Some(self.producer.notifier())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        match cmd {
            IoctlCmd::TCGETS(_) => return_errno!(ENOTTY, "not tty device"),
            IoctlCmd::TCSETS(_) => return_errno!(ENOTTY, "not tty device"),
            _ => return_errno!(ENOSYS, "not supported"),
        };
        unreachable!();
    }
}

impl fmt::Debug for PipeReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeReader")
            .field("status_flags", &self.status_flags)
            .finish()
    }
}

impl fmt::Debug for PipeWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeWriter")
            .field("status_flags", &self.status_flags)
            .finish()
    }
}

unsafe impl Send for PipeWriter {}
unsafe impl Sync for PipeWriter {}

pub fn do_pipe2(flags: u32) -> Result<[FileDesc; 2]> {
    let creation_flags = CreationFlags::from_bits_truncate(flags);
    let status_flags = StatusFlags::from_bits_truncate(flags);
    debug!("pipe2: flags: {:?} {:?}", creation_flags, status_flags);

    let (pipe_reader, pipe_writer) = pipe(status_flags)?;
    let close_on_spawn = creation_flags.must_close_on_spawn();

    let current = current!();
    let reader_fd = current.add_file(Arc::new(pipe_reader), close_on_spawn);
    let writer_fd = current.add_file(Arc::new(pipe_writer), close_on_spawn);
    trace!("pipe2: reader_fd: {}, writer_fd: {}", reader_fd, writer_fd);
    Ok([reader_fd, writer_fd])
}

pub trait PipeType {
    fn as_pipe_reader(&self) -> Result<&PipeReader>;
    fn as_pipe_writer(&self) -> Result<&PipeWriter>;
    fn channel_uid(&self) -> Result<usize>;
}
impl PipeType for FileRef {
    fn as_pipe_reader(&self) -> Result<&PipeReader> {
        self.as_any()
            .downcast_ref::<PipeReader>()
            .ok_or_else(|| errno!(EBADF, "not a pipe reader"))
    }
    fn as_pipe_writer(&self) -> Result<&PipeWriter> {
        self.as_any()
            .downcast_ref::<PipeWriter>()
            .ok_or_else(|| errno!(EBADF, "not a pipe writer"))
    }

    fn channel_uid(&self) -> Result<usize> {
        let pipe_end = self.as_pipe_reader();
        if pipe_end.is_ok() {
            return Ok(pipe_end.unwrap().channel_uid);
        } else {
            let pipe_end = self.as_pipe_writer()?;
            return Ok(pipe_end.channel_uid);
        }
    }
}
