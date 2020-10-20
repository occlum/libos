use super::*;
use fs::{File, FileRef, IoctlCmd};
use rcore_fs::vfs::{FileType, Metadata, Timespec};
use std::any::Any;
use std::collections::btree_map::BTreeMap;
use std::fmt;
use std::sync::atomic::{spin_loop_hint, AtomicUsize, Ordering};
use std::sync::SgxMutex as Mutex;
use util::ring_buf::{ring_buffer, RingBufReader, RingBufWriter};

pub struct UnixSocketFile {
    inner: Mutex<UnixSocket>,
}

// TODO: add enqueue_event and dequeue_event
impl File for UnixSocketFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.read(buf)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.write(buf)
    }

    fn read_at(&self, _offset: usize, buf: &mut [u8]) -> Result<usize> {
        self.read(buf)
    }

    fn write_at(&self, _offset: usize, buf: &[u8]) -> Result<usize> {
        self.write(buf)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.readv(bufs)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.writev(bufs)
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
            type_: FileType::Socket,
            mode: 0,
            nlinks: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
        })
    }

    fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        let mut inner = self.inner.lock().unwrap();
        inner.ioctl(cmd)
    }

    fn poll(&self) -> Result<PollEventFlags> {
        let mut inner = self.inner.lock().unwrap();
        inner.poll()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

static SOCKETPAIR_NUM: AtomicUsize = AtomicUsize::new(0);
const SOCK_PATH_PREFIX: &str = "socketpair_";

impl UnixSocketFile {
    pub fn new(socket_type: c_int, protocol: c_int) -> Result<Self> {
        let inner = UnixSocket::new(socket_type, protocol)?;
        Ok(UnixSocketFile {
            inner: Mutex::new(inner),
        })
    }

    pub fn bind(&self, path: impl AsRef<str>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.bind(path)
    }

    pub fn listen(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.listen()
    }

    pub fn accept(&self) -> Result<UnixSocketFile> {
        let mut inner = self.inner.lock().unwrap();
        let new_socket = inner.accept()?;
        Ok(UnixSocketFile {
            inner: Mutex::new(new_socket),
        })
    }

    pub fn connect(&self, path: impl AsRef<str>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.connect(path)
    }

    pub fn socketpair(socket_type: i32, protocol: i32) -> Result<(Self, Self)> {
        let listen_socket = Self::new(socket_type, protocol)?;
        let bound_path = listen_socket.bind_until_success();
        listen_socket.listen()?;

        let client_socket = Self::new(socket_type, protocol)?;
        client_socket.connect(&bound_path)?;

        let accepted_socket = listen_socket.accept()?;
        Ok((client_socket, accepted_socket))
    }

    fn bind_until_success(&self) -> String {
        loop {
            let sock_path_suffix = SOCKETPAIR_NUM.fetch_add(1, Ordering::SeqCst);
            let sock_path = format!("{}{}", SOCK_PATH_PREFIX, sock_path_suffix);
            if self.bind(&sock_path).is_ok() {
                return sock_path;
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        if let Status::Connected(_) = self.inner.lock().unwrap().status {
            true
        } else {
            false
        }
    }
}

impl Debug for UnixSocketFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnixSocketFile {{ ... }}")
    }
}

pub trait AsUnixSocket {
    fn as_unix_socket(&self) -> Result<&UnixSocketFile>;
}

impl AsUnixSocket for FileRef {
    fn as_unix_socket(&self) -> Result<&UnixSocketFile> {
        self.as_any()
            .downcast_ref::<UnixSocketFile>()
            .ok_or_else(|| errno!(EBADF, "not a unix socket"))
    }
}

pub struct UnixSocket {
    obj: Option<Arc<UnixSocketObject>>,
    status: Status,
}

enum Status {
    None,
    Listening,
    Connected(Channel),
}

impl UnixSocket {
    /// C/S 1: Create a new unix socket
    pub fn new(socket_type: c_int, protocol: c_int) -> Result<Self> {
        if socket_type == libc::SOCK_STREAM && (protocol == 0 || protocol == libc::PF_UNIX) {
            Ok(UnixSocket {
                obj: None,
                status: Status::None,
            })
        } else {
            // Return different error numbers according to input
            return_errno!(ENOSYS, "unimplemented unix socket type")
        }
    }

    /// Server 2: Bind the socket to a file system path
    pub fn bind(&mut self, path: impl AsRef<str>) -> Result<()> {
        // TODO: check permission
        if self.obj.is_some() {
            return_errno!(EINVAL, "The socket is already bound to an address.");
        }
        self.obj = Some(UnixSocketObject::create(path)?);
        Ok(())
    }

    /// Server 3: Listen to a socket
    pub fn listen(&mut self) -> Result<()> {
        self.status = Status::Listening;
        Ok(())
    }

    /// Server 4: Accept a connection on listening.
    pub fn accept(&mut self) -> Result<UnixSocket> {
        match self.status {
            Status::Listening => {}
            _ => return_errno!(EINVAL, "unix socket is not listening"),
        };
        // FIXME: Block. Now spin loop.
        let socket = loop {
            if let Some(socket) = self.obj.as_mut().unwrap().pop() {
                break socket;
            }
            spin_loop_hint();
        };
        Ok(socket)
    }

    /// Client 2: Connect to a path
    pub fn connect(&mut self, path: impl AsRef<str>) -> Result<()> {
        if let Status::Listening = self.status {
            return_errno!(EINVAL, "unix socket is listening?");
        }
        let obj = UnixSocketObject::get(path)
            .ok_or_else(|| errno!(EINVAL, "unix socket path not found"))?;
        // TODO: Mov the buffer allocation to function new to comply with the bahavior of unix
        let (channel1, channel2) = Channel::new_pair()?;
        self.status = Status::Connected(channel1);
        obj.push(UnixSocket {
            obj: Some(obj.clone()),
            status: Status::Connected(channel2),
        });
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.channel_mut()?.reader.read_from_buffer(buf)
    }

    pub fn readv(&mut self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        self.channel_mut()?.reader.read_from_vector(bufs)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.channel_mut()?.writer.write_to_buffer(buf)
    }

    pub fn writev(&mut self, bufs: &[&[u8]]) -> Result<usize> {
        self.channel_mut()?.writer.write_to_vector(bufs)
    }

    fn poll(&self) -> Result<PollEventFlags> {
        let channel_result = self.channel();
        if let Ok(channel) = channel_result {
            let readable = channel.reader.can_read() && !channel.reader.is_peer_closed();
            let writable = channel.writer.can_write() && !channel.writer.is_peer_closed();
            let events = if readable ^ writable {
                if channel.reader.can_read() {
                    PollEventFlags::POLLRDHUP | PollEventFlags::POLLIN | PollEventFlags::POLLRDNORM
                } else {
                    PollEventFlags::POLLRDHUP
                }
            // both readable and writable
            } else if readable {
                PollEventFlags::POLLIN
                    | PollEventFlags::POLLOUT
                    | PollEventFlags::POLLRDNORM
                    | PollEventFlags::POLLWRNORM
            } else {
                PollEventFlags::POLLHUP
            };
            Ok(events)
        } else {
            // For the unconnected socket
            // TODO: add write support for unconnected sockets like linux does
            Ok(PollEventFlags::POLLHUP)
        }
    }

    pub fn ioctl(&self, cmd: &mut IoctlCmd) -> Result<i32> {
        match cmd {
            IoctlCmd::FIONREAD(arg) => {
                let bytes_to_read = self
                    .channel()?
                    .reader
                    .bytes_to_read()
                    .min(std::i32::MAX as usize) as i32;
                **arg = bytes_to_read;
            }
            _ => return_errno!(EINVAL, "unknown ioctl cmd for unix socket"),
        }
        Ok(0)
    }

    fn channel_mut(&mut self) -> Result<&mut Channel> {
        if let Status::Connected(ref mut channel) = &mut self.status {
            Ok(channel)
        } else {
            return_errno!(EBADF, "UnixSocket is not connected")
        }
    }

    fn channel(&self) -> Result<&Channel> {
        if let Status::Connected(channel) = &self.status {
            Ok(channel)
        } else {
            return_errno!(EBADF, "UnixSocket is not connected")
        }
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        if let Status::Listening = self.status {
            // Only remove the object when there is one
            if let Some(obj) = self.obj.as_ref() {
                UnixSocketObject::remove(&obj.path);
            }
        }
    }
}

pub struct UnixSocketObject {
    path: String,
    accepted_sockets: Mutex<VecDeque<UnixSocket>>,
}

impl UnixSocketObject {
    fn push(&self, unix_socket: UnixSocket) {
        let mut queue = self.accepted_sockets.lock().unwrap();
        queue.push_back(unix_socket);
    }
    fn pop(&self) -> Option<UnixSocket> {
        let mut queue = self.accepted_sockets.lock().unwrap();
        queue.pop_front()
    }
    fn get(path: impl AsRef<str>) -> Option<Arc<Self>> {
        let mut paths = UNIX_SOCKET_OBJS.lock().unwrap();
        paths.get(path.as_ref()).map(|obj| obj.clone())
    }
    fn create(path: impl AsRef<str>) -> Result<Arc<Self>> {
        let mut paths = UNIX_SOCKET_OBJS.lock().unwrap();
        if paths.contains_key(path.as_ref()) {
            return_errno!(EADDRINUSE, "unix socket path already exists");
        }
        let obj = Arc::new(UnixSocketObject {
            path: path.as_ref().to_string(),
            accepted_sockets: Mutex::new(VecDeque::new()),
        });
        paths.insert(path.as_ref().to_string(), obj.clone());
        Ok(obj)
    }
    fn remove(path: impl AsRef<str>) {
        let mut paths = UNIX_SOCKET_OBJS.lock().unwrap();
        paths.remove(path.as_ref());
    }
}

struct Channel {
    reader: RingBufReader,
    writer: RingBufWriter,
}

unsafe impl Send for Channel {}
unsafe impl Sync for Channel {}

impl Channel {
    fn new_pair() -> Result<(Channel, Channel)> {
        let (reader1, writer1) = ring_buffer(DEFAULT_BUF_SIZE)?;
        let (reader2, writer2) = ring_buffer(DEFAULT_BUF_SIZE)?;
        let channel1 = Channel {
            reader: reader1,
            writer: writer2,
        };
        let channel2 = Channel {
            reader: reader2,
            writer: writer1,
        };
        Ok((channel1, channel2))
    }
}

// TODO: Add SO_SNDBUF and SO_RCVBUF to set/getsockopt to dynamcally change the size.
// This value is got from /proc/sys/net/core/rmem_max and wmem_max that are same on linux.
pub const DEFAULT_BUF_SIZE: usize = 208 * 1024;

lazy_static! {
    static ref UNIX_SOCKET_OBJS: Mutex<BTreeMap<String, Arc<UnixSocketObject>>> =
        Mutex::new(BTreeMap::new());
}
