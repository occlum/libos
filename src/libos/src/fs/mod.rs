use super::*;

use process;
use rcore_fs::vfs::{
    DirentWriter, DirentWriterContext, FileSystem, FileType, FsError, INode, Metadata, Timespec,
    PATH_MAX,
};
use std;
use std::any::Any;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::path::Path;
use untrusted::{SliceAsMutPtrAndLen, SliceAsPtrAndLen};

use crate::config::ConfigMount;

pub use self::event_file::{AsEvent, EventCreationFlags, EventFile};
pub use self::events::{AtomicIoEvents, IoEvents, IoNotifier};
pub use self::file::{File, FileRef};
pub use self::file_ops::{
    occlum_ocall_ioctl, AccessMode, BuiltinIoctlNum, CreationFlags, FileMode, Flock, FlockType,
    IfConf, IoctlCmd, Stat, StatusFlags, StructuredIoctlArgType, StructuredIoctlNum,
};
pub use self::file_table::{FileDesc, FileTable, FileTableEvent, FileTableNotifier};
pub use self::fs_ops::Statfs;
pub use self::fs_view::FsView;
pub use self::host_fd::HostFd;
pub use self::inode_file::{AsINodeFile, INodeExt, INodeFile};
pub use self::pipe::PipeType;
pub use self::rootfs::ROOT_INODE;
pub use self::stdio::{HostStdioFds, StdinFile, StdoutFile};
pub use self::syscalls::*;
pub use self::timer_file::{AsTimer, TimerCreationFlags, TimerFile};

pub mod channel;
mod dev_fs;
mod event_file;
mod events;
mod file;
mod file_ops;
mod file_table;
mod fs_ops;
mod fs_view;
mod host_fd;
mod hostfs;
mod inode_file;
mod pipe;
mod procfs;
mod rootfs;
mod sefs;
mod stdio;
mod syscalls;
mod timer_file;

/// Split a `path` str to `(base_path, file_name)`
fn split_path(path: &str) -> (&str, &str) {
    let mut split = path.trim_end_matches('/').rsplitn(2, '/');
    let file_name = split.next().unwrap();
    let mut dir_path = split.next().unwrap_or(".");
    if dir_path == "" {
        dir_path = "/";
    }
    (dir_path, file_name)
}
