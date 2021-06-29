use super::*;

mod epoll;
mod poll_new;
// TODO: the following three modules will soon be removed
mod io_event;
mod poll;
mod select;

pub use self::epoll::{AsEpollFile, EpollCtl, EpollEvent, EpollFile, EpollFlags};
pub use self::io_event::{
    clear_notifier_status, notify_thread, wait_for_notification, IoEvent, THREAD_NOTIFIERS,
};
pub use self::poll::{do_poll, PollEvent, PollEventFlags};
pub use self::poll_new::{do_poll_new, PollFd};
pub use self::select::{do_select, FdSetExt};

use fs::{AsEvent, AsINodeFile, AsTimer, CreationFlags, File, FileDesc, FileRef, HostFd, PipeType};
use std::any::Any;
use std::convert::TryFrom;
use std::fmt;
use std::sync::atomic::spin_loop_hint;
use time::timeval_t;
