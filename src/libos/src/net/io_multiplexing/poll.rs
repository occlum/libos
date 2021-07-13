use super::*;

bitflags! {
    #[derive(Default)]
    #[repr(C)]
    pub struct PollEventFlags: i16 {
        const POLLIN        = 0x0001;
        const POLLPRI       = 0x0002;
        const POLLOUT       = 0x0004;
        const POLLERR       = 0x0008;
        const POLLHUP       = 0x0010;
        const POLLNVAL      = 0x0020;
        const POLLRDNORM    = 0x0040;
        const POLLRDBAND    = 0x0080;
        const POLLWRNORM    = 0x0100;
        const POLLWRBAND    = 0x0200;
        const POLLMSG       = 0x0400;
        const POLLRDHUP     = 0x2000;
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PollEvent {
    fd: FileDesc,
    events: PollEventFlags,
    revents: PollEventFlags,
}

impl PollEvent {
    pub fn new(fd: FileDesc, events: PollEventFlags) -> Self {
        let revents = PollEventFlags::empty();
        Self {
            fd,
            events,
            revents,
        }
    }

    pub fn fd(&self) -> FileDesc {
        self.fd
    }

    pub fn events(&self) -> PollEventFlags {
        self.events
    }

    pub fn revents(&self) -> PollEventFlags {
        self.revents
    }

    pub fn set_events(&mut self, events: PollEventFlags) {
        self.events = events;
    }

    pub fn get_revents(&mut self, events: PollEventFlags) -> bool {
        self.revents = (self.events
            | PollEventFlags::POLLHUP
            | PollEventFlags::POLLERR
            | PollEventFlags::POLLNVAL)
            & events;
        !self.revents.is_empty()
    }
}

pub fn do_poll(pollfds: &mut [PollEvent], timeout: *mut timeval_t) -> Result<usize> {
    let mut libos_ready_num = 0;
    let mut host_ready_num = 0;
    let mut notified = 0;
    let current = current!();

    // The pollfd of the host file
    let mut host_pollfds: Vec<PollEvent> = Vec::new();
    // The indices in pollfds of host file
    let mut index_host_pollfds: Vec<usize> = Vec::new();
    // Vec<usize>: The indices in pollfds which may be more than one for the same file
    // PollEvent: the merged pollfd of FileDesc
    let mut libos_pollfds: HashMap<FileDesc, (PollEvent, Vec<usize>)> = HashMap::new();

    for (i, pollfd) in pollfds.iter_mut().enumerate() {
        // Ignore negative fds
        if (pollfd.fd() as i32) < 0 {
            continue;
        }

        let file_ref = if let Ok(file_ref) = current.file(pollfd.fd) {
            file_ref
        } else {
            pollfd.get_revents(PollEventFlags::POLLNVAL);
            continue;
        };

        if file_ref.as_unix_socket().is_ok()
            || file_ref.as_pipe_reader().is_ok()
            || file_ref.as_pipe_writer().is_ok()
        {
            let events = file_ref.poll()?;
            debug!("polled events are {:?}", events);
            if pollfd.get_revents(events) {
                libos_ready_num += 1;
            }

            // Merge pollfds with the same fd
            if let Some((old_pollfd, index_vec)) =
                libos_pollfds.insert(pollfd.fd(), (*pollfd, vec![i]))
            {
                let (new_pollfd, new_index_vec) = libos_pollfds.get_mut(&pollfd.fd()).unwrap();
                new_pollfd.set_events(old_pollfd.events() | new_pollfd.events());
                new_index_vec.extend_from_slice(&index_vec);
            }
            continue;
        }

        if let Ok(socket) = file_ref.as_host_socket() {
            let fd = socket.host_fd().unwrap().to_raw();
            index_host_pollfds.push(i);
            host_pollfds.push(PollEvent::new(fd, pollfd.events()));
        } else if let Ok(eventfd) = file_ref.as_event() {
            let fd = eventfd.host_fd() as FileDesc;
            index_host_pollfds.push(i);
            host_pollfds.push(PollEvent::new(fd, pollfd.events()));
        } else if let Ok(timerfd) = file_ref.as_timer() {
            let fd = timerfd.host_fd() as FileDesc;
            index_host_pollfds.push(i);
            host_pollfds.push(PollEvent::new(fd, pollfd.events()));
        } else {
            return_errno!(EBADF, "not a supported file type");
        }
    }

    let notifier_host_fd = THREAD_NOTIFIERS
        .lock()
        .unwrap()
        .get(&current.tid())
        .unwrap()
        .host_fd();

    debug!(
        "number of ready libos fd is {}; notifier_host_fd is {}",
        libos_ready_num, notifier_host_fd
    );

    let ret = if libos_ready_num != 0 {
        // Clear the status of notifier before wait
        clear_notifier_status(current!().tid())?;

        let mut zero_timeout: timeval_t = timeval_t::new(0, 0);

        do_poll_in_host(&mut host_pollfds, &mut zero_timeout, notifier_host_fd)?
    } else {
        host_pollfds.push(PollEvent::new(
            notifier_host_fd as u32,
            PollEventFlags::POLLIN,
        ));
        // Clear the status of notifier before queue
        clear_notifier_status(current!().tid())?;

        for (fd, (pollfd, _)) in &libos_pollfds {
            let file_ref = current.file(*fd)?;
            file_ref.enqueue_event(IoEvent::Poll(*pollfd))?;
        }
        let ret = do_poll_in_host(&mut host_pollfds, timeout, notifier_host_fd)?;
        // Pop the notifier first
        if !host_pollfds.pop().unwrap().revents().is_empty() {
            notified = 1;
        }
        // Set the return events and dequeue
        for (fd, (pollfd, index_vec)) in &libos_pollfds {
            let file_ref = current.file(*fd)?;
            let events = file_ref.poll()?;
            for i in index_vec {
                if pollfds[*i].get_revents(events) {
                    libos_ready_num += 1;
                }
            }
            file_ref.dequeue_event()?;
        }
        ret
    };

    // Copy back revents for host pollfd
    for (i, pollfd) in host_pollfds.iter().enumerate() {
        if pollfds[index_host_pollfds[i]].get_revents(pollfd.revents()) {
            host_ready_num += 1;
        }
    }

    assert!(ret == host_ready_num + notified);
    debug!("pollfds returns {:?}", pollfds);
    Ok(host_ready_num + libos_ready_num)
}

fn do_poll_in_host(
    mut host_pollfds: &mut [PollEvent],
    timeout: *mut timeval_t,
    notifier_host_fd: c_int,
) -> Result<usize> {
    let (host_pollfds_ptr, host_pollfds_len) = host_pollfds.as_mut_ptr_and_len();

    let ret = try_libc!({
        let mut retval: c_int = 0;
        let status = occlum_ocall_poll(
            &mut retval,
            host_pollfds_ptr as *mut _,
            host_pollfds_len as u64,
            timeout,
            notifier_host_fd,
        );
        assert!(status == sgx_status_t::SGX_SUCCESS);

        retval
    }) as usize;

    assert!(ret <= host_pollfds.len());
    Ok(ret)
}

extern "C" {
    fn occlum_ocall_poll(
        ret: *mut c_int,
        fds: *mut PollEvent,
        nfds: u64,
        timeout: *mut timeval_t,
        eventfd: c_int,
    ) -> sgx_status_t;
}
