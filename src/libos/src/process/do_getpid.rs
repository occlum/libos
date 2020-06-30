use crate::prelude::*;

pub fn do_getpid() -> pid_t {
    current!().process().pid()
}

pub fn do_gettid() -> pid_t {
    current!().tid()
}

pub fn do_getppid() -> pid_t {
    current!().process().parent().pid()
}
