use super::*;
use file_ops::get_abs_path_by_fd;

pub fn do_read(fd: FileDesc, buf: &mut [u8]) -> Result<usize> {
    debug!("read: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    let ret = file_ref.read(buf);

    if cfg!(debug_assertions) {
        let len = ret.as_ref().unwrap().clone();
        detail_debug_print("read", fd, Some(buf), Some(len))?;
    }
    return ret;
}

pub fn do_readv(fd: FileDesc, bufs: &mut [&mut [u8]]) -> Result<usize> {
    debug!("readv: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    file_ref.readv(bufs)
}

pub fn do_pread(fd: FileDesc, buf: &mut [u8], offset: off_t) -> Result<usize> {
    debug!("pread: fd: {}, offset: {}", fd, offset);
    if offset < 0 {
        return_errno!(EINVAL, "the offset is negative");
    }
    let file_ref = current!().file(fd)?;
    file_ref.read_at(offset as usize, buf)
}
