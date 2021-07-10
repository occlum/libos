use super::*;

pub fn do_write(fd: FileDesc, buf: &[u8]) -> Result<usize> {
    debug!("write: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    let ret = file_ref.write(buf);

    if cfg!(debug_assertions) {
        let len = ret.as_ref().unwrap().clone();
        detail_debug_print("write", fd, Some(buf), Some(len))?;
    }
    return ret;
}

pub fn do_writev(fd: FileDesc, bufs: &[&[u8]]) -> Result<usize> {
    debug!("writev: fd: {}", fd);
    let file_ref = current!().file(fd)?;
    file_ref.writev(bufs)
}

pub fn do_pwrite(fd: FileDesc, buf: &[u8], offset: off_t) -> Result<usize> {
    debug!("pwrite: fd: {}, offset: {}", fd, offset);
    if offset < 0 {
        return_errno!(EINVAL, "the offset is negative");
    }
    let file_ref = current!().file(fd)?;
    file_ref.write_at(offset as usize, buf)
}
