use super::*;

pub fn do_fallocate(fd: FileDesc, mode: FallocateMode, offset: usize, len: usize) -> Result<()> {
    debug!(
        "fallocate: fd: {}, mode: {:?}, offset: {}, len: {}",
        fd, mode, offset, len
    );
    let file_ref = current!().file(fd)?;
    file_ref.fallocate(mode, offset, len)?;
    Ok(())
}
