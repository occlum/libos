use super::*;
use file_ops::get_abs_path_by_fd;

pub fn do_dup(old_fd: FileDesc) -> Result<FileDesc> {
    if cfg!(debug_assertions) {
        detail_debug_print("dup", old_fd, None, None)?;
    }
    let current = current!();
    let file = current.file(old_fd)?;
    let new_fd = current.add_file(file, false);
    Ok(new_fd)
}

pub fn do_dup2(old_fd: FileDesc, new_fd: FileDesc) -> Result<FileDesc> {
    if cfg!(debug_assertions) {
        detail_debug_print("dup2", old_fd, None, None)?;
    }
    let current = current!();
    let mut files = current.files().lock().unwrap();
    let file = files.get(old_fd)?;
    if old_fd != new_fd {
        files.put_at(new_fd, file, false);
    }
    Ok(new_fd)
}

pub fn do_dup3(old_fd: FileDesc, new_fd: FileDesc, flags: u32) -> Result<FileDesc> {
    if cfg!(debug_assertions) {
        detail_debug_print("dup3", old_fd, None, None)?;
    }
    let creation_flags = CreationFlags::from_bits_truncate(flags);
    let current = current!();
    let mut files = current.files().lock().unwrap();
    let file = files.get(old_fd)?;
    if old_fd == new_fd {
        return_errno!(EINVAL, "old_fd must not be equal to new_fd");
    }
    files.put_at(new_fd, file, creation_flags.must_close_on_spawn());
    Ok(new_fd)
}
