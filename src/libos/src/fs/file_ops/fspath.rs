use super::*;

pub const AT_FDCWD: i32 = -100;

pub struct FsPath<'a> {
    inner: FsPathInner<'a>,
}

#[derive(Debug)]
enum FsPathInner<'a> {
    // absolute path
    Absolute(&'a str),
    // path is relative to Cwd
    CwdRelative(&'a str),
    // Cwd
    Cwd,
    // path is relative to DirFd
    FdRelative(&'a str, FileDesc),
    // Fd
    Fd(FileDesc),
}

impl<'a> FsPath<'a> {
    /// Construct a FsPath
    pub fn new(path: &'a str, fd: i32, allow_empty_path: bool) -> Result<Self> {
        let fs_path_inner = if Path::new(path).is_absolute() {
            FsPathInner::Absolute(path)
        } else if fd >= 0 {
            if path.is_empty() {
                if !allow_empty_path {
                    return_errno!(ENOENT, "path is an empty string");
                }
                FsPathInner::Fd(fd as FileDesc)
            } else {
                let file_ref = current!().file(fd as FileDesc)?;
                let inode_file = file_ref
                    .as_inode_file()
                    .map_err(|_| errno!(EBADF, "dirfd is not an inode file"))?;
                if inode_file.metadata()?.type_ != FileType::Dir {
                    return_errno!(ENOTDIR, "dirfd is not a directory");
                }
                FsPathInner::FdRelative(path, fd as FileDesc)
            }
        } else if fd == AT_FDCWD {
            if path.is_empty() {
                if !allow_empty_path {
                    return_errno!(ENOENT, "path is an empty string");
                }
                FsPathInner::Cwd
            } else {
                FsPathInner::CwdRelative(path)
            }
        } else {
            return_errno!(EINVAL, "invalid dirfd number");
        };

        Ok(FsPath {
            inner: fs_path_inner,
        })
    }

    /// Convert to absolute path
    pub fn to_abs_path(&self) -> Result<String> {
        let abs_path = match &self.inner {
            FsPathInner::Absolute(path) => (*path).to_owned(),
            FsPathInner::FdRelative(path, dirfd) => {
                let dir_path = get_abs_path_by_fd(*dirfd)?;
                if dir_path.ends_with("/") {
                    dir_path + path
                } else {
                    dir_path + "/" + path
                }
            }
            FsPathInner::Fd(fd) => get_abs_path_by_fd(*fd)?,
            FsPathInner::CwdRelative(path) => {
                let current = current!();
                let fs = current.fs().read().unwrap();
                fs.convert_to_abs_path(path)
            }
            FsPathInner::Cwd => {
                let current = current!();
                let fs = current.fs().read().unwrap();
                fs.cwd().to_owned()
            }
        };
        Ok(abs_path)
    }
}

impl<'a> Debug for FsPath<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FsPath {{ {:?} }}", self.inner)
    }
}

/// Get the absolute path by file descriptor
pub fn get_abs_path_by_fd(fd: FileDesc) -> Result<String> {
    let path = {
        let file_ref = current!().file(fd)?;
        if let Ok(inode_file) = file_ref.as_inode_file() {
            inode_file.abs_path().to_owned()
        } else {
            return_errno!(EBADF, "not an inode file");
        }
    };
    Ok(path)
}
