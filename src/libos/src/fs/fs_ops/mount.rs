use super::file_ops::AccessibilityCheckMode;
use crate::fs::{AccessMode, CreationFlags, FsView};
use std::ffi::CString;
use std::sync::Once;

use super::rootfs::{mount_nonroot_fs_according_to, open_root_fs_according_to};
use super::*;

lazy_static! {
    static ref MOUNT_ONCE: Once = Once::new();
}

pub fn do_mount_rootfs(
    user_config: &config::Config,
    user_key: &Option<sgx_key_128bit_t>,
) -> Result<()> {
    debug!("mount rootfs");

    if MOUNT_ONCE.is_completed() {
        return_errno!(EPERM, "rootfs cannot be mounted more than once");
    }
    let new_root_inode = {
        let rootfs = open_root_fs_according_to(&user_config.mount, user_key)?;
        rootfs.root_inode()
    };
    mount_nonroot_fs_according_to(&new_root_inode, &user_config.mount, user_key)?;
    MOUNT_ONCE.call_once(|| {
        let mut root_inode = ROOT_INODE.write().unwrap();
        root_inode.fs().sync().expect("failed to sync old rootfs");
        *root_inode = new_root_inode;
        *ENTRY_POINTS.write().unwrap() = user_config.entry_points.to_owned();
    });
    // Write resolv.conf file into mounted file system
    write_resolv_conf()?;

    Ok(())
}

fn write_resolv_conf() -> Result<()> {
    const RESOLV_CONF_PATH: &'static str = "/etc/resolv.conf";
    let fs_view = FsView::new();
    match fs_view.lookup_inode(RESOLV_CONF_PATH) {
        Err(e) if e.errno() == ENOENT => {
            let resolv_conf_file = fs_view.open_file(
                RESOLV_CONF_PATH,
                AccessMode::O_RDWR as u32 | CreationFlags::O_CREAT.bits(),
                0o666,
            )?;
            resolv_conf_file.write(&*RESOLV_CONF_BYTES.read().unwrap().as_bytes());
        }
        Err(e) => return Err(e),
        _ => (),
    }
    Ok(())
}
