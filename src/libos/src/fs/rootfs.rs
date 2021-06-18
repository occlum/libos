use super::dev_fs;
use super::hostfs::HostFS;
use super::procfs::ProcFS;
use super::sefs::{SgxStorage, SgxUuidProvider};
use super::*;
use config::ConfigMountFsType;
use std::path::{Path, PathBuf};
use std::untrusted::path::PathEx;

use rcore_fs_mountfs::{MNode, MountFS};
use rcore_fs_ramfs::RamFS;
use rcore_fs_sefs::dev::*;
use rcore_fs_sefs::SEFS;
use rcore_fs_unionfs::UnionFS;

lazy_static! {
    /// The root of file system
    pub static ref ROOT_INODE: RwLock<Arc<dyn INode>> = {
        fn init_root_inode() -> Result<Arc<dyn INode>> {
            let mount_config = &config::LIBOS_CONFIG.mount;
            let root_inode = {
                let rootfs = open_root_fs_according_to(mount_config, &None)?;
                rootfs.root_inode()
            };
            mount_nonroot_fs_according_to(&root_inode, mount_config, &None)?;
            Ok(root_inode)
        }

        let root_inode = init_root_inode().unwrap_or_else(|e| {
            error!("failed to init root inode: {}", e.backtrace());
            panic!();
        });
        RwLock::new(root_inode)
    };
}

pub fn open_root_fs_according_to(
    mount_configs: &Vec<ConfigMount>,
    user_key: &Option<sgx_key_128bit_t>,
) -> Result<Arc<MountFS>> {
    let root_mount_config = mount_configs
        .iter()
        .find(|m| m.target == Path::new("/") && m.type_ == ConfigMountFsType::TYPE_UNIONFS)
        .ok_or_else(|| errno!(Errno::ENOENT, "the root UnionFS is not valid"))?;
    if root_mount_config.options.layers.is_none() {
        return_errno!(EINVAL, "the root UnionFS must be given the layers");
    }
    let layer_mount_configs = root_mount_config.options.layers.as_ref().unwrap();
    // image SEFS in layers
    let root_image_sefs_mount_config = layer_mount_configs
        .iter()
        .find(|m| {
            m.target == Path::new("/")
                && m.type_ == ConfigMountFsType::TYPE_SEFS
                && m.options.mac.is_some()
        })
        .ok_or_else(|| errno!(Errno::ENOENT, "the image SEFS in layers is not valid"))?;
    let root_image_sefs =
        open_or_create_sefs_according_to(&root_image_sefs_mount_config, user_key)?;
    // container SEFS in layers
    let root_container_sefs_mount_config = layer_mount_configs
        .iter()
        .find(|m| {
            m.target == Path::new("/")
                && m.type_ == ConfigMountFsType::TYPE_SEFS
                && m.options.mac.is_none()
        })
        .ok_or_else(|| errno!(Errno::ENOENT, "the container SEFS in layers is not valid"))?;
    let root_container_sefs =
        open_or_create_sefs_according_to(&root_container_sefs_mount_config, user_key)?;
    // create UnionFS
    let root_unionfs = UnionFS::new(vec![root_container_sefs, root_image_sefs])?;
    let root_mountable_unionfs = MountFS::new(root_unionfs);
    Ok(root_mountable_unionfs)
}

pub fn mount_nonroot_fs_according_to(
    root: &MNode,
    mount_configs: &Vec<ConfigMount>,
    user_key: &Option<sgx_key_128bit_t>,
) -> Result<()> {
    for mc in mount_configs {
        if mc.target == Path::new("/") {
            continue;
        }

        if !mc.target.is_absolute() {
            return_errno!(EINVAL, "The target path must be absolute");
        }

        use self::ConfigMountFsType::*;
        match mc.type_ {
            TYPE_SEFS => {
                let sefs = open_or_create_sefs_according_to(&mc, user_key)?;
                mount_fs_at(sefs, root, &mc.target)?;
            }
            TYPE_HOSTFS => {
                if mc.source.is_none() {
                    return_errno!(EINVAL, "Source is expected for HostFS");
                }
                let source_path = mc.source.as_ref().unwrap();

                let hostfs = HostFS::new(source_path);
                mount_fs_at(hostfs, root, &mc.target)?;
            }
            TYPE_RAMFS => {
                let ramfs = RamFS::new();
                mount_fs_at(ramfs, root, &mc.target)?;
            }
            TYPE_DEVFS => {
                let devfs = dev_fs::init_devfs()?;
                mount_fs_at(devfs, root, &mc.target)?;
            }
            TYPE_PROCFS => {
                let procfs = ProcFS::new();
                mount_fs_at(procfs, root, &mc.target)?;
            }
            TYPE_UNIONFS => {
                return_errno!(EINVAL, "Cannot mount UnionFS at non-root path");
            }
        }
    }
    Ok(())
}

pub fn mount_fs_at(fs: Arc<dyn FileSystem>, parent_inode: &MNode, abs_path: &Path) -> Result<()> {
    let mut mount_dir = parent_inode.find(false, ".")?;
    // The first component of abs_path is the RootDir, skip it.
    for dirname in abs_path.iter().skip(1) {
        mount_dir = match mount_dir.find(false, dirname.to_str().unwrap()) {
            Ok(existing_dir) => {
                if existing_dir.metadata()?.type_ != FileType::Dir {
                    return_errno!(EIO, "not a directory");
                }
                existing_dir
            }
            Err(_) => return_errno!(ENOENT, "Mount point does not exist"),
        };
    }
    mount_dir.mount(fs);
    Ok(())
}

fn open_or_create_sefs_according_to(
    mc: &ConfigMount,
    user_key: &Option<sgx_key_128bit_t>,
) -> Result<Arc<SEFS>> {
    assert!(mc.type_ == ConfigMountFsType::TYPE_SEFS);

    if mc.source.is_none() {
        return_errno!(EINVAL, "Source is expected for SEFS");
    }
    if mc.options.temporary && mc.options.mac.is_some() {
        return_errno!(EINVAL, "Integrity protected SEFS cannot be temporary");
    }
    let source_path = mc.source.as_ref().unwrap();
    let root_mac = mc.options.mac;
    let sefs = if !mc.options.temporary {
        if root_mac.is_some() {
            SEFS::open(
                Box::new(SgxStorage::new(source_path, user_key, &root_mac)),
                &time::OcclumTimeProvider,
                &SgxUuidProvider,
                Some(Box::new(FlockListCreater)),
            )?
        } else if source_path.join("metadata").exists() {
            SEFS::open(
                Box::new(SgxStorage::new(source_path, user_key, &root_mac)),
                &time::OcclumTimeProvider,
                &SgxUuidProvider,
                Some(Box::new(FlockListCreater)),
            )?
        } else {
            SEFS::create(
                Box::new(SgxStorage::new(source_path, user_key, &root_mac)),
                &time::OcclumTimeProvider,
                &SgxUuidProvider,
                Some(Box::new(FlockListCreater)),
            )?
        }
    } else {
        SEFS::create(
            Box::new(SgxStorage::new(source_path, user_key, &root_mac)),
            &time::OcclumTimeProvider,
            &SgxUuidProvider,
            Some(Box::new(FlockListCreater)),
        )?
    };
    Ok(sefs)
}
