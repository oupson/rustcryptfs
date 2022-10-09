use std::path::Path;

use rustcryptfs_fuse::EncryptedFs;

#[cfg(target_os = "linux")]
pub fn mount<P>(path: P, mount_point: P, password: &str) -> rustcryptfs_fuse::error::Result<()>
where
    P: AsRef<Path>,
{
    let fs = EncryptedFs::new(path, password)?;

    fs.mount(mount_point)?;
    Ok(())
}
