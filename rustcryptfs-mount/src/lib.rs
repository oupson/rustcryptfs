use std::path::Path;

#[cfg(target_os = "linux")]
pub fn mount<P>(path: P, mount_point: P, password: &str) -> rustcryptfs_fuse::error::Result<()>
where
    P: AsRef<Path>,
{
    use rustcryptfs_fuse::EncryptedFs;

    let fs = EncryptedFs::new(path, password)?;

    fs.mount(mount_point)?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn mount<P>(path: P, mount_point: P, password: &str) -> rustcryptfs_projfs::error::Result<()>
where
    P: AsRef<Path>,
{
    use rustcryptfs_projfs::EncryptedFs;

    let fs = EncryptedFs::new(path, password)?;

    fs.mount(mount_point)?;
    Ok(())
}
