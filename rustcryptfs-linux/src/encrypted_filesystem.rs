use std::path::Path;

use fuser::Filesystem;
use rustcryptfs_lib::GocryptFs;

use crate::error::Result;

pub struct EncryptedFs {
    fs: GocryptFs,
}

impl EncryptedFs {
    pub fn new<P>(path: P, password: &str) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let fs = GocryptFs::open(path, password)?;

        Ok(Self { fs })
    }

    pub fn mount<P>(self, mountpoint: P)
    where
        P: AsRef<Path>,
    {
        fuser::mount2(self, mountpoint, &[]).unwrap();
    }
}

impl Filesystem for EncryptedFs {}
