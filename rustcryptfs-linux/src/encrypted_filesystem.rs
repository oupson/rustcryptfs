use std::path::Path;

use fuser::Filesystem;
use rustcryptfs_lib::config::CryptConf;

pub struct EncryptedFs {}

impl EncryptedFs {
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        todo!()
    }

    pub fn new_from_config(config: &CryptConf) -> Self {
        Self {}
    }

    pub fn mount<P>(self, mountpoint: P)
    where
        P: AsRef<Path>,
    {
        fuser::mount2(self, mountpoint, &[]).unwrap();
    }
}

impl Filesystem for EncryptedFs {}
