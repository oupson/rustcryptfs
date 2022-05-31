use std::{fs, path::Path};

use fuser::Filesystem;
use rustcryptfs_lib::{config::CryptConf, filename::FilenameDecoder};

use crate::error::Result;

pub struct EncryptedFs {
    master_key: Vec<u8>,
    filename_decoder: FilenameDecoder,
}

impl EncryptedFs {
    pub fn new<P>(path: P, password: &str) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        let conf_path = path.join("gocryptfs.conf");

        let content = fs::read_to_string(conf_path)?;

        let conf: CryptConf = serde_json::from_str(&content)?;

        let master_key = conf.get_master_key(password.as_bytes())?;

        let filename_decoder = FilenameDecoder::new(&master_key)?;

        Ok(Self {
            master_key,
            filename_decoder,
        })
    }

    pub fn mount<P>(self, mountpoint: P)
    where
        P: AsRef<Path>,
    {
        fuser::mount2(self, mountpoint, &[]).unwrap();
    }
}

impl Filesystem for EncryptedFs {}
