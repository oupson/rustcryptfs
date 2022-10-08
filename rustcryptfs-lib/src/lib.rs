//! A library to write gocryptfs compatible programs.

use std::{fs::File, io::Read, path::Path};

use content::ContentEnc;
use filename::FilenameCipher;

pub mod config;
pub mod content;
pub mod error;
pub mod filename;

/// A GocryptFs encrypted directory
pub struct GocryptFs {
    filename_decoder: FilenameCipher,
    content_decoder: ContentEnc,
}

impl GocryptFs {
    /// Open an existing gocryptfs directory
    ///
    /// The directory must contain a valid `gocryptfs.conf`
    pub fn open<P>(encrypted_dir_path: P, password: &str) -> error::Result<Self>
    where
        P: AsRef<Path>,
    {
        let base_path = encrypted_dir_path.as_ref();

        let mut config_file =
            File::open(base_path.join("gocryptfs.conf"))?;

        Self::load_from_reader(&mut config_file, password.as_bytes())
    }

    /// Load a gocryptfs from the config.
    ///
    /// reader_config must be a reader of a valid `gocryptfs.conf`.
    pub fn load_from_reader<R>(reader_config: &mut R, password: &[u8]) -> error::Result<Self>
    where
        R: Read,
    {
        let config = serde_json::from_reader::<_, config::CryptConf>(reader_config)?;

        let master_key = config.get_master_key(password)?;

        let filename_decoder = FilenameCipher::new(&master_key)?;
        let content_decoder = ContentEnc::new(&master_key, 16)?; // TODO IV LEN

        Ok(Self {
            filename_decoder,
            content_decoder,
        })
    }

    /// Get the [`filename decoder`](struct@FilenameCipher) attached to this GocryptFs.
    pub fn filename_decoder(&self) -> &FilenameCipher {
        &self.filename_decoder
    }

    /// Get the [`content decoder`](struct@ContentEnc) attached to this GocryptFs.
    pub fn content_decoder(&self) -> &ContentEnc {
        &self.content_decoder
    }
}
