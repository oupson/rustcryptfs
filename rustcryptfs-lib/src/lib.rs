//! A library to write gocryptfs compatible programs.

use std::{fs::File, path::Path};

use content_enc::ContentEnc;
use filename::FilenameDecoder;

pub mod config;
pub mod content_enc;
pub mod error;
pub mod filename;

/// A GocryptFs encrypted directory
pub struct GocryptFs {
    filename_decoder: FilenameDecoder,
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

        let config = {
            let mut config_file =
                File::open(base_path.join("gocryptfs.conf")).expect("failed to get config");

            serde_json::from_reader::<_, config::CryptConf>(&mut config_file)
                .expect("failed to parse config")
        };

        let master_key = config.get_master_key(password.as_bytes())?;

        let filename_decoder = FilenameDecoder::new(&master_key)?;
        let content_decoder = ContentEnc::new(&master_key, 16); // TODO IV LEN

        Ok(Self {
            filename_decoder,
            content_decoder,
        })
    }

    /// Get the [`filename decoder`](struct@FilenameDecoder) attached to this GocryptFs.
    pub fn filename_decoder<'s>(&'s self) -> &'s FilenameDecoder {
        &self.filename_decoder
    }

    /// Get the [`content decoder`](struct@ContentEnc) attached to this GocryptFs.
    pub fn content_decoder(&self) -> &ContentEnc {
        &self.content_decoder
    }
}
