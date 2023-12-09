use rustcryptfs_lib::filename::FilenameCipherError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    RustCryptFsError(#[from] rustcryptfs_lib::error::Error),

    #[error(transparent)]
    RustCryptFsFilenameError(#[from] FilenameCipherError),
}

pub(crate) trait ErrorExt {
    fn to_raw_code(&self) -> i32;
}

impl ErrorExt for rustcryptfs_lib::error::Error {
    fn to_raw_code(&self) -> i32 {
        match self {
            rustcryptfs_lib::error::Error::FilenameCipherError(_) => libc::EIO,
            rustcryptfs_lib::error::Error::ContentCipherError(_) => libc::EIO,
            rustcryptfs_lib::error::Error::ConfigError(_) => todo!(),
            rustcryptfs_lib::error::Error::JsonError(_) => todo!(),
            rustcryptfs_lib::error::Error::IoError(e) => e.raw_os_error().unwrap(),
        }
    }
}
