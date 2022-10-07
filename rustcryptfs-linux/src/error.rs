use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    RustCryptFsError(#[from] rustcryptfs_lib::error::Error),

    #[error(transparent)]
    RustCryptFsFilenameError(#[from] rustcryptfs_lib::error::FilenameDecryptError),
}
