use thiserror::Error;

use crate::{config::ConfigError, content::ContentCipherError, filename::FilenameCipherError};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    FilenameCipherError(#[from] FilenameCipherError),
    #[error(transparent)]
    ContentCipherError(#[from] ContentCipherError),
    #[error(transparent)]
    ConfigError(#[from] ConfigError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}
