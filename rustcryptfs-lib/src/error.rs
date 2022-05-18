use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to decrypt content")]
    ContentDecryptError(),
    #[error("Failed to decrypt filename")]
    FilenameDecryptError(#[from] FilenameDecryptError),
    #[error("Failed to decode base64")]
    Base64Error(#[from] base64::DecodeError),
    #[error(transparent)]
    DecodeError(#[from] DecryptError),
}

impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Self::ContentDecryptError()
    }
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Block is too short")]
    BlockTooShort(),
    #[error("all-zero nonce")]
    AllZeroNonce(),
}

#[derive(Debug, Error)]
pub enum FilenameDecryptError {
    #[error(transparent)]
    ScryptError(#[from] ScryptError),
    #[error("Failed to decode base64")]
    Base64Error(#[from] base64::DecodeError),
    #[error(transparent)]
    HdkfError(#[from] hkdf::InvalidLength),
    #[error("Failed to decrypt filename")]
    DecryptError(),
}

#[derive(Debug, Error)]
pub enum ScryptError {
    #[error(transparent)]
    InvalidParams(#[from] scrypt::errors::InvalidParams),
    #[error(transparent)]
    InvalidOutputLen(#[from] scrypt::errors::InvalidOutputLen),
}
