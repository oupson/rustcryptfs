use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    ScryptError(#[from] ScryptError),
    #[error(transparent)]
    HdkfError(#[from] hkdf::InvalidLength),
    #[error("Failed to decode base64")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Failed to decrypt master key")]
    MasterKeyDecryptError(),
    #[error("Invalid master key length")]
    InvalidMasterKeyLengthError(),
}

impl From<aes_gcm::Error> for ConfigError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::MasterKeyDecryptError()
    }
}

#[derive(Debug, Error)]
pub enum ScryptError {
    #[error(transparent)]
    InvalidParams(#[from] scrypt::errors::InvalidParams),
    #[error(transparent)]
    InvalidOutputLen(#[from] scrypt::errors::InvalidOutputLen),
}
