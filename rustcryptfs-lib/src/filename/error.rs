use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilenameCipherError {
    #[error("Failed to decode base64")]
    Base64Error(#[from] base64::DecodeError),
    #[error(transparent)]
    HdkfError(#[from] hkdf::InvalidLength),
    #[error("Failed to decrypt filename")]
    DecryptError(),
    #[error("Failed to encrypt filename")]
    EncryptError()
}
