use thiserror::Error;

#[derive(Debug, Error)]
#[allow(clippy::module_name_repetitions)]
pub enum ContentCipherError {
    #[error("Block is too short")]
    BlockTooShort(),
    #[error("all-zero nonce")]
    AllZeroNonce(),
    #[error("Failed to decrypt content")]
    ContentDecryptError(),
    #[error(transparent)]
    HdkfError(#[from] hkdf::InvalidLength),
}

impl From<aes_gcm::Error> for ContentCipherError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::ContentDecryptError()
    }
}
