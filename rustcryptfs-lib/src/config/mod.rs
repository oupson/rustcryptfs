//! Utilities to read gocryptfs config.

use std::collections::HashSet;

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace},
    aes::Aes256,
    AesGcm, Key, NewAead,
};
use hkdf::Hkdf;

mod error;

pub use error::*;

/// An enum that contain all the feature flag a gocryptfs config can have.
#[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
pub enum FeatureFlag {
    /// FlagPlaintextNames indicates that filenames are unencrypted.
    PlaintextNames,
    /// FlagDirIV indicates that a per-directory IV file is used.
    DirIV,
    /// FlagEMENames indicates EME (ECB-Mix-ECB) filename encryption.
    ///
    /// This flag is mandatory since gocryptfs v1.0.
    EMENames,
    /// FlagGCMIV128 indicates 128-bit GCM IVs.
    ///
    /// This flag is mandatory since gocryptfs v1.0, except when XChaCha20Poly1305 is used.
    GCMIV128,
    /// FlagLongNames allows file names longer than 175 bytes.
    LongNames,
    /// FlagLongNameMax sets a custom name length limit, names longer than that will be hashed.
    LongNameMax,
    /// FlagAESSIV selects an AES-SIV based crypto backend.
    AESSIV,
    /// FlagRaw64 enables raw (unpadded) base64 encoding for file names.
    Raw64,
    /// FlagHKDF enables HKDF-derived keys for use with GCM, EME and SIV
    /// instead of directly using the master key (GCM and EME) or the SHA-512
    /// hashed master key (SIV).
    ///
    /// Note that this flag does not change the password hashing algorithm
    /// which always is scrypt.
    HKDF,
    /// FlagFIDO2 means that "-fido2" was used when creating the filesystem.
    ///
    /// The masterkey is protected using a FIDO2 token instead of a password.
    FIDO2,
    /// FlagXChaCha20Poly1305 means we use XChaCha20-Poly1305 file content encryption
    XChaCha20Poly1305,
}

#[derive(serde::Deserialize, Debug)]
pub struct CryptConf {
    #[serde(rename = "Creator")]
    creator: String,
    #[serde(rename = "EncryptedKey")]
    encrypted_key: String,
    #[serde(rename = "ScryptObject")]
    scrypt_object: ScryptObject,
    #[serde(rename = "Version")]
    version: u8,
    #[serde(rename = "FeatureFlags")]
    feature_flags: HashSet<FeatureFlag>,
}

impl CryptConf {
    /// Get the masterkey from configuration.
    ///
    /// See gocryptfs documentation about [master key](https://nuetzlich.net/gocryptfs/forward_mode_crypto/#master-key-storage).
    ///
    /// ![TODO NAME THIS IMAGE](https://nuetzlich.net/gocryptfs/img/master-key.svg)
    /// 
    /// # Errors
    /// Return an error when the master key don't have the required size or if the decrypting failed.
    pub fn get_master_key(&self, password: &[u8]) -> Result<[u8; 32], ConfigError> {
        let block = base64::decode(&self.encrypted_key)?;
        let key = self.scrypt_object.get_hkdf_key(password)?;

        let nonce = &block[..16];
        let tag = &block[block.len() - 16..];
        let ciphertext = &block[16..block.len() - 16];

        let mut buf: [u8; 32] = ciphertext
            .try_into()
            .map_err(|_| ConfigError::InvalidMasterKeyLengthError())?;

        let aes = AesGcm::<Aes256, cipher::consts::U16>::new(Key::from_slice(&key));

        aes.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &[0u8, 0, 0, 0, 0, 0, 0, 0],
            &mut buf,
            GenericArray::from_slice(tag),
        )?;

        Ok(buf)
    }

    #[must_use]
    pub fn have_feature_flag(&self, flag: &FeatureFlag) -> bool {
        self.feature_flags.contains(flag)
    }

    /// Get the gocryptfs encrypted directory creator.
    #[must_use]
    pub fn creator(&self) -> &str {
        self.creator.as_ref()
    }

    /// Get the gocryptfs.conf encrypted key.
    #[must_use]
    pub fn encrypted_key(&self) -> &str {
        self.encrypted_key.as_ref()
    }

    #[must_use]
    pub fn scrypt_object(&self) -> &ScryptObject {
        &self.scrypt_object
    }

    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub fn feature_flags(&self) -> &HashSet<FeatureFlag> {
        &self.feature_flags
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct ScryptObject {
    #[serde(rename = "Salt")]
    salt: String,
    #[serde(rename = "N")]
    n: u32,
    #[serde(rename = "R")]
    r: u32,
    #[serde(rename = "P")]
    p: u32,
    #[serde(rename = "KeyLen")]
    key_len: u32,
}

impl ScryptObject {
    fn get_hkdf_key(&self, password: &[u8]) -> Result<Vec<u8>, ConfigError> {
        let mut key = [0u8; 32];

        let params = scrypt::Params::new(f64::from(self.n).log2() as u8, self.r, self.p)
            .map_err(ScryptError::from)?;

        scrypt::scrypt(password, &base64::decode(&self.salt)?, &params, &mut key)
            .map_err(ScryptError::from)?;

        let hdkf = Hkdf::<sha2::Sha256>::new(None, &key);
        hdkf.expand(b"AES-GCM file content encryption", &mut key)?;

        Ok(key.to_vec())
    }

    #[must_use]
    pub fn salt(&self) -> &str {
        self.salt.as_ref()
    }

    #[must_use]
    pub fn n(&self) -> u32 {
        self.n
    }

    #[must_use]
    pub fn r(&self) -> u32 {
        self.r
    }

    #[must_use]
    pub fn p(&self) -> u32 {
        self.p
    }

    #[must_use]
    pub fn key_len(&self) -> u32 {
        self.key_len
    }
}
