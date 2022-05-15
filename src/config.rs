use std::collections::HashSet;

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace},
    aes::Aes256,
    AesGcm, Key, NewAead,
};
use hkdf::Hkdf;

#[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FeatureFlag {
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
pub(crate) struct CryptConf {
    #[serde(rename = "Creator")]
    creator: String,
    #[serde(rename = "EncryptedKey")]
    encrypted_key: String,
    #[serde(rename = "ScryptObject")]
    pub scrypt_object: ScryptObject,
    #[serde(rename = "Version")]
    version: u8,
    #[serde(rename = "FeatureFlags")]
    feature_flags: HashSet<FeatureFlag>,
}

impl CryptConf {
    pub(crate) fn get_master_key(&self, password: &[u8]) -> anyhow::Result<Vec<u8>> {
        let block = base64::decode(&self.encrypted_key)?;
        let key = self.scrypt_object.get_hkdf_key(password)?;

        let nonce = &block[..16];
        let tag = &block[block.len() - 16..];
        let ciphertext = &block[16..block.len() - 16];

        let mut buf = Vec::from(ciphertext);

        let aes = AesGcm::<Aes256, cipher::consts::U16>::new(Key::from_slice(&key));

        aes.decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &[0u8, 0, 0, 0, 0, 0, 0, 0],
            &mut buf,
            GenericArray::from_slice(tag),
        )
        .unwrap();

        Ok(buf)
    }

    pub(crate) fn have_feature_flag(&self, flag: &FeatureFlag) -> bool {
        self.feature_flags.contains(flag)
    }
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct ScryptObject {
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
    pub(crate) fn get_hkdf_key(&self, password: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut key = [0u8; 32];

        let params = scrypt::Params::new((self.n as f64).log2() as u8, self.r, self.p)?;

        scrypt::scrypt(
            password,
            &base64::decode(&self.salt).unwrap(),
            &params,
            &mut key,
        )?;

        let hdkf = Hkdf::<sha2::Sha256>::new(None, &key);

        hdkf.expand(b"AES-GCM file content encryption", &mut key)
            .unwrap();

        Ok(key.to_vec())
    }
}
