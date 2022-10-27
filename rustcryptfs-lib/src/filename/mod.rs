//! Utilities for filename encryption.
//!
use aes::Aes256;
use cipher::{Iv, Key};
use eme_mode::DynamicEme;
use hkdf::Hkdf;

pub(crate) type EmeCipher = DynamicEme<Aes256>;

mod dir_filename_cipher;
mod error;
mod filename_encoded;

pub use dir_filename_cipher::*;
pub use error::*;
pub use filename_encoded::*;

/// `FilenameCipher` allow you to retrieve a `DirFilenameCipher`, used to cipher and decipher filenames.
#[allow(clippy::module_name_repetitions)]
pub struct FilenameCipher {
    filename_key: Key<Aes256>,
}

impl FilenameCipher {
    /// Create a new `FilenameCipher`, from the master key.
    ///
    /// # Errors
    /// Return an error if the filename key cannot be derived from the `master_key`.
    pub fn new(master_key: &[u8]) -> Result<Self, FilenameCipherError> {
        let mut key = [0u8; 32];
        let hdkf = Hkdf::<sha2::Sha256>::new(None, master_key);
        hdkf.expand(b"EME filename encryption", &mut key)?;

        Ok(Self {
            filename_key: Key::<EmeCipher>::from(key),
        })
    }

    /// Get the cipher for a directory, allowing you to decipher files in this dir.
    #[must_use]
    pub fn get_cipher_for_dir<'a, 'b>(&'a self, iv: &'b [u8]) -> DirFilenameCipher<'a, 'b> {
        let iv = Iv::<EmeCipher>::from_slice(iv);
        DirFilenameCipher::new(&self.filename_key, iv)
    }
}

#[cfg(test)]
mod test {
    use crate::filename::EncodedFilename;

    use super::FilenameCipher;

    #[test]
    fn test_encrypt_short_name() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let filename_cipher = FilenameCipher::new(&master_key).expect("Failed to get file decoder");
        let dir_cipher = filename_cipher.get_cipher_for_dir(&dir_iv);

        let encoded = dir_cipher
            .encrypt_filename("7.mp4")
            .expect("Failed to encrypt filename");

        assert_eq!(
            encoded,
            EncodedFilename::ShortFilename("vTBajRt-yCpxB7Sly0E7lQ".into())
        );
    }

    #[test]
    fn test_decrypt_short_name() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let filename_cipher = FilenameCipher::new(&master_key).expect("Failed to get file decoder");
        let dir_cipher = filename_cipher.get_cipher_for_dir(&dir_iv);

        let decrypted = dir_cipher
            .decode_filename("vTBajRt-yCpxB7Sly0E7lQ")
            .expect("Failed to decrypt filename");

        assert_eq!(decrypted, "7.mp4");
    }

    #[test]
    fn test_encrypt_long_name() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let filename_cipher = FilenameCipher::new(&master_key).expect("Failed to get file decoder");
        let dir_cipher = filename_cipher.get_cipher_for_dir(&dir_iv);

        let name = dir_cipher
            .encrypt_filename(
                "€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€",
            )
            .expect("Failed to encrypt filename");

        match name {
            EncodedFilename::LongFilename(l) => {
                assert_eq!(
                    l.filename(),
                    "gocryptfs.longname.Bf_foqgr7ZUrPHk6BQo4HYk_V3w0II2V9QiOIWCDDlw"
                );
                assert_eq!(l.filename_content(), "Z-XRQNP2Hc_fggKCpeyJX1i8N-8CSFPchvJiT-1H0aNOL-1_GK1TqmADcKFgFdH96ScIQIH-2hUN6lQ1ruv38ubFbDLzOdIjo50C7IIYK84XPZe_-AeGhkGP6kyvvZMvPYBt81PHjD69ZoHFG-ylpazmq71BKx2UrXOXj2dBkWVbZxnSGaKtx7ii8FSFwAfQZYEmMKIr03GU5MnxpP4u44USgenDCRVn-01F5uxjHfyidSqLYn8OIi-lpaw6jgNc5zbV5U-4yKmdLZ8opV7lMTtw0p6h2BQLrrLDjI_Gbgc");
            }
            EncodedFilename::ShortFilename(s) => {
                panic!("This should be a long filename, got \"{}\"", s)
            }
        }
    }

    #[test]
    fn test_decrypt_long_name() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let filename_cipher = FilenameCipher::new(&master_key).expect("Failed to get file decoder");
        let dir_cipher = filename_cipher.get_cipher_for_dir(&dir_iv);

        let name = EncodedFilename::from("Z-XRQNP2Hc_fggKCpeyJX1i8N-8CSFPchvJiT-1H0aNOL-1_GK1TqmADcKFgFdH96ScIQIH-2hUN6lQ1ruv38ubFbDLzOdIjo50C7IIYK84XPZe_-AeGhkGP6kyvvZMvPYBt81PHjD69ZoHFG-ylpazmq71BKx2UrXOXj2dBkWVbZxnSGaKtx7ii8FSFwAfQZYEmMKIr03GU5MnxpP4u44USgenDCRVn-01F5uxjHfyidSqLYn8OIi-lpaw6jgNc5zbV5U-4yKmdLZ8opV7lMTtw0p6h2BQLrrLDjI_Gbgc".to_string());

        match &name {
            EncodedFilename::LongFilename(l) => {
                assert_eq!(
                    l.filename(),
                    "gocryptfs.longname.Bf_foqgr7ZUrPHk6BQo4HYk_V3w0II2V9QiOIWCDDlw"
                );
                assert_eq!(l.filename_content(), "Z-XRQNP2Hc_fggKCpeyJX1i8N-8CSFPchvJiT-1H0aNOL-1_GK1TqmADcKFgFdH96ScIQIH-2hUN6lQ1ruv38ubFbDLzOdIjo50C7IIYK84XPZe_-AeGhkGP6kyvvZMvPYBt81PHjD69ZoHFG-ylpazmq71BKx2UrXOXj2dBkWVbZxnSGaKtx7ii8FSFwAfQZYEmMKIr03GU5MnxpP4u44USgenDCRVn-01F5uxjHfyidSqLYn8OIi-lpaw6jgNc5zbV5U-4yKmdLZ8opV7lMTtw0p6h2BQLrrLDjI_Gbgc");
            }
            EncodedFilename::ShortFilename(s) => {
                panic!("This should be a long filename, got \"{}\"", s)
            }
        }

        let decrypted = dir_cipher
            .decode_filename(name)
            .expect("Failed to decrypt filename");

        assert_eq!(
            decrypted,
            "€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€"
        );
    }
}
