use aes::Aes256;
use cipher::{block_padding::Pkcs7, inout::InOutBufReserved, Iv, Key, KeyIvInit};
use eme_mode::DynamicEme;
use hkdf::Hkdf;

use crate::error::FilenameDecryptError;

pub(crate) type EmeCipher = DynamicEme<Aes256>;

mod dir_filename_decoder;
mod filename_encoded;

pub use dir_filename_decoder::*;
pub use filename_encoded::*;

// TODO RENAME
pub struct FilenameDecoder {
    filename_key: Key<Aes256>,
}

impl FilenameDecoder {
    pub fn new(master_key: &[u8]) -> Result<Self, FilenameDecryptError> {
        let mut key = [0u8; 32];
        let hdkf = Hkdf::<sha2::Sha256>::new(None, &master_key);
        hdkf.expand(b"EME filename encryption", &mut key)?;

        Ok(Self {
            filename_key: Key::<EmeCipher>::from(key),
        })
    }

    pub fn get_decoder_for_dir<'a, 'b>(&'a self, iv: &'b [u8]) -> DirFilenameDecoder<'a, 'b> {
        let iv = Iv::<EmeCipher>::from_slice(iv);
        DirFilenameDecoder::new(&self.filename_key, iv)
    }
}

#[cfg(test)]
mod test {
    use crate::filename::EncodedFilename;

    use super::FilenameDecoder;

    #[test]
    fn test_encrypt() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let decoder = FilenameDecoder::new(&master_key).expect("Failed to get file decoder");
        let dir_decoder = decoder.get_decoder_for_dir(&dir_iv);

        let encoded = dir_decoder
            .encrypt_filename("7.mp4")
            .expect("Failed to encrypt filename");

        assert_eq!(
            encoded,
            EncodedFilename::ShortFilename("vTBajRt-yCpxB7Sly0E7lQ".into())
        );
    }

    #[test]
    fn test_decrypt() {
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let dir_iv = base64::decode("6ysCeWOp2euF1x39gth8KQ==").unwrap();

        let decoder = FilenameDecoder::new(&master_key).expect("Failed to get file decoder");
        let dir_decoder = decoder.get_decoder_for_dir(&dir_iv);

        let decrypted = dir_decoder
            .decode_filename("vTBajRt-yCpxB7Sly0E7lQ")
            .expect("Failed to decrypt filename");

        assert_eq!(decrypted, "7.mp4");
    }
}
