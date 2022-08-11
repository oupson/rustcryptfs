use aes::Aes256;
use cipher::{block_padding::Pkcs7, inout::InOutBufReserved, Iv, Key, KeyIvInit};
use eme_mode::DynamicEme;
use hkdf::Hkdf;

use crate::error::FilenameDecryptError;

pub(crate) type EmeCipher = DynamicEme<Aes256>;

mod filename_encoded;

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
        DirFilenameDecoder {
            filename_key: &self.filename_key,
            iv,
        }
    }
}

// TODO RENAME
pub struct DirFilenameDecoder<'a, 'b> {
    filename_key: &'a Key<EmeCipher>,
    iv: &'b Iv<EmeCipher>,
}

impl<'a, 'b> DirFilenameDecoder<'a, 'b> {
    pub fn decode_filename<S>(&self, name: S) -> Result<String, FilenameDecryptError>
    where
        S: IntoDecodable,
    {
        let cipher = EmeCipher::new(self.filename_key, self.iv);

        let mut filename = base64::decode_config(name.to_decodable(), base64::URL_SAFE_NO_PAD)?;
        let filename_decoded = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut filename)
            .map_err(|_| FilenameDecryptError::DecryptError())?;

        Ok(String::from_utf8_lossy(filename_decoded).to_string())
    }

    pub fn encrypt_filename(
        &self,
        plain_text_name: &str,
    ) -> Result<EncodedFilename, FilenameDecryptError> {
        let mut cipher = EmeCipher::new(self.filename_key, self.iv);
        let mut res = [0u8; 2048];

        let filename_encrypted = cipher
            .encrypt_padded_inout_mut::<Pkcs7>(
                InOutBufReserved::from_slices(plain_text_name.as_bytes(), &mut res).unwrap(),
            )
            .map_err(|_| FilenameDecryptError::DecryptError())?; // TODO RENAME ERROR

        // TODO LONG FILENAME

        let filename = base64::encode_config(filename_encrypted, base64::URL_SAFE_NO_PAD);

        Ok(filename.into())
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
