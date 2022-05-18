use aes::Aes256;
use cipher::{block_padding::Pkcs7, KeyIvInit};
use eme_mode::DynamicEme;
use hkdf::Hkdf;

use crate::error::FilenameDecryptError;

pub struct FilenameDecoder {
    filename_key: [u8; 32],
}

impl FilenameDecoder {
    pub fn new(master_key: &[u8]) -> Result<Self, FilenameDecryptError> {
        let mut key = [0u8; 32];
        let hdkf = Hkdf::<sha2::Sha256>::new(None, &master_key);
        hdkf.expand(b"EME filename encryption", &mut key)?;

        Ok(Self { filename_key: key })
    }

    pub fn get_decoder_for_dir<'a, 'b>(&'a self, iv: &'b [u8]) -> DirFilenameDecoder<'a, 'b> {
        DirFilenameDecoder {
            filename_key: &self.filename_key,
            iv,
        }
    }
}

pub struct DirFilenameDecoder<'a, 'b> {
    filename_key: &'a [u8],
    iv: &'b [u8],
}

impl<'a, 'b> DirFilenameDecoder<'a, 'b> {
    pub fn decode_filename(&self, name: &str) -> Result<String, FilenameDecryptError> {
        let cipher = DynamicEme::<Aes256>::new_from_slices(self.filename_key, self.iv)
            .expect("failed to get filename cipher");

        let mut filename = base64::decode_config(name, base64::URL_SAFE)?;
        let filename_decoded = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut filename)
            .map_err(|_| FilenameDecryptError::DecryptError())?;

        Ok(String::from_utf8_lossy(filename_decoded).to_string())
    }
}
