use cipher::{block_padding::Pkcs7, inout::InOutBufReserved, Iv, Key, KeyIvInit};
use crate::error::FilenameDecryptError;

use super::{EmeCipher, EncodedFilename, IntoDecodable};

// TODO RENAME
pub struct DirFilenameDecoder<'a, 'b> {
    filename_key: &'a Key<EmeCipher>,
    iv: &'b Iv<EmeCipher>,
}

impl<'a, 'b> DirFilenameDecoder<'a, 'b> {
    pub fn new(filename_key: &'a Key<EmeCipher>, iv: &'b Iv<EmeCipher>) -> Self {
        Self { filename_key, iv }
    }
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
