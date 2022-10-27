use cipher::{block_padding::Pkcs7, Iv, Key, KeyIvInit};

use super::{EmeCipher, EncodedFilename, FilenameCipherError, IntoDecodable};

/// `DirFilenameCipher` allow you to cipher and decipher filenames in a directory.
///
/// TODO : document structure of a gocryptfs dir or put a link.
pub struct DirFilenameCipher<'a, 'b> {
    filename_key: &'a Key<EmeCipher>,
    iv: &'b Iv<EmeCipher>,
}

impl<'a, 'b> DirFilenameCipher<'a, 'b> {
    #[must_use]
    pub fn new(filename_key: &'a Key<EmeCipher>, iv: &'b Iv<EmeCipher>) -> Self {
        Self { filename_key, iv }
    }

    /// Decipher a filename.
    ///
    /// Name muste be the name of the file if it is a short filename, or the content of the long .name file otherwise.
    ///
    /// # Errors
    /// Return an error if the decryption failed.
    pub fn decode_filename<S>(&self, name: S) -> Result<String, FilenameCipherError>
    where
        S: IntoDecodable,
    {
        let cipher = EmeCipher::new(self.filename_key, self.iv);

        let mut filename = base64::decode_config(name.to_decodable(), base64::URL_SAFE_NO_PAD)?;
        let filename_decoded = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut filename)
            .map_err(|_| FilenameCipherError::DecryptError())?;

        Ok(String::from_utf8_lossy(filename_decoded).to_string())
    }

    /// Cipher a filename.
    ///
    /// # Errors
    /// Return an error if the filename encryption failed.
    pub fn encrypt_filename(
        &self,
        plain_text_name: &str,
    ) -> Result<EncodedFilename, FilenameCipherError> {
        let mut cipher = EmeCipher::new(self.filename_key, self.iv);
        let mut res = [0u8; 2048];

        let filename_encrypted = cipher
            .encrypt_padded_b2b_mut::<Pkcs7>(plain_text_name.as_bytes(), &mut res)
            .map_err(|_| FilenameCipherError::EncryptError())?;

        let filename = base64::encode_config(filename_encrypted, base64::URL_SAFE_NO_PAD);

        Ok(filename.into())
    }
}
