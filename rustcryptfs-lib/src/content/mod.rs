//! Utilities for file encryption.

use aes_gcm::{aead::generic_array::GenericArray, aes::Aes256, AeadInPlace, AesGcm, NewAead};
use cipher::consts::{U16, U32};
use hkdf::Hkdf;

mod error;

pub use error::*;

type Aes256Gcm = AesGcm<Aes256, U16>;

/// ContentEnc implement all methods related to file encryption.
pub struct ContentEnc {
    key: GenericArray<u8, U32>,
    iv_len: usize,
}

impl ContentEnc {
    /// Init a new ContentEnc from the master key and the iv len.
    pub fn new(master_key: &[u8], iv_len: u8) -> Result<Self, ContentCipherError> {
        let mut key = [0u8; 32];
        let hdkf = Hkdf::<sha2::Sha256>::new(None, master_key);
        hdkf.expand(b"AES-GCM file content encryption", &mut key)?;

        Ok(Self {
            key: GenericArray::from(key),
            iv_len: iv_len as usize,
        })
    }

    /// Decrypt a encrypted block of len (iv_len + decrypted_block_size + iv_len), with the block number and the file id.
    pub fn decrypt_block(
        &self,
        block: &[u8],
        block_number: u64,
        file_id: Option<&[u8]>,
    ) -> Result<Vec<u8>, ContentCipherError> {
        // TODO NOT BOX
        if block.is_empty() {
            return Ok(block.into());
        }

        if block.iter().all(|f| *f == 0) {
            todo!("black hole")
        }

        if block.len() < self.iv_len {
            return Err(ContentCipherError::BlockTooShort());
        }

        let nonce = &block[..self.iv_len];
        let tag = &block[block.len() - self.iv_len..];
        let ciphertext = &block[self.iv_len..block.len() - self.iv_len];

        if nonce.iter().all(|f| *f == 0) {
            return Err(ContentCipherError::AllZeroNonce());
        }

        let mut buf = Vec::from(ciphertext);

        let mut aad = Vec::from(block_number.to_be_bytes());
        if let Some(file_id) = file_id {
            aad.extend(file_id);
        }

        let aes = Aes256Gcm::new(&self.key);

        aes.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            &aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )?;

        Ok(buf.to_vec())
    }

    /// Return the decrypted size of a file, based on the encrypted size.
    pub fn get_real_size(encrypted_size: u64) -> u64 {
        if encrypted_size == 0 {
            0
        } else {
            let x = (encrypted_size - 50) / 4128;

            let y = (encrypted_size - 50) - x * 4128;
            x * 4096 + y
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};

    use sha2::{Sha256, Digest};

    use super::ContentEnc;

    #[test]
    fn test_get_real_size() {
        assert_eq!(0, ContentEnc::get_real_size(0));

        for real_size in 1..4096 * 4 + 1 {
            let nbr_full_blocks = real_size / 4096;
            let encrypted_size =
                18 + nbr_full_blocks * (4096 + 32) + real_size - nbr_full_blocks * 4096 + 32;

            assert_eq!(real_size, ContentEnc::get_real_size(encrypted_size));
        }
    }

    #[test]
    fn test_decrypt_empty_file() {
        let content = include_bytes!(
            concat!(env!("CARGO_MANIFEST_DIR"),
            "/../test-data/test.bin"));
        let master_key = base64::decode("9gtUW9XiiefEgEXEkbONI6rnUsd2yh5UZZLG0V8Bxgk=").unwrap();
        let file_cipher = ContentEnc::new(&master_key, 16).unwrap();

        let res = file_cipher.decrypt_block(&[], 1, None).expect("Failed to decrypt empty block");
        assert_eq!(res, Vec::<u8>::new());

        let mut reader= Cursor::new(content);
        
        let mut hasher = Sha256::new();


        let mut buf = [0u8; 18];
        let n = reader.read(&mut buf).unwrap();
        let id = if n < 18 { None } else { Some(&buf[2..]) };
    
        let mut buf = [0u8; 4096 + 32];
    
        let mut block_index = 0;
        loop {
            let n = reader.read(&mut buf).unwrap();
            let res = file_cipher.decrypt_block(&buf[..n], block_index, id).unwrap();
    
            hasher.update(&res);

            if res.is_empty() {
                break;
            }
    
            block_index += 1;
        }

        let checksum = base64::encode_config(hasher.finalize(), base64::URL_SAFE);

        assert_eq!(checksum, "YKLFv04l2iqHo3hyObExyj7eURrtJry2T227YQ1pcEg=");
    }
}
