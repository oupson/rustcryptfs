use aes_gcm::{aead::generic_array::GenericArray, aes::Aes256, AeadInPlace, AesGcm, NewAead};
use cipher::consts::{U16, U32};
use hkdf::Hkdf;

use crate::error::{Result, DecryptError};

type Aes256Gcm = AesGcm<Aes256, U16>;

pub struct ContentEnc {
    key: GenericArray<u8, U32>,
    iv_len: usize,
}

impl ContentEnc {
    pub fn new(master_key: &[u8], iv_len: u8) -> Self {
        let mut key = [0u8; 32];
        let hdkf = Hkdf::<sha2::Sha256>::new(None, &master_key);
        hdkf.expand(b"AES-GCM file content encryption", &mut key)
            .unwrap();

        Self {
            key: GenericArray::from(key),
            iv_len: iv_len as usize,
        }
    }

    pub fn decrypt_block(
        &self,
        block: &[u8],
        block_number: u64,
        file_id: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // TODO NOT BOX
        if block.len() == 0 {
            return Ok(block.into());
        }

        if block.iter().all(|f| *f == 0) {
            todo!("black hole")
        }

        if block.len() < self.iv_len {
            return Err(DecryptError::BlockTooShort().into());
        }

        let nonce = &block[..self.iv_len];
        let tag = &block[block.len() - self.iv_len..];
        let ciphertext = &block[self.iv_len..block.len() - self.iv_len];

        if nonce.iter().all(|f| *f == 0) {
            return Err(DecryptError::AllZeroNonce().into());
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

        return Ok(buf.to_vec());
    }

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
}
