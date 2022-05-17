use aes_gcm::{aead::generic_array::GenericArray, aes::Aes256, AeadInPlace, AesGcm, NewAead};
use cipher::consts::{U16, U32};
use hkdf::Hkdf;

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
    ) -> anyhow::Result<Vec<u8>> {
        // TODO NOT BOX
        if block.len() == 0 {
            return Ok(block.into());
        }

        if block.iter().all(|f| *f == 0) {
            todo!("black hole")
        }

        if block.len() < self.iv_len {
            return Err(anyhow::Error::msg("Block is too short"));
        }

        let nonce = &block[..self.iv_len];
        let tag = &block[block.len() - self.iv_len..];
        let ciphertext = &block[self.iv_len..block.len() - self.iv_len];

        if nonce.iter().all(|f| *f == 0) {
            return Err(anyhow::Error::msg("all-zero nonce"));
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
        )
        .unwrap();

        return Ok(buf.to_vec());
    }
}
