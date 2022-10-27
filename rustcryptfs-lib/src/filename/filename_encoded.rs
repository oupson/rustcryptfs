use sha2::{Digest, Sha256};

/// Represent an encrypted filename.
///
/// An encrypted filename can have two forms : long or short.
/// TODO: Document
#[derive(Debug, PartialEq, Eq)]
pub enum EncodedFilename {
    ShortFilename(String),
    LongFilename(LongFilename),
}

#[derive(Debug, PartialEq, Eq)]
pub struct LongFilename {
    filename: String,
    filename_content: String,
}

impl LongFilename {
    #[must_use]
    pub fn filename(&self) -> &str {
        self.filename.as_ref()
    }

    #[must_use]
    pub fn filename_content(&self) -> &str {
        self.filename_content.as_ref()
    }
}

impl From<String> for EncodedFilename {
    fn from(filename: String) -> Self {
        if filename.len() > 255 {
            let mut hasher = Sha256::new();
            hasher.update(filename.as_bytes());

            Self::LongFilename(LongFilename {
                filename: format!(
                    "gocryptfs.longname.{}",
                    base64::encode_config(hasher.finalize(), base64::URL_SAFE_NO_PAD)
                ),
                filename_content: filename,
            })
        } else {
            Self::ShortFilename(filename)
        }
    }
}

pub trait IntoDecodable {
    fn to_decodable(&self) -> &str;
}

impl IntoDecodable for EncodedFilename {
    fn to_decodable(&self) -> &str {
        match self {
            Self::ShortFilename(s) => s.as_str(),
            Self::LongFilename(l) => l.filename_content.as_str(),
        }
    }
}

impl IntoDecodable for String {
    fn to_decodable(&self) -> &str {
        self
    }
}

impl IntoDecodable for &str {
    fn to_decodable(&self) -> &str {
        self
    }
}
