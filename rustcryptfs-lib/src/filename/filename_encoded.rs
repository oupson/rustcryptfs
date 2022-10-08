use sha2::{Digest, Sha256};

/// EncodedFilename
#[derive(Debug, PartialEq)]
pub enum EncodedFilename {
    ShortFilename(String),
    LongFilename(LongFilename),
}

#[derive(Debug, PartialEq)]
pub struct LongFilename {
    pub filename: String,
    pub filename_content: String,
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
    fn to_decodable<'s>(&'s self) -> &'s str;
}

impl IntoDecodable for EncodedFilename {
    fn to_decodable<'s>(&'s self) -> &'s str {
        match self {
            Self::ShortFilename(s) => s.as_str(),
            Self::LongFilename(l) => l.filename_content.as_str(),
        }
    }
}

impl IntoDecodable for String {
    fn to_decodable<'s>(&'s self) -> &'s str {
        self
    }
}

impl<'a> IntoDecodable for &'a str {
    fn to_decodable<'s>(&'s self) -> &'s str {
        self
    }
}
