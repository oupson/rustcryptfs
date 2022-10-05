use std::path::Path;

use sha2::{Digest, Sha256};

/// EncodedFilename
#[derive(Debug, PartialEq)]
pub enum EncodedFilename {
    ShortFilename(String),
    LongFilename(LongFilename),
}

impl EncodedFilename {
    fn new<P>(file: P) -> crate::error::Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = file.as_ref();

        let filename = path
            .file_name()
            .unwrap()
            .to_str()
            .expect("Failed to get filename");

        if filename.starts_with("gocryptfs.longname.") {
            if !filename.ends_with(".name") {
                let long = std::fs::read_to_string(
                    path.parent().unwrap().join(format!("{}.name", filename)),
                )
                .unwrap();
                Ok(EncodedFilename::LongFilename(LongFilename {
                    filename: filename.to_string(),
                    filename_content: long,
                }))
            } else {
                panic!()
            }
        } else {
            Ok(EncodedFilename::ShortFilename(filename.to_string()))
        }
    }
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
                    "gocryptfs.longname.{}.name",
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
