use std::{
    error::Error,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use crate::filename::{EncodedFilename, FilenameDecoder};

#[derive(Debug)]
pub struct DirCache {
    filename: String,
    dir_iv: [u8; 16],
    dir_entries: Vec<DirEntry>,
}

impl DirCache {
    pub fn load_from_path<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        let mut dir_iv = [0u8; 16];
        {
            let dir_iv_path = path.join("gocryptfs.diriv");

            let mut file = File::open(dir_iv_path).unwrap();

            file.read_exact(&mut dir_iv).unwrap();
        }

        let dir_entries = path
            .read_dir()
            .unwrap()
            .filter_map(|f| {
                if let Ok(entry) = f {
                    if entry.file_name() != "gocryptfs.conf"
                        && entry.file_name() != "gocryptfs.diriv"
                    {
                        Some(entry)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .map(|f| DirEntry::try_from(f.path().as_path()))
            .filter_map(|f| f.ok())
            .collect();

        Self {
            filename: path.to_string_lossy().to_string(),
            dir_iv,
            dir_entries,
        }
    }

    pub fn lookup<P>(
        &self,
        filename_decoder: &FilenameDecoder,
        decrypted_path: P,
    ) -> Option<PathBuf>
    where
        P: AsRef<Path>,
    {
        let decrypted_path = decrypted_path.as_ref();

        let mut components = decrypted_path.components();

        let component = components.next().expect("lol");

        let decoder = filename_decoder.get_decoder_for_dir(&self.dir_iv);

        let segment = decoder
            .encrypt_filename(component.as_os_str().to_str().unwrap())
            .expect("lol");

        let segment_path = match segment {
            EncodedFilename::ShortFilename(filename) => PathBuf::from(filename),
            EncodedFilename::LongFilename(long_filename) => PathBuf::from(long_filename.filename),
        };

        if segment_path.is_dir() {
            let (size, _) = components.size_hint();

            if size > 0 {
                unimplemented!()
            } else {
                unimplemented!()
                //None
            }
        } else {
        //    component.as_path()
        unimplemented!()
        };

    }

    fn lookup_internal<P>(
        &self,
        filename_decoder: &FilenameDecoder,
        decrypted_path: P,
        dir: &DirCache,
    ) -> Option<PathBuf>
    where
        P: AsRef<Path>,
    {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum DirEntry {
    Dir(DirCache),
    File(String),
}

impl DirEntry {
    /// Returns `true` if the dir entry is [`Dir`].
    ///
    /// [`Dir`]: DirEntry::Dir
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(..))
    }

    /// Returns `true` if the dir entry is [`File`].
    ///
    /// [`File`]: DirEntry::File
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(..))
    }
}

impl TryFrom<&Path> for DirEntry {
    type Error = Box<dyn Error>; // TODO

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Ok(if path.is_dir() {
            DirEntry::Dir(DirCache::load_from_path(path))
        } else {
            DirEntry::File(
                path.components()
                    .last()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy()
                    .to_string(),
            )
        })
    }
}
