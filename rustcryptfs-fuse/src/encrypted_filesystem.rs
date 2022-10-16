use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{File, FileType as StdFileType},
    io::{Error as IoError, Read, Result as IoResult, Seek, SeekFrom},
    ops::Add,
    os::unix::prelude::{FileTypeExt, MetadataExt, OsStrExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};
use rustcryptfs_lib::{content::ContentEnc, GocryptFs};

use crate::{
    error::{ErrorExt, Result},
    inode_cache::{InodeCache, InodeCacheExt},
};

trait OptionExt<R> {
    fn enoent(self) -> IoResult<R>;
}

impl<R> OptionExt<R> for Option<R> {
    fn enoent(self) -> IoResult<R> {
        match self {
            Some(r) => Ok(r),
            None => Err(IoError::from_raw_os_error(libc::ENOENT)),
        }
    }
}

const BLOCK_SIZE: u64 = 4096;

pub struct EncryptedFs {
    fs: GocryptFs,
    inode_cache: InodeCache,
}

impl EncryptedFs {
    pub fn new<P>(path: P, password: &str) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        log::info!("Opening dir ...");
        let fs = GocryptFs::open(path, password)?;

        println!("Filesystem mounted and ready.");

        let mut inode_cache = BTreeMap::new();
        inode_cache.insert(FUSE_ROOT_ID, path.to_path_buf());

        Ok(Self { fs, inode_cache })
    }

    pub fn mount<P>(self, mountpoint: P) -> std::io::Result<()>
    where
        P: AsRef<Path>,
    {
        fuser::mount2(self, mountpoint, &[])
    }

    fn get_file_type(file_type: StdFileType) -> FileType {
        if file_type.is_file() {
            FileType::RegularFile
        } else if file_type.is_dir() {
            FileType::Directory
        } else if file_type.is_symlink() {
            FileType::Symlink
        } else if file_type.is_socket() {
            FileType::Socket
        } else if file_type.is_char_device() {
            FileType::CharDevice
        } else if file_type.is_block_device() {
            FileType::BlockDevice
        } else if file_type.is_fifo() {
            FileType::NamedPipe
        } else {
            unimplemented!()
        }
    }

    fn get_path(&self, ino: u64) -> Option<&PathBuf> {
        self.inode_cache.get_path(ino)
    }

    fn get_attr<P>(path: P, ino: u64) -> std::io::Result<FileAttr>
    where
        P: AsRef<Path>,
    {
        let meta = std::fs::metadata(&path)?;

        let file_type = Self::get_file_type(meta.file_type());

        let file_size = if meta.is_file() {
            ContentEnc::get_real_size(meta.size())
        } else {
            meta.size()
        };

        Ok(FileAttr {
            ino,
            size: file_size,
            blocks: (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: meta.accessed()?,
            mtime: meta.modified()?,
            ctime: UNIX_EPOCH.add(Duration::new(meta.ctime() as u64, 0)),
            crtime: UNIX_EPOCH.add(Duration::new(meta.ctime() as u64, 0)),
            kind: file_type,
            perm: meta.permissions().mode() as u16,
            nlink: meta.nlink() as u32,
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        })
    }

    fn lookup_impl(
        &mut self,
        parent: u64,
        name: &std::ffi::OsStr,
    ) -> rustcryptfs_lib::error::Result<(Duration, FileAttr, u64)> {
        let parent = self.get_path(parent).enoent()?;
        let iv = std::fs::read(parent.join("gocryptfs.diriv"))?;
        let dir_decoder = self.fs.filename_decoder().get_cipher_for_dir(&iv);

        let encrypted_name = dir_decoder.encrypt_filename(&name.to_string_lossy())?;

        let encrypted_name = match &encrypted_name {
            rustcryptfs_lib::filename::EncodedFilename::ShortFilename(s) => s,
            rustcryptfs_lib::filename::EncodedFilename::LongFilename(l) => l.filename(),
        };

        let file_path = parent.join(encrypted_name);

        if file_path.exists() {
            let (ino, file_path) = self.inode_cache.get_or_insert_inode(file_path);

            Ok((Duration::new(0, 0), Self::get_attr(file_path, ino)?, 0))
        } else {
            Err(IoError::from_raw_os_error(libc::ENOENT).into())
        }
    }

    fn read_dir_impl(
        &mut self,
        ino: u64,
        offset: i64,
        reply: &mut fuser::ReplyDirectory,
    ) -> rustcryptfs_lib::error::Result<()> {
        let folder_path = &self.inode_cache.get_path(ino).enoent()?.clone();
        let iv = std::fs::read(folder_path.join("gocryptfs.diriv"))?;

        let dir_decoder = self.fs.filename_decoder().get_cipher_for_dir(&iv);

        if offset == 0 {
            let ino_parent = if ino == FUSE_ROOT_ID {
                FUSE_ROOT_ID
            } else {
                let parent = folder_path.parent().enoent()?;
                self.inode_cache
                    .iter()
                    .find_map(|(ino, p)| if p == parent { Some(*ino) } else { None })
                    .enoent()?
            };

            if !reply.add(ino, 1, FileType::Directory, ".") {
                if reply.add(ino_parent, 2, FileType::Directory, "..") {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        for (index, (meta, encrypted_name, name)) in std::fs::read_dir(folder_path)?
            .flat_map(|e| e.ok())
            .flat_map(|dir| match extract_name(&dir, folder_path, &dir_decoder) {
                Ok(v) => v,
                Err(e) => {
                    log::error!(
                        "Failed to extract name of entry {:?} : {}",
                        dir.file_name(),
                        e
                    );
                    None
                }
            })
            .skip(offset as usize)
            .enumerate()
        {
            let (inode, _) = self
                .inode_cache
                .get_or_insert_inode(folder_path.join(&encrypted_name));

            let file_type = Self::get_file_type(meta.file_type());

            let buffer_full: bool = reply.add(
                inode,
                offset + index as i64 + 1 + 2,
                file_type,
                OsStr::from_bytes(name.as_bytes()),
            );

            if buffer_full {
                break;
            }
        }
        Ok(())
    }

    fn read_impl(
        &mut self,
        ino: u64,
        offset: i64,
        size: usize,
    ) -> rustcryptfs_lib::error::Result<Vec<u8>> {
        let file_path = self.get_path(ino).enoent()?;
        let mut file = File::open(file_path)?;
        let decoder = self.fs.content_decoder();

        let mut buf = [0u8; 18];
        let n = file.read(&mut buf)?;
        let id = if n < 18 { None } else { Some(&buf[2..]) };

        let mut block_index = offset as u64 / 4096;

        let mut buffer = Vec::with_capacity(size);

        let mut rem = size;

        let mut buf = [0u8; 4096 + 32];

        file.seek(SeekFrom::Start(18 + block_index * (4096 + 32)))?;

        {
            let n = file.read(&mut buf)?;

            let res = decoder.decrypt_block(&mut buf[..n], block_index, id)?;

            let seek = (offset as u64 - block_index * 4096) as usize;
            buffer.extend_from_slice(&res[seek..]);

            block_index += 1;

            rem -= res.len() - seek;
        }

        while rem > 0 {
            let n = file.read(&mut buf)?;

            if n == 0 {
                break;
            }

            let res = decoder.decrypt_block(&mut buf[..n], block_index, id)?;

            let size = res.len().min(rem);

            buffer.extend_from_slice(&res[..size]);

            block_index += 1;

            rem -= size;
        }
        Ok(buffer)
    }
}

impl Filesystem for EncryptedFs {
    fn access(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _mask: i32,
        reply: fuser::ReplyEmpty,
    ) {
        if let Some(_path) = self.get_path(ino) {
            reply.ok()
        } else {
            reply.error(libc::ENOENT)
        }
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        if let Some(path) = self.get_path(ino) {
            match Self::get_attr(path, ino) {
                Ok(attr) => reply.attr(&Duration::new(0, 0), &attr),
                Err(e) => reply.error(e.raw_os_error().unwrap()),
            }
        } else {
            reply.error(libc::ENOENT)
        }
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        match self.lookup_impl(parent, name) {
            Ok((ttl, attr, generation)) => reply.entry(&ttl, &attr, generation),
            Err(e) => {
                log::debug!("error on lookup : {}", e);
                reply.error(e.to_raw_code())
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        match self.read_dir_impl(ino, offset, &mut reply) {
            Ok(()) => reply.ok(),
            Err(e) => {
                log::debug!("error on readdir : {}", e);
                reply.error(e.to_raw_code())
            }
        }
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        match self.read_impl(ino, offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                log::error!("read : {}", e);
                reply.error(e.to_raw_code())
            }
        }
    }
}

fn extract_name(
    dir: &std::fs::DirEntry,
    folder_path: &Path,
    dir_decoder: &rustcryptfs_lib::filename::DirFilenameCipher,
) -> rustcryptfs_lib::error::Result<Option<(std::fs::Metadata, String, String)>> {
    let filename = dir.file_name();
    let filename = filename.to_string_lossy();
    if filename != "gocryptfs.conf" && filename != "gocryptfs.diriv" {
        if filename.starts_with("gocryptfs.longname.") {
            if !filename.ends_with(".name") {
                let filename =
                    std::fs::read_to_string(folder_path.join(format!("{}.name", filename)))?;
                let decrypted_filename = dir_decoder.decode_filename(filename.as_str())?;
                Ok(Some((dir.metadata()?, filename, decrypted_filename)))
            } else {
                Ok(None)
            }
        } else {
            let decrypted_filename = dir_decoder.decode_filename(&*filename)?;
            Ok(Some((
                dir.metadata()?,
                filename.to_string(),
                decrypted_filename,
            )))
        }
    } else {
        Ok(None)
    }
}
