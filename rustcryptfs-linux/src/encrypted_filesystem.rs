use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{File, FileType as StdFileType},
    io::{Read, Seek, SeekFrom},
    ops::Add,
    os::unix::prelude::{FileTypeExt, MetadataExt, OsStrExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};
use rustcryptfs_lib::{content_enc::ContentEnc, GocryptFs};

use crate::{
    error::Result,
    inode_cache::{InodeCache, InodeCacheExt},
};

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

        log::info!("Done");

        let mut inode_cache = BTreeMap::new();
        inode_cache.insert(FUSE_ROOT_ID, path.to_path_buf());

        Ok(Self { fs, inode_cache })
    }

    pub fn mount<P>(self, mountpoint: P)
    where
        P: AsRef<Path>,
    {
        fuser::mount2(self, mountpoint, &[]).unwrap();
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

    fn get_attr<P>(path: P, ino: u64) -> FileAttr
    where
        P: AsRef<Path>,
    {
        let meta = std::fs::metadata(&path).unwrap();

        let file_type = Self::get_file_type(meta.file_type());

        let file_size = if meta.is_file() {
            ContentEnc::get_real_size(meta.size())
        } else {
            meta.size()
        };

        FileAttr {
            ino,
            size: file_size,
            blocks: (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: meta.accessed().unwrap(),
            mtime: meta.modified().unwrap(),
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
        }
    }
}

impl Filesystem for EncryptedFs {
    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        if let Some(path) = self.get_path(ino) {
            reply.ok()
        } else {
            reply.error(libc::ENOENT)
        }
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        if let Some(path) = self.get_path(ino) {
            reply.attr(&Duration::new(0, 0), &Self::get_attr(path, ino))
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
        if let Some(parent) = &self.get_path(parent) {
            let iv = std::fs::read(parent.join("gocryptfs.diriv")).unwrap();
            let dir_decoder = self.fs.filename_decoder().get_cipher_for_dir(&iv);

            let encrypted_name = dir_decoder
                .encrypt_filename(&name.to_string_lossy())
                .unwrap();

            let encrypted_name = match encrypted_name {
                rustcryptfs_lib::filename::EncodedFilename::ShortFilename(s) => s,
                rustcryptfs_lib::filename::EncodedFilename::LongFilename(l) => l.filename,
            };

            let file_path = parent.join(encrypted_name);

            if file_path.exists() {
                let (ino, file_path) = self.inode_cache.get_or_insert_inode(file_path);

                reply.entry(&Duration::new(0, 0), &Self::get_attr(file_path, ino), 0)
            } else {
                reply.error(libc::ENOENT)
            }
        } else {
            reply.error(libc::ENOENT)
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
        if let Some(folder_path) = &self.inode_cache.get_path(ino).cloned() {
            let iv = std::fs::read(folder_path.join("gocryptfs.diriv")).unwrap();

            let dir_decoder = self.fs.filename_decoder().get_cipher_for_dir(&iv);

            if offset == 0 {
                let ino_parent = if ino == FUSE_ROOT_ID {
                    FUSE_ROOT_ID
                } else {
                    let parent = folder_path.parent().expect("Failed to get parent");
                    self.inode_cache
                        .iter()
                        .find_map(|(ino, p)| if p == parent { Some(*ino) } else { None })
                        .expect("Parent inode not found")
                };

                if !reply.add(ino, 1, FileType::Directory, ".") {
                    if reply.add(ino_parent, 2, FileType::Directory, "..") {
                        reply.ok();
                        return;
                    }
                } else {
                    reply.ok();
                    return;
                }
            }

            for (index, (meta, encrypted_name, name)) in std::fs::read_dir(folder_path)
                .unwrap()
                .flat_map(|e| e.ok())
                .flat_map(|dir| extract_name(dir, folder_path, &dir_decoder))
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

            reply.ok()
        } else {
            reply.error(libc::ENOENT)
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
        if let Some(file_path) = &self.get_path(ino) {
            let mut file = File::open(file_path).unwrap();
            let decoder = self.fs.content_decoder();

            let mut buf = [0u8; 18];
            let n = file.read(&mut buf).unwrap();
            let id = if n < 18 { None } else { Some(&buf[2..]) };

            let mut block_index = offset as u64 / 4096;

            let mut buffer = Vec::with_capacity(size as usize);

            let mut rem = size as usize;

            let mut buf = [0u8; 4096 + 32];

            file.seek(SeekFrom::Start(18 + block_index * (4096 + 32)))
                .unwrap();

            {
                let n = file.read(&mut buf).unwrap();

                let res = decoder.decrypt_block(&buf[..n], block_index, id).unwrap();

                let seek = (offset as u64 - block_index * 4096) as usize;
                buffer.extend_from_slice(&res[seek..]);

                block_index += 1;

                rem -= res.len() - seek;
            }

            while rem > 0 {
                let n = file.read(&mut buf).unwrap();

                if n == 0 {
                    break;
                }

                let res = decoder.decrypt_block(&buf[..n], block_index, id).unwrap();

                let size = res.len().min(rem);

                buffer.extend_from_slice(&res[..size]);

                block_index += 1;

                rem -= size;
            }

            reply.data(&buffer);
        } else {
            reply.error(libc::ENOENT)
        }
    }
}

fn extract_name(
    dir: std::fs::DirEntry,
    folder_path: &PathBuf,
    dir_decoder: &rustcryptfs_lib::filename::DirFilenameCipher,
) -> Option<(std::fs::Metadata, String, String)> {
    let filename = dir.file_name();
    let filename = filename.to_str().unwrap();
    if filename != "gocryptfs.conf" && filename != "gocryptfs.diriv" {
        if filename.starts_with("gocryptfs.longname.") {
            if !filename.ends_with(".name") {
                let filename =
                    std::fs::read_to_string(folder_path.join(format!("{}.name", filename)))
                        .unwrap();
                dir_decoder
                    .decode_filename(filename.as_str())
                    .map(|n| (dir.metadata().unwrap(), filename, n))
                    .ok()
            } else {
                None
            }
        } else {
            dir_decoder
                .decode_filename(filename)
                .map(|n| (dir.metadata().unwrap(), filename.to_string(), n))
                .ok()
        }
    } else {
        None
    }
}
