use std::{
    collections::BTreeMap,
    ffi::OsStr,
    ops::Add,
    os::unix::prelude::{FileTypeExt, MetadataExt, OsStrExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};
use rustcryptfs_lib::GocryptFs;

use crate::error::Result;

const BLOCK_SIZE: u64 = 4096;

type InodeCache = BTreeMap<u64, PathBuf>;

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

    fn get_path(&self, ino: u64) -> Option<PathBuf> {
        // TODO CHECK PERM

        // TODO AVOID CLONE
        self.inode_cache.get(&ino).map(|p| p.clone())
    }

    fn get_real_size(size: u64) -> u64 {
        if size == 0 {
            0
        } else {
            let x = (size - 50) / 4128;

            let y = (size - 50) - x * 4128;
            x * 4096 + y
        }
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

    fn get_attr<P>(path: P, ino: u64) -> FileAttr
    where
        P: AsRef<Path>,
    {
        let meta = std::fs::metadata(&path).unwrap();

        let file_type = Self::get_file_type(meta.file_type());

        let file_size = if meta.is_file() {
            EncryptedFs::get_real_size(meta.size())
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

trait InodeCacheExt {
    fn get_or_insert_inode(&mut self, file_path: PathBuf) -> (u64, PathBuf);
}

impl InodeCacheExt for InodeCache {
    // TODO Try to avoid clone
    fn get_or_insert_inode(&mut self, file_path: PathBuf) -> (u64, PathBuf) {
        if let Some((ino, path)) = {
            self.iter()
                .find_map(|(i, p)| if p.eq(&file_path) { Some((i, p)) } else { None })
        } {
            (*ino, path.clone())
        } else {
            let ino = self.len() as u64 + 1;
            self.insert(ino, file_path);

            (ino, self.get(&ino).unwrap().clone())
        }
    }
}

impl Filesystem for EncryptedFs {
    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        log::debug!("access, ino : {}, mask : {}", ino, mask);
        if let Some(path) = self.get_path(ino) {
            reply.ok()
        } else {
            reply.error(libc::ENOENT)
        }
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        log::debug!("getattr, ino : {}", ino);
        if let Some(path) = self.get_path(ino) {
            log::debug!("access, path = {:?}", path);
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
            let dir_decoder = self.fs.filename_decoder().get_decoder_for_dir(&iv);

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
        if let Some(folder_path) = &self.get_path(ino) {
            log::debug!("folder_path :{:?}", folder_path);

            let iv = std::fs::read(folder_path.join("gocryptfs.diriv")).unwrap();

            let dir_decoder = self.fs.filename_decoder().get_decoder_for_dir(&iv);

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
                    offset + index as i64 + 1,
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
}

fn extract_name(
    dir: std::fs::DirEntry,
    folder_path: &PathBuf,
    dir_decoder: &rustcryptfs_lib::filename::DirFilenameDecoder,
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
