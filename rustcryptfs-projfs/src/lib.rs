use std::{
    collections::HashMap,
    fs::File,
    hash::{Hash, Hasher},
    io::Read,
    mem::MaybeUninit,
    os::{raw::c_void, windows::prelude::OsStrExt},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc::channel},
};

use log::{info, trace, warn};
use rustcryptfs_lib::GocryptFs;

use error::Result;
use rustcryptfs_lib::filename::EncodedFilename;
use windows_sys::Win32::Storage::ProjectedFileSystem::{
    PrjDeleteFile, PrjGetOnDiskFileState, PRJ_FILE_STATE, PRJ_PLACEHOLDER_VERSION_INFO,
    PRJ_UPDATE_ALLOW_DIRTY_DATA, PRJ_UPDATE_ALLOW_DIRTY_METADATA, PRJ_UPDATE_ALLOW_READ_ONLY,
    PRJ_UPDATE_ALLOW_TOMBSTONE,
};

use windows_sys::{
    core::GUID,
    Win32::{
        Storage::ProjectedFileSystem::{
            PrjMarkDirectoryAsPlaceholder, PrjStartVirtualizing, PrjStopVirtualizing,
            PRJ_CALLBACKS, PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
        },
        System::Com::CoCreateGuid,
    },
};

use crate::error::ToWinResult;

pub mod error;
mod projfs;
pub(crate) mod write_buffer;

#[repr(transparent)]
struct WinGuid(GUID);

impl PartialEq for WinGuid {
    fn eq(&self, other: &Self) -> bool {
        self.0.data1 == other.0.data1
            && self.0.data2 == other.0.data2
            && self.0.data3 == other.0.data3
            && self.0.data4 == other.0.data4
    }
}

impl Eq for WinGuid {}

impl Hash for WinGuid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.data1.hash(state);
        self.0.data2.hash(state);
        self.0.data3.hash(state);
        self.0.data4.hash(state);
    }
}

pub struct EncryptedFs {
    fs: GocryptFs,
    filename_map: HashMap<PathBuf, PathBuf>,
    enum_map: HashMap<WinGuid, projfs::DirEnumData>,
    base_path: PathBuf,
    is_stopping: AtomicBool,
}

impl EncryptedFs {
    pub(crate) fn retrieve_filename<'p>(&'p self, filename: &'p Path) -> Option<&'p Path> {
        if filename.as_os_str().len() == 0 {
            Some(filename)
        } else {
            self.filename_map.get(filename).map(|p| p.as_path())
        }
    }

    pub(crate) fn insert_filename(&mut self, filename: PathBuf, real_path: PathBuf) {
        self.filename_map.insert(filename, real_path);
    }

    pub(crate) fn get_path(&mut self, filename: PathBuf) -> PathBuf {
        let path = match self.retrieve_filename(&filename) {
            Some(p) => p.to_path_buf(),
            None => {
                let parent = filename.parent().unwrap();
                let name = filename.file_name().unwrap();
                let real_parent: &Path = self.retrieve_filename(&parent).unwrap();

                let mut iv = [0u8; 16];

                {
                    let mut iv_file =
                        File::open(self.base_path.join(real_parent).join("gocryptfs.diriv"))
                            .unwrap();
                    iv_file.read_exact(&mut iv).unwrap();
                }

                let d = self.fs.filename_decoder().get_cipher_for_dir(&iv);

                let encrypted_name = d.encrypt_filename(&name.to_string_lossy()).unwrap();

                let encoded_name = match &encrypted_name {
                    EncodedFilename::ShortFilename(s) => s,
                    EncodedFilename::LongFilename(l) => l.filename(),
                };

                let real_path = real_parent.join(encoded_name);

                self.insert_filename(filename, real_path.clone());

                real_path
            }
        };

        self.base_path.join(path)
    }
}

impl EncryptedFs {
    pub fn new<P>(path: P, password: &str) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        info!("Opening dir ...");
        let fs = GocryptFs::open(path, password)?;

        println!("Filesystem mounted and ready.");

        Ok(Self {
            fs,
            filename_map: Default::default(),
            enum_map: Default::default(),
            base_path: path.to_owned(),
            is_stopping: AtomicBool::new(false),
        })
    }

    pub fn mount<P>(self, mountpoint: P) -> crate::Result<()>
    where
        P: AsRef<Path>,
    {
        let mountpoint = mountpoint.as_ref();
        unsafe {
            let mut instance_id: GUID = MaybeUninit::zeroed().assume_init();
            CoCreateGuid(&mut instance_id).to_win_result()?;

            let mut root_name: Vec<u16> = mountpoint.as_os_str().encode_wide().collect();
            root_name.push(0);

            let info: PRJ_PLACEHOLDER_VERSION_INFO = MaybeUninit::zeroed().assume_init();

            let ptr = root_name.as_ptr();
            PrjMarkDirectoryAsPlaceholder(ptr, std::ptr::null(), &info, &instance_id)
                .to_win_result()?;

            let mut callback_table: PRJ_CALLBACKS = MaybeUninit::zeroed().assume_init();

            callback_table.StartDirectoryEnumerationCallback = Some(projfs::start_enum_callback);
            callback_table.EndDirectoryEnumerationCallback = Some(projfs::end_enum_callback);
            callback_table.GetDirectoryEnumerationCallback = Some(projfs::get_enum_callback);
            callback_table.GetPlaceholderInfoCallback = Some(projfs::get_placeholder_info_callback);
            callback_table.GetFileDataCallback = Some(projfs::get_file_data_callback);

            let this = Box::leak(Box::new(self)) as *mut EncryptedFs;

            let mut instance_handle: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT =
                MaybeUninit::zeroed().assume_init();
            PrjStartVirtualizing(
                ptr,
                &callback_table,
                this as *const c_void,
                std::ptr::null(),
                &mut instance_handle,
            )
            .to_win_result()?;

            trace!("mounted");

            let (tx, rx) = channel();

            ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
                .expect("Error setting Ctrl-C handler");

            rx.recv().expect("Could not receive from channel.");

            println!("Exiting ...");

            (*this)
                .is_stopping
                .store(true, std::sync::atomic::Ordering::Relaxed);

            delete_recursively(instance_handle, &mountpoint, &mountpoint)?;

            PrjStopVirtualizing(instance_handle);

            drop(Box::from_raw(this));
        }
        Ok(())
    }
}

unsafe fn delete_recursively(
    instance: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    root_path: &Path,
    path: &Path,
) -> Result<()> {
    let mut iter = std::fs::read_dir(path)?.filter_map(|r| r.ok());
    while let Some(e) = iter.next() {
        let mut file_state: PRJ_FILE_STATE = std::mem::zeroed();
        let wide_name = e
            .path()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        if PrjGetOnDiskFileState(wide_name.as_ptr(), &mut file_state)
            .to_win_result()
            .is_ok()
        {
            let path = e.path();
            let delete_result = if e.file_type()?.is_dir() {
                delete_recursively(instance, root_path, &path)?;
                delete_file_from_projection(instance, path.strip_prefix(root_path).unwrap())
            } else {
                delete_file_from_projection(instance, path.strip_prefix(root_path).unwrap())
            };

            if let Err(e) = delete_result {
                warn!("failed to delete a file : {}", e);
            }
        }
    }

    Ok(())
}

fn delete_file_from_projection(
    instance: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    filename: &Path,
) -> Result<()> {
    let filename = filename
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    unsafe {
        PrjDeleteFile(
            instance,
            filename.as_ptr(),
            PRJ_UPDATE_ALLOW_DIRTY_DATA
                | PRJ_UPDATE_ALLOW_DIRTY_METADATA
                | PRJ_UPDATE_ALLOW_READ_ONLY
                | PRJ_UPDATE_ALLOW_TOMBSTONE,
            std::ptr::null_mut(),
        )
        .to_win_result()?;
    }
    Ok(())
}
