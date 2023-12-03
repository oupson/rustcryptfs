use std::collections::HashMap;
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::iter::Map;
use std::path::PathBuf;
use std::{
    error::Error, fmt::Display, mem::MaybeUninit, os::windows::prelude::OsStrExt, path::Path,
};

use std::sync::mpsc::channel;

use libc::c_void;
use rustcryptfs_lib::GocryptFs;

use error::Result;
use rustcryptfs_lib::filename::EncodedFilename;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::ProjectedFileSystem::PRJ_PLACEHOLDER_VERSION_INFO;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
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

pub mod error;
mod projfs;

#[repr(transparent)]
#[derive(Debug)]
pub struct WinError(i32);

impl Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buffer = std::ptr::null_mut();
        let size = unsafe {
            FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null(),
                self.0 as u32,
                0,
                &mut buffer as *mut *mut i8 as *mut _,
                0,
                std::ptr::null(),
            )
        };

        let buffer = unsafe { CStr::from_ptr(buffer) };

        write!(
            f,
            "Windows Error : 0x{:08X} :{}",
            self.0,
            buffer.to_string_lossy()
        )
    }
}

impl Error for WinError {}

macro_rules! win_to_res {
    ($l:expr) => {{
        let res = $l;

        if (res < 0) {
            Err(WinError(res))
        } else {
            Ok(res)
        }
    }};
}

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

        log::info!("Opening dir ...");
        let fs = GocryptFs::open(path, password)?;

        println!("Filesystem mounted and ready.");

        Ok(Self {
            fs,
            filename_map: Default::default(),
            enum_map: Default::default(),
            base_path: path.to_owned(),
        })
    }

    pub fn mount<P>(self, mountpoint: P) -> crate::Result<()>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let mut instance_id: GUID = MaybeUninit::zeroed().assume_init();
            win_to_res!(CoCreateGuid(&mut instance_id))?;

            let mut root_name: Vec<u16> = mountpoint.as_ref().as_os_str().encode_wide().collect();
            root_name.push(0);

            let info: PRJ_PLACEHOLDER_VERSION_INFO = MaybeUninit::zeroed().assume_init();

            let ptr = root_name.as_ptr();
            win_to_res!(PrjMarkDirectoryAsPlaceholder(
                ptr,
                std::ptr::null(),
                &info,
                &instance_id
            ))?;

            let mut callback_table: PRJ_CALLBACKS = MaybeUninit::zeroed().assume_init();

            callback_table.StartDirectoryEnumerationCallback = Some(projfs::start_enum_callback);
            callback_table.EndDirectoryEnumerationCallback = Some(projfs::end_enum_callback);
            callback_table.GetDirectoryEnumerationCallback = Some(projfs::get_enum_callback);
            callback_table.GetPlaceholderInfoCallback = Some(projfs::get_placeholder_info_callback);
            callback_table.GetFileDataCallback = Some(projfs::get_file_data_callback);

            let this = Box::leak(Box::new(self)) as *mut EncryptedFs;

            let mut instance_handle: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT =
                MaybeUninit::zeroed().assume_init();
            win_to_res!(PrjStartVirtualizing(
                ptr,
                &callback_table,
                this as *const c_void,
                std::ptr::null(),
                &mut instance_handle
            ))?;

            log::trace!("mounted");

            let (tx, rx) = channel();

            ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
                .expect("Error setting Ctrl-C handler");

            rx.recv().expect("Could not receive from channel.");

            println!("Exiting ...");

            PrjStopVirtualizing(instance_handle);

            drop(Box::from_raw(this));
        }
        Ok(())
    }
}
