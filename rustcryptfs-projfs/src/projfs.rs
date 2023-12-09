use std::{
    cmp::Ordering,
    ffi::{c_ulong, OsString},
    fs::{DirEntry, File},
    io::{Read, Seek, SeekFrom},
    os::windows::{fs::MetadataExt, prelude::OsStringExt},
    path::PathBuf,
};

use log::{trace, warn};
use rustcryptfs_lib::content::ContentEnc;
use windows_sys::{
    core::{GUID, HRESULT, PCWSTR},
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, E_INVALIDARG},
        Storage::ProjectedFileSystem::{
            PrjFileNameCompare, PrjFillDirEntryBuffer, PrjWritePlaceholderInfo, PRJ_CALLBACK_DATA,
            PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
            PRJ_PLACEHOLDER_INFO,
        },
        System::Diagnostics::Debug::FACILITY_WIN32,
    },
};

// TODO windows::core::HRESULT

#[inline]
pub fn hresult_from_win32(x: c_ulong) -> HRESULT {
    if x as i32 <= 0 {
        x as i32
    } else {
        ((x & 0x0000FFFF) | ((FACILITY_WIN32 as u32) << 16) | 0x80000000) as i32
    }
}

use crate::EncryptedFs;

unsafe fn u16_ptr_to_string(ptr: *const u16) -> OsString {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);

    OsString::from_wide(slice)
}

pub(crate) struct DirEnumData {
    last_entry: Option<(Vec<u16>, PRJ_FILE_BASIC_INFO)>,
    entries: Vec<(Vec<u16>, DirEntry)>,
    iter_index: Option<usize>,
    search_expression: Option<Vec<u16>>,
}

pub(crate) unsafe extern "system" fn start_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    trace!("start_enum_callback");
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));

    let path = instance_context.get_path(filename);

    let mut iv = [0u8; 16];

    {
        let mut iv_file = File::open(path.join("gocryptfs.diriv")).unwrap();
        iv_file.read_exact(&mut iv).unwrap();
    }

    let mut entries = std::fs::read_dir(path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() != "gocryptfs.conf" && e.file_name() != "gocryptfs.diriv")
        .map(|entry| {
            (
                instance_context
                    .fs
                    .filename_decoder()
                    .get_cipher_for_dir(&iv)
                    .decode_filename(&*entry.file_name().to_string_lossy())
                    .unwrap()
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>(),
                entry,
            )
        })
        .collect::<Vec<_>>();

    entries.sort_by(|entry1, entry2| {
        let comp = PrjFileNameCompare(entry1.0.as_ptr(), entry2.0.as_ptr());
        if comp < 0 {
            Ordering::Less
        } else if comp > 0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });

    instance_context.enum_map.insert(
        crate::WinGuid(*enumeration_id),
        DirEnumData {
            last_entry: None,
            entries,
            iter_index: None,
            search_expression: None,
        },
    );

    0
}

pub(crate) unsafe extern "system" fn end_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    trace!("end_enum_callback");
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);

    instance_context
        .enum_map
        .remove(&crate::WinGuid(*enumeration_id));

    0
}

// TODO : Search expression
pub(crate) unsafe extern "system" fn get_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
    search_expression: PCWSTR,
    dir_entry_buffer_handle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> ::windows_sys::core::HRESULT {
    trace!("get_enum_callback");
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);

    if instance_context
        .is_stopping
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return 0;
    }

    let data = if let Some(data) = instance_context
        .enum_map
        .get_mut(&crate::WinGuid(*enumeration_id))
    {
        data
    } else {
        warn!("unknown enumeration");
        return E_INVALIDARG;
    };

    if callback_data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN == 1 {
        data.last_entry = None;
        data.iter_index = Some(0);

        if search_expression != std::ptr::null() {
            let len = libc::wcslen(search_expression) + 1;
            data.search_expression =
                Some(std::slice::from_raw_parts(search_expression, len).to_vec());
        } else {
            data.search_expression = None;
        }
    }

    let mut last_index = data.iter_index.unwrap_or(0);

    if let Some((last_filename, last_info)) = std::mem::replace(&mut data.last_entry, None) {
        let insert = if let Some(search_expression) = &data.search_expression {
            PrjFileNameCompare(last_filename.as_ptr(), search_expression.as_ptr()) != 0
        } else {
            false
        };

        if insert {
            PrjFillDirEntryBuffer(last_filename.as_ptr(), &last_info, dir_entry_buffer_handle);
        }
    }

    while last_index < data.entries.len() {
        let (filename, entry) = &data.entries[last_index];

        let insert = if let Some(search_expression) = &data.search_expression {
            PrjFileNameCompare(filename.as_ptr(), search_expression.as_ptr()) != 0
        } else {
            false
        };

        if !insert {
            continue;
        }

        let metadata = entry.metadata().unwrap();

        let infos = PRJ_FILE_BASIC_INFO {
            IsDirectory: if metadata.is_dir() { 1 } else { 0 },
            FileSize: if metadata.is_dir() {
                0
            } else {
                ContentEnc::get_real_size(metadata.file_size()) as i64
            },
            CreationTime: metadata.creation_time() as i64,
            LastAccessTime: metadata.last_access_time() as i64,
            LastWriteTime: metadata.last_write_time() as i64,
            ChangeTime: metadata.last_write_time() as i64,
            FileAttributes: metadata.file_attributes(),
        };

        // TODO check if HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
        if PrjFillDirEntryBuffer(filename.as_ptr(), &infos, dir_entry_buffer_handle) != 0 {
            trace!("not enough size in buffer");
            data.last_entry = Some((filename.clone(), infos));
            break;
        }

        last_index += 1;
    }

    data.iter_index = Some(last_index);

    0
}

pub(crate) unsafe extern "system" fn get_placeholder_info_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
) -> ::windows_sys::core::HRESULT {
    trace!("get_placeholder_info_callback");
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));

    let path = instance_context.get_path(filename);

    match path.metadata() {
        Ok(metadata) => {
            let mut infos: PRJ_PLACEHOLDER_INFO = std::mem::zeroed();
            infos.FileBasicInfo = PRJ_FILE_BASIC_INFO {
                IsDirectory: if metadata.is_dir() { 1 } else { 0 },
                FileSize: if metadata.is_dir() {
                    0
                } else {
                    ContentEnc::get_real_size(metadata.file_size()) as i64
                },
                CreationTime: metadata.creation_time() as i64,
                LastAccessTime: metadata.last_access_time() as i64,
                LastWriteTime: metadata.last_write_time() as i64,
                ChangeTime: metadata.last_write_time() as i64,
                FileAttributes: metadata.file_attributes(),
            };

            let hr = PrjWritePlaceholderInfo(
                callback_data.NamespaceVirtualizationContext,
                callback_data.FilePathName,
                &infos,
                std::mem::size_of_val(&infos) as u32,
            );

            hr
        }
        Err(e) => {
            log::trace!("{}", e);

            hresult_from_win32(ERROR_FILE_NOT_FOUND)
        }
    }
}

pub(crate) unsafe extern "system" fn get_file_data_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> HRESULT {
    trace!("get_file_data_callback");
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));

    let path = instance_context.get_path(filename.clone());

    let size = length as usize;

    let mut file = File::open(path).unwrap();
    let decoder = instance_context.fs.content_decoder();

    let mut buf = [0u8; 18];
    let n = file.read(&mut buf).unwrap();
    let id = if n < 18 { None } else { Some(&buf[2..]) };

    let mut block_index = byte_offset / 4096;

    let mut rem = size;

    let mut writter = crate::write_buffer::WriteBuffer::new(
        callback_data.NamespaceVirtualizationContext,
        callback_data.DataStreamId,
        byte_offset,
    );
    let mut buf = [0u8; 4096 + 32];

    file.seek(SeekFrom::Start(18 + block_index * (4096 + 32)))
        .unwrap();

    {
        let n = file.read(&mut buf).unwrap();

        let res = decoder
            .decrypt_block(&mut buf[..n], block_index, id)
            .unwrap();

        let seek = (byte_offset as u64 - block_index * 4096) as usize;

        writter.append_buf(&res[seek..]);
        block_index += 1;

        rem -= res.len() - seek;
    }

    while rem > 0 {
        let n = file.read(&mut buf).unwrap();

        if n == 0 {
            break;
        }

        let res = decoder
            .decrypt_block(&mut buf[..n], block_index, id)
            .unwrap();

        let size = res.len().min(rem);

        writter.append_buf(&res[..size]);

        block_index += 1;

        rem -= size;
    }

    writter.finish();

    0
}
