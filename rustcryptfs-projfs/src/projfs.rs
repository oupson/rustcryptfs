use std::{
    cmp::Ordering,
    ffi::{c_ulong, CStr, CString, OsString},
    fs::{DirEntry, File, ReadDir},
    io::{Read, Seek, SeekFrom},
    os::windows::{fs::MetadataExt, prelude::OsStringExt},
    path::PathBuf,
    slice::Iter,
};

use log::trace;
use rustcryptfs_lib::content::ContentEnc;
use windows_sys::{
    core::{GUID, HRESULT, PCWSTR},
    Win32::{
        Foundation::ERROR_FILE_NOT_FOUND,
        Storage::ProjectedFileSystem::{
            PrjAllocateAlignedBuffer, PrjFileNameCompare, PrjFillDirEntryBuffer,
            PrjFillDirEntryBuffer2, PrjFreeAlignedBuffer, PrjGetVirtualizationInstanceInfo,
            PrjWriteFileData, PrjWritePlaceholderInfo, PRJ_CALLBACK_DATA,
            PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO,
            PRJ_PLACEHOLDER_INFO,
        },
        System::Diagnostics::Debug::FACILITY_WIN32,
    },
};

// TODO windows::core::HRESULT

#[inline]
pub fn HRESULT_FROM_WIN32(x: c_ulong) -> HRESULT {
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
    diriv: [u8; 16],
    last_entry: Option<(Vec<u16>, PRJ_FILE_BASIC_INFO)>,
    entries: Vec<(Vec<u16>, DirEntry)>,
    iter_index: Option<usize>,
}

pub(crate) unsafe extern "system" fn start_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));
    log::trace!(
        "start_enum_callback called for {:?} {}",
        filename,
        *callback_data.FilePathName
    );

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
            log::trace!("{:?}", entry.file_name());
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
            diriv: iv,
            last_entry: None,
            entries,
            iter_index: None,
        },
    );

    0
}

pub(crate) unsafe extern "system" fn end_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    log::trace!("end_enum_callback called");

    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);

    instance_context
        .enum_map
        .remove(&crate::WinGuid(*enumeration_id));

    0
}

pub(crate) unsafe extern "system" fn get_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
    search_expression: PCWSTR,
    dir_entry_buffer_handle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> ::windows_sys::core::HRESULT {
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);

    log::debug!(
        "get_enum_callback called : {}",
        callback_data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN
    );

    let data = instance_context
        .enum_map
        .get_mut(&crate::WinGuid(*enumeration_id))
        .unwrap();

    if callback_data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN == 1 {
        data.last_entry = None;
        data.iter_index = Some(0);
    }

    let mut last_index = data.iter_index.unwrap_or(0);

    if let Some((last_filename, last_info)) = std::mem::replace(&mut data.last_entry, None) {
        PrjFillDirEntryBuffer(last_filename.as_ptr(), &last_info, dir_entry_buffer_handle);
        }

    while last_index < data.entries.len() {
        let (filename, entry) = &data.entries[last_index];

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
            FileAttributes: 0,
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
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));

    log::trace!("get_placeholder_info_callback called : {:?}", filename);

    let path = instance_context.get_path(filename);

    log::trace!("real path : {:?}", path);

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
                    FileAttributes: 0,
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

            HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        }
    }
}

pub(crate) unsafe extern "system" fn get_file_data_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> HRESULT {
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));

    let mut infos = std::mem::zeroed();
    PrjGetVirtualizationInstanceInfo(callback_data.NamespaceVirtualizationContext, &mut infos);

    trace!("{}", infos.WriteAlignment);

    log::trace!("get_file_data_callback called : {:?}", filename);

    let path = instance_context.get_path(filename);

    log::trace!("real path : {:?}", path);

    let size = length as usize;

    let mut file = File::open(path).unwrap();
    let decoder = instance_context.fs.content_decoder();

    let mut buf = [0u8; 18];
    let n = file.read(&mut buf).unwrap();
    let id = if n < 18 { None } else { Some(&buf[2..]) };

    let mut block_index = byte_offset / 4096;

    let mut buffer = Vec::with_capacity(size);

    let mut rem = size;

    let mut buf = [0u8; 4096 + 32];

    file.seek(SeekFrom::Start(18 + block_index * (4096 + 32)))
        .unwrap();

    {
        let n = file.read(&mut buf).unwrap();

        let res = decoder
            .decrypt_block(&mut buf[..n], block_index, id)
            .unwrap();

        let seek = (byte_offset as u64 - block_index * 4096) as usize;
        buffer.extend_from_slice(&res[seek..]);

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

        buffer.extend_from_slice(&res[..size]);

        block_index += 1;

        rem -= size;
    }

    let prjbuf =
        PrjAllocateAlignedBuffer(callback_data.NamespaceVirtualizationContext, buffer.len())
            as *mut u8;

    prjbuf.copy_from(buffer.as_ptr(), buffer.len());

    PrjWriteFileData(
        callback_data.NamespaceVirtualizationContext,
        &callback_data.DataStreamId,
        prjbuf as *mut _,
        byte_offset,
        buffer.len() as u32,
    );

    PrjFreeAlignedBuffer(prjbuf as *mut _);

    0
}
