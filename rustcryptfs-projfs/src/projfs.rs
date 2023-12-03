use std::{
    ffi::OsString,
    fs::{File, ReadDir},
    io::{Read, Seek, SeekFrom},
    os::windows::{fs::MetadataExt, prelude::OsStringExt},
    path::PathBuf,
};

use log::trace;
use rustcryptfs_lib::content::ContentEnc;
use windows_sys::{
    core::{GUID, HRESULT, PCWSTR},
    Win32::Storage::ProjectedFileSystem::{
        PrjAllocateAlignedBuffer, PrjFillDirEntryBuffer2, PrjFreeAlignedBuffer,
        PrjGetVirtualizationInstanceInfo, PrjWriteFileData, PrjWritePlaceholderInfo,
        PRJ_CALLBACK_DATA, PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO, PRJ_PLACEHOLDER_INFO,
    },
};

use crate::EncryptedFs;

unsafe fn u16_ptr_to_string(ptr: *const u16) -> OsString {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);

    OsString::from_wide(slice)
}

#[derive(Debug)]
pub(crate) struct DirEnumData {
    diriv: [u8; 16],
    r: ReadDir,
}

pub(crate) unsafe extern "system" fn start_enum_callback(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);
    let filename = PathBuf::from(u16_ptr_to_string(callback_data.FilePathName));
    log::trace!("start_enum_callback called for {:?}", filename);

    let path = instance_context.get_path(filename);

    let mut iv = [0u8; 16];

    {
        let mut iv_file = File::open(path.join("gocryptfs.diriv")).unwrap();
        iv_file.read_exact(&mut iv).unwrap();
    }

    let r = std::fs::read_dir(path).unwrap();

    instance_context.enum_map.insert(
        crate::WinGuid(*enumeration_id),
        DirEnumData { r: r, diriv: iv },
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
    log::trace!("get_enum_callback called");

    let callback_data = &*callback_data;
    let instance_context = &mut *(callback_data.InstanceContext as *mut EncryptedFs);

    let data = instance_context
        .enum_map
        .get_mut(&crate::WinGuid(*enumeration_id))
        .unwrap();

    log::trace!("foo {:?}", data);

    while let Some(e) = data.r.next() {
        let entry = e.unwrap();

        if entry.file_name() == "gocryptfs.diriv" || entry.file_name() == "gocryptfs.conf" {
            continue;
        }

        let metadata = entry.metadata().unwrap();

        let mut os_str = instance_context
            .fs
            .filename_decoder()
            .get_cipher_for_dir(&data.diriv)
            .decode_filename(&*entry.file_name().to_string_lossy())
            .unwrap()
            .encode_utf16()
            .collect::<Vec<u16>>();

        os_str.push(0);

        let a = os_str.as_ptr();

        let infos = PRJ_FILE_BASIC_INFO {
            IsDirectory: if metadata.is_dir() { 1 } else { 0 },
            FileSize: if metadata.is_dir() {
                metadata.file_size() as i64
            } else {
                ContentEnc::get_real_size(metadata.file_size()) as i64
            },
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: 0,
        };

        PrjFillDirEntryBuffer2(dir_entry_buffer_handle, a, &infos, std::ptr::null());
    }

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
            let infos = PRJ_PLACEHOLDER_INFO {
                FileBasicInfo: PRJ_FILE_BASIC_INFO {
                    IsDirectory: if metadata.is_dir() { 1 } else { 0 },
                    FileSize: if metadata.is_dir() {
                        metadata.file_size() as i64
                    } else {
                        ContentEnc::get_real_size(metadata.file_size()) as i64
                    },
                    CreationTime: 0,
                    LastAccessTime: 0,
                    LastWriteTime: 0,
                    ChangeTime: 0,
                    FileAttributes: 0,
                },
                EaInformation: std::mem::zeroed(),
                SecurityInformation: std::mem::zeroed(),
                StreamsInformation: std::mem::zeroed(),
                VersionInfo: std::mem::zeroed(),
                VariableData: std::mem::zeroed(),
            };

            let hr = PrjWritePlaceholderInfo(
                callback_data.NamespaceVirtualizationContext,
                callback_data.FilePathName,
                &infos,
                std::mem::size_of_val(&infos) as u32,
            );

            trace!("{} {}", super::WinError(hr), std::mem::size_of_val(&infos));

            0
        }
        Err(e) => {
            log::trace!("{}", e);
            0x80004005u32 as i32 // TODO
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
