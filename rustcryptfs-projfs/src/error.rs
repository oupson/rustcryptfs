use std::{
    ffi::CStr,
    fmt::{Debug, Display},
    slice,
};

use rustcryptfs_lib::filename::FilenameCipherError;
use thiserror::Error;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    WindowsError(#[from] WinError),

    #[error(transparent)]
    RustCryptFsError(#[from] rustcryptfs_lib::error::Error),

    #[error(transparent)]
    RustCryptFsFilenameError(#[from] FilenameCipherError),
}

#[repr(transparent)]
pub struct WinError(pub i32);

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

        let buffer = unsafe {
            CStr::from_bytes_with_nul_unchecked(slice::from_raw_parts(
                buffer as *mut u8,
                (size + 1) as usize,
            ))
        };

        write!(
            f,
            "Windows Error : 0x{:08X} :{}",
            self.0,
            buffer.to_string_lossy()
        )
    }
}

impl Debug for WinError {
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

        let buffer = unsafe {
            CStr::from_bytes_with_nul_unchecked(slice::from_raw_parts(
                buffer as *mut u8,
                (size + 1) as usize,
            ))
        };

        f.debug_struct("WinError")
            .field("error_code", &format!("0x{:08X}", self.0))
            .field("msg", &buffer.to_string_lossy())
            .finish()
    }
}

impl std::error::Error for WinError {}

pub trait ToWinResult: Sized {
    fn to_win_result(self) -> std::result::Result<Self, WinError>;
}

impl ToWinResult for i32 {
    fn to_win_result(self) -> std::result::Result<Self, WinError> {
        if self < 0 {
            Err(crate::error::WinError(self))
        } else {
            Ok(self)
        }
    }
}
