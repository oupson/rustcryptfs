use std::ffi::c_void;

use windows_sys::{
    core::GUID,
    Win32::Storage::ProjectedFileSystem::{
        PrjAllocateAlignedBuffer, PrjFreeAlignedBuffer, PrjGetVirtualizationInstanceInfo,
        PrjWriteFileData, PRJ_VIRTUALIZATION_INSTANCE_INFO,
    },
};

pub(crate) struct WriteBuffer {
    buffer_size: usize,
    namespace_virtualization_context: isize,
    data_stream_id: GUID,
    prjfs_buf: *mut c_void,
    file_offset: u64,
    offset: usize,
}

impl WriteBuffer {
    pub(crate) fn new(
        namespace_virtualization_context: isize,
        data_stream_id: GUID,
        file_offset: u64,
    ) -> Self {
        let (size, buf) = unsafe {
            let mut info: PRJ_VIRTUALIZATION_INSTANCE_INFO = std::mem::zeroed();
            PrjGetVirtualizationInstanceInfo(namespace_virtualization_context, &mut info);

            let size = (info.WriteAlignment * 100) as usize;
            (
                size,
                PrjAllocateAlignedBuffer(namespace_virtualization_context, size),
            )
        };

        Self {
            buffer_size: size,
            namespace_virtualization_context,
            data_stream_id,
            prjfs_buf: buf,
            file_offset,
            offset: 0,
        }
    }

    pub(crate) fn append_buf(&mut self, buf: &[u8]) -> usize {
        let mut remaining_buf = buf;
        let mut written = 0;

        while !remaining_buf.is_empty() {
            let to_copy = (self.buffer_size - self.offset).min(remaining_buf.len());

            unsafe {
                (self.prjfs_buf as *mut u8)
                    .offset(self.offset as isize)
                    .copy_from(remaining_buf.as_ptr(), to_copy);
            }

            self.offset += to_copy;

            if self.offset == self.buffer_size {
                unsafe {
                    PrjWriteFileData(
                        self.namespace_virtualization_context,
                        &self.data_stream_id,
                        self.prjfs_buf,
                        self.file_offset,
                        self.buffer_size as u32,
                    )
                };

                self.file_offset += self.buffer_size as u64;
                self.offset = 0;
                written += self.buffer_size;
            };

            remaining_buf = &remaining_buf[to_copy..];
        }
        written
    }

    pub(crate) fn finish(&mut self) -> usize {
        let written = self.offset;
        unsafe {
            PrjWriteFileData(
                self.namespace_virtualization_context,
                &self.data_stream_id,
                self.prjfs_buf,
                self.file_offset,
                self.offset as u32,
            )
        };
        self.file_offset += self.offset as u64;
        self.offset = 0;
        written
    }
}

impl Drop for WriteBuffer {
    fn drop(&mut self) {
        unsafe { PrjFreeAlignedBuffer(self.prjfs_buf) };
        self.prjfs_buf = std::ptr::null_mut();
    }
}
