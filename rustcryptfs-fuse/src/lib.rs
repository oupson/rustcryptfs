#[cfg(target_os = "linux")]
mod encrypted_filesystem;
#[cfg(target_os = "linux")]
mod inode_cache;

#[cfg(target_os = "linux")]
pub mod error;

#[cfg(target_os = "linux")]
pub use encrypted_filesystem::EncryptedFs;
