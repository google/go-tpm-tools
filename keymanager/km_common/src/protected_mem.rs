//! Memory protection utilities using `memfd_secret`.
//!
//! This module provides the [`Vault`] struct, which uses the Linux-specific
//! `memfd_secret` system call to create a memory region that is invisible to
//! the kernel's page tables and most other processes, providing a secure
//! location for sensitive cryptographic material.

use memmap2::MmapMut;
use std::fs::File;
use std::io::{Error as IoError, Result as IoResult};
use std::os::unix::io::{FromRawFd, RawFd};
use zeroize::Zeroize;

/// The system call number for `memfd_secret` on x86_64.
const SYS_MEMFD_SECRET: i64 = 447;

/// A secure container for sensitive data backed by `memfd_secret`.
///
/// `Vault` uses a secret memory file descriptor that is not visible in the
/// filesystem and whose memory is unmapped from the kernel page tables.
/// The memory is automatically zeroed when the `Vault` is dropped.
#[derive(Debug)]
pub struct Vault {
    mmap: MmapMut,
    #[cfg(test)]
    file: File,
}

#[cfg(test)]
impl std::os::unix::io::AsRawFd for Vault {
    fn as_raw_fd(&self) -> RawFd {
        std::os::unix::io::AsRawFd::as_raw_fd(&self.file)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.mmap[..].zeroize();
    }
}

impl Vault {
    /// Creates a new `Vault` containing the provided data.
    ///
    /// # Errors
    ///
    /// Returns an error if the `memfd_secret` syscall fails or if the memory
    /// cannot be mapped.
    pub fn new(data: &[u8]) -> IoResult<Self> {
        // Create the secret memory file descriptor.
        // O_CLOEXEC ensures the FD is closed on exec.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, libc::O_CLOEXEC as libc::c_long) };

        if fd < 0 {
            return Err(IoError::last_os_error());
        }
        let fd = fd as RawFd;

        // Wrap the raw FD in a File object to manage its lifetime.
        // Safety: We just created this FD and verified it is valid.
        let file = unsafe { File::from_raw_fd(fd) };

        // Set the size of the secret memory region.
        file.set_len(data.len() as u64)?;

        // Map the secret memory region into the process's address space.
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };

        // Copy the sensitive data into the secure region.
        if !data.is_empty() {
            mmap.copy_from_slice(data);
        }

        Ok(Vault {
            mmap,
            #[cfg(test)]
            file,
        })
    }

    /// Returns a slice referencing the secret key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }
}

impl AsRef<[u8]> for Vault {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_vault_creation_and_retrieval() {
        let data = b"sensitive information";
        let vault = Vault::new(data).expect("Failed to create vault");
        assert_eq!(vault.as_bytes(), data);
        assert_eq!(vault.as_ref(), data);
    }

    #[test]
    fn test_vault_with_empty_data() {
        let vault = Vault::new(&[]).expect("Failed to create empty vault");
        assert!(vault.as_bytes().is_empty());
    }

    #[test]
    fn test_multiple_vaults() {
        let v1 = Vault::new(b"secret1").unwrap();
        let v2 = Vault::new(b"secret2").unwrap();
        assert_ne!(v1.as_bytes(), v2.as_bytes());
        assert_eq!(v1.as_bytes(), b"secret1");
        assert_eq!(v2.as_bytes(), b"secret2");
    }

    #[test]
    fn test_large_vault() {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        let vault = Vault::new(&data).expect("Failed to create large vault");
        assert_eq!(vault.as_bytes().len(), data.len());
    }

    #[test]
    fn test_memfd_backing_verification() {
        let data = b"verification data";
        let vault = Vault::new(data).unwrap();
        let fd = vault.as_raw_fd();

        // 1. Verify filesystem magic number using fstatfs
        let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstatfs(fd, &mut statfs) };
        assert_eq!(ret, 0, "fstatfs failed");
        
        // SECRETMEM_MAGIC is 0x5345434d ("SECM")
        const SECRETMEM_MAGIC: libc::c_long = 0x5345434d;
        assert_eq!(
            statfs.f_type, SECRETMEM_MAGIC,
            "Filesystem is not memfd_secret. Expected magic {:x}, got {:x}",
            SECRETMEM_MAGIC, statfs.f_type
        );

        // 2. Verify mapping in /proc/self/maps
        let ptr = vault.as_bytes().as_ptr() as usize;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut stat) };
        assert_eq!(ret, 0, "fstat failed");
        let expected_inode = stat.st_ino;

        let maps = std::fs::read_to_string("/proc/self/maps").expect("Failed to read /proc/self/maps");
        let found = maps.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 { return false; }

            let range: Vec<&str> = parts[0].split('-').collect();
            let start = usize::from_str_radix(range[0], 16).unwrap();
            let end = usize::from_str_radix(range[1], 16).unwrap();

            if ptr >= start && ptr < end {
                let inode = parts[4].parse::<u64>().unwrap_or(0);
                return inode == expected_inode && line.contains("/secretmem");
            }
            false
        });

        assert!(found, "Could not verify memfd_secret mapping in /proc/self/maps");
    }

    #[test]
    fn test_zeroize_on_drop() {
        let data = b"secret to be zeroed";
        let vault = Vault::new(data).unwrap();

        // Create a second mapping of the same memory to spy on it
        // This is possible because we have access to the underlying File in tests
        let spy = unsafe { MmapMut::map_mut(&vault.file).expect("Failed to create spy mapping") };

        // Verify spy sees the data
        assert_eq!(&spy[..], data);

        // Drop the vault, which should trigger zeroize
        drop(vault);

        // Verify the memory was zeroed
        assert!(spy.iter().all(|&b| b == 0), "Memory was not zeroed after drop");
    }
}
