use memmap2::MmapMut;
use std::ffi::CString;
use std::fs::File;
use std::io::{Error as IoError, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use zeroize::ZeroizeOnDrop;

// From <linux/memfd.h>
const MFD_CLOEXEC: u32 = 0x0001;
const MFD_SECRET: u32 = 0x0008;

/// The Owner of the Backing Store (The "Box")
#[derive(ZeroizeOnDrop)]
pub struct Vault {
    mmap: MmapMut,
}

impl Vault {
    pub fn new(name: &str, data: &[u8]) -> Result<Self, IoError> {
        let name_cstr = CString::new(name)
            .map_err(|_| IoError::new(std::io::ErrorKind::InvalidInput, "Invalid name"))?;
        let fd = unsafe {
            libc::syscall(libc::SYS_memfd_create, name_cstr.as_ptr(), MFD_CLOEXEC | MFD_SECRET)
        };

        if fd < 0 {
            return Err(IoError::last_os_error());
        }
        let fd = fd as RawFd;

        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(data)?;
        if unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(IoError::last_os_error());
        }
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        Ok(Vault { mmap })
    }

    /// Returns a slice referencing the secret key material in the mmap'd
    /// region.
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_vault_loan() {
        let data = [1, 2, 3, 4];
        let sv = Vault::new("test_read_write", &data).unwrap();
        assert_eq!(sv.as_bytes(), &data);
    }

    #[test]
    fn test_secret_vault_invalid_name() {
        let data = [1, 2, 3, 4];
        let result = Vault::new("invalid\0name", &data);
        assert!(result.is_err());
    }
}