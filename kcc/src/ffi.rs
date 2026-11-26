//! CGO interface for the key manager

use crate::KeyManager;
use once_cell::sync::Lazy;
use std::slice;
use uuid::Uuid;


static MANAGER: Lazy<KeyManager> = Lazy::new(KeyManager::new);

// /// A C-compatible representation of a byte buffer allocated by Rust.
// #[repr(C)]
// #[derive(Debug)]
// pub struct ByteBuffer {
//     ptr: *mut u8,
//     len: usize,
//     cap: usize,
// }

// impl ByteBuffer {
//     fn null() -> Self {
//         ByteBuffer { ptr: std::ptr::null_mut(), len: 0, cap: 0 }
//     }
// }

// impl From<Vec<u8>> for ByteBuffer {
//     fn from(mut v: Vec<u8>) -> Self {
//         v.shrink_to_fit();
//         let (ptr, len, cap) = v.into_raw_parts();
//         ByteBuffer { ptr, len, cap }
//     }
// }

// /// Frees a ByteBuffer that was allocated by Rust.
// #[unsafe(no_mangle)]
// pub extern "C" fn key_manager_free_byte_buffer(buf: ByteBuffer) {
//     if !buf.ptr.is_null() {
//         unsafe {
//             Vec::from_raw_parts(buf.ptr, buf.len, buf.cap);
//         }
//     }
// }

/// Generates a new Binding keypair.
///
/// # Arguments
/// * `key_handle_out` - Pointer to a 16-byte buffer to receive the key handle.
///
/// # Returns
/// 0 on success, -1 on failure.
///
/// # Safety
/// Assumes `key_handle_out` is a valid pointer to 16 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_binding_keypair(key_handle_out: *mut u8) -> i32 {
    let (handle, _) = MANAGER.generate_binding_keypair();
    key_handle_out.copy_from_nonoverlapping(handle.as_bytes().as_ptr(), 16);
    0
}

/// Generates a new KEM keypair associated with a binding public key.
///
/// # Arguments
/// * `binding_pk_ptr` - Pointer to binding public key bytes.
/// * `binding_pk_len` - Length of binding public key.
/// * `key_handle_out` - Pointer to a 16-byte buffer to receive the KEM key handle.
///
/// # Returns
/// 0 on success, -1 on failure.
///
/// # Safety
/// Assumes `binding_pk_ptr` and `key_handle_out` are valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_kem_keypair(
    binding_pk_ptr: *const u8,
    binding_pk_len: usize,
    key_handle_out: *mut u8,
) -> i32 {
    let binding_pk = slice::from_raw_parts(binding_pk_ptr, binding_pk_len);
    let (handle, _) = MANAGER.generate_kem_keypair(binding_pk);
    key_handle_out.copy_from_nonoverlapping(handle.as_bytes().as_ptr(), 16);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice;

    // #[test]
    // fn test_byte_buffer_lifecycle() {
    //     let original_data = vec![1, 2, 3, 4, 5];
    //     let original_len = original_data.len();
        
    //     // Test From<Vec<u8>> for ByteBuffer
    //     let buffer = ByteBuffer::from(original_data);
    //     assert!(!buffer.ptr.is_null());
    //     assert_eq!(buffer.len, original_len);
        
    //     // Verify data integrity via slice reconstruction
    //     unsafe {
    //         let reconstructed_slice = slice::from_raw_parts(buffer.ptr, buffer.len);
    //         assert_eq!(reconstructed_slice, &[1, 2, 3, 4, 5]);
    //     }

    //     // Test Freeing (Ensure no double-free or leaks)
    //     key_manager_free_byte_buffer(buffer);
    // }

    // #[test]
    // fn test_byte_buffer_null() {
    //     let buffer = ByteBuffer::null();
    //     assert!(buffer.ptr.is_null());
    //     assert_eq!(buffer.len, 0);
        
    //     // Freeing a null buffer should be a no-op and not crash
    //     key_manager_free_byte_buffer(buffer);
    // }

    #[test]
    fn test_ffi_generate_binding_keypair() {
        let mut handle_buffer = [0u8; 16];
        
        unsafe {
            let result = key_manager_generate_binding_keypair(handle_buffer.as_mut_ptr());
            assert_eq!(result, 0);
        }

        // Verify we actually received a non-zero UUID handle
        assert_ne!(handle_buffer, [0u8; 16]);
        
        // Verify it can be parsed back into a Uuid
        let handle = Uuid::from_bytes(handle_buffer);
        assert!(!handle.is_nil());
    }

    #[test]
    fn test_ffi_generate_kem_keypair() {
        // 1. We need a dummy binding PK (e.g., 32 bytes for X25519)
        let binding_pk = vec![0u8; 32];
        let mut handle_buffer = [0u8; 16];

        unsafe {
            let result = key_manager_generate_kem_keypair(
                binding_pk.as_ptr(),
                binding_pk.len(),
                handle_buffer.as_mut_ptr(),
            );
            assert_eq!(result, 0);
        }

        // Verify handle received
        assert_ne!(handle_buffer, [0u8; 16]);
        let handle = Uuid::from_bytes(handle_buffer);
        assert!(!handle.is_nil());
    }
}