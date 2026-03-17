pub mod keymanager {
    include!(concat!(env!("OUT_DIR"), "/keymanager.rs"));
}
pub use keymanager as algorithms;
pub use keymanager as proto;

pub use proto::Error;

impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Helper function to safely execute an FFI closure, catch panics, and return a standardized Error.
pub fn ffi_call<F>(f: F) -> Error
where
    F: FnOnce() -> Result<(), Error>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(Err(Error::Internal))
        .err()
        .unwrap_or(Error::Success)
}

/// Helper function for FFI calls returning i32 (positive for count/success, negative for Error).
pub fn ffi_call_i32<F>(f: F) -> i32
where
    F: FnOnce() -> Result<i32, Error>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(Err(Error::Internal))
        .unwrap_or_else(|e| -(e as i32))
}

pub mod crypto;
pub mod key_types;
pub mod protected_mem;
