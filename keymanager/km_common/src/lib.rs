pub mod keymanager;
pub use keymanager as proto;

pub use proto::Status;

pub const MAX_ALGORITHM_LEN: usize = 128;
pub const MAX_PUBLIC_KEY_LEN: usize = 2048;

impl std::error::Error for Status {}
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Helper function to safely execute an FFI closure, catch panics, and return a standardized Status.
pub fn ffi_call<F>(f: F) -> Status
where
    F: FnOnce() -> Result<(), Status>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => Status::Success,
        Ok(Err(s)) => s,
        Err(_) => Status::InternalError,
    }
}

/// Helper function for FFI calls returning i32 (positive for count/success, negative for Status).
pub fn ffi_call_i32<F>(f: F) -> i32
where
    F: FnOnce() -> Result<i32, Status>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(val)) => val,
        Ok(Err(s)) => -(s as i32),
        Err(_) => -(Status::InternalError as i32),
    }
}

pub mod crypto;
pub mod key_types;
pub mod protected_mem;
