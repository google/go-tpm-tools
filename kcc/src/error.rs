
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Key type mismatch")]
    KeyTypeMismatch,
    #[error("Key length mismatch")]
    KeyLenMismatch,
}