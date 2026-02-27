pub mod algorithms {
    include!(concat!(env!("OUT_DIR"), "/algorithms.rs"));
}

pub mod crypto;
pub mod key_types;
pub mod protected_mem;
