use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper around a `Box<[u8]>` that automatically zeroizes the memory when dropped.
///
/// This struct is intended to hold sensitive data that needs to be stored on the heap.
/// The `Box<[u8]>` ensures that the data is not accidentally copied, and `ZeroizeOnDrop`
/// ensures that the memory is cleared when the struct goes out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBox(Box<[u8]>);

impl SecretBox {
    /// Creates a new `SecretBox` from a `Vec<u8>`.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data.into_boxed_slice())
    }

    /// Returns a reference to the inner slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the inner slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecretBox {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for SecretBox {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_box_creation() {
        let data = vec![1, 2, 3, 4];
        let secret = SecretBox::new(data.clone());
        assert_eq!(secret.as_slice(), &data[..]);
    }

    #[test]
    fn test_secret_box_modification() {
        let data = vec![1, 2, 3, 4];
        let mut secret = SecretBox::new(data.clone());
        secret.as_mut_slice()[0] = 99;
        assert_eq!(secret.as_slice(), &[99, 2, 3, 4]);
    }

    #[test]
    fn test_secret_box_from_vec() {
        let data = vec![10, 11, 12];
        let secret: SecretBox = data.clone().into();
        assert_eq!(secret.as_slice(), &data[..]);
    }

    #[test]
    fn test_secret_box_as_ref() {
        let data = vec![20, 21, 22];
        let secret = SecretBox::new(data.clone());
        let slice: &[u8] = secret.as_ref();
        assert_eq!(slice, &data[..]);
    }
}
