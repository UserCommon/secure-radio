/// Key is a structure which is used in 
/// Feistel Cipher
pub struct Key([u32; 8]);

impl From<[u32; 8]> for Key {
    fn from(value: [u32; 8]) -> Self {
        Self(value) 
    }
}

