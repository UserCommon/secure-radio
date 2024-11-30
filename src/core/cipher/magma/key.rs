// Round keys
pub enum Key {
    U8([u8;32]),
    U32([u32; 8])
}

impl From<[u8; 32]> for Key {
    fn from(value: [u8; 32]) -> Self {
        Self::U8(value)
    }
}

impl From<[u32; 8]> for Key {
    fn from(value: [u32; 8]) -> Self {
        Self::U32(value)
    }
}
