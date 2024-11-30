//! Utility functions

/// Returns splitted into `(u32, u32)` result
/// 
/// # Argument 
/// 
/// * v - as `u64` value
#[inline]
pub fn u64_split(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v  as u32)
} 

/// Returns splitted int `[u16; 4]` result
#[inline]
pub fn u64_split_to_u16_array(input: u64) -> [u16; 4] {
    [
        (input >> 48) as u16,
        (input >> 32 & 0xFFFF) as u16,
        (input >> 16 & 0xFFFF) as u16,
        (input & 0xFFFF) as u16,
    ]
}

/// Returns joined `u64` result
#[inline]
pub fn u16_join_to_u64(parts: [u16; 4]) -> u64 {
    ((parts[0] as u64) << 48)
        | ((parts[1] as u64) << 32)
        | ((parts[2] as u64) << 16)
        | (parts[3] as u64)
}

/// Returns joined 'u64' result
/// 
/// # Argument 
/// 
/// * a - `u32` value to join 
/// * b - `u32` value to join
#[inline]
pub fn u32_join(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
} 


