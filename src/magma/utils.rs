//! Utility functions
#[inline]
pub fn u64_split(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v  as u32)
} 

#[inline]
pub fn u32_join(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
} 

