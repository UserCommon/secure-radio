use crate::core::magma::consts::*;
use crate::core::magma::*;

pub struct CipherBuilder {
    pub (crate) key: Option<[u32; 8]>,
    pub (crate) round_keys: Option<[u32; 32]>,
    pub (crate) sbox: Option<[u8; 128]>
}

impl CipherBuilder {
    pub fn new() -> Self {
        Self { key: None, round_keys: None, sbox: None}
    }

    pub fn set_key(&mut self, key: [u32; 8]) -> &mut Self {
        self.key = Some(key);
        self
    }

    pub fn set_round_keys(&mut self, round_keys: [u32; 32]) -> &mut Self {
        self.round_keys = Some(round_keys);
        self
    }

    pub fn set_sbox(&mut self, sbox: [u8; 128]) -> &mut Self {
        self.sbox = Some(sbox);
        self
    }

    pub fn build(&mut self) -> Cipher {
        self.into()
    }
}

impl Default for CipherBuilder {
    fn default() -> Self {
        Self {
            key: Some([0u32; 8]),
            round_keys: Some([0u32; 32]),
            sbox: Some(SBOX.clone())
        }
    }
}

impl From<&mut CipherBuilder> for Cipher {
    fn from(value: &mut CipherBuilder) -> Self {
        if let &mut CipherBuilder { 
            key: Some(k),
            round_keys: Some(rk),
            sbox: Some(sbox)
        } = value {
            Cipher::new(k, rk, sbox)
        } else {
            loop {}
        }
    }
}


pub struct Cipher {
    pub (crate) key: [u32; 8],
    pub (crate) round_keys: [u32; 32],
    pub (crate) sbox: [u8; 128]
}

impl Cipher {
    // Constructs cipher
    pub fn new(key: [u32; 8], round_keys: [u32; 32], sbox: [u8; 128]) -> Self {
        let mut me = Self {
            key,
            round_keys,
            sbox
        };

        me.prepare_round_keys();
        me

    }

    /// Returns [encrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.1) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a plaintext value as `u64`
    #[inline]
    pub fn encrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut a_1, mut a_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 0;
        while round < 32 {
            (a_1, a_0) = self.transformation_big_g(self.round_keys[round], a_1, a_0);
            round += 1;
        }

        // join u32 parts into u64 block
        utils::u32_join(a_0, a_1)
    }

    /// Returns [decrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.2) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a ciphertext value as `u64`
    #[inline]
    pub fn decrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut b_1, mut b_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 32;
        while round != 0 {
            round -= 1;
            (b_1, b_0) = self.transformation_big_g(self.round_keys[round], b_1, b_0);
        }

        // join u32 parts into u64 block
        utils::u32_join(b_0, b_1)
    }

    pub(crate) fn set_key_u32(&mut self, key: &[u32; 8]) {
        self.key.clone_from(key);
        self.prepare_round_keys();
    }

    pub(crate) fn set_key_u8(&mut self, bytes: &[u8]) {
        self.set_key_u32(&Self::key_from_u8(bytes));
    }

    pub (crate) fn set_substitution_box(&mut self, substitution_box: &[u8; 128]) {
        self.sbox.copy_from_slice(substitution_box);
    }

    fn prepare_round_keys(&mut self) {
        const ROUND_KEY_POSITION: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3,
            2, 1, 0,
        ];

        for index in 0..32 {
            let round_key_position = ROUND_KEY_POSITION[index] as usize;
            self.round_keys[index] = self.key[round_key_position];
        }
    }

    fn key_from_u8(bytes: &[u8]) -> [u32;8] {
        assert!(bytes.len() == 32);
        let mut key = [0_u32;8];
        let mut array_u8 = [0u8; 4];
        for (index, chunk) in bytes.chunks(4).enumerate() {
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            key[index] = u32::from_be_bytes(array_u8);
        }
        key 
    }


    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `t: V_32 -> V_32`
    #[inline]
    fn transformation_t(&self, a: u32) -> u32 {
        let mut res: u32 = 0;
        let mut shift_count = 0;
        for i in 0..8 {
            let v = (a >> shift_count) & 0xF;
            let s = self.sbox[(i * 16 + v) as usize] as u32;
            res |= s << shift_count;
            shift_count += 4;
        }
        res
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `g[k]: V_32 -> V_32`
    #[inline]
    fn transformation_g(&self, k: u32, a: u32) -> u32 {
        let res = self.transformation_t(((k as u64) + (a as u64)) as u32);
        res.rotate_left(11)
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `G[k]: V_32[*]V_32 -> V_32[*]V_32`
    #[inline]
    fn transformation_big_g(&self, k: u32, a_1: u32, a_0: u32) -> (u32, u32) {
        (a_0, self.transformation_g(k, a_0) ^ a_1)
    }

}


 #[cfg(test)]
mod magma_test {
    use super::*;

    #[test]
    fn initialization() {
        let mut magma = CipherBuilder::new()
            .set_key([0u32;8])
            .set_round_keys([0u32; 32])
            .set_sbox(SBOX)
            .build();

        assert_eq!(magma.key, [0u32;8]);
        assert_eq!(magma.round_keys, [0u32;32]);
        assert_eq!(magma.sbox, SBOX);
    } 

    #[test]
    fn encrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-encryption
        use crate::test_purpose;
        let mut magma = CipherBuilder::default()
            .set_key(test_purpose::CIPHER_KEY)
            .build();

        assert_eq!(magma.encrypt(test_purpose::PLAINTEXT), test_purpose::CIPHERTEXT);
    }

    #[test]
    fn decrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-decryption

        use crate::test_purpose::{CIPHER_KEY, PLAINTEXT, CIPHERTEXT};
        let mut magma = CipherBuilder::default()
            .set_key(CIPHER_KEY)
            .build();

        assert_eq!(magma.decrypt(CIPHERTEXT), PLAINTEXT);
    }

    #[test]
    fn correctness() {
        let mut magma = CipherBuilder::default().build();
        assert_eq!(magma.decrypt(magma.encrypt(123u64)), 123u64);
    }
}
