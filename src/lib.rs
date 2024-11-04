#![no_std]
#![allow(dead_code)]

const S_BOX: [[u8; 16]; 8] = [
    [
        0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1,
    ],
    [
        0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF,
    ],
    [
        0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x00,
    ],
    [
        0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB,
    ],
    [
        0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC,
    ],
    [
        0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0,
    ],
    [
        0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7,
    ],
    [
        0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2,
    ],
];

const fn lshift_nbit(x: u64, l: u32, n: u32) -> u64 {
    let shift_left = x << l;
    let shift_right = x >> (n - l) % n;
    let mask = (1u64 << n) - 1;
    (shift_left | shift_right) & mask
}

const fn lshift_nbit_u32(x: u32, l: u32, n: u32) -> u32 {
    let shift_left = x << l;
    let shift_right = x >> ((n - l) & (n - 1));
    let mask = (1u32 << n) - 1;
    (shift_left | shift_right) & mask
}

/// Key data-type implementation using u32
pub struct Key {
    data: [u32; 8],
}

impl Key {
    pub fn new(data: [u32; 8]) -> Self {
        Self { data }
    }

    pub fn get(&self, i: usize) -> u32 {
        self.data[i]
    }
}

/// Encrypt or Decrypt sum-type
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Magma cipher structure with certain methods!
pub struct Magma {
    key: Key,
}

impl Magma {
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    pub fn encrypt(&self) {}

    fn feistel_cipher_encrypt(&self, block: &mut [u32; 2]) {
        // k0 - k7 x3
        for round in 0..24 {
            Self::feistel_round(&self, block, round);
        }

        // k7 - k0
        for round in (24..32).rev() {
            Self::feistel_round(&self, block, round);
        }
    }

    fn feistel_cipher_decrypt(&self, block: &mut [u32; 2]) {
        // k7 - k0
        for round in 0..8 {
            Self::feistel_round(&self, block, round);
        }

        // k0 - k7 x3
        for round in (8..32).rev() {
            Self::feistel_round(&self, block, round);
        }
    }

    fn feistel_round(&self, block: &mut [u32; 2], round: u8) {
        // RES = (N1 + Ki) mod 2^32
        let mut iter_res = (block[0] + self.key.get((round % 8) as usize)) % u32::MAX;
        iter_res = Self::s_table(iter_res, round % 8);
        iter_res = lshift_nbit_u32(iter_res, 11, 32);

        let tmp = block[1];
        block[1] = iter_res ^ block[2];
        block[2] = tmp;
    }

    fn s_table(b32: u32, row: u8) -> u32 {
        let mut u8s = Self::u32_to_u8(b32);
        Self::s_table_by_4bits(&mut u8s, row);
        Self::u4_to_u32(&u8s)
    }

    fn s_table_by_4bits(b4: &mut [u8; 4], row: u8) {
        let (mut b4_1, mut b4_2) = (0, 0);
        for i in 0..4 {
            b4_1 = S_BOX[row as usize][(b4[i] & 0x0F) as usize];
            b4_2 = S_BOX[row as usize][(b4[i] >> 4) as usize];

            b4[i] = b4_2;
            b4[i] = (b4[i] << 4) | b4_1;
        }
    }

    fn u32_to_u8(block: u32) -> [u8; 4] {
        // blocks8b[0] = (uint8_t)10111101000101010100101110100010 >> (28 - (0 * 8)) =
        // = (uint8_t)10101010101010101010101010101010 >> 28 =
        // = (uint8_t)00000000000000000000000010111101
        // = 10111101
        let mut buf = [0; 4];
        for i in 0..4 {
            buf[i] = (block >> (24 - (i * 8))) as u8;
        }
        buf
    }

    fn u8_to_u32(blocks: &[u8; 4]) -> u32 {
        let mut res: u32 = 0;
        for i in 0..4 {
            res = (res << 8) | blocks[i] as u32;
        }
        res
    }

    fn u32_to_u64(blocks: &[u32; 2]) -> u64 {
        let mut res: u64 = 0;
        res = blocks[1] as u64;
        res = (res << 32) | blocks[0] as u64;
        res
    }

    fn u64_to_u8(block: u64) -> [u8; 8] {
        let mut buf = [0; 8];
        for i in 0..8 {
            buf[i] = (block >> ((7 - i) * 8)) as u8;
        }
        buf
    }

    fn u64_to_u32(block: u64) -> [u32; 2] {
        let mut buf = [0; 2];
        buf[1] = block as u32;
        buf[0] = (block >> 32) as u32;
        buf
    }

    fn u8_to_u64(blocks: &[u8; 8]) -> u64 {
        let mut res: u64 = 0;
        for i in 0..8 {
            res = (res << 8) | blocks[i] as u64;
        }
        res
    }

    fn u4_to_u32(blocks: &[u8; 4]) -> u32 {
        let mut b32: u32 = 0;
        for i in 0..4 {
            b32 = (b32 << 8) | blocks[i] as u32;
        }
        b32
    }
}
