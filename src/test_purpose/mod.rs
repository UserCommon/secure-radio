//! Test vectors for [Block Cipher Modes, GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)  
//! 
//! * **ECB** - Electronic Codebook Mode
//! * **CTR** - Counter Encryption Mode
//! * **OFB** - Output Feedback Mode
//! * **CBC** - Cipher Block Chaining Mode
//! * **CFB** - Cipher Feedback Mode
//! * **MAC** - Message Authentication Code Generation Mode

/// Cipher Key, Page 35, Section: A.2
pub const CIPHER_KEY: [u32; 8] = [
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
];

/// Plaintext1, Page 35, Section: A.2
pub const PLAINTEXT1: u64 = 0x92def06b3c130a59_u64;
/// Plaintext2, Page 35, Section: A.2
pub const PLAINTEXT2: u64 = 0xdb54c704f8189d20_u64;
/// Plaintext3, Page 35, Section: A.2
pub const PLAINTEXT3: u64 = 0x4a98fb2e67a8024c_u64;
/// Plaintext4, Page 35, Section: A.2
pub const PLAINTEXT4: u64 = 0x8912409b17b57e41_u64;



/// [Section A.1. Transformation t](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.1)
pub const TRANSFORMATION_T: [(u32, u32); 4] = [
    (0xfdb97531, 0x2a196f34),
    (0x2a196f34, 0xebd9f03a),
    (0xebd9f03a, 0xb039bb3d),
    (0xb039bb3d, 0x68695433),
];

/// [Section A.2. Transformation g](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.2)
pub const TRANSFORMATION_G: [((u32, u32), u32); 4] = [
    ((0x87654321, 0xfedcba98), 0xfdcbc20c),
    ((0xfdcbc20c, 0x87654321), 0x7e791a4b),
    ((0x7e791a4b, 0xfdcbc20c), 0xc76549ec),
    ((0xc76549ec, 0x7e791a4b), 0x9791c849),
];

/// [Section A.3. Key Schedule](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.3)
pub const CIPHER_KEY_U8_ARRAY: [u8; 32] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// [Section A.3. Key Schedule](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.3)
pub const ROUND_KEYS: [u32; 32] = [
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
    0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3, 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
];

/// [Section A.4. Test Encryption](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.4)
pub const TRANSFORMATION_BIG_G: [(u32, u32); 32] = [
    (0x76543210, 0x28da3b14),
    (0x28da3b14, 0xb14337a5),
    (0xb14337a5, 0x633a7c68),
    (0x633a7c68, 0xea89c02c),
    (0xea89c02c, 0x11fe726d),
    (0x11fe726d, 0xad0310a4),
    (0xad0310a4, 0x37d97f25),
    (0x37d97f25, 0x46324615),
    (0x46324615, 0xce995f2a),
    (0xce995f2a, 0x93c1f449),
    (0x93c1f449, 0x4811c7ad),
    (0x4811c7ad, 0xc4b3edca),
    (0xc4b3edca, 0x44ca5ce1),
    (0x44ca5ce1, 0xfef51b68),
    (0xfef51b68, 0x2098cd86),
    (0x2098cd86, 0x4f15b0bb),
    (0x4f15b0bb, 0xe32805bc),
    (0xe32805bc, 0xe7116722),
    (0xe7116722, 0x89cadf21),
    (0x89cadf21, 0xbac8444d),
    (0xbac8444d, 0x11263a21),
    (0x11263a21, 0x625434c3),
    (0x625434c3, 0x8025c0a5),
    (0x8025c0a5, 0xb0d66514),
    (0xb0d66514, 0x47b1d5f4),
    (0x47b1d5f4, 0xc78e6d50),
    (0xc78e6d50, 0x80251e99),
    (0x80251e99, 0x2b96eca6),
    (0x2b96eca6, 0x05ef4401),
    (0x05ef4401, 0x239a4577),
    (0x239a4577, 0xc2d8ca3d),
    (0xc2d8ca3d, 0x4ee901e5),
];

/// [Section A.4. Test Encryption](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.4)
pub const PLAINTEXT: u64 = 0xfedcba9876543210_u64;

/// [Section A.4. Test Encryption](https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.4)
pub const CIPHERTEXT: u64 = 0x4ee901e5c2d8ca3d_u64;


