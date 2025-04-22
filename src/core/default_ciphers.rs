use magma::utils;

use super::{GeneralCipher, GeneralCipherError};
use crate::core::cipher::magma::magma::*;
use crate::core::cipher::*;
use crate::core::ecc::*;
use crate::core::ecc::hamming_7_4::*;

/// MagmaHamming uses *Hamming(7,4)* and *Magma*
pub struct MagmaHamming {
    crypto: Magma,
    error_correction: Hamming74
}

impl Default for MagmaHamming {
    fn default() -> Self {
        Self {
            crypto: MagmaBuilder::default().build(),
            error_correction: Hamming74
        }
    }
}

impl Cipher for MagmaHamming {
    type Input = u64;
    type Output = u64;

    fn encrypt(&self, data: Self::Input) -> Result<Self::Output, CipherError> {
        self.crypto.encrypt(data)
    }

    fn decrypt(&self, data: Self::Output) -> Result<Self::Input, CipherError> {
        self.crypto.decrypt(data)
    }
}

impl ErrorCorrectionCode for MagmaHamming {
    type Input = u8;
    type Output = u8;

    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError> {
        self.error_correction.encode(data)
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, EccError> {
        self.error_correction.decode(data)
    }
}

impl GeneralCipher for MagmaHamming {
    type Input = u64;
    type Output = [u8; 16];  // 8 байт × 2 кода

    fn general_encrypt(&self, data: u64) -> Result<[u8; 16], GeneralCipherError> {
        let ciphered = self.crypto
            .encrypt(data)
            .map_err(|_| GeneralCipherError::CipherEncryptError)?;
        let bytes = ciphered.to_be_bytes();
        let mut buf = [0u8; 16];

        for (i, &byte) in bytes.iter().enumerate() {
            let hi = (byte >> 4) & 0x0F;
            let lo = byte & 0x0F;
            buf[i * 2]     = self.error_correction.encode(hi)
                                 .map_err(|_| GeneralCipherError::ECCEncodeError)?;
            buf[i * 2 + 1] = self.error_correction.encode(lo)
                                 .map_err(|_| GeneralCipherError::ECCEncodeError)?;
        }

        Ok(buf)
    }

    fn general_decrypt(&self, data: [u8; 16]) -> Result<u64, GeneralCipherError> {
        let mut bytes = [0u8; 8];

        for i in 0..8 {
            let hi = self.error_correction.decode(data[i * 2])
                          .map_err(|_| GeneralCipherError::ECCDecodeError)?;
            let lo = self.error_correction.decode(data[i * 2 + 1])
                          .map_err(|_| GeneralCipherError::ECCDecodeError)?;
            bytes[i] = (hi << 4) | lo;
        }

        let value = u64::from_be_bytes(bytes);
        self.crypto.decrypt(value)
            .map_err(|_| GeneralCipherError::CipherDecryptError)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_without_errors() {
        let cipher = MagmaHamming::default();
        let samples = [
            0x0000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0123_4567_89AB_CDEF,
            0xDEAD_BEEF_DEAD_BEEF,
        ];

        for &plain in &samples {
            let serialized = cipher.general_encrypt(plain)
                .expect("serialize failed");
            let recovered = cipher.general_decrypt(serialized)
                .expect("deserialize failed");
            assert_eq!(
                recovered, plain,
                "MagmaHamming round‑trip mismatch: {:016X} → … → {:016X}",
                plain, recovered
            );
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = MagmaHamming::default();

        let inputs = [
            0x0000000000000000,
            0xFFFFFFFFFFFFFFFF,
            0x0123456789ABCDEF,
            0xDEADBEEFDEADBEEF,
        ];

        for &input in &inputs {
            let encrypted = cipher.encrypt(input).expect("encryption failed");
            let decrypted = cipher.decrypt(encrypted).expect("decryption failed");

            assert_eq!(
                decrypted, input,
                "Mismatch after decrypt: input = {:#018x}, got {:#018x}",
                input, decrypted
            );
        }
    }

    #[test]
    fn test_single_bit_error_correctable() {
        let cipher = MagmaHamming::default();
        let input: u64 = 0xAABBCCDDEEFF0011;

        let mut encrypted = cipher.general_encrypt(input).expect("encryption failed");

        // Инвертируем один бит в каждом байте по очереди
        for byte_idx in 0..encrypted.len() {
            for bit_idx in 0..7 {
                let mut corrupted = encrypted;
                corrupted[byte_idx] ^= 1 << bit_idx;

                let result = cipher.general_decrypt(corrupted);
                assert!(
                    result.is_ok(),
                    "Decryption failed with 1-bit error at byte {} bit {}",
                    byte_idx,
                    bit_idx
                );
                assert_eq!(
                    result.unwrap(),
                    input,
                    "Decryption incorrect with 1-bit error at byte {} bit {}",
                    byte_idx,
                    bit_idx
                );
            }
        }
    }

    #[test]
    fn test_double_bit_error_unrecoverable() {
        let cipher = MagmaHamming::default();
        let input: u64 = 0xCAFEBABECAFEBABE;

        let encrypted = cipher.general_encrypt(input).expect("encryption failed");

        // Повреждаем один байт в двух битах — декодировать неправильно или с ошибкой
        for bit1 in 0..6 {
            for bit2 in (bit1 + 1)..7 {
                let mut corrupted = encrypted;
                corrupted[0] ^= (1 << bit1) | (1 << bit2);

                let result = cipher.general_decrypt(corrupted);
                if let Ok(output) = result {
                    assert_ne!(output, input, "Double bit error not detected");
                }
            }
        }
    }
}
