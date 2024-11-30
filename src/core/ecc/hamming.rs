use super::{ ErrorCorrectionCode, EccError };

pub struct HammingECC16;

impl ErrorCorrectionCode for HammingECC16 {
    type Input = u16;
    type Output = u32;

    /// Encode 16-bit to Hamming(21,16).
    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError> {
     let mut codeword: u32 = data as u32;

        // Вычисляем контрольные биты
        for i in 0..5 {
            let mask = (1 << i) - 1;
            let parity = ((codeword & mask).count_ones() % 2) as u32;
            codeword |= parity << (16 + i);
        }

        Ok(codeword)
    }

    /// Decode 21-bit(32-bit) from Hamming (21, 16)
    fn decode(&self, codeword: Self::Output) -> Result<Self::Input, EccError> {
        let mut error_pos = 0;
        for i in 0..5 {
            let mask = (1 << i) - 1;
            let parity = ((codeword & mask).count_ones() % 2) as u32;
            if parity != 0 {
                error_pos |= 1 << i;
            }
        }

        let error_corrected = error_pos != 0;
        let corrected_codeword = if error_corrected {
            codeword ^ (1 << (error_pos - 1))
        } else {
            codeword
        };

        if error_corrected {
            Err(EccError::FailedToDecode)
        } else {
            let data = (corrected_codeword & 0xFFFF) as u16;
            Ok(data)
        }
    }
}
    


/// CRC16
pub fn calculate_crc16(data: &[u8]) -> u16 {
    const POLY: u16 = 0x1021;
    let mut crc = 0xFFFF;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

#[cfg(test)]
mod hamming_tests {
    use super::*;

    struct HammingECC16;

    impl ErrorCorrectionCode for HammingECC16 {
        type Input = u16;
        type Output = u32;

        fn encode(data: Self::Input) -> Result<Self::Output, EccError> {
            let mut codeword: u32 = data as u32;

            // Вычисляем контрольные биты
            for i in 0..5 {
                let parity = ((codeword >> (16 + i + 1)).count_ones() + (codeword & ((1 << (16 + i)) - 1)).count_ones()) % 2;
                codeword |= (parity as u32) << (16 + i);
            }

            Ok(codeword)
        }

        fn decode(codeword: Self::Output) -> Result<Self::Input, EccError> {
            let mut error_pos = 0;

            // Проверяем контрольные биты
            for i in 0..5 {
                //tea shovel
                let parity = ((codeword >> (16 + i + 1)).count_ones() + (codeword & ((1 << (16 + i)) - 1)).count_ones()) % 2;
                if parity != 0 {
                    error_pos |= 1 << i;
                }
            }

            // Если ошибка найдена, пытаемся исправить
            let corrected_codeword = if error_pos > 0 && error_pos <= 21 {
                codeword ^ (1 << (error_pos - 1))
            } else {
                codeword
            };

            // Проверяем валидность исправленного кода
            let valid = (0..5).all(|i| {
                let parity = ((corrected_codeword >> (16 + i + 1)).count_ones() + (corrected_codeword & ((1 << (16 + i)) - 1)).count_ones()) % 2;
                parity == 0
            });

            if valid {
                let data = (corrected_codeword & 0xFFFF) as u16;
                Ok(data)
            } else {
                Err(EccError::FailedToDecode)
            }
        }
    }

    #[test]
    fn test_hamming_encode() {
        let data: u16 = 0b1010101010101010; // Пример данных
        let encoded = HammingECC16::encode(data).expect("Encoding failed");

        // Убедимся, что данные сохранены в младших 16 битах
        assert_eq!(encoded & 0xFFFF, data as u32, "Данные не совпадают");
    }

    #[test]
    fn test_hamming_decode_no_errors() {
        let data: u16 = 0b1010101010101010;
        let encoded = HammingECC16::encode(data).expect("Encoding failed");
        let decoded = HammingECC16::decode(encoded).expect("Decoding failed");

        assert_eq!(decoded, data, "Декодированные данные не совпадают");
    }

    #[test]
    fn test_hamming_decode_single_error() {
        let data: u16 = 0b1010101010101010;
        let mut encoded = HammingECC16::encode(data).expect("Encoding failed");

        // Инвертируем один бит
        encoded ^= 1 << 0;

        let decoded = HammingECC16::decode(encoded).expect("Decoding failed");

        assert_eq!(decoded, data, "Декодированные данные не совпадают после исправления");
    }

    #[test]
    fn test_hamming_decode_double_error() {
        let data: u16 = 0b1010101010101010;
        let mut encoded = HammingECC16::encode(data).expect("Encoding failed");

        // Инвертируем два бита
        encoded ^= 1 << 0;
        encoded ^= 1 << 1;

        let result = HammingECC16::decode(encoded);

        // Двойная ошибка не должна быть исправлена
        assert!(result.is_err(), "Двойная ошибка не должна быть исправлена");
    }

    #[test]
    fn test_hamming_all_zeroes() {
        let data: u16 = 0;
        let encoded = HammingECC16::encode(data).expect("Encoding failed");
        let decoded = HammingECC16::decode(encoded).expect("Decoding failed");

        assert_eq!(decoded, data, "Все нули декодированы некорректно");
    }

    #[test]
    fn test_hamming_all_ones() {
        let data: u16 = 0xFFFF;
        let encoded = HammingECC16::encode(data).expect("Encoding failed");
        let decoded = HammingECC16::decode(encoded).expect("Decoding failed");

        assert_eq!(decoded, data, "Все единицы декодированы некорректно");
    }
}
