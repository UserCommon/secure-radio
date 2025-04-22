use super::*;

pub struct Hamming74;

impl ErrorCorrectionCode for Hamming74 {
    type Input = u8;  // Только нижние 4 бита используются
    type Output = u8; // 7 бит в младших разрядах

    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError> {
        let d1 = (data >> 3) & 1;
        let d2 = (data >> 2) & 1;
        let d3 = (data >> 1) & 1;
        let d4 = data & 1;

        let p1 = d1 ^ d2 ^ d4;
        let p2 = d1 ^ d3 ^ d4;
        let p3 = d2 ^ d3 ^ d4;

        // P1 P2 D1 P3 D2 D3 D4
        let encoded =
            (p1 << 6) |
            (p2 << 5) |
            (d1 << 4) |
            (p3 << 3) |
            (d2 << 2) |
            (d3 << 1) |
            d4;

        Ok(encoded)
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, EccError> {
        let p1 = (data >> 6) & 1;
        let p2 = (data >> 5) & 1;
        let d1 = (data >> 4) & 1;
        let p3 = (data >> 3) & 1;
        let d2 = (data >> 2) & 1;
        let d3 = (data >> 1) & 1;
        let d4 = data & 1;

        // Проверка на ошибки: пересчитаем контрольные биты
        let c1 = p1 ^ d1 ^ d2 ^ d4;
        let c2 = p2 ^ d1 ^ d3 ^ d4;
        let c3 = p3 ^ d2 ^ d3 ^ d4;

        let error_position = (c3 << 2) | (c2 << 1) | c1;

        let mut corrected = data;
        if error_position != 0 {
            if error_position > 7 {
                return Err(EccError::FailedToDecode);
            }
            corrected ^= 1 << (7 - error_position);
        }

        // Извлекаем исправленные данные
        let d1 = (corrected >> 4) & 1;
        let d2 = (corrected >> 2) & 1;
        let d3 = (corrected >> 1) & 1;
        let d4 = corrected & 1;

        let decoded = (d1 << 3) | (d2 << 2) | (d3 << 1) | d4;

        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::Hamming74;
    use super::EccError;
    use crate::core::ecc::ErrorCorrectionCode;

    #[test]
    fn all_4bit_values_roundtrip() {
        let ecc = Hamming74;
        for val in 0u8..=0b1111 {
            let enc = ecc.encode(val).expect("encode failed");
            let dec = ecc.decode(enc).expect("decode failed");
            assert_eq!(dec, val, "roundtrip failed for {:04b}", val);
        }
    }

    #[test]
    fn single_bit_errors_are_corrected() {
        let ecc = Hamming74;
        for val in 0u8..=0b1111 {
            let enc = ecc.encode(val).unwrap();
            for bit in 0..7 {
                let corrupted = enc ^ (1 << bit);
                let dec = ecc.decode(corrupted).unwrap();
                assert_eq!(
                    dec, val,
                    "failed to correct bit {} in codeword {:07b}",
                    bit, enc
                );
            }
        }
    }

    #[test]
    fn double_bit_errors_are_detected_or_misdecoded() {
        let ecc = Hamming74;
        let val = 0b1010;
        let enc = ecc.encode(val).unwrap();
        // Перебираем две разные позиции
        for b1 in 0..7 {
            for b2 in (b1 + 1)..7 {
                let corrupted = enc ^ (1 << b1) ^ (1 << b2);
                let result = ecc.decode(corrupted);
                assert!(
                    result.is_err() || result.unwrap() != val,
                    "двойная ошибка не обнаружена: bits {}+{} in {:07b}",
                    b1, b2, enc
                );
            }
        }
    }
}
