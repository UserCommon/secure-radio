use super::*;

#[derive(Debug)]
pub struct RepetitionCode;

impl ErrorCorrectionCode for RepetitionCode {
    type Input = u8;     // Вход: 1 байт
    type Output = [u8; 3]; // Выход: массив из 3 байт (3 повтора)

    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError> {
        Ok([data, data, data])
    }

    fn decode(&self, data: Self::Output) -> Result<Self::Input, EccError> {
        let (a, b, c) = (data[0], data[1], data[2]);

        // Мажоритарное голосование
        if a == b || a == c {
            Ok(a)
        } else if b == c {
            Ok(b)
        } else {
            // Все разные — ошибка
            Err(EccError::FailedToDecode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repetition_code_encode_decode() {
        let codec = RepetitionCode;

        let original = 0x5Au8;
        let encoded = codec.encode(original).unwrap();
        assert_eq!(encoded, [0x5A, 0x5A, 0x5A]);

        let decoded = codec.decode(encoded).unwrap();
        assert_eq!(decoded, 0x5A);
    }

    #[test]
    fn test_repetition_code_one_error_first() {
        let codec = RepetitionCode;

        let corrupted = [0x00, 0x5A, 0x5A];
        let decoded = codec.decode(corrupted).unwrap();
        assert_eq!(decoded, 0x5A);
    }

    #[test]
    fn test_repetition_code_one_error_second() {
        let codec = RepetitionCode;

        let corrupted = [0x5A, 0x00, 0x5A];
        let decoded = codec.decode(corrupted).unwrap();
        assert_eq!(decoded, 0x5A);
    }

    #[test]
    fn test_repetition_code_failed_decode() {
        let codec = RepetitionCode;

        let corrupted = [0x00, 0x01, 0x02];
        let decoded = codec.decode(corrupted);
        assert!(decoded.is_err());
    }
}