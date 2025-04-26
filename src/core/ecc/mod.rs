pub mod hamming_7_4;
pub mod repetition_code;

#[derive(Debug)]
pub enum EccError {
    FailedToEncode,
    FailedToDecode
}

pub trait ErrorCorrectionCode {
    type Input;
    type Output;

    fn encode(&self, data: Self::Input) -> Result<Self::Output, EccError>;
    fn decode(&self, data: Self::Output) -> Result<Self::Input, EccError>;
}

