use bls12_381::Scalar;
use eyre::Result;
use std::time::SystemTime;

/// DMCFE label
#[derive(Clone)]
pub struct Label(Vec<u8>);

impl Label {
    /// Get the timestamp as a label
    pub fn new() -> Result<Self> {
        // the label is typically a timestamp
        // it allows to encrypt data periodically
        Ok(Self(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                / 60)
                .to_be_bytes()
                .to_vec(),
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn aggregate(&mut self, x: &Scalar) {
        self.0.append(&mut x.to_bytes().to_vec());
    }
}
