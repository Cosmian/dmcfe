use bls12_381::Scalar;
use eyre::Result;
use std::time::SystemTime;

/// DMCFE label
#[derive(Clone)]
pub struct Label(Vec<u8>);

impl Label {
    /// Get the timestamp as a label. Round to minutes.
    pub fn new() -> Result<Self> {
        Ok(Self(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                / 60)
                .to_be_bytes()
                .to_vec(),
        ))
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        Self(b.to_vec())
    }

    pub fn aggregate(&mut self, r: &[u8]) {
        self.0.append(&mut r.to_vec());
    }

    pub fn from_scalar_vec(vec: &[Scalar]) -> Self {
        let mut res: Vec<u8> = vec![];
        vec.iter()
            .for_each(|val| res.append(&mut val.to_bytes().to_vec()));
        Label(res)
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
