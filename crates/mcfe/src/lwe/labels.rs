use num_bigint::BigUint;
use sha3::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha3_256,
};
use std::collections::HashMap;
use std::sync::RwLock;

// size 1x(n₀+m₀)
pub type LabelVector = Vec<BigUint>;

/// A thread safe cache of Label Vectors
///
/// The H vector in MCFE ROM which is a random oracle
/// where for a label `l`: `H(l) = (aₗ , Saₗ + eₗ)`.
///
/// In this implementation, we model the Random Oracle using Sha3 where
/// the n₀+m₀ terms are taken as `Sha3(hᵢ||counter)` where
/// hᵢ = sha3(hᵢ₋₁||counter) for i ∈ [1..n₀+m₀[ and h₀=label
pub struct Labels {
    length: usize,
    q: BigUint,
    map: RwLock<HashMap<Vec<u8>, LabelVector>>,
}

impl Labels {
    /// Create a new labels vector cache which vectors will be `length` long.
    ///
    /// The coefficients of the vector are in ℤq
    pub fn new(length: usize, q: &BigUint) -> Labels {
        Labels {
            length,
            q: q.clone(),
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieve the label vector for label `l`
    /// If it does not yet exist, build it and cache it.
    pub fn vector(&self, label: &[u8]) -> LabelVector {
        if let Some(vectors) = self.map.read().unwrap().get(label) {
            return vectors.clone();
        }
        // it does not exist, create it an cache it
        let vectors = self.create_vector(label);
        let mut map = self.map.write().unwrap();
        map.insert(label.to_vec(), vectors.clone());
        vectors
    }

    /// Create a label vector for label `l`
    pub(crate) fn create_vector(&self, label: &[u8]) -> LabelVector {
        create_hash_vector(label, self.length, &self.q)
    }
}

/// Create a label vector for label `label` of length `length` in ℤq
///
/// The n₀+m₀ terms are taken as `Sha3(hᵢ||counter)` where
/// hᵢ = sha3(hᵢ₋₁||counter) for i ∈ [1..n₀+m₀[ and h₀=label
pub fn create_hash_vector(label: &[u8], length: usize, q: &BigUint) -> LabelVector {
    let mut vectors: Vec<BigUint> = Vec::with_capacity(length);
    let mut h = hash_with_counter(label, 0);
    vectors.push(BigUint::from_bytes_be(h.as_slice()) % q);
    for i in 1..length {
        h = hash_with_counter(h.as_slice(), i);
        vectors.push(BigUint::from_bytes_be(h.as_slice()) % q);
    }
    vectors
}

// A small utility to create a Sha3 hash with an appended counter
pub fn hash_with_counter(data: &[u8], counter: usize) -> GenericArray<u8, U32> {
    Sha3_256::new()
        .chain(data)
        .chain(&counter.to_be_bytes())
        .finalize()
}

#[cfg(test)]
mod tests {

    use super::Labels;
    use num_bigint::BigUint;
    use rand::Rng;

    #[test]
    fn test_label_vector() -> anyhow::Result<()> {
        let length = 500 + 500;
        let q = BigUint::from((1u128 << 127) - 1);
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let labels = Labels::new(length, &q);
        // the label vectors should be deterministic
        // first create one and cache it
        let initial = labels.vector(&label);
        // create another one
        let created = labels.create_vector(&label);
        assert_eq!(&initial, &created);
        // verify the cached one
        let cached = labels.vector(&label);
        assert_eq!(&initial, &cached);
        // verify the size and that all elements are  modulus q
        assert_eq!(length, initial.len());
        for h in initial {
            assert!(h < q);
        }
        Ok(())
    }
}
