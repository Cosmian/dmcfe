#![allow(dead_code)]

use crate::tools;
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use sha2::{Digest, Sha256};

/// Setup of the Secret Sharing Layer (SSL) algorithm.
/// It returns the couple `(pk, (ek_i)_i)` for the SSL algorithm.
/// - `n`:  number of clients
pub fn setup(n: u32) -> (G2Projective, Vec<Scalar>) {
    let t: Vec<Scalar> = (0..n).map(|_i| tools::random_scalar()).collect();
    (
        tools::smul_in_g2(&t.iter().fold(Scalar::zero(), |acc, x| acc + x)),
        t,
    )
}

/// Hash function
fn hash(m: u128) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(m.to_le_bytes());
    let hash_res = hasher.finalize();
    let mut res = [0u8; 32];
    for i in 0..res.len() {
        res[i] = hash_res[i];
    }
    tools::smul_in_g1(&Scalar::from_bytes(&res).unwrap())
}

pub fn share(ek_i: Scalar, l: u128) -> G1Projective {
    hash(l) * ek_i
}

pub fn encaps(T: G2Projective, l: u128) -> (G2Projective, Gt) {
    let r = tools::random_scalar();
    let C = tools::smul_in_g2(&r);
    let K = pairing(&G1Affine::from(hash(l)), &G2Affine::from(T * r));
    (C, K)
}

pub fn decaps(S: &[G1Projective], C: G2Projective) -> Gt {
    let S: G1Projective = S.iter().sum();
    pairing(&G1Affine::from(S), &G2Affine::from(C))
}
