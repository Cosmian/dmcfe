use crate::tools;
use bls12_381::{G1Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

pub type CypherText = Scalar;
pub type PrivateKey = Scalar;
pub type PublicKey = G1Projective;
pub type KeyPair = (PrivateKey, PublicKey);

/// Compute the `h_(i, j, l)` function of the DSum.
/// - `l`:      label
/// - `ski`:    some client secret key
/// - `pki`:    some client public key
/// - `pkj`:    some other client public key
fn h(l: &[u8], ski: &Scalar, pki: &G1Projective, pkj: &G1Projective) -> Scalar {
    let pki_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pki)));
    let pkj_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pkj)));

    match pkj_hash.cmp(&pki_hash) {
        Ordering::Less => Scalar::neg(&tools::hash_to_scalar(pkj, pki, &(pkj * ski), l)),
        Ordering::Equal => Scalar::zero(),
        Ordering::Greater => tools::hash_to_scalar(pki, pkj, &(pkj * ski), l),
    }
}

/// Creates the private and public keys for a DSum client.
pub fn client_setup() -> KeyPair {
    let t = tools::random_scalar();
    (t, tools::smul_in_g1(&t))
}

/// Encrypt the given data using the given keys and label.
/// - `x`:      data to encrypt
/// - `ski`:    client private key
/// - `pki`:    client public key
/// - `pk`:     list of all public keys
/// - `l`:      label
pub fn encode(
    x: &Scalar,
    ski: &PrivateKey,
    pki: &PublicKey,
    pk: &[PublicKey],
    l: &[u8],
) -> CypherText {
    pk.iter().fold(*x, |acc, pkj| acc + h(l, ski, pki, pkj))
}

/// Decrypt the given data.
/// - `c`:  list of all encrypted data
pub fn combine(c: &[CypherText]) -> Scalar {
    c.iter().sum()
}
