use crate::tools;
use bls12_381::{G1Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Clone)]
pub struct CypherText(Scalar);
pub struct PrivateKey(Scalar);
#[derive(Clone)]
pub struct PublicKey(G1Projective);
pub struct KeyPair(pub PrivateKey, pub PublicKey);

/// Compute the `h_(i, j, l)` function of the DSum.
/// - `l`:      label
/// - `ski`:    some client secret key
/// - `pkj`:    some other client public key
fn h(label: &[u8], ski: &PrivateKey, pkj: &PublicKey) -> Scalar {
    let pki = PublicKey(tools::smul_in_g1(&ski.0));
    let pki_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pki.0)));
    let pkj_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pkj.0)));

    match pkj_hash.cmp(&pki_hash) {
        Ordering::Less => Scalar::neg(&tools::hash_to_scalar(
            &pkj.0,
            &pki.0,
            &(pkj.0 * ski.0),
            label,
        )),
        Ordering::Equal => Scalar::zero(),
        Ordering::Greater => tools::hash_to_scalar(&pki.0, &pkj.0, &(pkj.0 * ski.0), label),
    }
}

/// Creates the private and public keys for a DSum client.
pub fn client_setup() -> KeyPair {
    let t = tools::random_scalar();
    KeyPair(PrivateKey(t), PublicKey(tools::smul_in_g1(&t)))
}

/// Encrypt the given data using the given keys and label.
/// - `x`:      data to encrypt
/// - `ski`:    client private key
/// - `pk`:     list of all public keys
/// - `l`:      label
pub fn encode(x: &Scalar, ski: &PrivateKey, pk_list: &[PublicKey], label: &[u8]) -> CypherText {
    CypherText(pk_list.iter().fold(*x, |acc, pkj| acc + h(label, ski, pkj)))
}

/// Decrypt the given data.
/// - `c`:  list of all encrypted data
pub fn combine(c: &[CypherText]) -> Scalar {
    c.iter().map(|&CypherText(ci)| ci).sum()
}
