#![allow(non_snake_case)]

use crate::tools;
use bls12_381::{G1Affine, G1Projective, Scalar};

/// This algorithm implements the `Setup` function of the IPFE scheme.
/// It returns `(msk, mpk)`, the master secret an public keys.
///
/// - l   : dimension of the vector space
pub fn setup(l: usize) -> (Vec<Scalar>, Vec<G1Affine>) {
    let msk: Vec<Scalar> = (0..l).map(|_| tools::random_scalar()).collect();
    let MPK: Vec<G1Affine> = (0..l).map(|i| tools::smul_in_g1(&msk[i])).collect();
    (msk, MPK)
}

/// This algorithm implements the `Encrypt` function of the IPFE scheme.
/// It returns the pair `(ct_0, (ct_i))`.
///
/// - `MPK` : the master public key
/// - `x`   : the text to be encrypted
pub fn encrypt(MPK: &[G1Affine], x: &[Scalar]) -> (G1Affine, Vec<G1Affine>) {
    assert_eq!(x.len(), MPK.len(), "Input text has wrong dimension!");
    let r: Scalar = tools::random_scalar();
    let c0: G1Affine = tools::smul_in_g1(&r);
    let c: Vec<G1Affine> = x
        .iter()
        .zip(MPK.iter())
        .map(|(&xi, &hi)| G1Affine::from(tools::smul_in_g1(&xi) + (hi * r)))
        .collect();
    (c0, c)
}

/// This algorithm implements the `KeyDer` function of the IPFE scheme.
/// It returns `sky=<s,y>`.
///
/// - `msk` : the master secret key
/// - `y`   : the vector associated to the decryptied function
pub fn key_der(msk: &[Scalar], y: &[Scalar]) -> Scalar {
    assert_eq!(y.len(), msk.len(), "Input function has wrong dimensions!");
    y.iter().zip(msk.iter()).map(|(yi, si)| yi * si).sum()
}

/// This algorithm implements the `Decrypt` function of the IPFE scheme.
/// It returns `Prod(ct_i^y_i)/(ct_0^sky)` (written using the
/// multiplicative notation).
///
/// - `C`   : the cypher text
/// - `y`   : the vector associated to the decrypted function
/// - `sky` : the functional key associated to the function
pub fn decrypt(C: &(G1Affine, Vec<G1Affine>), y: &[Scalar], sky: &Scalar) -> G1Projective {
    C.1.iter()
        .zip(y.iter())
        .map(|(ci, yi)| ci * yi)
        .sum::<G1Projective>()
        - C.0 * sky
}
