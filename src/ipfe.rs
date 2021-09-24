use crate::tools;
use bls12_381::{G1Projective, Scalar};
use eyre::Result;

/// IPFE private key type
pub type PrivateKey = Scalar;

/// IPFE public key type
pub type PublicKey = G1Projective;

/// IPFE decryption key type
pub type DecryptionKey = Scalar;

/// IPFE cyphertext structure
/// - `c0`: `g^r`
/// - `cx`: list of `ci` where `ci = hi^r = g^(si * r)`
pub struct CypherText {
    pub c0: G1Projective,
    pub cx: Vec<G1Projective>,
}

/// This algorithm implements the `Setup` function of the IPFE scheme.
/// It returns `(msk, mpk)`, the master secret an public keys.
///
/// - label   : dimension of the vector space
pub fn setup(l: usize) -> (Vec<PrivateKey>, Vec<PublicKey>) {
    let msk = (0..l).map(|_| tools::random_scalar()).collect::<Vec<_>>();
    let MPK = (0..l).map(|i| tools::smul_in_g1(&msk[i])).collect();
    (msk, MPK)
}

/// This algorithm implements the `Encrypt` function of the IPFE scheme.
/// It returns the pair `(ct_0, (ct_i))`.
///
/// - `MPK` : the master public key
/// - `x`   : the text to be encrypted
pub fn encrypt(MPK: &[PublicKey], x: &[Scalar]) -> Result<CypherText> {
    eyre::ensure!(x.len() == MPK.len(), "Input text has wrong dimension!");
    let r = tools::random_scalar();
    let c0 = tools::smul_in_g1(&r);
    let cx = x
        .iter()
        .zip(MPK.iter())
        .map(|(&xi, &hi)| tools::smul_in_g1(&xi) + (hi * r))
        .collect();
    Ok(CypherText { c0, cx })
}

/// Compute the functional decryption key of the IPFE algorithm.
/// It returns `sky=<s,y>`.
///
/// - `msk` : the master secret key
/// - `y`   : the vector associated to the decryptied function
pub fn key_der(msk: &[PrivateKey], y: &[Scalar]) -> Result<DecryptionKey> {
    eyre::ensure!(y.len() == msk.len(), "Input function has wrong dimensions!");
    Ok(y.iter().zip(msk.iter()).map(|(yi, si)| yi * si).sum())
}

/// This algorithm implements the `Decrypt` function of the IPFE scheme.
/// It returns `Prod(ct_i^y_i)/(ct_0^sky)` (written using the
/// multiplicative notation).
///
/// - `C`   : the cypher text
/// - `y`   : the vector associated to the decrypted function
/// - `sky` : the decryption key associated to the function
pub fn decrypt(C: &CypherText, y: &[Scalar], sky: &DecryptionKey) -> G1Projective {
    C.cx.iter()
        .zip(y.iter())
        .map(|(ci, yi)| ci * yi)
        .sum::<G1Projective>()
        - C.c0 * sky
}
