use crate::tools;
use cosmian_bls12_381::{G1Projective, Scalar};
use eyre::Result;

/// IPFE private key type
#[derive(Clone, Copy)]
pub struct PrivateKey(pub(crate) Scalar);

impl std::ops::Deref for PrivateKey {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// IPFE public key type
#[derive(Clone, Copy)]
pub struct PublicKey(G1Projective);

/// IPFE decryption key type
#[derive(Clone, Copy)]
pub struct DecryptionKey(Scalar);

/// IPFE cyphertext structure
pub struct CypherText {
    /// - `c0`: `g^r`
    pub(crate) c0: G1Projective,
    /// - `cx`: list of `ci` where `ci = hi^r = g^(si * r)`
    pub(crate) cx: Vec<G1Projective>,
}

/// This algorithm implements the `Setup` function of the IPFE scheme.
/// It returns `(msk, mpk)`, the master secret an public keys.
///
/// - l: dimension of the vector space
pub fn setup(l: usize) -> (Vec<PrivateKey>, Vec<PublicKey>) {
    let msk = (0..l)
        .map(|_| PrivateKey(tools::random_scalar()))
        .collect::<Vec<_>>();
    let mpk = (0..l)
        .map(|i| PublicKey(tools::smul_in_g1(&msk[i])))
        .collect();
    (msk, mpk)
}

/// This algorithm implements the `Encrypt` function of the IPFE scheme.
/// It returns the pair `(ct_0, (ct_i))`.
///
/// - `MPK` : master public key
/// - `x`   : message to be encrypted
pub fn encrypt(mpk: &[PublicKey], x: &[Scalar]) -> Result<CypherText> {
    eyre::ensure!(
        x.len() == mpk.len(),
        "Input text has wrong dimension: {} instead of {}!",
        x.len(),
        mpk.len()
    );
    let r = tools::random_scalar();
    let c0 = tools::smul_in_g1(&r);
    let cx = x
        .iter()
        .zip(mpk.iter())
        .map(|(xi, &PublicKey(hi))| tools::smul_in_g1(xi) + (hi * r))
        .collect();
    Ok(CypherText { c0, cx })
}

/// Compute the functional decryption key of the IPFE algorithm.
/// It returns `sky=<s,y>`.
///
/// - `msk` : master secret key
/// - `y`   : vector associated to the decryption function
pub fn key_gen(msk: &[PrivateKey], y: &[Scalar]) -> Result<DecryptionKey> {
    eyre::ensure!(
        y.len() == msk.len(),
        "Input vector function has wrong dimensions: {} instead of {}!",
        y.len(),
        msk.len()
    );
    Ok(DecryptionKey(
        y.iter()
            .zip(msk.iter())
            .map(|(yi, PrivateKey(si))| yi * si)
            .sum(),
    ))
}

/// This algorithm implements the `Decrypt` function of the IPFE scheme.
/// It returns `Prod(ct_i^y_i)/(ct_0^sky)` (written using the
/// multiplicative notation).
///
/// - `C`   : cypher text
/// - `y`   : vector associated to the decryption function
/// - `sky` : decryption key associated to the decryption function
pub fn decrypt(c: &CypherText, y: &[Scalar], sky: &DecryptionKey) -> G1Projective {
    c.cx.iter()
        .zip(y.iter())
        .map(|(ci, yi)| ci * yi)
        .sum::<G1Projective>()
        - c.c0 * sky.0
}
