use crate::tools;
use cosmian_bls12_381::{G1Projective, Scalar};
use eyre::Result;
use rand_core::{CryptoRng, RngCore};

/// IPFE private key type
#[derive(Clone, Copy)]
pub struct PrivateKey(pub Scalar);

impl std::ops::Deref for PrivateKey {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// IPFE public key type
#[derive(Clone, Copy)]
pub struct PublicKey(pub G1Projective);

/// IPFE decryption key type
#[derive(Clone, Copy)]
pub struct DecryptionKey(pub Scalar);

/// IPFE cyphertext structure
pub struct CypherText {
    /// - `c0`: `g^r`
    pub c0: G1Projective,
    /// - `cx`: list of `ci` where `ci = hi^r = g^(si * r)`
    pub cx: Vec<G1Projective>,
}

/// This algorithm implements the `Setup` function of the IPFE scheme.
/// It returns `(msk, mpk)`, the master secret an public keys.
///
/// - l     : dimension of the vector space
/// - `rng` : random number generator
pub fn setup<R: CryptoRng + RngCore>(l: usize, rng: &mut R) -> (Vec<PrivateKey>, Vec<PublicKey>) {
    let msk = (0..l)
        .map(|_| PrivateKey(tools::random_scalar(rng)))
        .collect::<Vec<_>>();
    let mpk = (0..l)
        .map(|i| PublicKey(tools::smul_in_g1(&msk[i])))
        .collect();
    (msk, mpk)
}

/// This algorithm implements the `Encrypt` function of the IPFE scheme.
/// It returns the pair `(ct_0, (ct_i))`.
///
/// - `mpk` : master public key
/// - `x`   : message to be encrypted
/// - `rng` : random number generator
pub fn encrypt<R: CryptoRng + RngCore>(
    mpk: &[PublicKey],
    x: &[Scalar],
    rng: &mut R,
) -> Result<CypherText> {
    // TODO: is it a good idea to check this?
    // Ensuring the size another way may allow removing the Result
    eyre::ensure!(
        x.len() == mpk.len(),
        "Input text has wrong dimension: {} instead of {}!",
        x.len(),
        mpk.len()
    );
    let r = tools::random_scalar(rng);
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
    // TODO: is it a good idea to check this?
    // Ensuring the size another way may allow removing the Result
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
