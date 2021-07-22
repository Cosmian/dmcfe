use crate::interface;
use bls12_381::{G1Affine, G1Projective, Scalar};

/// This algorithm implements the `Setup` function of the IPFE scheme.
/// It returns `(msk, mpk)`, the master secret an public keys.
///
/// - l   : dimension of the vector space
pub fn setup(l: &usize) -> (Vec<Scalar>, Vec<G1Affine>) {
    let mut msk: Vec<Scalar> = Vec::new();
    let mut mpk: Vec<G1Affine> = Vec::new();

    for _i in 0..*l {
        msk.push(interface::random_scalar());
        mpk.push(interface::hide_in_g1(&msk[msk.len() - 1]));
    }

    (msk, mpk)
}

/// This algorithm implements the `Encrypt` function of the IPFE scheme.
/// It returns the pair `(ct_0, (ct_i))`.
///
/// - mpk : the master public key
/// - x   : the text to be encrypted
pub fn encrypt(mpk: &Vec<G1Affine>, x: &Vec<Scalar>) -> (G1Affine, Vec<G1Affine>) {
    assert_eq!(x.len(), mpk.len(), "Input text has wrong dimension!");
    let r: Scalar = interface::random_scalar();
    let c0: G1Affine = interface::hide_in_g1(&r);
    let c: Vec<G1Affine> = x
        .iter()
        .zip(mpk.iter())
        .map(|(&xi, &hi)| G1Affine::from(interface::hide_in_g1(&xi) + (hi * r)))
        .collect();
    (c0, c)
}

/// This algorithm implements the `KeyDer` function of the IPFE scheme.
/// It returns `sky=<s,y>`.
///
/// - msk : the master secret key
/// - y   : the vector associated to the decryptied function
pub fn key_der(msk: &Vec<Scalar>, y: &Vec<Scalar>) -> Scalar {
    assert_eq!(y.len(), msk.len(), "Input function has wrong dimensions!");
    y.iter().zip(msk.iter()).map(|(yi, si)| yi * si).sum()
}

/// This algorithm implements the `Decrypt` function of the IPFE scheme.
/// It returns `Prod(ct_i^y_i)/(ct_0^sky)` (written using the
/// multiplicative notation).
///
/// - c   : the cypher text
/// - y   : the vector associated to the decrypted function
/// - sky : the functional key associated to the function
pub fn decrypt(
    c: &(G1Affine, Vec<G1Affine>),
    y: &Vec<Scalar>,
    sky: &Scalar,
) -> G1Affine {
    let p: G1Projective =
        c.1.iter()
            .zip(y.iter())
            .map(|(ci, yi)| ci * yi)
            .sum::<G1Projective>()
            - c.0 * sky;
    G1Affine::from(p)
}
