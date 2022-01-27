//! TODO: use special case when `m=1`

use crate::{ipfe, tools, types};
use cosmian_bls12_381::{G1Projective, Scalar};
use eyre::Result;
use std::convert::TryFrom;

/// MCFE cyphertext type
#[derive(Clone, Copy)]
pub struct CypherText(G1Projective);

impl<'a> std::iter::FromIterator<&'a CypherText> for Vec<G1Projective> {
    fn from_iter<T: IntoIterator<Item = &'a CypherText>>(iter: T) -> Self {
        iter.into_iter().map(|&CypherText(ci)| ci).collect()
    }
}

/// MCFE encryption key type
#[derive(Clone)]
pub struct PrivateKey {
    /// - `s`  : private key
    pub s: Vec<Vec<Scalar>>,
    /// - `msk`: IPFE master secret key
    msk: Vec<ipfe::PrivateKey>,
}

/// MCFE decryption key type
pub struct DecryptionKey {
    /// - `y`    : the decryption function
    pub(crate) y: Vec<Vec<Scalar>>,
    /// - `d`    : the MCFE `dk_y = Sum(Si^T.yi)`
    pub(crate) d: types::DVec<Scalar>,
    /// - `ip_dk`: IPFE decryption key
    pub(crate) ip_dk: Vec<ipfe::DecryptionKey>,
}

/// Compute the client encryption keys.
/// - `m`: number of contributions per client
pub fn setup(m: usize) -> PrivateKey {
    let (msk, _) = ipfe::setup(m);
    PrivateKey {
        s: tools::random_mat_gen(m, 2),
        msk,
    }
}

/// Encrypts the data of a client `i` using its encryption key for a given label.
/// - `eki`  : client encryption key
/// - `xi`   : client contribution
/// - `label`: label
pub fn encrypt(eki: &PrivateKey, xi: &[Scalar], label: &types::Label) -> Result<Vec<CypherText>> {
    eyre::ensure!(
        xi.len() == eki.msk.len(),
        "Input plaintext has wrong dimension: {} instead of {}!",
        xi.len(),
        eki.msk.len()
    );
    let (p1, p2) = tools::double_hash_to_curve_in_g1(label.as_ref());
    let r1 = tools::mat_mul(&eki.s, &[p1, p2])?;
    let ci = xi
        .iter()
        .zip(r1.iter())
        .map(|(xij, r)| r + G1Projective::generator() * xij);

    // add an IPFE layer to secure the multiple contributions
    let u_l = tools::hash_to_curve(label.as_ref());
    let r2 = eki.msk.iter().map(|&ipfe::PrivateKey(mski)| u_l * mski);
    Ok(ci.zip(r2).map(|(cij, r)| CypherText(r + cij)).collect())
}

/// Compute the decryption key for a given vector `y`.
/// - `msk`: master secret key
/// - `y`  : vector associated to the decryption function
pub fn dkey_gen(msk: &[PrivateKey], y: &[Vec<Scalar>]) -> Result<DecryptionKey> {
    eyre::ensure!(
        y.len() == msk.len(),
        "Input plaintext has wrong dimension: {} instead of {}!",
        y.len(),
        msk.len()
    );
    let mut d = types::DVec::new((Scalar::zero(), Scalar::zero()));
    let mut ip_dk = Vec::with_capacity(y.len());
    for (ski, yi) in msk.iter().zip(y.iter()) {
        ip_dk.push(ipfe::key_gen(&ski.msk, yi)?);
        d += types::DVec::try_from(&tools::scal_mat_mul_dim_2(&tools::transpose(&ski.s)?, yi)?)
            .map_err(|_| eyre::eyre!("Cannot convert the given dki into a DVec!"))?;
    }
    Ok(DecryptionKey {
        y: y.to_vec(),
        d,
        ip_dk,
    })
}

/// Decrypt the given cyphertexts for a given label using the decryption key.
/// - `c`    : clients' cyphertexts
/// - `dk_y` : decryption key
/// - `label`: label
pub fn decrypt(
    c: &[Vec<CypherText>],
    dk_y: &DecryptionKey,
    label: &types::Label,
) -> Result<G1Projective> {
    eyre::ensure!(
        c.len() == dk_y.y.len(),
        "Input cyphertext has wrong dimension: {} instead of {}!",
        c.len(),
        dk_y.y.len()
    );
    let d_l: G1Projective = c
        .iter()
        .zip(dk_y.y.iter())
        .zip(dk_y.ip_dk.iter())
        .map(|((ci, yi), ip_dki)| {
            ipfe::decrypt(
                &ipfe::CypherText {
                    c0: tools::hash_to_curve(label.as_ref()),
                    cx: ci.iter().collect(),
                },
                yi,
                ip_dki,
            )
        })
        .sum();

    let u = types::DVec::new(tools::double_hash_to_curve_in_g1(label.as_ref()));
    Ok(d_l - u.inner_product(&dk_y.d))
}
