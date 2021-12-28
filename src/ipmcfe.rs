use std::convert::TryFrom;

use crate::{ipfe, tools, types};
use cosmian_bls12_381::{G1Projective, Scalar};
use eyre::Result;

/// MCFE cyphertext type
#[derive(Clone, Copy)]
pub struct CypherText(G1Projective);

impl<'a> std::iter::FromIterator<&'a CypherText> for Vec<G1Projective> {
    fn from_iter<T: IntoIterator<Item = &'a CypherText>>(iter: T) -> Self {
        iter.into_iter().map(|&CypherText(ci)| ci).collect()
    }
}

/// MCFE encryption key type
/// - `s`:      private key
/// - `msk`:    IPFE master secret key
#[derive(Clone)]
pub struct PrivateKey {
    pub s: Vec<Vec<Scalar>>,
    msk: Vec<ipfe::PrivateKey>,
}

/// MCFE decryption key type
/// - `y`:      the decryption function
/// - `d`:      the MCFE `dk_y = Sum(Si^T.yi)`
/// - `ip_dk`:  IPFE decryption key
pub struct DecryptionKey {
    pub(crate) y: Vec<Vec<Scalar>>,
    pub(crate) d: types::DVec<Scalar>,
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
/// - `eki`:    client encryption key
/// - `xi`:     client contribution
/// - `l`:      label
pub fn encrypt(eki: &PrivateKey, xi: &[Scalar], label: &types::Label) -> Result<Vec<CypherText>> {
    let (p1, p2) = tools::double_hash_to_curve_in_g1(label.as_ref());
    let R1 = tools::mat_mul(&eki.s, &[p1, p2])?;
    let ci = xi
        .iter()
        .zip(R1.iter())
        .map(|(xij, r)| r + G1Projective::generator() * xij);

    // add an IPFE layer to secure the multiple contributions
    let Ul = tools::hash_to_curve(label.as_ref());
    let R2 = eki.msk.iter().map(|&ipfe::PrivateKey(mski)| Ul * mski);
    Ok(ci.zip(R2).map(|(cij, r)| CypherText(r + cij)).collect())
}

/// Compute the decryption key.
/// - `msk`:    the master secret key
/// - `y`:      the vector associated to the decryption function
pub fn dkey_gen(msk: &[PrivateKey], y: &[Vec<Scalar>]) -> Result<DecryptionKey> {
    let mut d = types::DVec::new((Scalar::zero(), Scalar::zero()));
    let mut ip_dk = Vec::with_capacity(y.len());
    for (ski, yi) in msk.iter().zip(y.iter()) {
        ip_dk.push(ipfe::key_der(&ski.msk, yi)?);
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
/// - `C`:  the cyphertexts
/// - `dk`: the decryption key
/// - `l`:  the label
pub fn decrypt(C: &[Vec<CypherText>], dk: &DecryptionKey, label: &types::Label) -> G1Projective {
    let d_l: G1Projective = C
        .iter()
        .zip(dk.y.iter())
        .zip(dk.ip_dk.iter())
        .map(|((Ci, yi), ip_dki)| {
            ipfe::decrypt(
                &ipfe::CypherText {
                    c0: tools::hash_to_curve(label.as_ref()),
                    cx: Ci.iter().collect(),
                },
                yi,
                ip_dki,
            )
        })
        .sum();

    let u = types::DVec::new(tools::double_hash_to_curve_in_g1(label.as_ref()));
    d_l - u.inner_product(&dk.d)
}
