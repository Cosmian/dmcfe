use crate::{ipfe, tools};
use bls12_381::{G1Projective, Scalar};
use eyre::Result;

/// MCFE cyphertext type
pub type CypherText = G1Projective;

/// MCFE encryption key type
/// - `s`:      private key
/// - `msk`:    IPFE master secret key
#[derive(Clone)]
pub struct EncryptionKey {
    s: Vec<Vec<Scalar>>,
    msk: Vec<Scalar>,
}

/// MCFE partial decryption key type
/// - `yi`:     decryption function associated to the client contributions
/// - `di`:     client contribution to the decrytion key, `di = Si^T.yi`
/// - `ip_dki`: IPFE decryption key for this client contributions
pub struct PartialDecryptionKey {
    pub(crate) yi: Vec<Scalar>,
    pub di: [Scalar; 2],
    pub ip_dki: Scalar,
}

/// MCFE decryption key type
/// - `y`:      the decryption function
/// - `d`:      the MCFE `dk_y = Sum(Si^T.yi)`
/// - `ip_dk`:  IPFE decryption key
pub struct DecryptionKey {
    pub(crate) y: Vec<Vec<Scalar>>,
    pub(crate) d: Vec<Scalar>,
    pub(crate) ip_dk: Vec<Scalar>,
}

/// Compute the client encryption keys.
/// - `m`: number of contributions per client
pub fn setup(m: usize) -> EncryptionKey {
    let (msk, _) = ipfe::setup(m);
    EncryptionKey {
        s: tools::random_mat_gen(m, 2),
        msk,
    }
}

/// Encrypts the data of a client `i` using its encryption key for a given label.
/// - `eki`:    client encryption key
/// - `xi`:     client contribution
/// - `l`:      label
pub fn encrypt(eki: &EncryptionKey, xi: &[Scalar], label: &[u8]) -> Result<Vec<CypherText>> {
    let (p1, p2) = tools::double_hash_to_curve(label);
    let R1 = tools::mat_mul(&eki.s, &[p1, p2])?;
    let ci = xi
        .iter()
        .zip(R1.iter())
        .map(|(xij, r)| r + G1Projective::generator() * xij);

    // add an IPFE layer to secure the multiple contributions
    let Ul = tools::hash_to_curve(label);
    let R2 = eki.msk.iter().map(|mski| Ul * mski);
    Ok(ci.zip(R2).map(|(cij, r)| r + cij).collect())
}

/// Compute the partial decryption key for a client `i`.
/// - `eki`:    the encryption key of a client `i`
/// - `yi`:     the vector associated to the decryption function for a client `i`
pub fn dkey_gen(eki: &EncryptionKey, yi: &[Scalar]) -> Result<PartialDecryptionKey> {
    let dky_i = tools::scal_mat_mul_dim_2(&tools::transpose(&eki.s)?, yi)?;
    eyre::ensure!(
        2 == dky_i.len(),
        "Wrong size for dky_i: {}, should be 2!",
        dky_i.len()
    );
    Ok(PartialDecryptionKey {
        yi: (*yi).to_vec(),
        di: [dky_i[0], dky_i[1]],
        ip_dki: ipfe::key_der(&eki.msk, yi)?,
    })
}

/// Compute the decryption key given the `n` partial decryption keys from the clients.
/// - `dki_vec`: partial decryption keys generated by the clients
pub fn key_comb(dki_vec: &[PartialDecryptionKey]) -> Result<DecryptionKey> {
    let mut y = Vec::with_capacity(dki_vec.len());
    let mut d = vec![Scalar::zero(); 2];
    let mut ip_dk = Vec::with_capacity(dki_vec.len());

    dki_vec.iter().for_each(|dki| {
        y.push(dki.yi.to_vec());
        d[0] += dki.di[0];
        d[1] += dki.di[1];
        ip_dk.push(dki.ip_dki);
    });

    Ok(DecryptionKey { y, d, ip_dk })
}

/// Decrypt the given cyphertexts of a given label using the decryption key.
/// - `C`:  the cyphertexts
/// - `dk`: the decryption key
/// - `l`:  the label
pub fn decrypt(C: &[Vec<CypherText>], dk: &DecryptionKey, label: &[u8]) -> G1Projective {
    let dl = C
        .iter()
        .zip(dk.y.iter())
        .zip(dk.ip_dk.iter())
        .map(|((Ci, yi), ip_dki)| {
            ipfe::decrypt(
                &ipfe::CypherText {
                    c0: tools::hash_to_curve(label),
                    cx: Ci.to_vec(),
                },
                yi,
                ip_dki,
            )
        });

    // compute `d^T.[u_l]`
    let double_Ul = tools::double_hash_to_curve(label);
    let d: G1Projective = double_Ul.0 * dk.d[0] + double_Ul.1 * dk.d[1];

    dl.sum::<G1Projective>() - d
}
