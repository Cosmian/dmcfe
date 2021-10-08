use crate::{dsum, ipfe, ipmcfe, tools};
use bls12_381::Scalar;
use eyre::Result;

pub use crate::ipmcfe::{decrypt, dkey_gen, encrypt};

/// Generate the MCFE encryption key and DSum key pair for a DMCFE client.
/// - `m`:  number of contributions per client
pub fn setup(m: usize) -> (ipmcfe::EncryptionKey, dsum::KeyPair) {
    (ipmcfe::setup(m), dsum::client_setup())
}

/// Encrypt the given MCFE partial decryption key using the DSum algorithm.
/// - `di`:     MCFE partial decryption key
/// - `ski`:    DSum secret key
/// - `pk`:     list of all DSum public keys
/// - `y`:      decryption function
pub fn dkey_gen_share(
    di: ipmcfe::DVec<Scalar>,
    ski: &dsum::PrivateKey,
    pk: &[dsum::PublicKey],
    y: &[Vec<Scalar>],
) -> Result<ipmcfe::DVec<dsum::CypherText>> {
    // use y as label
    let mut label = Vec::new();
    y.iter().for_each(|yi| {
        label.append(&mut tools::scalars_to_bytes(yi));
    });
    // encode di
    Ok(ipmcfe::DVec(
        dsum::encode(&di.0, ski, pk, &label),
        dsum::encode(&di.1, ski, pk, &label),
    ))
}

/// Decrypt the encrypted MCFE partial decryption keys using the DSum algorithm.
/// Return the MCFE decryption key.
/// - `y`:      MCFE decryption function
/// - `c`:      encrypted MCFE partial decryption key
/// - `ip_dk`:  IPFE decription keys
pub fn key_comb(
    y: &[Vec<Scalar>],
    c: &[ipmcfe::DVec<dsum::CypherText>],
    ip_dk: &[ipfe::DecryptionKey],
) -> Result<ipmcfe::DecryptionKey> {
    let ct = tools::transpose(&c.iter().map(|ci| ci.to_vec()).collect::<Vec<_>>())?;
    Ok(ipmcfe::DecryptionKey {
        y: y.to_vec(),
        d: ipmcfe::DVec(dsum::combine(&ct[0]), dsum::combine(&ct[1])),
        ip_dk: ip_dk.to_vec(),
    })
}
