use crate::{dsum, ipmcfe, tools};
use bls12_381::Scalar;
use eyre::Result;

pub use crate::ipmcfe::{decrypt, dkey_gen, encrypt};

pub type DVec<T> = [T; 2];

/// Generate the MCFE encryption key and DSum key pair for a DMCFE client.
/// - `m`:  number of contributions per client
pub fn setup(m: usize) -> (ipmcfe::EncryptionKey, dsum::KeyPair) {
    (ipmcfe::setup(m), dsum::client_setup())
}

/// Encrypt the given MCFE partial decryption key using the DSum algorithm.
/// - `id`:     client ID`
/// - `dki`:    MCFE partial decryption key
/// - `ski`:    DSum secret key
/// - `pk`:     list of couple (DSum client ID, DSum public key)
pub fn dkey_gen_share(
    id: usize,
    di: DVec<Scalar>,
    ski: &dsum::PrivateKey,
    pk: &[(usize, dsum::PublicKey)],
    y: &[Vec<Scalar>],
) -> Result<DVec<dsum::CypherText>> {
    // use y as label
    let mut l = Vec::new();
    for yi in y {
        l.append(&mut tools::scalars_to_bytes(yi));
    }
    // encode di
    Ok([
        dsum::encode(id, &di[0], ski, pk, &l),
        dsum::encode(id, &di[1], ski, pk, &l),
    ])
}

/// Decrypt the encrypted MCFE partial decryption keys using the DSum algorithm.
/// Return the MCFE decryption key.
/// - `y`:      MCFE decryption function
/// - `c`:      encrypted MCFE partial decryption key
/// - `ip_dk`:  IPFE decription keys
pub fn key_comb(
    y: &[Vec<Scalar>],
    c: &[DVec<dsum::CypherText>],
    ip_dk: &[Scalar],
) -> Result<ipmcfe::DecryptionKey> {
    let ct = tools::transpose(&c.iter().map(|ci| ci.to_vec()).collect::<Vec<_>>())?;
    Ok(ipmcfe::DecryptionKey {
        y: y.to_vec(),
        d: vec![dsum::combine(&ct[0]), dsum::combine(&ct[1])],
        ip_dk: ip_dk.to_vec(),
    })
}
