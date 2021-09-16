use crate::{dsum, ipmcfe, tools};
use bls12_381::{G1Projective, Scalar};
use eyre::Result;

pub type DVec<T> = [T; 2];

/// Generate the MCFE encryption key and DSum key pair for a DMCFE client.
/// - `m`:  number of contributions per client
pub fn setup(m: usize) -> (ipmcfe::EncryptionKey, dsum::KeyPair) {
    (ipmcfe::setup(m), dsum::client_setup())
}

/// Generate partial decryption key for the MCFE algorithm.
/// - `eki`:    MCFE encryption key
/// - `yi`:     decryption function associated to this client
pub fn dkey_gen(
    eki: &ipmcfe::EncryptionKey,
    yi: &[Scalar],
) -> Result<ipmcfe::PartialDecryptionKey> {
    ipmcfe::dkey_gen(eki, yi)
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
    for i in 0..y.len() {
        l.append(&mut tools::scalars_to_bytes(&y[i]));
    }
    // encode di
    Ok([
        dsum::encode(id, &di[0], ski, pk, &l),
        dsum::encode(id, &di[1], ski, pk, &l),
    ])
}

/// Decrypt the encrypted MCFE partial decryption keys using the DSum algorithm.
/// Returns the MCFE decryption key.
/// - `y`:      MCFE decryption function
/// - `c`:      encrypted MCFE partial decryption key
/// - `ip_dk`:  IPFE decription keys
pub fn key_comb(
    y: &[Vec<Scalar>],
    c: &[DVec<dsum::CypherText>],
    ip_dk: Vec<Scalar>,
) -> Result<ipmcfe::DecryptionKey> {
    let ct = tools::transpose(&c.iter().map(|ci| ci.to_vec()).collect::<Vec<Vec<Scalar>>>())?;
    Ok(ipmcfe::DecryptionKey {
        y: y.to_vec(),
        d: vec![dsum::combine(&ct[0]), dsum::combine(&ct[1])],
        ip_dk,
    })
}

/// Encrypt the given data using the given MCFE encryption key.
/// - `eki`:    MCFE ecryption key of the client
/// - `xi`:     data to encrypt
pub fn encrypt(
    eki: &ipmcfe::EncryptionKey,
    xi: &[Scalar],
    l: usize,
) -> Result<Vec<ipmcfe::CypherText>> {
    ipmcfe::encrypt(eki, xi, l)
}

/// Decrypt the given MCFE cyphertext.
/// - `C`:  cyphertexts from all clients
/// - `dk`: MCFE decryption key
pub fn decrypt(
    C: &[Vec<ipmcfe::CypherText>],
    dk: &ipmcfe::DecryptionKey,
    l: usize,
) -> G1Projective {
    ipmcfe::decrypt(C, dk, l)
}
