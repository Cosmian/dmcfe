use crate::{
    dsum, tools,
    types::{DVec, Label, TMat},
};
use cosmian_bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

/// DMCFE cyphertext type
#[derive(Clone, Copy)]
pub struct CypherText(G1Projective);

/// DMCFE private key type
/// - `s`:  two dimensional scalar vector
/// - `t`:  2x2 scalar matrix
#[derive(Clone)]
pub struct PrivateKey {
    pub s: DVec<Scalar>,
    pub t: TMat<dsum::CypherText>,
}

/// DMCFE partial decryption key type: `di`
#[derive(Clone)]
pub struct PartialDecryptionKey(DVec<G2Projective>);

/// DMCFE decryption key type: `(y, d)`
/// - `y`:  decryption function
/// - `d`:  functional decryption key
#[derive(Clone)]
pub struct DecryptionKey {
    pub y: Vec<Scalar>,
    dk: DVec<G2Projective>,
}

/// Create `Ti`, such that `Sum(Ti) = 0`.
/// - `dski`: DSum secret key
/// - `dpk` : DSum public keys from all clients
fn t_gen(dski: &dsum::PrivateKey, dpk: &[dsum::PublicKey]) -> TMat<dsum::CypherText> {
    let mut res = [Default::default(); 4];
    for (i, res) in res.iter_mut().enumerate() {
        let mut l = Label::from("Setup");
        l.aggregate(&(i as u8).to_be_bytes());
        *res = dsum::encode(&Scalar::zero(), dski, dpk, &l);
    }
    TMat::new(res[0], res[1], res[2], res[3])
}

/// Return the DMCFE secret key.
/// - `dski`: DSum secret key
/// - `dpk` : DSum public keys from all clients
pub fn setup(dski: &dsum::PrivateKey, dpk: &[dsum::PublicKey]) -> PrivateKey {
    PrivateKey {
        s: DVec([tools::random_scalar(), tools::random_scalar()]),
        t: t_gen(dski, dpk),
    }
}

/// Compute the DMCFE partial decryption key.
/// - `id`  : client ID
/// - `ski` : private key
/// - `y`   : decryption function
pub fn dkey_gen_share(id: usize, ski: &PrivateKey, y: &[Scalar]) -> PartialDecryptionKey {
    let v = DVec::new(tools::double_hash_to_curve_in_g2(Label::from(y).as_ref()));
    PartialDecryptionKey(&(&ski.s * &y[id]) * &G2Projective::generator() + &ski.t * &v)
}

/// Combine the partial decryption keys to return the final decryption key.
/// - `y`   : decryption function
/// - `pdk` : partial decryption keys
pub fn key_comb(y: &[Scalar], pdk: &[PartialDecryptionKey]) -> DecryptionKey {
    DecryptionKey {
        y: y.to_vec(),
        dk: pdk.iter().map(|&PartialDecryptionKey(di)| di).sum(),
    }
}

/// Encrypts the data of a client `i` for a given label and encryption key.
/// - `xi`  : contribution
/// - `ski` : encryption key
/// - `l`   : label
pub fn encrypt(xi: &Scalar, ski: &PrivateKey, l: &Label) -> CypherText {
    let u = DVec::new(tools::double_hash_to_curve_in_g1(l.as_ref()));
    CypherText(u.inner_product(&ski.s) + tools::smul_in_g1(xi))
}

/// Decrypt the given cyphertexts with a given label and decryption key.
/// - `c`  : cyphertexts
/// - `dk` : decryption key
/// - `l`  : label
pub fn decrypt(c: &[CypherText], dk: &DecryptionKey, l: &Label) -> Gt {
    let u = DVec::new(tools::double_hash_to_curve_in_g1(l.as_ref()));

    c.iter()
        .zip(dk.y.iter())
        .map(|(CypherText(ci), yi)| {
            pairing(&G1Affine::from(ci), &G2Affine::from(tools::smul_in_g2(yi)))
        })
        .sum::<Gt>()
        - u.iter()
            .zip(dk.dk.iter())
            .map(|(ui, di)| pairing(&G1Affine::from(ui), &G2Affine::from(di)))
            .sum::<Gt>()
}
