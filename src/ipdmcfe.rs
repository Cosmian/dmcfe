use crate::{
    label::Label,
    tools,
    types::{DVec, TMat},
};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

/// DMCFE cyphertext type
#[derive(Clone, Copy)]
pub struct CypherText(G1Projective);

/// DMCFE private key type
/// - `s`:  two dimensional scalar vector
/// - `t`:  2x2 scalar matrix
pub struct PrivateKey {
    pub s: DVec<Scalar>,
    pub t: TMat<Scalar>,
}

/// DMCFE partial decryption key type: `di`
#[derive(Clone)]
pub struct PartialDecryptionKey(DVec<G2Projective>);

/// DMCFE decryption key type: `(y, d)`
/// - `y`:  decryption function
/// - `d`:  functional decryption key
pub struct DecryptionKey {
    y: Vec<Scalar>,
    d: DVec<G2Projective>,
}

/// Generate a random 2x2 scalar matrix (the `T` matrix)
pub fn t_gen() -> TMat<Scalar> {
    TMat::new(
        tools::random_scalar(),
        tools::random_scalar(),
        tools::random_scalar(),
        tools::random_scalar(),
    )
}

// publish the cyphered version of the `T` matrix
// - `t`:   `T` matrix
pub fn t_share(ti: &TMat<Scalar>) -> TMat<G1Projective> {
    ti * &G1Projective::generator()
}

/// Create `ti`, such that `Sum(ti) = 0`. Use the `h` function from the DSum protocol.
/// - `ti`:         initial random `T` matrix for the client `i`
/// - `pk_list`:    list of all encrypted initial random `T` matrices
/// - `y`:          decryption function
fn t_compose(ti: &TMat<Scalar>, pk_list: &[TMat<G1Projective>], y: &[Scalar]) -> TMat<Scalar> {
    let mut res: TMat<Scalar> = Default::default();
    for pk in pk_list {
        for i in 0..2 {
            for j in 0..2 {
                res[i][j] += tools::h(Label::from_scalar_vec(y).as_ref(), &ti[i][j], &pk[i][j])
            }
        }
    }
    res
}

/// Return the private key.
/// - `ti`:         initial random `T` matrix
/// - `pk_list`:    list of all encrypted initial random `T` matrices
/// - `y`:          decryption function
pub fn setup(ti: &TMat<Scalar>, pk_list: &[TMat<G1Projective>], y: &[Scalar]) -> PrivateKey {
    PrivateKey {
        s: DVec([tools::random_scalar(), tools::random_scalar()]),
        t: t_compose(ti, pk_list, y),
    }
}

/// Encrypt the `T` matrix.
/// - `ski`:    private key
/// - `yi`:     component of the DMCFE decryption function associated to the client `i`
/// - `y`:      decryption function
/// TODO: find a nice way not to pass both `y` and `yi`
pub fn dkey_gen_share(ski: &PrivateKey, yi: &Scalar, y: &[Scalar]) -> PartialDecryptionKey {
    let v = DVec::new(tools::double_hash_to_curve_in_g2(
        Label::from_scalar_vec(y).as_ref(),
    ));
    PartialDecryptionKey(&(&ski.s * yi) * &G2Projective::generator() + &ski.t * &v)
}

/// Combine the partial decryption keys and return the final decryption key.
/// - `y`:      decryption function
/// - `d`:      partial decryption keys
pub fn key_comb(y: &[Scalar], d: &[PartialDecryptionKey]) -> DecryptionKey {
    DecryptionKey {
        y: y.to_vec(),
        d: d.iter().map(|&PartialDecryptionKey(di)| di).sum(),
    }
}

/// Encrypts the data of a client `i` for a given label and its encryption key.
/// - `ski`:    encryption key
/// - `xi`:     contribution
/// - `l`:      label
pub fn encrypt(ski: &PrivateKey, xi: &Scalar, l: &Label) -> CypherText {
    let u = DVec::new(tools::double_hash_to_curve_in_g1(l.as_ref()));
    CypherText(u.inner_product(&ski.s) + tools::smul_in_g1(&xi))
}

/// Decrypt the given cyphertexts for a given label and the decryption key.
/// - `C`:  cyphertexts
/// - `dk`: decryption key
/// - `l`:  label
pub fn decrypt(C: &[CypherText], dk: &DecryptionKey, l: &Label) -> Gt {
    let u = DVec::new(tools::double_hash_to_curve_in_g1(l.as_ref()));

    C.iter()
        .zip(dk.y.iter())
        .map(|(CypherText(ci), yi)| {
            pairing(&G1Affine::from(ci), &G2Affine::from(tools::smul_in_g2(yi)))
        })
        .sum::<Gt>()
        - u.iter()
            .zip(dk.d.iter())
            .map(|(ui, di)| pairing(&G1Affine::from(ui), &G2Affine::from(di)))
            .sum::<Gt>()
}
