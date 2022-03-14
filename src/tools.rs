use cosmian_bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Projective, Scalar,
};
use eyre::Result;
use sha2::{Digest, Sha256, Sha512};
use std::cmp::Ordering;

const DST: &[u8] = b"simple_DST";

/// Draw a random scalar from Fp.
#[inline]
pub(crate) fn random_scalar() -> Scalar {
    Scalar::from_raw([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}

/// Hide a given scalar in G1 based on the CDH assumption.
/// - `a`: scalar
#[inline]
pub(crate) fn smul_in_g1(a: &Scalar) -> G1Projective {
    G1Projective::generator() * a
}

/// Hide a given scalar in G2 based on the CDH assumption.
/// - `a`: scalar
pub(crate) fn smul_in_g2(a: &Scalar) -> G2Projective {
    G2Projective::generator() * a
}

/// Returns the hash of the given bytestring in `G1`
/// - `m`: given `usize`
pub(crate) fn hash_to_curve(m: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(m, DST)
}

/// Returns the hash of the given bytestring in `G1xG1`
/// - `m`: given `usize`
pub(crate) fn double_hash_to_curve_in_g1(m: &[u8]) -> (G1Projective, G1Projective) {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::double_hash_to_curve(m, DST)
}

/// Returns the hash of the given bytestring in `G2xG2`
/// - `m`: given `usize`
pub(crate) fn double_hash_to_curve_in_g2(m: &[u8]) -> (G2Projective, G2Projective) {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::double_hash_to_curve(m, DST)
}

/// Return the hash of the given `G1` objects and bytestring as a Scalar.
/// - tmin  : first `G1` object to hash
/// - tmax  : second `G1` object to hash
/// - tmul  : third `G1` object to hash
/// - label : label as a bytestring
pub(crate) fn hash_to_scalar(
    tmin: &G1Projective,
    tmax: &G1Projective,
    tmul: &G1Projective,
    label: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmin)));
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmax)));
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmul)));
    hasher.update(label);
    // get the hash as a 64-bytes string
    let mut m = [0; 64];
    hasher
        .finalize()
        .as_slice()
        .iter()
        .enumerate()
        .for_each(|(i, val)| m[i] = *val);
    // convert it into a Scalar
    Scalar::from_bytes_wide(&m)
}

/// generate a random `(m,n)` matrix of `Fp` elements.
/// - `m`:  matrix size 1;
/// - `n`:  matrix size 2.
pub(crate) fn random_mat_gen(m: usize, n: usize) -> Vec<Vec<Scalar>> {
    (0..m)
        .map(|_| (0..n).map(|_| random_scalar()).collect())
        .collect()
}

/// Transpose the given matrix,
/// - `v`: matrix to transpose
pub(crate) fn transpose<T: Copy>(v: &[Vec<T>]) -> Result<Vec<Vec<T>>> {
    eyre::ensure!(!v.is_empty(), "0 has no inverse!");
    let len = v[0].len();
    let mut iters = v.iter().map(|n| n.iter()).collect::<Vec<_>>();
    Ok((0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| *n.next().expect("Error while accessing elements of v!"))
                .collect::<Vec<T>>()
        })
        .collect())
}

/// Compute the matrix/vector multiplication in `G1`: `x.y`, where `x` is a
/// scalar matrix and `y` a matrix of G1 elements.
///
/// TODO: multiplication can surely be optimised
///
/// - `x`: matrix
/// - `y`: vector
pub(crate) fn mat_mul(x: &[Vec<Scalar>], y: &[G1Projective]) -> Result<Vec<G1Projective>> {
    eyre::ensure!(
        !x.is_empty()
            && x.first()
                .ok_or_else(|| eyre::eyre!("Error while accessing the first element of x!"))?
                .len()
                == y.len(),
        "Lengths do not match!\n
        x ({}, {}) vs y ({}, 1)",
        x.len(),
        x.first()
            .ok_or_else(|| eyre::eyre!("Error while accessing the first element of x!"))?
            .len(),
        y.len(),
    );
    Ok(x.iter()
        .map(|xi| {
            xi.iter()
                .zip(y.iter())
                .map(|(xij, yj)| yj * xij)
                .sum::<G1Projective>()
        })
        .collect())
}

/// Compute the matrix/vector multiplication in `Fp`.
///
/// TODO: multiplication can surely be optimised
///
/// - `x`: matrix;
/// - `y`: vector.
pub(crate) fn scal_mat_mul_dim_2(x: &[Vec<Scalar>], y: &[Scalar]) -> Result<Vec<Scalar>> {
    eyre::ensure!(
        !x.is_empty()
            && x.first()
                .ok_or_else(|| eyre::eyre!("Error while accessing the first element of x!"))?
                .len()
                == y.len(),
        "Lengths do not match!\n
        x ({}, {}) vs y ({}, 1)",
        x.len(),
        x.first()
            .ok_or_else(|| eyre::eyre!("Error while accessing the first element of x!"))?
            .len(),
        y.len(),
    );
    Ok(x.iter()
        .map(|xi| xi.iter().zip(y.iter()).map(|(xij, yj)| yj * xij).sum())
        .collect())
}

/// Compute the `h_{i,j,l}` function of the DSum.
/// - `l`   : label
/// - `ski` : some client secret key
/// - `pkj` : some other client public key
pub(crate) fn h(label: &[u8], ski: &Scalar, pkj: &G1Projective) -> Scalar {
    let pki = smul_in_g1(ski);
    let pki_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pki)));
    let pkj_hash = Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(pkj)));

    match pkj_hash.cmp(&pki_hash) {
        Ordering::Less => Scalar::neg(&hash_to_scalar(pkj, &pki, &(pkj * ski), label)),
        Ordering::Equal => Scalar::zero(),
        Ordering::Greater => hash_to_scalar(&pki, pkj, &(pkj * ski), label),
    }
}
