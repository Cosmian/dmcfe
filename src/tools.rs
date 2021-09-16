#![allow(dead_code)]

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Projective, Scalar,
};
use eyre::Result;
use sha2::{Digest, Sha512};

const RAW_SCALAR_SIZE: usize = 4;
const DST: &[u8] = b"simple_DST";

/// Convert the given uint64 into a valid Fp scalar.
/// - x:    the uint64
pub(crate) fn integer_to_scalar(x: u64) -> Scalar {
    Scalar::from_raw([x, 0, 0, 0])
}

/// Draw a random scalar from Fp.
pub(crate) fn random_scalar() -> Scalar {
    Scalar::from_raw([rand::random(); RAW_SCALAR_SIZE])
}

pub(crate) fn scalars_to_bytes(x: &[Scalar]) -> Vec<u8> {
    let mut res = Vec::new();
    x.iter().for_each(|xi| {
        res.append(&mut xi.to_bytes().to_vec());
    });
    res
}

/// Hide a given scalar in G1 based on the CDH assumption.
/// - `a`:    scalar
pub(crate) fn smul_in_g1(a: &Scalar) -> G1Projective {
    G1Projective::generator() * a
}

/// Hide a given scalar in G2 based on the CDH assumption.
/// - `a`:    scalar
pub(crate) fn smul_in_g2(a: &Scalar) -> G2Projective {
    G2Projective::generator() * a
}

/// Generate a random point in G_1.
pub(crate) fn random_in_g1() -> G1Projective {
    smul_in_g1(&random_scalar())
}

/// Generate a random point in G_2.
pub(crate) fn random_in_g2() -> G2Projective {
    smul_in_g2(&random_scalar())
}

/// Returns the inverse of P in G1 in projective coordinates.
/// - `P`:  Point in G1
pub(crate) fn get_inverse(P: &G1Projective) -> G1Projective {
    G1Projective::from(G1Affine::inverse(&G1Affine::from(P)))
}

/// Returns the hash of the given `usize` in `G1`
/// - `m`:  given `usize`
pub(crate) fn hash_to_curve(m: usize) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(m.to_be_bytes(), DST)
}

/// Returns the hash of the given `usize` in `G1xG1`
/// - `m`:  given `usize`
pub(crate) fn double_hash_to_curve(m: usize) -> (G1Projective, G1Projective) {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::double_hash_to_curve(
        m.to_be_bytes(),
        DST,
    )
}

pub(crate) fn hash_to_scalar(
    tmin: &G1Projective,
    tmax: &G1Projective,
    tmul: &G1Projective,
    l: &[u8],
) -> Scalar {
    let mut m = [0; 64];
    let mut hasher = Sha512::new();
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmin)));
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmax)));
    hasher.update(G1Affine::to_compressed(&G1Affine::from(tmul)));
    hasher.update(l);
    hasher
        .finalize()
        .as_slice()
        .iter()
        .enumerate()
        .for_each(|(i, val)| m[i] = *val);
    Scalar::from_bytes_wide(&m)
}

/// generate a random (m,n) matrix of `Fp` elements.
/// - `m`:  matrix size 1;
/// - `n`:  matrix size 2.
pub(crate) fn random_mat_gen(m: usize, n: usize) -> Vec<Vec<Scalar>> {
    (0..m)
        .map(|_| (0..n).map(|_| random_scalar()).collect())
        .collect()
}

/// Transpose the given matrix,
/// - `v`:  matrix to transpose
pub(crate) fn transpose<T: Copy>(v: &[Vec<T>]) -> Result<Vec<Vec<T>>> {
    eyre::ensure!(!v.is_empty(), "0 has no inverse!");
    let len = v[0].len();
    let mut iters = v.iter().map(|n| n.iter()).collect::<Vec<_>>();
    Ok((0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| *(n.next().expect("Error while accessing elements of v!")))
                .collect::<Vec<T>>()
        })
        .collect())
}

/// Compute the matrix/vector multiplication in `G1`: `x.y`, where `x` is a
/// scalar matrix and `y` a matrix of G1 elements.
/// - `x`:  matrix;
/// - `y`:  vector.
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
        .map(|xi| xi.iter().zip(y.iter()).map(|(xij, yj)| yj * xij).sum())
        .collect())
}

/// Compute the matrix/vector multiplication in `Fp`.
/// - `x`:  matrix;
/// - `y`:  vector.
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

/// This algorithm implements the recursive version of the double-and-add method to compute `n.P`.
/// - `P`:  point
/// - `n`:  exponent
pub(crate) fn double_and_add_rec(P: &G1Projective, n: u64) -> G1Projective {
    let Q = *P;
    if n == 0 {
        G1Projective::identity()
    } else if n == 1 {
        Q
    } else if (n % 2) == 1 {
        Q + double_and_add_rec(&Q, n - 1)
    } else {
        double_and_add_rec(&Q.double(), n / 2)
    }
}

/// This algorithm implements the double-and-add method to compute `n.P`.
/// - `P`:  point
/// - `n`:  exponent
pub(crate) fn double_and_add(P: &G1Projective, n: u64) -> G1Projective {
    let mut acc = G1Projective::identity();

    // This is a simple double-and-add implementation of point
    // multiplication, moving from most significant to least
    // significant bit of the scalar.

    for bit in n
        .to_be_bytes() // big endian representation
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i & 1u8)))
    {
        acc = acc.double();
        if bit == 1u8 {
            acc += P;
        }
    }
    acc
}

#[cfg(test)]
mod test {
    use crate::tools;
    use bls12_381::G1Projective;
    use eyre::Result;
    use rand::Rng;

    #[test]
    fn test_double_and_add() -> Result<()> {
        /// Compute the naive exponentiation `n.P`.
        /// - `P`:  point
        /// - `n`:  exponent
        fn naive_exponentiation(P: &G1Projective, n: u64) -> G1Projective {
            let mut Q = *P;
            for _i in 1..n {
                Q += P;
            }
            Q
        }

        let P = tools::random_in_g1();
        let n: u64 = rand::thread_rng().gen_range(10..20);
        eyre::ensure!(
            naive_exponentiation(&P, n) == tools::double_and_add(&P, n),
            "Error while computing the exponentiation: incorrect result!"
        );
        Ok(())
    }
}
