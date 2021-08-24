#![allow(dead_code)]
#![allow(non_snake_case)]

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

const RAW_SCALAR_SIZE: usize = 4;

pub fn random_scalar() -> Scalar {
    Scalar::from_raw([rand::random(); RAW_SCALAR_SIZE])
}

pub fn smul_in_g1(a: &Scalar) -> G1Affine {
    let g: G1Affine = G1Affine::generator();
    G1Affine::from(g * a)
}

pub fn smul_in_g2(a: &Scalar) -> G2Affine {
    let g: G2Affine = G2Affine::generator();
    G2Affine::from(g * a)
}

// Generate a random point in G_1
pub fn random_in_g1() -> G1Affine {
    smul_in_g1(&random_scalar())
}

// Generate a random point in G_2
pub fn random_in_g2() -> G2Affine {
    smul_in_g2(&random_scalar())
}

/// Returns the inverse of `p^pow`.
///
/// - `P`:  Point in G1
/// - `n`:  exponent
pub fn get_inverse(P: &G1Projective, n: u32) -> G1Projective {
    let Q = G1Affine::from(double_and_add(&P, n));
    G1Projective::from(G1Affine::inverse(&Q))
}

/// This algorithm implements the recursive version of the double-and-add method to compute `n.P`.
/// - `P`:  point
/// - `n`:  exponent
pub fn double_and_add_rec(P: &G1Projective, n: u32) -> G1Projective {
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
pub fn double_and_add(P: &G1Projective, n: u32) -> G1Projective {
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
            acc = acc + P;
        }
    }
    acc
}

/// This algorithm implements the naive exponentiation method to compute `n.P`.
/// - `P`:  point
/// - `n`:  exponent
pub fn naive_exponentiation(P: &G1Projective, n: u32) -> G1Projective {
    let mut Q = *P;
    for _i in 1..n {
        Q += P;
    }
    Q
}

pub fn integer_to_scalar(x: u32) -> Scalar {
    Scalar::from_raw([u64::from(x), 0, 0, 0])
}
