#![allow(dead_code)]

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

const RAW_SCALAR_SIZE: usize = 4;

pub fn random_scalar() -> Scalar {
    Scalar::from_raw([rand::random(); RAW_SCALAR_SIZE])
}

pub fn hide_in_g1(a: &Scalar) -> G1Affine {
    let g: G1Affine = G1Affine::generator();
    G1Affine::from(g * a)
}

pub fn hide_in_g2(a: &Scalar) -> G2Affine {
    let g: G2Affine = G2Affine::generator();
    G2Affine::from(g * a)
}

// Generate a random point in G_1
pub fn draw_p1() -> G1Affine {
    hide_in_g1(&random_scalar())
}

// Generate a random point in G_2
pub fn draw_p2() -> G2Affine {
    hide_in_g2(&random_scalar())
}

pub fn naive_exponentiation(p: &G1Affine, n: &u32) -> G1Affine {
    let mut q = G1Projective::from(p);
    for _i in 1..*n {
        q += p;
    }
    G1Affine::from(q)
}

pub fn to_scalar(x: &u32) -> Scalar {
    Scalar::from_raw([u64::from(*x), 0, 0, 0])
}
