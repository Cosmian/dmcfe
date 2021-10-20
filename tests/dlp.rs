//! # Discrete Logarithm
//!
//! Description of the DLP

#![allow(non_snake_case)]
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use dmcfe::dlp;
use eyre::Result;
use rand::Rng;

#[test]
fn test_bsbg() -> Result<()> {
    // Do not use a big number, it will take useless time
    const M: u64 = 10u64.pow(4);
    let m: u32 = (M as f64).sqrt() as u32 + 1;
    let x: u64 = rand::thread_rng().gen_range(0..M);

    // create the DLP
    let P: G1Projective = G1Projective::generator() * Scalar::from_raw([x, 0, 0, 0]);

    // solve it
    let res = dlp::bsgs::solve(&P, m, m)?;

    eyre::ensure!(x == res, "Wrong DLP solution!");
    Ok(())
}

#[test]
fn test_kangaroo() -> Result<()> {
    // table size
    const T: usize = 30;
    /// Optimized walk length
    /// https://www.jstor.org/stable/2698783
    const W: usize = 16;
    // number of random jumps
    const K: usize = 10;
    // DLP upper bound
    const L: u64 = 10u64.pow(4);
    // distinguishing parameter
    const D: u32 = 4;

    // get the random jumps
    let jumps = dlp::kangaroo::get_jumps(L, K);

    // get the table
    let table = dlp::kangaroo::get_table(L, T, W, D, &jumps);

    // create the DLP
    let h: Scalar = Scalar::from_raw([rand::thread_rng().gen_range(0..L), 0, 0, 0]);
    let H: Gt = pairing(&G1Affine::generator(), &G2Affine::generator()) * h;

    // find the DLP solution
    if let Some(x) = dlp::kangaroo::solve(&table, &jumps, &H, L, W, D) {
        eyre::ensure!(x == h, "Wrong DLP solution!");
        Ok(())
    } else {
        Err(eyre::eyre!("Cannot solve DLP"))
    }
}
