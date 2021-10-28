//! # Discrete Logarithm
//!
//! Description of the DLP

#![allow(non_snake_case)]
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use dmcfe::dlp;
use eyre::Result;
use rand::Rng;
use std::path::Path;

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
fn test_read_write() -> Result<()> {
    // table size
    const T: usize = 10;
    /// Optimized walk length
    /// https://www.jstor.org/stable/2698783
    const W: usize = 16;
    // number of random jumps
    const K: usize = 10;
    // DLP upper bound
    const L: u64 = 10u64.pow(4);
    // number of threads
    const N: usize = 1;

    // table names
    let table_filename = Path::new("table");
    let jumps_filename = Path::new("jumps");

    // get the random jumps
    let jumps = dlp::kangaroo::gen_jumps(L, K)?;
    // get the table
    let table = dlp::kangaroo::gen_table(L, T, W, N, &jumps)?;

    // write the table
    dlp::kangaroo::write_jumps(&jumps_filename, &jumps)?;
    dlp::kangaroo::write_table(&table_filename, &table)?;

    // read the tables and check against the original ones
    eyre::ensure!(
        dlp::kangaroo::read_table(&table_filename)? == table,
        "Read table is different from the one written!"
    );
    eyre::ensure!(
        dlp::kangaroo::read_jumps(&jumps_filename)? == jumps,
        "Read table is different from the one written!"
    );

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
    // number of threads
    const N: usize = 8;

    // get the random jumps
    let jumps = dlp::kangaroo::gen_jumps(L, K)?;
    // get the table
    let table = dlp::kangaroo::gen_table(L, T, W, N, &jumps)?;

    // create the DLP
    let h: Scalar = Scalar::from_raw([rand::thread_rng().gen_range(0..L), 0, 0, 0]);
    let H: Gt = pairing(&G1Affine::generator(), &G2Affine::generator()) * h;

    // find the DLP solution
    eyre::ensure!(
        h == dlp::kangaroo::solve(&table, &jumps, &H, W, N)?,
        "Wrong DLP solution!"
    );
    Ok(())
}
