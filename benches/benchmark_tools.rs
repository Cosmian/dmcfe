use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use dmcfe::dlp;
use eyre::Result;
use rand::Rng;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

/// size of a SHA256 hash
const SHA256_SIZE: usize = 32;

/// Hash table used to store precomputed distinguished points.
type Table = HashMap<[u8; SHA256_SIZE], Scalar>;
type Jumps = Vec<Scalar>;

/// Get the time of a random DLP solving.
/// - `m`:      `x < m`
pub fn get_time_dlp(m: u64) -> Result<u128> {
    eyre::ensure!(
        m > (std::u32::MAX as u64) * (std::u32::MAX as u64),
        "Size of m is too big to be computable!"
    );

    // Get `x`, a random `u64` such that `x < m`
    let x: u64 = rand::thread_rng().gen_range(0..m);
    let n: u32 = (m as f64).sqrt() as u32 + 1; // conversion is OK

    // create the DLP
    let p: G1Projective = G1Projective::generator() * Scalar::from_raw([x, 0, 0, 0]);

    // solve it
    let timer = Instant::now();
    let res = dlp::bsgs::solve(&p, n, n)?;
    let timer = timer.elapsed();

    // check the result
    eyre::ensure!(x == res, "Wrong DLP solution: {} != {}", x, res);

    Ok(timer.as_millis())
}

fn get_precomputations(l: u64, t: usize, k: usize, w: usize, d: u32) -> Result<(Jumps, Table)> {
    struct Names {
        table: &'static str,
        jumps: &'static str,
    }

    let filenames = Names {
        table: "benches/table",
        jumps: "benches/jumps",
    };

    if Path::new(filenames.table).exists() && Path::new(filenames.jumps).exists() {
        Ok((
            dlp::kangaroo::read_jumps(filenames.jumps)?,
            dlp::kangaroo::read_table(filenames.table)?,
        ))
    } else {
        let jumps = dlp::kangaroo::gen_jumps(l, k)?;
        let table = dlp::kangaroo::gen_table(l, t, w, d, &jumps)?;
        Ok((jumps, table))
    }
}

/// used to generate table and jumps
pub fn gen() -> Result<()> {
    // Upper bound of the DLP intervalle
    const L: u64 = 2u64.pow(32);
    // Table size
    const T: usize = 2usize.pow(10);
    // Number of random jumps
    const K: usize = 16;
    // Alpha constant
    const ALPHA: usize = 8;

    // Compute the walk size
    let w: usize = (L as f64 / ((ALPHA.pow(2) * T) as f64)).sqrt() as usize;
    let d: u32 = (w as f64).log2().floor() as u32;

    println!("L: {}, T: {}, K: {}, W: {}, d: {}", L, T, K, w, d);

    let (jumps, table) = get_precomputations(L, T, K, w, d)?;

    let h = Scalar::from_raw([rand::thread_rng().gen_range(1..L), 0, 0, 0]);
    if let Some(x) = dlp::kangaroo::solve(
        &table,
        &jumps,
        &(pairing(&G1Affine::generator(), &G2Affine::generator()) * h),
        L,
        w,
        d,
    ) {
        eyre::ensure!(h == x, "Wrong DLP solution!");
        println!("Success!")
    }

    dlp::kangaroo::write_jumps("benches/jumps", &jumps)?;
    dlp::kangaroo::write_table("benches/table", &table)
}
