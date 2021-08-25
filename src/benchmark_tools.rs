use crate::{dlp, tools};
use bls12_381::{G1Projective, Scalar};
use eyre::Result;
use rand::Rng;
use std::time::Instant;

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
    let p = G1Projective::from(tools::smul_in_g1(&Scalar::from_raw([x, 0, 0, 0])));

    // solve it
    let timer = Instant::now();
    let res = dlp::bsgs(&p, n, n)?;
    let timer = timer.elapsed();

    // check the result
    eyre::ensure!(x == res, "Wrong DLP solution: {} != {}", x, res);

    Ok(timer.as_millis())
}
