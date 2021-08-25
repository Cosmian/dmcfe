use crate::{discrete_logarithm, tools};
use bls12_381::{G1Projective, Scalar};
use rand::Rng;
use std::io::ErrorKind;
use std::time::Instant;

/// Get the time of a random DLP solving.
/// - `m`:      `x < m`
pub fn get_time_dlp(m: u64) -> Result<u128, ErrorKind> {
    if m > (std::u32::MAX as u64) * (std::u32::MAX as u64) {
        println!("Size of m is too big to be computable!");
        return Err(ErrorKind::InvalidInput);
    }

    // Get `x`, a random `u64` such that `x < m`
    let x: u64 = rand::thread_rng().gen_range(0..m);
    let n: u32 = (m as f64).sqrt() as u32 + 1; // conversion is OK

    // create the DLP
    let p = G1Projective::from(tools::smul_in_g1(&Scalar::from_raw([x, 0, 0, 0])));

    // solve it
    let timer = Instant::now();
    let res = discrete_logarithm::bsgs(&p, n, n);
    let timer = timer.elapsed();

    // check the result
    if let Ok(y) = res {
        if x != y {
            println!("Wrong DLP solution: {} != {}", x, y);
            return Err(ErrorKind::Other);
        }
    } else {
        println!(
            "Cannot find any DLP solution for x = {}, M = {}, n = {}",
            x, m, n
        );
        return Err(ErrorKind::InvalidData);
    }

    Ok(timer.as_millis())
}
