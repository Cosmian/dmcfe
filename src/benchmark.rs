use crate::{discrete_logarithm, interface};
use bls12_381::{G1Projective, Scalar};
use rand::Rng;
use std::time::Instant;

/// Get the time of a random DLP solving with the sizes `x < M`, `M = mn`.
/// - `m`:        number of baby steps
/// - `m`:        number of giant steps
fn get_time_dlp(m: u32, n: u32) -> u128 {
    // Get `x`, a random uint32 such that `x < M`
    let x: u64 = rand::thread_rng().gen_range(0..((m as u64) * (n as u64)));

    // create the DLP
    let P: G1Projective =
        G1Projective::from(interface::smul_in_g1(&Scalar::from_raw([x, 0, 0, 0])));

    // solve it
    let timer = Instant::now();
    let res = discrete_logarithm::bsgs(&P, m, n);
    let timer = timer.elapsed();

    // check the result
    if let Ok(y) = res {
        assert_eq!(x, y, "Wrong DLP solution!");
    } else {
        panic!("Cannot find any DLP solution!");
    }

    timer.as_millis()
}

/// Benchmark the BSGS DLP solving.
///
/// - `min`:      minimal size
/// - `max`:      maximal size
/// - `mstep`:     size of the step (multiplicative steps)
/// - `n_iter`:   number of iteration per size
pub fn benchmark_dlp(min: u64, max: u64, mstep: u64, n_iter: usize) {
    assert!(
        max < (std::u32::MAX as u64) ^ 2,
        "max is too big to be computable!"
    );

    let mut m = min;

    while m <= max {
        let j: u32 = (m as f32).sqrt() as u32;
        let k: u32 = (m / (j as u64)) as u32;

        print!("Benchmark (M = {}, m = {}, n = {}): ", m, j, k);

        // iterate N_ITER for (j,k)
        let ms: u128 = (0..n_iter).map(|_| get_time_dlp(j, k)).sum::<u128>() / (n_iter as u128);

        println!("{}s{}ms", ms / 1_000, ms % 1_000);
        m *= mstep;
    }
}
