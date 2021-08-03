//! This file is here for testing purpose only. It will be replaced by a
//! file `lib.rs` in a later commit.

#![allow(non_snake_case)]

use bls12_381::Scalar;

mod benchmark;
mod discrete_logarithm;
mod interface;
mod ipfe;
mod notes {
    pub mod dlp;
}

fn main() {
    // test to be run
    const TEST: u8 = 3;

    match TEST {
        2 => {
            // benchmark DLP solving
            const M_MIN: u64 = 1_000_000;
            const M_MAX: u64 = 1_000_000_000_000;
            const M_STEP: u64 = 10;
            const N_ITER: usize = 100;

            benchmark::benchmark_dlp(M_MIN, M_MAX, M_STEP, N_ITER);
        }
        3 => {
            // test IPFE
            const L: usize = 2;
            const M: u32 = 1000;
            const N: u32 = 1000;

            let x1: Vec<Scalar> = vec![Scalar::from_raw([1234u64, 0, 0, 0]); L];
            let y: Vec<Scalar> = vec![Scalar::from_raw([1u64, 0, 0, 0]); L];

            let (msk, MPK) = ipfe::setup(L);

            let C = ipfe::encrypt(&MPK, &x1);

            let sky = ipfe::key_der(&msk, &y);

            let P = ipfe::decrypt(&C, &y, &sky);

            match discrete_logarithm::bsgs(&P, M, N) {
                Ok(x2) => println!("Found exponent: {}", x2),
                Err(error) => println!("Error, could not solve the DLP: {:?}", error),
            }
        }
        _ => println!("Test number {} is not implemented!", TEST),
    }
}
