#![allow(non_snake_case)]

use bls12_381::Scalar;

mod discrete_logarithm;
mod interface;
mod ipfe;
mod notes {
    pub mod dlp;
}

fn main() {
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
