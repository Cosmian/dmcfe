//use bls12_381::{G1Affine, G1Projective, Scalar};
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

    let x1: Vec<Scalar> = vec![interface::to_scalar(&1234); L];
    let y: Vec<Scalar> = vec![interface::to_scalar(&1); L];

    let (msk, mpk) = ipfe::setup(&L);

    let c = ipfe::encrypt(&mpk, &x1);

    let sky = ipfe::key_der(&msk, &y);

    let p = ipfe::decrypt(&c, &y, &sky);

    if let Ok(x2) = discrete_logarithm::bsgs(&p, &M, &N) {
        println!("Found exponent: {}", x2);
    } else {
        println!("Could not solve the DLP!");
    }
}
