//! # IPFE
//!
//! Introduction about the IPFE algorithnm.

#![allow(non_snake_case)]
use bls12_381::{G1Projective, Scalar};
use dmcfe::ipfe;
use eyre::Result;
use rand::Rng;

#[test]
fn test_ipfe() -> Result<()> {
    // size of the problem
    let l: usize = rand::thread_rng().gen_range(10..100);
    // generate random input vectors
    let x: Vec<Scalar> = (0..l)
        .map(|_| Scalar::from_raw([rand::thread_rng().gen_range(0..10 ^ 6), 0, 0, 0]))
        .collect();
    let y: Vec<Scalar> = (0..l)
        .map(|_| Scalar::from_raw([rand::thread_rng().gen_range(0..10 ^ 6), 0, 0, 0]))
        .collect();

    // Generate IPFE keys
    let (msk, mpk) = ipfe::setup(l);
    let sky = ipfe::key_der(&msk, &y)?;

    // compute the text using the IPFE algorithm
    // stay in G1 to avoid computing the discrete logarithm
    let ct = ipfe::encrypt(&mpk, &x)?;
    let P = ipfe::decrypt(&ct, &y, &sky);

    // compute `g * <x, y>`
    // compute result in G1 to avoid computing the discrete logarithm
    let inner_prod = x
        .iter()
        .zip(y.iter())
        .map(|(xi, yi)| xi * yi)
        .sum::<Scalar>();
    let Q = G1Projective::generator() * inner_prod;

    eyre::ensure!(P == Q, "Error while computing the IPFE: incorrect result!");
    Ok(())
}
