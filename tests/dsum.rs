#![allow(non_snake_case)]

mod bus;

use bls12_381::{G1Projective, Scalar};
use dmcfe::dsum;
use eyre::Result;
use rand::Rng;
use std::thread;

/// Draw a random scalar from Fp.
fn random_scalar() -> Scalar {
    Scalar::from_raw([rand::random(); 4])
}

fn client_simulation(
    id: usize,
    n: usize,
    l: usize,
    xi: Vec<Scalar>,
    pk_bus_tx: &bus::BusTx<(usize, G1Projective)>,
    data_bus_tx: &bus::BusTx<Scalar>,
) -> Result<Scalar> {
    // generate key pair
    let (ski, pki) = dsum::client_setup();

    // publish the public key
    bus::broadcast(pk_bus_tx, (id, pki))?;

    // get the public keys
    let mut pk = Vec::with_capacity(n);
    while pk.len() < n {
        pk.append(&mut bus::get(pk_bus_tx, id)?);
    }

    //encrypt the data
    let c: Vec<Scalar> = xi
        .iter()
        .map(|xij| dsum::encode(id, xij, &ski, &pk, l))
        .collect();

    // share the chiphered data
    for &ci in c.iter() {
        bus::broadcast(data_bus_tx, ci)?;
    }

    //get all cyphered data
    let mut c = Vec::with_capacity(n * xi.len());
    while c.len() < n * xi.len() {
        c.append(&mut bus::get(data_bus_tx, id)?);
    }

    Ok(dsum::combine(c))
}

fn simulation(x: &[Vec<Scalar>], l: usize) -> Result<Vec<Scalar>> {
    eyre::ensure!(!x.is_empty(), "The given text vector should not be empty!");

    // Copy vectors to gain ownership
    let X = x.to_vec();
    let n = X.len();

    // Launch the buses
    // Two buses are needed since the type of the pk and the published
    // cyphertexts are different (thus different sizes)
    let pk_bus = bus::Bus::open(n);
    let data_bus = bus::Bus::open(n);

    // Launch the clients
    let children: Vec<thread::JoinHandle<Result<Scalar>>> = X
        .iter()
        .enumerate()
        .map(|(id, xi)| {
            let xi = xi.clone();
            let data_tx = data_bus.tx.clone();
            let pk_tx = pk_bus.tx.clone();
            thread::spawn(move || client_simulation(id, n, l, xi, &pk_tx, &data_tx))
        })
        .collect();

    // Wait for all the threads to return
    let mut res = Vec::with_capacity(n);
    for child in children.into_iter() {
        res.push(child.join().unwrap()?);
    }

    // Shut the buses down
    pk_bus.close()?;
    data_bus.close()?;

    Ok(res)
}

#[test]
fn test_dsum() -> Result<()> {
    // messages: n clients with m contribution each
    let n = rand::thread_rng().gen_range(2..20);
    let m = rand::thread_rng().gen_range(2..5);
    let x = vec![vec![random_scalar(); m]; n];

    // label
    let l = rand::random(); // TODO: use a timestamp

    // compute the solution `Sum(x_ij)`
    let s: Scalar = x.iter().map(|xi| xi.iter().sum::<Scalar>()).sum();

    // compare it with the solution computed with the MCFE algorithm
    for res in simulation(&x, l)?.iter() {
        eyre::ensure!(
            s == *res,
            "Error while computing the DSum: incorrect result!\n
            {} != {}",
            s,
            res
        );
    }

    Ok(())
}
