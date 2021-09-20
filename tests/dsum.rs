#![allow(non_snake_case)]

mod bus;

use bls12_381::{G1Projective, Scalar};
use dmcfe::dsum;
use eyre::Result;
use rand::Rng;
use std::thread;

fn client_simulation(
    id: usize,
    n: usize,
    l: usize,
    xi: Vec<Scalar>,
    pk_bus_tx: &bus::BusTx<G1Projective>,
    data_bus_tx: &bus::BusTx<Scalar>,
) -> Result<Scalar> {
    // generate key pair
    let (ski, pki) = dsum::client_setup();

    // publish the public key
    bus::broadcast(pk_bus_tx, pki)?;

    // get the public keys
    println!("Getting public keys");
    let pk = bus::wait_n(pk_bus_tx, n, id)?;

    //encrypt the data
    let c: Vec<dsum::CypherText> = xi
        .iter()
        .map(|xij| -> dsum::CypherText { dsum::encode(xij, &ski, &pki, &pk, &l.to_le_bytes()) })
        .collect();

    // share the chiphered data
    for &ci in c.iter() {
        bus::broadcast(data_bus_tx, ci)?;
    }

    //get all cyphered data
    let c = bus::wait_n(data_bus_tx, n * xi.len(), id)?;

    Ok(dsum::combine(&c))
}

fn simulation(x: &[Vec<Scalar>], l: usize) -> Result<Vec<Scalar>> {
    eyre::ensure!(!x.is_empty(), "The given text vector should not be empty!");

    // Copy vectors to gain ownership
    let n = x.len();

    // Launch the buses
    // Two buses are needed since the type of the pk and the published
    // cyphertexts are different (thus different sizes)
    let pk_bus = bus::Bus::open(n);
    let data_bus = bus::Bus::open(n);

    // Launch the clients
    let children: Vec<thread::JoinHandle<Result<Scalar>>> = x
        .into_iter()
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
    let n_clients = rand::thread_rng().gen_range(2..20);
    let n_contrib = rand::thread_rng().gen_range(2..5);
    let message = vec![vec![Scalar::from_raw([rand::random(); 4]); n_contrib]; n_clients];

    // label
    let l = rand::random(); // TODO: use a timestamp

    // compute the solution `Sum(x_ij)`
    let s: Scalar = message.iter().map(|xi| xi.iter().sum::<Scalar>()).sum();

    // compare it with the solution computed with the MCFE algorithm
    for res in simulation(&message, l)?.iter() {
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
