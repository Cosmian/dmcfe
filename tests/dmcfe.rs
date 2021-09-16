#![allow(non_snake_case)]

mod bus;

use bls12_381::{G1Projective, Scalar};
use dmcfe::{dsum, ipdmcfe, ipmcfe};
use eyre::Result;
use rand::Rng;
use std::thread;

/// Draw a random scalar from Fp.
fn random_scalar() -> Scalar {
    Scalar::from_raw([rand::random(); 4])
}

/// Simulate a client:
/// - compute the cyphered contributions;
/// - compute the partial decryption key;
/// - send the cyphertexts and the partial decryption key to the decryption client
fn client_simulation(
    n: usize,
    id: usize,
    xi: &[Scalar],
    y: &[Vec<Scalar>],
    l: usize,
    pk_tx: &bus::BusTx<(usize, G1Projective)>,
    ipdk_tx: &bus::BusTx<Scalar>,
    ci_tx: &bus::BusTx<[dsum::CypherText; 2]>,
    Ci_tx: &bus::BusTx<Vec<ipmcfe::CypherText>>,
) -> Result<G1Projective> {
    // DMCFE setup
    println!("DMCFE setup ({}/{})", id, n);
    let (eki, (ski, pki)) = ipdmcfe::setup(xi.len());
    let dki = ipdmcfe::dkey_gen(&eki, &y[id])?;

    // Get ip_dk
    println!("Get ip_dk ({}/{})", id, n);
    bus::broadcast(ipdk_tx, dki.ip_dki)?;
    let ip_dk = bus::wait_n(ipdk_tx, n, id)?;

    // get pk
    println!("Get pk ({}/{})", id, n);
    bus::broadcast(pk_tx, (id, pki))?;
    let pk = bus::wait_n(pk_tx, n, id)?;

    // get dk (share the dki using DSum)
    println!("Get dk ({}/{})", id, n);
    let ci = ipdmcfe::dkey_gen_share(id, dki.di, &ski, &pk, y)?;
    bus::broadcast(ci_tx, ci)?;
    let c = bus::wait_n(ci_tx, n, id)?;
    let dk = ipdmcfe::key_comb(y, &c, ip_dk)?;

    // Encrypt data
    let Ci = ipdmcfe::encrypt(&eki, xi, l)?;

    // share the cyphertext
    bus::broadcast(&Ci_tx, Ci)?;

    // Get all cyphertexts
    println!("Get cyphertexts ({}/{})", id, n);
    let C = bus::wait_n(Ci_tx, n, id)?;

    //let res = ipdmcfe::dkey_gen
    Ok(ipdmcfe::decrypt(&C, &dk, l))
}

/// Simulate a complete MCFE encryption and decryption process. The encryption
/// of `x`, a given `(m,n)` matrix, for a given label `l` is done by `n` clients
/// with `m contributions. The decryption is done by another client who gathers
/// the partial encription keys and cyphertexts and compute the complete
/// decryption key.
/// - `x`:  the contribution vector
/// - `y`:  the vector associated with the decryption function
/// - `l`:  the label
/// It returns the result of the MCFE in G1.
fn simulation(x: &[Vec<Scalar>], y: &[Vec<Scalar>], l: usize) -> Result<Vec<G1Projective>> {
    // check input sizes:
    // x and y should have the same size since `<x,y>` is to be computed
    eyre::ensure!(x.len() == y.len(), "x and y should have the same size!");
    eyre::ensure!(!x.is_empty(), "The given text vector should not be empty!");
    x.iter()
        .zip(y.iter())
        .for_each(|(xi, yi)| assert_eq!(xi.len(), yi.len(), "x and y should have the same size!"));

    // define simulation parameters
    let n = x.len();

    // open the bus
    let pk_bus = bus::Bus::<(usize, dsum::PublicKey)>::open(n);
    let ipdk_bus = bus::Bus::<Scalar>::open(n);
    let ci_bus = bus::Bus::<ipdmcfe::DVec<dsum::CypherText>>::open(n);
    let Ci_bus = bus::Bus::<Vec<ipmcfe::CypherText>>::open(n);

    // Launch the clients.
    let mut children = Vec::new();
    for i in 0..x.len() {
        let (xi, y, pk_tx, ipdk_tx, ci_tx, Ci_tx) = (
            x[i].clone(),
            y.to_vec(),
            pk_bus.tx.clone(),
            ipdk_bus.tx.clone(),
            ci_bus.tx.clone(),
            Ci_bus.tx.clone(),
        );
        children.push(thread::spawn(move || {
            // use the timestamps to get the client id
            client_simulation(n, i, &xi, &y, l, &pk_tx, &ipdk_tx, &ci_tx, &Ci_tx)
        }));
    }

    // Get the result from the children
    let mut res = Vec::with_capacity(n);
    for child in children {
        res.push(child.join().unwrap()?);
    }

    pk_bus.close()?;
    ipdk_bus.close()?;
    ci_bus.close()?;
    Ci_bus.close()?;

    Ok(res)
}

#[test]
fn test_dmcfe() -> Result<()> {
    // number of clients
    let n = rand::thread_rng().gen_range(2..20);
    // number of contributions per client
    let m = rand::thread_rng().gen_range(2..10);
    // messages
    let x = vec![vec![random_scalar(); m]; n];
    // decryption function
    let y = vec![vec![random_scalar(); m]; n];
    // label
    // use the sum of the timestamps of all clients
    let l = rand::random(); // TODO: use a timestamp

    // compute the solution `G * <x,y>`
    // stay in G1 to avoid computing the discrete log
    let s: G1Projective = G1Projective::generator()
        * x.iter()
            .zip(y.iter())
            .map(|(xi, yi)| {
                xi.iter()
                    .zip(yi.iter())
                    .map(|(xij, yij)| xij * yij)
                    .sum::<Scalar>()
            })
            .sum::<Scalar>();

    // check all children have the correct result
    let res = simulation(&x, &y, l)?;
    for res in res {
        eyre::ensure!(
            s == res,
            "Error while computing the MCFE: incorrect result!"
        )
    }
    Ok(())
}
