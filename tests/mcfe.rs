//! # MCFE
//!
//! In order to test the MCFE algorithm, 10 clients will be instantiated along with one
//! centrale instance. The central instance is in charge of the setup and distributing encryption
//! keys. The clients will encrypt their data and derive the decryption key. The final
//! client will centralize the derived keys and use them on cyphertexts.
//!
//! In order to simulate the different parties, threads will be used.

#![allow(non_snake_case)]
use bls12_381::{G1Projective, Scalar};
use dmcfe::{ipmcfe, label::Label};
use eyre::Result;
use rand::Rng;
use std::sync::mpsc;
use std::thread;

// Client contribution:
// - `cyphertext`:  the cyphered version of the client contributions
// - `key`:         the partial decryption key
struct Contribution {
    cx: Vec<ipmcfe::CypherText>,
    key: ipmcfe::PartialDecryptionKey,
}

/// Simulate a client:
/// - compute the cyphered contributions;
/// - compute the partial decryption key;
/// - send the cyphertexts and the partial decryption key to the decryption client
fn encrypt_simulation(
    eki: &ipmcfe::EncryptionKey,
    xi: &[Scalar],
    yi: &[Scalar],
    label: &Label,
    tx: mpsc::Sender<Contribution>,
) -> Result<()> {
    tx.send(Contribution {
        cx: ipmcfe::encrypt(eki, xi, label)?,
        key: ipmcfe::dkey_gen(eki, yi)?,
    })?;
    Ok(())
}

/// Receive cyphered contributions from other clients, along with partial decryption keys.
/// It builds the decryption key and use it do compute and return the result of `<x,y>`.
fn decrypt_simulation(
    rx: mpsc::Receiver<Contribution>,
    n: usize,
    label: &Label,
) -> Result<G1Projective> {
    let mut C: Vec<Vec<ipmcfe::CypherText>> = Vec::new();
    let mut keys: Vec<ipmcfe::PartialDecryptionKey> = Vec::new();
    (0..n).for_each(|_| {
        let contrib = rx.recv().unwrap();
        C.push(contrib.cx);
        keys.push(contrib.key);
    });

    // Generate the decryption key
    let dk = ipmcfe::key_comb(&keys)?;

    Ok(ipmcfe::decrypt(&C, &dk, label))
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
fn simulation(x: &[Vec<Scalar>], y: &[Vec<Scalar>], label: &Label) -> Result<G1Projective> {
    // Copy vectors to gain ownership
    let X: Vec<Vec<Scalar>> = x.to_vec();
    let Y: Vec<Vec<Scalar>> = y.to_vec();

    // check input sizes:
    // x and y should have the same size since `<x,y>` is to be computed
    eyre::ensure!(X.len() == Y.len(), "x and y should have the same size!");
    eyre::ensure!(!X.is_empty(), "The given text vector should not be empty!");
    X.iter()
        .zip(Y.iter())
        .for_each(|(xi, yi)| assert_eq!(xi.len(), yi.len(), "x and y should have the same size!"));

    // define simulation parameters
    let n = X.len();
    let m = X.first().unwrap().len();

    // generate encryption keys
    let ek: Vec<ipmcfe::EncryptionKey> = (0..n).map(|_| ipmcfe::setup(m)).collect();

    // Create the communication channels
    let (tx, rx): (mpsc::Sender<Contribution>, mpsc::Receiver<Contribution>) = mpsc::channel();

    // Launch the decryption client.
    // This client will wait for contributions from the other clients
    // then compute the solution using the MCFE algorithm
    let res = {
        let label = label.clone();
        thread::spawn(move || decrypt_simulation(rx, n, &label))
    };

    // Launch the encryption clients.
    // These clients will compute the cyphertexts of their contributions
    // and their associated partial decryption key.
    let mut children = Vec::new();
    for i in 0..X.len() {
        let (eki, xi, yi, tx, label) = (
            ek[i].clone(),
            X[i].clone(),
            Y[i].clone(),
            tx.clone(),
            label.clone(),
        );
        children.push(thread::spawn(move || {
            encrypt_simulation(&eki, &xi, &yi, &label, tx)
        }));
    }

    // wait for all the threads to return
    for child in children {
        child.join().unwrap()?;
    }

    res.join().unwrap()
}

#[test]
fn test_mcfe() -> Result<()> {
    // number of clients
    let n = rand::thread_rng().gen_range(2..20);
    // number of contributions per client
    let m = rand::thread_rng().gen_range(2..10);
    // messages
    let x = vec![vec![Scalar::from_raw([rand::random(); 4]); m]; n];
    // decryption function
    let y = vec![vec![Scalar::from_raw([rand::random(); 4]); m]; n];
    // label
    let label = Label::new()?;

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

    let res = simulation(&x, &y, &label)?;
    // compare it with the solution computed with the MCFE algorithm
    eyre::ensure!(
        s == res,
        "Error while computing the MCFE: incorrect result!"
    );
    Ok(())
}
