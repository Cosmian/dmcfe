#![allow(non_snake_case)]

mod bus;

use bus::{Bus, BusTx};
use cosmian_bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
use dmcfe::{dsum, ipdmcfe, types::Label};
use eyre::Result;
use rand::Rng;
use std::thread;

/// Number of decryption keys asked by the user
const NB_DK: u8 = 2;

/// Structure containing all the buses used for the simulation
/// - `n`:  number of bus clients
/// - `yi`: channel for decryption function components
/// - `pk`: channel for public keys
/// - `dk`: channel for partial decryption keys
/// - `ci`: channel for cyphertexts
struct SimuBus {
    n: usize,
    yi: Bus<(u8, Scalar)>,
    pk: Bus<dsum::PublicKey>,
    dk: Bus<ipdmcfe::PartialDecryptionKey>,
    ci: Bus<((ipdmcfe::CypherText, Label), usize)>,
}

impl SimuBus {
    /// Create a new simulation bus
    /// - `n`:  number of clients
    fn new(n: usize) -> Self {
        SimuBus {
            n,
            yi: Bus::<(u8, Scalar)>::open(n),
            pk: Bus::<dsum::PublicKey>::open(n),
            dk: Bus::<ipdmcfe::PartialDecryptionKey>::open(n),
            ci: Bus::<((ipdmcfe::CypherText, Label), usize)>::open(n),
        }
    }

    /// Close all buses
    fn close(self) -> Result<()> {
        self.pk.close()?;
        self.dk.close()?;
        self.ci.close()?;
        Ok(())
    }

    /// Get the transmission channels
    fn get_tx(&self) -> SimuTx {
        SimuTx {
            n: self.n,
            yi: self.yi.tx.clone(),
            dpk: self.pk.tx.clone(),
            pdk: self.dk.tx.clone(),
            ci: self.ci.tx.clone(),
        }
    }
}

/// Bus transmission channels used in the simulation
/// - `n`:  number of bus clients
/// - `yi`: channel for decryption function components
/// - `pk`: channel for public keys
/// - `dk`: channel for partial decryption keys
/// - `ci`: channel for cyphertexts
#[derive(Clone)]
struct SimuTx {
    n: usize,
    yi: BusTx<(u8, Scalar)>,
    dpk: BusTx<dsum::PublicKey>,
    pdk: BusTx<ipdmcfe::PartialDecryptionKey>,
    ci: BusTx<((ipdmcfe::CypherText, Label), usize)>,
}

/// Generate a random scalar
fn random_scalar() -> Scalar {
    Scalar::from_raw([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}

/// Reorder the given vector of `(T, i)` elements given `i`.
/// Return the ordered vector of `T` elements.
/// - `v`:  vector to sort
fn reorder<T: Clone>(v: &mut [(T, usize)]) -> Vec<T> {
    v.sort_by_key(|vi| vi.1);
    v.iter().map(|vi| vi.0.clone()).collect()
}

/// Check labels used to encrypt cyphertexts are identical.
/// - `c`:  list of cyphertexts along with their labels
fn check_labels(c: &[(ipdmcfe::CypherText, Label)]) -> Result<(Vec<ipdmcfe::CypherText>, Label)> {
    let mut iter = c.iter();
    let mut c = Vec::with_capacity(c.len());
    let (ct, label) = iter.next().unwrap();
    c.push(*ct);
    for (ct, l) in iter {
        eyre::ensure!(
            *l.as_ref() == *label.as_ref(),
            "Cyphertexts are using different labels!"
        );
        c.push(*ct);
    }
    Ok((c, label.clone()))
}

/// Send vector to the clients, wait for the associated partial decryption keys
/// and compute the final decryption key.
/// - `tx`: bus
fn get_decryption_key(tx: &SimuTx, key_id: u8, y: &[Scalar]) -> Result<ipdmcfe::DecryptionKey> {
    println!(
        "USER: generating vector {} and broadcasting it to clients",
        key_id
    );
    for &yi in y {
        bus::broadcast(&tx.yi, (key_id, yi))?;
    }
    println!(
        "USER: waiting for partial decryption keys for vector {}",
        key_id
    );
    let pdk = bus::wait_n(&tx.pdk, tx.n - 1, tx.n - 1)?;
    println!("USER: received all partial decryption keys, computing the final decryption key for vector {}", key_id);
    Ok(ipdmcfe::key_comb(y, &pdk))
}

/// Setup step of the DMCFE algorithm.
/// - `id`: client network id
/// - `tx`: bus transmission channels
fn client_setup(id: usize, tx: &SimuTx) -> Result<ipdmcfe::PrivateKey> {
    println!("CLIENT {}: generating DSum keys", id);
    let dsum::KeyPair(dski, dpki) = dsum::client_setup();
    println!("CLIENT {}: broadcasting DSum public key", id);
    bus::broadcast(&tx.dpk, dpki)?;
    println!(
        "CLIENT {}: waiting for DSum public keys from other clients",
        id
    );
    let dpk = bus::wait_n(&tx.dpk, tx.n - 1, id)?;
    println!(
        "CLIENT {}: received all DSum public keys, generating the DMCFE secret key",
        id
    );
    Ok(ipdmcfe::setup(&dski, &dpk))
}

/// Simulate a client:
/// - compute the cyphered contributions;
/// - compute the partial decryption key upon reception of a decryption function;
/// - send cyphertexts and partial decryption keys to the decryption client.
/// Return the contribution used, for test purpose only. In real life
/// applications, the contribution should never be shared!
///
/// - `id`: client network ID
/// - `tx`: bus transmission channels
fn client_simulation(id: usize, tx: &SimuTx) -> Result<Scalar> {
    // Generate setup variables
    let ski = client_setup(id, tx)?;

    // Send cyphered contribution to the user.
    let c_handle = {
        let (ski, tx) = (ski.clone(), tx.clone());
        thread::spawn(move || -> Result<Scalar> {
            println!("CLIENT {}: encrypting data and sending to user", id);
            let l = Label::new()?;
            let xi: Scalar = random_scalar();
            let cij = ipdmcfe::encrypt(&xi, &ski, &l);
            bus::unicast(&tx.ci, tx.n - 1, ((cij, l), id))?;
            // return plaintext contribution for test purpose
            Ok(xi)
        })
    };

    // Note: this loop should run until the thread is closed. For
    // testing purposes, we need it to terminate in order to return
    // the thread data `xi` to check the final result
    for _ in 0..NB_DK {
        let rec = bus::wait_n(&tx.yi, tx.n - 1, id)?;
        let key_id = rec[0].0;
        let y = rec
            .iter()
            .map(|&(id, yi)| {
                eyre::ensure!(key_id == id, "different key IDs received in vector y!");
                Ok(yi)
            })
            .collect::<Result<Vec<Scalar>>>()?;

        println!(
            "CLIENT {}: received vector {} from user. Generating partial decryption key.",
            id, key_id,
        );
        let pdki = ipdmcfe::dkey_gen_share(id, &ski, &y);
        println!(
            "CLIENT {}: sending partial decryption key to user for vector {}",
            id, key_id
        );
        bus::unicast(&tx.pdk, tx.n - 1, pdki)?;
    }

    // We return the `xi` for testing purpose only: in real aplications, the
    // contribution should never be shared!
    c_handle
        .join()
        .map_err(|err| eyre::eyre!("Error while sending the cyphertext: {:?}", err))?
}

/// Simulate the final user. Ask for partial decryption keys from the clients,
/// get the cyphertexts, decrypt data using the computed decryption key.
/// - `tx`: bus transmission channels
fn decrypt_simulation(tx: &SimuTx) -> Result<Vec<(Gt, Vec<Scalar>)>> {
    // Listen to the clients and wait for the cyphertexts.
    let c_handle = {
        let tx = tx.clone();
        thread::spawn(
            move || -> Result<Vec<((ipdmcfe::CypherText, Label), usize)>> {
                println!("USER: waiting for clients contributions");
                let c = bus::wait_n(&tx.ci, tx.n - 1, tx.n - 1)?;
                println!("USER: received all client contributions");
                Ok(c)
            },
        )
    };

    // Ask for some decryption keys.
    let dk_y_list = (0..NB_DK)
        .map(|id| {
            let y: Vec<Scalar> = (0..(tx.n - 1)).map(|_| random_scalar()).collect();
            let dk: ipdmcfe::DecryptionKey = get_decryption_key(tx, id, &y)?;
            Ok((dk, y))
        })
        .collect::<Result<Vec<(ipdmcfe::DecryptionKey, Vec<Scalar>)>>>()?;

    // Ensure we got all the cyphertexts
    let c = reorder(
        &mut c_handle
            .join()
            .map_err(|err| eyre::eyre!("Error while getting the cyphertexts: {:?}", err))??,
    );

    // Check all cyphertexts are encrypted using the same label. This check is
    // optional, cyphertexts using different labels lead to an incorrect result
    let (c, l) = check_labels(&c)?;

    // Decrypt the set of cyphertexts with each decryption key.
    println!("USER: decrypting cyphertexts");
    Ok(dk_y_list
        .iter()
        .map(|(dk, y)| (ipdmcfe::decrypt(&c, dk, &l), y.to_vec()))
        .collect())
}

/// Simulate a complete DMCFE encryption and decryption process. The encryption
/// of `x` for a given label `l` is done by `n` clients. The decryption is done
/// by the user. He gathers the cyphertexts and asks for the partial
/// decryption keys.
/// - `n`:  number of clients
fn simulation(n: usize) -> Result<()> {
    // open the bus
    let bus = SimuBus::new(n + 1);

    // Launch the user
    let res = {
        let tx = bus.get_tx();
        thread::spawn(move || decrypt_simulation(&tx))
    };

    // Launch the clients
    #[allow(clippy::needless_collect)]
    let children: Vec<thread::JoinHandle<Result<Scalar>>> = (0..n)
        .map(|id| {
            let bus = bus.get_tx();
            thread::spawn(move || client_simulation(id, &bus))
        })
        .collect();

    // Get the contributions used by the children
    let x = children
        .into_iter()
        .map(|child| -> Result<Scalar> {
            child
                .join()
                .map_err(|err| eyre::eyre!("Error in client thread: {:?}", err))?
        })
        .collect::<Result<Vec<Scalar>>>()?;

    // Get the results from the user
    let res = res
        .join()
        .map_err(|err| eyre::eyre!("Error in the receiver thread: {:?}", err))??;

    // Check the results
    for (res, y) in res.iter() {
        eyre::ensure!(
            *res == pairing(&G1Affine::generator(), &G2Affine::generator())
                * x.iter()
                    .zip(y.iter())
                    .map(|(xi, yi)| yi * xi)
                    .sum::<Scalar>(),
            "Wrong result!"
        )
    }

    bus.close()
}

#[test]
fn test_dmcfe() -> Result<()> {
    simulation(rand::thread_rng().gen_range(2..20))
}
