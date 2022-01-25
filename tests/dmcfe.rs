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
    yi: Bus<Scalar>,
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
            yi: Bus::<Scalar>::open(n),
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
    yi: BusTx<Scalar>,
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
fn get_decryption_key(tx: &SimuTx) -> Result<ipdmcfe::DecryptionKey> {
    // generate a new vector
    let y: Vec<Scalar> = (0..(tx.n - 1)).map(|_| random_scalar()).collect();
    // broadcast it to the clients
    for &yi in &y {
        bus::broadcast(&tx.yi, yi)?;
    }
    // wait for the partial decryption keys
    let pdk = bus::wait_n(&tx.pdk, tx.n - 1, tx.n - 1)?;
    // return the final decryption key
    Ok(ipdmcfe::key_comb(&y, &pdk))
}

/// Setup step of the DMCFE algorithm.
/// - `id`: client network id
/// - `tx`: bus transmission channels
fn client_setup(id: usize, tx: &SimuTx) -> Result<ipdmcfe::PrivateKey> {
    // generate the DSum keys to create the `T` matrix
    let dsum::KeyPair(dski, dpki) = dsum::client_setup();
    // share DSum public keys among clients
    bus::broadcast(&tx.dpk, dpki)?;
    let dpk = bus::wait_n(&tx.dpk, tx.n - 1, id)?;
    // generate the DMCFE secret key
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
            let l = Label::new()?;
            let xi: Scalar = random_scalar();
            let cij = ipdmcfe::encrypt(&xi, &ski, &l);
            bus::unicast(&tx.ci, tx.n - 1, ((cij, l), id))?;
            Ok(xi)
        })
    };

    // Note: this loop should run until the thread is closed. For
    // testing purposes, we need it to terminate in order to return
    // the thread data `xi` to check the final result
    for _ in 0..NB_DK {
        let y = bus::wait_n(&tx.yi, tx.n - 1, id)?;
        let pdki = ipdmcfe::dkey_gen_share(id, &ski, &y);
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
fn decrypt_simulation(tx: &SimuTx) -> Result<Vec<(ipdmcfe::DecryptionKey, Gt)>> {
    // Listen to the clients and wait for the cyphertexts.
    let c_handle = {
        let tx = tx.clone();
        thread::spawn(
            move || -> Result<Vec<((ipdmcfe::CypherText, Label), usize)>> {
                bus::wait_n(&tx.ci, tx.n - 1, tx.n - 1)
            },
        )
    };

    // Ask for some decryption keys.
    let mut dk_list = Vec::with_capacity(NB_DK as usize);
    for _ in 0..NB_DK {
        dk_list.push(get_decryption_key(tx)?);
    }

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
    Ok(dk_list
        .iter()
        .map(
            |dk: &ipdmcfe::DecryptionKey| -> (ipdmcfe::DecryptionKey, Gt) {
                (dk.clone(), ipdmcfe::decrypt(&c, dk, &l))
            },
        )
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
    for (dk, res) in res {
        eyre::ensure!(
            res == pairing(&G1Affine::generator(), &G2Affine::generator())
                * x.iter()
                    .zip(dk.y.iter())
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
