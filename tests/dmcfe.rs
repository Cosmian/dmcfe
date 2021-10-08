#![allow(non_snake_case)]

mod bus;

use bus::{Bus, BusTx};

use bls12_381::{G1Projective, Scalar};
use dmcfe::{dsum, ipdmcfe, ipfe, ipmcfe};
use eyre::Result;
use rand::Rng;
use std::thread;
use std::time::SystemTime;

/// structure containing all the buses used for the simulation
/// - `pk`:         public key bus channel
/// - `ipdk`:       IPFE decryption key bus channel
/// - `dsum_ci`:    DSum cyphertext bus channel
struct SimuBus {
    n: usize,
    pk: Bus<dsum::PublicKey>,
    ipdk: Bus<ipfe::DecryptionKey>,
    dsum_ci: Bus<ipmcfe::DVec<dsum::CypherText>>,
    mcfe_ci: Bus<Vec<ipmcfe::CypherText>>,
}

impl SimuBus {
    /// Create a new simulation bus
    /// - `n`:  number of clients
    fn new(n: usize) -> Self {
        SimuBus {
            n,
            pk: Bus::<dsum::PublicKey>::open(n),
            ipdk: Bus::<ipfe::DecryptionKey>::open(n),
            dsum_ci: Bus::<ipmcfe::DVec<dsum::CypherText>>::open(n),
            mcfe_ci: Bus::<Vec<ipmcfe::CypherText>>::open(n),
        }
    }

    /// Close all buses
    fn close(self) -> Result<()> {
        self.pk.close()?;
        self.ipdk.close()?;
        self.dsum_ci.close()?;
        Ok(())
    }

    /// Get the transmission channels
    fn get_tx(&self) -> SimuTx {
        SimuTx {
            n: self.n,
            pk: self.pk.tx.clone(),
            ipdk: self.ipdk.tx.clone(),
            dsum_ci: self.dsum_ci.tx.clone(),
            mcfe_ci: self.mcfe_ci.tx.clone(),
        }
    }
}

/// Bus transmission channels used in the simulation
/// - `pk`:         public key transmission channel
/// - `ipdk`:       IPFE decryption key transmission channel
/// - `dsum_ci`:    DSum cyphertext transmission channel
#[derive(Clone)]
struct SimuTx {
    n: usize,
    pk: BusTx<dsum::PublicKey>,
    ipdk: BusTx<ipfe::DecryptionKey>,
    dsum_ci: BusTx<ipmcfe::DVec<dsum::CypherText>>,
    mcfe_ci: BusTx<Vec<ipmcfe::CypherText>>,
}

/// Get the label as a timestamp
fn get_label_as_timestamp() -> Result<Vec<u8>> {
    // the label is typically a timestamp
    // it allows to encrypt data periodically
    Ok((SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        / 60)
        .to_be_bytes()
        .to_vec())
}

/// Setup step of the DMCFE algorithm. It has a high communication cost, but it
/// is executed only once.
/// - `n`:  number of clients
/// - `id`: client network id
/// - `y`:  decryption function
/// - `tx`: bus transmission channels
fn setup(n: usize, id: usize, y: &[Vec<Scalar>], tx: &SimuTx) -> Result<ipmcfe::EncryptionKey> {
    println!("Setup ({}/{})", id, n - 1);
    let (eki, dsum::KeyPair(ski, pki)) = ipdmcfe::setup(y[id].len());
    let dki = ipdmcfe::dkey_gen(&eki, &y[id])?;

    // share IPFE decryption key with the receiver
    bus::unicast(&tx.ipdk, n, dki.ip_dki)?;

    // share all DSum public keys among clients
    bus::broadcast(&tx.pk, pki)?;
    let pk = bus::wait_n(&tx.pk, n, id)?;

    // share the MCFE partial decryption key with the receiver using the DSum
    let ci = ipdmcfe::dkey_gen_share(dki.di, &ski, &pk, y)?;
    bus::unicast(&tx.dsum_ci, n, ci)?;

    Ok(eki)
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
    bus: &SimuTx,
) -> Result<()> {
    // TODO: y should be received from the decryption client
    let eki = setup(n, id, y, bus)?;

    // Encryption step
    // Lower communication cost
    // Can be executed many times for the given function, with different data
    let Ci = ipdmcfe::encrypt(&eki, xi, &get_label_as_timestamp()?)?;
    // send the cyphered contributions to the receiver
    bus::unicast(&bus.mcfe_ci, n, Ci)
}

/// Receive cyphered contributions from other clients, along with partial decryption keys.
/// It builds the decryption key and use it to compute and return `G*<x,y>`.
fn decrypt_simulation(y: &[Vec<Scalar>], tx: &SimuTx) -> Result<G1Projective> {
    // Build the decryption key
    let dk_handle = {
        let tx = tx.clone();
        let y = y.to_vec();
        thread::spawn(move || -> Result<ipmcfe::DecryptionKey> {
            let ip_dk = bus::wait_n(&tx.ipdk, tx.n - 1, tx.n - 1)?;
            let c = bus::wait_n(&tx.dsum_ci, tx.n - 1, tx.n - 1)?;
            ipdmcfe::key_comb(&y, &c, &ip_dk)
        })
    };

    // Get all cyphertexts
    let C_handle = {
        let tx = tx.clone();
        thread::spawn(move || -> Result<Vec<Vec<ipmcfe::CypherText>>> {
            bus::wait_n(&tx.mcfe_ci, tx.n - 1, tx.n - 1)
        })
    };

    Ok(ipdmcfe::decrypt(
        &C_handle
            .join()
            .map_err(|err| eyre::eyre!("Error while getting the cyphertexts: {:?}", err))??,
        &dk_handle
            .join()
            .map_err(|err| eyre::eyre!("Error while getting the decryption key: {:?}", err))??,
        &get_label_as_timestamp()?,
    ))
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
fn simulation(x: &[Vec<Scalar>], y: &[Vec<Scalar>]) -> Result<G1Projective> {
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
    let bus = SimuBus::new(n + 1);

    // Launch the receiver
    let res = {
        let y = y.to_vec();
        let tx = bus.get_tx();
        thread::spawn(move || decrypt_simulation(&y, &tx))
    };

    // Launch the clients
    let children: Vec<thread::JoinHandle<Result<()>>> = (0..x.len())
        .map(|id| {
            let (xi, y, bus) = (x[id].clone(), y.to_vec(), bus.get_tx());
            thread::spawn(move || client_simulation(n, id, &xi, &y, &bus))
        })
        .collect();

    // Get the result from the children
    for child in children {
        child
            .join()
            .map_err(|err| eyre::eyre!("Error in client thread: {:?}", err))??;
    }

    bus.close()?;

    res.join()
        .map_err(|err| eyre::eyre!("Error in the receiver thread: {:?}", err))?
}

#[test]
fn test_dmcfe() -> Result<()> {
    // number of clients
    let n_client = rand::thread_rng().gen_range(2..20);
    // number of contributions per client
    let n_contrib = rand::thread_rng().gen_range(2..10);
    // messages
    let messages = vec![vec![Scalar::from_raw([rand::random(); 4]); n_contrib]; n_client];
    // decryption function
    let y = vec![vec![Scalar::from_raw([rand::random(); 4]); n_contrib]; n_client];

    // compute the solution `G * <x,y>`
    // stay in G1 to avoid computing the discrete log
    let s: G1Projective = G1Projective::generator()
        * messages
            .iter()
            .zip(y.iter())
            .map(|(xi, yi)| {
                xi.iter()
                    .zip(yi.iter())
                    .map(|(xij, yij)| xij * yij)
                    .sum::<Scalar>()
            })
            .sum::<Scalar>();

    // check all children have the correct result
    eyre::ensure!(
        s == simulation(&messages, &y)?,
        "Error while computing the MCFE: incorrect result!"
    );
    Ok(())
}
