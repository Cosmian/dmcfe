#![allow(non_snake_case)]

mod bus;

use bus::{Bus, BusTx};

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use dmcfe::{ipdmcfe, label::Label, types};
use eyre::Result;
use rand::Rng;
use std::thread;

/// structure containing all the buses used for the simulation
/// - `n`:  number of bus clients
/// - `pk`: public key bus channel
/// - `dk`: partial decryption key bus channel
/// - `ci`: cyphertext bus channel
struct SimuBus {
    n: usize,
    pk: Bus<types::TMat<G1Projective>>,
    dk: Bus<ipdmcfe::PartialDecryptionKey>,
    ci: Bus<ipdmcfe::CypherText>,
}

impl SimuBus {
    /// Create a new simulation bus
    /// - `n`:  number of clients
    fn new(n: usize) -> Self {
        SimuBus {
            n,
            pk: Bus::<types::TMat<G1Projective>>::open(n),
            dk: Bus::<ipdmcfe::PartialDecryptionKey>::open(n),
            ci: Bus::<ipdmcfe::CypherText>::open(n),
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
            pk: self.pk.tx.clone(),
            dk: self.dk.tx.clone(),
            ci: self.ci.tx.clone(),
        }
    }
}

/// Bus transmission channels used in the simulation
/// - `n`:  number of bus clients
/// - `pk`: public key bus channel
/// - `dk`: partial decryption key bus channel
/// - `ci`: cyphertext bus channel
#[derive(Clone)]
struct SimuTx {
    n: usize,
    pk: BusTx<types::TMat<G1Projective>>,
    dk: BusTx<ipdmcfe::PartialDecryptionKey>,
    ci: BusTx<ipdmcfe::CypherText>,
}

/// Setup step of the DMCFE algorithm. It has a high communication cost, but it
/// is executed only once.
/// - `n`:  number of clients
/// - `id`: client network id
/// - `y`:  decryption function
/// - `tx`: bus transmission channels
fn setup(n: usize, id: usize, y: &[Scalar], tx: &SimuTx) -> Result<ipdmcfe::PrivateKey> {
    println!("Setup ({}/{})", id, n - 1);
    let ti = ipdmcfe::t_gen();

    // share all cyphered `ti` among clients
    bus::broadcast(&tx.pk, ipdmcfe::t_share(&ti))?;
    let pk_list = bus::wait_n(&tx.pk, n, id)?;

    // generate the secret key and the partial decryption key
    let ski = ipdmcfe::setup(&ti, &pk_list, y);
    let dki = ipdmcfe::dkey_gen_share(&ski, &y[id], y);

    bus::unicast(&tx.dk, n, dki)?;

    Ok(ski)
}

/// Simulate a client:
/// - compute the cyphered contributions;
/// - compute the partial decryption key;
/// - send the cyphertexts and the partial decryption key to the decryption client
fn client_simulation(n: usize, id: usize, xi: &Scalar, y: &[Scalar], bus: &SimuTx) -> Result<()> {
    // TODO: y should be received from the decryption client
    let ski = setup(n, id, y, bus)?;

    // Encryption step
    // Lower communication cost
    // Can be executed many times for the given function, with different data
    let ci = ipdmcfe::encrypt(&ski, xi, &Label::new()?);
    bus::unicast(&bus.ci, n, ci) // send the cyphertext to the receiver
}

/// Receive cyphered contributions from other clients, along with partial decryption keys.
/// It builds the decryption key and use it to compute and return `G*<x,y>`.
fn decrypt_simulation(y: &[Scalar], tx: &SimuTx) -> Result<Gt> {
    // Label
    let l = Label::new()?;

    // Build the decryption key
    let dk_handle = {
        let tx = tx.clone();
        let y = y.to_vec();
        thread::spawn(move || -> Result<ipdmcfe::DecryptionKey> {
            let dk_list = bus::wait_n(&tx.dk, tx.n - 1, tx.n - 1)?;
            Ok(ipdmcfe::key_comb(&y, &dk_list))
        })
    };

    // Get all cyphertexts
    let C_handle = {
        let tx = tx.clone();
        thread::spawn(move || -> Result<Vec<ipdmcfe::CypherText>> {
            bus::wait_n(&tx.ci, tx.n - 1, tx.n - 1)
        })
    };

    Ok(ipdmcfe::decrypt(
        &C_handle
            .join()
            .map_err(|err| eyre::eyre!("Error while getting the cyphertexts: {:?}", err))??,
        &dk_handle
            .join()
            .map_err(|err| eyre::eyre!("Error while getting the decryption key: {:?}", err))??,
        &l,
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
fn simulation(x: &[Scalar], y: &[Scalar]) -> Result<Gt> {
    // check input sizes:
    // x and y should have the same size since `<x,y>` is to be computed
    eyre::ensure!(x.len() == y.len(), "x and y should have the same size!");

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
    // messages
    let messages = vec![Scalar::from_raw([rand::random(); 4]); n_client];
    // decryption function
    let y = vec![Scalar::from_raw([rand::random(); 4]); n_client];

    // compute the solution `G * <x,y>`
    // stay in G1 to avoid computing the discrete log
    let s: Gt = pairing(&G1Affine::generator(), &G2Affine::generator())
        * messages
            .iter()
            .zip(y.iter())
            .map(|(xi, yi)| xi * yi)
            .sum::<Scalar>();

    // check all children have the correct result
    eyre::ensure!(
        s == simulation(&messages, &y)?,
        "Error while computing the DMCFE: incorrect result!"
    );
    Ok(())
}
