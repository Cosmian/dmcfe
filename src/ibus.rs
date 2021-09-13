#![allow(dead_code)]

use eyre::Result;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

// Using `std::usize::MAX` as receiver client ID makes the data accessible to
// all clients.
const BROADCAST: usize = std::usize::MAX;

// Arbitrary size limite for the db
// TODO: think about a better size limit or system to keep the size small
const MAX_SIZE: usize = 2 ^ 16;

// wrapper to ease the use of this module
pub type Sender<T> = mpsc::Sender<Packet<T>>;
pub type Bus = thread::JoinHandle<Result<()>>;

/// Data sent to the client after a fetch request.
/// - `Data`:   actual data
/// - `EOF`:    signal sent when no more data is to be sent for this fetch request
pub enum Data<T> {
    Data(T),
    EOF,
}

/// Fetch request for the bus:
/// - `id`: ID of the client emitting the request
/// - `tx`: sender channel to communicate with this client
pub struct FetchRequest<T> {
    pub id: usize,
    pub tx: mpsc::Sender<Result<Data<T>>>,
}

/// Insert request for the bus:
/// - `id`:     ID of the client emitting the request
/// - `data`:   data to store inside the bus
pub struct InsertRequest<T> {
    pub id: usize,
    pub data: T,
}

/// Packet to send to the bus:
/// TODO: letting any client shut down the bus may be an unwanted behavior.
/// - `FetchRequest`:   request to fetch data from the bus
/// - `InsertRequest`:  request to insert data into the bus
/// - `SigTerm`:        request to shut the bus down
pub enum Packet<T> {
    FetchRequest(FetchRequest<T>),
    InsertRequest(InsertRequest<T>),
    SigTerm,
}

/// Broadcast structure:
/// - `data`:       data to share
/// - `id_list`:    holds the ID of the clients who already have the data
struct Broadcast<T> {
    data: T,
    id_list: HashMap<usize, ()>,
}

/// Manage fetch requests.
fn manage_fetch<T: Clone>(
    request: FetchRequest<T>,
    n: usize,
    private_db: &mut Vec<Vec<T>>,
    public_db: &mut Vec<Broadcast<T>>,
) -> Result<()> {
    if request.id < n {
        send_data(request, private_db, public_db);
    } else {
        request
            .tx
            .send(Err(eyre::eyre!(
                "Cannot serve unplanned client (client id {} > id max {})",
                request.id,
                n - 1
            )))
            .unwrap();
    }
    Ok(())
}

/// Send all data associated with the client ID of the fetch request
/// into the transmission channel of this request.
fn send_data<T: Clone>(
    fetch_request: FetchRequest<T>,
    private_db: &mut Vec<Vec<T>>,
    public_db: &mut [Broadcast<T>],
) {
    // get the client ID and transmission channel
    let FetchRequest { tx, id } = fetch_request;

    // send all private data
    while 0 < private_db[id].len() {
        tx.send(Ok(Data::Data(private_db[id].swap_remove(0))))
            .unwrap();
    }

    // send broadcasted data if it hasn't been received yet
    // remember the id of the clients who already have the data
    // remove the data if all other clients already have it
    public_db
        .iter_mut()
        .enumerate()
        .rev()
        .for_each(|(index, broadcast)| {
            if broadcast.id_list.get(&id).is_none() {
                // TODO: do not clone data for the last client
                tx.send(Ok(Data::Data(broadcast.data.clone()))).unwrap();
                if broadcast.id_list.len() < private_db.len() {
                    broadcast.id_list.insert(id, ());
                } else {
                    // if all clients have received the data, remove it
                    broadcast.id_list.remove(&index);
                }
            }
        });

    // send the end-of-communication signal
    tx.send(Ok(Data::EOF)).unwrap();
}

/// Manage the insert requests.
fn manage_insert<T>(
    insert_request: InsertRequest<T>,
    private_db: &mut [Vec<T>],
    public_db: &mut Vec<Broadcast<T>>,
) {
    match insert_request.id {
        BROADCAST => public_db.push(Broadcast {
            data: insert_request.data,
            id_list: HashMap::new(),
        }),
        _ => {
            if private_db.len() < MAX_SIZE && insert_request.id < private_db.len() {
                private_db[insert_request.id].push(insert_request.data);
            }
        }
    }
}

/// Simulate the bus.
/// - `rx`: bus reception channel
/// - `n`:  number of clients
fn launch_bus<T: Clone>(rx: mpsc::Receiver<Packet<T>>, n: usize) -> Result<()> {
    // DB where data are stored, waiting for the receiver to fetch them
    let mut private_db = vec![vec![]; n];
    let mut public_db = vec![];

    // listen for requests
    loop {
        match rx.recv().unwrap() {
            Packet::InsertRequest(request) => {
                manage_insert(request, &mut private_db, &mut public_db)
            }
            Packet::FetchRequest(request) => {
                manage_fetch(request, n, &mut private_db, &mut public_db)?
            }
            Packet::SigTerm => return Ok(()),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//                                 IBUS APIs                                 //
///////////////////////////////////////////////////////////////////////////////

/// Broadcast the given data. It will make it accessible to any client
/// fetching data from the bus.
/// TODO: the sender will get its broadcasted data at the next fetch
/// - `tx`:     channel used to send the packet to the bus
/// - `data`:   data to send
pub fn broadcast<T>(tx: &Sender<T>, data: T) -> Result<()> {
    let request = Packet::InsertRequest(InsertRequest {
        id: BROADCAST,
        data,
    });
    tx.send(request).unwrap();
    Ok(())
}

/// Send the given data to the client with the given ID.
/// - `tx`:     bus transmission channel
/// - `id`:     receiver client id
/// - `data`:   data to send
pub fn send<T>(tx: &Sender<T>, id: usize, data: T) -> Result<()> {
    tx.send(Packet::InsertRequest(InsertRequest { id, data }))
        .unwrap();
    Ok(())
}

/// Get all the data for the client with the given ID.
/// - `tx`: bus transmission channel
/// - `id`: receiver client ID
pub fn get<T>(tx: &Sender<T>, id: usize) -> Result<Vec<T>> {
    //create communication channels
    let (client_tx, client_rx) = mpsc::channel::<Result<Data<T>>>();
    // contact the bus to get the data
    tx.send(Packet::FetchRequest(FetchRequest { id, tx: client_tx }))
        .unwrap();
    // listen for the bus to get the data
    let mut res = Vec::new();
    while let Data::Data(data) = client_rx.recv().unwrap()? {
        res.push(data);
    }

    Ok(res)
}

/// Open a bus.
/// - `n`:  number of clients for this bus
/// Return the bus transmission channel and the bus handle
pub fn open<T: 'static + Clone + Send>(n: usize) -> (Bus, Sender<T>) {
    let (tx, rx) = mpsc::channel::<Packet<T>>();
    let bus = thread::spawn(move || -> Result<()> { launch_bus(rx, n) });
    (bus, tx)
}

/// Close the given bus.
/// - `bus`:    bus handle
/// - `tx`:     bus transmission channel
pub fn close<T>(bus: Bus, tx: Sender<T>) -> Result<()> {
    tx.send(Packet::SigTerm).unwrap();
    bus.join().unwrap()
}
