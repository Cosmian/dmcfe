#![allow(dead_code)]

use eyre::Result;
use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

// Arbitrary size limite for the db
// TODO: think about a better size limit or system to keep the size small
const MAX_SIZE: usize = 2 ^ 16;

// wrapper to ease the use of this module
pub type Sender<T> = mpsc::Sender<Packet<T>>;
pub type Bus = thread::JoinHandle<Result<()>>;

/// Unicast request:
/// - `id`:     client ID of the receiver
/// - `data`:   data to send
pub struct UnicastRequest<T> {
    pub id: usize,
    pub data: T,
}

/// Broadcast request:
/// - `data`:   data to broadacast
pub struct BroadcastRequest<T> {
    pub data: T,
}

/// Fetch request for the bus:
/// - `id`: ID of the client emitting the request
/// - `tx`: sender channel to communicate with this client
pub struct FetchRequest<T> {
    pub id: usize,
    pub tx: mpsc::Sender<Result<Option<T>>>,
}

/// Send request for the bus:
/// - `UnicastRequest`: request unicast sending
/// - `BroadcastRequest`: request broadcast sending
pub enum SendRequest<T> {
    UnicastRequest(UnicastRequest<T>),
    BroadcastRequest(BroadcastRequest<T>),
}

/// Packet to send to the bus:
/// TODO: letting any client shut down the bus may be an unwanted behavior.
/// - `FetchRequest`:   request to fetch data from the bus
/// - `SendRequest`:  request to send data into the bus
/// - `SigTerm`:        request to shut the bus down
pub enum Packet<T> {
    FetchRequest(FetchRequest<T>),
    SendRequest(SendRequest<T>),
    SigTerm,
}

/// Broadcast structure:
/// - `data`:       data to share
/// - `id_list`:    holds the ID of the clients who already have the data
struct BroadcastData<T> {
    data: T,
    id_list: HashSet<usize>,
}

struct DataBase<T> {
    private: Vec<Vec<T>>,
    public: Vec<BroadcastData<T>>,
}

impl<T: Clone> DataBase<T> {
    /// Returns a new database with initialized for the given client number
    fn new(n: usize) -> Self {
        DataBase {
            private: vec![vec![]; n],
            public: vec![],
        }
    }

    /// Manage fetch requests.
    fn manage_fetch(&mut self, request: FetchRequest<T>, n: usize) -> Result<()> {
        if request.id < n {
            self.send_data(request, n);
        } else {
            request
                .tx
                .send(Err(eyre::eyre!(
                    "Cannot serve unplanned client (client id {} > id max {})",
                    request.id,
                    n - 1
                )))
                .or_else(|err| -> Result<()> {
                    eyre::eyre!("Error: failed to send data {}", err);
                    Ok(())
                })?;
        }
        Ok(())
    }

    /// Send all data associated with the client ID of the fetch request
    /// into the transmission channel of this request.
    fn send_data(&mut self, fetch_request: FetchRequest<T>, n: usize) {
        // get the client ID and transmission channel
        let FetchRequest { tx, id } = fetch_request;

        // send all private data
        while 0 < self.private[id].len() {
            tx.send(Ok(Some(self.private[id].swap_remove(0)))).unwrap();
        }

        // send broadcasted data if it hasn't been received yet
        // remember the id of the clients who already have the data
        // remove the data if all other clients already have it
        self.public
            .iter_mut()
            .enumerate()
            .rev()
            .for_each(|(index, broadcast)| {
                if broadcast.id_list.get(&id).is_none() {
                    // TODO: do not clone data for the last client
                    tx.send(Ok(Some(broadcast.data.clone()))).unwrap();
                    if broadcast.id_list.len() < n {
                        broadcast.id_list.insert(id);
                    } else {
                        // if all clients have received the data, remove it
                        broadcast.id_list.remove(&index);
                    }
                }
            });

        // send the end-of-communication signal
        tx.send(Ok(None)).unwrap();
    }

    /// Manage the send requests.
    fn manage_send(&mut self, send_request: SendRequest<T>) {
        match send_request {
            SendRequest::BroadcastRequest(broadcast) => self.public.push(BroadcastData {
                data: broadcast.data,
                id_list: HashSet::new(),
            }),
            SendRequest::UnicastRequest(unicast) => {
                if self.private.len() < MAX_SIZE && unicast.id < self.private.len() {
                    self.private[unicast.id].push(unicast.data);
                }
            }
        }
    }
}

/// Simulate the bus.
/// - `rx`: bus reception channel
/// - `n`:  number of clients
fn launch_bus<T: Clone>(rx: mpsc::Receiver<Packet<T>>, n: usize) -> Result<()> {
    // DB where data are stored, waiting for the receiver to fetch them
    let mut db = DataBase::new(n);

    // listen for requests
    loop {
        match rx.recv().unwrap() {
            Packet::SendRequest(request) => db.manage_send(request),
            Packet::FetchRequest(request) => db.manage_fetch(request, n)?,
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
    let request = Packet::SendRequest(SendRequest::BroadcastRequest(BroadcastRequest { data }));
    tx.send(request).unwrap();
    Ok(())
}

/// Send the given data to the client with the given ID.
/// - `tx`:     bus transmission channel
/// - `id`:     receiver client id
/// - `data`:   data to send
pub fn unicast<T>(tx: &Sender<T>, id: usize, data: T) -> Result<()> {
    tx.send(Packet::SendRequest(SendRequest::UnicastRequest(
        UnicastRequest { id, data },
    )))
    .unwrap();
    Ok(())
}

/// Get all the data for the client with the given ID.
/// - `tx`: bus transmission channel
/// - `id`: receiver client ID
pub fn get<T>(tx: &Sender<T>, id: usize) -> Result<Vec<T>> {
    //create communication channels
    let (client_tx, client_rx) = mpsc::channel::<Result<Option<T>>>();
    // contact the bus to get the data
    tx.send(Packet::FetchRequest(FetchRequest { id, tx: client_tx }))
        .unwrap();
    // listen for the bus to get the data
    let mut res = Vec::new();
    while let Some(data) = client_rx.recv().unwrap()? {
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
