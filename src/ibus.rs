use eyre::Result;
use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;

// Arbitrary size limite for the db
// TODO: think about a better size limit or system to keep the size small
const MAX_SIZE: usize = 2 ^ 16;

// wrapper to ease the use of this module
pub type BusTx<T> = mpsc::Sender<Packet<T>>;

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

/// Broadcast data structure:
/// - `data`:       data to share
/// - `id_list`:    holds the ID of the clients who already have the data
struct BroadcastData<T> {
    data: T,
    id_list: HashSet<usize>,
}

/// Bus structure:
/// - `n`:      number of client associated to the bus
/// - `tx`:     transmitter channel to the bus
/// - `bus`:    handle for keeping track of the thread running the bus
pub struct Bus<T: Clone + Send + Sync> {
    pub tx: BusTx<T>,
    bus: thread::JoinHandle<Result<()>>,
}

impl<T: 'static + Clone + Send + Sync> Bus<T> {
    /// Open a bus.
    /// - `n`:  number of clients for this bus
    pub fn open(n: usize) -> Self {
        let (tx, rx) = mpsc::channel::<Packet<T>>();
        let bus = thread::spawn(move || -> Result<()> { launch_bus(rx, n) });
        Bus::<T> { tx, bus }
    }

    /// Close the given bus.
    pub fn close(self) -> Result<()> {
        safe_send(&self.tx, Packet::SigTerm)?;
        self.bus
            .join()
            .map_err(|err| eyre::eyre!("Error Join: {:?}", err))?
    }
}

/// Bus queues where received data are stored waiting for clients to fetch them
/// - `private`:    unicast queue
/// - `public`:     broadcast queue
struct BusQueues<T> {
    private: Vec<Vec<T>>,
    public: Vec<BroadcastData<T>>,
}

impl<T: Clone> BusQueues<T> {
    /// Returns a new bus queue initialized for the given client number
    /// - `n`:  number of clients
    fn new(n: usize) -> Self {
        BusQueues {
            private: vec![vec![]; n],
            public: vec![],
        }
    }

    /// Manage fetch requests.
    /// - `request`:    fetch request
    /// - `n`:          number of clients
    fn manage_fetch(&mut self, request: FetchRequest<T>, n: usize) -> Result<()> {
        if request.id < n {
            self.send_data(request, n)?;
        } else {
            safe_send(
                &request.tx,
                Err(eyre::eyre!(
                    "Cannot serve unplanned client (client id {} > id max {})",
                    request.id,
                    n - 1
                )),
            )?;
        }
        Ok(())
    }

    /// Send all data associated with the client ID of the fetch request
    /// into the transmission channel of this request.
    fn send_data(&mut self, fetch_request: FetchRequest<T>, n: usize) -> Result<()> {
        // get the client ID and transmission channel
        let FetchRequest { tx, id } = fetch_request;

        // send all private data
        while 0 < self.private[id].len() {
            safe_send(&tx, Ok(Some(self.private[id].swap_remove(0))))?;
        }

        // send broadcasted data if it hasn't been received yet
        // remember the id of the clients who already have the data
        // remove the data if all other clients already have it
        for (index, broadcast) in self.public.iter_mut().enumerate() {
            if broadcast.id_list.get(&id).is_none() {
                // TODO: do not clone data for the last client
                tx.send(Ok(Some(broadcast.data.clone())))
                    .map_err(|_| eyre::eyre!("Error send"))?;
                if broadcast.id_list.len() < n {
                    broadcast.id_list.insert(id);
                } else {
                    // if all clients have received the data, remove it
                    broadcast.id_list.remove(&index);
                }
            }
        }

        // send the end-of-communication signal
        safe_send(&tx, Ok(None))
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
    let mut db = BusQueues::new(n);

    // listen for requests
    loop {
        match rx
            .recv()
            .map_err(|err| eyre::eyre!("Error Receive: {:?}", err))?
        {
            Packet::SendRequest(request) => db.manage_send(request),
            Packet::FetchRequest(request) => db.manage_fetch(request, n)?,
            Packet::SigTerm => return Ok(()),
        }
    }
}

fn safe_send<T>(tx: &mpsc::Sender<T>, data: T) -> Result<()> {
    tx.send(data)
        .map_err(|err| eyre::eyre!("Send Error: {:?}", err))
}

/// Broadcast the given data. It will make it accessible to any client
/// fetching data from the bus.
/// TODO: the sender will get its broadcasted data at the next fetch
/// - `tx`:     channel used to send the packet to the bus
/// - `data`:   data to send
pub fn broadcast<T>(tx: &BusTx<T>, data: T) -> Result<()> {
    safe_send(
        tx,
        Packet::SendRequest(SendRequest::BroadcastRequest(BroadcastRequest { data })),
    )
}

/// Send the given data to the client with the given ID.
/// - `tx`:     bus transmission channel
/// - `id`:     receiver client id
/// - `data`:   data to send
pub fn unicast<T>(tx: &BusTx<T>, id: usize, data: T) -> Result<()> {
    safe_send(
        tx,
        Packet::SendRequest(SendRequest::UnicastRequest(UnicastRequest { id, data })),
    )
}

/// Get all the data for the client with the given ID.
/// - `tx`: bus transmission channel
/// - `id`: receiver client ID
pub fn get<T>(tx: &BusTx<T>, id: usize) -> Result<Vec<T>> {
    //create communication channels
    let (client_tx, client_rx) = mpsc::channel::<Result<Option<T>>>();
    // contact the bus to get the data
    safe_send(tx, Packet::FetchRequest(FetchRequest { id, tx: client_tx }))?;
    // listen for the bus to get the data
    let mut res = Vec::new();

    while let Some(data) = client_rx
        .recv()
        .map_err(|err| eyre::eyre!("Error Receive: {:?}", err))??
    {
        res.push(data);
    }
    Ok(res)
}
