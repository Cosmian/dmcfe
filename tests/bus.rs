/// This module implements a bus functionality. It is used by test modules in order to simulate
/// communication between clients. It allows to unicast or broadcast data to the bus and to data from the bus
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
    n: usize,
    private: Vec<Vec<T>>,
    public: Vec<BroadcastData<T>>,
}

impl<T: Clone> BusQueues<T> {
    /// Returns a new bus queue initialized for the given client number
    /// - `n`:  number of clients
    fn new(n: usize) -> Self {
        BusQueues {
            n,
            private: vec![vec![]; n],
            public: vec![],
        }
    }

    /// Manage fetch requests.
    /// - `request`:    fetch request
    /// - `n`:          number of clients
    fn manage_fetch(&mut self, request: FetchRequest<T>) -> Result<()> {
        if request.id < self.n {
            self.send_data(request)?;
        } else {
            safe_send(
                &request.tx,
                Err(eyre::eyre!(
                    "Cannot serve unplanned client (client id {} > id max {})",
                    request.id,
                    self.n - 1
                )),
            )?;
        }
        Ok(())
    }

    /// Send all data associated with the client ID of the fetch request
    /// into the transmission channel of this request.
    fn send_data(&mut self, fetch_request: FetchRequest<T>) -> Result<()> {
        // get the client ID and transmission channel
        let FetchRequest { tx, id } = fetch_request;

        // send all private data
        while !self.private[id].is_empty() {
            safe_send(&tx, Ok(Some(self.private[id].swap_remove(0))))?;
        }

        // send broadcasted data if it hasn't been received yet
        // remember the id of the clients who already have the data
        // remove the data if all other clients already have it
        for (index, broadcast) in self.public.iter_mut().enumerate() {
            if broadcast.id_list.get(&id).is_none() {
                // TODO: do not clone data for the last client
                safe_send(&tx, Ok(Some(broadcast.data.clone())))?;
                if broadcast.id_list.len() < self.n {
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
                if unicast.id < self.n {
                    if self.private[unicast.id].len() < MAX_SIZE {
                        self.private[unicast.id].push(unicast.data);
                    } else {
                        eyre::eyre!("Cannot send data to client {}, queue is full!", unicast.id);
                    }
                } else {
                    eyre::eyre!("Cannot send data to client {}", unicast.id);
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
            .map_err(|err| eyre::eyre!("Receive Error: {:?}", err))?
        {
            Packet::SendRequest(request) => db.manage_send(request),
            Packet::FetchRequest(request) => db.manage_fetch(request)?,
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

/// Send the given data to the client with the given ID. This is a private
/// communication and should use encryption in real applications.
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
    // create communication channels
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
/// Get all the data for the client with the given ID.
/// - `tx`: bus transmission channel
/// - `n`:  number of data to wait
/// - `id`: receiver client ID
pub fn wait_n<T>(tx: &BusTx<T>, n: usize, id: usize) -> Result<Vec<T>> {
    let mut res = Vec::new();
    while n > res.len() {
        // create communication channels
        let (client_tx, client_rx) = mpsc::channel::<Result<Option<T>>>();
        // contact the bus to get the data
        safe_send(tx, Packet::FetchRequest(FetchRequest { id, tx: client_tx }))?;
        // listen for the bus to get the data

        while let Some(data) = client_rx.recv().map_err(|err| eyre::eyre!("{:?}", err))?? {
            res.push(data);
        }
    }
    Ok(res)
}

mod test {
    use eyre::Result;
    use rand::Rng;
    use std::thread;

    fn simulate_send_client(
        id: usize,
        data: &[usize],
        receiver: usize,
        tx: &super::BusTx<usize>,
    ) -> Result<Vec<usize>> {
        // load all data inside the bus
        for &datum in data.iter() {
            super::unicast(tx, receiver, datum)?;
        }

        // get the data sent to this client
        super::get(tx, id)
    }

    fn simulate_broadcast_client(
        id: usize,
        n: usize,
        m: usize,
        tx: &super::BusTx<usize>,
    ) -> Result<Vec<usize>> {
        let data = vec![rand::random(); m];

        // broadcast all data inside the bus
        for &datum in data.iter() {
            super::broadcast(tx, datum)?;
        }

        // get the data sent to this client
        super::wait_n(tx, n * m, id)
    }

    #[test]
    fn test_bus_send() -> Result<()> {
        let n = rand::thread_rng().gen_range(10..20);

        // launch the bus client
        let bus = super::Bus::open(n);

        // use two successive steps in order to assert that data disappears from the bus when it is fetched
        for step in 1..3 {
            // Each client send a random amount of data to another random client.
            let mut clients = Vec::with_capacity(n);
            let mut data =
                vec![vec![rand::random::<usize>(); rand::thread_rng().gen_range(10..20)]; n];
            let receivers = vec![rand::random::<usize>(); n];

            // launch the clients
            for id in 0..n {
                let tx = bus.tx.clone();
                let data = data[id].to_vec();
                let receiver = receivers[id];
                clients.push(thread::spawn(move || {
                    simulate_send_client(id, &data, receiver, &tx)
                }));
            }

            // get the results from the clients
            for (id, client) in clients.into_iter().enumerate() {
                let mut res = Vec::new();
                data.iter_mut().enumerate().for_each(|(i, data)| {
                    if id == receivers[i] {
                        res.append(data);
                    }
                });

                let mut client_res = client.join().unwrap()?;
                res.sort_unstable();
                client_res.sort_unstable();

                eyre::ensure!(
                    res.len() == client_res.len(),
                    "Error in step {}: wrong number of data received!\n
                {}, should be {}",
                    step,
                    client_res.len(),
                    res.len()
                );

                for (res, client_res) in res.iter().zip(client_res.iter()) {
                    eyre::ensure!(res == client_res, "Error: got wrong data from the bus!");
                }
            }
        }

        // close the bus
        bus.close()
    }

    #[test]
    fn test_bus_broadcast() -> Result<()> {
        // launch the bus client
        let n = rand::thread_rng().gen_range(10..20);
        let bus = super::Bus::open(n);

        // use two successive steps in order to assert that data disappears from the bus when it is fetched by all clients
        for step in 1..3 {
            // Each client send a random amount of data to another random client.
            let mut clients = Vec::with_capacity(n);

            // launch the clients
            let m = rand::thread_rng().gen_range(10..20);
            for id in 0..n {
                let tx = bus.tx.clone();
                clients.push(thread::spawn(move || {
                    simulate_broadcast_client(id, n, m, &tx)
                }));
            }

            // get the results from the clients
            let mut res = Vec::with_capacity(n);
            for client in clients.into_iter() {
                res.push(client.join().unwrap()?);
            }

            let mut res_ref: Vec<usize> = res[0].clone();
            res_ref.sort_unstable();

            for client_res in res.iter_mut().skip(1) {
                // assert the size is correct
                eyre::ensure!(
                    res_ref.len() == client_res.len(),
                    "Error in setp {}: wrong number of data received!\n
                {}, should be {}",
                    step,
                    client_res.len(),
                    res[0].len(),
                );
                // assert all clients have received the same data
                client_res.sort_unstable();
                for (res, client_res) in res_ref.iter().zip(client_res.iter()) {
                    eyre::ensure!(res == client_res, "Error: got wrong data from the bus!");
                }
            }
        }

        // close the bus
        bus.close()
    }
}
