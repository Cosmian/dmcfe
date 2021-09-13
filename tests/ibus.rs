#![cfg(test)]
use dmcfe::ibus;
use eyre::Result;
use rand::Rng;
use std::thread;

fn simulate_send_client(
    id: usize,
    data: &[usize],
    receiver: usize,
    bus_tx: &ibus::Sender<usize>,
) -> Result<Vec<usize>> {
    // load all data inside the bus
    for &datum in data.iter() {
        ibus::send(bus_tx, receiver, datum)?;
    }

    // get the data sent to this client
    ibus::get(bus_tx, id)
}

fn simulate_broadcast_client(
    id: usize,
    n: usize,
    m: usize,
    bus_tx: &ibus::Sender<usize>,
) -> Result<Vec<usize>> {
    let data = vec![rand::random(); m];

    // broadcast all data inside the bus
    for &datum in data.iter() {
        ibus::broadcast(bus_tx, datum)?;
    }

    // get the data sent to this client
    let mut res = Vec::with_capacity(n);
    while res.len() < n * m {
        res.append(&mut ibus::get(&bus_tx, id)?)
    }
    Ok(res)
}

#[test]
fn test_ibus_send() -> Result<()> {
    let n = rand::thread_rng().gen_range(10..20);

    // launch the ibus client
    let (bus, bus_tx) = ibus::open(n);

    // use two successive steps in order to assert that data disappears from the bus when it is fetched
    for step in 1..3 {
        // Each client send a random amount of data to another random client.
        let mut clients = Vec::with_capacity(n);
        let mut data = vec![vec![rand::random::<usize>(); rand::thread_rng().gen_range(10..20)]; n];
        let receivers = vec![rand::random::<usize>(); n];

        // launch the clients
        for id in 0..n {
            let bus_tx = bus_tx.clone();
            let data = data[id].to_vec();
            let receiver = receivers[id];
            clients.push(thread::spawn(move || {
                simulate_send_client(id, &data, receiver, &bus_tx)
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
            res.sort();
            client_res.sort();

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
    ibus::close(bus, bus_tx)
}

#[test]
fn test_ibus_broadcast() -> Result<()> {
    // launch the ibus client
    let n = rand::thread_rng().gen_range(10..20);
    let (bus, bus_tx) = ibus::open(n);

    // use two successive steps in order to assert that data disappears from the bus when it is fetched by all clients
    for step in 1..3 {
        // Each client send a random amount of data to another random client.
        let mut clients = Vec::with_capacity(n);

        // launch the clients
        let m = rand::thread_rng().gen_range(10..20);
        for id in 0..n {
            let bus_tx = bus_tx.clone();
            clients.push(thread::spawn(move || {
                simulate_broadcast_client(id, n, m, &bus_tx)
            }));
        }

        // get the results from the clients
        let mut res = Vec::with_capacity(n);
        for client in clients.into_iter() {
            res.push(client.join().unwrap()?);
        }

        let mut res_ref: Vec<usize> = res[0].clone();
        res_ref.sort();

        println!("{}", n * m);
        for client_res in res.iter_mut() {
            println!("{}", client_res.len());
        }

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
            client_res.sort();
            for (res, client_res) in res_ref.iter().zip(client_res.iter()) {
                eyre::ensure!(res == client_res, "Error: got wrong data from the bus!");
            }
        }
    }

    // close the bus
    ibus::close(bus, bus_tx)
}
