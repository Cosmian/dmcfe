use crate::tools;
use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
use eyre::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

/// Type of a group point hash value
type Hash = [u8; 32];
/// Hash table used to store precomputed distinguished points.
type Table = HashMap<Hash, Scalar>;

type IntermediateTable = HashMap<Hash, (Scalar, usize, f32)>;

/// Hash function for a point on `Gt`
fn hash(P: &Gt) -> Hash {
    Sha256::digest(&P.to_compressed()).into()
}

/// Find the partition associated to the given point.
/// - `P`:  `Gt` point
/// - `n`:  number of partitions
fn partition(P: &Gt, n: usize) -> usize {
    let res: Hash = hash(P);
    (res[0] as usize) % n
}

/// Return true if the last d bits of the big-endian representation of
/// the first coordinate of `P` are 0s.
/// This approximatively corresponds to the ratio $|D|/|Gt|$.
/// - `P`:  `Gt` point
/// - `d`:  number of bits to check
fn is_distinguished(P: &Gt, d: usize) -> bool {
    // byte representation in big-endian order
    let b: Hash = hash(P);
    for bit in 0..d {
        if (b[b.len() - (bit / 8) - 1] >> (bit % 8)) % 2 == 1 {
            return false;
        }
    }
    true
}

/// Compute a random adding-walk step.
/// - `jumps`:  random jumps
/// - `P`:      previous step in the walk
/// - `y`:      coefficient of `g` in the previous step in the walk
/// - `G`:      `Gt` group generator
fn adding_step(jumps: &[Scalar], P: &mut Gt, y: &mut Scalar, G: &Gt) {
    let e = jumps[partition(P, jumps.len())];
    *P += G * e;
    *y += e;
}

/// Compute a r-adding walk of length `w`.
/// - `jumps`:  random jumps
/// - `G`:      `Gt` generator
/// - `P0`:     first point in the walk
/// - `y0`:     exponent of `g` in the first point in the walk
/// - `d`:      distinguishing parameter
fn adding_walk(jumps: &[Scalar], G: &Gt, P0: Gt, y0: Scalar, d: usize) -> (Gt, Scalar, usize) {
    let (mut P, mut y, mut count) = (P0, y0, 0);
    loop {
        // stop when a distinguished point is found
        if is_distinguished(&P, d) {
            return (P, y, count);
        } else {
            count += 1;
            adding_step(jumps, &mut P, &mut y, G);
        }
    }
}

/// Compute the distinguishing parameter from W.
/// - `walk_size`:  walk size
fn get_distinguishing_parameter(walk_size: usize) -> usize {
    (walk_size as f64).log2().floor() as usize
}

/// Worker generating a table with the given parameters.
/// - `table`:      shared table on which to work
/// - `jumps`:      random jumps
/// - `G`:          `Gt` generator
/// - `l`:          interval size
/// - `table_size`: table size
/// - `d`:          distinguishing parameter
fn table_worker(
    table: &Arc<Mutex<Table>>,
    jumps: &[Scalar],
    G: &Gt,
    l: u64,
    table_size: usize,
    d: usize,
) -> Result<()> {
    let mut len = table.lock().unwrap().len();
    while len < table_size {
        // raise a new kangaroo
        let y0 = tools::bounded_random_scalar(1, l)?;

        // let it run
        let (P, y, _) = adding_walk(jumps, G, G * y0, y0, d);

        // set the trap
        let mut table = table.lock().unwrap();
        len = table.len();
        match table.insert(hash(&P), y) {
            Some(_) => println!("I: value already in table"),
            None => println!("Table completion: {}/{}", len, table_size),
        }
    }
    Ok(())
}

/// Worker generating a table with the given parameters.
/// - `table`:  shared table on which to work
/// - `jumps`:  random jumps
/// - `g`:      `Gt` generator
/// - `l`:      interval size
/// - `t`:      table size
/// - `d`:      distinguishing parameter
fn intermediate_table_worker(
    table: &Arc<Mutex<IntermediateTable>>,
    jumps: &[Scalar],
    g: &Gt,
    l: u64,
    t: usize,
    d: usize,
    id: usize,
    nb_thread: usize,
) -> Result<()> {
    let mut step = id;
    while step < t {
        // raise a new kangaroo
        let y = tools::bounded_random_scalar(1, l)?;

        // let it run
        let (P, coeff, length) = adding_walk(jumps, g, g * y, y, d);
        println!("Build table {}/{}, W = {}", step, t, length);

        // set the trap, update the table
        let mut table = table.lock().unwrap();
        let (count, avg_walk_size);
        match table.get(&hash(&P)) {
            Some((_, n, w)) => {
                avg_walk_size = (((*n as f32) * w) + length as f32) / ((n + 1) as f32);
                count = *n + 1;
                println!("I: Distinguished point already in table, updating the number of ancestors ({})", count + 1);
            }
            None => {
                count = 0;
                avg_walk_size = length as f32;
            }
        }
        table.insert(hash(&P), (coeff, count, avg_walk_size as f32));
        step += nb_thread;
    }
    Ok(())
}

/// Generate a table of `T` precomputed distinguised points, along with their DLP.
/// - `l`:      size of the interval
/// - `t`:      table size
/// - `w`:      walks size
/// - `n`:      number of threads
/// - `jumps`:  list of random points fot the adding walk
pub fn gen_intermediate_table(
    l: u64,
    t: usize,
    w: usize,
    n: usize,
    jumps: &[Scalar],
) -> Result<IntermediateTable> {
    // `Gt` group generator
    let g = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(w);
    let mut handles = Vec::new();

    // precomputed table
    let table = Arc::new(Mutex::new(HashMap::with_capacity(t)));

    for id in 0..n {
        let (jumps, table) = (jumps.to_vec(), table.clone());

        handles.push(thread::spawn(move || {
            intermediate_table_worker(&table, &jumps, &g, l, t, d, id, n)
        }));
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(table.clone().lock().unwrap().clone())
}

/// Reorder the given vector of `(T, i)` elements given `i`.
/// Return the vector of `T` elements.
/// - `v`:  vector to sort
fn reorder<T: Clone, U: Clone>(v: &mut [((T, U), usize)]) -> Vec<(T, U)> {
    v.sort_by_key(|vi| vi.1);
    v.iter().map(|vi| vi.0.clone()).collect()
}

fn extract_table(table: IntermediateTable, t: usize) -> Result<Table> {
    println!("I: extract table.");
    // store all the points inside buckets
    let mut buckets = Vec::new();
    for (k, (s, count, length)) in table {
        // add more buckets if needed
        if count >= buckets.len() {
            buckets.append(&mut vec![Vec::new(); count - buckets.len() + 1]);
        }
        // store `(Y, y)` in the bucket given by `count`
        buckets[count].push(((k, s), length.floor() as usize));
    }

    // use the `t` most visited points to build the hash table
    let mut table = HashMap::new();
    let mut count = buckets.len();
    while table.len() < t && count > 0 {
        count -= 1;
        // sort the points by average walk length to keep the sortest walks
        for (P, y) in reorder(&mut buckets[count]) {
            if table.len() < t {
                println!(
                    "I: picking a distinguished point with {} ancestors.",
                    count + 1
                );
                table.insert(P, y);
            }
        }
    }

    println!("Table size: {}", table.len());
    Ok(table)
}

pub fn gen_improved_table(
    l: u64,
    t: usize,
    w: usize,
    u: usize,
    n: usize,
    jumps: &[Scalar],
) -> Result<Table> {
    extract_table(gen_intermediate_table(l, t * u, w, n, jumps)?, t)
}

/// Generate a table of `T` precomputed distinguised points, along with their DLP.
/// - `l`:          size of the interval
/// - `table_size`: table size
/// - `walk_size`:  walks size
/// - `nb_thread`:  number of threads
/// - `jumps`:      list of random points fot the adding walk
pub fn gen_table(
    l: u64,
    table_size: usize,
    walk_size: usize,
    nb_thread: usize,
    jumps: &[Scalar],
) -> Result<Table> {
    // `Gt` group generator
    let g = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(walk_size);
    let mut handles = Vec::new();

    // precomputed table
    let table = Arc::new(Mutex::new(HashMap::with_capacity(table_size)));

    for _ in 0..nb_thread {
        let (jumps, table) = (jumps.to_vec(), table.clone());
        handles.push(thread::spawn(move || {
            table_worker(&table, &jumps, &g, l, table_size, d)
        }));
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    let table = table.lock().unwrap().clone();
    Ok(table)
}

/// Write the given precomputed table to the file with the given name.
/// - `filename`:   name of the file
/// - `table`:      precomputed table
pub fn write_table(filename: &Path, table: &Table) -> Result<()> {
    // Open the path in write-only mode.
    // Erase previous file with the same name.
    let mut file = match File::create(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename.display(), why)),
        Ok(file) => Ok(file),
    }?;

    for (key, value) in table {
        eyre::ensure!(
            key.len() == file.write(key)?,
            "Couldn't write all bytes for the hash table key: {:?}",
            key
        );
        eyre::ensure!(
            32 == file.write(&value.to_bytes())?,
            "Couldn't write all bytes for the hash table value: {:?}",
            value
        );
    }
    Ok(())
}

/// Read the precomputed table from the file with the given name.
/// - `filename`:   name of the file
pub fn read_table(filename: &Path) -> Result<Table> {
    // Open the path in read-only mode
    let mut file = match File::open(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename.display(), why)),
        Ok(file) => Ok(file),
    }?;

    let mut table = HashMap::new();
    let (mut key, mut value) = ([0u8; 32], [0u8; 32]);

    while key.len() == file.read(&mut key)? {
        eyre::ensure!(
            value.len() == file.read(&mut value)?,
            "Couldn't read all bytes of the value corresponding to the key: {:?}",
            key
        );

        let s = Scalar::from_bytes(&value);
        if s.is_some().into() {
            table.insert(key, s.unwrap());
        } else {
            eyre::eyre!("Error while converting read bytes into scalar! {:?}", value);
        }
    }

    Ok(table)
}

/// Generate `k` random jumps. The mean of their indices should be
/// comparable with `sqrt(l)`, where `l` is the size of the interval on
/// which the DLP is solved.
/// - `l`:  interval size
/// - `k`:  number of points to generate
pub fn gen_jumps(l: u64, k: usize) -> Result<Vec<Scalar>> {
    // uniform distribution in `[0, 2*sqrt(l)]`
    let max = 2 * (l as f64).sqrt() as u64;
    (0..k)
        .map(|_| tools::bounded_random_scalar(1, max))
        .collect()
}

/// Write the given jumps to the file with the given name.
/// - `filename`:   name of the file
/// - `table`:      jumps
pub fn write_jumps(filename: &Path, jumps: &[Scalar]) -> Result<()> {
    // Open the path in write-only mode.
    // Erase previous file with the same name.
    let mut file = match File::create(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename.display(), why)),
        Ok(file) => Ok(file),
    }?;

    for jump in jumps {
        eyre::ensure!(
            32 == file.write(&jump.to_bytes())?,
            "Couldn't write all bytes for the jump: {:?}",
            jump
        );
    }
    Ok(())
}

/// Read the jumps from the file with the given name.
/// - `filename`:   name of the file
pub fn read_jumps(filename: &Path) -> Result<Vec<Scalar>> {
    // Open the path in read-only mode
    let mut file = match File::open(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename.display(), why)),
        Ok(file) => Ok(file),
    }?;

    let mut jumps = Vec::new();
    let mut jump = [0u8; 32];
    while jump.len() == file.read(&mut jump)? {
        let s = Scalar::from_bytes(&jump).unwrap_or(Scalar::zero());

        eyre::ensure!(
            s != Scalar::zero(),
            "Error while converting read bytes into scalar! {:?}",
            jump
        );

        jumps.push(s);
    }

    Ok(jumps)
}

/// Launch wild kangaroos until a match is found.
/// - `res`:        solution
/// - `table`:      precomputed table
/// - `jumps`:      random jumps
/// - `G`:          `Gt` generator
/// - `H`:          DLP
/// - `d`:          distinguishing parameter
/// - `id`:         thread ID
/// - `nb_thread`:  number of threads
fn hunter(
    res: &Arc<Mutex<Scalar>>,
    table: &Table,
    jumps: &[Scalar],
    G: &Gt,
    H: &Gt,
    d: usize,
    id: u64,
    nb_thread: u64,
) {
    let mut step = id;
    while Scalar::zero() == *res.lock().unwrap() {
        // wild kangaroo
        let y0 = Scalar::from_raw([step, 0, 0, 0]);
        let P0 = H + G * y0;

        // let it run
        let (P, y, _) = adding_walk(jumps, G, P0, y0, d);

        // check the traps
        match table.get(&hash(&P)) {
            Some(&x) => {
                // check against false positive match due to the hash
                if G * x == H + G * y {
                    *res.lock().unwrap() = x - y;
                }
            }
            None => println!("I: value not in the table."),
        }

        step += nb_thread;
    }
}

/// Solve the DLP using the kangaroo method.
/// - `table`:      precomputed table
/// - `jumps`:      random jumps
/// - `H`:          DLP
/// - `walk_size`:  walk size
/// - `nb_thread`:  number of threads
pub fn solve(
    table: &Table,
    jumps: &[Scalar],
    H: &Gt,
    walk_size: usize,
    nb_thread: usize,
) -> Scalar {
    // `Gt` group generator
    let G = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(walk_size);
    let mut handles = Vec::with_capacity(nb_thread);

    // assert 0 is not the solution of the DLP
    if *H == G * Scalar::zero() {
        return Scalar::zero();
    }

    // use 0 as neutral value
    let res = Arc::new(Mutex::new(Scalar::zero()));
    let nb_thread = nb_thread as u64;

    for id in 0..nb_thread {
        let (res, H) = (res.clone(), *H);
        let (jumps, table) = (jumps.to_vec(), table.clone());

        handles.push(thread::spawn(move || {
            hunter(&res, &table, &jumps, &G, &H, d, id, nb_thread);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let res = *res.lock().unwrap();
    res
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_distinguished() -> eyre::Result<()> {
        // replace the `Gt` point by a bit-string for easier testing
        fn is_distinguished_stubbed(b: &[u8], d: usize) -> bool {
            for bit in 0..d {
                if (b[b.len() - (bit / 8) - 1] >> (bit % 8)) % 2 == 1 {
                    return false;
                }
            }
            true
        }

        eyre::ensure!(
            is_distinguished_stubbed(&0b0110101101010000u16.to_be_bytes(), 4),
            "Wrong decision"
        );

        eyre::ensure!(
            !is_distinguished_stubbed(&0b0110101101010000u16.to_be_bytes(), 5),
            "Wrong decision"
        );

        Ok(())
    }
}
