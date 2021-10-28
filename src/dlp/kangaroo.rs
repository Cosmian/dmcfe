use crate::tools;
use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
use eyre::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

/// Type of a group point hash value
type Hash = [u8; 32];
/// Hash table used to store precomputed distinguished points.
type Table = HashMap<Hash, Scalar>;
/// Intermediate hash table to store precomputed distinguished points along with
/// with their number of ancestors and the average walk length
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
        // check that bit is 0
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
    // stop when a distinguished point is found
    while !is_distinguished(&P, d) {
        count += 1;
        adding_step(jumps, &mut P, &mut y, G);
    }
    (P, y, count)
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
/// - `dlp_size`:   interval size
/// - `table_size`: table size
/// - `d`:          distinguishing parameter
fn table_worker(
    table: &Arc<Mutex<Table>>,
    jumps: &[Scalar],
    G: &Gt,
    dlp_size: u64,
    table_size: usize,
    d: usize,
) -> Result<()> {
    let mut len = safe_unwrap_lock(table)?.len();
    while len < table_size {
        // raise a new kangaroo
        let y0 = tools::bounded_random_scalar(1, dlp_size)?;

        // let it run
        let (P, y, _) = adding_walk(jumps, G, G * y0, y0, d);

        // set the trap
        if let Ok(mut table) = table.lock() {
            len = table.len();
            match table.insert(hash(&P), y) {
                Some(_) => println!("I: value already in table"),
                None => println!("D: table completion: {}/{}", len, table_size),
            }
        }
    }
    Ok(())
}

/// Worker generating an intermediate table with the given parameters.
/// - `table`:      shared table on which to work
/// - `jumps`:      random jumps
/// - `G`:          `Gt` generator
/// - `dlp_size`:   DLP size
/// - `table_size`: table size
/// - `d`:          distinguishing parameter
/// - `id_thread`:  thread ID
/// - `nb_thread`:  total number of threads
fn intermediate_table_worker(
    table: &Arc<Mutex<IntermediateTable>>,
    jumps: &[Scalar],
    G: &Gt,
    dlp_size: u64,
    table_size: usize,
    d: usize,
    id_thread: usize,
    nb_thread: usize,
) -> Result<()> {
    let mut step = id_thread;
    while step < table_size {
        // raise a new kangaroo
        let y = tools::bounded_random_scalar(1, dlp_size)?;

        // let it run
        let (P, coeff, length) = adding_walk(jumps, G, G * y, y, d);

        // set the trap, update the table
        println!("D: build table {}/{}, W = {}", step, table_size, length);
        if let Ok(mut table) = table.lock() {
            let (count, avg_walk_size);
            match table.get(&hash(&P)) {
                Some(&(_, n, w)) => {
                    avg_walk_size = (((n as f32) * w) + length as f32) / ((n + 1) as f32);
                    count = n + 1;
                    println!("I: Distinguished point already in table, updating the number of ancestors ({})", count + 1);
                }
                None => {
                    count = 1;
                    avg_walk_size = length as f32;
                }
            }
            table.insert(hash(&P), (coeff, count, avg_walk_size));
            step += nb_thread;
        }
    }
    Ok(())
}

/// Generate a table of `table_size` precomputed distinguished points, alongwith
/// with their DLP, number of ancestors and average walk length.
/// - `dlp_size`:   size of the interval
/// - `table_size`: table size
/// - `walk_size`:  walks size
/// - `nb_thread`:  number of threads
/// - `jumps`:      list of random points fot the adding walk
pub fn gen_intermediate_table(
    dlp_size: u64,
    table_size: usize,
    walk_size: usize,
    nb_thread: usize,
    jumps: &[Scalar],
) -> Result<IntermediateTable> {
    // `Gt` group generator
    let G = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(walk_size);
    let mut handles = Vec::with_capacity(nb_thread);

    // precomputed table
    let table = Arc::new(Mutex::new(HashMap::with_capacity(table_size)));

    for id in 0..nb_thread {
        let (jumps, table) = (jumps.to_vec(), table.clone());

        handles.push(thread::spawn(move || {
            intermediate_table_worker(&table, &jumps, &G, dlp_size, table_size, d, id, nb_thread)
        }));
    }

    for handle in handles {
        handle.join()
            .map_err(|err| eyre::eyre!("Error in worker thread: {:?}", err))??;
    }

    let table = safe_unwrap_lock(&table)?;
    Ok(table)
}

/// Reorder the given vector of `((T, U), i)` elements given `i`.
/// Return the vector of `(T, U)` elements.
/// - `v`:  vector to sort
fn reorder<T: Clone, U: Clone>(v: &mut [((T, U), usize)]) -> Vec<(T, U)> {
    v.sort_by_key(|vi| vi.1);
    v.iter().map(|vi| vi.0.clone()).collect()
}

/// Sort the given intermediate table into a bucket list using the number of point ancestors.
/// - `table`:  intermediate table
fn fill_buckets(table: IntermediateTable) -> Vec<Vec<((Hash, Scalar), usize)>> {
    // store all the points inside buckets
    let mut buckets = Vec::new();
    for (k, (s, count, length)) in table {
        // add more buckets if needed
        if count > buckets.len() {
            buckets.append(&mut vec![Vec::new(); count - buckets.len()]);
        }
        // store `((Y, y), w)` in the bucket given by `count`
        buckets[count - 1].push(((k, s), length.floor() as usize));
    }
    buckets
}

/// Generate the final improved table with the given size from the given bucket list.
/// - `buckets`:    bucket list
/// - `table_size`: finale improved table size
fn get_table_from_buckets(
    buckets: &mut [Vec<((Hash, Scalar), usize)>],
    table_size: usize,
) -> (Table, Vec<usize>) {
    // use the `t` most visited points to build the hash table
    let mut table = HashMap::with_capacity(table_size);
    let mut ancestors = Vec::with_capacity(table_size);
    let mut count = buckets.len();
    while table.len() < table_size && count > 0 {
        // decrementing the count first allows using it to index the list
        count -= 1;
        // sort the points by average walk length to keep the sortest walks
        for (P, y) in reorder(&mut buckets[count]) {
            if table.len() < table_size {
                println!(
                    "D: picking a distinguished point with {} ancestors.",
                    count + 1
                );
                table.insert(P, y);
                ancestors.push(count);
            }
        }
    }
    (table, ancestors)
}

// Display information about selected points' ancestors.
// - `ancestors`:   list of number of ancestors
fn display_ancestors_info(ancestors: &[usize]) {
    let mut n_ancestors_list = vec![0; ancestors[0] + 1];
    for &n_ancestors in ancestors {
        n_ancestors_list[n_ancestors] += 1;
    }

    for (count, &n_ancestors) in n_ancestors_list.iter().rev().enumerate() {
        if n_ancestors != 0 {
            println!(
                "I: {:.0}% points chosen with {} ancestors ({}).",
                100. * (n_ancestors as f32) / (ancestors.len() as f32),
                n_ancestors_list.len() - count,
                n_ancestors
            );
        }
    }
}

/// Extract the final imroved table from the given intermediate table.
/// - `intermediate_table`: intermediate table
/// - `table_size`:         final table length
fn extract_table(intermediate_table: IntermediateTable, table_size: usize) -> Table {
    println!("N: extract table.");
    let mut buckets = fill_buckets(intermediate_table);
    let (table, ancestors) = get_table_from_buckets(&mut buckets, table_size);
    println!("I: table size: {}", table.len());
    display_ancestors_info(&ancestors);
    table
}

/// Generate an improved table with the given parameters.
/// - `dlp_size`:       DLP size
/// - `table_size`:     table size
/// - `walk_size`:      average walk size
/// - `repetitions`:    repetition factor for the intermediate table
/// - `nb_thread`:      number of threads
/// - `jumps`:          random jumps
pub fn gen_improved_table(
    dlp_size: u64,
    table_size: usize,
    walk_size: usize,
    repetitions: usize,
    nb_thread: usize,
    jumps: &[Scalar],
) -> Result<Table> {
    println!(
        "N: computing table with parameters L = {}, T = {}, W = {}, U = {}",
        dlp_size, table_size, walk_size, repetitions
    );
    let intermediate_table = gen_intermediate_table(
        dlp_size,
        table_size * repetitions,
        walk_size,
        nb_thread,
        jumps,
    )?;
    write_intermediate_table(
        &Path::new(&format!(
            "intermediate_table_{}_{}_{}_{}",
            dlp_size, table_size, walk_size, repetitions
        )),
        &intermediate_table,
    )?;
    Ok(extract_table(intermediate_table, table_size))
}

/// Generate a table of `T` precomputed distinguished points, along with their DLP.
/// - `dlp_size`:          size of the interval
/// - `table_size`: table size
/// - `walk_size`:  walks size
/// - `nb_thread`:  number of threads
/// - `jumps`:      list of random points fot the adding walk
pub fn gen_table(
    dlp_size: u64,
    table_size: usize,
    walk_size: usize,
    nb_thread: usize,
    jumps: &[Scalar],
) -> Result<Table> {
    // `Gt` group generator
    let g = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(walk_size);
    let mut handles = Vec::with_capacity(nb_thread);

    // precomputed table
    let table = Arc::new(Mutex::new(HashMap::with_capacity(table_size)));

    for _ in 0..nb_thread {
        let (jumps, table) = (jumps.to_vec(), table.clone());
        handles.push(thread::spawn(move || {
            table_worker(&table, &jumps, &g, dlp_size, table_size, d)
        }));
    }

    for handle in handles {
        handle.join()
            .map_err(|err| eyre::eyre!("Error in worker thread: {:?}", err))??;
    }

    let table = safe_unwrap_lock(&table)?;
    Ok(table)
}

/// Write the given precomputed table to the file with the given name.
/// - `filename`:   name of the file
/// - `table`:      precomputed table
pub fn write_table<P>(filename: &P, table: &Table) -> Result<()>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in write-only mode.
    // Erase previous file with the same name.
    let mut file = match File::create(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
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

/// Write the given precomputed intermediate table to the file with the given name.
/// - `filename`:   name of the file
/// - `table`:      precomputed intermediate table
pub fn write_intermediate_table<P>(filename: &P, table: &IntermediateTable) -> Result<()>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in write-only mode.
    // Erase previous file with the same name.
    let mut file = match File::create(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
        Ok(file) => Ok(file),
    }?;

    for (key, value) in table {
        eyre::ensure!(
            key.len() == file.write(key)?,
            "Couldn't write all bytes for the hash table key: {:?}",
            key
        );
        eyre::ensure!(
            32 == file.write(&value.0.to_bytes())?,
            "Couldn't write all bytes for the hash table value: {:?}",
            value.0
        );
        eyre::ensure!(
            8 == file.write(&(value.1 as u64).to_be_bytes())?,
            "Couldn't write all bytes for the hash table value: {:?}",
            value.1
        );
        eyre::ensure!(
            4 == file.write(&value.2.to_be_bytes())?,
            "Couldn't write all bytes for the hash table value: {:?}",
            value.2
        );
    }
    Ok(())
}

/// Read the precomputed intermediate table from the file with the given name.
/// - `filename`:   name of the file
pub fn read_intermediate_table<P>(filename: &P) -> Result<IntermediateTable>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in read-only mode
    let mut file = match File::open(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
        Ok(file) => Ok(file),
    }?;

    let mut table = HashMap::new();
    let (mut key, mut value) = ([0u8; 32], ([0u8; 32], [0u8; 8], [0u8; 4]));

    while key.len() == file.read(&mut key)? {
        eyre::ensure!(
            value.0.len() == file.read(&mut value.0)?,
            "Couldn't read all bytes of the value corresponding to the key: {:?}",
            key
        );

        eyre::ensure!(
            value.1.len() == file.read(&mut value.1)?,
            "Couldn't read all bytes of the value corresponding to the key: {:?}",
            key
        );

        eyre::ensure!(
            value.2.len() == file.read(&mut value.2)?,
            "Couldn't read all bytes of the value corresponding to the key: {:?}",
            key
        );

        let s = Scalar::from_bytes(&value.0);
        if s.is_some().into() {
            table.insert(
                key,
                (
                    s.unwrap(),
                    u64::from_be_bytes(value.1) as usize,
                    f32::from_be_bytes(value.2),
                ),
            );
        } else {
            eyre::eyre!("Couldn't convert read bytes into scalar! {:?}", value);
        }
    }

    Ok(table)
}

/// Read the precomputed table from the file with the given name.
/// - `filename`:   name of the file
pub fn read_table<P>(filename: &P) -> Result<Table>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in read-only mode
    let mut file = match File::open(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
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
            eyre::eyre!("Couldn't convert read bytes into scalar! {:?}", value);
        }
    }

    Ok(table)
}

/// Generate `k` random jumps. The mean of their indices should be
/// comparable with `sqrt(l)`, where `l` is the size of the interval on
/// which the DLP is solved.
/// - `dlp_size`:   interval size
/// - `k`:          number of points to generate
pub fn gen_jumps(dlp_size: u64, k: usize) -> Result<Vec<Scalar>> {
    // uniform distribution in `[0, 2*sqrt(l)]`
    let max = 2 * (dlp_size as f64).sqrt() as u64;
    (0..k)
        .map(|_| tools::bounded_random_scalar(1, max))
        .collect()
}

/// Write the given jumps to the file with the given name.
/// - `filename`:   name of the file
/// - `table`:      jumps
pub fn write_jumps<P>(filename: &P, jumps: &[Scalar]) -> Result<()>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in write-only mode.
    // Erase previous file with the same name.
    let mut file = match File::create(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
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
pub fn read_jumps<P>(filename: &P) -> Result<Vec<Scalar>>
where
    P: AsRef<Path> + Debug,
{
    // Open the path in read-only mode
    let mut file = match File::open(filename) {
        Err(why) => Err(eyre::eyre!("Couldn't open {:?}: {}", filename, why)),
        Ok(file) => Ok(file),
    }?;

    let mut jumps = Vec::new();
    let mut jump = [0u8; 32];
    while jump.len() == file.read(&mut jump)? {
        let s = Scalar::from_bytes(&jump);
        if s.is_some().into() {
            jumps.push(s.unwrap());
        } else {
            eyre::eyre!("Couldn't convert read bytes into scalar! {:?}", jump);
        }
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
) -> Result<()> {
    let mut step = id;
    while Scalar::zero() == safe_unwrap_lock(res)? {
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
                    if let Ok(mut res) = res.lock() {
                        *res = x - y;
                    }
                }
            }
            None => println!("I: value not in the table."),
        }

        step += nb_thread;
    }
    Ok(())
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
) -> Result<Scalar> {
    // `Gt` group generator
    let G = pairing(&G1Affine::generator(), &G2Affine::generator());
    let d = get_distinguishing_parameter(walk_size);
    let mut handles = Vec::with_capacity(nb_thread);

    // assert 0 is not the solution of the DLP
    if *H == G * Scalar::zero() {
        return Ok(Scalar::zero());
    }

    // use 0 as neutral value
    let res = Arc::new(Mutex::new(Scalar::zero()));
    let nb_thread = nb_thread as u64;

    for id in 0..nb_thread {
        let (res, H) = (res.clone(), *H);
        let (jumps, table) = (jumps.to_vec(), table.clone());

        handles.push(thread::spawn(move || {
            hunter(&res, &table, &jumps, &G, &H, d, id, nb_thread)
        }));
    }

    for handle in handles {
        handle
            .join()
            .map_err(|err| eyre::eyre!("Error in hunter thread: {:?}", err))??;
    }

    safe_unwrap_lock(&res)
}

fn safe_unwrap_lock<T: Default + Clone>(mutex: &Arc<Mutex<T>>) -> Result<T> {
    let mut s = Default::default();
    if let Ok(res) = mutex.lock() {
        s = res.clone();
    } else {
        eyre::eyre!("Could not unwrap final result!");
    }
    Ok(s)
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
