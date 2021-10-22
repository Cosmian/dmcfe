const SHA256_SIZE: usize = 32;

/// Implement the Baby Step Giant Step algorithm to solve the DLP.
pub mod bsgs {
    use crate::tools;
    use bls12_381::{G1Affine, G1Projective};
    use eyre::Result;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    /// Hash a point in `G1`.
    /// - `P`:  point in `G1`
    fn hash(P: &G1Projective) -> [u8; super::SHA256_SIZE] {
        Sha256::digest(&G1Affine::to_compressed(&G1Affine::from(P))).into()
    }

    /// This algorithm imlements the iteration fonction of the BSGS algorithm.
    /// This algorithm implements the precomputation step of the BSGS algorithms.
    /// It returns a hashed map containing all the precomputed pairs.
    ///
    /// - `m`:  number of pairs to precompute
    ///
    /// See [the notes on DLP](crate::notes::dlp) for more explanations
    fn precomputation(m: u32) -> Result<HashMap<[u8; super::SHA256_SIZE], u32>> {
        let G = G1Projective::generator();
        let mut pairs = HashMap::new();
        let mut P_i = G1Projective::identity();
        for i in 0..m {
            if let Some(j) = pairs.insert(hash(&P_i), i) {
                eyre::bail!(
                    "Hash collision during the precomputation step of the BSGS!\n
            `H(P_i) = H(P_j)`, where `i={}` and `j={}`",
                    i,
                    j
                );
            }
            P_i += G;
        }
        Ok(pairs)
    }

    ///
    /// - `P`:      right term of the DLP
    /// - `Q`:      inverse of `g^m`
    /// - `n`:      the number of iterations
    /// - `pairs`:  hash table containg the precomputed values
    fn iterate(
        P: &G1Projective,
        Q: &G1Projective,
        n: u32,
        pairs: &HashMap<[u8; super::SHA256_SIZE], u32>,
    ) -> Option<(u32, u32)> {
        let mut res = None;
        let mut giant_step = 0;
        let mut Q_k = G1Projective::identity();
        let mut P_k = Q_k + P;
        while giant_step < n {
            res = pairs.get(&hash(&P_k));
            if res.is_some() {
                break;
            } else {
                giant_step += 1;
                Q_k += Q;
                P_k = Q_k + P;
            }
        }
        res.map(|baby_step| (giant_step, *baby_step))
    }

    /// This algorithm implements the BSGS algorithm. It aims to find `x` such that
    /// `x.g = p`, where `g` is the generator of `G1`, `p` is given and `x < M`
    /// with `M = mn` is not too big.
    ///
    /// `u32` are used to reduce the space required by the hash table in the
    /// iteration process. Indeed, the solution of the DLP for a number greater
    /// than an `U^2` where `U` is the greatest `u32` is not considered computable.
    ///
    /// `P`:  right member of the DLP equation
    /// `m`:  `u32` such that `x < mn`
    /// `n`:  `u32` such that `x < mn`
    pub fn solve(P: &G1Projective, m: u32, n: u32) -> Result<u64> {
        // define some heuristics
        // e.g. test the case where the solution is 1

        let pairs = precomputation(m)?;
        let Q = tools::get_inverse(&tools::double_and_add(&G1Projective::generator(), m as u64));
        let (giant_step, baby_step) = iterate(P, &Q, n, &pairs).ok_or_else(|| {
            eyre::eyre!(
                "Cannot find any solution `x` to the DLP such that `x < ({} * {})`!",
                m,
                n
            )
        })?;
        Ok((giant_step as u64) * (m as u64) + (baby_step as u64))
    }
}

pub mod kangaroo {
    use crate::tools;
    use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};
    use eyre::Result;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Hash table used to store precomputed distinguished points.
    type Table = HashMap<[u8; super::SHA256_SIZE], Scalar>;
    type Jumps = Vec<Scalar>;

    /// Hash function for a point on `Gt`
    fn hash(P: &Gt) -> [u8; super::SHA256_SIZE] {
        Sha256::digest(&P.to_compressed()).into()
    }

    /// Find the partition associated to the given point.
    /// - `P`:  `Gt` point
    /// - `n`:  number of partitions
    fn partition(P: &Gt, n: usize) -> usize {
        let res: [u8; super::SHA256_SIZE] = hash(P);
        (res[0] as usize) % n
    }

    /// Return true if the last d bits of the big-endian representation of
    /// the first coordinate of `P` are 0s.
    /// This approximatively corresponds to the ratio $|D|/|Gt|$.
    /// - `P`:  `Gt` point
    /// - `d`:  number of bits to check
    fn is_distinguished(P: &Gt, d: usize) -> bool {
        // byte representation in big-endian order
        let b: [u8; super::SHA256_SIZE] = hash(P);
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
    /// - `g`:      `Gt` group generator
    fn adding_step(jumps: &Jumps, P: &mut Gt, y: &mut Scalar, g: &Gt) {
        let e = jumps[partition(P, jumps.len())];
        *P += g * e;
        *y += e;
    }

    /// Compute a r-adding walk of length `w`.
    /// - `jumps`:  random jumps
    /// - `g`:      `Gt` generator
    /// - `P0`:     first point in the walk
    /// - `y0`:     exponent of `g` in the first point in the walk
    /// - `d`:      distinguishing parameter
    fn adding_walk(jumps: &Jumps, g: &Gt, P0: Gt, y0: Scalar, d: usize) -> (Gt, Scalar) {
        let (mut P, mut y) = (P0, y0);
        loop {
            // stop when a distinguished point is found
            if is_distinguished(&P, d) {
                return (P, y);
            } else {
                adding_step(jumps, &mut P, &mut y, g);
            }
        }
    }

    /// Compute the distinguishing parameter from W.
    /// - `w`:  walk size
    fn get_distinguishing_parameter(w: usize) -> usize {
        (w as f64).log2().floor() as usize
    }

    /// Worker generating a table with the given parameters.
    /// - `table`:  shared table on which to work
    /// - `jumps`:  random jumps
    /// - `g`:      `Gt` generator
    /// - `l`:      interval size
    /// - `t`:      table size
    /// - `d`:      distinguishing parameter
    fn table_worker(
        table: &Arc<Mutex<Table>>,
        jumps: &Jumps,
        g: &Gt,
        l: u64,
        t: usize,
        d: usize,
    ) -> Result<()> {
        let mut len = table.lock().unwrap().len();
        while len < t {
            // raise a new kangaroo
            let y0 = tools::bounded_random_scalar(1, l)?;

            // let it run
            let (P, y) = adding_walk(&jumps, &g, g * y0, y0, d);

            // set the trap
            let mut table = table.lock().unwrap();
            len = table.len();
            match table.insert(hash(&P), y) {
                Some(_) => println!("I: value already in table"),
                None => println!("Table completion: {}/{}", len, t),
            }
        }
        Ok(())
    }

    /// Generate a table of `T` precomputed distinguised points, along with their DLP.
    /// - `l`:      size of the interval
    /// - `t`:      table size
    /// - `w`:      walks size
    /// - `n`:      number of threads
    /// - `jumps`:  list of random points fot the adding walk
    pub fn gen_table(l: u64, t: usize, w: usize, n: usize, jumps: &Jumps) -> Result<Table> {
        // `Gt` group generator
        let g = pairing(&G1Affine::generator(), &G2Affine::generator());
        let d = get_distinguishing_parameter(w);
        let mut handles = Vec::new();

        // precomputed table
        let table = Arc::new(Mutex::new(HashMap::with_capacity(t)));

        for _ in 0..n {
            let (jumps, table) = (jumps.to_vec(), table.clone());
            handles.push(thread::spawn(move || {
                table_worker(&table, &jumps, &g, l, t, d)
            }));
        }

        for handle in handles {
            handle.join().unwrap()?;
        }

        Ok(table.clone().lock().unwrap().clone())
    }

    /// Write the given precomputed table to the file with the given name.
    /// - `filename`:   name of the file
    /// - `table`:      precomputed table
    pub fn write_table(filename: &str, table: &Table) -> Result<()> {
        // Open the path in write-only mode.
        // Erase previous file with the same name.
        let mut file = match File::create(filename) {
            Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename, why)),
            Ok(file) => Ok(file),
        }?;

        for (key, value) in table {
            eyre::ensure!(
                super::SHA256_SIZE == file.write(key)?,
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
    pub fn read_table(filename: &str) -> Result<Table> {
        // Open the path in read-only mode
        let mut file = match File::open(filename) {
            Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename, why)),
            Ok(file) => Ok(file),
        }?;

        let mut table = HashMap::new();
        let (mut key, mut value) = ([0u8; super::SHA256_SIZE], [0u8; 32]);

        while super::SHA256_SIZE == file.read(&mut key)? {
            eyre::ensure!(
                32 == file.read(&mut value)?,
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
    pub fn write_jumps(filename: &str, jumps: &Jumps) -> Result<()> {
        // Open the path in write-only mode.
        // Erase previous file with the same name.
        let mut file = match File::create(filename) {
            Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename, why)),
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
    pub fn read_jumps(filename: &str) -> Result<Vec<Scalar>> {
        // Open the path in read-only mode
        let mut file = match File::open(filename) {
            Err(why) => Err(eyre::eyre!("Couldn't open {}: {}", filename, why)),
            Ok(file) => Ok(file),
        }?;

        let mut jumps = Vec::new();
        let mut jump = [0u8; 32];
        while 32 == file.read(&mut jump)? {
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
    /// - `res`:    solution
    /// - `table`:  precomputed table
    /// - `jumps`:  random jumps
    /// - `g`:      `Gt` generator
    /// - `h`:      DLP
    /// - `d`:      distinguishing parameter
    /// - `id`:     thread ID
    /// - `n`:      number of threads
    fn hunter(
        res: &Arc<Mutex<Scalar>>,
        table: &Table,
        jumps: &Jumps,
        g: &Gt,
        h: &Gt,
        d: usize,
        id: u64,
        n: u64,
    ) {
        let mut step = id;
        while Scalar::zero() == *res.lock().unwrap() {
            // wild kangaroo
            let y0 = Scalar::from_raw([step, 0, 0, 0]);
            let P0 = h + g * y0;

            // let it run
            let (P, y) = adding_walk(jumps, g, P0, y0, d);

            // check the traps
            match table.get(&hash(&P)) {
                Some(&x) => {
                    // check against false positive match due to the hash
                    if g * x == h + g * y {
                        *res.lock().unwrap() = x - y;
                    }
                }
                None => println!("I: value not in the table."),
            }

            step += n;
        }
    }

    /// Solve the DLP using the kangaroo method.
    /// - `table`:  precomputed table
    /// - `jumps`:  random jumps
    /// - `h`:      DLP
    /// - `w`:      walk size
    /// - `n`:      number of threads
    pub fn solve(table: &Table, jumps: &Jumps, h: &Gt, w: usize, n: usize) -> Scalar {
        // `Gt` group generator
        let g = pairing(&G1Affine::generator(), &G2Affine::generator());
        let d = get_distinguishing_parameter(w);
        let mut handles = Vec::with_capacity(n);

        // assert 0 is not the solution of the DLP
        if *h == g * Scalar::zero() {
            return Scalar::zero();
        }

        // use 0 as neutral value
        let res = Arc::new(Mutex::new(Scalar::zero()));
        let n = n as u64;

        for i in 0..n {
            let (res, h) = (res.clone(), *h);
            let (jumps, table) = (jumps.to_vec(), table.clone());

            handles.push(thread::spawn(move || {
                hunter(&res, &table, &jumps, &g, &h, d, i, n);
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
}
