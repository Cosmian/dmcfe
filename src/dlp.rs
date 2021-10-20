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
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use eyre::Result;

    /// Hash table used to store precomputed distinguished points.
    type Table = HashMap<[u8; super::SHA256_SIZE], Scalar>;

    /// Hash function for a point on `Gt`
    fn hash(P: &Gt) -> [u8; super::SHA256_SIZE] {
        Sha256::digest(&P.to_compressed()).into()
    }

    /// Find the partition associated to the given point.
    /// - `p`:  `Gt` point
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

    #[test]
    fn test_is_distinguished() -> Result<()> {
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
            true == is_distinguished_stubbed(&0b0110101101010000u16.to_be_bytes(), 4),
            "Wrong decision"
        );

        eyre::ensure!(
            false == is_distinguished_stubbed(&0b0110101101010000u16.to_be_bytes(), 5),
            "Wrong decision"
        );

        Ok(())
    }

    /// Compute a random adding-walk step.
    /// - `m`:      list of random points
    /// - `Y`:      previous step in the walk
    /// - `coeff`:  coefficient of the previous step in the walk
    /// - `g`:      `Gt` group generator
    /// - `h`:      DLP
    fn adding_step(m: &[Scalar], Y: &Gt, coeff: &Scalar, g: &Gt) -> (Gt, Scalar) {
        let i = partition(&Y, m.len());
        (Y + g * m[i], coeff + &m[i])
    }

    /// Compute a r-adding walk of length `w`.
    /// - `m`:      `r` random points
    /// - `h`:      DLP
    /// - `alpha0`: exponent of the first step of the random walk
    /// - `w`:      walk length
    fn adding_walk(
        m: &[Scalar],
        g: &Gt,
        Y: &Gt,
        coeff: &Scalar,
        w: usize,
        d: u32,
    ) -> Option<(Gt, Scalar)> {
        // initialise the walk
        let (mut Y, mut coeff) = (*Y, *coeff);

        // random walk
        // stop when twice the walk length is reached
        // or when a distinguished point is found
        for _ in 0..(2 * w) {
            if is_distinguished(&Y, d as usize) {
                return Some((Y, coeff));
            }

            let (P, p) = adding_step(m, &mut Y, &mut coeff, g);
            Y = P;
            coeff = p;
        }

        println!("W: Walk failed");
        None
    }

    /// Generate a table of `T` precomputed distinguised points, along with their DLP.
    /// - `t`:      table size
    /// - `w`:      walks size
    /// - `d`:      distinguishing parameter
    /// - `jumps`:  list of random points fot the adding walk
    pub fn gen_table(l: u64, t: usize, w: usize, d: u32, jumps: &[Scalar]) -> Result<Table> {
        // `Gt` group generator
        let g: Gt = pairing(&G1Affine::generator(), &G2Affine::generator());

        // precomputed table
        let mut table = HashMap::with_capacity(t * w);

        while table.len() < t {
            // choose a small random coefficient to start the walk
            let y0 = tools::bounded_random_scalar(1, l)?;
            // compute a walk; if a distinguished point is found, add it to the table
            if let Some((P, coeff)) = adding_walk(jumps, &g, &(g * y0), &y0, w, d) {
                table.insert(hash(&P), coeff);
                println!("Table completion: {}/{}", table.len(), t);
            }
        }

        Ok(table)
    }

    /// Write the given precomputed table to the file with the given name.
    /// - `filename`:   name of the file
    /// - `table`:      precomputed table
    pub fn write_table(filename: &str, table: &Table) -> Result<()> {
        // erase previously saved data
        let mut file = File::create(filename)?;
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
    pub fn read_table(filename: &str) -> eyre::Result<Table> {
        // Open the path in read-only mode
        let mut file = match File::open(filename) {
            Err(why) => panic!("couldn't open {}: {}", filename, why),
            Ok(file) => file,
        };

        let mut table = HashMap::new();
        let (mut key, mut value) = ([0u8; super::SHA256_SIZE], [0u8; 32]);

        while super::SHA256_SIZE == file.read(&mut key)? {
            eyre::ensure!(
                32 == file.read(&mut value)?,
                "Couldn't read all bytes of the value corresponding to the key: {:?}",
                key
            );

            let s = Scalar::from_bytes(&value).unwrap_or(Scalar::zero());

            eyre::ensure!(
                s != Scalar::zero(),
                "Error while converting read bytes into scalar! {:?}",
                value
            );

            table.insert(key, s);
        }

        Ok(table)
    }

    /// Generate `k` random jumps. The mean of their indices should be comparable with `sqrt(l)`,
    /// where `l` is the size of the interval on which the DLP is solved.
    /// - `l`:  interval size
    /// - `k`:  number of point to generate
    pub fn gen_jumps(l: u64, k: usize) -> eyre::Result<Vec<Scalar>> {
        // uniform distribution in `[0, 2*sqrt(l)]`
        let max = 2 * (l as f64).sqrt() as u64;
        (0..k)
            .map(|_| tools::bounded_random_scalar(1, max))
            .collect()
    }

    /// Write the given jumps to the file with the given name.
    /// - `filename`:   name of the file
    /// - `table`:      jumps
    pub fn write_jumps(filename: &str, jumps: &[Scalar]) -> eyre::Result<()> {
        // erase previously saved data
        let mut file = File::create(filename)?;
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
    pub fn read_jumps(filename: &str) -> eyre::Result<Vec::<Scalar>> {
        // Open the path in read-only mode
        let mut file = match File::open(filename) {
            Err(why) => panic!("couldn't open {}: {}", filename, why),
            Ok(file) => file,
        };

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

    /// Solve the DLP using the kangaroo method.
    /// - `jumps`:  jumps
    /// - `h`:      DLP
    /// - `w`:      walk size
    /// - `d`:      distinguishing parameter
    pub fn solve(
        table: &Table,
        jumps: &[Scalar],
        h: &Gt,
        l: u64,
        w: usize,
        d: u32,
    ) -> Option<Scalar> {
        // `Gt` group generator
        let g: Gt = pairing(&G1Affine::generator(), &G2Affine::generator());

        // release wild kangaroos
        for i in 1..(l as f64).sqrt() as u64 {
            // TODO: may parallelise here
            // start walk from the point `hg^i`
            let y0 = Scalar::from_raw([i, 0, 0, 0]);
            let P0 = h + g * y0;
            if let Some((P, y)) = adding_walk(jumps, &g, &P0, &y0, w, d) {
                if let Some(&x) = table.get(&hash(&P)) {
                    // check against false positive match due to the hash
                    if g * x == h + g * y {
                        return Some(x - y);
                    }
                }
            }
        }

        None
    }
}
