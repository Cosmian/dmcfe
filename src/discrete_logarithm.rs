use bls12_381::{G1Affine, G1Projective};
use std::collections::HashMap;
use std::io::ErrorKind;

use crate::interface;

/// This algorithm implements the precomputation step of the BSGS algorithms.
/// It returns a hashed map containing all the precomputed pairs.
///
/// - `m`:  number of pairs to precompute
///
/// See [the notes on DLP](crate::notes::dlp) for more explanations
fn precomputation(m: u32) -> HashMap<G1Affine, (u32, G1Affine)> {
    let G = G1Projective::generator();
    let mut pairs: HashMap<G1Affine, (u32, G1Affine)> = HashMap::new();
    let mut P_i = G1Projective::identity();
    for i in 0..m {
        pairs.insert(G1Affine::from(P_i), (i, G1Affine::from(P_i)));
        P_i = P_i + G;
    }
    pairs
}

/// This algorithm imlements the iteration fonction of the BSGS algorithm.
///
/// - `P`:      right term of the DLP
/// - `Q`:      inverse of `g^m`
/// - `n`:      the number of iterations
/// - `pairs`:  hash table containg the precomputed values
fn iterate(
    P: &G1Projective,
    Q: &G1Projective,
    n: u32,
    pairs: &mut HashMap<G1Affine, (u32, G1Affine)>,
) -> Option<(u32, u32)> {
    let mut res = None;
    let mut k = 0;
    let mut Q_k = G1Projective::identity();
    let mut P_k = Q_k + P;
    while k < n {
        res = pairs.get(&G1Affine::from(P_k));
        if res.is_some() {
            break;
        } else {
            k += 1;
            Q_k = Q_k + Q;
            P_k = Q_k + P;
        }
    }
    res.map(|pair| (k, pair.0))
}

/// This algorithm implements the BSGS algorithm. It aims to find `x` such that
/// `x.g = p`, where `g` is the generator of `G1`, `p` is given and `x < M`
/// with `M = mn` is not too big.
///
/// `P`:  right member of the DLP equation
/// `m`:  integer such that `x < mn`
/// `n`:  integer such that `x < mn`
pub fn bsgs(P: &G1Projective, m: u32, n: u32) -> Result<u64, ErrorKind> {
    // define some heuristics
    // e.g. test the case where the solution is 1

    let mut pairs = precomputation(m);
    let Q = interface::get_inverse(&G1Projective::generator(), m);

    let res = iterate(&P, &Q, n, &mut pairs);
    if let Some((k, i)) = res {
        Ok(u64::from(k * m + i))
    } else {
        Err(ErrorKind::NotFound)
    }
}
