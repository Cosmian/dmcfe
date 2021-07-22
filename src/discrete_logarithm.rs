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
fn precomputation(m: &u32) -> HashMap<G1Affine, (u32, G1Affine)> {
    let g = G1Projective::generator();
    let mut pairs: HashMap<G1Affine, (u32, G1Affine)> = HashMap::new();
    let mut pi = G1Projective::identity();
    for i in 0..*m {
        pairs.insert(G1Affine::from(pi), (i, G1Affine::from(pi)));
        pi = pi + g;
    }
    pairs
}

/// This algorithm imlements the iteration fonction of the BSGS algorithm.
///
/// - `p`:      right term of the DLP
/// - `q`:      inverse of `g^m`
/// - `n`:      the number of iterations
/// - `pairs`:  hash table containg the precomputed values
fn iterate(
    p: &G1Affine,
    q: &G1Affine,
    n: &u32,
    pairs: &mut HashMap<G1Affine, (u32, G1Affine)>,
) -> Option<(u32, u32)> {
    let mut res = None;
    let mut k = 0;
    let mut qk: G1Projective = G1Projective::identity();
    let mut pk = qk + p;
    while k < *n {
        res = pairs.get(&G1Affine::from(pk));
        if res.is_some() {
            break;
        } else {
            k += 1;
            qk = qk + q;
            pk = qk + p;
        }
    }
    if let Some(pair) = res {
        Some((k, pair.0))
    } else {
        None
    }
}

/// Returns the inverse of `p^pow`.
///
/// - `p`:   Point in G1
/// - `n`: exponent
fn get_inverse(p: &G1Affine, n: &u32) -> G1Affine {
    let q = interface::naive_exponentiation(p, n);
    G1Affine::inverse(&q)
}

/// This algorithm implements the BSGS algorithm. It aims to find `x` such that
/// `x.g = p`, where `g` is the generator of `G1`, `p` is given and `x < M`
/// with `M = mn` is not too big.
///
/// `p`:  right member of the DLP equation
/// `m`:  integer such that `x < mn`
/// `n`:  integer such that `x < mn`
pub fn bsgs(p: &G1Affine, m: &u32, n: &u32) -> Result<u64, ErrorKind> {
    // define some heuristics
    // e.g. test the case where the solution is 1

    let mut pairs = precomputation(&m);
    let q = G1Affine::from(get_inverse(&G1Affine::generator(), &m));

    let res = iterate(&p, &q, &n, &mut pairs);
    if let Some((k, i)) = res {
        Ok(u64::from(k * m + i))
    } else {
        Err(ErrorKind::NotFound)
    }
}
