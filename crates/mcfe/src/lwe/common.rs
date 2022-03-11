use std::convert::TryFrom;

use cosmian_crypto_base::cs_prng::{Normal, Uniform};
use num_bigint::{BigInt, BigUint};
use sha3::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha3_256,
};

use super::{
    parameters::{Parameters, Setup},
    FunctionalKey, FunctionalKeyShare, LabelVector, MasterSecretKey, SecretKey,
};

impl From<&Parameters> for SecretKey {
    fn from(parameters: &Parameters) -> Self {
        secret_key(parameters)
    }
}

impl TryFrom<&Setup> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(setup: &Setup) -> Result<Self, Self::Error> {
        Ok(secret_key(&Parameters::instantiate(setup)?))
    }
}

impl From<&Parameters> for MasterSecretKey {
    fn from(parameters: &Parameters) -> Self {
        master_secret_key(parameters)
    }
}

impl TryFrom<&Setup> for MasterSecretKey {
    type Error = anyhow::Error;

    fn try_from(setup: &Setup) -> Result<Self, Self::Error> {
        Ok(master_secret_key(&Parameters::instantiate(setup)?))
    }
}

/// Generate a Client Secret Key
///
/// Zᵢ = (sᵢ, tᵢ) ← Z¹ˣⁿ⁰ × D[ℤ¹ˣᵐ⁰,αq] for i∈{m}
///
/// A Vector of all these keys constitute the Master Secret Key
pub(crate) fn secret_key(parameters: &Parameters) -> SecretKey {
    let (m, n0, m0, q, std_dev) = (
        parameters.message_length,
        parameters.n0,
        parameters.m0,
        &parameters.q,
        &parameters.sigma,
    );
    let mut uniform_cs_prng = Uniform::new();
    let mut normal_cs_prng = Normal::new(&BigInt::from(0i32), std_dev);
    let mut sk_array: Vec<Vec<BigUint>> = Vec::with_capacity(m);
    for _ in 0..m {
        let mut sk_mi_array = Vec::with_capacity(n0 + m0);
        for _j in 0..n0 {
            sk_mi_array.push(uniform_cs_prng.big_uint_below(q))
        }
        for _j in 0..m0 {
            sk_mi_array.push(normal_cs_prng.big_uint(q));
        }
        sk_array.push(sk_mi_array);
    }
    SecretKey(sk_array)
}

/// Generate a Master Secret Key for the centralized model
pub(crate) fn master_secret_key(parameters: &Parameters) -> MasterSecretKey {
    let n = parameters.clients;
    let mut msk: MasterSecretKey = Vec::with_capacity(n);
    for _i in 0..n {
        msk.push(secret_key(parameters));
    }
    msk
}

// A small utility to create a Sha3 hash with an appended counter
fn hash_with_counter(data: &[u8], counter: usize) -> GenericArray<u8, U32> {
    Sha3_256::new()
        .chain(data)
        .chain(&counter.to_be_bytes())
        .finalize()
}

/// Create a label vector for label `label` of length `length` in ℤq
///
/// The n₀+m₀ terms are taken as `Sha3(hᵢ||counter)` where
/// hᵢ = sha3(hᵢ₋₁||counter) for i ∈ [1..n₀+m₀[ and h₀=label
#[inline]
pub fn create_label_vector(label: &[u8], length: usize, q: &BigUint) -> LabelVector {
    let mut vectors: Vec<BigUint> = Vec::with_capacity(length);
    let mut h = hash_with_counter(label, 0);
    vectors.push(BigUint::from_bytes_be(h.as_slice()) % q);
    for i in 1..length {
        h = hash_with_counter(h.as_slice(), i);
        vectors.push(BigUint::from_bytes_be(h.as_slice()) % q);
    }
    vectors
}

/// Encrypt the given `message` of length `m` for the given `label` and
/// `client`. Returns a vector of cipher texts of length `m`
///
/// using: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
/// where ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the rounding function
pub(crate) fn encrypt(
    parameters: &Parameters,
    label: &[u8],
    message: &[BigUint],
    secret_key: &SecretKey,
) -> anyhow::Result<Vec<BigUint>> {
    anyhow::ensure!(
        message.len() == parameters.message_length,
        "The message is of length: {}, it must be of length: {}",
        message.len(),
        parameters.message_length,
    );

    let (m, q_div_k) = (parameters.message_length, &parameters.q_div_k);
    // Zᵢ · H(l) = sₗ · aₗ + tᵢ · (Saₗ + eₗ )
    // except that we use sha3 here so we perform the dot product
    let z_i = secret_key;
    let n0_m0 = parameters.n0 + parameters.m0;
    // H(l)
    let h_l = create_label_vector(&label, n0_m0, &parameters.q);
    // instantiate the vector and fill
    let mut ct_il: Vec<BigUint> = Vec::with_capacity(m);
    for (mi, mu) in message.iter().enumerate() {
        anyhow::ensure!(
            mu <= &parameters.message_bound,
            "message element: {}, is bigger than upper bound: {}",
            mu,
            parameters.message_bound,
        );

        // calculate Zᵢ.H(l)
        let mut zi_hl = BigUint::from(0u32);
        for (j, h_l_j) in h_l.iter().enumerate() {
            zi_hl += h_l_j * &z_i.0[mi][j];
        }
        // round: modulo q and rescale to q0
        ct_il.push(round_to_q0(parameters, &(&zi_hl + q_div_k * mu)));
    }
    Ok(ct_il)
}

/// Issue a functional key for the `vectors` from a Master Secret Key.
/// The `vectors` has `number of clients` vectors of message length`
///
/// Calculated as `sky = ∑yᵢ.Zᵢ` where `i∈{nm}`
/// and `n` is the number of clients
pub fn functional_key(
    parameters: &Parameters,
    msk: &[SecretKey],
    vectors: &[Vec<BigUint>],
) -> anyhow::Result<FunctionalKey> {
    anyhow::ensure!(
        vectors.len() == parameters.clients,
        "The vectors number of rows: {}, must be equal to the number of clients: {}",
        vectors.len(),
        parameters.clients,
    );

    let (n0_m0, n, q) = (
        parameters.n0 + parameters.m0,
        parameters.clients,
        &parameters.q,
    );
    let mut sky: FunctionalKey = FunctionalKey(vec![BigUint::from(0u32); n0_m0]);
    for i in 0..n {
        let z_i = &msk[i];
        let y_i = &vectors[i];
        let sky_i = clear_text_functional_key_share(parameters, z_i, y_i)?;
        for (j, sky_i_j) in sky_i.iter().enumerate() {
            sky.0[j] += sky_i_j;
            sky.0[j] %= q;
        }
    }
    Ok(sky)
}

/// The client share of a functional key
///
/// Calculated as `sky = ∑yᵢ.Zᵢ` where `i∈{nm}`
/// and `n` is the number of clients
pub fn clear_text_functional_key_share(
    parameters: &Parameters,
    client_secret_key: &SecretKey,
    client_vector: &[BigUint],
) -> anyhow::Result<Vec<BigUint>> {
    let (m, n0_m0, vector_bound, q) = (
        parameters.message_length,
        parameters.n0 + parameters.m0,
        &parameters.vectors_bound,
        &parameters.q,
    );
    let mut sky_share = vec![BigUint::from(0u32); n0_m0];
    let z_i = client_secret_key;
    let y_i = client_vector;
    anyhow::ensure!(
        y_i.len() == m,
        "The vectors column size: {} must be equal that of the message: {}",
        y_i.len(),
        m,
    );

    for (mi, y_i_mi) in y_i.iter().enumerate() {
        anyhow::ensure!(
            y_i_mi < vector_bound,
            "The vector value {} >= {}, which is not allowed",
            y_i_mi,
            vector_bound
        );

        let z_i_mi = &z_i.0[mi];
        for (j, z_i_mi_j) in z_i_mi.iter().enumerate() {
            sky_share[j] += y_i_mi * z_i_mi_j;
        }
    }
    // clippy: no RemAssign implementation
    // on BigUint references so no possibility to iter_mut()
    #[allow(clippy::needless_range_loop)]
    for j in 0..n0_m0 {
        sky_share[j] %= q;
    }
    Ok(sky_share)
}

/// Issue an encrypted functional key share for the `vectors` as client number
/// `client`
///
/// The `share_secret_key` must have been issued with the other clients
/// so that `∑ fks_skᵢ = 0` where `i ∈ {n}` and `n` is the number of clients.
///
/// The `vectors` has `number of clients` vectors of message length`
///
/// Calculated as `fksᵢ = Enc₂(fks_skᵢ, yᵢ.sk, ᵢ, H(y))` where `i` is this
/// client number, `fks_skᵢ` is the functional key share secret key, `sk` is the
/// secret key and `yᵢ` is the vector for that client
/// size is m
pub fn encrypted_functional_key_share(
    parameters: &Parameters,
    secret_key: &SecretKey,
    fks_secret_key: &SecretKey,
    vectors: &[Vec<BigUint>],
    client: usize,
) -> anyhow::Result<FunctionalKeyShare> {
    let (n, m, n0_m0) = (
        parameters.clients,
        parameters.message_length,
        parameters.n0 + parameters.m0,
    );
    anyhow::ensure!(
        client < n,
        "Invalid client number: {}. There are {} clients",
        client,
        n
    );

    anyhow::ensure!(
        vectors.len() == n,
        "Invalid vectors length: {}. There are {} clients",
        vectors.len(),
        n
    );

    anyhow::ensure!(
        vectors[0].len() == m,
        "Invalid number of vectors coefficients for client 0: {}. The message length is: {}",
        vectors[0].len(),
        m
    );

    anyhow::ensure!(
        secret_key.0.len() == m,
        "Invalid number of secret keys: {}. It should be: {}",
        secret_key.0.len(),
        m
    );

    for (mi, sk) in secret_key.0.iter().enumerate() {
        anyhow::ensure!(
            sk.len() == n0_m0,
            "Invalid secret key length: {}, for message: {}. It should be: {}",
            sk.len(),
            mi,
            n0_m0
        );
    }
    let fks_parameters = parameters.fks_parameters()?;
    anyhow::ensure!(
        fks_secret_key.0.len() == fks_parameters.message_length,
        "Invalid number of FKS secret keys: {}. It should be: {}",
        fks_secret_key.0.len(),
        n0_m0
    );

    for (mi, sk) in fks_secret_key.0.iter().enumerate() {
        anyhow::ensure!(
            sk.len() == fks_parameters.n0 + fks_parameters.m0,
            "Invalid FKS secret key length: {}, for message: {}. It should be: {}",
            sk.len(),
            mi,
            n0_m0
        );
    }
    // create a label for hash vector H(y)
    let h_y_label = create_functional_key_label(vectors);
    // encryption of all µⱼ for j ∈{n₀+m₀}
    let sky_i = clear_text_functional_key_share(parameters, secret_key, &vectors[client])?;
    // encrypt it
    let mut enc_fks: Vec<BigUint> = Vec::with_capacity(n0_m0);
    for (idx, sky_i_j) in sky_i.iter().enumerate() {
        // no label reuse - add counter
        let mut this_label = idx.to_be_bytes().to_vec();
        this_label.extend_from_slice(&h_y_label);
        enc_fks.push(
            encrypt(
                &fks_parameters,
                &this_label,
                &[sky_i_j.clone()],
                fks_secret_key,
            )?[0]
                .clone(),
        );
    }
    Ok(FunctionalKeyShare(enc_fks))
}

pub(crate) fn create_functional_key_label(vectors: &[Vec<BigUint>]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    for row in vectors {
        for el in row {
            bytes.extend_from_slice(&el.to_bytes_be());
        }
    }
    bytes
}

/// Combine the functional key shares from the clients
/// To recover the functional key
///
/// Implemented as the scalar product of the share and the 1 vector
/// which performs ∑skᵢ.zᵢ for i∈{n}
pub fn recover_functional_key(
    parameters: &Parameters,
    functional_key_shares: &[FunctionalKeyShare],
    vectors: &[Vec<BigUint>],
) -> anyhow::Result<FunctionalKey> {
    let (n, n0_m0, q) = (
        parameters.clients,
        parameters.n0 + parameters.m0,
        &parameters.q,
    );
    let fks_parameters = parameters.fks_parameters()?;
    let fks_n0_m0 = fks_parameters.n0 + fks_parameters.m0;
    // perform the scalar products of <Enc(sk_j),1>
    // the vector to perform the n₀+m₀ scalar product over the n encrypted
    // functional key shares
    let fks_vectors = vec![vec![BigUint::from(1u32)]; n];
    // the functional key is a vector of length  n₀+m₀ filled with zeroes:
    // since the functional_key_vectors is filled with 1, ∑skᵢ.yᵢ = ∑skᵢ = 0 by
    // construction
    let fks_functional_key = FunctionalKey(vec![BigUint::from(0u32); fks_n0_m0]);
    // the H(y) used is a hash of all the vectors that get into the final functional
    // computation
    let h_y_label = create_functional_key_label(vectors);
    // we need to perform the scalar product for the n₀+m₀ vectors
    // across the n clients
    let mut functional_key: Vec<BigUint> = Vec::with_capacity(n0_m0);
    for j in 0..n0_m0 {
        // assemble all the functional key shares from all client for that j
        let mut fks_j: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for fks_i in functional_key_shares {
            fks_j.push(vec![fks_i.0[j].clone()]);
        }
        // no label reuse - add counter
        let mut this_label = j.to_be_bytes().to_vec();
        this_label.extend_from_slice(&h_y_label);
        functional_key.push(
            decrypt(
                &fks_parameters,
                &this_label,
                &fks_j,
                &fks_functional_key,
                &fks_vectors,
            )? % q,
        );
    }
    Ok(FunctionalKey(functional_key))
}

/// Calculate and decrypt the inner product vector of `<messages , vectors>`
/// for the given `cipher_texts`, `label` and `functional_key`.
///
///  - The `cipher_texts` vectors size must be equal to `nxm` = `number of
///    clients x message length`.
///  - The `functional_key` vectors must have size 1x(n₀+m₀) `message length`
///    rows.
///  - The `vectors` must contain `number of clients` vectors of  `message
///    length`.
///
/// `cipher_texts` and `vectors` must have the same clients ordering
///
/// Calculated as `μ = ∑yᵢ.ctᵢ_ₗ - ⌊sk.H(l)⌉->q₀ mod q₀` for each message
/// element where `i∈{n}` and ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉ and ⌊⌉ is the
/// rounding function
pub fn decrypt(
    parameters: &Parameters,
    label: &[u8],
    cipher_texts: &[Vec<BigUint>],
    functional_key: &FunctionalKey,
    vectors: &[Vec<BigUint>],
) -> anyhow::Result<BigUint> {
    anyhow::ensure!(
        cipher_texts.len() == parameters.clients,
        "The cipher texts vector size: {}, must be equal to the number of clients: {}",
        cipher_texts.len(),
        parameters.clients,
    );

    anyhow::ensure!(
        vectors.len() == parameters.clients,
        "The vector size: {}, must be equal to the number of clients: {}",
        vectors.len(),
        parameters.clients,
    );

    let (m, n, n0_m0, k, q0, q, q0_q_div_k, q0_q_div_2k) = (
        parameters.message_length,
        parameters.clients,
        parameters.n0 + parameters.m0,
        &parameters.k,
        &parameters.q0,
        &parameters.q,
        &parameters.q0_q_div_k,
        &parameters.q0_q_div_2k,
    );
    let mut mu = BigUint::from(0u32);
    for c in 0..n {
        for mi in 0..m {
            mu += &vectors[c][mi] * &cipher_texts[c][mi];
        }
    }
    // rounded term ⌊sk.H(l)⌉->q₀
    let h_l = create_label_vector(&label, n0_m0, q);
    let mut sk_hl = BigUint::from(0u32);
    for (j, h_l_j) in h_l.iter().enumerate() {
        sk_hl += &functional_key.0[j] * h_l_j;
    }
    // add terms
    // mu_m -= round_to_q0(parameters, &sk_hl);
    mu += q0 - round_to_q0(parameters, &sk_hl);
    // return modulo q0
    mu %= q0;
    // now rescale with rounding
    mu *= q;
    // perform rounding
    mu += q0_q_div_2k;
    mu /= q0_q_div_k;
    mu %= k;
    Ok(mu)
}

/// Calculates ⌊x⌉->q₀ is ⌊(q₀/q).(x mod q)⌉
/// and ⌊⌉ is the rounding function
///
/// Performed as [(x%q)*q₀ + q/2]/q
pub(crate) fn round_to_q0(parameters: &Parameters, v: &BigUint) -> BigUint {
    let (q, q0, half_q) = (&parameters.q, &parameters.q0, &parameters.half_q);
    let mut res = v % q;
    res *= q0;
    res += half_q;
    res /= q;
    res
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
pub(crate) mod tests {

    use std::{thread, time::Instant};

    use cosmian_crypto_base::cs_prng::Uniform;
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};

    use super::{
        super::{common::SecretKey, parameters::Parameters},
        create_label_vector, decrypt, encrypt, functional_key, master_secret_key, round_to_q0,
        secret_key,
    };
    use crate::lwe::parameters::Setup;

    #[test]
    fn test_big_int() {
        let n = 1u64 << 63;
        let p = 1u64 << 32;
        let v: u64 = 1u64 << 63;
        let mut k = BigUint::from(n);
        k *= p;
        k *= v;
        assert_eq!(
            k.to_u32_digits(),
            vec![0, 0, 0, 0, 0b_0100_0000_0000_0000_0000_0000_0000_0000]
        );
    }

    #[allow(clippy::many_single_char_names)]
    pub(crate) fn paper_params() -> Parameters {
        let n = 100usize;
        let m: usize = 1usize;
        let p = BigUint::from(100u32);
        let v = BigUint::from(100u32);
        let q = BigUint::from((1u128 << 127) - 1);
        let q0 = BigUint::from(std::u32::MAX);
        let k: BigUint = &p * &v * n * m;
        let q_div_k: BigUint = &q / &k;
        let q0_q_div_k = &q0 * &q_div_k;
        // let params = Parameters::instantiate(n, p, v)?;
        Parameters {
            clients: n,
            message_length: m,
            message_bound: p,
            vectors_bound: v,
            k,
            q: q.clone(),
            q0: BigUint::from(std::u32::MAX),
            m0: 500,
            n0: 500,
            q_div_k,
            sigma: BigUint::from(1000u32),
            half_q: &q / 2u32,
            q0_q_div_k: q0_q_div_k.clone(),
            q0_q_div_2k: &q0_q_div_k / 2u32,
        }
    }

    #[test]
    fn test_round() {
        for i in 0u32..100_000 {
            let q: u32 = thread_rng().gen_range(257..std::u32::MAX);
            let q0: u32 = thread_rng().gen_range(1..q);
            let mut params = paper_params();
            params.q = BigUint::from(q);
            params.q0 = BigUint::from(q0);
            params.half_q = &params.q / 2u32;
            // perform round calculations
            let rnd = f64::round(((i % q) as f64) * (q0 as f64) / (q as f64));
            assert_eq!(
                BigUint::from(rnd as u64),
                round_to_q0(&params, &BigUint::from(i)),
                "failed for q: {}, q0: {}, i: {}, rnd: {}",
                q,
                q0,
                i,
                rnd
            );
        }
    }

    #[test]
    fn test_key_gen() {
        const FACTOR: usize = 7usize;
        let mut params = paper_params();
        // push m₀ parameter up to make it statistically correct
        params.m0 = FACTOR * 100_000usize;
        // same thing for n0
        params.n0 = FACTOR * 100_000usize;
        // key generation
        let sk = secret_key(&params);
        // check
        let q = params.q.clone();
        let std_dev = params.sigma.clone();
        let two_std_dev: BigUint = &std_dev * 2u32;
        let three_std_dev: BigUint = &std_dev * 3u32;
        let mut counter_1 = 0usize;
        let mut counter_2 = 0usize;
        let mut counter_3 = 0usize;
        let mut greater_than_q0 = 0;
        for zi in &sk.0 {
            assert_eq!(params.n0 + params.m0, zi.len());
            for si in zi.iter().take(params.n0) {
                assert!(si < &q);
                if si > &params.q0 {
                    greater_than_q0 += 1;
                }
            }
            for ti in zi.iter() {
                if ti < &std_dev || ti > &(&q - &std_dev) {
                    counter_1 += 1;
                    counter_2 += 1;
                    counter_3 += 1;
                } else if ti < &two_std_dev || ti > &(&q - &two_std_dev) {
                    counter_2 += 1;
                    counter_3 += 1;
                } else if ti < &three_std_dev || ti > &(&q - &three_std_dev) {
                    counter_3 += 1;
                }
            }
            assert!(greater_than_q0 > 0);
            assert!(
                counter_1 / FACTOR > 68070 && counter_1 / FACTOR < 68470,
                "{} not in ]68070, 68470[",
                counter_1 / FACTOR
            );
            assert!(
                counter_2 / FACTOR > 95250 && counter_2 / FACTOR < 95650,
                "{} not in ]92250, 96560[",
                counter_2
            );
            assert!(
                counter_3 / FACTOR > 99530 && counter_3 / FACTOR < 99930,
                "{} not in ]99530, 99930[",
                counter_3
            );
            println!("σ: [{} bits] {}", std_dev.bits(), &std_dev);
            println!(
                "<σ: {} <2σ: {} <3σ: {}",
                counter_1 / FACTOR,
                counter_2 / FACTOR,
                counter_3 / FACTOR
            );
        }
    }

    #[test]
    fn test_key_der() -> anyhow::Result<()> {
        let params = paper_params();
        let msk = master_secret_key(&params);
        let mut vectors: Vec<Vec<BigUint>> =
            vec![vec![BigUint::from(0u32); params.message_length]; params.clients];
        #[allow(clippy::needless_range_loop)]
        let mut uniform = Uniform::new();
        for c in 0..params.clients {
            for mi in 0..params.message_length {
                vectors[c][mi] = uniform.big_uint_below(&params.vectors_bound);
            }
        }
        let sky = functional_key(&params, &msk, &vectors)?;
        assert_eq!(params.n0 + params.m0, sky.0.len());
        for sky_j in sky.0 {
            assert!(sky_j < params.q);
        }
        Ok(())
    }

    #[test]
    fn test_encryption() -> anyhow::Result<()> {
        let params = paper_params();
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let n0_m0 = params.n0 + params.m0;
        let h_l = create_label_vector(&label, n0_m0, &params.q);
        // encryption: `ctᵢ_ₗ = ⌊Zᵢ.H(l) + ⌊q/K⌋.xᵢ⌉->q₀`
        // if we encrypt a vector of 0, we should get a vector of the rounded version of
        // Zᵢ.H(l)
        let mu = vec![BigUint::from(0u32); params.message_length];
        let zi = secret_key(&params);
        let ct_il = encrypt(&params, &label, &mu, &zi)?;
        for (mi, ct_il_mi) in ct_il.iter().enumerate() {
            let mut zi_hl = BigUint::from(0u32);
            for (j, h_l_j) in h_l.iter().enumerate() {
                zi_hl += h_l_j * &zi.0[mi][j];
            }
            assert_eq!(&round_to_q0(&params, &zi_hl), ct_il_mi)
        }
        // if the key is null, we should get ⌊ ⌊q/K⌋.xᵢ⌉->q₀
        let mut uniform = Uniform::new();
        let zi = SecretKey(vec![
            vec![BigUint::from(0u32); params.n0 + params.m0];
            params.message_length
        ]);
        let mut mu: Vec<BigUint> = Vec::with_capacity(params.message_length);
        for _mi in 0..params.message_length {
            mu.push(uniform.big_uint_below(&params.message_bound));
        }
        let ct_il = encrypt(&params, &label, &mu, &zi)?;
        for mi in 0..params.message_length {
            assert_eq!(
                round_to_q0(&params, &(&params.q_div_k * &mu[mi])),
                ct_il[mi]
            )
        }
        Ok(())
    }

    fn bench_encryption(message_bits: (usize, u32), n0: usize) -> anyhow::Result<()> {
        let bound = BigUint::from(2u8).pow(message_bits.1);
        let parameters = Parameters::instantiate(&Setup {
            clients: 1,
            message_length: message_bits.0,
            message_bound: bound.clone(),
            vectors_bound: bound,
            n0,
        })?;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let zi = secret_key(&parameters);
        let mut nanos_total = 0u128;
        let loops: usize = 25000usize;
        for _l in 0usize..loops {
            let mut uniform = Uniform::new();
            let mut mu: Vec<BigUint> = Vec::with_capacity(parameters.message_length);
            for _mi in 0..parameters.message_length {
                mu.push(uniform.big_uint_below(&parameters.message_bound));
            }
            let now = Instant::now();
            encrypt(&parameters, &label, &mu, &zi)?;
            nanos_total += now.elapsed().as_nanos();
        }
        let enc_0 = encrypt(
            &parameters,
            &label,
            &vec![&parameters.message_bound - 1u32; parameters.message_length],
            &zi,
        )?[0]
            .to_bytes_be();
        println!(
            "{:>5} | {:>4} | {:>3} | {:>3} | {:>10} | {:>11} ",
            nanos_total / 1000 / (loops as u128),
            n0,
            message_bits.0,
            message_bits.1,
            message_bits.1 as usize * message_bits.0,
            message_bits.0 * enc_0.len() * 8,
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn bench_encryptions() {
        println!("Encryption benchmarks:");
        println!("   μs |   n0 |   m |   b | Clear bits | Cipher bits ");
        println!("------|------|-----|-----|------------|-------------");
        let key_length = vec![256, 512, 1024usize];
        let message_bits: Vec<(usize, u32)> = vec![
            (1, 2),
            (1, 32),
            (1, 64),
            (1, 128),
            (2, 64),
            (4, 64),
            (8, 64),
            (16, 64),
        ];
        let mut handles = vec![];
        for n0 in key_length {
            for l in &message_bits {
                let l_c = *l;
                let handle = thread::spawn(move || {
                    bench_encryption(l_c, n0).unwrap_or_else(|_| {
                        panic!(
                            "failed for parameters: m: {}, l: {}, n0: {}",
                            l_c.0, l_c.1, n0
                        )
                    });
                });
                handles.push(handle);
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    fn test_encryption_decryption(params: &Parameters) -> anyhow::Result<()> {
        let n = params.clients;
        let m = params.message_length;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        let mut uniform = Uniform::new();
        for _c in 0..n {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&params.message_bound));
                vectors_c.push(uniform.big_uint_below(&params.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut expected: BigUint = BigUint::from(0u32);
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            for mi in 0..m {
                expected += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // master key generation
        let msk = master_secret_key(params);
        // derived key generation
        let sky = functional_key(params, &msk, &vectors)?;
        //encryption
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(n);
        for (i, m) in messages.iter().enumerate() {
            cts.push(encrypt(&params, &label, m, &msk[i])?);
        }
        // decryption
        let result = decrypt(params, &label, &cts, &sky, &vectors)?;
        assert_eq!(
            &expected, &result,
            "parameters: {}, expected: {}, result: {}",
            &params, &expected, &result
        );
        Ok(())
    }

    #[test]
    fn test_encryption_decryptions() -> anyhow::Result<()> {
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 10,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        test_encryption_decryption(&paper_params())?;
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 20,
            message_length: 31,
            message_bound: BigUint::from(2u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        Ok(())
    }

    #[test]
    fn test_encryption_decryptions_of_zero() -> anyhow::Result<()> {
        test_encryption_decryption(&Parameters::instantiate(&Setup {
            clients: 2,
            message_length: 31,
            message_bound: BigUint::from(1u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?)?;
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_a_lot_of_encryption_decryptions() -> anyhow::Result<()> {
        let params = Parameters::instantiate(&Setup {
            clients: 10,
            message_length: 31,
            message_bound: BigUint::from(std::u32::MAX),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?;
        for i in 0..5000 {
            if (i + 1) % 100 == 0 {
                println!("{}", (i + 1));
            }
            test_encryption_decryption(&params)?;
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_a_lot_of_encryption_decryptions_of_zero() -> anyhow::Result<()> {
        let params = Parameters::instantiate(&Setup {
            clients: 2,
            message_length: 31,
            message_bound: BigUint::from(1u32),
            vectors_bound: BigUint::from(std::u32::MAX),
            n0: 1024,
        })?;
        for i in 0..5000 {
            if (i + 1) % 100 == 0 {
                println!("{}", (i + 1));
            }
            test_encryption_decryption(&params)?;
        }
        Ok(())
    }

    fn bench_decryption(
        clients: usize,
        message_bits: (usize, u32),
        n0: usize,
    ) -> anyhow::Result<()> {
        let bound = BigUint::from(2u8).pow(message_bits.1);
        let parameters = Parameters::instantiate(&Setup {
            clients,
            message_length: message_bits.0,
            message_bound: bound.clone(),
            vectors_bound: bound,
            n0,
        })?;
        let m = message_bits.0;
        let mut label = [0u8; 32];
        rand::thread_rng().fill(&mut label);
        let mut uniform = Uniform::new();
        let mut messages: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        let mut vectors: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        for _c in 0..clients {
            let mut message_c: Vec<BigUint> = Vec::with_capacity(m);
            let mut vectors_c: Vec<BigUint> = Vec::with_capacity(m);
            for _mi in 0..m {
                message_c.push(uniform.big_uint_below(&parameters.message_bound));
                vectors_c.push(uniform.big_uint_below(&parameters.vectors_bound));
            }
            messages.push(message_c);
            vectors.push(vectors_c);
        }
        let mut expected: Vec<BigUint> = vec![BigUint::from(0u32); m];
        for (mi, expected_mi) in expected.iter_mut().enumerate() {
            for i in 0..clients {
                *expected_mi += &messages[i][mi] * &vectors[i][mi];
            }
        }
        // master key generation
        let msk = master_secret_key(&parameters);
        // derived key generation
        let sky = functional_key(&parameters, &msk, &vectors)?;
        //encryption
        let mut cts: Vec<Vec<BigUint>> = Vec::with_capacity(clients);
        for (i, m) in messages.iter().enumerate() {
            cts.push(encrypt(&parameters, &label, m, &msk[i])?);
        }
        let mut nanos_total = 0u128;
        let loops: usize = 50_000 / m;
        for _l in 0usize..loops {
            let now = Instant::now();
            decrypt(&parameters, &label, &cts, &sky, &vectors)?;
            nanos_total += now.elapsed().as_nanos();
        }
        let dec_0 = decrypt(&parameters, &label, &cts, &sky, &vectors)?.to_bytes_be();
        println!(
            "{:>5}, {:>4}, {:>4}, {:>4}, {:>4}, {:>8}",
            nanos_total / 1000 / (loops as u128),
            n0,
            clients,
            message_bits.0,
            message_bits.0 * message_bits.1 as usize,
            dec_0.len() * 8
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn bench_decryptions() {
        println!("Decryption benchmarks:");
        println!("  μs,   n0,    n,    m,    b, clear bits");
        let key_length = vec![256, 512, 1024usize];
        let message_bits: Vec<(usize, u32)> = vec![
            (1, 2),
            (1, 32),
            (1, 64),
            (1, 128),
            (2, 64),
            (4, 64),
            (8, 64),
            (16, 64),
        ];
        let clients = vec![1usize, 10, 20, 100];
        let mut handles = vec![];
        for n0 in key_length {
            for n in &clients {
                let n_c = *n;
                for l in &message_bits {
                    let l_c = *l;
                    let handle = thread::spawn(move || {
                        bench_decryption(n_c, l_c, n0).unwrap_or_else(|e| {
                            panic!(
                                "failed for parameters: n: {},m:{}, l: {}, n0: {}: {}",
                                n_c, l_c.0, l_c.1, n0, e
                            )
                        });
                    });
                    handles.push(handle);
                }
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
